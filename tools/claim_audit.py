#!/usr/bin/env python3
"""Fail-closed validation of the succinct Rabung claim evidence.

The expensive programs are intentionally not launched by this module.  It
validates their byte-preserved outputs, verifies the digests printed by the
programs, and checks that a manifest contains exactly the evidence required by
one entry of audit/claims.json.  Any missing, duplicate, malformed, negative,
or hash-mismatched datum is a hard failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLAIMS = ROOT / "audit" / "claims.json"
SCHEMA_ID = "vdw-claim-manifest/v1"
FNV_OFFSET = 14695981039346656037
FNV_PRIME = 1099511628211
MASK64 = (1 << 64) - 1
HEX64_RE = re.compile(r"^[0-9a-f]{16}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NEGATIVE_RE = re.compile(
    r"(?:\*\*DIFF\*\*|\bECHEC\b|\bFAIL\b|\bREJECT\b|\bINVALIDE\b)",
    re.IGNORECASE,
)


class ClaimAuditError(ValueError):
    """An evidence item failed a fail-closed validation rule."""


def fail(message: str) -> None:
    raise ClaimAuditError(message)


def fnv1a64_le(values) -> int:
    """FNV-1a over a canonical sequence of unsigned little-endian u64s."""
    digest = FNV_OFFSET
    for raw in values:
        value = int(raw)
        if value < 0 or value > MASK64:
            fail(f"digest input outside u64: {value}")
        for _ in range(8):
            digest ^= value & 0xFF
            digest = (digest * FNV_PRIME) & MASK64
            value >>= 8
    return digest


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_output(data) -> str:
    if isinstance(data, str):
        return data.replace("\r\n", "\n").replace("\r", "\n")
    try:
        return bytes(data).decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError as exc:
        fail(f"output is not valid UTF-8: {exc}")


def claim_numbers(claim):
    try:
        p = int(claim["prime"])
        r = int(claim["colors"])
        k = int(claim["length"])
        bound = int(claim["lower_bound"])
    except (KeyError, TypeError, ValueError) as exc:
        fail(f"malformed claim: {exc}")
    expected = (k - 1) * p + 1
    if bound != expected:
        fail(f"claim arithmetic mismatch: {bound} != {expected}")
    return p, r, k, bound


def require_exit_zero(exit_code, stage):
    if int(exit_code) != 0:
        fail(f"{stage}: non-zero exit code {exit_code}")


def require_no_negative(text, stage):
    match = NEGATIVE_RE.search(text)
    if match:
        fail(f"{stage}: negative token {match.group(0)!r}")


def one_match(pattern, text, stage, flags=re.MULTILINE):
    matches = list(re.finditer(pattern, text, flags))
    if len(matches) != 1:
        fail(f"{stage}: expected exactly one match for {pattern!r}, got {len(matches)}")
    return matches[0]


def parse_kv_line(prefix, text, stage):
    lines = [line for line in text.splitlines() if line.startswith(prefix + " ")]
    if len(lines) != 1:
        fail(f"{stage}: expected exactly one {prefix} line, got {len(lines)}")
    fields = {}
    for token in lines[0].split()[1:]:
        if "=" not in token:
            fail(f"{stage}: malformed {prefix} token {token!r}")
        key, value = token.split("=", 1)
        if not key or key in fields:
            fail(f"{stage}: duplicate or empty {prefix} key {key!r}")
        fields[key] = value
    return fields


VERIFY_ROW_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+"
    r"(OK|\*\*DIFF\*\*)\s*$",
    re.MULTILINE,
)


def parse_verify1(stdout, exit_code, claim):
    stage = "scan_gpu --verify1"
    require_exit_zero(exit_code, stage)
    text = decode_output(stdout)
    require_no_negative(text, stage)
    p, r, k, bound = claim_numbers(claim)

    header = one_match(r"^VERIFY1 p=(\d+) g=(\d+)\s*$", text, stage)
    if int(header.group(1)) != p:
        fail(f"{stage}: output prime {header.group(1)} != expected {p}")

    rows = {}
    for match in VERIFY_ROW_RE.finditer(text):
        rr = int(match.group(1))
        if rr in rows:
            fail(f"{stage}: duplicate profile row r={rr}")
        values = [int(match.group(i)) for i in range(2, 8)]
        if match.group(8) != "OK" or len(set(values)) != 1:
            fail(f"{stage}: non-concordant profile row r={rr}")
        if any(value < 1 for value in values):
            fail(f"{stage}: non-positive maxrun in profile row r={rr}")
        rows[rr] = values
    expected_rows = {rr for rr in range(2, 10) if (p - 1) % rr == 0}
    if set(rows) != expected_rows:
        fail(
            f"{stage}: profile rows differ: "
            f"missing={sorted(expected_rows - set(rows))}, "
            f"extra={sorted(set(rows) - expected_rows)}"
        )

    profile_values = [p]
    for rr in sorted(rows):
        profile_values.extend([rr, *rows[rr], 1])
    profile_digest = fnv1a64_le(profile_values)

    legacy = one_match(r"^CHECKSUM\(maxrun\) (\d+)\s*$", text, stage)
    if int(legacy.group(1)) != profile_digest:
        fail(f"{stage}: legacy/profile checksum mismatch")
    profile_line = parse_kv_line("PROFILE_DIGEST", text, stage)
    if profile_line != {
        "algorithm": "fnv1a64-le64",
        "value": f"{profile_digest:016x}",
    }:
        fail(f"{stage}: invalid PROFILE_DIGEST {profile_line}")

    one_match(r"^TRIPLET x2 : ACCORD 100% \(V2a=B7=CPU, double-run identique\)\s*$", text, stage)
    classification = one_match(
        r"^CLASSIFICATION r=(\d+) k=(\d+) maxrun=(\d+) "
        r"A=(PASS|FAIL) Bstar=(PASS|FAIL) A_AND_B=(PASS|FAIL)\s*$",
        text,
        stage,
    )
    if (int(classification.group(1)), int(classification.group(2))) != (r, k):
        fail(f"{stage}: classification targets the wrong claim")
    maxrun = int(classification.group(3))
    if maxrun != rows[r][0]:
        fail(f"{stage}: classification maxrun differs from the profile")
    if classification.group(4, 5, 6) != ("PASS", "PASS", "PASS"):
        fail(f"{stage}: classification did not pass A and Bstar")

    fields = parse_kv_line("CLAIM_RESULT", text, stage)
    required = {
        "version", "digest_alg", "p", "r", "k", "bound", "maxrun",
        "profile_digest", "applicable", "A", "Bstar", "A_AND_B",
        "triplet", "verdict", "digest",
    }
    if set(fields) != required:
        fail(f"{stage}: CLAIM_RESULT keys differ: {sorted(set(fields) ^ required)}")
    expected_fields = {
        "version": "1",
        "digest_alg": "fnv1a64-le64",
        "p": str(p),
        "r": str(r),
        "k": str(k),
        "bound": str(bound),
        "maxrun": str(maxrun),
        "profile_digest": f"{profile_digest:016x}",
        "applicable": "YES",
        "A": "PASS",
        "Bstar": "PASS",
        "A_AND_B": "PASS",
        "triplet": "ACCORD",
        "verdict": "ACCEPT",
    }
    for key, value in expected_fields.items():
        if fields[key] != value:
            fail(f"{stage}: CLAIM_RESULT {key}={fields[key]!r}, expected {value!r}")
    if not HEX64_RE.fullmatch(fields["digest"]):
        fail(f"{stage}: malformed claim digest")

    claim_digest = fnv1a64_le([
        p, r, k, bound, profile_digest,
        1,  # applicable
        1,  # A
        1,  # Bstar
        1,  # A_AND_B
        1,  # triplet accord
        1,  # final accept
    ])
    if fields["digest"] != f"{claim_digest:016x}":
        fail(f"{stage}: claim digest mismatch")

    return {
        "p": p,
        "r": r,
        "k": k,
        "bound": bound,
        "maxrun": maxrun,
        "profile_digest": f"{profile_digest:016x}",
        "claim_digest": f"{claim_digest:016x}",
        "profiles": {str(rr): values for rr, values in sorted(rows.items())},
        "verdict": "ACCEPT",
    }


def parse_rabung(stdout, exit_code, claim):
    stage = "rabung_criterion -q"
    require_exit_zero(exit_code, stage)
    claim_numbers(claim)
    text = decode_output(stdout)
    require_no_negative(text, stage)
    if text.strip() != "1":
        fail(f"{stage}: stdout must be exactly 1, got {text.strip()!r}")
    return {"criterion": 1, "verdict": "ACCEPT"}


def parse_verify_claim(stdout, exit_code, claim):
    stage = "verify_claim"
    require_exit_zero(exit_code, stage)
    text = decode_output(stdout)
    require_no_negative(text, stage)
    p, r, k, bound = claim_numbers(claim)
    nonempty = [line.strip() for line in text.splitlines() if line.strip()]
    if len(nonempty) != 1:
        fail(f"{stage}: expected one final stdout line, got {len(nonempty)}")
    match = re.fullmatch(
        r"ACCEPT\s+W\((\d+),(\d+)\)\s+>\s+(\d+)\s+"
        r"\[ACCEPT : \(a\) et \(b\) OK\]",
        nonempty[0],
    )
    if not match:
        fail(f"{stage}: malformed or missing final ACCEPT line")
    if (int(match.group(1)), int(match.group(2)), int(match.group(3))) != (r, k, bound):
        fail(f"{stage}: ACCEPT line targets the wrong claim")
    return {"p": p, "r": r, "k": k, "bound": bound, "verdict": "ACCEPT"}


WITNESS_ROW_RE = re.compile(r"^WITNESS p=(\d+) r=(\d+) maxrun=(\d+)\s*$", re.MULTILINE)


def parse_highp_witness(stdout, exit_code, claim, expected_maxrun):
    stage = "highp_witness"
    require_exit_zero(exit_code, stage)
    text = decode_output(stdout)
    require_no_negative(text, stage)
    p, r, k, bound = claim_numbers(claim)
    one_match(r"^\[C1\].*:\s*OK\s*$", text, stage)
    one_match(r"^\[C2\].*:\s*OK(?:\s+\(.*\))?\s*$", text, stage)
    one_match(r"^\[C3\].*:\s*\d+ comparaisons, 0 desaccords -> OK\s*$", text, stage)
    one_match(r"^\[C4\].*:\s*\d+ comparaisons, 0 desaccords -> OK\s*$", text, stage)
    rows = {}
    for match in WITNESS_ROW_RE.finditer(text):
        pp, rr, maxrun = map(int, match.groups())
        if pp != p:
            fail(f"{stage}: witness prime {pp} != expected {p}")
        if rr in rows:
            fail(f"{stage}: duplicate row r={rr}")
        rows[rr] = maxrun
    if not rows or r not in rows:
        fail(f"{stage}: requested row r={r} is absent")
    if rows[r] != int(expected_maxrun):
        fail(f"{stage}: maxrun {rows[r]} != verify1 maxrun {expected_maxrun}")
    values = [p]
    for rr in sorted(rows):
        values.extend([rr, rows[rr]])
    expected_digest = fnv1a64_le(values)
    checksum = one_match(r"^WITNESS_CHECKSUM (\d+)\s*$", text, stage)
    if int(checksum.group(1)) != expected_digest:
        fail(f"{stage}: checksum mismatch")
    one_match(r"^VERDICT_TEMOIN : VALIDE\s*$", text, stage)
    return {
        "p": p,
        "r": r,
        "k": k,
        "bound": bound,
        "maxrun": rows[r],
        "profiles": {str(rr): value for rr, value in sorted(rows.items())},
        "witness_digest": f"{expected_digest:016x}",
        "verdict": "ACCEPT",
    }


def load_claims(path=DEFAULT_CLAIMS):
    with Path(path).open(encoding="utf-8") as handle:
        document = json.load(handle)
    claims = document.get("claims")
    if not isinstance(claims, list) or not claims:
        fail("claims document has no non-empty claims array")
    result = {}
    for claim in claims:
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or not claim_id or claim_id in result:
            fail(f"invalid or duplicate claim id {claim_id!r}")
        claim_numbers(claim)
        result[claim_id] = claim
    return result


def verify_artifact(reference, base_dir):
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256", "bytes"}:
        fail("artifact keys must be exactly path, sha256, bytes")
    if not isinstance(reference["path"], str) or not reference["path"]:
        fail("artifact path must be a non-empty string")
    if not SHA256_RE.fullmatch(str(reference["sha256"])):
        fail("artifact has malformed SHA-256")
    if (
        not isinstance(reference["bytes"], int)
        or isinstance(reference["bytes"], bool)
        or reference["bytes"] < 0
    ):
        fail("artifact byte count must be a non-negative integer")
    base = Path(base_dir).resolve()
    candidate = (base / str(reference["path"])).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        fail(f"artifact escapes manifest directory: {reference['path']}")
    try:
        data = candidate.read_bytes()
    except OSError as exc:
        fail(f"cannot read artifact {reference['path']}: {exc}")
    if len(data) != reference["bytes"]:
        fail(f"artifact byte count mismatch: {reference['path']}")
    if sha256_bytes(data) != reference["sha256"]:
        fail(f"artifact SHA-256 mismatch: {reference['path']}")
    return data


def validate_argv(stage, argv, claim):
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) or not item for item in argv):
        fail(f"{stage}: argv must be a non-empty array of non-empty strings")
    p, r, k, _ = claim_numbers(claim)
    expected = {
        "scan_gpu_verify1": ["--verify1", str(p), str(k), str(r)],
        "rabung_criterion": ["-q", str(p), str(r), str(k)],
        "verify_claim": [str(p), str(r), str(k)],
    }
    if stage in expected:
        suffix = expected[stage]
        if len(argv) != len(suffix) + 1 or argv[1:] != suffix:
            fail(f"{stage}: argv does not identify the expected claim")
    else:
        if len(argv) not in (2, 3) or argv[1] != str(p):
            fail("highp_witness: argv does not identify the expected prime")
        if len(argv) == 3 and (not argv[2].isdigit() or int(argv[2]) <= 0):
            fail("highp_witness: invalid sample count")


def safe_repository_path(root, raw_path, label):
    if not isinstance(raw_path, str) or not raw_path:
        fail(f"{label}: path must be a non-empty string")
    relative = Path(raw_path)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != raw_path:
        fail(f"{label}: path must be canonical and repository-relative")
    root = Path(root).resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        fail(f"{label}: path escapes repository")
    return candidate


def git_bytes(root, *argv):
    process = subprocess.run(
        ["git", "-C", str(root), *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        fail(
            f"git {' '.join(argv)} failed: "
            f"{process.stderr.decode('utf-8', errors='replace')[-500:]}"
        )
    return process.stdout


def verify_build_artifacts(build, repository_root):
    """Re-establish commit ancestry and every declared source/binary hash.

    Source hashes are checked both against the recorded Git commit and the
    release worktree. Binary hashes are checked against preserved repository
    artifacts. This turns the maps into evidence instead of decorative fields.
    """
    root = Path(repository_root).resolve()
    if not (root / ".git").exists():
        fail("repository root is not a Git worktree")
    commit = build["git_commit"]
    git_bytes(root, "cat-file", "-e", f"{commit}^{{commit}}")
    process = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", commit, "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        fail("build commit is not an ancestor of the release worktree HEAD")

    for path, expected in build["sources_sha256"].items():
        candidate = safe_repository_path(root, path, "source hash")
        try:
            current = candidate.read_bytes()
        except OSError as exc:
            fail(f"cannot read declared source {path}: {exc}")
        if sha256_bytes(current) != expected:
            fail(f"current source SHA-256 mismatch: {path}")
        committed = git_bytes(root, "show", f"{commit}:{path}")
        if sha256_bytes(committed) != expected:
            fail(f"build-commit source SHA-256 mismatch: {path}")

    for path, expected in build["binaries_sha256"].items():
        candidate = safe_repository_path(root, path, "binary hash")
        try:
            binary = candidate.read_bytes()
        except OSError as exc:
            fail(f"cannot read declared binary {path}: {exc}")
        if sha256_bytes(binary) != expected:
            fail(f"preserved binary SHA-256 mismatch: {path}")


def validate_manifest(manifest, manifest_dir, expected_claim, repository_root=None):
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "claim", "build", "runs", "final"}:
        fail("manifest top-level keys differ from the v1 contract")
    if manifest["schema"] != SCHEMA_ID:
        fail(f"unsupported manifest schema {manifest['schema']!r}")

    if not isinstance(manifest["claim"], dict) or manifest["claim"] != expected_claim:
        fail("manifest claim differs from audit/claims.json")
    claim_numbers(manifest["claim"])

    build = manifest["build"]
    required_build = {
        "git_commit", "git_clean", "sources_sha256", "binaries_sha256",
        "compile_commands", "compiler_versions",
    }
    if not isinstance(build, dict) or set(build) != required_build or build["git_clean"] is not True:
        fail("build metadata is incomplete or the worktree was not clean")
    if not re.fullmatch(r"[0-9a-f]{40}", str(build["git_commit"])):
        fail("build git_commit must be a full lowercase SHA-1")
    for collection in (build["sources_sha256"], build["binaries_sha256"]):
        if not isinstance(collection, dict) or not collection:
            fail("source and binary hash maps must be non-empty")
        if any(not isinstance(key, str) or not key for key in collection):
            fail("source and binary hash names must be non-empty strings")
        if any(not SHA256_RE.fullmatch(str(value)) for value in collection.values()):
            fail("malformed source or binary SHA-256")
    if not isinstance(build["compile_commands"], dict) or not build["compile_commands"]:
        fail("compile commands are missing")
    if any(
        not isinstance(key, str)
        or not key
        or not isinstance(command, list)
        or not command
        or any(not isinstance(item, str) or not item for item in command)
        for key, command in build["compile_commands"].items()
    ):
        fail("compile commands must be non-empty argv arrays")
    if not isinstance(build["compiler_versions"], dict) or not build["compiler_versions"]:
        fail("compiler versions are missing")
    if any(
        not isinstance(key, str)
        or not key
        or not isinstance(version, str)
        or not version
        for key, version in build["compiler_versions"].items()
    ):
        fail("compiler versions must be non-empty strings")
    if set(build["compile_commands"]) != set(build["binaries_sha256"]):
        fail("compile-command keys must equal declared binary paths")
    if repository_root is not None:
        verify_build_artifacts(build, repository_root)

    runs = manifest["runs"]
    if not isinstance(runs, list):
        fail("runs must be an array")
    parsed_by_stage = {}
    verify_maxrun = None
    attempts_by_stage = {}
    artifact_paths = set()
    for run in runs:
        required_run = {"stage", "attempt", "argv", "exit_code", "stdout", "stderr", "parsed"}
        if not isinstance(run, dict) or set(run) != required_run:
            fail("run keys differ from the v1 contract")
        stage = run["stage"]
        if stage not in {"scan_gpu_verify1", "rabung_criterion", "verify_claim", "highp_witness"}:
            fail(f"unknown run stage {stage!r}")
        if not isinstance(run["attempt"], int) or isinstance(run["attempt"], bool) or run["attempt"] < 1:
            fail(f"{stage}: attempt must be a positive integer")
        if not isinstance(run["exit_code"], int) or isinstance(run["exit_code"], bool):
            fail(f"{stage}: exit_code must be an integer")
        if not isinstance(run["parsed"], dict):
            fail(f"{stage}: parsed result must be an object")
        if run["attempt"] in attempts_by_stage.setdefault(stage, set()):
            fail(f"{stage}: duplicate attempt {run['attempt']}")
        attempts_by_stage[stage].add(run["attempt"])
        validate_argv(stage, run["argv"], expected_claim)
        for stream in ("stdout", "stderr"):
            artifact_path = run[stream].get("path") if isinstance(run[stream], dict) else None
            if artifact_path in artifact_paths:
                fail(f"raw artifact reused by multiple runs: {artifact_path!r}")
            artifact_paths.add(artifact_path)
        stdout = verify_artifact(run["stdout"], manifest_dir)
        stderr = verify_artifact(run["stderr"], manifest_dir)
        require_no_negative(decode_output(stderr), f"{stage} stderr")
        if stage == "scan_gpu_verify1":
            parsed = parse_verify1(stdout, run["exit_code"], expected_claim)
            verify_maxrun = parsed["maxrun"] if verify_maxrun is None else verify_maxrun
            if parsed["maxrun"] != verify_maxrun:
                fail("external verify1 repeats disagree on maxrun")
        elif stage == "rabung_criterion":
            parsed = parse_rabung(stdout, run["exit_code"], expected_claim)
        elif stage == "verify_claim":
            parsed = parse_verify_claim(stdout, run["exit_code"], expected_claim)
        else:
            if verify_maxrun is None:
                fail("highp witness must follow at least one verify1 run")
            parsed = parse_highp_witness(stdout, run["exit_code"], expected_claim, verify_maxrun)
        if run["parsed"] != parsed:
            fail(f"stored parsed result differs from raw output for {stage}")
        parsed_by_stage.setdefault(stage, []).append(parsed)

    minimums = {"scan_gpu_verify1": 2, "rabung_criterion": 2, "verify_claim": 1}
    for stage, minimum in minimums.items():
        if len(parsed_by_stage.get(stage, [])) < minimum:
            fail(f"manifest has fewer than {minimum} {stage} runs")
    for stage, attempts in attempts_by_stage.items():
        if attempts != set(range(1, len(attempts) + 1)):
            fail(f"{stage}: attempts must be contiguous from 1")
    profiles = [entry["profiles"] for entry in parsed_by_stage["scan_gpu_verify1"]]
    if any(profile != profiles[0] for profile in profiles[1:]):
        fail("external verify1 repeats have different profiles")
    if expected_claim.get("requires_montgomery_free_witness") and not parsed_by_stage.get("highp_witness"):
        fail("claim requires a Montgomery-free witness")
    witnesses = [entry["profiles"] for entry in parsed_by_stage.get("highp_witness", [])]
    if any(profile != witnesses[0] for profile in witnesses[1:]):
        fail("external Montgomery-free witnesses have different profiles")

    if manifest["final"] != {"verdict": "ACCEPT", "fail_closed": True}:
        fail("manifest final verdict is not fail-closed ACCEPT")
    claim_digests = [entry["claim_digest"] for entry in parsed_by_stage["scan_gpu_verify1"]]
    if any(digest != claim_digests[0] for digest in claim_digests[1:]):
        fail("external verify1 repeats have different claim digests")
    verify1_count = len(parsed_by_stage["scan_gpu_verify1"])
    witness_count = len(parsed_by_stage.get("highp_witness", []))
    return {
        "claim_id": expected_claim["id"],
        "claim": f"W({expected_claim['colors']},{expected_claim['length']}) > {expected_claim['lower_bound']}",
        "provenance": (
            f"{expected_claim['origin']} — {expected_claim.get('priority_credit', '')}"
            if expected_claim.get("priority_credit")
            else expected_claim["origin"]
        ),
        "priority_credit": expected_claim.get("priority_credit", ""),
        "v2a": f"PASS ({verify1_count} outputs x 2 repeats)",
        "b7": f"PASS ({verify1_count} outputs x 2 repeats)",
        "cpu_walk": f"PASS ({verify1_count} outputs x 2 repeats)",
        "cpu_criterion": f"PASS ({len(parsed_by_stage['rabung_criterion'])} outputs)",
        "verify_claim": f"PASS ({len(parsed_by_stage['verify_claim'])} outputs)",
        "no_montgomery_witness": (
            f"PASS ({witness_count} outputs)" if witness_count else "not required"
        ),
        "claim_digest": claim_digests[0],
        "profile_digest": parsed_by_stage["scan_gpu_verify1"][0]["profile_digest"],
        "verdict": "ACCEPT",
    }


def load_and_validate_manifest(path, claims, repository_root=None):
    path = Path(path)
    data = path.read_bytes()
    manifest = json.loads(data)
    if not isinstance(manifest, dict):
        fail("manifest JSON must be an object")
    claim_id = manifest.get("claim", {}).get("id")
    if claim_id not in claims:
        fail(f"manifest has unknown claim id {claim_id!r}")
    result = validate_manifest(
        manifest, path.parent, claims[claim_id], repository_root=repository_root
    )
    result["manifest_sha256"] = sha256_bytes(data)
    return result


TABLE_FIELDS = (
    ("Claim", "claim"),
    ("Provenance", "provenance"),
    ("V2a", "v2a"),
    ("B7", "b7"),
    ("CPU walk", "cpu_walk"),
    ("CPU criterion", "cpu_criterion"),
    ("verify_claim", "verify_claim"),
    ("No-Montgomery witness", "no_montgomery_witness"),
    ("Manifest / digest", "manifest_and_digest"),
)


def build_set_document(results, claims):
    found = [result.get("claim_id") for result in results]
    if len(found) != len(set(found)):
        fail("duplicate claim manifests")
    if set(found) != set(claims):
        fail(
            f"manifest set differs: missing={sorted(set(claims) - set(found))}, "
            f"extra={sorted(set(found) - set(claims))}"
        )
    by_id = {result["claim_id"]: result for result in results}
    rows = []
    for claim_id in claims:
        result = dict(by_id[claim_id])
        if result.get("verdict") != "ACCEPT":
            fail(f"claim {claim_id}: non-ACCEPT validated result")
        result["manifest_and_digest"] = (
            f"sha256:{result['manifest_sha256']}; claim:{result['claim_digest']}"
        )
        rows.append(result)
    return {
        "schema": "vdw-claim-audit-table/v1",
        "verdict": "ACCEPT",
        "claim_count": len(rows),
        "claims": rows,
    }


def markdown_escape(value):
    return str(value).replace("|", r"\|").replace("\n", " ")


def render_markdown(document):
    headers = [header for header, _ in TABLE_FIELDS]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in document["claims"]:
        lines.append(
            "| " + " | ".join(markdown_escape(row[key]) for _, key in TABLE_FIELDS) + " |"
        )
    return "\n".join(lines) + "\n"


def tex_escape(value):
    text = str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in text).replace("\n", " ")


def render_tex(document):
    columns = "l" * len(TABLE_FIELDS)
    header = " & ".join(tex_escape(name) for name, _ in TABLE_FIELDS) + r" \\"
    lines = [r"\begin{tabular}{" + columns + "}", header, r"\hline"]
    for row in document["claims"]:
        lines.append(" & ".join(tex_escape(row[key]) for _, key in TABLE_FIELDS) + r" \\")
    lines.append(r"\end{tabular}")
    return "\n".join(lines) + "\n"


def write_set_outputs(document, output_json=None, output_md=None, output_tex=None):
    outputs = []
    payloads = (
        (output_json, json.dumps(document, sort_keys=True, indent=2) + "\n"),
        (output_md, render_markdown(document)),
        (output_tex, render_tex(document)),
    )
    for path, payload in payloads:
        if path is None:
            continue
        path = Path(path)
        path.write_text(payload, encoding="utf-8")
        outputs.append(str(path))
    return outputs


def command_parse(args, claims):
    claim = claims.get(args.claim_id)
    if claim is None:
        fail(f"unknown claim id {args.claim_id!r}")
    data = Path(args.stdout).read_bytes()
    if args.stage == "verify1":
        parsed = parse_verify1(data, args.exit_code, claim)
    elif args.stage == "rabung":
        parsed = parse_rabung(data, args.exit_code, claim)
    elif args.stage == "verify_claim":
        parsed = parse_verify_claim(data, args.exit_code, claim)
    else:
        if args.maxrun is None:
            fail("--maxrun is required for a witness output")
        parsed = parse_highp_witness(data, args.exit_code, claim, args.maxrun)
    print(json.dumps(parsed, sort_keys=True, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claims", type=Path, default=DEFAULT_CLAIMS)
    sub = parser.add_subparsers(dest="command", required=True)

    parse_cmd = sub.add_parser("parse", help="parse one preserved stdout fail-closed")
    parse_cmd.add_argument("--stage", choices=("verify1", "rabung", "verify_claim", "witness"), required=True)
    parse_cmd.add_argument("--claim-id", required=True)
    parse_cmd.add_argument("--stdout", type=Path, required=True)
    parse_cmd.add_argument("--exit-code", type=int, required=True)
    parse_cmd.add_argument("--maxrun", type=int)

    manifest_cmd = sub.add_parser("validate-manifest", help="validate one manifest and its raw files")
    manifest_cmd.add_argument("manifest", type=Path)
    manifest_cmd.add_argument(
        "--repository-root", type=Path,
        help="also re-hash source blobs at the recorded Git commit and preserved binaries",
    )

    set_cmd = sub.add_parser("validate-set", help="require exactly one valid manifest per canonical claim")
    set_cmd.add_argument("directory", type=Path)
    set_cmd.add_argument("--output-json", type=Path)
    set_cmd.add_argument("--output-md", type=Path)
    set_cmd.add_argument("--output-tex", type=Path)
    set_cmd.add_argument(
        "--repository-root", type=Path,
        help="also re-hash source blobs at each recorded Git commit and preserved binaries",
    )

    args = parser.parse_args(argv)
    try:
        claims = load_claims(args.claims)
        if args.command == "parse":
            command_parse(args, claims)
        elif args.command == "validate-manifest":
            print(json.dumps(load_and_validate_manifest(
                args.manifest, claims, repository_root=args.repository_root
            ), sort_keys=True))
        else:
            paths = sorted(args.directory.glob("*/manifest.json"))
            results = [
                load_and_validate_manifest(
                    path, claims, repository_root=args.repository_root
                )
                for path in paths
            ]
            document = build_set_document(results, claims)
            outputs = write_set_outputs(
                document, args.output_json, args.output_md, args.output_tex
            )
            print(json.dumps({
                "verdict": "ACCEPT",
                "claim_count": document["claim_count"],
                "claims": [row["claim_id"] for row in document["claims"]],
                "outputs": outputs,
            }, indent=2))
        return 0
    except (ClaimAuditError, OSError, json.JSONDecodeError) as exc:
        print(f"CLAIM_AUDIT_REJECT: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
