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
import math
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


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
PROGRAMS = ("scan_gpu", "rabung_criterion", "verify_claim", "highp_witness")
REQUIRED_SOURCE_PATHS = (
    "audit/claim-manifest-v1.schema.json",
    "audit/claims.json",
    "scripts/capture_claim_evidence.py",
    "src/scan_gpu.cu",
    "tools/claim_audit.py",
    "tools/highp_witness.c",
    "tools/rabung_criterion.cpp",
    "tools/verify_claim.cpp",
)
STAGE_TO_PROGRAM = {
    "scan_gpu_verify1": "scan_gpu",
    "rabung_criterion": "rabung_criterion",
    "verify_claim": "verify_claim",
    "highp_witness": "highp_witness",
}
COMPILER_NAMES = ("nvcc", "g++", "gcc")
WITNESS_SAMPLES = 20000
CANONICAL_SET_OUTPUTS = {
    "json": "validated-claims.json",
    "markdown": "validated-claims.md",
    "tex": "validated-claims.tex",
}


class ClaimAuditError(ValueError):
    """An evidence item failed a fail-closed validation rule."""


def fail(message: str) -> None:
    raise ClaimAuditError(message)


def _no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value):
    fail(f"non-finite JSON constant {value!r}")


def _strict_json_float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        fail(f"non-finite JSON number {value!r}")
    return parsed


def strict_json_loads(data, *, label="JSON"):
    if isinstance(data, bytes):
        if data.startswith(b"\xef\xbb\xbf"):
            fail(f"{label}: UTF-8 BOM is forbidden")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            fail(f"{label}: invalid UTF-8: {exc}")
    elif isinstance(data, str):
        text = data
        if text.startswith("\ufeff"):
            fail(f"{label}: UTF-8 BOM is forbidden")
    else:
        fail(f"{label}: expected bytes or text")
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicate_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_strict_json_float,
        )
    except json.JSONDecodeError as exc:
        fail(f"{label}: malformed JSON: {exc}")


def load_strict_json(path, *, label="JSON"):
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        fail(f"{label}: cannot read {path}: {exc}")
    return strict_json_loads(data, label=label)


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
    document = load_strict_json(path, label="claims document")
    if not isinstance(document, dict) or set(document) != {
        "claims", "notation", "schema_version"
    }:
        fail("claims document keys differ from the canonical contract")
    if document["schema_version"] != 1 or document["notation"] != (
        "W(colors,length) > lower_bound"
    ):
        fail("claims document schema metadata is not canonical")
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


def verify_artifact(reference, base_dir, *, expected_path=None):
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256", "bytes"}:
        fail("artifact keys must be exactly path, sha256, bytes")
    canonical_repository_path(reference["path"], "artifact")
    if expected_path is not None and reference["path"] != expected_path:
        fail(
            f"artifact path {reference['path']!r} != canonical {expected_path!r}"
        )
    if not SHA256_RE.fullmatch(str(reference["sha256"])):
        fail("artifact has malformed SHA-256")
    if (
        not isinstance(reference["bytes"], int)
        or isinstance(reference["bytes"], bool)
        or reference["bytes"] < 0
    ):
        fail("artifact byte count must be a non-negative integer")
    base = Path(base_dir).resolve(strict=True)
    raw_candidate = base / reference["path"]
    current = base
    for part in PurePosixPath(reference["path"]).parts:
        current = current / part
        if current.is_symlink():
            fail(f"artifact traverses symbolic link: {reference['path']}")
    if not raw_candidate.is_file():
        fail(f"artifact is missing or not a regular file: {reference['path']}")
    candidate = raw_candidate.resolve(strict=True)
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


def preserved_binary_paths(commit):
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("cannot derive preserved binary paths from malformed Git commit")
    return {
        program: f"results/claims/_build/{commit}/{program}"
        for program in PROGRAMS
    }


def exact_compile_commands(build_rel):
    canonical_repository_path(build_rel, "compile output directory")
    return {
        "scan_gpu": [
            "nvcc", "-O3", "-std=c++17", "-lineinfo", "-Xptxas=-v",
            "-gencode", "arch=compute_120,code=sm_120",
            "-gencode", "arch=compute_120,code=compute_120",
            "src/scan_gpu.cu", "-o", f"{build_rel}/scan_gpu",
        ],
        "rabung_criterion": [
            "g++", "-O2", "-std=c++17", "tools/rabung_criterion.cpp",
            "-o", f"{build_rel}/rabung_criterion",
        ],
        "verify_claim": [
            "g++", "-O2", "-std=c++17", "tools/verify_claim.cpp",
            "-o", f"{build_rel}/verify_claim",
        ],
        "highp_witness": [
            "gcc", "-O2", "-std=c17", "-Wall", "-Wextra", "-Werror",
            "tools/highp_witness.c", "-o", f"{build_rel}/highp_witness",
        ],
    }


def canonical_repository_path(raw_path, label):
    if not isinstance(raw_path, str) or not raw_path:
        fail(f"{label}: path must be a non-empty string")
    relative = PurePosixPath(raw_path)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or "." in relative.parts
        or relative.as_posix() != raw_path
    ):
        fail(f"{label}: path must be canonical and repository-relative")
    return raw_path


def expected_run_sequence(claim):
    sequence = [
        ("scan_gpu_verify1", 1),
        ("scan_gpu_verify1", 2),
        ("rabung_criterion", 1),
        ("rabung_criterion", 2),
        ("verify_claim", 1),
    ]
    if claim.get("requires_montgomery_free_witness"):
        sequence.append(("highp_witness", 1))
    return sequence


def frozen_argv_suffix(stage, claim):
    p, r, k, _ = claim_numbers(claim)
    return {
        "scan_gpu_verify1": ["--verify1", str(p), str(k), str(r)],
        "rabung_criterion": ["-q", str(p), str(r), str(k)],
        "verify_claim": [str(p), str(r), str(k)],
        "highp_witness": [str(p), str(WITNESS_SAMPLES)],
    }[stage]


def validate_argv(stage, argv, claim, binary_path):
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) or not item for item in argv):
        fail(f"{stage}: argv must be a non-empty array of non-empty strings")
    expected = [binary_path, *frozen_argv_suffix(stage, claim)]
    if argv != expected:
        fail(f"{stage}: argv must be exactly {expected}")


def safe_repository_path(root, raw_path, label):
    canonical_repository_path(raw_path, label)
    relative = PurePosixPath(raw_path)
    root = Path(root).resolve(strict=True)
    raw_candidate = root / Path(*relative.parts)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            fail(f"{label}: path traverses symbolic link")
    candidate = raw_candidate.resolve()
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
        if (
            not candidate.is_file()
            or candidate.is_symlink()
            or not os.access(candidate, os.X_OK)
        ):
            fail(f"declared binary is missing, symlinked, or non-executable: {path}")
        try:
            binary = candidate.read_bytes()
        except OSError as exc:
            fail(f"cannot read declared binary {path}: {exc}")
        if sha256_bytes(binary) != expected:
            fail(f"preserved binary SHA-256 mismatch: {path}")


def validate_compiler_versions(versions):
    if not isinstance(versions, dict) or set(versions) != set(COMPILER_NAMES):
        fail(f"compiler versions must describe exactly {list(COMPILER_NAMES)}")
    for name in COMPILER_NAMES:
        encoded = versions[name]
        if not isinstance(encoded, str) or not encoded:
            fail(f"compiler identity is missing: {name}")
        identity = strict_json_loads(encoded, label=f"compiler identity {name}")
        expected_keys = {"command", "resolved_path", "sha256", "version"}
        if not isinstance(identity, dict) or set(identity) != expected_keys:
            fail(f"compiler identity keys differ: {name}")
        if identity["command"] != name:
            fail(f"compiler identity command differs: {name}")
        if (
            not isinstance(identity["resolved_path"], str)
            or not identity["resolved_path"]
            or not Path(identity["resolved_path"]).is_absolute()
        ):
            fail(f"compiler resolved path is not absolute: {name}")
        if not isinstance(identity["sha256"], str) or not SHA256_RE.fullmatch(
            identity["sha256"]
        ):
            fail(f"compiler SHA-256 is malformed: {name}")
        if not isinstance(identity["version"], str) or not identity["version"]:
            fail(f"compiler version is missing: {name}")


def validate_compile_commands(commands, binary_paths):
    expected_keys = set(binary_paths.values())
    if not isinstance(commands, dict) or set(commands) != expected_keys:
        fail("compile-command keys must equal the exact preserved binary set")
    for program, binary_path in binary_paths.items():
        command = commands[binary_path]
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(token, str) or not token for token in command)
        ):
            fail(f"compile command is malformed: {program}")
        if len(command) < 3 or command[-2] != "-o":
            fail(f"compile command has no canonical output: {program}")
        output_path = canonical_repository_path(
            command[-1], f"compile output {program}"
        )
        output = PurePosixPath(output_path)
        if (
            len(output.parts) < 2
            or output.parts[0] != "build"
            or output.name != program
        ):
            fail(f"compile output is not canonical build evidence: {program}")
        build_rel = output.parent.as_posix()
        expected_command = exact_compile_commands(build_rel)[program]
        if command != expected_command:
            fail(f"compile command differs from the frozen argv: {program}")


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
    if not isinstance(build["sources_sha256"], dict) or set(
        build["sources_sha256"]
    ) != set(REQUIRED_SOURCE_PATHS):
        fail("source hash map must contain exactly the frozen protocol sources")
    binary_paths = preserved_binary_paths(build["git_commit"])
    if not isinstance(build["binaries_sha256"], dict) or set(
        build["binaries_sha256"]
    ) != set(binary_paths.values()):
        fail("binary hash map must contain exactly the four preserved binaries")
    for collection in (build["sources_sha256"], build["binaries_sha256"]):
        if any(not SHA256_RE.fullmatch(str(value)) for value in collection.values()):
            fail("malformed source or binary SHA-256")
    validate_compile_commands(build["compile_commands"], binary_paths)
    validate_compiler_versions(build["compiler_versions"])
    if repository_root is not None:
        verify_build_artifacts(build, repository_root)

    runs = manifest["runs"]
    if not isinstance(runs, list):
        fail("runs must be an array")
    parsed_by_stage = {}
    verify_maxrun = None
    attempts_by_stage = {}
    artifact_paths = set()
    expected_sequence = expected_run_sequence(expected_claim)
    if len(runs) != len(expected_sequence):
        fail(
            f"manifest must contain exactly {len(expected_sequence)} canonical runs"
        )
    for ordinal, run in enumerate(runs, start=1):
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
        if (stage, run["attempt"]) != expected_sequence[ordinal - 1]:
            fail(
                f"run {ordinal}: expected {expected_sequence[ordinal - 1]}, "
                f"got {(stage, run['attempt'])}"
            )
        program = STAGE_TO_PROGRAM[stage]
        validate_argv(
            stage, run["argv"], expected_claim, binary_paths[program]
        )
        for stream in ("stdout", "stderr"):
            artifact_path = run[stream].get("path") if isinstance(run[stream], dict) else None
            if artifact_path in artifact_paths:
                fail(f"raw artifact reused by multiple runs: {artifact_path!r}")
            artifact_paths.add(artifact_path)
        stem = f"run-{ordinal:02d}-{stage}-attempt-{run['attempt']}"
        stdout = verify_artifact(
            run["stdout"], manifest_dir, expected_path=f"{stem}.stdout"
        )
        stderr = verify_artifact(
            run["stderr"], manifest_dir, expected_path=f"{stem}.stderr"
        )
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

    exact_counts = {"scan_gpu_verify1": 2, "rabung_criterion": 2, "verify_claim": 1}
    if expected_claim.get("requires_montgomery_free_witness"):
        exact_counts["highp_witness"] = 1
    for stage, count in exact_counts.items():
        if len(parsed_by_stage.get(stage, [])) != count:
            fail(f"manifest must contain exactly {count} {stage} runs")
    if not expected_claim.get("requires_montgomery_free_witness") and parsed_by_stage.get(
        "highp_witness"
    ):
        fail("manifest contains an unrequired Montgomery-free witness")
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
    if path.is_symlink() or not path.is_file():
        fail(f"manifest is missing, symlinked, or not a regular file: {path}")
    data = path.read_bytes()
    manifest = strict_json_loads(data, label=f"claim manifest {path}")
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


CLAIM_ID_RE = re.compile(r"w(?P<colors>[0-9]+)_k(?P<length>[0-9]+)_p(?P<prime>[0-9]+)")
CLAIM_TEXT_RE = re.compile(
    r"W\((?P<colors>[0-9]+),(?P<length>[0-9]+)\) > (?P<bound>[0-9]+)"
)


def tex_group_integer(value):
    digits = str(value)
    if not re.fullmatch(r"[0-9]+", digits):
        fail(f"cannot render non-integer value in claim table: {value!r}")
    groups = []
    while digits:
        groups.append(digits[-3:])
        digits = digits[:-3]
    return r"\,".join(reversed(groups))


def tex_breakable_digest(value):
    digest = str(value)
    if not re.fullmatch(r"[0-9a-f]+", digest):
        fail(f"cannot render malformed digest in claim table: {value!r}")
    chunks = [digest[offset : offset + 8] for offset in range(0, len(digest), 8)]
    return r"\texttt{" + r"\allowbreak{}".join(chunks) + "}"


def tex_claim_certificate(row):
    claim_id = str(row.get("claim_id", ""))
    claim = str(row.get("claim", ""))
    identity = CLAIM_ID_RE.fullmatch(claim_id)
    inequality = CLAIM_TEXT_RE.fullmatch(claim)
    if identity is None or inequality is None:
        fail(f"cannot render malformed claim identity {claim_id!r} / {claim!r}")
    for field in ("colors", "length"):
        if identity.group(field) != inequality.group(field):
            fail(f"claim id and inequality disagree on {field}: {claim_id!r}")
    return (
        r"\(\begin{aligned}"
        f"W({identity.group('colors')},{identity.group('length')})&>"
        f"{tex_group_integer(inequality.group('bound'))}"
        r"\\ p&="
        f"{tex_group_integer(identity.group('prime'))}"
        r"\end{aligned}\)"
    )


def tex_provenance(row):
    origin = str(row.get("provenance", "")).split(" — ", 1)[0]
    labels = {
        "this_scan": "this scan",
        "monroe_phase2_archive": "Monroe phase-2 archive; verification here",
        "monroe_phase2_archive_and_this_scan": (
            "Monroe phase-2 archive; rediscovery and verification here"
        ),
    }
    return tex_escape(labels.get(origin, origin))


def tex_compact_status(value, *, internal_repeats=False):
    text = str(value)
    if text == "not required":
        return r"\emph{not required}"
    match = re.fullmatch(
        r"PASS \(([0-9]+) outputs(?: x ([0-9]+) repeats)?\)", text
    )
    if match is None:
        fail(f"cannot render malformed status in claim table: {value!r}")
    outputs, repeats = match.groups()
    if internal_repeats:
        if repeats is None:
            fail(f"status lacks internal repeat count: {value!r}")
        return (
            rf"\textbf{{PASS}}: {outputs} captures $\times$ {repeats} "
            r"internal repeats"
        )
    if repeats is not None:
        fail(f"unexpected internal repeat count: {value!r}")
    return rf"\textbf{{PASS}} ({outputs})"


def render_tex(document):
    lines = [
        r"\begingroup",
        r"\footnotesize",
        r"\setlength{\tabcolsep}{3pt}",
        r"\renewcommand{\arraystretch}{1.12}",
        r"\begin{longtable}{@{}P{0.23\linewidth}P{0.18\linewidth}P{0.26\linewidth}P{0.27\linewidth}@{}}",
        (
            r"\caption{Canonical fail-closed audit view of the thirteen accepted "
            r"direct claims. The GPU column records the two captured structured "
            r"checks; the separate-source column records the separate CPU criterion, "
            r"stand-alone verifier, and Montgomery-free witness when required. "
            r"Each claim is followed by its full claim, profile, and manifest "
            r"identities. The JSON and Markdown views retain the full commands, "
            r"artifacts, and provenance.}\label{tab:validated-claims}\\"
        ),
        r"\toprule",
        r"Claim and certificate & Provenance & GPU triplet & Separate-source checks \\",
        r"\midrule",
        r"\endfirsthead",
        r"\multicolumn{4}{@{}l}{\footnotesize Table~\thetable\ continued}\\",
        r"\toprule",
        r"Claim and certificate & Provenance & GPU triplet & Separate-source checks \\",
        r"\midrule",
        r"\endhead",
        r"\midrule",
        r"\multicolumn{4}{r@{}}{\footnotesize Continued on next page}\\",
        r"\endfoot",
        r"\bottomrule",
        r"\endlastfoot",
    ]
    for row in document["claims"]:
        gpu_statuses = {row["v2a"], row["b7"], row["cpu_walk"]}
        if len(gpu_statuses) != 1:
            fail(f"claim {row['claim_id']}: GPU triplet statuses disagree")
        gpu = (
            r"\texttt{V2a}, \texttt{B7}, and CPU walk\newline "
            + tex_compact_status(row["v2a"], internal_repeats=True)
        )
        independent = r"\newline ".join(
            (
                r"criterion: " + tex_compact_status(row["cpu_criterion"]),
                r"stand-alone verifier: " + tex_compact_status(row["verify_claim"]),
                r"Montgomery-free: "
                + tex_compact_status(row["no_montgomery_witness"]),
            )
        )
        identity = r"\quad ".join(
            (
                r"claim " + tex_breakable_digest(row["claim_digest"]),
                r"profile " + tex_breakable_digest(row["profile_digest"]),
            )
        ) + (
            r"\newline manifest SHA-256 "
            + tex_breakable_digest(row["manifest_sha256"])
        )
        lines.append(f"% claim-id: {row['claim_id']}")
        lines.append(
            " & ".join(
                (
                    tex_claim_certificate(row),
                    tex_provenance(row),
                    gpu,
                    independent,
                )
            )
            + r" \\"
        )
        lines.append(
            r"\multicolumn{4}{@{}P{0.93\linewidth}@{}}{\scriptsize "
            r"\textit{Evidence identity:} "
            + identity
            + r"} \\"
        )
        lines.append(r"\addlinespace[4pt]")
    lines.extend((r"\end{longtable}", r"\endgroup"))
    return "\n".join(lines) + "\n"


def set_output_payloads(document):
    return {
        "json": json.dumps(
            document, sort_keys=True, indent=2, allow_nan=False
        ) + "\n",
        "markdown": render_markdown(document),
        "tex": render_tex(document),
    }


def write_set_outputs(document, output_json=None, output_md=None, output_tex=None):
    outputs = []
    rendered = set_output_payloads(document)
    payloads = (
        (output_json, rendered["json"]),
        (output_md, rendered["markdown"]),
        (output_tex, rendered["tex"]),
    )
    for path, payload in payloads:
        if path is None:
            continue
        path = Path(path)
        temporary = path.with_name(path.name + ".tmp")
        if temporary.exists() or temporary.is_symlink():
            fail(f"set-output temporary path already exists: {temporary}")
        try:
            temporary.write_text(payload, encoding="utf-8")
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
        outputs.append(str(path))
    return outputs


def canonical_set_output_paths(directory):
    directory = Path(directory)
    return {
        kind: directory / filename
        for kind, filename in CANONICAL_SET_OUTPUTS.items()
    }


def write_canonical_set_outputs(document, directory):
    paths = canonical_set_output_paths(directory)
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        fail("canonical validated-claim outputs already exist")
    outputs = write_set_outputs(
        document,
        paths["json"],
        paths["markdown"],
        paths["tex"],
    )
    verify_canonical_set_outputs(document, directory)
    return outputs


def verify_canonical_set_outputs(document, directory):
    paths = canonical_set_output_paths(directory)
    payloads = set_output_payloads(document)
    for kind, path in paths.items():
        if path.is_symlink() or not path.is_file():
            fail(f"canonical {kind} claim table is missing or symlinked: {path}")
        try:
            data = path.read_bytes()
        except OSError as exc:
            fail(f"cannot read canonical {kind} claim table: {exc}")
        expected = payloads[kind].encode("utf-8")
        if data != expected:
            fail(f"canonical {kind} claim table differs byte-for-byte")
    return [str(paths[kind]) for kind in ("json", "markdown", "tex")]


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
            canonical_outputs = verify_canonical_set_outputs(
                document, args.directory
            )
            outputs = write_set_outputs(
                document, args.output_json, args.output_md, args.output_tex
            )
            print(json.dumps({
                "verdict": "ACCEPT",
                "claim_count": document["claim_count"],
                "claims": [row["claim_id"] for row in document["claims"]],
                "canonical_outputs": canonical_outputs,
                "outputs": outputs,
            }, indent=2))
        return 0
    except (ClaimAuditError, OSError, json.JSONDecodeError) as exc:
        print(f"CLAIM_AUDIT_REJECT: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
