#!/usr/bin/env python3
"""Validate the fail-closed publication contract for this repository.

The checker deliberately distinguishes two classes of findings:

* an ``error`` means that the repository contradicts its own contract (for
  example, a forbidden path is exported, a target hash is wrong, or a gate is
  marked ``passed`` while its evidence is invalid);
* a ``blocker`` is an explicitly unfinished publication requirement.

Thus ``staging`` and ``report`` accept an honest, incomplete repository, while
``release`` accepts only a structurally valid repository with no blocker.
No expensive calculation is launched by this program.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
STATUS_SCHEMA = "vdw-publication-status/v1"
SCOPE_SCHEMA = "vdw-export-scope/v1"
REPORT_SCHEMA = "vdw-publication-contract-report/v1"
ALLOWED_GATE_STATUSES = {
    "open",
    "blocked_pc",
    "blocked_external",
    "blocked_human_decision",
    "passed",
}
REQUIRED_GATES = (
    "source-export",
    "cpu-ci-clean-tag",
    "bibliography-primary-source-audit",
    "paper-clean-build",
    "claim-manifests-13",
    "campaign-archive-515",
    "ordered-prime-identity-515",
    "cuda-release-qualification",
    "outbound-rights",
    "doi-tag-archive-freeze",
)
EXPECTED_EXTERNAL_CLAIM_ORDER = (
    "w2_k25_p1138900957",
    "w3_k17_p1961601427",
    "w2_k27_p3459826103",
    "w2_k28_p3476732783",
)
EXPECTED_EXTERNAL_CLAIMS = set(EXPECTED_EXTERNAL_CLAIM_ORDER)
EXTERNAL_REQUIRED_FIELDS = (
    "claim_id",
    "candidate_git_commit",
    "verifier_path",
    "verifier_sha256",
    "command_argv",
    "environment",
    "stdout_path",
    "stdout_sha256",
    "stderr_path",
    "stderr_sha256",
    "exit_code",
    "verdict",
    "operator_id",
    "operator_attestation",
)
OPERATOR_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}\Z")
CAMPAIGN_LOWER_INCLUSIVE = 970_000_000
CAMPAIGN_UPPER_EXCLUSIVE = 2_000_000_000
CAMPAIGN_CHUNK_WIDTH = 2_000_000
CAMPAIGN_CHUNK_COUNT = 515
CAMPAIGN_PRIME_COUNT = 48_823_489
CAMPAIGN_SCHEMA = "vdw-campaign-archive/v1"
PRIME_IDENTITY_SCHEMA = "vdw-prime-identity/v2"
CUDA_EVIDENCE_SCHEMA = "vdw-cuda-qualification/v1"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
CHUNK7_GIT_COMMIT = "ebd54ea0fbdf78287392e9be80b2578618964975"
CHUNK7_DRIVER_DECODED_SHA256 = "2d7c27d86ec1e07f98bf4bbe59575b46f438cbcb7b4a1f35ad0bc725f973af37"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER_RE = re.compile(r"@@[A-Z][A-Z0-9_]*@@")
SKIP_UNTRACKED_PARTS = {".git", ".pytest_cache", "__pycache__", "build", "dist"}
SOURCE_IMPORT_CLASSIFICATIONS = {"imported", "derived", "new"}
BIB_ENTRY_RE = re.compile(
    r"(?m)^\s*@(?!comment\b|string\b|preamble\b)[A-Za-z]+\s*\{\s*([^,\s{}]+)\s*,",
    re.IGNORECASE,
)
CITATION_RE = re.compile(
    r"\\cite(?:alp|alt|author|p|t|year|yearpar)?\*?\s*"
    r"(?:\[[^\]]*\]\s*){0,2}\{([^{}]+)\}",
)


class ContractDataError(ValueError):
    """A contract document could not be parsed safely."""


class Findings:
    """Accumulate deterministic, de-duplicated contract findings."""

    def __init__(self) -> None:
        self.errors: list[dict[str, str]] = []
        self.blockers: list[dict[str, str]] = []
        self._seen: set[tuple[str, str, str]] = set()

    def add(self, severity: str, code: str, message: str) -> None:
        key = (severity, code, message)
        if key in self._seen:
            return
        self._seen.add(key)
        item = {"code": code, "message": message}
        if severity == "error":
            self.errors.append(item)
        elif severity == "blocker":
            self.blockers.append(item)
        else:  # pragma: no cover - internal programming error
            raise AssertionError(f"unknown finding severity {severity!r}")

    def error(self, code: str, message: str) -> None:
        self.add("error", code, message)

    def blocker(self, code: str, message: str) -> None:
        self.add("blocker", code, message)


def _no_duplicate_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ContractDataError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_constant(value):
    raise ContractDataError(f"non-finite JSON constant {value}")


def _bounded_integer(value):
    number = int(value)
    if not -(1 << 63) <= number < (1 << 64):
        raise ContractDataError("JSON integer outside the signed/unsigned 64-bit domain")
    return number


def _reject_unsafe_json(value, location="$" ) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ContractDataError(f"Unicode surrogate at {location}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_unsafe_json(item, f"{location}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_unsafe_json(key, f"{location}.<key>")
            _reject_unsafe_json(item, f"{location}.{key}")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ContractDataError(f"non-finite number at {location}")


def load_json(path: Path):
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ContractDataError("UTF-8 BOM is forbidden")
    value = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=_no_duplicate_pairs,
        parse_constant=_reject_constant,
        parse_int=_bounded_integer,
    )
    _reject_unsafe_json(value)
    return value


def canonical_repo_path(value, *, directory=False) -> str:
    if not isinstance(value, str) or not value:
        raise ContractDataError("repository path must be a non-empty string")
    if "\\" in value or "\x00" in value:
        raise ContractDataError(f"non-canonical repository path {value!r}")
    bare = value[:-1] if directory and value.endswith("/") else value
    path = PurePosixPath(bare)
    if (
        not bare
        or path.is_absolute()
        or path.as_posix() != bare
        or any(part in {"", ".", ".."} for part in path.parts)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise ContractDataError(f"non-canonical repository path {value!r}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def exported_paths(root: Path) -> list[str]:
    """Return every materialized path subject to an export decision.

    The positive allowlist protects preparation work before it is staged as
    well as the eventual Git tree.  Administration, cache, and build
    directories are the only directory-level exclusions shared with the
    source-import generator.
    """
    paths: list[str] = []
    for directory, names, files in os.walk(root, followlinks=False):
        relative_directory = Path(directory).relative_to(root)
        names[:] = sorted(name for name in names if name not in SKIP_UNTRACKED_PARTS)
        for name in sorted(files):
            relative = relative_directory / name
            if any(part in SKIP_UNTRACKED_PARTS for part in relative.parts):
                continue
            paths.append(relative.as_posix())
    return sorted(paths)


def _fold_path(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def scope_violation(path: str, scope: dict) -> str | None:
    folded = _fold_path(path)
    for forbidden in scope.get("forbidden_exact_paths", []):
        if folded == _fold_path(forbidden):
            return f"matches forbidden exact path {forbidden!r}"
    for prefix in scope.get("forbidden_prefixes", []):
        if folded.startswith(_fold_path(prefix)):
            return f"is below forbidden prefix {prefix!r}"
    for fragment in scope.get("forbidden_name_fragments", []):
        if _fold_path(fragment) in folded:
            return f"contains forbidden name fragment {fragment!r}"
    return None


def validate_scope(root: Path, scope, findings: Findings) -> None:
    if not isinstance(scope, dict):
        findings.error("scope.type", "publication/scope.json must contain an object")
        return
    if scope.get("schema") != SCOPE_SCHEMA:
        findings.error("scope.schema", f"expected scope schema {SCOPE_SCHEMA!r}")
    if scope.get("source_policy") != "explicit_allowlist":
        findings.error("scope.policy", "source_policy must be explicit_allowlist")

    expected_fields = {
        "allowed_paths",
        "excluded_topics",
        "forbidden_exact_paths",
        "forbidden_name_fragments",
        "forbidden_prefixes",
        "included_scientific_scope",
        "schema",
        "source_policy",
    }
    if set(scope) != expected_fields:
        findings.error(
            "scope.shape",
            f"publication/scope.json must contain exactly {sorted(expected_fields)}",
        )

    for key, directory in (
        ("allowed_paths", False),
        ("forbidden_prefixes", True),
        ("forbidden_exact_paths", False),
        ("forbidden_name_fragments", False),
        ("excluded_topics", False),
    ):
        values = scope.get(key)
        if not isinstance(values, list) or not values or not all(isinstance(item, str) and item for item in values):
            findings.error("scope.field", f"{key} must be a non-empty string array")
            continue
        if len(values) != len(set(values)):
            findings.error("scope.duplicate", f"{key} contains a duplicate")
        if key != "excluded_topics" and values != sorted(values):
            findings.error("scope.order", f"{key} must be in canonical order")
        if key in {"allowed_paths", "forbidden_prefixes", "forbidden_exact_paths"}:
            for value in values:
                try:
                    canonical_repo_path(value, directory=directory)
                except ContractDataError as exc:
                    findings.error("scope.path", str(exc))

    if any(key not in scope for key in ("allowed_paths", "forbidden_prefixes", "forbidden_exact_paths", "forbidden_name_fragments")):
        return
    present = exported_paths(root)
    allowed = scope["allowed_paths"]
    missing_decisions = sorted(set(present) - set(allowed))
    stale_decisions = sorted(set(allowed) - set(present))
    if missing_decisions or stale_decisions:
        findings.error(
            "scope.allowlist_mismatch",
            f"explicit allowlist differs: unapproved={missing_decisions}, stale={stale_decisions}",
        )
    for path in present:
        reason = scope_violation(path, scope)
        if reason:
            findings.error("scope.forbidden_path", f"{path}: {reason}")
        candidate = root / path
        if candidate.is_symlink():
            findings.error("scope.symlink", f"exported symlink is not allowed: {path}")


def _require_object(value, code: str, message: str, findings: Findings) -> bool:
    if not isinstance(value, dict):
        findings.error(code, message)
        return False
    return True


def validate_status(status, findings: Findings) -> dict[str, dict]:
    gates: dict[str, dict] = {}
    if not _require_object(status, "status.type", "STATUS.json must contain an object", findings):
        return gates
    if status.get("schema") != STATUS_SCHEMA:
        findings.error("status.schema", f"expected status schema {STATUS_SCHEMA!r}")
    source = status.get("source")
    if not isinstance(source, dict):
        findings.error("status.source", "STATUS.json source must be an object")
    else:
        if not isinstance(source.get("repository"), str) or not source.get("repository"):
            findings.error("status.source", "source.repository must be non-empty")
        if not SHA1_RE.fullmatch(str(source.get("commit", ""))):
            findings.error("status.source", "source.commit must be a 40-character lowercase Git SHA-1")
        if source.get("export_policy") != "explicit_allowlist":
            findings.error("status.source", "source.export_policy must be explicit_allowlist")

    allowed = status.get("allowed_gate_statuses")
    if not isinstance(allowed, list) or set(allowed) != ALLOWED_GATE_STATUSES or len(allowed) != len(ALLOWED_GATE_STATUSES):
        findings.error("status.allowed_statuses", "allowed_gate_statuses must list the complete supported set exactly once")

    rows = status.get("release_gates")
    if not isinstance(rows, list):
        findings.error("status.gates", "release_gates must be an array")
        return gates
    for row in rows:
        if not isinstance(row, dict):
            findings.error("status.gate_type", "every release gate must be an object")
            continue
        gate_id = row.get("id")
        if not isinstance(gate_id, str) or not gate_id:
            findings.error("status.gate_id", "every release gate needs a non-empty id")
            continue
        if gate_id in gates:
            findings.error("status.gate_duplicate", f"duplicate release gate {gate_id!r}")
            continue
        gates[gate_id] = row
        if row.get("status") not in ALLOWED_GATE_STATUSES:
            findings.error("status.gate_status", f"{gate_id}: unsupported status {row.get('status')!r}")
        evidence = row.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            findings.error("status.gate_evidence", f"{gate_id}: evidence must be a non-empty array")
        else:
            for path in evidence:
                try:
                    canonical_repo_path(path)
                except ContractDataError as exc:
                    findings.error("status.gate_evidence", f"{gate_id}: {exc}")
        if not isinstance(row.get("note"), str) or not row.get("note"):
            findings.error("status.gate_note", f"{gate_id}: note must be non-empty")

    missing = sorted(set(REQUIRED_GATES) - set(gates))
    extra = sorted(set(gates) - set(REQUIRED_GATES))
    if missing:
        findings.error("status.gates_missing", f"missing required release gates: {', '.join(missing)}")
    if extra:
        findings.error("status.gates_extra", f"unknown release gates: {', '.join(extra)}")

    if set(gates) == set(REQUIRED_GATES):
        all_passed = all(gates[gate]["status"] == "passed" for gate in REQUIRED_GATES)
        if all_passed and status.get("citable_release") is not True:
            findings.error("status.release_flag", "all gates passed but citable_release is not true")
        if not all_passed and status.get("citable_release") is not False:
            findings.error("status.release_flag", "citable_release must remain false while any gate is unfinished")

    for gate_id in REQUIRED_GATES:
        row = gates.get(gate_id)
        if row and row.get("status") != "passed":
            expected = []
            if isinstance(row.get("expected_count"), int):
                expected.append(f"expected_count={row['expected_count']}")
            if isinstance(row.get("expected_chunk_count"), int):
                expected.append(f"expected_chunk_count={row['expected_chunk_count']}")
            suffix = f" ({', '.join(expected)})" if expected else ""
            findings.blocker(
                f"gate.{gate_id}",
                f"{gate_id}: {row.get('status')}{suffix}; {row.get('note', '')}",
            )
    return gates


def _gate_result(findings: Findings, gates: dict[str, dict], gate_id: str, code: str, message: str) -> None:
    gate = gates.get(gate_id, {})
    if gate.get("status") == "passed":
        findings.error(code, f"{gate_id} is marked passed, but {message}")
    else:
        findings.blocker(code, message)


def _source_import_identity(record, *, context: str, findings: Findings):
    """Validate one exact path/blob/SHA/size identity and return it."""
    expected = {"path", "git_blob_sha1", "sha256", "size"}
    if not isinstance(record, dict) or set(record) != expected:
        findings.error(
            "source_import.identity_shape",
            f"{context} must contain exactly {sorted(expected)}",
        )
        return None
    try:
        path = canonical_repo_path(record["path"])
    except ContractDataError as exc:
        findings.error("source_import.path", f"{context}: {exc}")
        return None
    valid = True
    if not isinstance(record["git_blob_sha1"], str) or not SHA1_RE.fullmatch(record["git_blob_sha1"]):
        findings.error("source_import.blob", f"{context}.git_blob_sha1 is malformed")
        valid = False
    if not isinstance(record["sha256"], str) or not SHA256_RE.fullmatch(record["sha256"]):
        findings.error("source_import.sha256", f"{context}.sha256 is malformed")
        valid = False
    if isinstance(record["size"], bool) or not isinstance(record["size"], int) or record["size"] < 0:
        findings.error("source_import.size", f"{context}.size must be a non-negative integer")
        valid = False
    if not valid:
        return None
    return {
        "path": path,
        "git_blob_sha1": record["git_blob_sha1"],
        "sha256": record["sha256"],
        "size": record["size"],
    }


def _source_import_disk_paths(root: Path, findings: Findings) -> set[str]:
    """Reproduce the generator's complete regular-file inventory policy."""
    present: set[str] = set()
    excluded = {"MANIFEST.sha256", "publication/source-import.json"}
    for current_raw, directories, filenames in os.walk(root, followlinks=False):
        current = Path(current_raw)
        kept = []
        for name in sorted(directories):
            candidate = current / name
            if name in SKIP_UNTRACKED_PARTS:
                continue
            if candidate.is_symlink():
                relative = candidate.relative_to(root).as_posix()
                findings.error("source_import.symlink", f"symbolic link is not inventory-safe: {relative}")
                continue
            kept.append(name)
        directories[:] = kept
        for name in sorted(filenames):
            candidate = current / name
            relative = candidate.relative_to(root).as_posix()
            if relative in excluded:
                continue
            if candidate.is_symlink() or not candidate.is_file():
                findings.error("source_import.non_regular", f"non-regular repository entry: {relative}")
                continue
            try:
                present.add(canonical_repo_path(relative))
            except ContractDataError as exc:
                findings.error("source_import.path", str(exc))
    return present


def validate_source_import(root: Path, status: dict, scope: dict, findings: Findings) -> None:
    path = root / "publication" / "source-import.json"
    if not path.is_file():
        findings.blocker(
            "source_import.missing",
            "publication/source-import.json has not yet frozen the final target hashes",
        )
        return
    try:
        document = load_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ContractDataError) as exc:
        findings.error("source_import.parse", f"publication/source-import.json: {exc}")
        return
    expected_top = {
        "files",
        "inventory",
        "omitted_source_files",
        "schema",
        "source",
        "summary",
    }
    if not isinstance(document, dict):
        findings.error("source_import.type", "publication/source-import.json must contain an object")
        return
    if set(document) != expected_top:
        findings.error(
            "source_import.shape",
            f"source import must contain exactly {sorted(expected_top)}",
        )
    if document.get("schema") != "vdw-source-import/v1":
        findings.error("source_import.schema", "source import schema must be vdw-source-import/v1")
    repository_source = document.get("source")
    expected_source = status.get("source", {}) if isinstance(status, dict) else {}
    if not isinstance(repository_source, dict) or set(repository_source) != {"repository", "commit"}:
        findings.error("source_import.source", "source import must identify its source repository and commit")
    else:
        for key in ("repository", "commit"):
            if repository_source.get(key) != expected_source.get(key):
                findings.error(
                    "source_import.source",
                    f"source.{key}={repository_source.get(key)!r} does not match STATUS.json",
                )

    expected_inventory = {
        "excluded_directory_names": [
            ".git",
            ".pytest_cache",
            "__pycache__",
            "build",
            "dist",
        ],
        "excluded_paths": ["MANIFEST.sha256", "publication/source-import.json"],
    }
    if document.get("inventory") != expected_inventory:
        findings.error("source_import.inventory", "source import inventory policy differs from the generator policy")

    rows = document.get("files")
    if not isinstance(rows, list) or not rows:
        findings.error("source_import.entries", "source import files must be a non-empty array")
        return
    seen: set[str] = set()
    counts = {classification: 0 for classification in SOURCE_IMPORT_CLASSIFICATIONS}
    previous = None
    for index, row in enumerate(rows):
        label = f"source import files[{index}]"
        if not isinstance(row, dict):
            findings.error("source_import.entry", f"{label} must be an object")
            continue
        classification = row.get("classification")
        if classification not in SOURCE_IMPORT_CLASSIFICATIONS:
            findings.error("source_import.classification", f"{label}.classification is invalid")
            continue
        expected_fields = {"classification", "git_blob_sha1", "path", "sha256", "size"}
        if classification != "new":
            expected_fields.add("source")
        if classification != "imported":
            expected_fields.add("rationale")
        if set(row) != expected_fields:
            findings.error(
                "source_import.entry_shape",
                f"{label} ({classification}) must contain exactly {sorted(expected_fields)}",
            )
        if classification != "imported" and (
            not isinstance(row.get("rationale"), str) or not row["rationale"].strip()
        ):
            findings.error(
                "source_import.rationale",
                f"{label}.rationale must be a non-empty string",
            )
        target_identity = _source_import_identity(
            {key: row.get(key) for key in ("path", "git_blob_sha1", "sha256", "size")},
            context=label,
            findings=findings,
        )
        if target_identity is None:
            continue
        target = target_identity["path"]
        if target in seen:
            findings.error("source_import.duplicate", f"duplicate target path {target!r}")
            continue
        seen.add(target)
        if previous is not None and target <= previous:
            findings.error("source_import.order", "source import files are not in canonical path order")
        previous = target
        counts[classification] += 1
        if isinstance(scope, dict):
            reason = scope_violation(target, scope)
            if reason:
                findings.error("source_import.forbidden", f"{target}: {reason}")

        candidate = root / target
        if not candidate.is_file() or candidate.is_symlink():
            findings.error("source_import.target_missing", f"target is missing or not a regular file: {target}")
            continue
        actual_sha = sha256_file(candidate)
        actual_blob = git_blob_sha1(candidate)
        actual_size = candidate.stat().st_size
        if target_identity["sha256"] != actual_sha:
            findings.error(
                "source_import.hash_mismatch",
                f"{target}: target SHA-256 {actual_sha} != recorded {target_identity['sha256']}",
            )
        if target_identity["git_blob_sha1"] != actual_blob:
            findings.error(
                "source_import.target_blob_mismatch",
                f"{target}: target Git blob {actual_blob} != recorded {target_identity['git_blob_sha1']}",
            )
        if target_identity["size"] != actual_size:
            findings.error(
                "source_import.size_mismatch",
                f"{target}: target size {actual_size} != recorded {target_identity['size']!r}",
            )

        if classification in {"imported", "derived"}:
            source_identity = _source_import_identity(
                row.get("source"), context=f"{label}.source", findings=findings
            )
            if source_identity is None:
                continue
            if source_identity["path"] != target:
                findings.error(
                    "source_import.source_path",
                    f"{target}: nested source path differs from target path",
                )
            equality = {
                key: target_identity[key] == source_identity[key]
                for key in ("git_blob_sha1", "sha256", "size")
            }
            if classification == "imported" and not all(equality.values()):
                findings.error(
                    "source_import.imported_mismatch",
                    f"{target}: imported target does not retain the source blob/SHA/size",
                )
            if classification == "derived" and all(equality.values()):
                findings.error(
                    "source_import.derived_unchanged",
                    f"{target}: derived target is byte-identical to its source",
                )
            if 2 <= sum(equality.values()) < 3:
                findings.error(
                    "source_import.identity_inconsistent",
                    f"{target}: source/target byte identities are internally inconsistent: {equality}",
                )

    omitted = document.get("omitted_source_files")
    omitted_seen: set[str] = set()
    if not isinstance(omitted, list):
        findings.error("source_import.omitted", "omitted_source_files must be an array")
        omitted = []
    previous = None
    for index, row in enumerate(omitted):
        identity = _source_import_identity(
            row,
            context=f"source import omitted_source_files[{index}]",
            findings=findings,
        )
        if identity is None:
            continue
        source_path = identity["path"]
        if source_path in seen or source_path in omitted_seen:
            findings.error("source_import.duplicate", f"duplicate present/omitted source path {source_path!r}")
        omitted_seen.add(source_path)
        if previous is not None and source_path <= previous:
            findings.error("source_import.order", "omitted source files are not in canonical path order")
        previous = source_path
        if (root / source_path).exists():
            findings.error("source_import.omitted_present", f"omitted source path is present: {source_path}")

    expected_summary = {
        **counts,
        "omitted_source": len(omitted),
        "total_present": len(rows),
    }
    if document.get("summary") != expected_summary:
        findings.error("source_import.summary", "source import summary does not match its records")

    disk_paths = _source_import_disk_paths(root, findings)
    if seen != disk_paths:
        findings.error(
            "source_import.coverage",
            f"source import coverage differs: missing={sorted(disk_paths - seen)}, stale={sorted(seen - disk_paths)}",
        )

    # In this repository, the generator can additionally bind every nested
    # source identity to the authoritative bootstrap rather than trusting the
    # generated manifest alone.
    builder = root / "tools" / "build_source_import.py"
    bootstrap = root / "publication" / "source-import-bootstrap.json"
    if builder.is_file() and bootstrap.is_file():
        process = subprocess.run(
            [
                sys.executable,
                str(builder),
                "--bootstrap",
                str(bootstrap),
                "--manifest",
                str(path),
                "--check",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if process.returncode != 0:
            detail = (process.stdout or process.stderr).strip().splitlines()
            findings.error(
                "source_import.authoritative",
                detail[-1] if detail else "build_source_import.py rejected the manifest",
            )


def _load_optional_json(path: Path, findings: Findings, code: str):
    if not path.is_file():
        return None
    try:
        return load_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ContractDataError) as exc:
        findings.error(code, f"{path}: {exc}")
        return None


def validate_claim_evidence(root: Path, gates: dict[str, dict], findings: Findings) -> None:
    gate_id = "claim-manifests-13"
    expected = 13
    claims = _load_optional_json(root / "audit" / "claims.json", findings, "claims.parse")
    canonical_ids: set[str] = set()
    if isinstance(claims, dict) and isinstance(claims.get("claims"), list):
        canonical_ids = {
            row.get("id") for row in claims["claims"]
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        }
    if len(canonical_ids) != expected:
        _gate_result(findings, gates, gate_id, "claims.canonical_count", f"audit/claims.json does not contain {expected} unique claim IDs")

    manifests = sorted((root / "results" / "claims").glob("*/manifest.json"))
    if len(manifests) != expected:
        _gate_result(findings, gates, gate_id, "claims.manifest_count", f"claim evidence contains {len(manifests)}/{expected} manifests")
        return
    if gates.get(gate_id, {}).get("status") != "passed":
        return
    total_runs = 0
    found_ids: set[str] = set()
    for manifest_path in manifests:
        manifest = _load_optional_json(manifest_path, findings, "claims.manifest_parse")
        if not isinstance(manifest, dict):
            continue
        claim_id = manifest.get("claim", {}).get("id") if isinstance(manifest.get("claim"), dict) else None
        if isinstance(claim_id, str):
            found_ids.add(claim_id)
        runs = manifest.get("runs")
        if isinstance(runs, list):
            total_runs += len(runs)
    if found_ids != canonical_ids:
        findings.error("claims.id_set", f"claim manifest ID set differs: missing={sorted(canonical_ids - found_ids)}, extra={sorted(found_ids - canonical_ids)}")
    minimum = gates[gate_id].get("minimum_recorded_runs", 67)
    if total_runs < minimum:
        findings.error("claims.run_count", f"only {total_runs} recorded runs; at least {minimum} required")
    command = [
        sys.executable,
        str(root / "tools" / "claim_audit.py"),
        "--claims",
        str(root / "audit" / "claims.json"),
        "validate-set",
        str(root / "results" / "claims"),
        "--repository-root",
        str(root),
    ]
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip().splitlines()
        findings.error("claims.audit_reject", detail[-1] if detail else "claim_audit.py rejected the set")


def _is_integer(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _evidence_problem(findings: Findings, gates: dict[str, dict], gate_id: str):
    """Return a gate-aware evidence reporter.

    An unfinished gate turns a well-formed-but-incomplete evidence envelope into
    a blocker.  The same defect is an error as soon as the gate claims to have
    passed.  JSON parse failures remain structural errors in
    ``_load_optional_json``.
    """

    def report(code: str, message: str) -> None:
        _gate_result(findings, gates, gate_id, code, message)

    return report


def _require_exact_keys(value, expected: set[str], *, context: str, code: str, problem) -> bool:
    if not isinstance(value, dict):
        problem(code, f"{context} must be an object with exactly {sorted(expected)}")
        return False
    if set(value) != expected:
        problem(
            code,
            f"{context} keys differ: missing={sorted(expected - set(value))}, "
            f"extra={sorted(set(value) - expected)}",
        )
        return False
    return True


def _artifact_identity(
    root: Path,
    record,
    *,
    context: str,
    code_prefix: str,
    problem,
    required_prefix: str | None = None,
):
    """Validate and rehash one exact repository artifact identity."""
    if not _require_exact_keys(
        record,
        {"path", "sha256", "size"},
        context=context,
        code=f"{code_prefix}.shape",
        problem=problem,
    ):
        return None
    try:
        relative = canonical_repo_path(record["path"])
    except ContractDataError as exc:
        problem(f"{code_prefix}.path", f"{context}: {exc}")
        return None
    if required_prefix is not None and not relative.startswith(required_prefix):
        problem(
            f"{code_prefix}.path",
            f"{context}.path must be below {required_prefix!r}: {relative!r}",
        )
    digest = record["sha256"]
    size = record["size"]
    valid_metadata = True
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        problem(f"{code_prefix}.sha256", f"{context}.sha256 is malformed")
        valid_metadata = False
    if not _is_integer(size) or size < 0:
        problem(f"{code_prefix}.size", f"{context}.size must be a non-negative integer")
        valid_metadata = False
    candidate = root / relative
    symlink_component = next(
        (
            (root / Path(*PurePosixPath(relative).parts[:index])).relative_to(root).as_posix()
            for index in range(1, len(PurePosixPath(relative).parts) + 1)
            if (root / Path(*PurePosixPath(relative).parts[:index])).is_symlink()
        ),
        None,
    )
    if symlink_component is not None:
        problem(f"{code_prefix}.symlink", f"{context} traverses symbolic link: {symlink_component}")
        return None
    if not candidate.is_file():
        problem(f"{code_prefix}.missing", f"{context} is missing or not a regular file: {relative}")
        return None
    try:
        resolved = candidate.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        problem(f"{code_prefix}.missing", f"cannot resolve {relative}: {exc}")
        return None
    if resolved != resolved_root and resolved_root not in resolved.parents:
        problem(f"{code_prefix}.escape", f"{context} resolves outside repository: {relative}")
        return None
    actual_size = candidate.stat().st_size
    actual_sha256 = sha256_file(candidate)
    if valid_metadata and size != actual_size:
        problem(
            f"{code_prefix}.size_mismatch",
            f"{relative}: size {actual_size} != recorded {size}",
        )
    if valid_metadata and digest != actual_sha256:
        problem(
            f"{code_prefix}.hash_mismatch",
            f"{relative}: SHA-256 {actual_sha256} != recorded {digest}",
        )
    if not valid_metadata:
        return None
    return {"path": relative, "sha256": digest, "size": size, "candidate": candidate}


def _expected_interval() -> dict[str, int]:
    return {
        "lower_inclusive": CAMPAIGN_LOWER_INCLUSIVE,
        "upper_exclusive": CAMPAIGN_UPPER_EXCLUSIVE,
        "chunk_width": CAMPAIGN_CHUNK_WIDTH,
    }


def _expected_chunk(chunk_id: int) -> tuple[int, int]:
    lower = CAMPAIGN_LOWER_INCLUSIVE + (chunk_id - 1) * CAMPAIGN_CHUNK_WIDTH
    return lower, min(lower + CAMPAIGN_CHUNK_WIDTH, CAMPAIGN_UPPER_EXCLUSIVE)


def validate_campaign_evidence(root: Path, gates: dict[str, dict], findings: Findings):
    """Validate the deterministic checkpoint-and-journal recovery product."""
    gate_id = "campaign-archive-515"
    problem = _evidence_problem(findings, gates, gate_id)
    manifest_path = root / "results" / "campaign" / "campaign_manifest.json"
    manifest = _load_optional_json(manifest_path, findings, "campaign.parse")
    if not isinstance(manifest, dict):
        problem("campaign.manifest_missing", "results/campaign/campaign_manifest.json is missing")
        return None
    expected_top = {
        "checkpoint",
        "chunk_7_checkpoint_evidence",
        "chunks",
        "interval",
        "journal",
        "recovery",
        "revisions",
        "schema",
        "source_map",
        "totals",
    }
    if not _require_exact_keys(
        manifest, expected_top, context="campaign manifest", code="campaign.shape", problem=problem
    ):
        return manifest
    if manifest["schema"] != CAMPAIGN_SCHEMA:
        problem("campaign.schema", f"campaign schema must be {CAMPAIGN_SCHEMA}")

    expected_interval = {
        "chunk_count": CAMPAIGN_CHUNK_COUNT,
        "chunk_width": CAMPAIGN_CHUNK_WIDTH,
        "lower_inclusive": CAMPAIGN_LOWER_INCLUSIVE,
        "upper_exclusive": CAMPAIGN_UPPER_EXCLUSIVE,
    }
    if manifest["interval"] != expected_interval:
        problem("campaign.interval", f"campaign interval must be exactly {expected_interval}")

    checkpoint = _artifact_identity(
        root,
        manifest["checkpoint"],
        context="campaign checkpoint",
        code_prefix="campaign.checkpoint_artifact",
        problem=problem,
        required_prefix="results/campaign/raw/",
    )
    journal = _artifact_identity(
        root,
        manifest["journal"],
        context="campaign journal",
        code_prefix="campaign.journal_artifact",
        problem=problem,
        required_prefix="results/campaign/raw/",
    )
    source_map = _artifact_identity(
        root,
        manifest["source_map"],
        context="campaign source map",
        code_prefix="campaign.source_map_artifact",
        problem=problem,
    )
    if source_map is not None and source_map["path"] != "provenance/scanners/campaign-source-map.json":
        problem("campaign.source_map_path", "campaign source map path is not canonical")

    recovery = manifest["recovery"]
    if _require_exact_keys(
        recovery,
        {"import_receipt", "inventory_commitment", "selection"},
        context="campaign recovery",
        code="campaign.recovery_shape",
        problem=problem,
    ):
        selection = _artifact_identity(
            root,
            recovery["selection"],
            context="campaign recovery selection",
            code_prefix="campaign.selection_artifact",
            problem=problem,
        )
        receipt = _artifact_identity(
            root,
            recovery["import_receipt"],
            context="campaign import receipt",
            code_prefix="campaign.receipt_artifact",
            problem=problem,
        )
        if selection is not None and selection["path"] != "results/campaign/recovery-selection.json":
            problem("campaign.selection_path", "campaign selection path is not canonical")
        if receipt is not None and receipt["path"] != "results/campaign/import-receipt.json":
            problem("campaign.receipt_path", "campaign import receipt path is not canonical")
        commitment = recovery["inventory_commitment"]
        commitment_keys = {
            "candidate_files_sha256",
            "inventory_files_sha256",
            "metadata_sha256",
            "source_git_commit",
            "source_git_tree",
        }
        if not _require_exact_keys(
            commitment,
            commitment_keys,
            context="campaign PC inventory commitment",
            code="campaign.inventory_commitment_shape",
            problem=problem,
        ):
            pass
        else:
            for key in ("candidate_files_sha256", "inventory_files_sha256", "metadata_sha256"):
                if not isinstance(commitment[key], str) or not SHA256_RE.fullmatch(commitment[key]):
                    problem("campaign.inventory_commitment", f"campaign {key} is malformed")
            for key in ("source_git_commit", "source_git_tree"):
                if not isinstance(commitment[key], str) or not SHA1_RE.fullmatch(commitment[key]):
                    problem("campaign.inventory_commitment", f"campaign {key} is malformed")

    revisions = manifest["revisions"]
    if not isinstance(revisions, list) or len(revisions) != 8:
        problem("campaign.revisions", "campaign manifest must bind exactly eight revisions")
        revisions = revisions if isinstance(revisions, list) else []
    cursor = 1
    for index, row in enumerate(revisions):
        expected_keys = {"driver", "first_chunk", "git_commit", "last_chunk", "scanner"}
        if not _require_exact_keys(
            row,
            expected_keys,
            context=f"campaign revision[{index}]",
            code="campaign.revision_shape",
            problem=problem,
        ):
            continue
        if (
            row["first_chunk"] != cursor
            or not _is_integer(row["last_chunk"])
            or not SHA1_RE.fullmatch(str(row["git_commit"]))
        ):
            problem("campaign.revision", f"campaign revision[{index}] is malformed or non-contiguous")
            continue
        cursor = row["last_chunk"] + 1
    if cursor != CAMPAIGN_CHUNK_COUNT + 1:
        problem("campaign.revision_coverage", "campaign revisions do not cover chunks 1..515")

    chunks = manifest["chunks"]
    if not isinstance(chunks, list) or len(chunks) != CAMPAIGN_CHUNK_COUNT:
        count = len(chunks) if isinstance(chunks, list) else 0
        problem("campaign.chunk_count", f"campaign manifest contains {count}/515 chunk rows")
        chunks = chunks if isinstance(chunks, list) else []
    seen_ids = set()
    for index, row in enumerate(chunks):
        if not isinstance(row, dict):
            problem("campaign.chunk_shape", f"campaign chunk[{index}] is not an object")
            continue
        chunk_id = row.get("chunk_id")
        if not _is_integer(chunk_id) or not 1 <= chunk_id <= CAMPAIGN_CHUNK_COUNT:
            problem("campaign.chunk_id", f"campaign chunk[{index}] has invalid chunk_id")
            continue
        if chunk_id in seen_ids:
            problem("campaign.chunk_duplicate", f"duplicate campaign chunk_id {chunk_id}")
        seen_ids.add(chunk_id)
        lower, upper = _expected_chunk(chunk_id)
        if (
            row.get("lower_inclusive") != lower
            or row.get("upper_exclusive") != upper
            or index + 1 != chunk_id
        ):
            problem("campaign.chunk_range", f"campaign chunk {chunk_id} range/order is not canonical")
        expected_class = "checkpoint_only_missing_journal" if chunk_id == 7 else "checkpoint_and_journal"
        if row.get("evidence_class") != expected_class:
            problem("campaign.chunk_evidence", f"campaign chunk {chunk_id} has wrong evidence class")
    expected_ids = set(range(1, CAMPAIGN_CHUNK_COUNT + 1))
    if seen_ids != expected_ids:
        problem(
            "campaign.chunk_ids",
            f"campaign IDs differ: missing={sorted(expected_ids - seen_ids)}, extra={sorted(seen_ids - expected_ids)}",
        )

    chunk7 = manifest["chunk_7_checkpoint_evidence"]
    expected_chunk7_keys = {
        "checkpoint_artifact",
        "checkpoint_json_key",
        "checkpoint_record_sha256",
        "chunk_id",
        "driver",
        "journal_artifact",
        "journal_match_count",
        "lower_inclusive",
        "resolution",
        "revision_commit",
        "upper_exclusive",
    }
    if _require_exact_keys(
        chunk7,
        expected_chunk7_keys,
        context="chunk-7 checkpoint evidence",
        code="campaign.chunk7_shape",
        problem=problem,
    ):
        driver = chunk7["driver"]
        expected_driver_keys = {"bytes", "git_blob_sha1", "name", "sha256"}
        if not _require_exact_keys(
            driver,
            expected_driver_keys,
            context="chunk-7 driver",
            code="campaign.chunk7_driver_shape",
            problem=problem,
        ):
            driver = {}
        if (
            chunk7["chunk_id"] != 7
            or chunk7["lower_inclusive"] != 982_000_000
            or chunk7["upper_exclusive"] != 984_000_000
            or chunk7["checkpoint_json_key"] != "982000000-984000000"
            or chunk7["journal_match_count"] != 0
            or chunk7["resolution"] != "checkpoint_recovers_missing_journal"
            or chunk7["revision_commit"] != CHUNK7_GIT_COMMIT
            or driver.get("name") != "campaign_ebd54ea"
            or driver.get("sha256") != CHUNK7_DRIVER_DECODED_SHA256
            or not SHA256_RE.fullmatch(str(chunk7["checkpoint_record_sha256"]))
            or chunk7["checkpoint_artifact"] != manifest["checkpoint"]
            or chunk7["journal_artifact"] != manifest["journal"]
        ):
            problem(
                "campaign.chunk7",
                "chunk 7 is not bound to its exact checkpoint row, absent journal row, ebd54ea revision, and driver",
            )

        driver_path = root / "provenance/scanners/historical/campaign_ebd54ea.py.base64"
        if not driver_path.is_file() or driver_path.is_symlink():
            problem("campaign.chunk7_driver_missing", "historical ebd54ea driver is missing")
        else:
            try:
                decoded = base64.b64decode(b"".join(driver_path.read_bytes().split()), validate=True)
            except (OSError, ValueError) as exc:
                problem("campaign.chunk7_driver_decode", f"cannot decode ebd54ea driver: {exc}")
            else:
                if hashlib.sha256(decoded).hexdigest() != CHUNK7_DRIVER_DECODED_SHA256:
                    problem("campaign.chunk7_driver_hash", "decoded ebd54ea driver hash differs")
                source_text = decoded.decode("utf-8", errors="replace")
                save_position = source_text.find("save_ckpt(ckpath,ck)")
                journal_position = source_text.find('L(f"chunk {ci}/{nchunks}')
                if save_position < 0 or journal_position < 0 or save_position >= journal_position:
                    problem("campaign.chunk7_driver_order", "ebd54ea driver does not save checkpoint before journal")

    totals = manifest["totals"]
    expected_total_keys = {
        "checkpoint_and_journal_chunks",
        "checkpoint_only_missing_journal_chunks",
        "chunk_count",
        "imported_bytes",
        "imported_file_count",
    }
    if _require_exact_keys(
        totals,
        expected_total_keys,
        context="campaign totals",
        code="campaign.totals_shape",
        problem=problem,
    ) and (
        totals["chunk_count"] != CAMPAIGN_CHUNK_COUNT
        or totals["checkpoint_and_journal_chunks"] != CAMPAIGN_CHUNK_COUNT - 1
        or totals["checkpoint_only_missing_journal_chunks"] != 1
        or not _is_integer(totals["imported_file_count"])
        or totals["imported_file_count"] < 2
        or not _is_integer(totals["imported_bytes"])
        or totals["imported_bytes"] <= 0
    ):
        problem("campaign.totals", "campaign totals are incoherent")

    recovery_tool = root / "tools" / "campaign_recovery.py"
    if not recovery_tool.is_file() or recovery_tool.is_symlink():
        problem("campaign.authoritative_missing", "tools/campaign_recovery.py is required")
    else:
        process = subprocess.run(
            [
                sys.executable,
                str(recovery_tool),
                "check",
                "--repository-root",
                str(root),
                "--manifest",
                str(manifest_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if process.returncode != 0:
            detail = (process.stderr or process.stdout).strip().splitlines()
            problem(
                "campaign.authoritative_reject",
                detail[-1] if detail else "campaign_recovery.py rejected the manifest",
            )
    return manifest


def _validate_prime_run(row, *, binary_path: str | None, lower: int, upper: int, context: str, problem):
    expected_keys = {
        "argv",
        "exit_code",
        "stderr_bytes",
        "stderr_sha256",
        "stdout_bytes",
        "stdout_sha256",
    }
    if not _require_exact_keys(
        row, expected_keys, context=context, code="prime_identity.run_shape", problem=problem
    ):
        return None
    expected_argv = [binary_path, "--dump-primes", str(lower), str(upper)] if binary_path else None
    if expected_argv is not None and row["argv"] != expected_argv:
        problem("prime_identity.argv", f"{context}.argv must be exactly {expected_argv}")
    if row["exit_code"] != 0:
        problem("prime_identity.exit_code", f"{context} did not exit zero")
    for field in ("stdout_bytes", "stderr_bytes"):
        if not _is_integer(row[field]) or row[field] < 0:
            problem("prime_identity.stream_size", f"{context}.{field} must be a non-negative integer")
    for field in ("stdout_sha256", "stderr_sha256"):
        if not isinstance(row[field], str) or not SHA256_RE.fullmatch(row[field]):
            problem("prime_identity.stream_hash", f"{context}.{field} is malformed")
    if row["stderr_bytes"] != 0 or row["stderr_sha256"] != EMPTY_SHA256:
        problem("prime_identity.stderr", f"{context} must have canonical empty stderr")
    if not _is_integer(row["stdout_bytes"]) or row["stdout_bytes"] <= 0:
        problem("prime_identity.stdout", f"{context} must record a non-empty canonical stdout stream")
    return row


def validate_prime_identity(
    root: Path,
    gates: dict[str, dict],
    findings: Findings,
    campaign_manifest=None,
) -> None:
    gate_id = "ordered-prime-identity-515"
    problem = _evidence_problem(findings, gates, gate_id)
    path = root / "results" / "campaign" / "prime_identity_manifest.json"
    manifest = _load_optional_json(path, findings, "prime_identity.parse")
    if not isinstance(manifest, dict):
        problem("prime_identity.missing", "ordered-prime identity manifest is missing")
        return
    expected_top = {"campaign_manifest", "chunks", "executables", "interval", "schema", "totals"}
    if not _require_exact_keys(
        manifest,
        expected_top,
        context="prime identity manifest",
        code="prime_identity.shape",
        problem=problem,
    ):
        return
    if manifest["schema"] != PRIME_IDENTITY_SCHEMA:
        problem("prime_identity.schema", f"prime identity schema must be {PRIME_IDENTITY_SCHEMA}")
    if not _require_exact_keys(
        manifest["interval"],
        {"chunk_width", "lower_inclusive", "upper_exclusive"},
        context="prime identity interval",
        code="prime_identity.interval_shape",
        problem=problem,
    ) or manifest["interval"] != _expected_interval():
        problem("prime_identity.interval", f"prime identity interval must be exactly {_expected_interval()}")

    campaign_identity = _artifact_identity(
        root,
        manifest["campaign_manifest"],
        context="prime identity campaign manifest",
        code_prefix="prime_identity.campaign_artifact",
        problem=problem,
    )
    if campaign_identity is not None and campaign_identity["path"] != "results/campaign/campaign_manifest.json":
        problem(
            "prime_identity.campaign_path",
            "prime identity evidence must bind results/campaign/campaign_manifest.json",
        )
    if not isinstance(campaign_manifest, dict):
        problem("prime_identity.campaign_missing", "a valid campaign manifest is required for range comparison")
    else:
        campaign_interval = campaign_manifest.get("interval")
        if not isinstance(campaign_interval, dict) or any(
            campaign_interval.get(key) != manifest["interval"].get(key)
            for key in ("chunk_width", "lower_inclusive", "upper_exclusive")
        ):
            problem("prime_identity.campaign_interval", "prime and campaign intervals differ")

    executables = manifest["executables"]
    executable_records: dict[str, dict] = {}
    executable_binary_paths: dict[str, str] = {}
    if _require_exact_keys(
        executables,
        {"independent", "scanner"},
        context="prime identity executables",
        code="prime_identity.executables_shape",
        problem=problem,
    ):
        expected_sources = {"scanner": "src/scan_gpu.cu", "independent": "tools/prime_coverage.c"}
        for role in ("scanner", "independent"):
            record = executables[role]
            if not _require_exact_keys(
                record,
                {"binary", "source"},
                context=f"prime identity {role} executable",
                code="prime_identity.executable_shape",
                problem=problem,
            ):
                continue
            binary = _artifact_identity(
                root,
                record["binary"],
                context=f"prime identity {role} binary",
                code_prefix="prime_identity.binary",
                problem=problem,
                required_prefix="results/campaign/prime-identity/bin/",
            )
            source = _artifact_identity(
                root,
                record["source"],
                context=f"prime identity {role} source",
                code_prefix="prime_identity.source",
                problem=problem,
            )
            if source is not None and source["path"] != expected_sources[role]:
                problem(
                    "prime_identity.source_path",
                    f"{role} source must be {expected_sources[role]!r}",
                )
            if binary is not None and not os.access(binary["candidate"], os.X_OK):
                problem("prime_identity.binary_mode", f"{binary['path']} is not executable")
            if binary is not None:
                executable_binary_paths[role] = binary["path"]
            if binary is not None and source is not None:
                executable_records[role] = {"binary": binary, "source": source}
        if set(executable_records) == {"scanner", "independent"}:
            if executable_records["scanner"]["binary"]["path"] == executable_records["independent"]["binary"]["path"]:
                problem("prime_identity.independence", "scanner and independent binaries share a path")
            if executable_records["scanner"]["binary"]["sha256"] == executable_records["independent"]["binary"]["sha256"]:
                problem("prime_identity.independence", "scanner and independent binaries are byte-identical")
            if executable_records["scanner"]["source"]["sha256"] == executable_records["independent"]["source"]["sha256"]:
                problem("prime_identity.independence", "scanner and independent sources are byte-identical")

    chunks = manifest["chunks"]
    if not isinstance(chunks, list) or len(chunks) != CAMPAIGN_CHUNK_COUNT:
        count = len(chunks) if isinstance(chunks, list) else 0
        problem(
            "prime_identity.chunk_count",
            f"prime identity manifest contains {count}/{CAMPAIGN_CHUNK_COUNT} chunk rows",
        )
        chunks = chunks if isinstance(chunks, list) else []
    seen: set[int] = set()
    total_primes = 0
    total_stream_bytes = 0
    valid_rows = 0
    campaign_chunks = campaign_manifest.get("chunks") if isinstance(campaign_manifest, dict) else None
    campaign_ranges = {
        row.get("chunk_id"): (row.get("lower_inclusive"), row.get("upper_exclusive"))
        for row in campaign_chunks
        if isinstance(row, dict) and _is_integer(row.get("chunk_id"))
    } if isinstance(campaign_chunks, list) else {}
    for index, row in enumerate(chunks):
        context = f"prime identity chunks[{index}]"
        expected_keys = {
            "byte_equal",
            "chunk_id",
            "count",
            "independent",
            "lower_inclusive",
            "scanner",
            "upper_exclusive",
        }
        if not _require_exact_keys(
            row, expected_keys, context=context, code="prime_identity.chunk_shape", problem=problem
        ):
            continue
        chunk_id = row["chunk_id"]
        if not _is_integer(chunk_id) or not 1 <= chunk_id <= CAMPAIGN_CHUNK_COUNT:
            problem("prime_identity.chunk_id", f"{context}.chunk_id is outside 1..515")
            continue
        if chunk_id in seen:
            problem("prime_identity.chunk_duplicate", f"duplicate prime chunk_id {chunk_id}")
        seen.add(chunk_id)
        lower, upper = _expected_chunk(chunk_id)
        if row["lower_inclusive"] != lower or row["upper_exclusive"] != upper:
            problem(
                "prime_identity.chunk_range",
                f"prime chunk {chunk_id} must cover [{lower},{upper})",
            )
        if index + 1 != chunk_id:
            problem("prime_identity.chunk_order", f"prime row {index} has non-contiguous chunk_id {chunk_id}")
        if campaign_ranges.get(chunk_id) != (row["lower_inclusive"], row["upper_exclusive"]):
            problem("prime_identity.campaign_range", f"prime chunk {chunk_id} differs from campaign range")
        if not _is_integer(row["count"]) or row["count"] < 0:
            problem("prime_identity.count", f"prime chunk {chunk_id} count is invalid")
            count = 0
        else:
            count = row["count"]
        scanner_binary = executable_binary_paths.get("scanner")
        independent_binary = executable_binary_paths.get("independent")
        scanner = _validate_prime_run(
            row["scanner"],
            binary_path=scanner_binary,
            lower=lower,
            upper=upper,
            context=f"prime chunk {chunk_id} scanner",
            problem=problem,
        )
        independent = _validate_prime_run(
            row["independent"],
            binary_path=independent_binary,
            lower=lower,
            upper=upper,
            context=f"prime chunk {chunk_id} independent",
            problem=problem,
        )
        if row["byte_equal"] is not True:
            problem("prime_identity.byte_equal", f"prime chunk {chunk_id} is not byte-equal")
        if scanner is not None and independent is not None:
            if _is_integer(scanner["stdout_bytes"]):
                total_stream_bytes += scanner["stdout_bytes"]
                total_primes += count
                valid_rows += 1
            if (
                scanner["stdout_bytes"] != independent["stdout_bytes"]
                or scanner["stdout_sha256"] != independent["stdout_sha256"]
            ):
                problem(
                    "prime_identity.stream_mismatch",
                    f"prime chunk {chunk_id} records different scanner and independent byte streams",
                )
    expected_ids = set(range(1, CAMPAIGN_CHUNK_COUNT + 1))
    if seen != expected_ids:
        problem(
            "prime_identity.chunk_ids",
            f"prime chunk IDs differ: missing={sorted(expected_ids - seen)}, extra={sorted(seen - expected_ids)}",
        )

    totals = manifest["totals"]
    if _require_exact_keys(
        totals,
        {"all_byte_equal", "chunk_count", "prime_count", "stream_bytes"},
        context="prime identity totals",
        code="prime_identity.totals_shape",
        problem=problem,
    ) and valid_rows == CAMPAIGN_CHUNK_COUNT:
        expected_totals = {
            "all_byte_equal": True,
            "chunk_count": CAMPAIGN_CHUNK_COUNT,
            "prime_count": total_primes,
            "stream_bytes": total_stream_bytes,
        }
        if totals != expected_totals:
            problem(
                "prime_identity.totals",
                f"prime totals are not the exact recomputed totals: expected {expected_totals}",
            )
        if totals.get("prime_count") != CAMPAIGN_PRIME_COUNT:
            problem(
                "prime_identity.known_total",
                f"prime_count must equal the frozen campaign total {CAMPAIGN_PRIME_COUNT}",
            )


def _git_bytes(root: Path, arguments: list[str]):
    process = subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return process.returncode, process.stdout, process.stderr


def validate_cuda_evidence(root: Path, gates: dict[str, dict], findings: Findings) -> None:
    gate_id = "cuda-release-qualification"
    problem = _evidence_problem(findings, gates, gate_id)
    qualification_prefix = "results/release/cuda-qualification/"
    path = root / qualification_prefix / "manifest.json"
    manifest = _load_optional_json(path, findings, "cuda.parse")
    if not isinstance(manifest, dict):
        problem("cuda.missing", "CUDA qualification manifest is missing")
        return
    expected_top = {
        "build",
        "environment",
        "finished_utc",
        "logs",
        "qualification",
        "schema",
        "started_utc",
        "tests",
    }
    if not _require_exact_keys(
        manifest, expected_top, context="CUDA manifest", code="cuda.shape", problem=problem
    ):
        return
    if manifest["schema"] != CUDA_EVIDENCE_SCHEMA:
        problem("cuda.schema", f"CUDA schema must be {CUDA_EVIDENCE_SCHEMA}")
    if manifest["qualification"] != "PASS":
        problem("cuda.qualification", "CUDA qualification must be PASS")
    utc_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    for field in ("started_utc", "finished_utc"):
        if not isinstance(manifest[field], str) or not utc_re.fullmatch(manifest[field]):
            problem("cuda.timestamp", f"CUDA {field} must be a second-resolution UTC timestamp")
    if (
        isinstance(manifest["started_utc"], str)
        and isinstance(manifest["finished_utc"], str)
        and manifest["finished_utc"] < manifest["started_utc"]
    ):
        problem("cuda.timestamp_order", "CUDA finished_utc precedes started_utc")

    build = manifest["build"]
    commit = None
    tree = None
    if _require_exact_keys(
        build,
        {"binaries", "command_argv", "git_commit", "git_tree", "sources", "worktree_clean_before_build"},
        context="CUDA build",
        code="cuda.build_shape",
        problem=problem,
    ):
        commit = build["git_commit"]
        tree = build["git_tree"]
        if not isinstance(commit, str) or not SHA1_RE.fullmatch(commit):
            problem("cuda.commit", "CUDA git_commit must be a lowercase 40-character SHA-1")
            commit = None
        if not isinstance(tree, str) or not SHA1_RE.fullmatch(tree):
            problem("cuda.tree", "CUDA git_tree must be a lowercase 40-character SHA-1")
            tree = None
        if build["worktree_clean_before_build"] is not True:
            problem("cuda.clean_attestation", "CUDA qualification must attest a clean pre-build worktree")
        if build["command_argv"] != ["bash", "tests/gpu/test_scan_sm120.sh"]:
            problem(
                "cuda.build_command",
                "CUDA build command_argv must be exactly ['bash', 'tests/gpu/test_scan_sm120.sh']",
            )

    environment = manifest["environment"]
    environment_keys = {
        "compiler",
        "cuda",
        "driver",
        "gpu",
        "kernel_log",
        "nvidia_smi_inventory",
        "os_release",
    }
    environment_artifacts = []
    if _require_exact_keys(
        environment,
        environment_keys,
        context="CUDA environment",
        code="cuda.environment_shape",
        problem=problem,
    ):
        compiler = environment["compiler"]
        if _require_exact_keys(
            compiler,
            {"identity", "version_log"},
            context="CUDA compiler",
            code="cuda.compiler_shape",
            problem=problem,
        ):
            if not isinstance(compiler["identity"], str) or not compiler["identity"].strip():
                problem("cuda.compiler", "CUDA compiler identity must be non-empty")
            identity = _artifact_identity(
                root,
                compiler["version_log"],
                context="CUDA compiler version log",
                code_prefix="cuda.environment_artifact",
                problem=problem,
                required_prefix=qualification_prefix,
            )
            if identity is not None:
                environment_artifacts.append(identity)
        cuda = environment["cuda"]
        if _require_exact_keys(
            cuda,
            {"cuobjdump_identity", "cuobjdump_version_log", "version"},
            context="CUDA toolkit identity",
            code="cuda.toolkit_shape",
            problem=problem,
        ):
            for key in ("cuobjdump_identity", "version"):
                if not isinstance(cuda[key], str) or not cuda[key].strip():
                    problem("cuda.toolkit", f"CUDA toolkit {key} must be non-empty")
            identity = _artifact_identity(
                root,
                cuda["cuobjdump_version_log"],
                context="cuobjdump version log",
                code_prefix="cuda.environment_artifact",
                problem=problem,
                required_prefix=qualification_prefix,
            )
            if identity is not None:
                environment_artifacts.append(identity)
        driver = environment["driver"]
        if _require_exact_keys(
            driver,
            {"device_query", "versions"},
            context="CUDA driver identity",
            code="cuda.driver_shape",
            problem=problem,
        ):
            versions = driver["versions"]
            if (
                not isinstance(versions, list)
                or not versions
                or not all(isinstance(value, str) and value for value in versions)
                or versions != sorted(set(versions))
            ):
                problem("cuda.driver", "CUDA driver versions must be a sorted unique non-empty string array")
            identity = _artifact_identity(
                root,
                driver["device_query"],
                context="CUDA GPU device query",
                code_prefix="cuda.environment_artifact",
                problem=problem,
                required_prefix=qualification_prefix,
            )
            if identity is not None:
                environment_artifacts.append(identity)
        gpu_rows = environment["gpu"]
        if not isinstance(gpu_rows, list) or not gpu_rows:
            problem("cuda.gpu", "CUDA GPU identity must be a non-empty array")
        else:
            seen_gpu_ids = set()
            for index, gpu in enumerate(gpu_rows):
                if not _require_exact_keys(
                    gpu,
                    {"compute_capability", "index", "memory_mib", "name", "uuid"},
                    context=f"CUDA GPU[{index}]",
                    code="cuda.gpu_shape",
                    problem=problem,
                ):
                    continue
                if not all(isinstance(gpu[key], str) and gpu[key].strip() for key in gpu):
                    problem("cuda.gpu", f"CUDA GPU[{index}] fields must all be non-empty strings")
                identifier = (gpu["index"], gpu["uuid"])
                if identifier in seen_gpu_ids:
                    problem("cuda.gpu_duplicate", f"duplicate CUDA GPU identity {identifier!r}")
                seen_gpu_ids.add(identifier)
        for key in ("kernel_log", "nvidia_smi_inventory", "os_release"):
            identity = _artifact_identity(
                root,
                environment[key],
                context=f"CUDA environment {key}",
                code_prefix="cuda.environment_artifact",
                problem=problem,
                required_prefix=qualification_prefix,
            )
            if identity is not None:
                environment_artifacts.append(identity)

    sources = []
    binaries = []
    if isinstance(build, dict) and set(build) == {
        "binaries", "command_argv", "git_commit", "git_tree", "sources", "worktree_clean_before_build"
    }:
        if not isinstance(build["sources"], list) or len(build["sources"]) != 3:
            problem("cuda.source_count", "CUDA build must identify exactly three qualification sources")
        else:
            for index, row in enumerate(build["sources"]):
                identity = _artifact_identity(
                    root,
                    row,
                    context=f"CUDA source[{index}]",
                    code_prefix="cuda.source",
                    problem=problem,
                )
                if identity is not None:
                    sources.append(identity)
            source_paths = {row["path"] for row in sources}
            expected_sources = {
                "scripts/validate_cuda.sh",
                "src/scan_gpu.cu",
                "tests/gpu/test_scan_sm120.sh",
            }
            if source_paths != expected_sources:
                problem(
                    "cuda.source_paths",
                    f"CUDA source paths must be exactly {sorted(expected_sources)}",
                )
        if not isinstance(build["binaries"], list) or not build["binaries"]:
            problem("cuda.binary_count", "CUDA build must identify at least one binary")
        else:
            for index, row in enumerate(build["binaries"]):
                identity = _artifact_identity(
                    root,
                    row,
                    context=f"CUDA binary[{index}]",
                    code_prefix="cuda.binary",
                    problem=problem,
                    required_prefix=qualification_prefix,
                )
                if identity is not None:
                    binaries.append(identity)
                    if not os.access(identity["candidate"], os.X_OK):
                        problem("cuda.binary_mode", f"CUDA binary is not executable: {identity['path']}")
            if "results/release/cuda-qualification/scan_gpu" not in {row["path"] for row in binaries}:
                problem("cuda.scan_binary", "CUDA build must bind the qualified scan_gpu binary")

    logs = []
    if not isinstance(manifest["logs"], list) or not manifest["logs"]:
        problem("cuda.logs", "CUDA logs must be a non-empty artifact array")
    else:
        for index, row in enumerate(manifest["logs"]):
            identity = _artifact_identity(
                root,
                row,
                context=f"CUDA log[{index}]",
                code_prefix="cuda.log",
                problem=problem,
                required_prefix=qualification_prefix,
            )
            if identity is not None:
                logs.append(identity)

    tests = manifest["tests"]
    test_artifacts = []
    test_names: set[str] = set()
    if not isinstance(tests, list) or not tests:
        problem("cuda.tests", "CUDA tests must be a non-empty array")
        tests = tests if isinstance(tests, list) else []
    for index, row in enumerate(tests):
        context = f"CUDA tests[{index}]"
        expected_keys = {
            "command_argv",
            "exit_code",
            "id",
            "stderr",
            "stdout",
            "success_marker",
            "success_marker_count",
            "verdict",
            "working_directory",
        }
        if not _require_exact_keys(
            row, expected_keys, context=context, code="cuda.test_shape", problem=problem
        ):
            continue
        name = row["id"]
        if not isinstance(name, str) or not name.strip():
            problem("cuda.test_name", f"{context}.name must be non-empty")
        elif name in test_names:
            problem("cuda.test_duplicate", f"duplicate CUDA test name {name!r}")
        else:
            test_names.add(name)
        command = row["command_argv"]
        if command != ["bash", "tests/gpu/test_scan_sm120.sh"]:
            problem("cuda.command", f"{context}.command_argv is not the frozen regression command")
        if row["working_directory"] != ".":
            problem("cuda.working_directory", f"{context}.working_directory must be '.'")
        if row["exit_code"] != 0 or row["verdict"] != "PASS":
            problem("cuda.verdict", f"{context} must record verdict PASS and exit_code 0")
        if (
            row["success_marker"] != "SCAN_SM120_REGRESSION_OK"
            or row["success_marker_count"] != 1
        ):
            problem("cuda.success_marker", f"{context} must record the unique regression success marker")
        for stream in ("stdout", "stderr"):
            identity = _artifact_identity(
                root,
                row[stream],
                context=f"{context}.{stream}",
                code_prefix=f"cuda.{stream}",
                problem=problem,
                required_prefix=qualification_prefix,
            )
            if identity is not None:
                test_artifacts.append(identity)
                if name == "scan-sm120-regression" and stream == "stdout":
                    marker_count = sum(
                        line == b"SCAN_SM120_REGRESSION_OK"
                        for line in identity["candidate"].read_bytes().splitlines()
                    )
                    if marker_count != 1:
                        problem(
                            "cuda.success_marker",
                            "scan-sm120-regression stdout must contain exactly one success marker",
                        )
    if "scan-sm120-regression" not in test_names:
        problem("cuda.regression_missing", "CUDA evidence lacks scan-sm120-regression")

    output_artifacts = [*binaries, *environment_artifacts, *logs, *test_artifacts]
    output_paths = [row["path"] for row in output_artifacts]
    if len(output_paths) != len(set(output_paths)):
        problem("cuda.artifact_duplicate", "a CUDA output artifact is referenced more than once")
    output_directory = root / qualification_prefix
    actual_output_paths = {
        candidate.relative_to(root).as_posix()
        for candidate in output_directory.rglob("*")
        if candidate.is_file() and not candidate.is_symlink() and candidate != path
    } if output_directory.is_dir() else set()
    if set(output_paths) != actual_output_paths:
        problem(
            "cuda.artifact_coverage",
            f"CUDA artifact coverage differs: missing={sorted(actual_output_paths - set(output_paths))}, "
            f"stale={sorted(set(output_paths) - actual_output_paths)}",
        )

    if commit is not None and tree is not None:
        returncode, actual_tree_raw, _ = _git_bytes(root, ["rev-parse", "--verify", f"{commit}^{{tree}}"])
        if returncode != 0:
            problem("cuda.commit_unavailable", f"CUDA commit {commit} is not available in this repository")
        else:
            actual_tree = actual_tree_raw.decode("ascii", errors="replace").strip()
            if tree != actual_tree:
                problem("cuda.tree_mismatch", f"CUDA git_tree {tree} != commit tree {actual_tree}")
            ancestor, _, _ = _git_bytes(root, ["merge-base", "--is-ancestor", commit, "HEAD"])
            if ancestor != 0:
                problem("cuda.not_ancestor", "CUDA qualification commit is not an ancestor of HEAD")
            for source in sources:
                show_code, committed_bytes, _ = _git_bytes(root, ["show", f"{commit}:{source['path']}"])
                if show_code != 0:
                    problem("cuda.source_not_in_commit", f"{source['path']} is absent at CUDA commit")
                elif (
                    len(committed_bytes) != source["size"]
                    or hashlib.sha256(committed_bytes).hexdigest() != source["sha256"]
                ):
                    problem(
                        "cuda.source_commit_mismatch",
                        f"{source['path']} identity differs from CUDA commit {commit}",
                    )


def _verify_local_artifact(root: Path, row: dict, path_key: str, hash_key: str, findings: Findings) -> None:
    value = row.get(path_key)
    digest = row.get(hash_key)
    try:
        value = canonical_repo_path(value)
    except ContractDataError as exc:
        findings.error("external.path", f"{path_key}: {exc}")
        return
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        findings.error("external.hash", f"{hash_key} is malformed for {value}")
        return
    path = root / value
    if not path.is_file() or sha256_file(path) != digest:
        findings.error("external.artifact", f"external replication artifact missing or hash-mismatched: {value}")


def validate_external_evidence(root: Path, gates: dict[str, dict], findings: Findings) -> None:
    gate_id = "external-replication-4"
    path = root / "publication" / "external-replication.json"
    ledger = _load_optional_json(path, findings, "external.parse")
    if not isinstance(ledger, dict):
        _gate_result(findings, gates, gate_id, "external.missing", "external replication ledger is missing")
        return
    expected_ledger_keys = {
        "claim_ids",
        "replications",
        "required_fields_per_claim",
        "schema",
        "status",
    }
    if set(ledger) != expected_ledger_keys:
        _gate_result(
            findings,
            gates,
            gate_id,
            "external.shape",
            f"external ledger keys differ: missing={sorted(expected_ledger_keys - set(ledger))}, "
            f"extra={sorted(set(ledger) - expected_ledger_keys)}",
        )
    if ledger.get("schema") != "vdw-external-replication/v1":
        _gate_result(
            findings,
            gates,
            gate_id,
            "external.schema",
            "external ledger schema must be vdw-external-replication/v1",
        )
    declared_ids = ledger.get("claim_ids")
    if declared_ids != list(EXPECTED_EXTERNAL_CLAIM_ORDER):
        _gate_result(
            findings,
            gates,
            gate_id,
            "external.claim_ids",
            "external ledger does not freeze the exact ordered four claim IDs",
        )
    rows = ledger.get("replications")
    complete = isinstance(rows, list) and len(rows) == 4
    if not complete:
        count = len(rows) if isinstance(rows, list) else 0
        _gate_result(findings, gates, gate_id, "external.replication_count", f"external replication ledger contains {count}/4 replications")
        return
    if gates.get(gate_id, {}).get("status") != "passed":
        return
    required = ledger.get("required_fields_per_claim")
    if required != list(EXTERNAL_REQUIRED_FIELDS):
        findings.error(
            "external.required_fields",
            f"external required_fields_per_claim must be exactly {list(EXTERNAL_REQUIRED_FIELDS)}",
        )
        return
    found: set[str] = set()
    operator_ids: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            findings.error("external.row", "external replication row must be an object")
            continue
        missing = [key for key in required if key not in row]
        if missing:
            findings.error("external.fields", f"replication {row.get('claim_id')!r} misses fields: {', '.join(missing)}")
            continue
        claim_id = row.get("claim_id")
        if isinstance(claim_id, str):
            found.add(claim_id)
        if not SHA1_RE.fullmatch(str(row.get("candidate_git_commit", ""))):
            findings.error("external.commit", f"{claim_id}: malformed candidate_git_commit")
        if not isinstance(row.get("command_argv"), list) or not row["command_argv"]:
            findings.error("external.command", f"{claim_id}: command_argv must be non-empty")
        if not isinstance(row.get("environment"), dict) or not row["environment"]:
            findings.error("external.environment", f"{claim_id}: environment must be non-empty")
        if row.get("exit_code") != 0 or row.get("verdict") not in {"PASS", "ACCEPT"}:
            findings.error("external.verdict", f"{claim_id}: external run did not pass with exit code zero")
        if not isinstance(row.get("operator_attestation"), str) or not row["operator_attestation"].strip():
            findings.error("external.attestation", f"{claim_id}: operator attestation is empty")
        operator_id = row.get("operator_id")
        if not isinstance(operator_id, str) or not OPERATOR_ID_RE.fullmatch(operator_id):
            findings.error(
                "external.operator_id",
                f"{claim_id}: operator_id must be 3-64 ASCII letters, digits, dot, underscore, or hyphen",
            )
        else:
            operator_ids.append(operator_id)
        for path_key, hash_key in (
            ("verifier_path", "verifier_sha256"),
            ("stdout_path", "stdout_sha256"),
            ("stderr_path", "stderr_sha256"),
        ):
            _verify_local_artifact(root, row, path_key, hash_key, findings)
    if found != EXPECTED_EXTERNAL_CLAIMS:
        findings.error("external.id_set", f"external replication ID set differs: missing={sorted(EXPECTED_EXTERNAL_CLAIMS - found)}, extra={sorted(found - EXPECTED_EXTERNAL_CLAIMS)}")
    if len(operator_ids) != 4 or len(set(operator_ids)) != 4:
        findings.error(
            "external.operator_id_distinct",
            "external replication requires exactly four distinct stable operator IDs",
        )
    validator = root / "tools" / "external_replication.py"
    set_directory = root / "results" / "external-replication"
    if not validator.is_file() or validator.is_symlink():
        findings.error(
            "external.authoritative_missing",
            "tools/external_replication.py is required to validate a passed external gate",
        )
    else:
        process = subprocess.run(
            [
                sys.executable,
                str(validator),
                "validate-set",
                "--repo",
                str(root),
                "--set-dir",
                str(set_directory),
                "--repository-prefix",
                "results/external-replication",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode != 0:
            detail = (process.stderr or process.stdout).decode("utf-8", errors="replace").strip().splitlines()
            findings.error(
                "external.authoritative_reject",
                detail[-1] if detail else "tools/external_replication.py rejected the four-package set",
            )
        else:
            try:
                authoritative = json.loads(
                    process.stdout.decode("utf-8", errors="strict"),
                    object_pairs_hook=_no_duplicate_pairs,
                    parse_constant=_reject_constant,
                    parse_int=_bounded_integer,
                )
                _reject_unsafe_json(authoritative)
            except (UnicodeDecodeError, json.JSONDecodeError, ContractDataError) as exc:
                findings.error("external.authoritative_parse", f"authoritative set output: {exc}")
                authoritative = None
            expected_authoritative_keys = {
                "candidate_git_commit",
                "packages",
                "replications",
                "repository_prefix",
                "schema",
            }
            if not isinstance(authoritative, dict) or set(authoritative) != expected_authoritative_keys:
                findings.error(
                    "external.authoritative_shape",
                    "authoritative set output does not have the exact v1 shape",
                )
            else:
                packages = authoritative["packages"]
                package_operators = {
                    row.get("operator_id") for row in packages if isinstance(row, dict)
                } if isinstance(packages, list) else set()
                package_claims = {
                    row.get("claim_id") for row in packages if isinstance(row, dict)
                } if isinstance(packages, list) else set()
                if (
                    authoritative["schema"] != "vdw-external-replication-set/v1"
                    or authoritative["repository_prefix"] != "results/external-replication"
                    or not isinstance(packages, list)
                    or len(packages) != 4
                    or len(package_operators) != 4
                    or package_claims != EXPECTED_EXTERNAL_CLAIMS
                ):
                    findings.error(
                        "external.authoritative_set",
                        "authoritative output does not bind four claims, four packages, and four operators",
                    )
                commits = {
                    row.get("candidate_git_commit")
                    for row in rows
                    if isinstance(row, dict)
                }
                if commits != {authoritative["candidate_git_commit"]}:
                    findings.error(
                        "external.authoritative_commit",
                        "ledger rows do not share the authoritative candidate commit",
                    )
                if authoritative["replications"] != rows:
                    findings.error(
                        "external.authoritative_rows",
                        "ledger replication rows differ from the rows derived from the four packages",
                    )
    if ledger.get("status") not in {"passed", "complete", "verified"}:
        findings.error("external.status", "external gate passed but ledger status is not complete")


def validate_passed_gate_evidence(root: Path, gates: dict[str, dict], findings: Findings) -> None:
    """Check inexpensive evidence for gates that claim to have passed."""
    optional_while_staging = {"publication/source-import.json"}
    for gate_id, gate in gates.items():
        if gate.get("status") != "passed":
            continue
        for relative in gate.get("evidence", []):
            if relative in optional_while_staging and not (root / relative).exists():
                continue
            if not (root / relative).exists():
                findings.error("gate.evidence_missing", f"{gate_id} is passed but evidence is missing: {relative}")

    # These gates have compact, locally checkable declarations beyond mere
    # path existence.  CPU/tag CI remains bound to the eventual hosting record.
    bibliography = gates.get("bibliography-primary-source-audit", {})
    if bibliography.get("status") == "passed":
        audit = _load_optional_json(root / "publication" / "bibliography-audit.json", findings, "bibliography.parse")
        cited = audit.get("cited_keys") if isinstance(audit, dict) else None
        entries = audit.get("entries") if isinstance(audit, dict) else None
        entry_keys = {
            row.get("key") for row in entries
            if isinstance(row, dict) and isinstance(row.get("key"), str)
        } if isinstance(entries, list) else set()
        complete = (
            isinstance(audit, dict)
            and audit.get("schema") == "vdw-bibliography-audit/v2"
            and isinstance(audit.get("priority_audit"), dict)
            and isinstance(cited, list) and bool(cited)
            and len(cited) == len(set(cited))
            and set(cited) == entry_keys
            and len(entries) == len(entry_keys)
            and all(
                isinstance(row, dict)
                and isinstance(row.get("status"), str)
                and row["status"]
                and "pending" not in row["status"].casefold()
                for row in entries
            )
        )
        if not complete:
            findings.error("bibliography.incomplete", "bibliography gate passed without a completed audit ledger")
        else:
            validate_bibliography_bindings(root, audit, findings)

    if gates.get("paper-clean-build", {}).get("status") == "passed" and not (root / "paper" / "main.pdf").is_file():
        findings.error("paper.pdf_missing", "paper-clean-build is passed but paper/main.pdf is absent")

    if gates.get("outbound-rights", {}).get("status") == "passed":
        rights = (root / "RIGHTS-STATUS.md").read_text(encoding="utf-8", errors="strict") if (root / "RIGHTS-STATUS.md").is_file() else ""
        licences = [path for path in root.glob("LICENSE*") if path.is_file()]
        if not licences or re.search(r"\b(?:decision\s+)?pending\b", rights, re.IGNORECASE):
            findings.error("rights.incomplete", "outbound-rights is passed but licence texts/status are incomplete")


def _strip_tex_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        cut = len(line)
        for index, character in enumerate(line):
            if character != "%":
                continue
            backslashes = 0
            cursor = index - 1
            while cursor >= 0 and line[cursor] == "\\":
                backslashes += 1
                cursor -= 1
            if backslashes % 2 == 0:
                cut = index
                break
        lines.append(line[:cut])
    return "\n".join(lines)


def validate_bibliography_bindings(root: Path, audit: dict, findings: Findings) -> None:
    """Bind the completed ledger to both actual TeX citations and BibTeX keys."""

    expected_top = {
        "checked_at_utc",
        "cited_keys",
        "entries",
        "policy",
        "priority_audit",
        "schema",
    }
    if set(audit) != expected_top:
        findings.error(
            "bibliography.shape",
            f"bibliography audit must contain exactly {sorted(expected_top)}",
        )
        return

    cited_keys = audit.get("cited_keys")
    entries = audit.get("entries")
    if not isinstance(cited_keys, list) or not isinstance(entries, list):
        return
    if cited_keys != sorted(cited_keys):
        findings.error("bibliography.order", "bibliography cited_keys are not sorted")

    tex_keys: list[str] = []
    tex_root = root / "paper" / "tex"
    for path in sorted(tex_root.glob("*.tex")):
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError) as exc:
            findings.error("bibliography.tex_read", f"cannot read {path}: {exc}")
            continue
        for match in CITATION_RE.finditer(_strip_tex_comments(text)):
            tex_keys.extend(key.strip() for key in match.group(1).split(",") if key.strip())

    bib_path = root / "paper" / "references.bib"
    try:
        bib_text = bib_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        findings.error("bibliography.bib_read", f"cannot read {bib_path}: {exc}")
        return
    bib_keys = BIB_ENTRY_RE.findall(bib_text)
    if len(bib_keys) != len(set(bib_keys)):
        findings.error("bibliography.bib_duplicate", "paper/references.bib contains duplicate entry keys")

    ledger_set = set(cited_keys)
    tex_set = set(tex_keys)
    bib_set = set(bib_keys)
    if tex_set != ledger_set:
        findings.error(
            "bibliography.tex_ledger",
            f"TeX citations differ from ledger: missing={sorted(tex_set - ledger_set)}, stale={sorted(ledger_set - tex_set)}",
        )
    if bib_set != ledger_set:
        findings.error(
            "bibliography.bib_ledger",
            f"BibTeX entries differ from ledger: missing={sorted(ledger_set - bib_set)}, extra={sorted(bib_set - ledger_set)}",
        )

    entry_keys = [row.get("key") for row in entries if isinstance(row, dict)]
    if len(entry_keys) != len(entries) or len(entry_keys) != len(set(entry_keys)):
        findings.error("bibliography.entry_keys", "audit entries must have unique string keys")
    for index, row in enumerate(entries):
        if not isinstance(row, dict):
            continue
        if not any(
            isinstance(row.get(field), str) and row[field].strip()
            for field in ("source_url", "live_url", "immutable_url")
        ):
            findings.error(
                "bibliography.source_url",
                f"bibliography entry {index} ({row.get('key')!r}) lacks a source URL",
            )

    priority = audit.get("priority_audit")
    expected_priority = {
        "admission_rule",
        "claim_language",
        "cutoff_utc",
        "findings",
        "scope",
        "search_methods",
    }
    if not isinstance(priority, dict) or set(priority) != expected_priority:
        findings.error(
            "bibliography.priority_shape",
            f"priority audit must contain exactly {sorted(expected_priority)}",
        )
        return
    if not all(
        isinstance(priority.get(field), str) and priority[field].strip()
        for field in ("admission_rule", "claim_language", "cutoff_utc", "scope")
    ):
        findings.error("bibliography.priority_text", "priority audit text fields must be non-empty strings")
    methods = priority.get("search_methods")
    if not isinstance(methods, list) or len(methods) < 3 or not all(
        isinstance(method, str) and method.strip() for method in methods
    ):
        findings.error("bibliography.priority_methods", "priority audit must record at least three search methods")
    rows = priority.get("findings")
    if not isinstance(rows, list) or not rows:
        findings.error("bibliography.priority_findings", "priority audit must contain findings")
        return
    row_ids = [row.get("id") for row in rows if isinstance(row, dict)]
    if len(row_ids) != len(rows) or len(row_ids) != len(set(row_ids)) or not all(
        isinstance(row_id, str) and row_id for row_id in row_ids
    ):
        findings.error("bibliography.priority_ids", "priority findings must have unique non-empty IDs")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        if not isinstance(row.get("status"), str) or not row["status"]:
            findings.error("bibliography.priority_status", f"priority finding {index} lacks a status")
        if not isinstance(row.get("claim"), str) or not row["claim"]:
            findings.error("bibliography.priority_claim", f"priority finding {index} lacks a claim")
        source_keys = row.get("source_keys")
        if not isinstance(source_keys, list) or not source_keys or not all(
            isinstance(key, str) and key in ledger_set for key in source_keys
        ):
            findings.error(
                "bibliography.priority_sources",
                f"priority finding {index} has missing or unregistered source keys",
            )
    required_findings = {
        "berlekamp1968_w3_24": "admitted_verified_seed",
        "landman_robertson_stronger_formula": "excluded_unverified_statement",
        "current_direct_three_colour_triples": "no_earlier_source_found_not_global_priority",
    }
    observed = {
        row.get("id"): row.get("status") for row in rows if isinstance(row, dict)
    }
    for finding_id, expected_status in required_findings.items():
        if observed.get(finding_id) != expected_status:
            findings.error(
                "bibliography.priority_required",
                f"priority finding {finding_id!r} must have status {expected_status!r}",
            )


def validate_release_metadata(root: Path, gates: dict[str, dict], findings: Findings) -> None:
    template = root / "release" / "zenodo-metadata.json.in"
    if template.is_file():
        placeholders = sorted(set(PLACEHOLDER_RE.findall(template.read_text(encoding="utf-8", errors="strict"))))
        if placeholders:
            findings.blocker("release.placeholders", f"unresolved archival placeholders: {', '.join(placeholders)}")

    cff = root / "CITATION.cff"
    cff_text = cff.read_text(encoding="utf-8", errors="strict") if cff.is_file() else ""
    missing_cff = [
        field for field in ("version", "date-released", "doi")
        if re.search(rf"(?m)^{re.escape(field)}\s*:\s*\S+", cff_text) is None
    ]
    if missing_cff:
        findings.blocker("release.citation_incomplete", f"CITATION.cff still lacks release fields: {', '.join(missing_cff)}")

    if not any(path.is_file() for path in root.glob("LICENSE*")):
        findings.blocker("release.licence_missing", "no outbound licence text has been selected")
    if not (root / "MANIFEST.sha256").is_file():
        findings.blocker("release.manifest_missing", "MANIFEST.sha256 has not been frozen")
    if not (root / "paper" / "main.pdf").is_file():
        findings.blocker("release.paper_missing", "paper/main.pdf has not been frozen")
    if not (root / "release" / "zenodo-metadata.json").is_file():
        findings.blocker("release.archive_metadata_missing", "final release/zenodo-metadata.json is absent")

    doi_gate = gates.get("doi-tag-archive-freeze", {})
    if doi_gate.get("status") == "passed":
        if PLACEHOLDER_RE.search(cff_text) or PLACEHOLDER_RE.search(template.read_text(encoding="utf-8") if template.is_file() else ""):
            findings.error("release.gate_placeholder", "DOI/tag gate passed while placeholders remain")
        for relative in ("MANIFEST.sha256", "paper/main.pdf", "release/zenodo-metadata.json"):
            if not (root / relative).is_file():
                findings.error("release.gate_evidence", f"DOI/tag gate passed but {relative} is missing")
        freeze_tool = root / "tools" / "freeze_release.py"
        if freeze_tool.is_file():
            process = subprocess.run(
                [
                    sys.executable,
                    str(freeze_tool),
                    "--root",
                    str(root),
                    "check",
                    "--skip-pdf-rebuild",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if process.returncode != 0:
                detail = (process.stderr or process.stdout).strip().splitlines()
                findings.error(
                    "release.freeze_authoritative",
                    detail[-1] if detail else "freeze_release.py rejected the structural freeze",
                )


def audit_repository(root: Path, mode: str = "staging") -> dict:
    root = root.resolve()
    findings = Findings()
    status_path = root / "STATUS.json"
    scope_path = root / "publication" / "scope.json"
    try:
        status = load_json(status_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ContractDataError) as exc:
        findings.error("status.parse", f"{status_path}: {exc}")
        status = {}
    try:
        scope = load_json(scope_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ContractDataError) as exc:
        findings.error("scope.parse", f"{scope_path}: {exc}")
        scope = {}

    gates = validate_status(status, findings)
    validate_scope(root, scope, findings)
    validate_source_import(root, status, scope, findings)
    validate_claim_evidence(root, gates, findings)
    campaign_manifest = validate_campaign_evidence(root, gates, findings)
    validate_prime_identity(root, gates, findings, campaign_manifest)
    validate_cuda_evidence(root, gates, findings)
    validate_passed_gate_evidence(root, gates, findings)
    validate_release_metadata(root, gates, findings)

    if isinstance(status, dict):
        if status.get("repository_state") != "archived_release":
            findings.blocker("release.repository_state", f"repository_state is {status.get('repository_state')!r}, not 'archived_release'")
        if status.get("citable_release") is not True:
            findings.blocker("release.not_citable", "citable_release is not true")

    errors = sorted(findings.errors, key=lambda item: (item["code"], item["message"]))
    blockers = sorted(findings.blockers, key=lambda item: (item["code"], item["message"]))
    if errors:
        verdict = "REJECT"
    elif blockers:
        verdict = "BLOCKED"
    else:
        verdict = "PASS"
    return {
        "schema": REPORT_SCHEMA,
        "mode": mode,
        "root": str(root),
        "verdict": verdict,
        "errors": errors,
        "blockers": blockers,
        "gate_statuses": {
            gate_id: gates[gate_id].get("status")
            for gate_id in REQUIRED_GATES
            if gate_id in gates
        },
    }


def _print_human(report: dict) -> None:
    for item in report["errors"]:
        print(f"ERROR [{item['code']}] {item['message']}")
    for item in report["blockers"]:
        print(f"BLOCKER [{item['code']}] {item['message']}")
    mode = report["mode"].upper()
    if report["errors"]:
        print(f"PUBLICATION_CONTRACT_{mode}_REJECT: {len(report['errors'])} error(s), {len(report['blockers'])} blocker(s)")
    elif report["mode"] == "release" and report["blockers"]:
        print(f"PUBLICATION_CONTRACT_RELEASE_BLOCKED: {len(report['blockers'])} blocker(s)")
    else:
        print(f"PUBLICATION_CONTRACT_{mode}_PASS: structurally valid; {len(report['blockers'])} publication blocker(s)")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--mode", choices=("staging", "report", "release"), default="staging")
    args = parser.parse_args(argv)
    report = audit_repository(args.root, args.mode)
    if args.mode == "report":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_human(report)
    if report["errors"]:
        return 1
    if args.mode == "release" and report["blockers"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
