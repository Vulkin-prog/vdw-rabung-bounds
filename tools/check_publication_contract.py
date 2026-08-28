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
    "external-replication-4",
    "outbound-rights",
    "doi-tag-archive-freeze",
)
EXPECTED_EXTERNAL_CLAIMS = {
    "w2_k25_p1138900957",
    "w3_k17_p1961601427",
    "w2_k27_p3459826103",
    "w2_k28_p3476732783",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER_RE = re.compile(r"@@[A-Z][A-Z0-9_]*@@")
SKIP_UNTRACKED_PARTS = {".git", ".pytest_cache", "__pycache__", "build", "dist"}
SOURCE_IMPORT_CLASSIFICATIONS = {"imported", "derived", "new"}


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
    """Return paths that would be exported, preferring Git's index.

    Before the local publication checkout is initialised, runtime bytecode is
    ignored: it is neither source material nor intended export content.  Once
    Git exists, ``git ls-files`` is authoritative and even a tracked ``.pyc``
    will be caught by the scope rules.
    """
    if (root / ".git").exists():
        process = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode == 0:
            return sorted(
                item.decode("utf-8", errors="strict")
                for item in process.stdout.split(b"\0")
                if item
            )

    paths: list[str] = []
    for directory, names, files in os.walk(root, followlinks=False):
        relative_directory = Path(directory).relative_to(root)
        names[:] = sorted(name for name in names if name not in SKIP_UNTRACKED_PARTS)
        for name in sorted(files):
            relative = relative_directory / name
            if name.endswith(".pyc") or any(part in SKIP_UNTRACKED_PARTS for part in relative.parts):
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

    for key, directory in (
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
        if key in {"forbidden_prefixes", "forbidden_exact_paths"}:
            for value in values:
                try:
                    canonical_repo_path(value, directory=directory)
                except ContractDataError as exc:
                    findings.error("scope.path", str(exc))

    if any(key not in scope for key in ("forbidden_prefixes", "forbidden_exact_paths", "forbidden_name_fragments")):
        return
    for path in exported_paths(root):
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
    excluded = "publication/source-import.json"
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
            if relative == excluded:
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
        "excluded_paths": ["publication/source-import.json"],
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


def validate_campaign_evidence(root: Path, gates: dict[str, dict], findings: Findings) -> None:
    gate_id = "campaign-archive-515"
    manifest_path = root / "results" / "campaign" / "campaign_manifest.json"
    manifest = _load_optional_json(manifest_path, findings, "campaign.parse")
    if not isinstance(manifest, dict):
        _gate_result(findings, gates, gate_id, "campaign.manifest_missing", "results/campaign/campaign_manifest.json is missing")
        return
    chunks = manifest.get("chunks")
    if not isinstance(chunks, list) or len(chunks) != 515:
        _gate_result(findings, gates, gate_id, "campaign.chunk_count", f"campaign manifest does not contain exactly 515 chunk rows")
        return
    identifiers = []
    for row in chunks:
        if isinstance(row, dict):
            identifiers.append(row.get("chunk", row.get("index", row.get("chunk_id"))))
    if len(set(map(str, identifiers))) != 515 or any(value is None for value in identifiers):
        _gate_result(findings, gates, gate_id, "campaign.chunk_ids", "campaign chunk identifiers are missing or duplicated")
    checkpoint = manifest.get("checkpoint")
    chunk7 = manifest.get("chunk_7_checkpoint_evidence")
    if not checkpoint or not chunk7:
        _gate_result(findings, gates, gate_id, "campaign.checkpoint", "campaign manifest lacks checkpoint and explicit chunk-7 checkpoint evidence")


def validate_prime_identity(root: Path, gates: dict[str, dict], findings: Findings) -> None:
    gate_id = "ordered-prime-identity-515"
    path = root / "results" / "campaign" / "prime_identity_manifest.json"
    manifest = _load_optional_json(path, findings, "prime_identity.parse")
    if not isinstance(manifest, dict):
        _gate_result(findings, gates, gate_id, "prime_identity.missing", "ordered-prime identity manifest is missing")
        return
    chunks = manifest.get("chunks")
    totals = manifest.get("totals")
    valid = (
        manifest.get("schema") == "vdw-prime-identity/v1"
        and isinstance(chunks, list)
        and len(chunks) == 515
        and isinstance(totals, dict)
        and totals.get("chunk_count") == 515
        and totals.get("all_byte_equal") is True
        and all(isinstance(row, dict) and row.get("byte_equal") is True and SHA256_RE.fullmatch(str(row.get("stream_sha256", ""))) for row in chunks)
    )
    if not valid:
        _gate_result(findings, gates, gate_id, "prime_identity.invalid", "ordered-prime evidence is not a 515-chunk byte-equal v1 manifest")


def validate_cuda_evidence(root: Path, gates: dict[str, dict], findings: Findings) -> None:
    gate_id = "cuda-release-qualification"
    path = root / "results" / "release" / "cuda-qualification" / "manifest.json"
    manifest = _load_optional_json(path, findings, "cuda.parse")
    if not isinstance(manifest, dict):
        _gate_result(findings, gates, gate_id, "cuda.missing", "CUDA qualification manifest is missing")
        return
    build = manifest.get("build")
    environment = manifest.get("environment")
    tests = manifest.get("tests")
    valid = (
        isinstance(build, dict)
        and SHA1_RE.fullmatch(str(build.get("git_commit", "")))
        and isinstance(build.get("sources_sha256"), dict) and bool(build["sources_sha256"])
        and isinstance(build.get("binaries_sha256"), dict) and bool(build["binaries_sha256"])
        and isinstance(environment, dict)
        and all(environment.get(key) for key in ("compiler", "cuda", "driver", "gpu"))
        and isinstance(tests, list) and bool(tests)
        and all(isinstance(row, dict) and row.get("verdict") in {"PASS", "ACCEPT"} for row in tests)
    )
    if not valid:
        _gate_result(findings, gates, gate_id, "cuda.invalid", "CUDA qualification lacks a pinned build, environment identity, or passing tests")


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
    declared_ids = ledger.get("claim_ids")
    if not isinstance(declared_ids, list) or set(declared_ids) != EXPECTED_EXTERNAL_CLAIMS or len(declared_ids) != 4:
        _gate_result(findings, gates, gate_id, "external.claim_ids", "external ledger does not freeze the exact four required claim IDs")
    rows = ledger.get("replications")
    complete = isinstance(rows, list) and len(rows) == 4
    if not complete:
        count = len(rows) if isinstance(rows, list) else 0
        _gate_result(findings, gates, gate_id, "external.replication_count", f"external replication ledger contains {count}/4 replications")
        return
    if gates.get(gate_id, {}).get("status") != "passed":
        return
    required = ledger.get("required_fields_per_claim")
    if not isinstance(required, list) or not all(isinstance(value, str) for value in required):
        findings.error("external.required_fields", "external required_fields_per_claim is invalid")
        return
    found: set[str] = set()
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
        for path_key, hash_key in (
            ("verifier_path", "verifier_sha256"),
            ("stdout_path", "stdout_sha256"),
            ("stderr_path", "stderr_sha256"),
        ):
            _verify_local_artifact(root, row, path_key, hash_key, findings)
    if found != EXPECTED_EXTERNAL_CLAIMS:
        findings.error("external.id_set", f"external replication ID set differs: missing={sorted(EXPECTED_EXTERNAL_CLAIMS - found)}, extra={sorted(found - EXPECTED_EXTERNAL_CLAIMS)}")
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
            and audit.get("schema") == "vdw-bibliography-audit/v1"
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

    if gates.get("paper-clean-build", {}).get("status") == "passed" and not (root / "paper" / "main.pdf").is_file():
        findings.error("paper.pdf_missing", "paper-clean-build is passed but paper/main.pdf is absent")

    if gates.get("outbound-rights", {}).get("status") == "passed":
        rights = (root / "RIGHTS-STATUS.md").read_text(encoding="utf-8", errors="strict") if (root / "RIGHTS-STATUS.md").is_file() else ""
        licences = [path for path in root.glob("LICENSE*") if path.is_file()]
        if not licences or re.search(r"\b(?:decision\s+)?pending\b", rights, re.IGNORECASE):
            findings.error("rights.incomplete", "outbound-rights is passed but licence texts/status are incomplete")


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
    validate_campaign_evidence(root, gates, findings)
    validate_prime_identity(root, gates, findings)
    validate_cuda_evidence(root, gates, findings)
    validate_external_evidence(root, gates, findings)
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
