#!/usr/bin/env python3
"""Capture and verify the four frozen CPU-only external replications.

The runner is intentionally separate from the publication gate.  It creates a
self-contained evidence package, but it never edits STATUS.json or the
canonical external-replication ledger.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import platform
import re
import shlex
import shutil
import struct
import subprocess
import sys
import time
import types
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SCHEMA = "vdw-external-replication-package/v1"
IMPORT_SCHEMA = "vdw-external-replication-import/v1"
SET_SCHEMA = "vdw-external-replication-set/v1"
EXTERNAL_SCHEMA = "vdw-external-replication/v1"
MANIFEST_NAME = "manifest.json"
PARTIAL_MANIFEST_NAME = "manifest.partial.json"
SUMS_NAME = "SHA256SUMS"

SHA1_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
OPERATOR_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}\Z")
UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

REQUIRED_ROW_FIELDS = (
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
ENVIRONMENT_FIELDS = {
    "compiler_argv",
    "compiler_executable",
    "compiler_executable_sha256",
    "compiler_version",
    "cpu_model",
    "git_version",
    "logical_cpu_count",
    "machine",
    "operating_system",
    "pointer_bits",
    "python_version",
    "system",
    "system_byteorder",
}

# These values are deliberately duplicated here.  A clean commit whose
# audit/claims.json silently changes a parameter must not cause an operator to
# execute a different experiment under the same frozen claim ID.
FROZEN_CLAIMS = (
    {
        "id": "w2_k25_p1138900957",
        "colors": 2,
        "length": 25,
        "prime": 1138900957,
        "lower_bound": 27333622969,
    },
    {
        "id": "w3_k17_p1961601427",
        "colors": 3,
        "length": 17,
        "prime": 1961601427,
        "lower_bound": 31385622833,
    },
    {
        "id": "w2_k27_p3459826103",
        "colors": 2,
        "length": 27,
        "prime": 3459826103,
        "lower_bound": 89955478679,
    },
    {
        "id": "w2_k28_p3476732783",
        "colors": 2,
        "length": 28,
        "prime": 3476732783,
        "lower_bound": 93871785142,
    },
)
FROZEN_CLAIM_IDS = tuple(row["id"] for row in FROZEN_CLAIMS)


class ReplicationError(ValueError):
    """A fail-closed replication or package-validation error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _reject_constant(value: str):
    raise ReplicationError(f"non-finite JSON constant {value!r}")


def _object_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ReplicationError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_json_bytes(data: bytes, *, label: str):
    if data.startswith(b"\xef\xbb\xbf"):
        raise ReplicationError(f"UTF-8 BOM is forbidden: {label}")
    try:
        return json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReplicationError(f"invalid JSON in {label}: {exc}") from exc


def load_json(path: Path):
    return load_json_bytes(path.read_bytes(), label=str(path))


def canonical_path(value, *, field: str = "path") -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReplicationError(f"{field} must be a non-empty POSIX relative path")
    if any(ord(char) < 32 for char in value):
        raise ReplicationError(f"{field} contains a control character")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise ReplicationError(f"{field} is not canonical: {value!r}")
    if any(part in ("", ".", "..") for part in path.parts):
        raise ReplicationError(f"{field} has an unsafe component: {value!r}")
    return value


def package_file(package: Path, relative: str, *, field: str = "path") -> Path:
    relative = canonical_path(relative, field=field)
    path = package / relative
    if path.is_symlink() or not path.is_file():
        raise ReplicationError(f"missing regular package file: {relative}")
    return path


def run_checked(argv: list[str], *, cwd: Path, label: str) -> bytes:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ReplicationError(f"cannot execute {label}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ReplicationError(f"{label} failed with exit {result.returncode}: {detail}")
    return result.stdout


def git_bytes(root: Path, commit: str, path: str) -> bytes:
    if not SHA1_RE.fullmatch(commit):
        raise ReplicationError(f"malformed Git commit: {commit!r}")
    canonical_path(path, field="committed path")
    return run_checked(
        ["git", "show", f"{commit}:{path}"],
        cwd=root,
        label=f"git show {commit}:{path}",
    )


def clean_head(root: Path) -> str:
    root = root.resolve()
    top = run_checked(
        ["git", "rev-parse", "--show-toplevel"], cwd=root, label="Git root lookup"
    ).decode("utf-8", errors="strict").strip()
    if Path(top).resolve() != root:
        raise ReplicationError(f"--repo must be the Git top level: {root}")
    status = run_checked(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        label="Git status",
    ).decode("utf-8", errors="strict")
    if status:
        first = status.splitlines()[0]
        raise ReplicationError(f"candidate worktree is not clean (first entry: {first})")
    commit = run_checked(
        ["git", "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=root,
        label="Git HEAD lookup",
    ).decode("ascii", errors="strict").strip()
    if not SHA1_RE.fullmatch(commit):
        raise ReplicationError(f"Git returned a malformed HEAD: {commit!r}")
    return commit


def committed_inputs(root: Path, commit: str) -> tuple[bytes, bytes, tuple[dict, ...]]:
    ledger = load_json_bytes(
        git_bytes(root, commit, "publication/external-replication.json"),
        label=f"{commit}:publication/external-replication.json",
    )
    if not isinstance(ledger, dict) or ledger.get("schema") != EXTERNAL_SCHEMA:
        raise ReplicationError("unsupported committed external-replication ledger")
    if ledger.get("claim_ids") != list(FROZEN_CLAIM_IDS):
        raise ReplicationError("committed ledger does not freeze the exact four claim IDs in order")
    if ledger.get("required_fields_per_claim") != list(REQUIRED_ROW_FIELDS):
        raise ReplicationError("committed ledger required-field contract has changed")

    claims_value = load_json_bytes(
        git_bytes(root, commit, "audit/claims.json"),
        label=f"{commit}:audit/claims.json",
    )
    rows = claims_value.get("claims") if isinstance(claims_value, dict) else None
    if not isinstance(rows, list):
        raise ReplicationError("committed audit/claims.json has no claims array")
    by_id = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise ReplicationError("committed claims contain a malformed row")
        if row["id"] in by_id:
            raise ReplicationError(f"duplicate committed claim ID: {row['id']}")
        by_id[row["id"]] = row
    for frozen in FROZEN_CLAIMS:
        row = by_id.get(frozen["id"])
        if row is None:
            raise ReplicationError(f"missing committed frozen claim: {frozen['id']}")
        for field in ("colors", "length", "prime", "lower_bound"):
            if row.get(field) != frozen[field]:
                raise ReplicationError(
                    f"committed {frozen['id']}.{field} differs from the frozen value"
                )
        if frozen["lower_bound"] != (frozen["length"] - 1) * frozen["prime"] + 1:
            raise ReplicationError(f"internal lower-bound invariant failed: {frozen['id']}")

    source = git_bytes(root, commit, "tools/verify_claim.cpp")
    parser_source = git_bytes(root, commit, "tools/claim_audit.py")
    return source, parser_source, tuple(copy.deepcopy(row) for row in FROZEN_CLAIMS)


def validate_operator_id(value: str) -> str:
    if not isinstance(value, str) or not OPERATOR_ID_RE.fullmatch(value):
        raise ReplicationError(
            "operator ID must be 3-64 ASCII letters, digits, dot, underscore, or hyphen"
        )
    return value


def read_attestation(
    path: Path,
    operator_id: str | None = None,
    candidate_commit: str | None = None,
) -> tuple[bytes, str]:
    if path.is_symlink() or not path.is_file():
        raise ReplicationError("--attestation must name a regular text file")
    data = path.read_bytes()
    if not data or len(data) > 64 * 1024 or b"\x00" in data:
        raise ReplicationError("attestation must be non-empty UTF-8 text of at most 64 KiB")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReplicationError("attestation is not strict UTF-8") from exc
    if not text.strip():
        raise ReplicationError("attestation contains no non-whitespace text")
    if operator_id is not None:
        matches = [
            line.split(":", 1)[1].strip()
            for line in text.splitlines()
            if line.startswith("Operator ID:") and ":" in line
        ]
        if matches != [operator_id]:
            raise ReplicationError(
                "attestation must contain exactly one 'Operator ID:' line matching --operator-id"
            )
    if candidate_commit is not None:
        matches = [
            line.split(":", 1)[1].strip()
            for line in text.splitlines()
            if line.startswith("Candidate Git commit:") and ":" in line
        ]
        if matches != [candidate_commit]:
            raise ReplicationError(
                "attestation must contain exactly one 'Candidate Git commit:' line matching HEAD"
            )
    return data, text


def claim_audit_module(source: bytes, *, label: str):
    """Load the required validators from the exact committed parser source."""

    try:
        text = source.decode("utf-8", errors="strict")
        module = types.ModuleType("committed_claim_audit")
        module.__file__ = label
        exec(compile(text, label, "exec"), module.__dict__)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ReplicationError(f"cannot load committed claim parser: {exc}") from exc
    required = ("decode_output", "parse_verify_claim", "require_no_negative")
    if any(not callable(getattr(module, name, None)) for name in required):
        raise ReplicationError("committed claim_audit.py lacks a required output validator")
    return module


def parse_claim_output(audit_module, stdout: bytes, exit_code: int, claim: dict):
    try:
        parsed = audit_module.parse_verify_claim(stdout, exit_code, claim)
    except Exception as exc:  # The committed fail-closed parser owns its error type.
        return None, f"{type(exc).__name__}: {exc}"
    if not isinstance(parsed, dict) or parsed.get("verdict") != "ACCEPT":
        return None, "committed parser returned no ACCEPT verdict"
    return parsed, None


def parse_claim_stderr(audit_module, stderr: bytes) -> str | None:
    try:
        text = audit_module.decode_output(stderr)
        audit_module.require_no_negative(text, "verify_claim stderr")
    except Exception as exc:  # The committed fail-closed parser owns its error type.
        return f"{type(exc).__name__}: {exc}"
    return None


def selftest_passes(stdout: bytes, exit_code: int) -> bool:
    try:
        text = stdout.decode("utf-8", errors="strict").replace("\r\n", "\n")
    except UnicodeDecodeError:
        return False
    nonempty = [line.strip() for line in text.splitlines() if line.strip()]
    return (
        exit_code == 0
        and len([line for line in nonempty if line.startswith("[OK]")]) == 10
        and nonempty[-1:] == ["== SELFTEST : 10/10 OK =="]
        and not any("FAIL" in line or "REJECT" in line for line in nonempty)
    )


def command_text(argv: list[str], *, cwd: Path) -> str:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {exc}"
    return result.stdout.decode("utf-8", errors="replace").strip() or "unreported"


def cpu_model() -> str:
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        try:
            for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.lower().startswith("model name") and ":" in line:
                    value = line.split(":", 1)[1].strip()
                    if value:
                        return value
        except OSError:
            pass
    return platform.processor() or "unreported"


def environment_snapshot(root: Path, cxx_argv: list[str]) -> dict:
    compiler_executable = shutil.which(cxx_argv[0])
    if compiler_executable is None or not Path(compiler_executable).is_file():
        raise ReplicationError(f"compiler executable cannot be resolved: {cxx_argv[0]}")
    return {
        "compiler_argv": list(cxx_argv),
        "compiler_executable": compiler_executable,
        "compiler_executable_sha256": sha256_file(Path(compiler_executable)),
        "compiler_version": command_text([*cxx_argv, "--version"], cwd=root),
        "cpu_model": cpu_model(),
        "git_version": command_text(["git", "--version"], cwd=root),
        "logical_cpu_count": os.cpu_count() or 1,
        "machine": platform.machine() or "unreported",
        "operating_system": platform.platform(aliased=False, terse=False),
        "pointer_bits": struct.calcsize("P") * 8,
        "python_version": platform.python_version(),
        "system": platform.system() or "unreported",
        "system_byteorder": sys.byteorder,
    }


def write_atomic(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def relative_hash_record(package: Path, relative: str) -> dict:
    path = package_file(package, relative)
    return {"path": relative, "sha256": sha256_file(path)}


def capture_command(
    argv: list[str], *, cwd: Path, stdout_path: Path, stderr_path: Path
) -> tuple[int, float]:
    started = time.monotonic()
    try:
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            result = subprocess.run(
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                check=False,
            )
        exit_code = result.returncode
    except OSError as exc:
        stdout_path.touch(exist_ok=True)
        stderr_path.write_text(f"launcher error: {exc}\n", encoding="utf-8")
        exit_code = 125
    return exit_code, time.monotonic() - started


def build_manifest_base(
    *,
    commit: str,
    attestation_path: str,
    attestation_sha256: str,
    environment: dict,
    operator_id: str,
    parser_path: str,
    parser_sha256: str,
    selected_claim_id: str,
    source_path: str,
    source_sha256: str,
) -> dict:
    return {
        "attestation_path": attestation_path,
        "attestation_sha256": attestation_sha256,
        "build": None,
        "candidate_git_commit": commit,
        "capture_finished_at_utc": None,
        "capture_started_at_utc": utc_now(),
        "capture_status": "incomplete",
        "environment": environment,
        "frozen_claim_ids": list(FROZEN_CLAIM_IDS),
        "operator_id": operator_id,
        "parser_source_path": parser_path,
        "parser_source_sha256": parser_sha256,
        "replications": [],
        "schema": PACKAGE_SCHEMA,
        "selected_claim_id": selected_claim_id,
        "verifier_source_path": source_path,
        "verifier_source_sha256": source_sha256,
    }


def write_sums(package: Path) -> None:
    paths = []
    for path in package.rglob("*"):
        if path.is_symlink():
            raise ReplicationError(f"symbolic link in package: {path.relative_to(package)}")
        if path.is_file() and path != package / SUMS_NAME:
            paths.append(path.relative_to(package).as_posix())
    lines = [f"{sha256_file(package / relative)}  {relative}\n" for relative in sorted(paths)]
    write_atomic(package / SUMS_NAME, "".join(lines).encode("utf-8"))


def run_replication(
    root: Path,
    output: Path,
    attestation_input: Path,
    cxx_value: str,
    claim_id: str,
    operator_id: str,
) -> tuple[dict, bool]:
    root = root.resolve()
    output = output.resolve()
    if output.exists():
        raise ReplicationError(f"output already exists: {output}")
    if claim_id not in FROZEN_CLAIM_IDS:
        raise ReplicationError(f"claim ID is not one of the four frozen IDs: {claim_id!r}")
    operator_id = validate_operator_id(operator_id)
    commit = clean_head(root)
    source, parser_source, claims = committed_inputs(root, commit)
    claim = next(row for row in claims if row["id"] == claim_id)
    attestation_bytes, attestation_text = read_attestation(
        attestation_input.resolve(), operator_id, commit
    )
    try:
        cxx_argv = shlex.split(cxx_value)
    except ValueError as exc:
        raise ReplicationError(f"invalid compiler command: {exc}") from exc
    if not cxx_argv:
        raise ReplicationError("compiler command is empty")

    output.mkdir(parents=True)
    (output / "attestation").mkdir()
    (output / "source" / "tools").mkdir(parents=True)
    (output / "build").mkdir()
    (output / "runs").mkdir()

    attestation_relative = "attestation/operator-attestation.txt"
    source_relative = "source/tools/verify_claim.cpp"
    parser_relative = "source/tools/claim_audit.py"
    binary_relative = "build/verify_claim.exe" if os.name == "nt" else "build/verify_claim"
    (output / attestation_relative).write_bytes(attestation_bytes)
    (output / source_relative).write_bytes(source)
    (output / parser_relative).write_bytes(parser_source)
    audit_module = claim_audit_module(
        parser_source, label=f"{commit}:tools/claim_audit.py"
    )
    environment = environment_snapshot(root, cxx_argv)
    manifest = build_manifest_base(
        commit=commit,
        attestation_path=attestation_relative,
        attestation_sha256=sha256_bytes(attestation_bytes),
        environment=environment,
        operator_id=operator_id,
        parser_path=parser_relative,
        parser_sha256=sha256_bytes(parser_source),
        selected_claim_id=claim_id,
        source_path=source_relative,
        source_sha256=sha256_bytes(source),
    )
    partial_path = output / PARTIAL_MANIFEST_NAME
    write_atomic(partial_path, canonical_json(manifest))

    build_stdout = "build/stdout.txt"
    build_stderr = "build/stderr.txt"
    build_argv = [
        *cxx_argv,
        "-O2",
        "-std=c++17",
        source_relative,
        "-o",
        binary_relative,
    ]
    build_started = utc_now()
    exit_code, duration = capture_command(
        build_argv,
        cwd=output,
        stdout_path=output / build_stdout,
        stderr_path=output / build_stderr,
    )
    manifest["build"] = {
        "command_argv": build_argv,
        "duration_seconds": round(duration, 6),
        "exit_code": exit_code,
        "finished_at_utc": utc_now(),
        "started_at_utc": build_started,
        "stderr_path": build_stderr,
        "stderr_sha256": sha256_file(output / build_stderr),
        "stdout_path": build_stdout,
        "stdout_sha256": sha256_file(output / build_stdout),
    }
    write_atomic(partial_path, canonical_json(manifest))
    if exit_code != 0 or not (output / binary_relative).is_file():
        raise ReplicationError(
            f"verifier compilation failed with exit {exit_code}; partial package retained"
        )

    selftest_stdout = "build/selftest.stdout.txt"
    selftest_stderr = "build/selftest.stderr.txt"
    selftest_argv = [binary_relative, "--selftest"]
    selftest_started = utc_now()
    selftest_exit, selftest_duration = capture_command(
        selftest_argv,
        cwd=output,
        stdout_path=output / selftest_stdout,
        stderr_path=output / selftest_stderr,
    )
    manifest["build"]["selftest"] = {
        "command_argv": selftest_argv,
        "duration_seconds": round(selftest_duration, 6),
        "exit_code": selftest_exit,
        "finished_at_utc": utc_now(),
        "started_at_utc": selftest_started,
        "stderr_path": selftest_stderr,
        "stderr_sha256": sha256_file(output / selftest_stderr),
        "stdout_path": selftest_stdout,
        "stdout_sha256": sha256_file(output / selftest_stdout),
    }
    write_atomic(partial_path, canonical_json(manifest))
    if not selftest_passes((output / selftest_stdout).read_bytes(), selftest_exit):
        raise ReplicationError("verifier selftest failed; partial package retained")

    verifier_sha256 = sha256_file(output / binary_relative)
    claim_dir_relative = f"runs/{claim['id']}"
    claim_dir = output / claim_dir_relative
    claim_dir.mkdir()
    stdout_relative = f"{claim_dir_relative}/stdout.txt"
    stderr_relative = f"{claim_dir_relative}/stderr.txt"
    argv = [
        binary_relative,
        str(claim["prime"]),
        str(claim["colors"]),
        str(claim["length"]),
    ]
    started = utc_now()
    exit_code, duration = capture_command(
        argv,
        cwd=output,
        stdout_path=output / stdout_relative,
        stderr_path=output / stderr_relative,
    )
    stdout_bytes = (output / stdout_relative).read_bytes()
    parsed, parse_error = parse_claim_output(audit_module, stdout_bytes, exit_code, claim)
    stderr_parse_error = parse_claim_stderr(
        audit_module, (output / stderr_relative).read_bytes()
    )
    verdict = (
        "ACCEPT" if parsed is not None and stderr_parse_error is None else "ERROR"
    )
    row = {
        "candidate_git_commit": commit,
        "claim_id": claim["id"],
        "claim_parameters": {
            "colors": claim["colors"],
            "length": claim["length"],
            "lower_bound": claim["lower_bound"],
            "prime": claim["prime"],
        },
        "command_argv": argv,
        "duration_seconds": round(duration, 6),
        "environment": copy.deepcopy(environment),
        "exit_code": exit_code,
        "finished_at_utc": utc_now(),
        "operator_attestation": attestation_text,
        "operator_id": operator_id,
        "parse_error": parse_error,
        "parsed": parsed,
        "started_at_utc": started,
        "stderr_path": stderr_relative,
        "stderr_parse_error": stderr_parse_error,
        "stderr_sha256": sha256_file(output / stderr_relative),
        "stdout_path": stdout_relative,
        "stdout_sha256": sha256_file(output / stdout_relative),
        "verdict": verdict,
        "verifier_path": binary_relative,
        "verifier_sha256": verifier_sha256,
    }
    manifest["replications"].append(row)
    write_atomic(partial_path, canonical_json(manifest))

    manifest["capture_finished_at_utc"] = utc_now()
    manifest["capture_status"] = "complete"
    write_atomic(output / MANIFEST_NAME, canonical_json(manifest))
    partial_path.unlink()
    write_sums(output)
    all_accept = row["exit_code"] == 0 and row["verdict"] == "ACCEPT"
    return manifest, all_accept


def _require_fields(value: dict, expected: set[str], *, context: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise ReplicationError(f"{context} fields differ: {actual}")


def validate_timestamp(value, *, field: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise ReplicationError(f"{field} is not a canonical UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ReplicationError(f"{field} is not a real UTC timestamp") from exc


def validate_duration(value, *, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReplicationError(f"{field} is malformed")
    if not math.isfinite(value) or value < 0:
        raise ReplicationError(f"{field} is malformed")


def verify_hash(package: Path, relative: str, digest: str, *, field: str) -> None:
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ReplicationError(f"{field} is not a SHA-256 digest")
    path = package_file(package, relative, field=field.replace("sha256", "path"))
    if sha256_file(path) != digest:
        raise ReplicationError(f"hash mismatch: {relative}")


def verify_sums(package: Path) -> None:
    sums = package_file(package, SUMS_NAME, field="checksum path")
    expected_paths = []
    for path in package.rglob("*"):
        if path.is_symlink():
            raise ReplicationError(f"symbolic link in package: {path.relative_to(package)}")
        if path.is_file() and path != package / SUMS_NAME:
            expected_paths.append(path.relative_to(package).as_posix())
    expected = "".join(
        f"{sha256_file(package / relative)}  {relative}\n"
        for relative in sorted(expected_paths)
    ).encode("utf-8")
    if sums.read_bytes() != expected:
        raise ReplicationError("SHA256SUMS is noncanonical, incomplete, or stale")


def verify_package(root: Path, package: Path) -> dict:
    root = root.resolve()
    package = package.resolve()
    if not package.is_dir():
        raise ReplicationError(f"package is not a directory: {package}")
    verify_sums(package)
    manifest_path = package_file(package, MANIFEST_NAME, field="manifest path")
    manifest = load_json(manifest_path)
    top_fields = {
        "attestation_path",
        "attestation_sha256",
        "build",
        "candidate_git_commit",
        "capture_finished_at_utc",
        "capture_started_at_utc",
        "capture_status",
        "environment",
        "frozen_claim_ids",
        "operator_id",
        "parser_source_path",
        "parser_source_sha256",
        "replications",
        "schema",
        "selected_claim_id",
        "verifier_source_path",
        "verifier_source_sha256",
    }
    _require_fields(manifest, top_fields, context="manifest")
    if manifest["schema"] != PACKAGE_SCHEMA or manifest["capture_status"] != "complete":
        raise ReplicationError("package is not a complete v1 capture")
    capture_started = validate_timestamp(
        manifest["capture_started_at_utc"], field="capture_started_at_utc"
    )
    capture_finished = validate_timestamp(
        manifest["capture_finished_at_utc"], field="capture_finished_at_utc"
    )
    if capture_finished < capture_started:
        raise ReplicationError("capture finish precedes capture start")
    if manifest["frozen_claim_ids"] != list(FROZEN_CLAIM_IDS):
        raise ReplicationError("package claim IDs differ from the frozen ordered list")
    selected_claim_id = manifest["selected_claim_id"]
    if selected_claim_id not in FROZEN_CLAIM_IDS:
        raise ReplicationError("package selected claim is not frozen")
    operator_id = validate_operator_id(manifest["operator_id"])
    exact_paths = {
        "attestation_path": "attestation/operator-attestation.txt",
        "parser_source_path": "source/tools/claim_audit.py",
        "verifier_source_path": "source/tools/verify_claim.cpp",
    }
    for field, expected in exact_paths.items():
        if manifest[field] != expected:
            raise ReplicationError(f"{field} differs from the package protocol")
    commit = manifest["candidate_git_commit"]
    if not isinstance(commit, str) or not SHA1_RE.fullmatch(commit):
        raise ReplicationError("package candidate Git commit is malformed")
    committed_source, committed_parser, claims = committed_inputs(root, commit)
    claim = next(row for row in claims if row["id"] == selected_claim_id)
    verify_hash(
        package,
        manifest["verifier_source_path"],
        manifest["verifier_source_sha256"],
        field="verifier_source_sha256",
    )
    if package_file(package, manifest["verifier_source_path"]).read_bytes() != committed_source:
        raise ReplicationError("packaged verifier source differs from the candidate commit")
    verify_hash(
        package,
        manifest["parser_source_path"],
        manifest["parser_source_sha256"],
        field="parser_source_sha256",
    )
    packaged_parser = package_file(package, manifest["parser_source_path"]).read_bytes()
    if packaged_parser != committed_parser:
        raise ReplicationError("packaged claim parser differs from the candidate commit")
    audit_module = claim_audit_module(
        packaged_parser, label=f"{commit}:tools/claim_audit.py"
    )
    verify_hash(
        package,
        manifest["attestation_path"],
        manifest["attestation_sha256"],
        field="attestation_sha256",
    )
    attestation_bytes, attestation_text = read_attestation(
        package_file(package, manifest["attestation_path"]), operator_id, commit
    )
    if sha256_bytes(attestation_bytes) != manifest["attestation_sha256"]:
        raise ReplicationError("attestation digest mismatch")
    environment = manifest["environment"]
    _require_fields(environment, ENVIRONMENT_FIELDS, context="environment")
    compiler_argv = environment.get("compiler_argv")
    if (
        not isinstance(compiler_argv, list)
        or not compiler_argv
        or not all(isinstance(value, str) and value for value in compiler_argv)
    ):
        raise ReplicationError("package compiler_argv is malformed")
    system = environment.get("system")
    if not isinstance(system, str) or not system:
        raise ReplicationError("package system identity is malformed")
    if environment["pointer_bits"] not in (32, 64):
        raise ReplicationError("package pointer width is malformed")
    if environment["system_byteorder"] not in ("little", "big"):
        raise ReplicationError("package byte order is malformed")
    if (
        isinstance(environment["logical_cpu_count"], bool)
        or not isinstance(environment["logical_cpu_count"], int)
        or environment["logical_cpu_count"] < 1
    ):
        raise ReplicationError("package logical CPU count is malformed")
    for field in ENVIRONMENT_FIELDS - {
        "compiler_argv",
        "logical_cpu_count",
        "pointer_bits",
    }:
        if not isinstance(environment[field], str) or not environment[field]:
            raise ReplicationError(f"package environment field is empty: {field}")
    if not SHA256_RE.fullmatch(environment["compiler_executable_sha256"]):
        raise ReplicationError("package compiler executable hash is malformed")
    expected_binary = "build/verify_claim.exe" if system == "Windows" else "build/verify_claim"

    build_fields = {
        "command_argv",
        "duration_seconds",
        "exit_code",
        "finished_at_utc",
        "selftest",
        "started_at_utc",
        "stderr_path",
        "stderr_sha256",
        "stdout_path",
        "stdout_sha256",
    }
    _require_fields(manifest["build"], build_fields, context="build")
    build = manifest["build"]
    if isinstance(build["exit_code"], bool) or build["exit_code"] != 0:
        raise ReplicationError("package does not record a successful verifier build")
    expected_build_argv = [
        *compiler_argv,
        "-O2",
        "-std=c++17",
        manifest["verifier_source_path"],
        "-o",
        expected_binary,
    ]
    if build["command_argv"] != expected_build_argv:
        raise ReplicationError("package build command differs from the exact protocol")
    if build["stdout_path"] != "build/stdout.txt" or build["stderr_path"] != "build/stderr.txt":
        raise ReplicationError("package build log paths differ from the protocol")
    build_started = validate_timestamp(build["started_at_utc"], field="build.started_at_utc")
    build_finished = validate_timestamp(build["finished_at_utc"], field="build.finished_at_utc")
    if build_finished < build_started:
        raise ReplicationError("build finish precedes build start")
    validate_duration(build["duration_seconds"], field="build.duration_seconds")
    for path_key, hash_key in (("stdout_path", "stdout_sha256"), ("stderr_path", "stderr_sha256")):
        verify_hash(package, build[path_key], build[hash_key], field=f"build.{hash_key}")

    selftest_fields = {
        "command_argv",
        "duration_seconds",
        "exit_code",
        "finished_at_utc",
        "started_at_utc",
        "stderr_path",
        "stderr_sha256",
        "stdout_path",
        "stdout_sha256",
    }
    _require_fields(build["selftest"], selftest_fields, context="build.selftest")
    selftest = build["selftest"]
    if selftest["command_argv"] != [expected_binary, "--selftest"]:
        raise ReplicationError("package selftest command differs from the protocol")
    if (
        selftest["stdout_path"] != "build/selftest.stdout.txt"
        or selftest["stderr_path"] != "build/selftest.stderr.txt"
    ):
        raise ReplicationError("package selftest log paths differ from the protocol")
    selftest_started = validate_timestamp(
        selftest["started_at_utc"], field="selftest.started_at_utc"
    )
    selftest_finished = validate_timestamp(
        selftest["finished_at_utc"], field="selftest.finished_at_utc"
    )
    if selftest_finished < selftest_started:
        raise ReplicationError("selftest finish precedes selftest start")
    validate_duration(selftest["duration_seconds"], field="selftest.duration_seconds")
    for path_key, hash_key in (("stdout_path", "stdout_sha256"), ("stderr_path", "stderr_sha256")):
        verify_hash(package, selftest[path_key], selftest[hash_key], field=f"selftest.{hash_key}")
    if isinstance(selftest["exit_code"], bool) or not isinstance(selftest["exit_code"], int):
        raise ReplicationError("package selftest exit code is malformed")
    if not selftest_passes(
        package_file(package, selftest["stdout_path"]).read_bytes(), selftest["exit_code"]
    ):
        raise ReplicationError("package verifier selftest did not pass")

    rows = manifest["replications"]
    if not isinstance(rows, list) or len(rows) != 1:
        raise ReplicationError("package must contain exactly one replication row")
    row_fields = set(REQUIRED_ROW_FIELDS) | {
        "claim_parameters",
        "duration_seconds",
        "finished_at_utc",
        "operator_id",
        "parse_error",
        "parsed",
        "started_at_utc",
        "stderr_parse_error",
    }
    for index, row in enumerate(rows):
        _require_fields(row, row_fields, context=f"replications[{index}]")
        if row["claim_id"] != claim["id"] or row["candidate_git_commit"] != commit:
            raise ReplicationError(f"replication row {index} has the wrong claim or commit")
        if row["operator_id"] != operator_id:
            raise ReplicationError(f"{claim['id']} operator ID differs from the package")
        expected_parameters = {
            "colors": claim["colors"],
            "length": claim["length"],
            "lower_bound": claim["lower_bound"],
            "prime": claim["prime"],
        }
        if row["claim_parameters"] != expected_parameters:
            raise ReplicationError(f"{claim['id']} parameters differ from the frozen values")
        expected_argv = [
            expected_binary,
            str(claim["prime"]),
            str(claim["colors"]),
            str(claim["length"]),
        ]
        if row["command_argv"] != expected_argv:
            raise ReplicationError(f"{claim['id']} command differs from the exact protocol")
        if row["verifier_path"] != expected_binary:
            raise ReplicationError(f"{claim['id']} verifier path differs from the protocol")
        expected_stdout_path = f"runs/{claim['id']}/stdout.txt"
        expected_stderr_path = f"runs/{claim['id']}/stderr.txt"
        if row["stdout_path"] != expected_stdout_path or row["stderr_path"] != expected_stderr_path:
            raise ReplicationError(f"{claim['id']} output paths differ from the protocol")
        if row["environment"] != environment:
            raise ReplicationError(f"{claim['id']} environment differs from package environment")
        if row["operator_attestation"] != attestation_text:
            raise ReplicationError(f"{claim['id']} does not retain the explicit attestation")
        for path_key, hash_key in (
            ("verifier_path", "verifier_sha256"),
            ("stdout_path", "stdout_sha256"),
            ("stderr_path", "stderr_sha256"),
        ):
            verify_hash(package, row[path_key], row[hash_key], field=f"{claim['id']}.{hash_key}")
        stdout = package_file(package, row["stdout_path"]).read_bytes()
        if isinstance(row["exit_code"], bool) or not isinstance(row["exit_code"], int):
            raise ReplicationError(f"{claim['id']} exit code is malformed")
        parsed, parse_error = parse_claim_output(
            audit_module, stdout, row["exit_code"], claim
        )
        stderr_parse_error = parse_claim_stderr(
            audit_module, package_file(package, row["stderr_path"]).read_bytes()
        )
        derived_verdict = (
            "ACCEPT" if parsed is not None and stderr_parse_error is None else "ERROR"
        )
        if row["parsed"] != parsed or row["parse_error"] != parse_error:
            raise ReplicationError(f"{claim['id']} stored parser result differs from raw stdout")
        if row["stderr_parse_error"] != stderr_parse_error:
            raise ReplicationError(f"{claim['id']} stored parser result differs from raw stderr")
        if row["verdict"] != derived_verdict:
            raise ReplicationError(f"{claim['id']} verdict is not derivable from exit/stdout")
        run_started = validate_timestamp(
            row["started_at_utc"], field=f"{claim['id']}.started_at_utc"
        )
        run_finished = validate_timestamp(
            row["finished_at_utc"], field=f"{claim['id']}.finished_at_utc"
        )
        if run_finished < run_started:
            raise ReplicationError(f"{claim['id']} finish precedes start")
        validate_duration(
            row["duration_seconds"], field=f"{claim['id']}.duration_seconds"
        )

    expected_files = {
        MANIFEST_NAME,
        SUMS_NAME,
        manifest["attestation_path"],
        manifest["verifier_source_path"],
        manifest["parser_source_path"],
        expected_binary,
        build["stdout_path"],
        build["stderr_path"],
        selftest["stdout_path"],
        selftest["stderr_path"],
    }
    for row in rows:
        expected_files.update((row["stdout_path"], row["stderr_path"]))
    actual_files = set()
    for path in package.rglob("*"):
        if path.is_symlink():
            raise ReplicationError(f"symbolic link in package: {path.relative_to(package)}")
        if path.is_file():
            actual_files.add(path.relative_to(package).as_posix())
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        extra = sorted(actual_files - expected_files)
        raise ReplicationError(f"package file set differs: missing={missing}, extra={extra}")
    return manifest


def accepting(manifest: dict) -> bool:
    rows = manifest.get("replications", [])
    return len(rows) == 1 and all(
        row.get("exit_code") == 0 and row.get("verdict") == "ACCEPT" for row in rows
    )


def ledger_fragment(root: Path, package: Path, prefix: str) -> dict:
    manifest = verify_package(root, package)
    if not accepting(manifest):
        raise ReplicationError("non-accepting capture cannot produce a ledger fragment")
    prefix = canonical_path(prefix, field="repository prefix")
    rows = []
    for source in manifest["replications"]:
        row = {field: copy.deepcopy(source[field]) for field in REQUIRED_ROW_FIELDS}
        for path_key in ("verifier_path", "stdout_path", "stderr_path"):
            row[path_key] = f"{prefix}/{canonical_path(row[path_key], field=path_key)}"
        rows.append(row)
    return {
        "package_manifest_sha256": sha256_file(package / MANIFEST_NAME),
        "replications": rows,
        "repository_prefix": prefix,
        "schema": IMPORT_SCHEMA,
    }


def validate_set(root: Path, set_dir: Path, repository_prefix: str | None = None) -> dict:
    """Validate four one-claim bundles from four distinct operators."""

    set_dir = set_dir.resolve()
    if not set_dir.is_dir():
        raise ReplicationError(f"set directory is not a directory: {set_dir}")
    entries = sorted(set_dir.iterdir(), key=lambda path: path.name)
    if any(path.is_symlink() or not path.is_dir() for path in entries):
        raise ReplicationError("set directory must contain package directories only")
    if len(entries) != 4:
        raise ReplicationError(f"set must contain exactly four package directories, got {len(entries)}")
    prefix = (
        canonical_path(repository_prefix, field="repository prefix")
        if repository_prefix is not None
        else None
    )
    manifests = []
    for package in entries:
        canonical_path(package.name, field="package directory name")
        manifest = verify_package(root, package)
        if not accepting(manifest):
            raise ReplicationError(f"non-accepting package in set: {package.name}")
        manifests.append((package.name, manifest))

    claim_ids = [manifest["selected_claim_id"] for _, manifest in manifests]
    operator_ids = [manifest["operator_id"] for _, manifest in manifests]
    commits = {manifest["candidate_git_commit"] for _, manifest in manifests}
    if set(claim_ids) != set(FROZEN_CLAIM_IDS) or len(claim_ids) != len(set(claim_ids)):
        raise ReplicationError("set does not contain each frozen claim exactly once")
    if len(set(operator_ids)) != 4:
        raise ReplicationError("set requires four distinct persistent operator IDs")
    if len(commits) != 1:
        raise ReplicationError("set packages do not target one candidate Git commit")

    rows = []
    package_records = []
    for package_name, manifest in sorted(
        manifests, key=lambda item: FROZEN_CLAIM_IDS.index(item[1]["selected_claim_id"])
    ):
        source = manifest["replications"][0]
        row = {field: copy.deepcopy(source[field]) for field in REQUIRED_ROW_FIELDS}
        artifact_prefix = package_name if prefix is None else f"{prefix}/{package_name}"
        for path_key in ("verifier_path", "stdout_path", "stderr_path"):
            row[path_key] = f"{artifact_prefix}/{canonical_path(row[path_key], field=path_key)}"
        rows.append(row)
        package_records.append(
            {
                "claim_id": manifest["selected_claim_id"],
                "manifest_sha256": sha256_file(set_dir / package_name / MANIFEST_NAME),
                "operator_id": manifest["operator_id"],
                "path": package_name,
            }
        )
    return {
        "candidate_git_commit": next(iter(commits)),
        "packages": package_records,
        "replications": rows,
        "repository_prefix": prefix,
        "schema": SET_SCHEMA,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run one assigned frozen check")
    run_parser.add_argument("--repo", type=Path, default=ROOT)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--attestation", type=Path, required=True)
    run_parser.add_argument("--claim-id", choices=FROZEN_CLAIM_IDS, required=True)
    run_parser.add_argument("--operator-id", required=True)
    run_parser.add_argument("--cxx", default=os.environ.get("CXX", "g++"))

    verify_parser = subparsers.add_parser(
        "validate-bundle", aliases=["verify"], help="verify one received package"
    )
    verify_parser.add_argument("--repo", type=Path, default=ROOT)
    verify_parser.add_argument("--package", type=Path, required=True)

    fragment_parser = subparsers.add_parser(
        "ledger-fragment", help="render reviewed rows with repository-relative paths"
    )
    fragment_parser.add_argument("--repo", type=Path, default=ROOT)
    fragment_parser.add_argument("--package", type=Path, required=True)
    fragment_parser.add_argument("--repository-prefix", required=True)

    set_parser = subparsers.add_parser(
        "validate-set", help="validate four bundles from four distinct operators"
    )
    set_parser.add_argument("--repo", type=Path, default=ROOT)
    set_parser.add_argument("--set-dir", type=Path, required=True)
    set_parser.add_argument("--repository-prefix")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            manifest, all_accept = run_replication(
                args.repo,
                args.output,
                args.attestation,
                args.cxx,
                args.claim_id,
                args.operator_id,
            )
            print(f"CAPTURE_COMPLETE {manifest['selected_claim_id']}")
            print("ALL_ACCEPT" if all_accept else "NON_ACCEPTING_CAPTURE")
            return 0 if all_accept else 1
        if args.command in {"validate-bundle", "verify"}:
            manifest = verify_package(args.repo, args.package)
            print(f"PACKAGE_VALID {manifest['selected_claim_id']}")
            print("ALL_ACCEPT" if accepting(manifest) else "NON_ACCEPTING_CAPTURE")
            return 0 if accepting(manifest) else 1
        if args.command == "ledger-fragment":
            fragment = ledger_fragment(args.repo, args.package, args.repository_prefix)
            sys.stdout.buffer.write(canonical_json(fragment))
            return 0
        result = validate_set(args.repo, args.set_dir, args.repository_prefix)
        sys.stdout.buffer.write(canonical_json(result))
        return 0
    except ReplicationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
