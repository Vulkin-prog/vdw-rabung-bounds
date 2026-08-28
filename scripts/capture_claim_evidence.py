#!/usr/bin/env python3
"""Capture the 13 canonical Rabung claims without accepting partial evidence.

``plan`` (and ``capture --dry-run``) is machine independent.  ``capture`` is
deliberately stricter: it starts only from an existing clean Git commit, uses
either four binaries built by the fixed commands below or four supplied
binaries accompanied by exact build metadata, preserves every raw stream and
exit code, parses every output fail-closed, and publishes results atomically
only after the complete 13-manifest set validates.

All paths stored in manifests are canonical repository-relative POSIX paths.
The expensive programs are never run by ``plan``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path

try:
    import fcntl
except ImportError:  # ``plan`` remains usable on non-POSIX authoring machines.
    fcntl = None


ROOT = Path(__file__).resolve().parents[1]
CLAIMS_PATH = ROOT / "audit" / "claims.json"
AUDITOR_PATH = ROOT / "tools" / "claim_audit.py"
SCHEMA = "vdw-claim-capture-plan/v1"
SUPPLIED_BUILD_SCHEMA = "vdw-claim-build-input/v1"
PROGRAMS = ("scan_gpu", "rabung_criterion", "verify_claim", "highp_witness")
REQUIRED_SOURCES = (
    "audit/claim-manifest-v1.schema.json",
    "audit/claims.json",
    "scripts/capture_claim_evidence.py",
    "src/scan_gpu.cu",
    "tools/claim_audit.py",
    "tools/highp_witness.c",
    "tools/rabung_criterion.cpp",
    "tools/verify_claim.cpp",
)
DEFAULT_TIMEOUT_SECONDS = 6 * 60 * 60
DEFAULT_WITNESS_SAMPLES = 20000


class CaptureError(RuntimeError):
    """The capture cannot safely produce canonical evidence."""


def load_auditor(path=AUDITOR_PATH):
    spec = importlib.util.spec_from_file_location("vdw_claim_audit", path)
    if spec is None or spec.loader is None:
        raise CaptureError(f"cannot load claim auditor: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def json_text(value) -> str:
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"


def _no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CaptureError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise CaptureError(f"non-finite JSON constant {value!r}")


def _strict_json_float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise CaptureError(f"non-finite JSON number {value!r}")
    return parsed


def strict_json_loads(data, *, label="JSON"):
    if isinstance(data, bytes):
        if data.startswith(b"\xef\xbb\xbf"):
            raise CaptureError(f"{label}: UTF-8 BOM is forbidden")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CaptureError(f"{label}: invalid UTF-8: {exc}") from exc
    elif isinstance(data, str):
        text = data
        if text.startswith("\ufeff"):
            raise CaptureError(f"{label}: UTF-8 BOM is forbidden")
    else:
        raise CaptureError(f"{label}: expected bytes or text")
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicate_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_strict_json_float,
        )
    except json.JSONDecodeError as exc:
        raise CaptureError(f"{label}: malformed JSON: {exc}") from exc


def write_json(path: Path, value) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json_text(value), encoding="utf-8")
    os.replace(temporary, path)


def canonical_relative_path(root: Path, raw, label: str, *, must_exist=False) -> Path:
    """Resolve a canonical POSIX repository-relative path without traversal."""
    if not isinstance(raw, str) or not raw:
        raise CaptureError(f"{label}: expected a non-empty path")
    relative = Path(raw)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or "." in relative.parts
        or relative.as_posix() != raw
    ):
        raise CaptureError(f"{label}: path must be canonical and repository-relative")
    root = root.resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise CaptureError(f"{label}: path escapes repository") from exc
    if must_exist and not candidate.exists():
        raise CaptureError(f"{label}: path does not exist: {raw}")
    return candidate


def repo_posix(root: Path, path: Path, label: str) -> str:
    root = root.resolve()
    path = path.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise CaptureError(f"{label}: path is outside the repository") from exc
    text = relative.as_posix()
    canonical_relative_path(root, text, label)
    return text


def git(root: Path, *args: str, check=True) -> subprocess.CompletedProcess:
    process = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and process.returncode != 0:
        stderr = process.stderr.decode("utf-8", errors="replace").strip()
        raise CaptureError(f"git {' '.join(args)} failed: {stderr[-1000:]}")
    return process


def require_clean_commit(root: Path) -> str:
    root = root.resolve()
    top = git(root, "rev-parse", "--show-toplevel").stdout.decode().strip()
    if Path(top).resolve() != root:
        raise CaptureError("script root and Git top-level differ")
    commit = git(root, "rev-parse", "--verify", "HEAD^{commit}").stdout.decode().strip()
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        raise CaptureError("HEAD is not a full lowercase SHA-1 commit")
    status_text = git(
        root, "status", "--porcelain=v1", "--untracked-files=all"
    ).stdout.decode("utf-8", errors="replace")
    if status_text:
        raise CaptureError("claim capture requires a clean Git worktree")
    for source in REQUIRED_SOURCES:
        git(root, "ls-files", "--error-unmatch", source)
        git(root, "cat-file", "-e", f"{commit}:{source}")
    return commit


def require_commit_unchanged(root: Path, commit: str) -> None:
    current = git(root, "rev-parse", "--verify", "HEAD^{commit}").stdout.decode().strip()
    if current != commit:
        raise CaptureError(f"HEAD changed during capture: {commit} -> {current}")
    status_text = git(
        root, "status", "--porcelain=v1", "--untracked-files=all"
    ).stdout.decode("utf-8", errors="replace")
    if status_text:
        raise CaptureError("worktree changed during capture")


def source_hashes(root: Path, commit: str) -> dict[str, str]:
    result = {}
    for relative in REQUIRED_SOURCES:
        path = canonical_relative_path(root, relative, "source", must_exist=True)
        current_hash = sha256_file(path)
        committed = git(root, "show", f"{commit}:{relative}").stdout
        committed_hash = hashlib.sha256(committed).hexdigest()
        if current_hash != committed_hash:
            raise CaptureError(f"source differs from build commit: {relative}")
        result[relative] = current_hash
    return result


def load_claims(auditor, path=CLAIMS_PATH):
    claims = auditor.load_claims(path)
    if len(claims) != 13:
        raise CaptureError(f"canonical claim count is {len(claims)}, expected 13")
    return claims


def claim_run_plan(claim) -> list[dict]:
    p = str(claim["prime"])
    r = str(claim["colors"])
    k = str(claim["length"])
    runs = [
        {"stage": "scan_gpu_verify1", "attempt": 1, "argv": ["scan_gpu", "--verify1", p, k, r]},
        {"stage": "scan_gpu_verify1", "attempt": 2, "argv": ["scan_gpu", "--verify1", p, k, r]},
        {"stage": "rabung_criterion", "attempt": 1, "argv": ["rabung_criterion", "-q", p, r, k]},
        {"stage": "rabung_criterion", "attempt": 2, "argv": ["rabung_criterion", "-q", p, r, k]},
        {"stage": "verify_claim", "attempt": 1, "argv": ["verify_claim", p, r, k]},
    ]
    if claim.get("requires_montgomery_free_witness"):
        runs.append({
            "stage": "highp_witness",
            "attempt": 1,
            "argv": ["highp_witness", p, str(DEFAULT_WITNESS_SAMPLES)],
        })
    return runs


def build_plan(claims) -> dict:
    rows = []
    total = 0
    for claim in claims.values():
        runs = claim_run_plan(claim)
        total += len(runs)
        rows.append({
            "claim_id": claim["id"],
            "claim": f"W({claim['colors']},{claim['length']}) > {claim['lower_bound']}",
            "requires_montgomery_free_witness": bool(
                claim.get("requires_montgomery_free_witness")
            ),
            "runs": runs,
        })
    if len(rows) != 13 or total != 67:
        raise CaptureError(f"capture plan is not canonical: {len(rows)} claims, {total} runs")
    return {
        "schema": SCHEMA,
        "claim_count": len(rows),
        "minimum_run_count": total,
        "publishes_partial_evidence": False,
        "claims": rows,
    }


def compiler_identity(command: str, executable: str) -> str:
    resolved = Path(executable).resolve()
    process = subprocess.run(
        [str(resolved), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    text = process.stdout.decode("utf-8", errors="replace").strip()
    if process.returncode != 0 or not text:
        raise CaptureError(f"cannot identify compiler: {executable}")
    return json.dumps(
        {
            "command": command,
            "resolved_path": str(resolved),
            "sha256": sha256_file(resolved),
            "version": text[:16384],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def validate_compiler_identities(identities) -> None:
    expected_names = {"nvcc", "g++", "gcc"}
    if not isinstance(identities, dict) or set(identities) != expected_names:
        raise CaptureError(
            "compiler identities must describe exactly nvcc, g++, and gcc"
        )
    for name in ("nvcc", "g++", "gcc"):
        encoded = identities[name]
        if not isinstance(name, str) or not name or not isinstance(encoded, str):
            raise CaptureError("compiler identity is malformed")
        identity = strict_json_loads(encoded, label=f"compiler identity {name}")
        if not isinstance(identity, dict) or set(identity) != {
            "command", "resolved_path", "sha256", "version"
        }:
            raise CaptureError(f"compiler identity keys differ: {name}")
        if identity["command"] != name:
            raise CaptureError(f"compiler identity command differs: {name}")
        if (
            not isinstance(identity["resolved_path"], str)
            or not identity["resolved_path"]
            or not Path(identity["resolved_path"]).is_absolute()
        ):
            raise CaptureError(f"compiler path is missing: {name}")
        digest = identity["sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise CaptureError(f"compiler SHA-256 is malformed: {name}")
        if not isinstance(identity["version"], str) or not identity["version"]:
            raise CaptureError(f"compiler version is missing: {name}")


def exact_build_commands(build_rel: str) -> dict[str, list[str]]:
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


def build_exact(root: Path, commit: str, build_dir_raw: str):
    build_base = canonical_relative_path(root, build_dir_raw, "build directory")
    build_dir = build_base / commit
    build_rel = repo_posix(root, build_dir, "build directory")
    resolved = {}
    for name in ("nvcc", "g++", "gcc"):
        found = shutil.which(name)
        if found is None:
            raise CaptureError(f"required exact-build compiler is unavailable: {name}")
        resolved[name] = found
    versions = {
        name: compiler_identity(name, path) for name, path in resolved.items()
    }
    if build_dir.exists() or build_dir.is_symlink():
        raise CaptureError(f"exact build directory already exists: {build_rel}")
    build_dir.mkdir(parents=True)
    commands = exact_build_commands(build_rel)
    for program in PROGRAMS:
        argv = commands[program]
        stdout_path = build_dir / f"build-{program}.stdout"
        stderr_path = build_dir / f"build-{program}.stderr"
        process = subprocess.run(
            argv,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        stdout_path.write_bytes(process.stdout)
        stderr_path.write_bytes(process.stderr)
        if process.returncode != 0:
            raise CaptureError(
                f"exact build failed for {program} with exit code {process.returncode}; "
                f"logs: {repo_posix(root, stderr_path, 'build log')}"
            )
        binary = build_dir / program
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise CaptureError(f"exact build did not create executable {program}")
    binaries = {program: build_dir / program for program in PROGRAMS}
    return binaries, commands, versions, {
        "schema": SUPPLIED_BUILD_SCHEMA,
        "git_commit": commit,
        "sources_sha256": source_hashes(root, commit),
        "binaries_sha256": {name: sha256_file(path) for name, path in binaries.items()},
        "compile_commands": commands,
        "compiler_versions": versions,
    }


def validate_supplied_metadata(document, root: Path, commit: str, binaries):
    required = {
        "schema", "git_commit", "sources_sha256", "binaries_sha256",
        "compile_commands", "compiler_versions",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise CaptureError("supplied build metadata has unexpected top-level keys")
    if document["schema"] != SUPPLIED_BUILD_SCHEMA or document["git_commit"] != commit:
        raise CaptureError("supplied build metadata has the wrong schema or Git commit")
    expected_sources = source_hashes(root, commit)
    if document["sources_sha256"] != expected_sources:
        raise CaptureError("supplied source hashes differ from the exact build commit")
    for key in ("binaries_sha256", "compile_commands"):
        if not isinstance(document[key], dict) or set(document[key]) != set(PROGRAMS):
            raise CaptureError(f"supplied {key} must describe exactly the four programs")
    validate_compiler_identities(document["compiler_versions"])
    binary_directories = {path.parent.resolve() for path in binaries.values()}
    if len(binary_directories) != 1:
        raise CaptureError("supplied binaries must share one canonical directory")
    binary_directory = next(iter(binary_directories))
    binary_directory_rel = repo_posix(root, binary_directory, "binary directory")
    if not binary_directory_rel.startswith("build/"):
        raise CaptureError("supplied binaries must be staged below build/")
    expected_commands = exact_build_commands(binary_directory_rel)
    if document["compile_commands"] != expected_commands:
        raise CaptureError("supplied compile commands differ from the frozen argv set")
    for name, path in binaries.items():
        expected = document["binaries_sha256"].get(name)
        if (
            not isinstance(expected, str)
            or len(expected) != 64
            or any(char not in "0123456789abcdef" for char in expected)
            or expected != sha256_file(path)
        ):
            raise CaptureError(f"supplied binary hash mismatch: {name}")


def load_supplied_build(
    root: Path, commit: str, binary_dir_raw: str, metadata_raw: str
):
    directory = canonical_relative_path(
        root, binary_dir_raw, "binary directory", must_exist=True
    )
    if not directory.is_dir():
        raise CaptureError("supplied binary path is not a directory")
    metadata_path = canonical_relative_path(
        root, metadata_raw, "build metadata", must_exist=True
    )
    binaries = {}
    for name in PROGRAMS:
        path = directory / name
        if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
            raise CaptureError(f"supplied binary is absent, symlinked, or not executable: {name}")
        binaries[name] = path
    try:
        document = strict_json_loads(
            metadata_path.read_bytes(), label="supplied build metadata"
        )
    except OSError as exc:
        raise CaptureError(f"cannot read supplied build metadata: {exc}") from exc
    validate_supplied_metadata(document, root, commit, binaries)
    return (
        binaries,
        document["compile_commands"],
        document["compiler_versions"],
        document,
    )


def artifact_reference(path: Path) -> dict:
    return {"path": path.name, "sha256": sha256_file(path), "bytes": path.stat().st_size}


def run_process(
    actual_binary: Path,
    recorded_binary: str,
    arguments: list[str],
    directory: Path,
    stem: str,
    timeout_seconds: int,
    *,
    gpu_lock=False,
):
    stdout_path = directory / f"{stem}.stdout"
    stderr_path = directory / f"{stem}.stderr"
    argv = [recorded_binary, *arguments]
    environment = os.environ.copy()
    environment.update({"LC_ALL": "C.UTF-8", "TZ": "UTC", "PYTHONHASHSEED": "0"})
    lock_handle = None
    try:
        if gpu_lock:
            if fcntl is None:
                raise CaptureError("GPU capture requires POSIX flock support")
            lock_handle = open("/tmp/vdw_claim_capture_gpu.lock", "a+b")
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            process = subprocess.run(
                [str(actual_binary), *arguments],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=timeout_seconds,
                check=False,
            )
            stdout = process.stdout
            stderr = process.stderr
            exit_code = process.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = (exc.stderr or b"") + b"\nCAPTURE_TIMEOUT\n"
            exit_code = 124
        except OSError as exc:
            stdout = b""
            stderr = f"CAPTURE_EXEC_ERROR: {exc}\n".encode("utf-8", errors="replace")
            exit_code = 127
    finally:
        if lock_handle is not None:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            lock_handle.close()
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    return argv, exit_code, stdout_path, stderr_path


def parse_run(auditor, stage, stdout: bytes, exit_code: int, claim, maxrun=None):
    if stage == "scan_gpu_verify1":
        return auditor.parse_verify1(stdout, exit_code, claim)
    if stage == "rabung_criterion":
        return auditor.parse_rabung(stdout, exit_code, claim)
    if stage == "verify_claim":
        return auditor.parse_verify_claim(stdout, exit_code, claim)
    if maxrun is None:
        raise CaptureError("witness cannot run before a validated verify1 maxrun")
    return auditor.parse_highp_witness(stdout, exit_code, claim, maxrun)


def capture_one_claim(
    auditor,
    claim,
    directory: Path,
    actual_binaries: dict[str, Path],
    recorded_binaries: dict[str, str],
    build_record: dict,
    timeout_seconds: int,
    witness_samples: int,
):
    if witness_samples != DEFAULT_WITNESS_SAMPLES:
        raise CaptureError(
            f"witness sample count is frozen at {DEFAULT_WITNESS_SAMPLES}"
        )
    directory.mkdir(parents=True)
    p = str(claim["prime"])
    r = str(claim["colors"])
    k = str(claim["length"])
    specifications = [
        ("scan_gpu_verify1", "scan_gpu", 1, ["--verify1", p, k, r]),
        ("scan_gpu_verify1", "scan_gpu", 2, ["--verify1", p, k, r]),
        ("rabung_criterion", "rabung_criterion", 1, ["-q", p, r, k]),
        ("rabung_criterion", "rabung_criterion", 2, ["-q", p, r, k]),
        ("verify_claim", "verify_claim", 1, [p, r, k]),
    ]
    if claim.get("requires_montgomery_free_witness"):
        specifications.append(
            ("highp_witness", "highp_witness", 1, [p, str(witness_samples)])
        )
    runs = []
    verify_maxrun = None
    for ordinal, (stage, program, attempt, arguments) in enumerate(specifications, start=1):
        stem = f"run-{ordinal:02d}-{stage}-attempt-{attempt}"
        argv, exit_code, stdout_path, stderr_path = run_process(
            actual_binaries[program],
            recorded_binaries[program],
            arguments,
            directory,
            stem,
            timeout_seconds,
            gpu_lock=(stage == "scan_gpu_verify1"),
        )
        raw_stdout = stdout_path.read_bytes()
        try:
            parsed = parse_run(
                auditor, stage, raw_stdout, exit_code, claim, maxrun=verify_maxrun
            )
            auditor.require_no_negative(
                auditor.decode_output(stderr_path.read_bytes()), f"{stage} stderr"
            )
        except Exception as exc:
            raise CaptureError(
                f"{claim['id']} {stage} attempt {attempt} rejected; "
                "no claim manifest will be published"
            ) from exc
        if stage == "scan_gpu_verify1":
            verify_maxrun = parsed["maxrun"] if verify_maxrun is None else verify_maxrun
        runs.append({
            "stage": stage,
            "attempt": attempt,
            "argv": argv,
            "exit_code": exit_code,
            "stdout": artifact_reference(stdout_path),
            "stderr": artifact_reference(stderr_path),
            "parsed": parsed,
        })
    manifest = {
        "schema": auditor.SCHEMA_ID,
        "claim": claim,
        "build": build_record,
        "runs": runs,
        "final": {"verdict": "ACCEPT", "fail_closed": True},
    }
    auditor.validate_manifest(manifest, directory, claim)
    write_json(directory / "manifest.json", manifest)
    return manifest


def prepare_stage(root: Path, output: Path) -> Path:
    if output.exists():
        entries = sorted(path.name for path in output.iterdir())
        if entries not in ([], ["README.md"]):
            raise CaptureError(
                "output directory already contains evidence; refusing to overwrite it"
            )
    build_root = root / "build"
    build_root.mkdir(exist_ok=True)
    stage = build_root / f"claim-capture-staging-{uuid.uuid4().hex}"
    stage.mkdir()
    readme = output / "README.md"
    if readme.is_file():
        shutil.copy2(readme, stage / "README.md")
    return stage


def preserve_binaries(
    root: Path,
    stage: Path,
    output_rel: str,
    commit: str,
    binaries,
    commands,
    versions,
    input_metadata,
):
    shared = stage / "_build" / commit
    shared.mkdir(parents=True)
    actual = {}
    recorded = {}
    for name in PROGRAMS:
        destination = shared / name
        shutil.copy2(binaries[name], destination)
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR)
        copied_hash = sha256_file(destination)
        if copied_hash != input_metadata["binaries_sha256"].get(name):
            raise CaptureError(
                f"binary changed between build validation and preservation: {name}"
            )
        actual[name] = destination
        recorded[name] = f"{output_rel}/_build/{commit}/{name}"
    build_record = {
        "git_commit": commit,
        "git_clean": True,
        "sources_sha256": dict(input_metadata["sources_sha256"]),
        "binaries_sha256": {
            recorded[name]: sha256_file(actual[name]) for name in PROGRAMS
        },
        "compile_commands": {
            recorded[name]: list(commands[name]) for name in PROGRAMS
        },
        "compiler_versions": dict(versions),
    }
    normalized = {
        "schema": SUPPLIED_BUILD_SCHEMA,
        "git_commit": commit,
        "sources_sha256": build_record["sources_sha256"],
        "binaries_sha256": {
            name: build_record["binaries_sha256"][recorded[name]] for name in PROGRAMS
        },
        "compile_commands": {name: list(commands[name]) for name in PROGRAMS},
        "compiler_versions": dict(versions),
    }
    write_json(shared / "build-metadata.json", normalized)
    return actual, recorded, build_record


def validate_complete_stage(auditor, claims, stage: Path):
    results = [
        auditor.load_and_validate_manifest(stage / claim_id / "manifest.json", claims)
        for claim_id in claims
    ]
    document = auditor.build_set_document(results, claims)
    if document.get("verdict") != "ACCEPT" or document.get("claim_count") != 13:
        raise CaptureError("complete staged claim set did not validate")
    auditor.write_canonical_set_outputs(document, stage)
    auditor.verify_canonical_set_outputs(document, stage)
    return document


def install_stage(root: Path, stage: Path, output: Path, auditor, claims) -> None:
    backup = output.with_name(output.name + f".pre-capture-{uuid.uuid4().hex}")
    had_output = output.exists()
    try:
        if had_output:
            os.replace(output, backup)
        os.replace(stage, output)
        results = [
            auditor.load_and_validate_manifest(
                output / claim_id / "manifest.json", claims, repository_root=root
            )
            for claim_id in claims
        ]
        document = auditor.build_set_document(results, claims)
        auditor.verify_canonical_set_outputs(document, output)
    except Exception:
        if output.exists():
            failed = stage.parent / f"claim-capture-rejected-{uuid.uuid4().hex}"
            os.replace(output, failed)
        if had_output and backup.exists():
            os.replace(backup, output)
        raise
    if backup.exists():
        shutil.rmtree(backup)


def capture(args, auditor, claims) -> dict:
    root = ROOT.resolve()
    output = canonical_relative_path(root, args.output, "output directory")
    output_rel = repo_posix(root, output, "output directory")
    if output_rel == "build" or output_rel.startswith("build/"):
        raise CaptureError("final claim evidence may not be published under build/")
    if output_rel != "results/claims":
        raise CaptureError("final claim evidence output must be exactly results/claims")
    if args.witness_samples != DEFAULT_WITNESS_SAMPLES:
        raise CaptureError(
            f"witness sample count is frozen at {DEFAULT_WITNESS_SAMPLES}"
        )
    if not output.parent.is_dir():
        raise CaptureError("final claim-evidence parent directory does not exist")
    if output.exists() and not output.is_dir():
        raise CaptureError("final claim-evidence output exists but is not a directory")
    commit = require_clean_commit(root)
    sources = source_hashes(root, commit)
    if args.build:
        binaries, commands, versions, metadata = build_exact(
            root, commit, args.build_dir
        )
    else:
        if not args.binary_dir or not args.build_metadata:
            raise CaptureError(
                "supplied mode requires both --binary-dir and --build-metadata"
            )
        binaries, commands, versions, metadata = load_supplied_build(
            root, commit, args.binary_dir, args.build_metadata
        )
    if metadata["sources_sha256"] != sources:
        raise CaptureError("build source hashes changed before capture")
    stage = prepare_stage(root, output)
    try:
        actual, recorded, build_record = preserve_binaries(
            root, stage, output_rel, commit, binaries, commands, versions, metadata
        )
        for index, claim in enumerate(claims.values(), start=1):
            print(f"[{index:02d}/13] capture {claim['id']}", file=sys.stderr, flush=True)
            capture_one_claim(
                auditor,
                claim,
                stage / claim["id"],
                actual,
                recorded,
                build_record,
                args.timeout_seconds,
                args.witness_samples,
            )
        validate_complete_stage(auditor, claims, stage)
        require_commit_unchanged(root, commit)
        install_stage(root, stage, output, auditor, claims)
    except Exception:
        if stage.exists():
            shutil.rmtree(stage)
        raise
    return {
        "verdict": "ACCEPT",
        "fail_closed": True,
        "git_commit": commit,
        "claim_count": 13,
        "run_count": 67,
        "output": output_rel,
    }


def positive_integer(value: str) -> int:
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", help="print the 13-claim/67-run plan without GPU access")
    capture_parser = subparsers.add_parser(
        "capture", help="execute, parse, validate, and atomically publish the complete set"
    )
    capture_parser.add_argument("--output", default="results/claims")
    mode = capture_parser.add_mutually_exclusive_group()
    mode.add_argument("--build", action="store_true", help="use the fixed four-program build")
    mode.add_argument("--binary-dir", help="repository-relative directory of supplied binaries")
    capture_parser.add_argument(
        "--build-metadata", help="vdw-claim-build-input/v1 metadata for supplied binaries"
    )
    capture_parser.add_argument("--build-dir", default="build/claim-evidence")
    capture_parser.add_argument(
        "--timeout-seconds", type=positive_integer, default=DEFAULT_TIMEOUT_SECONDS
    )
    capture_parser.add_argument(
        "--witness-samples", type=positive_integer, default=DEFAULT_WITNESS_SAMPLES
    )
    capture_parser.add_argument(
        "--dry-run", action="store_true", help="print the plan; do not inspect or run binaries"
    )
    args = parser.parse_args(argv)
    try:
        auditor = load_auditor()
        claims = load_claims(auditor)
        if args.command == "plan" or args.dry_run:
            print(json_text(build_plan(claims)), end="")
            return 0
        if not args.build and not args.binary_dir:
            raise CaptureError("capture requires --build or --binary-dir")
        if args.build_metadata and not args.binary_dir:
            raise CaptureError("--build-metadata is valid only with --binary-dir")
        print(json_text(capture(args, auditor, claims)), end="")
        return 0
    except (CaptureError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"CLAIM_CAPTURE_REJECT: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
