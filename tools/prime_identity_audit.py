#!/usr/bin/env python3
"""Compare scanner and independent ordered-prime streams, chunk by chunk.

Both executables must implement ``--dump-primes LO HI`` and emit the canonical
``VDW-PRIMES-v1`` byte stream.  A v2 manifest binds the recovered campaign
manifest, the two exact sources, distinct installed executables, every frozen
argv, and the byte size/hash/exit status of both streams.  Failed or noisy runs
never produce a manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath


SCHEMA = "vdw-prime-identity/v2"
CAMPAIGN_MANIFEST_PATH = "results/campaign/campaign_manifest.json"
OUTPUT_MANIFEST_PATH = "results/campaign/prime_identity_manifest.json"
SCANNER_SOURCE_PATH = "src/scan_gpu.cu"
INDEPENDENT_SOURCE_PATH = "tools/prime_coverage.c"
SCANNER_BINARY_PATH = "results/campaign/prime-identity/bin/scanner-prime-stream"
INDEPENDENT_BINARY_PATH = (
    "results/campaign/prime-identity/bin/independent-prime-stream"
)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class PrimeIdentityError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_relative_path(label: str, role: str) -> str:
    if not isinstance(label, str) or not label:
        raise PrimeIdentityError(f"{role} path must be a non-empty string")
    path = PurePosixPath(label)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or path.as_posix() != label
    ):
        raise PrimeIdentityError(
            f"{role} path must be a canonical relative POSIX path"
        )
    return label


def _repository_file(root: Path, relative: str, role: str) -> Path:
    relative = canonical_relative_path(relative, role)
    candidate = root / relative
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise PrimeIdentityError(f"{role} traverses a symbolic link: {relative}")
    if not candidate.is_file():
        raise PrimeIdentityError(f"{role} is missing or not a regular file: {relative}")
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PrimeIdentityError(f"cannot resolve {role}: {exc}") from exc
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise PrimeIdentityError(f"{role} escapes the repository: {relative}")
    return candidate


def artifact_identity(root: Path, relative: str, role: str) -> dict:
    candidate = _repository_file(root, relative, role)
    return {
        "path": relative,
        "sha256": sha256_file(candidate),
        "size": candidate.stat().st_size,
    }


def require_unchanged_identity(root: Path, record: dict, role: str) -> None:
    current = artifact_identity(root, record["path"], role)
    if current != record:
        raise PrimeIdentityError(f"{role} changed during the prime-stream audit")


def parse_stream(data: bytes, lo: int, hi: int) -> list[int]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PrimeIdentityError(f"stream is not ASCII: {exc}") from exc
    if not text.endswith("\n"):
        raise PrimeIdentityError("canonical stream lacks final newline")
    lines = text.splitlines()
    if len(lines) < 3 or lines[0] != "VDW-PRIMES-v1":
        raise PrimeIdentityError("wrong canonical stream header")
    if lines[1] != str(lo) or lines[2] != str(hi):
        raise PrimeIdentityError("stream endpoints do not match the requested interval")
    primes: list[int] = []
    previous = lo - 1
    for line in lines[3:]:
        if not line or not line.isascii() or not line.isdecimal():
            raise PrimeIdentityError(f"non-canonical prime line {line!r}")
        value = int(line)
        if line != str(value):
            raise PrimeIdentityError(f"non-canonical decimal prime line {line!r}")
        if value < lo or value >= hi or value <= previous:
            raise PrimeIdentityError("prime stream is not strictly increasing in range")
        primes.append(value)
        previous = value
    return primes


def _input_executable(path: Path, role: str) -> Path:
    if path.is_symlink():
        raise PrimeIdentityError(f"{role} input executable must not be a symlink: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise PrimeIdentityError(f"cannot resolve {role} input executable: {exc}") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PrimeIdentityError(f"{role} is not an executable regular file: {resolved}")
    return resolved


def _copy_executable(source: Path, destination: Path, role: str) -> None:
    before_size = source.stat().st_size
    before_hash = sha256_file(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("xb") as output, source.open("rb") as input_handle:
            shutil.copyfileobj(input_handle, output, length=1 << 20)
    except FileExistsError as exc:
        raise PrimeIdentityError(
            f"refusing to overwrite existing {role} evidence binary: {destination}"
        ) from exc
    destination.chmod(
        stat.S_IRUSR
        | stat.S_IWUSR
        | stat.S_IXUSR
        | stat.S_IRGRP
        | stat.S_IXGRP
        | stat.S_IROTH
        | stat.S_IXOTH
    )
    after_hash = sha256_file(source)
    copied_hash = sha256_file(destination)
    if (
        source.stat().st_size != before_size
        or destination.stat().st_size != before_size
        or after_hash != before_hash
        or copied_hash != before_hash
    ):
        raise PrimeIdentityError(f"{role} input changed while it was copied")


def _prepare_destination_parent(
    root: Path, relative: str, role: str, *, create: bool
) -> Path:
    relative = canonical_relative_path(relative, role)
    current = root
    parts = PurePosixPath(relative).parts
    for part in parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise PrimeIdentityError(
                f"{role} destination traverses a symbolic link: {relative}"
            )
        if current.exists() and not current.is_dir():
            raise PrimeIdentityError(
                f"{role} destination parent is not a directory: {current}"
            )
    if create:
        current.mkdir(parents=True, exist_ok=True)
    elif not current.is_dir():
        raise PrimeIdentityError(f"{role} destination directory is missing: {current}")
    if current.is_symlink():
        raise PrimeIdentityError(
            f"{role} destination parent is a symbolic link: {relative}"
        )
    return root / relative


def prepare_executables(
    root: Path,
    scanner: Path,
    independent: Path,
    *,
    install: bool,
) -> tuple[Path, Path, dict]:
    scanner_input = _input_executable(scanner, "scanner")
    independent_input = _input_executable(independent, "independent sieve")
    scanner_input_hash = sha256_file(scanner_input)
    independent_input_hash = sha256_file(independent_input)
    if (
        scanner_input == independent_input
        or scanner_input_hash == independent_input_hash
    ):
        raise PrimeIdentityError(
            "scanner and independent sieve must be distinct executables"
        )

    scanner_source = artifact_identity(
        root, SCANNER_SOURCE_PATH, "scanner source"
    )
    independent_source = artifact_identity(
        root, INDEPENDENT_SOURCE_PATH, "independent source"
    )
    if scanner_source["sha256"] == independent_source["sha256"]:
        raise PrimeIdentityError("scanner and independent sources are byte-identical")

    scanner_destination = _prepare_destination_parent(
        root, SCANNER_BINARY_PATH, "scanner evidence binary", create=install
    )
    independent_destination = _prepare_destination_parent(
        root,
        INDEPENDENT_BINARY_PATH,
        "independent evidence binary",
        create=install,
    )
    if install:
        if (
            scanner_destination.exists()
            or scanner_destination.is_symlink()
            or independent_destination.exists()
            or independent_destination.is_symlink()
        ):
            raise PrimeIdentityError(
                "refusing to overwrite an existing prime-identity evidence binary"
            )
        _copy_executable(scanner_input, scanner_destination, "scanner")
        _copy_executable(
            independent_input, independent_destination, "independent sieve"
        )
    else:
        for candidate, input_hash, role in (
            (scanner_destination, scanner_input_hash, "scanner"),
            (
                independent_destination,
                independent_input_hash,
                "independent sieve",
            ),
        ):
            if (
                not candidate.is_file()
                or not os.access(candidate, os.X_OK)
                or sha256_file(candidate) != input_hash
            ):
                raise PrimeIdentityError(
                    f"installed {role} binary is absent, non-executable, or differs from input"
                )

    scanner_identity = artifact_identity(
        root, SCANNER_BINARY_PATH, "scanner evidence binary"
    )
    independent_identity = artifact_identity(
        root, INDEPENDENT_BINARY_PATH, "independent evidence binary"
    )
    if scanner_identity["sha256"] == independent_identity["sha256"]:
        raise PrimeIdentityError("installed evidence binaries are byte-identical")
    executables = {
        "independent": {
            "binary": independent_identity,
            "source": independent_source,
        },
        "scanner": {
            "binary": scanner_identity,
            "source": scanner_source,
        },
    }
    return scanner_destination, independent_destination, executables


def run_stream(
    executable: Path, recorded_binary_path: str, lo: int, hi: int
) -> tuple[bytes, dict]:
    recorded_binary_path = canonical_relative_path(
        recorded_binary_path, "recorded executable"
    )
    actual_argv = [str(executable), "--dump-primes", str(lo), str(hi)]
    recorded_argv = [recorded_binary_path, "--dump-primes", str(lo), str(hi)]
    process = subprocess.run(
        actual_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    run = {
        "argv": recorded_argv,
        "exit_code": process.returncode,
        "stderr_bytes": len(process.stderr),
        "stderr_sha256": hashlib.sha256(process.stderr).hexdigest(),
        "stdout_bytes": len(process.stdout),
        "stdout_sha256": hashlib.sha256(process.stdout).hexdigest(),
    }
    if process.returncode != 0:
        raise PrimeIdentityError(
            f"{recorded_binary_path}: exit {process.returncode}; "
            f"stderr={process.stderr[-500:]!r}"
        )
    if process.stderr:
        raise PrimeIdentityError(
            f"{recorded_binary_path}: dump mode must be silent on stderr; "
            f"got {process.stderr[-500:]!r}"
        )
    if run["stderr_sha256"] != EMPTY_SHA256:
        raise PrimeIdentityError("internal empty-stderr identity mismatch")
    return process.stdout, run


def audit_chunk(
    scanner: Path,
    independent: Path,
    lo: int,
    hi: int,
    *,
    chunk_id: int = 1,
    scanner_binary_path: str = SCANNER_BINARY_PATH,
    independent_binary_path: str = INDEPENDENT_BINARY_PATH,
) -> dict:
    scanner_data, scanner_run = run_stream(
        scanner, scanner_binary_path, lo, hi
    )
    independent_data, independent_run = run_stream(
        independent, independent_binary_path, lo, hi
    )
    scanner_primes = parse_stream(scanner_data, lo, hi)
    independent_primes = parse_stream(independent_data, lo, hi)
    if scanner_data != independent_data:
        mismatch = next(
            (
                index
                for index, pair in enumerate(zip(scanner_data, independent_data))
                if pair[0] != pair[1]
            ),
            min(len(scanner_data), len(independent_data)),
        )
        raise PrimeIdentityError(
            f"ordered prime streams differ for [{lo},{hi}) at byte {mismatch}; "
            f"counts {len(scanner_primes)} != {len(independent_primes)}"
        )
    return {
        "byte_equal": True,
        "chunk_id": chunk_id,
        "count": len(scanner_primes),
        "independent": independent_run,
        "lower_inclusive": lo,
        "scanner": scanner_run,
        "upper_exclusive": hi,
    }


def _no_duplicate_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PrimeIdentityError(f"duplicate campaign JSON key: {key!r}")
        result[key] = value
    return result


def _expected_ranges(lo: int, hi: int, chunk: int) -> list[tuple[int, int, int]]:
    if lo < 0 or hi <= lo or chunk <= 0:
        raise PrimeIdentityError("invalid audit interval or chunk width")
    ranges = []
    cursor = lo
    chunk_id = 1
    while cursor < hi:
        end = min(cursor + chunk, hi)
        ranges.append((chunk_id, cursor, end))
        cursor = end
        chunk_id += 1
    return ranges


def load_campaign_manifest(
    root: Path, interval: dict, expected_ranges: list[tuple[int, int, int]]
) -> tuple[dict, dict]:
    campaign_path = _repository_file(
        root, CAMPAIGN_MANIFEST_PATH, "campaign manifest"
    )
    try:
        campaign = json.loads(
            campaign_path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PrimeIdentityError(f"invalid campaign JSON constant {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrimeIdentityError(f"cannot parse campaign manifest: {exc}") from exc
    # The campaign archive records its frozen chunk count in addition to the
    # three geometric fields carried by the prime-identity manifest.  Keep the
    # latter schema narrow, but compare the recovered campaign against its
    # actual four-field interval contract.
    campaign_interval = {"chunk_count": len(expected_ranges), **interval}
    if (
        not isinstance(campaign, dict)
        or campaign.get("interval") != campaign_interval
    ):
        raise PrimeIdentityError("campaign manifest interval differs from prime audit")
    chunks = campaign.get("chunks")
    if not isinstance(chunks, list) or len(chunks) != len(expected_ranges):
        raise PrimeIdentityError(
            "campaign manifest chunk count differs from prime audit"
        )
    actual_ranges = []
    for row in chunks:
        if not isinstance(row, dict):
            raise PrimeIdentityError("campaign manifest contains a non-object chunk")
        values = (
            row.get("chunk_id"),
            row.get("lower_inclusive"),
            row.get("upper_exclusive"),
        )
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in values):
            raise PrimeIdentityError("campaign manifest chunk range is malformed")
        actual_ranges.append(values)
    if actual_ranges != expected_ranges:
        raise PrimeIdentityError("campaign manifest ranges differ from prime audit")
    return campaign, artifact_identity(
        root, CAMPAIGN_MANIFEST_PATH, "campaign manifest"
    )


def run_audit(
    root: Path,
    scanner: Path,
    independent: Path,
    lo: int,
    hi: int,
    chunk: int,
    *,
    install_binaries: bool = True,
) -> dict:
    root = root.resolve(strict=True)
    ranges = _expected_ranges(lo, hi, chunk)
    interval = {
        "chunk_width": chunk,
        "lower_inclusive": lo,
        "upper_exclusive": hi,
    }
    _, campaign_identity = load_campaign_manifest(root, interval, ranges)
    scanner_binary, independent_binary, executables = prepare_executables(
        root, scanner, independent, install=install_binaries
    )
    rows = []
    for chunk_id, lower, upper in ranges:
        rows.append(
            audit_chunk(
                scanner_binary,
                independent_binary,
                lower,
                upper,
                chunk_id=chunk_id,
                scanner_binary_path=executables["scanner"]["binary"]["path"],
                independent_binary_path=executables["independent"]["binary"][
                    "path"
                ],
            )
        )
    require_unchanged_identity(root, campaign_identity, "campaign manifest")
    for role in ("scanner", "independent"):
        require_unchanged_identity(
            root, executables[role]["source"], f"{role} source"
        )
        require_unchanged_identity(
            root, executables[role]["binary"], f"{role} evidence binary"
        )
    return {
        "campaign_manifest": campaign_identity,
        "chunks": rows,
        "executables": executables,
        "interval": interval,
        "schema": SCHEMA,
        "totals": {
            "all_byte_equal": all(row["byte_equal"] for row in rows),
            "chunk_count": len(rows),
            "prime_count": sum(row["count"] for row in rows),
            "stream_bytes": sum(row["scanner"]["stdout_bytes"] for row in rows),
        },
    }


def canonical_json(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def write_manifest(path: Path, manifest: dict) -> None:
    if path.exists() or path.is_symlink():
        raise PrimeIdentityError(f"refusing to overwrite existing manifest: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise PrimeIdentityError(f"temporary manifest path already exists: {temporary}")
    try:
        temporary.write_text(canonical_json(manifest), encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _resolved_argument(path: Path) -> Path:
    if path.is_absolute():
        return path
    return Path.cwd() / path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the checkout containing this tool)",
    )
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--independent", type=Path, required=True)
    parser.add_argument("--lo", type=int, default=970_000_000)
    parser.add_argument("--hi", type=int, default=2_000_000_000)
    parser.add_argument("--chunk", type=int, default=2_000_000)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path)
    destination.add_argument(
        "--check",
        type=Path,
        metavar="MANIFEST",
        help="rerun installed binaries and require byte-identical canonical JSON",
    )
    args = parser.parse_args()
    try:
        root = args.root.resolve(strict=True)
        expected_output = root / OUTPUT_MANIFEST_PATH
        requested_output = _resolved_argument(args.output or args.check).resolve()
        if requested_output != expected_output:
            raise PrimeIdentityError(
                f"manifest path must be exactly {OUTPUT_MANIFEST_PATH}"
            )
        if args.output is not None and (
            expected_output.exists() or expected_output.is_symlink()
        ):
            raise PrimeIdentityError(
                f"refusing to overwrite existing manifest: {expected_output}"
            )
        if args.check is not None and (
            not expected_output.is_file() or expected_output.is_symlink()
        ):
            raise PrimeIdentityError(
                f"existing manifest is missing or not a regular file: {expected_output}"
            )
        manifest = run_audit(
            root,
            _resolved_argument(args.scanner),
            _resolved_argument(args.independent),
            args.lo,
            args.hi,
            args.chunk,
            install_binaries=args.output is not None,
        )
        if args.check is not None:
            try:
                actual = expected_output.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise PrimeIdentityError(
                    f"cannot read existing manifest: {exc}"
                ) from exc
            if actual != canonical_json(manifest):
                raise PrimeIdentityError("existing manifest differs from rerun")
        else:
            write_manifest(expected_output, manifest)
    except PrimeIdentityError as exc:
        raise SystemExit(f"prime identity audit failed: {exc}") from exc
    print(
        f"PASS: {manifest['totals']['chunk_count']} chunks, "
        f"{manifest['totals']['prime_count']} primes, byte-identical streams"
    )


if __name__ == "__main__":
    main()
