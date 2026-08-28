#!/usr/bin/env python3
"""Compare exact ordered prime streams from the scanner and an independent sieve.

Both executables must implement ``--dump-primes LO HI`` and emit the canonical
VDW-PRIMES-v1 byte stream.  Equality is checked byte for byte before a per-chunk
SHA-256 is admitted to the manifest.  The scanner mode is CPU-only and must run
before CUDA initialisation, so this audit does not repeat the GPU computation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


class PrimeIdentityError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


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
        if value < lo or value >= hi or value <= previous:
            raise PrimeIdentityError("prime stream is not strictly increasing in range")
        primes.append(value)
        previous = value
    return primes


def canonical_label(label: str, role: str) -> str:
    path = Path(label)
    if not label or path.is_absolute() or ".." in path.parts or path.as_posix() != label:
        raise PrimeIdentityError(f"{role} label must be a canonical relative POSIX path")
    return label


def run_stream(
    executable: Path, label: str, lo: int, hi: int
) -> tuple[bytes, bytes, list[str]]:
    actual_argv = [str(executable), "--dump-primes", str(lo), str(hi)]
    recorded_argv = [label, "--dump-primes", str(lo), str(hi)]
    process = subprocess.run(
        actual_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if process.returncode != 0:
        raise PrimeIdentityError(
            f"{executable}: exit {process.returncode}; stderr={process.stderr[-500:]!r}"
        )
    if process.stderr:
        raise PrimeIdentityError(
            f"{executable}: dump mode must be silent on stderr; got {process.stderr[-500:]!r}"
        )
    return process.stdout, process.stderr, recorded_argv


def audit_chunk(
    scanner: Path,
    independent: Path,
    lo: int,
    hi: int,
    scanner_label: str = "scanner-prime-stream",
    independent_label: str = "independent-prime-stream",
) -> dict:
    scanner_label = canonical_label(scanner_label, "scanner")
    independent_label = canonical_label(independent_label, "independent")
    scanner_data, scanner_stderr, scanner_argv = run_stream(
        scanner, scanner_label, lo, hi
    )
    independent_data, independent_stderr, independent_argv = run_stream(
        independent, independent_label, lo, hi
    )
    scanner_primes = parse_stream(scanner_data, lo, hi)
    independent_primes = parse_stream(independent_data, lo, hi)
    if scanner_data != independent_data:
        mismatch = next(
            (index for index, pair in enumerate(zip(scanner_data, independent_data)) if pair[0] != pair[1]),
            min(len(scanner_data), len(independent_data)),
        )
        raise PrimeIdentityError(
            f"ordered prime streams differ for [{lo},{hi}) at byte {mismatch}; "
            f"counts {len(scanner_primes)} != {len(independent_primes)}"
        )
    digest = hashlib.sha256(scanner_data).hexdigest()
    return {
        "lower_inclusive": lo,
        "upper_exclusive": hi,
        "count": len(scanner_primes),
        "stream_bytes": len(scanner_data),
        "stream_sha256": digest,
        "byte_equal": True,
        "scanner": {
            "argv": scanner_argv,
            "stderr_sha256": hashlib.sha256(scanner_stderr).hexdigest(),
            "stderr_bytes": len(scanner_stderr),
        },
        "independent": {
            "argv": independent_argv,
            "stderr_sha256": hashlib.sha256(independent_stderr).hexdigest(),
            "stderr_bytes": len(independent_stderr),
        },
    }


def run_audit(
    scanner: Path,
    independent: Path,
    lo: int,
    hi: int,
    chunk: int,
    scanner_label: str = "scanner-prime-stream",
    independent_label: str = "independent-prime-stream",
) -> dict:
    if lo < 0 or hi < lo or chunk <= 0:
        raise PrimeIdentityError("invalid audit interval or chunk width")
    scanner = scanner.resolve()
    independent = independent.resolve()
    scanner_label = canonical_label(scanner_label, "scanner")
    independent_label = canonical_label(independent_label, "independent")
    if scanner_label == independent_label:
        raise PrimeIdentityError("scanner and independent labels must differ")
    for executable in (scanner, independent):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise PrimeIdentityError(f"not an executable file: {executable}")
    scanner_sha256 = sha256_file(scanner)
    independent_sha256 = sha256_file(independent)
    if scanner == independent or scanner_sha256 == independent_sha256:
        raise PrimeIdentityError(
            "scanner and independent sieve must be distinct executables"
        )
    rows = []
    cursor = lo
    while cursor < hi:
        end = min(cursor + chunk, hi)
        rows.append(
            audit_chunk(
                scanner,
                independent,
                cursor,
                end,
                scanner_label,
                independent_label,
            )
        )
        cursor = end
    return {
        "schema": "vdw-prime-identity/v1",
        "interval": {"lower_inclusive": lo, "upper_exclusive": hi, "chunk_width": chunk},
        "executables": {
            "scanner": {"label": scanner_label, "sha256": scanner_sha256},
            "independent": {"label": independent_label, "sha256": independent_sha256},
        },
        "chunks": rows,
        "totals": {
            "chunk_count": len(rows),
            "prime_count": sum(row["count"] for row in rows),
            "all_byte_equal": all(row["byte_equal"] for row in rows),
        },
    }


def write_manifest(path: Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--independent", type=Path, required=True)
    parser.add_argument("--scanner-label", default="scanner-prime-stream")
    parser.add_argument("--independent-label", default="independent-prime-stream")
    parser.add_argument("--lo", type=int, default=970_000_000)
    parser.add_argument("--hi", type=int, default=2_000_000_000)
    parser.add_argument("--chunk", type=int, default=2_000_000)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path)
    destination.add_argument(
        "--check", type=Path, metavar="MANIFEST",
        help="rerun the audit and require byte-identical canonical JSON",
    )
    args = parser.parse_args()
    try:
        manifest = run_audit(
            args.scanner,
            args.independent,
            args.lo,
            args.hi,
            args.chunk,
            args.scanner_label,
            args.independent_label,
        )
        if args.check is not None:
            expected = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            if args.check.read_text(encoding="utf-8") != expected:
                raise PrimeIdentityError("existing manifest differs from rerun")
        else:
            write_manifest(args.output, manifest)
    except PrimeIdentityError as exc:
        raise SystemExit(f"prime identity audit failed: {exc}") from exc
    print(
        f"PASS: {manifest['totals']['chunk_count']} chunks, "
        f"{manifest['totals']['prime_count']} primes, byte-identical streams"
    )


if __name__ == "__main__":
    main()
