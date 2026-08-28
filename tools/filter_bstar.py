#!/usr/bin/env python3
"""Reproduce the B* filter for the committed complete (3,17) survivor list."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "results" / "valid_3_17" / "valid_3_17_full.txt"
OUTPUT = ROOT / "results" / "valid_3_17" / "valid_3_17_ab_full.txt"
SUMS = ROOT / "results" / "valid_3_17" / "SHA256SUMS"
COLORS = 3
LENGTH = 17
SPLIT = 1_330_000_000


class FilterError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_prime32(value: int) -> bool:
    if value < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small:
        if value % prime == 0:
            return value == prime
    odd = value - 1
    power = 0
    while odd % 2 == 0:
        odd //= 2
        power += 1
    for base in (2, 3, 5, 7, 11):
        witness = pow(base, odd, value)
        if witness in (1, value - 1):
            continue
        for _ in range(power - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def parse_survivors(data: bytes) -> list[int]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise FilterError(f"input is not strict UTF-8: {exc}") from exc
    if not text.endswith("\n"):
        raise FilterError("input must end with a newline")
    values = []
    number_seen = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise FilterError(f"blank input line {line_number}")
        if line.startswith("#") and not number_seen:
            continue
        number_seen = True
        if not line.isascii() or not line.isdecimal():
            raise FilterError(f"non-canonical prime at line {line_number}")
        value = int(line)
        if value <= LENGTH or value >= 1 << 32 or (value - 1) % COLORS:
            raise FilterError(f"prime outside the (3,17) domain at line {line_number}")
        if not is_prime32(value):
            raise FilterError(f"composite value at line {line_number}: {value}")
        if values and value <= values[-1]:
            raise FilterError("input primes must be strictly increasing and unique")
        values.append(value)
    if not values:
        raise FilterError("input contains no primes")
    return values


def boundary_ok(prime: int, colors: int = COLORS, length: int = LENGTH) -> bool:
    """Evaluate Rabung's boundary condition without scanner or walk code."""

    if not is_prime32(prime) or colors < 2 or length < 2:
        raise FilterError("invalid boundary-check parameters")
    if (prime - 1) % colors or prime <= length:
        raise FilterError("Rabung preconditions do not hold")
    minus_one_class = ((prime - 1) // 2) % colors
    if minus_one_class == 0:
        endpoint = (length - 1 + 1) // 2
    elif colors % 2 == 0 and minus_one_class == colors // 2:
        endpoint = length - 1
    else:
        raise FilterError("theta(-1) is neither +1 nor -1")
    exponent = (prime - 1) // colors
    characters = {pow(value, exponent, prime) for value in range(1, endpoint + 1)}
    return len(characters) > 1


def render(values: list[int]) -> bytes:
    accepted = [prime for prime in values if boundary_ok(prime)]
    before = [prime for prime in values if prime < SPLIT]
    before_ok = [prime for prime in before if boundary_ok(prime)]
    after = [prime for prime in values if prime >= SPLIT]
    after_ok = [prime for prime in after if boundary_ok(prime)]
    lines = [
        "# Liste COMPLETE des (3,17) (a)^(b)-valides -- "
        f"{len(accepted)} premiers (2026-07-25)",
        "# = valid_3_17_full.txt filtre par tools/filter_bstar.py "
        "(condition B*, O(k log p)/premier).",
        f"# Tally : {len(values)} lus, {len(accepted)} acceptes, "
        f"{len(values) - len(accepted)} rejets-(b) = "
        f"{100 * (len(values) - len(accepted)) / len(values):.3f} %.",
        f"# Decoupe au gel (p < 1.33e9) : pre-gel {len(before)}/{len(before_ok)} "
        f"({100 * (len(before) - len(before_ok)) / len(before):.3f} %), "
        f"post-gel {len(after)}/{len(after_ok)} "
        f"({100 * (len(after) - len(after_ok)) / len(after):.3f} %).",
        "# Reproductible par tools/filter_bstar.py --check; aucun audit "
        "conversationnel n'est une entree.",
        *(str(prime) for prime in accepted),
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def sums_bytes(input_data: bytes, output_data: bytes) -> bytes:
    return (
        f"{sha256(output_data)}  results/valid_3_17/valid_3_17_ab_full.txt\n"
        f"{sha256(input_data)}  results/valid_3_17/valid_3_17_full.txt\n"
    ).encode("ascii")


def atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    input_data = INPUT.read_bytes()
    values = parse_survivors(input_data)
    output_data = render(values)
    expected_sums = sums_bytes(input_data, output_data)
    if args.check:
        if OUTPUT.read_bytes() != output_data:
            raise SystemExit("B* output is stale or non-canonical")
        if SUMS.read_bytes() != expected_sums:
            raise SystemExit("B* SHA256SUMS is stale or non-canonical")
    else:
        atomic_write(OUTPUT, output_data)
        atomic_write(SUMS, expected_sums)
    print(
        f"BSTAR_FILTER_OK input={len(values)} accepted="
        f"{sum(boundary_ok(prime) for prime in values)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
