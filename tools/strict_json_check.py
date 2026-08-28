#!/usr/bin/env python3
"""Reject non-canonical or unsafe JSON features in repository JSON files."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", "__pycache__", "build", "dist"}
# Recurrence closure deliberately contains exact mathematical integers larger
# than machine words.  All operational manifests remain 64-bit bounded.
ARBITRARY_INTEGER_FILES = {Path("audit/generated/bounds_closure.json")}


class StrictJSONError(ValueError):
    pass


def pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def finite_constant(value):
    raise StrictJSONError(f"non-finite numeric constant {value}")


def bounded_int(value):
    number = int(value)
    if not -(1 << 63) <= number < (1 << 64):
        raise StrictJSONError("integer outside supported signed/unsigned 64-bit domain")
    return number


def reject_surrogates(value, location="$"):
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise StrictJSONError(f"Unicode surrogate at {location}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_surrogates(item, f"{location}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            reject_surrogates(key, f"{location}.<key>")
            reject_surrogates(item, f"{location}.{key}")
    elif isinstance(value, float) and not math.isfinite(value):
        raise StrictJSONError(f"non-finite float at {location}")


def load_strict(path: Path, *, allow_arbitrary_integers: bool = False):
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise StrictJSONError("UTF-8 BOM is forbidden")
    text = raw.decode("utf-8", errors="strict")
    value = json.loads(
        text,
        object_pairs_hook=pairs_no_duplicates,
        parse_constant=finite_constant,
        parse_int=int if allow_arbitrary_integers else bounded_int,
    )
    reject_surrogates(value)
    return value


def repository_json_files(root: Path):
    for path in sorted(root.rglob("*.json")):
        if not any(part in SKIP_PARTS for part in path.relative_to(root).parts):
            yield path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()
    paths = args.paths or list(repository_json_files(ROOT))
    try:
        for path in paths:
            try:
                relative = path.resolve().relative_to(ROOT.resolve())
            except ValueError:
                relative = None
            load_strict(
                path,
                allow_arbitrary_integers=relative in ARBITRARY_INTEGER_FILES,
            )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StrictJSONError) as exc:
        print(f"STRICT_JSON_REJECT: {path}: {exc}")
        return 1
    print(f"PASS: {len(paths)} strict JSON files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
