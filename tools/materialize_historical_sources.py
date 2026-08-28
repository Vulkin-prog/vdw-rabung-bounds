#!/usr/bin/env python3
"""Validate or materialize byte-exact Base64-preserved historical sources."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAP = ROOT / "provenance" / "scanners" / "campaign-source-map.json"
PREREG = ROOT / "publication" / "preregistration-ledger.json"


class HistoricalSourceError(RuntimeError):
    pass


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def decode_entry(root: Path, entry: dict) -> bytes:
    required = {"encoded_path", "decoded_path", "git_blob_sha1", "sha256", "bytes"}
    if set(entry) != required:
        raise HistoricalSourceError("historical artifact has unexpected fields")
    encoded = (root / entry["encoded_path"]).resolve()
    try:
        encoded.relative_to(root.resolve())
    except ValueError as exc:
        raise HistoricalSourceError("encoded path escapes repository") from exc
    try:
        compact = b"".join(encoded.read_bytes().split())
        data = base64.b64decode(compact, validate=True)
    except (OSError, binascii.Error) as exc:
        raise HistoricalSourceError(f"cannot decode {entry['encoded_path']}: {exc}") from exc
    if len(data) != entry["bytes"]:
        raise HistoricalSourceError(f"decoded byte count mismatch: {entry['encoded_path']}")
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise HistoricalSourceError(f"decoded SHA-256 mismatch: {entry['encoded_path']}")
    if git_blob_sha1(data) != entry["git_blob_sha1"]:
        raise HistoricalSourceError(f"Git blob mismatch: {entry['encoded_path']}")
    return data


def load_map(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "vdw-campaign-source-map/v1":
        raise HistoricalSourceError("unsupported source-map schema")
    artifacts = data.get("artifacts")
    revisions = data.get("revisions")
    if not isinstance(artifacts, dict) or len(artifacts) != 11:
        raise HistoricalSourceError("expected four scanners and seven drivers")
    if not isinstance(revisions, list) or len(revisions) != 8:
        raise HistoricalSourceError("expected eight campaign revisions")
    cursor = 1
    for revision in revisions:
        if revision.get("scanner") not in artifacts or revision.get("driver") not in artifacts:
            raise HistoricalSourceError("revision references an unknown artifact")
        if revision.get("first_chunk") != cursor:
            raise HistoricalSourceError("campaign revision ranges are not contiguous")
        if revision.get("last_chunk") - revision.get("first_chunk") + 1 != revision.get("chunks"):
            raise HistoricalSourceError("revision chunk count mismatch")
        cursor = revision["last_chunk"] + 1
    if cursor != 516:
        raise HistoricalSourceError("campaign revisions do not cover chunks 1..515")
    return data


def validate_prereg_tracker(root: Path) -> None:
    ledger = json.loads(PREREG.read_text(encoding="utf-8"))
    tracker = dict(ledger["schedule_freeze"]["tracker"])
    tracker["decoded_path"] = "tools/eta_track.py"
    decode_entry(root, tracker)


def validate(mapping_path: Path = DEFAULT_MAP) -> tuple[dict, dict[str, bytes]]:
    mapping = load_map(mapping_path)
    decoded = {
        name: decode_entry(ROOT, entry)
        for name, entry in sorted(mapping["artifacts"].items())
    }
    validate_prereg_tracker(ROOT)
    return mapping, decoded


def materialize(output_dir: Path, mapping: dict, decoded: dict[str, bytes]) -> None:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in decoded.items():
        suffix = ".cu" if name.startswith("scan_") else ".py"
        target = output_dir / f"{name}{suffix}"
        if target.exists():
            raise HistoricalSourceError(f"refusing to overwrite {target}")
        target.write_bytes(data)
    tracker = json.loads(PREREG.read_text(encoding="utf-8"))["schedule_freeze"]["tracker"]
    tracker_entry = dict(tracker, decoded_path="tools/eta_track.py")
    tracker_target = output_dir / "eta_track.py"
    if tracker_target.exists():
        raise HistoricalSourceError(f"refusing to overwrite {tracker_target}")
    tracker_target.write_bytes(decode_entry(ROOT, tracker_entry))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if not args.check and args.output_dir is None:
        parser.error("choose --check or --output-dir")
    try:
        mapping, decoded = validate()
        if args.output_dir is not None:
            materialize(args.output_dir, mapping, decoded)
    except (HistoricalSourceError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"HISTORICAL_SOURCE_REJECT: {exc}")
        return 1
    print("PASS: 4 scanner blobs, 7 driver blobs, 8 revisions, 515 chunks, and tracker validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
