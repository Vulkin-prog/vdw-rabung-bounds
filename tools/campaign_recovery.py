#!/usr/bin/env python3
"""Recover the historical 515-chunk campaign without touching its source.

The pipeline has five deliberately separate stages:

``validate-inventory``
    Authenticate and parse the explicitly public-campaign-scoped, read-only
    output of ``scripts/inventory_pc.sh``. Any path outside
    ``results/campaign/`` is rejected.
``propose-selection``
    Produce a complete review ledger.  Nothing is selected automatically.
``import``
    Recheck every selected byte against the inventory and copy it to a new,
    repository-shaped staging directory.  The source checkout is never opened
    for writing.
``build``
    Derive one strict 515-row campaign manifest from the shared checkpoint and
    one or more campaign journals.  It does not manufacture 515 pretend raw
    files.
``check``
    Rebuild the manifest in memory and require byte-identical canonical JSON.

The historical checkpoint is the common evidence object for all chunk rows.
Chunk 7 is treated explicitly: its checkpoint key must exist for
``[982000000,984000000)``, its revision must resolve to ``ebd54ea...``, and the
combined campaign journals must contain no chunk-7 row while containing every
other row.  The preserved historical driver is decoded and authenticated
before its checkpoint-before-journal ordering is accepted.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import unicodedata
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]

INVENTORY_SCHEMA = "vdw-pc-read-only-inventory/v2"
INVENTORY_SCOPE = {
    "mode": "public_campaign_only",
    "path": "results/campaign/",
}
SELECTION_SCHEMA = "vdw-campaign-recovery-selection/v1"
RECEIPT_SCHEMA = "vdw-campaign-recovery-import/v1"
CAMPAIGN_SCHEMA = "vdw-campaign-archive/v1"
SOURCE_MAP_SCHEMA = "vdw-campaign-source-map/v1"

CAMPAIGN_LOWER = 970_000_000
CAMPAIGN_UPPER = 2_000_000_000
CAMPAIGN_WIDTH = 2_000_000
CAMPAIGN_CHUNKS = 515
CHUNK7_LOWER = 982_000_000
CHUNK7_UPPER = 984_000_000

INVENTORY_FILES = (
    "candidate-files.jsonl",
    "git-ignored.z",
    "git-status-v2.z",
    "git-untracked.z",
    "metadata.json",
)
INVENTORY_ARCHIVE_FILES = tuple(sorted((*INVENTORY_FILES, "inventory-files.sha256")))
INVENTORY_METADATA_KEYS = {
    "branch",
    "candidate_count",
    "commit_date",
    "completed_utc",
    "git_commit",
    "git_tree",
    "ignored_path_count",
    "inventory_errors",
    "schema",
    "scope",
    "source_checkout_name",
    "started_utc",
    "untracked_path_count",
}
SELECTION_ENTRY_KEYS = {
    "decision",
    "destination_path",
    "reason",
    "role",
    "size",
    "source_path",
    "source_sha256",
    "source_type",
    "suggested_destination_path",
    "suggested_role",
}
ALLOWED_ROLES = {
    "authoritative_checkpoint",
    "campaign_daily",
    "auxiliary_unparsed",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHORT_REV_RE = re.compile(r"^[0-9a-f]{7,40}$")
DAILY_CHUNK_RE = re.compile(
    r"^\s*-\s+chunk\s+([0-9]+)/([0-9]+)\s+p~([0-9]+\.[0-9]{3})e9\b"
)
GENERIC_DAILY_CHUNK_RE = re.compile(r"^\s*-\s+chunk\b", re.IGNORECASE)
CHUNK7_REFERENCE_RE = re.compile(
    r"(?:\bchunk\s*(?:#\s*)?0*7\s*(?:/|of|sur)\s*515\b|"
    r"982000000\s*[-,]\s*984000000|p\s*[~=:]?\s*0\.982\s*e9)",
    re.IGNORECASE,
)

EXPECTED_REVISIONS = (
    (1, 7, "ebd54ea0fbdf78287392e9be80b2578618964975", "scan_9cef0b03", "campaign_ebd54ea"),
    (8, 17, "657a140a1d907a54d168c4e37b4d79c774fef539", "scan_b2c529cc", "campaign_657a140"),
    (18, 35, "185b8680172bb4e20be1d7765f72cda3d26cf72d", "scan_b2c529cc", "campaign_185b868"),
    (36, 78, "062cc3cdf97ff2d158b907ed3d62c2f68884e89b", "scan_09a89151", "campaign_062cc3c"),
    (79, 79, "4f9e2cf8e56c659684d2bb7269d65a89f68069b8", "scan_8e22d632", "campaign_4f9e2cf"),
    (80, 353, "c3a9b9eb318f63720146c03d3032de7d5c9183e0", "scan_8e22d632", "campaign_c3a9b9e"),
    (354, 425, "a93cec91826d73df4200903bda941a9c805929ff", "scan_8e22d632", "campaign_a93cec9"),
    (426, 515, "7c1ba34b1cb09dc0bf5fd08ffc4ef2812075f066", "scan_8e22d632", "campaign_a93cec9"),
)

EXPECTED_SOURCE_ARTIFACTS = {
    "campaign_062cc3c": {
        "bytes": 13_545,
        "decoded_path": "src/campaign.py",
        "encoded_path": "provenance/scanners/historical/campaign_062cc3c.py.base64",
        "git_blob_sha1": "f5bad86c67cfcfe6da426260417332ccae279059",
        "sha256": "d796c55bcf35d5e7b67efd50bbfbd5cc2bfbf59dbd2e6b3c5046db58b36682e4",
    },
    "campaign_185b868": {
        "bytes": 12_253,
        "decoded_path": "src/campaign.py",
        "encoded_path": "provenance/scanners/historical/campaign_185b868.py.base64",
        "git_blob_sha1": "3e4481648ea18c18b4f34b68e0d0ceb460617abf",
        "sha256": "872cf7781626ccb042587d9c64682eed4bae2bc76560de1b01dccb1d7f0b6802",
    },
    "campaign_4f9e2cf": {
        "bytes": 14_830,
        "decoded_path": "src/campaign.py",
        "encoded_path": "provenance/scanners/historical/campaign_4f9e2cf.py.base64",
        "git_blob_sha1": "525353d099fad3d786f0bfa82e90d400a7e1e657",
        "sha256": "d68890ebeb5bef4439df81532d2e7ffa339f6760110e21bb68e72e5bd73caabe",
    },
    "campaign_657a140": {
        "bytes": 11_893,
        "decoded_path": "src/campaign.py",
        "encoded_path": "provenance/scanners/historical/campaign_657a140.py.base64",
        "git_blob_sha1": "6a2d1715b0b2d929638320220a9bad3f0444a9f1",
        "sha256": "332faf161d6aed2649c1c025ba927a893f73af1c48afdeea5923f10e32358389",
    },
    "campaign_a93cec9": {
        "bytes": 16_355,
        "decoded_path": "src/campaign.py",
        "encoded_path": "provenance/scanners/historical/campaign_a93cec9.py.base64",
        "git_blob_sha1": "dc06cf3f8f494f5bc4aedec739dda6289e26ef61",
        "sha256": "de4637a4a9c96b16320a94093f5c122446812a2fde08d09b5c42a103f38283d1",
    },
    "campaign_c3a9b9e": {
        "bytes": 14_962,
        "decoded_path": "src/campaign.py",
        "encoded_path": "provenance/scanners/historical/campaign_c3a9b9e.py.base64",
        "git_blob_sha1": "4b2e630a6f24d02836c85263287fc9168472a696",
        "sha256": "af952ab12c3b2fe8f0b9357583680b5a02db0268a130f909052527d55d0d650b",
    },
    "campaign_ebd54ea": {
        "bytes": 8_289,
        "decoded_path": "src/campaign.py",
        "encoded_path": "provenance/scanners/historical/campaign_ebd54ea.py.base64",
        "git_blob_sha1": "314ce77fc5377bd84648d688960ce275bb04f1a7",
        "sha256": "2d7c27d86ec1e07f98bf4bbe59575b46f438cbcb7b4a1f35ad0bc725f973af37",
    },
    "scan_09a89151": {
        "bytes": 46_748,
        "decoded_path": "src/scan_gpu.cu",
        "encoded_path": "provenance/scanners/historical/scan_gpu_09a89151.cu.base64",
        "git_blob_sha1": "09a89151f78f3d89f5e5c03b8c9802436df352f8",
        "sha256": "cca301fe923b661643ebc33eee68db0bbc63d68cea2c16740c0701a6ca39d31e",
    },
    "scan_8e22d632": {
        "bytes": 47_870,
        "decoded_path": "src/scan_gpu.cu",
        "encoded_path": "provenance/scanners/historical/scan_gpu_8e22d632.cu.base64",
        "git_blob_sha1": "8e22d6329f9c7cd6e193763bfc835afda06200a5",
        "sha256": "3b5d1049c4695e3e2f7854aeceef731cc801142df503f4248fcb2cc5924d5c7e",
    },
    "scan_9cef0b03": {
        "bytes": 43_494,
        "decoded_path": "src/scan_gpu.cu",
        "encoded_path": "provenance/scanners/historical/scan_gpu_9cef0b03.cu.base64",
        "git_blob_sha1": "9cef0b03fdf5f0db5b7fe85221e4961634f92080",
        "sha256": "87f10166f15cf7d9f0dd0c7b51cd943220cdbe7d51f0f995b901c34921b6ce92",
    },
    "scan_b2c529cc": {
        "bytes": 45_359,
        "decoded_path": "src/scan_gpu.cu",
        "encoded_path": "provenance/scanners/historical/scan_gpu_b2c529cc.cu.base64",
        "git_blob_sha1": "b2c529cc723d9283dc6ff375c7aeaa061a3d0b5b",
        "sha256": "3598aea6115e05cfeec8d00f569c466ea5c39b9811db2060e872e7dada9ae62e",
    },
}


class RecoveryError(RuntimeError):
    """One recovery invariant failed."""


def fail(message: str) -> None:
    raise RecoveryError(message)


def _no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value):
    fail(f"non-finite JSON constant {value}")


def _reject_unsafe_json(value, location: str = "$") -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            fail(f"Unicode surrogate at {location}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_unsafe_json(item, f"{location}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_unsafe_json(key, f"{location}.<key>")
            _reject_unsafe_json(item, f"{location}.{key}")
    elif isinstance(value, float) and not math.isfinite(value):
        fail(f"non-finite JSON number at {location}")


def load_json_bytes(raw: bytes, label: str):
    if raw.startswith(b"\xef\xbb\xbf"):
        fail(f"{label}: UTF-8 BOM is forbidden")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_no_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label}: invalid JSON: {exc}")
    _reject_unsafe_json(value)
    return value


def load_json(path: Path):
    try:
        return load_json_bytes(path.read_bytes(), str(path))
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")


def canonical_json_bytes(value) -> bytes:
    _reject_unsafe_json(value)
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    raw = read_absolute_snapshot(path, f"file {path}")
    return sha256_bytes(raw)


def is_integer(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def exact_keys(value, expected: set[str], label: str) -> None:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    if set(value) != expected:
        fail(
            f"{label} keys differ: missing={sorted(expected - set(value))}, "
            f"extra={sorted(set(value) - expected)}"
        )


def canonical_relative_path(value, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        fail(f"{label} must be a non-empty canonical POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or unicodedata.normalize("NFC", value) != value
    ):
        fail(f"{label} is not canonical: {value!r}")
    return value


def canonical_under(value, prefix: str, label: str) -> str:
    value = canonical_relative_path(value, label)
    if not value.startswith(prefix):
        fail(f"{label} must be below {prefix!r}: {value!r}")
    return value


def regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        fail(f"{label} is unavailable: {exc}")
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file: {path}")


def _inode_identity(metadata) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def _file_identity(metadata) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_regular_snapshot(root: Path, relative: str, label: str) -> bytes:
    """Read one path through an ``openat`` chain and reject every race.

    Keeping each parent directory descriptor open prevents path-component
    substitution while the file is streamed.  Re-looking-up every component
    and the final file before returning closes the remaining rename window.
    """

    relative = canonical_relative_path(relative, f"{label} path")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        fail(f"{label} root is unavailable: {exc}")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    file_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
        file_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
        file_flags |= os.O_NOFOLLOW

    descriptors: list[int] = []
    chain: list[tuple[int, str, int]] = []
    file_descriptor: int | None = None
    try:
        root_descriptor = os.open(resolved_root, directory_flags)
        descriptors.append(root_descriptor)
        if not stat.S_ISDIR(os.fstat(root_descriptor).st_mode):
            fail(f"{label} root is not a directory")
        parent_descriptor = root_descriptor
        parts = PurePosixPath(relative).parts
        for component in parts[:-1]:
            child_descriptor = os.open(component, directory_flags, dir_fd=parent_descriptor)
            if not stat.S_ISDIR(os.fstat(child_descriptor).st_mode):
                os.close(child_descriptor)
                fail(f"{label} path component is not a directory: {component}")
            descriptors.append(child_descriptor)
            chain.append((parent_descriptor, component, child_descriptor))
            parent_descriptor = child_descriptor

        final_name = parts[-1]
        file_descriptor = os.open(final_name, file_flags, dir_fd=parent_descriptor)
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"{label} must be a regular non-symlink file")
        blocks = []
        while True:
            block = os.read(file_descriptor, 8 * 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        after = os.fstat(file_descriptor)
        current = os.stat(final_name, dir_fd=parent_descriptor, follow_symlinks=False)
        if _file_identity(before) != _file_identity(after) or _file_identity(after) != _file_identity(current):
            fail(f"{label} changed while it was read")
        raw = b"".join(blocks)
        if len(raw) != after.st_size:
            fail(f"{label} byte count changed while it was read")

        for parent, component, child in chain:
            current_component = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if _inode_identity(current_component) != _inode_identity(os.fstat(child)):
                fail(f"{label} path component changed while it was read: {component}")
        root_current = os.stat(resolved_root, follow_symlinks=False)
        if _inode_identity(root_current) != _inode_identity(os.fstat(root_descriptor)):
            fail(f"{label} root changed while it was read")
        return raw
    except RecoveryError:
        raise
    except OSError as exc:
        fail(f"cannot read {label}: {exc}")
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def read_absolute_snapshot(path: Path, label: str) -> bytes:
    return read_regular_snapshot(path.parent, path.name, label)


def artifact_snapshot(repository_root: Path, relative: str) -> tuple[dict, bytes]:
    relative = canonical_relative_path(relative, "artifact path")
    raw = read_regular_snapshot(repository_root, relative, f"artifact {relative}")
    return {"path": relative, "sha256": sha256_bytes(raw), "size": len(raw)}, raw


def artifact_identity(repository_root: Path, relative: str) -> dict:
    identity, _ = artifact_snapshot(repository_root, relative)
    return identity


def _publish_new(temporary: Path, destination: Path) -> None:
    """Publish a same-directory temporary without an overwrite race."""

    try:
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError:
        fail(f"refusing to overwrite {destination}")
    except OSError as exc:
        fail(f"cannot publish {destination}: {exc}")
    try:
        temporary.unlink()
    except OSError as exc:
        fail(f"published {destination}, but cannot remove temporary file: {exc}")


def atomic_write(path: Path, data: bytes, *, replace: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not replace and (path.exists() or path.is_symlink()):
        fail(f"refusing to overwrite {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        fail(f"temporary output already exists: {temporary}")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        if replace:
            os.replace(temporary, path)
        else:
            _publish_new(temporary, path)
    except RecoveryError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        fail(f"cannot write {path}: {exc}")


def parse_checksum_bytes(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"cannot read inventory checksum list: {exc}")
    if text and not text.endswith("\n"):
        fail("inventory checksum list must end with a newline")
    rows: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match:
            fail(f"inventory checksum line {line_number} is malformed")
        digest, name = match.groups()
        if name in rows:
            fail(f"duplicate inventory checksum for {name}")
        rows[name] = digest
    if set(rows) != set(INVENTORY_FILES):
        fail(
            "inventory checksum set differs: "
            f"missing={sorted(set(INVENTORY_FILES) - set(rows))}, "
            f"extra={sorted(set(rows) - set(INVENTORY_FILES))}"
        )
    return rows


def _validate_nul_bytes(raw: bytes, expected_count: int, label: str) -> list[bytes]:
    if raw and not raw.endswith(b"\0"):
        fail(f"{label} is not a canonical NUL-terminated Git path stream")
    if raw.count(b"\0") != expected_count:
        fail(f"{label} count differs: {raw.count(b'\0')} != {expected_count}")
    entries = raw.split(b"\0")[:-1] if raw else []
    if any(not entry for entry in entries):
        fail(f"{label} contains an empty Git path")
    if len(entries) != len(set(entries)):
        fail(f"{label} contains duplicate Git paths")
    return entries


def _require_scoped_git_path(raw: bytes, label: str) -> None:
    try:
        value = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail(f"{label} is not a canonical UTF-8 repository path")
    if value == INVENTORY_SCOPE["path"]:
        return
    canonical_under(value, INVENTORY_SCOPE["path"], label)


def _validate_scoped_status(raw: bytes) -> None:
    if raw and not raw.endswith(b"\0"):
        fail("Git status inventory is not a canonical NUL-terminated porcelain-v2 stream")
    tokens = raw.split(b"\0")[:-1] if raw else []
    if any(not token for token in tokens):
        fail("Git status inventory contains an empty porcelain-v2 token")
    expect_original = False
    for index, token in enumerate(tokens):
        if expect_original:
            _require_scoped_git_path(token, f"Git status original path token {index}")
            expect_original = False
            continue
        if token.startswith(b"# "):
            continue
        if token.startswith((b"? ", b"! ")):
            path = token[2:]
        elif token.startswith(b"1 "):
            fields = token.split(b" ", 8)
            if len(fields) != 9:
                fail(f"Git status ordinary record {index} is malformed")
            path = fields[8]
        elif token.startswith(b"2 "):
            fields = token.split(b" ", 9)
            if len(fields) != 10:
                fail(f"Git status rename record {index} is malformed")
            path = fields[9]
            expect_original = True
        elif token.startswith(b"u "):
            fields = token.split(b" ", 10)
            if len(fields) != 11:
                fail(f"Git status unmerged record {index} is malformed")
            path = fields[10]
        else:
            fail(f"Git status record {index} has an unsupported porcelain-v2 type")
        _require_scoped_git_path(path, f"Git status path token {index}")
    if expect_original:
        fail("Git status rename record lacks its original path token")


def validate_inventory(directory: Path) -> dict:
    directory = directory.resolve()
    if not directory.is_dir():
        fail(f"inventory directory does not exist: {directory}")
    snapshots = {
        "inventory-files.sha256": read_regular_snapshot(
            directory, "inventory-files.sha256", "inventory checksum list"
        )
    }
    checksums = parse_checksum_bytes(snapshots["inventory-files.sha256"])
    for name in INVENTORY_FILES:
        raw = read_regular_snapshot(directory, name, f"inventory artifact {name}")
        snapshots[name] = raw
        actual = sha256_bytes(raw)
        if actual != checksums[name]:
            fail(f"inventory artifact hash mismatch for {name}: {actual} != {checksums[name]}")

    metadata = load_json_bytes(snapshots["metadata.json"], "metadata.json")
    exact_keys(metadata, INVENTORY_METADATA_KEYS, "inventory metadata")
    if metadata["schema"] != INVENTORY_SCHEMA:
        fail(f"inventory schema must be {INVENTORY_SCHEMA}")
    if metadata["scope"] != INVENTORY_SCOPE:
        fail(f"inventory scope must be exactly {INVENTORY_SCOPE}")
    if not SHA1_RE.fullmatch(str(metadata["git_commit"])):
        fail("inventory git_commit must be a full lowercase SHA-1")
    if not SHA1_RE.fullmatch(str(metadata["git_tree"])):
        fail("inventory git_tree must be a full lowercase SHA-1")
    for key in ("candidate_count", "ignored_path_count", "untracked_path_count"):
        if not is_integer(metadata[key]) or metadata[key] < 0:
            fail(f"inventory {key} must be a non-negative integer")
    for key in ("branch", "commit_date", "completed_utc", "source_checkout_name", "started_utc"):
        if not isinstance(metadata[key], str) or not metadata[key]:
            fail(f"inventory {key} must be a non-empty string")
    if metadata["inventory_errors"] != []:
        fail(f"inventory reports read errors: {metadata['inventory_errors']!r}")

    records: list[dict] = []
    previous = None
    lines = snapshots["candidate-files.jsonl"].splitlines()
    for line_number, raw in enumerate(lines, 1):
        if not raw:
            fail(f"empty candidate JSONL row {line_number}")
        record = load_json_bytes(raw, f"candidate-files.jsonl:{line_number}")
        if not isinstance(record, dict):
            fail(f"candidate row {line_number} must be an object")
        kind = record.get("type")
        base_keys = {"mtime_ns", "path", "size", "type"}
        expected = {
            "regular": base_keys | {"sha256", "stable_during_read"},
            "symlink": base_keys | {"target"},
            "other": base_keys,
        }.get(kind)
        if expected is None:
            fail(f"candidate row {line_number} has unsupported type {kind!r}")
        exact_keys(record, expected, f"candidate row {line_number}")
        path = canonical_relative_path(record["path"], f"candidate row {line_number} path")
        if not path.startswith(INVENTORY_SCOPE["path"]):
            fail(f"candidate {path} is outside the authenticated public campaign scope")
        if previous is not None and path <= previous:
            fail("candidate inventory paths are duplicated or not strictly sorted")
        previous = path
        if not is_integer(record["mtime_ns"]) or record["mtime_ns"] < 0:
            fail(f"candidate {path} has invalid mtime_ns")
        if not is_integer(record["size"]) or record["size"] < 0:
            fail(f"candidate {path} has invalid size")
        if kind == "regular":
            if not SHA256_RE.fullmatch(str(record["sha256"])):
                fail(f"candidate {path} has malformed SHA-256")
            if record["stable_during_read"] is not True:
                fail(f"candidate {path} changed during inventory")
        elif kind == "symlink" and not isinstance(record["target"], str):
            fail(f"candidate symlink {path} has a non-string target")
        records.append(record)
    if len(records) != metadata["candidate_count"]:
        fail(f"candidate count differs: {len(records)} != {metadata['candidate_count']}")
    ignored_entries = _validate_nul_bytes(
        snapshots["git-ignored.z"], metadata["ignored_path_count"], "ignored path inventory"
    )
    untracked_entries = _validate_nul_bytes(
        snapshots["git-untracked.z"], metadata["untracked_path_count"], "untracked path inventory"
    )
    for label, entries in (
        ("ignored path inventory", ignored_entries),
        ("untracked path inventory", untracked_entries),
    ):
        for index, entry in enumerate(entries):
            _require_scoped_git_path(entry, f"{label} entry {index}")
    _validate_scoped_status(snapshots["git-status-v2.z"])

    commitment = {
        "candidate_files_sha256": checksums["candidate-files.jsonl"],
        "inventory_files_sha256": sha256_bytes(snapshots["inventory-files.sha256"]),
        "metadata_sha256": checksums["metadata.json"],
        "source_git_commit": metadata["git_commit"],
        "source_git_tree": metadata["git_tree"],
    }
    return {
        "directory": directory,
        "metadata": metadata,
        "records": records,
        "record_by_path": {record["path"]: record for record in records},
        "commitment": commitment,
        "snapshots": snapshots,
    }


def suggested_role(path: str, kind: str) -> str | None:
    if kind != "regular":
        return None
    name = PurePosixPath(path).name.casefold()
    if name == "checkpoint.json":
        return "authoritative_checkpoint"
    if name == "campaign_daily.md" or ("campaign" in name and "daily" in name):
        return "campaign_daily"
    return "auxiliary_unparsed"


def suggested_destination(path: str, kind: str) -> str | None:
    if kind != "regular":
        return None
    prefix = "results/campaign/"
    suffix = path[len(prefix):] if path.startswith(prefix) else f"source/{path}"
    return canonical_under(f"results/campaign/raw/{suffix}", "results/campaign/raw/", "suggested destination")


def make_selection_document(inventory: dict) -> dict:
    entries = []
    for record in inventory["records"]:
        entries.append(
            {
                "decision": "review",
                "destination_path": None,
                "reason": "",
                "role": None,
                "size": record["size"],
                "source_path": record["path"],
                "source_sha256": record.get("sha256"),
                "source_type": record["type"],
                "suggested_destination_path": suggested_destination(record["path"], record["type"]),
                "suggested_role": suggested_role(record["path"], record["type"]),
            }
        )
    return {
        "schema": SELECTION_SCHEMA,
        "status": "proposed",
        "inventory": inventory["commitment"],
        "files": entries,
    }


def validate_selection(selection, inventory: dict | None, *, require_approved: bool) -> list[dict]:
    exact_keys(selection, {"files", "inventory", "schema", "status"}, "recovery selection")
    if selection["schema"] != SELECTION_SCHEMA:
        fail(f"selection schema must be {SELECTION_SCHEMA}")
    if selection["status"] not in {"proposed", "approved"}:
        fail("selection status must be proposed or approved")
    if require_approved and selection["status"] != "approved":
        fail("selection must be explicitly marked approved")
    inventory_keys = {
        "candidate_files_sha256",
        "inventory_files_sha256",
        "metadata_sha256",
        "source_git_commit",
        "source_git_tree",
    }
    exact_keys(selection["inventory"], inventory_keys, "selection inventory commitment")
    for key in ("candidate_files_sha256", "inventory_files_sha256", "metadata_sha256"):
        if not SHA256_RE.fullmatch(str(selection["inventory"][key])):
            fail(f"selection inventory {key} is malformed")
    for key in ("source_git_commit", "source_git_tree"):
        if not SHA1_RE.fullmatch(str(selection["inventory"][key])):
            fail(f"selection inventory {key} is malformed")
    if inventory is not None and selection["inventory"] != inventory["commitment"]:
        fail("selection is not bound to the supplied inventory")
    entries = selection["files"]
    if not isinstance(entries, list):
        fail("selection files must be an array")
    if inventory is not None and len(entries) != len(inventory["records"]):
        fail("selection does not classify every inventoried candidate")
    seen_sources: set[str] = set()
    seen_destinations: set[str] = set()
    imported: list[dict] = []
    for index, entry in enumerate(entries):
        exact_keys(entry, SELECTION_ENTRY_KEYS, f"selection files[{index}]")
        source_path = canonical_relative_path(entry["source_path"], f"selection files[{index}].source_path")
        if source_path in seen_sources:
            fail(f"duplicate selection source path {source_path}")
        seen_sources.add(source_path)
        source_type = entry["source_type"]
        if source_type not in {"regular", "symlink", "other"}:
            fail(f"selection {source_path} has invalid source_type")
        if not is_integer(entry["size"]) or entry["size"] < 0:
            fail(f"selection {source_path} has invalid size")
        if source_type == "regular":
            if not SHA256_RE.fullmatch(str(entry["source_sha256"])):
                fail(f"selection {source_path} has malformed source SHA-256")
        elif entry["source_sha256"] is not None:
            fail(f"selection {source_path} must not invent a hash for {source_type}")
        if inventory is not None:
            source_record = inventory["record_by_path"].get(source_path)
            if source_record is None:
                fail(f"selection source is absent from inventory: {source_path}")
            if (
                source_type != source_record["type"]
                or entry["size"] != source_record["size"]
                or entry["source_sha256"] != source_record.get("sha256")
            ):
                fail(f"selection metadata differs from inventory for {source_path}")
        expected_suggestion = suggested_role(source_path, source_type)
        expected_destination = suggested_destination(source_path, source_type)
        if entry["suggested_role"] != expected_suggestion:
            fail(f"selection suggested_role was altered for {source_path}")
        if entry["suggested_destination_path"] != expected_destination:
            fail(f"selection suggested_destination_path was altered for {source_path}")

        decision = entry["decision"]
        if decision not in {"review", "import", "exclude"}:
            fail(f"selection {source_path} has invalid decision {decision!r}")
        if require_approved and decision == "review":
            fail(f"selection remains unreviewed: {source_path}")
        if decision == "import":
            if source_type != "regular":
                fail(f"only stable regular files may be imported: {source_path}")
            if entry["role"] not in ALLOWED_ROLES:
                fail(f"selection {source_path} has unsupported role {entry['role']!r}")
            destination = canonical_under(
                entry["destination_path"], "results/campaign/raw/", f"selection destination for {source_path}"
            )
            if destination in seen_destinations:
                fail(f"duplicate selection destination {destination}")
            seen_destinations.add(destination)
            if not isinstance(entry["reason"], str) or not entry["reason"].strip():
                fail(f"import decision requires a reason: {source_path}")
            imported.append(entry)
        elif decision == "exclude":
            if entry["role"] is not None or entry["destination_path"] is not None:
                fail(f"excluded selection must not have role/destination: {source_path}")
            if not isinstance(entry["reason"], str) or not entry["reason"].strip():
                fail(f"exclude decision requires a reason: {source_path}")
        else:
            if entry["role"] is not None or entry["destination_path"] is not None or entry["reason"] != "":
                fail(f"unreviewed selection must retain empty decision fields: {source_path}")

    if inventory is not None and seen_sources != set(inventory["record_by_path"]):
        fail("selection source set differs from the inventory")
    if require_approved:
        checkpoints = [entry for entry in imported if entry["role"] == "authoritative_checkpoint"]
        journals = [entry for entry in imported if entry["role"] == "campaign_daily"]
        if len(checkpoints) != 1:
            fail(f"approved selection requires exactly one authoritative checkpoint, got {len(checkpoints)}")
        if not journals:
            fail("approved selection requires at least one campaign_daily journal")
    return imported


def _git_read(source: Path, *args: str) -> str:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    process = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-C",
            str(source),
            *args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if process.returncode != 0:
        fail(f"read-only Git query failed: {process.stderr.decode('utf-8', errors='replace')[-500:]}")
    return process.stdout.decode("utf-8", errors="strict").strip()


def source_root_and_identity(source: Path) -> tuple[Path, str, str]:
    source = source.resolve()
    root = Path(_git_read(source, "rev-parse", "--show-toplevel")).resolve()
    commit = _git_read(root, "rev-parse", "--verify", "HEAD^{commit}")
    tree = _git_read(root, "rev-parse", "--verify", "HEAD^{tree}")
    return root, commit, tree


def _open_source_regular(source_root: Path, relative: str, record: dict):
    relative = canonical_relative_path(relative, "selected source path")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    file_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
        file_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
        file_flags |= os.O_NOFOLLOW

    directories: list[int] = []
    chain: list[tuple[int, str, int]] = []
    descriptor: int | None = None
    try:
        resolved_root = source_root.resolve(strict=True)
        root_descriptor = os.open(resolved_root, directory_flags)
        directories.append(root_descriptor)
        if not stat.S_ISDIR(os.fstat(root_descriptor).st_mode):
            fail("historical source root is not a directory")
        parent_descriptor = root_descriptor
        parts = PurePosixPath(relative).parts
        for component in parts[:-1]:
            child_descriptor = os.open(component, directory_flags, dir_fd=parent_descriptor)
            if not stat.S_ISDIR(os.fstat(child_descriptor).st_mode):
                os.close(child_descriptor)
                fail(f"selected source component is not a directory: {relative}")
            directories.append(child_descriptor)
            chain.append((parent_descriptor, component, child_descriptor))
            parent_descriptor = child_descriptor
        final_name = parts[-1]
        descriptor = os.open(final_name, file_flags, dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"selected source is no longer a regular file: {relative}")
        if metadata.st_size != record["size"] or metadata.st_mtime_ns != record["mtime_ns"]:
            fail(f"selected source metadata changed since inventory: {relative}")
        return {
            "before": metadata,
            "chain": chain,
            "descriptor": descriptor,
            "directories": directories,
            "final_name": final_name,
            "parent_descriptor": parent_descriptor,
            "relative": relative,
            "resolved_root": resolved_root,
            "root_descriptor": root_descriptor,
        }
    except RecoveryError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for directory in reversed(directories):
            try:
                os.close(directory)
            except OSError:
                pass
        raise
    except OSError as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for directory in reversed(directories):
            try:
                os.close(directory)
            except OSError:
                pass
        fail(f"cannot open selected source {relative}: {exc}")


def _verify_source_handle(handle, after, operation: str) -> None:
    relative = handle["relative"]
    current = os.stat(
        handle["final_name"],
        dir_fd=handle["parent_descriptor"],
        follow_symlinks=False,
    )
    if (
        _file_identity(handle["before"]) != _file_identity(after)
        or _file_identity(after) != _file_identity(current)
    ):
        fail(f"selected source changed while being {operation}: {relative}")
    for parent, component, child in handle["chain"]:
        current_component = os.stat(component, dir_fd=parent, follow_symlinks=False)
        if _inode_identity(current_component) != _inode_identity(os.fstat(child)):
            fail(f"selected source path changed while being {operation}: {relative}")
    current_root = os.stat(handle["resolved_root"], follow_symlinks=False)
    if _inode_identity(current_root) != _inode_identity(os.fstat(handle["root_descriptor"])):
        fail(f"historical source root changed while being {operation}: {relative}")


def _close_source_handle(handle) -> None:
    try:
        os.close(handle["descriptor"])
    except OSError:
        pass
    for directory in reversed(handle["directories"]):
        try:
            os.close(directory)
        except OSError:
            pass


def _hash_selected_source(source_root: Path, relative: str, record: dict) -> None:
    handle = _open_source_regular(source_root, relative, record)
    digest = hashlib.sha256()
    try:
        while True:
            block = os.read(handle["descriptor"], 8 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(handle["descriptor"])
        _verify_source_handle(handle, after, "preflighted")
    except OSError as exc:
        fail(f"cannot preflight selected source {relative}: {exc}")
    finally:
        _close_source_handle(handle)
    if digest.hexdigest() != record["sha256"]:
        fail(f"selected source hash changed since inventory: {relative}")


def _copy_selected_source(source_root: Path, relative: str, record: dict, destination: Path) -> None:
    handle = _open_source_regular(source_root, relative, record)
    temporary = destination.with_name(destination.name + ".tmp")
    digest = hashlib.sha256()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            fail(f"refusing to overwrite import destination {destination}")
        if temporary.exists() or temporary.is_symlink():
            fail(f"temporary import destination already exists: {temporary}")
        with temporary.open("xb") as output:
            while True:
                block = os.read(handle["descriptor"], 8 * 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(handle["descriptor"])
        _verify_source_handle(handle, after, "copied")
        if digest.hexdigest() != record["sha256"]:
            fail(f"selected source hash changed while being copied: {relative}")
    except RecoveryError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        fail(f"cannot import {relative}: {exc}")
    finally:
        _close_source_handle(handle)
    os.chmod(temporary, 0o644)
    try:
        _publish_new(temporary, destination)
    except RecoveryError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def import_selection(source: Path, inventory_directory: Path, selection_path: Path, output: Path) -> dict:
    inventory = validate_inventory(inventory_directory)
    selection_raw = read_absolute_snapshot(selection_path, "recovery selection")
    selection = load_json_bytes(selection_raw, str(selection_path))
    imported = validate_selection(selection, inventory, require_approved=True)
    source_root, commit, tree = source_root_and_identity(source)
    if commit != inventory["metadata"]["git_commit"] or tree != inventory["metadata"]["git_tree"]:
        fail("source checkout Git identity changed since inventory")
    for entry in imported:
        _hash_selected_source(source_root, entry["source_path"], inventory["record_by_path"][entry["source_path"]])

    requested_output = Path(os.path.abspath(output))
    if requested_output.exists() or requested_output.is_symlink():
        fail(f"import output must be a new path: {requested_output}")
    output = requested_output.parent.resolve() / requested_output.name
    try:
        output.relative_to(source_root)
    except ValueError:
        pass
    else:
        fail("import output must be outside the historical source checkout")
    if output.exists() or output.is_symlink():
        fail(f"import output must be a new path: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    receipt_files = []
    for entry in sorted(imported, key=lambda item: item["destination_path"]):
        destination = output / entry["destination_path"]
        _copy_selected_source(
            source_root,
            entry["source_path"],
            inventory["record_by_path"][entry["source_path"]],
            destination,
        )
        receipt_files.append(
            {
                "destination_path": entry["destination_path"],
                "role": entry["role"],
                "sha256": entry["source_sha256"],
                "size": entry["size"],
                "source_path": entry["source_path"],
            }
        )

    inventory_artifacts = []
    for name in INVENTORY_ARCHIVE_FILES:
        relative = f"results/campaign/recovery-inventory/{name}"
        raw = inventory["snapshots"][name]
        atomic_write(output / relative, raw, replace=False)
        inventory_artifacts.append(
            {"path": relative, "sha256": sha256_bytes(raw), "size": len(raw)}
        )

    stored_selection_path = output / "results/campaign/recovery-selection.json"
    stored_selection_bytes = canonical_json_bytes(selection)
    atomic_write(stored_selection_path, stored_selection_bytes, replace=False)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "inventory": selection["inventory"],
        "inventory_artifacts": inventory_artifacts,
        "selection": {
            "path": "results/campaign/recovery-selection.json",
            "sha256": sha256_bytes(stored_selection_bytes),
            "size": len(stored_selection_bytes),
        },
        "files": receipt_files,
        "totals": {
            "imported_bytes": sum(row["size"] for row in receipt_files),
            "imported_file_count": len(receipt_files),
        },
    }
    receipt_path = output / "results/campaign/import-receipt.json"
    atomic_write(receipt_path, canonical_json_bytes(receipt), replace=False)
    return receipt


def _validate_artifact_record(root: Path, record: dict, label: str) -> dict:
    exact_keys(record, {"path", "sha256", "size"}, label)
    relative = canonical_relative_path(record["path"], f"{label}.path")
    if not SHA256_RE.fullmatch(str(record["sha256"])):
        fail(f"{label}.sha256 is malformed")
    if not is_integer(record["size"]) or record["size"] < 0:
        fail(f"{label}.size is invalid")
    actual = artifact_identity(root, relative)
    if actual != record:
        fail(f"{label} does not match the imported artifact")
    return actual


def validate_receipt(repository_root: Path) -> tuple[dict, dict, list[dict], dict[str, dict]]:
    repository_root = repository_root.resolve()
    selection_relative = "results/campaign/recovery-selection.json"
    receipt_relative = "results/campaign/import-receipt.json"
    selection_identity, selection_raw = artifact_snapshot(repository_root, selection_relative)
    receipt_identity, receipt_raw = artifact_snapshot(repository_root, receipt_relative)
    selection = load_json_bytes(selection_raw, selection_relative)
    receipt = load_json_bytes(receipt_raw, receipt_relative)
    exact_keys(
        receipt,
        {"files", "inventory", "inventory_artifacts", "schema", "selection", "totals"},
        "import receipt",
    )
    if receipt["schema"] != RECEIPT_SCHEMA:
        fail(f"import receipt schema must be {RECEIPT_SCHEMA}")
    exact_keys(receipt["selection"], {"path", "sha256", "size"}, "receipt selection")
    if receipt["selection"] != selection_identity:
        fail("receipt selection does not match the exact parsed selection bytes")
    if selection_identity["path"] != "results/campaign/recovery-selection.json":
        fail("receipt selection path is not canonical")

    inventory_records = receipt["inventory_artifacts"]
    if not isinstance(inventory_records, list):
        fail("receipt inventory_artifacts must be an array")
    expected_inventory_paths = [
        f"results/campaign/recovery-inventory/{name}" for name in INVENTORY_ARCHIVE_FILES
    ]
    if len(inventory_records) != len(expected_inventory_paths):
        fail("receipt must preserve the exact six inventory artifacts")
    for index, (record, expected_path) in enumerate(zip(inventory_records, expected_inventory_paths)):
        identity = _validate_artifact_record(
            repository_root, record, f"receipt inventory_artifacts[{index}]"
        )
        if identity["path"] != expected_path:
            fail("receipt inventory artifacts are not complete and canonically sorted")

    inventory = validate_inventory(repository_root / "results/campaign/recovery-inventory")
    actual_inventory_records = [
        {
            "path": f"results/campaign/recovery-inventory/{name}",
            "sha256": sha256_bytes(inventory["snapshots"][name]),
            "size": len(inventory["snapshots"][name]),
        }
        for name in INVENTORY_ARCHIVE_FILES
    ]
    if inventory_records != actual_inventory_records:
        fail("receipt inventory records differ from the inventory bytes that were parsed")
    imported = validate_selection(selection, inventory, require_approved=True)
    if receipt["inventory"] != selection["inventory"] or receipt["inventory"] != inventory["commitment"]:
        fail("import receipt, selection, and preserved inventory commitments differ")

    if not isinstance(receipt["files"], list):
        fail("import receipt files must be an array")
    expected = {
        entry["destination_path"]: {
            "destination_path": entry["destination_path"],
            "role": entry["role"],
            "sha256": entry["source_sha256"],
            "size": entry["size"],
            "source_path": entry["source_path"],
        }
        for entry in imported
    }
    actual: dict[str, dict] = {}
    previous = None
    for index, row in enumerate(receipt["files"]):
        exact_keys(
            row,
            {"destination_path", "role", "sha256", "size", "source_path"},
            f"receipt files[{index}]",
        )
        destination = canonical_under(
            row["destination_path"], "results/campaign/raw/", f"receipt files[{index}].destination_path"
        )
        if previous is not None and destination <= previous:
            fail("import receipt files are duplicated or not canonically sorted")
        previous = destination
        if destination in actual:
            fail(f"duplicate receipt destination {destination}")
        if row.get("role") not in ALLOWED_ROLES:
            fail(f"receipt {destination} has unsupported role")
        if not SHA256_RE.fullmatch(str(row.get("sha256"))):
            fail(f"receipt {destination} has malformed SHA-256")
        if not is_integer(row.get("size")) or row["size"] < 0:
            fail(f"receipt {destination} has invalid size")
        canonical_relative_path(row.get("source_path"), f"receipt source for {destination}")
        artifact = artifact_identity(repository_root, destination)
        if artifact["sha256"] != row["sha256"] or artifact["size"] != row["size"]:
            fail(f"imported artifact differs from receipt: {destination}")
        actual[destination] = row
    if actual != expected:
        fail(
            "import receipt differs from approved selection: "
            f"missing={sorted(set(expected) - set(actual))}, extra={sorted(set(actual) - set(expected))}"
        )
    exact_keys(receipt["totals"], {"imported_bytes", "imported_file_count"}, "receipt totals")
    totals = {
        "imported_bytes": sum(row["size"] for row in receipt["files"]),
        "imported_file_count": len(receipt["files"]),
    }
    if receipt["totals"] != totals:
        fail(f"import receipt totals differ: {receipt['totals']} != {totals}")
    return selection, receipt, imported, {
        "receipt": receipt_identity,
        "selection": selection_identity,
    }


def expected_chunk(chunk_id: int) -> tuple[int, int, str]:
    if not 1 <= chunk_id <= CAMPAIGN_CHUNKS:
        fail(f"chunk_id outside 1..{CAMPAIGN_CHUNKS}: {chunk_id}")
    lower = CAMPAIGN_LOWER + (chunk_id - 1) * CAMPAIGN_WIDTH
    upper = min(lower + CAMPAIGN_WIDTH, CAMPAIGN_UPPER)
    return lower, upper, f"{lower}-{upper}"


def _source_map_relative(repository_root: Path, source_map_path: Path) -> str:
    try:
        absolute = Path(os.path.abspath(source_map_path))
        relative = absolute.relative_to(repository_root.resolve()).as_posix()
    except ValueError:
        fail("source map must be inside the publication repository")
    return canonical_relative_path(relative, "source-map path")


def validate_source_map(
    repository_root: Path, source_map_path: Path
) -> tuple[dict, dict, list[dict], dict[str, bytes]]:
    relative = _source_map_relative(repository_root, source_map_path)
    source_map_identity, source_map_raw = artifact_snapshot(repository_root, relative)
    source_map = load_json_bytes(source_map_raw, relative)
    exact_keys(
        source_map,
        {"artifacts", "revisions", "schema", "source_repository"},
        "campaign source map",
    )
    if source_map.get("schema") != SOURCE_MAP_SCHEMA:
        fail(f"source map schema must be {SOURCE_MAP_SCHEMA}")
    if source_map["source_repository"] != "Vulkin-prog/vdw-gpu-starter":
        fail("source map names the wrong source repository")
    artifacts = source_map.get("artifacts")
    revisions = source_map.get("revisions")
    if not isinstance(artifacts, dict) or not isinstance(revisions, list):
        fail("source map artifacts/revisions are malformed")
    expected_artifact_names = {
        name for row in EXPECTED_REVISIONS for name in (row[3], row[4])
    }
    if set(artifacts) != expected_artifact_names:
        fail(
            "source map artifact set differs: "
            f"missing={sorted(expected_artifact_names - set(artifacts))}, "
            f"extra={sorted(set(artifacts) - expected_artifact_names)}"
        )

    decoded_sources: dict[str, bytes] = {}
    for name in sorted(expected_artifact_names):
        identity = artifacts[name]
        exact_keys(
            identity,
            {"bytes", "decoded_path", "encoded_path", "git_blob_sha1", "sha256"},
            f"source map artifact {name}",
        )
        if identity != EXPECTED_SOURCE_ARTIFACTS[name]:
            fail(f"source map artifact {name} differs from its frozen historical identity")
        expected_decoded = "src/scan_gpu.cu" if name.startswith("scan_") else "src/campaign.py"
        if canonical_relative_path(identity["decoded_path"], f"source map {name}.decoded_path") != expected_decoded:
            fail(f"source map {name}.decoded_path differs from {expected_decoded}")
        encoded_path = canonical_under(
            identity["encoded_path"],
            "provenance/scanners/historical/",
            f"source map {name}.encoded_path",
        )
        if not encoded_path.endswith(".base64"):
            fail(f"source map {name}.encoded_path must name a Base64 artifact")
        if not SHA1_RE.fullmatch(str(identity["git_blob_sha1"])):
            fail(f"source map {name}.git_blob_sha1 is malformed")
        if not SHA256_RE.fullmatch(str(identity["sha256"])):
            fail(f"source map {name}.sha256 is malformed")
        if not is_integer(identity["bytes"]) or identity["bytes"] < 0:
            fail(f"source map {name}.bytes is invalid")

        _, encoded = artifact_snapshot(repository_root, encoded_path)
        try:
            compact = b"".join(encoded.split())
            decoded = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError) as exc:
            fail(f"source map {name} Base64 cannot be decoded: {exc}")
        git_blob_sha1 = hashlib.sha1(
            f"blob {len(decoded)}\0".encode("ascii") + decoded
        ).hexdigest()
        if (
            len(decoded) != identity["bytes"]
            or sha256_bytes(decoded) != identity["sha256"]
            or git_blob_sha1 != identity["git_blob_sha1"]
        ):
            fail(f"decoded historical source {name} differs from its frozen identity")
        decoded_sources[name] = decoded

    if len(revisions) != len(EXPECTED_REVISIONS):
        fail("source map must contain the exact eight historical revisions")
    normalized = []
    for index, (row, expected) in enumerate(zip(revisions, EXPECTED_REVISIONS)):
        first, last, commit, scanner_name, driver_name = expected
        expected_row = {
            "git_commit": commit,
            "chunks": last - first + 1,
            "first_chunk": first,
            "last_chunk": last,
            "scanner": scanner_name,
            "driver": driver_name,
        }
        if row != expected_row:
            fail(f"source map revision {index} differs from the frozen campaign map")
        source_identities = {}
        for role, name in (("scanner", scanner_name), ("driver", driver_name)):
            identity = artifacts.get(name)
            source_identities[role] = {
                "bytes": identity["bytes"],
                "git_blob_sha1": identity["git_blob_sha1"],
                "name": name,
                "sha256": identity["sha256"],
            }
        normalized.append(
            {
                "driver": source_identities["driver"],
                "first_chunk": first,
                "git_commit": commit,
                "last_chunk": last,
                "scanner": source_identities["scanner"],
            }
        )
    return source_map, source_map_identity, normalized, decoded_sources


def verify_chunk7_driver_order(driver: bytes) -> dict:
    try:
        text = driver.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"campaign_ebd54ea is not UTF-8: {exc}")
    needles = (
        ("run_scan_returns", "tg,cs,cands,dt=run_scan(lo,hi,a.walltime)"),
        ("checkpoint_done_assignment", 'ck["done"][key]={"checksum":cs,"dt":round(dt,1),"rev":rev}'),
        ("checkpoint_atomic_save", "save_ckpt(ckpath,ck)"),
        (
            "journal_append_open",
            'with open(os.path.join(a.out,"campaign_daily.md"),"a") as df:',
        ),
    )
    offsets: dict[str, list[int]] = {
        label: [match.start() for match in re.finditer(re.escape(needle), text)]
        for label, needle in needles
    }
    for label in ("run_scan_returns", "checkpoint_done_assignment", "journal_append_open"):
        if len(offsets[label]) != 1:
            fail(f"campaign_ebd54ea must contain exactly one {label} statement")
    run_offset = offsets["run_scan_returns"][0]
    done_offset = offsets["checkpoint_done_assignment"][0]
    journal_offset = offsets["journal_append_open"][0]
    saves_between = [
        offset for offset in offsets["checkpoint_atomic_save"]
        if done_offset < offset < journal_offset
    ]
    if not (run_offset < done_offset < journal_offset) or len(saves_between) != 1:
        fail(
            "campaign_ebd54ea does not establish run_scan -> done -> save_ckpt -> journal order"
        )
    ordered_offsets = (run_offset, done_offset, saves_between[0], journal_offset)
    statements = []
    for (label, _), offset in zip(needles, ordered_offsets):
        statements.append(
            {
                "line_number": text.count("\n", 0, offset) + 1,
                "statement": label,
            }
        )
    return {
        "decoded_driver_sha256": sha256_bytes(driver),
        "order": [label for label, _ in needles],
        "statements": statements,
        "verified": True,
    }


def revision_for_chunk(chunk_id: int, revisions: list[dict]) -> dict:
    matches = [row for row in revisions if row["first_chunk"] <= chunk_id <= row["last_chunk"]]
    if len(matches) != 1:
        fail(f"chunk {chunk_id} has {len(matches)} revision bindings")
    return matches[0]


def validate_checkpoint(raw: bytes, revisions: list[dict], label: str) -> tuple[dict, list[dict]]:
    checkpoint = load_json_bytes(raw, label)
    if not isinstance(checkpoint, dict) or not isinstance(checkpoint.get("done"), dict):
        fail("authoritative checkpoint must contain a done object")
    done = checkpoint["done"]
    expected_keys = {expected_chunk(chunk_id)[2] for chunk_id in range(1, CAMPAIGN_CHUNKS + 1)}
    if set(done) != expected_keys:
        fail(
            "checkpoint done-key set differs: "
            f"missing={sorted(expected_keys - set(done))[:8]}, extra={sorted(set(done) - expected_keys)[:8]}"
        )
    rows = []
    for chunk_id in range(1, CAMPAIGN_CHUNKS + 1):
        lower, upper, key = expected_chunk(chunk_id)
        record = done[key]
        if not isinstance(record, dict):
            fail(f"checkpoint record {key} must be an object")
        for required in ("checksum", "dt", "rev"):
            if required not in record:
                fail(f"checkpoint record {key} lacks {required}")
        checksum = record["checksum"]
        duration = record["dt"]
        observed_revision = record["rev"]
        if not is_integer(checksum) or not 0 <= checksum < (1 << 64):
            fail(f"checkpoint record {key} has invalid checksum")
        if (
            not isinstance(duration, (int, float))
            or isinstance(duration, bool)
            or not math.isfinite(float(duration))
            or duration < 0
        ):
            fail(f"checkpoint record {key} has invalid duration")
        if not isinstance(observed_revision, str) or not SHORT_REV_RE.fullmatch(observed_revision):
            fail(f"checkpoint record {key} has malformed revision {observed_revision!r}")
        revision = revision_for_chunk(chunk_id, revisions)
        if not revision["git_commit"].startswith(observed_revision):
            fail(
                f"checkpoint record {key} revision {observed_revision} does not match "
                f"{revision['git_commit']}"
            )
        rows.append(
            {
                "checkpoint": {
                    "checksum": checksum,
                    "duration_seconds": duration,
                    "json_key": key,
                    "record_sha256": sha256_bytes(canonical_json_bytes(record)),
                    "revision_observed": observed_revision,
                },
                "chunk_id": chunk_id,
                "lower_inclusive": lower,
                "revision_commit": revision["git_commit"],
                "upper_exclusive": upper,
            }
        )
    return checkpoint, rows


def parse_campaign_daily(
    raw: bytes, *, artifact_path: str
) -> tuple[dict[int, list[dict]], int]:
    if raw.startswith(b"\xef\xbb\xbf"):
        fail(f"campaign daily journal {artifact_path} must not have a UTF-8 BOM")
    rows: dict[int, list[dict]] = {}
    chunk7_matches = 0
    for line_number, raw_line in enumerate(raw.splitlines(keepends=True), 1):
        try:
            line = raw_line.decode("utf-8", errors="strict").rstrip("\r\n")
        except UnicodeDecodeError as exc:
            fail(f"campaign daily journal {artifact_path} is not UTF-8 at line {line_number}: {exc}")
        if CHUNK7_REFERENCE_RE.search(line):
            fail(
                f"campaign daily {artifact_path}:{line_number} contains a chunk-7 reference"
            )
        match = DAILY_CHUNK_RE.match(line)
        if not match:
            if GENERIC_DAILY_CHUNK_RE.match(line):
                fail(
                    f"campaign daily {artifact_path}:{line_number} looks like a chunk row "
                    "but does not match the frozen grammar"
                )
            continue
        chunk_id, total = map(int, match.groups()[:2])
        if total != CAMPAIGN_CHUNKS or not 1 <= chunk_id <= CAMPAIGN_CHUNKS:
            fail(f"campaign daily line {line_number} has invalid chunk coordinates")
        lower, _, _ = expected_chunk(chunk_id)
        if match.group(3) != f"{lower / 1e9:.3f}":
            fail(f"campaign daily line {line_number} has the wrong chunk interval label")
        if chunk_id == 7:
            # The broad check above normally rejects first.  Keep this guard
            # so later grammar changes cannot silently admit chunk 7.
            chunk7_matches += 1
            continue
        rows.setdefault(chunk_id, []).append(
            {
                "artifact_path": artifact_path,
                "line_number": line_number,
                "line_sha256": sha256_bytes(raw_line),
            }
        )
    return rows, chunk7_matches


def build_manifest_document(
    repository_root: Path,
    *,
    source_map_path: Path | None = None,
) -> dict:
    repository_root = repository_root.resolve()
    if not repository_root.is_dir():
        fail(f"repository root does not exist: {repository_root}")
    selection, receipt, imported, recovery_identities = validate_receipt(repository_root)
    source_map_path = (
        source_map_path
        if source_map_path is not None
        else repository_root / "provenance/scanners/campaign-source-map.json"
    )
    _, source_map_identity, revisions, decoded_sources = validate_source_map(
        repository_root, source_map_path
    )
    chunk7_driver_ordering = verify_chunk7_driver_order(decoded_sources["campaign_ebd54ea"])

    by_role: dict[str, list[dict]] = {}
    for entry in imported:
        by_role.setdefault(entry["role"], []).append(entry)
    checkpoints = by_role.get("authoritative_checkpoint", [])
    journals = sorted(by_role.get("campaign_daily", []), key=lambda row: row["destination_path"])
    if len(checkpoints) != 1 or not journals:
        fail("manifest build requires one authoritative checkpoint and at least one campaign daily")
    checkpoint_relative = checkpoints[0]["destination_path"]
    checkpoint_identity, checkpoint_raw = artifact_snapshot(repository_root, checkpoint_relative)
    if (
        checkpoint_identity["sha256"] != checkpoints[0]["source_sha256"]
        or checkpoint_identity["size"] != checkpoints[0]["size"]
    ):
        fail("authoritative checkpoint changed after receipt validation")
    _, rows = validate_checkpoint(checkpoint_raw, revisions, checkpoint_relative)

    journal_identities = []
    journal_rows: dict[int, list[dict]] = {}
    chunk7_matches = 0
    for journal_entry in journals:
        journal_relative = journal_entry["destination_path"]
        journal_identity, journal_raw = artifact_snapshot(repository_root, journal_relative)
        if (
            journal_identity["sha256"] != journal_entry["source_sha256"]
            or journal_identity["size"] != journal_entry["size"]
        ):
            fail(f"campaign journal changed after receipt validation: {journal_relative}")
        journal_identities.append(journal_identity)
        parsed_rows, parsed_chunk7 = parse_campaign_daily(
            journal_raw, artifact_path=journal_relative
        )
        chunk7_matches += parsed_chunk7
        for chunk_id, matches in parsed_rows.items():
            journal_rows.setdefault(chunk_id, []).extend(matches)

    expected_journal_chunks = set(range(1, CAMPAIGN_CHUNKS + 1)) - {7}
    if set(journal_rows) != expected_journal_chunks:
        fail(
            "combined campaign journals differ from the 514 expected rows: "
            f"missing={sorted(expected_journal_chunks - set(journal_rows))[:8]}, "
            f"extra={sorted(set(journal_rows) - expected_journal_chunks)[:8]}"
        )
    if chunk7_matches != 0:
        fail("combined campaign journals unexpectedly contain a chunk-7 row")
    primary_journal_identity = journal_identities[0]

    for row in rows:
        chunk_id = row["chunk_id"]
        if chunk_id == 7:
            row["evidence_class"] = "checkpoint_only_missing_journal"
            row["journal"] = {
                "match_count": chunk7_matches,
                "searched_artifacts": journal_identities,
                "status": "missing_historical",
            }
            row["driver_ordering"] = chunk7_driver_ordering
        else:
            matches = journal_rows[chunk_id]
            row["evidence_class"] = "checkpoint_and_journal"
            row["journal"] = {
                "match_count": len(matches),
                "matches": matches,
                "status": "present",
            }

    selection_identity = recovery_identities["selection"]
    receipt_identity = recovery_identities["receipt"]
    chunk7 = rows[6]
    revision7 = revision_for_chunk(7, revisions)
    manifest = {
        "schema": CAMPAIGN_SCHEMA,
        "interval": {
            "chunk_count": CAMPAIGN_CHUNKS,
            "chunk_width": CAMPAIGN_WIDTH,
            "lower_inclusive": CAMPAIGN_LOWER,
            "upper_exclusive": CAMPAIGN_UPPER,
        },
        "recovery": {
            "import_receipt": receipt_identity,
            "inventory_commitment": selection["inventory"],
            "selection": selection_identity,
        },
        "source_map": source_map_identity,
        "revisions": revisions,
        "checkpoint": checkpoint_identity,
        # The publication contract retains one primary-journal handle.  The
        # authoritative reconstruction reparses every imported journal; all
        # identities are exposed by chunk 7 and all matches by their chunks.
        "journal": primary_journal_identity,
        "chunks": rows,
        "chunk_7_checkpoint_evidence": {
            "checkpoint_artifact": checkpoint_identity,
            "checkpoint_json_key": chunk7["checkpoint"]["json_key"],
            "checkpoint_record_sha256": chunk7["checkpoint"]["record_sha256"],
            "chunk_id": 7,
            "driver": revision7["driver"],
            "journal_artifact": primary_journal_identity,
            "journal_match_count": chunk7_matches,
            "lower_inclusive": CHUNK7_LOWER,
            "resolution": "checkpoint_recovers_missing_journal",
            "revision_commit": revision7["git_commit"],
            "upper_exclusive": CHUNK7_UPPER,
        },
        "totals": {
            "checkpoint_and_journal_chunks": CAMPAIGN_CHUNKS - 1,
            "checkpoint_only_missing_journal_chunks": 1,
            "chunk_count": CAMPAIGN_CHUNKS,
            "imported_bytes": receipt["totals"]["imported_bytes"],
            "imported_file_count": receipt["totals"]["imported_file_count"],
        },
    }
    return manifest


def build_manifest(repository_root: Path, output: Path, source_map_path: Path | None = None) -> dict:
    document = build_manifest_document(repository_root, source_map_path=source_map_path)
    output = Path(os.path.abspath(output))
    try:
        output.relative_to(repository_root.resolve())
    except ValueError:
        fail("campaign manifest output must be inside the repository root")
    atomic_write(output, canonical_json_bytes(document), replace=True)
    return document


def check_manifest(repository_root: Path, manifest_path: Path, source_map_path: Path | None = None) -> dict:
    expected = build_manifest_document(repository_root, source_map_path=source_map_path)
    root = repository_root.resolve()
    try:
        manifest_relative = Path(os.path.abspath(manifest_path)).relative_to(root).as_posix()
    except ValueError:
        fail("campaign manifest must be inside the repository root")
    manifest_relative = canonical_relative_path(manifest_relative, "campaign manifest path")
    _, raw = artifact_snapshot(root, manifest_relative)
    actual = load_json_bytes(raw, manifest_relative)
    if actual != expected:
        fail("campaign manifest content differs from deterministic reconstruction")
    canonical = canonical_json_bytes(expected)
    if raw != canonical:
        fail("campaign manifest is not canonical byte-identical JSON")
    return expected


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate_cmd = commands.add_parser("validate-inventory", help="validate a read-only PC inventory")
    validate_cmd.add_argument("inventory", type=Path)

    propose_cmd = commands.add_parser("propose-selection", help="write a complete human-review ledger")
    propose_cmd.add_argument("inventory", type=Path)
    propose_cmd.add_argument("--output", type=Path, required=True)

    import_cmd = commands.add_parser("import", help="copy an approved selection into a new staging root")
    import_cmd.add_argument("--source", type=Path, required=True)
    import_cmd.add_argument("--inventory", type=Path, required=True)
    import_cmd.add_argument("--selection", type=Path, required=True)
    import_cmd.add_argument("--output", type=Path, required=True)

    build_cmd = commands.add_parser("build", help="derive the strict 515-row campaign manifest")
    build_cmd.add_argument("--repository-root", type=Path, default=ROOT)
    build_cmd.add_argument("--source-map", type=Path)
    build_cmd.add_argument("--output", type=Path)

    check_cmd = commands.add_parser("check", help="rebuild and byte-compare the campaign manifest")
    check_cmd.add_argument("--repository-root", type=Path, default=ROOT)
    check_cmd.add_argument("--source-map", type=Path)
    check_cmd.add_argument("--manifest", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "validate-inventory":
            inventory = validate_inventory(args.inventory)
            print(f"PC_INVENTORY_VALID  {len(inventory['records'])} candidate(s)")
        elif args.command == "propose-selection":
            inventory = validate_inventory(args.inventory)
            document = make_selection_document(inventory)
            atomic_write(
                Path(os.path.abspath(args.output)),
                canonical_json_bytes(document),
                replace=False,
            )
            print(f"SELECTION_PROPOSED  {len(document['files'])} candidate(s); human approval required")
        elif args.command == "import":
            receipt = import_selection(args.source, args.inventory, args.selection, args.output)
            print(
                "CAMPAIGN_IMPORT_OK  "
                f"{receipt['totals']['imported_file_count']} file(s), "
                f"{receipt['totals']['imported_bytes']} byte(s)"
            )
        elif args.command == "build":
            root = args.repository_root.resolve()
            output = args.output or root / "results/campaign/campaign_manifest.json"
            document = build_manifest(root, output, args.source_map)
            print(f"CAMPAIGN_MANIFEST_BUILT  {document['totals']['chunk_count']} chunks")
        else:
            root = args.repository_root.resolve()
            manifest = args.manifest or root / "results/campaign/campaign_manifest.json"
            document = check_manifest(root, manifest, args.source_map)
            print(f"CAMPAIGN_MANIFEST_OK  {document['totals']['chunk_count']} chunks")
    except (RecoveryError, OSError, UnicodeError) as exc:
        print(f"CAMPAIGN_RECOVERY_REJECT: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
