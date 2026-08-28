#!/usr/bin/env python3
"""Create and verify the external two-layer archive deposit receipt.

The receipt is intentionally forbidden from the repository payload.  It binds
the frozen release identity to both the deterministic local archive and a
separately downloaded copy of the draft upload.  Creation succeeds only after
a streaming byte-for-byte comparison; checking repeats that comparison and
rehashes both files.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "vdw-deposit-receipt/v1"

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[-+][0-9A-Za-z.-]+)?\Z")
DOI_RE = re.compile(r"10\.\d{4,9}/\S+\Z", re.IGNORECASE)
PROVIDER_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,63})\Z")
TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class ReceiptError(ValueError):
    """A receipt, artifact, or destination violates the deposit contract."""


def _reject_constant(value: str):
    raise ReceiptError(f"non-finite JSON constant {value!r}")


def _object_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ReceiptError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_json_bytes(raw: bytes, *, context: str):
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ReceiptError("UTF-8 BOM is forbidden in the deposit receipt")
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"invalid strict JSON in {context}: {exc}") from exc


def load_json(path: Path):
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReceiptError(f"cannot read receipt {path}: {exc}") from exc
    return load_json_bytes(raw, context=str(path))


def canonical_json(value) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _repository_root(root: Path) -> Path:
    if not root.is_absolute():
        raise ReceiptError("repository root must be an absolute path")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ReceiptError(f"cannot resolve repository root {root}: {exc}") from exc
    if resolved != root or not resolved.is_dir():
        raise ReceiptError("repository root is ambiguous, symlinked, or not a directory")
    return resolved


def _normalized_absolute(path: Path, *, label: str) -> Path:
    if not path.is_absolute():
        raise ReceiptError(f"{label} path must be absolute")
    normalized = Path(os.path.abspath(os.fspath(path)))
    if normalized != path or any(part in (".", "..") for part in path.parts):
        raise ReceiptError(f"{label} path is ambiguous or non-canonical: {path}")
    return normalized


def _safe_filename(value: str, *, label: str, require_tar_gz: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or "/" in value
        or "\\" in value
        or PurePosixPath(value).name != value
    ):
        raise ReceiptError(f"{label} is not a safe unambiguous filename")
    try:
        value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ReceiptError(f"{label} must use a portable ASCII filename") from exc
    if require_tar_gz and not value.endswith(".tar.gz"):
        raise ReceiptError("local archive filename must end with .tar.gz")
    return value


def _existing_regular_file(path: Path, *, label: str) -> tuple[Path, os.stat_result]:
    path = _normalized_absolute(path, label=label)
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise ReceiptError(f"cannot inspect {label} {path}: {exc}") from exc
    if resolved != path:
        raise ReceiptError(f"{label} path contains a symbolic link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ReceiptError(f"{label} is not a regular file: {path}")
    return path, metadata


def _external_new_path(root: Path, path: Path) -> Path:
    path = _normalized_absolute(path, label="receipt output")
    _safe_filename(path.name, label="receipt output filename")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise ReceiptError(f"receipt output parent is unavailable: {exc}") from exc
    if parent != path.parent or not parent.is_dir():
        raise ReceiptError("receipt output parent is ambiguous, symlinked, or not a directory")
    if path == root or root in path.parents:
        raise ReceiptError("deposit receipt output must remain outside the repository")
    try:
        path.lstat()
    except FileNotFoundError:
        return path
    except OSError as exc:
        raise ReceiptError(f"cannot inspect receipt output {path}: {exc}") from exc
    raise ReceiptError(f"refusing to overwrite existing receipt output: {path}")


def _external_existing_receipt(root: Path, path: Path) -> Path:
    path, _ = _existing_regular_file(path, label="deposit receipt")
    if path == root or root in path.parents:
        raise ReceiptError("deposit receipt must remain outside the repository")
    return path


def _open_regular(path: Path, *, label: str) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReceiptError(f"cannot open {label} {path}: {exc}") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ReceiptError(f"{label} is not a regular file: {path}")
    return descriptor, metadata


def _stable_stat(before: os.stat_result, after: os.stat_result) -> bool:
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _read_stable_regular(path: Path, *, label: str) -> bytes:
    descriptor, before = _open_regular(path, label=label)
    blocks = []
    try:
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise ReceiptError(f"cannot read {label} {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    if not _stable_stat(before, after):
        raise ReceiptError(f"{label} changed while it was read")
    return b"".join(blocks)


def compare_artifacts(local_archive: Path, deposit_copy: Path) -> tuple[dict, dict]:
    """Snapshot two distinct regular files and require exact byte equality."""

    local_archive, local_path_stat = _existing_regular_file(
        local_archive, label="local archive"
    )
    deposit_copy, copy_path_stat = _existing_regular_file(
        deposit_copy, label="deposit copy"
    )
    if local_archive == deposit_copy or (
        local_path_stat.st_dev,
        local_path_stat.st_ino,
    ) == (copy_path_stat.st_dev, copy_path_stat.st_ino):
        raise ReceiptError("local archive and deposit copy must be distinct files")
    local_name = _safe_filename(
        local_archive.name, label="local archive filename", require_tar_gz=True
    )
    copy_name = _safe_filename(deposit_copy.name, label="deposit copy filename")

    local_fd, local_before = _open_regular(local_archive, label="local archive")
    try:
        copy_fd, copy_before = _open_regular(deposit_copy, label="deposit copy")
    except BaseException:
        os.close(local_fd)
        raise
    if (local_path_stat.st_dev, local_path_stat.st_ino) != (
        local_before.st_dev,
        local_before.st_ino,
    ) or (copy_path_stat.st_dev, copy_path_stat.st_ino) != (
        copy_before.st_dev,
        copy_before.st_ino,
    ):
        os.close(local_fd)
        os.close(copy_fd)
        raise ReceiptError("an artifact path changed while it was opened")
    if (local_before.st_dev, local_before.st_ino) == (
        copy_before.st_dev,
        copy_before.st_ino,
    ):
        os.close(local_fd)
        os.close(copy_fd)
        raise ReceiptError("local archive and deposit copy must be distinct files")
    local_digest = hashlib.sha256()
    copy_digest = hashlib.sha256()
    size = 0
    try:
        while True:
            local_block = os.read(local_fd, 1024 * 1024)
            copy_block = os.read(copy_fd, 1024 * 1024)
            if local_block != copy_block:
                raise ReceiptError(
                    f"deposit copy is not byte-identical at or before offset {size}"
                )
            if not local_block:
                break
            size += len(local_block)
            local_digest.update(local_block)
            copy_digest.update(copy_block)
        local_after = os.fstat(local_fd)
        copy_after = os.fstat(copy_fd)
    except OSError as exc:
        raise ReceiptError(f"cannot compare archive layers: {exc}") from exc
    finally:
        os.close(local_fd)
        os.close(copy_fd)

    if not _stable_stat(local_before, local_after):
        raise ReceiptError("local archive changed during comparison")
    if not _stable_stat(copy_before, copy_after):
        raise ReceiptError("deposit copy changed during comparison")
    if size == 0:
        raise ReceiptError("release archive must not be empty")
    local_identity = {
        "filename": local_name,
        "sha256": local_digest.hexdigest(),
        "size": size,
    }
    copy_identity = {
        "filename": copy_name,
        "sha256": copy_digest.hexdigest(),
        "size": size,
    }
    return local_identity, copy_identity


def _exact_keys(value, expected: set[str], *, context: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReceiptError(f"{context} must contain exactly {sorted(expected)}")
    return value


def _timestamp(value, *, field: str) -> dt.datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        raise ReceiptError(f"{field} must be canonical UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ReceiptError(f"{field} is not a valid UTC timestamp") from exc
    return parsed.replace(tzinfo=dt.timezone.utc)


def _opaque_string(value, *, field: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ReceiptError(f"{field} must be a non-empty unambiguous string")
    return value


def _https_url(value, *, field: str) -> str:
    value = _opaque_string(value, field=field, maximum=2048)
    if "\\" in value or any(character.isspace() for character in value):
        raise ReceiptError(f"{field} must be an unambiguous HTTPS URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ReceiptError(f"{field} is malformed: {exc}") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or port is not None
        or parsed.netloc != parsed.hostname
        or not parsed.path.startswith("/")
        or "//" in parsed.path
        or "%" in parsed.path
        or any(part in (".", "..") for part in parsed.path.split("/"))
    ):
        raise ReceiptError(f"{field} must be a canonical credential-free HTTPS URL")
    return value


def _normalize_doi(value) -> str:
    value = _opaque_string(value, field="release.doi")
    normalized = re.sub(
        r"^https?://(?:dx\.)?doi\.org/", "", value, flags=re.IGNORECASE
    )
    normalized = re.sub(r"^doi:\s*", "", normalized, flags=re.IGNORECASE)
    if DOI_RE.fullmatch(normalized) is None or any(
        character.isspace() for character in normalized
    ):
        raise ReceiptError(f"release.doi is malformed: {value!r}")
    return normalized.casefold()


def _validate_identity(value, *, context: str, require_tar_gz: bool) -> dict:
    value = _exact_keys(
        value, {"filename", "sha256", "size"}, context=context
    )
    _safe_filename(
        value["filename"], label=f"{context}.filename", require_tar_gz=require_tar_gz
    )
    if not isinstance(value["sha256"], str) or SHA256_RE.fullmatch(value["sha256"]) is None:
        raise ReceiptError(f"{context}.sha256 must be lowercase hexadecimal")
    if (
        isinstance(value["size"], bool)
        or not isinstance(value["size"], int)
        or value["size"] <= 0
    ):
        raise ReceiptError(f"{context}.size must be a positive integer")
    return value


def _validate_deposit_record(value, *, context: str, timestamp_field: str) -> dt.datetime:
    value = _exact_keys(
        value, {"identifier", "url", timestamp_field}, context=context
    )
    _opaque_string(value["identifier"], field=f"{context}.identifier")
    _https_url(value["url"], field=f"{context}.url")
    return _timestamp(value[timestamp_field], field=f"{context}.{timestamp_field}")


def validate_document(value) -> dict:
    """Validate the exact receipt schema and all cross-field invariants."""

    value = _exact_keys(
        value,
        {
            "archive",
            "comparison",
            "created_utc",
            "deposit",
            "deposit_copy",
            "operator",
            "release",
            "schema",
        },
        context="receipt",
    )
    if value["schema"] != SCHEMA:
        raise ReceiptError(f"receipt.schema must be {SCHEMA!r}")
    created = _timestamp(value["created_utc"], field="created_utc")
    _opaque_string(value["operator"], field="operator")

    release = _exact_keys(
        value["release"], {"commit", "doi", "tag", "version"}, context="release"
    )
    if not isinstance(release["commit"], str) or COMMIT_RE.fullmatch(release["commit"]) is None:
        raise ReceiptError("release.commit must be a full lowercase Git object ID")
    if not isinstance(release["version"], str) or VERSION_RE.fullmatch(release["version"]) is None:
        raise ReceiptError("release.version is not canonical")
    if release["tag"] != f"v{release['version']}":
        raise ReceiptError("release.tag must equal 'v' plus release.version")
    if release["doi"] != _normalize_doi(release["doi"]):
        raise ReceiptError("release.doi must use its normalized bare DOI form")

    archive = _validate_identity(value["archive"], context="archive", require_tar_gz=True)
    copy = _validate_identity(
        value["deposit_copy"], context="deposit_copy", require_tar_gz=False
    )
    if (archive["size"], archive["sha256"]) != (copy["size"], copy["sha256"]):
        raise ReceiptError("archive and deposit_copy identities are not byte-identical")

    comparison = _exact_keys(
        value["comparison"],
        {"byte_identical", "compared_utc", "method"},
        context="comparison",
    )
    if comparison["method"] != "stream-byte-for-byte-sha256":
        raise ReceiptError("comparison.method is unsupported")
    if comparison["byte_identical"] is not True:
        raise ReceiptError("comparison.byte_identical must be true")
    compared = _timestamp(comparison["compared_utc"], field="comparison.compared_utc")

    deposit = _exact_keys(
        value["deposit"], {"draft", "final", "provider"}, context="deposit"
    )
    if not isinstance(deposit["provider"], str) or PROVIDER_RE.fullmatch(
        deposit["provider"]
    ) is None:
        raise ReceiptError("deposit.provider must be a lowercase provider identifier")
    draft_recorded = _validate_deposit_record(
        deposit["draft"], context="deposit.draft", timestamp_field="recorded_utc"
    )
    final_published = None
    if deposit["final"] is not None:
        final_published = _validate_deposit_record(
            deposit["final"],
            context="deposit.final",
            timestamp_field="published_utc",
        )
        if deposit["final"]["url"] == deposit["draft"]["url"]:
            raise ReceiptError("draft and final deposit URLs must be distinct")

    if not draft_recorded <= compared <= created:
        raise ReceiptError(
            "timestamps must satisfy draft.recorded_utc <= compared_utc <= created_utc"
        )
    if final_published is not None and not compared <= final_published <= created:
        raise ReceiptError(
            "timestamps must satisfy compared_utc <= final.published_utc <= created_utc"
        )
    return value


def _utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _atomic_write_new(path: Path, content: bytes) -> None:
    descriptor, temporary_raw = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-", dir=path.parent
    )
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise ReceiptError(f"refusing to overwrite existing receipt output: {path}") from exc
        except OSError as exc:
            raise ReceiptError(f"cannot publish receipt atomically: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def create_receipt(
    root: Path,
    local_archive: Path,
    deposit_copy: Path,
    output: Path,
    *,
    commit: str,
    tag: str,
    version: str,
    doi: str,
    operator: str,
    draft_identifier: str,
    draft_url: str,
    provider: str = "zenodo",
    created_utc: str | None = None,
    compared_utc: str | None = None,
    draft_recorded_utc: str | None = None,
    final_identifier: str | None = None,
    final_url: str | None = None,
    final_published_utc: str | None = None,
) -> dict:
    """Compare both layers and atomically publish a new external receipt."""

    root = _repository_root(root)
    output = _external_new_path(root, output)
    final_values = (final_identifier, final_url, final_published_utc)
    if any(value is not None for value in final_values) and not all(
        value is not None for value in final_values
    ):
        raise ReceiptError(
            "final_identifier, final_url, and final_published_utc are all-or-none"
        )

    now = created_utc or _utc_now()
    comparison_time = compared_utc or now
    draft_time = draft_recorded_utc or comparison_time
    archive_identity, copy_identity = compare_artifacts(local_archive, deposit_copy)
    final = None
    if final_identifier is not None:
        final = {
            "identifier": final_identifier,
            "published_utc": final_published_utc,
            "url": final_url,
        }
    value = {
        "archive": archive_identity,
        "comparison": {
            "byte_identical": True,
            "compared_utc": comparison_time,
            "method": "stream-byte-for-byte-sha256",
        },
        "created_utc": now,
        "deposit": {
            "draft": {
                "identifier": draft_identifier,
                "recorded_utc": draft_time,
                "url": draft_url,
            },
            "final": final,
            "provider": provider,
        },
        "deposit_copy": copy_identity,
        "operator": operator,
        "release": {
            "commit": commit,
            "doi": _normalize_doi(doi),
            "tag": tag,
            "version": version,
        },
        "schema": SCHEMA,
    }
    validate_document(value)
    _atomic_write_new(output, canonical_json(value))
    return value


def check_receipt(
    root: Path,
    receipt: Path,
    local_archive: Path,
    deposit_copy: Path,
) -> dict:
    """Strictly revalidate metadata, identities, and byte equality."""

    root = _repository_root(root)
    receipt = _external_existing_receipt(root, receipt)
    raw = _read_stable_regular(receipt, label="deposit receipt")
    value = load_json_bytes(raw, context=str(receipt))
    validate_document(value)
    if raw != canonical_json(value):
        raise ReceiptError("deposit receipt is not canonically serialized")
    archive_identity, copy_identity = compare_artifacts(local_archive, deposit_copy)
    if value["archive"] != archive_identity:
        raise ReceiptError("local archive identity differs from the deposit receipt")
    if value["deposit_copy"] != copy_identity:
        raise ReceiptError("deposit copy identity differs from the deposit receipt")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  deposit_receipt.py create /abs/release-v1.2.3.tar.gz /abs/download.tar.gz /abs/receipt.json \\
    --commit <full-git-id> --tag v1.2.3 --version 1.2.3 --doi 10.5281/zenodo.123 \\
    --operator release-operator --draft-identifier zenodo-draft:123 \\
    --draft-url https://zenodo.org/uploads/123
  deposit_receipt.py check /abs/receipt.json /abs/release-v1.2.3.tar.gz /abs/download.tar.gz
""",
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=ROOT,
        help="absolute repository root used only to enforce the outer-layer boundary",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="compare two layers and create a receipt")
    create.add_argument("local_archive", type=Path)
    create.add_argument("deposit_copy", type=Path)
    create.add_argument("output", type=Path)
    create.add_argument("--commit", required=True)
    create.add_argument("--tag", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--doi", required=True)
    create.add_argument("--operator", required=True)
    create.add_argument("--provider", default="zenodo")
    create.add_argument("--draft-identifier", required=True)
    create.add_argument("--draft-url", required=True)
    create.add_argument("--draft-recorded-utc")
    create.add_argument("--compared-utc")
    create.add_argument("--created-utc")
    create.add_argument("--final-identifier")
    create.add_argument("--final-url")
    create.add_argument("--final-published-utc")
    check = commands.add_parser("check", help="rehash and compare against a receipt")
    check.add_argument("receipt", type=Path)
    check.add_argument("local_archive", type=Path)
    check.add_argument("deposit_copy", type=Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    values = _parser().parse_args(arguments)
    try:
        if values.command == "create":
            receipt = create_receipt(
                values.repository_root,
                values.local_archive,
                values.deposit_copy,
                values.output,
                commit=values.commit,
                tag=values.tag,
                version=values.version,
                doi=values.doi,
                operator=values.operator,
                provider=values.provider,
                draft_identifier=values.draft_identifier,
                draft_url=values.draft_url,
                draft_recorded_utc=values.draft_recorded_utc,
                compared_utc=values.compared_utc,
                created_utc=values.created_utc,
                final_identifier=values.final_identifier,
                final_url=values.final_url,
                final_published_utc=values.final_published_utc,
            )
            action = "created"
            destination = values.output
        else:
            receipt = check_receipt(
                values.repository_root,
                values.receipt,
                values.local_archive,
                values.deposit_copy,
            )
            action = "verified"
            destination = values.receipt
    except ReceiptError as exc:
        print(f"DEPOSIT_RECEIPT_REJECT: {exc}", file=sys.stderr)
        return 2
    print(f"PASS: {action} {destination}")
    print(
        f"archive={receipt['archive']['filename']} "
        f"size={receipt['archive']['size']} sha256={receipt['archive']['sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
