#!/usr/bin/env python3
"""Build or verify the byte-level source-import manifest.

The bootstrap is the only authority for identities in the source repository.
Its exact JSON shape is::

    {
      "schema": "vdw-source-import-bootstrap/v1",
      "source": {
        "repository": "Vulkin-prog/vdw-gpu-starter",
        "commit": "02796ae9e08da5b051a94b2d9001763908375f6e"
      },
      "files": [
        {
          "path": "relative/source/and/target/path",
          "sha256": "64 lowercase hexadecimal digits",
          "git_blob_sha1": "40 lowercase hexadecimal digits",
          "size": 123
        }
      ]
    }

No source identity is inferred from a target file.  A present path listed in
the bootstrap is ``imported`` when its bytes retain all three recorded source
identities, and ``derived`` otherwise.  A present path absent from the
bootstrap is ``new``.  Bootstrap paths absent from the export remain explicit
in ``omitted_source_files``.  The generated manifest inventories every regular
repository file except itself and cache/VCS administration directories.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BOOTSTRAP = ROOT / "publication" / "source-import-bootstrap.json"
DEFAULT_MANIFEST = ROOT / "publication" / "source-import.json"

SOURCE_REPOSITORY = "Vulkin-prog/vdw-gpu-starter"
SOURCE_COMMIT = "02796ae9e08da5b051a94b2d9001763908375f6e"
SOURCE = {"repository": SOURCE_REPOSITORY, "commit": SOURCE_COMMIT}

BOOTSTRAP_SCHEMA = "vdw-source-import-bootstrap/v1"
MANIFEST_SCHEMA = "vdw-source-import/v1"
IGNORED_DIRECTORY_NAMES = (".git", ".pytest_cache", "__pycache__", "build", "dist")
CLASSIFICATIONS = ("imported", "derived", "new")

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_BLOB_RE = re.compile(r"[0-9a-f]{40}\Z")


class SourceImportError(ValueError):
    """Raised when source metadata or a materialized export is inconsistent."""


def _reject_constant(value: str):
    raise SourceImportError(f"non-finite JSON constant {value!r}")


def _object_without_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SourceImportError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_json(path: Path):
    """Load strict UTF-8 JSON, rejecting duplicate keys and NaN/Infinity."""

    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise SourceImportError(f"UTF-8 BOM is forbidden: {path}")
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceImportError(f"invalid JSON in {path}: {exc}") from exc


def canonical_json(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def byte_identity(data: bytes) -> dict:
    return {
        "git_blob_sha1": git_blob_sha1(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def canonical_repo_path(value, *, field: str = "path") -> str:
    if not isinstance(value, str) or not value:
        raise SourceImportError(f"{field} must be a non-empty string")
    if "\\" in value or any(ord(char) < 32 for char in value):
        raise SourceImportError(f"{field} is not a safe POSIX repository path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise SourceImportError(f"{field} is not canonical: {value!r}")
    if any(part in ("", ".", "..") for part in path.parts):
        raise SourceImportError(f"{field} has an unsafe component: {value!r}")
    return value


def validate_identity(record: dict, *, context: str, include_path: bool) -> dict:
    fields = {"git_blob_sha1", "sha256", "size"}
    if include_path:
        fields.add("path")
    if not isinstance(record, dict) or set(record) != fields:
        raise SourceImportError(f"{context} must contain exactly {sorted(fields)}")
    normalized = dict(record)
    if include_path:
        normalized["path"] = canonical_repo_path(record["path"], field=f"{context}.path")
    if not isinstance(record["sha256"], str) or not SHA256_RE.fullmatch(record["sha256"]):
        raise SourceImportError(f"{context}.sha256 must be lowercase hexadecimal")
    if not isinstance(record["git_blob_sha1"], str) or not GIT_BLOB_RE.fullmatch(
        record["git_blob_sha1"]
    ):
        raise SourceImportError(f"{context}.git_blob_sha1 must be lowercase hexadecimal")
    if isinstance(record["size"], bool) or not isinstance(record["size"], int):
        raise SourceImportError(f"{context}.size must be a non-negative integer")
    if record["size"] < 0:
        raise SourceImportError(f"{context}.size must be a non-negative integer")
    return normalized


def load_bootstrap(path: Path) -> dict[str, dict]:
    """Return bootstrap source records keyed by their canonical path."""

    value = load_json(path)
    if not isinstance(value, dict) or set(value) != {"schema", "source", "files"}:
        raise SourceImportError("bootstrap must contain exactly schema, source, and files")
    if value["schema"] != BOOTSTRAP_SCHEMA:
        raise SourceImportError(f"unsupported bootstrap schema {value['schema']!r}")
    if value["source"] != SOURCE:
        raise SourceImportError(
            f"bootstrap source must be {SOURCE_REPOSITORY}@{SOURCE_COMMIT}"
        )
    if not isinstance(value["files"], list):
        raise SourceImportError("bootstrap.files must be an array")

    records = {}
    for index, raw in enumerate(value["files"]):
        record = validate_identity(raw, context=f"bootstrap.files[{index}]", include_path=True)
        path_value = record["path"]
        if path_value in records:
            raise SourceImportError(f"duplicate bootstrap path {path_value!r}")
        records[path_value] = record
    return records


def _relative_to_root(root: Path, path: Path, *, label: str) -> str:
    root = root.resolve()
    path = path.resolve()
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise SourceImportError(f"{label} must be inside repository root {root}") from exc
    return canonical_repo_path(relative, field=label)


def repository_files(root: Path, excluded_paths: set[str]):
    """Yield all regular repository files in canonical path order."""

    root = root.resolve()
    if not root.is_dir():
        raise SourceImportError(f"repository root is not a directory: {root}")

    found = []
    for current_raw, directories, filenames in os.walk(root, followlinks=False):
        current = Path(current_raw)
        kept_directories = []
        for name in sorted(directories):
            candidate = current / name
            if name in IGNORED_DIRECTORY_NAMES:
                continue
            if candidate.is_symlink():
                relative = candidate.relative_to(root).as_posix()
                raise SourceImportError(f"symbolic links are not supported: {relative}")
            kept_directories.append(name)
        directories[:] = kept_directories

        for name in sorted(filenames):
            candidate = current / name
            relative = canonical_repo_path(candidate.relative_to(root).as_posix())
            if relative in excluded_paths:
                continue
            if candidate.is_symlink() or not candidate.is_file():
                raise SourceImportError(f"non-regular repository entry: {relative}")
            found.append((relative, candidate))
    yield from sorted(found)


def _source_identity(record: dict) -> dict:
    return {
        "git_blob_sha1": record["git_blob_sha1"],
        "path": record["path"],
        "sha256": record["sha256"],
        "size": record["size"],
    }


def publication_rationale(path: str, classification: str) -> str:
    """Give every non-verbatim file a concise, reviewable origin rationale."""

    if classification == "new":
        return "Created specifically for the focused publication and release contract."
    if path == "paper/references.bib":
        return "Reduced to the cited entries and corrected against the source-audit ledger."
    if path.startswith("paper/tex/generated_") or path.startswith("audit/generated/"):
        return "Regenerated from canonical inputs after the publication-scope adaptations."
    if path.startswith("paper/"):
        return "Adapted to the focused repository, public evidence paths, and release gates."
    if path.startswith("audit/"):
        return "Adapted to fail-closed public provenance and release validation."
    if path.startswith("tools/") or path.startswith("tests/"):
        return "Hardened for portable, fail-closed publication validation."
    return "Adapted for the focused publication package; source and target identities are retained."


def build_manifest(root: Path, bootstrap_path: Path, manifest_path: Path) -> dict:
    """Construct a deterministic manifest without guessing source metadata."""

    root = root.resolve()
    manifest_relative = _relative_to_root(root, manifest_path, label="manifest path")
    bootstrap = load_bootstrap(bootstrap_path)
    present_paths = set()
    files = []
    counts = {classification: 0 for classification in CLASSIFICATIONS}

    for relative, path in repository_files(root, {manifest_relative}):
        data = path.read_bytes()
        target = {"path": relative, **byte_identity(data)}
        source = bootstrap.get(relative)
        if source is None:
            classification = "new"
        else:
            source_values = {key: source[key] for key in ("git_blob_sha1", "sha256", "size")}
            target_values = {key: target[key] for key in ("git_blob_sha1", "sha256", "size")}
            matches = {key: target_values[key] == source_values[key] for key in source_values}
            if all(matches.values()):
                classification = "imported"
            else:
                # Two equal byte identities and one unequal one cannot be a legitimate
                # description of the same content; reject the bootstrap rather than
                # laundering it as a derived file.
                if sum(matches.values()) >= 2:
                    raise SourceImportError(
                        f"internally inconsistent source identity for {relative}: {matches}"
                    )
                classification = "derived"
            target["source"] = _source_identity(source)
        target["classification"] = classification
        if classification != "imported":
            target["rationale"] = publication_rationale(relative, classification)
        counts[classification] += 1
        present_paths.add(relative)
        files.append(target)

    omitted = [
        _source_identity(record)
        for path, record in sorted(bootstrap.items())
        if path not in present_paths
    ]
    return {
        "files": files,
        "inventory": {
            "excluded_directory_names": list(IGNORED_DIRECTORY_NAMES),
            "excluded_paths": [manifest_relative],
        },
        "omitted_source_files": omitted,
        "schema": MANIFEST_SCHEMA,
        "source": dict(SOURCE),
        "summary": {
            **counts,
            "omitted_source": len(omitted),
            "total_present": len(files),
        },
    }


def _validate_manifest_shape(value: dict, *, manifest_relative: str) -> None:
    expected_top = {"files", "inventory", "omitted_source_files", "schema", "source", "summary"}
    if not isinstance(value, dict) or set(value) != expected_top:
        raise SourceImportError(f"manifest must contain exactly {sorted(expected_top)}")
    if value["schema"] != MANIFEST_SCHEMA:
        raise SourceImportError(f"unsupported manifest schema {value['schema']!r}")
    if value["source"] != SOURCE:
        raise SourceImportError(f"manifest source must be {SOURCE_REPOSITORY}@{SOURCE_COMMIT}")
    expected_inventory = {
        "excluded_directory_names": list(IGNORED_DIRECTORY_NAMES),
        "excluded_paths": [manifest_relative],
    }
    if value["inventory"] != expected_inventory:
        raise SourceImportError("manifest inventory policy is not the enforced policy")
    if not isinstance(value["files"], list) or not isinstance(value["omitted_source_files"], list):
        raise SourceImportError("manifest files and omitted_source_files must be arrays")

    seen = set()
    previous = None
    counts = {classification: 0 for classification in CLASSIFICATIONS}
    for index, raw in enumerate(value["files"]):
        context = f"manifest.files[{index}]"
        if not isinstance(raw, dict):
            raise SourceImportError(f"{context} must be an object")
        classification = raw.get("classification")
        if classification not in CLASSIFICATIONS:
            raise SourceImportError(f"{context}.classification is invalid")
        expected = {"classification", "git_blob_sha1", "path", "sha256", "size"}
        if classification != "new":
            expected.add("source")
        if classification != "imported":
            expected.add("rationale")
        if set(raw) != expected:
            raise SourceImportError(f"{context} must contain exactly {sorted(expected)}")
        target = validate_identity(
            {key: raw[key] for key in ("git_blob_sha1", "path", "sha256", "size")},
            context=context,
            include_path=True,
        )
        relative = target["path"]
        if relative in seen:
            raise SourceImportError(f"duplicate manifest path {relative!r}")
        if previous is not None and relative <= previous:
            raise SourceImportError("manifest files are not in canonical path order")
        seen.add(relative)
        previous = relative
        counts[classification] += 1
        if classification != "imported":
            rationale = raw.get("rationale")
            if not isinstance(rationale, str) or not rationale.strip():
                raise SourceImportError(f"{context}.rationale must be non-empty")
        if classification != "new":
            source = validate_identity(raw["source"], context=f"{context}.source", include_path=True)
            same = all(target[key] == source[key] for key in ("git_blob_sha1", "sha256", "size"))
            if (classification == "imported") != same:
                raise SourceImportError(
                    f"{context} classification disagrees with its byte identities"
                )

    omitted_seen = set()
    previous = None
    for index, raw in enumerate(value["omitted_source_files"]):
        record = validate_identity(
            raw, context=f"manifest.omitted_source_files[{index}]", include_path=True
        )
        relative = record["path"]
        if relative in seen or relative in omitted_seen:
            raise SourceImportError(f"duplicate present/omitted source path {relative!r}")
        if previous is not None and relative <= previous:
            raise SourceImportError("omitted source files are not in canonical path order")
        omitted_seen.add(relative)
        previous = relative

    expected_summary = {
        **counts,
        "omitted_source": len(value["omitted_source_files"]),
        "total_present": len(value["files"]),
    }
    if value["summary"] != expected_summary:
        raise SourceImportError("manifest summary does not match its file records")


def check_manifest(
    root: Path,
    manifest_path: Path,
    bootstrap_path: Path | None = None,
    *,
    require_canonical: bool = True,
) -> dict:
    """Verify shape, coverage, bytes, and optionally the authoritative bootstrap."""

    root = root.resolve()
    manifest_relative = _relative_to_root(root, manifest_path, label="manifest path")
    value = load_json(manifest_path)
    _validate_manifest_shape(value, manifest_relative=manifest_relative)

    disk_files = {}
    for relative, path in repository_files(root, {manifest_relative}):
        disk_files[relative] = byte_identity(path.read_bytes())
    recorded = {record["path"]: record for record in value["files"]}
    if set(recorded) != set(disk_files):
        missing = sorted(set(disk_files) - set(recorded))
        stale = sorted(set(recorded) - set(disk_files))
        raise SourceImportError(f"manifest coverage mismatch; missing={missing}, stale={stale}")
    for relative, identity in disk_files.items():
        record = recorded[relative]
        for key, actual in identity.items():
            if record[key] != actual:
                raise SourceImportError(f"target {key} mismatch for {relative}")
    for record in value["omitted_source_files"]:
        if (root / record["path"]).exists():
            raise SourceImportError(f"omitted source path is present: {record['path']}")

    if bootstrap_path is not None:
        expected = build_manifest(root, bootstrap_path, manifest_path)
        if value != expected:
            raise SourceImportError("manifest does not match the authoritative bootstrap and worktree")
    if require_canonical and manifest_path.read_bytes() != canonical_json(value):
        raise SourceImportError("manifest JSON is not canonically serialized")
    return value


def write_manifest(root: Path, bootstrap_path: Path, manifest_path: Path) -> dict:
    value = build_manifest(root, bootstrap_path, manifest_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = manifest_path.with_name(f".{manifest_path.name}.tmp")
    temporary.write_bytes(canonical_json(value))
    os.replace(temporary, manifest_path)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", type=Path, default=DEFAULT_BOOTSTRAP)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the existing manifest instead of rebuilding it",
    )
    args = parser.parse_args()
    try:
        if args.check:
            value = check_manifest(ROOT, args.manifest, args.bootstrap)
            verb = "validated"
        else:
            value = write_manifest(ROOT, args.bootstrap, args.manifest)
            verb = "wrote"
    except (OSError, SourceImportError) as exc:
        print(f"SOURCE_IMPORT_REJECT: {exc}")
        return 1
    summary = value["summary"]
    print(
        f"PASS: {verb} {args.manifest} with {summary['imported']} imported, "
        f"{summary['derived']} derived, {summary['new']} new, and "
        f"{summary['omitted_source']} omitted source files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
