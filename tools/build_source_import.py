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
in ``omitted_source_files``.

``publication/scope.json`` is the positive export authority.  Its exact,
canonical ``allowed_paths`` list must equal the materialized export; an
innocently named new file and a stale approval both fail closed.  The generated
manifest inventories every approved regular file except itself and the release
checksum manifest, whose reciprocal inclusion would create an unavoidable hash
cycle.  Both excluded files still require an explicit allowlist decision when
they are present in the export.
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
DEFAULT_SCOPE = ROOT / "publication" / "scope.json"

SOURCE_REPOSITORY = "Vulkin-prog/vdw-gpu-starter"
SOURCE_COMMIT = "02796ae9e08da5b051a94b2d9001763908375f6e"
SOURCE = {"repository": SOURCE_REPOSITORY, "commit": SOURCE_COMMIT}

BOOTSTRAP_SCHEMA = "vdw-source-import-bootstrap/v1"
MANIFEST_SCHEMA = "vdw-source-import/v1"
SCOPE_SCHEMA = "vdw-export-scope/v1"
IGNORED_DIRECTORY_NAMES = (".git", ".pytest_cache", "__pycache__", "build", "dist")
ALWAYS_EXCLUDED_PATHS = ("MANIFEST.sha256",)
CLASSIFICATIONS = ("imported", "derived", "new")

SCOPE_FIELDS = {
    "allowed_paths",
    "excluded_topics",
    "forbidden_exact_paths",
    "forbidden_name_fragments",
    "forbidden_prefixes",
    "included_scientific_scope",
    "schema",
    "source_policy",
}

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


def _string_array(value, *, field: str, non_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (non_empty and not value):
        qualifier = "a non-empty" if non_empty else "an"
        raise SourceImportError(f"scope.{field} must be {qualifier} string array")
    if any(not isinstance(item, str) or not item for item in value):
        raise SourceImportError(f"scope.{field} must contain only non-empty strings")
    if len(value) != len(set(value)):
        raise SourceImportError(f"scope.{field} contains a duplicate")
    return value


def _scope_violation(path: str, scope: dict) -> str | None:
    if path in scope["forbidden_exact_paths"]:
        return "forbidden exact path"
    for prefix in scope["forbidden_prefixes"]:
        if path.startswith(prefix):
            return f"forbidden prefix {prefix!r}"
    for fragment in scope["forbidden_name_fragments"]:
        if fragment in path:
            return f"forbidden name fragment {fragment!r}"
    return None


def load_scope_allowlist(path: Path) -> list[str]:
    """Load the exact positive path decisions from publication/scope.json."""

    value = load_json(path)
    if not isinstance(value, dict) or set(value) != SCOPE_FIELDS:
        raise SourceImportError(
            f"scope must contain exactly {sorted(SCOPE_FIELDS)}"
        )
    if value["schema"] != SCOPE_SCHEMA:
        raise SourceImportError(f"unsupported scope schema {value['schema']!r}")
    if value["source_policy"] != "explicit_allowlist":
        raise SourceImportError("scope.source_policy must be explicit_allowlist")
    if (
        not isinstance(value["included_scientific_scope"], str)
        or not value["included_scientific_scope"].strip()
    ):
        raise SourceImportError("scope.included_scientific_scope must be non-empty")

    allowed_raw = _string_array(value["allowed_paths"], field="allowed_paths")
    allowed = [
        canonical_repo_path(item, field=f"scope.allowed_paths[{index}]")
        for index, item in enumerate(allowed_raw)
    ]
    if allowed != sorted(allowed):
        raise SourceImportError("scope.allowed_paths must be in canonical path order")

    exact_raw = _string_array(
        value["forbidden_exact_paths"], field="forbidden_exact_paths"
    )
    exact = [
        canonical_repo_path(item, field=f"scope.forbidden_exact_paths[{index}]")
        for index, item in enumerate(exact_raw)
    ]
    if exact != sorted(exact):
        raise SourceImportError("scope.forbidden_exact_paths must be in canonical path order")

    prefixes = _string_array(value["forbidden_prefixes"], field="forbidden_prefixes")
    for index, prefix in enumerate(prefixes):
        if not prefix.endswith("/"):
            raise SourceImportError(
                f"scope.forbidden_prefixes[{index}] must end with '/'"
            )
        canonical_repo_path(
            prefix[:-1], field=f"scope.forbidden_prefixes[{index}]"
        )
    if prefixes != sorted(prefixes):
        raise SourceImportError("scope.forbidden_prefixes must be in canonical path order")

    fragments = _string_array(
        value["forbidden_name_fragments"], field="forbidden_name_fragments"
    )
    if fragments != sorted(fragments):
        raise SourceImportError(
            "scope.forbidden_name_fragments must be in canonical order"
        )
    _string_array(value["excluded_topics"], field="excluded_topics")

    for relative in allowed:
        reason = _scope_violation(relative, value)
        if reason is not None:
            raise SourceImportError(
                f"scope allows forbidden export path {relative!r}: {reason}"
            )
    return allowed


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


def inventory_excluded_paths(manifest_relative: str) -> list[str]:
    """Return the deterministic exclusions from the byte inventory.

    At release time ``MANIFEST.sha256`` hashes ``source-import.json``.  Having
    the latter hash ``MANIFEST.sha256`` in return would make both files
    impossible to construct.  No other release artifact is exempted.
    """

    return sorted({manifest_relative, *ALWAYS_EXCLUDED_PATHS})


def validate_export_allowlist(
    root: Path,
    manifest_relative: str,
    scope_path: Path,
    materialized_paths: set[str],
) -> list[str]:
    """Require one exact positive scope decision for every exported path.

    The source-import manifest may be absent only while it is the output about
    to be constructed.  No analogous exception is made for MANIFEST.sha256:
    once that release artifact exists, it must be added deliberately to the
    allowlist before source-import can be regenerated.
    """

    scope_relative = _relative_to_root(root, scope_path, label="scope path")
    if scope_relative == manifest_relative:
        raise SourceImportError("scope path and source-import manifest path must differ")
    allowed = load_scope_allowlist(scope_path)
    effective_paths = set(materialized_paths)
    effective_paths.add(manifest_relative)
    missing_decisions = sorted(effective_paths - set(allowed))
    stale_decisions = sorted(set(allowed) - effective_paths)
    if missing_decisions or stale_decisions:
        raise SourceImportError(
            "scope allowlist mismatch; "
            f"unapproved={missing_decisions}, stale={stale_decisions}"
        )
    return allowed


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


def build_manifest(
    root: Path,
    bootstrap_path: Path,
    manifest_path: Path,
    scope_path: Path | None = None,
) -> dict:
    """Construct a deterministic manifest without guessing source metadata."""

    root = root.resolve()
    manifest_relative = _relative_to_root(root, manifest_path, label="manifest path")
    if scope_path is None:
        scope_path = root / "publication" / "scope.json"
    export_files = list(repository_files(root, set()))
    materialized_paths = {relative for relative, _ in export_files}
    validate_export_allowlist(
        root, manifest_relative, scope_path, materialized_paths
    )
    bootstrap = load_bootstrap(bootstrap_path)
    present_paths = set()
    files = []
    counts = {classification: 0 for classification in CLASSIFICATIONS}

    excluded_paths = inventory_excluded_paths(manifest_relative)
    for relative, path in export_files:
        if relative in excluded_paths:
            continue
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
            "excluded_paths": excluded_paths,
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
        "excluded_paths": inventory_excluded_paths(manifest_relative),
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
    scope_path: Path | None = None,
    require_canonical: bool = True,
) -> dict:
    """Verify shape, coverage, bytes, and optionally the authoritative bootstrap."""

    root = root.resolve()
    manifest_relative = _relative_to_root(root, manifest_path, label="manifest path")
    if scope_path is None:
        scope_path = root / "publication" / "scope.json"
    export_files = list(repository_files(root, set()))
    materialized_paths = {relative for relative, _ in export_files}
    validate_export_allowlist(
        root, manifest_relative, scope_path, materialized_paths
    )
    value = load_json(manifest_path)
    _validate_manifest_shape(value, manifest_relative=manifest_relative)

    disk_files = {}
    excluded_paths = set(inventory_excluded_paths(manifest_relative))
    for relative, path in export_files:
        if relative in excluded_paths:
            continue
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
        expected = build_manifest(
            root, bootstrap_path, manifest_path, scope_path=scope_path
        )
        if value != expected:
            raise SourceImportError("manifest does not match the authoritative bootstrap and worktree")
    if require_canonical and manifest_path.read_bytes() != canonical_json(value):
        raise SourceImportError("manifest JSON is not canonically serialized")
    return value


def write_manifest(
    root: Path,
    bootstrap_path: Path,
    manifest_path: Path,
    scope_path: Path | None = None,
) -> dict:
    value = build_manifest(
        root, bootstrap_path, manifest_path, scope_path=scope_path
    )
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = manifest_path.with_name(f".{manifest_path.name}.tmp")
    temporary.write_bytes(canonical_json(value))
    os.replace(temporary, manifest_path)
    return check_manifest(
        root,
        manifest_path,
        bootstrap_path,
        scope_path=scope_path,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", type=Path, default=DEFAULT_BOOTSTRAP)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the existing manifest instead of rebuilding it",
    )
    args = parser.parse_args()
    try:
        if args.check:
            value = check_manifest(
                ROOT, args.manifest, args.bootstrap, scope_path=args.scope
            )
            verb = "validated"
        else:
            value = write_manifest(
                ROOT, args.bootstrap, args.manifest, scope_path=args.scope
            )
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
