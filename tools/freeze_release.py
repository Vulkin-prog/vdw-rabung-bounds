#!/usr/bin/env python3
"""Create or verify the byte-exact archival release freeze.

The release inventory is the Git index/tree, not an ad-hoc filesystem walk.
``MANIFEST.sha256`` therefore contains every tracked regular file except
itself (a cryptographic self-hash is impossible).  Verification rejects a
missing or extra path as well as a digest mismatch.

The PDF timestamp is read from the tracked ``release/SOURCE_DATE_EPOCH`` file.
For a final release it must be midnight UTC on ``CITATION.cff``'s
``date-released``.  In particular, it is never inferred from ``HEAD``: the
committed PDF can be rebuilt without moving its own timestamp input.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE = "MANIFEST.sha256"
PDF_RELATIVE = "paper/main.pdf"
EPOCH_RELATIVE = "release/SOURCE_DATE_EPOCH"
ZENODO_RELATIVE = "release/zenodo-metadata.json"
CITATION_RELATIVE = "CITATION.cff"
STATUS_RELATIVE = "STATUS.json"
RIGHTS_MAP_RELATIVE = "release/rights-map.json"
RIGHTS_SCHEMA = "vdw-release-rights/v1"
STATUS_SCHEMA = "vdw-publication-status/v1"

ALLOWED_GATE_STATUSES = {
    "open",
    "blocked_pc",
    "blocked_external",
    "blocked_human_decision",
    "passed",
}
REQUIRED_RELEASE_GATES = {
    "source-export",
    "cpu-ci-clean-tag",
    "bibliography-primary-source-audit",
    "paper-clean-build",
    "claim-manifests-13",
    "campaign-archive-515",
    "ordered-prime-identity-515",
    "cuda-release-qualification",
    "external-replication-4",
    "outbound-rights",
    "doi-tag-archive-freeze",
}
EXPECTED_KEYWORDS = (
    "van der Waerden numbers",
    "Rabung certificates",
    "power-residue colorings",
    "GPU computation",
    "reproducible research",
)

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
DOI_RE = re.compile(r"10\.\d{4,9}/\S+\Z", re.IGNORECASE)
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[-+][0-9A-Za-z.-]+)?\Z")
LICENSE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*\Z")
PLACEHOLDER_RE = re.compile(
    r"@@|\b(?:TBD|TODO|FIXME|PENDING)\b|PRIVATE\s+STAGING|ONCE\s+IT\s+EXISTS",
    re.IGNORECASE,
)
MANIFEST_LINE_RE = re.compile(r"([0-9a-f]{64})  (.+)\Z")
REPOSITORY_URL = "https://github.com/Vulkin-prog/vdw-rabung-bounds"

STAGING_TEX_PATTERNS = (
    re.compile(r"\bprivate\s+(?:prepublication|preparation)\b", re.IGNORECASE),
    re.compile(r"\bnot\s+(?:an?\s+|the\s+)?citable\s+release\b", re.IGNORECASE),
    re.compile(r"\bfinal\b[^\n.]{0,120}\bpending\b", re.IGNORECASE),
    re.compile(r"\bnot\s+yet\b[^\n.]{0,120}\b(?:frozen|populated|published)\b", re.IGNORECASE),
    re.compile(r"\bonce\s+it\s+exists\b", re.IGNORECASE),
    re.compile(r"\brelease\s+gates?\b[^\n.]{0,80}\b(?:open|blocked|unfinished)\b", re.IGNORECASE),
    re.compile(r"\bblocked_(?:pc|external|human_decision)\b", re.IGNORECASE),
)


class FreezeError(ValueError):
    """A release candidate violates the archival freeze policy."""


def _run_git(root: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise FreezeError("git is required for a release freeze") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        raise FreezeError(f"git {' '.join(arguments)} failed: {detail}") from exc


def _strict_json(path: Path):
    def reject_constant(value: str):
        raise FreezeError(f"non-finite JSON constant {value!r} in {path}")

    def reject_duplicate(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise FreezeError(f"duplicate JSON key {key!r} in {path}")
            value[key] = item
        return value

    try:
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raise FreezeError(f"UTF-8 BOM is forbidden: {path}")
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreezeError(f"cannot read strict JSON {path}: {exc}") from exc


def _yaml_scalar(raw: str, *, field: str) -> str:
    value = raw.strip()
    if not value or value[0] in "|>":
        raise FreezeError(f"CITATION.cff {field} must be a one-line scalar")
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise FreezeError(f"invalid quoted CITATION.cff {field}: {exc}") from exc
        if not isinstance(parsed, str):
            raise FreezeError(f"CITATION.cff {field} must be a string")
        return parsed
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise FreezeError(f"invalid quoted CITATION.cff {field}")
        return value[1:-1].replace("''", "'")
    return value


def _cff_block(lines: list[str], key: str) -> list[tuple[int, str]]:
    start = None
    for index, line in enumerate(lines):
        if line == f"{key}:":
            if start is not None:
                raise FreezeError(f"duplicate top-level CITATION.cff field {key!r}")
            start = index
    if start is None:
        raise FreezeError(f"CITATION.cff lacks final field {key!r}")

    block = []
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            break
        if line.strip() and not line.lstrip().startswith("#"):
            block.append((index + 1, line))
    if not block:
        raise FreezeError(f"CITATION.cff {key} must not be empty")
    return block


def _cff_authors(lines: list[str]) -> tuple[str, ...]:
    authors: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for number, line in _cff_block(lines, "authors"):
        start = re.fullmatch(r"  - ([A-Za-z][A-Za-z0-9-]*):(?:[ \t]*(.*))?", line)
        continuation = re.fullmatch(
            r"    ([A-Za-z][A-Za-z0-9-]*):(?:[ \t]*(.*))?", line
        )
        if start is not None:
            current = {}
            authors.append(current)
            match = start
        elif continuation is not None and current is not None:
            match = continuation
        else:
            raise FreezeError(f"unsupported CITATION.cff authors line {number}")
        key, raw = match.groups()
        if key in current:
            raise FreezeError(f"duplicate CITATION.cff author field {key!r}")
        if not raw:
            raise FreezeError(f"CITATION.cff author field {key!r} must be scalar")
        current[key] = _yaml_scalar(raw, field=f"authors.{key}")

    names = []
    for author in authors:
        if not author.get("family-names") or not author.get("given-names"):
            raise FreezeError("each CITATION.cff author needs family-names and given-names")
        names.append(f"{author['family-names']}, {author['given-names']}")
    if len(names) != len(set(names)):
        raise FreezeError("CITATION.cff contains duplicate authors")
    return tuple(names)


def _cff_keywords(lines: list[str]) -> tuple[str, ...]:
    keywords = []
    for number, line in _cff_block(lines, "keywords"):
        match = re.fullmatch(r"  -[ \t]+(.+)", line)
        if match is None:
            raise FreezeError(f"unsupported CITATION.cff keywords line {number}")
        keywords.append(_yaml_scalar(match.group(1), field="keywords"))
    if len(keywords) != len(set(keywords)):
        raise FreezeError("CITATION.cff contains duplicate keywords")
    return tuple(keywords)


def load_citation(path: Path) -> dict:
    """Read the top-level scalar fields needed by the freeze, without PyYAML."""

    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise FreezeError(f"cannot read {path}: {exc}") from exc
    if PLACEHOLDER_RE.search(text):
        raise FreezeError("CITATION.cff still contains staging or placeholder text")

    lines = text.splitlines()
    fields: dict = {}
    for number, line in enumerate(lines, start=1):
        if not line or line[0].isspace() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*):(?:[ \t]*(.*))?", line)
        if match is None:
            raise FreezeError(f"unsupported top-level CITATION.cff line {number}")
        key, raw = match.groups()
        if key in fields:
            raise FreezeError(f"duplicate top-level CITATION.cff field {key!r}")
        if raw:
            fields[key] = _yaml_scalar(raw, field=key)

    required = {
        "cff-version",
        "title",
        "type",
        "version",
        "date-released",
        "doi",
        "license",
        "repository-code",
    }
    missing = sorted(required - fields.keys())
    if missing:
        raise FreezeError(f"CITATION.cff lacks final scalar fields: {', '.join(missing)}")
    if fields["repository-code"].rstrip("/") != REPOSITORY_URL:
        raise FreezeError("CITATION.cff repository-code does not name this repository")
    if fields["type"] != "software":
        raise FreezeError("CITATION.cff type must be 'software' for this release")
    if not VERSION_RE.fullmatch(fields["version"]):
        raise FreezeError(f"unsupported release version {fields['version']!r}")
    normalize_doi(fields["doi"])
    release_date(fields["date-released"])
    if not fields["license"].strip() or PLACEHOLDER_RE.search(fields["license"]):
        raise FreezeError("CITATION.cff license is not final")
    if LICENSE_ID_RE.fullmatch(fields["license"]) is None:
        raise FreezeError("CITATION.cff license must be one SPDX-style identifier")
    fields["author_names"] = _cff_authors(lines)
    if "Pouly, Brice" not in fields["author_names"]:
        raise FreezeError("CITATION.cff must identify Brice Pouly as an author")
    fields["keywords"] = _cff_keywords(lines)
    if fields["keywords"] != EXPECTED_KEYWORDS:
        raise FreezeError("CITATION.cff keywords do not equal the expected release keywords")
    return fields


def normalize_doi(value: str) -> str:
    normalized = value.strip()
    normalized = re.sub(r"^https?://(?:dx\.)?doi\.org/", "", normalized, flags=re.I)
    normalized = re.sub(r"^doi:\s*", "", normalized, flags=re.I)
    if not DOI_RE.fullmatch(normalized) or any(char.isspace() for char in normalized):
        raise FreezeError(f"malformed DOI {value!r}")
    return normalized.casefold()


def release_date(value: str) -> dt.date:
    try:
        parsed = dt.date.fromisoformat(value)
    except ValueError as exc:
        raise FreezeError(f"date-released is not an ISO calendar date: {value!r}") from exc
    if parsed.isoformat() != value:
        raise FreezeError(f"date-released is not canonical YYYY-MM-DD: {value!r}")
    return parsed


def expected_epoch(date_value: str) -> int:
    date = release_date(date_value)
    instant = dt.datetime.combine(date, dt.time(), tzinfo=dt.timezone.utc)
    return int(instant.timestamp())


def load_epoch(root: Path, citation: dict) -> int:
    path = root / EPOCH_RELATIVE
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise FreezeError(f"cannot read tracked PDF epoch policy {path}: {exc}") from exc
    if not re.fullmatch(rb"[0-9]+\n", raw):
        raise FreezeError(f"{EPOCH_RELATIVE} must contain one integer and a newline")
    value = int(raw)
    wanted = expected_epoch(citation["date-released"])
    if value != wanted:
        raise FreezeError(
            f"{EPOCH_RELATIVE}={value}, expected midnight UTC on date-released ({wanted})"
        )
    return value


def _zenodo_dois(root_value: dict, metadata: dict, related: list) -> set[str]:
    candidates = []
    for container in (root_value, metadata):
        if isinstance(container.get("doi"), str):
            candidates.append(container["doi"])
        reserved = container.get("prereserve_doi")
        if isinstance(reserved, dict) and isinstance(reserved.get("doi"), str):
            candidates.append(reserved["doi"])
    for row in related:
        if (
            isinstance(row, dict)
            and str(row.get("scheme", "")).casefold() == "doi"
            and str(row.get("relation", "")).casefold() == "isidenticalto"
            and isinstance(row.get("identifier"), str)
        ):
            candidates.append(row["identifier"])
    normalized = set()
    for value in candidates:
        normalized.add(normalize_doi(value))
    return normalized


def validate_zenodo(root: Path, citation: dict, tag: str) -> None:
    path = root / ZENODO_RELATIVE
    value = _strict_json(path)
    if not isinstance(value, dict) or not isinstance(value.get("metadata"), dict):
        raise FreezeError("release/zenodo-metadata.json must contain a metadata object")
    if PLACEHOLDER_RE.search(json.dumps(value, ensure_ascii=False)):
        raise FreezeError("release/zenodo-metadata.json still contains placeholders")
    metadata = value["metadata"]
    related = metadata.get("related_identifiers")
    if not isinstance(related, list):
        raise FreezeError("Zenodo metadata.related_identifiers must be an array")

    expected = {
        "version": citation["version"],
        "publication_date": citation["date-released"],
        "license": citation["license"],
    }
    for field, wanted in expected.items():
        if metadata.get(field) != wanted:
            raise FreezeError(
                f"Zenodo metadata.{field}={metadata.get(field)!r}, expected {wanted!r}"
            )
    allowed_titles = {
        citation["title"],
        f"Reproducibility package for: {citation['title']}",
    }
    if metadata.get("title") not in allowed_titles:
        raise FreezeError("Zenodo title is inconsistent with CITATION.cff")
    if not isinstance(metadata.get("description"), str) or not metadata["description"].strip():
        raise FreezeError("Zenodo description is empty")
    if metadata.get("upload_type") != "software":
        raise FreezeError("Zenodo metadata.upload_type must be 'software'")

    creators = metadata.get("creators")
    if not isinstance(creators, list) or not creators:
        raise FreezeError("Zenodo metadata.creators must be a non-empty array")
    creator_names = []
    for creator in creators:
        if not isinstance(creator, dict) or not isinstance(creator.get("name"), str):
            raise FreezeError("every Zenodo creator must contain a string name")
        name = creator["name"].strip()
        if not name:
            raise FreezeError("Zenodo creator names must not be empty")
        creator_names.append(name)
    if len(creator_names) != len(set(creator_names)):
        raise FreezeError("Zenodo metadata contains duplicate creators")
    if tuple(creator_names) != citation["author_names"]:
        raise FreezeError("Zenodo creators do not exactly match CITATION.cff authors")

    keywords = metadata.get("keywords")
    if not isinstance(keywords, list) or any(not isinstance(item, str) for item in keywords):
        raise FreezeError("Zenodo metadata.keywords must be an array of strings")
    if tuple(keywords) != citation["keywords"] or tuple(keywords) != EXPECTED_KEYWORDS:
        raise FreezeError("Zenodo keywords do not match CITATION.cff and the expected set")

    citation_doi = normalize_doi(citation["doi"])
    dois = _zenodo_dois(value, metadata, related)
    if citation_doi not in dois:
        raise FreezeError("Zenodo final metadata does not bind the CITATION.cff DOI")

    expected_url = f"{REPOSITORY_URL}/releases/tag/{tag}"
    tag_rows = [
        row
        for row in related
        if isinstance(row, dict)
        and row.get("relation") == "isIdenticalTo"
        and row.get("scheme") == "url"
    ]
    if len(tag_rows) != 1 or tag_rows[0].get("identifier") != expected_url:
        raise FreezeError(f"Zenodo metadata must bind exactly the release URL {expected_url}")


def _exact_object(value, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise FreezeError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        raise FreezeError(
            f"{label} fields mismatch: missing={sorted(keys - actual)}, "
            f"extra={sorted(actual - keys)}"
        )
    return value


def _nonempty_regular(root: Path, relative: str, label: str) -> None:
    path = root / _canonical_repo_path(relative)
    try:
        resolved = path.resolve(strict=True)
        mode = path.lstat().st_mode
        size = path.stat().st_size
    except OSError as exc:
        raise FreezeError(f"{label} is unavailable: {relative}: {exc}") from exc
    if resolved != root.resolve() / PurePosixPath(relative):
        raise FreezeError(f"{label} traverses a symlink: {relative}")
    if not stat.S_ISREG(mode) or path.is_symlink() or size == 0:
        raise FreezeError(f"{label} must be a non-empty regular file: {relative}")


def validate_rights(root: Path, citation: dict) -> set[str]:
    value = _strict_json(root / RIGHTS_MAP_RELATIVE)
    value = _exact_object(value, {"schema", "components", "third_party"}, "rights map")
    if value["schema"] != RIGHTS_SCHEMA:
        raise FreezeError(f"rights map schema must be {RIGHTS_SCHEMA!r}")

    components = _exact_object(
        value["components"], {"code", "paper_pdf", "data"}, "rights map components"
    )
    required_paths = {RIGHTS_MAP_RELATIVE}
    decisions = {}
    for component in ("code", "paper_pdf", "data"):
        row = _exact_object(
            components[component], {"license_id", "license_file"}, f"rights map {component}"
        )
        identifier = row["license_id"]
        relative = row["license_file"]
        if not isinstance(identifier, str) or LICENSE_ID_RE.fullmatch(identifier) is None:
            raise FreezeError(f"rights map {component}.license_id is not an SPDX-style identifier")
        if PLACEHOLDER_RE.search(identifier):
            raise FreezeError(f"rights map {component}.license_id is still a placeholder")
        if not isinstance(relative, str):
            raise FreezeError(f"rights map {component}.license_file must be a path string")
        relative = _canonical_repo_path(relative)
        _nonempty_regular(root, relative, f"rights map {component} licence")
        required_paths.add(relative)
        decisions[component] = identifier

    if decisions["code"] != citation["license"]:
        raise FreezeError("CITATION.cff license does not equal the code licence in rights map")

    third_party = _exact_object(
        value["third_party"],
        {"redistributed", "policy", "notice_file"},
        "rights map third_party",
    )
    if third_party["redistributed"] is not False or third_party["policy"] != "not_redistributed":
        raise FreezeError("rights map must explicitly record third-party material as not redistributed")
    notice_relative = third_party["notice_file"]
    if not isinstance(notice_relative, str):
        raise FreezeError("rights map third_party.notice_file must be a path string")
    notice_relative = _canonical_repo_path(notice_relative)
    _nonempty_regular(root, notice_relative, "third-party notice")
    required_paths.add(notice_relative)
    try:
        notice_text = (root / notice_relative).read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise FreezeError(f"cannot read third-party notice: {exc}") from exc
    if not (
        re.search(r"\bno\s+third-party\b", notice_text, re.IGNORECASE)
        and re.search(r"\bnot\s+redistributed\b", notice_text, re.IGNORECASE)
    ):
        raise FreezeError("third-party notice must state that no third-party material is redistributed")

    status_path = root / "RIGHTS-STATUS.md"
    try:
        status_text = status_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise FreezeError(f"cannot read {status_path}: {exc}") from exc
    if re.search(r"\b(?:decision\s+)?pending\b", status_text, re.IGNORECASE):
        raise FreezeError("RIGHTS-STATUS.md still records a pending outbound licence")
    for component, identifier in decisions.items():
        if identifier.casefold() not in status_text.casefold():
            raise FreezeError(
                f"RIGHTS-STATUS.md does not name the {component} licence identifier"
            )
    required_paths.add("RIGHTS-STATUS.md")
    return required_paths


def validate_status(root: Path) -> None:
    value = _strict_json(root / STATUS_RELATIVE)
    if not isinstance(value, dict):
        raise FreezeError("STATUS.json must contain an object")
    if value.get("schema") != STATUS_SCHEMA:
        raise FreezeError(f"STATUS.json schema must be {STATUS_SCHEMA!r}")
    if value.get("artifact") != "vdw-rabung-bounds":
        raise FreezeError("STATUS.json artifact does not name this release")
    if value.get("repository_state") != "archived_release":
        raise FreezeError("STATUS.json repository_state must be 'archived_release'")
    if value.get("citable_release") is not True:
        raise FreezeError("STATUS.json citable_release must be true")
    allowed = value.get("allowed_gate_statuses")
    if (
        not isinstance(allowed, list)
        or len(allowed) != len(ALLOWED_GATE_STATUSES)
        or set(allowed) != ALLOWED_GATE_STATUSES
    ):
        raise FreezeError("STATUS.json allowed_gate_statuses does not match the current schema")

    rows = value.get("release_gates")
    if not isinstance(rows, list):
        raise FreezeError("STATUS.json release_gates must be an array")
    gates = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise FreezeError("every STATUS.json release gate must have a string id")
        gate_id = row["id"]
        if gate_id in gates:
            raise FreezeError(f"duplicate STATUS.json release gate {gate_id!r}")
        gates[gate_id] = row
        if row.get("status") not in ALLOWED_GATE_STATUSES:
            raise FreezeError(f"unsupported STATUS.json gate status for {gate_id!r}")
        if row.get("status") != "passed":
            raise FreezeError(f"STATUS.json release gate {gate_id!r} is not passed")
        evidence = row.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise FreezeError(f"STATUS.json release gate {gate_id!r} lacks evidence")
        for relative in evidence:
            if not isinstance(relative, str):
                raise FreezeError(f"STATUS.json gate {gate_id!r} evidence must be path strings")
            _canonical_repo_path(relative)
        if not isinstance(row.get("note"), str) or not row["note"].strip():
            raise FreezeError(f"STATUS.json release gate {gate_id!r} lacks a note")

    actual = set(gates)
    if actual != REQUIRED_RELEASE_GATES:
        raise FreezeError(
            "STATUS.json release gate set mismatch: "
            f"missing={sorted(REQUIRED_RELEASE_GATES - actual)}, "
            f"extra={sorted(actual - REQUIRED_RELEASE_GATES)}"
        )


def validate_manuscript_finality(root: Path) -> set[str]:
    tex_root = root / "paper" / "tex"
    try:
        sources = sorted(tex_root.rglob("*.tex"))
    except OSError as exc:
        raise FreezeError(f"cannot enumerate manuscript TeX sources: {exc}") from exc
    if not sources:
        raise FreezeError("paper/tex contains no TeX source")
    relatives = set()
    for path in sources:
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as exc:
            raise FreezeError(f"TeX source lies outside the release root: {path}") from exc
        relative = _canonical_repo_path(relative)
        _nonempty_regular(root, relative, "manuscript TeX source")
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError) as exc:
            raise FreezeError(f"cannot read manuscript TeX source {relative}: {exc}") from exc
        for pattern in (PLACEHOLDER_RE, *STAGING_TEX_PATTERNS):
            match = pattern.search(text)
            if match is not None:
                line = text.count("\n", 0, match.start()) + 1
                raise FreezeError(
                    f"manuscript staging marker in {relative}:{line}: {match.group(0)!r}"
                )
        relatives.add(relative)
    return relatives


def expected_tag(citation: dict[str, str], supplied: str | None) -> str:
    wanted = f"v{citation['version']}"
    if supplied is not None and supplied != wanted:
        raise FreezeError(f"release tag {supplied!r} does not equal version-derived tag {wanted!r}")
    return wanted


def _canonical_repo_path(value: str) -> str:
    if not value or "\\" in value or any(ord(char) < 32 for char in value):
        raise FreezeError(f"unsafe repository path {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise FreezeError(f"non-canonical repository path {value!r}")
    if any(part in ("", ".", "..") for part in path.parts):
        raise FreezeError(f"unsafe repository path {value!r}")
    return value


def tracked_paths(root: Path) -> list[str]:
    top = _run_git(root, "rev-parse", "--show-toplevel").stdout.rstrip(b"\n")
    try:
        git_root = Path(os.fsdecode(top)).resolve()
    except (OSError, UnicodeError) as exc:
        raise FreezeError(f"cannot decode Git repository root: {exc}") from exc
    if git_root != root.resolve():
        raise FreezeError(f"release root {root.resolve()} is not the Git top level {git_root}")

    raw = _run_git(root, "ls-files", "-z").stdout
    paths = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            relative = item.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FreezeError("release paths must be UTF-8") from exc
        paths.append(_canonical_repo_path(relative))
    if len(paths) != len(set(paths)):
        raise FreezeError("Git index contains duplicate release paths")
    return sorted(paths)


def _validate_regular_files(root: Path, paths: list[str]) -> None:
    for relative in paths:
        path = root / relative
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise FreezeError(f"tracked release path is unavailable: {relative}: {exc}") from exc
        if not stat.S_ISREG(mode):
            raise FreezeError(f"tracked release path is not a regular file: {relative}")


def ensure_candidate_index(root: Path, *, creating: bool) -> list[str]:
    paths = tracked_paths(root)
    if creating:
        unstaged = _run_git(root, "diff", "--name-only", "-z").stdout
        dirty = {
            item.decode("utf-8", errors="strict")
            for item in unstaged.split(b"\0")
            if item and item.decode("utf-8", errors="strict") != MANIFEST_RELATIVE
        }
        if dirty:
            raise FreezeError(
                "candidate has unstaged tracked changes: " + ", ".join(sorted(dirty))
            )
    else:
        if _run_git(root, "diff", "--quiet", check=False).returncode != 0:
            raise FreezeError("release check requires a clean tracked worktree")
        if _run_git(root, "diff", "--cached", "--quiet", check=False).returncode != 0:
            raise FreezeError("release check requires HEAD to match the Git index")

    untracked_raw = _run_git(root, "ls-files", "--others", "--exclude-standard", "-z").stdout
    untracked = {
        item.decode("utf-8", errors="strict")
        for item in untracked_raw.split(b"\0")
        if item and item.decode("utf-8", errors="strict") != MANIFEST_RELATIVE
    }
    if untracked:
        raise FreezeError(
            "untracked, non-ignored files are outside the release inventory: "
            + ", ".join(sorted(untracked))
        )
    if not creating and MANIFEST_RELATIVE not in paths:
        raise FreezeError("MANIFEST.sha256 is not tracked")
    inventory = [path for path in paths if path != MANIFEST_RELATIVE]
    _validate_regular_files(root, inventory)
    return inventory


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_manifest_bytes(root: Path, paths: list[str]) -> bytes:
    lines = [f"{sha256_file(root / relative)}  {relative}\n" for relative in paths]
    return "".join(lines).encode("utf-8")


def parse_manifest(path: Path) -> dict[str, str]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise FreezeError(f"cannot read {path}: {exc}") from exc
    if not text or not text.endswith("\n"):
        raise FreezeError("MANIFEST.sha256 must be non-empty and newline-terminated")
    records = {}
    previous = None
    for number, line in enumerate(text.splitlines(), start=1):
        match = MANIFEST_LINE_RE.fullmatch(line)
        if match is None:
            raise FreezeError(f"malformed MANIFEST.sha256 line {number}")
        digest, relative = match.groups()
        relative = _canonical_repo_path(relative)
        if relative == MANIFEST_RELATIVE:
            raise FreezeError("MANIFEST.sha256 cannot contain a circular self-hash")
        if relative in records:
            raise FreezeError(f"duplicate manifest path {relative!r}")
        if previous is not None and relative <= previous:
            raise FreezeError("MANIFEST.sha256 paths are not in canonical order")
        records[relative] = digest
        previous = relative
    return records


def validate_manifest(root: Path, inventory: list[str]) -> None:
    records = parse_manifest(root / MANIFEST_RELATIVE)
    wanted = set(inventory)
    actual = set(records)
    missing = sorted(wanted - actual)
    extra = sorted(actual - wanted)
    if missing or extra:
        raise FreezeError(f"manifest inventory mismatch: missing={missing}, extra={extra}")
    mismatches = [
        relative
        for relative in inventory
        if records[relative] != sha256_file(root / relative)
    ]
    if mismatches:
        raise FreezeError("manifest SHA-256 mismatch: " + ", ".join(mismatches))
    if PDF_RELATIVE not in records:
        raise FreezeError("MANIFEST.sha256 does not bind paper/main.pdf")


def verify_pdf_reproducible(root: Path) -> str:
    frozen = root / PDF_RELATIVE
    if not frozen.is_file() or frozen.is_symlink() or frozen.stat().st_size == 0:
        raise FreezeError("paper/main.pdf is not a non-empty regular file")
    builder = root / "scripts" / "build_paper.sh"
    if not builder.is_file():
        raise FreezeError("scripts/build_paper.sh is absent")
    with tempfile.TemporaryDirectory(prefix="vdw-rabung-freeze-") as raw:
        rebuilt = Path(raw) / "main.pdf"
        try:
            completed = subprocess.run(
                [str(builder), str(rebuilt)],
                cwd=root,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except OSError as exc:
            raise FreezeError(f"cannot execute paper builder: {exc}") from exc
        if completed.returncode != 0:
            tail = "\n".join(completed.stdout.splitlines()[-40:])
            raise FreezeError(f"clean PDF rebuild failed:\n{tail}")
        frozen_digest = sha256_file(frozen)
        rebuilt_digest = sha256_file(rebuilt)
        if frozen_digest != rebuilt_digest:
            raise FreezeError(
                "paper/main.pdf differs from a two-pass deterministic clean rebuild: "
                f"frozen={frozen_digest}, rebuilt={rebuilt_digest}"
            )
        return frozen_digest


def verify_head_tag(root: Path, tag: str) -> None:
    head = _run_git(root, "rev-parse", "HEAD^{commit}").stdout.strip()
    tagged = _run_git(root, "rev-parse", f"refs/tags/{tag}^{{commit}}").stdout.strip()
    if head != tagged:
        raise FreezeError(f"tag {tag!r} does not resolve to HEAD")


def validate_metadata(root: Path, supplied_tag: str | None) -> tuple[dict, str, set[str]]:
    citation = load_citation(root / CITATION_RELATIVE)
    tag = expected_tag(citation, supplied_tag)
    load_epoch(root, citation)
    validate_zenodo(root, citation, tag)
    rights_paths = validate_rights(root, citation)
    validate_status(root)
    tex_paths = validate_manuscript_finality(root)
    required_paths = rights_paths | tex_paths | {
        PDF_RELATIVE,
        EPOCH_RELATIVE,
        ZENODO_RELATIVE,
        CITATION_RELATIVE,
        STATUS_RELATIVE,
    }
    return citation, tag, required_paths


def create_freeze(root: Path, supplied_tag: str) -> tuple[str, str]:
    _, tag, required_paths = validate_metadata(root, supplied_tag)
    inventory = ensure_candidate_index(root, creating=True)
    for required in sorted(required_paths):
        if required not in inventory:
            raise FreezeError(f"required release file is not tracked/staged: {required}")
    pdf_digest = verify_pdf_reproducible(root)
    content = build_manifest_bytes(root, inventory)
    destination = root / MANIFEST_RELATIVE
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        temporary.write_bytes(content)
        os.chmod(temporary, 0o644)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return tag, pdf_digest


def check_freeze(
    root: Path,
    supplied_tag: str | None,
    *,
    require_head_tag: bool,
    verify_pdf: bool = True,
) -> tuple[str, str]:
    _, tag, required_paths = validate_metadata(root, supplied_tag)
    inventory = ensure_candidate_index(root, creating=False)
    for required in sorted(required_paths):
        if required not in inventory:
            raise FreezeError(f"required release file is not tracked: {required}")
    validate_manifest(root, inventory)
    pdf_digest = sha256_file(root / PDF_RELATIVE)
    if verify_pdf:
        pdf_digest = verify_pdf_reproducible(root)
    if require_head_tag:
        verify_head_tag(root, tag)
    return tag, pdf_digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="verify the staged candidate and write MANIFEST.sha256")
    create.add_argument("--tag", required=True)
    check = subparsers.add_parser("check", help="verify the immutable release freeze")
    check.add_argument("--tag")
    check.add_argument("--require-head-tag", action="store_true")
    check.add_argument(
        "--skip-pdf-rebuild",
        action="store_true",
        help="perform the structural freeze check without invoking the TeX rebuild",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.root.resolve()
    try:
        if args.command == "create":
            tag, digest = create_freeze(root, args.tag)
            print(f"RELEASE_FREEZE_CREATED tag={tag} paper_sha256={digest}")
            print("Stage MANIFEST.sha256, commit the exact candidate, then create the immutable tag.")
        else:
            tag, digest = check_freeze(
                root,
                args.tag,
                require_head_tag=args.require_head_tag,
                verify_pdf=not args.skip_pdf_rebuild,
            )
            structural = " structural_only=true" if args.skip_pdf_rebuild else ""
            print(f"RELEASE_FREEZE_OK tag={tag} paper_sha256={digest}{structural}")
    except FreezeError as exc:
        print(f"RELEASE_FREEZE_ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
