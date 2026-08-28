#!/usr/bin/env python3
"""Build and verify the deterministic ``tar.gz`` release archive.

The archive is a byte-for-byte rendering of ``HEAD``.  Every tracked path,
including ``MANIFEST.sha256``, is included exactly once.  The manifest binds
all other tracked files and ``release/SOURCE_DATE_EPOCH`` supplies every tar
member timestamp as well as the gzip timestamp.

The destination deliberately has to live outside the repository: the archive
is a release product, not an input to its own inventory.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE = "MANIFEST.sha256"
EPOCH_RELATIVE = "release/SOURCE_DATE_EPOCH"

MANIFEST_LINE_RE = re.compile(r"([0-9a-f]{64})  (.+)\Z")
TREE_RECORD_RE = re.compile(rb"([0-7]{6}) ([a-z]+) ([0-9a-f]+)\t(.*)\Z")
ALLOWED_GIT_MODES = {"100644": 0o644, "100755": 0o755}


class ArchiveError(ValueError):
    """The repository or archive violates the release archive contract."""


class TreeEntry(NamedTuple):
    path: str
    mode: str
    oid: str

    @property
    def archive_mode(self) -> int:
        return ALLOWED_GIT_MODES[self.mode]


def _run_git(
    root: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise ArchiveError("git is required to build a release archive") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        raise ArchiveError(f"git {' '.join(arguments)} failed: {detail}") from exc


def _canonical_path(value: str) -> str:
    if not value or "\\" in value or any(ord(character) < 32 for character in value):
        raise ArchiveError(f"unsafe repository path {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise ArchiveError(f"non-canonical repository path {value!r}")
    if any(part in ("", ".", "..") for part in path.parts):
        raise ArchiveError(f"unsafe repository path {value!r}")
    return value


def _require_repository_root(root: Path) -> Path:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ArchiveError(f"cannot resolve repository root {root}: {exc}") from exc
    top_raw = _run_git(resolved, "rev-parse", "--show-toplevel").stdout.rstrip(b"\n")
    try:
        top = Path(os.fsdecode(top_raw)).resolve(strict=True)
    except (OSError, UnicodeError) as exc:
        raise ArchiveError(f"cannot decode Git repository root: {exc}") from exc
    if top != resolved:
        raise ArchiveError(f"archive root {resolved} is not the Git top level {top}")
    return resolved


def _require_clean(root: Path) -> None:
    status = _run_git(
        root, "status", "--porcelain=v1", "-z", "--untracked-files=all"
    ).stdout
    if status:
        raise ArchiveError(
            "release archive requires a completely clean worktree and index "
            "(including no untracked files)"
        )


def tree_entries(root: Path) -> list[TreeEntry]:
    """Return the canonical regular-file inventory from the ``HEAD`` tree."""

    raw = _run_git(root, "ls-tree", "-rz", "--full-tree", "HEAD").stdout
    entries: list[TreeEntry] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        match = TREE_RECORD_RE.fullmatch(record)
        if match is None:
            raise ArchiveError("Git returned a malformed HEAD tree record")
        mode_raw, kind_raw, oid_raw, path_raw = match.groups()
        try:
            mode = mode_raw.decode("ascii", errors="strict")
            kind = kind_raw.decode("ascii", errors="strict")
            oid = oid_raw.decode("ascii", errors="strict")
            relative = path_raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ArchiveError("release tree paths must be canonical UTF-8") from exc
        relative = _canonical_path(relative)
        if kind != "blob" or mode not in ALLOWED_GIT_MODES:
            description = "symbolic link" if mode == "120000" else "non-regular entry"
            raise ArchiveError(
                f"tracked release path is a {description}: {relative} "
                f"(mode={mode}, type={kind})"
            )
        entries.append(TreeEntry(relative, mode, oid))

    entries.sort(key=lambda entry: entry.path)
    if not entries:
        raise ArchiveError("HEAD has no tracked release files")
    paths = [entry.path for entry in entries]
    if len(paths) != len(set(paths)):
        raise ArchiveError("HEAD contains duplicate release paths")
    return entries


class _BatchReader:
    """Read Git blobs without spawning one process per tracked file."""

    def __init__(self, root: Path):
        self.root = root
        self.process: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> "_BatchReader":
        try:
            self.process = subprocess.Popen(
                ["git", "-C", str(self.root), "cat-file", "--batch"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ArchiveError("git is required to read the release tree") from exc
        return self

    def read(self, oid: str) -> bytes:
        process = self.process
        if process is None or process.stdin is None or process.stdout is None:
            raise ArchiveError("internal Git object reader is not active")
        try:
            process.stdin.write(oid.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline()
        except (BrokenPipeError, OSError) as exc:
            raise ArchiveError(f"cannot query Git object {oid}: {exc}") from exc
        fields = header.rstrip(b"\n").split(b" ")
        if len(fields) != 3 or fields[0] != oid.encode("ascii") or fields[1] != b"blob":
            raise ArchiveError(f"Git object {oid} is unavailable or is not a blob")
        try:
            size = int(fields[2])
        except ValueError as exc:
            raise ArchiveError(f"Git returned an invalid size for object {oid}") from exc
        data = process.stdout.read(size)
        terminator = process.stdout.read(1)
        if len(data) != size or terminator != b"\n":
            raise ArchiveError(f"Git returned a truncated blob {oid}")
        return data

    def __exit__(self, exc_type, exc, traceback) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
        if exc_type is not None:
            process.terminate()
        if process.stdout is not None:
            process.stdout.close()
        stderr = b""
        if process.stderr is not None:
            stderr = process.stderr.read()
            process.stderr.close()
        return_code = process.wait()
        if exc_type is None and return_code != 0:
            detail = stderr.decode("utf-8", errors="replace").strip()
            raise ArchiveError(f"git cat-file --batch failed: {detail}")


def _read_regular_worktree_file(path: Path, relative: str) -> tuple[int, str]:
    """Hash one non-symlink regular file and return its size and SHA-256."""

    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArchiveError(f"cannot open tracked release path {relative}: {exc}") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ArchiveError(f"tracked release path is not a regular file: {relative}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
    finally:
        os.close(descriptor)
    return size, digest.hexdigest()


def parse_manifest(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ArchiveError("MANIFEST.sha256 is not strict UTF-8") from exc
    if not text or not text.endswith("\n"):
        raise ArchiveError("MANIFEST.sha256 must be non-empty and newline-terminated")
    records: dict[str, str] = {}
    previous: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        match = MANIFEST_LINE_RE.fullmatch(line)
        if match is None:
            raise ArchiveError(f"malformed MANIFEST.sha256 line {number}")
        digest, relative = match.groups()
        relative = _canonical_path(relative)
        if relative == MANIFEST_RELATIVE:
            raise ArchiveError("MANIFEST.sha256 cannot contain a circular self-hash")
        if relative in records:
            raise ArchiveError(f"duplicate manifest path {relative!r}")
        if previous is not None and relative <= previous:
            raise ArchiveError("MANIFEST.sha256 paths are not in canonical order")
        records[relative] = digest
        previous = relative
    return records


def _load_epoch(raw: bytes) -> int:
    if re.fullmatch(rb"[0-9]+\n", raw) is None:
        raise ArchiveError(
            f"{EPOCH_RELATIVE} must contain one non-negative integer and a newline"
        )
    epoch = int(raw)
    if epoch > 0xFFFFFFFF:
        raise ArchiveError(f"{EPOCH_RELATIVE} exceeds the portable gzip timestamp range")
    return epoch


def _validate_output_path(root: Path, destination: Path) -> Path:
    try:
        parent = destination.parent.resolve(strict=True)
    except OSError as exc:
        raise ArchiveError(f"archive destination parent is unavailable: {exc}") from exc
    if not parent.is_dir():
        raise ArchiveError("archive destination parent is not a directory")
    resolved = parent / destination.name
    if resolved == root or root in resolved.parents:
        raise ArchiveError("release archive must be written outside the repository")
    try:
        metadata = resolved.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ArchiveError(f"cannot inspect archive destination {resolved}: {exc}") from exc
    else:
        if not stat.S_ISREG(metadata.st_mode):
            raise ArchiveError("archive destination exists and is not a regular file")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _build_to_temporary(root: Path, destination: Path) -> tuple[Path, str]:
    """Render a validated HEAD tree to a temporary file next to destination."""

    entries = tree_entries(root)
    by_path = {entry.path: entry for entry in entries}
    if MANIFEST_RELATIVE not in by_path:
        raise ArchiveError("MANIFEST.sha256 is not tracked in HEAD")
    if EPOCH_RELATIVE not in by_path:
        raise ArchiveError(f"{EPOCH_RELATIVE} is not tracked in HEAD")

    descriptor, temporary_raw = tempfile.mkstemp(
        prefix=f".{destination.name}.tmp-", dir=destination.parent
    )
    temporary = Path(temporary_raw)
    try:
        with _BatchReader(root) as reader:
            manifest_raw = reader.read(by_path[MANIFEST_RELATIVE].oid)
            records = parse_manifest(manifest_raw)
            wanted = [entry.path for entry in entries if entry.path != MANIFEST_RELATIVE]
            actual = list(records)
            if actual != wanted:
                missing = sorted(set(wanted) - set(actual))
                extra = sorted(set(actual) - set(wanted))
                raise ArchiveError(
                    f"manifest inventory mismatch: missing={missing}, extra={extra}"
                )
            epoch_raw = reader.read(by_path[EPOCH_RELATIVE].oid)
            epoch = _load_epoch(epoch_raw)

            with os.fdopen(descriptor, "wb") as raw_output:
                descriptor = -1
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    compresslevel=9,
                    fileobj=raw_output,
                    mtime=epoch,
                ) as compressed:
                    with tarfile.open(
                        fileobj=compressed,
                        mode="w|",
                        format=tarfile.PAX_FORMAT,
                    ) as archive:
                        for entry in entries:
                            if entry.path == MANIFEST_RELATIVE:
                                content = manifest_raw
                            elif entry.path == EPOCH_RELATIVE:
                                content = epoch_raw
                            else:
                                content = reader.read(entry.oid)

                            worktree_size, worktree_digest = _read_regular_worktree_file(
                                root / entry.path, entry.path
                            )
                            blob_digest = hashlib.sha256(content).hexdigest()
                            if worktree_size != len(content) or worktree_digest != blob_digest:
                                raise ArchiveError(
                                    f"worktree bytes differ from HEAD for {entry.path}"
                                )
                            if entry.path != MANIFEST_RELATIVE:
                                expected_digest = records[entry.path]
                                if expected_digest != blob_digest:
                                    raise ArchiveError(
                                        "manifest SHA-256 mismatch: " + entry.path
                                    )

                            information = tarfile.TarInfo(entry.path)
                            information.type = tarfile.REGTYPE
                            information.mode = entry.archive_mode
                            information.uid = 0
                            information.gid = 0
                            information.uname = ""
                            information.gname = ""
                            information.mtime = epoch
                            information.size = len(content)
                            information.pax_headers = {}
                            archive.addfile(information, io.BytesIO(content))
                raw_output.flush()
                os.fsync(raw_output.fileno())

        _require_clean(root)
        os.chmod(temporary, 0o644)
        return temporary, _sha256_file(temporary)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def build_archive(root: Path, destination: Path) -> str:
    """Atomically create an archive and return its SHA-256 digest."""

    root = _require_repository_root(root)
    destination = _validate_output_path(root, destination)
    _require_clean(root)
    temporary, digest = _build_to_temporary(root, destination)
    try:
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return digest


def _files_equal(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open("rb") as left_stream, right.open("rb") as right_stream:
        while True:
            left_block = left_stream.read(1024 * 1024)
            right_block = right_stream.read(1024 * 1024)
            if left_block != right_block:
                return False
            if not left_block:
                return True


def check_archive(root: Path, archive: Path) -> str:
    """Rebuild the archive and require byte-for-byte identity."""

    root = _require_repository_root(root)
    archive = _validate_output_path(root, archive)
    try:
        metadata = archive.lstat()
    except OSError as exc:
        raise ArchiveError(f"cannot read release archive {archive}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ArchiveError("release archive is not a regular file")

    _require_clean(root)
    with tempfile.TemporaryDirectory(prefix="archive-check-", dir=archive.parent) as raw:
        rebuilt = Path(raw) / "rebuilt.tar.gz"
        build_archive(root, rebuilt)
        if not _files_equal(archive, rebuilt):
            raise ArchiveError("release archive is not byte-identical to a clean rebuild")
    return _sha256_file(archive)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root (default: the checkout containing this tool)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build an atomic deterministic archive")
    build.add_argument("archive", type=Path, help="output .tar.gz path outside the repo")
    check = commands.add_parser("check", help="require byte identity with a clean rebuild")
    check.add_argument("archive", type=Path, help="existing .tar.gz path outside the repo")
    return parser


def main(arguments: list[str] | None = None) -> int:
    parser = _parser()
    values = parser.parse_args(arguments)
    try:
        if values.command == "build":
            digest = build_archive(values.root, values.archive)
            action = "built"
        else:
            digest = check_archive(values.root, values.archive)
            action = "verified"
    except ArchiveError as exc:
        print(f"release archive error: {exc}", file=sys.stderr)
        return 2
    print(f"{action}: {values.archive}")
    print(f"sha256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
