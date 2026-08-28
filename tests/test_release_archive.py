import gzip
import hashlib
import importlib.util
import os
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_release_archive", ROOT / "tools" / "build_release_archive.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


EPOCH = 1_788_134_400


def run(*arguments: str, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(arguments),
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_manifest(root: Path) -> None:
    paths = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and ".git" not in path.relative_to(root).parts
        and path.name != "MANIFEST.sha256"
    )
    content = "".join(f"{sha256(root / path)}  {path}\n" for path in paths)
    (root / "MANIFEST.sha256").write_text(content, encoding="utf-8")


def initialize_repository(root: Path) -> None:
    (root / "release").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "release" / "SOURCE_DATE_EPOCH").write_text(
        f"{EPOCH}\n", encoding="ascii"
    )
    (root / "payload.txt").write_text("deterministic payload\n", encoding="utf-8")
    executable = root / "bin" / "verify"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    write_manifest(root)
    run("git", "init", "-b", "main", cwd=root)
    run("git", "config", "user.name", "Archive Test", cwd=root)
    run("git", "config", "user.email", "archive@example.invalid", cwd=root)
    run("git", "add", ".", cwd=root)
    run("git", "commit", "-m", "frozen release", cwd=root)


def commit_manifest_update(root: Path, message: str) -> None:
    run("git", "add", "MANIFEST.sha256", cwd=root)
    run("git", "commit", "-m", message, cwd=root)


class ReleaseArchiveTest(unittest.TestCase):
    def test_build_is_byte_deterministic_and_metadata_is_canonical(self):
        with tempfile.TemporaryDirectory() as raw_repo, tempfile.TemporaryDirectory() as raw_out:
            root = Path(raw_repo)
            output = Path(raw_out)
            initialize_repository(root)
            first = output / "first.tar.gz"
            second = output / "renamed.tar.gz"

            first_digest = MODULE.build_archive(root, first)
            second_digest = MODULE.build_archive(root, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_digest, sha256(first))
            self.assertEqual(MODULE.check_archive(root, first), first_digest)

            gzip_mtime = struct.unpack("<I", first.read_bytes()[4:8])[0]
            self.assertEqual(gzip_mtime, EPOCH)
            tracked = run("git", "ls-files", cwd=root).stdout.decode().splitlines()
            with tarfile.open(first, "r:gz") as archive:
                members = archive.getmembers()
                self.assertEqual([member.name for member in members], sorted(tracked))
                self.assertTrue(all(member.isfile() for member in members))
                for member in members:
                    self.assertEqual(member.uid, 0)
                    self.assertEqual(member.gid, 0)
                    self.assertEqual(member.uname, "")
                    self.assertEqual(member.gname, "")
                    self.assertEqual(member.mtime, EPOCH)
                    expected_mode = 0o755 if member.name == "bin/verify" else 0o644
                    self.assertEqual(member.mode, expected_mode)
                    extracted = archive.extractfile(member)
                    assert extracted is not None
                    self.assertEqual(extracted.read(), (root / member.name).read_bytes())

    def test_dirty_tracked_untracked_and_staged_states_are_rejected(self):
        for mutation in ("tracked", "untracked", "staged"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw_repo, tempfile.TemporaryDirectory() as raw_out:
                root = Path(raw_repo)
                initialize_repository(root)
                if mutation == "tracked":
                    (root / "payload.txt").write_text("changed\n", encoding="utf-8")
                elif mutation == "untracked":
                    (root / "scratch.txt").write_text("untracked\n", encoding="utf-8")
                else:
                    (root / "payload.txt").write_text("staged\n", encoding="utf-8")
                    run("git", "add", "payload.txt", cwd=root)
                with self.assertRaisesRegex(MODULE.ArchiveError, "clean worktree"):
                    MODULE.build_archive(root, Path(raw_out) / "release.tar.gz")

    def test_tracked_symbolic_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw_repo, tempfile.TemporaryDirectory() as raw_out:
            root = Path(raw_repo)
            initialize_repository(root)
            os.symlink("payload.txt", root / "payload-link")
            # The manifest need only have the correct inventory shape: tree-mode
            # validation rejects the link before accepting any payload hash.
            write_manifest(root)
            run("git", "add", ".", cwd=root)
            run("git", "commit", "-m", "add forbidden symlink", cwd=root)
            with self.assertRaisesRegex(MODULE.ArchiveError, "symbolic link"):
                MODULE.build_archive(root, Path(raw_out) / "release.tar.gz")

    def test_manifest_hash_and_inventory_must_be_exact(self):
        for mutation, pattern in (
            ("digest", "manifest SHA-256 mismatch"),
            ("inventory", "manifest inventory mismatch"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw_repo, tempfile.TemporaryDirectory() as raw_out:
                root = Path(raw_repo)
                initialize_repository(root)
                manifest = root / "MANIFEST.sha256"
                lines = manifest.read_text(encoding="utf-8").splitlines()
                if mutation == "digest":
                    lines[0] = "0" * 64 + lines[0][64:]
                else:
                    lines.pop()
                manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
                commit_manifest_update(root, "invalidate manifest")
                with self.assertRaisesRegex(MODULE.ArchiveError, pattern):
                    MODULE.build_archive(root, Path(raw_out) / "release.tar.gz")

    def test_epoch_is_strict_and_archive_must_remain_outside_repo(self):
        with tempfile.TemporaryDirectory() as raw_repo, tempfile.TemporaryDirectory() as raw_out:
            root = Path(raw_repo)
            initialize_repository(root)
            with self.assertRaisesRegex(MODULE.ArchiveError, "outside the repository"):
                MODULE.build_archive(root, root / "release.tar.gz")

            epoch = root / "release" / "SOURCE_DATE_EPOCH"
            epoch.write_text("not-an-epoch\n", encoding="ascii")
            write_manifest(root)
            run("git", "add", ".", cwd=root)
            run("git", "commit", "-m", "invalid epoch", cwd=root)
            with self.assertRaisesRegex(MODULE.ArchiveError, "non-negative integer"):
                MODULE.build_archive(root, Path(raw_out) / "release.tar.gz")

    def test_check_requires_byte_identity_and_regular_archive(self):
        with tempfile.TemporaryDirectory() as raw_repo, tempfile.TemporaryDirectory() as raw_out:
            root = Path(raw_repo)
            output = Path(raw_out)
            initialize_repository(root)
            archive = output / "release.tar.gz"
            MODULE.build_archive(root, archive)
            content = bytearray(archive.read_bytes())
            content[-1] ^= 1
            archive.write_bytes(content)
            with self.assertRaisesRegex(MODULE.ArchiveError, "byte-identical"):
                MODULE.check_archive(root, archive)

            archive.unlink()
            archive.mkdir()
            with self.assertRaisesRegex(MODULE.ArchiveError, "not a regular file"):
                MODULE.check_archive(root, archive)


if __name__ == "__main__":
    unittest.main()
