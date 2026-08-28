import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_source_import", ROOT / "tools" / "build_source_import.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class SourceImportTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.root = base / "repository"
        self.root.mkdir()
        (self.root / "publication").mkdir()
        (self.root / "src").mkdir()
        self.manifest = self.root / "publication" / "source-import.json"
        self.scope = self.root / "publication" / "scope.json"
        self.bootstrap = base / "bootstrap.json"

        self.imported_bytes = b"exact source bytes\n"
        self.derived_source_bytes = b"before adaptation\n"
        (self.root / "src" / "imported.txt").write_bytes(self.imported_bytes)
        (self.root / "src" / "derived.txt").write_bytes(b"after adaptation\n")
        (self.root / "new.txt").write_bytes(b"created for publication\n")
        self.scope_value = {
            "allowed_paths": sorted(
                [
                    "new.txt",
                    "publication/scope.json",
                    "publication/source-import.json",
                    "src/derived.txt",
                    "src/imported.txt",
                ]
            ),
            "excluded_topics": ["unrelated fixture work"],
            "forbidden_exact_paths": ["private-note.txt"],
            "forbidden_name_fragments": [".pyc"],
            "forbidden_prefixes": ["private/"],
            "included_scientific_scope": "source-import fixture",
            "schema": MODULE.SCOPE_SCHEMA,
            "source_policy": "explicit_allowlist",
        }
        self.write_scope()
        self.bootstrap_value = {
            "schema": MODULE.BOOTSTRAP_SCHEMA,
            "source": dict(MODULE.SOURCE),
            "files": [
                self.source_record("src/imported.txt", self.imported_bytes),
                self.source_record("src/derived.txt", self.derived_source_bytes),
                self.source_record("src/omitted.txt", b"deliberately not exported\n"),
            ],
        }
        self.write_bootstrap()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def source_record(path: str, data: bytes) -> dict:
        return {"path": path, **MODULE.byte_identity(data)}

    def write_bootstrap(self):
        self.bootstrap.write_text(
            json.dumps(self.bootstrap_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def write_scope(self):
        self.scope.write_text(
            json.dumps(self.scope_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def approve_path(self, path: str):
        self.scope_value["allowed_paths"].append(path)
        self.scope_value["allowed_paths"] = sorted(
            set(self.scope_value["allowed_paths"])
        )
        self.write_scope()

    def build(self):
        return MODULE.write_manifest(self.root, self.bootstrap, self.manifest)

    def test_build_classifies_and_check_revalidates_every_file(self):
        value = self.build()
        classes = {record["path"]: record["classification"] for record in value["files"]}
        self.assertEqual(classes["src/imported.txt"], "imported")
        self.assertEqual(classes["src/derived.txt"], "derived")
        self.assertEqual(classes["new.txt"], "new")
        records = {record["path"]: record for record in value["files"]}
        self.assertNotIn("rationale", records["src/imported.txt"])
        self.assertTrue(records["src/derived.txt"]["rationale"])
        self.assertTrue(records["new.txt"]["rationale"])
        self.assertEqual(
            [record["path"] for record in value["omitted_source_files"]],
            ["src/omitted.txt"],
        )
        self.assertEqual(MODULE.check_manifest(self.root, self.manifest, self.bootstrap), value)

    def test_target_tampering_and_unapproved_innocent_file_are_rejected(self):
        self.build()
        (self.root / "src" / "imported.txt").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(MODULE.SourceImportError, "mismatch"):
            MODULE.check_manifest(self.root, self.manifest)

        self.build()
        (self.root / "meeting-notes.txt").write_bytes(b"innocently named but unapproved\n")
        for operation in (
            lambda: MODULE.check_manifest(self.root, self.manifest),
            self.build,
        ):
            with self.subTest(operation=operation.__name__), self.assertRaisesRegex(
                MODULE.SourceImportError,
                r"scope allowlist mismatch; unapproved=\['meeting-notes.txt'\]",
            ):
                operation()

    def test_stale_allowlist_decision_is_rejected(self):
        self.approve_path("approved-but-missing.txt")
        with self.assertRaisesRegex(
            MODULE.SourceImportError,
            r"stale=\['approved-but-missing.txt'\]",
        ):
            self.build()

    def test_bootstrap_pin_and_source_identity_are_never_inferred(self):
        bad_pin = copy.deepcopy(self.bootstrap_value)
        bad_pin["source"]["commit"] = "0" * 40
        self.bootstrap.write_text(json.dumps(bad_pin), encoding="utf-8")
        with self.assertRaisesRegex(MODULE.SourceImportError, "bootstrap source must"):
            MODULE.build_manifest(self.root, self.bootstrap, self.manifest)

        bad_identity = copy.deepcopy(self.bootstrap_value)
        del bad_identity["files"][0]["git_blob_sha1"]
        self.bootstrap.write_text(json.dumps(bad_identity), encoding="utf-8")
        with self.assertRaisesRegex(MODULE.SourceImportError, "must contain exactly"):
            MODULE.build_manifest(self.root, self.bootstrap, self.manifest)

    def test_check_rejects_source_substitution_and_noncanonical_json(self):
        value = self.build()
        changed = copy.deepcopy(value)
        record = next(item for item in changed["files"] if item["path"] == "src/derived.txt")
        record["source"]["sha256"] = "0" * 64
        self.manifest.write_bytes(MODULE.canonical_json(changed))
        with self.assertRaisesRegex(MODULE.SourceImportError, "authoritative bootstrap"):
            MODULE.check_manifest(self.root, self.manifest, self.bootstrap)

        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(MODULE.SourceImportError, "not canonically serialized"):
            MODULE.check_manifest(self.root, self.manifest)

    def test_git_blob_identity_uses_the_git_header(self):
        data = b"test content\n"
        self.assertEqual(
            MODULE.git_blob_sha1(data),
            "d670460b4b4aece5915caf5c68d12f560a9fe3e4",
        )
        self.assertEqual(MODULE.byte_identity(data)["sha256"], hashlib.sha256(data).hexdigest())

    def test_release_checksum_manifest_is_the_only_fixed_file_exclusion(self):
        (self.root / "MANIFEST.sha256").write_text(
            "release checksum file may hash source-import.json\n", encoding="utf-8"
        )
        self.approve_path("MANIFEST.sha256")
        value = self.build()
        self.assertEqual(
            value["inventory"]["excluded_paths"],
            ["MANIFEST.sha256", "publication/source-import.json"],
        )
        self.assertNotIn(
            "MANIFEST.sha256", {record["path"] for record in value["files"]}
        )
        self.assertEqual(MODULE.check_manifest(self.root, self.manifest, self.bootstrap), value)

        (self.root / "release-extra.txt").write_text(
            "must remain inventoried\n", encoding="utf-8"
        )
        self.approve_path("release-extra.txt")
        with self.assertRaisesRegex(MODULE.SourceImportError, "coverage mismatch"):
            MODULE.check_manifest(self.root, self.manifest)


if __name__ == "__main__":
    unittest.main()
