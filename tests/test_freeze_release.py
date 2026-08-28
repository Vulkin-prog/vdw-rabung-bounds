import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "freeze_release", ROOT / "tools" / "freeze_release.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


VERSION = "1.2.3"
TAG = f"v{VERSION}"
DATE = "2026-09-01"
DOI = "10.5281/zenodo.1234567"
TITLE = "Certified lower bounds fixture"


def final_status() -> dict:
    return {
        "schema": MODULE.STATUS_SCHEMA,
        "artifact": "vdw-rabung-bounds",
        "repository_state": "archived_release",
        "citable_release": True,
        "allowed_gate_statuses": sorted(MODULE.ALLOWED_GATE_STATUSES),
        "release_gates": [
            {
                "id": gate_id,
                "status": "passed",
                "evidence": ["payload.txt"],
                "note": "Fixture evidence passed.",
            }
            for gate_id in sorted(MODULE.REQUIRED_RELEASE_GATES)
        ],
    }


def run(*arguments, cwd: Path) -> None:
    subprocess.run(
        list(arguments),
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def write_candidate(root: Path) -> None:
    (root / "release").mkdir(parents=True)
    (root / "paper").mkdir()
    (root / "paper" / "tex").mkdir()
    (root / "scripts").mkdir()
    (root / "CITATION.cff").write_text(
        "\n".join(
            [
                "cff-version: 1.2.0",
                'message: "Cite the immutable archived release."',
                f'title: "{TITLE}"',
                "type: software",
                f"version: {VERSION}",
                f"date-released: {DATE}",
                f'doi: "https://doi.org/{DOI}"',
                "license: MIT",
                f'repository-code: "{MODULE.REPOSITORY_URL}"',
                "authors:",
                '  - family-names: "Pouly"',
                '    given-names: "Brice"',
                "keywords:",
                *[f'  - "{keyword}"' for keyword in MODULE.EXPECTED_KEYWORDS],
                "",
            ]
        ),
        encoding="utf-8",
    )
    zenodo = {
        "doi": DOI,
        "metadata": {
            "title": f"Reproducibility package for: {TITLE}",
            "description": "Final fixture package.",
            "version": VERSION,
            "publication_date": DATE,
            "license": "MIT",
            "upload_type": "software",
            "creators": [{"name": "Pouly, Brice"}],
            "keywords": list(MODULE.EXPECTED_KEYWORDS),
            "related_identifiers": [
                {
                    "identifier": f"{MODULE.REPOSITORY_URL}/releases/tag/{TAG}",
                    "relation": "isIdenticalTo",
                    "scheme": "url",
                }
            ],
        },
    }
    (root / "release" / "zenodo-metadata.json").write_text(
        json.dumps(zenodo, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    epoch = MODULE.expected_epoch(DATE)
    (root / "release" / "SOURCE_DATE_EPOCH").write_text(f"{epoch}\n", encoding="ascii")
    (root / "LICENSE-CODE").write_text("MIT fixture licence text\n", encoding="utf-8")
    (root / "LICENSE-PAPER").write_text("CC-BY-4.0 fixture licence text\n", encoding="utf-8")
    (root / "LICENSE-DATA").write_text("CC0-1.0 fixture licence text\n", encoding="utf-8")
    rights_map = {
        "schema": MODULE.RIGHTS_SCHEMA,
        "components": {
            "code": {"license_id": "MIT", "license_file": "LICENSE-CODE"},
            "paper_pdf": {
                "license_id": "CC-BY-4.0",
                "license_file": "LICENSE-PAPER",
            },
            "data": {"license_id": "CC0-1.0", "license_file": "LICENSE-DATA"},
        },
        "third_party": {
            "redistributed": False,
            "policy": "not_redistributed",
            "notice_file": "THIRD_PARTY_NOTICES.md",
        },
    }
    (root / "release" / "rights-map.json").write_text(
        json.dumps(rights_map, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "RIGHTS-STATUS.md").write_text(
        "Final decisions: code MIT; paper/PDF CC-BY-4.0; data CC0-1.0.\n",
        encoding="utf-8",
    )
    (root / "THIRD_PARTY_NOTICES.md").write_text(
        "No third-party material is included. It is not redistributed.\n",
        encoding="utf-8",
    )
    (root / "STATUS.json").write_text(
        json.dumps(final_status(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "paper" / "main.pdf").write_bytes(b"%PDF-1.4\nfixture\n%%EOF\n")
    (root / "paper" / "tex" / "main.tex").write_text(
        "\\documentclass{article}\n\\begin{document}\nFinal article.\n\\end{document}\n",
        encoding="utf-8",
    )
    builder = root / "scripts" / "build_paper.sh"
    builder.write_text(
        "#!/bin/sh\nset -eu\ncp \"$PWD/paper/main.pdf\" \"$1\"\n",
        encoding="utf-8",
    )
    builder.chmod(0o755)
    (root / "payload.txt").write_text("release payload\n", encoding="utf-8")


def initialize_git(root: Path) -> None:
    run("git", "init", "-b", "main", cwd=root)
    run("git", "config", "user.name", "Freeze Test", cwd=root)
    run("git", "config", "user.email", "freeze@example.invalid", cwd=root)
    run("git", "add", ".", cwd=root)
    run("git", "commit", "-m", "candidate", cwd=root)


class ReleaseFreezeTest(unittest.TestCase):
    def test_complete_freeze_binds_inventory_pdf_metadata_and_tag(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            initialize_git(root)

            tag, pdf_digest = MODULE.create_freeze(root, TAG)
            self.assertEqual(tag, TAG)
            self.assertEqual(pdf_digest, MODULE.sha256_file(root / "paper" / "main.pdf"))
            run("git", "add", "MANIFEST.sha256", cwd=root)
            run("git", "commit", "-m", "freeze", cwd=root)
            run("git", "tag", TAG, cwd=root)

            checked_tag, checked_digest = MODULE.check_freeze(
                root, None, require_head_tag=True
            )
            self.assertEqual((checked_tag, checked_digest), (tag, pdf_digest))
            records = MODULE.parse_manifest(root / "MANIFEST.sha256")
            self.assertNotIn("MANIFEST.sha256", records)
            self.assertIn("paper/main.pdf", records)
            self.assertEqual(
                set(records), set(MODULE.tracked_paths(root)) - {"MANIFEST.sha256"}
            )

    def test_manifest_rejects_hash_tampering_and_new_tracked_path(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            initialize_git(root)
            inventory = MODULE.ensure_candidate_index(root, creating=True)
            (root / "MANIFEST.sha256").write_bytes(MODULE.build_manifest_bytes(root, inventory))
            MODULE.validate_manifest(root, inventory)

            (root / "payload.txt").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.FreezeError, "SHA-256 mismatch"):
                MODULE.validate_manifest(root, inventory)
            (root / "payload.txt").write_text("release payload\n", encoding="utf-8")

            (root / "new-record.txt").write_text("new\n", encoding="utf-8")
            run("git", "add", "new-record.txt", cwd=root)
            expanded = MODULE.tracked_paths(root)
            with self.assertRaisesRegex(MODULE.FreezeError, "inventory mismatch"):
                MODULE.validate_manifest(root, expanded)

    def test_metadata_mismatches_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            MODULE.validate_metadata(root, TAG)

            metadata_path = root / "release" / "zenodo-metadata.json"
            value = json.loads(metadata_path.read_text(encoding="utf-8"))
            value["metadata"]["version"] = "9.9.9"
            metadata_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.FreezeError, "metadata.version"):
                MODULE.validate_metadata(root, TAG)

    def test_create_and_check_reject_manuscript_staging_markers(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            tex = root / "paper" / "tex" / "main.tex"
            tex.write_text("This is a private prepublication draft.\n", encoding="utf-8")
            initialize_git(root)
            with self.assertRaisesRegex(MODULE.FreezeError, "manuscript staging marker"):
                MODULE.create_freeze(root, TAG)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            initialize_git(root)
            MODULE.create_freeze(root, TAG)
            run("git", "add", "MANIFEST.sha256", cwd=root)
            run("git", "commit", "-m", "freeze", cwd=root)
            tex = root / "paper" / "tex" / "main.tex"
            tex.write_text("The final manifest is pending.\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.FreezeError, "manuscript staging marker"):
                MODULE.check_freeze(root, TAG, require_head_tag=False)

    def test_status_must_be_complete_release_final(self):
        mutations = (
            (
                lambda value: value.update(citable_release=False),
                "citable_release must be true",
            ),
            (
                lambda value: value.update(repository_state="private_preparation"),
                "repository_state must be 'archived_release'",
            ),
            (
                lambda value: value["release_gates"][0].update(status="open"),
                "is not passed",
            ),
            (
                lambda value: value["release_gates"].pop(),
                "release gate set mismatch",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                write_candidate(root)
                path = root / "STATUS.json"
                value = json.loads(path.read_text(encoding="utf-8"))
                mutate(value)
                path.write_text(json.dumps(value) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(MODULE.FreezeError, message):
                    MODULE.validate_metadata(root, TAG)

    def test_structural_check_can_skip_only_the_pdf_rebuild(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            initialize_git(root)
            MODULE.create_freeze(root, TAG)
            run("git", "add", "MANIFEST.sha256", cwd=root)
            run("git", "commit", "-m", "freeze", cwd=root)

            builder = root / "scripts" / "build_paper.sh"
            builder.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
            inventory = MODULE.tracked_paths(root)
            inventory.remove("MANIFEST.sha256")
            (root / "MANIFEST.sha256").write_bytes(
                MODULE.build_manifest_bytes(root, inventory)
            )
            run("git", "add", "scripts/build_paper.sh", "MANIFEST.sha256", cwd=root)
            run("git", "commit", "-m", "broken builder fixture", cwd=root)

            with self.assertRaisesRegex(MODULE.FreezeError, "clean PDF rebuild failed"):
                MODULE.check_freeze(root, TAG, require_head_tag=False)
            checked_tag, _ = MODULE.check_freeze(
                root,
                TAG,
                require_head_tag=False,
                verify_pdf=False,
            )
            self.assertEqual(checked_tag, TAG)

    def test_rights_map_is_component_specific_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            path = root / "release" / "rights-map.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["components"]["data"]["license_file"] = "../LICENSE-DATA"
            path.write_text(json.dumps(value) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.FreezeError, "unsafe repository path"):
                MODULE.validate_metadata(root, TAG)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            path = root / "release" / "rights-map.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["third_party"]["redistributed"] = True
            path.write_text(json.dumps(value) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.FreezeError, "not redistributed"):
                MODULE.validate_metadata(root, TAG)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            (root / "LICENSE-PAPER").write_bytes(b"")
            with self.assertRaisesRegex(MODULE.FreezeError, "non-empty regular file"):
                MODULE.validate_metadata(root, TAG)

    def test_cff_and_zenodo_authors_type_and_keywords_are_coherent(self):
        mutations = (
            (
                lambda value: value["metadata"].update(upload_type="dataset"),
                "upload_type",
            ),
            (
                lambda value: value["metadata"].update(
                    creators=[{"name": "Not Pouly, Alice"}]
                ),
                "creators do not exactly match",
            ),
            (
                lambda value: value["metadata"].update(keywords=["Rabung certificates"]),
                "keywords do not match",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                write_candidate(root)
                path = root / "release" / "zenodo-metadata.json"
                value = json.loads(path.read_text(encoding="utf-8"))
                mutate(value)
                path.write_text(json.dumps(value) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(MODULE.FreezeError, message):
                    MODULE.validate_metadata(root, TAG)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            path = root / "CITATION.cff"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    '  - "GPU computation"', '  - "GPU arithmetic"'
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.FreezeError, "expected release keywords"):
                MODULE.validate_metadata(root, TAG)

    def test_every_rights_and_tex_input_must_be_tracked(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            (root / ".gitignore").write_text("LICENSE-DATA\n", encoding="utf-8")
            initialize_git(root)
            with self.assertRaisesRegex(MODULE.FreezeError, "required release file.*LICENSE-DATA"):
                MODULE.create_freeze(root, TAG)

    def test_epoch_is_exact_midnight_utc_and_tag_is_version_derived(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            citation = MODULE.load_citation(root / "CITATION.cff")
            path = root / "release" / "SOURCE_DATE_EPOCH"
            path.write_text(f"{MODULE.expected_epoch(DATE) + 1}\n", encoding="ascii")
            with self.assertRaisesRegex(MODULE.FreezeError, "expected midnight UTC"):
                MODULE.load_epoch(root, citation)
            with self.assertRaisesRegex(MODULE.FreezeError, "version-derived tag"):
                MODULE.expected_tag(citation, "release-1.2.3")

    def test_pdf_rebuild_must_match_frozen_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_candidate(root)
            MODULE.verify_pdf_reproducible(root)
            builder = root / "scripts" / "build_paper.sh"
            builder.write_text(
                "#!/bin/sh\nset -eu\nprintf 'different' >\"$1\"\n", encoding="utf-8"
            )
            builder.chmod(0o755)
            with self.assertRaisesRegex(MODULE.FreezeError, "differs from"):
                MODULE.verify_pdf_reproducible(root)

    def test_build_script_uses_only_the_tracked_epoch_policy(self):
        script = (ROOT / "scripts" / "build_paper.sh").read_text(encoding="utf-8")
        self.assertIn('release/SOURCE_DATE_EPOCH', script)
        self.assertNotIn('git -C "$REPOSITORY_ROOT" log', script)
        self.assertNotIn('${SOURCE_DATE_EPOCH:-}', script)


if __name__ == "__main__":
    unittest.main()
