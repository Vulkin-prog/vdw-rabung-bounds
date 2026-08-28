import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "campaign_recovery", ROOT / "tools" / "campaign_recovery.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(MODULE.canonical_json_bytes(value))


def rewrite_inventory_checksums(directory: Path) -> None:
    rows = [
        f"{MODULE.sha256_file(directory / name)}  {name}\n"
        for name in MODULE.INVENTORY_FILES
    ]
    (directory / "inventory-files.sha256").write_text("".join(rows), encoding="ascii")


def git(source: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def revision_for(chunk_id: int) -> str:
    for first, last, commit, _, _ in MODULE.EXPECTED_REVISIONS:
        if first <= chunk_id <= last:
            return commit[:7]
    raise AssertionError(chunk_id)


def checkpoint_document(*, missing_chunk=None, wrong_revision_chunk=None):
    done = {}
    for chunk_id in range(1, MODULE.CAMPAIGN_CHUNKS + 1):
        _, _, key = MODULE.expected_chunk(chunk_id)
        revision = revision_for(chunk_id)
        if wrong_revision_chunk == chunk_id:
            revision = "deadbee"
        done[key] = {
            "checksum": (chunk_id * 1_000_003) % (1 << 64),
            "dt": round(chunk_id / 10.0, 1),
            "rev": revision,
        }
    if missing_chunk is not None:
        done.pop(MODULE.expected_chunk(missing_chunk)[2])
    return {
        "_sess": {"n": 1, "sum": 1.0, "work": 1.0},
        "agg": {},
        "done": done,
        "record_best": {},
        "records": [],
    }


def journal_bytes(*, missing=frozenset({7}), duplicate=None, chunks=None):
    lines = []
    chunk_ids = chunks if chunks is not None else range(1, MODULE.CAMPAIGN_CHUNKS + 1)
    for chunk_id in chunk_ids:
        if chunk_id in missing:
            continue
        lower, _, _ = MODULE.expected_chunk(chunk_id)
        line = (
            f"- chunk {chunk_id}/{MODULE.CAMPAIGN_CHUNKS} "
            f"p~{lower / 1e9:.3f}e9 | faits {chunk_id}\n"
        )
        lines.append(line)
        if duplicate == chunk_id:
            lines.append(line)
    return "".join(lines).encode("utf-8")


class RecoveryFixture:
    def __init__(
        self,
        base: Path,
        *,
        missing_checkpoint_chunk=None,
        wrong_revision_chunk=None,
        journal_missing=frozenset({7}),
        journal_duplicate=None,
    ):
        self.base = base
        self.source = base / "source"
        self.inventory = base / "inventory"
        self.selection_path = base / "selection.json"
        self.publication = base / "publication"
        self.source.mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=self.source, check=True)
        git(self.source, "config", "user.name", "Campaign Fixture")
        git(self.source, "config", "user.email", "fixture@example.invalid")
        (self.source / ".gitignore").write_text("results/campaign/\n", encoding="utf-8")
        (self.source / "README.md").write_text("fixture\n", encoding="utf-8")
        git(self.source, "add", ".gitignore", "README.md")
        git(self.source, "commit", "-qm", "fixture source")

        campaign = self.source / "results/campaign"
        campaign.mkdir(parents=True)
        write_json(
            campaign / "checkpoint.json",
            checkpoint_document(
                missing_chunk=missing_checkpoint_chunk,
                wrong_revision_chunk=wrong_revision_chunk,
            ),
        )
        (campaign / "campaign_daily.md").write_bytes(
            journal_bytes(missing=journal_missing, duplicate=journal_duplicate)
        )
        (campaign / "unrelated.tmp").write_text("not selected\n", encoding="utf-8")

    def make_inventory(self):
        subprocess.run(
            [
                str(ROOT / "scripts/inventory_pc.sh"),
                "--public-campaign-scope",
                str(self.source),
                str(self.inventory),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return MODULE.validate_inventory(self.inventory)

    def approve_selection(self, inventory=None, selection=None):
        inventory = inventory or MODULE.validate_inventory(self.inventory)
        selection = selection or MODULE.make_selection_document(inventory)
        selection["status"] = "approved"
        for entry in selection["files"]:
            if entry["suggested_role"] == "authoritative_checkpoint":
                entry.update(
                    decision="import",
                    destination_path=entry["suggested_destination_path"],
                    reason="complete historical checkpoint fixture",
                    role="authoritative_checkpoint",
                )
            elif entry["suggested_role"] == "campaign_daily":
                entry.update(
                    decision="import",
                    destination_path=entry["suggested_destination_path"],
                    reason="historical daily journal fixture",
                    role="campaign_daily",
                )
            else:
                entry.update(
                    decision="exclude",
                    destination_path=None,
                    reason="unrelated fixture file",
                    role=None,
                )
        write_json(self.selection_path, selection)
        return selection

    def import_evidence(self):
        MODULE.import_selection(
            self.source,
            self.inventory,
            self.selection_path,
            self.publication,
        )
        self.copy_provenance()

    def copy_provenance(self):
        shutil.copytree(
            ROOT / "provenance/scanners",
            self.publication / "provenance/scanners",
            dirs_exist_ok=True,
        )

    def build(self):
        manifest = self.publication / "results/campaign/campaign_manifest.json"
        document = MODULE.build_manifest(self.publication, manifest)
        return document, manifest


class CampaignRecoveryEndToEndTests(unittest.TestCase):
    def test_all_five_cli_stages_form_one_replayable_flow(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            tool = ROOT / "tools/campaign_recovery.py"

            validate = subprocess.run(
                [sys.executable, str(tool), "validate-inventory", str(fixture.inventory)],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            self.assertIn("PC_INVENTORY_VALID", validate.stdout)
            propose = subprocess.run(
                [
                    sys.executable,
                    str(tool),
                    "propose-selection",
                    str(fixture.inventory),
                    "--output",
                    str(fixture.selection_path),
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            self.assertIn("SELECTION_PROPOSED", propose.stdout)
            proposed = MODULE.load_json(fixture.selection_path)
            self.assertEqual(proposed["status"], "proposed")
            fixture.approve_selection(selection=proposed)

            imported = subprocess.run(
                [
                    sys.executable,
                    str(tool),
                    "import",
                    "--source",
                    str(fixture.source),
                    "--inventory",
                    str(fixture.inventory),
                    "--selection",
                    str(fixture.selection_path),
                    "--output",
                    str(fixture.publication),
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            self.assertIn("CAMPAIGN_IMPORT_OK", imported.stdout)
            fixture.copy_provenance()
            built = subprocess.run(
                [
                    sys.executable,
                    str(tool),
                    "build",
                    "--repository-root",
                    str(fixture.publication),
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            self.assertIn("CAMPAIGN_MANIFEST_BUILT  515 chunks", built.stdout)
            checked = subprocess.run(
                [
                    sys.executable,
                    str(tool),
                    "check",
                    "--repository-root",
                    str(fixture.publication),
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            self.assertIn("CAMPAIGN_MANIFEST_OK  515 chunks", checked.stdout)

    def test_inventory_is_explicitly_public_campaign_scoped(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            (fixture.source / "paper2").mkdir()
            (fixture.source / "paper2/prime-private.txt").write_text(
                "out of publication scope\n", encoding="utf-8"
            )
            (fixture.source / "logs").mkdir()
            (fixture.source / "logs/campaign_daily.md").write_text(
                "out of publication scope\n", encoding="utf-8"
            )
            inventory = fixture.make_inventory()

            self.assertEqual(inventory["metadata"]["scope"], MODULE.INVENTORY_SCOPE)
            self.assertEqual(len(inventory["records"]), 3)
            self.assertTrue(
                all(row["path"].startswith("results/campaign/") for row in inventory["records"])
            )
            for name in ("candidate-files.jsonl", "git-ignored.z", "git-status-v2.z", "git-untracked.z"):
                raw_inventory = inventory["snapshots"][name]
                self.assertNotIn(b"paper2", raw_inventory)
                self.assertNotIn(b"logs/campaign_daily.md", raw_inventory)

    def test_inventory_refuses_implicit_unscoped_mode(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            output = fixture.base / "implicit-inventory"
            process = subprocess.run(
                [
                    str(ROOT / "scripts/inventory_pc.sh"),
                    str(fixture.source),
                    str(output),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(process.returncode, 2)
            self.assertIn("--public-campaign-scope", process.stderr)
            self.assertFalse(output.exists())

    def test_shared_checkpoint_builds_exact_515_rows_and_chunk7_proof(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            inventory = fixture.make_inventory()
            self.assertEqual(len(inventory["records"]), 3)
            fixture.approve_selection(inventory)
            fixture.import_evidence()
            document, manifest = fixture.build()

            self.assertEqual(len(document["chunks"]), 515)
            self.assertEqual(document["totals"]["imported_file_count"], 2)
            self.assertEqual(document["totals"]["checkpoint_and_journal_chunks"], 514)
            chunk7 = document["chunks"][6]
            self.assertEqual(chunk7["chunk_id"], 7)
            self.assertEqual(chunk7["lower_inclusive"], 982_000_000)
            self.assertEqual(chunk7["upper_exclusive"], 984_000_000)
            self.assertEqual(chunk7["journal"]["match_count"], 0)
            self.assertEqual(chunk7["evidence_class"], "checkpoint_only_missing_journal")
            self.assertTrue(chunk7["driver_ordering"]["verified"])
            self.assertEqual(
                [row["line_number"] for row in chunk7["driver_ordering"]["statements"]],
                [90, 93, 106, 113],
            )
            self.assertEqual(
                document["chunk_7_checkpoint_evidence"]["resolution"],
                "checkpoint_recovers_missing_journal",
            )
            self.assertEqual(
                document["chunk_7_checkpoint_evidence"]["revision_commit"],
                MODULE.EXPECTED_REVISIONS[0][2],
            )
            MODULE.check_manifest(fixture.publication, manifest)

    def test_check_rejects_a_tampered_manifest(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            document, manifest = fixture.build()
            document["totals"]["chunk_count"] = 514
            write_json(manifest, document)
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.check_manifest(fixture.publication, manifest)

    def test_preserved_inventory_makes_the_import_self_contained(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            shutil.rmtree(fixture.inventory)
            shutil.rmtree(fixture.source)

            selection, receipt, imported, _ = MODULE.validate_receipt(fixture.publication)
            self.assertEqual(selection["inventory"], receipt["inventory"])
            self.assertEqual(len(receipt["inventory_artifacts"]), 6)
            self.assertEqual(len(imported), 2)
            document, _ = fixture.build()
            self.assertEqual(document["totals"]["chunk_count"], 515)

    def test_two_split_journals_cover_the_campaign(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            campaign = fixture.source / "results/campaign"
            (campaign / "campaign_daily.md").write_bytes(
                journal_bytes(chunks=range(1, 258))
            )
            (campaign / "campaign_daily_part2.md").write_bytes(
                journal_bytes(chunks=range(258, MODULE.CAMPAIGN_CHUNKS + 1))
            )
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            document, _ = fixture.build()

            self.assertEqual(
                len(document["chunks"][6]["journal"]["searched_artifacts"]), 2
            )
            self.assertEqual(
                document["chunks"][256]["journal"]["matches"][0]["artifact_path"],
                "results/campaign/raw/campaign_daily.md",
            )
            self.assertEqual(
                document["chunks"][257]["journal"]["matches"][0]["artifact_path"],
                "results/campaign/raw/campaign_daily_part2.md",
            )

    def test_duplicate_restart_rows_are_preserved_not_discarded(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw), journal_duplicate=9)
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            document, _ = fixture.build()
            row9 = document["chunks"][8]
            self.assertEqual(row9["journal"]["match_count"], 2)
            self.assertEqual(len(row9["journal"]["matches"]), 2)

    def test_auxiliary_import_is_bound_but_closes_no_campaign_gate(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            inventory = fixture.make_inventory()
            selection = fixture.approve_selection(inventory)
            auxiliary = next(
                entry for entry in selection["files"]
                if entry["source_path"].endswith("/unrelated.tmp")
            )
            auxiliary.update(
                decision="import",
                destination_path=auxiliary["suggested_destination_path"],
                reason="retain fixture auxiliary bytes without making a parsed claim",
                role="auxiliary_unparsed",
            )
            write_json(fixture.selection_path, selection)
            fixture.import_evidence()
            document, _ = fixture.build()
            self.assertEqual(document["totals"]["imported_file_count"], 3)
            self.assertNotIn("unrelated.tmp", str(document["chunks"]))


class CampaignRecoveryFailClosedTests(unittest.TestCase):
    def test_authenticated_inventory_rejects_a_different_scope(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            metadata_path = fixture.inventory / "metadata.json"
            metadata = MODULE.load_json(metadata_path)
            metadata["scope"] = {"mode": "whole_checkout", "path": ""}
            write_json(metadata_path, metadata)
            rewrite_inventory_checksums(fixture.inventory)
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.validate_inventory(fixture.inventory)

    def test_authenticated_inventory_rejects_out_of_scope_git_metadata(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            ignored_path = fixture.inventory / "git-ignored.z"
            ignored_path.write_bytes(ignored_path.read_bytes() + b"paper2/private-prime.txt\0")
            metadata_path = fixture.inventory / "metadata.json"
            metadata = MODULE.load_json(metadata_path)
            metadata["ignored_path_count"] += 1
            write_json(metadata_path, metadata)
            rewrite_inventory_checksums(fixture.inventory)
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.validate_inventory(fixture.inventory)

    def test_authenticated_inventory_rejects_git_path_traversal(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            untracked_path = fixture.inventory / "git-untracked.z"
            untracked_path.write_bytes(b"results/campaign/../paper2/private.txt\0")
            metadata_path = fixture.inventory / "metadata.json"
            metadata = MODULE.load_json(metadata_path)
            metadata["untracked_path_count"] = 1
            write_json(metadata_path, metadata)
            rewrite_inventory_checksums(fixture.inventory)
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.validate_inventory(fixture.inventory)

    def test_inventory_checksum_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            with (fixture.inventory / "candidate-files.jsonl").open("ab") as handle:
                handle.write(b"\n")
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.validate_inventory(fixture.inventory)

    def test_source_mutation_after_inventory_is_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            inventory = fixture.make_inventory()
            fixture.approve_selection(inventory)
            checkpoint = fixture.source / "results/campaign/checkpoint.json"
            metadata = checkpoint.stat()
            altered = bytearray(checkpoint.read_bytes())
            altered[-1] = ord(" ")
            checkpoint.write_bytes(altered)
            # Preserve both inventoried size and mtime: the SHA-256 comparison,
            # not merely metadata drift, must catch this mutation.
            os.utime(checkpoint, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.import_selection(
                    fixture.source,
                    fixture.inventory,
                    fixture.selection_path,
                    fixture.publication,
                )
            self.assertFalse(fixture.publication.exists())

    def test_successful_import_leaves_every_source_byte_unchanged(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            fixture.approve_selection()
            before = {
                path.relative_to(fixture.source).as_posix(): path.read_bytes()
                for path in fixture.source.rglob("*")
                if path.is_file() and ".git" not in path.relative_to(fixture.source).parts
            }
            status_before = subprocess.check_output(
                ["git", "-C", str(fixture.source), "status", "--porcelain=v2", "-z"]
            )
            MODULE.import_selection(
                fixture.source,
                fixture.inventory,
                fixture.selection_path,
                fixture.publication,
            )
            after = {
                path.relative_to(fixture.source).as_posix(): path.read_bytes()
                for path in fixture.source.rglob("*")
                if path.is_file() and ".git" not in path.relative_to(fixture.source).parts
            }
            status_after = subprocess.check_output(
                ["git", "-C", str(fixture.source), "status", "--porcelain=v2", "-z"]
            )
            self.assertEqual(after, before)
            self.assertEqual(status_after, status_before)

    def test_journal_interval_label_is_bound_to_chunk_geometry(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            journal = fixture.source / "results/campaign/campaign_daily.md"
            text = journal.read_text(encoding="utf-8")
            text = text.replace("- chunk 8/515 p~0.984e9", "- chunk 8/515 p~0.999e9")
            journal.write_text(text, encoding="utf-8")
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            with self.assertRaises(MODULE.RecoveryError):
                fixture.build()

    def test_destination_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            inventory = fixture.make_inventory()
            selection = fixture.approve_selection(inventory)
            checkpoint = next(
                entry for entry in selection["files"]
                if entry["role"] == "authoritative_checkpoint"
            )
            checkpoint["destination_path"] = "../escaped-checkpoint.json"
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.validate_selection(selection, inventory, require_approved=True)

    def test_import_output_inside_source_checkout_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            fixture.approve_selection()
            unsafe_output = fixture.source / "generated-import"
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.import_selection(
                    fixture.source,
                    fixture.inventory,
                    fixture.selection_path,
                    unsafe_output,
                )
            self.assertFalse(unsafe_output.exists())

    def test_import_output_symlink_is_rejected_without_writing_its_target(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            fixture.approve_selection()
            target = fixture.base / "redirected-import"
            fixture.publication.symlink_to(target, target_is_directory=True)
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.import_selection(
                    fixture.source,
                    fixture.inventory,
                    fixture.selection_path,
                    fixture.publication,
                )
            self.assertFalse(target.exists())

    def test_checkpoint_missing_one_chunk_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw), missing_checkpoint_chunk=300)
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            with self.assertRaises(MODULE.RecoveryError):
                fixture.build()

    def test_checkpoint_wrong_historical_revision_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw), wrong_revision_chunk=7)
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            with self.assertRaises(MODULE.RecoveryError):
                fixture.build()

    def test_journal_must_miss_chunk7_and_no_other_chunk(self):
        cases = (
            (frozenset(), None),
            (frozenset({7, 8}), None),
        )
        for missing, duplicate in cases:
            with self.subTest(missing=missing, duplicate=duplicate):
                with tempfile.TemporaryDirectory() as raw:
                    fixture = RecoveryFixture(
                        Path(raw),
                        journal_missing=missing,
                        journal_duplicate=duplicate,
                    )
                    fixture.make_inventory()
                    fixture.approve_selection()
                    fixture.import_evidence()
                    with self.assertRaises(MODULE.RecoveryError):
                        fixture.build()

    def test_noncanonical_chunk7_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            journal = fixture.source / "results/campaign/campaign_daily.md"
            journal.write_bytes(
                journal.read_bytes() + b"completed chunk 007 of 515 at p=0.982 e9\n"
            )
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            with self.assertRaises(MODULE.RecoveryError):
                fixture.build()

    def test_chunk7_reference_hidden_in_a_valid_other_row_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            journal = fixture.source / "results/campaign/campaign_daily.md"
            text = journal.read_text(encoding="utf-8")
            text = text.replace(
                "- chunk 8/515 p~0.984e9 | faits 8",
                "- chunk 8/515 p~0.984e9 | faits 8; recovered chunk 7/515",
            )
            journal.write_text(text, encoding="utf-8")
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            with self.assertRaises(MODULE.RecoveryError):
                fixture.build()

    def test_malformed_chunk_like_row_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            journal = fixture.source / "results/campaign/campaign_daily.md"
            text = journal.read_text(encoding="utf-8")
            text = text.replace("- chunk 9/515 p~0.986e9", "- chunk 9/515 near 0.986e9")
            journal.write_text(text, encoding="utf-8")
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            with self.assertRaises(MODULE.RecoveryError):
                fixture.build()

    def test_tampered_historical_base64_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            driver = (
                fixture.publication
                / "provenance/scanners/historical/campaign_ebd54ea.py.base64"
            )
            raw_driver = bytearray(driver.read_bytes())
            index = next(i for i, byte in enumerate(raw_driver) if byte == ord("Q"))
            raw_driver[index] = ord("R")
            driver.write_bytes(raw_driver)
            with self.assertRaises(MODULE.RecoveryError):
                fixture.build()

    def test_jointly_rewritten_source_map_and_driver_cannot_redefine_history(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            fixture.make_inventory()
            fixture.approve_selection()
            fixture.import_evidence()
            driver = (
                fixture.publication
                / "provenance/scanners/historical/campaign_ebd54ea.py.base64"
            )
            decoded = base64.b64decode(b"".join(driver.read_bytes().split()), validate=True)
            self.assertIn(b"PF4", decoded)
            decoded = decoded.replace(b"PF4", b"PF5", 1)
            driver.write_bytes(base64.encodebytes(decoded))
            source_map_path = fixture.publication / "provenance/scanners/campaign-source-map.json"
            source_map = json.loads(source_map_path.read_text(encoding="utf-8"))
            identity = source_map["artifacts"]["campaign_ebd54ea"]
            identity["bytes"] = len(decoded)
            identity["sha256"] = hashlib.sha256(decoded).hexdigest()
            identity["git_blob_sha1"] = hashlib.sha1(
                f"blob {len(decoded)}\0".encode("ascii") + decoded
            ).hexdigest()
            write_json(source_map_path, source_map)
            with self.assertRaises(MODULE.RecoveryError):
                fixture.build()

    def test_atomic_new_write_never_overwrites_an_existing_target(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "existing.json"
            target.write_bytes(b"original\n")
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.atomic_write(target, b"replacement\n", replace=False)
            self.assertEqual(target.read_bytes(), b"original\n")

    def test_candidate_symlink_cannot_be_imported(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            target = fixture.source / "results/campaign/checkpoint-copy.json"
            target.symlink_to("checkpoint.json")
            inventory = fixture.make_inventory()
            selection = fixture.approve_selection(inventory)
            symlink = next(
                entry for entry in selection["files"]
                if entry["source_path"].endswith("checkpoint-copy.json")
            )
            symlink.update(
                decision="import",
                destination_path="results/campaign/raw/checkpoint-copy.json",
                reason="invalid attempted symlink import",
                role="auxiliary_unparsed",
            )
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.validate_selection(selection, inventory, require_approved=True)

    def test_intermediate_source_symlink_is_rejected_after_inventory(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = RecoveryFixture(Path(raw))
            inventory = fixture.make_inventory()
            fixture.approve_selection(inventory)
            relocated = fixture.base / "relocated-results"
            (fixture.source / "results").rename(relocated)
            (fixture.source / "results").symlink_to(relocated, target_is_directory=True)
            with self.assertRaises(MODULE.RecoveryError):
                MODULE.import_selection(
                    fixture.source,
                    fixture.inventory,
                    fixture.selection_path,
                    fixture.publication,
                )
            self.assertFalse(fixture.publication.exists())


if __name__ == "__main__":
    unittest.main()
