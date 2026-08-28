import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "deposit_receipt", ROOT / "tools" / "deposit_receipt.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


COMMIT = "0123456789abcdef" * 2 + "01234567"
VERSION = "1.2.3"
TAG = f"v{VERSION}"
DOI = "10.5281/zenodo.1234567"
DRAFT_TIME = "2026-09-01T10:00:00Z"
COMPARE_TIME = "2026-09-01T10:05:00Z"
FINAL_TIME = "2026-09-01T10:10:00Z"
CREATED_TIME = "2026-09-01T10:15:00Z"


class Fixture:
    def __init__(self, raw: str):
        self.base = Path(raw)
        self.repository = self.base / "repository"
        self.exchange = self.base / "exchange"
        self.repository.mkdir()
        self.exchange.mkdir()
        payload = b"deterministic gzip fixture\x00" * 97
        self.archive = self.exchange / "vdw-rabung-bounds-v1.2.3.tar.gz"
        self.copy = self.exchange / "downloaded-draft.tar.gz"
        self.archive.write_bytes(payload)
        self.copy.write_bytes(payload)
        self.receipt = self.exchange / "deposit-receipt.json"

    def create(self, **overrides):
        arguments = {
            "commit": COMMIT,
            "tag": TAG,
            "version": VERSION,
            "doi": f"https://doi.org/{DOI}",
            "operator": "release-operator:fixture",
            "provider": "zenodo",
            "draft_identifier": "zenodo-draft:7654321",
            "draft_url": "https://zenodo.org/uploads/7654321",
            "draft_recorded_utc": DRAFT_TIME,
            "compared_utc": COMPARE_TIME,
            "created_utc": CREATED_TIME,
        }
        arguments.update(overrides)
        return MODULE.create_receipt(
            self.repository,
            self.archive,
            self.copy,
            self.receipt,
            **arguments,
        )


class DepositReceiptTest(unittest.TestCase):
    def test_create_and_check_bind_both_layers_and_optional_final_record(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(raw)
            value = fixture.create(
                final_identifier="zenodo-record:7654321",
                final_url="https://zenodo.org/records/7654321",
                final_published_utc=FINAL_TIME,
            )
            self.assertEqual(value["schema"], MODULE.SCHEMA)
            self.assertEqual(value["release"]["doi"], DOI)
            self.assertEqual(value["release"]["tag"], TAG)
            self.assertEqual(value["archive"]["sha256"], value["deposit_copy"]["sha256"])
            self.assertEqual(value["archive"]["size"], value["deposit_copy"]["size"])
            self.assertTrue(value["comparison"]["byte_identical"])
            self.assertEqual(
                fixture.receipt.read_bytes(), MODULE.canonical_json(value)
            )
            self.assertEqual(
                MODULE.check_receipt(
                    fixture.repository,
                    fixture.receipt,
                    fixture.archive,
                    fixture.copy,
                ),
                value,
            )

    def test_mismatched_copy_fails_without_creating_any_output(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(raw)
            fixture.copy.write_bytes(fixture.copy.read_bytes() + b"tampered")
            with self.assertRaisesRegex(MODULE.ReceiptError, "not byte-identical"):
                fixture.create()
            self.assertFalse(fixture.receipt.exists())
            self.assertEqual(list(fixture.exchange.glob(".deposit-receipt.json.tmp-*")), [])

    def test_output_is_no_clobber_and_atomic_publication_failure_cleans_temp(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(raw)
            fixture.receipt.write_bytes(b"do not overwrite\n")
            with self.assertRaisesRegex(MODULE.ReceiptError, "refusing to overwrite"):
                fixture.create()
            self.assertEqual(fixture.receipt.read_bytes(), b"do not overwrite\n")

        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(raw)
            with mock.patch.object(
                MODULE.os, "link", side_effect=OSError("simulated publish failure")
            ):
                with self.assertRaisesRegex(MODULE.ReceiptError, "publish receipt atomically"):
                    fixture.create()
            self.assertFalse(fixture.receipt.exists())
            self.assertEqual(list(fixture.exchange.glob(".deposit-receipt.json.tmp-*")), [])

    def test_paths_must_be_absolute_distinct_regular_unsymlinked_and_external(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(raw)
            with self.assertRaisesRegex(MODULE.ReceiptError, "must be absolute"):
                MODULE.create_receipt(
                    fixture.repository,
                    Path(fixture.archive.name),
                    fixture.copy,
                    fixture.receipt,
                    commit=COMMIT,
                    tag=TAG,
                    version=VERSION,
                    doi=DOI,
                    operator="fixture",
                    draft_identifier="draft:1",
                    draft_url="https://zenodo.org/uploads/1",
                )

            symlink = fixture.exchange / "archive-link.tar.gz"
            os.symlink(fixture.archive.name, symlink)
            with self.assertRaisesRegex(MODULE.ReceiptError, "symbolic link"):
                MODULE.compare_artifacts(symlink, fixture.copy)

            directory = fixture.exchange / "not-a-file.tar.gz"
            directory.mkdir()
            with self.assertRaisesRegex(MODULE.ReceiptError, "not a regular file"):
                MODULE.compare_artifacts(directory, fixture.copy)

            ambiguous = Path(f"{fixture.exchange}/unused/../{fixture.archive.name}")
            with self.assertRaisesRegex(MODULE.ReceiptError, "ambiguous"):
                MODULE.compare_artifacts(ambiguous, fixture.copy)

            hardlink = fixture.exchange / "hardlink.tar.gz"
            os.link(fixture.archive, hardlink)
            with self.assertRaisesRegex(MODULE.ReceiptError, "distinct files"):
                MODULE.compare_artifacts(fixture.archive, hardlink)

            inside = fixture.repository / "receipt.json"
            with self.assertRaisesRegex(MODULE.ReceiptError, "outside the repository"):
                MODULE.create_receipt(
                    fixture.repository,
                    fixture.archive,
                    fixture.copy,
                    inside,
                    commit=COMMIT,
                    tag=TAG,
                    version=VERSION,
                    doi=DOI,
                    operator="fixture",
                    draft_identifier="draft:1",
                    draft_url="https://zenodo.org/uploads/1",
                )

            receipt_target = fixture.exchange / "receipt-target.json"
            receipt_target.write_text("{}\n", encoding="utf-8")
            receipt_link = fixture.exchange / "receipt-link.json"
            os.symlink(receipt_target.name, receipt_link)
            with self.assertRaisesRegex(MODULE.ReceiptError, "symbolic link"):
                MODULE.check_receipt(
                    fixture.repository,
                    receipt_link,
                    fixture.archive,
                    fixture.copy,
                )

    def test_check_rejects_duplicate_nonfinite_noncanonical_and_tampered_receipts(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(raw)
            value = fixture.create()

            duplicate = (
                '{"schema":"vdw-deposit-receipt/v1",'
                '"schema":"vdw-deposit-receipt/v1"}\n'
            )
            fixture.receipt.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ReceiptError, "duplicate JSON key"):
                MODULE.check_receipt(
                    fixture.repository, fixture.receipt, fixture.archive, fixture.copy
                )

            fixture.receipt.write_text('{"value":NaN}\n', encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ReceiptError, "non-finite"):
                MODULE.check_receipt(
                    fixture.repository, fixture.receipt, fixture.archive, fixture.copy
                )

            fixture.receipt.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ReceiptError, "not canonically serialized"):
                MODULE.check_receipt(
                    fixture.repository, fixture.receipt, fixture.archive, fixture.copy
                )

            tampered = copy.deepcopy(value)
            tampered["archive"]["sha256"] = "0" * 64
            tampered["deposit_copy"]["sha256"] = "0" * 64
            fixture.receipt.write_bytes(MODULE.canonical_json(tampered))
            with self.assertRaisesRegex(MODULE.ReceiptError, "identity differs"):
                MODULE.check_receipt(
                    fixture.repository, fixture.receipt, fixture.archive, fixture.copy
                )

    def test_cross_field_metadata_and_chronology_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(raw)
            cases = [
                ({"tag": "release-1.2.3"}, "release.tag"),
                ({"commit": "A" * 40}, "release.commit"),
                ({"doi": "not-a-doi"}, "doi is malformed"),
                ({"compared_utc": "2026-09-01T09:00:00Z"}, "timestamps must satisfy"),
                ({"final_identifier": "record:1"}, "all-or-none"),
                ({"draft_url": "http://zenodo.org/uploads/1"}, "HTTPS URL"),
            ]
            for overrides, pattern in cases:
                with self.subTest(overrides=overrides):
                    with self.assertRaisesRegex(MODULE.ReceiptError, pattern):
                        fixture.create(**overrides)
                    self.assertFalse(fixture.receipt.exists())


if __name__ == "__main__":
    unittest.main()
