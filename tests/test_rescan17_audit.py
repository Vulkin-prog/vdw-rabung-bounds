import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "rescan17_audit", ROOT / "tools" / "rescan17_audit.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class Rescan17AuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry_path = ROOT / "audit" / "rescan17.json"
        cls.registry = MODULE.load_registry(cls.registry_path)
        cls.lo = cls.registry["interval"]["lower_inclusive"]
        cls.hi = cls.registry["interval"]["upper_exclusive"]
        cls.transcript_path = ROOT / cls.registry["transcript"]["path"]
        cls.transcript = cls.transcript_path.read_text(encoding="utf-8")

    def test_preserved_transcript_passes(self):
        result = MODULE.audit(self.registry_path)
        self.assertEqual(result["status"], "PASS_AGGREGATE_COUNTS")
        self.assertEqual(result["parsed"]["prime_count"], 1_641_614)
        self.assertEqual(result["parsed"]["candidate_counts"]["3,17"], 405)
        self.assertEqual(
            result["parsed"]["class_counts"],
            self.registry["preregistered_independent_counts"]["congruence_classes"],
        )

    def test_truncation_is_rejected(self):
        with self.assertRaises(MODULE.RescanAuditError):
            MODULE.parse_transcript(self.transcript.rstrip("\n"), self.lo, self.hi)

    def test_missing_target_is_rejected(self):
        lines = self.transcript.splitlines(keepends=True)
        changed = "".join(
            line for line in lines if not line.startswith("TARGET r=3 k=25 ")
        )
        with self.assertRaises(MODULE.RescanAuditError):
            MODULE.parse_transcript(changed, self.lo, self.hi)

    def test_histo_target_disagreement_is_rejected(self):
        changed = self.transcript.replace(
            "HISTO r=3 : 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 405 ",
            "HISTO r=3 : 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 404 ",
            1,
        )
        self.assertNotEqual(changed, self.transcript)
        with self.assertRaises(MODULE.RescanAuditError):
            MODULE.parse_transcript(changed, self.lo, self.hi)

    def test_unknown_or_duplicate_line_is_rejected(self):
        for changed in (
            self.transcript + "UNKNOWN success\n",
            self.transcript.replace(
                "CHECKSUM 5891343475671667447\n",
                "CHECKSUM 5891343475671667447\nCHECKSUM 5891343475671667447\n",
            ),
        ):
            with self.subTest(changed=changed[-80:]):
                with self.assertRaises(MODULE.RescanAuditError):
                    MODULE.parse_transcript(changed, self.lo, self.hi)


if __name__ == "__main__":
    unittest.main()
