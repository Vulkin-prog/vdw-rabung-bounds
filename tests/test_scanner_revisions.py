import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "render_scanner_revisions", ROOT / "tools" / "render_scanner_revisions.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ScannerRevisionRegistryTest(unittest.TestCase):
    def test_exact_partition_and_counts(self):
        data = MODULE.load_registry()
        rows = data["fingerprints"]
        self.assertEqual(
            [(row["first_chunk"], row["last_chunk"]) for row in rows],
            [(1, 7), (8, 35), (36, 78), (79, 515)],
        )
        self.assertEqual([row["target_count"] for row in rows], [10, 10, 13, 13])
        self.assertEqual(sum(row["last_chunk"] - row["first_chunk"] + 1 for row in rows), 515)

    def test_final_fingerprint_has_437_chunks(self):
        data = MODULE.load_registry()
        final = data["fingerprints"][-1]
        self.assertEqual(final["source_sha256_prefix"], "3b5d1049")
        self.assertEqual(final["last_chunk"] - final["first_chunk"] + 1, 437)


if __name__ == "__main__":
    unittest.main()
