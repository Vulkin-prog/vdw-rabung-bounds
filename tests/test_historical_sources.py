import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "materialize_historical_sources", ROOT / "tools" / "materialize_historical_sources.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class HistoricalSourceTest(unittest.TestCase):
    def test_all_historical_sources_match_exact_blobs(self):
        mapping, decoded = MODULE.validate()
        self.assertEqual(len(decoded), 11)
        self.assertEqual(len(mapping["revisions"]), 8)
        self.assertEqual(sum(row["chunks"] for row in mapping["revisions"]), 515)

    def test_git_blob_hash_includes_header(self):
        self.assertEqual(
            MODULE.git_blob_sha1(b"test content\n"),
            "d670460b4b4aece5915caf5c68d12f560a9fe3e4",
        )


if __name__ == "__main__":
    unittest.main()
