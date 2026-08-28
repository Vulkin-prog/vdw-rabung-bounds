import importlib.util
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "filter_bstar", ROOT / "tools" / "filter_bstar.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class BStarFilterTest(unittest.TestCase):
    def test_committed_list_is_reproducible(self):
        completed = subprocess.run(
            ["python3", "tools/filter_bstar.py", "--check"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("input=1859 accepted=1830", completed.stdout)

    def test_filter_matches_all_committed_rows(self):
        values = MODULE.parse_survivors(MODULE.INPUT.read_bytes())
        accepted = [prime for prime in values if MODULE.boundary_ok(prime)]
        output_rows = [
            int(line)
            for line in MODULE.OUTPUT.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(len(values), 1859)
        self.assertEqual(len(accepted), 1830)
        self.assertEqual(accepted, output_rows)
        self.assertEqual(sum(prime < MODULE.SPLIT for prime in accepted), 1702)

    def test_singleton_boundary_case_is_rejected(self):
        self.assertFalse(MODULE.boundary_ok(5, 2, 3))
        self.assertTrue(MODULE.boundary_ok(5, 2, 4))

    def test_parser_rejects_composite_and_duplicate(self):
        with self.assertRaises(MODULE.FilterError):
            MODULE.parse_survivors(b"# fixture\n7\n7\n")
        with self.assertRaises(MODULE.FilterError):
            MODULE.parse_survivors(b"# fixture\n25\n")


if __name__ == "__main__":
    unittest.main()
