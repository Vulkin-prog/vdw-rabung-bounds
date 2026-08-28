import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "results" / "cpu" / "rabung-p10000.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RabungSweepEvidenceTests(unittest.TestCase):
    def test_record_is_honest_and_self_consistent(self):
        record = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
        self.assertEqual(record["schema"], "vdw-rabung-sweep-evidence/v1")
        self.assertEqual(record["status"], "preliminary_staging")
        self.assertFalse(record["release_gate_satisfied"])
        self.assertTrue(record["git"]["worktree_clean_before_build"])

        for identity in record["artifacts"].values():
            path = ROOT / identity["path"]
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_size, identity["size"])
            self.assertEqual(sha256(path), identity["sha256"])

        source = record["build"]["source"]
        source_path = ROOT / source["path"]
        self.assertEqual(source_path.stat().st_size, source["size"])
        self.assertEqual(sha256(source_path), source["sha256"])
        available_commit = None
        for commit in (
            record["git"]["commit"],
            record["git"]["published_equivalent_commit"],
        ):
            probe = subprocess.run(
                ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if probe.returncode == 0:
                available_commit = commit
                break
        self.assertIsNotNone(available_commit)
        committed_tree = subprocess.check_output(
            ["git", "rev-parse", f"{available_commit}^{{tree}}"], cwd=ROOT, text=True
        ).strip()
        self.assertEqual(committed_tree, record["git"]["tree"])
        committed_source = subprocess.run(
            ["git", "show", f"{available_commit}:{source['path']}"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        committed_matches = hashlib.sha256(committed_source).hexdigest() == source["sha256"]
        self.assertEqual(record["git"]["source_matches_commit"], committed_matches)

    def test_raw_output_matches_recorded_counts(self):
        record = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
        stdout = (ROOT / record["artifacts"]["stdout"]["path"]).read_text(encoding="utf-8")
        stderr = (ROOT / record["artifacts"]["stderr"]["path"]).read_bytes()
        strong = re.search(r"-> (\d+) cas testes, (\d+) incoherence\(s\) fortes", stdout)
        sweep = re.search(
            r"-> (\d+) \(p,r,k\) testes ; (\d+) valides selon critere ; (\d+) MISMATCH\(es\)",
            stdout,
        )
        self.assertIsNotNone(strong)
        self.assertIsNotNone(sweep)
        self.assertEqual(tuple(map(int, strong.groups())), (190, 0))
        self.assertEqual(tuple(map(int, sweep.groups())), (20170, 4499, 0))
        self.assertEqual(record["execution"]["exit_code"], 0)
        self.assertEqual(stderr, b"")


if __name__ == "__main__":
    unittest.main()
