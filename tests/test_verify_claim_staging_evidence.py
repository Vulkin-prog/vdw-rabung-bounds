import base64
import hashlib
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "results" / "cpu" / "verify-claim-w2-k25.json"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class VerifyClaimStagingEvidenceTest(unittest.TestCase):
    def test_record_is_byte_bound_and_does_not_close_release_gates(self):
        record = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
        self.assertEqual(record["schema"], "vdw-verify-claim-staging-evidence/v1")
        self.assertEqual(record["status"], "preliminary_staging")
        self.assertFalse(record["release_claim_gate_satisfied"])
        self.assertFalse(record["external_replication_gate_satisfied"])
        self.assertTrue(record["git"]["worktree_clean_before_build"])
        self.assertTrue(record["git"]["source_matches_head"])

        for name in ("compiler", "stdout", "stderr_base64"):
            identity = record["artifacts"][name]
            data = (ROOT / identity["path"]).read_bytes()
            self.assertEqual(len(data), identity["size"])
            self.assertEqual(digest(data), identity["sha256"])

        encoded = (ROOT / record["artifacts"]["stderr_base64"]["path"]).read_bytes()
        decoded = base64.b64decode(encoded, validate=False)
        stderr_identity = record["artifacts"]["stderr_base64"]
        self.assertEqual(len(decoded), stderr_identity["decoded_size"])
        self.assertEqual(digest(decoded), stderr_identity["decoded_sha256"])

    def test_source_and_acceptance_are_reproducibly_identified(self):
        record = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
        source = record["build"]["source"]
        source_bytes = (ROOT / source["path"]).read_bytes()
        self.assertEqual(len(source_bytes), source["size"])
        self.assertEqual(digest(source_bytes), source["sha256"])

        available_commit = None
        for commit in (
            record["git"]["head_at_run"],
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
        self.assertEqual(digest(committed_source), record["git"]["head_source_sha256"])
        self.assertEqual(digest(committed_source), source["sha256"])

        stdout = (ROOT / record["artifacts"]["stdout"]["path"]).read_text(encoding="utf-8")
        claim = record["claim"]
        self.assertEqual(claim["lower_bound"], (claim["length"] - 1) * claim["prime"] + 1)
        self.assertEqual(
            stdout,
            "ACCEPT  W(2,25) > 27333622969  [ACCEPT : (a) et (b) OK]\n",
        )
        self.assertEqual(record["execution"]["exit_code"], 0)
        self.assertEqual(record["execution"]["verdict"], "ACCEPT")


if __name__ == "__main__":
    unittest.main()
