import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "external_replication", ROOT / "tools" / "external_replication.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


FAKE_VERIFIER = r'''#include <cstdio>
#include <cstdlib>
#include <cstring>
int main(int argc, char **argv) {
    if (argc == 2 && !std::strcmp(argv[1], "--selftest")) {
        for (int i = 0; i < 10; ++i) std::printf("[OK] fixture %d\n", i + 1);
        std::printf("== SELFTEST : 10/10 OK ==\n");
        return 0;
    }
    if (argc != 4) return 9;
    unsigned long long p = std::strtoull(argv[1], nullptr, 10);
    int r = std::atoi(argv[2]);
    int k = std::atoi(argv[3]);
    unsigned long long bound = (unsigned long long)(k - 1) * p + 1;
    std::printf("ACCEPT  W(%d,%d) > %llu  [ACCEPT : (a) et (b) OK]\n", r, k, bound);
    std::fprintf(stderr, "fixture p=%llu r=%d k=%d\n", p, r, k);
    return 0;
}
'''


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class ExternalReplicationTest(unittest.TestCase):
    def setUp(self):
        if shutil.which("git") is None or shutil.which("g++") is None:
            self.skipTest("git and g++ are required")
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.repo = base / "repository"
        self.repo.mkdir()
        (self.repo / "tools").mkdir()
        (self.repo / "audit").mkdir()
        (self.repo / "publication").mkdir()
        (self.repo / "tools" / "verify_claim.cpp").write_text(
            FAKE_VERIFIER, encoding="utf-8"
        )
        (self.repo / "tools" / "claim_audit.py").write_bytes(
            (ROOT / "tools" / "claim_audit.py").read_bytes()
        )
        write_json(
            self.repo / "publication" / "external-replication.json",
            {
                "schema": MODULE.EXTERNAL_SCHEMA,
                "status": "pending",
                "claim_ids": list(MODULE.FROZEN_CLAIM_IDS),
                "required_fields_per_claim": list(MODULE.REQUIRED_ROW_FIELDS),
                "replications": [],
            },
        )
        claims = []
        for frozen in MODULE.FROZEN_CLAIMS:
            claims.append({**frozen, "evidence_class": "fixture"})
        write_json(self.repo / "audit" / "claims.json", {"claims": claims})
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "Fixture"], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "config", "user.email", "fixture@example.invalid"],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=self.repo, check=True)
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repo,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        self.attestation = base / "attestation.txt"
        self.attestation.write_text(
            f"Operator ID: operator-01\nCandidate Git commit: {self.commit}\n"
            "Independent administration: yes\n",
            encoding="utf-8",
        )
        self.package = base / "package"

    def tearDown(self):
        self.temporary.cleanup()

    def build_package(self, claim_id=None, operator_id="operator-01", package=None):
        claim_id = claim_id or MODULE.FROZEN_CLAIM_IDS[0]
        package = package or self.package
        attestation = self.attestation
        if operator_id != "operator-01":
            attestation = Path(self.temporary.name) / f"{operator_id}.txt"
            attestation.write_text(
                f"Operator ID: {operator_id}\nCandidate Git commit: {self.commit}\n"
                "Independent administration: yes\n",
                encoding="utf-8",
            )
        manifest, accepted = MODULE.run_replication(
            self.repo, package, attestation, "g++", claim_id, operator_id
        )
        self.assertTrue(accepted)
        return manifest

    def test_run_executes_one_assigned_claim_and_received_package_verifies(self):
        manifest = self.build_package()
        self.assertEqual(len(manifest["replications"]), 1)
        self.assertEqual(manifest["replications"][0]["claim_id"], MODULE.FROZEN_CLAIM_IDS[0])
        self.assertEqual(manifest["operator_id"], "operator-01")
        self.assertTrue(all(row["verdict"] == "ACCEPT" for row in manifest["replications"]))
        verified = MODULE.verify_package(self.repo, self.package)
        self.assertTrue(MODULE.accepting(verified))
        self.assertFalse((self.package / MODULE.PARTIAL_MANIFEST_NAME).exists())
        self.assertTrue((self.package / MODULE.SUMS_NAME).is_file())

    def test_dirty_candidate_is_rejected_before_output_creation(self):
        (self.repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.ReplicationError, "not clean"):
            MODULE.run_replication(
                self.repo,
                self.package,
                self.attestation,
                "g++",
                MODULE.FROZEN_CLAIM_IDS[0],
                "operator-01",
            )
        self.assertFalse(self.package.exists())

    def test_hash_tampering_is_rejected(self):
        self.build_package()
        stdout = self.package / "runs" / MODULE.FROZEN_CLAIM_IDS[0] / "stdout.txt"
        stdout.write_bytes(stdout.read_bytes() + b"tampered\n")
        with self.assertRaisesRegex(MODULE.ReplicationError, "SHA256SUMS"):
            MODULE.verify_package(self.repo, self.package)

    def test_rehashed_extra_file_is_rejected(self):
        self.build_package()
        (self.package / "unrequested.txt").write_text("extra\n", encoding="utf-8")
        MODULE.write_sums(self.package)
        with self.assertRaisesRegex(MODULE.ReplicationError, "package file set differs"):
            MODULE.verify_package(self.repo, self.package)

    def test_manifest_row_and_environment_schemas_are_closed(self):
        self.build_package()
        manifest_path = self.package / MODULE.MANIFEST_NAME
        value = MODULE.load_json(manifest_path)

        value["unexpected"] = True
        manifest_path.write_bytes(MODULE.canonical_json(value))
        MODULE.write_sums(self.package)
        with self.assertRaisesRegex(MODULE.ReplicationError, "manifest fields differ"):
            MODULE.verify_package(self.repo, self.package)

        del value["unexpected"]
        value["replications"][0]["unexpected"] = True
        manifest_path.write_bytes(MODULE.canonical_json(value))
        MODULE.write_sums(self.package)
        with self.assertRaisesRegex(MODULE.ReplicationError, r"replications\[0\] fields differ"):
            MODULE.verify_package(self.repo, self.package)

        del value["replications"][0]["unexpected"]
        del value["environment"]["cpu_model"]
        value["replications"][0]["environment"] = value["environment"]
        manifest_path.write_bytes(MODULE.canonical_json(value))
        MODULE.write_sums(self.package)
        with self.assertRaisesRegex(MODULE.ReplicationError, "environment fields differ"):
            MODULE.verify_package(self.repo, self.package)

    def test_attestation_is_bound_to_operator_and_candidate_commit(self):
        wrong = Path(self.temporary.name) / "wrong-attestation.txt"
        wrong.write_text(
            "Operator ID: another-operator\nCandidate Git commit: "
            f"{self.commit}\nIndependent administration: yes\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MODULE.ReplicationError, "Operator ID"):
            MODULE.run_replication(
                self.repo,
                self.package,
                wrong,
                "g++",
                MODULE.FROZEN_CLAIM_IDS[0],
                "operator-01",
            )
        self.assertFalse(self.package.exists())

    def test_forged_accept_verdict_is_rejected_even_with_rehashed_package(self):
        self.build_package()
        manifest_path = self.package / MODULE.MANIFEST_NAME
        value = MODULE.load_json(manifest_path)
        row = value["replications"][0]
        row["exit_code"] = 1
        row["verdict"] = "ACCEPT"
        manifest_path.write_bytes(MODULE.canonical_json(value))
        MODULE.write_sums(self.package)
        with self.assertRaisesRegex(MODULE.ReplicationError, "parser result|not derivable"):
            MODULE.verify_package(self.repo, self.package)

    def test_negative_stderr_cannot_remain_accepting(self):
        self.build_package()
        manifest_path = self.package / MODULE.MANIFEST_NAME
        value = MODULE.load_json(manifest_path)
        row = value["replications"][0]
        stderr_path = self.package / row["stderr_path"]
        stderr_path.write_bytes(stderr_path.read_bytes() + b"FAIL injected\n")
        row["stderr_sha256"] = hashlib.sha256(stderr_path.read_bytes()).hexdigest()
        audit_module = MODULE.claim_audit_module(
            (self.package / value["parser_source_path"]).read_bytes(),
            label="fixture parser",
        )
        row["stderr_parse_error"] = MODULE.parse_claim_stderr(
            audit_module, stderr_path.read_bytes()
        )
        row["verdict"] = "ERROR"
        manifest_path.write_bytes(MODULE.canonical_json(value))
        MODULE.write_sums(self.package)
        verified = MODULE.verify_package(self.repo, self.package)
        self.assertFalse(MODULE.accepting(verified))

    def test_ledger_fragment_has_only_contract_fields_and_relative_paths(self):
        self.build_package()
        fragment = MODULE.ledger_fragment(
            self.repo, self.package, "results/external-replication/operator-01"
        )
        self.assertEqual(fragment["schema"], MODULE.IMPORT_SCHEMA)
        for row in fragment["replications"]:
            self.assertEqual(set(row), set(MODULE.REQUIRED_ROW_FIELDS))
            self.assertEqual(row["operator_id"], "operator-01")
            for key in ("verifier_path", "stdout_path", "stderr_path"):
                self.assertTrue(
                    row[key].startswith("results/external-replication/operator-01/")
                )
                self.assertFalse(Path(row[key]).is_absolute())

    def test_cli_verify_returns_nonzero_for_structurally_valid_nonaccepting_capture(self):
        self.build_package()
        manifest_path = self.package / MODULE.MANIFEST_NAME
        value = MODULE.load_json(manifest_path)
        row = value["replications"][0]
        stdout_path = self.package / row["stdout_path"]
        stdout_path.write_text("REJECT fixture\n", encoding="utf-8")
        row["stdout_sha256"] = hashlib.sha256(stdout_path.read_bytes()).hexdigest()
        row["exit_code"] = 1
        row["verdict"] = "ERROR"
        parser_source = (self.package / value["parser_source_path"]).read_bytes()
        audit_module = MODULE.claim_audit_module(parser_source, label="fixture parser")
        claim = next(
            claim for claim in MODULE.FROZEN_CLAIMS if claim["id"] == row["claim_id"]
        )
        row["parsed"], row["parse_error"] = MODULE.parse_claim_output(
            audit_module, stdout_path.read_bytes(), row["exit_code"], claim
        )
        manifest_path.write_bytes(MODULE.canonical_json(value))
        MODULE.write_sums(self.package)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = MODULE.main(
                [
                    "validate-bundle",
                    "--repo",
                    str(self.repo),
                    "--package",
                    str(self.package),
                ]
            )
        self.assertEqual(exit_code, 1)
        self.assertIn("NON_ACCEPTING_CAPTURE", output.getvalue())
        with self.assertRaisesRegex(MODULE.ReplicationError, "non-accepting"):
            MODULE.ledger_fragment(
                self.repo, self.package, "results/external-replication/operator-01"
            )

    def test_validate_set_requires_all_claims_and_four_distinct_operators(self):
        set_dir = Path(self.temporary.name) / "set"
        set_dir.mkdir()
        for index, claim_id in enumerate(MODULE.FROZEN_CLAIM_IDS, start=1):
            self.build_package(
                claim_id=claim_id,
                operator_id=f"operator-{index:02d}",
                package=set_dir / f"bundle-{index:02d}",
            )
        result = MODULE.validate_set(
            self.repo, set_dir, "results/external-replication/set-01"
        )
        self.assertEqual(result["schema"], MODULE.SET_SCHEMA)
        self.assertEqual(
            [row["claim_id"] for row in result["replications"]],
            list(MODULE.FROZEN_CLAIM_IDS),
        )
        self.assertEqual(len({row["operator_id"] for row in result["replications"]}), 4)
        self.assertTrue(
            all(
                row["stdout_path"].startswith("results/external-replication/set-01/")
                for row in result["replications"]
            )
        )

    def test_validate_set_rejects_duplicate_operator_ids(self):
        set_dir = Path(self.temporary.name) / "duplicate-set"
        set_dir.mkdir()
        for index, claim_id in enumerate(MODULE.FROZEN_CLAIM_IDS, start=1):
            self.build_package(
                claim_id=claim_id,
                operator_id="same-operator",
                package=set_dir / f"bundle-{index:02d}",
            )
        with self.assertRaisesRegex(MODULE.ReplicationError, "four distinct"):
            MODULE.validate_set(self.repo, set_dir)

    def test_high_prime_boundary_index_is_llp64_safe(self):
        source = (ROOT / "tools" / "verify_claim.cpp").read_text(encoding="utf-8")
        self.assertIn("auto cat=[&](int64_t t)", source)
        self.assertNotIn("auto cat=[&](long t)", source)


if __name__ == "__main__":
    unittest.main()
