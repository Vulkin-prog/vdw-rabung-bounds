#!/usr/bin/env python3
import importlib.util
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "claim_audit", ROOT / "tools" / "claim_audit.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


CLAIM = {
    "id": "fixture_w2_k4_p11",
    "colors": 2,
    "length": 4,
    "prime": 11,
    "lower_bound": 34,
    "origin": "fixture",
    "priority_credit": "fixture",
    "evidence_class": "succinct_rabung_certificate",
}


def fixture(name):
    return (ROOT / "tests" / name).read_bytes()


class ClaimAuditParserTests(unittest.TestCase):
    def test_positive_outputs(self):
        verify = MODULE.parse_verify1(
            fixture("claim_audit_verify1_accept.txt"), 0, CLAIM
        )
        self.assertEqual(verify["maxrun"], 3)
        self.assertEqual(verify["profile_digest"], "cd745910193fc509")
        self.assertEqual(verify["claim_digest"], "81182dbb4c586518")
        self.assertEqual(
            MODULE.parse_rabung(fixture("claim_audit_rabung_accept.txt"), 0, CLAIM)["verdict"],
            "ACCEPT",
        )
        self.assertEqual(
            MODULE.parse_verify_claim(
                fixture("claim_audit_verify_claim_accept.txt"), 0, CLAIM
            )["bound"],
            34,
        )
        witness = MODULE.parse_highp_witness(
            fixture("claim_audit_witness_accept.txt"), 0, CLAIM, 3
        )
        self.assertEqual(witness["witness_digest"], "74ac88167766fc88")

    def test_historical_diff_is_rejected_even_with_repeated_checksum(self):
        with self.assertRaises(MODULE.ClaimAuditError):
            MODULE.parse_verify1(
                fixture("claim_audit_verify1_diff_same_checksum.txt"), 0, CLAIM
            )

    def test_classification_failure_is_rejected_even_with_exit_zero(self):
        with self.assertRaises(MODULE.ClaimAuditError):
            MODULE.parse_verify1(
                fixture("claim_audit_verify1_classification_fail.txt"), 0, CLAIM
            )

    def test_truncated_profile_is_rejected_even_with_recomputed_text(self):
        text = fixture("claim_audit_verify1_accept.txt").decode("utf-8")
        text = "\n".join(line for line in text.splitlines() if not line.startswith("5    ")) + "\n"
        with self.assertRaises(MODULE.ClaimAuditError):
            MODULE.parse_verify1(text, 0, CLAIM)

    def test_truncated_verify_claim_is_rejected(self):
        with self.assertRaises(MODULE.ClaimAuditError):
            MODULE.parse_verify_claim(
                fixture("claim_audit_verify_claim_truncated.txt"), 0, CLAIM
            )

    def test_rabung_zero_is_rejected_despite_exit_zero(self):
        with self.assertRaises(MODULE.ClaimAuditError):
            MODULE.parse_rabung(fixture("claim_audit_rabung_zero.txt"), 0, CLAIM)

    def test_nonzero_exit_is_always_rejected(self):
        with self.assertRaises(MODULE.ClaimAuditError):
            MODULE.parse_verify_claim(
                fixture("claim_audit_verify_claim_accept.txt"), 9, CLAIM
            )

    def test_witness_is_bound_to_the_prime(self):
        wrong = dict(CLAIM, prime=13, lower_bound=40)
        with self.assertRaises(MODULE.ClaimAuditError):
            MODULE.parse_highp_witness(
                fixture("claim_audit_witness_accept.txt"), 0, wrong, 3
            )

    def test_canonical_claim_set_has_thirteen_arithmetically_valid_entries(self):
        claims = MODULE.load_claims(ROOT / "audit" / "claims.json")
        self.assertEqual(len(claims), 13)
        for claim in claims.values():
            MODULE.claim_numbers(claim)

    def test_schema_is_strict_at_manifest_and_run_levels(self):
        schema = json.loads(
            (ROOT / "audit" / "claim-manifest-v1.schema.json").read_text()
        )
        self.assertEqual(schema["$id"], MODULE.SCHEMA_ID)
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(schema["properties"]["claim"]["additionalProperties"])
        self.assertFalse(schema["$defs"]["run"]["additionalProperties"])


class ClaimAuditManifestTests(unittest.TestCase):
    def artifact(self, directory, name, data):
        path = directory / name
        path.write_bytes(data)
        return {
            "path": name,
            "sha256": MODULE.sha256_bytes(data),
            "bytes": len(data),
        }

    def run_record(self, directory, stage, attempt, data, parsed):
        suffix = {
            "scan_gpu_verify1": ["--verify1", "11", "4", "2"],
            "rabung_criterion": ["-q", "11", "2", "4"],
            "verify_claim": ["11", "2", "4"],
            "highp_witness": ["11", "100"],
        }[stage]
        return {
            "stage": stage,
            "attempt": attempt,
            "argv": [stage, *suffix],
            "exit_code": 0,
            "stdout": self.artifact(directory, f"{stage}-{attempt}.stdout", data),
            "stderr": self.artifact(directory, f"{stage}-{attempt}.stderr", b""),
            "parsed": parsed,
        }

    def make_manifest(self, directory):
        verify_data = fixture("claim_audit_verify1_accept.txt")
        rabung_data = fixture("claim_audit_rabung_accept.txt")
        claim_data = fixture("claim_audit_verify_claim_accept.txt")
        parsed_verify = MODULE.parse_verify1(verify_data, 0, CLAIM)
        parsed_rabung = MODULE.parse_rabung(rabung_data, 0, CLAIM)
        parsed_claim = MODULE.parse_verify_claim(claim_data, 0, CLAIM)
        return {
            "schema": MODULE.SCHEMA_ID,
            "claim": dict(CLAIM),
            "build": {
                "git_commit": "a" * 40,
                "git_clean": True,
                "sources_sha256": {"source": "b" * 64},
                "binaries_sha256": {"binary": "c" * 64},
                "compile_commands": {"binary": ["cc", "source"]},
                "compiler_versions": {"cc": "fixture 1.0"},
            },
            "runs": [
                self.run_record(directory, "scan_gpu_verify1", 1, verify_data, parsed_verify),
                self.run_record(directory, "scan_gpu_verify1", 2, verify_data, parsed_verify),
                self.run_record(directory, "rabung_criterion", 1, rabung_data, parsed_rabung),
                self.run_record(directory, "rabung_criterion", 2, rabung_data, parsed_rabung),
                self.run_record(directory, "verify_claim", 1, claim_data, parsed_claim),
            ],
            "final": {"verdict": "ACCEPT", "fail_closed": True},
        }

    def test_complete_manifest_accepts(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest = self.make_manifest(directory)
            result = MODULE.validate_manifest(manifest, directory, CLAIM)
            self.assertEqual(result["verdict"], "ACCEPT")

    def test_tampered_raw_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest = self.make_manifest(directory)
            (directory / "verify_claim-1.stdout").write_bytes(b"tampered\n")
            with self.assertRaises(MODULE.ClaimAuditError):
                MODULE.validate_manifest(manifest, directory, CLAIM)

    def test_negative_stderr_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest = self.make_manifest(directory)
            negative = b"FAIL: device comparison disagreed\n"
            (directory / "scan_gpu_verify1-1.stderr").write_bytes(negative)
            manifest["runs"][0]["stderr"] = {
                "path": "scan_gpu_verify1-1.stderr",
                "sha256": MODULE.sha256_bytes(negative),
                "bytes": len(negative),
            }
            with self.assertRaises(MODULE.ClaimAuditError):
                MODULE.validate_manifest(manifest, directory, CLAIM)


    def test_missing_repeat_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest = self.make_manifest(directory)
            manifest["runs"] = [
                run for run in manifest["runs"]
                if not (run["stage"] == "scan_gpu_verify1" and run["attempt"] == 2)
            ]
            with self.assertRaises(MODULE.ClaimAuditError):
                MODULE.validate_manifest(manifest, directory, CLAIM)

    def test_wrong_command_arguments_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest = self.make_manifest(directory)
            manifest["runs"][2]["argv"][-1] = "5"
            with self.assertRaises(MODULE.ClaimAuditError):
                MODULE.validate_manifest(manifest, directory, CLAIM)

    def test_empty_compile_command_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest = self.make_manifest(directory)
            manifest["build"]["compile_commands"] = {"binary": []}
            with self.assertRaises(MODULE.ClaimAuditError):
                MODULE.validate_manifest(manifest, directory, CLAIM)

    def test_reusing_one_raw_file_as_two_runs_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest = self.make_manifest(directory)
            manifest["runs"][1]["stdout"] = dict(manifest["runs"][0]["stdout"])
            with self.assertRaises(MODULE.ClaimAuditError):
                MODULE.validate_manifest(manifest, directory, CLAIM)

    def test_repository_backed_build_hashes_are_recomputed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            root.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.invalid"],
                cwd=root,
                check=True,
            )
            source = root / "source.cpp"
            source.write_bytes(b"int main(){}\n")
            subprocess.run(["git", "add", "source.cpp"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "source"], cwd=root, check=True)
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()
            binary = root / "build" / "program"
            binary.parent.mkdir()
            binary.write_bytes(b"fixture binary\n")
            build = {
                "git_commit": commit,
                "git_clean": True,
                "sources_sha256": {
                    "source.cpp": hashlib.sha256(source.read_bytes()).hexdigest()
                },
                "binaries_sha256": {
                    "build/program": hashlib.sha256(binary.read_bytes()).hexdigest()
                },
                "compile_commands": {"build/program": ["c++", "source.cpp"]},
                "compiler_versions": {"c++": "fixture"},
            }
            MODULE.verify_build_artifacts(build, root)
            binary.write_bytes(b"tampered\n")
            with self.assertRaises(MODULE.ClaimAuditError):
                MODULE.verify_build_artifacts(build, root)


class ClaimAuditTableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.claims = MODULE.load_claims(ROOT / "audit" / "claims.json")

    def result_for(self, claim_id):
        claim = self.claims[claim_id]
        return {
            "claim_id": claim_id,
            "claim": f"W({claim['colors']},{claim['length']}) > {claim['lower_bound']}",
            "provenance": claim["origin"],
            "priority_credit": claim["priority_credit"],
            "v2a": "PASS (2 outputs x 2 repeats)",
            "b7": "PASS (2 outputs x 2 repeats)",
            "cpu_walk": "PASS (2 outputs x 2 repeats)",
            "cpu_criterion": "PASS (2 outputs)",
            "verify_claim": "PASS (1 outputs)",
            "no_montgomery_witness": "not required",
            "claim_digest": "1" * 16,
            "profile_digest": "2" * 16,
            "manifest_sha256": "3" * 64,
            "verdict": "ACCEPT",
        }

    def test_missing_claim_prevents_all_generation(self):
        results = [self.result_for(claim_id) for claim_id in list(self.claims)[:-1]]
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "claims.md"
            with self.assertRaises(MODULE.ClaimAuditError):
                document = MODULE.build_set_document(results, self.claims)
                MODULE.write_set_outputs(document, output_md=output)
            self.assertFalse(output.exists())

    def test_exact_set_generates_thirteen_rows_in_all_formats(self):
        results = [self.result_for(claim_id) for claim_id in self.claims]
        document = MODULE.build_set_document(results, self.claims)
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            json_path = directory / "claims.json"
            md_path = directory / "claims.md"
            tex_path = directory / "claims.tex"
            MODULE.write_set_outputs(document, json_path, md_path, tex_path)
            rendered = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(rendered["claim_count"], 13)
            self.assertEqual(len(rendered["claims"]), 13)
            self.assertEqual(
                sum(line.startswith("| W(") for line in md_path.read_text(encoding="utf-8").splitlines()),
                13,
            )
            self.assertEqual(
                sum(" & " in line and line.rstrip().endswith(r"\\") for line in tex_path.read_text(encoding="utf-8").splitlines()) - 1,
                13,
            )

if __name__ == "__main__":
    unittest.main()
