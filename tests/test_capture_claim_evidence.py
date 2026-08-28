#!/usr/bin/env python3
import importlib.util
import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from argparse import Namespace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "capture_claim_evidence", ROOT / "scripts" / "capture_claim_evidence.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
AUDITOR = MODULE.load_auditor()

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
    return ROOT / "tests" / name


class CapturePlanTests(unittest.TestCase):
    def test_canonical_plan_has_thirteen_claims_and_sixty_seven_runs(self):
        claims = MODULE.load_claims(AUDITOR)
        plan = MODULE.build_plan(claims)
        self.assertEqual(plan["claim_count"], 13)
        self.assertEqual(plan["minimum_run_count"], 67)
        self.assertFalse(plan["publishes_partial_evidence"])
        self.assertEqual(
            sum(row["requires_montgomery_free_witness"] for row in plan["claims"]),
            2,
        )

    def test_plan_cli_needs_no_gpu_or_binary_arguments(self):
        process = subprocess.run(
            ["python3", "scripts/capture_claim_evidence.py", "plan"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["minimum_run_count"], 67)

    def test_paths_must_be_repository_relative_and_canonical(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for candidate in ("/tmp/evidence", "../evidence", "a/../evidence", "a//b"):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(MODULE.CaptureError):
                        MODULE.canonical_relative_path(root, candidate, "fixture")


class CaptureGitTests(unittest.TestCase):
    def test_dirty_worktree_is_rejected_before_capture(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.invalid"],
                cwd=root,
                check=True,
            )
            for relative in MODULE.REQUIRED_SOURCES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if relative == "audit/claims.json":
                    path.write_bytes((ROOT / relative).read_bytes())
                else:
                    path.write_text(relative + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            (root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
            with self.assertRaises(MODULE.CaptureError):
                MODULE.require_clean_commit(root)

    def test_supplied_compiler_identity_requires_a_sha256(self):
        malformed = {}
        for name in ("nvcc", "g++", "gcc"):
            identity = {
                "command": name,
                "resolved_path": f"/usr/bin/{name}",
                "sha256": "d" * 64,
                "version": "fixture",
            }
            if name == "g++":
                identity.pop("sha256")
            malformed[name] = json.dumps(identity)
        with self.assertRaises(MODULE.CaptureError):
            MODULE.validate_compiler_identities(malformed)

    def test_capture_json_parser_rejects_duplicates_nonfinite_and_bom(self):
        for payload in (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":1e9999}',
            b'\xef\xbb\xbf{"a":1}',
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(MODULE.CaptureError):
                    MODULE.strict_json_loads(payload, label="fixture")

    def test_capture_and_auditor_freeze_the_same_compile_commands(self):
        self.assertEqual(MODULE.REQUIRED_SOURCES, AUDITOR.REQUIRED_SOURCE_PATHS)
        self.assertEqual(MODULE.PROGRAMS, AUDITOR.PROGRAMS)
        self.assertEqual(
            MODULE.DEFAULT_WITNESS_SAMPLES, AUDITOR.WITNESS_SAMPLES
        )
        self.assertEqual(
            MODULE.exact_build_commands("build/fixture"),
            AUDITOR.exact_compile_commands("build/fixture"),
        )


class CaptureExecutionTests(unittest.TestCase):
    COMMIT = "a" * 40

    def make_program(self, root, name, output):
        path = root / "bin" / name
        path.parent.mkdir(exist_ok=True)
        path.write_text(
            "#!/bin/sh\nexec /bin/cat " + str(output) + "\n", encoding="utf-8"
        )
        path.chmod(0o755)
        return path

    def binaries(self, root, claim_output=None):
        claim_output = claim_output or fixture("claim_audit_verify_claim_accept.txt")
        return {
            "scan_gpu": self.make_program(
                root, "scan_gpu", fixture("claim_audit_verify1_accept.txt")
            ),
            "rabung_criterion": self.make_program(
                root, "rabung_criterion", fixture("claim_audit_rabung_accept.txt")
            ),
            "verify_claim": self.make_program(root, "verify_claim", claim_output),
            "highp_witness": self.make_program(
                root, "highp_witness", fixture("claim_audit_witness_accept.txt")
            ),
        }

    def build_record(self):
        binaries = AUDITOR.preserved_binary_paths(self.COMMIT)
        commands = MODULE.exact_build_commands("build/fixture")
        compiler_versions = {
            name: json.dumps(
                {
                    "command": name,
                    "resolved_path": f"/fixture/{name}",
                    "sha256": "d" * 64,
                    "version": f"{name} fixture 1.0",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            for name in ("nvcc", "g++", "gcc")
        }
        return {
            "git_commit": self.COMMIT,
            "git_clean": True,
            "sources_sha256": {
                source: "b" * 64 for source in MODULE.REQUIRED_SOURCES
            },
            "binaries_sha256": {
                binaries[name]: "c" * 64 for name in MODULE.PROGRAMS
            },
            "compile_commands": {
                binaries[name]: commands[name] for name in MODULE.PROGRAMS
            },
            "compiler_versions": compiler_versions,
        }

    def recorded_binaries(self):
        return AUDITOR.preserved_binary_paths(self.COMMIT)

    def test_complete_fixture_captures_exactly_five_validated_runs(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            binaries = self.binaries(root)
            output = root / "claim"
            manifest = MODULE.capture_one_claim(
                AUDITOR,
                CLAIM,
                output,
                binaries,
                self.recorded_binaries(),
                self.build_record(),
                timeout_seconds=30,
                witness_samples=MODULE.DEFAULT_WITNESS_SAMPLES,
            )
            self.assertEqual(len(manifest["runs"]), 5)
            self.assertEqual(manifest["final"], {"verdict": "ACCEPT", "fail_closed": True})
            AUDITOR.validate_manifest(manifest, output, CLAIM)
            self.assertEqual(len(list(output.glob("*.stdout"))), 5)
            self.assertEqual(len(list(output.glob("*.stderr"))), 5)

    def test_required_montgomery_free_witness_is_captured_and_validated(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            binaries = self.binaries(root)
            output = root / "claim"
            witness_claim = dict(CLAIM, requires_montgomery_free_witness=True)
            manifest = MODULE.capture_one_claim(
                AUDITOR,
                witness_claim,
                output,
                binaries,
                self.recorded_binaries(),
                self.build_record(),
                timeout_seconds=30,
                witness_samples=MODULE.DEFAULT_WITNESS_SAMPLES,
            )
            self.assertEqual(len(manifest["runs"]), 6)
            self.assertEqual(manifest["runs"][-1]["stage"], "highp_witness")
            AUDITOR.validate_manifest(manifest, output, witness_claim)

    def test_noncanonical_witness_sample_count_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "claim"
            witness_claim = dict(CLAIM, requires_montgomery_free_witness=True)
            with self.assertRaises(MODULE.CaptureError):
                MODULE.capture_one_claim(
                    AUDITOR,
                    witness_claim,
                    output,
                    self.binaries(root),
                    self.recorded_binaries(),
                    self.build_record(),
                    timeout_seconds=30,
                    witness_samples=100,
                )
            self.assertFalse((output / "manifest.json").exists())

    def test_printed_fake_accept_never_creates_a_manifest(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fake = root / "fake-accept.txt"
            fake.write_text(
                "ACCEPT W(2,4) > 999 [ACCEPT : (a) et (b) OK]\n", encoding="utf-8"
            )
            binaries = self.binaries(root, fake)
            output = root / "claim"
            with self.assertRaises(MODULE.CaptureError):
                MODULE.capture_one_claim(
                    AUDITOR,
                    CLAIM,
                    output,
                    binaries,
                    self.recorded_binaries(),
                    self.build_record(),
                    timeout_seconds=30,
                    witness_samples=MODULE.DEFAULT_WITNESS_SAMPLES,
                )
            self.assertFalse((output / "manifest.json").exists())


class CaptureTransactionTests(unittest.TestCase):
    FAKE_PROGRAM = r'''#!/usr/bin/env python3
import os
import sys

OFFSET = 14695981039346656037
PRIME = 1099511628211
MASK = (1 << 64) - 1

def digest(values):
    result = OFFSET
    for value in values:
        value = int(value)
        for _ in range(8):
            result ^= value & 255
            result = (result * PRIME) & MASK
            value >>= 8
    return result

name = os.path.basename(sys.argv[0])
if name == "scan_gpu":
    _, p, k, r = sys.argv[1:]
    p, k, r = int(p), int(k), int(r)
    active = [rr for rr in range(2, 10) if (p - 1) % rr == 0]
    profile_values = [p]
    for rr in active:
        profile_values.extend([rr, 1, 1, 1, 1, 1, 1, 1])
    profile = digest(profile_values)
    bound = (k - 1) * p + 1
    claim = digest([p, r, k, bound, profile, 1, 1, 1, 1, 1, 1])
    print(f"VERIFY1 p={p} g=2")
    for rr in active:
        print(rr, 1, 1, 1, 1, 1, 1, "OK")
    print(f"CHECKSUM(maxrun) {profile}")
    print(f"PROFILE_DIGEST algorithm=fnv1a64-le64 value={profile:016x}")
    print("TRIPLET x2 : ACCORD 100% (V2a=B7=CPU, double-run identique)")
    print(f"CLASSIFICATION r={r} k={k} maxrun=1 A=PASS Bstar=PASS A_AND_B=PASS")
    print(
        "CLAIM_RESULT version=1 digest_alg=fnv1a64-le64 "
        f"p={p} r={r} k={k} bound={bound} maxrun=1 "
        f"profile_digest={profile:016x} applicable=YES A=PASS Bstar=PASS "
        f"A_AND_B=PASS triplet=ACCORD verdict=ACCEPT digest={claim:016x}"
    )
elif name == "rabung_criterion":
    print("1")
elif name == "verify_claim":
    p, r, k = map(int, sys.argv[1:])
    print(f"ACCEPT W({r},{k}) > {(k - 1) * p + 1} [ACCEPT : (a) et (b) OK]")
elif name == "highp_witness":
    p = int(sys.argv[1])
    active = [rr for rr in range(2, 10) if (p - 1) % rr == 0]
    print("[C1] racine primitive : OK")
    print("[C2] marche fermee : OK")
    print("[C3] marche vs caractere : 1 comparaisons, 0 desaccords -> OK")
    print("[C4] identite miroir : 1 comparaisons, 0 desaccords -> OK")
    values = [p]
    for rr in active:
        print(f"WITNESS p={p} r={rr} maxrun=1")
        values.extend([rr, 1])
    print(f"WITNESS_CHECKSUM {digest(values)}")
    print("VERDICT_TEMOIN : VALIDE")
else:
    raise SystemExit(2)
'''

    def test_complete_set_is_published_only_after_all_sixty_seven_runs_validate(self):
        claims = MODULE.load_claims(AUDITOR)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.invalid"],
                cwd=root,
                check=True,
            )
            (root / ".gitignore").write_text("build/\n", encoding="utf-8")
            for relative in MODULE.REQUIRED_SOURCES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if relative == "audit/claims.json":
                    path.write_bytes((ROOT / relative).read_bytes())
                else:
                    path.write_text(relative + "\n", encoding="utf-8")
            readme = root / "results" / "claims" / "README.md"
            readme.parent.mkdir(parents=True)
            readme.write_text("fixture placeholder\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()

            binary_dir = root / "build" / "fake"
            binary_dir.mkdir(parents=True)
            for name in MODULE.PROGRAMS:
                path = binary_dir / name
                path.write_text(textwrap.dedent(self.FAKE_PROGRAM), encoding="utf-8")
                path.chmod(0o755)
            compiler_versions = {
                name: json.dumps(
                    {
                        "command": name,
                        "resolved_path": f"/fixture/{name}",
                        "sha256": "d" * 64,
                        "version": f"{name} fixture 1.0",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for name in ("nvcc", "g++", "gcc")
            }
            metadata = {
                "schema": MODULE.SUPPLIED_BUILD_SCHEMA,
                "git_commit": commit,
                "sources_sha256": MODULE.source_hashes(root, commit),
                "binaries_sha256": {
                    name: MODULE.sha256_file(binary_dir / name)
                    for name in MODULE.PROGRAMS
                },
                "compile_commands": MODULE.exact_build_commands("build/fake"),
                "compiler_versions": compiler_versions,
            }
            metadata_path = binary_dir / "build-metadata.json"
            metadata_path.write_text(MODULE.json_text(metadata), encoding="utf-8")
            args = Namespace(
                output="results/claims",
                build=False,
                binary_dir="build/fake",
                build_metadata="build/fake/build-metadata.json",
                build_dir="build/unused",
                timeout_seconds=30,
                witness_samples=MODULE.DEFAULT_WITNESS_SAMPLES,
            )
            old_root = MODULE.ROOT
            MODULE.ROOT = root
            try:
                result = MODULE.capture(args, AUDITOR, claims)
            finally:
                MODULE.ROOT = old_root
            self.assertEqual(result["run_count"], 67)
            manifests = sorted((root / "results" / "claims").glob("*/manifest.json"))
            self.assertEqual(len(manifests), 13)
            self.assertEqual(
                sum(len(json.loads(path.read_text())["runs"]) for path in manifests),
                67,
            )
            self.assertTrue(readme.is_file())
            output = root / "results" / "claims"
            for filename in AUDITOR.CANONICAL_SET_OUTPUTS.values():
                self.assertTrue((output / filename).is_file())
            results = [
                AUDITOR.load_and_validate_manifest(
                    output / claim_id / "manifest.json",
                    claims,
                    repository_root=root,
                )
                for claim_id in claims
            ]
            document = AUDITOR.build_set_document(results, claims)
            AUDITOR.verify_canonical_set_outputs(document, output)
            validated = subprocess.run(
                [
                    "python3",
                    str(ROOT / "tools" / "claim_audit.py"),
                    "--claims",
                    str(root / "audit" / "claims.json"),
                    "validate-set",
                    str(output),
                    "--repository-root",
                    str(root),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(validated.returncode, 0, validated.stderr)
            summary = json.loads(validated.stdout)
            self.assertEqual(summary["claim_count"], 13)
            self.assertEqual(len(summary["canonical_outputs"]), 3)


if __name__ == "__main__":
    unittest.main()
