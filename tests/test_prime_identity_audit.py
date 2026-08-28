import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "prime_identity_audit", ROOT / "tools" / "prime_identity_audit.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "prime_identity_contract", ROOT / "tools" / "check_publication_contract.py"
)
CONTRACT = importlib.util.module_from_spec(CONTRACT_SPEC)
assert CONTRACT_SPEC.loader is not None
CONTRACT_SPEC.loader.exec_module(CONTRACT)


class PrimeIdentityAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.independent = Path(cls.tempdir.name) / "prime_coverage"
        subprocess.run(
            [
                "gcc",
                "-O2",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "tools" / "prime_coverage.c"),
                "-o",
                str(cls.independent),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def make_equivalent_distinct_executable(self, directory: Path) -> Path:
        wrapper = directory / "scanner_wrapper.py"
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import os,sys\n"
            f"os.execv({str(self.independent)!r}, "
            f"[{str(self.independent)!r}, *sys.argv[1:]])\n",
            encoding="utf-8",
        )
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        return wrapper

    def make_repository(
        self, base: Path, lo: int = 2, hi: int = 100, chunk: int = 31
    ) -> tuple[Path, dict]:
        root = base / "repo"
        (root / "src").mkdir(parents=True)
        (root / "tools").mkdir()
        (root / "results" / "campaign").mkdir(parents=True)
        (root / MODULE.SCANNER_SOURCE_PATH).write_text(
            "// scanner source fixture\n", encoding="utf-8"
        )
        shutil.copyfile(
            ROOT / MODULE.INDEPENDENT_SOURCE_PATH,
            root / MODULE.INDEPENDENT_SOURCE_PATH,
        )
        ranges = MODULE._expected_ranges(lo, hi, chunk)
        campaign = {
            "chunks": [
                {
                    "chunk_id": chunk_id,
                    "lower_inclusive": lower,
                    "upper_exclusive": upper,
                }
                for chunk_id, lower, upper in ranges
            ],
            "interval": {
                "chunk_width": chunk,
                "lower_inclusive": lo,
                "upper_exclusive": hi,
            },
        }
        (root / MODULE.CAMPAIGN_MANIFEST_PATH).write_text(
            json.dumps(campaign, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return root, campaign

    def test_canonical_small_stream(self):
        output = subprocess.check_output(
            [str(self.independent), "--dump-primes", "2", "30"]
        )
        self.assertEqual(
            MODULE.parse_stream(output, 2, 30),
            [2, 3, 5, 7, 11, 13, 17, 19, 23, 29],
        )
        upper_prime = subprocess.check_output(
            [str(self.independent), "--dump-primes", "2", "29"]
        )
        self.assertEqual(
            MODULE.parse_stream(upper_prime, 2, 29),
            [2, 3, 5, 7, 11, 13, 17, 19, 23],
        )

    def test_default_campaign_geometry_has_exactly_515_chunks(self):
        ranges = MODULE._expected_ranges(
            970_000_000, 2_000_000_000, 2_000_000
        )
        self.assertEqual(len(ranges), 515)
        self.assertEqual(ranges[0], (1, 970_000_000, 972_000_000))
        self.assertEqual(ranges[-1], (515, 1_998_000_000, 2_000_000_000))

    def test_v2_manifest_is_accepted_by_hardened_contract_on_small_fixture(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, campaign = self.make_repository(base)
            scanner = self.make_equivalent_distinct_executable(base)
            manifest = MODULE.run_audit(
                root, scanner, self.independent, 2, 100, 31
            )
            MODULE.write_manifest(root / MODULE.OUTPUT_MANIFEST_PATH, manifest)

            self.assertEqual(
                set(manifest),
                {
                    "campaign_manifest",
                    "chunks",
                    "executables",
                    "interval",
                    "schema",
                    "totals",
                },
            )
            self.assertEqual(manifest["schema"], "vdw-prime-identity/v2")
            self.assertEqual(manifest["totals"], {
                "all_byte_equal": True,
                "chunk_count": 4,
                "prime_count": 25,
                "stream_bytes": sum(
                    row["scanner"]["stdout_bytes"] for row in manifest["chunks"]
                ),
            })
            self.assertNotIn(str(base), json.dumps(manifest, sort_keys=True))
            self.assertEqual(
                set(manifest["executables"]), {"scanner", "independent"}
            )
            for role, source_path, binary_path in (
                ("scanner", MODULE.SCANNER_SOURCE_PATH, MODULE.SCANNER_BINARY_PATH),
                (
                    "independent",
                    MODULE.INDEPENDENT_SOURCE_PATH,
                    MODULE.INDEPENDENT_BINARY_PATH,
                ),
            ):
                record = manifest["executables"][role]
                self.assertEqual(set(record), {"binary", "source"})
                self.assertEqual(record["source"]["path"], source_path)
                self.assertEqual(record["binary"]["path"], binary_path)
                self.assertTrue(os.access(root / binary_path, os.X_OK))
                for identity in record.values():
                    self.assertEqual(set(identity), {"path", "sha256", "size"})
                    candidate = root / identity["path"]
                    self.assertEqual(identity["size"], candidate.stat().st_size)
                    self.assertEqual(
                        identity["sha256"], MODULE.sha256_file(candidate)
                    )
            self.assertNotEqual(
                manifest["executables"]["scanner"]["binary"]["sha256"],
                manifest["executables"]["independent"]["binary"]["sha256"],
            )

            expected_chunk_keys = {
                "byte_equal",
                "chunk_id",
                "count",
                "independent",
                "lower_inclusive",
                "scanner",
                "upper_exclusive",
            }
            expected_run_keys = {
                "argv",
                "exit_code",
                "stderr_bytes",
                "stderr_sha256",
                "stdout_bytes",
                "stdout_sha256",
            }
            for chunk_id, row in enumerate(manifest["chunks"], 1):
                self.assertEqual(set(row), expected_chunk_keys)
                self.assertEqual(row["chunk_id"], chunk_id)
                self.assertIs(row["byte_equal"], True)
                for role in ("scanner", "independent"):
                    run = row[role]
                    binary_path = manifest["executables"][role]["binary"]["path"]
                    self.assertEqual(set(run), expected_run_keys)
                    self.assertEqual(
                        run["argv"],
                        [
                            binary_path,
                            "--dump-primes",
                            str(row["lower_inclusive"]),
                            str(row["upper_exclusive"]),
                        ],
                    )
                    self.assertEqual(run["exit_code"], 0)
                    self.assertEqual(run["stderr_bytes"], 0)
                    self.assertEqual(run["stderr_sha256"], MODULE.EMPTY_SHA256)
                    self.assertGreater(run["stdout_bytes"], 0)
                self.assertEqual(
                    row["scanner"]["stdout_sha256"],
                    row["independent"]["stdout_sha256"],
                )
                self.assertEqual(
                    row["scanner"]["stdout_bytes"],
                    row["independent"]["stdout_bytes"],
                )

            frozen = (
                CONTRACT.CAMPAIGN_LOWER_INCLUSIVE,
                CONTRACT.CAMPAIGN_UPPER_EXCLUSIVE,
                CONTRACT.CAMPAIGN_CHUNK_WIDTH,
                CONTRACT.CAMPAIGN_CHUNK_COUNT,
                CONTRACT.CAMPAIGN_PRIME_COUNT,
            )
            try:
                CONTRACT.CAMPAIGN_LOWER_INCLUSIVE = 2
                CONTRACT.CAMPAIGN_UPPER_EXCLUSIVE = 100
                CONTRACT.CAMPAIGN_CHUNK_WIDTH = 31
                CONTRACT.CAMPAIGN_CHUNK_COUNT = 4
                CONTRACT.CAMPAIGN_PRIME_COUNT = 25
                findings = CONTRACT.Findings()
                CONTRACT.validate_prime_identity(
                    root,
                    {"ordered-prime-identity-515": {"status": "passed"}},
                    findings,
                    campaign,
                )
                self.assertEqual(findings.errors, [])
            finally:
                (
                    CONTRACT.CAMPAIGN_LOWER_INCLUSIVE,
                    CONTRACT.CAMPAIGN_UPPER_EXCLUSIVE,
                    CONTRACT.CAMPAIGN_CHUNK_WIDTH,
                    CONTRACT.CAMPAIGN_CHUNK_COUNT,
                    CONTRACT.CAMPAIGN_PRIME_COUNT,
                ) = frozen

    def test_absolute_or_ambiguous_recorded_paths_are_rejected(self):
        for label in ("/tmp/scanner", "../scanner", "./scanner", ""):
            with self.subTest(label=label):
                with self.assertRaises(MODULE.PrimeIdentityError):
                    MODULE.canonical_relative_path(label, "scanner")

    def test_same_binary_is_rejected_as_non_independent(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, _ = self.make_repository(base)
            with self.assertRaises(MODULE.PrimeIdentityError):
                MODULE.run_audit(
                    root, self.independent, self.independent, 2, 100, 31
                )
            self.assertFalse((root / MODULE.OUTPUT_MANIFEST_PATH).exists())

    def test_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            bad = Path(raw) / "bad_stream.py"
            bad.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "lo,hi=sys.argv[-2:]\n"
                "print('VDW-PRIMES-v1')\nprint(lo)\nprint(hi)\nprint(lo)\n",
                encoding="utf-8",
            )
            bad.chmod(bad.stat().st_mode | stat.S_IXUSR)
            with self.assertRaises(MODULE.PrimeIdentityError):
                MODULE.audit_chunk(bad, self.independent, 2, 30)

    def test_stderr_fails_closed_even_with_zero_exit(self):
        with tempfile.TemporaryDirectory() as raw:
            noisy = Path(raw) / "noisy_stream.py"
            noisy.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "lo,hi=sys.argv[-2:]\n"
                "print('VDW-PRIMES-v1')\nprint(lo)\nprint(hi)\n"
                "print('FAIL: diagnostic', file=sys.stderr)\n",
                encoding="utf-8",
            )
            noisy.chmod(noisy.stat().st_mode | stat.S_IXUSR)
            with self.assertRaises(MODULE.PrimeIdentityError):
                MODULE.audit_chunk(noisy, self.independent, 14, 16)

    def test_campaign_range_mismatch_fails_before_binary_installation(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, campaign = self.make_repository(base)
            campaign["chunks"][0]["upper_exclusive"] += 1
            (root / MODULE.CAMPAIGN_MANIFEST_PATH).write_text(
                json.dumps(campaign, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            scanner = self.make_equivalent_distinct_executable(base)
            with self.assertRaises(MODULE.PrimeIdentityError):
                MODULE.run_audit(root, scanner, self.independent, 2, 100, 31)
            self.assertFalse((root / MODULE.SCANNER_BINARY_PATH).exists())
            self.assertFalse((root / MODULE.OUTPUT_MANIFEST_PATH).exists())

    def test_cli_output_and_check_are_deterministic(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, _ = self.make_repository(base)
            scanner = self.make_equivalent_distinct_executable(base)
            common = [
                "python3",
                str(ROOT / "tools" / "prime_identity_audit.py"),
                "--root",
                str(root),
                "--scanner",
                str(scanner),
                "--independent",
                str(self.independent),
                "--lo",
                "2",
                "--hi",
                "100",
                "--chunk",
                "31",
            ]
            output = root / MODULE.OUTPUT_MANIFEST_PATH
            created = subprocess.run(
                [*common, "--output", str(output)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            before = output.read_bytes()
            checked = subprocess.run(
                [*common, "--check", str(output)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
