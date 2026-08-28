import importlib.util
import os
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


class PrimeIdentityAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.independent = Path(cls.tempdir.name) / "prime_coverage"
        subprocess.run(
            [
                "gcc", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
                str(ROOT / "tools" / "prime_coverage.c"), "-o", str(cls.independent),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def test_canonical_small_stream(self):
        output = subprocess.check_output(
            [str(self.independent), "--dump-primes", "2", "30"]
        )
        self.assertEqual(MODULE.parse_stream(output, 2, 30), [2, 3, 5, 7, 11, 13, 17, 19, 23, 29])
        upper_prime = subprocess.check_output(
            [str(self.independent), "--dump-primes", "2", "29"]
        )
        self.assertEqual(MODULE.parse_stream(upper_prime, 2, 29), [2, 3, 5, 7, 11, 13, 17, 19, 23])

    def make_equivalent_distinct_executable(self):
        wrapper = Path(self.tempdir.name) / "scanner_wrapper.py"
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import os,sys\n"
            f"os.execv({str(self.independent)!r}, [{str(self.independent)!r}, *sys.argv[1:]])\n",
            encoding="utf-8",
        )
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        return wrapper

    def test_distinct_executables_produce_manifest(self):
        scanner = self.make_equivalent_distinct_executable()
        manifest = MODULE.run_audit(scanner, self.independent, 2, 100, 31)
        self.assertTrue(manifest["totals"]["all_byte_equal"])
        self.assertEqual(manifest["totals"]["prime_count"], 25)
        self.assertEqual(manifest["totals"]["chunk_count"], 4)
        serialized = str(manifest)
        self.assertNotIn(self.tempdir.name, serialized)
        self.assertEqual(
            manifest["executables"]["scanner"]["label"], "scanner-prime-stream"
        )

    def test_absolute_or_ambiguous_labels_are_rejected(self):
        scanner = self.make_equivalent_distinct_executable()
        for label in ("/tmp/scanner", "../scanner", ""):
            with self.subTest(label=label):
                with self.assertRaises(MODULE.PrimeIdentityError):
                    MODULE.run_audit(
                        scanner, self.independent, 2, 30, 20, scanner_label=label
                    )

    def test_same_binary_is_rejected_as_non_independent(self):
        with self.assertRaises(MODULE.PrimeIdentityError):
            MODULE.run_audit(self.independent, self.independent, 2, 100, 31)

    def test_mismatch_fails_closed(self):
        bad = Path(self.tempdir.name) / "bad_stream.py"
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
        noisy = Path(self.tempdir.name) / "noisy_stream.py"
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


if __name__ == "__main__":
    unittest.main()
