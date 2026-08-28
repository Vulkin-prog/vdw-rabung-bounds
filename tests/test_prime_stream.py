#!/usr/bin/env python3
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "scan_gpu.cu"
BEGIN = "// BEGIN VDW_PRIME_STREAM_CPU"
END = "// END VDW_PRIME_STREAM_CPU"


@unittest.skipUnless(shutil.which("g++"), "g++ is required for the CPU-only smoke test")
class PrimeStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text(encoding="utf-8")
        block = source.split(BEGIN, 1)[1].split(END, 1)[0]
        harness = """\
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
using u32=uint32_t; using u64=uint64_t;
""" + block + """\
int main(int argc,char** argv){
    if(argc==4&&!strcmp(argv[1],"--sieve")){
        u64 lo=0,hi=0;
        if(!parse_u64_decimal(argv[2],&lo)||!parse_u64_decimal(argv[3],&hi))return 2;
        for(u32 p:sieve_primes(lo,hi))printf("%u\\n",p);
        return 0;
    }
    if(argc==5&&!strcmp(argv[1],"--sample")){
        u64 lo=0,hi=0,ns=0;
        if(!parse_u64_decimal(argv[2],&lo)||!parse_u64_decimal(argv[3],&hi)||!parse_u64_decimal(argv[4],&ns))return 2;
        std::vector<u32> sample;
        if(!make_prime_sample("--sample",sieve_primes(lo,hi),(long)ns,&sample))return 2;
        for(u32 p:sample)printf("%u\\n",p);
        return 0;
    }
    u64 lo=0,hi=0;
    if(argc!=3||!parse_u64_decimal(argv[1],&lo)||!parse_u64_decimal(argv[2],&hi))return 2;
    return dump_prime_stream(lo,hi);
}
"""
        cls._temporary = tempfile.TemporaryDirectory()
        cls.binary = Path(cls._temporary.name) / "prime-stream-smoke"
        subprocess.run(
            ["g++", "-x", "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-o", str(cls.binary), "-"],
            input=harness,
            text=True,
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def test_half_open_interval_with_prime_upper_bound(self):
        result = subprocess.run(
            [str(self.binary), "2", "29"],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            result.stdout,
            "VDW-PRIMES-v1\n2\n29\n2\n3\n5\n7\n11\n13\n17\n19\n23\n",
        )

    def test_dispatch_precedes_cuda_initialization(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertLess(source.index('if(!strcmp(argv[1],"--dump-primes"))'), source.index("cudaGetDeviceProperties"))

    def test_internal_sieve_excludes_two(self):
        result = subprocess.run(
            [str(self.binary), "--sieve", "2", "3"],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, "3\n")

    def test_sample_rejects_interval_without_odd_prime(self):
        result = subprocess.run(
            [str(self.binary), "--sample", "2", "2", "1"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("SAMPLE_INPUT_REJECT", result.stderr)

    def test_sample_rejects_nonpositive_size(self):
        result = subprocess.run(
            [str(self.binary), "--sample", "2", "3", "0"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("SAMPLE_INPUT_REJECT", result.stderr)


if __name__ == "__main__":
    unittest.main()
