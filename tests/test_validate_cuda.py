import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATE_CUDA = ROOT / "scripts" / "validate_cuda.sh"
CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "validate_cuda_contract", ROOT / "tools" / "check_publication_contract.py"
)
CONTRACT = importlib.util.module_from_spec(CONTRACT_SPEC)
assert CONTRACT_SPEC.loader is not None
CONTRACT_SPEC.loader.exec_module(CONTRACT)


def write_executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ValidateCudaTest(unittest.TestCase):
    def make_fixture(self, base: Path, *, test_exit: int = 0) -> tuple[Path, dict[str, str]]:
        repository = base / "repo"
        (repository / "scripts").mkdir(parents=True)
        (repository / "src").mkdir()
        (repository / "tests" / "gpu").mkdir(parents=True)
        (repository / "scripts" / "validate_cuda.sh").write_bytes(
            VALIDATE_CUDA.read_bytes()
        )
        (repository / "scripts" / "validate_cuda.sh").chmod(0o755)
        (repository / "src" / "scan_gpu.cu").write_text(
            "// isolated CUDA qualification fixture\n", encoding="utf-8"
        )
        write_executable(
            repository / "tests" / "gpu" / "test_scan_sm120.sh",
            """#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
mkdir -p "$ROOT/build/sm120-regression/logs"
printf 'fixture binary\\n' >"$ROOT/build/sm120-regression/scan_gpu"
printf 'fixture log\\n' >"$ROOT/build/sm120-regression/logs/scan.log"
"""
            + (
                "printf 'SCAN_SM120_REGRESSION_OK\\n'\n"
                if test_exit == 0
                else f"exit {test_exit}\n"
            ),
        )

        subprocess.run(["git", "init", "-q", repository], check=True)
        subprocess.run(
            ["git", "-C", repository, "config", "user.name", "CUDA fixture"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", repository, "config", "user.email", "fixture@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", repository, "add", "."], check=True)
        subprocess.run(
            ["git", "-C", repository, "commit", "-qm", "fixture"], check=True
        )

        cuda_bin = base / "cuda-bin"
        write_executable(
            cuda_bin / "nvcc",
            """#!/usr/bin/env bash
printf 'nvcc: NVIDIA (R) Cuda compiler driver\\n'
printf 'Cuda compilation tools, release 12.8, V12.8.93\\n'
""",
        )
        write_executable(
            cuda_bin / "cuobjdump",
            """#!/usr/bin/env bash
printf 'cuobjdump release 12.8, V12.8.90\\n'
""",
        )

        fake_bin = base / "fake-bin"
        write_executable(
            fake_bin / "nvidia-smi",
            """#!/usr/bin/env bash
case "${1:-}" in
  --query-gpu=*)
    printf '0, NVIDIA RTX fixture, GPU-fixture, 12.0, 570.00, 32768\\n'
    ;;
  -L)
    printf 'GPU 0: NVIDIA RTX fixture (UUID: GPU-fixture)\\n'
    ;;
  *)
    exit 2
    ;;
esac
""",
        )
        environment = os.environ.copy()
        environment["CUDA_BIN_DIR"] = str(cuda_bin)
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        return repository, environment

    def test_success_creates_contract_manifest_with_relative_paths(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            repository, environment = self.make_fixture(base)
            output = repository / "results" / "release" / "cuda-qualification"
            completed = subprocess.run(
                ["bash", "scripts/validate_cuda.sh", str(output)],
                cwd=repository,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(str(output / "manifest.json"), completed.stdout)
            self.assertFalse((output / "qualification.json").exists())

            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(
                set(manifest),
                {
                    "build",
                    "environment",
                    "finished_utc",
                    "logs",
                    "qualification",
                    "schema",
                    "started_utc",
                    "tests",
                },
            )
            self.assertEqual(manifest["schema"], "vdw-cuda-qualification/v1")
            self.assertEqual(manifest["qualification"], "PASS")
            build = manifest["build"]
            self.assertEqual(
                set(build),
                {
                    "binaries",
                    "command_argv",
                    "git_commit",
                    "git_tree",
                    "sources",
                    "worktree_clean_before_build",
                },
            )
            self.assertRegex(build["git_commit"], r"^[0-9a-f]{40}$")
            self.assertEqual(
                build["git_tree"],
                subprocess.run(
                    ["git", "-C", repository, "rev-parse", "HEAD^{tree}"],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                ).stdout.strip(),
            )
            self.assertIs(build["worktree_clean_before_build"], True)
            self.assertEqual(
                build["command_argv"], ["bash", "tests/gpu/test_scan_sm120.sh"]
            )
            sources = {row["path"]: row for row in build["sources"]}
            self.assertEqual(
                set(sources),
                {
                    "scripts/validate_cuda.sh",
                    "src/scan_gpu.cu",
                    "tests/gpu/test_scan_sm120.sh",
                },
            )
            self.assertEqual(
                sources["src/scan_gpu.cu"]["sha256"],
                sha256(repository / "src" / "scan_gpu.cu"),
            )
            self.assertEqual(len(build["binaries"]), 1)
            self.assertEqual(
                build["binaries"][0]["path"],
                "results/release/cuda-qualification/scan_gpu",
            )
            self.assertEqual(
                build["binaries"][0]["sha256"],
                sha256(output / "scan_gpu"),
            )
            self.assertEqual(
                set(manifest["environment"]),
                {
                    "compiler",
                    "cuda",
                    "driver",
                    "gpu",
                    "kernel_log",
                    "nvidia_smi_inventory",
                    "os_release",
                },
            )
            self.assertEqual(manifest["environment"]["cuda"]["version"], "12.8")
            self.assertEqual(
                manifest["environment"]["driver"]["versions"], ["570.00"]
            )
            self.assertEqual(
                manifest["environment"]["gpu"][0]["compute_capability"], "12.0"
            )
            self.assertEqual(manifest["tests"][0]["exit_code"], 0)
            self.assertEqual(manifest["tests"][0]["verdict"], "PASS")
            self.assertEqual(manifest["tests"][0]["success_marker_count"], 1)

            environment_artifacts = [
                manifest["environment"]["compiler"]["version_log"],
                manifest["environment"]["cuda"]["cuobjdump_version_log"],
                manifest["environment"]["driver"]["device_query"],
                manifest["environment"]["kernel_log"],
                manifest["environment"]["nvidia_smi_inventory"],
                manifest["environment"]["os_release"],
            ]
            output_artifacts = [
                *build["binaries"],
                *environment_artifacts,
                *manifest["logs"],
                manifest["tests"][0]["stdout"],
                manifest["tests"][0]["stderr"],
            ]
            output_paths = [row["path"] for row in output_artifacts]
            self.assertEqual(len(output_paths), len(set(output_paths)))
            self.assertEqual(
                set(output_paths),
                {
                    path.relative_to(repository).as_posix()
                    for path in output.rglob("*")
                    if path.is_file() and path.name != "manifest.json"
                },
            )
            for row in [*build["sources"], *output_artifacts]:
                self.assertEqual(set(row), {"path", "sha256", "size"})
                self.assertFalse(Path(row["path"]).is_absolute())
                candidate = repository / row["path"]
                self.assertEqual(row["size"], candidate.stat().st_size)
                self.assertEqual(row["sha256"], sha256(candidate))
            for row in output_artifacts:
                self.assertTrue(
                    row["path"].startswith("results/release/cuda-qualification/")
                )

            findings = CONTRACT.Findings()
            CONTRACT.validate_cuda_evidence(
                repository,
                {"cuda-release-qualification": {"status": "passed"}},
                findings,
            )
            self.assertEqual(findings.errors, [])

    def test_no_gpu_preflight_leaves_no_evidence_directory(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            repository, environment = self.make_fixture(base)
            output = repository / "results" / "release" / "cuda-qualification"
            write_executable(
                Path(environment["PATH"].split(":", 1)[0]) / "nvidia-smi",
                "#!/usr/bin/env bash\nexit 9\n",
            )
            completed = subprocess.run(
                ["bash", "scripts/validate_cuda.sh", str(output)],
                cwd=repository,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("no qualification evidence was created", completed.stderr)
            self.assertFalse(output.exists())

    def test_failed_suite_preserves_diagnostics_but_not_manifest(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            repository, environment = self.make_fixture(base, test_exit=7)
            output = repository / "results" / "release" / "cuda-qualification"
            completed = subprocess.run(
                ["bash", "scripts/validate_cuda.sh", str(output)],
                cwd=repository,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertTrue((output / "qualification.stderr").is_file())
            self.assertEqual((output / "test-exit-code.txt").read_text().strip(), "7")
            self.assertFalse((output / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
