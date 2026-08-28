#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
if (( $# > 1 )); then
  printf 'usage: %s [results/release/cuda-qualification]\n' "$0" >&2
  exit 2
fi

CUDA_OUTPUT_REQUEST=${1:-"$REPOSITORY_ROOT/results/release/cuda-qualification"}
if [[ "$CUDA_OUTPUT_REQUEST" != /* ]]; then
  CUDA_OUTPUT_REQUEST="$PWD/$CUDA_OUTPUT_REQUEST"
fi
CUDA_OUTPUT=$(realpath -m -- "$CUDA_OUTPUT_REQUEST")
CUDA_CONTRACT_OUTPUT="$REPOSITORY_ROOT/results/release/cuda-qualification"
if [[ "$CUDA_OUTPUT" != "$CUDA_CONTRACT_OUTPUT" ]]; then
  printf 'ERROR: publication-contract CUDA output must be exactly: %s\n' \
    "$CUDA_CONTRACT_OUTPUT" >&2
  exit 2
fi
if [[ -e "$CUDA_OUTPUT" || -L "$CUDA_OUTPUT" ]]; then
  printf 'ERROR: qualification output already exists: %s\n' "$CUDA_OUTPUT" >&2
  exit 2
fi

CUDA_BIN_DIR=${CUDA_BIN_DIR:-/usr/local/cuda/bin}
CUDA_NVCC="$CUDA_BIN_DIR/nvcc"
CUDA_CUOBJDUMP="$CUDA_BIN_DIR/cuobjdump"

for CUDA_COMMAND in git python3 sha256sum timeout flock nvidia-smi date uname realpath; do
  if ! command -v "$CUDA_COMMAND" >/dev/null 2>&1; then
    printf 'ERROR: required CUDA-qualification command is unavailable: %s\n' "$CUDA_COMMAND" >&2
    exit 2
  fi
done
for CUDA_PATH in "$CUDA_NVCC" "$CUDA_CUOBJDUMP"; do
  if [[ ! -x "$CUDA_PATH" ]]; then
    printf 'ERROR: required CUDA tool is unavailable: %s\n' "$CUDA_PATH" >&2
    exit 2
  fi
done

if [[ $(git -C "$REPOSITORY_ROOT" rev-parse --is-inside-work-tree 2>/dev/null) != true ]]; then
  printf 'ERROR: qualification must run from a Git worktree.\n' >&2
  exit 2
fi
CUDA_GIT_TOP=$(git -C "$REPOSITORY_ROOT" rev-parse --show-toplevel)
CUDA_GIT_TOP=$(cd "$CUDA_GIT_TOP" && pwd -P)
if [[ "$CUDA_GIT_TOP" != "$REPOSITORY_ROOT" ]]; then
  printf 'ERROR: script repository root and Git top-level differ.\n' >&2
  exit 2
fi
for CUDA_TRACKED_PATH in \
  scripts/validate_cuda.sh \
  src/scan_gpu.cu \
  tests/gpu/test_scan_sm120.sh; do
  if ! git -C "$REPOSITORY_ROOT" ls-files --error-unmatch "$CUDA_TRACKED_PATH" >/dev/null 2>&1; then
    printf 'ERROR: required qualification source is not tracked: %s\n' "$CUDA_TRACKED_PATH" >&2
    exit 2
  fi
done

CUDA_GIT_STATUS=$(GIT_OPTIONAL_LOCKS=0 git -C "$REPOSITORY_ROOT" status --porcelain=v1 --untracked-files=all)
if [[ -n "$CUDA_GIT_STATUS" ]]; then
  printf 'ERROR: CUDA qualification requires a clean worktree.\n%s\n' "$CUDA_GIT_STATUS" >&2
  exit 1
fi

CUDA_GIT_COMMIT=$(git -C "$REPOSITORY_ROOT" rev-parse --verify 'HEAD^{commit}')
CUDA_GIT_TREE=$(git -C "$REPOSITORY_ROOT" rev-parse --verify 'HEAD^{tree}')
CUDA_BUILD_DIR="$REPOSITORY_ROOT/build/sm120-regression"
if [[ -e "$CUDA_BUILD_DIR" || -L "$CUDA_BUILD_DIR" ]]; then
  printf 'ERROR: fresh qualification requires an absent build directory: %s\n' "$CUDA_BUILD_DIR" >&2
  exit 1
fi

# Complete the hardware/toolchain preflight before creating an evidence
# directory.  In particular, an installed nvidia-smi with no usable GPU must
# not leave anything that could be mistaken for release qualification.
if ! CUDA_NVCC_VERSION=$("$CUDA_NVCC" --version 2>&1); then
  printf 'ERROR: nvcc version query failed.\n' >&2
  exit 2
fi
if ! CUDA_CUOBJDUMP_VERSION=$("$CUDA_CUOBJDUMP" --version 2>&1); then
  printf 'ERROR: cuobjdump version query failed.\n' >&2
  exit 2
fi
if ! CUDA_GPU_DEVICES=$(nvidia-smi \
  --query-gpu=index,name,uuid,compute_cap,driver_version,memory.total \
  --format=csv,noheader,nounits 2>&1); then
  printf 'ERROR: no queryable NVIDIA GPU is available; no qualification evidence was created.\n' >&2
  exit 2
fi
if [[ -z "${CUDA_GPU_DEVICES//[[:space:]]/}" ]]; then
  printf 'ERROR: NVIDIA GPU query returned no devices; no qualification evidence was created.\n' >&2
  exit 2
fi
if ! CUDA_NVIDIA_SMI_LIST=$(nvidia-smi -L 2>&1); then
  printf 'ERROR: NVIDIA GPU identity query failed; no qualification evidence was created.\n' >&2
  exit 2
fi
if [[ -z "${CUDA_NVIDIA_SMI_LIST//[[:space:]]/}" ]]; then
  printf 'ERROR: NVIDIA GPU identity query returned no devices; no qualification evidence was created.\n' >&2
  exit 2
fi
if [[ ! -r /etc/os-release ]]; then
  printf 'ERROR: /etc/os-release is unreadable; no qualification evidence was created.\n' >&2
  exit 2
fi

CUDA_STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
umask 077
mkdir -p -- "$CUDA_OUTPUT/logs"
printf '%s\n' "$CUDA_GIT_COMMIT" >"$CUDA_OUTPUT/git-commit.txt"
printf '%s\n' 'bash tests/gpu/test_scan_sm120.sh' >"$CUDA_OUTPUT/command.txt"
printf '%s\n' "$(uname -srm)" >"$CUDA_OUTPUT/kernel.txt"
cp /etc/os-release "$CUDA_OUTPUT/os-release.txt"
printf '%s\n' "$CUDA_NVCC_VERSION" >"$CUDA_OUTPUT/nvcc-version.txt"
printf '%s\n' "$CUDA_CUOBJDUMP_VERSION" >"$CUDA_OUTPUT/cuobjdump-version.txt"
printf '%s\n' "$CUDA_GPU_DEVICES" >"$CUDA_OUTPUT/gpu-devices.csv"
printf '%s\n' "$CUDA_NVIDIA_SMI_LIST" >"$CUDA_OUTPUT/nvidia-smi-L.txt"
(
  cd "$REPOSITORY_ROOT"
  sha256sum \
    scripts/validate_cuda.sh \
    src/scan_gpu.cu \
    tests/gpu/test_scan_sm120.sh \
    >"$CUDA_OUTPUT/source-sha256.txt"
)

set +e
(
  cd "$REPOSITORY_ROOT"
  bash tests/gpu/test_scan_sm120.sh
) >"$CUDA_OUTPUT/qualification.stdout" 2>"$CUDA_OUTPUT/qualification.stderr"
CUDA_TEST_EXIT=$?
set -e

if [[ -d "$CUDA_BUILD_DIR/logs" ]]; then
  cp -a "$CUDA_BUILD_DIR/logs/." "$CUDA_OUTPUT/logs/"
fi
if [[ -f "$CUDA_BUILD_DIR/scan_gpu" ]]; then
  cp "$CUDA_BUILD_DIR/scan_gpu" "$CUDA_OUTPUT/scan_gpu"
  chmod 0755 "$CUDA_OUTPUT/scan_gpu"
fi

CUDA_SUCCESS_MARKER_COUNT=$(grep -Fxc 'SCAN_SM120_REGRESSION_OK' "$CUDA_OUTPUT/qualification.stdout" || true)
if (( CUDA_TEST_EXIT != 0 )) \
  || (( CUDA_SUCCESS_MARKER_COUNT != 1 )) \
  || [[ ! -f "$CUDA_OUTPUT/scan_gpu" ]]; then
  printf '%s\n' "$CUDA_TEST_EXIT" >"$CUDA_OUTPUT/test-exit-code.txt"
  printf 'CUDA_QUALIFICATION_FAILED; diagnostic logs preserved at %s (no manifest.json created)\n' \
    "$CUDA_OUTPUT" >&2
  exit 1
fi

CUDA_FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
export VDW_CUDA_OUTPUT=$CUDA_OUTPUT
export VDW_CUDA_REPOSITORY_ROOT=$REPOSITORY_ROOT
export VDW_CUDA_GIT_COMMIT=$CUDA_GIT_COMMIT
export VDW_CUDA_GIT_TREE=$CUDA_GIT_TREE
export VDW_CUDA_STARTED_UTC=$CUDA_STARTED_UTC
export VDW_CUDA_FINISHED_UTC=$CUDA_FINISHED_UTC
export VDW_CUDA_TEST_EXIT=$CUDA_TEST_EXIT
export VDW_CUDA_SUCCESS_MARKER_COUNT=$CUDA_SUCCESS_MARKER_COUNT

# manifest.json is the sole successful qualification record recognized by the
# publication contract.  It is installed atomically only after every check has
# passed; failed runs retain diagnostics but never this filename.
python3 - <<'PY'
import csv
import hashlib
import json
import os
import re
from pathlib import Path

output = Path(os.environ["VDW_CUDA_OUTPUT"])
root = Path(os.environ["VDW_CUDA_REPOSITORY_ROOT"])


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def identity(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"qualification artifact is not a regular file: {path}")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise SystemExit(f"qualification artifact escapes repository: {path}") from exc
    return {
        "path": relative,
        "sha256": sha256(path),
        "size": path.stat().st_size,
    }


nvcc_version = (output / "nvcc-version.txt").read_text(encoding="utf-8").strip()
cuobjdump_version = (output / "cuobjdump-version.txt").read_text(encoding="utf-8").strip()
cuda_match = re.search(r"\brelease\s+([^,\s]+)", nvcc_version)
cuda_version = cuda_match.group(1) if cuda_match else nvcc_version

gpu_rows = []
driver_versions = set()
with (output / "gpu-devices.csv").open(newline="", encoding="utf-8") as handle:
    for row in csv.reader(handle, skipinitialspace=True):
        if len(row) != 6 or not all(value.strip() for value in row):
            raise SystemExit("malformed nvidia-smi GPU identity row")
        index, name, uuid, compute_capability, driver, memory_mib = (
            value.strip() for value in row
        )
        driver_versions.add(driver)
        gpu_rows.append(
            {
                "compute_capability": compute_capability,
                "index": index,
                "memory_mib": memory_mib,
                "name": name,
                "uuid": uuid,
            }
        )
if not gpu_rows or not driver_versions:
    raise SystemExit("no GPU identity available for manifest")

source_paths = (
    "scripts/validate_cuda.sh",
    "src/scan_gpu.cu",
    "tests/gpu/test_scan_sm120.sh",
)
sources = [identity(root / path) for path in source_paths]
binary = identity(output / "scan_gpu")
nvcc_log = identity(output / "nvcc-version.txt")
cuobjdump_log = identity(output / "cuobjdump-version.txt")
device_query = identity(output / "gpu-devices.csv")
kernel_log = identity(output / "kernel.txt")
nvidia_smi_inventory = identity(output / "nvidia-smi-L.txt")
os_release = identity(output / "os-release.txt")
qualification_stdout = identity(output / "qualification.stdout")
qualification_stderr = identity(output / "qualification.stderr")

classified_output_paths = {
    row["path"]
    for row in (
        binary,
        nvcc_log,
        cuobjdump_log,
        device_query,
        kernel_log,
        nvidia_smi_inventory,
        os_release,
        qualification_stdout,
        qualification_stderr,
    )
}
all_output_files = []
for candidate in sorted(output.rglob("*")):
    if candidate.is_symlink():
        raise SystemExit(f"qualification output contains symbolic link: {candidate}")
    if candidate.is_file():
        all_output_files.append(candidate)
logs = [
    identity(candidate)
    for candidate in all_output_files
    if candidate.relative_to(root).as_posix() not in classified_output_paths
]
if not logs:
    raise SystemExit("qualification output contains no diagnostic logs")

record = {
    "build": {
        "binaries": [binary],
        "command_argv": ["bash", "tests/gpu/test_scan_sm120.sh"],
        "git_commit": os.environ["VDW_CUDA_GIT_COMMIT"],
        "git_tree": os.environ["VDW_CUDA_GIT_TREE"],
        "sources": sources,
        "worktree_clean_before_build": True,
    },
    "environment": {
        "compiler": {
            "identity": nvcc_version,
            "version_log": nvcc_log,
        },
        "cuda": {
            "cuobjdump_identity": cuobjdump_version,
            "cuobjdump_version_log": cuobjdump_log,
            "version": cuda_version,
        },
        "driver": {
            "versions": sorted(driver_versions),
            "device_query": device_query,
        },
        "gpu": gpu_rows,
        "kernel_log": kernel_log,
        "nvidia_smi_inventory": nvidia_smi_inventory,
        "os_release": os_release,
    },
    "finished_utc": os.environ["VDW_CUDA_FINISHED_UTC"],
    "logs": logs,
    "qualification": "PASS",
    "schema": "vdw-cuda-qualification/v1",
    "started_utc": os.environ["VDW_CUDA_STARTED_UTC"],
    "tests": [
        {
            "command_argv": ["bash", "tests/gpu/test_scan_sm120.sh"],
            "exit_code": int(os.environ["VDW_CUDA_TEST_EXIT"]),
            "id": "scan-sm120-regression",
            "stderr": qualification_stderr,
            "stdout": qualification_stdout,
            "success_marker": "SCAN_SM120_REGRESSION_OK",
            "success_marker_count": int(
                os.environ["VDW_CUDA_SUCCESS_MARKER_COUNT"]
            ),
            "verdict": "PASS",
            "working_directory": ".",
        }
    ],
}

temporary = output / ".manifest.json.tmp"
temporary.write_text(
    json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
temporary.replace(output / "manifest.json")
PY

printf 'CUDA_QUALIFICATION_OK  %s\n' "$CUDA_OUTPUT/manifest.json"
