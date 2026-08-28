#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
if (( $# > 1 )); then
  printf 'usage: %s [NEW_OUTPUT_DIR]\n' "$0" >&2
  exit 2
fi

CUDA_OUTPUT_REQUEST=${1:-"$REPOSITORY_ROOT/results/release/cuda-qualification"}
if [[ "$CUDA_OUTPUT_REQUEST" != /* ]]; then
  CUDA_OUTPUT_REQUEST="$PWD/$CUDA_OUTPUT_REQUEST"
fi
CUDA_OUTPUT=$(realpath -m -- "$CUDA_OUTPUT_REQUEST")
if [[ -e "$CUDA_OUTPUT" || -L "$CUDA_OUTPUT" ]]; then
  printf 'ERROR: qualification output already exists: %s\n' "$CUDA_OUTPUT" >&2
  exit 2
fi

for CUDA_COMMAND in git python3 sha256sum timeout flock nvidia-smi; do
  if ! command -v "$CUDA_COMMAND" >/dev/null 2>&1; then
    printf 'ERROR: required CUDA-qualification command is unavailable: %s\n' "$CUDA_COMMAND" >&2
    exit 2
  fi
done
for CUDA_PATH in /usr/local/cuda/bin/nvcc /usr/local/cuda/bin/cuobjdump; do
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
for CUDA_TRACKED_PATH in src/scan_gpu.cu tests/gpu/test_scan_sm120.sh; do
  git -C "$REPOSITORY_ROOT" ls-files --error-unmatch "$CUDA_TRACKED_PATH" >/dev/null
done

CUDA_GIT_STATUS=$(GIT_OPTIONAL_LOCKS=0 git -C "$REPOSITORY_ROOT" status --porcelain=v1 --untracked-files=all)
if [[ -n "$CUDA_GIT_STATUS" ]]; then
  printf 'ERROR: CUDA qualification requires a clean worktree.\n%s\n' "$CUDA_GIT_STATUS" >&2
  exit 1
fi

CUDA_GIT_COMMIT=$(git -C "$REPOSITORY_ROOT" rev-parse --verify 'HEAD^{commit}')
CUDA_STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CUDA_BUILD_DIR="$REPOSITORY_ROOT/build/sm120-regression"
if [[ -e "$CUDA_BUILD_DIR" || -L "$CUDA_BUILD_DIR" ]]; then
  printf 'ERROR: fresh qualification requires an absent build directory: %s\n' "$CUDA_BUILD_DIR" >&2
  exit 1
fi

umask 077
mkdir -p -- "$CUDA_OUTPUT/logs"
printf '%s\n' "$CUDA_GIT_COMMIT" >"$CUDA_OUTPUT/git-commit.txt"
printf '%s\n' 'bash tests/gpu/test_scan_sm120.sh' >"$CUDA_OUTPUT/command.txt"
printf '%s\n' "$(uname -srm)" >"$CUDA_OUTPUT/kernel.txt"
if [[ -r /etc/os-release ]]; then
  cp /etc/os-release "$CUDA_OUTPUT/os-release.txt"
fi
/usr/local/cuda/bin/nvcc --version >"$CUDA_OUTPUT/nvcc-version.txt" 2>&1
/usr/local/cuda/bin/cuobjdump --version >"$CUDA_OUTPUT/cuobjdump-version.txt" 2>&1
nvidia-smi --query-gpu=index,name,uuid,compute_cap,driver_version,memory.total \
  --format=csv,noheader >"$CUDA_OUTPUT/gpu-devices.csv"
nvidia-smi -L >"$CUDA_OUTPUT/nvidia-smi-L.txt"
(
  cd "$REPOSITORY_ROOT"
  sha256sum \
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

CUDA_FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
export VDW_CUDA_OUTPUT=$CUDA_OUTPUT
export VDW_CUDA_GIT_COMMIT=$CUDA_GIT_COMMIT
export VDW_CUDA_STARTED_UTC=$CUDA_STARTED_UTC
export VDW_CUDA_FINISHED_UTC=$CUDA_FINISHED_UTC
export VDW_CUDA_TEST_EXIT=$CUDA_TEST_EXIT

python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

output = Path(os.environ["VDW_CUDA_OUTPUT"])
binary = output / "scan_gpu"


def sha256(path: Path):
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


exit_code = int(os.environ["VDW_CUDA_TEST_EXIT"])
stdout = (output / "qualification.stdout").read_text(encoding="utf-8", errors="replace")
marker_count = sum(line == "SCAN_SM120_REGRESSION_OK" for line in stdout.splitlines())
passed = exit_code == 0 and marker_count == 1 and binary.is_file()
record = {
    "binary_sha256": sha256(binary),
    "finished_utc": os.environ["VDW_CUDA_FINISHED_UTC"],
    "git_commit": os.environ["VDW_CUDA_GIT_COMMIT"],
    "qualification": "passed" if passed else "failed",
    "schema": "vdw-cuda-qualification/v1",
    "started_utc": os.environ["VDW_CUDA_STARTED_UTC"],
    "success_marker_count": marker_count,
    "test_exit_code": exit_code,
}
(output / "qualification.json").write_text(
    json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

(
  cd "$CUDA_OUTPUT"
  find . -type f ! -name MANIFEST.sha256 -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    >MANIFEST.sha256
)

CUDA_SUCCESS_MARKER_COUNT=$(grep -Fxc 'SCAN_SM120_REGRESSION_OK' "$CUDA_OUTPUT/qualification.stdout" || true)
if (( CUDA_TEST_EXIT != 0 )) \
  || (( CUDA_SUCCESS_MARKER_COUNT != 1 )) \
  || [[ ! -f "$CUDA_OUTPUT/scan_gpu" ]]; then
  printf 'CUDA_QUALIFICATION_FAILED  evidence preserved at %s\n' "$CUDA_OUTPUT" >&2
  exit 1
fi
printf 'CUDA_QUALIFICATION_OK  %s\n' "$CUDA_OUTPUT"
