#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$REPOSITORY_ROOT"

export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=0
export TZ=UTC
export LC_ALL=C.UTF-8

CPU_PYTHON=${PYTHON:-python3}
CPU_CXX=${CXX:-g++}
CPU_CC=${CC:-gcc}

for CPU_COMMAND in "$CPU_PYTHON" "$CPU_CXX" "$CPU_CC" sha256sum; do
  if ! command -v "$CPU_COMMAND" >/dev/null 2>&1; then
    printf 'ERROR: required command is unavailable: %s\n' "$CPU_COMMAND" >&2
    exit 2
  fi
done

CPU_BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/vdw-rabung-cpu.XXXXXXXX")
cleanup_cpu_build() {
  rm -rf -- "$CPU_BUILD_DIR"
}
trap cleanup_cpu_build EXIT

run_logged() {
  local label=$1
  shift
  local log_path="$CPU_BUILD_DIR/${label}.log"
  printf '[cpu] %s\n' "$label"
  if ! "$@" >"$log_path" 2>&1; then
    printf 'ERROR: %s failed; first 400 log lines follow.\n' "$label" >&2
    sed -n '1,400p' "$log_path" >&2
    exit 1
  fi
}

printf '[cpu] strict JSON and generated-artifact checks\n'
"$CPU_PYTHON" tools/strict_json_check.py
"$CPU_PYTHON" tools/materialize_historical_sources.py --check
"$CPU_PYTHON" tools/close_baselines.py --check
"$CPU_PYTHON" tools/density_holdout_audit.py --check
"$CPU_PYTHON" tools/rescan17_audit.py --check
"$CPU_PYTHON" tools/render_scanner_revisions.py --check

printf '[cpu] Python unit tests\n'
"$CPU_PYTHON" -m unittest discover -s tests -p 'test_*.py' -v

printf '[cpu] native builds\n'
"$CPU_CXX" -O2 -std=c++17 \
  reference/vdw_reference.cpp -o "$CPU_BUILD_DIR/vdw_reference"
"$CPU_CXX" -O2 -std=c++17 \
  tools/verify_claim.cpp -o "$CPU_BUILD_DIR/verify_claim"
"$CPU_CXX" -O2 -std=c++17 \
  tools/rabung_criterion.cpp -o "$CPU_BUILD_DIR/rabung_criterion"
"$CPU_CXX" -O2 -std=c++17 \
  tests/test_ordered_reduce.cpp -o "$CPU_BUILD_DIR/test_ordered_reduce"
"$CPU_CC" -O2 -std=c11 -Wall -Wextra -Werror \
  tools/prime_coverage.c -o "$CPU_BUILD_DIR/prime_coverage"
"$CPU_CC" -O2 -std=c17 -Wall -Wextra -Werror \
  tools/highp_witness.c -o "$CPU_BUILD_DIR/highp_witness"

run_logged reference-oracle "$CPU_BUILD_DIR/vdw_reference"
run_logged independent-verifier "$CPU_BUILD_DIR/verify_claim" --selftest
run_logged rabung-criterion "$CPU_BUILD_DIR/rabung_criterion" 1000
run_logged ordered-reduction "$CPU_BUILD_DIR/test_ordered_reduce"
run_logged high-range-witness-smoke "$CPU_BUILD_DIR/highp_witness" 1000003 1000

printf '[cpu] independent prime-stream smoke test\n'
PRIME_STREAM_ACTUAL=$("$CPU_BUILD_DIR/prime_coverage" --dump-primes 2 30)
PRIME_STREAM_EXPECTED=$'VDW-PRIMES-v1\n2\n30\n2\n3\n5\n7\n11\n13\n17\n19\n23\n29'
if [[ "$PRIME_STREAM_ACTUAL" != "$PRIME_STREAM_EXPECTED" ]]; then
  printf 'ERROR: independent prime stream differs from its canonical fixture.\n' >&2
  printf '%s\n' "$PRIME_STREAM_ACTUAL" >&2
  exit 1
fi

printf '[cpu] staging publication contract\n'
if [[ ! -f tools/check_publication_contract.py ]]; then
  printf 'ERROR: tools/check_publication_contract.py is missing.\n' >&2
  exit 1
fi
"$CPU_PYTHON" tools/check_publication_contract.py --mode staging

printf 'CPU_CHECKS_OK\n'
