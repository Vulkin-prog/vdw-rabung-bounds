#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD="$ROOT/build/sm120-regression"
LOG="$BUILD/logs"
LOCK=/tmp/vdw_sm120_gpu.lock
mkdir -p "$BUILD" "$LOG"
NV=(/usr/local/cuda/bin/nvcc -O3 -std=c++17 -lineinfo -Xptxas=-v -gencode arch=compute_120,code=sm_120 -gencode arch=compute_120,code=compute_120)
timeout 300 "${NV[@]}" "$ROOT/src/scan_gpu.cu" -o "$BUILD/scan_gpu" 2>"$LOG/scan_compile.log"
gpu(){ local cap=$1; shift; timeout "$cap" flock "$LOCK" "$@"; }
gpu 300 "$BUILD/scan_gpu" --validate 30000 >"$LOG/scan_validate.log" 2>&1
grep -Fq 'VERDICT : ACCORD 100% (V2a/V2b + B7 + tri + CPU concordants)' "$LOG/scan_validate.log"
grep -Fq 'B*(powmod) vs B*(walk) : 279136 comparaisons, 0 desaccords' "$LOG/scan_validate.log"
gpu 120 "$BUILD/scan_gpu" --montcheck 20000 3459826103 3476732783 4294967197 4294967231 4294967279 4294967291 >"$LOG/scan_montcheck.log" 2>&1
test "$(grep -c 'MONTCHECK .* verdict=PASS' "$LOG/scan_montcheck.log")" -eq 6
gpu 120 "$BUILD/scan_gpu" --montcheck 20000 9 15 2147483649 4294967295 >"$LOG/scan_montcheck_composite.log" 2>&1
test "$(grep -c 'prime=0.*verdict=PASS' "$LOG/scan_montcheck_composite.log")" -eq 4
gpu 90 "$BUILD/scan_gpu" --scan 1000 5000 >"$LOG/scan_bstar.log" 2>&1
grep -q 'TARGET r=2 k=25 A_count=501 .* AB_count=499 .* Bstar_reject=2' "$LOG/scan_bstar.log"
grep -q 'CANDIDATS_A r=2 k=25 :.*2689.*3529' "$LOG/scan_bstar.log"
if grep 'CANDIDATS_AB r=2 k=25 :' "$LOG/scan_bstar.log" | grep -Eq '(^| )(2689|3529)( |$)'; then
  echo 'FAIL: faux candidats A-only présents dans CANDIDATS_AB' >&2
  exit 1
fi
gpu 90 "$BUILD/scan_gpu" --b7db 1009 1100 2 >"$LOG/scan_b7db.log" 2>&1
grep -q 'B7 multi-r DOUBLE-BUFFERED' "$LOG/scan_b7db.log"
if grep -q 'DeviceReduce' "$ROOT/src/scan_gpu.cu"; then
  echo 'FAIL: DeviceReduce réintroduit dans le scanner' >&2
  exit 1
fi
/usr/local/cuda/bin/cuobjdump --dump-sass "$BUILD/scan_gpu" >"$LOG/scan.sass"
if grep -q 'DeviceReduce.*Summ' "$LOG/scan.sass"; then
  echo 'FAIL: chemin Summ non commutatif DeviceReduce encore présent' >&2
  exit 1
fi
printf 'SCAN_SM120_REGRESSION_OK\n'
