#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's own Examples/ARM programs, built by build.sh with normal flags. Each computes a
# result with the library and checks it against a reference computed in MATLAB, printing
# SUCCESS (or FAILURE) under -DSEMIHOSTING. Three examples print values instead of a verdict;
# those are compared against their known-correct output.
BIN="$SRC/build-test/examples"
[ -d "$BIN" ] || { echo "test.sh: $BIN missing - run mayhem/build.sh first" >&2; emit_ctrf "cmsis-dsp-examples" 0 1; exit 1; }

# name|expected line (grep -F, whole line); "SUCCESS" for the self-checking examples
CASES='arm_convolution_example|SUCCESS
arm_dotproduct_example|SUCCESS
arm_fft_bin_example|SUCCESS
arm_fir_example|SUCCESS
arm_graphic_equalizer_example|SUCCESS
arm_linear_interp_example|SUCCESS
arm_matrix_example|SUCCESS
arm_signal_converge_example|SUCCESS
arm_sin_cos_example|SUCCESS
arm_variance_example|SUCCESS
arm_bayes_example|Class = 2
arm_class_marks_example|mean = 212.300003, std = 50.912827
arm_svm_example|Result = 0
arm_svm_example|Result = 1'

passed=0; failed=0
while IFS='|' read -r name expect; do
  if [ ! -x "$BIN/$name" ]; then echo "FAIL $name: binary missing"; failed=$((failed+1)); continue; fi
  out=$(timeout 60 "$BIN/$name" 2>&1); rc=$?
  if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -qxF -- "$expect" && ! printf '%s\n' "$out" | grep -q FAILURE; then
    echo "PASS $name: $expect"; passed=$((passed+1))
  else
    echo "FAIL $name (rc=$rc): expected line '$expect', got:"; printf '%s\n' "$out" | tail -5; failed=$((failed+1))
  fi
done <<< "$CASES"

emit_ctrf "cmsis-dsp-examples" "$passed" "$failed" 0
