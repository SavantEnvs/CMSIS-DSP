#!/usr/bin/env bash
# mayhem/build.sh — build CMSIS-DSP's libFuzzer harnesses and its example-based test suite.
#
# CMSIS-DSP has no host build of its own besides CMake (which pulls in CMSIS-Core config);
# each family directory ships an aggregate Source/<Family>/<Family>.c that #includes every
# arm_*.c of the family, which is exactly what upstream's own CMake "unity" option compiles.
# We compile those aggregates (minus the *F16 ones, which need _Float16 and duplicate the f32
# algorithms) for the host: __GNUC_PYTHON__ is upstream's host switch (removes the CMSIS-Core
# cmsis_compiler.h dependency), ARM_MATH_LOOPUNROLL and ARM_MATH_MATRIX_CHECK match the CMake
# defaults/options. Outputs: build-fuzz/ and build-test/ (gitignored by upstream's `build-*`).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
cd "$SRC"

DEFS="-D__GNUC_PYTHON__ -DDISABLEFLOAT16 -DARM_MATH_LOOPUNROLL -DARM_MATH_MATRIX_CHECK"
INCS="-I$SRC/Include -I$SRC/PrivateInclude"
FAMILIES="BasicMathFunctions BayesFunctions CommonTables ComplexMathFunctions ControllerFunctions
DistanceFunctions FastMathFunctions FilteringFunctions InterpolationFunctions MatrixFunctions
QuaternionMathFunctions SVMFunctions StatisticsFunctions SupportFunctions TransformFunctions
WindowFunctions"

# build_lib <outdir> <cflags...>: compile every family aggregate into <outdir>/libcmsisdsp.a
build_lib() {
  local out="$1"; shift
  mkdir -p "$out"
  rm -f "$out"/*.o "$out/libcmsisdsp.a"
  local pids=() f
  for f in $FAMILIES; do
    $CC -c "$@" $DEFS $INCS "Source/$f/$f.c" -o "$out/$f.o" &
    pids+=($!)
    if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
  done
  for p in "${pids[@]}"; do wait "$p"; done
  ar rcs "$out/libcmsisdsp.a" "$out"/*.o
}

# 1) The library itself, instrumented (ASan+UBSan halting, SanCov for the fuzzer), DWARF 3.
# UBSan shift-base and signed-integer-overflow are relaxed for the LIBRARY only. The fixed-point
# kernels document that their accumulators wrap on overflow (inputs are expected to be pre-scaled,
# e.g. arm_fir_decimate_q31: "scale down the input by log2(numTaps)"), and CMSIS-DSP left-shifts
# negative fixed-point
# values everywhere by design (q7->q15 conversion, Q-format rescaling, the none.h intrinsic
# emulations), which is well defined on every Arm/clang target it ships for; left on, it halts on
# the first sample of nearly every q7/q15/q31 kernel. Every other ASan/UBSan check stays on and halting
# (including shift-exponent, i.e. shifting by >= the type width).
# The harnesses get the same relaxation because the header-inline kernels (arm_pid_q15, the
# none.h intrinsics) are compiled in the harness translation unit.
UBSAN_RELAX="${SANITIZER_FLAGS:+-fno-sanitize=shift-base,signed-integer-overflow}"
build_lib build-fuzz -O1 $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link
$CC -c $SANITIZER_FLAGS $DEBUG_FLAGS mayhem/lsan_off.c -o build-fuzz/lsan_off.o
$CC -c $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" -o build-fuzz/standalone_main.o

# 2) Every harness twice: libFuzzer binary and run-once standalone reproducer.
for h in mayhem/harnesses/fuzz_*.c; do
  n=$(basename "$h" .c)
  $CC -O1 $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS $LIB_FUZZING_ENGINE $DEFS $INCS -Imayhem/harnesses \
      "$h" build-fuzz/lsan_off.o build-fuzz/libcmsisdsp.a -lm -o "$SRC/$n"
  $CC -O1 $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS $DEFS $INCS -Imayhem/harnesses \
      "$h" build-fuzz/standalone_main.o build-fuzz/lsan_off.o build-fuzz/libcmsisdsp.a -lm -o "$SRC/$n-standalone"
done

# 3) Test suite: upstream's own Examples/ARM programs (each compares its output against a
#    MATLAB-computed reference and prints SUCCESS/FAILURE under -DSEMIHOSTING), built with
#    normal flags against an uninstrumented library.
build_lib build-test -O2 $COVERAGE_FLAGS
mkdir -p build-test/examples
for d in Examples/ARM/*/; do
  n=$(basename "$d")
  $CC -O2 -DSEMIHOSTING $COVERAGE_FLAGS $DEFS $INCS "$d"*.c build-test/libcmsisdsp.a -lm -o "build-test/examples/$n"
done
echo "build.sh: done"
