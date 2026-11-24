/* FIR, sparse FIR, FIR lattice and IIR lattice filters.
 * Sizes from the doc comments in Source/FilteringFunctions:
 *   fir f32/f64/q31/q7: state numTaps+blockSize-1
 *   fir q15: numTaps even and >= 4 (init returns ARM_MATH_ARGUMENT_ERROR), state numTaps+blockSize
 *            (LOOPUNROLL build)
 *   sparse: state maxDelay+blockSize, scratchIn blockSize, scratchOut (q15/q7) blockSize,
 *           pTapDelay[numTaps] with every delay <= maxDelay; numTaps >= 2 (see sparse())
 *   fir lattice: coeffs numStages, state numStages
 *   iir lattice: k numStages, v numStages+1, state numStages+blockSize */
#include "fuzz_common.h"

static void fir(FR *r, uint8_t type) {
  uint16_t numTaps = (uint16_t)fr_range(r, 1, 160);
  uint32_t blockSize = fr_range(r, 1, 128);
  uint32_t nb = fr_range(r, 1, 3);
  uint32_t st = numTaps + blockSize - 1;
  switch (type % 7) {
  case 0: { arm_fir_instance_f32 S; float32_t *c = fr_f32(r, numTaps), *s = ALLOC(float32_t, st);
    arm_fir_init_f32(&S, numTaps, c, s, blockSize);
    for (uint32_t b = 0; b < nb; b++) { float32_t *i = fr_f32(r, blockSize), *o = ALLOC(float32_t, blockSize);
      arm_fir_f32(&S, i, o, blockSize); free(i); free(o); }
    free(c); free(s); break; }
  case 1: { arm_fir_instance_f64 S; float64_t *c = fr_f64(r, numTaps), *s = ALLOC(float64_t, st);
    arm_fir_init_f64(&S, numTaps, c, s, blockSize);
    for (uint32_t b = 0; b < nb; b++) { float64_t *i = fr_f64(r, blockSize), *o = ALLOC(float64_t, blockSize);
      arm_fir_f64(&S, i, o, blockSize); free(i); free(o); }
    free(c); free(s); break; }
  case 2: case 3: { arm_fir_instance_q15 S; q15_t *c = fr_q15(r, numTaps), *s = ALLOC(q15_t, numTaps + blockSize);
    if (arm_fir_init_q15(&S, numTaps, c, s, blockSize) == ARM_MATH_SUCCESS)
      for (uint32_t b = 0; b < nb; b++) { q15_t *i = fr_q15(r, blockSize), *o = ALLOC(q15_t, blockSize);
        if (type % 7 == 2) arm_fir_q15(&S, i, o, blockSize); else arm_fir_fast_q15(&S, i, o, blockSize);
        free(i); free(o); }
    free(c); free(s); break; }
  case 4: case 5: { arm_fir_instance_q31 S; q31_t *c = fr_q31(r, numTaps), *s = ALLOC(q31_t, st);
    arm_fir_init_q31(&S, numTaps, c, s, blockSize);
    for (uint32_t b = 0; b < nb; b++) { q31_t *i = fr_q31(r, blockSize), *o = ALLOC(q31_t, blockSize);
      if (type % 7 == 4) arm_fir_q31(&S, i, o, blockSize); else arm_fir_fast_q31(&S, i, o, blockSize);
      free(i); free(o); }
    free(c); free(s); break; }
  default: { arm_fir_instance_q7 S; q7_t *c = fr_q7(r, numTaps), *s = ALLOC(q7_t, st);
    arm_fir_init_q7(&S, numTaps, c, s, blockSize);
    for (uint32_t b = 0; b < nb; b++) { q7_t *i = fr_q7(r, blockSize), *o = ALLOC(q7_t, blockSize);
      arm_fir_q7(&S, i, o, blockSize); free(i); free(o); }
    free(c); free(s); break; }
  }
}

static void sparse(FR *r, uint8_t type) {
  /* numTaps >= 2: every arm_fir_sparse_* kernel computes the first and last taps outside
   * its loop and sets tapCnt = numTaps - 2U, so numTaps == 1 wraps tapCnt to 0xFFFFFFFF and
   * the loop reads pCoeffs[1..]/pTapDelay[1..] past their numTaps-sized arrays (an upstream
   * bug, the 4 arm_fir_sparse_* defects of runs #1 and #2; the doc gives no minimum). Left
   * reachable, nearly every sparse input hit it within a few executions, so Mayhem's
   * 5-iteration sanity check failed and nothing else in this target got fuzzed. */
  uint16_t numTaps = (uint16_t)fr_range(r, 2, 64);
  uint16_t maxDelay = (uint16_t)fr_range(r, 0, 256);
  uint32_t blockSize = fr_range(r, 1, 128);
  uint32_t nb = fr_range(r, 1, 3);
  int32_t *delay = ALLOC(int32_t, numTaps);
  for (uint32_t i = 0; i < numTaps; i++) delay[i] = (int32_t)fr_range(r, 0, maxDelay);
  uint32_t st = maxDelay + blockSize;
  switch (type % 4) {
  case 0: { arm_fir_sparse_instance_f32 S; float32_t *c = fr_f32(r, numTaps), *s = ALLOC(float32_t, st);
    arm_fir_sparse_init_f32(&S, numTaps, c, s, delay, maxDelay, blockSize);
    for (uint32_t b = 0; b < nb; b++) { float32_t *i = fr_f32(r, blockSize), *o = ALLOC(float32_t, blockSize), *x = ALLOC(float32_t, blockSize);
      arm_fir_sparse_f32(&S, i, o, x, blockSize); free(i); free(o); free(x); }
    free(c); free(s); break; }
  case 1: { arm_fir_sparse_instance_q31 S; q31_t *c = fr_q31(r, numTaps), *s = ALLOC(q31_t, st);
    arm_fir_sparse_init_q31(&S, numTaps, c, s, delay, maxDelay, blockSize);
    for (uint32_t b = 0; b < nb; b++) { q31_t *i = fr_q31(r, blockSize), *o = ALLOC(q31_t, blockSize), *x = ALLOC(q31_t, blockSize);
      arm_fir_sparse_q31(&S, i, o, x, blockSize); free(i); free(o); free(x); }
    free(c); free(s); break; }
  case 2: { arm_fir_sparse_instance_q15 S; q15_t *c = fr_q15(r, numTaps), *s = ALLOC(q15_t, st);
    arm_fir_sparse_init_q15(&S, numTaps, c, s, delay, maxDelay, blockSize);
    for (uint32_t b = 0; b < nb; b++) { q15_t *i = fr_q15(r, blockSize), *o = ALLOC(q15_t, blockSize), *x = ALLOC(q15_t, blockSize);
      q31_t *y = ALLOC(q31_t, blockSize);
      arm_fir_sparse_q15(&S, i, o, x, y, blockSize); free(i); free(o); free(x); free(y); }
    free(c); free(s); break; }
  default: { arm_fir_sparse_instance_q7 S; q7_t *c = fr_q7(r, numTaps), *s = ALLOC(q7_t, st);
    arm_fir_sparse_init_q7(&S, numTaps, c, s, delay, maxDelay, blockSize);
    for (uint32_t b = 0; b < nb; b++) { q7_t *i = fr_q7(r, blockSize), *o = ALLOC(q7_t, blockSize), *x = ALLOC(q7_t, blockSize);
      q31_t *y = ALLOC(q31_t, blockSize);
      arm_fir_sparse_q7(&S, i, o, x, y, blockSize); free(i); free(o); free(x); free(y); }
    free(c); free(s); break; }
  }
  free(delay);
}

static void lattice(FR *r, uint8_t type) {
  uint16_t ns = (uint16_t)fr_range(r, 1, 32);
  uint32_t bs = fr_range(r, 1, 128);
  switch (type % 6) {
  case 0: { arm_fir_lattice_instance_f32 S; float32_t *c = fr_f32(r, ns), *s = ALLOC(float32_t, ns);
    float32_t *i = fr_f32(r, bs), *o = ALLOC(float32_t, bs);
    arm_fir_lattice_init_f32(&S, ns, c, s); arm_fir_lattice_f32(&S, i, o, bs);
    free(c); free(s); free(i); free(o); break; }
  case 1: { arm_fir_lattice_instance_q31 S; q31_t *c = fr_q31(r, ns), *s = ALLOC(q31_t, ns);
    q31_t *i = fr_q31(r, bs), *o = ALLOC(q31_t, bs);
    arm_fir_lattice_init_q31(&S, ns, c, s); arm_fir_lattice_q31(&S, i, o, bs);
    free(c); free(s); free(i); free(o); break; }
  case 2: { arm_fir_lattice_instance_q15 S; q15_t *c = fr_q15(r, ns), *s = ALLOC(q15_t, ns);
    q15_t *i = fr_q15(r, bs), *o = ALLOC(q15_t, bs);
    arm_fir_lattice_init_q15(&S, ns, c, s); arm_fir_lattice_q15(&S, i, o, bs);
    free(c); free(s); free(i); free(o); break; }
  case 3: { arm_iir_lattice_instance_f32 S; float32_t *k = fr_f32(r, ns), *v = fr_f32(r, ns + 1), *s = ALLOC(float32_t, ns + bs);
    float32_t *i = fr_f32(r, bs), *o = ALLOC(float32_t, bs);
    arm_iir_lattice_init_f32(&S, ns, k, v, s, bs); arm_iir_lattice_f32(&S, i, o, bs);
    free(k); free(v); free(s); free(i); free(o); break; }
  case 4: { arm_iir_lattice_instance_q31 S; q31_t *k = fr_q31(r, ns), *v = fr_q31(r, ns + 1), *s = ALLOC(q31_t, ns + bs);
    q31_t *i = fr_q31(r, bs), *o = ALLOC(q31_t, bs);
    arm_iir_lattice_init_q31(&S, ns, k, v, s, bs); arm_iir_lattice_q31(&S, i, o, bs);
    free(k); free(v); free(s); free(i); free(o); break; }
  default: { arm_iir_lattice_instance_q15 S; q15_t *k = fr_q15(r, ns), *v = fr_q15(r, ns + 1), *s = ALLOC(q15_t, ns + bs);
    q15_t *i = fr_q15(r, bs), *o = ALLOC(q15_t, bs);
    arm_iir_lattice_init_q15(&S, ns, k, v, s, bs); arm_iir_lattice_q15(&S, i, o, bs);
    free(k); free(v); free(s); free(i); free(o); break; }
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 4) return 0;
  uint8_t sel = fr_u8(&r), type = fr_u8(&r);
  switch (sel % 3) {
  case 0: fir(&r, type); break;
  case 1: sparse(&r, type); break;
  default: lattice(&r, type); break;
  }
  return 0;
}
