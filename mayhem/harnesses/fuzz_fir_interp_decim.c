/* FIR interpolators and decimators (arm_fir_interpolate_*, arm_fir_decimate_*).
 * Sizes from the doc comments in Source/FilteringFunctions:
 *   interpolate: numTaps multiple of L; state (numTaps/L)+blockSize-1; out blockSize*L
 *   decimate:    blockSize multiple of M; state numTaps+blockSize-1; out blockSize/M
 * Init rejects inconsistent parameters with ARM_MATH_LENGTH_ERROR; we then stop. */
#include "fuzz_common.h"

static void interp(FR *r) {
  uint8_t type = fr_u8(r) % 3;
  uint8_t L = (uint8_t)fr_range(r, 1, 16);
  uint16_t numTaps = (uint16_t)fr_range(r, 1, 128);
  uint32_t blockSize = fr_range(r, 1, 64);
  uint32_t nblocks = fr_range(r, 1, 3);
  uint32_t stLen = numTaps / L + blockSize - 1;
  if (type == 0) {
    arm_fir_interpolate_instance_f32 S;
    float32_t *c = fr_f32(r, numTaps), *st = ALLOC(float32_t, stLen);
    if (arm_fir_interpolate_init_f32(&S, L, numTaps, c, st, blockSize) == ARM_MATH_SUCCESS)
      for (uint32_t b = 0; b < nblocks; b++) {
        float32_t *in = fr_f32(r, blockSize), *out = ALLOC(float32_t, blockSize * L);
        arm_fir_interpolate_f32(&S, in, out, blockSize);
        free(in); free(out);
      }
    free(c); free(st);
  } else if (type == 1) {
    arm_fir_interpolate_instance_q15 S;
    q15_t *c = fr_q15(r, numTaps), *st = ALLOC(q15_t, stLen);
    if (arm_fir_interpolate_init_q15(&S, L, numTaps, c, st, blockSize) == ARM_MATH_SUCCESS)
      for (uint32_t b = 0; b < nblocks; b++) {
        q15_t *in = fr_q15(r, blockSize), *out = ALLOC(q15_t, blockSize * L);
        arm_fir_interpolate_q15(&S, in, out, blockSize);
        free(in); free(out);
      }
    free(c); free(st);
  } else {
    arm_fir_interpolate_instance_q31 S;
    q31_t *c = fr_q31(r, numTaps), *st = ALLOC(q31_t, stLen);
    if (arm_fir_interpolate_init_q31(&S, L, numTaps, c, st, blockSize) == ARM_MATH_SUCCESS)
      for (uint32_t b = 0; b < nblocks; b++) {
        q31_t *in = fr_q31(r, blockSize), *out = ALLOC(q31_t, blockSize * L);
        arm_fir_interpolate_q31(&S, in, out, blockSize);
        free(in); free(out);
      }
    free(c); free(st);
  }
}

static void decim(FR *r) {
  uint8_t type = fr_u8(r) % 6;
  uint8_t M = (uint8_t)fr_range(r, 1, 16);
  uint16_t numTaps = (uint16_t)fr_range(r, 1, 128);
  uint32_t blockSize = fr_range(r, 1, 128);
  uint32_t nblocks = fr_range(r, 1, 3);
  uint32_t stLen = numTaps + blockSize - 1;
  uint32_t outLen = blockSize / M;
  if (type == 0) {
    arm_fir_decimate_instance_f32 S;
    float32_t *c = fr_f32(r, numTaps), *st = ALLOC(float32_t, stLen);
    if (arm_fir_decimate_init_f32(&S, numTaps, M, c, st, blockSize) == ARM_MATH_SUCCESS)
      for (uint32_t b = 0; b < nblocks; b++) {
        float32_t *in = fr_f32(r, blockSize), *out = ALLOC(float32_t, outLen);
        arm_fir_decimate_f32(&S, in, out, blockSize);
        free(in); free(out);
      }
    free(c); free(st);
  } else if (type == 1) {
    arm_fir_decimate_instance_f64 S;
    float64_t *c = fr_f64(r, numTaps), *st = ALLOC(float64_t, stLen);
    if (arm_fir_decimate_init_f64(&S, numTaps, M, c, st, blockSize) == ARM_MATH_SUCCESS)
      for (uint32_t b = 0; b < nblocks; b++) {
        float64_t *in = fr_f64(r, blockSize), *out = ALLOC(float64_t, outLen);
        arm_fir_decimate_f64(&S, in, out, blockSize);
        free(in); free(out);
      }
    free(c); free(st);
  } else if (type <= 3) {
    arm_fir_decimate_instance_q15 S;
    q15_t *c = fr_q15(r, numTaps), *st = ALLOC(q15_t, stLen);
    if (arm_fir_decimate_init_q15(&S, numTaps, M, c, st, blockSize) == ARM_MATH_SUCCESS)
      for (uint32_t b = 0; b < nblocks; b++) {
        q15_t *in = fr_q15(r, blockSize), *out = ALLOC(q15_t, outLen);
        if (type == 2) arm_fir_decimate_q15(&S, in, out, blockSize);
        else arm_fir_decimate_fast_q15(&S, in, out, blockSize);
        free(in); free(out);
      }
    free(c); free(st);
  } else {
    arm_fir_decimate_instance_q31 S;
    q31_t *c = fr_q31(r, numTaps), *st = ALLOC(q31_t, stLen);
    if (arm_fir_decimate_init_q31(&S, numTaps, M, c, st, blockSize) == ARM_MATH_SUCCESS)
      for (uint32_t b = 0; b < nblocks; b++) {
        q31_t *in = fr_q31(r, blockSize), *out = ALLOC(q31_t, outLen);
        if (type == 4) arm_fir_decimate_q31(&S, in, out, blockSize);
        else arm_fir_decimate_fast_q31(&S, in, out, blockSize);
        free(in); free(out);
      }
    free(c); free(st);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 4) return 0;
  if (fr_u8(&r) & 1) interp(&r); else decim(&r);
  return 0;
}
