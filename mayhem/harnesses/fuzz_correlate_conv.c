/* Correlation and convolution (arm_correlate_*, arm_conv_*, arm_conv_partial_*).
 * Sizes from the doc comments in Source/FilteringFunctions:
 *   correlate: pDst 2*max(srcALen,srcBLen)-1
 *   conv:      pDst srcALen+srcBLen-1
 *   *_opt_q15 / *_opt_q7 scratch1: max(A,B)+2*min(A,B)-2, scratch2: min(A,B)
 *   conv_partial writes pDst[firstIndex .. firstIndex+numPoints-1] of the full
 *   A+B-1 output and returns ARM_MATH_ARGUMENT_ERROR when that range is out of bounds. */
#include "fuzz_common.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 6) return 0;
  uint8_t op = fr_u8(&r) % 3;      /* correlate / conv / conv_partial */
  uint8_t type = fr_u8(&r);
  uint32_t A = fr_range(&r, 1, 256), B = fr_range(&r, 1, 256);
  uint32_t mx = MAX(A, B), mn = MIN(A, B);
  uint32_t corrLen = 2 * mx - 1, convLen = A + B - 1;
  uint32_t first = fr_range(&r, 0, convLen + 4), npts = fr_range(&r, 0, convLen + 4);
  uint32_t s1 = mx + 2 * mn - 2, s2 = mn;

  if (op == 0) {
    switch (type % 8) {
    case 0: { float32_t *a = fr_f32(&r, A), *b = fr_f32(&r, B), *d = ALLOC(float32_t, corrLen);
      arm_correlate_f32(a, A, b, B, d); free(a); free(b); free(d); break; }
    case 1: { float64_t *a = fr_f64(&r, A), *b = fr_f64(&r, B), *d = ALLOC(float64_t, corrLen);
      arm_correlate_f64(a, A, b, B, d); free(a); free(b); free(d); break; }
    case 2: case 3: { q15_t *a = fr_q15(&r, A), *b = fr_q15(&r, B), *d = ALLOC(q15_t, corrLen);
      if (type % 8 == 2) arm_correlate_q15(a, A, b, B, d); else arm_correlate_fast_q15(a, A, b, B, d);
      free(a); free(b); free(d); break; }
    case 4: { q15_t *a = fr_q15(&r, A), *b = fr_q15(&r, B), *d = ALLOC(q15_t, corrLen), *sc = ALLOC(q15_t, s1);
      if (type & 0x80) arm_correlate_fast_opt_q15(a, A, b, B, d, sc); else arm_correlate_opt_q15(a, A, b, B, d, sc);
      free(a); free(b); free(d); free(sc); break; }
    case 5: { q31_t *a = fr_q31(&r, A), *b = fr_q31(&r, B), *d = ALLOC(q31_t, corrLen);
      if (type & 0x80) arm_correlate_fast_q31(a, A, b, B, d); else arm_correlate_q31(a, A, b, B, d);
      free(a); free(b); free(d); break; }
    case 6: { q7_t *a = fr_q7(&r, A), *b = fr_q7(&r, B), *d = ALLOC(q7_t, corrLen);
      arm_correlate_q7(a, A, b, B, d); free(a); free(b); free(d); break; }
    default: { q7_t *a = fr_q7(&r, A), *b = fr_q7(&r, B), *d = ALLOC(q7_t, corrLen);
      q15_t *x = ALLOC(q15_t, s1), *y = ALLOC(q15_t, s2);
      arm_correlate_opt_q7(a, A, b, B, d, x, y); free(a); free(b); free(d); free(x); free(y); break; }
    }
  } else if (op == 1) {
    switch (type % 7) {
    case 0: { float32_t *a = fr_f32(&r, A), *b = fr_f32(&r, B), *d = ALLOC(float32_t, convLen);
      arm_conv_f32(a, A, b, B, d); free(a); free(b); free(d); break; }
    case 1: case 2: { q15_t *a = fr_q15(&r, A), *b = fr_q15(&r, B), *d = ALLOC(q15_t, convLen);
      if (type % 7 == 1) arm_conv_q15(a, A, b, B, d); else arm_conv_fast_q15(a, A, b, B, d);
      free(a); free(b); free(d); break; }
    case 3: { q15_t *a = fr_q15(&r, A), *b = fr_q15(&r, B), *d = ALLOC(q15_t, convLen);
      q15_t *x = ALLOC(q15_t, s1), *y = ALLOC(q15_t, s2);
      if (type & 0x80) arm_conv_fast_opt_q15(a, A, b, B, d, x, y); else arm_conv_opt_q15(a, A, b, B, d, x, y);
      free(a); free(b); free(d); free(x); free(y); break; }
    case 4: { q31_t *a = fr_q31(&r, A), *b = fr_q31(&r, B), *d = ALLOC(q31_t, convLen);
      if (type & 0x80) arm_conv_fast_q31(a, A, b, B, d); else arm_conv_q31(a, A, b, B, d);
      free(a); free(b); free(d); break; }
    case 5: { q7_t *a = fr_q7(&r, A), *b = fr_q7(&r, B), *d = ALLOC(q7_t, convLen);
      arm_conv_q7(a, A, b, B, d); free(a); free(b); free(d); break; }
    default: { q7_t *a = fr_q7(&r, A), *b = fr_q7(&r, B), *d = ALLOC(q7_t, convLen);
      q15_t *x = ALLOC(q15_t, s1), *y = ALLOC(q15_t, s2);
      arm_conv_opt_q7(a, A, b, B, d, x, y); free(a); free(b); free(d); free(x); free(y); break; }
    }
  } else {
    switch (type % 6) {
    case 0: { float32_t *a = fr_f32(&r, A), *b = fr_f32(&r, B), *d = ALLOC(float32_t, convLen);
      arm_conv_partial_f32(a, A, b, B, d, first, npts); free(a); free(b); free(d); break; }
    case 1: { q15_t *a = fr_q15(&r, A), *b = fr_q15(&r, B), *d = ALLOC(q15_t, convLen);
      if (type & 0x80) arm_conv_partial_fast_q15(a, A, b, B, d, first, npts); else arm_conv_partial_q15(a, A, b, B, d, first, npts);
      free(a); free(b); free(d); break; }
    case 2: { q15_t *a = fr_q15(&r, A), *b = fr_q15(&r, B), *d = ALLOC(q15_t, convLen);
      q15_t *x = ALLOC(q15_t, s1), *y = ALLOC(q15_t, s2);
      if (type & 0x80) arm_conv_partial_fast_opt_q15(a, A, b, B, d, first, npts, x, y);
      else arm_conv_partial_opt_q15(a, A, b, B, d, first, npts, x, y);
      free(a); free(b); free(d); free(x); free(y); break; }
    case 3: { q31_t *a = fr_q31(&r, A), *b = fr_q31(&r, B), *d = ALLOC(q31_t, convLen);
      if (type & 0x80) arm_conv_partial_fast_q31(a, A, b, B, d, first, npts); else arm_conv_partial_q31(a, A, b, B, d, first, npts);
      free(a); free(b); free(d); break; }
    case 4: { q7_t *a = fr_q7(&r, A), *b = fr_q7(&r, B), *d = ALLOC(q7_t, convLen);
      arm_conv_partial_q7(a, A, b, B, d, first, npts); free(a); free(b); free(d); break; }
    default: { q7_t *a = fr_q7(&r, A), *b = fr_q7(&r, B), *d = ALLOC(q7_t, convLen);
      q15_t *x = ALLOC(q15_t, s1), *y = ALLOC(q15_t, s2);
      arm_conv_partial_opt_q7(a, A, b, B, d, first, npts, x, y);
      free(a); free(b); free(d); free(x); free(y); break; }
    }
  }
  return 0;
}
