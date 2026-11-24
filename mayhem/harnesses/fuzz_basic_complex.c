/* Basic math (Source/BasicMathFunctions) and complex math (Source/ComplexMathFunctions).
 * One op + type per input; blockSize, scale, shift, offset and clip bounds (low <= high,
 * as the clip doc requires) come from the input. Buffers are exact size: real vectors
 * blockSize, complex vectors 2*numSamples. */
#include "fuzz_common.h"

static void basic(FR *r) {
  uint8_t op = fr_u8(r) % 12, type = fr_u8(r) % 5;
  uint32_t n = fr_range(r, 1, 1024);
  int8_t shift = (int8_t)fr_u8(r);
  if (type == 0) {
    float32_t *a = fr_f32(r, n), *b = fr_f32(r, n), *d = ALLOC(float32_t, n), k = fr_float(r), k2 = fr_float(r), res;
    switch (op) {
    case 0: arm_add_f32(a, b, d, n); break;
    case 1: arm_sub_f32(a, b, d, n); break;
    case 2: arm_mult_f32(a, b, d, n); break;
    case 3: arm_scale_f32(a, k, d, n); break;
    case 4: arm_abs_f32(a, d, n); break;
    case 5: arm_negate_f32(a, d, n); break;
    case 6: arm_offset_f32(a, k, d, n); break;
    case 7: arm_dot_prod_f32(a, b, n, &res); break;
    default: arm_clip_f32(a, d, k < k2 ? k : k2, k < k2 ? k2 : k, n); break;
    }
    free(a); free(b); free(d);
  } else if (type == 1) {
    float64_t *a = fr_f64(r, n), *b = fr_f64(r, n), *d = ALLOC(float64_t, n), k = fr_float(r), res;
    switch (op % 8) {
    case 0: arm_add_f64(a, b, d, n); break;
    case 1: arm_sub_f64(a, b, d, n); break;
    case 2: arm_mult_f64(a, b, d, n); break;
    case 3: arm_scale_f64(a, k, d, n); break;
    case 4: arm_abs_f64(a, d, n); break;
    case 5: arm_negate_f64(a, d, n); break;
    case 6: arm_offset_f64(a, k, d, n); break;
    default: arm_dot_prod_f64(a, b, n, &res); break;
    }
    free(a); free(b); free(d);
  } else if (type == 2) {
    q31_t *a = fr_q31(r, n), *b = fr_q31(r, n), *d = ALLOC(q31_t, n), k = (q31_t)fr_u32(r), k2 = (q31_t)fr_u32(r);
    q63_t res;
    switch (op) {
    case 0: arm_add_q31(a, b, d, n); break;
    case 1: arm_sub_q31(a, b, d, n); break;
    case 2: arm_mult_q31(a, b, d, n); break;
    case 3: arm_scale_q31(a, k, shift, d, n); break;
    case 4: arm_abs_q31(a, d, n); break;
    case 5: arm_negate_q31(a, d, n); break;
    case 6: arm_offset_q31(a, k, d, n); break;
    case 7: arm_dot_prod_q31(a, b, n, &res); break;
    case 8: arm_shift_q31(a, shift, d, n); break;
    default: arm_clip_q31(a, d, k < k2 ? k : k2, k < k2 ? k2 : k, n); break;
    }
    free(a); free(b); free(d);
  } else if (type == 3) {
    q15_t *a = fr_q15(r, n), *b = fr_q15(r, n), *d = ALLOC(q15_t, n), k = (q15_t)fr_u16(r), k2 = (q15_t)fr_u16(r);
    q63_t res;
    switch (op) {
    case 0: arm_add_q15(a, b, d, n); break;
    case 1: arm_sub_q15(a, b, d, n); break;
    case 2: arm_mult_q15(a, b, d, n); break;
    case 3: arm_scale_q15(a, k, shift, d, n); break;
    case 4: arm_abs_q15(a, d, n); break;
    case 5: arm_negate_q15(a, d, n); break;
    case 6: arm_offset_q15(a, k, d, n); break;
    case 7: arm_dot_prod_q15(a, b, n, &res); break;
    case 8: arm_shift_q15(a, shift, d, n); break;
    default: arm_clip_q15(a, d, k < k2 ? k : k2, k < k2 ? k2 : k, n); break;
    }
    free(a); free(b); free(d);
  } else {
    q7_t *a = fr_q7(r, n), *b = fr_q7(r, n), *d = ALLOC(q7_t, n), k = (q7_t)fr_u8(r), k2 = (q7_t)fr_u8(r);
    q31_t res;
    switch (op) {
    case 0: arm_add_q7(a, b, d, n); break;
    case 1: arm_sub_q7(a, b, d, n); break;
    case 2: arm_mult_q7(a, b, d, n); break;
    case 3: arm_scale_q7(a, k, shift, d, n); break;
    case 4: arm_abs_q7(a, d, n); break;
    case 5: arm_negate_q7(a, d, n); break;
    case 6: arm_offset_q7(a, k, d, n); break;
    case 7: arm_dot_prod_q7(a, b, n, &res); break;
    case 8: arm_shift_q7(a, shift, d, n); break;
    case 9: { uint8_t *x = (uint8_t *)a, *y = (uint8_t *)b, *z = (uint8_t *)d;
      arm_and_u8(x, y, z, n); arm_or_u8(x, y, z, n); arm_xor_u8(x, y, z, n); arm_not_u8(x, z, n); break; }
    case 10: { uint32_t *x = ALLOC(uint32_t, n), *y = ALLOC(uint32_t, n), *z = ALLOC(uint32_t, n);
      for (uint32_t i = 0; i < n; i++) { x[i] = fr_u32(r); y[i] = fr_u32(r); }
      arm_and_u32(x, y, z, n); arm_or_u32(x, y, z, n); arm_xor_u32(x, y, z, n); arm_not_u32(x, z, n);
      uint16_t *p = ALLOC(uint16_t, n), *q = ALLOC(uint16_t, n), *s = ALLOC(uint16_t, n);
      for (uint32_t i = 0; i < n; i++) { p[i] = (uint16_t)x[i]; q[i] = (uint16_t)y[i]; }
      arm_and_u16(p, q, s, n); arm_or_u16(p, q, s, n); arm_xor_u16(p, q, s, n); arm_not_u16(p, s, n);
      free(x); free(y); free(z); free(p); free(q); free(s); break; }
    default: arm_clip_q7(a, d, k < k2 ? k : k2, k < k2 ? k2 : k, n); break;
    }
    free(a); free(b); free(d);
  }
}

static void cmplx(FR *r) {
  uint8_t op = fr_u8(r) % 6, type = fr_u8(r) % 4;
  uint32_t n = fr_range(r, 1, 512);
  if (type == 0) {
    float32_t *a = fr_f32(r, 2 * n), *b = fr_f32(r, 2 * n), *d = ALLOC(float32_t, 2 * n), re, im;
    switch (op) {
    case 0: arm_cmplx_conj_f32(a, d, n); break;
    case 1: arm_cmplx_mag_f32(a, d, n); break;
    case 2: arm_cmplx_mag_squared_f32(a, d, n); break;
    case 3: arm_cmplx_mult_cmplx_f32(a, b, d, n); break;
    case 4: arm_cmplx_mult_real_f32(a, b, d, n); break; /* b used as n reals */
    default: arm_cmplx_dot_prod_f32(a, b, n, &re, &im); break;
    }
    free(a); free(b); free(d);
  } else if (type == 1) {
    float64_t *a = fr_f64(r, 2 * n), *b = fr_f64(r, 2 * n), *d = ALLOC(float64_t, 2 * n);
    switch (op % 3) {
    case 0: arm_cmplx_mag_f64(a, d, n); break;
    case 1: arm_cmplx_mag_squared_f64(a, d, n); break;
    default: arm_cmplx_mult_cmplx_f64(a, b, d, n); break;
    }
    free(a); free(b); free(d);
  } else if (type == 2) {
    q31_t *a = fr_q31(r, 2 * n), *b = fr_q31(r, 2 * n), *d = ALLOC(q31_t, 2 * n);
    q63_t re, im;
    switch (op) {
    case 0: arm_cmplx_conj_q31(a, d, n); break;
    case 1: arm_cmplx_mag_q31(a, d, n); break;
    case 2: arm_cmplx_mag_squared_q31(a, d, n); break;
    case 3: arm_cmplx_mult_cmplx_q31(a, b, d, n); break;
    case 4: arm_cmplx_mult_real_q31(a, b, d, n); break;
    default: arm_cmplx_dot_prod_q31(a, b, n, &re, &im); break;
    }
    free(a); free(b); free(d);
  } else {
    q15_t *a = fr_q15(r, 2 * n), *b = fr_q15(r, 2 * n), *d = ALLOC(q15_t, 2 * n);
    q31_t re, im;
    switch (op) {
    case 0: arm_cmplx_conj_q15(a, d, n); break;
    case 1: if (n & 1) arm_cmplx_mag_fast_q15(a, d, n); else arm_cmplx_mag_q15(a, d, n); break;
    case 2: arm_cmplx_mag_squared_q15(a, d, n); break;
    case 3: arm_cmplx_mult_cmplx_q15(a, b, d, n); break;
    case 4: arm_cmplx_mult_real_q15(a, b, d, n); break;
    default: arm_cmplx_dot_prod_q15(a, b, n, &re, &im); break;
    }
    free(a); free(b); free(d);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 4) return 0;
  if (fr_u8(&r) & 1) cmplx(&r); else basic(&r);
  return 0;
}
