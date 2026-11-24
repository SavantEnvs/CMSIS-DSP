/* Sorting (arm_sort_f32 six algorithms, arm_merge_sort_f32) and interpolation
 * (cubic spline, linear, bilinear). Preconditions from the doc comments:
 *   bitonic sort: blockSize a power of 2; merge sort: buffer of blockSize
 *   spline: n >= 2 known points with strictly increasing x, coeffs 3*(n-1), temp 2*n-1
 *   linear_interp_f32: table of nValues, x1/xSpacing from the input
 *   linear_interp_q*: x in 12.20 format, table of nValues
 *   bilinear_interp: table numRows*numCols */
#include "fuzz_common.h"

static void sort(FR *r) {
  uint8_t alg = fr_u8(r) % 7, dir = fr_u8(r) & 1;
  uint32_t n = fr_range(r, 1, 512);
  if (alg == ARM_SORT_BITONIC) n = 1u << fr_range(r, 0, 9);
  float32_t *src = fr_f32(r, n), *dst = ALLOC(float32_t, n);
  if (alg == 6) {
    arm_merge_sort_instance_f32 S; float32_t *buf = ALLOC(float32_t, n);
    arm_merge_sort_init_f32(&S, (arm_sort_dir)dir, buf);
    arm_merge_sort_f32(&S, src, dst, n); free(buf);
  } else {
    arm_sort_instance_f32 S;
    arm_sort_init_f32(&S, (arm_sort_alg)alg, (arm_sort_dir)dir);
    arm_sort_f32(&S, src, dst, n);
  }
  free(src); free(dst);
}

static void spline(FR *r) {
  arm_spline_type type = (arm_spline_type)(fr_u8(r) & 1);
  uint32_t n = fr_range(r, 2, 64), q = fr_range(r, 1, 128);
  float32_t *x = ALLOC(float32_t, n), *y = fr_f32(r, n);
  float32_t acc = fr_float(r);
  for (uint32_t i = 0; i < n; i++) { x[i] = acc; acc += 1.0f / 64.0f + (float32_t)fr_u8(r) / 16.0f; }
  float32_t *coeffs = ALLOC(float32_t, 3 * (n - 1)), *tmp = ALLOC(float32_t, 2 * n - 1);
  float32_t *xq = fr_f32(r, q), *out = ALLOC(float32_t, q);
  arm_spline_instance_f32 S;
  arm_spline_init_f32(&S, type, x, y, n, coeffs, tmp);
  arm_spline_f32(&S, xq, out, q);
  free(x); free(y); free(coeffs); free(tmp); free(xq); free(out);
}

static void linear(FR *r) {
  uint32_t n = fr_range(r, 1, 256);
  uint8_t t = fr_u8(r) % 4;
  uint32_t nq = fr_range(r, 1, 16);
  if (t == 0) {
    float32_t *tab = fr_f32(r, n);
    /* xSpacing is the (positive) distance between table entries: the kernel divides by it */
    float32_t x1 = fr_float(r), sp = fr_float(r);
    sp = (sp < 0 ? -sp : sp) + 1.0f / 256.0f;
    arm_linear_interp_instance_f32 S = {n, x1, sp, tab};
    for (uint32_t i = 0; i < nq; i++) (void)arm_linear_interp_f32(&S, fr_float(r));
    free(tab);
  } else if (t == 1) {
    q31_t *tab = fr_q31(r, n);
    for (uint32_t i = 0; i < nq; i++) (void)arm_linear_interp_q31(tab, (q31_t)fr_u32(r), n);
    free(tab);
  } else if (t == 2) {
    q15_t *tab = fr_q15(r, n);
    for (uint32_t i = 0; i < nq; i++) (void)arm_linear_interp_q15(tab, (q31_t)fr_u32(r), n);
    free(tab);
  } else {
    q7_t *tab = fr_q7(r, n);
    for (uint32_t i = 0; i < nq; i++) (void)arm_linear_interp_q7(tab, (q31_t)fr_u32(r), n);
    free(tab);
  }
}

static void bilinear(FR *r) {
  uint16_t rows = (uint16_t)fr_range(r, 1, 32), cols = (uint16_t)fr_range(r, 1, 32);
  uint8_t t = fr_u8(r) % 4;
  uint32_t nq = fr_range(r, 1, 16), n = (uint32_t)rows * cols;
  if (t == 0) {
    arm_bilinear_interp_instance_f32 S = {rows, cols, fr_f32(r, n)};
    for (uint32_t i = 0; i < nq; i++) (void)arm_bilinear_interp_f32(&S, fr_float(r), fr_float(r));
    free((void *)S.pData);
  } else if (t == 1) {
    arm_bilinear_interp_instance_q31 S = {rows, cols, fr_q31(r, n)};
    for (uint32_t i = 0; i < nq; i++) (void)arm_bilinear_interp_q31(&S, (q31_t)fr_u32(r), (q31_t)fr_u32(r));
    free((void *)S.pData);
  } else if (t == 2) {
    arm_bilinear_interp_instance_q15 S = {rows, cols, fr_q15(r, n)};
    for (uint32_t i = 0; i < nq; i++) (void)arm_bilinear_interp_q15(&S, (q31_t)fr_u32(r), (q31_t)fr_u32(r));
    free((void *)S.pData);
  } else {
    arm_bilinear_interp_instance_q7 S = {rows, cols, fr_q7(r, n)};
    for (uint32_t i = 0; i < nq; i++) (void)arm_bilinear_interp_q7(&S, (q31_t)fr_u32(r), (q31_t)fr_u32(r));
    free((void *)S.pData);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 4) return 0;
  switch (fr_u8(&r) % 4) {
  case 0: sort(&r); break;
  case 1: spline(&r); break;
  case 2: linear(&r); break;
  default: bilinear(&r); break;
  }
  return 0;
}
