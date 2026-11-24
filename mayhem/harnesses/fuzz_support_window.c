/* Support functions (type conversions with saturation, copy/fill, barycenter, weighted
 * average) and window generators (Source/SupportFunctions, Source/WindowFunctions).
 * Exact-size heap buffers: conversions blockSize in/out; barycenter in[nbVectors*vecDim],
 * weights[nbVectors], out[vecDim]; weighted_average in/weights[blockSize]; windows write
 * blockSize samples. */
#include "fuzz_common.h"

typedef void (*win32)(float32_t *, uint32_t);
typedef void (*win64)(float64_t *, uint32_t);
static const win32 kW32[] = {arm_welch_f32, arm_bartlett_f32, arm_hamming_f32, arm_hanning_f32, arm_nuttall3_f32,
                             arm_nuttall4_f32, arm_nuttall3a_f32, arm_nuttall3b_f32, arm_nuttall4a_f32,
                             arm_blackman_harris_92db_f32, arm_nuttall4b_f32, arm_nuttall4c_f32, arm_hft90d_f32,
                             arm_hft95_f32, arm_hft116d_f32, arm_hft144d_f32, arm_hft169d_f32, arm_hft196d_f32,
                             arm_hft223d_f32, arm_hft248d_f32};
static const win64 kW64[] = {arm_welch_f64, arm_bartlett_f64, arm_hamming_f64, arm_hanning_f64, arm_nuttall3_f64,
                             arm_nuttall4_f64, arm_nuttall3a_f64, arm_nuttall3b_f64, arm_nuttall4a_f64,
                             arm_blackman_harris_92db_f64, arm_nuttall4b_f64, arm_nuttall4c_f64, arm_hft90d_f64,
                             arm_hft95_f64, arm_hft116d_f64, arm_hft144d_f64, arm_hft169d_f64, arm_hft196d_f64,
                             arm_hft223d_f64, arm_hft248d_f64};

static void convert(FR *r) {
  uint8_t src = fr_u8(r) % 5, dst = fr_u8(r) % 5;
  uint32_t n = fr_range(r, 1, 1024);
  float32_t *f = NULL; float64_t *d = NULL; q31_t *q31 = NULL; q15_t *q15 = NULL; q7_t *q7 = NULL;
  float32_t *of = ALLOC(float32_t, n); float64_t *od = ALLOC(float64_t, n);
  q31_t *o31 = ALLOC(q31_t, n); q15_t *o15 = ALLOC(q15_t, n); q7_t *o7 = ALLOC(q7_t, n);
  switch (src) {
  case 0: f = fr_f32(r, n);
    switch (dst) { case 0: arm_copy_f32(f, of, n); break; case 1: arm_float_to_f64(f, od, n); break;
      case 2: arm_float_to_q31(f, o31, n); break; case 3: arm_float_to_q15(f, o15, n); break; default: arm_float_to_q7(f, o7, n); }
    break;
  case 1: d = fr_f64(r, n);
    switch (dst) { case 0: arm_f64_to_float(d, of, n); break; case 1: arm_copy_f64(d, od, n); break;
      case 2: arm_f64_to_q31(d, o31, n); break; case 3: arm_f64_to_q15(d, o15, n); break; default: arm_f64_to_q7(d, o7, n); }
    break;
  case 2: q31 = fr_q31(r, n);
    switch (dst) { case 0: arm_q31_to_float(q31, of, n); break; case 1: arm_q31_to_f64(q31, od, n); break;
      case 2: arm_copy_q31(q31, o31, n); break; case 3: arm_q31_to_q15(q31, o15, n); break; default: arm_q31_to_q7(q31, o7, n); }
    break;
  case 3: q15 = fr_q15(r, n);
    switch (dst) { case 0: arm_q15_to_float(q15, of, n); break; case 1: arm_q15_to_f64(q15, od, n); break;
      case 2: arm_q15_to_q31(q15, o31, n); break; case 3: arm_copy_q15(q15, o15, n); break; default: arm_q15_to_q7(q15, o7, n); }
    break;
  default: q7 = fr_q7(r, n);
    switch (dst) { case 0: arm_q7_to_float(q7, of, n); break; case 1: arm_q7_to_f64(q7, od, n); break;
      case 2: arm_q7_to_q31(q7, o31, n); break; case 3: arm_q7_to_q15(q7, o15, n); break; default: arm_copy_q7(q7, o7, n); }
    break;
  }
  switch (fr_u8(r) % 5) {
  case 0: arm_fill_f32(fr_float(r), of, n); break;
  case 1: arm_fill_f64(fr_float(r), od, n); break;
  case 2: arm_fill_q31((q31_t)fr_u32(r), o31, n); break;
  case 3: arm_fill_q15((q15_t)fr_u16(r), o15, n); break;
  default: arm_fill_q7((q7_t)fr_u8(r), o7, n); break;
  }
  free(f); free(d); free(q31); free(q15); free(q7); free(of); free(od); free(o31); free(o15); free(o7);
}

static void bary(FR *r) {
  uint32_t nv = fr_range(r, 1, 64), dim = fr_range(r, 1, 32);
  float32_t *in = fr_f32(r, nv * dim), *w = fr_f32(r, nv), *out = ALLOC(float32_t, dim);
  arm_barycenter_f32(in, w, out, nv, dim);
  (void)arm_weighted_average_f32(in, w, nv);
  free(in); free(w); free(out);
}

static void window(FR *r) {
  uint8_t k = fr_u8(r);
  uint32_t n = fr_range(r, 1, 2048);
  if (k & 0x80) { float64_t *d = ALLOC(float64_t, n); kW64[k % 20](d, n); free(d); }
  else { float32_t *d = ALLOC(float32_t, n); kW32[k % 20](d, n); free(d); }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 3) return 0;
  switch (fr_u8(&r) % 3) {
  case 0: convert(&r); break;
  case 1: bary(&r); break;
  default: window(&r); break;
  }
  return 0;
}
