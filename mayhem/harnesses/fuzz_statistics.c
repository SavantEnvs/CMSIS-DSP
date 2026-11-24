/* Statistics functions (Source/StatisticsFunctions): min/max/absmin/absmax (with and
 * without index), mean, power, rms, std, var, mse, entropy, Kullback-Leibler, logsumexp,
 * accumulate, for every numeric type. The length comes from the input; each function gets
 * exact-size heap buffers (logsumexp_dot_prod: tmp[blockSize]). Lengths start at 1: the
 * mean/var/std/rms kernels divide by blockSize (and var/std by blockSize-1 after their
 * documented blockSize <= 1 early return). */
#include "fuzz_common.h"

typedef void (*idx_f32)(const float32_t *, uint32_t, float32_t *, uint32_t *);
typedef void (*val_f32)(const float32_t *, uint32_t, float32_t *);
typedef void (*idx_f64)(const float64_t *, uint32_t, float64_t *, uint32_t *);
typedef void (*val_f64)(const float64_t *, uint32_t, float64_t *);
typedef void (*idx_q31)(const q31_t *, uint32_t, q31_t *, uint32_t *);
typedef void (*val_q31)(const q31_t *, uint32_t, q31_t *);
typedef void (*idx_q15)(const q15_t *, uint32_t, q15_t *, uint32_t *);
typedef void (*val_q15)(const q15_t *, uint32_t, q15_t *);
typedef void (*idx_q7)(const q7_t *, uint32_t, q7_t *, uint32_t *);
typedef void (*val_q7)(const q7_t *, uint32_t, q7_t *);

static const idx_f32 kIdxF32[] = {arm_min_f32, arm_max_f32, arm_absmin_f32, arm_absmax_f32};
static const val_f32 kValF32[] = {arm_min_no_idx_f32, arm_max_no_idx_f32, arm_absmin_no_idx_f32, arm_absmax_no_idx_f32,
                                  arm_mean_f32, arm_power_f32, arm_rms_f32, arm_std_f32, arm_var_f32, arm_accumulate_f32};
static const idx_f64 kIdxF64[] = {arm_min_f64, arm_max_f64, arm_absmin_f64, arm_absmax_f64};
static const val_f64 kValF64[] = {arm_min_no_idx_f64, arm_max_no_idx_f64, arm_absmin_no_idx_f64, arm_absmax_no_idx_f64,
                                  arm_mean_f64, arm_power_f64, arm_std_f64, arm_var_f64, arm_accumulate_f64};
static const idx_q31 kIdxQ31[] = {arm_min_q31, arm_max_q31, arm_absmin_q31, arm_absmax_q31};
static const val_q31 kValQ31[] = {arm_min_no_idx_q31, arm_max_no_idx_q31, arm_absmin_no_idx_q31, arm_absmax_no_idx_q31,
                                  arm_mean_q31, arm_rms_q31, arm_std_q31, arm_var_q31};
static const idx_q15 kIdxQ15[] = {arm_min_q15, arm_max_q15, arm_absmin_q15, arm_absmax_q15};
static const val_q15 kValQ15[] = {arm_min_no_idx_q15, arm_max_no_idx_q15, arm_absmin_no_idx_q15, arm_absmax_no_idx_q15,
                                  arm_mean_q15, arm_rms_q15, arm_std_q15, arm_var_q15};
static const idx_q7 kIdxQ7[] = {arm_min_q7, arm_max_q7, arm_absmin_q7, arm_absmax_q7};
static const val_q7 kValQ7[] = {arm_min_no_idx_q7, arm_max_no_idx_q7, arm_absmin_no_idx_q7, arm_absmax_no_idx_q7, arm_mean_q7};

#define N(a) (sizeof(a) / sizeof((a)[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 4) return 0;
  uint8_t type = fr_u8(&r) % 6, op = fr_u8(&r);
  uint32_t n = fr_range(&r, 1, 1024), idx;
  switch (type) {
  case 0: { float32_t *a = fr_f32(&r, n), *b = fr_f32(&r, n), res;
    uint32_t k = op % (N(kIdxF32) + N(kValF32) + 5);
    if (k < N(kIdxF32)) kIdxF32[k](a, n, &res, &idx);
    else if ((k -= N(kIdxF32)) < N(kValF32)) kValF32[k](a, n, &res);
    else switch (k - N(kValF32)) {
      case 0: arm_mse_f32(a, b, n, &res); break;
      case 1: (void)arm_logsumexp_f32(a, n); break;
      case 2: { float32_t *t = ALLOC(float32_t, n); (void)arm_logsumexp_dot_prod_f32(a, b, n, t); free(t); break; }
      case 3: /* probability distributions: positive entries */
        for (uint32_t i = 0; i < n; i++) { a[i] = (a[i] < 0 ? -a[i] : a[i]) + 1e-3f; b[i] = (b[i] < 0 ? -b[i] : b[i]) + 1e-3f; }
        (void)arm_kullback_leibler_f32(a, b, n); break;
      default:
        for (uint32_t i = 0; i < n; i++) a[i] = (a[i] < 0 ? -a[i] : a[i]) + 1e-3f;
        (void)arm_entropy_f32(a, n); break;
    }
    free(a); free(b); break; }
  case 1: { float64_t *a = fr_f64(&r, n), *b = fr_f64(&r, n), res;
    uint32_t k = op % (N(kIdxF64) + N(kValF64) + 3);
    if (k < N(kIdxF64)) kIdxF64[k](a, n, &res, &idx);
    else if ((k -= N(kIdxF64)) < N(kValF64)) kValF64[k](a, n, &res);
    else switch (k - N(kValF64)) {
      case 0: arm_mse_f64(a, b, n, &res); break;
      case 1:
        for (uint32_t i = 0; i < n; i++) { a[i] = (a[i] < 0 ? -a[i] : a[i]) + 1e-3; b[i] = (b[i] < 0 ? -b[i] : b[i]) + 1e-3; }
        (void)arm_kullback_leibler_f64(a, b, n); break;
      default:
        for (uint32_t i = 0; i < n; i++) a[i] = (a[i] < 0 ? -a[i] : a[i]) + 1e-3;
        (void)arm_entropy_f64(a, n); break;
    }
    free(a); free(b); break; }
  case 2: { q31_t *a = fr_q31(&r, n), *b = fr_q31(&r, n), res; q63_t p;
    uint32_t k = op % (N(kIdxQ31) + N(kValQ31) + 2);
    if (k < N(kIdxQ31)) kIdxQ31[k](a, n, &res, &idx);
    else if ((k -= N(kIdxQ31)) < N(kValQ31)) kValQ31[k](a, n, &res);
    else if (k == N(kValQ31)) arm_mse_q31(a, b, n, &res);
    else arm_power_q31(a, n, &p);
    free(a); free(b); break; }
  case 3: { q15_t *a = fr_q15(&r, n), *b = fr_q15(&r, n), res; q63_t p;
    uint32_t k = op % (N(kIdxQ15) + N(kValQ15) + 2);
    if (k < N(kIdxQ15)) kIdxQ15[k](a, n, &res, &idx);
    else if ((k -= N(kIdxQ15)) < N(kValQ15)) kValQ15[k](a, n, &res);
    else if (k == N(kValQ15)) arm_mse_q15(a, b, n, &res);
    else arm_power_q15(a, n, &p);
    free(a); free(b); break; }
  default: { q7_t *a = fr_q7(&r, n), *b = fr_q7(&r, n), res; q31_t p;
    uint32_t k = op % (N(kIdxQ7) + N(kValQ7) + 2);
    if (k < N(kIdxQ7)) kIdxQ7[k](a, n, &res, &idx);
    else if ((k -= N(kIdxQ7)) < N(kValQ7)) kValQ7[k](a, n, &res);
    else if (k == N(kValQ7)) arm_mse_q7(a, b, n, &res);
    else arm_power_q7(a, n, &p);
    free(a); free(b); break; }
  }
  return 0;
}
