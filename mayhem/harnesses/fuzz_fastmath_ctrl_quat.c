/* Fast math (sqrt, divide, atan2, sin/cos, vlog, vexp: table lookups indexed from the input
 * value), controller functions (PID, sin_cos) and quaternion math. Fixed-point scalars are
 * taken raw from the input (INT_MIN, zero divisor, negatives included: the functions
 * document their status for those). Vectors are exact-size heap buffers; quaternion
 * arrays are 4*n floats, rotation matrices 9*n. vlog/vexp float inputs are bounded
 * finite values (fuzz_common.h). */
#include "fuzz_common.h"

static void fast(FR *r) {
  uint8_t op = fr_u8(r) % 16;
  uint32_t n = fr_range(r, 1, 256);
  switch (op) {
  case 0: { q31_t o; (void)arm_sqrt_q31((q31_t)fr_u32(r), &o); break; }
  case 1: { q15_t o; (void)arm_sqrt_q15((q15_t)fr_u16(r), &o); break; }
  case 2: { q31_t q; int16_t s; (void)arm_divide_q31((q31_t)fr_u32(r), (q31_t)fr_u32(r), &q, &s); break; }
  case 3: { q15_t q; int16_t s; (void)arm_divide_q15((q15_t)fr_u16(r), (q15_t)fr_u16(r), &q, &s); break; }
  case 4: { float32_t o; (void)arm_atan2_f32(fr_float(r), fr_float(r), &o); break; }
  case 5: { q31_t o; (void)arm_atan2_q31((q31_t)fr_u32(r), (q31_t)fr_u32(r), &o); break; }
  case 6: { q15_t o; (void)arm_atan2_q15((q15_t)fr_u16(r), (q15_t)fr_u16(r), &o); break; }
  case 7: (void)arm_sin_f32(fr_float(r) * 64.0f); (void)arm_cos_f32(fr_float(r) * 64.0f);
    (void)arm_sin_q31((q31_t)fr_u32(r)); (void)arm_cos_q31((q31_t)fr_u32(r));
    (void)arm_sin_q15((q15_t)fr_u16(r)); (void)arm_cos_q15((q15_t)fr_u16(r)); break;
  case 8: { float32_t *a = fr_f32(r, n), *d = ALLOC(float32_t, n); arm_vlog_f32(a, d, n); arm_vexp_f32(a, d, n); free(a); free(d); break; }
  case 9: { float64_t *a = fr_f64(r, n), *d = ALLOC(float64_t, n); arm_vlog_f64(a, d, n); arm_vexp_f64(a, d, n); free(a); free(d); break; }
  case 10: { q31_t *a = fr_q31(r, n), *d = ALLOC(q31_t, n); arm_vlog_q31(a, d, n); free(a); free(d); break; }
  case 11: { q15_t *a = fr_q15(r, n), *d = ALLOC(q15_t, n); arm_vlog_q15(a, d, n); free(a); free(d); break; }
  case 12: { float32_t s, c; arm_sin_cos_f32(fr_float(r) * 8.0f, &s, &c); q31_t sq, cq; arm_sin_cos_q31((q31_t)fr_u32(r), &sq, &cq); break; }
  case 13: { arm_pid_instance_f32 S; S.Kp = fr_float(r); S.Ki = fr_float(r); S.Kd = fr_float(r);
    arm_pid_init_f32(&S, 1); for (uint32_t i = 0; i < n; i++) (void)arm_pid_f32(&S, fr_float(r)); arm_pid_reset_f32(&S); break; }
  case 14: { arm_pid_instance_q31 S; S.Kp = (q31_t)fr_u32(r); S.Ki = (q31_t)fr_u32(r); S.Kd = (q31_t)fr_u32(r);
    arm_pid_init_q31(&S, 1); for (uint32_t i = 0; i < n; i++) (void)arm_pid_q31(&S, (q31_t)fr_u32(r)); arm_pid_reset_q31(&S); break; }
  default: { arm_pid_instance_q15 S; S.Kp = (q15_t)fr_u16(r); S.Ki = (q15_t)fr_u16(r); S.Kd = (q15_t)fr_u16(r);
    arm_pid_init_q15(&S, 1); for (uint32_t i = 0; i < n; i++) (void)arm_pid_q15(&S, (q15_t)fr_u16(r)); arm_pid_reset_q15(&S); break; }
  }
}

static void quat(FR *r) {
  uint8_t op = fr_u8(r) % 8;
  uint32_t n = fr_range(r, 1, 64);
  float32_t *a = fr_f32(r, 4 * n), *b = fr_f32(r, 4 * n);
  switch (op) {
  case 0: { float32_t *d = ALLOC(float32_t, n); arm_quaternion_norm_f32(a, d, n); free(d); break; }
  case 1: { float32_t *d = ALLOC(float32_t, 4 * n); arm_quaternion_inverse_f32(a, d, n); free(d); break; }
  case 2: { float32_t *d = ALLOC(float32_t, 4 * n); arm_quaternion_conjugate_f32(a, d, n); free(d); break; }
  case 3: { float32_t *d = ALLOC(float32_t, 4 * n); arm_quaternion_normalize_f32(a, d, n); free(d); break; }
  case 4: { float32_t d[4]; arm_quaternion_product_single_f32(a, b, d); break; }
  case 5: { float32_t *d = ALLOC(float32_t, 4 * n); arm_quaternion_product_f32(a, b, d, n); free(d); break; }
  case 6: { float32_t *d = ALLOC(float32_t, 9 * n); arm_quaternion2rotation_f32(a, d, n); free(d); break; }
  default: { float32_t *m = fr_f32(r, 9 * n), *d = ALLOC(float32_t, 4 * n); arm_rotation2quaternion_f32(m, d, n); free(m); free(d); break; }
  }
  free(a); free(b);
}

static void park_clarke(FR *r) {
  float32_t a, b, c, d, s = fr_float(r), co = fr_float(r);
  arm_clarke_f32(fr_float(r), fr_float(r), &a, &b);
  arm_inv_clarke_f32(a, b, &c, &d);
  arm_park_f32(a, b, &c, &d, s, co);
  arm_inv_park_f32(c, d, &a, &b, s, co);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 3) return 0;
  switch (fr_u8(&r) % 3) {
  case 0: fast(&r); break;
  case 1: quat(&r); break;
  default: park_clarke(&r); break;
  }
  return 0;
}
