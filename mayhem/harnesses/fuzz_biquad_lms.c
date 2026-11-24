/* Biquad cascades, LMS / normalized LMS adaptive filters and Levinson-Durbin.
 * Sizes from the doc comments in Source/FilteringFunctions:
 *   df1 f32/q31: coeffs 5*numStages, state 4*numStages; df1 q15: coeffs 6*numStages
 *   df1_32x64: coeffs 5*numStages (q31), state 4*numStages (q63)
 *   df2T f32/f64: coeffs 5*numStages, state 2*numStages
 *   stereo df2T: coeffs 5*numStages, state 4*numStages, io 2*blockSize interleaved
 *   lms/lms_norm: coeffs numTaps, state numTaps+blockSize-1
 *   levinson_durbin: phi nbCoefs+1, a nbCoefs */
#include "fuzz_common.h"

static void biquad(FR *r, uint8_t type) {
  uint8_t ns = (uint8_t)fr_range(r, 1, 8);
  uint32_t bs = fr_range(r, 1, 128);
  int8_t ps = (int8_t)fr_range(r, 0, 3);
  switch (type % 8) {
  case 0: { arm_biquad_casd_df1_inst_f32 S; float32_t *c = fr_f32(r, 5 * ns), *s = ALLOC(float32_t, 4 * ns);
    float32_t *i = fr_f32(r, bs), *o = ALLOC(float32_t, bs);
    arm_biquad_cascade_df1_init_f32(&S, ns, c, s); arm_biquad_cascade_df1_f32(&S, i, o, bs);
    free(c); free(s); free(i); free(o); break; }
  case 1: case 2: { arm_biquad_casd_df1_inst_q31 S; q31_t *c = fr_q31(r, 5 * ns), *s = ALLOC(q31_t, 4 * ns);
    q31_t *i = fr_q31(r, bs), *o = ALLOC(q31_t, bs);
    arm_biquad_cascade_df1_init_q31(&S, ns, c, s, ps);
    if (type % 8 == 1) arm_biquad_cascade_df1_q31(&S, i, o, bs); else arm_biquad_cascade_df1_fast_q31(&S, i, o, bs);
    free(c); free(s); free(i); free(o); break; }
  case 3: case 4: { arm_biquad_casd_df1_inst_q15 S; q15_t *c = fr_q15(r, 6 * ns), *s = ALLOC(q15_t, 4 * ns);
    q15_t *i = fr_q15(r, bs), *o = ALLOC(q15_t, bs);
    arm_biquad_cascade_df1_init_q15(&S, ns, c, s, ps);
    if (type % 8 == 3) arm_biquad_cascade_df1_q15(&S, i, o, bs); else arm_biquad_cascade_df1_fast_q15(&S, i, o, bs);
    free(c); free(s); free(i); free(o); break; }
  case 5: { arm_biquad_cas_df1_32x64_ins_q31 S; q31_t *c = fr_q31(r, 5 * ns); q63_t *s = ALLOC(q63_t, 4 * ns);
    q31_t *i = fr_q31(r, bs), *o = ALLOC(q31_t, bs);
    arm_biquad_cas_df1_32x64_init_q31(&S, ns, c, s, (uint8_t)ps); arm_biquad_cas_df1_32x64_q31(&S, i, o, bs);
    free(c); free(s); free(i); free(o); break; }
  case 6: { if (type & 0x80) {
      arm_biquad_cascade_df2T_instance_f64 S; float64_t *c = fr_f64(r, 5 * ns), *s = ALLOC(float64_t, 2 * ns);
      float64_t *i = fr_f64(r, bs), *o = ALLOC(float64_t, bs);
      arm_biquad_cascade_df2T_init_f64(&S, ns, c, s); arm_biquad_cascade_df2T_f64(&S, i, o, bs);
      free(c); free(s); free(i); free(o);
    } else {
      arm_biquad_cascade_df2T_instance_f32 S; float32_t *c = fr_f32(r, 5 * ns), *s = ALLOC(float32_t, 2 * ns);
      float32_t *i = fr_f32(r, bs), *o = ALLOC(float32_t, bs);
      arm_biquad_cascade_df2T_init_f32(&S, ns, c, s); arm_biquad_cascade_df2T_f32(&S, i, o, bs);
      free(c); free(s); free(i); free(o);
    } break; }
  default: { arm_biquad_cascade_stereo_df2T_instance_f32 S; float32_t *c = fr_f32(r, 5 * ns), *s = ALLOC(float32_t, 4 * ns);
    float32_t *i = fr_f32(r, 2 * bs), *o = ALLOC(float32_t, 2 * bs);
    arm_biquad_cascade_stereo_df2T_init_f32(&S, ns, c, s); arm_biquad_cascade_stereo_df2T_f32(&S, i, o, bs);
    free(c); free(s); free(i); free(o); break; }
  }
}

static void lms(FR *r, uint8_t type) {
  uint16_t nt = (uint16_t)fr_range(r, 1, 64);
  uint32_t bs = fr_range(r, 1, 64);
  uint32_t ps = fr_range(r, 0, 4);
  uint32_t st = nt + bs - 1;
  switch (type % 6) {
  case 0: case 1: { float32_t *c = fr_f32(r, nt), *s = ALLOC(float32_t, st), mu = fr_float(r) / 256.0f;
    float32_t *i = fr_f32(r, bs), *ref = fr_f32(r, bs), *o = ALLOC(float32_t, bs), *e = ALLOC(float32_t, bs);
    if (type % 6 == 0) { arm_lms_instance_f32 S; arm_lms_init_f32(&S, nt, c, s, mu, bs); arm_lms_f32(&S, i, ref, o, e, bs); }
    else { arm_lms_norm_instance_f32 S; arm_lms_norm_init_f32(&S, nt, c, s, mu, bs); arm_lms_norm_f32(&S, i, ref, o, e, bs); }
    free(c); free(s); free(i); free(ref); free(o); free(e); break; }
  case 2: case 3: { q31_t *c = fr_q31(r, nt), *s = ALLOC(q31_t, st), mu = (q31_t)fr_u32(r);
    q31_t *i = fr_q31(r, bs), *ref = fr_q31(r, bs), *o = ALLOC(q31_t, bs), *e = ALLOC(q31_t, bs);
    if (type % 6 == 2) { arm_lms_instance_q31 S; arm_lms_init_q31(&S, nt, c, s, mu, bs, ps); arm_lms_q31(&S, i, ref, o, e, bs); }
    else { arm_lms_norm_instance_q31 S; arm_lms_norm_init_q31(&S, nt, c, s, mu, bs, (uint8_t)ps); arm_lms_norm_q31(&S, i, ref, o, e, bs); }
    free(c); free(s); free(i); free(ref); free(o); free(e); break; }
  default: { q15_t *c = fr_q15(r, nt), *s = ALLOC(q15_t, st), mu = (q15_t)fr_u16(r);
    q15_t *i = fr_q15(r, bs), *ref = fr_q15(r, bs), *o = ALLOC(q15_t, bs), *e = ALLOC(q15_t, bs);
    if (type % 6 == 4) { arm_lms_instance_q15 S; arm_lms_init_q15(&S, nt, c, s, mu, bs, ps); arm_lms_q15(&S, i, ref, o, e, bs); }
    else { arm_lms_norm_instance_q15 S; arm_lms_norm_init_q15(&S, nt, c, s, mu, bs, (uint8_t)ps); arm_lms_norm_q15(&S, i, ref, o, e, bs); }
    free(c); free(s); free(i); free(ref); free(o); free(e); break; }
  }
}

static void levinson(FR *r, uint8_t type) {
  int n = (int)fr_range(r, 1, 32);
  if (type & 1) {
    float32_t *phi = fr_f32(r, n + 1), *a = ALLOC(float32_t, n), err;
    arm_levinson_durbin_f32(phi, a, &err, n); free(phi); free(a);
  } else {
    q31_t *phi = fr_q31(r, n + 1), *a = ALLOC(q31_t, n), err;
    arm_levinson_durbin_q31(phi, a, &err, n); free(phi); free(a);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 4) return 0;
  uint8_t sel = fr_u8(&r), type = fr_u8(&r);
  switch (sel % 3) {
  case 0: biquad(&r, type); break;
  case 1: lms(&r, type); break;
  default: levinson(&r, type); break;
  }
  return 0;
}
