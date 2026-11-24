/* Transforms: CFFT (f32/f64/q15/q31), real FFT (fast f32/f64, q15/q31),
 * radix-2/radix-4 CFFT. The length is chosen from the input, including invalid
 * lengths so each init's error path runs; processing only runs on ARM_MATH_SUCCESS.
 * Buffers (Source/TransformFunctions doc comments):
 *   cfft / radix2 / radix4: in-place complex buffer 2*fftLen
 *   rfft_fast: in fftLen, out fftLen
 *   rfft q15/q31: in fftLenReal (RIFFT: the 2*fftLenReal spectrum layout the forward
 *                 transform produces, since the inverse split reads past fftLenReal), out 2*fftLenReal
 */
#include "fuzz_common.h"

static const uint16_t kLens[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 8, 4, 2, 1, 100, 0};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 3) return 0;
  uint8_t sel = fr_u8(&r);
  uint8_t flags = fr_u8(&r);
  uint32_t len = kLens[fr_u8(&r) % (sizeof(kLens) / sizeof(kLens[0]))];
  uint8_t ifft = flags & 1, brev = (flags >> 1) & 1;
  switch (sel % 12) {
  case 0: { arm_cfft_instance_f32 S; if (arm_cfft_init_f32(&S, (uint16_t)len) != ARM_MATH_SUCCESS) break;
    float32_t *b = fr_f32(&r, 2 * len); arm_cfft_f32(&S, b, ifft, brev); free(b); break; }
  case 1: { arm_cfft_instance_f64 S; if (arm_cfft_init_f64(&S, (uint16_t)len) != ARM_MATH_SUCCESS) break;
    float64_t *b = fr_f64(&r, 2 * len); arm_cfft_f64(&S, b, ifft, brev); free(b); break; }
  case 2: { arm_cfft_instance_q15 S; if (arm_cfft_init_q15(&S, (uint16_t)len) != ARM_MATH_SUCCESS) break;
    q15_t *b = fr_q15(&r, 2 * len); arm_cfft_q15(&S, b, ifft, brev); free(b); break; }
  case 3: { arm_cfft_instance_q31 S; if (arm_cfft_init_q31(&S, (uint16_t)len) != ARM_MATH_SUCCESS) break;
    q31_t *b = fr_q31(&r, 2 * len); arm_cfft_q31(&S, b, ifft, brev); free(b); break; }
  case 4: { arm_rfft_fast_instance_f32 S; if (arm_rfft_fast_init_f32(&S, (uint16_t)len) != ARM_MATH_SUCCESS) break;
    float32_t *i = fr_f32(&r, len), *o = ALLOC(float32_t, len); arm_rfft_fast_f32(&S, i, o, ifft); free(i); free(o); break; }
  case 5: { arm_rfft_fast_instance_f64 S; if (arm_rfft_fast_init_f64(&S, (uint16_t)len) != ARM_MATH_SUCCESS) break;
    float64_t *i = fr_f64(&r, len), *o = ALLOC(float64_t, len); arm_rfft_fast_f64(&S, i, o, ifft); free(i); free(o); break; }
  case 6: { arm_rfft_instance_q15 S; if (arm_rfft_init_q15(&S, len, ifft, brev) != ARM_MATH_SUCCESS) break;
    q15_t *i = fr_q15(&r, ifft ? 2 * len : len), *o = ALLOC(q15_t, 2 * len); arm_rfft_q15(&S, i, o); free(i); free(o); break; }
  case 7: { arm_rfft_instance_q31 S; if (arm_rfft_init_q31(&S, len, ifft, brev) != ARM_MATH_SUCCESS) break;
    q31_t *i = fr_q31(&r, ifft ? 2 * len : len), *o = ALLOC(q31_t, 2 * len); arm_rfft_q31(&S, i, o); free(i); free(o); break; }
  case 8: { if (flags & 4) { arm_cfft_radix2_instance_f32 S;
      if (arm_cfft_radix2_init_f32(&S, (uint16_t)len, ifft, brev) != ARM_MATH_SUCCESS) break;
      float32_t *b = fr_f32(&r, 2 * len); arm_cfft_radix2_f32(&S, b); free(b);
    } else { arm_cfft_radix4_instance_f32 S;
      if (arm_cfft_radix4_init_f32(&S, (uint16_t)len, ifft, brev) != ARM_MATH_SUCCESS) break;
      float32_t *b = fr_f32(&r, 2 * len); arm_cfft_radix4_f32(&S, b); free(b);
    } break; }
  case 9: { if (flags & 4) { arm_cfft_radix2_instance_q31 S;
      if (arm_cfft_radix2_init_q31(&S, (uint16_t)len, ifft, brev) != ARM_MATH_SUCCESS) break;
      q31_t *b = fr_q31(&r, 2 * len); arm_cfft_radix2_q31(&S, b); free(b);
    } else { arm_cfft_radix4_instance_q31 S;
      if (arm_cfft_radix4_init_q31(&S, (uint16_t)len, ifft, brev) != ARM_MATH_SUCCESS) break;
      q31_t *b = fr_q31(&r, 2 * len); arm_cfft_radix4_q31(&S, b); free(b);
    } break; }
  case 10: { if (flags & 4) { arm_cfft_radix2_instance_q15 S;
      if (arm_cfft_radix2_init_q15(&S, (uint16_t)len, ifft, brev) != ARM_MATH_SUCCESS) break;
      q15_t *b = fr_q15(&r, 2 * len); arm_cfft_radix2_q15(&S, b); free(b);
    } else { arm_cfft_radix4_instance_q15 S;
      if (arm_cfft_radix4_init_q15(&S, (uint16_t)len, ifft, brev) != ARM_MATH_SUCCESS) break;
      q15_t *b = fr_q15(&r, 2 * len); arm_cfft_radix4_q15(&S, b); free(b);
    } break; }
  default: {
    /* f64 radix-free CFFT round trip: forward then inverse on the same buffer. */
    arm_cfft_instance_f64 S; if (arm_cfft_init_f64(&S, (uint16_t)len) != ARM_MATH_SUCCESS) break;
    float64_t *b = fr_f64(&r, 2 * len); arm_cfft_f64(&S, b, 0, 1); arm_cfft_f64(&S, b, 1, 1); free(b);
    break; }
  }
  return 0;
}
