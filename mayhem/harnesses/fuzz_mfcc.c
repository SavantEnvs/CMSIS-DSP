/* MFCC (Source/TransformFunctions/arm_mfcc_{f32,q15,q31}.c): window, real FFT, magnitude,
 * mel filter bank, log, DCT. The caller provides the filter bank; the harness builds one
 * from the input that honours the documented layout: filter i reads filterLengths[i]
 * spectrum bins starting at filterPos[i], all within the fftLen/2+1 bins of the spectrum;
 * filterCoefs holds sum(filterLengths); dctCoefs nbDctOutputs*nbMelFilters; window fftLen.
 * pSrc fftLen samples (modified in place), pDst nbDctOutputs, pTmp a complex buffer of
 * fftLen (2*fftLen values; q15 uses q31 tmp). Init failures (invalid fftLen) stop. */
#include "fuzz_common.h"

static const uint32_t kLens[] = {32, 64, 128, 256, 512, 1024, 2048, 4096, 16, 100};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 6) return 0;
  uint8_t type = fr_u8(&r) % 3;
  uint32_t fftLen = kLens[fr_u8(&r) % 10];
  uint32_t bins = fftLen / 2 + 1;
  /* A mel filter bank has at most one filter per spectrum bin (each filter covers >= 1 bin);
   * the kernels reuse pSrc (fftLen values) to hold the nbMelFilters filter outputs. */
  uint32_t nbMel = fr_range(&r, 1, bins < 40 ? bins : 40), nbDct = fr_range(&r, 1, 24);
  uint32_t *pos = ALLOC(uint32_t, nbMel), *len = ALLOC(uint32_t, nbMel), total = 0;
  for (uint32_t i = 0; i < nbMel; i++) {
    pos[i] = fr_range(&r, 0, bins - 1);
    len[i] = fr_range(&r, 1, bins - pos[i]);
    total += len[i];
  }
  if (type == 0) {
    arm_mfcc_instance_f32 S;
    float32_t *dct = fr_f32(&r, nbDct * nbMel), *fc = fr_f32(&r, total), *win = fr_f32(&r, fftLen);
    if (arm_mfcc_init_f32(&S, fftLen, nbMel, nbDct, dct, pos, len, fc, win) == ARM_MATH_SUCCESS) {
      float32_t *src = fr_f32(&r, fftLen), *dst = ALLOC(float32_t, nbDct), *tmp = ALLOC(float32_t, 2 * fftLen);
      arm_mfcc_f32(&S, src, dst, tmp);
      free(src); free(dst); free(tmp);
    }
    free(dct); free(fc); free(win);
  } else if (type == 1) {
    arm_mfcc_instance_q15 S;
    q15_t *dct = fr_q15(&r, nbDct * nbMel), *fc = fr_q15(&r, total), *win = fr_q15(&r, fftLen);
    if (arm_mfcc_init_q15(&S, fftLen, nbMel, nbDct, dct, pos, len, fc, win) == ARM_MATH_SUCCESS) {
      q15_t *src = fr_q15(&r, fftLen), *dst = ALLOC(q15_t, nbDct);
      q31_t *tmp = ALLOC(q31_t, 2 * fftLen);
      (void)arm_mfcc_q15(&S, src, dst, tmp);
      free(src); free(dst); free(tmp);
    }
    free(dct); free(fc); free(win);
  } else {
    arm_mfcc_instance_q31 S;
    q31_t *dct = fr_q31(&r, nbDct * nbMel), *fc = fr_q31(&r, total), *win = fr_q31(&r, fftLen);
    if (arm_mfcc_init_q31(&S, fftLen, nbMel, nbDct, dct, pos, len, fc, win) == ARM_MATH_SUCCESS) {
      q31_t *src = fr_q31(&r, fftLen), *dst = ALLOC(q31_t, nbDct), *tmp = ALLOC(q31_t, 2 * fftLen);
      (void)arm_mfcc_q31(&S, src, dst, tmp);
      free(src); free(dst); free(tmp);
    }
    free(dct); free(fc); free(win);
  }
  free(pos); free(len);
  return 0;
}
