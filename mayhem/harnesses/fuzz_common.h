/* Shared helpers for the CMSIS-DSP libFuzzer harnesses.
 *
 * CMSIS-DSP is a kernel library: untrusted data reaches it as sample buffers plus
 * size/shape parameters. Every harness derives sizes from the input, allocates
 * EXACTLY the buffer sizes the function's doc comment requires on the heap (so
 * ASan sees any kernel over-read/over-write), checks every init status, and only
 * then runs the kernel. Float samples are derived from bounded integers so they
 * stay finite: NaN/inf inputs would make every float->fixed cast in the library
 * a UBSan float-cast-overflow on the first iteration and drown real findings.
 */
#ifndef CMSIS_DSP_FUZZ_COMMON_H
#define CMSIS_DSP_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "arm_math.h"

typedef struct {
  const uint8_t *p;
  size_t n;
} FR;

static inline uint8_t fr_u8(FR *r) {
  if (!r->n) return 0;
  r->n--;
  return *r->p++;
}
static inline uint16_t fr_u16(FR *r) {
  uint16_t a = fr_u8(r);
  return (uint16_t)(a | ((uint16_t)fr_u8(r) << 8));
}
static inline uint32_t fr_u32(FR *r) {
  uint32_t a = fr_u16(r);
  return a | ((uint32_t)fr_u16(r) << 16);
}
/* value in [lo, hi] */
static inline uint32_t fr_range(FR *r, uint32_t lo, uint32_t hi) {
  uint32_t span = hi - lo + 1;
  uint32_t v = span <= 256 ? fr_u8(r) : (span <= 65536 ? fr_u16(r) : fr_u32(r));
  return lo + v % span;
}
static inline float fr_float(FR *r) { return (float)(int16_t)fr_u16(r) / 256.0f; }

static inline void *fr_alloc(size_t bytes) {
  void *p = malloc(bytes ? bytes : 1);
  if (!p) abort();
  return p;
}
/* Exact-size heap arrays filled from the input (zero once it runs out). */
static inline float32_t *fr_f32(FR *r, size_t cnt) {
  float32_t *a = (float32_t *)fr_alloc(cnt * sizeof(float32_t));
  for (size_t i = 0; i < cnt; i++) a[i] = fr_float(r);
  return a;
}
static inline float64_t *fr_f64(FR *r, size_t cnt) {
  float64_t *a = (float64_t *)fr_alloc(cnt * sizeof(float64_t));
  for (size_t i = 0; i < cnt; i++) a[i] = (float64_t)fr_float(r);
  return a;
}
static inline q31_t *fr_q31(FR *r, size_t cnt) {
  q31_t *a = (q31_t *)fr_alloc(cnt * sizeof(q31_t));
  for (size_t i = 0; i < cnt; i++) a[i] = (q31_t)fr_u32(r);
  return a;
}
static inline q15_t *fr_q15(FR *r, size_t cnt) {
  q15_t *a = (q15_t *)fr_alloc(cnt * sizeof(q15_t));
  for (size_t i = 0; i < cnt; i++) a[i] = (q15_t)fr_u16(r);
  return a;
}
static inline q7_t *fr_q7(FR *r, size_t cnt) {
  q7_t *a = (q7_t *)fr_alloc(cnt * sizeof(q7_t));
  for (size_t i = 0; i < cnt; i++) a[i] = (q7_t)fr_u8(r);
  return a;
}
#define ALLOC(type, cnt) ((type *)fr_alloc((size_t)(cnt) * sizeof(type)))

#endif
