/* Distance functions (Source/DistanceFunctions): float distances, bit-packed boolean
 * distances and dynamic time warping. Sizes from the doc comments:
 *   float distances: two vectors of blockSize
 *   boolean distances: numberOfBools bits packed in ceil(numberOfBools/32) uint32 words
 *   DTW: distance, window (q7) and cost matrices all queryLen x templateLen,
 *        path 2*(rows+cols) int16 entries */
#include "fuzz_common.h"

static void floats(FR *r) {
  uint8_t op = fr_u8(r) % 15;
  uint32_t n = fr_range(r, 1, 256);
  if (op >= 12) {
    float64_t *a = fr_f64(r, n), *b = fr_f64(r, n);
    if (op == 12) (void)arm_euclidean_distance_f64(a, b, n);
    else if (op == 13) (void)arm_chebyshev_distance_f64(a, b, n);
    else { (void)arm_cityblock_distance_f64(a, b, n); (void)arm_cosine_distance_f64(a, b, n); }
    free(a); free(b);
    return;
  }
  float32_t *a = fr_f32(r, n), *b = fr_f32(r, n);
  switch (op) {
  case 0: (void)arm_euclidean_distance_f32(a, b, n); break;
  case 1: (void)arm_braycurtis_distance_f32(a, b, n); break;
  case 2: (void)arm_canberra_distance_f32(a, b, n); break;
  case 3: (void)arm_chebyshev_distance_f32(a, b, n); break;
  case 4: (void)arm_cityblock_distance_f32(a, b, n); break;
  case 5: (void)arm_correlation_distance_f32(a, b, n); break;
  case 6: (void)arm_cosine_distance_f32(a, b, n); break;
  case 7: { /* Jensen-Shannon takes probability vectors: make them positive */
    for (uint32_t i = 0; i < n; i++) { a[i] = (a[i] < 0 ? -a[i] : a[i]) + 1e-3f; b[i] = (b[i] < 0 ? -b[i] : b[i]) + 1e-3f; }
    (void)arm_jensenshannon_distance_f32(a, b, n); break; }
  default: (void)arm_minkowski_distance_f32(a, b, (int32_t)fr_range(r, 1, 8), n); break;
  }
  free(a); free(b);
}

static void bools(FR *r) {
  uint8_t op = fr_u8(r) % 9;
  uint32_t nb = fr_range(r, 1, 1024), words = (nb + 31) / 32;
  uint32_t *a = ALLOC(uint32_t, words), *b = ALLOC(uint32_t, words);
  for (uint32_t i = 0; i < words; i++) { a[i] = fr_u32(r); b[i] = fr_u32(r); }
  switch (op) {
  case 0: (void)arm_dice_distance(a, b, nb); break;
  case 1: (void)arm_hamming_distance(a, b, nb); break;
  case 2: (void)arm_jaccard_distance(a, b, nb); break;
  case 3: (void)arm_kulsinski_distance(a, b, nb); break;
  case 4: (void)arm_rogerstanimoto_distance(a, b, nb); break;
  case 5: (void)arm_russellrao_distance(a, b, nb); break;
  case 6: (void)arm_sokalmichener_distance(a, b, nb); break;
  case 7: (void)arm_sokalsneath_distance(a, b, nb); break;
  default: (void)arm_yule_distance(a, b, nb); break;
  }
  free(a); free(b);
}

static void dtw(FR *r) {
  uint16_t rows = (uint16_t)fr_range(r, 1, 48), cols = (uint16_t)fr_range(r, 1, 48);
  uint8_t wsel = fr_u8(r) % 3;
  int32_t wsize = (int32_t)fr_range(r, 0, 64);
  size_t n = (size_t)rows * cols;
  arm_matrix_instance_f32 dist = {rows, cols, fr_f32(r, n)}, cost = {rows, cols, ALLOC(float32_t, n)};
  for (size_t i = 0; i < n; i++) dist.pData[i] = dist.pData[i] < 0 ? -dist.pData[i] : dist.pData[i];
  arm_matrix_instance_q7 win = {rows, cols, ALLOC(q7_t, n)}, *pw = NULL;
  if (wsel) {
    arm_dtw_window wt = wsel == 1 ? ARM_DTW_SAKOE_CHIBA_WINDOW : ARM_DTW_SLANTED_BAND_WINDOW;
    if (arm_dtw_init_window_q7(wt, wsize, &win) == ARM_MATH_SUCCESS) pw = &win;
  }
  float32_t d;
  if (arm_dtw_distance_f32(&dist, pw, &cost, &d) == ARM_MATH_SUCCESS) {
    int16_t *path = ALLOC(int16_t, 2 * ((size_t)rows + cols));
    uint32_t plen;
    arm_dtw_path_f32(&cost, path, &plen);
    free(path);
  }
  free(dist.pData); free(cost.pData); free(win.pData);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 4) return 0;
  switch (fr_u8(&r) % 3) {
  case 0: floats(&r); break;
  case 1: bools(&r); break;
  default: dtw(&r); break;
  }
  return 0;
}
