/* Classifiers: SVM (linear, polynomial, RBF, sigmoid), Gaussian naive Bayes, SEFR.
 * Buffer sizes from the doc comments (Source/SVMFunctions, Source/BayesFunctions):
 *   SVM: dualCoefficients[nbSV], supportVectors[nbSV*dim], classes[2], input[dim]
 *   Bayes: theta/sigma[classes*dim], priors[classes], probabilities[classes], buffer[classes]
 *   SEFR: weights[classes*dim], bias[classes], training pSrc[numSamples*dim],
 *         labels[numSamples] (validated by the library), tmp arm_sefr_*_tmp_buffer_size() */
#include "fuzz_common.h"

static void svm(FR *r) {
  uint8_t kind = fr_u8(r) % 4;
  uint32_t nsv = fr_range(r, 1, 32), dim = fr_range(r, 1, 32);
  float32_t intercept = fr_float(r);
  float32_t *dual = fr_f32(r, nsv), *sv = fr_f32(r, nsv * dim), *in = fr_f32(r, dim);
  int32_t classes[2] = {(int32_t)fr_u32(r), (int32_t)fr_u32(r)}, res;
  float32_t coef0 = fr_float(r), gamma = fr_float(r) / 64.0f;
  int32_t degree = (int32_t)fr_range(r, 0, 6);
  switch (kind) {
  case 0: { arm_svm_linear_instance_f32 S;
    arm_svm_linear_init_f32(&S, nsv, dim, intercept, dual, sv, classes); arm_svm_linear_predict_f32(&S, in, &res); break; }
  case 1: { arm_svm_polynomial_instance_f32 S;
    arm_svm_polynomial_init_f32(&S, nsv, dim, intercept, dual, sv, classes, degree, coef0, gamma);
    arm_svm_polynomial_predict_f32(&S, in, &res); break; }
  case 2: { arm_svm_rbf_instance_f32 S;
    arm_svm_rbf_init_f32(&S, nsv, dim, intercept, dual, sv, classes, gamma); arm_svm_rbf_predict_f32(&S, in, &res); break; }
  default: { arm_svm_sigmoid_instance_f32 S;
    arm_svm_sigmoid_init_f32(&S, nsv, dim, intercept, dual, sv, classes, coef0, gamma);
    arm_svm_sigmoid_predict_f32(&S, in, &res); break; }
  }
  free(dual); free(sv); free(in);
}

static void bayes(FR *r) {
  uint32_t nc = fr_range(r, 1, 16), dim = fr_range(r, 1, 32);
  float32_t *theta = fr_f32(r, nc * dim), *sigma = fr_f32(r, nc * dim), *prior = fr_f32(r, nc);
  for (uint32_t i = 0; i < nc * dim; i++) sigma[i] = sigma[i] < 0 ? -sigma[i] : sigma[i];
  for (uint32_t i = 0; i < nc; i++) prior[i] = (prior[i] < 0 ? -prior[i] : prior[i]) + 1e-3f;
  arm_gaussian_naive_bayes_instance_f32 S = {dim, nc, theta, sigma, prior, 1e-6f};
  float32_t *in = fr_f32(r, dim), *prob = ALLOC(float32_t, nc), *buf = ALLOC(float32_t, nc);
  (void)arm_gaussian_naive_bayes_predict_f32(&S, in, prob, buf);
  free(theta); free(sigma); free(prior); free(in); free(prob); free(buf);
}

static void sefr(FR *r) {
  uint32_t nc = fr_range(r, 1, 8), dim = fr_range(r, 1, 16), ns = fr_range(r, 0, 64);
  uint8_t lda = fr_u8(r) & 1;
  float32_t *w = ALLOC(float32_t, nc * dim), *bias = ALLOC(float32_t, nc);
  arm_sefr_instance_f32 S;
  arm_sefr_init_f32(&S, dim, nc, w, bias);
  float32_t *src = fr_f32(r, ns * dim);
  uint32_t *labels = ALLOC(uint32_t, ns);
  for (uint32_t i = 0; i < ns; i++) labels[i] = fr_u8(r) % (nc + 1); /* nc = out of range, rejected */
  arm_status st;
  if (lda) {
    float32_t *tmp = ALLOC(float32_t, arm_sefr_lda_tmp_buffer_size(nc));
    st = arm_sefr_lda_f32(&S, src, labels, ns, tmp); free(tmp);
  } else {
    float32_t *tmp = ALLOC(float32_t, arm_sefr_train_tmp_buffer_size(dim, nc));
    st = arm_sefr_train_f32(&S, src, labels, ns, tmp); free(tmp);
  }
  if (st == ARM_MATH_SUCCESS) {
    float32_t *in = fr_f32(r, dim), *scores = ALLOC(float32_t, nc);
    (void)arm_sefr_predict_f32(&S, in, scores); free(in); free(scores);
  }
  free(w); free(bias); free(src); free(labels);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 4) return 0;
  switch (fr_u8(&r) % 3) {
  case 0: svm(&r); break;
  case 1: bayes(&r); break;
  default: sefr(&r); break;
  }
  return 0;
}
