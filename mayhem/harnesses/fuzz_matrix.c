/* Matrix functions (Source/MatrixFunctions). The library is built with
 * ARM_MATH_MATRIX_CHECK, so every arm_mat_* call validates operand shapes and returns
 * ARM_MATH_SIZE_MISMATCH. The harness therefore picks each operand's shape independently
 * from the input (compatible or not) and allocates every matrix exactly rows*cols
 * (complex: 2*rows*cols) elements. Scratch sizes from the doc comments:
 *   mult_q7/q15/fast_q15/opt_q31 pState: numRowsB*numColsB; cmplx_mult_q15 scratch 2*numRowsB*numColsB
 *   qr (m x n, m >= n): R m x n, Q m x m, tau n, tmpA m, tmpB m
 *   ldlt (n x n): L n x n, D n x n, pp n
 *   mat_vec_mult: vector numCols, out numRows
 *   solve_{upper,lower}_triangular: dst is "the solution X of UT . X = A", i.e. A's (here B's)
 *     shape; the kernel indexes ut and a by dst's shape, which MATRIX_CHECK does not validate */
#include "fuzz_common.h"

#define DIM(r) ((uint16_t)fr_range((r), 1, 12))

#define MK(T, name, FILL, R, C, K)                     \
  arm_matrix_instance_##T name;                          \
  name.numRows = (R); name.numCols = (C);                \
  name.pData = FILL(r, (size_t)(R) * (C) * (K));

/* Re-allocate the destination with B's shape (the documented solution shape). */
#define SOLVE_DST(T)                                     \
  free(D.pData); D.numRows = br; D.numCols = bc;         \
  D.pData = fr_##T(r, (size_t)br * bc);

static void f32(FR *r, uint8_t op) {
  uint16_t ar = DIM(r), ac = DIM(r), br = DIM(r), bc = DIM(r), dr = DIM(r), dc = DIM(r);
  MK(f32, A, fr_f32, ar, ac, 1)
  MK(f32, B, fr_f32, br, bc, 1)
  MK(f32, D, fr_f32, dr, dc, 1)
  switch (op % 12) {
  case 0: arm_mat_add_f32(&A, &B, &D); break;
  case 1: arm_mat_sub_f32(&A, &B, &D); break;
  case 2: arm_mat_mult_f32(&A, &B, &D); break;
  case 3: arm_mat_trans_f32(&A, &D); break;
  case 4: arm_mat_scale_f32(&A, fr_float(r), &D); break;
  case 5: arm_mat_inverse_f32(&A, &D); break;
  case 6: arm_mat_cholesky_f32(&A, &D); break;
  case 7: SOLVE_DST(f32) arm_mat_solve_upper_triangular_f32(&A, &B, &D); break;
  case 8: SOLVE_DST(f32) arm_mat_solve_lower_triangular_f32(&A, &B, &D); break;
  case 9: { float32_t *v = fr_f32(r, ac), *o = ALLOC(float32_t, ar);
    arm_mat_vec_mult_f32(&A, v, o); free(v); free(o); break; }
  case 10: { /* complex: re-shape as complex operands of the same element counts */
    arm_matrix_instance_f32 CA = {ar, ac, fr_f32(r, 2u * ar * ac)}, CB = {br, bc, fr_f32(r, 2u * br * bc)},
                            CD = {dr, dc, fr_f32(r, 2u * dr * dc)};
    if (op & 0x80) arm_mat_cmplx_mult_f32(&CA, &CB, &CD); else arm_mat_cmplx_trans_f32(&CA, &CD);
    free(CA.pData); free(CB.pData); free(CD.pData); break; }
  default: { /* QR of the m x n matrix A (m >= n required, else status error) */
    uint16_t m = ar, n = ac;
    arm_matrix_instance_f32 R = {m, n, ALLOC(float32_t, (size_t)m * n)}, Q = {m, m, ALLOC(float32_t, (size_t)m * m)};
    float32_t *tau = ALLOC(float32_t, n), *ta = ALLOC(float32_t, m), *tb = ALLOC(float32_t, m);
    if (m >= n) arm_mat_qr_f32(&A, 1e-6f, &R, &Q, tau, ta, tb);
    free(R.pData); free(Q.pData); free(tau); free(ta); free(tb); break; }
  }
  free(A.pData); free(B.pData); free(D.pData);
}

static void f64(FR *r, uint8_t op) {
  uint16_t ar = DIM(r), ac = DIM(r), br = DIM(r), bc = DIM(r), dr = DIM(r), dc = DIM(r);
  MK(f64, A, fr_f64, ar, ac, 1)
  MK(f64, B, fr_f64, br, bc, 1)
  MK(f64, D, fr_f64, dr, dc, 1)
  switch (op % 9) {
  case 0: arm_mat_sub_f64(&A, &B, &D); break;
  case 1: arm_mat_mult_f64(&A, &B, &D); break;
  case 2: arm_mat_trans_f64(&A, &D); break;
  case 3: arm_mat_inverse_f64(&A, &D); break;
  case 4: arm_mat_cholesky_f64(&A, &D); break;
  case 5: SOLVE_DST(f64) arm_mat_solve_upper_triangular_f64(&A, &B, &D); break;
  case 6: SOLVE_DST(f64) arm_mat_solve_lower_triangular_f64(&A, &B, &D); break;
  case 7: { uint16_t n = ar; /* LDLT of the n x n matrix A */
    arm_matrix_instance_f64 L = {n, n, ALLOC(float64_t, (size_t)n * n)}, Dg = {n, n, ALLOC(float64_t, (size_t)n * n)};
    uint16_t *pp = ALLOC(uint16_t, n);
    arm_mat_ldlt_f64(&A, &L, &Dg, pp);
    free(L.pData); free(Dg.pData); free(pp); break; }
  default: { uint16_t m = ar, n = ac;
    arm_matrix_instance_f64 R = {m, n, ALLOC(float64_t, (size_t)m * n)}, Q = {m, m, ALLOC(float64_t, (size_t)m * m)};
    float64_t *tau = ALLOC(float64_t, n), *ta = ALLOC(float64_t, m), *tb = ALLOC(float64_t, m);
    if (m >= n) arm_mat_qr_f64(&A, 1e-9, &R, &Q, tau, ta, tb);
    free(R.pData); free(Q.pData); free(tau); free(ta); free(tb); break; }
  }
  free(A.pData); free(B.pData); free(D.pData);
}

static void ldlt32(FR *r) {
  uint16_t n = DIM(r);
  arm_matrix_instance_f32 A = {n, n, fr_f32(r, (size_t)n * n)};
  /* make it symmetric, as LDLT requires */
  for (uint16_t i = 0; i < n; i++) for (uint16_t j = 0; j < i; j++) A.pData[i * n + j] = A.pData[j * n + i];
  arm_matrix_instance_f32 L = {n, n, ALLOC(float32_t, (size_t)n * n)}, D = {n, n, ALLOC(float32_t, (size_t)n * n)};
  uint16_t *pp = ALLOC(uint16_t, n);
  arm_mat_ldlt_f32(&A, &L, &D, pp);
  free(A.pData); free(L.pData); free(D.pData); free(pp);
}

static void fixed(FR *r, uint8_t op) {
  uint16_t ar = DIM(r), ac = DIM(r), br = DIM(r), bc = DIM(r), dr = DIM(r), dc = DIM(r);
  uint8_t t = op % 3;
  if (t == 0) {
    MK(q31, A, fr_q31, ar, ac, 1) MK(q31, B, fr_q31, br, bc, 1) MK(q31, D, fr_q31, dr, dc, 1)
    q31_t *st = ALLOC(q31_t, (size_t)br * bc);
    switch ((op >> 2) % 8) {
    case 0: arm_mat_add_q31(&A, &B, &D); break;
    case 1: arm_mat_sub_q31(&A, &B, &D); break;
    case 2: arm_mat_mult_q31(&A, &B, &D); break;
    case 3: arm_mat_mult_fast_q31(&A, &B, &D); break;
    case 4: arm_mat_mult_opt_q31(&A, &B, &D, st); break;
    case 5: arm_mat_trans_q31(&A, &D); break;
    case 6: arm_mat_scale_q31(&A, (q31_t)fr_u32(r), (int32_t)fr_range(r, 0, 8), &D); break;
    default: { q31_t *v = fr_q31(r, ac), *o = ALLOC(q31_t, ar); arm_mat_vec_mult_q31(&A, v, o); free(v); free(o); break; }
    }
    free(st); free(A.pData); free(B.pData); free(D.pData);
  } else if (t == 1) {
    MK(q15, A, fr_q15, ar, ac, 1) MK(q15, B, fr_q15, br, bc, 1) MK(q15, D, fr_q15, dr, dc, 1)
    q15_t *st = ALLOC(q15_t, (size_t)br * bc);
    switch ((op >> 2) % 7) {
    case 0: arm_mat_add_q15(&A, &B, &D); break;
    case 1: arm_mat_sub_q15(&A, &B, &D); break;
    case 2: arm_mat_mult_q15(&A, &B, &D, st); break;
    case 3: arm_mat_mult_fast_q15(&A, &B, &D, st); break;
    case 4: arm_mat_trans_q15(&A, &D); break;
    case 5: arm_mat_scale_q15(&A, (q15_t)fr_u16(r), (int32_t)fr_range(r, 0, 8), &D); break;
    default: { q15_t *v = fr_q15(r, ac), *o = ALLOC(q15_t, ar); arm_mat_vec_mult_q15(&A, v, o); free(v); free(o); break; }
    }
    free(st); free(A.pData); free(B.pData); free(D.pData);
  } else {
    MK(q7, A, fr_q7, ar, ac, 1) MK(q7, B, fr_q7, br, bc, 1) MK(q7, D, fr_q7, dr, dc, 1)
    q7_t *st = ALLOC(q7_t, (size_t)br * bc);
    switch ((op >> 2) % 3) {
    case 0: arm_mat_mult_q7(&A, &B, &D, st); break;
    case 1: arm_mat_trans_q7(&A, &D); break;
    default: { q7_t *v = fr_q7(r, ac), *o = ALLOC(q7_t, ar); arm_mat_vec_mult_q7(&A, v, o); free(v); free(o); break; }
    }
    free(st); free(A.pData); free(B.pData); free(D.pData);
  }
}

static void cmplx_fixed(FR *r, uint8_t op) {
  uint16_t ar = DIM(r), ac = DIM(r), br = DIM(r), bc = DIM(r), dr = DIM(r), dc = DIM(r);
  if (op & 1) {
    arm_matrix_instance_q15 A = {ar, ac, fr_q15(r, 2u * ar * ac)}, B = {br, bc, fr_q15(r, 2u * br * bc)},
                            D = {dr, dc, fr_q15(r, 2u * dr * dc)};
    q15_t *sc = ALLOC(q15_t, 2u * br * bc);
    if (op & 2) arm_mat_cmplx_mult_q15(&A, &B, &D, sc); else arm_mat_cmplx_trans_q15(&A, &D);
    free(sc); free(A.pData); free(B.pData); free(D.pData);
  } else {
    arm_matrix_instance_q31 A = {ar, ac, fr_q31(r, 2u * ar * ac)}, B = {br, bc, fr_q31(r, 2u * br * bc)},
                            D = {dr, dc, fr_q31(r, 2u * dr * dc)};
    if (op & 2) arm_mat_cmplx_mult_q31(&A, &B, &D); else arm_mat_cmplx_trans_q31(&A, &D);
    free(A.pData); free(B.pData); free(D.pData);
  }
}

static void householder(FR *r, uint8_t op) {
  uint32_t n = fr_range(r, 1, 64);
  if (op & 1) { float32_t *s = fr_f32(r, n), *o = ALLOC(float32_t, n); arm_householder_f32(s, 1e-6f, n, o); free(s); free(o); }
  else { float64_t *s = fr_f64(r, n), *o = ALLOC(float64_t, n); arm_householder_f64(s, 1e-9, n, o); free(s); free(o); }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FR r = {data, size};
  if (size < 8) return 0;
  uint8_t sel = fr_u8(&r), op = fr_u8(&r);
  switch (sel % 6) {
  case 0: f32(&r, op); break;
  case 1: f64(&r, op); break;
  case 2: fixed(&r, op); break;
  case 3: cmplx_fixed(&r, op); break;
  case 4: ldlt32(&r); break;
  default: householder(&r, op); break;
  }
  return 0;
}
