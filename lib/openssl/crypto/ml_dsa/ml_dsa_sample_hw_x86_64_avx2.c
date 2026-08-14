/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
******************************************************************************/

/*
 * AVX2 x4-SHAKE ML-DSA template.
 * Uses the C-implemented SHAKE x4 over keccak_f1600_x4_avx2 (sha3_x4_avx2.c).
 */

#include "openssl_compat.h"
#include "ml_dsa_local.h"
#include "ml_dsa_vector.h"
#include "ml_dsa_matrix.h"
#include "ml_dsa_hash.h"
#include "internal/constant_time.h"
#include "internal/sha3.h"

/* Scalar helpers used by the template */
#include "ml_dsa_sample_helpers.h"

/* AVX2 x4 Keccak context */
#define ML_DSA_X4_CTX KECCAK1600_X4_CTX

/* x4 SHAKE-128 incremental API */
#define ML_DSA_SHA3_SHAKE128_X4_INC_INIT    ossl_sha3_shake128_x4_inc_init_avx2
#define ML_DSA_SHA3_SHAKE128_X4_INC_ABSORB  ossl_sha3_shake128_x4_inc_absorb_avx2
#define ML_DSA_SHA3_SHAKE128_X4_INC_SQUEEZE ossl_sha3_shake128_x4_inc_squeeze_avx2

/* x4 SHAKE-256 one-shot and incremental API */
#define ML_DSA_SHA3_SHAKE256_X4             ossl_sha3_shake256_x4_avx2
#define ML_DSA_SHA3_SHAKE256_X4_INC_INIT    ossl_sha3_shake256_x4_inc_init_avx2
#define ML_DSA_SHA3_SHAKE256_X4_INC_ABSORB  ossl_sha3_shake256_x4_inc_absorb_avx2
#define ML_DSA_SHA3_SHAKE256_X4_INC_SQUEEZE ossl_sha3_shake256_x4_inc_squeeze_avx2
#define ML_DSA_SHA3_SHAKE256_X4_INC_CLEANUP ossl_sha3_shake256_x4_inc_cleanup_avx2

/* Internal helper names (static, unique within this TU) */
#define ML_DSA_REJ_NTT_POLY_MB     rej_ntt_poly_mb_avx2
#define ML_DSA_REJ_BOUNDED_POLY_MB rej_bounded_poly_mb_avx2

/* Exported sampling function names */
#define ML_DSA_VECTOR_EXPAND_MASK vector_expand_mask_avx2
#define ML_DSA_MATRIX_EXPAND_A    matrix_expand_A_avx2
#define ML_DSA_VECTOR_EXPAND_S    vector_expand_S_avx2

/* Exported init function */
#define ML_DSA_SAMPLE_INIT_FN ossl_ml_dsa_sample_init_avx2

#include "ml_dsa_sample_template.h"
