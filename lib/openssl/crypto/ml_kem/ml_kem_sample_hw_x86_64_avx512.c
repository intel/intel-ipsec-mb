/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * AVX-512VL x4-SHAKE ML-KEM template.
 */

#include "openssl_compat.h"
#include "crypto/ml_kem.h"
#include "internal/sha3.h"

/* AVX-512VL x4 Keccak context */
#define ML_KEM_X4_CTX KECCAK1600_X4_CTX

/* x4 SHAKE-128 incremental API */
#define ML_KEM_SHA3_SHAKE128_X4_INC_INIT    ossl_sha3_shake128_x4_inc_init_avx512vl
#define ML_KEM_SHA3_SHAKE128_X4_INC_ABSORB  ossl_sha3_shake128_x4_inc_absorb_avx512vl
#define ML_KEM_SHA3_SHAKE128_X4_INC_SQUEEZE ossl_sha3_shake128_x4_inc_squeeze_avx512vl
#define ML_KEM_SHA3_SHAKE128_X4_INC_CLEANUP ossl_sha3_shake128_x4_inc_cleanup_avx512vl

/* Internal helper name (static, unique within this TU) */
#define ML_KEM_SAMPLE_NTT_X4 sample_ntt_x4_avx512

/* Matrix expansion function name (static, installed via ML_KEM_SAMPLE_INIT_FN) */
#define ML_KEM_MATRIX_EXPAND matrix_expand_x4_avx512

/* Exported init function */
#define ML_KEM_SAMPLE_INIT_FN ossl_ml_kem_sample_init_avx512

#include "crypto/ml_kem_sample_template.h"
