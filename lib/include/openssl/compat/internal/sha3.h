/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

      * Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
      * Neither the name of Intel Corporation nor the names of its contributors
        may be used to endorse or promote products derived from this software
        without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

/**
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * Compatibility shim for "internal/sha3.h" used by the vendored ML-DSA
 * (FIPS 204) sources.  Provides the full KECCAK1600_CTX context (matching
 * OpenSSL's struct keccak_st), the PROV_SHA3_METHOD vtable, and all
 * ossl_sha3_* / SHA3_absorb / SHA3_squeeze declarations.  The x4 parallel
 * SHAKE API for AVX512VL is also declared here.
 *
 * The macros, struct keccak_st layout, and function declarations in this
 * file are copied near-verbatim from OpenSSL's "internal/sha3.h" and
 * therefore carry the OpenSSL copyright/license notice above alongside the
 * Intel one.
 */

#ifndef IMB_ML_DSA_COMPAT_INTERNAL_SHA3_H
#define IMB_ML_DSA_COMPAT_INTERNAL_SHA3_H

#include <stddef.h>
#include <stdint.h>

#define KECCAK1600_WIDTH             1600
#define SHA3_MDSIZE(bitlen)          ((bitlen) / 8)
#define SHA3_BLOCKSIZE(bitlen)       ((KECCAK1600_WIDTH - (bitlen) * 2) / 8)
#define CSHAKE_KECCAK_MDSIZE(bitlen) (2 * ((bitlen) / 8))

/* XOF state machine values (must match OpenSSL's sha3.c) */
#define XOF_STATE_INIT    0
#define XOF_STATE_ABSORB  1
#define XOF_STATE_FINAL   2
#define XOF_STATE_SQUEEZE 3

/* Forward declarations for the vtable function types */
typedef struct keccak_st KECCAK1600_CTX;
typedef size_t(sha3_absorb_fn)(KECCAK1600_CTX *ctx, const unsigned char *in, size_t inlen);
typedef int(sha3_final_fn)(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen);
typedef int(sha3_squeeze_fn)(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen);

typedef struct prov_sha3_meth_st {
        sha3_absorb_fn *absorb;
        sha3_final_fn *final;
        sha3_squeeze_fn *squeeze;
} PROV_SHA3_METHOD;

/* Single-buffer Keccak-1600 context (matches OpenSSL struct keccak_st) */
struct keccak_st {
        uint64_t A[5][5];
        unsigned char buf[KECCAK1600_WIDTH / 8 - 32]; /* 168 bytes, covers SHAKE-128 rate */
        size_t block_size;                            /* cached rate in bytes */
        size_t md_size;                               /* output length */
        size_t bufsz;                                 /* buffered bytes */
        unsigned char pad;                            /* domain-separation suffix */
        PROV_SHA3_METHOD meth;                        /* platform-specific dispatch */
        int xof_state;                                /* XOF_STATE_* */
};

/* Low-level permutation absorb/squeeze (provided by keccak1600-x86_64 asm) */
size_t
SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len, size_t r);
void
SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r, int next);

/* Single-buffer SHA3/SHAKE API (provided by sha3_ossl.c) */
void
ossl_sha3_reset(KECCAK1600_CTX *ctx);
int
ossl_sha3_init(KECCAK1600_CTX *ctx, unsigned char pad, size_t bitlen);
int
ossl_keccak_init(KECCAK1600_CTX *ctx, unsigned char pad, size_t bitlen, size_t mdlen);
int
ossl_sha3_absorb(KECCAK1600_CTX *ctx, const unsigned char *in, size_t len);
int
ossl_sha3_final(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen);
int
ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen);

/* Default (generic x86_64) implementations — called directly by the EVP shim */
size_t
ossl_sha3_absorb_default(KECCAK1600_CTX *ctx, const unsigned char *inp, size_t len);
int
ossl_sha3_final_default(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen);
int
ossl_shake_squeeze_default(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen);

/* Allocates and initialises a SHAKE-256 context (used by ML-KEM) */
KECCAK1600_CTX *
ossl_shake256_new(void);

/* Multi-buffer (x4) Keccak-f[1600] context and API */
#if defined(KECCAK1600_ASM) &&                                                                     \
        (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) &&      \
        !defined(OPENSSL_NO_ASM)

/* Runtime capability check for AVX512VL */
int
SHA3_avx512vl_capable(void);

/* Context for 4-way parallel SHAKE operations */
typedef struct {
        /* 4 interleaved Keccak states (800 bytes)
           plus 8 bytes to store the number of
           already absorbed or not yet squeezed bytes */
        uint64_t A[(25 * 4) + 1];
        size_t rate;        /* Rate in bytes: 168 (SHAKE-128) or 136 (SHAKE-256) */
        unsigned finalized; /* Has finalize been called? 0=no, 1=yes */
} KECCAK1600_X4_AVX512VL_CTX;

/* SHAKE-128 x4 incremental API */
void
ossl_sha3_shake128_x4_inc_init_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx);

void
ossl_sha3_shake128_x4_inc_absorb_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx, const void *in0,
                                          const void *in1, const void *in2, const void *in3,
                                          size_t inlen);

void
ossl_sha3_shake128_x4_inc_cleanup_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx);

void
ossl_sha3_shake128_x4_inc_squeeze_avx512vl(void *out0, void *out1, void *out2, void *out3,
                                           size_t outlen, KECCAK1600_X4_AVX512VL_CTX *ctx);

/* SHAKE-256 x4 incremental API */
void
ossl_sha3_shake256_x4_inc_init_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx);

void
ossl_sha3_shake256_x4_inc_absorb_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx, const void *in0,
                                          const void *in1, const void *in2, const void *in3,
                                          size_t inlen);

void
ossl_sha3_shake256_x4_inc_cleanup_avx512vl(KECCAK1600_X4_AVX512VL_CTX *ctx);

void
ossl_sha3_shake256_x4_inc_squeeze_avx512vl(void *out0, void *out1, void *out2, void *out3,
                                           size_t outlen, KECCAK1600_X4_AVX512VL_CTX *ctx);

/* Single-call SHAKE x4 APIs (wrapper functions) */
void
ossl_sha3_shake128_x4_avx512vl(void *out0, void *out1, void *out2, void *out3, size_t outlen,
                               const void *in0, const void *in1, const void *in2, const void *in3,
                               size_t inlen);

void
ossl_sha3_shake256_x4_avx512vl(void *out0, void *out1, void *out2, void *out3, size_t outlen,
                               const void *in0, const void *in1, const void *in2, const void *in3,
                               size_t inlen);

#endif /* KECCAK1600_ASM && x86_64 && !OPENSSL_NO_ASM */

#endif /* IMB_ML_DSA_COMPAT_INTERNAL_SHA3_H */
