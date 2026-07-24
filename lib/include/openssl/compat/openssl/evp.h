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
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * Compatibility shim for <openssl/evp.h> used by the vendored ML-DSA
 * (FIPS 204) sources.  Provides a header-only EVP digest interface that
 * understands SHAKE-128 and SHAKE-256, backed by the OpenSSL KECCAK1600_CTX
 * with the optimized keccak1600-x86_64 asm permutation.
 *
 * The x4 parallel SHAKE path (AVX512VL) is unchanged and continues to be
 * selected at run time via OPENSSL_ia32cap_P in the sampling layer.
 */

#ifndef IMB_ML_DSA_COMPAT_EVP_H
#define IMB_ML_DSA_COMPAT_EVP_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "internal/sha3.h" /* KECCAK1600_CTX, PROV_SHA3_METHOD, ossl_sha3_* */
#include "openssl_compat.h"

/* ML-DSA algorithm identifiers (match OpenSSL NID values, FIPS 204). */
#ifndef EVP_PKEY_ML_DSA_44
#define EVP_PKEY_ML_DSA_44 1457
#endif
#ifndef EVP_PKEY_ML_DSA_65
#define EVP_PKEY_ML_DSA_65 1458
#endif
#ifndef EVP_PKEY_ML_DSA_87
#define EVP_PKEY_ML_DSA_87 1459
#endif

/* ML-KEM algorithm identifiers (match OpenSSL NID values, FIPS 203). */
#ifndef NID_ML_KEM_512
#define NID_ML_KEM_512 1454
#endif
#ifndef NID_ML_KEM_768
#define NID_ML_KEM_768 1455
#endif
#ifndef NID_ML_KEM_1024
#define NID_ML_KEM_1024 1456
#endif

typedef struct {
        int rate;    /* block size in bytes: 168 (SHAKE-128) or 136 (SHAKE-256) */
        int md_size; /* nominal output bytes: 16 or 32 */
        int bitlen;  /* security parameter: 128 or 256 */
        uint8_t suffix;
        const char *name;
} EVP_MD;

typedef struct {
        const EVP_MD *md;
        KECCAK1600_CTX sctx;
} EVP_MD_CTX;

typedef void OSSL_LIB_CTX;
typedef void ENGINE;

static EVP_MD imb_evp_shake128 = { 168, 16, 128, 0x1F, "SHAKE-128" };
static EVP_MD imb_evp_shake256 = { 136, 32, 256, 0x1F, "SHAKE-256" };
/* SHA3-256/512 are used by ML-KEM for G(), H() and J(); pad=0x06 (FIPS 202). */
static EVP_MD imb_evp_sha3_256 = { 136, 32, 256, 0x06, "SHA3-256" };
static EVP_MD imb_evp_sha3_512 = { 72, 64, 512, 0x06, "SHA3-512" };

static ossl_inline ossl_unused EVP_MD *
EVP_MD_fetch(OSSL_LIB_CTX *c, const char *name, const char *propq)
{
        (void) c;
        (void) propq;
        if (name != NULL && (strcmp(name, "SHAKE-128") == 0 || strcmp(name, "SHAKE128") == 0))
                return &imb_evp_shake128;
        if (name != NULL && (strcmp(name, "SHAKE-256") == 0 || strcmp(name, "SHAKE256") == 0))
                return &imb_evp_shake256;
        if (name != NULL && (strcmp(name, "SHA3-256") == 0 || strcmp(name, "SHA3_256") == 0))
                return &imb_evp_sha3_256;
        if (name != NULL && (strcmp(name, "SHA3-512") == 0 || strcmp(name, "SHA3_512") == 0))
                return &imb_evp_sha3_512;
        return NULL;
}

static ossl_inline ossl_unused int
EVP_MD_up_ref(EVP_MD *md)
{
        (void) md;
        return 1;
}

static ossl_inline ossl_unused void
EVP_MD_free(EVP_MD *md)
{
        (void) md;
}

static ossl_inline ossl_unused int
EVP_MD_get_size(const EVP_MD *md)
{
        return md != NULL ? md->md_size : 0;
}

static ossl_inline ossl_unused const EVP_MD *
EVP_MD_CTX_get0_md(const EVP_MD_CTX *ctx)
{
        return ctx != NULL ? ctx->md : NULL;
}

static ossl_inline ossl_unused int
EVP_MD_xof(const EVP_MD *md)
{
        /* both SHAKE-128 and SHAKE-256 are XOFs */
        (void) md;
        return 1;
}

static ossl_inline ossl_unused EVP_MD_CTX *
EVP_MD_CTX_new(void)
{
        return (EVP_MD_CTX *) calloc(1, sizeof(EVP_MD_CTX));
}

static ossl_inline ossl_unused void
EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
        if (ctx != NULL) {
                OPENSSL_cleanse(ctx, sizeof(*ctx));
                free(ctx);
        }
}

static ossl_inline ossl_unused int
EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *md, const OSSL_PARAM *p)
{
        /**
         * ossl_sha3_init sets block_size, md_size, pad, and zeros xof_state/bufsz
         * but does NOT populate ctx->sctx.meth.  Set the x86_64 generic vtable
         * entries explicitly so ossl_sha3_absorb / ossl_sha3_squeeze dispatch
         * correctly without needing the full ossl_shake256_new() allocator path.
         */
        static const PROV_SHA3_METHOD shake_meth = {
                ossl_sha3_absorb_default,
                ossl_sha3_final_default,
                ossl_shake_squeeze_default,
        };
        (void) p;
        if (ctx == NULL || md == NULL)
                return 0;
        ctx->md = md;
        if (!ossl_sha3_init(&ctx->sctx, (unsigned char) md->suffix, (size_t) md->bitlen))
                return 1;
        ctx->sctx.meth = shake_meth;
        return 1;
}

static ossl_inline ossl_unused int
EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *e)
{
        (void) e;
        return EVP_DigestInit_ex2(ctx, md, NULL);
}

static ossl_inline ossl_unused int
EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t len)
{
        if (ctx == NULL)
                return 0;
        return ossl_sha3_absorb(&ctx->sctx, (const unsigned char *) data, len);
}

static ossl_inline ossl_unused int
EVP_DigestSqueeze(EVP_MD_CTX *ctx, uint8_t *out, size_t len)
{
        if (ctx == NULL)
                return 0;
        return ossl_sha3_squeeze(&ctx->sctx, out, len);
}

static ossl_inline ossl_unused int
EVP_DigestFinalXOF(EVP_MD_CTX *ctx, uint8_t *out, size_t len)
{
        return EVP_DigestSqueeze(ctx, out, len);
}

/**
 * Fixed-length digest finalisation (SHA3-256/SHA3-512), used by ML-KEM for
 * G(), H() and the pubkey-hash / implicit-rejection derivations.
 */
static ossl_inline ossl_unused int
EVP_DigestFinal_ex(EVP_MD_CTX *ctx, uint8_t *out, unsigned int *outlen)
{
        size_t sz;

        if (ctx == NULL || ctx->md == NULL)
                return 0;

        sz = (size_t) ctx->md->md_size;
        if (!ossl_sha3_final(&ctx->sctx, out, sz))
                return 0;

        if (outlen != NULL)
                *outlen = (unsigned int) sz;
        return 1;
}

#endif /* IMB_ML_DSA_COMPAT_EVP_H */
