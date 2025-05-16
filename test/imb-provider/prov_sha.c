/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

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

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <intel-ipsec-mb.h>

#include "prov_sw_sha.h"
#include "prov_provider.h"
#include "prov_evp.h"
#include "e_prov.h"

static int
prov_sha_init(void *vctx, ossl_unused const OSSL_PARAM params[])
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (!prov_is_running())
                return 0;
        if (!sha_async_init(ctx))
                return 0;

        return 1;
}

static int
prov_sha_update(void *vctx, const unsigned char *inp, size_t len)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (!prov_is_running())
                return 0;

        return sha_async_update(ctx, inp, len);
}

static int
prov_sha_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
        int ret = 1;
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (!prov_is_running())
                return 0;

        if (outl != NULL && outsz >= ctx->md_size) {
                ret = sha_async_final(ctx, out);
                *outl = ctx->md_size;
        }
        return ret;
}

static const OSSL_PARAM prov_sha_default_known_gettable_params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL), OSSL_PARAM_END
};

const OSSL_PARAM *
prov_sha_digest_default_gettable_params()
{
        return prov_sha_default_known_gettable_params;
}

int
prov_sha_digest_default_get_params(OSSL_PARAM params[], size_t blksz, size_t paramsz,
                                   unsigned long flags)
{
        OSSL_PARAM *p = NULL;

        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_XOF) != 0))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_ALGID_ABSENT) != 0))
                return 0;
        return 1;
}

static void *
prov_sha_dupctx(void *ctx)
{
        ALG_CTX *in = (ALG_CTX *) ctx;
        if (in == NULL)
                return NULL;
        ALG_CTX *ret = prov_is_running() ? OPENSSL_malloc(sizeof(*ret)) : NULL;
        if (ret != NULL)
                *ret = *in;
        return ret;
}

static void
prov_sha_freectx(void *vctx)
{
        sha_async_cleanup((ALG_CTX *) vctx);
}

#define PROV_FUNC_SHA_GET_PARAM(name, blksize, dgstsize, flags)                                    \
        static OSSL_FUNC_digest_get_params_fn prov_##name##_get_params;                            \
        static int prov_##name##_get_params(OSSL_PARAM params[])                                   \
        {                                                                                          \
                return prov_sha_digest_default_get_params(params, blksize, dgstsize, flags);       \
        }

#define PROV_SHA_NEW_CTX(name, bitlen, hashalg, blksize, dgstsize)                                 \
        static OSSL_FUNC_digest_newctx_fn prov_##name##_newctx;                                    \
        static void *prov_##name##_newctx(void *provctx)                                           \
        {                                                                                          \
                ALG_CTX *ctx = prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;            \
                if (ctx == NULL)                                                                   \
                        return NULL;                                                               \
                ctx->block_size = blksize;                                                         \
                ctx->hash_alg = hashalg;                                                           \
                ctx->md_size = dgstsize;                                                           \
                return ctx;                                                                        \
        }

#define PROV_FUNC_SHA_COMMON(name, blksize, dgstsize, flags)                                       \
        PROV_FUNC_SHA_GET_PARAM(name, blksize, dgstsize, flags)                                    \
        const OSSL_DISPATCH prov_##name##_functions[] = {                                          \
                { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) prov_##name##_newctx },                \
                { OSSL_FUNC_DIGEST_INIT, (void (*)(void)) prov_sha_init },                         \
                { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) prov_sha_update },                     \
                { OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) prov_sha_final },                       \
                { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) prov_sha_freectx },                   \
                { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void)) prov_sha_dupctx },                     \
                { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) prov_##name##_get_params },        \
                { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                                \
                  (void (*)(void)) prov_sha_digest_default_gettable_params },                      \
                { 0, NULL }                                                                        \
        };

#define PROVIDER_SHA_MB_IMPLEMENTION(bitlen, blksize, hashalg, dgstsize, flags)                    \
        PROV_SHA_NEW_CTX(sha##bitlen, bitlen, hashalg, blksize, dgstsize)                          \
        PROV_FUNC_SHA_COMMON(sha##bitlen, bitlen, blksize, dgstsize)

/* prov_sha1_functions */
PROVIDER_SHA_MB_IMPLEMENTION(1, IMB_SHA1_BLOCK_SIZE, IMB_AUTH_SHA_1, IMB_SHA1_DIGEST_SIZE_IN_BYTES,
                             SHA_FLAGS)
/* prov_sha224_functions */
PROVIDER_SHA_MB_IMPLEMENTION(224, IMB_SHA_224_BLOCK_SIZE, IMB_AUTH_SHA_224,
                             IMB_SHA224_DIGEST_SIZE_IN_BYTES, SHA_FLAGS)
/* prov_sha256_functions */
PROVIDER_SHA_MB_IMPLEMENTION(256, IMB_SHA_256_BLOCK_SIZE, IMB_AUTH_SHA_256,
                             IMB_SHA256_DIGEST_SIZE_IN_BYTES, SHA_FLAGS)
/* prov_sha384_functions */
PROVIDER_SHA_MB_IMPLEMENTION(384, IMB_SHA_384_BLOCK_SIZE, IMB_AUTH_SHA_384,
                             IMB_SHA384_DIGEST_SIZE_IN_BYTES, SHA_FLAGS)
/* prov_sha512_functions */
PROVIDER_SHA_MB_IMPLEMENTION(512, IMB_SHA_512_BLOCK_SIZE, IMB_AUTH_SHA_512,
                             IMB_SHA512_DIGEST_SIZE_IN_BYTES, SHA_FLAGS)
