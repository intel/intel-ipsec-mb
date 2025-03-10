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

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include "prov_sw_sha2.h"
#include "prov_provider.h"
#include "prov_evp.h"
#include "e_prov.h"

/*
 * Forward declaration of any unique methods implemented here. This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_FUNC_digest_init_fn prov_sha2_init;
static OSSL_FUNC_digest_update_fn prov_sha2_update;
static OSSL_FUNC_digest_final_fn prov_sha2_final;

static int
prov_sha2_init(void *vctx, ossl_unused const OSSL_PARAM params[])
{
        PROV_SHA2_CTX *ctx = (PROV_SHA2_CTX *) vctx;

        if (!prov_is_running())
                return 0;
        if (!mb_prov_SHA2_init(ctx)) {
                fprintf(stderr, "sha2 ctx init failed!\n");
                return 0;
        }
        return 1;
}

static int
prov_sha2_update(void *vctx, const unsigned char *inp, size_t len)
{
        PROV_SHA2_CTX *ctx = (PROV_SHA2_CTX *) vctx;

        if (!prov_is_running())
                return 0;

        return mb_prov_SHA2_update(ctx, inp, len);
}

static int
prov_sha2_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
        int ret = 1;
        PROV_SHA2_CTX *ctx = (PROV_SHA2_CTX *) vctx;

        if (!prov_is_running())
                return 0;

        *outl = ctx->md_size;
        if (outsz > 0) {
                ret = mb_prov_SHA2_final(ctx, out);
        }
        return ret;
}

static const OSSL_PARAM prov_sha2_default_known_gettable_params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL), OSSL_PARAM_END
};

const OSSL_PARAM *
prov_sha2_default_gettable_params(void *provctx)
{
        return prov_sha2_default_known_gettable_params;
}

static int
prov_sha2_default_get_params(OSSL_PARAM params[], size_t blksz, size_t paramsz, unsigned long flags)
{
        OSSL_PARAM *p = NULL;

        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_XOF) != 0)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_DIGEST_FLAG_ALGID_ABSENT) != 0)) {
                return 0;
        }
        return 1;
}

static void
set_ctx_md_type(PROV_SHA2_CTX *ctx, int bitlen)
{
        switch (bitlen) {
        case 224:
                ctx->md_type = NID_sha224;
                break;
        case 256:
                ctx->md_type = NID_sha256;
                break;
        case 384:
                ctx->md_type = NID_sha384;
                break;
        case 512:
                ctx->md_type = NID_sha512;
                break;
        }
}

#define PROV_DISPATCH_FUNC_SHA2_GET_PARAMS(name)                                                   \
        { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) prov_##name##_get_params },                \
        {                                                                                          \
                OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                                  \
                        (void (*)(void)) prov_sha2_default_gettable_params                         \
        }

#define PROV_FUNC_SHA2_GET_PARAM(name, blksize, dgstsize, flags)                                   \
        static OSSL_FUNC_digest_get_params_fn prov_##name##_get_params;                            \
        static int prov_##name##_get_params(OSSL_PARAM params[])                                   \
        {                                                                                          \
                return prov_sha2_default_get_params(params, blksize, dgstsize, flags);             \
        }

#define PROV_DISPATCH_FUNC_DIGEST_FREE_DUP(name, blksize)                                          \
        static void prov_##name##_freectx(void *vctx)                                              \
        {                                                                                          \
                PROV_SHA2_CTX *ctx = (PROV_SHA2_CTX *) vctx;                                       \
                                                                                                   \
                mb_prov_sha2_cleanup(ctx);                                                         \
        }                                                                                          \
        static void *prov_##name##_dupctx(void *ctx)                                               \
        {                                                                                          \
                PROV_SHA2_CTX *in = (PROV_SHA2_CTX *) ctx;                                         \
                PROV_SHA2_CTX *ret = prov_is_running() ? OPENSSL_malloc(sizeof(*ret)) : NULL;      \
                if (ret != NULL)                                                                   \
                        *ret = *in;                                                                \
                return ret;                                                                        \
        }

#define PROV_FUNC_SHA2_COMMON(name, bitlen, blksize, dgstsize, flags)                              \
        PROV_FUNC_SHA2_GET_PARAM(name, blksize, dgstsize, flags)                                   \
        PROV_DISPATCH_FUNC_DIGEST_FREE_DUP(name, blksize)                                          \
        const OSSL_DISPATCH prov_##name##_functions[] = {                                          \
                { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) prov_##name##_newctx },                \
                { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) prov_sha2_update },                    \
                { OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) prov_sha2_final },                      \
                { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) prov_##name##_freectx },              \
                { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void)) prov_##name##_dupctx },                \
                PROV_DISPATCH_FUNC_SHA2_GET_PARAMS(name)

#define PROV_FUNC_SHA2(name, bitlen, blksize, dgstsize, flags)                                     \
        PROV_FUNC_SHA2_COMMON(name, bitlen, blksize, dgstsize, flags),                             \
                { OSSL_FUNC_DIGEST_INIT, (void (*)(void)) prov_sha2_init },                        \
        {                                                                                          \
                0, NULL                                                                            \
        }                                                                                          \
        }                                                                                          \
        ;

#define SHA2_NEW_CTX(name, bitlen, blksize, dgstsize, pad_val, sha_name)                           \
        static OSSL_FUNC_digest_newctx_fn prov_##name##_newctx;                                    \
        static void *prov_##name##_newctx(void *provctx)                                           \
        {                                                                                          \
                PROV_SHA2_CTX *ctx = prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;      \
                                                                                                   \
                if (ctx == NULL)                                                                   \
                        return NULL;                                                               \
                                                                                                   \
                set_ctx_md_type(ctx, bitlen);                                                      \
                ctx->block_size = blksize;                                                         \
                ctx->md_size = dgstsize;                                                           \
                return ctx;                                                                        \
        }

#define PROV_PROVIDER_SHA2_IMPLEMENTION(bitlen, blksize, dgstsize, flags, sha_name)                \
        SHA2_NEW_CTX(sha##bitlen, bitlen, blksize, dgstsize, '\x06', sha_name)                     \
        PROV_FUNC_SHA2(sha##bitlen, bitlen, blksize, dgstsize, flags)

/* prov_sha224_functions */
PROV_PROVIDER_SHA2_IMPLEMENTION(224, PROV_SHA256_CBLOCK, PROV_SHA224_DIGEST_LENGTH, SHA2_FLAGS,
                                "SHA-224")
/* prov_sha256_functions */
PROV_PROVIDER_SHA2_IMPLEMENTION(256, PROV_SHA256_CBLOCK, PROV_SHA256_DIGEST_LENGTH, SHA2_FLAGS,
                                "SHA2-256")
/* prov_sha384_functions */
PROV_PROVIDER_SHA2_IMPLEMENTION(384, PROV_SHA512_CBLOCK, PROV_SHA384_DIGEST_LENGTH, SHA2_FLAGS,
                                "SHA-384")
/* prov_sha512_functions */
PROV_PROVIDER_SHA2_IMPLEMENTION(512, PROV_SHA512_CBLOCK, PROV_SHA512_DIGEST_LENGTH, SHA2_FLAGS,
                                "SHA-512")
