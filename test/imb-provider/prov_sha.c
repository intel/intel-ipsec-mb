/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
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

/* ====================================================================
 * SHA3 fixed-output digest implementations (SHA3-224/256/384/512)
 * ==================================================================== */

#define PROV_SHA3_NEW_CTX(variant, hashalg, blksize, dgstsize)                                     \
        static OSSL_FUNC_digest_newctx_fn prov_sha3_##variant##_newctx;                            \
        static void *prov_sha3_##variant##_newctx(void *provctx)                                   \
        {                                                                                          \
                ALG_CTX *ctx = prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;            \
                if (ctx == NULL)                                                                   \
                        return NULL;                                                               \
                ctx->block_size = blksize;                                                         \
                ctx->hash_alg = hashalg;                                                           \
                ctx->md_size = dgstsize;                                                           \
                return ctx;                                                                        \
        }

#define PROV_SHA3_FUNC_COMMON(variant, blksize, dgstsize, flags)                                   \
        PROV_FUNC_SHA_GET_PARAM(sha3_##variant, blksize, dgstsize, flags)                          \
        const OSSL_DISPATCH prov_sha3_##variant##_functions[] = {                                  \
                { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) prov_sha3_##variant##_newctx },        \
                { OSSL_FUNC_DIGEST_INIT, (void (*)(void)) prov_sha_init },                         \
                { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) prov_sha_update },                     \
                { OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) prov_sha_final },                       \
                { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) prov_sha_freectx },                   \
                { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void)) prov_sha_dupctx },                     \
                { OSSL_FUNC_DIGEST_GET_PARAMS,                                                     \
                  (void (*)(void)) prov_sha3_##variant##_get_params },                             \
                { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                                \
                  (void (*)(void)) prov_sha_digest_default_gettable_params },                      \
                { 0, NULL }                                                                        \
        };

#define PROVIDER_SHA3_MB_IMPLEMENTION(variant, hashalg, blksize, dgstsize)                         \
        PROV_SHA3_NEW_CTX(variant, hashalg, blksize, dgstsize)                                     \
        PROV_SHA3_FUNC_COMMON(variant, blksize, dgstsize, SHA_FLAGS)

/* prov_sha3_224_functions */
PROVIDER_SHA3_MB_IMPLEMENTION(224, IMB_AUTH_SHA3_224, PROV_SHA3_224_BLOCK_SIZE,
                              IMB_SHA3_224_DIGEST_SIZE_IN_BYTES)
/* prov_sha3_256_functions */
PROVIDER_SHA3_MB_IMPLEMENTION(256, IMB_AUTH_SHA3_256, PROV_SHA3_256_BLOCK_SIZE,
                              IMB_SHA3_256_DIGEST_SIZE_IN_BYTES)
/* prov_sha3_384_functions */
PROVIDER_SHA3_MB_IMPLEMENTION(384, IMB_AUTH_SHA3_384, PROV_SHA3_384_BLOCK_SIZE,
                              IMB_SHA3_384_DIGEST_SIZE_IN_BYTES)
/* prov_sha3_512_functions */
PROVIDER_SHA3_MB_IMPLEMENTION(512, IMB_AUTH_SHA3_512, PROV_SHA3_512_BLOCK_SIZE,
                              IMB_SHA3_512_DIGEST_SIZE_IN_BYTES)

/* ====================================================================
 * SHAKE implementations
 * ==================================================================== */

/*
 * Maximum XOFLEN accepted from caller-supplied parameters.
 * Prevents unbounded heap allocations from untrusted input.
 * 64 KiB covers all known practical SHAKE use cases.
 */
#define SHAKE_MAX_XOFLEN (64u * 1024u)

static const OSSL_PARAM prov_shake_settable_ctx_params_list[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_XOFLEN, NULL), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_shake_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
        return prov_shake_settable_ctx_params_list;
}

static int
prov_shake_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        const OSSL_PARAM *p;

        if (params == NULL)
                return 1;

        p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
        if (p != NULL) {
                size_t xoflen = 0;

                if (!OSSL_PARAM_get_size_t(p, &xoflen) || xoflen == 0)
                        return 0;

                if (xoflen > SHAKE_MAX_XOFLEN) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_SIZE);
                        return 0;
                }

                /* Release any previously allocated XOF buffer */
                if (ctx->xof_buf != NULL) {
                        if (ctx->md_size > 0)
                                OPENSSL_cleanse(ctx->xof_buf, ctx->md_size);
                        OPENSSL_free(ctx->xof_buf);
                        ctx->xof_buf = NULL;
                }

                /* Allocate a new buffer only when output exceeds the static
                 * auths[] array; otherwise the existing 64-byte slot is used. */
                if (xoflen > sizeof(ctx->auths)) {
                        ctx->xof_buf = OPENSSL_malloc(xoflen);
                        if (ctx->xof_buf == NULL)
                                return 0;
                }
                ctx->md_size = xoflen;
        }
        return 1;
}

/* SHAKE-specific dupctx: deep-copy xof_buf when present */
static void *
prov_shake_dupctx(void *vctx)
{
        ALG_CTX *in = (ALG_CTX *) vctx;

        if (in == NULL)
                return NULL;

        ALG_CTX *ret = prov_is_running() ? OPENSSL_malloc(sizeof(*ret)) : NULL;
        if (ret == NULL)
                return NULL;

        *ret = *in;

        if (in->xof_buf != NULL) {
                ret->xof_buf = OPENSSL_malloc(in->md_size);
                if (ret->xof_buf == NULL) {
                        OPENSSL_free(ret);
                        return NULL;
                }
                memcpy(ret->xof_buf, in->xof_buf, in->md_size);
        }
        return ret;
}

#define PROV_SHAKE_NEW_CTX(bits, hashalg, blksize, default_dgstsize)                               \
        static OSSL_FUNC_digest_newctx_fn prov_shake##bits##_newctx;                               \
        static void *prov_shake##bits##_newctx(void *provctx)                                      \
        {                                                                                          \
                ALG_CTX *ctx = prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;            \
                if (ctx == NULL)                                                                   \
                        return NULL;                                                               \
                ctx->block_size = blksize;                                                         \
                ctx->hash_alg = hashalg;                                                           \
                ctx->md_size = default_dgstsize;                                                   \
                return ctx;                                                                        \
        }

#define PROV_SHAKE_FUNC_COMMON(bits, blksize, default_dgstsize, flags)                             \
        PROV_FUNC_SHA_GET_PARAM(shake##bits, blksize, default_dgstsize, flags)                     \
        const OSSL_DISPATCH prov_shake##bits##_functions[] = {                                     \
                { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void)) prov_shake##bits##_newctx },           \
                { OSSL_FUNC_DIGEST_INIT, (void (*)(void)) prov_sha_init },                         \
                { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) prov_sha_update },                     \
                { OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) prov_sha_final },                       \
                { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) prov_sha_freectx },                   \
                { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void)) prov_shake_dupctx },                   \
                { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) prov_shake##bits##_get_params },   \
                { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,                                                \
                  (void (*)(void)) prov_sha_digest_default_gettable_params },                      \
                { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void)) prov_shake_set_ctx_params },   \
                { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,                                            \
                  (void (*)(void)) prov_shake_settable_ctx_params },                               \
                { 0, NULL }                                                                        \
        };

#define PROVIDER_SHAKE_MB_IMPLEMENTION(bits, hashalg, blksize, default_dgstsize)                   \
        PROV_SHAKE_NEW_CTX(bits, hashalg, blksize, default_dgstsize)                               \
        PROV_SHAKE_FUNC_COMMON(bits, blksize, default_dgstsize,                                    \
                               PROV_DIGEST_FLAG_XOF | PROV_DIGEST_FLAG_ALGID_ABSENT)

/* prov_shake128_functions  (default output = 32 bytes) */
PROVIDER_SHAKE_MB_IMPLEMENTION(128, IMB_AUTH_SHAKE128, PROV_SHAKE128_BLOCK_SIZE,
                               PROV_SHAKE128_DEFAULT_DIGEST_SIZE)
/* prov_shake256_functions  (default output = 64 bytes) */
PROVIDER_SHAKE_MB_IMPLEMENTION(256, IMB_AUTH_SHAKE256, PROV_SHAKE256_BLOCK_SIZE,
                               PROV_SHAKE256_DEFAULT_DIGEST_SIZE)
