/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
**/

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include "prov_sw_hmac_sha.h"
#include "prov_provider.h"
#include "prov_evp.h"
#include "e_prov.h"
#include <intel-ipsec-mb.h>

int
prov_hmac_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int
prov_hmac_sha_init(void *vctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[])
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (!prov_is_running())
                return 0;

        if (!prov_hmac_set_ctx_params(ctx, params))
                return 0;

        if (key != NULL) {
                unsigned char *tmp;

                if (keylen == 0)
                        return 0;

                tmp = OPENSSL_memdup(key, keylen);
                if (tmp == NULL)
                        return 0;

                OPENSSL_clear_free(ctx->key, ctx->keylen);
                ctx->key = tmp;
                ctx->keylen = keylen;
        }

        return hmac_sha_async_init(ctx);
}

static int
prov_hmac_sha_update(void *vctx, const unsigned char *inp, const size_t len)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (!prov_is_running())
                return 0;

        if (inp == NULL || len == 0) {
                fprintf(stderr, "Input data is null or length is zero\n");
                return 0;
        }

        return hmac_sha_async_update(ctx, inp, len);
}

static int
prov_hmac_sha_final(void *vctx, unsigned char *out, size_t *outl, const size_t outsz)
{
        int ret = 1;
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (!prov_is_running())
                return 0;

        if (outl != NULL && outsz >= ctx->md_size) {
                ret = hmac_sha_async_final(ctx, out);
                *outl = ctx->md_size;
        }

        return ret;
}

static const OSSL_PARAM prov_hmac_sha_known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_hmac_sha_gettable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
        return prov_hmac_sha_known_gettable_ctx_params;
}

static int
prov_hmac_sha_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->md_size))
                return 0;

        p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->block_size))
                return 0;

        return 1;
}

static void *
prov_hmac_sha_dupctx(void *ctx)
{
        ALG_CTX *src = (ALG_CTX *) ctx;
        ALG_CTX *dst;

        if (src == NULL || !prov_is_running())
                return NULL;

        dst = OPENSSL_memdup(src, sizeof(*src));
        if (dst == NULL)
                return NULL;

        /*
         * The key is owned by the context, so it has to be duplicated - both
         * copies free it. Everything else the MAC path uses (hash_alg, md_size,
         * block_size, auths) is by value and came across with the memdup.
         */
        dst->key = NULL;
        dst->keylen = 0;
        if (src->key != NULL && src->keylen > 0) {
                dst->key = OPENSSL_memdup(src->key, src->keylen);
                if (dst->key == NULL) {
                        OPENSSL_clear_free(dst, sizeof(*dst));
                        return NULL;
                }
                dst->keylen = src->keylen;
        }

        /* The fetched EVP_MD is only consulted while parsing params, and
         * PROV_DIGEST owns its reference; do not share it with the copy. */
        memset(&dst->digest, 0, sizeof(dst->digest));

        /* Per-operation state that must not be shared. */
        dst->mac_ctx = NULL;
        dst->imb_job = NULL;

        return dst;
}

/*
 * The SHA3 rates have no macro in intel-ipsec-mb.h, unlike the SHA2 block
 * sizes, so they are spelled out here: 1600 bits of state less twice the
 * digest length, in bytes.
 */
#define PROV_SHA3_224_BLOCK_SIZE 144
#define PROV_SHA3_256_BLOCK_SIZE 136
#define PROV_SHA3_384_BLOCK_SIZE 104
#define PROV_SHA3_512_BLOCK_SIZE 72

static const struct {
        const char *name;
        IMB_HASH_ALG hash_alg;
        size_t md_size;
        size_t block_size;
} prov_hmac_algs[] = {
        { "SHA1", IMB_AUTH_HMAC_SHA_1, IMB_SHA1_DIGEST_SIZE_IN_BYTES, IMB_SHA1_BLOCK_SIZE },
        { "SHA2-224", IMB_AUTH_HMAC_SHA_224, IMB_SHA224_DIGEST_SIZE_IN_BYTES,
          IMB_SHA_224_BLOCK_SIZE },
        { "SHA2-256", IMB_AUTH_HMAC_SHA_256, IMB_SHA256_DIGEST_SIZE_IN_BYTES,
          IMB_SHA_256_BLOCK_SIZE },
        { "SHA2-384", IMB_AUTH_HMAC_SHA_384, IMB_SHA384_DIGEST_SIZE_IN_BYTES,
          IMB_SHA_384_BLOCK_SIZE },
        { "SHA2-512", IMB_AUTH_HMAC_SHA_512, IMB_SHA512_DIGEST_SIZE_IN_BYTES,
          IMB_SHA_512_BLOCK_SIZE },
        { "SHA3-224", IMB_AUTH_HMAC_SHA3_224, IMB_SHA3_224_DIGEST_SIZE_IN_BYTES,
          PROV_SHA3_224_BLOCK_SIZE },
        { "SHA3-256", IMB_AUTH_HMAC_SHA3_256, IMB_SHA3_256_DIGEST_SIZE_IN_BYTES,
          PROV_SHA3_256_BLOCK_SIZE },
        { "SHA3-384", IMB_AUTH_HMAC_SHA3_384, IMB_SHA3_384_DIGEST_SIZE_IN_BYTES,
          PROV_SHA3_384_BLOCK_SIZE },
        { "SHA3-512", IMB_AUTH_HMAC_SHA3_512, IMB_SHA3_512_DIGEST_SIZE_IN_BYTES,
          PROV_SHA3_512_BLOCK_SIZE },
};

/*
 * set_sha_ctx_params - select the ipsec-mb algorithm for a fetched digest.
 *
 * Matching is done with EVP_MD_is_a() on the fetched EVP_MD rather than by
 * comparing the caller's string, so every OpenSSL alias for a digest resolves
 * to the same algorithm - "SHA2-256", "SHA-256" and "sha256" all name the one
 * that a plain strcmp() against a single short name would miss.
 */
static int
set_sha_ctx_params(ALG_CTX *ctx, const EVP_MD *md)
{
        for (size_t i = 0; i < sizeof(prov_hmac_algs) / sizeof(prov_hmac_algs[0]); i++) {
                if (!EVP_MD_is_a(md, prov_hmac_algs[i].name))
                        continue;

                ctx->hash_alg = prov_hmac_algs[i].hash_alg;
                ctx->md_size = prov_hmac_algs[i].md_size;
                ctx->block_size = prov_hmac_algs[i].block_size;
                return 1;
        }

        return 0;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
        OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_NOINIT, NULL),
        OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_ONESHOT, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, NULL),
        OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_hmac_settable_ctx_params()
{
        return known_settable_ctx_params;
}

static const EVP_MD *
prov_prov_digest_fetch(PROV_DIGEST *pd, OSSL_LIB_CTX *libctx, const char *mdname,
                       const char *propquery)
{
        EVP_MD_free(pd->alloc_md);
        pd->md = pd->alloc_md = EVP_MD_fetch(libctx, mdname, propquery);

        return pd->md;
}

static int
load_common(const OSSL_PARAM params[], const char **propquery, ENGINE **engine)
{
        const OSSL_PARAM *p;

        *propquery = NULL;
        p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES);
        if (p != NULL) {
                if (p->data_type != OSSL_PARAM_UTF8_STRING)
                        return 0;
                *propquery = p->data;
        }

        *engine = NULL;

        return 1;
}

static int
prov_hmac_common_set_ctx_params(ALG_CTX *actx, const OSSL_PARAM params[])
{
        const OSSL_PARAM *p;
        const char *propquery;
        PROV_DIGEST *pd = &actx->digest;
        OSSL_LIB_CTX *ctx = actx->libctx;

        if (params == NULL)
                return 1;

        if (!load_common(params, &propquery, &pd->engine))
                return 0;

        p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
        if (p == NULL)
                return 1;
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
                return 0;

        ERR_set_mark();
        prov_prov_digest_fetch(pd, ctx, p->data, propquery);

        if (pd->md != NULL)
                ERR_pop_to_mark();
        else
                ERR_clear_last_mark();
        return pd->md != NULL;
}

int
prov_hmac_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
        const OSSL_PARAM *p;
        ALG_CTX *hctx = vctx;

        if (params == NULL)
                return 1;

        if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL) {
                unsigned char *key;

                if (p->data_type != OSSL_PARAM_OCTET_STRING || p->data == NULL ||
                    p->data_size == 0) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                        return 0;
                }

                key = OPENSSL_memdup(p->data, p->data_size);
                if (key == NULL)
                        return 0;

                /* A second set of params must replace the key, not leak the
                 * first one. */
                OPENSSL_clear_free(hctx->key, hctx->keylen);
                hctx->key = key;
                hctx->keylen = p->data_size;
        }

        if ((p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST)) != NULL) {
                if (!prov_hmac_common_set_ctx_params(hctx, params))
                        return 0;

                if (!set_sha_ctx_params(hctx, hctx->digest.md)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                        return 0;
                }
        }

        return 1;
}

static void
prov_hmac_sha_freectx(void *vctx)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (ctx == NULL)
                return;

        /* Released here rather than in hmac_sha_async_cleanup(), which clears
         * and frees the context itself and so cannot see these afterwards. */
        OPENSSL_clear_free(ctx->key, ctx->keylen);
        ctx->key = NULL;
        ctx->keylen = 0;
        EVP_MD_free(ctx->digest.alloc_md);
        memset(&ctx->digest, 0, sizeof(ctx->digest));

        hmac_sha_async_cleanup(ctx);
}

static ALG_CTX *
prov_hmac_sha_newctx(void *provctx)
{
        ALG_CTX *ctx = prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;

        if (ctx == NULL)
                return NULL;

        /* Digests are fetched against this; the provider's own context owns it,
         * so it must not be replaced (and leaked) on every set_ctx_params(). */
        ctx->provctx = provctx;
        ctx->libctx = prov_libctx_of(provctx);

        return ctx;
}

const OSSL_DISPATCH prov_hmac_sha_functions[] = {
        { OSSL_FUNC_MAC_NEWCTX, (void (*)(void)) prov_hmac_sha_newctx },
        { OSSL_FUNC_MAC_DUPCTX, (void (*)(void)) prov_hmac_sha_dupctx },
        { OSSL_FUNC_MAC_FREECTX, (void (*)(void)) prov_hmac_sha_freectx },
        { OSSL_FUNC_MAC_INIT, (void (*)(void)) prov_hmac_sha_init },
        { OSSL_FUNC_MAC_UPDATE, (void (*)(void)) prov_hmac_sha_update },
        { OSSL_FUNC_MAC_FINAL, (void (*)(void)) prov_hmac_sha_final },
        { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void)) prov_hmac_sha_gettable_ctx_params },
        { OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void)) prov_hmac_sha_get_ctx_params },
        { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void)) prov_hmac_settable_ctx_params },
        { OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void)) prov_hmac_set_ctx_params },
        { 0, NULL }
};