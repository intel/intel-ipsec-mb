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

static int
prov_hmac_sha_init(void *vctx, const OSSL_PARAM params[])
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (ctx->mac_ctx != NULL && ctx->key != NULL) {
                if (EVP_MAC_init(ctx->mac_ctx, ctx->key, ctx->keylen, params) != 1)
                        return 0;

                return hmac_sha_async_init(ctx);
        }

        return 0;
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

        *outl = ctx->md_size;
        if (outl != NULL && outsz >= ctx->md_size) {
                ret = hmac_sha_async_final(ctx, out);
                *outl = ctx->md_size;
        }

        return ret;
}

static const OSSL_PARAM prov_hmac_sha_default_known_gettable_params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL), OSSL_PARAM_END
};

static const OSSL_PARAM *
prov_hmac_sha_digest_default_gettable_params()
{
        return prov_hmac_sha_default_known_gettable_params;
}

static void *
prov_hmac_sha_dupctx(void *ctx)
{
        ALG_CTX *src_ctx = (ALG_CTX *) ctx;
        ALG_CTX *dst_ctx = OPENSSL_zalloc(sizeof(ALG_CTX));

        if (dst_ctx == NULL)
                return NULL;

        dst_ctx->mac_ctx = EVP_MAC_CTX_dup(src_ctx->mac_ctx);
        if (dst_ctx->mac_ctx == NULL) {
                OPENSSL_free(dst_ctx);
                return NULL;
        }

        return dst_ctx;
}

static void
set_sha_ctx_params(ALG_CTX *ctx, const int bitlen)
{
        switch (bitlen) {
        case 1:
                ctx->hash_alg = IMB_AUTH_HMAC_SHA_1;
                ctx->md_size = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
                break;
        case 224:
                ctx->hash_alg = IMB_AUTH_HMAC_SHA_224;
                ctx->md_size = IMB_SHA224_DIGEST_SIZE_IN_BYTES;
                break;
        case 256:
                ctx->hash_alg = IMB_AUTH_HMAC_SHA_256;
                ctx->md_size = IMB_SHA256_DIGEST_SIZE_IN_BYTES;
                break;
        case 384:
                ctx->hash_alg = IMB_AUTH_HMAC_SHA_384;
                ctx->md_size = IMB_SHA384_DIGEST_SIZE_IN_BYTES;
                break;
        case 512:
                ctx->hash_alg = IMB_AUTH_HMAC_SHA_512;
                ctx->md_size = IMB_SHA512_DIGEST_SIZE_IN_BYTES;
                break;
        }
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

static int
prov_prov_set_macctx(EVP_MAC_CTX *macctx, const OSSL_PARAM params[], const char *mdname,
                     const char *properties, const unsigned char *key, size_t keylen)
{
        const OSSL_PARAM *p;
        OSSL_PARAM mac_params[6], *mp = mac_params;

        if (params != NULL) {
                if (mdname == NULL) {
                        if ((p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST)) != NULL) {
                                if (p->data_type != OSSL_PARAM_UTF8_STRING)
                                        return 0;
                                mdname = p->data;
                        }
                }
        }

        if (mdname != NULL)
                *mp++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *) mdname, 0);
        if (properties != NULL)
                *mp++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES,
                                                         (char *) properties, 0);

        if (key != NULL)
                *mp++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (unsigned char *) key,
                                                          keylen);

        *mp = OSSL_PARAM_construct_end();

        return EVP_MAC_CTX_set_params(macctx, mac_params);
}

static int
prov_prov_macctx_load_from_params(ALG_CTX *hctx, EVP_MAC_CTX **macctx, const OSSL_PARAM params[],
                                  const char *macname, const char *ciphername, const char *mdname,
                                  OSSL_LIB_CTX *libctx)
{
        const OSSL_PARAM *p;
        const char *properties = NULL;

        if (macname == NULL && (p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_MAC)) != NULL) {
                if (p->data_type != OSSL_PARAM_UTF8_STRING)
                        return 0;
                macname = p->data;
        }
        if ((p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES)) != NULL) {
                if (p->data_type != OSSL_PARAM_UTF8_STRING)
                        return 0;
                properties = p->data;
        }

        for (p = params; p != NULL && p->key != NULL; p++) {
                if (strcmp(p->key, OSSL_MAC_PARAM_KEY) == 0) {
                        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
                                return 0;
                        }

                        // Allocate memory for the key and copy it
                        hctx->key = OPENSSL_malloc(p->data_size);
                        if (hctx->key == NULL) {
                                return 0;
                        }
                        memcpy(hctx->key, p->data, p->data_size);
                        hctx->keylen = p->data_size;
                }
        }

        /* If we got a new mac name, we make a new EVP_MAC_CTX */
        if (macname != NULL) {
                EVP_MAC *mac = EVP_MAC_fetch(libctx, macname, properties);

                EVP_MAC_CTX_free(*macctx);
                *macctx = mac == NULL ? NULL : EVP_MAC_CTX_new(mac);
                /* The context holds on to the MAC */
                EVP_MAC_free(mac);
                if (*macctx == NULL)
                        return 0;
        }

        /*
         * If there is no MAC yet (and therefore, no MAC context), we ignore
         * all other parameters.
         */
        if (*macctx == NULL)
                return 1;

        if (prov_prov_set_macctx(*macctx, params, mdname, properties, hctx->key, hctx->keylen))
                return 1;

        EVP_MAC_CTX_free(*macctx);
        *macctx = NULL;
        return 0;
}

int
prov_hmac_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
        const OSSL_PARAM *p;
        ALG_CTX *hctx = vctx;
        hctx->libctx = OSSL_LIB_CTX_new();

        if (params == NULL)
                return 1;

        if ((p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST)) != NULL) {
                if (!prov_hmac_common_set_ctx_params(hctx, params))
                        return 0;
                if (strcasecmp(p->data, SN_sha1) == 0) {
                        set_sha_ctx_params(hctx, 1);
                        if (!prov_prov_macctx_load_from_params(hctx, &hctx->mac_ctx, params,
                                                               OSSL_MAC_NAME_HMAC, NULL, SN_sha1,
                                                               hctx->libctx)) {
                                return 0;
                        }
                } else if (strcasecmp(p->data, SN_sha224) == 0) {
                        set_sha_ctx_params(hctx, 224);
                        if (!prov_prov_macctx_load_from_params(hctx, &hctx->mac_ctx, params,
                                                               OSSL_MAC_NAME_HMAC, NULL, SN_sha224,
                                                               hctx->libctx)) {
                                return 0;
                        }
                } else if (strcasecmp(p->data, SN_sha256) == 0) {
                        set_sha_ctx_params(hctx, 256);
                        if (!prov_prov_macctx_load_from_params(hctx, &hctx->mac_ctx, params,
                                                               OSSL_MAC_NAME_HMAC, NULL, SN_sha256,
                                                               hctx->libctx)) {
                                return 0;
                        }
                } else if (strcasecmp(p->data, SN_sha384) == 0) {
                        set_sha_ctx_params(hctx, 384);
                        if (!prov_prov_macctx_load_from_params(hctx, &hctx->mac_ctx, params,
                                                               OSSL_MAC_NAME_HMAC, NULL, SN_sha384,
                                                               hctx->libctx)) {
                                return 0;
                        }
                } else if (strcasecmp(p->data, SN_sha512) == 0) {
                        set_sha_ctx_params(hctx, 512);
                        if (!prov_prov_macctx_load_from_params(hctx, &hctx->mac_ctx, params,
                                                               OSSL_MAC_NAME_HMAC, NULL, SN_sha512,
                                                               hctx->libctx)) {
                                return 0;
                        }
                }
        }

        return 1;
}

static void
prov_hmac_sha_freectx(void *vctx)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        hmac_sha_async_cleanup(ctx);
}

static int
prov_hmac_sha_get_params(OSSL_PARAM params[])
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
        if (p != NULL)
                return 0;

        p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
        if (p != NULL)
                return 0;

        return 1;
}

static ALG_CTX *
prov_hmac_sha_newctx(void *provctx)
{
        ALG_CTX *ctx = prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;
        return ctx;
}

const OSSL_DISPATCH prov_hmac_sha_functions[] = {
        { OSSL_FUNC_MAC_NEWCTX, (void (*)(void)) prov_hmac_sha_newctx },
        { OSSL_FUNC_MAC_DUPCTX, (void (*)(void)) prov_hmac_sha_dupctx },
        { OSSL_FUNC_MAC_FREECTX, (void (*)(void)) prov_hmac_sha_freectx },
        { OSSL_FUNC_MAC_INIT, (void (*)(void)) prov_hmac_sha_init },
        { OSSL_FUNC_MAC_UPDATE, (void (*)(void)) prov_hmac_sha_update },
        { OSSL_FUNC_MAC_FINAL, (void (*)(void)) prov_hmac_sha_final },
        { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void)) prov_hmac_sha_get_params },
        { OSSL_FUNC_MAC_GETTABLE_PARAMS,
          (void (*)(void)) prov_hmac_sha_digest_default_gettable_params },
        { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void)) prov_hmac_settable_ctx_params },
        { OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void)) prov_hmac_set_ctx_params },
        { 0, NULL }
};