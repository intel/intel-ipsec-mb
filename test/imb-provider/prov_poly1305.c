/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "prov_provider.h"
#include "prov_poly1305.h"
#include "e_prov.h"
#include "prov_sw_poly1305.h"
#include <openssl/evp.h>

#define SUCCESS 1
#define FAILURE 0

void *
prov_poly1305_newctx(void *provctx)
{
        ALG_CTX *ctx = OPENSSL_zalloc(sizeof(ALG_CTX));
        if (ctx == NULL)
                return NULL;

        ctx->keylen = POLY1305_KEY_SIZE;
        ctx->blocksize = POLY1305_BLOCK_SIZE;
        ctx->md_size = POLY1305_TAG_SIZE;
        ctx->key_set = 0;
        ctx->provctx = provctx;
        ctx->libctx = prov_libctx_of(provctx);
        return ctx;
}

void
prov_poly1305_freectx(void *vctx)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (ctx != NULL) {
                poly1305_async_cleanup(ctx);
                OPENSSL_clear_free(ctx, sizeof(*ctx));
        }
}

int
prov_poly1305_init(void *vctx, const unsigned char *key, const int keylen, const unsigned char *iv,
                   const int ivlen, const int enc)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (ctx == NULL)
                return FAILURE;

        if (!prov_is_running())
                return FAILURE;

        if (key != NULL) {
                if (keylen != POLY1305_KEY_SIZE) {
                        fprintf(stderr, "Invalid Poly1305 key length: %d (expected %d)\n", keylen,
                                POLY1305_KEY_SIZE);
                        return FAILURE;
                }

                if (!poly1305_async_init(ctx, key, keylen))
                        return FAILURE;

                ctx->key_set = 1;
        }

        return SUCCESS;
}

int
prov_poly1305_update(void *vctx, unsigned char *out, size_t *outl, const size_t outsize,
                     const unsigned char *in, const size_t inl)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (ctx == NULL)
                return FAILURE;

        if (!ctx->key_set) {
                if (outl != NULL)
                        *outl = 0;
                return SUCCESS;
        }

        if (inl == 0) {
                *outl = 0;
                return SUCCESS;
        }

        if (outsize < POLY1305_TAG_SIZE) {
                fprintf(stderr, "Output buffer too small for Poly1305 tag\n");
                return FAILURE;
        }

        return poly1305_async_do_mac(ctx, out, outl, outsize, in, inl);
}

int
prov_poly1305_final(void *vctx, unsigned char *out, size_t *outl, const size_t outsize)
{
        *outl = 0;
        return SUCCESS;
}

int
prov_poly1305_cipher(void *vctx, unsigned char *out, size_t *outl, const size_t outsize,
                     const unsigned char *in, const size_t inl)
{
        return prov_poly1305_update(vctx, out, outl, outsize, in, inl);
}

int
prov_poly1305_get_params(OSSL_PARAM params[])
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, POLY1305_KEY_SIZE))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, 0))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, POLY1305_BLOCK_SIZE))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
        if (p != NULL && !OSSL_PARAM_set_int(p, EVP_CIPH_STREAM_CIPHER))
                return FAILURE;

        return SUCCESS;
}

int
prov_poly1305_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        OSSL_PARAM *p;

        if (ctx == NULL)
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, 0))
                return FAILURE;

        return SUCCESS;
}

int
prov_poly1305_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
        /* Poly1305 has no settable parameters for now */
        return SUCCESS;
}

static const OSSL_PARAM poly1305_known_gettable_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_MODE, NULL), OSSL_PARAM_END
};

const OSSL_PARAM *
prov_poly1305_gettable_params(void *provctx)
{
        return poly1305_known_gettable_params;
}

static const OSSL_PARAM poly1305_known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL), OSSL_PARAM_END
};

const OSSL_PARAM *
prov_poly1305_gettable_ctx_params(void *cctx, void *provctx)
{
        return poly1305_known_gettable_ctx_params;
}

static const OSSL_PARAM poly1305_known_settable_ctx_params[] = { OSSL_PARAM_END };

const OSSL_PARAM *
prov_poly1305_settable_ctx_params(void *cctx, void *provctx)
{
        return poly1305_known_settable_ctx_params;
}

/* Function table for Poly1305 */
const OSSL_DISPATCH prov_poly1305_functions[] = {
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) prov_poly1305_newctx },
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) prov_poly1305_freectx },
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) prov_poly1305_init },
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) prov_poly1305_init },
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) prov_poly1305_update },
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) prov_poly1305_final },
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) prov_poly1305_cipher },
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) prov_poly1305_get_params },
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void)) prov_poly1305_get_ctx_params },
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void)) prov_poly1305_set_ctx_params },
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void)) prov_poly1305_gettable_params },
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
          (void (*)(void)) prov_poly1305_gettable_ctx_params },
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
          (void (*)(void)) prov_poly1305_settable_ctx_params },
        { 0, NULL }
};
