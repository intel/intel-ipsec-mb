/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "prov_chacha20_poly1305.h"
#include "prov_sw_chacha20_poly1305.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include "prov_provider.h"
#include "prov_ciphers.h"
#include "prov_sw_request.h" /* For ALG_CTX definition */

#define SUCCESS 1
#define FAILURE 0

static int
chacha20_poly1305_replace_aad(ALG_CTX *ctx, const unsigned char *aad, size_t aad_len)
{
        unsigned char *new_aad;

        if (ctx == NULL)
                return FAILURE;

        if (aad == NULL || aad_len == 0) {
                /* Keep allocation for reuse across operations. */
                ctx->aad_len = 0;
                return SUCCESS;
        }

        if (aad_len > INT_MAX)
                return FAILURE;

        new_aad = OPENSSL_realloc(ctx->aad, aad_len);

        if (new_aad == NULL)
                return FAILURE;

        memcpy(new_aad, aad, aad_len);
        ctx->aad = new_aad;
        ctx->aad_len = (int) aad_len;

        return SUCCESS;
}

static int
chacha20_poly1305_append_aad(ALG_CTX *ctx, const unsigned char *aad, size_t aad_len)
{
        unsigned char *new_aad;

        if (ctx == NULL)
                return FAILURE;

        if (aad == NULL || aad_len == 0)
                return SUCCESS;

        if (ctx->aad_len < 0)
                return FAILURE;

        size_t total = (size_t) ctx->aad_len + aad_len;
        if (total > INT_MAX)
                return FAILURE;

        new_aad = OPENSSL_realloc(ctx->aad, total);
        if (new_aad == NULL)
                return FAILURE;

        memcpy(new_aad + (size_t) ctx->aad_len, aad, aad_len);
        ctx->aad = new_aad;
        ctx->aad_len = (int) total;

        return SUCCESS;
}

static int
chacha20_poly1305_ensure_init(ALG_CTX *ctx)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (ctx == NULL || tlv == NULL || tlv->imb_mgr == NULL)
                return FAILURE;

        if (!ctx->key_set || !ctx->iv_set)
                return FAILURE;

        if (ctx->chacha20_poly1305_ctx_init)
                return SUCCESS;

        IMB_CHACHA20_POLY1305_INIT(tlv->imb_mgr, ctx->chacha20_key, &ctx->chacha20_poly1305_ctx,
                                   ctx->chacha20_iv, ctx->aad, (uint64_t) ctx->aad_len);
        ctx->chacha20_poly1305_ctx_init = 1;

        return SUCCESS;
}

static int
chacha20_poly1305_generic_init(void *ctx, const unsigned char *key, const int keylen,
                               const unsigned char *iv, const int ivlen, const int enc)
{
        ALG_CTX *algctx = (ALG_CTX *) ctx;

        if (!algctx) {
                fprintf(stderr, "Error: Invalid context in chacha20_poly1305_generic_init\n");
                return FAILURE;
        }

        algctx->enc = enc;
        algctx->tag_set = 0;
        algctx->tag_calculated = 0;
        algctx->chacha20_poly1305_ctx_init = 0;

        if (!chacha20_poly1305_replace_aad(algctx, NULL, 0))
                return FAILURE;

        if (key != NULL) {
                if (keylen != CHACHA20_POLY1305_KEY_SIZE)
                        return FAILURE;

                memcpy(algctx->chacha20_key, key, keylen);
                algctx->keylen = keylen;
                algctx->key_set = 1;
        }

        if (iv != NULL) {
                if (ivlen != CHACHA20_POLY1305_IV_SIZE)
                        return FAILURE;

                memcpy(algctx->chacha20_iv, iv, ivlen);
                algctx->ivlen = ivlen;
                algctx->iv_set = 1;
        }

        return SUCCESS;
}

void *
chacha20_poly1305_newctx(void *provctx)
{
        ALG_CTX *ctx;

        if (!prov_is_running())
                return NULL;

        ctx = OPENSSL_zalloc(sizeof(ALG_CTX));
        if (ctx == NULL) {
                fprintf(stderr, "Error: Failed to allocate ALG_CTX\n");
                return NULL;
        }

        /* Initialize context */
        ctx->libctx = prov_libctx_of(provctx);

        /* Set default values */
        ctx->keylen = CHACHA20_POLY1305_KEY_SIZE;
        ctx->ivlen = CHACHA20_POLY1305_IV_SIZE;
        ctx->tag_len = CHACHA20_POLY1305_TAG_SIZE;
        ctx->tag = OPENSSL_zalloc(CHACHA20_POLY1305_TAG_SIZE);
        if (ctx->tag == NULL) {
                OPENSSL_free(ctx);
                return NULL;
        }

        return ctx;
}

void
chacha20_poly1305_freectx(void *ctx)
{
        ALG_CTX *algctx = (ALG_CTX *) ctx;

        if (algctx) {
                if (algctx->aad != NULL)
                        OPENSSL_free(algctx->aad);
                if (algctx->tag != NULL)
                        OPENSSL_free(algctx->tag);
                OPENSSL_cleanse(algctx->chacha20_key, sizeof(algctx->chacha20_key));
                OPENSSL_free(algctx);
        }
}

static void *
chacha20_poly1305_dupctx(void *vctx)
{
        ALG_CTX *in = (ALG_CTX *) vctx;
        ALG_CTX *ret = prov_alg_ctx_dup_base(in);

        if (ret == NULL)
                return NULL;

        if (!prov_cipher_dup_buf(&ret->tag, in->tag, CHACHA20_POLY1305_TAG_SIZE) ||
            !prov_cipher_dup_buf(&ret->aad, in->aad, in->aad_len)) {
                chacha20_poly1305_freectx(ret);
                return NULL;
        }

        return ret;
}

int
chacha20_poly1305_einit(void *ctx, const unsigned char *key, const int keylen,
                        const unsigned char *iv, const int ivlen)
{
        return chacha20_poly1305_generic_init(ctx, key, keylen, iv, ivlen, 1);
}

int
chacha20_poly1305_dinit(void *ctx, const unsigned char *key, const int keylen,
                        const unsigned char *iv, const int ivlen)
{
        return chacha20_poly1305_generic_init(ctx, key, keylen, iv, ivlen, 0);
}

int
chacha20_poly1305_stream_update(void *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                                const unsigned char *in, const size_t inl)
{
        ALG_CTX *algctx = (ALG_CTX *) ctx;
        mb_thread_data *tlv = mb_check_thread_local();

        (void) outsize;

        if (!algctx) {
                if (outl)
                        *outl = 0;
                return FAILURE;
        }

        if (in == NULL || inl == 0) {
                if (outl)
                        *outl = 0;
                return SUCCESS;
        }

        if (out == NULL) {
                if (outl)
                        *outl = 0;
                return chacha20_poly1305_append_aad(algctx, in, inl);
        }

        if (inl > outsize) {
                if (outl)
                        *outl = 0;
                return FAILURE;
        }

        if (tlv == NULL || tlv->imb_mgr == NULL)
                return FAILURE;

        if (!chacha20_poly1305_ensure_init(algctx))
                return FAILURE;

        if (algctx->enc)
                IMB_CHACHA20_POLY1305_ENC_UPDATE(tlv->imb_mgr, algctx->chacha20_key,
                                                 &algctx->chacha20_poly1305_ctx, out, in,
                                                 (uint64_t) inl);
        else
                IMB_CHACHA20_POLY1305_DEC_UPDATE(tlv->imb_mgr, algctx->chacha20_key,
                                                 &algctx->chacha20_poly1305_ctx, out, in,
                                                 (uint64_t) inl);

        if (outl)
                *outl = inl;

        return SUCCESS;
}

int
chacha20_poly1305_stream_final(void *ctx, unsigned char *out, size_t *outl, size_t outsize)
{
        ALG_CTX *algctx = (ALG_CTX *) ctx;
        mb_thread_data *tlv = mb_check_thread_local();
        unsigned char calc_tag[CHACHA20_POLY1305_TAG_SIZE];

        (void) out;
        (void) outsize;

        if (outl)
                *outl = 0;

        if (algctx == NULL || tlv == NULL || tlv->imb_mgr == NULL)
                return FAILURE;

        if (!chacha20_poly1305_ensure_init(algctx))
                return FAILURE;

        if (algctx->enc) {
                IMB_CHACHA20_POLY1305_ENC_FINALIZE(tlv->imb_mgr, &algctx->chacha20_poly1305_ctx,
                                                   algctx->auths, (uint64_t) algctx->tag_len);
        } else {
                if (algctx->tag == NULL || !algctx->tag_set)
                        return FAILURE;
                IMB_CHACHA20_POLY1305_DEC_FINALIZE(tlv->imb_mgr, &algctx->chacha20_poly1305_ctx,
                                                   calc_tag, (uint64_t) algctx->tag_len);
                if (CRYPTO_memcmp(algctx->tag, calc_tag, (size_t) algctx->tag_len) != 0)
                        return FAILURE;
                memcpy(algctx->auths, calc_tag, (size_t) algctx->tag_len);
        }

        algctx->tag_calculated = 1;
        return SUCCESS;
}

int
chacha20_poly1305_cipher(void *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                         const unsigned char *in, const size_t inl)
{
        size_t update_outl = 0;
        size_t final_outl = 0;

        if (!chacha20_poly1305_stream_update(ctx, out, &update_outl, outsize, in, inl)) {
                return FAILURE;
        }

        if (!chacha20_poly1305_stream_final(ctx, out + update_outl, &final_outl,
                                            outsize - update_outl)) {
                return FAILURE;
        }

        *outl = update_outl + final_outl;
        return SUCCESS;
}

int
chacha20_poly1305_get_params(OSSL_PARAM params[])
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
        if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_STREAM_CIPHER)) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_KEY_SIZE)) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_IV_SIZE)) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, 1)) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
        if (p != NULL && !OSSL_PARAM_set_int(p, 1)) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_TAG_SIZE)) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_IV_SIZE)) {
                return FAILURE;
        }

        return SUCCESS;
}

const OSSL_PARAM *
chacha20_poly1305_gettable_params(void *provctx)
{
        static const OSSL_PARAM known_gettable_params[] = {
                OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
                OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
                OSSL_PARAM_END
        };
        return known_gettable_params;
}

int
chacha20_poly1305_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
        ALG_CTX *algctx = (ALG_CTX *) ctx;
        const OSSL_PARAM *p;

        if (!algctx) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
                if (algctx->tag == NULL) {
                        return FAILURE;
                }
                memcpy(algctx->tag, p->data, p->data_size);
                algctx->tag_set = 1;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if (p != NULL) {
                size_t tag_len;
                if (!OSSL_PARAM_get_size_t(p, &tag_len) || tag_len != CHACHA20_POLY1305_TAG_SIZE) {
                        return FAILURE;
                }
                algctx->tag_len = tag_len;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
        if (p != NULL) {
                if (!chacha20_poly1305_replace_aad(algctx, p->data, p->data_size))
                        return FAILURE;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
        if (p != NULL) {
                size_t ivlen;
                if (!OSSL_PARAM_get_size_t(p, &ivlen) || ivlen != CHACHA20_POLY1305_IV_SIZE) {
                        return FAILURE;
                }
                algctx->ivlen = ivlen;
        }

        return SUCCESS;
}

int
chacha20_poly1305_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
        ALG_CTX *algctx = (ALG_CTX *) ctx;
        OSSL_PARAM *p;

        if (!algctx) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
                if (!algctx->tag_calculated) {
                        return FAILURE;
                }
                if (!OSSL_PARAM_set_octet_string(p, algctx->auths, algctx->tag_len)) {
                        return FAILURE;
                }
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, algctx->tag_len)) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, algctx->keylen)) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, algctx->ivlen)) {
                return FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, algctx->ivlen)) {
                return FAILURE;
        }

        return SUCCESS;
}

const OSSL_PARAM *
chacha20_poly1305_settable_ctx_params(void *ctx, void *provctx)
{
        static const OSSL_PARAM known_settable_ctx_params[] = {
                OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
                OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL), OSSL_PARAM_END
        };
        return known_settable_ctx_params;
}

const OSSL_PARAM *
chacha20_poly1305_gettable_ctx_params(void *ctx, void *provctx)
{
        static const OSSL_PARAM known_gettable_ctx_params[] = {
                OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
                OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
                OSSL_PARAM_END
        };
        return known_gettable_ctx_params;
}

const OSSL_DISPATCH prov_chacha20_poly1305_functions[] = {
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) chacha20_poly1305_newctx },
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) chacha20_poly1305_freectx },
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) chacha20_poly1305_dupctx },
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) chacha20_poly1305_einit },
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) chacha20_poly1305_dinit },
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) chacha20_poly1305_stream_update },
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) chacha20_poly1305_stream_final },
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) chacha20_poly1305_cipher },
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) chacha20_poly1305_get_params },
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void)) chacha20_poly1305_gettable_params },
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void)) chacha20_poly1305_get_ctx_params },
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void)) chacha20_poly1305_set_ctx_params },
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
          (void (*)(void)) chacha20_poly1305_gettable_ctx_params },
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
          (void (*)(void)) chacha20_poly1305_settable_ctx_params },
        { 0, NULL }
};
