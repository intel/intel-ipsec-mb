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
chacha20_poly1305_generic_init(void *ctx, const unsigned char *key, const int keylen,
                               const unsigned char *iv, const int ivlen, const int enc)
{
        ALG_CTX *algctx = (ALG_CTX *) ctx;

        if (!algctx) {
                fprintf(stderr, "Error: Invalid context in chacha20_poly1305_generic_init\n");
                return FAILURE;
        }

        algctx->enc = enc;

        if (key != NULL && iv != NULL) {
                return chacha20_poly1305_async_init(algctx, key, keylen, iv, ivlen, enc);
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

        return ctx;
}

void
chacha20_poly1305_freectx(void *ctx)
{
        ALG_CTX *algctx = (ALG_CTX *) ctx;

        if (algctx) {
                chacha20_poly1305_async_cleanup(algctx);
                OPENSSL_free(algctx);
        }
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

        if (!algctx || !in || inl == 0) {
                if (outl)
                        *outl = 0;
                return SUCCESS;
        }

        algctx->out = out;

        if (!chacha20_poly1305_async_update(algctx, in, inl)) {
                return FAILURE;
        }

        *outl = inl;
        return SUCCESS;
}

int
chacha20_poly1305_stream_final(void *ctx, unsigned char *out, size_t *outl, size_t outsize)
{
        (void) outsize;
        ALG_CTX *algctx = (ALG_CTX *) ctx;

        if (!algctx && outl) {
                *outl = 0;
                return FAILURE;
        }

        if (!chacha20_poly1305_async_final(algctx, out)) {
                if (outl)
                        *outl = 0;
                return FAILURE;
        }

        if (outl)
                *outl = 0;
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
                algctx->aad = p->data;
                algctx->aad_len = p->data_size;
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
