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

#include "prov_chacha20.h"
#include "prov_sw_chacha20.h"
#include "prov_provider.h"
#include "prov_ciphers.h"

#define SUCCESS 1
#define FAILURE 0

/* ChaCha20 OSSL function declarations */
OSSL_FUNC_cipher_update_fn chacha20_stream_update_cha;
OSSL_FUNC_cipher_final_fn chacha20_stream_final;
OSSL_FUNC_cipher_cipher_fn chacha20_cipher_cha;

/* ChaCha20 async function declarations */
int
chacha20_async_init(ALG_CTX *ctx, const unsigned char *key, size_t keylen, const unsigned char *iv,
                    size_t ivlen, int enc);
int
chacha20_async_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
                         const unsigned char *in, size_t inl);
void
chacha20_async_cleanup(ALG_CTX *ctx);

int
chacha20_initiv(ALG_CTX *ctx, const unsigned char *iv, const size_t ivlen)
{
        if (ivlen != ctx->ivlen || ivlen > sizeof(ctx->iv))
                return FAILURE;

        ctx->iv_set = 1;
        memcpy(ctx->iv, iv, ivlen);
        memcpy(ctx->oiv, iv, ivlen);
        memcpy(ctx->next_iv, iv, ivlen);
        return SUCCESS;
}

int
chacha20_get_ctx_params(ALG_CTX *ctx, OSSL_PARAM params[])
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_string(p, &ctx->oiv, ctx->ivlen))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
        if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, ctx->tlsmac, ctx->tlsmacsize))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->blocksize))
                return FAILURE;

        return SUCCESS;
}

int
chacha20_set_ctx_params(ALG_CTX *ctx, const OSSL_PARAM params[])
{
        if (params == NULL)
                return SUCCESS;

        const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC);
        if (p != NULL) {
                if (p->data_type != OSSL_PARAM_OCTET_STRING)
                        return FAILURE;
                ctx->tlsmac = p->data;
                ctx->tlsmacsize = p->data_size;
        }

        return SUCCESS;
}

void
chacha20_freectx(ALG_CTX *ctx)
{
        if (ctx != NULL) {
                chacha20_async_cleanup(ctx);
                OPENSSL_clear_free(ctx, sizeof(*ctx));
        }
}

static int
chacha20_einit(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
               const unsigned char *iv, const size_t ivlen, const OSSL_PARAM params[])
{
        int ret;
        ctx->enc = 1;

        if (inkey != NULL) {
                if (keylen != ctx->keylen) {
                        return FAILURE;
                }
                ret = chacha20_async_init(ctx, inkey, keylen, iv, ivlen, ctx->enc);
                if (!ret)
                        return FAILURE;
                ctx->key_set = 1;
        }

        if (iv != NULL) {
                if (ivlen != ctx->ivlen)
                        return FAILURE;
                if (!chacha20_initiv(ctx, iv, ivlen))
                        return FAILURE;
        }

        if (params != NULL && !chacha20_set_ctx_params(ctx, params))
                return FAILURE;

        return SUCCESS;
}

static int
chacha20_dinit(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
               const unsigned char *iv, const size_t ivlen, const OSSL_PARAM params[])
{
        int ret;
        ctx->enc = 0;

        if (inkey != NULL) {
                if (keylen != ctx->keylen) {
                        return FAILURE;
                }
                ret = chacha20_async_init(ctx, inkey, keylen, iv, ivlen, ctx->enc);
                if (!ret)
                        return FAILURE;
                ctx->key_set = 1;
        }

        if (iv != NULL) {
                if (ivlen != ctx->ivlen)
                        return FAILURE;
                if (!chacha20_initiv(ctx, iv, ivlen))
                        return FAILURE;
        }

        if (params != NULL && !chacha20_set_ctx_params(ctx, params))
                return FAILURE;

        return SUCCESS;
}

int
chacha20_stream_update_cha(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                           const unsigned char *in, size_t inl)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        if (!prov_is_running())
                return FAILURE;

        if (!ctx->key_set)
                return FAILURE;

        if (outsize < inl)
                return FAILURE;

        int ret = chacha20_async_do_cipher(ctx, out, outl, outsize, in, inl);

        if (ret <= 0)
                return FAILURE;

        if (outl != NULL)
                *outl = inl;

        return SUCCESS;
}

int
chacha20_stream_final(void *vctx, unsigned char *out, size_t *outl, const size_t outsize)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        if (!prov_is_running())
                return FAILURE;

        if (!ctx->key_set)
                return FAILURE;

        if (outl != NULL)
                *outl = 0;
        return SUCCESS;
}

int
chacha20_cipher_cha(void *vctx, unsigned char *out, size_t *outl, const size_t outsize,
                    const unsigned char *in, const size_t inl)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        if (!chacha20_stream_update_cha(ctx, out, outl, outsize, in, inl))
                return FAILURE;

        if (!chacha20_stream_final(ctx, out + *outl, outl, outsize - *outl))
                return FAILURE;

        if (outl != NULL)
                *outl += inl;

        return SUCCESS;
}

void
cipher_generic_initkey_cha(ALG_CTX *ctx, const int kbits, const int blkbits, const int ivbits,
                           const int mode, const uint64_t flags, void *provctx, const int nid)
{
        ctx->nid = nid;
        ctx->keylen = ((kbits) / 8);
        ctx->ivlen = ((ivbits) / 8);

        ctx->libctx = prov_libctx_of(provctx);

        ctx->mode = mode;
        ctx->blocksize = blkbits / 8;
        if (provctx != NULL)
                ctx->libctx = prov_libctx_of(provctx);
}

#define IMPLEMENT_chacha20_cipher_cha(alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits,   \
                                      typ, nid)                                                    \
        static int alg##_##kbits##_##lcmode##_get_params(OSSL_PARAM params[])                      \
        {                                                                                          \
                return prov_cipher_generic_get_params(params, EVP_CIPH_STREAM_CIPHER, flags,       \
                                                      kbits, blkbits, ivbits);                     \
        }                                                                                          \
        static void *alg##_##kbits##_##lcmode##_newctx(void *provctx)                              \
        {                                                                                          \
                ALG_CTX *ctx = prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;            \
                if (ctx != NULL) {                                                                 \
                        cipher_generic_initkey_cha(ctx, kbits, blkbits, ivbits,                    \
                                                   EVP_CIPH_STREAM_CIPHER, flags, provctx, nid);   \
                }                                                                                  \
                return ctx;                                                                        \
        }                                                                                          \
        const OSSL_DISPATCH prov_chacha20_functions[] = {                                          \
                { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) alg##_##kbits##_##lcmode##_newctx },   \
                { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) chacha20_freectx },                   \
                { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) chacha20_einit },                \
                { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) chacha20_dinit },                \
                { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) chacha20_stream_update_cha },          \
                { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) chacha20_stream_final },                \
                { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) chacha20_cipher_cha },                 \
                { OSSL_FUNC_CIPHER_GET_PARAMS,                                                     \
                  (void (*)(void)) alg##_##kbits##_##lcmode##_get_params },                        \
                { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void)) chacha20_get_ctx_params },     \
                { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void)) chacha20_set_ctx_params },     \
                { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                                \
                  (void (*)(void)) prov_cipher_generic_gettable_params },                          \
                { 0, NULL }                                                                        \
        };

/* chacha20_functions */
IMPLEMENT_chacha20_cipher_cha(chacha, CHACHA, 20, 20, 0, 256, 8, 96, stream, NID_chacha20)
