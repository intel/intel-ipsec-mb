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

#include "prov_aes_cfb.h"
#include "prov_sw_aes_cfb.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include "prov_provider.h"
#include "prov_ciphers.h"

#define SUCCESS 1
#define FAILURE 0

int
aes_generic_initiv(ALG_CTX *ctx, const unsigned char *iv, size_t ivlen)
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
aes_cfb_get_ctx_params(ALG_CTX *ctx, OSSL_PARAM params[])
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
        if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->pad))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_string(p, &ctx->oiv, ctx->ivlen))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen) &&
            !OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
        if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->num))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
                return FAILURE;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
        if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, ctx->tlsmac, ctx->tlsmacsize))
                return FAILURE;

        return SUCCESS;
}

int
aes_cfb_set_ctx_params(ALG_CTX *ctx, const OSSL_PARAM params[])
{
        const OSSL_PARAM *p;

        if (params == NULL)
                return SUCCESS;

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
        if (p != NULL) {
                unsigned int pad;

                if (!OSSL_PARAM_get_uint(p, &pad))
                        return FAILURE;

                ctx->pad = pad ? 1 : 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_USE_BITS);
        if (p != NULL) {
                unsigned int bits;

                if (!OSSL_PARAM_get_uint(p, &bits))
                        return FAILURE;

                ctx->use_bits = bits ? 1 : 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
        if (p != NULL) {
                if (!OSSL_PARAM_get_uint(p, &ctx->tlsversion))
                        return FAILURE;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
        if (p != NULL) {
                if (!OSSL_PARAM_get_size_t(p, &ctx->tlsmacsize))
                        return FAILURE;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
        if (p != NULL) {
                unsigned int num;

                if (!OSSL_PARAM_get_uint(p, &num))
                        return FAILURE;

                ctx->num = num;
        }
        return SUCCESS;
}

static void
aes_freectx(ALG_CTX *ctx)
{
        if (ctx != NULL)
                OPENSSL_free(ctx->tlsmac);

        OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static int
aes_init_internal(ALG_CTX *ctx, const unsigned char *key, size_t keylen, const unsigned char *iv,
                  const size_t ivlen, const OSSL_PARAM params[], const int enc)
{
        ctx->enc = enc ? 1 : 0;

        if (!prov_is_running())
                return FAILURE;

        // Only handle IV initialization here
        if (iv != NULL) {
                if (!aes_generic_initiv(ctx, iv, ivlen))
                        return FAILURE;
        }

        if (key != NULL) {
                if (ctx->variable_keylength == 0) {
                        if (keylen != ctx->keylen)
                                return FAILURE;

                } else {
                        ctx->keylen = keylen;
                }
                // IV is already set in ctx, so pass ctx->iv and ctx->ivlen
                if (!aes_cfb_async_init(ctx, key, keylen, ctx->iv, ctx->ivlen, ctx->enc))
                        return FAILURE;
                ctx->key_set = 1;
        }
        return aes_cfb_set_ctx_params(ctx, params);
}

int
aes_cfb_einit(ALG_CTX *ctx, const unsigned char *key, size_t keylen, const unsigned char *iv,
              size_t ivlen, const OSSL_PARAM params[])
{
        return aes_init_internal(ctx, key, keylen, iv, ivlen, params, 1);
}

int
aes_cfb_dinit(ALG_CTX *ctx, const unsigned char *key, size_t keylen, const unsigned char *iv,
              size_t ivlen, const OSSL_PARAM params[])
{
        return aes_init_internal(ctx, key, keylen, iv, ivlen, params, 0);
}

int
aes_cfb_stream_update(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
                      const unsigned char *in, size_t inl)
{
        if (!ctx->key_set)
                return FAILURE;

        if (inl == 0) {
                *outl = 0;
                return SUCCESS;
        }

        if (outsize < inl)
                return FAILURE;

        if (!aes_cfb_async_do_cipher(ctx, out, outl, outsize, in, inl))
                return FAILURE;

        *outl = inl;

        return SUCCESS;
}

int
aes_cfb_stream_final(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize)
{
        if (!prov_is_running())
                return FAILURE;

        if (!ctx->key_set)
                return FAILURE;

        *outl = 0;
        return SUCCESS;
}

int
aes_cfb_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
               const unsigned char *in, size_t inl)
{
        if (!prov_is_running())
                return FAILURE;

        if (!ctx->key_set)
                return FAILURE;

        if (outsize < inl)
                return FAILURE;

        if (!aes_cfb_async_do_cipher(ctx, out, outl, outsize, in, inl))
                return FAILURE;

        *outl = inl;
        return SUCCESS;
}

void
cipher_generic_initkey(ALG_CTX *ctx, size_t kbits, size_t blkbits, size_t ivbits, unsigned int mode,
                       uint64_t flags, void *provctx, int nid)
{
        ctx->nid = nid;
        ctx->pad = 1;
        ctx->keylen = ((kbits) / 8);
        ctx->ivlen = ((ivbits) / 8);

        ctx->libctx = prov_libctx_of(provctx);

        ctx->mode = mode;
        ctx->blocksize = blkbits / 8;
        if ((flags & PROV_CIPHER_FLAG_INVERSE_CIPHER) != 0)
                ctx->inverse_cipher = 1;
        if ((flags & PROV_CIPHER_FLAG_VARIABLE_LENGTH) != 0)
                ctx->variable_keylength = 1;
        if (provctx != NULL)
                ctx->libctx = prov_libctx_of(provctx); /* used for rand */
}

#define IMPLEMENT_generic_cipher(alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits, ivbits, typ,   \
                                 nid)                                                              \
        static int alg##_##kbits##_##lcmode##_get_params(OSSL_PARAM params[])                      \
        {                                                                                          \
                return prov_cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags,     \
                                                      kbits, blkbits, ivbits);                     \
        }                                                                                          \
        static void *alg##_##kbits##_##lcmode##_newctx(void *provctx)                              \
        {                                                                                          \
                ALG_CTX *ctx = prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;            \
                if (ctx != NULL) {                                                                 \
                        cipher_generic_initkey(ctx, kbits, blkbits, ivbits,                        \
                                               EVP_CIPH_##UCMODE##_MODE, flags, provctx, nid);     \
                }                                                                                  \
                return ctx;                                                                        \
        }                                                                                          \
        const OSSL_DISPATCH prov_##alg##kbits##lcmode##_functions[] = {                            \
                { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) alg##_##kbits##_##lcmode##_newctx },   \
                { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) alg##_freectx },                      \
                { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) aes_cfb_einit },                 \
                { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) aes_cfb_dinit },                 \
                { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) aes_cfb_##typ##_update },              \
                { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) aes_cfb_##typ##_final },                \
                { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) aes_cfb_cipher },                      \
                { OSSL_FUNC_CIPHER_GET_PARAMS,                                                     \
                  (void (*)(void)) alg##_##kbits##_##lcmode##_get_params },                        \
                { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void)) aes_cfb_get_ctx_params },      \
                { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void)) aes_cfb_set_ctx_params },      \
                { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                                \
                  (void (*)(void)) prov_cipher_generic_gettable_params },                          \
                { 0, NULL }                                                                        \
        };

/* aes128cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb, CFB, 0, 128, 8, 128, stream, NID_aes_128_cfb128)

        /* aes192cfb_functions */
        IMPLEMENT_generic_cipher(aes, AES, cfb, CFB, 0, 192, 8, 128, stream, NID_aes_192_cfb128)

        /* aes256cfb_functions */
        IMPLEMENT_generic_cipher(aes, AES, cfb, CFB, 0, 256, 8, 128, stream, NID_aes_256_cfb128)