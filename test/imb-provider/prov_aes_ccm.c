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

#include "prov_provider.h"
#include "prov_aes_ccm.h"
#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_ccm.h"
#include "prov_sw_request.h"
#include "prov_ciphers.h"

#define AEAD_FLAGS            (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)
#define PROV_AES_CCM_OP_VALUE 15

void
prov_aes_ccm_init_ctx(void *provctx, ALG_CTX *ctx, const size_t keybits)
{
        ctx->keylen = keybits / 8;
        ctx->key_set = 0;
        ctx->iv_set = 0;
        ctx->tag_set = 0;
        ctx->L = 8;
        ctx->M = 12;
        ctx->tls_aad_len = -1;
        ctx->pad = 1;
        ctx->mode = EVP_CIPH_CCM_MODE;
        ctx->tag_len = -1;
        ctx->libctx = prov_libctx_of(provctx);
        ctx->iv_len = (EVP_CCM_TLS_FIXED_IV_LEN + EVP_CCM_TLS_EXPLICIT_IV_LEN);
}

static void *
prov_aes_ccm_newctx(void *provctx, const size_t keybits, const int nid)
{
        ALG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
        PROV_EVP_CIPHER *cipher;

        if (!prov_is_running())
                return NULL;

        if (ctx == NULL)
                return NULL;

        cipher = OPENSSL_zalloc(sizeof(PROV_EVP_CIPHER));
        if (cipher == NULL) {
                OPENSSL_free(ctx);
                return NULL;
        }

        cipher->nid = nid;
        ctx->cipher = cipher;
        ctx->nid = nid;

        prov_aes_ccm_init_ctx(provctx, ctx, keybits);

        return ctx;
}

size_t
prov_aes_ccm_get_ivlen(ALG_CTX *ctx)
{
        return PROV_AES_CCM_OP_VALUE - ctx->L;
}

int
prov_aes_ccm_einit(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
                   const unsigned char *iv, const size_t ivlen)
{
        return prov_sw_ccm_init(ctx, inkey, keylen, iv, ivlen, 1);
}

int
prov_aes_ccm_dinit(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
                   const unsigned char *iv, const size_t ivlen)
{
        return prov_sw_ccm_init(ctx, inkey, keylen, iv, ivlen, 0);
}

int
prov_aes_ccm_stream_update(ALG_CTX *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                           const unsigned char *in, const size_t inl)
{
        if (inl == 0) {
                *outl = 0;
                return 1;
        }

        if (outsize < inl)
                return 0;

        if ((prov_sw_ccm_do_cipher(ctx, out, outl, outsize, in, inl)) <= 0)
                return 0;

        return 1;
}

int
prov_aes_ccm_stream_final(ALG_CTX *ctx, unsigned char *out, size_t *outl, const size_t outsize)
{
        if (!prov_is_running())
                return 0;

        if (prov_sw_ccm_do_cipher(ctx, out, outl, outsize, NULL, 0) <= 0)
                return 0;

        *outl = 0;
        return 1;
}

int
prov_aes_ccm_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                       const unsigned char *in, const size_t inl)
{
        if (!prov_is_running())
                return 0;

        if (outsize < inl)
                return 0;

        if (prov_sw_ccm_do_cipher(ctx, out, outl, outsize, in, inl) <= 0)
                return 0;

        *outl = 0;
        return 1;
}

int
prov_aes_ccm_get_ctx_params(ALG_CTX *ctx, OSSL_PARAM params[])
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, prov_aes_ccm_get_ivlen(ctx)))
                return 0;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
                return 0;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if (p != NULL) {
                size_t m = ctx->M;
                if (!OSSL_PARAM_set_size_t(p, m))
                        return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if (p != NULL) {
                if (prov_aes_ccm_get_ivlen(ctx) > p->data_size)
                        return 0;

                if (!OSSL_PARAM_set_octet_string(p, ctx->iv, p->data_size) &&
                    !OSSL_PARAM_set_octet_ptr(p, ctx->iv, p->data_size))
                        return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if (p != NULL) {
                if (ctx->iv_set == IV_STATE_UNINITIALISED)
                        return 0;
                if (prov_aes_ccm_get_ivlen(ctx) > p->data_size)
                        return 0;

                if (!OSSL_PARAM_set_octet_string(p, ctx->iv, p->data_size) &&
                    !OSSL_PARAM_set_octet_ptr(p, ctx->iv, p->data_size)) {
                        return 0;
                }
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tls_aad_pad_sz))
                return 0;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        return 1;
}

int
prov_aes_ccm_set_ctx_params(ALG_CTX *ctx, const OSSL_PARAM params[])
{
        const OSSL_PARAM *p;
        size_t sz = 0;

        if (params == NULL)
                return 1;

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
                if (p->data_type != OSSL_PARAM_OCTET_STRING)
                        return 0;

                if ((p->data_size & 1) || (p->data_size < 4) || p->data_size > 16)
                        return 0;

                if (p->data != NULL) {
                        if (ctx->enc)
                                return 0;

                        if (p->data_size > sizeof(ctx->buf))
                                return 0;

                        memcpy(ctx->buf, p->data, p->data_size);
                        ctx->tag_set = 1;
                }
                prov_aes_ccm_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, p->data_size, p->data);
                ctx->M = p->data_size;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
        if (p != NULL) {
                size_t ivlen;

                if (!OSSL_PARAM_get_size_t(p, &sz))
                        return 0;

                ivlen = PROV_AES_CCM_OP_VALUE - sz;
                if (ivlen < 2 || ivlen > 8)
                        return 0;

                if (ctx->L != ivlen) {
                        ctx->L = ivlen;
                        ctx->iv_set = 0;
                }
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
        if (p != NULL) {
                if (p->data_type != OSSL_PARAM_OCTET_STRING)
                        return 0;

                sz = prov_aes_ccm_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, p->data_size, p->data);

                if (sz == 0)
                        return 0;

                ctx->tls_aad_pad_sz = sz;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
        if (p != NULL) {
                if (p->data_type != OSSL_PARAM_OCTET_STRING)
                        return 0;

                if (prov_aes_ccm_ctrl(ctx, EVP_CTRL_CCM_SET_IV_FIXED, p->data_size, p->data) == 0)
                        return 0;
        }
        return 1;
}

int
prov_aes_ccm_generic_get_params(OSSL_PARAM params[], unsigned int md, uint64_t flags, size_t kbits,
                                size_t blkbits, size_t ivbits)
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
        if (p != NULL && !OSSL_PARAM_set_uint(p, md))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CTS) != 0))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK) != 0))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8))
                return 0;
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8))
                return 0;
        return 1;
}

static void
prov_aes_ccm_freectx(ALG_CTX *ctx)
{
        if (ctx != NULL) {
                OPENSSL_free(ctx->cipher);
                prov_sw_ccm_cleanup(ctx);
                OPENSSL_clear_free(ctx, sizeof(*ctx));
        }
}

static const OSSL_PARAM prov_aes_ccm_known_gettable_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
        OSSL_PARAM_END
};

const OSSL_PARAM *
prov_aes_ccm_generic_gettable_params(ossl_unused void *provctx)
{
        return prov_aes_ccm_known_gettable_params;
}

static const OSSL_PARAM prov_aes_ccm_aead_known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, NULL, 0),
        OSSL_PARAM_END
};

const OSSL_PARAM *
prov_aes_ccm_aead_gettable_ctx_params()
{
        return prov_aes_ccm_aead_known_gettable_ctx_params;
}

static const OSSL_PARAM prov_aes_ccm_aead_known_settable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
        OSSL_PARAM_END
};

const OSSL_PARAM *
prov_aes_ccm_aead_settable_ctx_params()
{
        return prov_aes_ccm_aead_known_settable_ctx_params;
}

/* prov_aes_128_ccm_functions */
PROV_aes_cipher(prov_aes, ccm, CCM, AEAD_FLAGS, 128, 8, 96, NID_aes_128_ccm);
/* prov_aes_256_ccm_functions */
PROV_aes_cipher(prov_aes, ccm, CCM, AEAD_FLAGS, 256, 8, 96, NID_aes_256_ccm);
