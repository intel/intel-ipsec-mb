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
#include "prov_ciphers.h"
#include "e_prov.h"

#include "prov_sw_gcm.h"

int nid;
#define AES_GCM_IV_MIN_SIZE (64 / 8)

#define UNINITIALISED_SIZET ((int) -1)

#define AEAD_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

const char *
prov_gcm_cipher_name(int nid)
{
        switch (nid) {
        case NID_aes_128_gcm:
                return LN_aes_128_gcm;
        case NID_aes_192_gcm:
                return LN_aes_192_gcm;
        case NID_aes_256_gcm:
                return LN_aes_256_gcm;
        default:
                fprintf(stderr, "Invalid nid %d\n", nid);
                return NULL;
        }
}
PROV_EVP_CIPHER
get_default_cipher_aes_gcm(int nid)
{
        static PROV_EVP_CIPHER gcm_cipher;
        static int initialized = 0;
        if (!initialized) {
                PROV_EVP_CIPHER *cipher = (PROV_EVP_CIPHER *) EVP_CIPHER_fetch(
                        NULL, prov_gcm_cipher_name(nid), "provider=default");
                if (cipher) {
                        gcm_cipher = *cipher;
                        EVP_CIPHER_free((EVP_CIPHER *) cipher);
                        initialized = 1;
                } else {
                        fprintf(stderr, "EVP_CIPHER_fetch from default provider failed");
                }
        }
        return gcm_cipher;
}

int
prov_aes_gcm_ctx_get_nid(const PROV_AES_GCM_CTX *ctx)
{
        return ctx->cipher->nid;
}

void
prov_gcm_initctx(void *provctx, PROV_GCM_CTX *ctx, size_t keybits, size_t ivlen_min)
{
        ctx->pad = 1;
        ctx->mode = EVP_CIPH_GCM_MODE;
        ctx->tag_len = UNINITIALISED_SIZET;
        ctx->tls_aad_len = UNINITIALISED_SIZET;
        ctx->ivlen_min = ivlen_min;
        ctx->iv_len = (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN);
        ctx->keylen = keybits / 8;
        ctx->libctx = prov_libctx_of(provctx);
}

static void *
prov_aes_gcm_newctx(void *provctx, size_t keybits, int nid)
{
        PROV_EVP_CIPHER *cipher = NULL;
        PROV_AES_GCM_CTX *ctx;

        if (!prov_is_running())
                return NULL;

        ctx = OPENSSL_zalloc(sizeof(*ctx));
        cipher = OPENSSL_zalloc(sizeof(PROV_EVP_CIPHER));

        cipher->nid = nid;
        ctx->cipher = cipher;

        if (ctx != NULL)
                prov_gcm_initctx(provctx, &ctx->base, keybits, AES_GCM_IV_MIN_SIZE);
        return ctx;
}

int
prov_gcm_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
        PROV_GCM_CTX *ctx = (PROV_GCM_CTX *) vctx;
        OSSL_PARAM *p;
        size_t sz;
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->iv_len)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if (p != NULL) {
                size_t taglen =
                        (ctx->tag_len != UNINITIALISED_SIZET) ? ctx->tag_len : GCM_TAG_MAX_SIZE;

                if (!OSSL_PARAM_set_size_t(p, taglen)) {
                        return 0;
                }
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if (p != NULL) {
                if (ctx->iv_set == IV_STATE_UNINITIALISED)
                        return 0;
                if (ctx->iv_len > p->data_size) {
                        return 0;
                }
                if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->iv_len) &&
                    !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->iv_len)) {
                        return 0;
                }
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if (p != NULL) {
                if (ctx->iv_set == IV_STATE_UNINITIALISED)
                        return 0;
                if (ctx->iv_len > p->data_size) {
                        return 0;
                }
                if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->iv_len) &&
                    !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->iv_len)) {
                        return 0;
                }
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tls_aad_pad_sz)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
                sz = p->data_size;
                if (sz == 0 || sz > EVP_GCM_TLS_TAG_LEN || !ctx->enc ||
                    ctx->tag_len == UNINITIALISED_SIZET) {
                        return 0;
                }
                if (!OSSL_PARAM_set_octet_string(p, ctx->buf, sz)) {
                        return 0;
                }
        }

        return 1;
}

int
prov_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
        PROV_GCM_CTX *ctx = (PROV_GCM_CTX *) vctx;
        const OSSL_PARAM *p;
        size_t sz = 0;
        void *vp;

        if (params == NULL)
                return 1;

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
                vp = ctx->buf;
                if (!OSSL_PARAM_get_octet_string(p, &vp, EVP_GCM_TLS_TAG_LEN, &sz)) {
                        return 0;
                }
                if (sz == 0 || ctx->enc) {
                        return 0;
                }
                ctx->tag_len = sz;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
        if (p != NULL) {
                if (!OSSL_PARAM_get_size_t(p, &sz)) {
                        return 0;
                }
                if (sz == 0 || sz > ctx->iv_len) {
                        return 0;
                }
                ctx->iv_len = sz;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
        if (p != NULL) {
                if (p->data_type != OSSL_PARAM_OCTET_STRING) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                        return 0;
                }
                sz = vaesgcm_ciphers_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, p->data_size, p->data);
                if (sz == 0) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_AAD);
                        return 0;
                }
                ctx->tls_aad_pad_sz = sz;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
        if (p != NULL) {
                if (p->data_type != OSSL_PARAM_OCTET_STRING) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                        return 0;
                }
                if (vaesgcm_ciphers_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, p->data_size, p->data) ==
                    0) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                        return 0;
                }
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV);
        if (p != NULL) {
                if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING ||
                    !vaesgcm_ciphers_ctrl(ctx, EVP_CTRL_GCM_SET_IV_INV, p->data_size, p->data))
                        return 0;
        }
        return 1;
}

int
prov_gcm_einit(void *vctx, const unsigned char *inkey, int keylen, const unsigned char *iv,
               int ivlen, int enc)
{
        int sts = 0;
        PROV_GCM_CTX *ctx = (PROV_GCM_CTX *) vctx;
        sts = vaesgcm_ciphers_init(ctx, inkey, iv, 1);
        return sts;
}

int
prov_gcm_dinit(void *vctx, const unsigned char *inkey, int keylen, const unsigned char *iv,
               int ivlen, int enc)
{
        int sts = 0;
        PROV_GCM_CTX *ctx = (PROV_GCM_CTX *) vctx;
        sts = vaesgcm_ciphers_init(ctx, inkey, iv, 0);
        return sts;
}

int
prov_gcm_stream_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                       const unsigned char *in, size_t inl)
{

        int ret = 0;
        PROV_GCM_CTX *ctx = (PROV_GCM_CTX *) vctx;

        if (inl == 0) {
                *outl = 0;
                ret = 1;
                goto end;
        }

        if (outsize < inl) {
                goto end;
        }

        if ((ret = vaesgcm_ciphers_do_cipher(ctx, out, outl, in, inl)) <= 0) {
                goto end;
        }
        ret = 1;

end:
        return ret;
}

int
prov_gcm_stream_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
        int ret = 0;

        PROV_GCM_CTX *ctx = (PROV_GCM_CTX *) vctx;
        int i = 0;

        if (!prov_is_running())
                goto end;

        i = vaesgcm_ciphers_do_cipher(ctx, out, outl, NULL, 0);

        if (i <= 0)
                goto end;

        *outl = 0;
        ret = 1;

end:
        return ret;
}

int
prov_gcm_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                const unsigned char *in, size_t inl)
{
        int ret = 0;
        PROV_GCM_CTX *ctx = (PROV_GCM_CTX *) vctx;

        if (!prov_is_running())
                goto end;

        if (outsize < inl) {
                goto end;
        }

        if (vaesgcm_ciphers_do_cipher(ctx, out, outl, in, inl) <= 0)
                goto end;
        *outl = inl;
        ret = 1;

end:
        return ret;
}

static void
prov_aes_gcm_freectx(void *vctx)
{
        PROV_AES_GCM_CTX *ctx = (PROV_AES_GCM_CTX *) vctx;
        if (ctx->cipher) {
                OPENSSL_free(ctx->cipher);
                ctx->cipher = NULL;
        }
        vaesgcm_ciphers_cleanup((PROV_GCM_CTX *) ctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static const OSSL_PARAM prov_cipher_known_gettable_params[] = {
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
prov_cipher_generic_gettable_params(ossl_unused void *provctx)
{
        return prov_cipher_known_gettable_params;
}

int
prov_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md, uint64_t flags, size_t kbits,
                               size_t blkbits, size_t ivbits)
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
        if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CTS) != 0)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK) != 0)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
        if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
                return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
                return 0;
        }
        return 1;
}

static const OSSL_PARAM prov_cipher_aead_known_gettable_ctx_params[] = {
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
prov_cipher_aead_gettable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
        return prov_cipher_aead_known_gettable_ctx_params;
}

static const OSSL_PARAM prov_cipher_aead_known_settable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
        OSSL_PARAM_END
};

const OSSL_PARAM *
prov_cipher_aead_settable_ctx_params(ossl_unused void *cctx, ossl_unused void *provctx)
{
        return prov_cipher_aead_known_settable_ctx_params;
}

/* prov_aes128gcm_functions */
PROV_aes_gcm_cipher(prov_aes, gcm, GCM, AEAD_FLAGS, 128, 8, 96, NID_aes_128_gcm);
/* prov_aes192gcm_functions */
PROV_aes_gcm_cipher(prov_aes, gcm, GCM, AEAD_FLAGS, 192, 8, 96, NID_aes_192_gcm);
/* prov_aes256gcm_functions */
PROV_aes_gcm_cipher(prov_aes, gcm, GCM, AEAD_FLAGS, 256, 8, 96, NID_aes_256_gcm);
