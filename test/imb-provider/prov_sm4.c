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

/* Standard Includes */
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* Intel IPsec library include */
#include <intel-ipsec-mb.h>

/* Local Includes */
#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sm4.h"
#include "prov_sw_request.h"
#include "prov_events.h"
#include "prov_sw_submit.h"

/* Forward declaration */
static int
prov_sm4_init(void *vctx, const unsigned char *key, int keylen, const unsigned char *iv,
              const int ivlen, const int enc);

int
sm4_async_cleanup(ALG_CTX *ctx)
{
        if (ctx) {
                if (ctx->enc_keys)
                        OPENSSL_free(ctx->enc_keys);
                if (ctx->dec_keys)
                        OPENSSL_free(ctx->dec_keys);
                if (ctx->aad)
                        OPENSSL_free(ctx->aad);
                ctx->enc_keys = NULL;
                ctx->dec_keys = NULL;
                ctx->aad = NULL;
                ctx->aad_len = 0;
        }
        return 1;
}

int
sm4_async_init(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
               const unsigned char *iv, const size_t ivlen, const int enc)
{
        if (mb_check_thread_local() == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL)
                return 0;

        /* Set common parameters */
        ctx->keylen = keylen;
        ctx->enc = enc;

        /* Handle NULL key case (re-initialization) */
        if (inkey == NULL) {
                if (!ctx->key_set) {
                        fprintf(stderr, "No key previously set for %d\n", ctx->nid);
                        return 0;
                }

                if (iv != NULL) {
                        /* IV validation based on cipher mode */
                        switch (ctx->nid) {
                        case NID_sm4_ecb:
                                /* ECB doesn't use IV */
                                break;
                        case NID_sm4_cbc:
                        case NID_sm4_ctr:
                                if (ivlen != SM4_IV_SIZE) {
                                        fprintf(stderr,
                                                "Invalid SM4-CBC or SM4-CTR IV length: %zu "
                                                "(expected %d)\n",
                                                ivlen, SM4_IV_SIZE);
                                        return 0;
                                }
                                memcpy(ctx->iv, iv, SM4_IV_SIZE);
                                memcpy(ctx->oiv, iv, SM4_IV_SIZE);
                                ctx->iv_set = 1;
                                break;
                        case NID_sm4_gcm:
                                if (ivlen < 1 || ivlen > SM4_GCM_IV_MAX_SIZE) {
                                        fprintf(stderr,
                                                "Invalid SM4-GCM IV length: %zu (expected 1-%d)\n",
                                                ivlen, SM4_GCM_IV_MAX_SIZE);
                                        return 0;
                                }
                                memcpy(ctx->iv, iv, ivlen);
                                memcpy(ctx->oiv, iv, ivlen);
                                ctx->ivlen = ivlen;
                                ctx->iv_set = 1;
                                break;
                        }
                }
                return 1;
        }

        /* Key length validation */
        if (keylen != SM4_KEY_SIZE) {
                fprintf(stderr, "Invalid SM4 key length: %zu (expected %d)\n", keylen,
                        SM4_KEY_SIZE);
                return 0;
        }

        /* Set mode-specific parameters */
        switch (ctx->nid) {
        case NID_sm4_ecb:
                ctx->blocksize = SM4_BLOCK_SIZE;
                ctx->ivlen = 0;  /* ECB doesn't use IV */
                ctx->iv_set = 1; /* ECB always considered IV set */
                break;
        case NID_sm4_cbc:
                ctx->blocksize = SM4_BLOCK_SIZE;
                ctx->ivlen = SM4_IV_SIZE;
                ctx->iv_set = 0;
                if (iv != NULL) {
                        if (ivlen != SM4_IV_SIZE) {
                                fprintf(stderr, "Invalid SM4 IV length: %zu (expected %d)\n", ivlen,
                                        SM4_IV_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, SM4_IV_SIZE);
                        memcpy(ctx->oiv, iv, SM4_IV_SIZE);
                        ctx->iv_set = 1;
                }
                break;
        case NID_sm4_ctr:
                ctx->blocksize = 1; /* CTR can handle any input size */
                ctx->ivlen = SM4_IV_SIZE;
                ctx->iv_set = 0;
                if (iv != NULL) {
                        if (ivlen != SM4_IV_SIZE) {
                                fprintf(stderr, "Invalid SM4 IV length: %zu (expected %d)\n", ivlen,
                                        SM4_IV_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, SM4_IV_SIZE);
                        memcpy(ctx->oiv, iv, SM4_IV_SIZE);
                        ctx->iv_set = 1;
                }
                break;
        case NID_sm4_gcm:
                ctx->blocksize = 1;           /* GCM can handle any input size */
                ctx->ivlen = SM4_GCM_IV_SIZE; /* Default IV size */
                ctx->iv_set = 0;
                if (iv != NULL) {
                        if (ivlen < 1 || ivlen > SM4_GCM_IV_MAX_SIZE) {
                                fprintf(stderr, "Invalid SM4-GCM IV length: %zu (expected 1-%d)\n",
                                        ivlen, SM4_GCM_IV_MAX_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, ivlen);
                        memcpy(ctx->oiv, iv, ivlen);
                        ctx->ivlen = ivlen;
                        ctx->iv_set = 1;
                }
                break;
        }

        /* Allocate key memory */
        if (!ctx->enc_keys)
                ctx->enc_keys = OPENSSL_zalloc(PROV_ENC_DEC_KEY_SIZE * 16);
        if (!ctx->dec_keys)
                ctx->dec_keys = OPENSSL_zalloc(PROV_ENC_DEC_KEY_SIZE * 16);

        if (!ctx->enc_keys || !ctx->dec_keys) {
                fprintf(stderr, "Failed to allocate SM4 key memory\n");
                OPENSSL_free(ctx->enc_keys);
                OPENSSL_free(ctx->dec_keys);
                ctx->enc_keys = NULL;
                ctx->dec_keys = NULL;
                return 0;
        }

        /* SM4 key expansion - store the key directly since SM4 uses same key for enc/dec */
        memcpy(ctx->enc_keys, inkey, keylen);
        memcpy(ctx->dec_keys, inkey, keylen);

        ctx->key_set = 1;

        return 1;
}

static int
sm4_async_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
                    const unsigned char *in, const size_t len)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL)
                return 0;

        if (out == NULL && in == NULL)
                return 0;

        const int nid = ctx->nid;

        if (nid != NID_sm4_ecb && nid != NID_sm4_cbc && nid != NID_sm4_gcm && nid != NID_sm4_ctr)
                return 0;

        /* Block size validation for ECB and CBC modes */
        if ((nid == NID_sm4_ecb || nid == NID_sm4_cbc) && len % SM4_BLOCK_SIZE != 0) {
                const char *mode_name = (nid == NID_sm4_ecb) ? "ECB" : "CBC";
                fprintf(stderr, "SM4-%s: Input length must be multiple of block size (%d)\n",
                        mode_name, SM4_BLOCK_SIZE);
                return 0;
        }

        ASYNC_JOB *async_job = ASYNC_get_current_job();
        if (async_job == NULL) {
                fprintf(stderr, "Not running asynchronously, exit\n");
                return 0;
        }

        struct IMB_JOB *imb_job = IMB_GET_NEXT_JOB(tlv->imb_mgr);

        memset(imb_job, 0, sizeof(*imb_job));

        imb_job->dst = out;
        imb_job->src = in;
        imb_job->cipher_direction = ctx->enc ? IMB_DIR_ENCRYPT : IMB_DIR_DECRYPT;
        imb_job->enc_keys = ctx->enc_keys;
        imb_job->dec_keys = ctx->dec_keys;
        imb_job->key_len_in_bytes = ctx->keylen;
        imb_job->cipher_start_src_offset_in_bytes = 0;
        imb_job->msg_len_to_cipher_in_bytes = len;
        imb_job->user_data2 = async_job;

        /* Set mode-specific parameters */
        switch (nid) {
        case NID_sm4_ecb:
                imb_job->cipher_mode = IMB_CIPHER_SM4_ECB;
                imb_job->hash_alg = IMB_AUTH_NULL;
                imb_job->chain_order = IMB_ORDER_CIPHER_HASH;
                imb_job->iv = NULL;
                imb_job->iv_len_in_bytes = 0;
                break;

        case NID_sm4_cbc:
                imb_job->cipher_mode = IMB_CIPHER_SM4_CBC;
                imb_job->hash_alg = IMB_AUTH_NULL;
                imb_job->chain_order = IMB_ORDER_CIPHER_HASH;
                imb_job->iv = ctx->iv;
                imb_job->iv_len_in_bytes = ctx->ivlen;
                break;

        case NID_sm4_ctr:
                imb_job->cipher_mode = IMB_CIPHER_SM4_CTR;
                imb_job->hash_alg = IMB_AUTH_NULL;
                imb_job->chain_order = IMB_ORDER_CIPHER_HASH;
                imb_job->iv = ctx->iv;
                imb_job->iv_len_in_bytes = ctx->ivlen;
                break;

        case NID_sm4_gcm:
                imb_job->cipher_mode = IMB_CIPHER_SM4_GCM;
                imb_job->hash_alg = IMB_AUTH_SM4_GCM;
                imb_job->chain_order = ctx->enc ? IMB_ORDER_CIPHER_HASH : IMB_ORDER_HASH_CIPHER;
                imb_job->iv = ctx->iv;
                imb_job->iv_len_in_bytes = ctx->ivlen;
                /* GCM-specific fields */
                imb_job->u.GCM.aad = ctx->aad;
                imb_job->u.GCM.aad_len_in_bytes = ctx->aad_len;
                imb_job->auth_tag_output = ctx->auths;
                imb_job->auth_tag_output_len_in_bytes = 16;
                break;

        default:
                fprintf(stderr, "Unsupported SM4 cipher mode: %d\n", nid);
                return 0;
        }

        const int ret = async_update(tlv, ctx, async_job, imb_job);
        if (ret == 0) {
                fprintf(stderr, "Failed to process job/s\n");
                return 0;
        }

        *outl = len;
        return ret;
}

/* Provider interface functions */
void *
prov_sm4_ecb_newctx(void *provctx)
{
        ALG_CTX *ctx = OPENSSL_zalloc(sizeof(ALG_CTX));
        if (ctx == NULL)
                return NULL;

        ctx->provctx = provctx;
        ctx->nid = NID_sm4_ecb;
        ctx->blocksize = SM4_BLOCK_SIZE;
        ctx->ivlen = 0; /* ECB doesn't use IV */
        ctx->keylen = SM4_KEY_SIZE;

        return ctx;
}

void *
prov_sm4_cbc_newctx(void *provctx)
{
        ALG_CTX *ctx = OPENSSL_zalloc(sizeof(ALG_CTX));
        if (ctx == NULL)
                return NULL;

        ctx->provctx = provctx;
        ctx->nid = NID_sm4_cbc;
        ctx->blocksize = SM4_BLOCK_SIZE;
        ctx->ivlen = SM4_IV_SIZE;
        ctx->keylen = SM4_KEY_SIZE;

        return ctx;
}

void *
prov_sm4_gcm_newctx(void *provctx)
{
        ALG_CTX *ctx = OPENSSL_zalloc(sizeof(ALG_CTX));
        if (ctx == NULL)
                return NULL;

        ctx->provctx = provctx;
        ctx->nid = NID_sm4_gcm;
        ctx->blocksize = 1; /* GCM can handle any input size */
        ctx->ivlen = SM4_GCM_IV_SIZE;
        ctx->keylen = SM4_KEY_SIZE;

        return ctx;
}

void *
prov_sm4_ctr_newctx(void *provctx)
{
        ALG_CTX *ctx = OPENSSL_zalloc(sizeof(ALG_CTX));
        if (ctx == NULL)
                return NULL;

        ctx->provctx = provctx;
        ctx->nid = NID_sm4_ctr;
        ctx->blocksize = 1; /* CTR can handle any input size */
        ctx->ivlen = SM4_IV_SIZE;
        ctx->keylen = SM4_KEY_SIZE;

        return ctx;
}

void
prov_sm4_freectx(void *vctx)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        if (ctx != NULL) {
                sm4_async_cleanup(ctx);
                OPENSSL_clear_free(ctx, sizeof(ALG_CTX));
        }
}

int
prov_sm4_encrypt_init(void *vctx, const unsigned char *key, const int keylen,
                      const unsigned char *iv, const int ivlen, const int enc)
{
        return prov_sm4_init(vctx, key, keylen, iv, ivlen, 1);
}

int
prov_sm4_decrypt_init(void *vctx, const unsigned char *key, const int keylen,
                      const unsigned char *iv, const int ivlen, const int enc)
{
        return prov_sm4_init(vctx, key, keylen, iv, ivlen, 0);
}

static int
prov_sm4_init(void *vctx, const unsigned char *key, const int keylen, const unsigned char *iv,
              const int ivlen, const int enc)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (ctx == NULL)
                return 0;

        /* If key is NULL, we're doing a re-init with the same key */
        if (key == NULL) {
                /* Use existing key, just update enc flag */
                ctx->enc = enc;

                /* Handle IV for re-init */
                if (ctx->nid == NID_sm4_cbc && iv != NULL) {
                        if (ivlen != SM4_IV_SIZE) {
                                fprintf(stderr, "Invalid SM4 IV length: %d (expected %d)\n", ivlen,
                                        SM4_IV_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, SM4_IV_SIZE);
                        memcpy(ctx->oiv, iv, SM4_IV_SIZE);
                        ctx->iv_set = 1;
                } else if (ctx->nid == NID_sm4_ctr && iv != NULL) {
                        if (ivlen != SM4_IV_SIZE) {
                                fprintf(stderr, "Invalid SM4 IV length: %d (expected %d)\n", ivlen,
                                        SM4_IV_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, SM4_IV_SIZE);
                        memcpy(ctx->oiv, iv, SM4_IV_SIZE);
                        ctx->iv_set = 1;
                } else if (ctx->nid == NID_sm4_gcm && iv != NULL) {
                        if (ivlen < 1 || ivlen > SM4_GCM_IV_MAX_SIZE) {
                                fprintf(stderr, "Invalid SM4-GCM IV length: %d (expected 1-%d)\n",
                                        ivlen, SM4_GCM_IV_MAX_SIZE);
                                return 0;
                        }
                        memcpy(ctx->iv, iv, ivlen);
                        memcpy(ctx->oiv, iv, ivlen);
                        ctx->ivlen = ivlen;
                        ctx->iv_set = 1;
                } else if (ctx->nid == NID_sm4_cbc && iv == NULL && ctx->iv_set) {
                        /* Restore original IV for CBC */
                        memcpy(ctx->iv, ctx->oiv, SM4_IV_SIZE);
                } else if (ctx->nid == NID_sm4_ctr && iv == NULL && ctx->iv_set) {
                        /* Restore original IV for CTR */
                        memcpy(ctx->iv, ctx->oiv, SM4_IV_SIZE);
                } else if (ctx->nid == NID_sm4_gcm && iv == NULL && ctx->iv_set) {
                        /* Restore original IV for GCM */
                        memcpy(ctx->iv, ctx->oiv, ctx->ivlen);
                }

                return 1;
        }

        /* Normal initialization with new key - use unified function */
        return sm4_async_init(ctx, key, keylen, iv, ivlen, enc);
}

int
prov_sm4_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                const unsigned char *in, const size_t inl)
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;

        if (ctx == NULL)
                return 0;

        if (ctx->nid == NID_sm4_ecb || ctx->nid == NID_sm4_cbc || ctx->nid == NID_sm4_ctr ||
            ctx->nid == NID_sm4_gcm) {
                return sm4_async_do_cipher(ctx, out, outl, outsize, in, inl);
        }

        return 0;
}

int
prov_sm4_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
        *outl = 0;
        return 1;
}

int
prov_sm4_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                const unsigned char *in, const size_t inl)
{
        return prov_sm4_update(vctx, out, outl, outsize, in, inl);
}

int
prov_sm4_get_params(OSSL_PARAM params[], const int nid, const int mode)
{
        OSSL_PARAM *p;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
        if (p != NULL && !OSSL_PARAM_set_uint(p, mode)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, SM4_KEY_SIZE)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, SM4_BLOCK_SIZE)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL) {
                size_t ivlen;
                if (nid == NID_sm4_ecb) {
                        ivlen = 0;
                } else if (nid == NID_sm4_cbc) {
                        ivlen = SM4_IV_SIZE;
                } else if (nid == NID_sm4_ctr) {
                        ivlen = SM4_IV_SIZE;
                } else if (nid == NID_sm4_gcm) {
                        ivlen = SM4_GCM_IV_SIZE;
                } else {
                        ivlen = 0;
                }
                if (!OSSL_PARAM_set_size_t(p, ivlen)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                        return 0;
                }
        }

        return 1;
}

int
prov_sm4_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        OSSL_PARAM *p;

        if (ctx == NULL)
                return 0;

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if (p != NULL && !OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
        }

        return 1;
}

int
prov_sm4_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
        ALG_CTX *ctx = (ALG_CTX *) vctx;
        const OSSL_PARAM *p;

        if (ctx == NULL)
                return 0;

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL) {
                size_t keylen;
                if (!OSSL_PARAM_get_size_t(p, &keylen)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                        return 0;
                }
                if (keylen != SM4_KEY_SIZE) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                        return 0;
                }
                ctx->keylen = keylen;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IV);
        if (p != NULL) {
                if (ctx->nid == NID_sm4_ecb) {
                        /* ECB mode doesn't use IV */
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                        return 0;
                }
                size_t ivlen;
                const void *iv = NULL;
                if (!OSSL_PARAM_get_octet_string_ptr(p, &iv, &ivlen)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                        return 0;
                }

                /* Validate IV length based on cipher mode */
                if (ctx->nid == NID_sm4_cbc && ivlen != SM4_IV_SIZE) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
                        return 0;
                } else if (ctx->nid == NID_sm4_ctr && ivlen != SM4_IV_SIZE) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
                        return 0;
                } else if (ctx->nid == NID_sm4_gcm && (ivlen < 1 || ivlen > SM4_GCM_IV_MAX_SIZE)) {
                        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
                        return 0;
                }

                memcpy(ctx->iv, iv, ivlen);
                memcpy(ctx->oiv, iv, ivlen);
                ctx->ivlen = ivlen;
                ctx->iv_set = 1;
        }

        return 1;
}

/* Generate the cipher function tables using the macro */
PROV_sm4_cipher(prov_sm4, ecb, ECB, PROV_SM4_ECB_FLAGS, 128, 0, NID_sm4_ecb);
PROV_sm4_cipher(prov_sm4, cbc, CBC, PROV_SM4_CBC_FLAGS, 128, 128, NID_sm4_cbc);
PROV_sm4_cipher(prov_sm4, ctr, CTR, PROV_SM4_CTR_FLAGS, 8, 128, NID_sm4_ctr);
PROV_sm4_cipher(prov_sm4, gcm, GCM, PROV_SM4_GCM_FLAGS, 8, 96, NID_sm4_gcm);
