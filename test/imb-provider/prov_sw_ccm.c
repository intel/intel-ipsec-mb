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

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>

/* Intel IPsec library include */
#include <intel-ipsec-mb.h>
#include <emmintrin.h>

/* Local Includes */
#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_request.h"
#include "prov_events.h"
#include "prov_sw_ccm.h"
#include "prov_aes_ccm.h"
#include "prov_sw_freelist.h"
#include "prov_sw_submit.h"

int
prov_sw_ccm_init(ALG_CTX *ctx, const unsigned char *key, const size_t keylen,
                 const unsigned char *iv, const size_t ivlen, const int enc)
{
        if (ctx == NULL)
                return 0;

        if (ctx->nid != NID_aes_128_ccm && ctx->nid != NID_aes_256_ccm)
                return 0;

        ctx->enc = enc;

        /* Use the provided ivlen if valid, otherwise use default */
        if (ivlen > 0 && ivlen <= PROV_CCM_IV_MAX_LEN) {
                ctx->iv_len = ivlen;
        } else if (ctx->iv_len <= 0) {
                ctx->iv_len = PROV_CCM_IV_MAX_LEN;
        }

        /* Initialize IV memory to zero */
        memset(ctx->iv, 0, sizeof(ctx->iv));
        memset(ctx->next_iv, 0, sizeof(ctx->next_iv));
        ctx->iv_set = 0;

        if (iv != NULL && ivlen > 0) {
                /* Use the smaller of the two lengths to prevent buffer overflow */
                size_t copy_len = (ivlen < ctx->iv_len) ? ivlen : ctx->iv_len;
                memcpy(ctx->iv, iv, copy_len);
                memcpy(ctx->next_iv, iv, copy_len);
                ctx->iv_set = 1;
        }

        return 1;
}

int
prov_sw_ccm_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, const size_t outsize,
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

        const int key_len = ctx->keylen;

        /* Additional safety checks */
        if (ctx->iv_len <= 0) {
                fprintf(stderr, "Invalid IV configuration\n");
                return 0;
        }

        /* CCM requires tag length to be set */
        if (ctx->M <= 0) {
                ctx->M = 12; /* Default tag length */
        }

        if (!ctx->enc_keys) {
                size_t required_size =
                        (key_len == 16) ? 11 * 16
                                        : 15 * 16; /* 11 round keys for AES-128, 15 for AES-256 */
                ctx->enc_keys = OPENSSL_zalloc(required_size);
        }

        /* Expand keys if not already done */
        if (ctx->key) {
                unsigned char dec_keys_unused[16 * 15]; /* CCM doesn't use dec_keys */
                if (key_len == 16) {
                        IMB_AES_KEYEXP_128(tlv->imb_mgr, ctx->key, ctx->enc_keys, dec_keys_unused);
                } else if (key_len == 32) {
                        IMB_AES_KEYEXP_256(tlv->imb_mgr, ctx->key, ctx->enc_keys, dec_keys_unused);
                } else {
                        fprintf(stderr, "Unsupported key length: %d\n", key_len);
                        return 0;
                }
        }

        if (ctx->nid != NID_aes_128_ccm && ctx->nid != NID_aes_256_ccm)
                return -1;

        ASYNC_JOB *async_job = ASYNC_get_current_job();
        if (async_job == NULL) {
                fprintf(stderr, "Not running asynchronously, exit\n");
                return 0;
        }

        struct IMB_JOB *imb_job = IMB_GET_NEXT_JOB(tlv->imb_mgr);

        if (!imb_job) {
                fprintf(stderr, "Failed to get IMB job\n");
                return 0;
        }

        imb_job->dst = out;
        imb_job->src = in;
        if (ctx->enc) {
                imb_job->cipher_direction = IMB_DIR_ENCRYPT;
                imb_job->chain_order = IMB_ORDER_CIPHER_HASH;
        } else {
                imb_job->cipher_direction = IMB_DIR_DECRYPT;
                imb_job->chain_order = IMB_ORDER_HASH_CIPHER;
        }
        imb_job->cipher_mode = IMB_CIPHER_CCM;
        imb_job->hash_alg = IMB_AUTH_AES_CCM;
        imb_job->enc_keys = ctx->enc_keys;
        imb_job->dec_keys = ctx->enc_keys;
        imb_job->key_len_in_bytes = key_len;
        imb_job->iv = ctx->next_iv;
        imb_job->iv_len_in_bytes = ctx->iv_len;
        imb_job->cipher_start_src_offset_in_bytes = 0;
        imb_job->msg_len_to_cipher_in_bytes = len;
        imb_job->user_data2 = async_job;
        imb_job->hash_start_src_offset_in_bytes = 0;
        imb_job->u.CCM.aad_len_in_bytes = 0;
        imb_job->u.CCM.aad = ctx->aad;
        if (ctx->tls_aad_len > 0) {
                imb_job->u.CCM.aad_len_in_bytes = ctx->tls_aad_len;
        } else {
                imb_job->u.CCM.aad_len_in_bytes = 0;
        }
        imb_job->auth_tag_output = ctx->auths;
        imb_job->auth_tag_output_len_in_bytes = ctx->M;
        imb_job->msg_len_to_hash_in_bytes = len;

        int ret = async_update(tlv, ctx, async_job, imb_job);
        if (ret == 0) {
                fprintf(stderr, "Failed to process job/s\n");
                return 0;
        }

        /* Set the output length to the input length for CCM */
        if (outl) {
                *outl = len;
        }

        return 1; /* Return 1 for success instead of ret */
}

int
prov_sw_ccm_cleanup(ALG_CTX *ctx)
{
        if (ctx) {
                /* Free allocated memory but not the context itself */
                if (ctx->aad) {
                        OPENSSL_free(ctx->aad);
                        ctx->aad = NULL;
                }
                if (ctx->key) {
                        OPENSSL_free(ctx->key);
                        ctx->key = NULL;
                }
                if (ctx->enc_keys) {
                        OPENSSL_free(ctx->enc_keys);
                        ctx->enc_keys = NULL;
                }
        }

        return 1;
}

int
prov_aes_ccm_ctrl(ALG_CTX *ctx, const int type, int arg, const void *ptr)
{
        unsigned int plen = 0;
        int enc = 0;
        if (NULL == ctx)
                return 0;

        enc = ctx->enc;

        if (NULL == ctx)
                return 0;

        switch (type) {
        case EVP_CTRL_INIT:
                ctx->tag_set = 0;
                ctx->M = 12;
                ctx->tls_aad_len = -1;
                return 1;
        case EVP_CTRL_CCM_SET_IV_FIXED:
                if (NULL == ptr) {
                        return 0;
                }

                /* Special case: -1 length restores whole IV */
                if (arg == -1) {
                        memcpy(ctx->next_iv, ptr, PROV_CCM_TLS_TOTAL_IV_LEN);
                        return 1;
                }
                /* Fixed field must be at least 4 bytes (EVP_CCM_TLS_FIXED_IV_LEN)
                 * and invocation field at least 8 (EVP_CCM_TLS_EXPLICIT_IV_LEN)
                 */
                if ((arg < EVP_CCM_TLS_FIXED_IV_LEN) ||
                    (ctx->iv_len - arg) < EVP_CCM_TLS_EXPLICIT_IV_LEN) {
                        return 0;
                }

                if (arg != EVP_CCM_TLS_FIXED_IV_LEN) {
                        return 0;
                }
                if (arg) {
                        memcpy(ctx->next_iv, ptr, arg);
                }
                return 1;
        case EVP_CTRL_AEAD_SET_TAG:

                if (arg < PROV_CCM_TAG_MIN_LEN || arg > PROV_CCM_TAG_MAX_LEN) {
                        return 0;
                }
                /* Use our own buffer from ALG_CTX instead of EVP_CIPHER_CTX buffer */
                if (ptr) {
                        /* Ensure we don't copy more than our buffer can hold */
                        size_t copy_len = (arg < sizeof(ctx->buf)) ? arg : sizeof(ctx->buf);
                        memcpy(ctx->buf, ptr, copy_len);
                        ctx->tag_set = 1;
                }
                ctx->tag_len = arg;
                ctx->M = arg;
                return 1;
        case EVP_CTRL_AEAD_GET_TAG:

                if (arg <= PROV_CCM_TAG_MIN_LEN || arg > PROV_CCM_TAG_MAX_LEN || !enc) {
                        return 0;
                }
                if (NULL == ptr) {
                        return 0;
                }
                /* Use the auth tag from the completed operation */
                size_t copy_len = (arg < sizeof(ctx->auths)) ? arg : sizeof(ctx->auths);
                memcpy((void *) ptr, ctx->auths, copy_len);
                ctx->tag_set = 0;
                return 1;
        case EVP_CTRL_AEAD_TLS1_AAD:
                /* Allocate the memory only the first time */
                if (ctx->tls_aad_len <= 0) {
                        int aad_buffer_len = TLS_VIRT_HDR_SIZE;
                        /* The length of the buffer for AAD must be multiple
                         * of block size */
                        if (aad_buffer_len % AES_BLOCK_SIZE) {
                                aad_buffer_len +=
                                        AES_BLOCK_SIZE - (aad_buffer_len % AES_BLOCK_SIZE);
                        }
                        ctx->aad = OPENSSL_malloc(arg);
                        if (NULL == ctx->aad) {
                                return 0;
                        }
                        /* Set the flag to mark the TLS case */
                        ctx->tls_aad_len = arg;
                }
                if (NULL == ctx->aad || NULL == ptr) {
                        return 0;
                }
                /* Copy the header from p into the buffer */
                memcpy(ctx->aad, ptr, arg);
                /* Extract the length of the payload from the TLS header */
                plen = ctx->aad[arg - PROV_CCM_TLS_PAYLOADLENGTH_MSB_OFFSET] << PROV_BYTE_SHIFT |
                       ctx->aad[arg - PROV_CCM_TLS_PAYLOADLENGTH_LSB_OFFSET];
                /* The payload contains the explicit IV -> correct the length */
                plen -= EVP_CCM_TLS_EXPLICIT_IV_LEN;
                /* If decrypting correct for tag too */
                if (!enc) {
                        plen -= ctx->M;
                }
                /* Fix the length like in the SW version of CCM */
                ctx->aad[arg - PROV_CCM_TLS_PAYLOADLENGTH_MSB_OFFSET] = plen >> PROV_BYTE_SHIFT;
                ctx->aad[arg - PROV_CCM_TLS_PAYLOADLENGTH_LSB_OFFSET] = plen & 0xff;
                /* Return the length of the TAG */
                return ctx->M;
        default:
                return -1;
        }
}