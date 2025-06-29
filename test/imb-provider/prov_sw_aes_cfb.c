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
#include <openssl/tls1.h>

/* Intel IPsec library include */
#include <intel-ipsec-mb.h>

/* Local Includes */
#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_aes_cfb.h"

#include "prov_sw_request.h"
#include "prov_events.h"
#include "prov_sw_submit.h"

const char *
prov_aes_cfb_cipher_name(int nid)
{
        switch (nid) {
        case NID_aes_128_cfb128:
                return LN_aes_128_cfb128;
        case NID_aes_192_cfb128:
                return LN_aes_192_cfb128;
        case NID_aes_256_cfb128:
                return LN_aes_256_cfb128;
        default:
                return NULL;
        }
}

void
aes_cfb_async_cleanup(ALG_CTX *ctx)
{
        if (ctx) {
                if (ctx->enc_keys)
                        OPENSSL_free(ctx->enc_keys);
                if (ctx->dec_keys)
                        OPENSSL_free(ctx->dec_keys);
                ctx->enc_keys = NULL;
                ctx->dec_keys = NULL;
        }
}

int
aes_cfb_async_init(ALG_CTX *ctx, const unsigned char *inkey, size_t keylen, const unsigned char *iv,
                   size_t ivlen, int enc)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL)
                return 0;

        ctx->ivlen = 16;

        if (!ctx->enc_keys)
                ctx->enc_keys = OPENSSL_zalloc(PROV_ENC_DEC_KEY_SIZE * 16);
        if (!ctx->dec_keys)
                ctx->dec_keys = OPENSSL_zalloc(PROV_ENC_DEC_KEY_SIZE * 16);

        switch (keylen) {
        case 16:
                IMB_AES_KEYEXP_128(tlv->imb_mgr, (const char *) inkey, ctx->enc_keys,
                                   ctx->dec_keys);
                break;
        case 24:
                IMB_AES_KEYEXP_192(tlv->imb_mgr, (const char *) inkey, ctx->enc_keys,
                                   ctx->dec_keys);
                break;
        case 32:
                IMB_AES_KEYEXP_256(tlv->imb_mgr, (const char *) inkey, ctx->enc_keys,
                                   ctx->dec_keys);
                break;
        default:
                return 0;
        }

        return 1;
}

int
aes_cfb_async_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
                        const unsigned char *in, size_t len)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL) {
                fprintf(stderr, "AES-CFB ctx is NULL.\n");
                return 0;
        }

        if (out == NULL || in == NULL)
                return 0;

        if (ctx->nid != NID_aes_128_cfb128 && ctx->nid != NID_aes_192_cfb128 &&
            ctx->nid != NID_aes_256_cfb128)
                return -1;

        ASYNC_JOB *async_job = ASYNC_get_current_job();
        if (async_job == NULL) {
                fprintf(stderr, "Not running asynchronously, exit\n");
                return 0;
        }

        struct IMB_JOB *imb_job = IMB_GET_NEXT_JOB(tlv->imb_mgr);

        imb_job->dst = out;
        imb_job->src = in;
        if (ctx->enc) {
                imb_job->cipher_direction = IMB_DIR_ENCRYPT;
        } else {
                imb_job->cipher_direction = IMB_DIR_DECRYPT;
        }
        imb_job->chain_order = IMB_ORDER_CIPHER_HASH;
        imb_job->cipher_mode = IMB_CIPHER_CFB;
        imb_job->hash_alg = IMB_AUTH_NULL;
        imb_job->enc_keys = ctx->enc_keys;
        imb_job->dec_keys = ctx->dec_keys;
        imb_job->key_len_in_bytes = ctx->keylen;
        imb_job->iv = ctx->next_iv;
        imb_job->iv_len_in_bytes = ctx->ivlen;
        imb_job->cipher_start_src_offset_in_bytes = 0;
        imb_job->msg_len_to_cipher_in_bytes = len;
        imb_job->user_data2 = async_job;

        int ret = async_update(tlv, ctx, async_job, imb_job);
        if (ret == 0) {
                fprintf(stderr, "Failed to process job/s\n");
                return 0;
        }

        return ret;
}
