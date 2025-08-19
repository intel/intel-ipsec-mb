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

#include <stdio.h>
#include <string.h>
#include <intel-ipsec-mb.h>

#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_chacha20.h"
#include "prov_sw_request.h"
#include "prov_events.h"
#include "prov_sw_submit.h"

#define PROV_ENC_DEC_KEY_SIZE 32

void
chacha20_async_cleanup(ALG_CTX *ctx)
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
chacha20_async_init(ALG_CTX *ctx, const unsigned char *inkey, const size_t keylen,
                    const unsigned char *iv, const size_t ivlen, const int enc)
{
        if (mb_check_thread_local() == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL)
                return 0;

        ctx->ivlen = 12;

        if (iv != NULL && ivlen != 12) {
                fprintf(stderr, "Invalid IV length for ChaCha20: %zu (expected 12)\n", ivlen);
                return 0;
        }

        if (!ctx->enc_keys)
                ctx->enc_keys = OPENSSL_zalloc(PROV_ENC_DEC_KEY_SIZE);
        if (!ctx->dec_keys)
                ctx->dec_keys = OPENSSL_zalloc(PROV_ENC_DEC_KEY_SIZE);

        if (keylen != 32) {
                fprintf(stderr, "Invalid key length for ChaCha20: %zu\n", keylen);
                return 0;
        }

        memcpy(ctx->enc_keys, inkey, keylen);
        memcpy(ctx->dec_keys, inkey, keylen);

        ctx->keylen = keylen;
        ctx->enc = enc;
        ctx->key_set = 1;

        return 1;
}

int
chacha20_async_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
                         const unsigned char *in, size_t len)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL) {
                fprintf(stderr, "ChaCha20 ctx is NULL.\n");
                return 0;
        }

        if (ctx->nid != NID_chacha20)
                return -1;

        /* Validate that key has been set */
        if (!ctx->key_set) {
                fprintf(stderr, "ChaCha20 key not set\n");
                return 0;
        }

        /* Validate key length */
        if (ctx->keylen != 32) {
                fprintf(stderr, "Invalid ChaCha20 key length: %zu\n", ctx->keylen);
                return 0;
        }

        /* Validate IV length */
        if (ctx->ivlen != 12) {
                fprintf(stderr, "Invalid ChaCha20 IV length: %zu\n", ctx->ivlen);
                return 0;
        }

        /* Validate output buffer size */
        if (outsize < len) {
                fprintf(stderr, "Output buffer too small: %zu < %zu\n", outsize, len);
                return 0;
        }

        if (in == NULL && out != NULL) {
                fprintf(stderr, "Input is NULL but output is provided.\n");
                return 0;
        }

        ASYNC_JOB *async_job = ASYNC_get_current_job();

        struct IMB_JOB *imb_job = IMB_GET_NEXT_JOB(tlv->imb_mgr);

        imb_job->dst = out;
        imb_job->src = in;
        imb_job->cipher_direction = ctx->enc;
        imb_job->chain_order = IMB_ORDER_CIPHER_HASH;
        imb_job->cipher_mode = IMB_CIPHER_CHACHA20;
        imb_job->hash_alg = IMB_AUTH_NULL;
        imb_job->enc_keys = ctx->enc_keys;
        imb_job->dec_keys = ctx->dec_keys;
        imb_job->key_len_in_bytes = 32;
        imb_job->iv = ctx->next_iv;
        imb_job->iv_len_in_bytes = 12;
        imb_job->cipher_start_src_offset_in_bytes = 0;
        imb_job->msg_len_to_cipher_in_bytes = len;
        imb_job->user_data2 = async_job;

        int ret;
        if (async_job != NULL) {
                ret = async_update(tlv, ctx, async_job, imb_job);
        } else {
                fprintf(stderr, "Async job is NULL\n");
                return 0;
        }

        if (ret == 0) {
                fprintf(stderr, "Failed to process job/s\n");
                return 0;
        }

        if (outl != NULL)
                *outl = len;

        return ret;
}
