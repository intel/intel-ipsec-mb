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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <intel-ipsec-mb.h>

#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_chacha20_poly1305.h"
#include "prov_sw_request.h"
#include "prov_events.h"
#include "prov_sw_submit.h"

#define SUCCESS 1
#define FAILURE 0

int
chacha20_poly1305_async_init(ALG_CTX *ctx, const unsigned char *key, const size_t keylen,
                             const unsigned char *iv, const size_t ivlen, const int enc)
{
        if (!mb_check_thread_local() || !ctx) {
                fprintf(stderr, "Error: Invalid context in chacha20_poly1305_async_init\n");
                return FAILURE;
        }

        if (keylen != CHACHA20_POLY1305_KEY_SIZE) {
                fprintf(stderr, "Error: Invalid key length %zu, expected %d\n", keylen,
                        CHACHA20_POLY1305_KEY_SIZE);
                return FAILURE;
        }

        if (ivlen != CHACHA20_POLY1305_IV_SIZE) {
                fprintf(stderr, "Error: Invalid IV length %zu, expected %d\n", ivlen,
                        CHACHA20_POLY1305_IV_SIZE);
                return FAILURE;
        }

        memcpy(ctx->chacha20_key, key, keylen);
        memcpy(ctx->chacha20_iv, iv, ivlen);
        ctx->keylen = keylen;
        ctx->ivlen = ivlen;
        ctx->enc = enc;
        ctx->key_set = 1;
        ctx->iv_set = 1;

        if (!ctx->tag) {
                ctx->tag = OPENSSL_zalloc(CHACHA20_POLY1305_TAG_SIZE);
                if (!ctx->tag) {
                        fprintf(stderr, "Error: Failed to allocate tag memory\n");
                        return FAILURE;
                }
                ctx->tag_len = CHACHA20_POLY1305_TAG_SIZE;
        }

        return SUCCESS;
}

int
chacha20_poly1305_async_update(ALG_CTX *ctx, const unsigned char *in, const size_t len)
{
        mb_thread_data *tlv = mb_check_thread_local();
        ASYNC_JOB *async_job = NULL;
        IMB_JOB *imb_job = NULL;

        if (!tlv || !ctx || !in) {
                fprintf(stderr, "Error: Invalid parameters in chacha20_poly1305_async_update\n");
                return FAILURE;
        }

        if (len == 0)
                return SUCCESS;

        async_job = ASYNC_get_current_job();
        if (!async_job) {
                fprintf(stderr, "Error: No current async job\n");
                return FAILURE;
        }

        imb_job = IMB_GET_NEXT_JOB(tlv->imb_mgr);
        if (!imb_job) {
                fprintf(stderr, "Error: Failed to get IMB job\n");
                return FAILURE;
        }

        imb_job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
        imb_job->hash_alg = IMB_AUTH_CHACHA20_POLY1305;
        imb_job->cipher_direction = ctx->enc ? IMB_DIR_ENCRYPT : IMB_DIR_DECRYPT;
        imb_job->chain_order = IMB_ORDER_CIPHER_HASH;
        imb_job->enc_keys = ctx->chacha20_key;
        imb_job->key_len_in_bytes = ctx->keylen;
        imb_job->iv = ctx->chacha20_iv;
        imb_job->iv_len_in_bytes = ctx->ivlen;
        imb_job->src = in;
        imb_job->dst = ctx->out;
        imb_job->msg_len_to_cipher_in_bytes = len;
        imb_job->msg_len_to_hash_in_bytes = len;
        imb_job->cipher_start_src_offset_in_bytes = 0;
        imb_job->hash_start_src_offset_in_bytes = 0;
        imb_job->u.CHACHA20_POLY1305.aad = ctx->aad;
        imb_job->u.CHACHA20_POLY1305.aad_len_in_bytes = ctx->aad_len;
        imb_job->auth_tag_output = ctx->auths;
        imb_job->auth_tag_output_len_in_bytes = ctx->tag_len;
        imb_job->user_data = ctx->auths;
        imb_job->user_data2 = async_job;

        const int ret = async_update(tlv, ctx, async_job, imb_job);
        if (ret == 0) {
                fprintf(stderr, "Error: async_update failed\n");
                return FAILURE;
        }

        return SUCCESS;
}

int
chacha20_poly1305_async_final(ALG_CTX *ctx, unsigned char *out)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (!tlv || !ctx) {
                fprintf(stderr, "Error: Invalid context in chacha20_poly1305_async_final\n");
                return FAILURE;
        }

        if (ctx->enc && out) {
                memcpy(out, ctx->auths, ctx->tag_len);
        }

        else if (!ctx->enc && ctx->tag_set) {
                if (memcmp(ctx->tag, ctx->auths, ctx->tag_len) != 0) {
                        fprintf(stderr, "Error: Authentication tag verification failed\n");
                        return FAILURE;
                }
        }

        ctx->tag_calculated = 1;
        return SUCCESS;
}

void
chacha20_poly1305_async_cleanup(ALG_CTX *ctx)
{
        if (ctx) {
                OPENSSL_cleanse(ctx->chacha20_key, sizeof(ctx->chacha20_key));

                if (ctx->tag) {
                        OPENSSL_free(ctx->tag);
                        ctx->tag = NULL;
                }

                ctx->key_set = 0;
                ctx->iv_set = 0;
                ctx->tag_set = 0;
                ctx->tag_calculated = 0;
        }
}
