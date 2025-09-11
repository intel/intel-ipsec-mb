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

/* Local Includes */
#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_poly1305.h"
#include "prov_sw_request.h"
#include "prov_events.h"
#include "prov_sw_submit.h"

void
poly1305_async_cleanup(ALG_CTX *ctx)
{
        if (ctx) {
                if (ctx->enc_keys)
                        OPENSSL_free(ctx->enc_keys);
                ctx->enc_keys = NULL;
        }
}

int
poly1305_async_init(ALG_CTX *ctx, const unsigned char *inkey, size_t keylen)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL)
                return 0;

        if (keylen != ctx->keylen) {
                fprintf(stderr, "Invalid Poly1305 key length: %zu (expected %zu)\n", keylen,
                        ctx->keylen);
                return 0;
        }

        /* Store the key */
        if (!ctx->enc_keys)
                ctx->enc_keys = OPENSSL_zalloc(ctx->keylen);

        if (!ctx->enc_keys)
                return 0;

        memcpy(ctx->enc_keys, inkey, keylen);

        return 1;
}

int
poly1305_async_do_mac(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
                      const unsigned char *in, size_t len)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        if (ctx == NULL) {
                fprintf(stderr, "Poly1305 ctx is NULL.\n");
                return 0;
        }

        if (outl == NULL || out == NULL || in == NULL)
                return 0;

        if (outsize < ctx->md_size) {
                fprintf(stderr, "Output buffer too small for Poly1305 tag\n");
                return 0;
        }

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

        memset(imb_job, 0, sizeof(*imb_job));

        imb_job->src = in;
        imb_job->msg_len_to_hash_in_bytes = len;
        imb_job->auth_tag_output = out;
        imb_job->auth_tag_output_len_in_bytes = ctx->md_size;
        imb_job->hash_alg = IMB_AUTH_POLY1305;
        imb_job->cipher_direction = IMB_DIR_ENCRYPT;
        imb_job->chain_order = IMB_ORDER_HASH_CIPHER;
        imb_job->cipher_mode = IMB_CIPHER_NULL;
        imb_job->hash_start_src_offset_in_bytes = 0;
        imb_job->user_data2 = async_job;

        /* Set Poly1305 specific fields */
        imb_job->u.POLY1305._key = ctx->enc_keys;

        int ret = async_update(tlv, ctx, async_job, imb_job);
        if (ret == 0) {
                fprintf(stderr, "Failed to process job/s\n");
                return 0;
        }

        *outl = ctx->md_size;
        return ret;
}
