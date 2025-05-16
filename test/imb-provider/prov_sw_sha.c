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

#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <xmmintrin.h>
#include <sys/epoll.h>

/* Local includes */
#include "e_prov.h"
#include "prov_events.h"
#include "prov_sw_sha.h"
#include "prov_sw_request.h"
#include "prov_sw_freelist.h"
#include "prov_sw_submit.h"

int
sha_async_init(ALG_CTX *ctx)
{
        if (ctx == NULL) {
                fprintf(stderr, " init ctx == NULL\n");
                return 0;
        }

        return 1;
}

int
sha_async_update(ALG_CTX *ctx, const unsigned char *in, size_t len)
{
        mb_thread_data *tlv = mb_check_thread_local();

        if (tlv == NULL) {
                fprintf(stderr, "Could not create/get thread local variables.\n");
                return 0;
        }

        ASYNC_JOB *async_job = ASYNC_get_current_job();
        if (async_job == NULL) {
                fprintf(stderr, "Not running asynchronously, exit\n");
                return 0;
        }

        if (ctx == NULL) {
                fprintf(stderr, "SHA ctx is NULL.\n");
                return 0;
        }

        struct IMB_JOB *imb_job = IMB_GET_NEXT_JOB(tlv->imb_mgr);

        memset(imb_job, 0, sizeof(*imb_job));

        imb_job->cipher_direction = IMB_DIR_ENCRYPT;
        imb_job->chain_order = IMB_ORDER_HASH_CIPHER;
        imb_job->auth_tag_output = ctx->auths;
        imb_job->auth_tag_output_len_in_bytes = ctx->md_size;
        imb_job->src = in;
        imb_job->msg_len_to_hash_in_bytes = len;
        imb_job->cipher_mode = IMB_CIPHER_NULL;
        imb_job->hash_alg = ctx->hash_alg;
        imb_job->user_data2 = async_job;

        const int ret = async_update(tlv, ctx, async_job, imb_job);
        if (ret == 0) {
                fprintf(stderr, "Failed to process job/s\n");
                return 0;
        }

        return ret;
}

int
sha_async_final(ALG_CTX *ctx, unsigned char *md)
{
        if (ctx == NULL || md == NULL) {
                fprintf(stderr, "Error: ctx (type ALG_CTX) or md (output buffer) is NULL.\n");
                return 0;
        }

        memcpy(md, ctx->auths, ctx->md_size);
        return 1;
}

int
sha_async_cleanup(ALG_CTX *ctx)
{
        if (ctx != NULL) {
                memset(ctx, 0, sizeof(ALG_CTX));
        }
        return 1;
}
