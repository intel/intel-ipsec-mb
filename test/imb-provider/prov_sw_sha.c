/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
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

        /* Reset hash output state for re-initialization.
         * Keep xof_buf allocated so the same CTX can be reused across
         * repeated init->update->final calls (e.g. openssl speed). */
        if (ctx->xof_buf != NULL && ctx->md_size > 0)
                OPENSSL_cleanse(ctx->xof_buf, ctx->md_size);
        else
                OPENSSL_cleanse(ctx->auths, sizeof(ctx->auths));

        ctx->data_hashed = 0;

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
        imb_job->auth_tag_output = ctx->xof_buf ? ctx->xof_buf : ctx->auths;
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

        ctx->data_hashed = 1;

        return ret;
}

int
sha_async_final(ALG_CTX *ctx, unsigned char *md)
{
        if (ctx == NULL || md == NULL) {
                fprintf(stderr, "Error: ctx (type ALG_CTX) or md (output buffer) is NULL.\n");
                return 0;
        }

        /*
         * EVP_DigestUpdate() returns success without calling the provider when
         * the input length is zero, so an empty message reaches us with nothing
         * hashed. Submit the empty message now; otherwise the caller would get
         * the cleared auths buffer instead of the digest of "".
         */
        if (!ctx->data_hashed) {
                static const unsigned char empty[1] = { 0 };

                if (!sha_async_update(ctx, empty, 0))
                        return 0;
        }

        const uint8_t *src = ctx->xof_buf ? ctx->xof_buf : ctx->auths;
        memcpy(md, src, ctx->md_size);
        return 1;
}

int
sha_async_cleanup(ALG_CTX *ctx)
{
        if (ctx != NULL) {
                if (ctx->xof_buf != NULL) {
                        if (ctx->md_size > 0)
                                OPENSSL_cleanse(ctx->xof_buf, ctx->md_size);
                        OPENSSL_free(ctx->xof_buf);
                        ctx->xof_buf = NULL;
                }
                OPENSSL_cleanse(ctx, sizeof(ALG_CTX));
        }
        return 1;
}
