/**********************************************************************
  Copyright(c) 2024-2026 Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "cipher_test.h"
#include "kat_common_cipher.h"

#define SNOW5G_KEY_SIZE 32
#define SNOW5G_IV_SIZE  16

static struct cipher_test *snow5g_nea4_vectors;

static void
free_snow5g_nea4_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        snow5g_nea4_vectors = NULL;
}

int
snow5g_nea4_test(IMB_MGR *mgr);

struct snow5g_nea4_job_ctx {
        uint8_t *key;
        uint8_t *iv;
};

static int
snow5g_nea4_job_prepare(struct IMB_MGR *mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                        void *ctx)
{
        struct snow5g_nea4_job_ctx *job_ctx = calloc(1, sizeof(*job_ctx));

        (void) mgr;
        (void) ctx;
        if (job_ctx == NULL)
                return -1;

        job->user_data = job_ctx;
        job_ctx->key = test_aligned_alloc_copy(16, vec->key, vec->keySize / 8);
        job_ctx->iv = malloc(vec->ivSize / 8 == 0 ? 1 : vec->ivSize / 8);
        if (job_ctx->key == NULL || job_ctx->iv == NULL)
                return -1;

        memcpy(job_ctx->iv, vec->iv, vec->ivSize / 8);
        job->enc_keys = job_ctx->key;
        job->dec_keys = job_ctx->key;
        job->iv = job_ctx->iv;
        job->iv_len_in_bytes = SNOW5G_IV_SIZE;
        return 0;
}

static void
snow5g_nea4_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct snow5g_nea4_job_ctx *job_ctx = job->user_data;

        (void) ctx;
        if (job_ctx != NULL) {
                test_aligned_free(job_ctx->key);
                free(job_ctx->iv);
                free(job_ctx);
        }
        job->user_data = NULL;
}

static int
run_snow5g_jobs(IMB_MGR *mgr, const struct cipher_test *vec, const uint32_t num_jobs)
{
        const struct cipher_test *vec_ptr = vec;
        const struct kat_cipher_job_ops ops = {
                .prepare = snow5g_nea4_job_prepare,
                .cleanup = snow5g_nea4_job_cleanup,
                .cipher_mode = IMB_CIPHER_SNOW5G_NEA4,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = SNOW5G_KEY_SIZE,
                .in_place = 0,
        };

        return kat_cipher_test_submit_flush(mgr, &vec_ptr, 1, num_jobs, &ops);
}

static void
test_vectors(IMB_MGR *mgr, struct test_suite_context *ctx, const struct cipher_test *vectors,
             const int num_jobs)
{
        for (; vectors->msg != NULL; vectors++) {
#ifdef DEBUG
                if (!quiet_mode)
                        printf("Vector %zu  KeySize:%zu IVSize:%zu MsgSize:%zu\n", vectors->tcId,
                               vectors->keySize, vectors->ivSize, vectors->msgSize);
#endif

                if (run_snow5g_jobs(mgr, vectors, num_jobs)) {
                        printf("Error #%zu encrypt, jobs: %i\n", vectors->tcId, num_jobs);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
}

int
snow5g_nea4_test(IMB_MGR *mgr)
{
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "snow5g_nea4_test.json", &snow5g_nea4_vectors,
                                &jctx) < 0)
                return 1;

        test_suite_start(&ctx, "SNOW5G-NEA4");

        for (uint32_t i = 0; i < test_num_jobs_size; i++)
                test_vectors(mgr, &ctx, snow5g_nea4_vectors, test_num_jobs[i]);

        free_snow5g_nea4_vectors(jctx);
        return test_suite_end(&ctx);
}
