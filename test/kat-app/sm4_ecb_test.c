/*****************************************************************************
 Copyright (c) 2018-2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <intel-ipsec-mb.h>

#include "utils.h"
#include "cipher_test.h"
#include "kat_common_cipher.h"

int
sm4_ecb_test(struct IMB_MGR *mb_mgr);

static struct cipher_test *sm4_ecb_vectors;

static void
free_sm4_ecb_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        sm4_ecb_vectors = NULL;
}

struct sm4_ecb_job_ctx {
        uint32_t *enc_keys;
        uint32_t *dec_keys;
};

static int
sm4_ecb_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                    void *ctx)
{
        const size_t key_sched_size = IMB_SM4_KEY_SCHEDULE_ROUNDS * sizeof(uint32_t);
        struct sm4_ecb_job_ctx *job_ctx = calloc(1, sizeof(*job_ctx));

        (void) ctx;
        if (job_ctx == NULL)
                return -1;

        job->user_data = job_ctx;
        job_ctx->enc_keys = test_aligned_alloc(16, key_sched_size);
        job_ctx->dec_keys = test_aligned_alloc(16, key_sched_size);
        if (job_ctx->enc_keys == NULL || job_ctx->dec_keys == NULL)
                return -1;

        IMB_SM4_KEYEXP(mb_mgr, vec->key, job_ctx->enc_keys, job_ctx->dec_keys);
        job->enc_keys = job_ctx->enc_keys;
        job->dec_keys = job_ctx->dec_keys;
        return 0;
}

static void
sm4_ecb_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct sm4_ecb_job_ctx *job_ctx = job->user_data;

        (void) ctx;
        if (job_ctx != NULL) {
                test_aligned_free(job_ctx->enc_keys);
                test_aligned_free(job_ctx->dec_keys);
                free(job_ctx);
        }
        job->user_data = NULL;
}

static int
test_sm4_ecb_many(struct IMB_MGR *mb_mgr, const struct cipher_test *vec,
                  const IMB_CIPHER_DIRECTION dir, const IMB_CHAIN_ORDER order, const int in_place,
                  const uint32_t num_jobs)
{
        const struct cipher_test *vec_ptr = vec;
        const struct kat_cipher_job_ops ops = {
                .prepare = sm4_ecb_job_prepare,
                .cleanup = sm4_ecb_job_cleanup,
                .cipher_mode = IMB_CIPHER_SM4_ECB,
                .cipher_direction = dir,
                .chain_order = order,
                .key_len_in_bytes = IMB_KEY_128_BYTES,
                .in_place = in_place,
        };

        return kat_cipher_test_submit_flush(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
}

static void
test_sm4_ecb_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs)
{
        const struct cipher_test *v = sm4_ecb_vectors;

        if (!quiet_mode)
                printf("SM4-ECB Test (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("SM4-ECB Test Case %zu\n", v->tcId);
#else
                        printf(".");
#endif
                }

                if (test_sm4_ecb_many(mb_mgr, v, IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH, 0,
                                      num_jobs)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_sm4_ecb_many(mb_mgr, v, IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER, 0,
                                      num_jobs)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_sm4_ecb_many(mb_mgr, v, IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH, 1,
                                      num_jobs)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_sm4_ecb_many(mb_mgr, v, IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER, 1,
                                      num_jobs)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }

        if (!quiet_mode)
                printf("\n");
}

int
sm4_ecb_test(struct IMB_MGR *mb_mgr)
{
        unsigned i;
        int errors = 0;
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "sm4_ecb_test.json", &sm4_ecb_vectors, &jctx) < 0)
                return 1;

        test_suite_start(&ctx, "SM4-ECB-128");
        for (i = 0; i < test_num_jobs_size; i++)
                test_sm4_ecb_vectors(mb_mgr, &ctx, test_num_jobs[i]);
        errors += test_suite_end(&ctx);

        free_sm4_ecb_vectors(jctx);
        return errors;
}
