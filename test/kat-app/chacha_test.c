/*****************************************************************************
 Copyright (c) 2020-2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>

#include "utils.h"
#include "cipher_test.h"
#include "kat_common_cipher.h"

int
chacha_test(struct IMB_MGR *mb_mgr);

static struct cipher_test *chacha_vectors;

static void
free_chacha_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        chacha_vectors = NULL;
}

struct chacha_job_ctx {
        uint8_t *key;
        uint8_t *iv;
};

static int
chacha_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                   void *ctx)
{
        struct chacha_job_ctx *job_ctx = calloc(1, sizeof(*job_ctx));

        (void) mb_mgr;
        (void) ctx;
        if (job_ctx == NULL)
                return -1;

        job->user_data = job_ctx;
        job_ctx->key = test_aligned_alloc(16, vec->keySize / 8);
        job_ctx->iv = test_aligned_alloc(16, vec->ivSize / 8);
        if (job_ctx->key == NULL || job_ctx->iv == NULL)
                return -1;

        memcpy(job_ctx->key, vec->key, vec->keySize / 8);
        memcpy(job_ctx->iv, vec->iv, vec->ivSize / 8);
        job->enc_keys = job_ctx->key;
        job->dec_keys = job_ctx->key;
        job->iv = job_ctx->iv;
        job->iv_len_in_bytes = vec->ivSize / 8;
        return 0;
}

static void
chacha_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct chacha_job_ctx *job_ctx = job->user_data;

        (void) ctx;
        if (job_ctx != NULL) {
                test_aligned_free(job_ctx->key);
                test_aligned_free(job_ctx->iv);
                free(job_ctx);
        }
        job->user_data = NULL;
}

static int
test_chacha_many(struct IMB_MGR *mb_mgr, const struct cipher_test *vec,
                 const IMB_CIPHER_DIRECTION dir, const IMB_CHAIN_ORDER order, const int in_place,
                 const uint32_t num_jobs)
{
        const struct cipher_test *vec_ptr = vec;
        const struct kat_cipher_job_ops ops = {
                .prepare = chacha_job_prepare,
                .cleanup = chacha_job_cleanup,
                .cipher_mode = IMB_CIPHER_CHACHA20,
                .cipher_direction = dir,
                .chain_order = order,
                .key_len_in_bytes = IMB_KEY_256_BYTES,
                .in_place = in_place,
        };

        return kat_cipher_test_submit_flush(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
}

static void
test_chacha_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs)
{
        const struct cipher_test *v = chacha_vectors;

        if (!quiet_mode)
                printf("CHACHA20 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("%zu Standard vector key_len:%zu\n", v->tcId, v->keySize / 8);
#else
                        printf(".");
#endif
                }

                if (test_chacha_many(mb_mgr, v, IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH, 0,
                                     num_jobs)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_chacha_many(mb_mgr, v, IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER, 0,
                                     num_jobs)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_chacha_many(mb_mgr, v, IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH, 1,
                                     num_jobs)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_chacha_many(mb_mgr, v, IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER, 1,
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
chacha_test(struct IMB_MGR *mb_mgr)
{
        unsigned i;
        int errors = 0;
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "chacha_test.json", &chacha_vectors, &jctx) < 0)
                return 1;

        test_suite_start(&ctx, "CHACHA20-256");
        for (i = 0; i < test_num_jobs_size; i++)
                test_chacha_vectors(mb_mgr, &ctx, test_num_jobs[i]);
        errors = test_suite_end(&ctx);

        free_chacha_vectors(jctx);
        return errors;
}
