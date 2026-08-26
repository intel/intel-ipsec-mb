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
#include "mac_test.h"
#include "kat_common_hash.h"

int
poly1305_test(struct IMB_MGR *mb_mgr);

static struct mac_test *poly1305_vectors;

struct poly1305_job_ctx {
        uint8_t *key;
};

struct poly1305_job_prepare_ctx {
        int dir;
};

static void
free_poly1305_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        poly1305_vectors = NULL;
}

static int
poly1305_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                     void *ctx)
{
        const struct poly1305_job_prepare_ctx *prepare_ctx = ctx;
        struct poly1305_job_ctx *poly = calloc(1, sizeof(*poly));
        const size_t key_size = vec->keySize / 8;

        (void) mb_mgr;

        if (poly == NULL)
                return -1;

        job->user_data = poly;

        poly->key = test_aligned_alloc(16, key_size);
        if (poly->key == NULL)
                return -1;

        memcpy(poly->key, vec->key, key_size);

        job->cipher_direction = prepare_ctx->dir;
        job->u.POLY1305._key = poly->key;

        return 0;
}

static void
poly1305_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct poly1305_job_ctx *poly = job->user_data;

        (void) ctx;
        if (poly != NULL) {
                test_aligned_free(poly->key);
                free(poly);
        }
        job->user_data = NULL;
}

static int
test_poly1305(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int dir, const int num_jobs)
{
        struct poly1305_job_prepare_ctx prepare_ctx = { dir };
        const struct kat_hash_job_ops ops = {
                .prepare = poly1305_job_prepare,
                .cleanup = poly1305_job_cleanup,
                .ctx = &prepare_ctx,
                .hash_alg = IMB_AUTH_POLY1305,
        };

        return kat_hash_test_submit_flush(mb_mgr, &vec, 1, num_jobs, &ops);
}

static void
test_poly1305_vectors(struct IMB_MGR *mb_mgr, const int num_jobs, struct test_suite_context *ctx,
                      const char *banner)
{
        const struct mac_test *v = poly1305_vectors;

        if (!quiet_mode)
                printf("%s (N jobs = %d):\n", banner, num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("RFC7539 Test Case %zu key_len:%zu "
                               "data_len:%zu digest_len:%zu\n",
                               v->tcId, v->keySize, v->msgSize / 8, v->tagSize);
#else
                        printf(".");
#endif
                }

                if (test_poly1305(mb_mgr, v, IMB_DIR_ENCRYPT, num_jobs)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else
                        test_suite_update(ctx, 1, 0);

                if (test_poly1305(mb_mgr, v, IMB_DIR_DECRYPT, num_jobs)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else
                        test_suite_update(ctx, 1, 0);
        }
        if (!quiet_mode)
                printf("\n");
}

int
poly1305_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;
        int i, errors;

        if (load_mac_vectors(kat_vector_dir, "poly1305_test.json", &poly1305_vectors, &jctx) < 0 ||
            poly1305_vectors == NULL)
                return 1;

        test_suite_start(&ctx, "POLY1305");
        for (i = 1; i < 20; i++)
                test_poly1305_vectors(mb_mgr, i, &ctx, "Poly1305 RFC7539 vectors");
        errors = test_suite_end(&ctx);

        free_poly1305_vectors(jctx);
        return errors;
}
