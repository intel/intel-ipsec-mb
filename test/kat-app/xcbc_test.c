/*****************************************************************************
 Copyright (c) 2020-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "utils.h"
#include "mac_test.h"
#include "kat_common_hash.h"

int
xcbc_test(struct IMB_MGR *mb_mgr);

static struct mac_test *xcbc_vectors;

struct xcbc_job_ctx {
        uint32_t *k1_exp;
        uint8_t *k2;
        uint8_t *k3;
};

struct xcbc_job_prepare_ctx {
        int dir;
};

static void
free_xcbc_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        xcbc_vectors = NULL;
}

static int
xcbc_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec, void *ctx)
{
        const struct xcbc_job_prepare_ctx *prepare_ctx = ctx;
        struct xcbc_job_ctx *xcbc = calloc(1, sizeof(*xcbc));

        if (xcbc == NULL)
                return -1;

        job->user_data = xcbc;

        xcbc->k1_exp = test_aligned_alloc(16, 11 * IMB_AES_BLOCK_SIZE);
        if (xcbc->k1_exp == NULL)
                return -1;

        xcbc->k2 = test_aligned_alloc(16, IMB_AES_BLOCK_SIZE);
        if (xcbc->k2 == NULL)
                return -1;

        xcbc->k3 = test_aligned_alloc(16, IMB_AES_BLOCK_SIZE);
        if (xcbc->k3 == NULL)
                return -1;

        IMB_AES_XCBC_KEYEXP(mb_mgr, (const void *) vec->key, xcbc->k1_exp, xcbc->k2, xcbc->k3);

        job->cipher_direction = prepare_ctx->dir;
        job->u.XCBC._k1_expanded = xcbc->k1_exp;
        job->u.XCBC._k2 = xcbc->k2;
        job->u.XCBC._k3 = xcbc->k3;

        return 0;
}

static void
xcbc_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct xcbc_job_ctx *xcbc = job->user_data;

        (void) ctx;
        if (xcbc != NULL) {
                test_aligned_free(xcbc->k1_exp);
                test_aligned_free(xcbc->k2);
                test_aligned_free(xcbc->k3);
                free(xcbc);
        }
        job->user_data = NULL;
}

static int
test_xcbc(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int dir, const int num_jobs)
{
        struct xcbc_job_prepare_ctx prepare_ctx = { dir };
        const struct kat_hash_job_ops ops = {
                .prepare = xcbc_job_prepare,
                .cleanup = xcbc_job_cleanup,
                .ctx = &prepare_ctx,
                .hash_alg = IMB_AUTH_AES_XCBC,
        };

        if (kat_hash_test_submit_flush(mb_mgr, &vec, 1, num_jobs, &ops))
                return -1;

        return 0;
}

static void
test_xcbc_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs)
{
        const struct mac_test *v = xcbc_vectors;

        if (!quiet_mode)
                printf("AES-XCBC-128 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard XCBC-128 vector %zu Msg len: %zu, "
                               "Tag len:%zu\n",
                               v->tcId, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_xcbc(mb_mgr, v, IMB_DIR_ENCRYPT, num_jobs)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_xcbc(mb_mgr, v, IMB_DIR_DECRYPT, num_jobs)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
xcbc_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;
        int i, errors;

        if (load_mac_vectors(kat_vector_dir, "xcbc_test.json", &xcbc_vectors, &jctx) < 0 ||
            xcbc_vectors == NULL)
                return 1;

        test_suite_start(&ctx, "AES-XCBC-128");
        /* AES-XCBC 128 with standard vectors */
        for (i = 1; i < 20; i++)
                test_xcbc_std_vectors(mb_mgr, &ctx, i);
        errors = test_suite_end(&ctx);

        free_xcbc_vectors(jctx);
        return errors;
}
