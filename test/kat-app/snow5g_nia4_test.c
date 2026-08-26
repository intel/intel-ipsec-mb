/*****************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

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
snow5g_nia4_test(struct IMB_MGR *mb_mgr);

static struct mac_test *snow5g_nia4_vectors;

struct snow5g_nia4_job_ctx {
        uint8_t *key;
        uint8_t *iv;
};

static void
free_snow5g_nia4_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        snow5g_nia4_vectors = NULL;
}

static int
snow5g_nia4_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                        void *ctx)
{
        struct snow5g_nia4_job_ctx *nia = calloc(1, sizeof(*nia));

        (void) mb_mgr;
        (void) ctx;
        if (nia == NULL)
                return -1;

        job->user_data = nia;
        nia->key = test_aligned_alloc(16, vec->keySize / 8);
        if (nia->key == NULL)
                return -1;

        nia->iv = test_aligned_alloc(16, vec->ivSize / 8);
        if (nia->iv == NULL)
                return -1;

        memcpy(nia->key, vec->key, vec->keySize / 8);
        memcpy(nia->iv, vec->iv, vec->ivSize / 8);
        job->u.NIA._key = nia->key;
        job->u.NIA._iv = nia->iv;

        return 0;
}

static void
snow5g_nia4_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct snow5g_nia4_job_ctx *nia = job->user_data;

        (void) ctx;
        if (nia != NULL) {
                test_aligned_free(nia->key);
                test_aligned_free(nia->iv);
                free(nia);
        }
        job->user_data = NULL;
}

static int
test_snow5g_nia4(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs)
{
        const struct kat_hash_job_ops ops = {
                .prepare = snow5g_nia4_job_prepare,
                .cleanup = snow5g_nia4_job_cleanup,
                .hash_alg = IMB_AUTH_SNOW5G_NIA4,
        };

        return kat_hash_test_submit_flush(mb_mgr, &vec, 1, num_jobs, &ops);
}

static void
test_snow5g_nia4_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                             const int num_jobs)
{
        const struct mac_test *v = snow5g_nia4_vectors;

        if (!quiet_mode)
                printf("SNOW5G-NIA4 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard SNOW5G-NIA4 vector %zu Message length: %zu, "
                               "Tag length:%zu\n",
                               v->tcId, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_snow5g_nia4(mb_mgr, v, num_jobs)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

/* Submit all vectors without flushing between them. */
static int
test_snow5g_nia4_submit_all_vectors(struct IMB_MGR *mb_mgr, const struct mac_test *vectors)
{
        const struct mac_test **vec_tab;
        const struct mac_test *vec;
        const struct kat_hash_job_ops ops = {
                .prepare = snow5g_nia4_job_prepare,
                .cleanup = snow5g_nia4_job_cleanup,
                .hash_alg = IMB_AUTH_SNOW5G_NIA4,
        };
        uint32_t num_vectors = 0;
        int ret;

        for (vec = vectors; vec->msg != NULL; vec++)
                num_vectors++;

        if (num_vectors == 0)
                return -1;

        vec_tab = malloc(num_vectors * sizeof(*vec_tab));
        if (vec_tab == NULL)
                return -1;

        for (uint32_t i = 0; i < num_vectors; i++)
                vec_tab[i] = &vectors[i];

        ret = kat_hash_test_submit_flush(mb_mgr, vec_tab, num_vectors, num_vectors, &ops);
        free(vec_tab);
        return ret;
}

int
snow5g_nia4_test(struct IMB_MGR *mb_mgr)
{
        int errors = 0;
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_mac_vectors(kat_vector_dir, "snow5g_nia4_test.json", &snow5g_nia4_vectors, &jctx) <
                    0 ||
            snow5g_nia4_vectors == NULL)
                return 1;

        /* SNOW5G-NIA4 with standard vectors */
        test_suite_start(&ctx, "SNOW5G-NIA4");
        for (size_t i = 0; i < test_num_jobs_size; i++)
                test_snow5g_nia4_std_vectors(mb_mgr, &ctx, test_num_jobs[i]);
        if (test_snow5g_nia4_submit_all_vectors(mb_mgr, snow5g_nia4_vectors))
                test_suite_update(&ctx, 0, 1);
        else
                test_suite_update(&ctx, 1, 0);
        errors += test_suite_end(&ctx);

        free_snow5g_nia4_vectors(jctx);
        return errors;
}
