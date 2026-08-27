/*****************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

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
aes_nia5_test(struct IMB_MGR *mb_mgr);

static struct mac_test *aes_nia5_vectors;

struct aes_nia5_job_ctx {
        uint32_t *expkey;
        uint8_t *iv;
};

static void
free_aes_nia5_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        aes_nia5_vectors = NULL;
}

static int
aes_nia5_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                     void *ctx)
{
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        struct aes_nia5_job_ctx *nia = calloc(1, sizeof(*nia));

        (void) ctx;
        if (nia == NULL)
                return -1;

        job->user_data = nia;
        nia->expkey = test_aligned_alloc(16, 15 * IMB_AES_BLOCK_SIZE);
        if (nia->expkey == NULL)
                return -1;

        nia->iv = test_aligned_alloc(16, vec->ivSize / 8);
        if (nia->iv == NULL)
                return -1;

        memcpy(nia->iv, vec->iv, vec->ivSize / 8);
        IMB_AES_KEYEXP_256(mb_mgr, vec->key, nia->expkey, dust);
        job->u.NIA._key = nia->expkey;
        job->u.NIA._iv = nia->iv;

        return 0;
}

static void
aes_nia5_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct aes_nia5_job_ctx *nia = job->user_data;

        (void) ctx;
        if (nia != NULL) {
                test_aligned_free(nia->expkey);
                test_aligned_free(nia->iv);
                free(nia);
        }
        job->user_data = NULL;
}

static int
test_aes_nia5(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs)
{
        const struct kat_hash_job_ops ops = {
                .prepare = aes_nia5_job_prepare,
                .cleanup = aes_nia5_job_cleanup,
                .hash_alg = IMB_AUTH_AES_NIA5,
        };

        return kat_hash_test_submit_flush(mb_mgr, &vec, 1, num_jobs, &ops);
}
static void
test_aes_nia5_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                          const int num_jobs)
{
        const struct mac_test *v = aes_nia5_vectors;

        if (!quiet_mode)
                printf("AES-NIA5 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard AES-NIA5 vector %zu Message length: %zu, "
                               "Tag length:%zu\n",
                               v->tcId, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_aes_nia5(mb_mgr, v, num_jobs)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
aes_nia5_test(struct IMB_MGR *mb_mgr)
{
        int i, errors = 0;
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_mac_vectors(kat_vector_dir, "aes_nia5_test.json", &aes_nia5_vectors, &jctx) < 0 ||
            aes_nia5_vectors == NULL)
                return 1;

        /* AES-NIA5 with standard vectors */
        test_suite_start(&ctx, "AES-NIA5");
        for (i = 1; i <= TEST_MAX_NUM_JOBS; i++)
                test_aes_nia5_std_vectors(mb_mgr, &ctx, i);
        /* exercise max-burst path */
        test_aes_nia5_std_vectors(mb_mgr, &ctx, IMB_MAX_BURST_SIZE);
        errors += test_suite_end(&ctx);

        free_aes_nia5_vectors(jctx);
        return errors;
}
