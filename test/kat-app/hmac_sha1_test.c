/*****************************************************************************
 Copyright (c) 2018-2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "utils.h"
#include "mac_test.h"
#include "wycheproof_test.h"
#include "kat_common_hash.h"

int
hmac_sha1_test(struct IMB_MGR *mb_mgr);

static struct mac_test *hmac_sha1_vectors;

struct hmac_sha1_job_ctx {
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA1_BLOCK_SIZE], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA1_BLOCK_SIZE], 16);
};

static int
hmac_sha1_job_prepare(struct IMB_JOB *job, void *ctx)
{
        const struct hmac_sha1_job_ctx *hmac = ctx;

        job->hash_alg = IMB_AUTH_HMAC_SHA_1;
        job->u.HMAC._hashed_auth_key_xor_ipad = hmac->ipad_hash;
        job->u.HMAC._hashed_auth_key_xor_opad = hmac->opad_hash;
        return 0;
}

static void
hmac_sha1_job_ctx_init(struct IMB_MGR *mb_mgr, const struct mac_test *vec,
                       struct hmac_sha1_job_ctx *ctx)
{
        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA_1, vec->key, vec->keySize / 8, ctx->ipad_hash,
                           ctx->opad_hash);
}

static void
free_hmac_sha1_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        hmac_sha1_vectors = NULL;
}

static void
test_hmac_sha1_std_vectors(struct IMB_MGR *mb_mgr, const uint32_t num_jobs,
                           struct test_suite_context *ts)
{
        const struct mac_test *v = hmac_sha1_vectors;
        struct hmac_sha1_job_ctx ctx;
        const struct kat_hash_job_ops ops = {
                .prepare = hmac_sha1_job_prepare,
                .ctx = &ctx,
        };

        if (!quiet_mode)
                printf("HMAC-SHA1 standard test vectors (N jobs = %u):\n", num_jobs);
        while (v->msg != NULL) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("RFC2202 Test Case %zu keySize:%zu "
                               "msgSize:%zu tagSize:%zu\n",
                               v->tcId, v->keySize / 8, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                hmac_sha1_job_ctx_init(mb_mgr, v, &ctx);
                if (kat_hash_test_submit_flush(mb_mgr, v, num_jobs, &ops)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else
                        test_suite_update(ts, 1, 0);
                if (kat_hash_test_burst(mb_mgr, v, num_jobs, &ops)) {
                        printf("error #%zu - burst API\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else
                        test_suite_update(ts, 1, 0);
                if (kat_hash_test_hash_burst(mb_mgr, v, num_jobs, IMB_AUTH_HMAC_SHA_1, &ops)) {
                        printf("error #%zu - hash-only burst API\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else
                        test_suite_update(ts, 1, 0);

                v++;
        }
        if (!quiet_mode)
                printf("\n");
}

int
hmac_sha1_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        struct test_json_alloc_ctx *ctx = NULL;
        int errors = 0;
        uint32_t num_jobs;
        uint32_t tag_size;
        const struct mac_test *v;
        struct hmac_sha1_job_ctx tag_ctx;
        struct kat_hash_job_ops tag_ops = {
                .prepare = hmac_sha1_job_prepare,
                .ctx = &tag_ctx,
        };

        if (load_mac_vectors(kat_vector_dir, "hmac_sha1_test.json", &hmac_sha1_vectors, &ctx) < 0)
                return 1;

        v = hmac_sha1_vectors;

        test_suite_start(&ts, "HMAC-SHA1");
        for (num_jobs = 1; num_jobs <= TEST_MAX_NUM_JOBS; num_jobs++)
                test_hmac_sha1_std_vectors(mb_mgr, num_jobs, &ts);
        /* exercise max-burst path */
        test_hmac_sha1_std_vectors(mb_mgr, IMB_MAX_BURST_SIZE, &ts);

        assert(v->tagSize / 8 == 20);
        for (tag_size = 4; tag_size <= 20; tag_size++) {
                tag_ops.tag_size = tag_size;
                hmac_sha1_job_ctx_init(mb_mgr, v, &tag_ctx);
                if (kat_hash_test_submit_flush(mb_mgr, v, TEST_MAX_NUM_JOBS, &tag_ops)) {
                        printf("error tag size: %u\n", tag_size);
                        test_suite_update(&ts, 0, 1);
                } else
                        test_suite_update(&ts, 1, 0);
        }

        /* exercise max-burst path at max tag size */
        tag_ops.tag_size = 20;
        hmac_sha1_job_ctx_init(mb_mgr, v, &tag_ctx);
        if (kat_hash_test_submit_flush(mb_mgr, v, IMB_MAX_BURST_SIZE, &tag_ops)) {
                printf("error tag size: %u (max burst)\n", 20);
                test_suite_update(&ts, 0, 1);
        } else
                test_suite_update(&ts, 1, 0);

        errors = test_suite_end(&ts);

        free_hmac_sha1_vectors(ctx);
        errors += wycheproof_hmac_sha1_test(mb_mgr);

        return errors;
}
