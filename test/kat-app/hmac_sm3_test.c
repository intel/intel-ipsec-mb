/*****************************************************************************
 Copyright (c) 2023-2026, Intel Corporation

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
hmac_sm3_test(struct IMB_MGR *mb_mgr);

static struct mac_test *hmac_sm3_vectors;

static void
free_hmac_sm3_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        hmac_sm3_vectors = NULL;
}

static int
hmac_sm3_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                     void *ctx)
{
        uint8_t *ipad = NULL, *opad = NULL;

        (void) ctx;
        ipad = test_aligned_alloc(16, IMB_SM3_DIGEST_SIZE);
        if (ipad == NULL)
                return -1;
        opad = test_aligned_alloc(16, IMB_SM3_DIGEST_SIZE);
        if (opad == NULL) {
                test_aligned_free(ipad);
                return -1;
        }

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SM3, vec->key, vec->keySize / 8, ipad, opad);
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad;
        job->u.HMAC._hashed_auth_key_xor_opad = opad;
        return 0;
}

static void
hmac_sm3_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        (void) ctx;
        test_aligned_free((void *) (uintptr_t) job->u.HMAC._hashed_auth_key_xor_ipad);
        test_aligned_free((void *) (uintptr_t) job->u.HMAC._hashed_auth_key_xor_opad);
        job->u.HMAC._hashed_auth_key_xor_ipad = NULL;
        job->u.HMAC._hashed_auth_key_xor_opad = NULL;
}

static int
test_hmac_sm3(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs)
{
        const struct kat_hash_job_ops ops = {
                .prepare = hmac_sm3_job_prepare,
                .cleanup = hmac_sm3_job_cleanup,
                .hash_alg = IMB_AUTH_HMAC_SM3,
        };

        return kat_hash_test_submit_flush(mb_mgr, &vec, 1, num_jobs, &ops);
}

static int
test_hmac_sm3_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs)
{
        const struct kat_hash_job_ops ops = {
                .prepare = hmac_sm3_job_prepare,
                .cleanup = hmac_sm3_job_cleanup,
                .hash_alg = IMB_AUTH_HMAC_SM3,
        };

        return kat_hash_test_burst(mb_mgr, &vec, 1, num_jobs, &ops);
}

static void
test_hmac_sm3_std_vectors(struct IMB_MGR *mb_mgr, const uint32_t num_jobs,
                          struct test_suite_context *ts)
{
        const struct mac_test *v = hmac_sm3_vectors;

        if (!quiet_mode)
                printf("HMAC-SM3 standard test vectors (N jobs = %u):\n", num_jobs);
        while (v->msg != NULL) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Test Case %zu keySize:%zu "
                               "msgSize:%zu tagSize:%zu\n",
                               v->tcId, v->keySize / 8, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_hmac_sm3(mb_mgr, v, num_jobs)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else
                        test_suite_update(ts, 1, 0);
                if (test_hmac_sm3_burst(mb_mgr, v, num_jobs)) {
                        printf("error #%zu - burst API\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else
                        test_suite_update(ts, 1, 0);

                v++;
        }
        if (!quiet_mode)
                printf("\n");
}

int
hmac_sm3_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        struct test_json_alloc_ctx *ctx = NULL;
        int errors = 0;
        uint32_t num_jobs;

        if (load_mac_vectors(kat_vector_dir, "hmac_sm3_test.json", &hmac_sm3_vectors, &ctx) < 0)
                return 1;

        test_suite_start(&ts, "HMAC-SM3");
        for (num_jobs = 1; num_jobs <= TEST_MAX_NUM_JOBS; num_jobs++)
                test_hmac_sm3_std_vectors(mb_mgr, num_jobs, &ts);
        /* exercise max-burst path */
        test_hmac_sm3_std_vectors(mb_mgr, IMB_MAX_BURST_SIZE, &ts);
        errors = test_suite_end(&ts);

        free_hmac_sm3_vectors(ctx);
        return errors;
}
