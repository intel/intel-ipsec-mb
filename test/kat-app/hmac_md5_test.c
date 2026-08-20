/*****************************************************************************
 Copyright (c) 2018-2024, Intel Corporation

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
hmac_md5_test(struct IMB_MGR *mb_mgr);

static struct mac_test *hmac_md5_vectors;
static int hmac_md5_unused_ctx;

static int
hmac_md5_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                     void *ctx)
{
        uint8_t *ipad = NULL, *opad = NULL;

        (void) ctx;
        ipad = test_aligned_alloc(16, IMB_MD5_BLOCK_SIZE);
        if (ipad == NULL)
                return -1;
        opad = test_aligned_alloc(16, IMB_MD5_BLOCK_SIZE);
        if (opad == NULL) {
                test_aligned_free(ipad);
                return -1;
        }

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_MD5, vec->key, vec->keySize / 8, ipad, opad);
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad;
        job->u.HMAC._hashed_auth_key_xor_opad = opad;
        return 0;
}

static void
hmac_md5_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        (void) ctx;
        test_aligned_free((void *) (uintptr_t) job->u.HMAC._hashed_auth_key_xor_ipad);
        test_aligned_free((void *) (uintptr_t) job->u.HMAC._hashed_auth_key_xor_opad);
        job->u.HMAC._hashed_auth_key_xor_ipad = NULL;
        job->u.HMAC._hashed_auth_key_xor_opad = NULL;
}

static void
free_hmac_md5_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        hmac_md5_vectors = NULL;
}

static void
test_hmac_md5_std_vectors(struct IMB_MGR *mb_mgr, const uint32_t num_jobs,
                          struct test_suite_context *ts)
{

        const struct mac_test *v = hmac_md5_vectors;
        const struct kat_hash_job_ops ops = {
                .prepare = hmac_md5_job_prepare,
                .cleanup = hmac_md5_job_cleanup,
                .ctx = &hmac_md5_unused_ctx,
                .hash_alg = IMB_AUTH_MD5,
        };

        if (!quiet_mode)
                printf("HMAC-MD5 standard test vectors (N jobs = %u):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("RFC2202 Test Case %zu key_len:%zu "
                               "data_len:%zu digest_len:%zu\n",
                               v->tcId, v->keySize / 8, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }
                /* No functionality for keys larger than block size */
                if ((v->keySize / 8) > IMB_MD5_BLOCK_SIZE) {
#ifdef DEBUG
                        if (!quiet_mode)
                                printf("Skipped vector %zu, "
                                       "Key size larger than block size\n",
                                       v->tcId);
#endif
                        continue;
                }
                if (kat_hash_test_submit_flush(mb_mgr, &v, 1, num_jobs, &ops)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else
                        test_suite_update(ts, 1, 0);
        }
        if (!quiet_mode)
                printf("\n");
}

int
hmac_md5_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        struct test_json_alloc_ctx *ctx = NULL;
        uint32_t num_jobs;
        int errors = 0;

        if (load_mac_vectors(kat_vector_dir, "hmac_md5_test.json", &hmac_md5_vectors, &ctx) < 0)
                return 1;

        test_suite_start(&ts, "HMAC-MD5");
        for (num_jobs = 1; num_jobs <= 17; num_jobs++)
                test_hmac_md5_std_vectors(mb_mgr, num_jobs, &ts);
        errors = test_suite_end(&ts);

        free_hmac_md5_vectors(ctx);
        return errors;
}
