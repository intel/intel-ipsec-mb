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
#include "hmac_common.h"

int
hmac_sha1_test(struct IMB_MGR *mb_mgr);

static struct mac_test *hmac_sha1_vectors;

/* SHANI HMAC-SHA implementation can return a completed job after 2nd submission */
static const struct hmac_alg_desc sha1_desc = { .hash_alg = IMB_AUTH_HMAC_SHA_1,
                                                .digest_size = IMB_SHA1_DIGEST_SIZE_IN_BYTES };

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

                {
                        if (hmac_test_submit_flush(mb_mgr, v, num_jobs, v->tagSize / 8,
                                                   &sha1_desc)) {
                                printf("error #%zu\n", v->tcId);
                                test_suite_update(ts, 0, 1);
                        } else {
                                test_suite_update(ts, 1, 0);
                        }
                        if (hmac_test_burst(mb_mgr, v, num_jobs, v->tagSize / 8, &sha1_desc)) {
                                printf("error #%zu - burst API\n", v->tcId);
                                test_suite_update(ts, 0, 1);
                        } else {
                                test_suite_update(ts, 1, 0);
                        }
                        if (hmac_test_hash_burst(mb_mgr, v, num_jobs, v->tagSize / 8, &sha1_desc)) {
                                printf("error #%zu - hash-only burst API\n", v->tcId);
                                test_suite_update(ts, 0, 1);
                        } else {
                                test_suite_update(ts, 1, 0);
                        }
                }

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
                if (hmac_test_submit_flush(mb_mgr, v, TEST_MAX_NUM_JOBS, tag_size, &sha1_desc)) {
                        printf("error tag size: %u\n", tag_size);
                        test_suite_update(&ts, 0, 1);
                } else {
                        test_suite_update(&ts, 1, 0);
                }
        }
        /* exercise max-burst path at max tag size */
        {
                if (hmac_test_submit_flush(mb_mgr, v, IMB_MAX_BURST_SIZE, 20, &sha1_desc)) {
                        printf("error tag size: %u (max burst)\n", 20);
                        test_suite_update(&ts, 0, 1);
                } else {
                        test_suite_update(&ts, 1, 0);
                }
        }

        errors = test_suite_end(&ts);

        free_hmac_sha1_vectors(ctx);
        errors += wycheproof_hmac_sha1_test(mb_mgr);

        return errors;
}
