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
#include "hmac_common.h"

int
hmac_md5_test(struct IMB_MGR *mb_mgr);

static struct mac_test *hmac_md5_vectors;

/* HMAC-MD5 requires 8 submissions to get one back */
static const struct hmac_alg_desc md5_desc = { .hash_alg = IMB_AUTH_MD5,
                                               .digest_size = IMB_MD5_DIGEST_SIZE_IN_BYTES };

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
                {
                        if (hmac_test_submit_flush(mb_mgr, v, num_jobs, v->tagSize / 8,
                                                   &md5_desc)) {
                                printf("error #%zu\n", v->tcId);
                                test_suite_update(ts, 0, 1);
                        } else {
                                test_suite_update(ts, 1, 0);
                        }
                }
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
