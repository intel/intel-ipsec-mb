/*****************************************************************************
 Copyright (c) 2023-2026, Intel Corporation

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
sm3_test(struct IMB_MGR *mb_mgr);

static struct mac_test *sm3_vectors;

static void
free_sm3_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        sm3_vectors = NULL;
}

static int
test_sm3(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs)
{
        const struct kat_hash_job_ops ops = {
                .hash_alg = IMB_AUTH_SM3,
        };

        return kat_hash_test_submit_flush(mb_mgr, &vec, 1, num_jobs, &ops);
}

static void
test_sm3_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs)
{
        const struct mac_test *v = sm3_vectors;

        if (!quiet_mode)
                printf("SM3 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
#ifdef DEBUG
                if (!quiet_mode) {
                        printf("SM3 Test Case %zu "
                               "data_len:%zu digest_len:%zu\n",
                               v->tcId, v->msgSize / 8, v->tagSize / 8);
                }
#endif
                if (test_sm3(mb_mgr, v, num_jobs)) {
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
}

int
sm3_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_mac_vectors(kat_vector_dir, "sm3_test.json", &sm3_vectors, &jctx) < 0 ||
            sm3_vectors == NULL)
                return 1;

        test_suite_start(&ctx, "SM3");

        for (unsigned i = 1; i <= 17; i++)
                test_sm3_vectors(mb_mgr, &ctx, i);

        const int errors = test_suite_end(&ctx);

        free_sm3_vectors(jctx);
        return errors;
}
