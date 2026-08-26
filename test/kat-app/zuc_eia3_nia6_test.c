/*****************************************************************************
 Copyright (c) 2009-2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

/*-----------------------------------------------------------------------
 * Zuc functional test
 *-----------------------------------------------------------------------
 *
 * A simple functional test for ZUC
 *
 *-----------------------------------------------------------------------*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <intel-ipsec-mb.h>

#include "gcm_ctr_vectors_test.h"
#include "utils.h"
#include "mac_test.h"
#include "kat_common_hash.h"

#define PASS_STATUS 0
#define FAIL_STATUS -1

enum api_type { TEST_SINGLE_JOB_API, TEST_BURST_JOB_API };

int
zuc_eia3_nia6_test(struct IMB_MGR *mb_mgr);

static struct mac_test *zuc_eia3_128_vectors;

static void
free_zuc_eia3_128_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        zuc_eia3_128_vectors = NULL;
}

static struct mac_test *zuc_nia6_vectors;

struct zuc_nia6_job_ctx {
        uint8_t *key;
        uint8_t *iv;
};

struct zuc_eia3_job_ctx {
        uint8_t *key;
        uint8_t *iv;
};

struct zuc_eia3_128_params {
        const uint32_t *count;
        const uint8_t *bearer;
        const uint8_t *direction;
};

static void
zuc_eia3_128_set_params(const struct mac_test *v, struct zuc_eia3_128_params *p);

static void
zuc_eia3_128_set_params(const struct mac_test *v, struct zuc_eia3_128_params *p)
{
        const uint8_t *params = (const uint8_t *) v->iv;

        p->count = (const uint32_t *) &params[0];
        p->bearer = &params[4];
        p->direction = &params[5];
}

static void
free_zuc_nia6_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        zuc_nia6_vectors = NULL;
}

static int
zuc_eia3_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                     void *ctx)
{
        struct zuc_eia3_job_ctx *eia = calloc(1, sizeof(*eia));
        struct zuc_eia3_128_params params;

        (void) ctx;
        if (eia == NULL)
                return -1;

        job->user_data = eia;
        eia->key = test_aligned_alloc(16, vec->keySize / 8);
        eia->iv = test_aligned_alloc(16, IMB_ZUC_IV_LEN_IN_BYTES);
        if (eia->key == NULL || eia->iv == NULL)
                return -1;

        zuc_eia3_128_set_params(vec, &params);
        memcpy(eia->key, vec->key, vec->keySize / 8);
        zuc_eia3_iv_gen(*params.count, *params.bearer, *params.direction, eia->iv);
        job->u.ZUC_EIA3._key = eia->key;
        job->u.ZUC_EIA3._iv = eia->iv;

        (void) mb_mgr;
        return 0;
}

static void
zuc_eia3_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct zuc_eia3_job_ctx *eia = job->user_data;

        (void) ctx;
        if (eia != NULL) {
                test_aligned_free(eia->key);
                test_aligned_free(eia->iv);
                free(eia);
        }
        job->user_data = NULL;
}

static int
validate_zuc_EIA_common(struct IMB_MGR *mb_mgr, const uint32_t num_jobs, const enum api_type type)
{
        const struct kat_hash_job_ops ops = {
                .prepare = zuc_eia3_job_prepare,
                .cleanup = zuc_eia3_job_cleanup,
                .hash_alg = IMB_AUTH_ZUC_EIA3,
        };
        const struct mac_test *vec = zuc_eia3_128_vectors;
        int ret = 0;

        for (; vec->msg != NULL; vec++) {
                const int err =
                        (type == TEST_SINGLE_JOB_API)
                                ? kat_hash_test_submit_flush(mb_mgr, &vec, 1, num_jobs, &ops)
                                : kat_hash_test_burst(mb_mgr, &vec, 1, num_jobs, &ops);
                if (err)
                        ret = err;
        }

        return ret;
}

static int
validate_zuc_EIA_mixed_common(struct IMB_MGR *mb_mgr, const uint32_t num_jobs,
                              const enum api_type type)
{
        const struct kat_hash_job_ops ops = {
                .prepare = zuc_eia3_job_prepare,
                .cleanup = zuc_eia3_job_cleanup,
                .hash_alg = IMB_AUTH_ZUC_EIA3,
        };
        const struct mac_test *vec = zuc_eia3_128_vectors;
        const struct mac_test *vec_tab[17];
        uint32_t num_vectors = 0;

        for (; vec->msg != NULL; vec++)
                num_vectors++;

        if (num_vectors == 0 || num_jobs == 0 || num_jobs > 17)
                return -1;

        for (uint32_t i = 0; i < num_jobs; i++)
                vec_tab[i] = &zuc_eia3_128_vectors[i % num_vectors];

        return (type == TEST_SINGLE_JOB_API)
                       ? kat_hash_test_submit_flush(mb_mgr, vec_tab, num_jobs, num_jobs, &ops)
                       : kat_hash_test_burst(mb_mgr, vec_tab, num_jobs, num_jobs, &ops);
}

static int
zuc_nia6_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                     void *ctx)
{
        struct zuc_nia6_job_ctx *nia = calloc(1, sizeof(*nia));

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
zuc_nia6_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct zuc_nia6_job_ctx *nia = job->user_data;

        (void) ctx;
        if (nia != NULL) {
                test_aligned_free(nia->key);
                test_aligned_free(nia->iv);
                free(nia);
        }
        job->user_data = NULL;
}

static int
validate_zuc_NIA6_common(struct IMB_MGR *mb_mgr, const uint32_t num_jobs, const enum api_type type)
{
        const struct kat_hash_job_ops ops = {
                .prepare = zuc_nia6_job_prepare,
                .cleanup = zuc_nia6_job_cleanup,
                .hash_alg = IMB_AUTH_ZUC_NIA6,
        };
        const struct mac_test *vec = zuc_nia6_vectors;
        int ret = 0;

        for (; vec->msg != NULL; vec++) {
                const int err =
                        (type == TEST_SINGLE_JOB_API)
                                ? kat_hash_test_submit_flush(mb_mgr, &vec, 1, num_jobs, &ops)
                                : kat_hash_test_burst(mb_mgr, &vec, 1, num_jobs, &ops);
                if (err)
                        ret = err;
        }

        return ret;
}

static int
validate_zuc_NIA6_mixed_common(struct IMB_MGR *mb_mgr, const uint32_t num_jobs,
                               const enum api_type type)
{
        const struct kat_hash_job_ops ops = {
                .prepare = zuc_nia6_job_prepare,
                .cleanup = zuc_nia6_job_cleanup,
                .hash_alg = IMB_AUTH_ZUC_NIA6,
        };
        const struct mac_test *vec = zuc_nia6_vectors;
        const struct mac_test *vec_tab[17];
        uint32_t num_vectors = 0;

        for (; vec->msg != NULL; vec++)
                num_vectors++;

        if (num_vectors == 0 || num_jobs == 0 || num_jobs > 17)
                return -1;

        for (uint32_t i = 0; i < num_jobs; i++)
                vec_tab[i] = &zuc_nia6_vectors[i % num_vectors];

        return (type == TEST_SINGLE_JOB_API)
                       ? kat_hash_test_submit_flush(mb_mgr, vec_tab, num_jobs, num_jobs, &ops)
                       : kat_hash_test_burst(mb_mgr, vec_tab, num_jobs, num_jobs, &ops);
}

int
zuc_eia3_nia6_test(struct IMB_MGR *mb_mgr)
{

        int errors = 0;
        struct test_suite_context eia3_ctx;
        struct test_suite_context nia6_ctx;
        struct test_json_alloc_ctx *eia3_jctx = NULL;
        struct test_json_alloc_ctx *nia6_jctx = NULL;

        if (load_mac_vectors(kat_vector_dir, "zuc_eia3_128_test.json", &zuc_eia3_128_vectors,
                             &eia3_jctx) < 0 ||
            zuc_eia3_128_vectors == NULL)
                return 1;
        if (load_mac_vectors(kat_vector_dir, "zuc_nia6_test.json", &zuc_nia6_vectors, &nia6_jctx) <
                    0 ||
            zuc_nia6_vectors == NULL) {
                free_zuc_eia3_128_vectors(eia3_jctx);
                return 1;
        }

        test_suite_start(&eia3_ctx, "ZUC-EIA3");
        test_suite_start(&nia6_ctx, "ZUC-NIA6");

        /* Job API tests */
        for (uint32_t i = 1; i <= 17; i++) {
                if (validate_zuc_EIA_common(mb_mgr, i, TEST_SINGLE_JOB_API))
                        test_suite_update(&eia3_ctx, 0, 1);
                else
                        test_suite_update(&eia3_ctx, 1, 0);
        }

        for (uint32_t i = 1; i <= 17; i++) {
                if (validate_zuc_EIA_common(mb_mgr, i, TEST_BURST_JOB_API))
                        test_suite_update(&eia3_ctx, 0, 1);
                else
                        test_suite_update(&eia3_ctx, 1, 0);
        }

        for (uint32_t i = 4; i <= 17; i++) {
                if (validate_zuc_EIA_mixed_common(mb_mgr, i, TEST_SINGLE_JOB_API))
                        test_suite_update(&eia3_ctx, 0, 1);
                else
                        test_suite_update(&eia3_ctx, 1, 0);
        }

        for (uint32_t i = 4; i <= 17; i++) {
                if (validate_zuc_EIA_mixed_common(mb_mgr, i, TEST_BURST_JOB_API))
                        test_suite_update(&eia3_ctx, 0, 1);
                else
                        test_suite_update(&eia3_ctx, 1, 0);
        }

        for (uint32_t i = 1; i <= 17; i++) {
                if (validate_zuc_NIA6_common(mb_mgr, i, TEST_SINGLE_JOB_API))
                        test_suite_update(&nia6_ctx, 0, 1);
                else
                        test_suite_update(&nia6_ctx, 1, 0);
        }

        for (uint32_t i = 1; i <= 17; i++) {
                if (validate_zuc_NIA6_common(mb_mgr, i, TEST_BURST_JOB_API))
                        test_suite_update(&nia6_ctx, 0, 1);
                else
                        test_suite_update(&nia6_ctx, 1, 0);
        }

        for (uint32_t i = 4; i <= 17; i++) {
                if (validate_zuc_NIA6_mixed_common(mb_mgr, i, TEST_SINGLE_JOB_API))
                        test_suite_update(&nia6_ctx, 0, 1);
                else
                        test_suite_update(&nia6_ctx, 1, 0);
        }

        for (uint32_t i = 4; i <= 17; i++) {
                if (validate_zuc_NIA6_mixed_common(mb_mgr, i, TEST_BURST_JOB_API))
                        test_suite_update(&nia6_ctx, 0, 1);
                else
                        test_suite_update(&nia6_ctx, 1, 0);
        }

        errors += test_suite_end(&eia3_ctx);
        errors += test_suite_end(&nia6_ctx);

        free_zuc_eia3_128_vectors(eia3_jctx);
        free_zuc_nia6_vectors(nia6_jctx);
        return errors;
}
