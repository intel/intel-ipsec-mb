/*****************************************************************************
 Copyright (c) 2017-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "aead_test.h"
#include "kat_common_aead.h"
#include "wycheproof_test.h"

int
ccm_test(struct IMB_MGR *mb_mgr);

static struct aead_test *ccm_128_vectors;
static struct aead_test *ccm_256_vectors;

/**
 * @brief Load AES-CCM vector sets from the configured kat-app JSON paths.
 *
 * @param ctx_128 receives context for ccm_128 vectors
 * @param ctx_256 receives context for ccm_256 vectors
 *
 * @return 0 on success or -1 on failure
 */
static int
load_ccm_vectors(struct test_json_alloc_ctx **ctx_128, struct test_json_alloc_ctx **ctx_256)
{
        if (load_aead_vectors(kat_vector_dir, "ccm_128_test.json", &ccm_128_vectors, ctx_128) < 0)
                return -1;
        if (load_aead_vectors(kat_vector_dir, "ccm_256_test.json", &ccm_256_vectors, ctx_256) < 0) {
                json_free_test_ctx(*ctx_128);
                *ctx_128 = NULL;
                ccm_128_vectors = NULL;
                return -1;
        }
        return 0;
}

/**
 * @brief Free AES-CCM vectors previously loaded by load_ccm_vectors().
 *
 * @param ctx_128 context for ccm_128 vectors
 * @param ctx_256 context for ccm_256 vectors
 */
static void
free_ccm_vectors(struct test_json_alloc_ctx *ctx_128, struct test_json_alloc_ctx *ctx_256)
{
        json_free_test_ctx(ctx_128);
        json_free_test_ctx(ctx_256);
        ccm_128_vectors = NULL;
        ccm_256_vectors = NULL;
}

struct ccm_job_ctx {
        const uint32_t *exp_key;
};

static int
ccm_job_prepare(IMB_MGR *mb_mgr, IMB_JOB *job, const struct aead_test *vec, const void *ctx)
{
        const struct ccm_job_ctx *job_ctx = ctx;

        (void) mb_mgr;
        job->enc_keys = job_ctx->exp_key;
        job->dec_keys = job_ctx->exp_key;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
        job->u.CCM.aad = (const uint8_t *) vec->aad;
        job->u.CCM.aad_len_in_bytes = vec->aadSize / 8;
        return 0;
}

static void
test_ccm_vectors(struct IMB_MGR *mb_mgr, const struct aead_test *vector, const uint32_t key_len,
                 struct test_suite_context *ts, const int num_jobs)
{
        uint32_t *expkey = test_aligned_alloc(16, 4 * 15 * sizeof(*expkey));
        uint32_t *dust = test_aligned_alloc(16, 4 * 15 * sizeof(*dust));

        if (expkey == NULL || dust == NULL) {
                test_suite_update(ts, 0, 1);
                test_aligned_free(expkey);
                test_aligned_free(dust);
                return;
        }

        if (key_len == IMB_KEY_128_BYTES)
                IMB_AES_KEYEXP_128(mb_mgr, vector->key, expkey, dust);
        else
                IMB_AES_KEYEXP_256(mb_mgr, vector->key, expkey, dust);

        struct ccm_job_ctx job_ctx = { .exp_key = expkey };

        struct kat_aead_job_ops encrypt_ops = {
                .prepare = ccm_job_prepare,
                .ctx = &job_ctx,
                .cipher_mode = IMB_CIPHER_CCM,
                .hash_alg = IMB_AUTH_AES_CCM,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = key_len,
                .in_place = 0,
        };
        struct kat_aead_job_ops encrypt_in_place_ops = {
                .prepare = ccm_job_prepare,
                .ctx = &job_ctx,
                .cipher_mode = IMB_CIPHER_CCM,
                .hash_alg = IMB_AUTH_AES_CCM,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = key_len,
                .in_place = 1,
        };
        struct kat_aead_job_ops decrypt_ops = {
                .prepare = ccm_job_prepare,
                .ctx = &job_ctx,
                .cipher_mode = IMB_CIPHER_CCM,
                .hash_alg = IMB_AUTH_AES_CCM,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = key_len,
                .in_place = 0,
        };
        struct kat_aead_job_ops decrypt_in_place_ops = {
                .prepare = ccm_job_prepare,
                .ctx = &job_ctx,
                .cipher_mode = IMB_CIPHER_CCM,
                .hash_alg = IMB_AUTH_AES_CCM,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = key_len,
                .in_place = 1,
        };

        const struct kat_aead_job_ops *ops[] = { &encrypt_ops, &encrypt_in_place_ops, &decrypt_ops,
                                                 &decrypt_in_place_ops };

        for (size_t i = 0; i < DIM(ops); i++) {
                if (kat_aead_test(mb_mgr, &vector, 1, num_jobs, ops[i], NULL,
                                  KAT_AEAD_SUBMIT_FLUSH) < 0) {
                        test_suite_update(ts, 0, 1);
                        test_aligned_free(expkey);
                        test_aligned_free(dust);
                        return;
                }
                test_suite_update(ts, 1, 0);

                if (kat_aead_test(mb_mgr, &vector, 1, num_jobs, ops[i], NULL, KAT_AEAD_CCM_BURST) <
                    0) {
                        test_suite_update(ts, 0, 1);
                        test_aligned_free(expkey);
                        test_aligned_free(dust);
                        return;
                }
                test_suite_update(ts, 1, 0);
        }

        if (num_jobs == 1) {
                if (kat_aead_test(mb_mgr, &vector, 1, 1, &encrypt_ops, &decrypt_ops,
                                  KAT_AEAD_ROUND_TRIP) < 0) {
                        test_suite_update(ts, 0, 1);
                        test_aligned_free(expkey);
                        test_aligned_free(dust);
                        return;
                }
                test_suite_update(ts, 1, 0);
        }

        test_aligned_free(expkey);
        test_aligned_free(dust);
}

static void
test_ccm_128_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs)
{
        const struct aead_test *v = ccm_128_vectors;

        if (!quiet_mode)
                printf("AES-CCM-128 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu NONCELen:%zu PktLen:%zu AADLen:%zu "
                               "Digestlen:%zu\n",
                               v->tcId, v->ivSize / 8, v->msgSize / 8, v->aadSize / 8,
                               v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                test_ccm_vectors(mb_mgr, v, IMB_KEY_128_BYTES, ctx, num_jobs);
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_ccm_256_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs)
{
        const struct aead_test *v = ccm_256_vectors;

        if (!quiet_mode)
                printf("AES-CCM-256 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu NONCELen:%zu PktLen:%zu AADLen:%zu "
                               "Digestlen:%zu\n",
                               v->tcId, v->ivSize / 8, v->msgSize / 8, v->aadSize / 8,
                               v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                test_ccm_vectors(mb_mgr, v, IMB_KEY_256_BYTES, ctx, num_jobs);
        }
        if (!quiet_mode)
                printf("\n");
}

int
ccm_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *ctx_128 = NULL;
        struct test_json_alloc_ctx *ctx_256 = NULL;
        int errors = 0;

        if (load_ccm_vectors(&ctx_128, &ctx_256) < 0)
                return 1;

        /* AES-CCM-128 tests */
        test_suite_start(&ctx, "AES-CCM-128");
        for (int i = 1; i <= 19; i++)
                test_ccm_128_std_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

        /* AES-CCM-256 tests */
        test_suite_start(&ctx, "AES-CCM-256");
        for (int i = 1; i <= 19; i++)
                test_ccm_256_std_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

        free_ccm_vectors(ctx_128, ctx_256);
        errors += wycheproof_ccm_test(mb_mgr);

        return errors;
}
