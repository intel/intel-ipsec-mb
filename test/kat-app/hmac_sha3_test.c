/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

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
#include "vector_utils.h"

int
hmac_sha3_test(struct IMB_MGR *mb_mgr);

struct hmac_sha3_variant {
        const char *name;
        IMB_HASH_ALG alg;
        size_t block_size;
        size_t digest_size;
        const struct mac_test *vecs;
};

struct hmac_sha3_job_ctx {
        IMB_HASH_ALG hash_alg;
};

static int
hmac_sha3_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                      void *ctx)
{
        const struct hmac_sha3_job_ctx *hmac = ctx;
        uint8_t *ipad = NULL, *opad = NULL;

        ipad = test_aligned_alloc(16, IMB_SHA3_MAX_BLOCK_SIZE);
        if (ipad == NULL)
                return -1;
        opad = test_aligned_alloc(16, IMB_SHA3_MAX_BLOCK_SIZE);
        if (opad == NULL) {
                test_aligned_free(ipad);
                return -1;
        }

        imb_hmac_ipad_opad(mb_mgr, hmac->hash_alg, vec->key, vec->keySize / 8, ipad, opad);
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad;
        job->u.HMAC._hashed_auth_key_xor_opad = opad;
        return 0;
}

static void
hmac_sha3_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        (void) ctx;
        test_aligned_free((void *) (uintptr_t) job->u.HMAC._hashed_auth_key_xor_ipad);
        test_aligned_free((void *) (uintptr_t) job->u.HMAC._hashed_auth_key_xor_opad);
        job->u.HMAC._hashed_auth_key_xor_ipad = NULL;
        job->u.HMAC._hashed_auth_key_xor_opad = NULL;
}

static struct mac_test *hmac_sha3_224_vecs;
static struct mac_test *hmac_sha3_256_vecs;
static struct mac_test *hmac_sha3_384_vecs;
static struct mac_test *hmac_sha3_512_vecs;
static struct test_json_alloc_ctx *ctx_224;
static struct test_json_alloc_ctx *ctx_256;
static struct test_json_alloc_ctx *ctx_384;
static struct test_json_alloc_ctx *ctx_512;

static struct hmac_sha3_variant variants[] = {
        { "HMAC-SHA3-224", IMB_AUTH_HMAC_SHA3_224, IMB_SHA3_224_BLOCK_SIZE,
          IMB_SHA3_224_DIGEST_SIZE_IN_BYTES, NULL },
        { "HMAC-SHA3-256", IMB_AUTH_HMAC_SHA3_256, IMB_SHA3_256_BLOCK_SIZE,
          IMB_SHA3_256_DIGEST_SIZE_IN_BYTES, NULL },
        { "HMAC-SHA3-384", IMB_AUTH_HMAC_SHA3_384, IMB_SHA3_384_BLOCK_SIZE,
          IMB_SHA3_384_DIGEST_SIZE_IN_BYTES, NULL },
        { "HMAC-SHA3-512", IMB_AUTH_HMAC_SHA3_512, IMB_SHA3_512_BLOCK_SIZE,
          IMB_SHA3_512_DIGEST_SIZE_IN_BYTES, NULL },
};

static int
load_hmac_sha3_vectors(void)
{
        char path[1024];
        int ret;
        static const struct {
                const char *file;
                struct mac_test **vecs;
                struct test_json_alloc_ctx **ctx;
        } entries[] = {
                { "hmac_sha3_224_test.json", &hmac_sha3_224_vecs, &ctx_224 },
                { "hmac_sha3_256_test.json", &hmac_sha3_256_vecs, &ctx_256 },
                { "hmac_sha3_384_test.json", &hmac_sha3_384_vecs, &ctx_384 },
                { "hmac_sha3_512_test.json", &hmac_sha3_512_vecs, &ctx_512 },
        };
        size_t i;

        if (kat_vector_dir == NULL) {
                fprintf(stderr, "Error: no vector directory set; use --vector-dir <DIR>\n");
                return -1;
        }

        for (i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
                ret = snprintf(path, sizeof(path), "%s/%s", kat_vector_dir, entries[i].file);
                if (ret < 0 || ret >= (int) sizeof(path))
                        goto err;
                if (json_load_mac_test(path, entries[i].vecs, entries[i].ctx) < 0)
                        goto err;
        }

        variants[0].vecs = hmac_sha3_224_vecs;
        variants[1].vecs = hmac_sha3_256_vecs;
        variants[2].vecs = hmac_sha3_384_vecs;
        variants[3].vecs = hmac_sha3_512_vecs;
        return 0;

err:
        for (i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
                json_free_test_ctx(*entries[i].ctx);
                *entries[i].ctx = NULL;
                *entries[i].vecs = NULL;
        }
        return -1;
}

static void
free_hmac_sha3_vectors(void)
{
        json_free_test_ctx(ctx_224);
        json_free_test_ctx(ctx_256);
        json_free_test_ctx(ctx_384);
        json_free_test_ctx(ctx_512);
        ctx_224 = ctx_256 = ctx_384 = ctx_512 = NULL;
        hmac_sha3_224_vecs = hmac_sha3_256_vecs = NULL;
        hmac_sha3_384_vecs = hmac_sha3_512_vecs = NULL;
}

static void
test_hmac_sha3_std_vectors(struct IMB_MGR *mb_mgr, const struct hmac_sha3_variant *var,
                           const uint32_t num_jobs, struct test_suite_context *ts)
{
        const struct mac_test *v = var->vecs;
        struct hmac_sha3_job_ctx ctx = { .hash_alg = var->alg };
        const struct kat_hash_job_ops ops = {
                .prepare = hmac_sha3_job_prepare,
                .cleanup = hmac_sha3_job_cleanup,
                .ctx = &ctx,
                .hash_alg = var->alg,
        };

        if (!quiet_mode)
                printf("%s standard test vectors (N jobs = %u):\n", var->name, num_jobs);
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

                if (kat_hash_test_submit_flush(mb_mgr, &v, 1, num_jobs, &ops)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else
                        test_suite_update(ts, 1, 0);
                if (kat_hash_test_burst(mb_mgr, &v, 1, num_jobs, &ops)) {
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
hmac_sha3_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        int errors = 0;
        uint32_t num_jobs;
        size_t i;

        if (load_hmac_sha3_vectors() < 0)
                return 1;

        test_suite_start(&ts, "HMAC-SHA3");
        for (i = 0; i < (sizeof(variants) / sizeof(variants[0])); i++) {
                for (num_jobs = 1; num_jobs <= TEST_MAX_NUM_JOBS; num_jobs++)
                        test_hmac_sha3_std_vectors(mb_mgr, &variants[i], num_jobs, &ts);
                /* exercise max-burst path */
                test_hmac_sha3_std_vectors(mb_mgr, &variants[i], IMB_MAX_BURST_SIZE, &ts);
        }
        errors = test_suite_end(&ts);

        free_hmac_sha3_vectors();
        return errors;
}
