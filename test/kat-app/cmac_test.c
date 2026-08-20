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
#include "wycheproof_test.h"
#include "kat_common_hash.h"

enum cmac_type {
        CMAC_128 = 0,
        CMAC_256,
};

int
cmac_test(struct IMB_MGR *mb_mgr);

static struct mac_test *cmac_128_vectors;
static struct mac_test *cmac_256_vectors;

struct cmac_job_ctx {
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        uint32_t skey1[4];
        uint32_t skey2[4];
        IMB_HASH_ALG hash_alg;
};

/**
 * @brief Load all CMAC vector sets used by the CMAC kat-app module.
 *
 * @param ctx_128 receives context for cmac_128 vectors
 * @param ctx_256 receives context for cmac_256 vectors
 *
 * @return 0 on success or -1 on failure
 */
static int
load_cmac_vectors(struct test_json_alloc_ctx **ctx_128, struct test_json_alloc_ctx **ctx_256)
{
        if (load_mac_vectors(kat_vector_dir, "cmac_128_test.json", &cmac_128_vectors, ctx_128) < 0)
                return -1;
        if (load_mac_vectors(kat_vector_dir, "cmac_256_test.json", &cmac_256_vectors, ctx_256) <
            0) {
                json_free_test_ctx(*ctx_128);
                *ctx_128 = NULL;
                cmac_128_vectors = NULL;
                return -1;
        }
        return 0;
}

/**
 * @brief Free all CMAC vector sets loaded by load_cmac_vectors().
 *
 * @param ctx_128 context for cmac_128 vectors
 * @param ctx_256 context for cmac_256 vectors
 */
static void
free_cmac_vectors(struct test_json_alloc_ctx *ctx_128, struct test_json_alloc_ctx *ctx_256)
{
        json_free_test_ctx(ctx_128);
        json_free_test_ctx(ctx_256);
}

static const struct cmac_subkeys {
        const char *key;
        const char *sub_key1;
        const char *sub_key2;
} cmac_128_subkeys[] = { { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { NULL, NULL, NULL } };

static const struct cmac_subkeys cmac_256_subkeys[] = {
        { "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61"
          "\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
          "\xca\xd1\xed\x03\x29\x9e\xed\xac\x2e\x9a\x99\x80\x86\x21\x50\x2f",
          "\x95\xa3\xda\x06\x53\x3d\xdb\x58\x5d\x35\x33\x01\x0c\x42\xa0\xd9" },
        { "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61"
          "\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
          "\xca\xd1\xed\x03\x29\x9e\xed\xac\x2e\x9a\x99\x80\x86\x21\x50\x2f",
          "\x95\xa3\xda\x06\x53\x3d\xdb\x58\x5d\x35\x33\x01\x0c\x42\xa0\xd9" },
        { "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61"
          "\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
          "\xca\xd1\xed\x03\x29\x9e\xed\xac\x2e\x9a\x99\x80\x86\x21\x50\x2f",
          "\x95\xa3\xda\x06\x53\x3d\xdb\x58\x5d\x35\x33\x01\x0c\x42\xa0\xd9" },
        { "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61"
          "\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
          "\xca\xd1\xed\x03\x29\x9e\xed\xac\x2e\x9a\x99\x80\x86\x21\x50\x2f",
          "\x95\xa3\xda\x06\x53\x3d\xdb\x58\x5d\x35\x33\x01\x0c\x42\xa0\xd9" },
        { NULL, NULL, NULL }
};

static int
cmac_subkey_test(const struct cmac_subkeys *skeys, const uint32_t *skey1, const uint32_t *skey2)
{
        const size_t sub_key_size = IMB_AES_BLOCK_SIZE;

        if (memcmp(skeys->sub_key1, skey1, sub_key_size)) {
                printf("sub-key1 mismatched\n");
                hexdump(stderr, "Received", skey1, sub_key_size);
                hexdump(stderr, "Expected", (const void *) skeys->sub_key1, sub_key_size);
                return 0;
        }

        if (memcmp(skeys->sub_key2, skey2, sub_key_size)) {
                printf("sub-key2 mismatched\n");
                hexdump(stderr, "Received", skey2, sub_key_size);
                hexdump(stderr, "Expected", (const void *) skeys->sub_key2, sub_key_size);
                return 0;
        }
        return 1;
}

static int
cmac_job_prepare(struct IMB_JOB *job, void *ctx)
{
        const struct cmac_job_ctx *cmac = ctx;

        job->hash_alg = cmac->hash_alg;
        job->u.CMAC._key_expanded = cmac->expkey;
        job->u.CMAC._skey1 = cmac->skey1;
        job->u.CMAC._skey2 = cmac->skey2;
        return 0;
}

static int
cmac_job_ctx_init(struct IMB_MGR *mb_mgr, const struct mac_test *vec,
                  const struct cmac_subkeys *subKeys, const enum cmac_type type,
                  struct cmac_job_ctx *ctx)
{
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);

        if (type == CMAC_128) {
                IMB_AES_KEYEXP_128(mb_mgr, vec->key, ctx->expkey, dust);
                IMB_AES_CMAC_SUBKEY_GEN_128(mb_mgr, ctx->expkey, ctx->skey1, ctx->skey2);
                ctx->hash_alg = IMB_AUTH_AES_CMAC;
        } else { /* AES-CMAC-256 */
                IMB_AES_KEYEXP_256(mb_mgr, vec->key, ctx->expkey, dust);
                IMB_AES_CMAC_SUBKEY_GEN_256(mb_mgr, ctx->expkey, ctx->skey1, ctx->skey2);
                ctx->hash_alg = IMB_AUTH_AES_CMAC_256;
        }

        return cmac_subkey_test(subKeys, ctx->skey1, ctx->skey2) ? 0 : -1;
}

static int
test_cmac(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const struct cmac_subkeys *subKeys,
          const int num_jobs, const enum cmac_type type)
{
        struct cmac_job_ctx ctx;
        const struct kat_hash_job_ops ops = {
                .prepare = cmac_job_prepare,
                .ctx = &ctx,
        };
        int i;

        if (cmac_job_ctx_init(mb_mgr, vec, subKeys, type, &ctx) < 0)
                return -1;

        if (kat_hash_test_submit_flush(mb_mgr, vec, num_jobs, &ops))
                return -1;

        /* Keep the per-job submit/flush coverage by running 1-job batches. */
        for (i = 0; i < num_jobs; i++) {
                if (kat_hash_test_submit_flush(mb_mgr, vec, 1, &ops))
                        return -1;
        }

        return 0;
}

static int
test_cmac_hash_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec,
                     const struct cmac_subkeys *subKeys, const uint32_t num_jobs,
                     const enum cmac_type type)
{
        struct cmac_job_ctx ctx;
        const struct kat_hash_job_ops ops = {
                .prepare = cmac_job_prepare,
                .ctx = &ctx,
        };

        if (cmac_job_ctx_init(mb_mgr, vec, subKeys, type, &ctx) < 0)
                return -1;

        return kat_hash_test_hash_burst(mb_mgr, vec, num_jobs, ctx.hash_alg, &ops);
}

static void
test_cmac_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs)
{
        const struct mac_test *v = cmac_128_vectors;
        const struct cmac_subkeys *sk = cmac_128_subkeys;

        if (!quiet_mode)
                printf("AES-CMAC-128 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++, sk++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard CMAC-128 vector %zu Message length: %zu, "
                               "Tag length:%zu\n",
                               v->tcId, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_cmac(mb_mgr, v, sk, num_jobs, CMAC_128)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else
                        test_suite_update(ctx, 1, 0);

                if (test_cmac_hash_burst(mb_mgr, v, sk, num_jobs, CMAC_128)) {
                        printf("hash burst error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else
                        test_suite_update(ctx, 1, 0);
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_cmac_256_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                          const int num_jobs)
{
        const struct mac_test *v = cmac_256_vectors;
        const struct cmac_subkeys *sk = cmac_256_subkeys;

        if (!quiet_mode)
                printf("AES-CMAC-256 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++, sk++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard CMAC-256 vector %zu Message length: %zu, "
                               "Tag length:%zu\n",
                               v->tcId, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_cmac(mb_mgr, v, sk, num_jobs, CMAC_256)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else
                        test_suite_update(ctx, 1, 0);
                if (test_cmac_hash_burst(mb_mgr, v, sk, num_jobs, CMAC_256)) {
                        printf("hash burst error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else
                        test_suite_update(ctx, 1, 0);
        }
        if (!quiet_mode)
                printf("\n");
}

int
cmac_test(struct IMB_MGR *mb_mgr)
{
        int i, errors = 0;
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *ctx_128 = NULL;
        struct test_json_alloc_ctx *ctx_256 = NULL;

        if (load_cmac_vectors(&ctx_128, &ctx_256) < 0)
                return 1;

        /* CMAC 128 with standard vectors */
        test_suite_start(&ctx, "AES-CMAC-128");
        for (i = 1; i <= TEST_MAX_NUM_JOBS; i++)
                test_cmac_std_vectors(mb_mgr, &ctx, i);
        /* exercise max-burst path */
        test_cmac_std_vectors(mb_mgr, &ctx, IMB_MAX_BURST_SIZE);
        errors += test_suite_end(&ctx);

        /* CMAC 256 with standard vectors */
        test_suite_start(&ctx, "AES-CMAC-256");
        for (i = 1; i <= TEST_MAX_NUM_JOBS; i++)
                test_cmac_256_std_vectors(mb_mgr, &ctx, i);
        /* exercise max-burst path */
        test_cmac_256_std_vectors(mb_mgr, &ctx, IMB_MAX_BURST_SIZE);
        errors += test_suite_end(&ctx);

        free_cmac_vectors(ctx_128, ctx_256);
        cmac_128_vectors = NULL;
        cmac_256_vectors = NULL;

        errors += wycheproof_cmac_test(mb_mgr);

        return errors;
}
