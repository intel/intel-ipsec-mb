/*****************************************************************************
 Copyright (c) 2025, Intel Corporation

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
sha3_test(struct IMB_MGR *mb_mgr);

static struct mac_test *sha3_vectors;
static struct mac_test *shake128_vectors;
static struct mac_test *shake256_vectors;

static void
free_sha3_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        sha3_vectors = NULL;
}

static void
free_shake128_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        shake128_vectors = NULL;
}

static void
free_shake256_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        shake256_vectors = NULL;
}

static int
test_sha3(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs,
          const IMB_HASH_ALG sha_type)
{
        const struct kat_hash_job_ops ops = {
                .hash_alg = sha_type,
        };

        return kat_hash_test_submit_flush(mb_mgr, &vec, 1, num_jobs, &ops);
}

static int
test_sha3_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
                const IMB_HASH_ALG sha_type)
{
        const struct kat_hash_job_ops ops = {
                .hash_alg = sha_type,
        };

        return kat_hash_test_burst(mb_mgr, &vec, 1, num_jobs, &ops);
}

static void
test_sha3_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *sha3_224_ctx,
                  struct test_suite_context *sha3_256_ctx, struct test_suite_context *sha3_384_ctx,
                  struct test_suite_context *sha3_512_ctx, const int num_jobs)
{
        struct test_suite_context *ctx;
        const struct mac_test *v = sha3_vectors;
        IMB_HASH_ALG sha_type;

        if (!quiet_mode)
                printf("SHA3 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {

                switch (v->tagSize) {
                case 224:
                        ctx = sha3_224_ctx;
                        sha_type = IMB_AUTH_SHA3_224;
                        break;
                case 256:
                        ctx = sha3_256_ctx;
                        sha_type = IMB_AUTH_SHA3_256;
                        break;
                case 384:
                        ctx = sha3_384_ctx;
                        sha_type = IMB_AUTH_SHA3_384;
                        break;
                case 512:
                        ctx = sha3_512_ctx;
                        sha_type = IMB_AUTH_SHA3_512;
                        break;
                default:
                        ctx = sha3_224_ctx;
                        printf("error #%zu, invalid tag size\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                        continue;
                }
#ifdef DEBUG
                if (!quiet_mode) {
                        printf("SHA3-%d Test Case %zu "
                               "data_len:%zu digest_len:%zu\n",
                               (int) v->tagSize, v->tcId, v->msgSize / 8, v->tagSize / 8);
                }
#endif
                if (test_sha3(mb_mgr, v, num_jobs, sha_type)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_sha3_burst(mb_mgr, v, num_jobs, sha_type)) {
                        printf("burst error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
}

static void
test_shake_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *shake128_ctx,
                   struct test_suite_context *shake256_ctx, const int num_jobs)
{
        struct test_suite_context *ctx;
        const struct mac_test *shake128_v = shake128_vectors;
        const struct mac_test *shake256_v = shake256_vectors;
        IMB_HASH_ALG sha_type;

        if (!quiet_mode)
                printf("SHAKE standard test vectors (N jobs = %d):\n", num_jobs);

        ctx = shake128_ctx;
        sha_type = IMB_AUTH_SHAKE128;
        for (; shake128_v->msg != NULL; shake128_v++) {
#ifdef DEBUG
                if (!quiet_mode) {
                        printf("SHAKE128 Test Case %zu "
                               "data_len:%zu digest_len:%zu\n",
                               shake128_v->tcId, shake128_v->msgSize / 8, shake128_v->tagSize / 8);
                }
#endif
                if (test_sha3(mb_mgr, shake128_v, num_jobs, sha_type)) {
                        printf("SHAKE128 error #%zu\n", shake128_v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (test_sha3_burst(mb_mgr, shake128_v, num_jobs, sha_type)) {
                        printf("SHAKE128 burst error #%zu\n", shake128_v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }

        ctx = shake256_ctx;
        sha_type = IMB_AUTH_SHAKE256;
        for (; shake256_v->msg != NULL; shake256_v++) {
#ifdef DEBUG
                if (!quiet_mode) {
                        printf("SHAKE256 Test Case %zu "
                               "data_len:%zu digest_len:%zu\n",
                               shake256_v->tcId, shake256_v->msgSize / 8, shake256_v->tagSize / 8);
                }
#endif
                if (test_sha3(mb_mgr, shake256_v, num_jobs, sha_type)) {
                        printf("SHAKE256 error #%zu\n", shake256_v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (test_sha3_burst(mb_mgr, shake256_v, num_jobs, sha_type)) {
                        printf("SHAKE256 burst error #%zu\n", shake256_v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
}

int
sha3_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context sha3_224_ctx, sha3_256_ctx, sha3_384_ctx, sha3_512_ctx;
        struct test_suite_context shake128_ctx, shake256_ctx;
        struct test_json_alloc_ctx *ctx_sha3 = NULL, *ctx_128 = NULL, *ctx_256 = NULL;
        int errors = 0;
        unsigned i;

        if (load_mac_vectors(kat_vector_dir, "sha3_test.json", &sha3_vectors, &ctx_sha3) < 0 ||
            sha3_vectors == NULL)
                return 1;
        if (load_mac_vectors(kat_vector_dir, "shake128_test.json", &shake128_vectors, &ctx_128) <
                    0 ||
            shake128_vectors == NULL) {
                free_sha3_vectors(ctx_sha3);
                return 1;
        }
        if (load_mac_vectors(kat_vector_dir, "shake256_test.json", &shake256_vectors, &ctx_256) <
                    0 ||
            shake256_vectors == NULL) {
                free_sha3_vectors(ctx_sha3);
                free_shake128_vectors(ctx_128);
                return 1;
        }

        test_suite_start(&sha3_224_ctx, "SHA3_224");
        test_suite_start(&sha3_256_ctx, "SHA3_256");
        test_suite_start(&sha3_384_ctx, "SHA3_384");
        test_suite_start(&sha3_512_ctx, "SHA3_512");
        for (i = 1; i <= 17; i++) {
                test_sha3_vectors(mb_mgr, &sha3_224_ctx, &sha3_256_ctx, &sha3_384_ctx,
                                  &sha3_512_ctx, i);
        }
        errors += test_suite_end(&sha3_224_ctx);
        errors += test_suite_end(&sha3_256_ctx);
        errors += test_suite_end(&sha3_384_ctx);
        errors += test_suite_end(&sha3_512_ctx);

        test_suite_start(&shake128_ctx, "SHAKE128");
        test_suite_start(&shake256_ctx, "SHAKE256");
        for (i = 1; i <= 17; i++) {
                test_shake_vectors(mb_mgr, &shake128_ctx, &shake256_ctx, i);
        }
        errors += test_suite_end(&shake128_ctx);
        errors += test_suite_end(&shake256_ctx);

        free_sha3_vectors(ctx_sha3);
        free_shake128_vectors(ctx_128);
        free_shake256_vectors(ctx_256);
        return errors;
}
