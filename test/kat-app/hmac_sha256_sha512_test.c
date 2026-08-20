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
#include "kat_common_hash.h"

#define max_burst_jobs 32

int
hmac_sha256_sha512_test(struct IMB_MGR *mb_mgr);

static struct mac_test *hmac_sha224_vectors;
static struct mac_test *hmac_sha256_vectors;
static struct mac_test *hmac_sha384_vectors;
static struct mac_test *hmac_sha512_vectors;

static void
free_hmac_sha224_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        hmac_sha224_vectors = NULL;
}

static void
free_hmac_sha256_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        hmac_sha256_vectors = NULL;
}

static void
free_hmac_sha384_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        hmac_sha384_vectors = NULL;
}

static void
free_hmac_sha512_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        hmac_sha512_vectors = NULL;
}

struct hmac_shax_job_ctx {
        IMB_HASH_ALG hash_alg;
};

static int
hmac_shax_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                      void *ctx)
{
        const struct hmac_shax_job_ctx *hmac = ctx;
        uint8_t *ipad = NULL, *opad = NULL;

        ipad = test_aligned_alloc(16, IMB_SHA512_DIGEST_SIZE_IN_BYTES);
        if (ipad == NULL)
                return -1;
        opad = test_aligned_alloc(16, IMB_SHA512_DIGEST_SIZE_IN_BYTES);
        if (opad == NULL) {
                test_aligned_free(ipad);
                return -1;
        }

        imb_hmac_ipad_opad(mb_mgr, hmac->hash_alg, vec->key, vec->keySize / 8, ipad, opad);
        job->hash_alg = hmac->hash_alg;
        job->u.HMAC._hashed_auth_key_xor_ipad = ipad;
        job->u.HMAC._hashed_auth_key_xor_opad = opad;
        return 0;
}

static void
hmac_shax_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        (void) ctx;
        test_aligned_free((void *) (uintptr_t) job->u.HMAC._hashed_auth_key_xor_ipad);
        test_aligned_free((void *) (uintptr_t) job->u.HMAC._hashed_auth_key_xor_opad);
        job->u.HMAC._hashed_auth_key_xor_ipad = NULL;
        job->u.HMAC._hashed_auth_key_xor_opad = NULL;
}

static int
hmac_shax_hash_alg(const int sha_type, IMB_HASH_ALG *hash_alg)
{
        switch (sha_type) {
        case 224:
                *hash_alg = IMB_AUTH_HMAC_SHA_224;
                break;
        case 256:
                *hash_alg = IMB_AUTH_HMAC_SHA_256;
                break;
        case 384:
                *hash_alg = IMB_AUTH_HMAC_SHA_384;
                break;
        case 512:
                *hash_alg = IMB_AUTH_HMAC_SHA_512;
                break;
        default:
                fprintf(stderr, "Wrong SHA type selection 'SHA-%d'!\n", sha_type);
                return -1;
        }

        return 0;
}

static int
test_hmac_shax(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
               const int sha_type, const size_t tag_size)
{
        struct hmac_shax_job_ctx ctx;
        /* Override the tag size on a local copy instead of the shared vector. */
        struct mac_test tag_vec = *vec;
        const struct mac_test *tag_vec_ptr = &tag_vec;

        tag_vec.tagSize = tag_size * 8;

        if (hmac_shax_hash_alg(sha_type, &ctx.hash_alg) < 0)
                return -1;

        const struct kat_hash_job_ops ops = {
                .prepare = hmac_shax_job_prepare,
                .cleanup = hmac_shax_job_cleanup,
                .ctx = &ctx,
                .hash_alg = ctx.hash_alg,
        };

        return kat_hash_test_submit_flush(mb_mgr, &tag_vec_ptr, 1, num_jobs, &ops);
}

static int
test_hmac_shax_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
                     const int sha_type)
{
        struct hmac_shax_job_ctx ctx;

        if (hmac_shax_hash_alg(sha_type, &ctx.hash_alg) < 0)
                return -1;

        const struct kat_hash_job_ops ops = {
                .prepare = hmac_shax_job_prepare,
                .cleanup = hmac_shax_job_cleanup,
                .ctx = &ctx,
                .hash_alg = ctx.hash_alg,
        };

        return kat_hash_test_burst(mb_mgr, &vec, 1, num_jobs, &ops);
}

static int
test_hmac_shax_hash_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec,
                          const uint32_t num_jobs, const int sha_type)
{
        struct hmac_shax_job_ctx ctx;

        if (hmac_shax_hash_alg(sha_type, &ctx.hash_alg) < 0)
                return -1;

        const struct kat_hash_job_ops ops = {
                .prepare = hmac_shax_job_prepare,
                .cleanup = hmac_shax_job_cleanup,
                .ctx = &ctx,
                .hash_alg = ctx.hash_alg,
        };

        return kat_hash_test_hash_burst(mb_mgr, &vec, 1, num_jobs, &ops);
}

static void
test_hmac_shax_std_vectors(struct IMB_MGR *mb_mgr, const int sha_type, const uint32_t num_jobs,
                           struct test_suite_context *ts)
{
        const struct mac_test *v;

        switch (sha_type) {
        case 224:
                v = hmac_sha224_vectors;
                break;
        case 256:
                v = hmac_sha256_vectors;
                break;
        case 384:
                v = hmac_sha384_vectors;
                break;
        default:
                v = hmac_sha512_vectors;
                break;
        }
        if (!quiet_mode)
                printf("HMAC-SHA%d standard test vectors (N jobs = %u):\n", sha_type, num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("RFC4231 Test Case %zu key_len:%zu "
                               "data_len:%zu\n",
                               v->tcId, v->keySize / 8, v->msgSize / 8);
#else
                        printf(".");
#endif
                }
                if (test_hmac_shax(mb_mgr, v, num_jobs, sha_type, v->tagSize / 8)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else
                        test_suite_update(ts, 1, 0);
                if (test_hmac_shax_burst(mb_mgr, v, num_jobs, sha_type)) {
                        printf("error #%zu - burst API\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else
                        test_suite_update(ts, 1, 0);
                if (test_hmac_shax_hash_burst(mb_mgr, v, num_jobs, sha_type)) {
                        printf("error #%zu - hash-only burst API\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else
                        test_suite_update(ts, 1, 0);
        }
        if (!quiet_mode)
                printf("\n");
}

int
hmac_sha256_sha512_test(struct IMB_MGR *mb_mgr)
{
        const int sha_types_tab[] = { 224, 256, 384, 512 };
        static const char *const sha_names_tab[] = { "HMAC-SHA224", "HMAC-SHA256", "HMAC-SHA384",
                                                     "HMAC-SHA512" };
        struct test_suite_context ts_sha224, ts_sha256, ts_sha384, ts_sha512;
        struct test_json_alloc_ctx *ctx224 = NULL, *ctx256 = NULL, *ctx384 = NULL, *ctx512 = NULL;
        unsigned i, num_jobs;
        int errors = 0;
        uint32_t tag_size;

        if (load_mac_vectors(kat_vector_dir, "hmac_sha224_test.json", &hmac_sha224_vectors,
                             &ctx224) < 0)
                return 1;
        if (load_mac_vectors(kat_vector_dir, "hmac_sha256_test.json", &hmac_sha256_vectors,
                             &ctx256) < 0) {
                free_hmac_sha224_vectors(ctx224);
                return 1;
        }
        if (load_mac_vectors(kat_vector_dir, "hmac_sha384_test.json", &hmac_sha384_vectors,
                             &ctx384) < 0) {
                free_hmac_sha224_vectors(ctx224);
                free_hmac_sha256_vectors(ctx256);
                return 1;
        }
        if (load_mac_vectors(kat_vector_dir, "hmac_sha512_test.json", &hmac_sha512_vectors,
                             &ctx512) < 0) {
                free_hmac_sha224_vectors(ctx224);
                free_hmac_sha256_vectors(ctx256);
                free_hmac_sha384_vectors(ctx384);
                return 1;
        }

        /* Initialize test suites and store in array */
        test_suite_start(&ts_sha224, sha_names_tab[0]);
        test_suite_start(&ts_sha256, sha_names_tab[1]);
        test_suite_start(&ts_sha384, sha_names_tab[2]);
        test_suite_start(&ts_sha512, sha_names_tab[3]);
        struct test_suite_context *sha_ts_tab[] = { &ts_sha224, &ts_sha256, &ts_sha384,
                                                    &ts_sha512 };

        for (i = 0; i < DIM(sha_types_tab); i++) {

                for (num_jobs = 1; num_jobs <= max_burst_jobs; num_jobs++)
                        test_hmac_shax_std_vectors(mb_mgr, sha_types_tab[i], num_jobs,
                                                   sha_ts_tab[i]);
        }

        const struct mac_test *vec_224 = hmac_sha224_vectors;
        assert(vec_224->tagSize / 8 == 28);
        for (tag_size = 4; tag_size <= 28; tag_size++) {
                if (test_hmac_shax(mb_mgr, vec_224, max_burst_jobs, sha_types_tab[0], tag_size)) {
                        printf("error tag size: %u\n", tag_size);
                        test_suite_update(&ts_sha224, 0, 1);
                } else
                        test_suite_update(&ts_sha224, 1, 0);
        }
        /* exercise max-burst path at max tag size */
        if (test_hmac_shax(mb_mgr, vec_224, IMB_MAX_BURST_SIZE, sha_types_tab[0], 28)) {
                printf("error tag size: 28 (max burst)\n");
                test_suite_update(&ts_sha224, 0, 1);
        } else
                test_suite_update(&ts_sha224, 1, 0);

        const struct mac_test *vec_256 = hmac_sha256_vectors;
        assert(vec_256->tagSize / 8 == 32);
        for (tag_size = 4; tag_size <= 32; tag_size++) {
                if (test_hmac_shax(mb_mgr, vec_256, max_burst_jobs, sha_types_tab[1], tag_size)) {
                        printf("error tag size: %u\n", tag_size);
                        test_suite_update(&ts_sha256, 0, 1);
                } else
                        test_suite_update(&ts_sha256, 1, 0);
        }
        /* exercise max-burst path at max tag size */
        if (test_hmac_shax(mb_mgr, vec_256, IMB_MAX_BURST_SIZE, sha_types_tab[1], 32)) {
                printf("error tag size: 32 (max burst)\n");
                test_suite_update(&ts_sha256, 0, 1);
        } else
                test_suite_update(&ts_sha256, 1, 0);

        const struct mac_test *vec_384 = hmac_sha384_vectors;
        assert(vec_384->tagSize / 8 == 48);
        for (tag_size = 4; tag_size <= 48; tag_size++) {
                if (test_hmac_shax(mb_mgr, vec_384, max_burst_jobs, sha_types_tab[2], tag_size)) {
                        printf("error tag size: %u\n", tag_size);
                        test_suite_update(&ts_sha384, 0, 1);
                } else
                        test_suite_update(&ts_sha384, 1, 0);
        }
        /* exercise max-burst path at max tag size */
        if (test_hmac_shax(mb_mgr, vec_384, IMB_MAX_BURST_SIZE, sha_types_tab[2], 48)) {
                printf("error tag size: 48 (max burst)\n");
                test_suite_update(&ts_sha384, 0, 1);
        } else
                test_suite_update(&ts_sha384, 1, 0);

        const struct mac_test *vec_512 = hmac_sha512_vectors;
        assert(vec_512->tagSize / 8 == 64);
        for (tag_size = 4; tag_size <= 64; tag_size++) {
                if (test_hmac_shax(mb_mgr, vec_512, max_burst_jobs, sha_types_tab[3], tag_size)) {
                        printf("error tag size: %u\n", tag_size);
                        test_suite_update(&ts_sha512, 0, 1);
                } else
                        test_suite_update(&ts_sha512, 1, 0);
        }
        /* exercise max-burst path at max tag size */
        if (test_hmac_shax(mb_mgr, vec_512, IMB_MAX_BURST_SIZE, sha_types_tab[3], 64)) {
                printf("error tag size: 64 (max burst)\n");
                test_suite_update(&ts_sha512, 0, 1);
        } else
                test_suite_update(&ts_sha512, 1, 0);

        /* End test suites */
        errors += test_suite_end(&ts_sha224);
        errors += test_suite_end(&ts_sha256);
        errors += test_suite_end(&ts_sha384);
        errors += test_suite_end(&ts_sha512);

        free_hmac_sha224_vectors(ctx224);
        free_hmac_sha256_vectors(ctx256);
        free_hmac_sha384_vectors(ctx384);
        free_hmac_sha512_vectors(ctx512);
        errors += wycheproof_hmac_sha224_test(mb_mgr);
        errors += wycheproof_hmac_sha256_test(mb_mgr);
        errors += wycheproof_hmac_sha384_test(mb_mgr);
        errors += wycheproof_hmac_sha512_test(mb_mgr);

        return errors;
}
