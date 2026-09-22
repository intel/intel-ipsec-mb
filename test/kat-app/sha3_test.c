/*****************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

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

/*
 * Mixed algorithm test.
 *
 * SHA3 and SHAKE jobs share one multi-buffer manager, so a single batch may
 * hold lanes running at different Keccak rates at the same time.
 * This exercises the variable rate absorb & squeeze code paths, including
 * flush with partially filled lanes.
 *
 * The common hash test module applies one algorithm to every job, so the
 * per-job algorithm is applied here through the prepare() callback, which
 * runs after the common code has set up the default job fields.
 *
 * Note: this relies on the JOB API only. The hash burst API takes a single
 * algorithm for the whole burst and would ignore the per-job value below.
 */
#define SHA3_MIXED_MAX_JOBS 17
#define SHA3_MIXED_ROUNDS   8

struct sha3_mixed_ctx {
        const struct mac_test *const *vec_tab;
        const IMB_HASH_ALG *alg_tab;
        uint32_t num_vecs;
};

static int
sha3_mixed_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                   void *ctx)
{
        const struct sha3_mixed_ctx *c = (const struct sha3_mixed_ctx *) ctx;

        (void) mb_mgr;

        /*
         * Locate the vector in the combined table to recover its algorithm.
         * A given vector belongs to exactly one source list, so a repeated
         * entry always maps to the same algorithm.
         */
        for (uint32_t k = 0; k < c->num_vecs; k++) {
                if (c->vec_tab[k] == vec) {
                        job->hash_alg = c->alg_tab[k];
                        return 0;
                }
        }

        printf("Unknown vector in mixed algorithm table\n");
        return -1;
}

/*
 * SHA3 vectors carry no algorithm field, so the digest size selects the
 * algorithm.
 */
static int
sha3_mixed_alg_from_tag_size(const struct mac_test *vec, IMB_HASH_ALG *alg)
{
        switch (vec->tagSize) {
        case 224:
                *alg = IMB_AUTH_SHA3_224;
                return 0;
        case 256:
                *alg = IMB_AUTH_SHA3_256;
                return 0;
        case 384:
                *alg = IMB_AUTH_SHA3_384;
                return 0;
        case 512:
                *alg = IMB_AUTH_SHA3_512;
                return 0;
        default:
                printf("error #%zu, invalid tag size\n", vec->tcId);
                return -1;
        }
}

#define SHA3_MIXED_MAX_RANGES 8

/*
 * A run of vectors that all use the same algorithm, plus a cursor over it.
 *
 * The SHA3 vectors of all four digest sizes share one list, stored as
 * contiguous per-digest-size groups. Each group becomes a range of its own, so
 * a cursor never leaves its digest size and every SHA3 algorithm stays
 * available to a batch. Each SHAKE list forms a single range.
 */
struct sha3_mixed_range {
        const struct mac_test *begin;
        const struct mac_test *end;
        const struct mac_test *cur;
        IMB_HASH_ALG alg;
};

static const struct mac_test *
sha3_mixed_next_vec(struct sha3_mixed_range *r)
{
        if (r->cur == r->end)
                r->cur = r->begin;

        return r->cur++;
}

static int
sha3_mixed_add_range(struct sha3_mixed_range *tab, unsigned *num, const struct mac_test *begin,
                     const struct mac_test *end, const IMB_HASH_ALG alg)
{
        if (*num >= SHA3_MIXED_MAX_RANGES || begin == end) {
                printf("Invalid mixed algorithm vector range\n");
                return -1;
        }

        tab[*num] =
                (struct sha3_mixed_range){ .begin = begin, .end = end, .cur = begin, .alg = alg };
        (*num)++;
        return 0;
}

static int
sha3_mixed_add_list(struct sha3_mixed_range *tab, unsigned *num, const struct mac_test *list,
                    const IMB_HASH_ALG alg)
{
        const struct mac_test *end = list;

        while (end->msg != NULL)
                end++;

        return sha3_mixed_add_range(tab, num, list, end, alg);
}

/*
 * Split the SHA3 list into its per-digest-size groups and append the SHAKE
 * lists. Every range takes its algorithm from the vectors themselves, so there
 * is no hand written list-to-algorithm table to keep in step.
 */
static int
sha3_mixed_build_ranges(struct sha3_mixed_range *tab, unsigned *num)
{
        const struct mac_test *v = sha3_vectors;

        *num = 0;

        while (v->msg != NULL) {
                const struct mac_test *begin = v;
                const size_t tag_size = v->tagSize;
                IMB_HASH_ALG alg;

                if (sha3_mixed_alg_from_tag_size(v, &alg) < 0)
                        return -1;

                while (v->msg != NULL && v->tagSize == tag_size)
                        v++;

                if (sha3_mixed_add_range(tab, num, begin, v, alg) < 0)
                        return -1;
        }

        if (sha3_mixed_add_list(tab, num, shake128_vectors, IMB_AUTH_SHAKE128) < 0)
                return -1;

        return sha3_mixed_add_list(tab, num, shake256_vectors, IMB_AUTH_SHAKE256);
}

/* Fixed seed, so that a failing batch can be reproduced by re-running. */
#define SHA3_MIXED_SEED 0x5A3C0DE5U

/*
 * Produce a random permutation of 0..n-1 (Fisher-Yates).
 *
 * Consuming the ranges one shuffled permutation at a time randomizes the order
 * in which algorithms are assigned to lanes while still placing every algorithm
 * in each group of n jobs, so batches keep mixing all the Keccak rates instead
 * of degenerating to a few of them by chance.
 */
static void
sha3_mixed_shuffle(unsigned *tab, const unsigned n)
{
        for (unsigned i = 0; i < n; i++)
                tab[i] = i;

        for (unsigned i = n; i > 1; i--) {
                const unsigned j = (unsigned) rand() % i;
                const unsigned t = tab[i - 1];

                tab[i - 1] = tab[j];
                tab[j] = t;
        }
}

static void
test_sha3_mixed_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx)
{
        unsigned order[SHA3_MIXED_MAX_RANGES];
        struct sha3_mixed_range ranges[SHA3_MIXED_MAX_RANGES];
        unsigned num_ranges;
        int failed = 0;

        if (!quiet_mode)
                printf("SHA3/SHAKE mixed algorithm test vectors:\n");

        if (sha3_mixed_build_ranges(ranges, &num_ranges) < 0) {
                test_suite_update(ctx, 0, 1);
                return;
        }

        srand(SHA3_MIXED_SEED);

        /*
         * Sweep the batch size repeatedly - each round reshuffles, so the same
         * batch size is retried with a different algorithm-to-lane assignment.
         */
        for (unsigned iter = 0; iter < (SHA3_MIXED_ROUNDS * SHA3_MIXED_MAX_JOBS); iter++) {
                const struct mac_test *vec_tab[SHA3_MIXED_MAX_JOBS];
                IMB_HASH_ALG alg_tab[SHA3_MIXED_MAX_JOBS];
                const unsigned num_jobs = (iter % SHA3_MIXED_MAX_JOBS) + 1;

                for (unsigned i = 0; i < num_jobs; i++) {
                        const unsigned slot = i % num_ranges;

                        /* refresh the permutation at the start of each group */
                        if (slot == 0)
                                sha3_mixed_shuffle(order, num_ranges);

                        struct sha3_mixed_range *r = &ranges[order[slot]];
                        vec_tab[i] = sha3_mixed_next_vec(r);
                        alg_tab[i] = r->alg;
                }

                struct sha3_mixed_ctx mixed_ctx = { .vec_tab = vec_tab,
                                                    .alg_tab = alg_tab,
                                                    .num_vecs = num_jobs };
                struct kat_hash_job_ops ops = {
                        .prepare = sha3_mixed_prepare,
                        .ctx = &mixed_ctx,
                        /* placeholder, overridden per job by sha3_mixed_prepare() */
                        .hash_alg = alg_tab[0],
                };

                if (kat_hash_test_submit_flush(mb_mgr, vec_tab, num_jobs, num_jobs, &ops) < 0) {
                        printf("mixed algorithm error (N jobs = %u)\n", num_jobs);
                        failed = 1;
                }
        }

        test_suite_update(ctx, failed ? 0 : 1, failed ? 1 : 0);
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
        struct test_suite_context shake128_ctx, shake256_ctx, sha3_mixed_ctx;
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

        test_suite_start(&sha3_mixed_ctx, "SHA3_SHAKE_MIXED");
        test_sha3_mixed_vectors(mb_mgr, &sha3_mixed_ctx);
        errors += test_suite_end(&sha3_mixed_ctx);

        free_sha3_vectors(ctx_sha3);
        free_shake128_vectors(ctx_128);
        free_shake256_vectors(ctx_256);
        return errors;
}
