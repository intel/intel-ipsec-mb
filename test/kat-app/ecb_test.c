/*****************************************************************************
 Copyright (c) 2019-2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <intel-ipsec-mb.h>

#include "utils.h"
#include "cipher_test.h"
#include "kat_common_cipher.h"

int
ecb_test(struct IMB_MGR *mb_mgr);

static struct cipher_test *ecb_vectors;

static void
free_ecb_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        ecb_vectors = NULL;
}

struct ecb_job_prepare_ctx {
        const void *enc_keys;
        const void *dec_keys;
        size_t key_sched_len;
};

struct ecb_job_ctx {
        void *enc_keys;
        void *dec_keys;
};

/* AES key schedule size, per FIPS-197: Nr = Nk + 6 rounds, Nr + 1 round keys of 16 bytes each. */
static size_t
aes_key_sched_len(const unsigned key_len_bytes)
{
        const unsigned key_len_words = key_len_bytes / 4; /* Nk */
        const unsigned num_rounds = key_len_words + 6;    /* Nr */
        const unsigned num_round_keys = num_rounds + 1;

        return num_round_keys * 16;
}

static int
ecb_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                void *ctx)
{
        const struct ecb_job_prepare_ctx *prepare_ctx = ctx;
        struct ecb_job_ctx *job_ctx = calloc(1, sizeof(*job_ctx));

        (void) mb_mgr;
        (void) vec;
        if (job_ctx == NULL)
                return -1;

        job->user_data = job_ctx;

        /* each job gets its own exactly-sized copy of the key schedule */
        job_ctx->enc_keys = test_aligned_alloc(16, prepare_ctx->key_sched_len);
        job_ctx->dec_keys = test_aligned_alloc(16, prepare_ctx->key_sched_len);
        if (job_ctx->enc_keys == NULL || job_ctx->dec_keys == NULL)
                return -1;

        memcpy(job_ctx->enc_keys, prepare_ctx->enc_keys, prepare_ctx->key_sched_len);
        memcpy(job_ctx->dec_keys, prepare_ctx->dec_keys, prepare_ctx->key_sched_len);

        job->enc_keys = job_ctx->enc_keys;
        job->dec_keys = job_ctx->dec_keys;
        return 0;
}

static void
ecb_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct ecb_job_ctx *job_ctx = job->user_data;

        (void) ctx;
        if (job_ctx != NULL) {
                test_aligned_free(job_ctx->enc_keys);
                test_aligned_free(job_ctx->dec_keys);
                free(job_ctx);
        }
        job->user_data = NULL;
}

static int
test_ecb_many(struct IMB_MGR *mb_mgr, void *enc_keys, void *dec_keys, const struct cipher_test *vec,
              int dir, int order, IMB_CIPHER_MODE cipher, const int in_place, const int key_len,
              const int num_jobs)
{
        struct ecb_job_prepare_ctx prepare_ctx = { enc_keys, dec_keys, aes_key_sched_len(key_len) };
        const struct cipher_test *vec_ptr = vec;
        const struct kat_cipher_job_ops ops = {
                .prepare = ecb_job_prepare,
                .cleanup = ecb_job_cleanup,
                .ctx = &prepare_ctx,
                .cipher_mode = cipher,
                .cipher_direction = dir,
                .chain_order = order,
                .key_len_in_bytes = key_len,
                .in_place = in_place,
        };

        return kat_cipher_test_submit_flush(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
}

static int
test_ecb_burst(struct IMB_MGR *mb_mgr, void *enc_keys, void *dec_keys,
               const struct cipher_test *vec, int dir, IMB_CIPHER_MODE cipher, const int in_place,
               const int key_len, const int num_jobs)
{
        struct ecb_job_prepare_ctx prepare_ctx = { enc_keys, dec_keys, aes_key_sched_len(key_len) };
        const struct cipher_test *vec_ptr = vec;
        const struct kat_cipher_job_ops ops = {
                .prepare = ecb_job_prepare,
                .cleanup = ecb_job_cleanup,
                .ctx = &prepare_ctx,
                .cipher_mode = cipher,
                .cipher_direction = dir,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = key_len,
                .in_place = in_place,
        };

        return kat_cipher_test_burst(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
}

static void
test_ecb_vectors(struct IMB_MGR *mb_mgr, const IMB_CIPHER_MODE cipher, const int num_jobs,
                 struct test_suite_context *ts128, struct test_suite_context *ts192,
                 struct test_suite_context *ts256)
{
        const struct cipher_test *v = ecb_vectors;
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);

        if (!quiet_mode)
                printf("AES-ECB standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                struct test_suite_context *ctx = NULL;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu key_len:%zu\n", v->tcId, v->keySize / 8);
#else
                        printf(".");
#endif
                }

                switch (v->keySize / 8) {
                case 16:
                        IMB_AES_KEYEXP_128(mb_mgr, v->key, enc_keys, dec_keys);
                        ctx = ts128;
                        break;
                case 24:
                        IMB_AES_KEYEXP_192(mb_mgr, v->key, enc_keys, dec_keys);
                        ctx = ts192;
                        break;
                case 32:
                default:
                        IMB_AES_KEYEXP_256(mb_mgr, v->key, enc_keys, dec_keys);
                        ctx = ts256;
                        break;
                }

                if (test_ecb_many(mb_mgr, enc_keys, dec_keys, v, IMB_DIR_ENCRYPT,
                                  IMB_ORDER_CIPHER_HASH, cipher, 0, (unsigned) v->keySize / 8,
                                  num_jobs)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ecb_many(mb_mgr, enc_keys, dec_keys, v, IMB_DIR_DECRYPT,
                                  IMB_ORDER_HASH_CIPHER, cipher, 0, (unsigned) v->keySize / 8,
                                  num_jobs)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ecb_many(mb_mgr, enc_keys, dec_keys, v, IMB_DIR_ENCRYPT,
                                  IMB_ORDER_CIPHER_HASH, cipher, 1, (unsigned) v->keySize / 8,
                                  num_jobs)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ecb_many(mb_mgr, enc_keys, dec_keys, v, IMB_DIR_DECRYPT,
                                  IMB_ORDER_HASH_CIPHER, cipher, 1, (unsigned) v->keySize / 8,
                                  num_jobs)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                // test burst API
                if (test_ecb_burst(mb_mgr, enc_keys, dec_keys, v, IMB_DIR_ENCRYPT, cipher, 0,
                                   (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu burst encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ecb_burst(mb_mgr, enc_keys, dec_keys, v, IMB_DIR_DECRYPT, cipher, 0,
                                   (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu burst decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ecb_burst(mb_mgr, enc_keys, dec_keys, v, IMB_DIR_ENCRYPT, cipher, 1,
                                   (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu burst encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ecb_burst(mb_mgr, enc_keys, dec_keys, v, IMB_DIR_DECRYPT, cipher, 1,
                                   (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu burst decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
ecb_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts128, ts192, ts256;
        unsigned i;
        int errors = 0;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "ecb_test.json", &ecb_vectors, &jctx) < 0)
                return 1;

        test_suite_start(&ts128, "AES-ECB-128");
        test_suite_start(&ts192, "AES-ECB-192");
        test_suite_start(&ts256, "AES-ECB-256");

        for (i = 0; i < test_num_jobs_size; i++)
                test_ecb_vectors(mb_mgr, IMB_CIPHER_ECB, test_num_jobs[i], &ts128, &ts192, &ts256);

        errors = test_suite_end(&ts128);
        errors += test_suite_end(&ts192);
        errors += test_suite_end(&ts256);

        free_ecb_vectors(jctx);
        return errors;
}
