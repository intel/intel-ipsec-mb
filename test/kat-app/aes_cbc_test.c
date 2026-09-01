/*****************************************************************************
 Copyright (c) 2023-2024, Intel Corporation

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
cbc_test(struct IMB_MGR *mb_mgr);

static struct cipher_test *cbc_vectors;

/**
 * @brief Free AES-CBC vectors previously loaded by load_cbc_vectors().
 *
 * @param ctx loader context returned by load_cbc_vectors()
 */
static void
free_cbc_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        cbc_vectors = NULL;
}

static int
aes_key_sched_len(const unsigned key_len)
{
        return (key_len / 4 + 7) * IMB_AES_BLOCK_SIZE;
}

struct aes_cbc_prepare_ctx {
        const void *enc_keys;
        const void *dec_keys;
        const void *iv;
        size_t key_sched_len;
};

struct aes_cbc_job_ctx {
        void *enc_keys;
        void *dec_keys;
};

static int
aes_cbc_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                    void *ctx)
{
        const struct aes_cbc_prepare_ctx *prepare_ctx = ctx;
        struct aes_cbc_job_ctx *job_ctx = calloc(1, sizeof(*job_ctx));

        (void) mb_mgr;
        (void) vec;
        if (job_ctx == NULL)
                return -1;

        job->user_data = job_ctx;
        job_ctx->enc_keys = test_aligned_alloc(16, prepare_ctx->key_sched_len);
        job_ctx->dec_keys = test_aligned_alloc(16, prepare_ctx->key_sched_len);
        if (job_ctx->enc_keys == NULL || job_ctx->dec_keys == NULL)
                return -1;

        memcpy(job_ctx->enc_keys, prepare_ctx->enc_keys, prepare_ctx->key_sched_len);
        memcpy(job_ctx->dec_keys, prepare_ctx->dec_keys, prepare_ctx->key_sched_len);
        job->enc_keys = job_ctx->enc_keys;
        job->dec_keys = job_ctx->dec_keys;
        job->iv = prepare_ctx->iv;
        job->iv_len_in_bytes = 16;
        return 0;
}

static void
aes_cbc_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct aes_cbc_job_ctx *job_ctx = job->user_data;

        (void) ctx;
        if (job_ctx != NULL) {
                test_aligned_free(job_ctx->enc_keys);
                test_aligned_free(job_ctx->dec_keys);
                free(job_ctx);
        }
        job->user_data = NULL;
}

static int
test_aes_common(struct IMB_MGR *mb_mgr, const void *enc_keys, const void *dec_keys, const void *iv,
                const uint8_t *in_text, const uint8_t *out_text, const unsigned text_len,
                const int dir, const int order, const IMB_CIPHER_MODE cipher, const int in_place,
                const int key_len, const int num_jobs, const int burst_type)
{
        const struct cipher_test vec = {
                .msg = (const char *) (dir == IMB_DIR_ENCRYPT ? in_text : out_text),
                .ct = (const char *) (dir == IMB_DIR_ENCRYPT ? out_text : in_text),
                .msgSize = text_len * 8,
        };
        const struct cipher_test *vec_ptr = &vec;
        struct aes_cbc_prepare_ctx prepare_ctx = { enc_keys, dec_keys, iv,
                                                   aes_key_sched_len(key_len) };
        const struct kat_cipher_job_ops ops = {
                .prepare = aes_cbc_job_prepare,
                .cleanup = aes_cbc_job_cleanup,
                .ctx = &prepare_ctx,
                .cipher_mode = cipher,
                .cipher_direction = dir,
                .chain_order = order,
                .key_len_in_bytes = key_len,
                .in_place = in_place,
        };

        if (burst_type == 1)
                return kat_cipher_test_generic_burst(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
        else if (burst_type == 2)
                return kat_cipher_test_burst(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
        else
                return kat_cipher_test_submit_flush(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
}

static int
test_aes_many(struct IMB_MGR *mb_mgr, const void *enc_keys, const void *dec_keys, const void *iv,
              const uint8_t *in_text, const uint8_t *out_text, const unsigned text_len,
              const int dir, const int order, const IMB_CIPHER_MODE cipher, const int in_place,
              const int key_len, const int num_jobs)
{
        return test_aes_common(mb_mgr, enc_keys, dec_keys, iv, in_text, out_text, text_len, dir,
                               order, cipher, in_place, key_len, num_jobs, 0);
}

static int
test_aes_many_burst(struct IMB_MGR *mb_mgr, const void *enc_keys, const void *dec_keys,
                    const void *iv, const uint8_t *in_text, const uint8_t *out_text,
                    const unsigned text_len, const int dir, const int order,
                    const IMB_CIPHER_MODE cipher, const int in_place, const int key_len,
                    const int num_jobs)
{
        return test_aes_common(mb_mgr, enc_keys, dec_keys, iv, in_text, out_text, text_len, dir,
                               order, cipher, in_place, key_len, num_jobs, 1);
}

static int
test_aes_many_cipher_burst(struct IMB_MGR *mb_mgr, const void *enc_keys, const void *dec_keys,
                           const void *iv, const uint8_t *in_text, const uint8_t *out_text,
                           const unsigned text_len, const int dir, const IMB_CIPHER_MODE cipher,
                           const int in_place, const int key_len, const int num_jobs)
{
        const int order = dir == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH : IMB_ORDER_HASH_CIPHER;

        return test_aes_common(mb_mgr, enc_keys, dec_keys, iv, in_text, out_text, text_len, dir,
                               order, cipher, in_place, key_len, num_jobs, 2);
}

static void
test_cbc_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx128,
                 struct test_suite_context *ctx192, struct test_suite_context *ctx256,
                 const IMB_CIPHER_MODE cipher, const int num_jobs)
{
        const struct cipher_test *v = cbc_vectors;
        DECLARE_ALIGNED(uint32_t enc_keys[15 * 4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15 * 4], 16);

        if (!quiet_mode)
                printf("CBC Test (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                struct test_suite_context *ctx;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("AES-CBC Test Case %zu key_len:%zu\n", v->tcId, v->keySize);
#else
                        printf(".");
#endif
                }

                switch (v->keySize / 8) {
                case 16:
                        IMB_AES_KEYEXP_128(mb_mgr, v->key, enc_keys, dec_keys);
                        ctx = ctx128;
                        break;
                case 24:
                        IMB_AES_KEYEXP_192(mb_mgr, v->key, enc_keys, dec_keys);
                        ctx = ctx192;
                        break;
                case 32:
                default:
                        IMB_AES_KEYEXP_256(mb_mgr, v->key, enc_keys, dec_keys);
                        ctx = ctx256;
                        break;
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys, v->iv, (const void *) v->msg,
                                  (const void *) v->ct, (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT,
                                  IMB_ORDER_CIPHER_HASH, cipher, 0, (unsigned) v->keySize / 8,
                                  num_jobs)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many_burst(mb_mgr, enc_keys, dec_keys, v->iv, (const void *) v->msg,
                                        (const void *) v->ct, (unsigned) v->msgSize / 8,
                                        IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH, cipher, 0,
                                        (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu encrypt burst\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys, v->iv, (const void *) v->ct,
                                  (const void *) v->msg, (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT,
                                  IMB_ORDER_HASH_CIPHER, cipher, 0, (unsigned) v->keySize / 8,
                                  num_jobs)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many_burst(mb_mgr, enc_keys, dec_keys, v->iv, (const void *) v->ct,
                                        (const void *) v->msg, (unsigned) v->msgSize / 8,
                                        IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER, cipher, 0,
                                        (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu decrypt burst\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys, v->iv, (const void *) v->msg,
                                  (const void *) v->ct, (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT,
                                  IMB_ORDER_CIPHER_HASH, cipher, 1, (unsigned) v->keySize / 8,
                                  num_jobs)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many_burst(mb_mgr, enc_keys, dec_keys, v->iv, (const void *) v->msg,
                                        (const void *) v->ct, (unsigned) v->msgSize / 8,
                                        IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH, cipher, 1,
                                        (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu encrypt burst in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys, v->iv, (const void *) v->ct,
                                  (const void *) v->msg, (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT,
                                  IMB_ORDER_HASH_CIPHER, cipher, 1, (unsigned) v->keySize / 8,
                                  num_jobs)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many_burst(mb_mgr, enc_keys, dec_keys, v->iv, (const void *) v->ct,
                                        (const void *) v->msg, (unsigned) v->msgSize / 8,
                                        IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER, cipher, 1,
                                        (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu decrypt burst in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many_cipher_burst(mb_mgr, enc_keys, dec_keys, v->iv,
                                               (const void *) v->msg, (const void *) v->ct,
                                               (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT, cipher,
                                               0, (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu encrypt cipher burst\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many_cipher_burst(mb_mgr, enc_keys, dec_keys, v->iv,
                                               (const void *) v->ct, (const void *) v->msg,
                                               (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT, cipher,
                                               0, (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu decrypt cipher burst\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many_cipher_burst(mb_mgr, enc_keys, dec_keys, v->iv,
                                               (const void *) v->msg, (const void *) v->ct,
                                               (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT, cipher,
                                               1, (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu encrypt cipher burst in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many_cipher_burst(mb_mgr, enc_keys, dec_keys, v->iv,
                                               (const void *) v->ct, (const void *) v->msg,
                                               (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT, cipher,
                                               1, (unsigned) v->keySize / 8, num_jobs)) {
                        printf("error #%zu decrypt cipher burst in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
cbc_test(struct IMB_MGR *mb_mgr)
{
        unsigned i;
        int errors = 0;
        struct test_suite_context ctx128;
        struct test_suite_context ctx192;
        struct test_suite_context ctx256;
        struct test_json_alloc_ctx *ctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "cbc_test.json", &cbc_vectors, &ctx) < 0)
                return 1;

        test_suite_start(&ctx128, "AES-CBC-128");
        test_suite_start(&ctx192, "AES-CBC-192");
        test_suite_start(&ctx256, "AES-CBC-256");
        for (i = 0; i < test_num_jobs_size; i++)
                test_cbc_vectors(mb_mgr, &ctx128, &ctx192, &ctx256, IMB_CIPHER_CBC,
                                 test_num_jobs[i]);
        errors += test_suite_end(&ctx128);
        errors += test_suite_end(&ctx192);
        errors += test_suite_end(&ctx256);

        free_cbc_vectors(ctx);

        return errors;
}
