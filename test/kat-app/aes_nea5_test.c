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
#include "cipher_test.h"
#include "kat_common_cipher.h"

#define MAX_CTR_JOBS 32

int
aes_nea5_test(struct IMB_MGR *);

static struct cipher_test *aes_nea5_vectors;

static void
free_aes_nea5_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        aes_nea5_vectors = NULL;
}

struct aes_nea5_prepare_ctx {
        const void *enc_keys;
        const void *iv;
        unsigned iv_len;
};

struct aes_nea5_job_ctx {
        void *enc_keys;
};

static int
aes_nea5_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                     void *ctx)
{
        const size_t key_sched_len = 15 * IMB_AES_BLOCK_SIZE;
        const struct aes_nea5_prepare_ctx *prepare_ctx = ctx;
        struct aes_nea5_job_ctx *job_ctx = calloc(1, sizeof(*job_ctx));

        (void) mb_mgr;
        (void) vec;
        if (job_ctx == NULL)
                return -1;

        job->user_data = job_ctx;
        job_ctx->enc_keys = test_aligned_alloc(16, key_sched_len);
        if (job_ctx->enc_keys == NULL)
                return -1;

        memcpy(job_ctx->enc_keys, prepare_ctx->enc_keys, key_sched_len);
        job->enc_keys = job_ctx->enc_keys;
        job->dec_keys = job_ctx->enc_keys;
        job->iv = prepare_ctx->iv;
        job->iv_len_in_bytes = prepare_ctx->iv_len;
        return 0;
}

static void
aes_nea5_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct aes_nea5_job_ctx *job_ctx = job->user_data;

        (void) ctx;
        if (job_ctx != NULL) {
                test_aligned_free(job_ctx->enc_keys);
                free(job_ctx);
        }
        job->user_data = NULL;
}

static int
test_ctr_common(struct IMB_MGR *mb_mgr, const void *expkey, unsigned key_len, const void *iv,
                unsigned iv_len, const uint8_t *in_text, const uint8_t *out_text, unsigned text_len,
                const IMB_CIPHER_DIRECTION dir, const IMB_CHAIN_ORDER order,
                const uint32_t num_jobs, const int burst)
{
        const struct cipher_test vec = {
                .msg = (const char *) (dir == IMB_DIR_ENCRYPT ? in_text : out_text),
                .ct = (const char *) (dir == IMB_DIR_ENCRYPT ? out_text : in_text),
                .msgSize = text_len,
        };
        const struct cipher_test *vec_ptr = &vec;
        struct aes_nea5_prepare_ctx prepare_ctx = { expkey, iv, iv_len };
        const struct kat_cipher_job_ops ops = {
                .prepare = aes_nea5_job_prepare,
                .cleanup = aes_nea5_job_cleanup,
                .ctx = &prepare_ctx,
                .cipher_mode = IMB_CIPHER_AES_NEA5,
                .cipher_direction = dir,
                .chain_order = order,
                .key_len_in_bytes = key_len,
                .in_place = 0,
        };

        if (burst)
                return kat_cipher_test_generic_burst(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
        else
                return kat_cipher_test_submit_flush(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
}

static int
test_ctr(struct IMB_MGR *mb_mgr, const void *expkey, unsigned key_len, const void *iv,
         unsigned iv_len, const uint8_t *in_text, const uint8_t *out_text, unsigned text_len,
         const IMB_CIPHER_DIRECTION dir, const IMB_CHAIN_ORDER order)
{
        return test_ctr_common(mb_mgr, expkey, key_len, iv, iv_len, in_text, out_text, text_len,
                               dir, order, 1, 0);
}

static int
test_ctr_burst(struct IMB_MGR *mb_mgr, const void *expkey, unsigned key_len, const void *iv,
               unsigned iv_len, const uint8_t *in_text, const uint8_t *out_text, unsigned text_len,
               const IMB_CIPHER_DIRECTION dir, const IMB_CHAIN_ORDER order, const uint32_t num_jobs)
{
        return test_ctr_common(mb_mgr, expkey, key_len, iv, iv_len, in_text, out_text, text_len,
                               dir, order, num_jobs, 1);
}

static void
test_ctr_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                 const struct cipher_test *v)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);

        printf("AES-NEA5 standard test vectors:\n");
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  KeySize:%zu IVSize:%zu MsgSize:%zu\n", v->tcId,
                               v->keySize, v->ivSize / 8, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                IMB_AES_KEYEXP_256(mb_mgr, v->key, expkey, dust);

                if (test_ctr(mb_mgr, expkey, (unsigned) v->keySize / 8, v->iv,
                             (unsigned) v->ivSize / 8, (const void *) v->msg, (const void *) v->ct,
                             (unsigned) v->msgSize, IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ctr(mb_mgr, expkey, (unsigned) v->keySize / 8, v->iv,
                             (unsigned) v->ivSize / 8, (const void *) v->ct, (const void *) v->msg,
                             (unsigned) v->msgSize, IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_ctr_vectors_burst(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                       const struct cipher_test *v, const uint32_t num_jobs)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);

        if (!quiet_mode)
                printf("AES-NEA5 standard test vectors - Burst API (N jobs = %u):\n", num_jobs);
        for (; v->msg != NULL; v++) {

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  KeySize:%zu IVSize:%zu MsgSize:%zu\n", v->tcId,
                               v->keySize, v->ivSize / 8, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                IMB_AES_KEYEXP_256(mb_mgr, v->key, expkey, dust);

                if (test_ctr_burst(mb_mgr, expkey, (unsigned) v->keySize / 8, v->iv,
                                   (unsigned) v->ivSize / 8, (const void *) v->msg,
                                   (const void *) v->ct, (unsigned) v->msgSize, IMB_DIR_ENCRYPT,
                                   IMB_ORDER_CIPHER_HASH, num_jobs)) {
                        printf("error #%zu encrypt burst\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ctr_burst(mb_mgr, expkey, (unsigned) v->keySize / 8, v->iv,
                                   (unsigned) v->ivSize / 8, (const void *) v->ct,
                                   (const void *) v->msg, (unsigned) v->msgSize, IMB_DIR_DECRYPT,
                                   IMB_ORDER_HASH_CIPHER, num_jobs)) {
                        printf("error #%zu decrypt burst\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
aes_nea5_test(struct IMB_MGR *mb_mgr)
{
        uint32_t i;
        int errors = 0;
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "aes_nea5_test.json", &aes_nea5_vectors, &jctx) < 0)
                return 1;

        /* Standard CTR vectors */
        test_suite_start(&ctx, "AES-NEA5");
        test_ctr_vectors(mb_mgr, &ctx, aes_nea5_vectors);
        for (i = 1; i <= MAX_CTR_JOBS; i++)
                test_ctr_vectors_burst(mb_mgr, &ctx, aes_nea5_vectors, i);
        errors += test_suite_end(&ctx);

        free_aes_nea5_vectors(jctx);
        return errors;
}
