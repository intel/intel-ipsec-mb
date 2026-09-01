/*****************************************************************************
 Copyright (c) 2017-2024, Intel Corporation

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
ctr_test(struct IMB_MGR *);

static struct cipher_test *ctr_vectors;

static void
free_ctr_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        ctr_vectors = NULL;
}

struct ctr_prepare_ctx {
        const void *enc_keys;
        const void *iv;
        size_t key_sched_len;
        unsigned iv_len;
};

struct ctr_job_ctx {
        void *enc_keys;
};

static int
ctr_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                void *ctx)
{
        const struct ctr_prepare_ctx *prepare_ctx = ctx;
        struct ctr_job_ctx *job_ctx = calloc(1, sizeof(*job_ctx));

        (void) mb_mgr;
        (void) vec;
        if (job_ctx == NULL)
                return -1;

        job->user_data = job_ctx;
        job_ctx->enc_keys = test_aligned_alloc(16, prepare_ctx->key_sched_len);
        if (job_ctx->enc_keys == NULL)
                return -1;

        memcpy(job_ctx->enc_keys, prepare_ctx->enc_keys, prepare_ctx->key_sched_len);
        job->enc_keys = job_ctx->enc_keys;
        job->dec_keys = job_ctx->enc_keys;
        job->iv = prepare_ctx->iv;
        job->iv_len_in_bytes = prepare_ctx->iv_len;
        return 0;
}

static void
ctr_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct ctr_job_ctx *job_ctx = job->user_data;

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
                const uint32_t num_jobs, const int burst_type)
{
        const struct cipher_test vec = {
                .msg = (const char *) (dir == IMB_DIR_ENCRYPT ? in_text : out_text),
                .ct = (const char *) (dir == IMB_DIR_ENCRYPT ? out_text : in_text),
                .msgSize = text_len,
        };
        const struct cipher_test *vec_ptr = &vec;
        struct ctr_prepare_ctx prepare_ctx = { expkey, iv, (key_len / 4 + 7) * IMB_AES_BLOCK_SIZE,
                                               iv_len };
        const struct kat_cipher_job_ops ops = {
                .prepare = ctr_job_prepare,
                .cleanup = ctr_job_cleanup,
                .ctx = &prepare_ctx,
                .cipher_mode = IMB_CIPHER_CNTR,
                .cipher_direction = dir,
                .chain_order = order,
                .key_len_in_bytes = key_len,
                .in_place = 0,
        };

        if (burst_type == 1)
                return kat_cipher_test_generic_burst(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
        else if (burst_type == 2)
                return kat_cipher_test_burst(mb_mgr, &vec_ptr, 1, num_jobs, &ops);
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

static int
test_ctr_cipher_burst(struct IMB_MGR *mb_mgr, const void *expkey, unsigned key_len, const void *iv,
                      unsigned iv_len, const uint8_t *in_text, const uint8_t *out_text,
                      unsigned text_len, const IMB_CIPHER_DIRECTION dir,
                      const IMB_CHAIN_ORDER order, const uint32_t num_jobs)
{
        return test_ctr_common(mb_mgr, expkey, key_len, iv, iv_len, in_text, out_text, text_len,
                               dir, order, num_jobs, 2);
}

static void
test_ctr_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx128,
                 struct test_suite_context *ctx192, struct test_suite_context *ctx256,
                 const struct cipher_test *v)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);

        printf("AES-CTR standard test vectors:\n");
        for (; v->msg != NULL; v++) {
                struct test_suite_context *ctx;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  KeySize:%zu IVSize:%zu MsgSize:%zu\n", v->tcId,
                               v->keySize, v->ivSize / 8, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(mb_mgr, v->key, expkey, dust);
                        ctx = ctx128;
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES_KEYEXP_192(mb_mgr, v->key, expkey, dust);
                        ctx = ctx192;
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(mb_mgr, v->key, expkey, dust);
                        ctx = ctx256;
                        break;
                default:
                        return;
                }

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

                if (v->ivSize / 8 == 12) {
                        /* IV in the table didn't include block counter (12 bytes).
                         * Let's encrypt & decrypt the same but
                         * with 16 byte IV that includes block counter.
                         */
                        const unsigned new_iv_len = 16;
                        const unsigned orig_iv_len = 12;
                        uint8_t local_iv[16];

                        memcpy(local_iv, v->iv, orig_iv_len);
                        /* 32-bit 0x1 in BE == 0x01000000 in LE */
                        local_iv[12] = 0x00;
                        local_iv[13] = 0x00;
                        local_iv[14] = 0x00;
                        local_iv[15] = 0x01;

                        if (test_ctr(mb_mgr, expkey, (unsigned) v->keySize / 8, local_iv,
                                     new_iv_len, (const void *) v->msg, (const void *) v->ct,
                                     (unsigned) v->msgSize, IMB_DIR_ENCRYPT,
                                     IMB_ORDER_CIPHER_HASH)) {
                                printf("error #%zu encrypt\n", v->tcId);
                                test_suite_update(ctx, 0, 1);
                        } else {
                                test_suite_update(ctx, 1, 0);
                        }

                        if (test_ctr(mb_mgr, expkey, (unsigned) v->keySize / 8, local_iv,
                                     new_iv_len, (const void *) v->ct, (const void *) v->msg,
                                     (unsigned) v->msgSize, IMB_DIR_DECRYPT,
                                     IMB_ORDER_HASH_CIPHER)) {
                                printf("error #%zu decrypt\n", v->tcId);
                                test_suite_update(ctx, 0, 1);
                        } else {
                                test_suite_update(ctx, 1, 0);
                        }
                }
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_ctr_vectors_burst(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx128,
                       struct test_suite_context *ctx192, struct test_suite_context *ctx256,
                       const struct cipher_test *v, const uint32_t num_jobs)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);

        if (!quiet_mode)
                printf("AES-CTR standard test vectors - Burst API (N jobs = %u):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                struct test_suite_context *ctx;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  KeySize:%zu IVSize:%zu MsgSize:%zu\n", v->tcId,
                               v->keySize, v->ivSize / 8, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(mb_mgr, v->key, expkey, dust);
                        ctx = ctx128;
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES_KEYEXP_192(mb_mgr, v->key, expkey, dust);
                        ctx = ctx192;
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(mb_mgr, v->key, expkey, dust);
                        ctx = ctx256;
                        break;
                default:
                        return;
                }

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

                if (v->ivSize / 8 == 12) {
                        /* IV in the table didn't include block counter (12 bytes).
                         * Let's encrypt & decrypt the same but
                         * with 16 byte IV that includes block counter.
                         */
                        const unsigned new_iv_len = 16;
                        const unsigned orig_iv_len = 12;
                        uint8_t local_iv[16];

                        memcpy(local_iv, v->iv, orig_iv_len);
                        /* 32-bit 0x1 in BE == 0x01000000 in LE */
                        local_iv[12] = 0x00;
                        local_iv[13] = 0x00;
                        local_iv[14] = 0x00;
                        local_iv[15] = 0x01;

                        if (test_ctr_burst(mb_mgr, expkey, (unsigned) v->keySize / 8, local_iv,
                                           new_iv_len, (const void *) v->msg, (const void *) v->ct,
                                           (unsigned) v->msgSize, IMB_DIR_ENCRYPT,
                                           IMB_ORDER_CIPHER_HASH, num_jobs)) {
                                printf("error #%zu encrypt burst\n", v->tcId);
                                test_suite_update(ctx, 0, 1);
                        } else {
                                test_suite_update(ctx, 1, 0);
                        }

                        if (test_ctr_burst(mb_mgr, expkey, (unsigned) v->keySize / 8, local_iv,
                                           new_iv_len, (const void *) v->ct, (const void *) v->msg,
                                           (unsigned) v->msgSize, IMB_DIR_DECRYPT,
                                           IMB_ORDER_HASH_CIPHER, num_jobs)) {
                                printf("error #%zu decrypt burst\n", v->tcId);
                                test_suite_update(ctx, 0, 1);
                        } else {
                                test_suite_update(ctx, 1, 0);
                        }
                }

                if (test_ctr_cipher_burst(mb_mgr, expkey, (unsigned) v->keySize / 8, v->iv,
                                          (unsigned) v->ivSize / 8, (const void *) v->msg,
                                          (const void *) v->ct, (unsigned) v->msgSize,
                                          IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH, num_jobs)) {
                        printf("error #%zu encrypt cipher-only burst\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ctr_cipher_burst(mb_mgr, expkey, (unsigned) v->keySize / 8, v->iv,
                                          (unsigned) v->ivSize / 8, (const void *) v->ct,
                                          (const void *) v->msg, (unsigned) v->msgSize,
                                          IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER, num_jobs)) {
                        printf("error #%zu decrypt cipher-only burst\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (v->ivSize / 8 == 12) {
                        /* IV in the table didn't include block counter (12 bytes).
                         * Let's encrypt & decrypt the same but
                         * with 16 byte IV that includes block counter.
                         */
                        const unsigned new_iv_len = 16;
                        const unsigned orig_iv_len = 12;
                        uint8_t local_iv[16];

                        memcpy(local_iv, v->iv, orig_iv_len);
                        /* 32-bit 0x1 in BE == 0x01000000 in LE */
                        local_iv[12] = 0x00;
                        local_iv[13] = 0x00;
                        local_iv[14] = 0x00;
                        local_iv[15] = 0x01;

                        if (test_ctr_cipher_burst(mb_mgr, expkey, (unsigned) v->keySize / 8,
                                                  local_iv, new_iv_len, (const void *) v->msg,
                                                  (const void *) v->ct, (unsigned) v->msgSize,
                                                  IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH,
                                                  num_jobs)) {
                                printf("error #%zu encrypt cipher-only burst\n", v->tcId);
                                test_suite_update(ctx, 0, 1);
                        } else {
                                test_suite_update(ctx, 1, 0);
                        }

                        if (test_ctr_cipher_burst(mb_mgr, expkey, (unsigned) v->keySize / 8,
                                                  local_iv, new_iv_len, (const void *) v->ct,
                                                  (const void *) v->msg, (unsigned) v->msgSize,
                                                  IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER,
                                                  num_jobs)) {
                                printf("error #%zu decrypt cipher-only burst\n", v->tcId);
                                test_suite_update(ctx, 0, 1);
                        } else {
                                test_suite_update(ctx, 1, 0);
                        }
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
ctr_test(struct IMB_MGR *mb_mgr)
{
        uint32_t i;
        int errors = 0;
        struct test_suite_context ctx128;
        struct test_suite_context ctx192;
        struct test_suite_context ctx256;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "ctr_test.json", &ctr_vectors, &jctx) < 0)
                return 1;

        /* Standard CTR vectors */
        test_suite_start(&ctx128, "AES-CTR-128");
        test_suite_start(&ctx192, "AES-CTR-192");
        test_suite_start(&ctx256, "AES-CTR-256");
        test_ctr_vectors(mb_mgr, &ctx128, &ctx192, &ctx256, ctr_vectors);
        for (i = 1; i <= MAX_CTR_JOBS; i++)
                test_ctr_vectors_burst(mb_mgr, &ctx128, &ctx192, &ctx256, ctr_vectors, i);
        errors += test_suite_end(&ctx128);
        errors += test_suite_end(&ctx192);
        errors += test_suite_end(&ctx256);

        free_ctr_vectors(jctx);
        return errors;
}
