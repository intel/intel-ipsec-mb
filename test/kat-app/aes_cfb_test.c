/*****************************************************************************
 Copyright (c) 2024, Intel Corporation

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

#define BYTE_ROUND_UP(x) ((x + 7) / 8)
#define IV_SIZE          16

int
aes_cfb_test(struct IMB_MGR *);

static struct cipher_test *aes_cfb_vectors;

static void
free_aes_cfb_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        aes_cfb_vectors = NULL;
}

struct aes_cfb_prepare_ctx {
        const void *enc_keys;
        const void *iv;
        size_t key_sched_len;
};

struct aes_cfb_job_ctx {
        void *enc_keys;
};

static int
aes_cfb_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                    void *ctx)
{
        const struct aes_cfb_prepare_ctx *prepare_ctx = ctx;
        struct aes_cfb_job_ctx *job_ctx = calloc(1, sizeof(*job_ctx));

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
        job->iv_len_in_bytes = IV_SIZE;
        return 0;
}

static void
aes_cfb_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct aes_cfb_job_ctx *job_ctx = job->user_data;

        (void) ctx;
        if (job_ctx != NULL) {
                test_aligned_free(job_ctx->enc_keys);
                free(job_ctx);
        }
        job->user_data = NULL;
}

static int
test_aes_cfb_common(struct IMB_MGR *mb_mgr, const void *enc_keys, unsigned key_len, const void *iv,
                    const uint8_t *in_text, const uint8_t *out_text, unsigned text_byte_len,
                    const IMB_CIPHER_DIRECTION dir, const int in_place, const uint32_t num_jobs,
                    const int burst_type)
{
        const struct cipher_test vec = {
                .msg = (const char *) (dir == IMB_DIR_ENCRYPT ? in_text : out_text),
                .ct = (const char *) (dir == IMB_DIR_ENCRYPT ? out_text : in_text),
                .msgSize = text_byte_len * 8,
        };
        const struct cipher_test *vec_ptr = &vec;
        struct aes_cfb_prepare_ctx prepare_ctx = { enc_keys, iv,
                                                   (key_len / 4 + 7) * IMB_AES_BLOCK_SIZE };
        const struct kat_cipher_job_ops ops = {
                .prepare = aes_cfb_job_prepare,
                .cleanup = aes_cfb_job_cleanup,
                .ctx = &prepare_ctx,
                .cipher_mode = IMB_CIPHER_CFB,
                .cipher_direction = dir,
                .chain_order =
                        dir == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH : IMB_ORDER_HASH_CIPHER,
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
test_aes_cfb(struct IMB_MGR *mb_mgr, const void *enc_keys, unsigned key_len, const void *iv,
             const uint8_t *in_text, const uint8_t *out_text, unsigned text_byte_len,
             const IMB_CIPHER_DIRECTION dir, const int in_place, const uint32_t num_jobs)
{
        return test_aes_cfb_common(mb_mgr, enc_keys, key_len, iv, in_text, out_text, text_byte_len,
                                   dir, in_place, num_jobs, 0);
}

static int
test_aes_cfb_burst(struct IMB_MGR *mb_mgr, const void *enc_keys, unsigned key_len, const void *iv,
                   const uint8_t *in_text, const uint8_t *out_text, unsigned text_byte_len,
                   const IMB_CIPHER_DIRECTION dir, const int in_place, const uint32_t num_jobs)
{
        return test_aes_cfb_common(mb_mgr, enc_keys, key_len, iv, in_text, out_text, text_byte_len,
                                   dir, in_place, num_jobs, 1);
}

static int
test_aes_cfb_cipher_burst(struct IMB_MGR *mb_mgr, const void *enc_keys, unsigned key_len,
                          const void *iv, const uint8_t *in_text, const uint8_t *out_text,
                          unsigned text_byte_len, const IMB_CIPHER_DIRECTION dir,
                          const int in_place, const uint32_t num_jobs)
{
        return test_aes_cfb_common(mb_mgr, enc_keys, key_len, iv, in_text, out_text, text_byte_len,
                                   dir, in_place, num_jobs, 2);
}

static void
test_aes_cfb_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx128,
                     struct test_suite_context *ctx192, struct test_suite_context *ctx256,
                     const struct cipher_test *v, const int num_jobs)
{
        const void *input, *output;
        const char encrypt[] = "encrypt";
        const char decrypt[] = "decrypt";
        const char *dir_text;
        DECLARE_ALIGNED(uint32_t enc_keys[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        uint32_t directions[2] = { IMB_DIR_ENCRYPT, IMB_DIR_DECRYPT };

        printf("aes_cfb standard test vectors:\n");
        for (; v->msg != NULL; v++) {
                struct test_suite_context *ctx;
                /* Get number of bytes */
                uint32_t text_byte_len = BYTE_ROUND_UP((unsigned) v->msgSize);
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Vector %zu  KeySize:%zu IVSize:%u MsgSize:%zu\n", v->tcId,
                               v->keySize, IV_SIZE, v->msgSize);
#else
                        printf(".");
#endif
                }

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(mb_mgr, v->key, enc_keys, dust);
                        ctx = ctx128;
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES_KEYEXP_192(mb_mgr, v->key, enc_keys, dust);
                        ctx = ctx192;
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(mb_mgr, v->key, enc_keys, dust);
                        ctx = ctx256;
                        break;
                default:
                        return;
                }

                for (uint32_t in_place = 0; in_place < 2; in_place++) {
                        for (uint32_t dir = 0; dir < 2; dir++) {
                                if (directions[dir] == IMB_DIR_ENCRYPT) {
                                        input = v->msg;
                                        output = v->ct;
                                        dir_text = encrypt;
                                } else {
                                        input = v->ct;
                                        output = v->msg;
                                        dir_text = decrypt;
                                }

                                if (test_aes_cfb(mb_mgr, enc_keys, (unsigned) v->keySize / 8, v->iv,
                                                 input, output, text_byte_len, directions[dir],
                                                 in_place, num_jobs)) {
                                        printf("error #%zu %s, jobs: %i\n", v->tcId, dir_text,
                                               num_jobs);
                                        test_suite_update(ctx, 0, 1);
                                } else {
                                        test_suite_update(ctx, 1, 0);
                                }

                                if (test_aes_cfb_burst(mb_mgr, enc_keys, (unsigned) v->keySize / 8,
                                                       v->iv, input, output, text_byte_len,
                                                       directions[dir], in_place, num_jobs)) {
                                        printf("error #%zu %s burst\n", v->tcId, dir_text);
                                        test_suite_update(ctx, 0, 1);
                                } else {
                                        test_suite_update(ctx, 1, 0);
                                }
                                if (test_aes_cfb_cipher_burst(
                                            mb_mgr, enc_keys, (unsigned) v->keySize / 8, v->iv,
                                            input, output, text_byte_len, directions[dir], in_place,
                                            num_jobs)) {
                                        printf("error #%zu %s cipher-only burst\n", v->tcId,
                                               dir_text);
                                        test_suite_update(ctx, 0, 1);
                                } else {
                                        test_suite_update(ctx, 1, 0);
                                }
                        }
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
aes_cfb_test(struct IMB_MGR *mb_mgr)
{
        uint32_t i;
        struct test_json_alloc_ctx *jctx = NULL;

        int errors = 0;
        struct test_suite_context ctx128;
        struct test_suite_context ctx192;
        struct test_suite_context ctx256;

        if (load_cipher_vectors(kat_vector_dir, "aes_cfb_test.json", &aes_cfb_vectors, &jctx) < 0)
                return 1;

        /* Standard aes_cfb vectors */
        test_suite_start(&ctx128, "AES-CFB-128");
        test_suite_start(&ctx192, "AES-CFB-192");
        test_suite_start(&ctx256, "AES-CFB-256");

        for (i = 0; i < test_num_jobs_size; i++)
                test_aes_cfb_vectors(mb_mgr, &ctx128, &ctx192, &ctx256, aes_cfb_vectors,
                                     test_num_jobs[i]);

        errors += test_suite_end(&ctx128);
        errors += test_suite_end(&ctx192);
        errors += test_suite_end(&ctx256);

        free_aes_cfb_vectors(jctx);
        return errors;
}