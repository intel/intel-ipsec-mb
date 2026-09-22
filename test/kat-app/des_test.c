/*****************************************************************************
 Copyright (c) 2017-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>

#include "utils.h"
#include "cipher_test.h"
#include "kat_common_aead.h"
#include "kat_common_cipher.h"

int
des_test(struct IMB_MGR *mb_mgr);

static struct cipher_test *des_vectors;
static struct cipher_test *des_docsis_vectors;
static struct cipher_test *des_cfb_vectors;
static struct cipher_test *des3_vectors;

static int
load_des_vectors(struct test_json_alloc_ctx **ctx_des, struct test_json_alloc_ctx **ctx_docsis,
                 struct test_json_alloc_ctx **ctx_cfb, struct test_json_alloc_ctx **ctx_3des)
{
        if (load_cipher_vectors(kat_vector_dir, "des_test.json", &des_vectors, ctx_des) < 0)
                return -1;
        if (load_cipher_vectors(kat_vector_dir, "des_docsis_test.json", &des_docsis_vectors,
                                ctx_docsis) < 0)
                return -1;
        if (load_cipher_vectors(kat_vector_dir, "des_cfb_test.json", &des_cfb_vectors, ctx_cfb) < 0)
                return -1;
        return load_cipher_vectors(kat_vector_dir, "des3_test.json", &des3_vectors, ctx_3des);
}

static void
free_des_vectors(struct test_json_alloc_ctx *ctx_des, struct test_json_alloc_ctx *ctx_docsis,
                 struct test_json_alloc_ctx *ctx_cfb, struct test_json_alloc_ctx *ctx_3des)
{
        json_free_test_ctx(ctx_des);
        des_vectors = NULL;
        json_free_test_ctx(ctx_docsis);
        des_docsis_vectors = NULL;
        json_free_test_ctx(ctx_cfb);
        des_cfb_vectors = NULL;
        json_free_test_ctx(ctx_3des);
        des3_vectors = NULL;
}

struct des3_job_ctx {
        uint64_t *ks1;
        uint64_t *ks2;
        uint64_t *ks3;
        const void *des3_keys[3];
};

static int
des3_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                 void *ctx)
{
        struct des3_job_ctx *dc = calloc(1, sizeof(*dc));
        /* vectors with an 8-byte key reuse the same schedule for all 3 rounds */
        const int multi_key = (vec->keySize / 8) >= 24;

        (void) mb_mgr;
        (void) ctx;
        if (dc == NULL)
                return -1;

        job->user_data = dc;

        dc->ks1 = test_aligned_alloc(16, IMB_DES_KEY_SCHED_SIZE);
        dc->ks2 = test_aligned_alloc(16, IMB_DES_KEY_SCHED_SIZE);
        dc->ks3 = test_aligned_alloc(16, IMB_DES_KEY_SCHED_SIZE);
        if (dc->ks1 == NULL || dc->ks2 == NULL || dc->ks3 == NULL)
                return -1;

        des_key_schedule(dc->ks1, vec->key);
        if (multi_key) {
                des_key_schedule(dc->ks2, vec->key + 8);
                des_key_schedule(dc->ks3, vec->key + 16);
        } else {
                memcpy(dc->ks2, dc->ks1, IMB_DES_KEY_SCHED_SIZE);
                memcpy(dc->ks3, dc->ks1, IMB_DES_KEY_SCHED_SIZE);
        }

        dc->des3_keys[0] = dc->ks1;
        dc->des3_keys[1] = dc->ks2;
        dc->des3_keys[2] = dc->ks3;
        job->enc_keys = dc->des3_keys;
        job->dec_keys = dc->des3_keys;
        job->key_len_in_bytes = 24;
        job->iv = (const uint8_t *) vec->iv;
        job->iv_len_in_bytes = IMB_DES_BLOCK_SIZE;
        return 0;
}

static void
des3_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct des3_job_ctx *dc = job->user_data;

        (void) ctx;
        if (dc != NULL) {
                test_aligned_free(dc->ks1);
                test_aligned_free(dc->ks2);
                test_aligned_free(dc->ks3);
                free(dc);
        }
        job->user_data = NULL;
}

static int
test_des_many(struct IMB_MGR *mb_mgr, const uint64_t *ks, const void *iv, const uint8_t *in_text,
              const uint8_t *out_text, unsigned text_len, int dir, int order,
              IMB_CIPHER_MODE cipher, const int in_place, const int num_jobs)
{
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **targets = calloc(num_jobs, sizeof(*targets));
        int i, jobs_rx = 0, ret = -1;

        if (targets == NULL)
                return -1;

        memset(padding, -1, sizeof(padding));

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_len + (sizeof(padding) * 2));
                if (targets[i] == NULL)
                        goto end;
                memset(targets[i], -1, text_len + (sizeof(padding) * 2));
                if (in_place) {
                        /* copy input text to the allocated buffer */
                        memcpy(targets[i] + sizeof(padding), in_text, text_len);
                }
        }

        /* flush the scheduler */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = dir;
                job->chain_order = order;
                if (!in_place) {
                        job->dst = targets[i] + sizeof(padding);
                        job->src = in_text;
                } else {
                        job->dst = targets[i] + sizeof(padding);
                        job->src = targets[i] + sizeof(padding);
                }
                job->cipher_mode = cipher;
                job->enc_keys = ks;
                job->dec_keys = ks;
                job->key_len_in_bytes = 8;
                job->iv = iv;
                job->iv_len_in_bytes = 8;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = text_len;
                job->user_data = (void *) ((uint64_t) i);

                job->hash_alg = IMB_AUTH_NULL;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        const int num = (const int) ((uint64_t) job->user_data);

                        jobs_rx++;
                        if (job->status != IMB_STATUS_COMPLETED) {
                                printf("%d error status:%d, job %d", __LINE__, job->status, num);
                                goto end;
                        }
                        if (memcmp(out_text, targets[num] + sizeof(padding), text_len)) {
                                printf("%d mismatched\n", num);
                                goto end;
                        }
                        if (memcmp(padding, targets[num], sizeof(padding))) {
                                printf("%d overwrite head\n", num);
                                goto end;
                        }
                        if (memcmp(padding, targets[num] + sizeof(padding) + text_len,
                                   sizeof(padding))) {
                                printf("%d overwrite tail\n", num);
                                goto end;
                        }
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                const int num = (const int) ((uint64_t) job->user_data);

                jobs_rx++;
                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("%d Error status:%d, job %d", __LINE__, job->status, num);
                        goto end;
                }
                if (memcmp(out_text, targets[num] + sizeof(padding), text_len)) {
                        printf("%d mismatched\n", num);
                        goto end;
                }
                if (memcmp(padding, targets[num], sizeof(padding))) {
                        printf("%d overwrite head\n", num);
                        goto end;
                }
                if (memcmp(padding, targets[num] + sizeof(padding) + text_len, sizeof(padding))) {
                        printf("%d overwrite tail\n", num);
                        goto end;
                }
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++)
                free(targets[i]);
        free(targets);
        return ret;
}

static int
test_des(struct IMB_MGR *mb_mgr, const uint64_t *ks, const void *iv, const uint8_t *in_text,
         const uint8_t *out_text, unsigned text_len, int dir, int order, IMB_CIPHER_MODE cipher,
         const int in_place)
{
        int ret = 0;

        ret |= test_des_many(mb_mgr, ks, iv, in_text, out_text, text_len, dir, order, cipher,
                             in_place, 1);
        ret |= test_des_many(mb_mgr, ks, iv, in_text, out_text, text_len, dir, order, cipher,
                             in_place, 32);
        return ret;
}

static void
test_des_vectors(struct IMB_MGR *mb_mgr, const struct cipher_test *v, const char *banner,
                 const IMB_CIPHER_MODE cipher, struct test_suite_context *ctx)
{

        uint64_t ks[16];

        printf("%s:\n", banner);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  PTLen:%zu\n", v->tcId, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                des_key_schedule(ks, v->key);

                if (test_des(mb_mgr, ks, v->iv, (const void *) v->msg, (const void *) v->ct,
                             (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH,
                             cipher, 0)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_des(mb_mgr, ks, v->iv, (const void *) v->ct, (const void *) v->msg,
                             (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER,
                             cipher, 0)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_des(mb_mgr, ks, v->iv, (const void *) v->msg, (const void *) v->ct,
                             (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH,
                             cipher, 1)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_des(mb_mgr, ks, v->iv, (const void *) v->ct, (const void *) v->msg,
                             (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER,
                             cipher, 1)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

struct docsis_des_job_ctx {
        const uint64_t *ks;
        const void *iv;
        const struct cipher_test *vec;
        int dir;
        int in_place;
};

static int
docsis_des_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, void *ctx)
{
        job->dst = NULL;

        if (ctx == NULL)
                return -1;

        const struct docsis_des_job_ctx *job_ctx = ctx;
        if (job_ctx->vec == NULL)
                return -1;

        const size_t msg_len = job_ctx->vec->msgSize / 8;
        uint8_t *target = malloc(msg_len == 0 ? 1 : msg_len);

        (void) mb_mgr;
        if (target == NULL)
                return -1;

        if (job_ctx->in_place)
                memcpy(target,
                       job_ctx->dir == IMB_DIR_ENCRYPT ? job_ctx->vec->msg : job_ctx->vec->ct,
                       msg_len);

        job->cipher_direction = job_ctx->dir;
        job->chain_order =
                job_ctx->dir == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH : IMB_ORDER_HASH_CIPHER;
        job->dst = target;
        job->src = job_ctx->in_place
                           ? target
                           : (const void *) (job_ctx->dir == IMB_DIR_ENCRYPT ? job_ctx->vec->msg
                                                                             : job_ctx->vec->ct);
        job->cipher_mode = IMB_CIPHER_DOCSIS_DES;
        job->enc_keys = job_ctx->ks;
        job->dec_keys = job_ctx->ks;
        job->key_len_in_bytes = 8;
        job->iv = job_ctx->iv;
        job->iv_len_in_bytes = IMB_DES_BLOCK_SIZE;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = msg_len;
        job->hash_alg = IMB_AUTH_NULL;
        return 0;
}

static void
docsis_des_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        (void) ctx;
        free(job->dst);
        job->dst = NULL;
}

static int
docsis_des_job_validate(struct IMB_JOB *job, const void *ctx)
{
        if (ctx == NULL)
                return -1;

        const struct docsis_des_job_ctx *job_ctx = ctx;
        if (job_ctx->vec == NULL)
                return -1;

        const void *expected =
                job_ctx->dir == IMB_DIR_ENCRYPT ? job_ctx->vec->ct : job_ctx->vec->msg;

        return memcmp(job->dst, expected, job_ctx->vec->msgSize / 8) == 0 ? 0 : -1;
}

static void
test_docsis_des_vectors(struct IMB_MGR *mb_mgr, const struct cipher_test *v, const char *banner,
                        struct test_suite_context *ctx)
{
        const uint32_t num_jobs[] = { 1, 32 };

        printf("%s:\n", banner);
        for (; v->msg != NULL; v++) {
                uint64_t ks[16];
                struct docsis_des_job_ctx encrypt_ctx = {
                        .ks = ks,
                        .iv = v->iv,
                        .vec = v,
                        .dir = IMB_DIR_ENCRYPT,
                        .in_place = 0,
                };
                struct docsis_des_job_ctx decrypt_ctx = {
                        .ks = ks,
                        .iv = v->iv,
                        .vec = v,
                        .dir = IMB_DIR_DECRYPT,
                        .in_place = 0,
                };
                struct docsis_des_job_ctx encrypt_in_place_ctx = encrypt_ctx;
                struct docsis_des_job_ctx decrypt_in_place_ctx = decrypt_ctx;
                const struct kat_custom_job_ops encrypt_ops = {
                        .prepare = docsis_des_job_prepare,
                        .cleanup = docsis_des_job_cleanup,
                        .validate = docsis_des_job_validate,
                        .ctx = &encrypt_ctx,
                };
                const struct kat_custom_job_ops decrypt_ops = {
                        .prepare = docsis_des_job_prepare,
                        .cleanup = docsis_des_job_cleanup,
                        .validate = docsis_des_job_validate,
                        .ctx = &decrypt_ctx,
                };
                struct kat_custom_job_ops encrypt_in_place_ops = encrypt_ops;
                struct kat_custom_job_ops decrypt_in_place_ops = decrypt_ops;
                const struct kat_custom_job_ops *ops[] = {
                        &encrypt_ops,
                        &decrypt_ops,
                        &encrypt_in_place_ops,
                        &decrypt_in_place_ops,
                };
                const char *labels[] = {
                        "encrypt",
                        "decrypt",
                        "encrypt in-place",
                        "decrypt in-place",
                };

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu PTLen:%zu\n", v->tcId, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                des_key_schedule(ks, v->key);
                encrypt_in_place_ctx.in_place = 1;
                decrypt_in_place_ctx.in_place = 1;
                encrypt_in_place_ops.ctx = &encrypt_in_place_ctx;
                decrypt_in_place_ops.ctx = &decrypt_in_place_ctx;

                for (size_t i = 0; i < DIM(num_jobs); i++)
                        for (size_t j = 0; j < DIM(ops); j++)
                                if (kat_aead_test_custom_submit_flush(mb_mgr, ops[j], num_jobs[i]) <
                                    0) {
                                        printf("error #%zu %s, %u jobs\n", v->tcId, labels[j],
                                               num_jobs[i]);
                                        test_suite_update(ctx, 0, 1);
                                } else {
                                        test_suite_update(ctx, 1, 0);
                                }
        }
        if (!quiet_mode)
                printf("\n");
}

/*
 * Builds a vector table once and submits growing batch sizes so that each
 * job in a batch uses a different vector's key schedule and IV.
 */
static void
test_des3_vectors(struct IMB_MGR *mb_mgr, const struct cipher_test *v, const char *banner,
                  struct test_suite_context *ctx)
{
        const struct cipher_test **vec_tab;
        const struct cipher_test *vec;
        uint32_t num_vectors = 0;

        printf("%s:\n", banner);

        for (vec = v; vec->msg != NULL; vec++)
                num_vectors++;

        if (num_vectors == 0) {
                if (!quiet_mode)
                        printf("\n");
                return;
        }

        vec_tab = malloc(num_vectors * sizeof(*vec_tab));
        if (vec_tab == NULL) {
                test_suite_update(ctx, 0, 1);
                return;
        }
        for (uint32_t i = 0; i < num_vectors; i++)
                vec_tab[i] = &v[i];

        const struct kat_cipher_job_ops enc_ops = {
                .prepare = des3_job_prepare,
                .cleanup = des3_job_cleanup,
                .cipher_mode = IMB_CIPHER_DES3,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 24,
                .in_place = 0,
        };
        const struct kat_cipher_job_ops dec_ops = {
                .prepare = des3_job_prepare,
                .cleanup = des3_job_cleanup,
                .cipher_mode = IMB_CIPHER_DES3,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 24,
                .in_place = 0,
        };
        struct kat_cipher_job_ops enc_inplace = enc_ops;
        struct kat_cipher_job_ops dec_inplace = dec_ops;

        enc_inplace.in_place = 1;
        dec_inplace.in_place = 1;

        for (size_t j = 0; j < test_num_jobs_size; j++) {
                const unsigned num_jobs = test_num_jobs[j];

                if (!quiet_mode)
                        printf(".");

                if (kat_cipher_test_submit_flush(mb_mgr, vec_tab, num_vectors, num_jobs, &enc_ops) <
                    0) {
                        printf("error encrypt, %u jobs\n", num_jobs);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (kat_cipher_test_submit_flush(mb_mgr, vec_tab, num_vectors, num_jobs, &dec_ops) <
                    0) {
                        printf("error decrypt, %u jobs\n", num_jobs);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (kat_cipher_test_submit_flush(mb_mgr, vec_tab, num_vectors, num_jobs,
                                                 &enc_inplace) < 0) {
                        printf("error encrypt in-place, %u jobs\n", num_jobs);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (kat_cipher_test_submit_flush(mb_mgr, vec_tab, num_vectors, num_jobs,
                                                 &dec_inplace) < 0) {
                        printf("error decrypt in-place, %u jobs\n", num_jobs);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }

        if (!quiet_mode)
                printf("\n");

        free(vec_tab);
}

static int
des_cfb_validate(struct test_suite_context *ctx)
{
        const struct cipher_test *v = des_cfb_vectors;

        printf("DES-CFB standard test vectors:\n");
        for (; v->msg != NULL; v++) {
                uint8_t output1[8];
                uint8_t output2[8];
                uint64_t ks[16];

                des_key_schedule(ks, v->key);

                /* Out of place */

                /* encrypt test */
                if (des_cfb_one(output1, (const void *) v->msg, (const uint64_t *) v->iv, ks,
                                (int) v->msgSize / 8) != 0 ||
                    memcmp(output1, (const void *) v->ct, v->msgSize / 8)) {
                        printf("DES-CFB enc (OOP) vector %zu mismatched\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                /* decrypt test */
                if (des_cfb_one(output2, (const void *) v->ct, (const uint64_t *) v->iv, ks,
                                (int) v->msgSize / 8) != 0 ||
                    memcmp(output2, (const void *) v->msg, v->msgSize / 8)) {
                        printf("DES-CFB dec (OOP) vector %zu mismatched\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                /* In place */

                /* encrypt test */
                memcpy(output1, (const void *) v->msg, v->msgSize / 8);
                if (des_cfb_one(output2, output1, (const uint64_t *) v->iv, ks,
                                (int) v->msgSize / 8) != 0 ||
                    memcmp(output2, (const void *) v->ct, v->msgSize / 8)) {
                        printf("DES-CFB enc (IP) vector %zu mismatched\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                /* decrypt test */
                memcpy(output1, (const void *) v->ct, v->msgSize / 8);
                if (des_cfb_one(output2, output1, (const uint64_t *) v->iv, ks,
                                (int) v->msgSize / 8) != 0 ||
                    memcmp(output2, (const void *) v->msg, v->msgSize / 8)) {
                        printf("DES-CFB dec (IP) vector %zu mismatched\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
        return 1;
}

int
des_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx_des = NULL;
        struct test_json_alloc_ctx *jctx_docsis = NULL;
        struct test_json_alloc_ctx *jctx_cfb = NULL;
        struct test_json_alloc_ctx *jctx_3des = NULL;
        int errors;

        if (load_des_vectors(&jctx_des, &jctx_docsis, &jctx_cfb, &jctx_3des) < 0) {
                free_des_vectors(jctx_des, jctx_docsis, jctx_cfb, jctx_3des);
                return 1;
        }

        test_suite_start(&ctx, "DES-CBC-64");
        test_des_vectors(mb_mgr, des_vectors, "DES standard test vectors", IMB_CIPHER_DES, &ctx);
        errors = test_suite_end(&ctx);

        test_suite_start(&ctx, "DOCSIS-DES-64");
        test_docsis_des_vectors(mb_mgr, des_docsis_vectors, "DOCSIS DES standard test vectors",
                                &ctx);
        errors += test_suite_end(&ctx);

        test_suite_start(&ctx, "DES-CFB-64");
        des_cfb_validate(&ctx);
        errors += test_suite_end(&ctx);

        test_suite_start(&ctx, "3DES-CBC-192");
        test_des3_vectors(mb_mgr, des_vectors, "3DES (single key) standard test vectors", &ctx);
        test_des3_vectors(mb_mgr, des3_vectors, "3DES (multiple keys) test vectors", &ctx);
        errors += test_suite_end(&ctx);

        free_des_vectors(jctx_des, jctx_docsis, jctx_cfb, jctx_3des);
        return errors;
}
