/*****************************************************************************
 Copyright (c) 2017-2024, Intel Corporation

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <intel-ipsec-mb.h>

#include "utils.h"
#include "cipher_test.h"

int
des_test(struct IMB_MGR *mb_mgr);

extern const struct cipher_test des_test_json[];
extern const struct cipher_test des_docsis_test_json[];
extern const struct cipher_test des_cfb_test_json[];
extern const struct cipher_test des3_test_json[];

static int
test_des_many(struct IMB_MGR *mb_mgr, const uint64_t *ks, const uint64_t *ks2, const uint64_t *ks3,
              const void *iv, const uint8_t *in_text, const uint8_t *out_text, unsigned text_len,
              int dir, int order, IMB_CIPHER_MODE cipher, const int in_place, const int num_jobs)
{
        const void *ks_ptr[3]; /* 3DES */
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        int i, jobs_rx = 0, ret = -1;

        assert(targets != NULL);

        memset(padding, -1, sizeof(padding));

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_len + (sizeof(padding) * 2));
                memset(targets[i], -1, text_len + (sizeof(padding) * 2));
                if (in_place) {
                        /* copy input text to the allocated buffer */
                        memcpy(targets[i] + sizeof(padding), in_text, text_len);
                }
        }

        /* Used in 3DES only */
        ks_ptr[0] = ks;
        ks_ptr[1] = ks2;
        ks_ptr[2] = ks3;

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
                if (cipher == IMB_CIPHER_DES3) {
                        job->enc_keys = (const void *) ks_ptr;
                        job->dec_keys = (const void *) ks_ptr;
                        job->key_len_in_bytes = 24; /* 3x keys only */
                } else {
                        job->enc_keys = ks;
                        job->dec_keys = ks;
                        job->key_len_in_bytes = 8;
                }
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
test_des(struct IMB_MGR *mb_mgr, const uint64_t *ks, const uint64_t *ks2, const uint64_t *ks3,
         const void *iv, const uint8_t *in_text, const uint8_t *out_text, unsigned text_len,
         int dir, int order, IMB_CIPHER_MODE cipher, const int in_place)
{
        int ret = 0;

        if (cipher == IMB_CIPHER_DES3) {
                if (ks2 == NULL && ks3 == NULL) {
                        ret |= test_des_many(mb_mgr, ks, ks, ks, iv, in_text, out_text, text_len,
                                             dir, order, cipher, in_place, 1);
                        ret |= test_des_many(mb_mgr, ks, ks, ks, iv, in_text, out_text, text_len,
                                             dir, order, cipher, in_place, 32);
                } else {
                        ret |= test_des_many(mb_mgr, ks, ks2, ks3, iv, in_text, out_text, text_len,
                                             dir, order, cipher, in_place, 1);
                        ret |= test_des_many(mb_mgr, ks, ks2, ks3, iv, in_text, out_text, text_len,
                                             dir, order, cipher, in_place, 32);
                }
        } else {
                ret |= test_des_many(mb_mgr, ks, NULL, NULL, iv, in_text, out_text, text_len, dir,
                                     order, cipher, in_place, 1);
                ret |= test_des_many(mb_mgr, ks, NULL, NULL, iv, in_text, out_text, text_len, dir,
                                     order, cipher, in_place, 32);
        }
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

                if (test_des(mb_mgr, ks, NULL, NULL, v->iv, (const void *) v->msg,
                             (const void *) v->ct, (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT,
                             IMB_ORDER_CIPHER_HASH, cipher, 0)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_des(mb_mgr, ks, NULL, NULL, v->iv, (const void *) v->ct,
                             (const void *) v->msg, (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT,
                             IMB_ORDER_HASH_CIPHER, cipher, 0)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_des(mb_mgr, ks, NULL, NULL, v->iv, (const void *) v->msg,
                             (const void *) v->ct, (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT,
                             IMB_ORDER_CIPHER_HASH, cipher, 1)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_des(mb_mgr, ks, NULL, NULL, v->iv, (const void *) v->ct,
                             (const void *) v->msg, (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT,
                             IMB_ORDER_HASH_CIPHER, cipher, 1)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_des3_vectors(struct IMB_MGR *mb_mgr, const struct cipher_test *v, const char *banner,
                  struct test_suite_context *ctx)
{
        uint64_t ks1[16];
        uint64_t ks2[16];
        uint64_t ks3[16];

        printf("%s:\n", banner);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  PTLen:%zu\n", v->tcId, v->msgSize / 8);
#else
                        printf(".");
#endif
                }
                des_key_schedule(ks1, v->key);
                des_key_schedule(ks2, v->key + 8);
                des_key_schedule(ks3, v->key + 16);

                if (test_des(mb_mgr, ks1, ks2, ks3, v->iv, (const void *) v->msg,
                             (const void *) v->ct, (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT,
                             IMB_ORDER_CIPHER_HASH, IMB_CIPHER_DES3, 0)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_des(mb_mgr, ks1, ks2, ks3, v->iv, (const void *) v->ct,
                             (const void *) v->msg, (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT,
                             IMB_ORDER_HASH_CIPHER, IMB_CIPHER_DES3, 0)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_des(mb_mgr, ks1, ks2, ks3, v->iv, (const void *) v->msg,
                             (const void *) v->ct, (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT,
                             IMB_ORDER_CIPHER_HASH, IMB_CIPHER_DES3, 1)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_des(mb_mgr, ks1, ks2, ks3, v->iv, (const void *) v->ct,
                             (const void *) v->msg, (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT,
                             IMB_ORDER_HASH_CIPHER, IMB_CIPHER_DES3, 1)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

static int
des_cfb_validate(struct test_suite_context *ctx)
{
        const struct cipher_test *v = des_cfb_test_json;

        printf("DES-CFB standard test vectors:\n");
        for (; v->msg != NULL; v++) {
                uint8_t output1[8];
                uint8_t output2[8];
                uint64_t ks[16];

                des_key_schedule(ks, v->key);

                /* Out of place */

                /* encrypt test */
                des_cfb_one(output1, (const void *) v->msg, (const uint64_t *) v->iv, ks,
                            (int) v->msgSize / 8);
                if (memcmp(output1, (const void *) v->ct, v->msgSize / 8)) {
                        printf("DES-CFB enc (OOP) vector %zu mismatched\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                /* decrypt test */
                des_cfb_one(output2, (const void *) v->ct, (const uint64_t *) v->iv, ks,
                            (int) v->msgSize / 8);
                if (memcmp(output2, (const void *) v->msg, v->msgSize / 8)) {
                        printf("DES-CFB dec (OOP) vector %zu mismatched\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                /* In place */

                /* encrypt test */
                memcpy(output1, (const void *) v->msg, v->msgSize / 8);
                des_cfb_one(output2, output1, (const uint64_t *) v->iv, ks, (int) v->msgSize / 8);
                if (memcmp(output2, (const void *) v->ct, v->msgSize / 8)) {
                        printf("DES-CFB enc (IP) vector %zu mismatched\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                /* decrypt test */
                memcpy(output1, (const void *) v->ct, v->msgSize / 8);
                des_cfb_one(output2, output1, (const uint64_t *) v->iv, ks, (int) v->msgSize / 8);
                if (memcmp(output2, (const void *) v->msg, v->msgSize / 8)) {
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
        int errors;

        test_suite_start(&ctx, "DES-CBC-64");
        test_des_vectors(mb_mgr, des_test_json, "DES standard test vectors", IMB_CIPHER_DES, &ctx);
        errors = test_suite_end(&ctx);

        test_suite_start(&ctx, "DOCSIS-DES-64");
        test_des_vectors(mb_mgr, des_docsis_test_json, "DOCSIS DES standard test vectors",
                         IMB_CIPHER_DOCSIS_DES, &ctx);
        errors += test_suite_end(&ctx);

        test_suite_start(&ctx, "DES-CFB-64");
        des_cfb_validate(&ctx);
        errors += test_suite_end(&ctx);

        test_suite_start(&ctx, "3DES-CBC-192");
        test_des_vectors(mb_mgr, des_test_json, "3DES (single key) standard test vectors",
                         IMB_CIPHER_DES3, &ctx);
        test_des3_vectors(mb_mgr, des3_test_json, "3DES (multiple keys) test vectors", &ctx);
        errors += test_suite_end(&ctx);

        return errors;
}
