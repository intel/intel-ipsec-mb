/*****************************************************************************
 Copyright (c) 2023, Intel Corporation

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
cbc_test(struct IMB_MGR *mb_mgr);

extern const struct cipher_test cbc_test_json[];

static int
aes_job_ok(const struct IMB_JOB *job, const uint8_t *out_text, const uint8_t *target,
           const uint8_t *padding, const size_t sizeof_padding, const unsigned text_len)
{
        const int num = (const int) ((uint64_t) job->user_data2);

        if (job->status != IMB_STATUS_COMPLETED) {
                printf("%d error status:%d, job %d", __LINE__, job->status, num);
                return 0;
        }
        if (memcmp(out_text, target + sizeof_padding, text_len)) {
                printf("%d mismatched\n", num);
                return 0;
        }
        if (memcmp(padding, target, sizeof_padding)) {
                printf("%d overwrite head\n", num);
                return 0;
        }
        if (memcmp(padding, target + sizeof_padding + text_len, sizeof_padding)) {
                printf("%d overwrite tail\n", num);
                return 0;
        }
        return 1;
}

static int
test_aes_many(struct IMB_MGR *mb_mgr, void *enc_keys, void *dec_keys, const void *iv,
              const uint8_t *in_text, const uint8_t *out_text, const unsigned text_len,
              const int dir, const int order, const IMB_CIPHER_MODE cipher, const int in_place,
              const int key_len, const int num_jobs)
{
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        int i, err, jobs_rx = 0, ret = -1;

        if (targets == NULL)
                goto end_alloc;

        memset(targets, 0, num_jobs * sizeof(void *));
        memset(padding, -1, sizeof(padding));

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_len + (sizeof(padding) * 2));
                if (targets[i] == NULL)
                        goto end_alloc;
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
                job->enc_keys = enc_keys;
                job->dec_keys = dec_keys;
                job->key_len_in_bytes = key_len;

                job->iv = iv;
                job->iv_len_in_bytes = 16;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = text_len;
                job->user_data = targets[i];
                job->user_data2 = (void *) ((uint64_t) i);

                job->hash_alg = IMB_AUTH_NULL;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job == NULL) {
                        /* no job returned - check for error */
                        err = imb_get_errno(mb_mgr);
                        if (err != 0) {
                                printf("Error: %s!\n", imb_get_strerror(err));
                                goto end;
                        }
                } else {
                        /* got job back */
                        jobs_rx++;
                        if (!aes_job_ok(job, out_text, job->user_data, padding, sizeof(padding),
                                        text_len))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                err = imb_get_errno(mb_mgr);
                if (err != 0) {
                        printf("Error: %s!\n", imb_get_strerror(err));
                        goto end;
                }

                jobs_rx++;
                if (!aes_job_ok(job, out_text, job->user_data, padding, sizeof(padding), text_len))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
        while (IMB_FLUSH_JOB(mb_mgr) != NULL) {
                err = imb_get_errno(mb_mgr);
                if (err != 0) {
                        printf("Error: %s!\n", imb_get_strerror(err));
                        goto end;
                }
        }

end_alloc:
        if (targets != NULL) {
                for (i = 0; i < num_jobs; i++)
                        free(targets[i]);
                free(targets);
        }

        return ret;
}

static int
test_aes_many_burst(struct IMB_MGR *mb_mgr, void *enc_keys, void *dec_keys, const void *iv,
                    const uint8_t *in_text, const uint8_t *out_text, const unsigned text_len,
                    const int dir, const int order, const IMB_CIPHER_MODE cipher,
                    const int in_place, const int key_len, const int num_jobs)
{
        struct IMB_JOB *job, *jobs[IMB_MAX_BURST_SIZE] = { NULL };
        uint8_t padding[16];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        int i, completed_jobs, jobs_rx = 0, ret = -1;

        if (targets == NULL)
                goto end_alloc;

        memset(targets, 0, num_jobs * sizeof(void *));
        memset(padding, -1, sizeof(padding));

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_len + (sizeof(padding) * 2));
                if (targets[i] == NULL)
                        goto end_alloc;
                memset(targets[i], -1, text_len + (sizeof(padding) * 2));
                if (in_place) {
                        /* copy input text to the allocated buffer */
                        memcpy(targets[i] + sizeof(padding), in_text, text_len);
                }
        }

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < (uint32_t) num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];

                job->cipher_direction = dir;
                job->chain_order = order;
                job->key_len_in_bytes = key_len;
                job->cipher_mode = cipher;
                job->hash_alg = IMB_AUTH_NULL;

                if (!in_place) {
                        job->dst = targets[i] + sizeof(padding);
                        job->src = in_text;
                } else {
                        job->dst = targets[i] + sizeof(padding);
                        job->src = targets[i] + sizeof(padding);
                }

                job->enc_keys = enc_keys;
                job->dec_keys = dec_keys;
                job->iv = iv;
                job->iv_len_in_bytes = 16;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = text_len;
                job->user_data = targets[i];
                job->user_data2 = (void *) ((uint64_t) i);

                imb_set_session(mb_mgr, job);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        if (completed_jobs == 0) {
                int err = imb_get_errno(mb_mgr);

                if (err != 0) {
                        printf("submit_burst error %d : '%s'\n", err, imb_get_strerror(err));
                        goto end;
                }
        }

check_burst_jobs:
        for (i = 0; i < completed_jobs; i++) {
                job = jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %d status not complete!\n", i + 1);
                        goto end;
                }

                if (!aes_job_ok(job, out_text, job->user_data, padding, sizeof(padding), text_len))
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs - completed_jobs, jobs);
                if (completed_jobs == 0) {
                        printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                        goto end;
                }
                goto check_burst_jobs;
        }
        ret = 0;

end:

end_alloc:
        if (targets != NULL) {
                for (i = 0; i < num_jobs; i++)
                        free(targets[i]);
                free(targets);
        }

        return ret;
}

static int
test_aes_many_cipher_burst(struct IMB_MGR *mb_mgr, void *enc_keys, void *dec_keys, const void *iv,
                           const uint8_t *in_text, const uint8_t *out_text, const unsigned text_len,
                           const int dir, const IMB_CIPHER_MODE cipher, const int in_place,
                           const int key_len, const int num_jobs)
{
        struct IMB_JOB *job, jobs[IMB_MAX_BURST_SIZE];
        uint8_t padding[16];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        int i, completed_jobs, jobs_rx = 0, ret = -1;

        if (targets == NULL)
                goto end_alloc;

        memset(targets, 0, num_jobs * sizeof(void *));
        memset(padding, -1, sizeof(padding));

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_len + (sizeof(padding) * 2));
                if (targets[i] == NULL)
                        goto end_alloc;
                memset(targets[i], -1, text_len + (sizeof(padding) * 2));
                if (in_place) {
                        /* copy input text to the allocated buffer */
                        memcpy(targets[i] + sizeof(padding), in_text, text_len);
                }
        }

        for (i = 0; i < num_jobs; i++) {
                job = &jobs[i];

                /* only set fields for generic burst API */
                if (!in_place) {
                        job->dst = targets[i] + sizeof(padding);
                        job->src = in_text;
                } else {
                        job->dst = targets[i] + sizeof(padding);
                        job->src = targets[i] + sizeof(padding);
                }

                job->enc_keys = enc_keys;
                job->dec_keys = dec_keys;
                job->iv = iv;
                job->iv_len_in_bytes = 16;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = text_len;
                job->user_data = targets[i];
                job->user_data2 = (void *) ((uint64_t) i);
        }

        completed_jobs = IMB_SUBMIT_CIPHER_BURST(mb_mgr, jobs, num_jobs, cipher, dir, key_len);
        if (completed_jobs != num_jobs) {
                int err = imb_get_errno(mb_mgr);

                if (err != 0) {
                        printf("submit_burst error %d : '%s'\n", err, imb_get_strerror(err));
                        goto end;
                } else {
                        printf("submit_burst error: not enough "
                               "jobs returned!\n");
                        goto end;
                }
        }

        for (i = 0; i < num_jobs; i++) {
                job = &jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %d status not complete!\n", i + 1);
                        goto end;
                }

                if (!aes_job_ok(job, out_text, job->user_data, padding, sizeof(padding), text_len))
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:

end_alloc:
        if (targets != NULL) {
                for (i = 0; i < num_jobs; i++)
                        free(targets[i]);
                free(targets);
        }

        return ret;
}

static void
test_cbc_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx128,
                 struct test_suite_context *ctx192, struct test_suite_context *ctx256,
                 const IMB_CIPHER_MODE cipher, const int num_jobs)
{
        const struct cipher_test *v = cbc_test_json;
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

        test_suite_start(&ctx128, "AES-CBC-128");
        test_suite_start(&ctx192, "AES-CBC-192");
        test_suite_start(&ctx256, "AES-CBC-256");
        for (i = 0; i < test_num_jobs_size; i++)
                test_cbc_vectors(mb_mgr, &ctx128, &ctx192, &ctx256, IMB_CIPHER_CBC,
                                 test_num_jobs[i]);
        errors += test_suite_end(&ctx128);
        errors += test_suite_end(&ctx192);
        errors += test_suite_end(&ctx256);

        return errors;
}
