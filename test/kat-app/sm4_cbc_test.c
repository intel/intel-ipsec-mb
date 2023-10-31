/*****************************************************************************
 Copyright (c) 2018-2023, Intel Corporation

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

#define MAX_BURST_JOBS 64

int
sm4_cbc_test(struct IMB_MGR *mb_mgr);

extern const struct cipher_test sm4_cbc_test_json[];

static int
sm4_job_ok(const struct IMB_JOB *job, IMB_MGR *mgr, const uint8_t *out_text, const uint8_t *target,
           const uint8_t *padding, const size_t sizeof_padding, const unsigned text_len)
{
        const int num = (const int) ((uint64_t) job->user_data2);

        if (job->status != IMB_STATUS_COMPLETED) {
                printf("%d error status:%d, job %d", __LINE__, job->status, num);
                imb_get_strerror(imb_get_errno(mgr));
                return 0;
        }
        if (memcmp(out_text, target + sizeof_padding, text_len)) {
                printf("%d mismatched\n", num);
                hexdump(stderr, "Expected", out_text, text_len);
                hexdump(stderr, "Received", target + sizeof_padding, text_len);
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
test_sm4_cbc_many(struct IMB_MGR *mb_mgr, uint32_t *exp_enc_keys, uint32_t *exp_dec_keys,
                  const void *iv, const uint8_t *in_text, const uint8_t *out_text,
                  const unsigned text_len, const int dir, const int order,
                  const IMB_CIPHER_MODE cipher, const int in_place, const int num_jobs)
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
                job->enc_keys = exp_enc_keys;
                job->dec_keys = exp_dec_keys;
                job->key_len_in_bytes = 16;

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
                        if (!sm4_job_ok(job, mb_mgr, out_text, job->user_data, padding,
                                        sizeof(padding), text_len))
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
                if (!sm4_job_ok(job, mb_mgr, out_text, job->user_data, padding, sizeof(padding),
                                text_len))
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

static void
test_sm4_cbc_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                     const IMB_CIPHER_MODE cipher, const int num_jobs)
{
        const struct cipher_test *v = sm4_cbc_test_json;
        DECLARE_ALIGNED(uint32_t exp_enc_keys[IMB_SM4_KEY_SCHEDULE_ROUNDS], 16);
        DECLARE_ALIGNED(uint32_t exp_dec_keys[IMB_SM4_KEY_SCHEDULE_ROUNDS], 16);

        if (!quiet_mode)
                printf("SM4-CBC Test (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("SM4-CBC Test Case %zu\n", v->tcId);
#else
                        printf(".");
#endif
                }

                IMB_SM4_KEYEXP(mb_mgr, v->key, exp_enc_keys, exp_dec_keys);

                if (test_sm4_cbc_many(mb_mgr, exp_enc_keys, exp_dec_keys, v->iv,
                                      (const void *) v->msg, (const void *) v->ct,
                                      (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT,
                                      IMB_ORDER_CIPHER_HASH, cipher, 0, num_jobs)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_sm4_cbc_many(mb_mgr, exp_enc_keys, exp_dec_keys, v->iv,
                                      (const void *) v->ct, (const void *) v->msg,
                                      (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT,
                                      IMB_ORDER_HASH_CIPHER, cipher, 0, num_jobs)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_sm4_cbc_many(mb_mgr, exp_enc_keys, exp_dec_keys, v->iv,
                                      (const void *) v->msg, (const void *) v->ct,
                                      (unsigned) v->msgSize / 8, IMB_DIR_ENCRYPT,
                                      IMB_ORDER_CIPHER_HASH, cipher, 1, num_jobs)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_sm4_cbc_many(mb_mgr, exp_enc_keys, exp_dec_keys, v->iv,
                                      (const void *) v->ct, (const void *) v->msg,
                                      (unsigned) v->msgSize / 8, IMB_DIR_DECRYPT,
                                      IMB_ORDER_HASH_CIPHER, cipher, 1, num_jobs)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }

        if (!quiet_mode)
                printf("\n");
}

int
sm4_cbc_test(struct IMB_MGR *mb_mgr)
{
        const int num_jobs_tab[] = { 1, 3, 4, 5, 7, 8, 9, 15, 16, 17, MAX_BURST_JOBS };
        unsigned i;
        int errors = 0;
        struct test_suite_context ctx;

        test_suite_start(&ctx, "SM4-CBC-128");
        for (i = 0; i < DIM(num_jobs_tab); i++)
                test_sm4_cbc_vectors(mb_mgr, &ctx, IMB_CIPHER_SM4_CBC, num_jobs_tab[i]);
        errors += test_suite_end(&ctx);

        return errors;
}
