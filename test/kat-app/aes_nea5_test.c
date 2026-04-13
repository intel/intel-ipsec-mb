/*****************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

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

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "cipher_test.h"

#define MAX_CTR_JOBS 32

int
aes_nea5_test(struct IMB_MGR *);

extern const struct cipher_test aes_nea5_test_json[];

static int
test_ctr(struct IMB_MGR *mb_mgr, const void *expkey, unsigned key_len, const void *iv,
         unsigned iv_len, const uint8_t *in_text, const uint8_t *out_text, unsigned text_len,
         const IMB_CIPHER_DIRECTION dir, const IMB_CHAIN_ORDER order)
{
        uint32_t text_byte_len = text_len / 8;
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t *target;
        int ret = -1;

        target = malloc(text_byte_len + (sizeof(padding) * 2));
        if (target == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end;
        }

        memset(target, -1, text_byte_len + (sizeof(padding) * 2));
        memset(padding, -1, sizeof(padding));

        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = dir;
        job->chain_order = order;
        job->dst = target + 16;
        job->src = in_text;
        job->cipher_mode = IMB_CIPHER_AES_NEA5;
        job->enc_keys = expkey;
        job->dec_keys = expkey;
        job->key_len_in_bytes = key_len;
        job->iv = iv;
        job->iv_len_in_bytes = iv_len;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = text_byte_len;

        job->hash_alg = IMB_AUTH_NULL;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (!job) {
                const int err = imb_get_errno(mb_mgr);

                printf("%d Unexpected null return from submit_job()\n"
                       "\t Error code %d, %s\n",
                       __LINE__, err, imb_get_strerror(err));
                goto end;
        }
        if (job->status != IMB_STATUS_COMPLETED) {
                const int err = imb_get_errno(mb_mgr);

                printf("%d job status: %d, error code %d, %s\n", __LINE__, job->status, err,
                       imb_get_strerror(err));
                goto end;
        }
        job = IMB_FLUSH_JOB(mb_mgr);
        if (job) {
                printf("%d Unexpected return from flush_job\n", __LINE__);
                goto end;
        }

        if (memcmp(out_text, target + 16, text_byte_len)) {
                printf("mismatched\n");
                hexdump(stderr, "Target", target + 16, text_byte_len);
                hexdump(stderr, "Expected", out_text, text_byte_len);
                goto end;
        }
        if (memcmp(padding, target, sizeof(padding))) {
                printf("overwrite head\n");
                hexdump(stderr, "Target", target, text_byte_len + 32);
                goto end;
        }
        if (memcmp(padding, target + sizeof(padding) + text_byte_len, sizeof(padding))) {
                printf("overwrite tail\n");
                hexdump(stderr, "Target", target, text_byte_len + 32);
                goto end;
        }
        ret = 0;
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;
end:
        if (target != NULL)
                free(target);
        return ret;
}

static int
test_ctr_burst(struct IMB_MGR *mb_mgr, const void *expkey, unsigned key_len, const void *iv,
               unsigned iv_len, const uint8_t *in_text, const uint8_t *out_text, unsigned text_len,
               const IMB_CIPHER_DIRECTION dir, const IMB_CHAIN_ORDER order, const uint32_t num_jobs)
{
        uint32_t text_byte_len, i, completed_jobs, jobs_rx = 0;
        struct IMB_JOB *job, *jobs[MAX_CTR_JOBS];
        uint8_t padding[16];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        int ret = -1;

        if (targets == NULL)
                goto end_alloc;

        text_byte_len = text_len / 8;
        memset(targets, 0, num_jobs * sizeof(void *));
        memset(padding, -1, sizeof(padding));

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_byte_len + (sizeof(padding) * 2));
                if (targets[i] == NULL)
                        goto end_alloc;
                memset(targets[i], -1, text_byte_len + (sizeof(padding) * 2));
        }

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];
                job->cipher_direction = dir;
                job->chain_order = order;
                job->dst = targets[i] + sizeof(padding);
                job->src = in_text;
                job->cipher_mode = IMB_CIPHER_AES_NEA5;
                job->enc_keys = expkey;
                job->dec_keys = expkey;
                job->key_len_in_bytes = key_len;
                job->iv = iv;
                job->iv_len_in_bytes = iv_len;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = text_byte_len;
                job->hash_alg = IMB_AUTH_NULL;
                job->user_data = targets[i];
                job->user_data2 = (void *) ((uint64_t) i);
                imb_set_session(mb_mgr, job);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
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
                job = jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %u status not complete!\n", i + 1);
                        goto end;
                }
                if (memcmp(out_text, targets[i] + sizeof(padding), text_byte_len)) {
                        printf("mismatched\n");
                        hexdump(stderr, "Target", targets[i] + sizeof(padding), text_byte_len);
                        hexdump(stderr, "Expected", out_text, text_byte_len);
                        goto end;
                }
                if (memcmp(padding, targets[i], sizeof(padding))) {
                        printf("overwrite head\n");
                        hexdump(stderr, "Target", targets[i],
                                text_byte_len + (sizeof(padding) * 2));
                        goto end;
                }
                if (memcmp(padding, targets[i] + sizeof(padding) + text_byte_len,
                           sizeof(padding))) {
                        printf("overwrite tail\n");
                        hexdump(stderr, "Target", targets[i],
                                text_byte_len + (sizeof(padding) * 2));
                        goto end;
                }
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
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

        /* Standard CTR vectors */
        test_suite_start(&ctx, "AES-NEA5");
        test_ctr_vectors(mb_mgr, &ctx, aes_nea5_test_json);
        for (i = 1; i <= MAX_CTR_JOBS; i++)
                test_ctr_vectors_burst(mb_mgr, &ctx, aes_nea5_test_json, i);
        errors += test_suite_end(&ctx);

        return errors;
}
