/*****************************************************************************
 Copyright (c) 2020-2023, Intel Corporation

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

#include "gcm_ctr_vectors_test.h"
#include "utils.h"
#include "cipher_test.h"

int aes_cbcs_test(struct IMB_MGR *mb_mgr);

extern const struct cipher_test aes_cbcs_test_json[];

static int
aes_job_ok(const struct IMB_JOB *job,
           const uint8_t *out_text,
           const uint8_t *target,
           const uint8_t *padding,
           const size_t sizeof_padding,
           const unsigned text_len,
           const uint8_t *last_cipher_block,
           const uint8_t *next_iv)
{
        const int num = (const int)((uint64_t)job->user_data2);

        if (job->status != IMB_STATUS_COMPLETED) {
                printf("%d error status:%d, job %d",
                       __LINE__, job->status, num);
                return 0;
        }
        if (memcmp(out_text, target + sizeof_padding,
                   text_len)) {
                printf("%d mismatched\n", num);
                return 0;
        }
        if (memcmp(padding, target, sizeof_padding)) {
                printf("%d overwrite head\n", num);
                return 0;
        }
        if (memcmp(padding,
                   target + sizeof_padding + text_len,
                   sizeof_padding)) {
                printf("%d overwrite tail\n", num);
                return 0;
        }
        if (memcmp(last_cipher_block, next_iv, IMB_AES_BLOCK_SIZE)) {
                printf("%d preserve IV\n", num);
                return 0;
        }
        return 1;
}

static int
test_aes_many(struct IMB_MGR *mb_mgr,
              void *enc_keys,
              void *dec_keys,
              const void *iv,
              const uint8_t *in_text,
              const uint8_t *out_text,
              const size_t text_len,
              const int dir,
              const int order,
              const IMB_CIPHER_MODE cipher,
              const int in_place,
              const size_t key_len,
              const int num_jobs)
{
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **targets = NULL;
        uint8_t **next_ivs = NULL;
        int i, jobs_rx = 0, ret = -1;
        uint64_t last_block_offset = 0;
        uint8_t last_cipher_block[IMB_AES_BLOCK_SIZE];

        targets = malloc(num_jobs * sizeof(void *));
        if (targets == NULL)
                goto end_alloc;
        memset(targets, 0, num_jobs * sizeof(void *));

        next_ivs = malloc(num_jobs * sizeof(uint8_t *));
        if (next_ivs == NULL)
                goto end_alloc;
        memset(next_ivs, 0, num_jobs * sizeof(uint8_t *));

        memset(padding, -1, sizeof(padding));
        memset(last_cipher_block, 0, sizeof(last_cipher_block));

        /* get offset of last AES block to be processed */
        if (text_len >= 16)
                /* last block offset = (number of blocks - 1) * 160 */
                last_block_offset =
                        (((text_len + 9 * IMB_AES_BLOCK_SIZE) / 160) - 1) * 160;

        /* store copy of last ciphertext block to validate context */
        if (dir == IMB_DIR_ENCRYPT)
                memcpy(last_cipher_block, out_text + last_block_offset,
                       IMB_AES_BLOCK_SIZE);
        else
                memcpy(last_cipher_block, in_text + last_block_offset,
                       IMB_AES_BLOCK_SIZE);

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_len + (sizeof(padding) * 2));
                if (targets[i] == NULL)
                        goto end_alloc;

                /* assume skipped PT is all zeros */
                memset(targets[i], 0, text_len + (sizeof(padding) * 2));

                memcpy(targets[i], padding, sizeof(padding));
                memcpy(targets[i] + sizeof(padding) + text_len,
                       padding, sizeof(padding));

                if (in_place) {
                        /* copy input text to the allocated buffer */
                        memcpy(targets[i] + sizeof(padding), in_text, text_len);
                }

                /* allocate buffers for next IVs */
                next_ivs[i] = malloc(IMB_AES_BLOCK_SIZE);
                if (next_ivs[i] == NULL)
                        goto end_alloc;

                memset(next_ivs[i], 0, IMB_AES_BLOCK_SIZE);
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
                job->user_data2 = (void *)((uint64_t)i);

                job->hash_alg = IMB_AUTH_NULL;

                job->cipher_fields.CBCS.next_iv = next_ivs[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (!aes_job_ok(job, out_text, job->user_data, padding,
                                        sizeof(padding), (unsigned) text_len,
                                        (uint8_t *)&last_cipher_block,
                                        next_ivs[(uint64_t)job->user_data2]))
                                goto end;
                        /* reset job next_iv pointer */
                        job->cipher_fields.CBCS.next_iv = NULL;
                } else if (dir == IMB_DIR_DECRYPT) {
                        printf("Expected decrypt job, received none!\n");
                        goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (!aes_job_ok(job, out_text, job->user_data, padding,
                                sizeof(padding), (unsigned) text_len,
                                (uint8_t *)&last_cipher_block,
                                next_ivs[(uint64_t)job->user_data2]))
                        goto end;
                /* reset job next_iv pointer */
                job->cipher_fields.CBCS.next_iv = NULL;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

 end:
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

end_alloc:
        if (targets != NULL) {
                for (i = 0; i < num_jobs; i++)
                        if (targets[i] != NULL)
                                free(targets[i]);
                free(targets);
        }
        if (next_ivs != NULL) {
                for (i = 0; i < num_jobs; i++)
                        if (next_ivs[i] != NULL)
                                free(next_ivs[i]);
                free(next_ivs);
        }

        return ret;
}

static void
test_aes_vectors(struct IMB_MGR *mb_mgr,
                 struct test_suite_context *ctx,
                 const IMB_CIPHER_MODE cipher, const int num_jobs)
{
        const struct cipher_test *v = aes_cbcs_test_json;
        DECLARE_ALIGNED(uint32_t enc_keys[15*4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15*4], 16);

        if (!quiet_mode)
	        printf("AES-CBC Test (N jobs = %d):\n", num_jobs);
	for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("AES-CBC Test Case %zu key_len:%zu\n",
                               v->tcId, v->keySize);
#else
                        printf(".");
#endif
                }
                IMB_AES_KEYEXP_128(mb_mgr, v->key, enc_keys, dec_keys);

                if (test_aes_many(mb_mgr, enc_keys, dec_keys,
                                  (const void *) v->iv, (const void *) v->msg,
                                  (const void *) v->ct, v->msgSize / 8,
                                  IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH,
                                  cipher, 0, v->keySize / 8, num_jobs)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys,
                                  (const void *) v->iv, (const void *) v->ct,
                                  (const void *) v->msg, v->msgSize / 8,
                                  IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER,
                                  cipher, 0, v->keySize / 8, num_jobs)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys,
                                  (const void *) v->iv, (const void *) v->msg,
                                  (const void *) v->ct, v->msgSize / 8,
                                  IMB_DIR_ENCRYPT, IMB_ORDER_CIPHER_HASH,
                                  cipher, 1, v->keySize / 8, num_jobs)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys,
                                  (const void *) v->iv, (const void *) v->ct,
                                  (const void *) v->msg, v->msgSize / 8,
                                  IMB_DIR_DECRYPT, IMB_ORDER_HASH_CIPHER,
                                  cipher, 1, v->keySize / 8, num_jobs)) {
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
aes_cbcs_test(struct IMB_MGR *mb_mgr)
{
        const int num_jobs_tab[] = {
                1, 3, 4, 5, 7, 8, 9, 15, 16, 17
        };
        unsigned i;
        int errors = 0;
        struct test_suite_context ctx;

        test_suite_start(&ctx, "AES-CBCS-128");
        for (i = 0; i < DIM(num_jobs_tab); i++)
                test_aes_vectors(mb_mgr, &ctx, IMB_CIPHER_CBCS_1_9,
                                 num_jobs_tab[i]);
        errors = test_suite_end(&ctx);

	return errors;
}
