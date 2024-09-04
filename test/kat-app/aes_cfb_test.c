/*****************************************************************************
 Copyright (c) 2024, Intel Corporation

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

#define BYTE_ROUND_UP(x) ((x + 7) / 8)
#define PADDING_SIZE     16
#define IV_SIZE          16

int
aes_cfb_test(struct IMB_MGR *);

extern const struct cipher_test aes_cfb_test_json[];

static int
aes_job_ok(const struct IMB_JOB *job, const uint8_t *out_text, const uint8_t *target,
           const uint8_t *padding, const unsigned text_len)
{
        const int num = (const int) ((uint64_t) job->user_data2);

        if (job->status != IMB_STATUS_COMPLETED) {
                printf("%d error status:%d, job %d", __LINE__, job->status, num);
                return 0;
        }
        if (memcmp(out_text, target + PADDING_SIZE, text_len)) {
                printf("%d mismatched\n", num);
                return 0;
        }
        if (memcmp(padding, target, PADDING_SIZE)) {
                printf("%d overwrite head\n", num);
                return 0;
        }
        if (memcmp(padding, target + PADDING_SIZE + text_len, PADDING_SIZE)) {
                printf("%d overwrite tail\n", num);
                return 0;
        }
        return 1;
}

static void
test_aes_cfb_setup_job(struct IMB_JOB *job, const void *enc_keys, unsigned key_len, const void *iv,
                       unsigned text_byte_len, const IMB_CIPHER_DIRECTION dir)
{
        if (dir == IMB_DIR_ENCRYPT)
                job->chain_order = IMB_ORDER_CIPHER_HASH;
        else
                job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_direction = dir;
        job->cipher_mode = IMB_CIPHER_CFB;
        job->key_len_in_bytes = key_len;

        job->enc_keys = enc_keys;
        job->dec_keys = enc_keys;
        job->iv = iv;
        job->iv_len_in_bytes = IV_SIZE;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = text_byte_len;
        job->hash_alg = IMB_AUTH_NULL;
}

static int
test_aes_cfb(struct IMB_MGR *mb_mgr, const void *enc_keys, unsigned key_len, const void *iv,
             const uint8_t *in_text, const uint8_t *out_text, unsigned text_byte_len,
             const IMB_CIPHER_DIRECTION dir, const int in_place, const uint32_t num_jobs)
{
        struct IMB_JOB *job;
        uint8_t padding[PADDING_SIZE];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        uint32_t err, jobs_rx = 0, ret = -1;

        if (targets == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end;
        }

        memset(targets, -1, num_jobs * sizeof(void *));
        memset(padding, -1, PADDING_SIZE);

        for (uint32_t i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_byte_len + (PADDING_SIZE * 2));
                if (targets[i] == NULL)
                        goto end_alloc;
                memset(targets[i], -1, text_byte_len + (PADDING_SIZE * 2));
                if (in_place) {
                        /* copy input text to the allocated buffer */
                        memcpy(targets[i] + PADDING_SIZE, in_text, text_byte_len);
                }
        }

        /* flush the scheduler */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (uint32_t i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (!in_place) {
                        job->src = in_text;
                } else {
                        job->src = targets[i] + PADDING_SIZE;
                }
                job->dst = targets[i] + sizeof(padding);
                job->user_data = targets[i];
                job->user_data2 = (void *) ((uint64_t) i);
                test_aes_cfb_setup_job(job, enc_keys, key_len, iv, text_byte_len, dir);

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
                        if (!aes_job_ok(job, out_text, job->user_data, padding, text_byte_len))
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
                if (!aes_job_ok(job, out_text, job->user_data, padding, text_byte_len))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
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
                for (uint32_t i = 0; i < num_jobs; i++)
                        free(targets[i]);
                free(targets);
        }

        return ret;
}

static int
test_aes_cfb_burst(struct IMB_MGR *mb_mgr, const void *enc_keys, unsigned key_len, const void *iv,
                   const uint8_t *in_text, const uint8_t *out_text, unsigned text_byte_len,
                   const IMB_CIPHER_DIRECTION dir, const int in_place, const uint32_t num_jobs)
{
        struct IMB_JOB *job, *jobs[IMB_MAX_BURST_SIZE] = { NULL };
        uint8_t padding[PADDING_SIZE];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        uint32_t completed_jobs, jobs_rx = 0, ret = -1;

        if (targets == NULL)
                goto end_alloc;

        memset(targets, 0, num_jobs * sizeof(void *));
        memset(padding, -1, PADDING_SIZE);

        for (uint32_t i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_byte_len + (PADDING_SIZE * 2));
                if (targets[i] == NULL)
                        goto end_alloc;
                memset(targets[i], -1, text_byte_len + (PADDING_SIZE * 2));
                if (in_place) {
                        /* copy input text to the allocated buffer */
                        memcpy(targets[i] + PADDING_SIZE, in_text, text_byte_len);
                }
        }

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < (uint32_t) num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (uint32_t i = 0; i < num_jobs; i++) {
                job = jobs[i];
                if (!in_place) {
                        job->src = in_text;
                } else {
                        job->src = targets[i] + PADDING_SIZE;
                }
                job->dst = targets[i] + sizeof(padding);
                job->user_data = targets[i];
                job->user_data2 = (void *) ((uint64_t) i);
                test_aes_cfb_setup_job(job, enc_keys, key_len, iv, text_byte_len, dir);
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
        for (uint32_t i = 0; i < completed_jobs; i++) {
                job = jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %d status not complete!\n", i + 1);
                        goto end;
                }

                if (!aes_job_ok(job, out_text, job->user_data, padding, text_byte_len))
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs - completed_jobs, jobs);
                if (completed_jobs == 0) {
                        printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                        goto end;
                }
                goto check_burst_jobs;
        }
        ret = 0;

end:

end_alloc:
        if (targets != NULL) {
                for (uint32_t i = 0; i < num_jobs; i++)
                        free(targets[i]);
                free(targets);
        }

        return ret;
}

static int
test_aes_cfb_cipher_burst(struct IMB_MGR *mb_mgr, const void *enc_keys, unsigned key_len,
                          const void *iv, const uint8_t *in_text, const uint8_t *out_text,
                          unsigned text_byte_len, const IMB_CIPHER_DIRECTION dir,
                          const int in_place, const uint32_t num_jobs)
{
        struct IMB_JOB *job, jobs[IMB_MAX_BURST_SIZE];
        uint8_t padding[16];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        uint32_t i, completed_jobs, jobs_rx = 0, ret = -1;

        if (targets == NULL)
                goto end_alloc;

        memset(targets, 0, num_jobs * sizeof(void *));
        memset(padding, -1, PADDING_SIZE);

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_byte_len + (PADDING_SIZE * 2));
                if (targets[i] == NULL)
                        goto end_alloc;
                memset(targets[i], -1, text_byte_len + (PADDING_SIZE * 2));
                if (in_place) {
                        /* copy input text to the allocated buffer */
                        memcpy(targets[i] + PADDING_SIZE, in_text, text_byte_len);
                }
        }

        for (i = 0; i < num_jobs; i++) {
                job = &jobs[i];
                if (!in_place) {
                        job->src = in_text;
                } else {
                        job->src = targets[i] + PADDING_SIZE;
                }
                job->dst = targets[i] + PADDING_SIZE;
                job->user_data = targets[i];
                job->user_data2 = (void *) ((uint64_t) i);
                test_aes_cfb_setup_job(job, enc_keys, key_len, iv, text_byte_len, dir);
        }

        completed_jobs =
                IMB_SUBMIT_CIPHER_BURST(mb_mgr, jobs, num_jobs, IMB_CIPHER_CFB, dir, key_len);
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

                if (!aes_job_ok(job, out_text, job->user_data, padding, text_byte_len))
                        goto end;
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

        int errors = 0;
        struct test_suite_context ctx128;
        struct test_suite_context ctx192;
        struct test_suite_context ctx256;

        /* Standard aes_cfb vectors */
        test_suite_start(&ctx128, "AES-CFB-128");
        test_suite_start(&ctx192, "AES-CFB-192");
        test_suite_start(&ctx256, "AES-CFB-256");

        for (i = 0; i < test_num_jobs_size; i++)
                test_aes_cfb_vectors(mb_mgr, &ctx128, &ctx192, &ctx256, aes_cfb_test_json,
                                     test_num_jobs[i]);

        errors += test_suite_end(&ctx128);
        errors += test_suite_end(&ctx192);
        errors += test_suite_end(&ctx256);

        return errors;
}