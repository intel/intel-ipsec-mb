/**********************************************************************
  Copyright(c) 2024-2025 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "cipher_test.h"

#define SNOW5G_KEY_SIZE 32
#define SNOW5G_IV_SIZE  16
#define BUFFER_PAD_SIZE 16
#define PAD_PATTERN     0xa5

extern const struct cipher_test snow5g_nea4_test_json[];

int
snow5g_nea4_test(IMB_MGR *mgr);

static int
validate_job_result(const struct IMB_JOB *job, const uint8_t *expected, const uint8_t *buffer,
                    const uint8_t *padding, const size_t len)
{
        const int job_num = (const int) ((uintptr_t) job->user_data2);

        if (job->status != IMB_STATUS_COMPLETED) {
                printf("Job %d error: status=%d\n", job_num, job->status);
                return 0;
        }
        if (memcmp(expected, buffer + BUFFER_PAD_SIZE, len) != 0) {
                printf("Job %d: output mismatch\n", job_num);
                return 0;
        }
        if (memcmp(padding, buffer, BUFFER_PAD_SIZE) != 0 ||
            memcmp(padding, buffer + BUFFER_PAD_SIZE + len, BUFFER_PAD_SIZE) != 0) {
                printf("Job %d: buffer overflow detected\n", job_num);
                return 0;
        }
        return 1;
}

static void
configure_job(struct IMB_JOB *job, const void *key, const void *iv, size_t len)
{
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_SNOW5G_NEA4;
        job->hash_alg = IMB_AUTH_NULL;
        job->key_len_in_bytes = SNOW5G_KEY_SIZE;
        job->iv_len_in_bytes = SNOW5G_IV_SIZE;
        job->cipher_start_src_offset_in_bytes = 0;
        job->enc_keys = key;
        job->iv = iv;
        job->msg_len_to_cipher_in_bytes = len;
}

static int
run_snow5g_jobs(IMB_MGR *mgr, const void *key, const void *iv, const void *input,
                const void *expected, size_t len, const uint32_t num_jobs)
{
        struct IMB_JOB *job;
        uint8_t padding[BUFFER_PAD_SIZE];
        uint8_t **buffers;
        uint32_t jobs_rx = 0;

        buffers = malloc(num_jobs * sizeof(void *));
        if (buffers == NULL) {
                fprintf(stderr, "Memory allocation failed\n");
                return -1;
        }

        /* Initialize all pointers to NULL for safe cleanup */
        for (uint32_t i = 0; i < num_jobs; i++)
                buffers[i] = NULL;

        memset(padding, PAD_PATTERN, BUFFER_PAD_SIZE);

        /* Allocate output buffers with padding */
        for (uint32_t i = 0; i < num_jobs; i++) {
                buffers[i] = malloc(len + (BUFFER_PAD_SIZE * 2));
                if (buffers[i] == NULL)
                        goto cleanup;
                memset(buffers[i], PAD_PATTERN, len + (BUFFER_PAD_SIZE * 2));
        }

        /* Flush scheduler before submitting new jobs */
        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        /* Submit jobs */
        for (uint32_t i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mgr);
                job->src = input;
                job->dst = buffers[i] + BUFFER_PAD_SIZE;
                job->user_data = buffers[i];
                job->user_data2 = (void *) ((uintptr_t) i);
                configure_job(job, key, iv, len);

                job = IMB_SUBMIT_JOB(mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (!validate_job_result(job, expected, job->user_data, padding, len))
                                goto cleanup;
                } else if (imb_get_errno(mgr) != 0) {
                        printf("Error: %s\n", imb_get_strerror(imb_get_errno(mgr)));
                        goto cleanup;
                }
        }

        /* Flush remaining jobs */
        while ((job = IMB_FLUSH_JOB(mgr)) != NULL) {
                if (imb_get_errno(mgr) != 0) {
                        printf("Error: %s\n", imb_get_strerror(imb_get_errno(mgr)));
                        goto cleanup;
                }
                jobs_rx++;
                if (!validate_job_result(job, expected, job->user_data, padding, len))
                        goto cleanup;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto cleanup;
        }

        /* Final flush to clear any remaining state */
        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        for (uint32_t i = 0; i < num_jobs; i++)
                free(buffers[i]);
        free(buffers);
        return 0;

cleanup:
        /* Final flush to clear any remaining state */
        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        for (uint32_t i = 0; i < num_jobs; i++)
                free(buffers[i]);
        free(buffers);
        return -1;
}

static void
test_vectors(IMB_MGR *mgr, struct test_suite_context *ctx, const struct cipher_test *vectors,
             const int num_jobs)
{
        for (; vectors->msg != NULL; vectors++) {
                const size_t len = vectors->msgSize / CHAR_BIT;

#ifdef DEBUG
                if (!quiet_mode)
                        printf("Vector %zu  KeySize:%zu IVSize:%zu MsgSize:%zu\n", vectors->tcId,
                               vectors->keySize, vectors->ivSize, vectors->msgSize);
#endif

                if (run_snow5g_jobs(mgr, vectors->key, vectors->iv, vectors->msg, vectors->ct, len,
                                    num_jobs)) {
                        printf("Error #%zu encrypt, jobs: %i\n", vectors->tcId, num_jobs);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
}

int
snow5g_nea4_test(IMB_MGR *mgr)
{
        struct test_suite_context ctx;

        test_suite_start(&ctx, "SNOW5G-NEA4");

        for (uint32_t i = 0; i < test_num_jobs_size; i++)
                test_vectors(mgr, &ctx, snow5g_nea4_test_json, test_num_jobs[i]);

        return test_suite_end(&ctx);
}
