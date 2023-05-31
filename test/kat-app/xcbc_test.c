/*****************************************************************************
 Copyright (c) 2020-2022, Intel Corporation

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
#include "gcm_ctr_vectors_test.h"
#include "utils.h"
#include "mac_test.h"

int xcbc_test(struct IMB_MGR *mb_mgr);

extern const struct mac_test xcbc_test_json[];

static int
xcbc_job_ok(const struct mac_test *vec,
            const struct IMB_JOB *job,
            const uint8_t *auth,
            const uint8_t *padding,
            const size_t sizeof_padding)
{
        const size_t auth_len = job->auth_tag_output_len_in_bytes;

        if (job->status != IMB_STATUS_COMPLETED) {
                printf("%d Error status:%d", __LINE__, job->status);
                return 0;
        }

        /* hash checks */
        if (memcmp(padding, &auth[sizeof_padding + auth_len],
                   sizeof_padding)) {
                printf("hash overwrite tail\n");
                hexdump(stderr, "Target",
                        &auth[sizeof_padding + auth_len], sizeof_padding);
                return 0;
        }

        if (memcmp(padding, &auth[0], sizeof_padding)) {
                printf("hash overwrite head\n");
                hexdump(stderr, "Target", &auth[0], sizeof_padding);
                return 0;
        }

        if (memcmp((const void *) vec->tag, &auth[sizeof_padding], auth_len)) {
                printf("hash mismatched\n");
                hexdump(stderr, "Received", &auth[sizeof_padding],
                        auth_len);
                hexdump(stderr, "Expected", (const void *) vec->tag,
                        auth_len);
                return 0;
        }
        return 1;
}

static int
test_xcbc(struct IMB_MGR *mb_mgr,
          const struct mac_test *vec,
          const int dir,
          const int num_jobs)
{
        DECLARE_ALIGNED(uint32_t k1_exp[4*11], 16);
        uint8_t k2[16], k3[16];
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        int i = 0, jobs_rx = 0, ret = -1;

        if (auths == NULL) {
		fprintf(stderr, "Can't allocate buffer memory\n");
		goto end2;
        }

        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                auths[i] = malloc(16 + (sizeof(padding) * 2));
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }

                memset(auths[i], -1, 16 + (sizeof(padding) * 2));
        }

        IMB_AES_XCBC_KEYEXP(mb_mgr, (const void *) vec->key, k1_exp, k2, k3);

        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        /**
         * Submit all jobs then flush any outstanding jobs
         */
        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = dir;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_AES_XCBC;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->u.XCBC._k1_expanded = k1_exp;
                job->u.XCBC._k2 = k2;
                job->u.XCBC._k3 = k3;
                job->src = (const void *) vec->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (num_jobs < 4) {
                                printf("%d Unexpected return from submit_job\n",
                                       __LINE__);
                                goto end;
                        }
                        if (!xcbc_job_ok(vec, job, job->user_data, padding,
                                         sizeof(padding)))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;

                if (!xcbc_job_ok(vec, job, job->user_data, padding,
                                 sizeof(padding)))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }

        /**
         * Submit each job and flush immediately
         */
        for (i = 0; i < num_jobs; i++) {
                struct IMB_JOB *first_job = NULL;

                job = IMB_GET_NEXT_JOB(mb_mgr);
                first_job = job;

                job->cipher_direction = dir;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_AES_XCBC;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->u.XCBC._k1_expanded = k1_exp;
                job->u.XCBC._k2 = k2;
                job->u.XCBC._k3 = k3;
                job->src = (const void *) vec->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        printf("Received job, expected NULL\n");
                        goto end;
                }

                while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                        if (job != first_job) {
                                printf("Invalid return job received\n");
                                goto end;
                        }
                        if (!xcbc_job_ok(vec, job, job->user_data, padding,
                                         sizeof(padding)))
                                goto end;
                }
        }

        ret = 0;

 end:
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                if (auths[i] != NULL)
                        free(auths[i]);
        }

 end2:
        if (auths != NULL)
                free(auths);

        return ret;
}

static void
test_xcbc_std_vectors(struct IMB_MGR *mb_mgr,
                      struct test_suite_context *ctx,
                      const int num_jobs)
{
        const struct mac_test *v = xcbc_test_json;

        if (!quiet_mode)
	        printf("AES-XCBC-128 standard test vectors (N jobs = %d):\n", num_jobs);
	for (; v->msg != NULL; v++) {

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard XCBC-128 vector %zu Msg len: %zu, "
                               "Tag len:%zu\n",
                               v->tcId,
                               v->msgSize / 8,
                               v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_xcbc(mb_mgr, v,
                              IMB_DIR_ENCRYPT, num_jobs)) {
                        printf("error #%zu encrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_xcbc(mb_mgr, v,
                              IMB_DIR_DECRYPT, num_jobs)) {
                        printf("error #%zu decrypt\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

	}
        if (!quiet_mode)
                printf("\n");
}

int
xcbc_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctx;
        int i, errors;

        test_suite_start(&ctx, "AES-XCBC-128");
        /* AES-XCBC 128 with standard vectors */
        for (i = 1; i < 20; i++)
                test_xcbc_std_vectors(mb_mgr, &ctx, i);
        errors = test_suite_end(&ctx);

	return errors;
}
