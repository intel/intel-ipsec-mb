/*****************************************************************************
 Copyright (c) 2017-2023, Intel Corporation

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
#include "aead_test.h"

int ccm_test(struct IMB_MGR *mb_mgr);

extern const struct aead_test ccm_128_test_json[];
extern const struct aead_test ccm_256_test_json[];

static int
ccm_job_ok(const struct aead_test *vec,
           const struct IMB_JOB *job,
           const uint8_t *target,
           const uint8_t *padding,
           const uint8_t *auth,
           const size_t sizeof_padding,
           const int dir,
           const int in_place)
{
        if (job->status != IMB_STATUS_COMPLETED) {
                printf("%d Error status:%d", __LINE__, job->status);
                return 0;
        }

        /* cipher checks */
        if (in_place) {
                if (dir == IMB_DIR_ENCRYPT) {
                        if (memcmp((const void *) vec->ct, target + sizeof_padding,
                            vec->msgSize / 8)) {
                                printf("cipher mismatched\n");
                                hexdump(stderr, "Received", target + sizeof_padding,
                                        vec->msgSize / 8);
                                hexdump(stderr, "Expected", (const void *) vec->ct,
                                        vec->msgSize / 8);
                                return 0;
                        }
                } else {
                        if (memcmp((const void *) vec->msg, target + sizeof_padding,
                                   vec->msgSize / 8)) {
                                printf("cipher mismatched\n");
                                hexdump(stderr, "Received", target + sizeof_padding,
                                        vec->msgSize / 8);
                                hexdump(stderr, "Expected", (const void *) vec->msg,
                                        vec->msgSize / 8);
                                return 0;
                        }
                }
        } else { /* out-of-place */
                if (dir == IMB_DIR_ENCRYPT) {
                        if (memcmp(vec->ct + vec->aadSize / 8, target + sizeof_padding,
                                   vec->msgSize / 8 - vec->aadSize / 8)) {
                                printf("cipher mismatched\n");
                                hexdump(stderr, "Received", target + sizeof_padding,
                                        vec->msgSize / 8 - vec->aadSize / 8);
                                hexdump(stderr, "Expected", vec->ct + vec->aadSize / 8,
                                        vec->msgSize / 8 - vec->aadSize / 8);
                                return 0;
                        }
                } else {
                        if (memcmp(vec->msg + vec->aadSize / 8, target + sizeof_padding,
                                   vec->msgSize / 8 - vec->aadSize / 8)) {
                                printf("cipher mismatched\n");
                                hexdump(stderr, "Received", target + sizeof_padding,
                                        vec->msgSize / 8 - vec->aadSize / 8);
                                hexdump(stderr, "Expected", vec->msg + vec->aadSize,
                                        vec->msgSize / 8 - vec->aadSize / 8);
                                return 0;
                        }
                }
        }

        if (memcmp(padding, target, sizeof_padding)) {
                printf("cipher overwrite head\n");
                hexdump(stderr, "Target", target, sizeof_padding);
                return 0;
        }

        if (in_place) {
                if (memcmp(padding, target + sizeof_padding + vec->msgSize / 8, sizeof_padding)) {
                        printf("cipher overwrite tail\n");
                        hexdump(stderr, "Target",
                                target + sizeof_padding + vec->msgSize / 8, sizeof_padding);
                        return 0;
                }
        } else {
                if (memcmp(padding, target + sizeof_padding + vec->msgSize / 8 - vec->aadSize / 8,
                           sizeof_padding)) {
                        printf("cipher overwrite tail\n");
                        hexdump(stderr, "Target", target + sizeof_padding + vec->msgSize / 8
                                - vec->aadSize / 8,
                                sizeof_padding);
                        return 0;
                }
        }

        /* hash checks */
        if (memcmp(padding, &auth[sizeof_padding + vec->tagSize / 8],
                   sizeof_padding)) {
                printf("hash overwrite tail\n");
                hexdump(stderr, "Target", &auth[sizeof_padding + vec->tagSize / 8],
                        sizeof_padding);
                return 0;
        }

        if (memcmp(padding, &auth[0], sizeof_padding)) {
                printf("hash overwrite head\n");
                hexdump(stderr, "Target", &auth[0], sizeof_padding);
                return 0;
        }

        if (memcmp(vec->ct + vec->msgSize / 8, &auth[sizeof_padding],
                   vec->tagSize / 8)) {
                printf("hash mismatched\n");
                hexdump(stderr, "Received", &auth[sizeof_padding], vec->tagSize / 8);
                hexdump(stderr, "Expected", vec->ct + vec->msgSize / 8,
                        vec->tagSize / 8);
                return 0;
        }
        return 1;
}

static int
test_ccm(struct IMB_MGR *mb_mgr,
         const struct aead_test *vec,
         const int dir, const int in_place,
         const int num_jobs,
         const uint64_t key_length)
{
        DECLARE_ALIGNED(uint32_t expkey[4*15], 16);
        DECLARE_ALIGNED(uint32_t dust[4*15], 16);
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        int i = 0, jobs_rx = 0, ret = -1;
        const int order = (dir == IMB_DIR_ENCRYPT) ? IMB_ORDER_HASH_CIPHER : IMB_ORDER_CIPHER_HASH;

        if (targets == NULL || auths == NULL) {
		fprintf(stderr, "Can't allocate buffer memory\n");
		goto end2;
        }

        memset(padding, -1, sizeof(padding));
        memset(targets, 0, num_jobs * sizeof(void *));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(vec->msgSize / 8 + (sizeof(padding) * 2));
                auths[i] = malloc(16 + (sizeof(padding) * 2));
                if (targets[i] == NULL || auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }

                memset(targets[i], -1, vec->msgSize / 8 + (sizeof(padding) * 2));
                memset(auths[i], -1, 16 + (sizeof(padding) * 2));

                if (in_place) {
                        if (dir == IMB_DIR_ENCRYPT)
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->msg,
                                       vec->msgSize / 8);
                        else
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->ct,
                                       vec->msgSize / 8);
                }
        }

        if (key_length == 16)
                IMB_AES_KEYEXP_128(mb_mgr, vec->key, expkey, dust);
        else
                IMB_AES_KEYEXP_256(mb_mgr, vec->key, expkey, dust);


        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = dir;
                job->chain_order = order;
                if (in_place) {
                        job->dst =
                                targets[i] + sizeof(padding) + vec->aadSize / 8;
                        job->src = targets[i] + sizeof(padding);
                } else {
                        if (dir == IMB_DIR_ENCRYPT) {
                                job->dst = targets[i] + sizeof(padding);
                                job->src = (const void *) vec->msg;
                        } else {
                                job->dst = targets[i] + sizeof(padding);
                                job->src = (const void *) vec->ct;
                        }
                }
                job->cipher_mode = IMB_CIPHER_CCM;
                job->enc_keys = expkey;
                job->dec_keys = expkey;
                job->key_len_in_bytes = key_length;
                job->iv = (const void *) vec->iv;
                job->iv_len_in_bytes = vec->ivSize / 8;
                job->cipher_start_src_offset_in_bytes = vec->aadSize / 8;
                job->msg_len_to_cipher_in_bytes =
                        vec->msgSize / 8 - vec->aadSize / 8;

                job->hash_alg = IMB_AUTH_AES_CCM;
                job->hash_start_src_offset_in_bytes = vec->aadSize / 8;
                job->msg_len_to_hash_in_bytes =
                        vec->msgSize / 8 - vec->aadSize / 8;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;

                job->u.CCM.aad_len_in_bytes = vec->aadSize / 8;
                job->u.CCM.aad = job->src;

                job->user_data = targets[i];
                job->user_data2 = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (num_jobs < 4) {
                                printf("%d Unexpected return from submit_job\n", __LINE__);
                                goto end;
                        }
                        if (!ccm_job_ok(vec, job, job->user_data, padding,
                                        job->user_data2, sizeof(padding),
                                        dir, in_place))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;

                if (!ccm_job_ok(vec, job, job->user_data, padding, job->user_data2,
                                sizeof(padding), dir, in_place))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

 end:
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                if (targets[i] != NULL)
                        free(targets[i]);
                if (auths[i] != NULL)
                        free(auths[i]);
        }

 end2:
        if (targets != NULL)
                free(targets);

        if (auths != NULL)
                free(auths);

        return ret;
}

static void
test_ccm_128_std_vectors(struct IMB_MGR *mb_mgr,
                         struct test_suite_context *ctx,
                         const int num_jobs)
{
	const struct aead_test *v = ccm_128_test_json;

        if (!quiet_mode)
	        printf("AES-CCM-128 standard test vectors (N jobs = %d):\n", num_jobs);
	for (; v->msg != NULL; v++) {

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu NONCELen:%zu PktLen:%zu AADLen:%zu "
                               "Digestlen:%zu\n", v->tcId, v->ivSize / 8, v->msgSize / 8,
                               v->aadSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_ENCRYPT, 1, num_jobs, IMB_KEY_128_BYTES)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_DECRYPT, 1, num_jobs, IMB_KEY_128_BYTES)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_ENCRYPT, 0, num_jobs, IMB_KEY_128_BYTES)) {
                        printf("error #%zu encrypt out-of-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_DECRYPT, 0, num_jobs, IMB_KEY_128_BYTES)) {
                        printf("error #%zu decrypt out-of-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
	}
        if (!quiet_mode)
                printf("\n");
}

static void
test_ccm_256_std_vectors(struct IMB_MGR *mb_mgr,
                         struct test_suite_context *ctx,
                         const int num_jobs)
{
        const struct aead_test *v = ccm_256_test_json;

        if (!quiet_mode)
	        printf("AES-CCM-256 standard test vectors (N jobs = %d):\n",
                       num_jobs);
	for (; v->msg != NULL; v++) {

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu NONCELen:%zu PktLen:%zu AADLen:%zu "
                               "Digestlen:%zu\n", v->tcId, v->ivSize / 8, v->msgSize / 8,
                               v->aadSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_ENCRYPT, 1, num_jobs, IMB_KEY_256_BYTES)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_DECRYPT, 1, num_jobs, IMB_KEY_256_BYTES)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_ENCRYPT, 0, num_jobs, IMB_KEY_256_BYTES)) {
                        printf("error #%zu encrypt out-of-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_DECRYPT, 0, num_jobs, IMB_KEY_256_BYTES)) {
                        printf("error #%zu decrypt out-of-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
	}
        if (!quiet_mode)
                printf("\n");
}


int
ccm_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctx;
        int errors = 0;

        /* AES-CCM-128 tests */
        test_suite_start(&ctx, "AES-CCM-128");
        for (int i = 0; i <= 19; i++)
                test_ccm_128_std_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

        /* AES-CCM-256 tests */
        test_suite_start(&ctx, "AES-CCM-256");
        for (int i = 0; i <= 19; i++)
                test_ccm_256_std_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

	return errors;
}
