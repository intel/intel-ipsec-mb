/*****************************************************************************
 Copyright (c) 2018-2022, Intel Corporation

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

int hmac_sha1_test(struct IMB_MGR *mb_mgr);

#define DIGEST96_SIZE 12
#define MAX_BURST_JOBS 32

extern const struct mac_test hmac_sha1_test_kat_json[];
static int
hmac_sha1_job_ok(const struct mac_test *vec,
                 const struct IMB_JOB *job,
                 const uint8_t *auth,
                 const uint8_t *padding,
                 const size_t sizeof_padding)
{
        if (job->status != IMB_STATUS_COMPLETED) {
                printf("line:%d job error status:%d ", __LINE__, job->status);
                return 0;
        }

        /* hash checks */
        if (memcmp(padding, &auth[sizeof_padding + vec->tagSize],
                   sizeof_padding)) {
                printf("hash overwrite tail\n");
                hexdump(stderr, "Target",
                        &auth[sizeof_padding + vec->tagSize],
                        sizeof_padding);
                return 0;
        }

        if (memcmp(padding, &auth[0], sizeof_padding)) {
                printf("hash overwrite head\n");
                hexdump(stderr, "Target", &auth[0], sizeof_padding);
                return 0;
        }

        if (memcmp(vec->tag, &auth[sizeof_padding],
                   vec->tagSize)) {
                printf("hash mismatched\n");
                hexdump(stderr, "Received", &auth[sizeof_padding],
                        vec->tagSize);
                hexdump(stderr, "Expected", vec->tag,
                        vec->tagSize);
                return 0;
        }
        return 1;
}

static int
test_hmac_sha1(struct IMB_MGR *mb_mgr,
               const struct mac_test *vec,
               const uint32_t num_jobs)
{
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        uint32_t i = 0, jobs_rx = 0;
        int ret = -1;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA1_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA1_DIGEST_SIZE_IN_BYTES], 16);

        if (auths == NULL) {
		fprintf(stderr, "Can't allocate buffer memory\n");
		goto end2;
        }

        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                const size_t alloc_len =
                        vec->tagSize + (sizeof(padding) * 2);

                auths[i] = malloc(alloc_len);
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }
                memset(auths[i], -1, alloc_len);
        }

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA_1,
                           vec->key, vec->keySize, ipad_hash, opad_hash);

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->enc_keys = NULL;
                job->dec_keys = NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->dst = NULL;
                job->key_len_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize;
                job->iv = NULL;
                job->iv_len_in_bytes = 0;
                job->src = (const void *) vec->msg;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
                job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_HMAC_SHA_1;

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        /*
                         * SHANI HMAC-SHA implementation can return a completed
                         * job after 2nd submission
                         */
                        if (num_jobs < 2) {
                                printf("%d Unexpected return from submit_job\n",
                                       __LINE__);
                                goto end;
                        }
                        if (!hmac_sha1_job_ok(vec, job, job->user_data,
                                              padding, sizeof(padding)))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (!hmac_sha1_job_ok(vec, job, job->user_data,
                                      padding, sizeof(padding)))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

 end:
        /* empty the manager before next tests */
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

static int
test_hmac_sha1_burst(struct IMB_MGR *mb_mgr,
                     const struct mac_test *vec,
                     const uint32_t num_jobs)
{
        struct IMB_JOB *job, *jobs[MAX_BURST_JOBS] = {NULL};
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        uint32_t i = 0, jobs_rx = 0;
        int ret = -1, err;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA1_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA1_DIGEST_SIZE_IN_BYTES], 16);
        uint32_t completed_jobs = 0;

        if (auths == NULL) {
		fprintf(stderr, "Can't allocate buffer memory\n");
		goto end2;
        }

        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                const size_t alloc_len =
                        vec->tagSize + (sizeof(padding) * 2);

                auths[i] = malloc(alloc_len);
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }
                memset(auths[i], -1, alloc_len);
        }

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA_1,
                           vec->key, vec->keySize, ipad_hash, opad_hash);

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];
                job->enc_keys = NULL;
                job->dec_keys = NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->dst = NULL;
                job->key_len_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize;
                job->iv = NULL;
                job->iv_len_in_bytes = 0;
                job->src = (const void *) vec->msg;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
                job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_HMAC_SHA_1;

                job->user_data = auths[i];

                imb_set_cipher_suite_id(mb_mgr, job);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        err = imb_get_errno(mb_mgr);

        if (err != 0) {
                printf("submit_burst error %d : '%s'\n", err,
                       imb_get_strerror(err));
                goto end;
        }

check_burst_jobs:
        for (i = 0; i < completed_jobs; i++) {
                job = jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %u status not complete!\n", i+1);
                        goto end;
                }

                if (!hmac_sha1_job_ok(vec, job, job->user_data,
                                      padding, sizeof(padding)))
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                completed_jobs = IMB_FLUSH_BURST(mb_mgr,
                                                 num_jobs - completed_jobs,
                                                 jobs);
                if (completed_jobs == 0) {
                        printf("Expected %u jobs, received %u\n",
                               num_jobs, jobs_rx);
                        goto end;
                }
                goto check_burst_jobs;
        }
        ret = 0;

 end:
        for (i = 0; i < num_jobs; i++) {
                if (auths[i] != NULL)
                        free(auths[i]);
        }

 end2:
        if (auths != NULL)
                free(auths);

        return ret;
}

static int
test_hmac_sha1_hash_burst(struct IMB_MGR *mb_mgr,
                          const struct mac_test *vec,
                          const uint32_t num_jobs)
{
        struct IMB_JOB *job, jobs[MAX_BURST_JOBS] = {0};
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        uint32_t i = 0, jobs_rx = 0;
        int ret = -1;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA1_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA1_DIGEST_SIZE_IN_BYTES], 16);
        uint32_t completed_jobs = 0;

        if (auths == NULL) {
		fprintf(stderr, "Can't allocate buffer memory\n");
		goto end2;
        }

        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                const size_t alloc_len =
                        vec->tagSize + (sizeof(padding) * 2);

                auths[i] = malloc(alloc_len);
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }
                memset(auths[i], -1, alloc_len);
        }

        imb_hmac_ipad_opad(mb_mgr, IMB_AUTH_HMAC_SHA_1,
                           vec->key, vec->keySize, ipad_hash, opad_hash);

        for (i = 0; i < num_jobs; i++) {
                job = &jobs[i];
                job->enc_keys = NULL;
                job->dec_keys = NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->dst = NULL;
                job->key_len_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize;
                job->iv = NULL;
                job->iv_len_in_bytes = 0;
                job->src = (const void *) vec->msg;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
                job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_HMAC_SHA_1;

                job->user_data = auths[i];

        }

        completed_jobs = IMB_SUBMIT_HASH_BURST(mb_mgr, jobs, num_jobs,
                                               IMB_AUTH_HMAC_SHA_1);
        if (completed_jobs != num_jobs) {
                int err = imb_get_errno(mb_mgr);

                if (err != 0) {
                        printf("submit_burst error %d : '%s'\n", err,
                               imb_get_strerror(err));
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
                        printf("job %u status not complete!\n", i+1);
                        goto end;
                }

                if (!hmac_sha1_job_ok(vec, job, job->user_data,
                                      padding, sizeof(padding)))
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

 end:
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
test_hmac_sha1_std_vectors(struct IMB_MGR *mb_mgr,
                           const uint32_t num_jobs,
                           struct test_suite_context *ts)
{
        const struct mac_test *v = hmac_sha1_test_kat_json;
	int vectors_cnt;
        /* Calculate vectors_cnt */
        for (vectors_cnt = 0; v->msg != NULL; vectors_cnt++, v++)
                ;
        v -= vectors_cnt;
	printf("HMAC-SHA1 standard test vectors (N jobs = %u):\n", num_jobs);
	while (v->msg != NULL) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("[%lu/%lu] RFC2202 Test Case %lu keySize:%lu "
                               "msgSize:%lu tagSize:%lu\n",
                               v->tcId, vectors_cnt,
                               v->tcId,
                               v->keySize,
                               v->msgSize / 8,
                               v->tagSize);
#else
                        printf(".");
#endif
                }

                if (test_hmac_sha1(mb_mgr, v, num_jobs)) {
                        printf("error #%lu\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else {
                        test_suite_update(ts, 1, 0);
                }
                if (test_hmac_sha1_burst(mb_mgr, v,
                                         num_jobs)) {
                        printf("error #%lu - burst API\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else {
                        test_suite_update(ts, 1, 0);
                }
                if (test_hmac_sha1_hash_burst(mb_mgr, v,
                                              num_jobs)) {
                        printf("error #%lu - hash-only burst API\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else {
                        test_suite_update(ts, 1, 0);
                }

                v++;
	}
        if (!quiet_mode)
                printf("\n");
}

int
hmac_sha1_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        int errors = 0;
        uint32_t num_jobs;

        test_suite_start(&ts, "HMAC-SHA1");
        for (num_jobs = 1; num_jobs <= MAX_BURST_JOBS; num_jobs++)
                test_hmac_sha1_std_vectors(mb_mgr, num_jobs, &ts);
        errors = test_suite_end(&ts);

	return errors;
}
