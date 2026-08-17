/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

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
#include "mac_test.h"
#include "hmac_common.h"

/* upper bound covering every HMAC digest size exercised by the KAT app */
#define HMAC_MAX_DIGEST_SIZE IMB_SHA512_DIGEST_SIZE_IN_BYTES

int
hmac_auth_bufs_alloc(struct hmac_auth_bufs *b, const uint32_t num_jobs, const size_t tag_size)
{
        uint32_t i;

        memset(b, 0, sizeof(*b));
        b->num_jobs = num_jobs;
        b->tag_size = tag_size;

        b->auths = malloc(num_jobs * sizeof(void *));
        if (b->auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                return -1;
        }
        memset(b->auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                const size_t alloc_len = tag_size;

                b->auths[i] = malloc(alloc_len);
                if (b->auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        hmac_auth_bufs_free(b);
                        return -1;
                }
                memset(b->auths[i], -1, alloc_len);
        }

        return 0;
}

void
hmac_auth_bufs_free(struct hmac_auth_bufs *b)
{
        uint32_t i;

        if (b->auths == NULL)
                return;

        for (i = 0; i < b->num_jobs; i++)
                free(b->auths[i]);

        free(b->auths);
        b->auths = NULL;
}

int
hmac_job_ok(const struct mac_test *vec, const struct IMB_JOB *job, const uint8_t *auth,
            const size_t tag_size)
{
        if (job->status != IMB_STATUS_COMPLETED) {
                printf("line:%d job error status:%d ", __LINE__, job->status);
                return 0;
        }

        if (memcmp(vec->tag, auth, tag_size)) {
                printf("hash mismatched\n");
                hexdump(stderr, "Received", auth, tag_size);
                hexdump(stderr, "Expected", vec->tag, tag_size);
                return 0;
        }
        return 1;
}

void
hmac_job_fill(struct IMB_JOB *job, const struct mac_test *vec, const struct hmac_alg_desc *desc,
              uint8_t *auth_buf, const size_t tag_size, const uint8_t *ipad_hash,
              const uint8_t *opad_hash)
{
        job->enc_keys = NULL;
        job->dec_keys = NULL;
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->dst = NULL;
        job->key_len_in_bytes = 0;
        job->auth_tag_output = auth_buf;
        job->auth_tag_output_len_in_bytes = tag_size;
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
        job->hash_alg = desc->hash_alg;

        job->user_data = auth_buf;
}

int
hmac_test_submit_flush(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
                       const size_t tag_size, const struct hmac_alg_desc *desc)
{
        struct hmac_auth_bufs bufs;
        struct IMB_JOB *job;
        uint32_t i, jobs_rx = 0;
        int ret = -1;
        DECLARE_ALIGNED(uint8_t ipad_hash[HMAC_MAX_DIGEST_SIZE], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[HMAC_MAX_DIGEST_SIZE], 16);

        if (hmac_auth_bufs_alloc(&bufs, num_jobs, tag_size) < 0)
                goto end;

        imb_hmac_ipad_opad(mb_mgr, desc->hash_alg, vec->key, vec->keySize / 8, ipad_hash,
                           opad_hash);

        /* empty the manager */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                hmac_job_fill(job, vec, desc, bufs.auths[i], tag_size, ipad_hash, opad_hash);

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (num_jobs < desc->min_jobs_for_early_completion) {
                                printf("%d Unexpected return from submit_job\n", __LINE__);
                                goto end;
                        }
                        if (!hmac_job_ok(vec, job, job->user_data, tag_size))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (!hmac_job_ok(vec, job, job->user_data, tag_size))
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

        hmac_auth_bufs_free(&bufs);

        return ret;
}

int
hmac_test_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
                const size_t tag_size, const struct hmac_alg_desc *desc)
{
        struct hmac_auth_bufs bufs;
        struct IMB_JOB *job, *jobs[IMB_MAX_BURST_SIZE] = { NULL };
        uint32_t i, jobs_rx = 0, completed_jobs = 0;
        int ret = -1, err;
        DECLARE_ALIGNED(uint8_t ipad_hash[HMAC_MAX_DIGEST_SIZE], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[HMAC_MAX_DIGEST_SIZE], 16);

        if (hmac_auth_bufs_alloc(&bufs, num_jobs, tag_size) < 0)
                goto end;

        imb_hmac_ipad_opad(mb_mgr, desc->hash_alg, vec->key, vec->keySize / 8, ipad_hash,
                           opad_hash);

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];
                hmac_job_fill(job, vec, desc, bufs.auths[i], tag_size, ipad_hash, opad_hash);
                imb_set_session(mb_mgr, job);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        err = imb_get_errno(mb_mgr);

        if (err != 0) {
                printf("submit_burst error %d : '%s'\n", err, imb_get_strerror(err));
                goto end;
        }

check_burst_jobs:
        for (i = 0; i < completed_jobs; i++) {
                job = jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %u status not complete!\n", i + 1);
                        goto end;
                }

                if (!hmac_job_ok(vec, job, job->user_data, tag_size))
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
        hmac_auth_bufs_free(&bufs);

        return ret;
}

int
hmac_test_hash_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
                     const size_t tag_size, const struct hmac_alg_desc *desc)
{
        struct hmac_auth_bufs bufs;
        struct IMB_JOB *job, jobs[IMB_MAX_BURST_SIZE] = { 0 };
        uint32_t i, jobs_rx = 0, completed_jobs = 0;
        int ret = -1;
        DECLARE_ALIGNED(uint8_t ipad_hash[HMAC_MAX_DIGEST_SIZE], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[HMAC_MAX_DIGEST_SIZE], 16);

        if (hmac_auth_bufs_alloc(&bufs, num_jobs, tag_size) < 0)
                goto end;

        imb_hmac_ipad_opad(mb_mgr, desc->hash_alg, vec->key, vec->keySize / 8, ipad_hash,
                           opad_hash);

        for (i = 0; i < num_jobs; i++)
                hmac_job_fill(&jobs[i], vec, desc, bufs.auths[i], tag_size, ipad_hash, opad_hash);

        completed_jobs = IMB_SUBMIT_HASH_BURST(mb_mgr, jobs, num_jobs, desc->hash_alg);
        if (completed_jobs != num_jobs) {
                const int err = imb_get_errno(mb_mgr);

                if (err != 0)
                        printf("submit_burst error %d : '%s'\n", err, imb_get_strerror(err));
                else
                        printf("submit_burst error: not enough "
                               "jobs returned!\n");
                goto end;
        }

        for (i = 0; i < num_jobs; i++) {
                job = &jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %u status not complete!\n", i + 1);
                        goto end;
                }

                if (!hmac_job_ok(vec, job, job->user_data, tag_size))
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
        hmac_auth_bufs_free(&bufs);

        return ret;
}
