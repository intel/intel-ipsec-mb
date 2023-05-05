/**********************************************************************
  Copyright(c) 2023 Intel Corporation All rights reserved.

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

#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>

#define NUM_BUFS IMB_MAX_JOBS
#define BURST_SIZE 32
#define BUF_SIZE 2048
#define KEY_SIZE 16
#define IV_SIZE 16
#define AAD_SIZE 12
#define DIGEST_SIZE 16
#define TOTAL_NUM_JOBS 10000UL

/*
 * Fill AES-128-GCM job to be submitted with IMB_SUBMIT_BURST
 */
static void
fill_job(IMB_JOB *job, const void *src_buf, void *dst_buf, const void *iv,
         const struct gcm_key_data *key, const void *aad, void *auth_tag)
{
        /* General parameters */
        job->src = src_buf;
        job->dst = dst_buf;
        job->chain_order = IMB_ORDER_CIPHER_HASH;

        /* Cipher parameters */
        job->cipher_mode = IMB_CIPHER_GCM;
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->enc_keys = key;
        job->dec_keys = key;
        job->key_len_in_bytes = KEY_SIZE;
        job->iv = iv;
        job->iv_len_in_bytes = IV_SIZE;
        job->msg_len_to_cipher_in_bytes = BUF_SIZE;
        job->cipher_start_src_offset_in_bytes = 0;

        /* Authentication parameters */
        job->hash_alg = IMB_AUTH_AES_GMAC;
        job->u.GCM.aad = aad;
        job->u.GCM.aad_len_in_bytes = AAD_SIZE;
        job->msg_len_to_hash_in_bytes = BUF_SIZE;
        job->hash_start_src_offset_in_bytes = 0;
        job->auth_tag_output = auth_tag;
        job->auth_tag_output_len_in_bytes = DIGEST_SIZE;
}

static int
allocate_array(void **array, const unsigned num_elems,
               const size_t elem_size)
{
        unsigned i;

        for (i = 0; i < num_elems; i++) {
                array[i] = malloc(elem_size);
                if (array[i] == NULL)
                        return -1;
        }

        return 0;
}

int main(void)
{
        unsigned i;
        IMB_MGR *mb_mgr = NULL;
        int exit_status = EXIT_FAILURE;

        /* Allocate buffers and authentication tags */
        void *src_bufs[NUM_BUFS];
        void *dst_bufs[NUM_BUFS];
        void *auth_tags[NUM_BUFS];

        memset(src_bufs, 0, sizeof(src_bufs));
        memset(dst_bufs, 0, sizeof(dst_bufs));
        memset(auth_tags, 0, sizeof(auth_tags));

        if (allocate_array(src_bufs, NUM_BUFS, BUF_SIZE) < 0) {
                printf("Could not allocate memory for source buffer\n");
                goto exit;
        }
        if (allocate_array(dst_bufs, NUM_BUFS, BUF_SIZE) < 0) {
                printf("Could not allocate memory for destination buffer\n");
                goto exit;
        }
        if (allocate_array(auth_tags, NUM_BUFS, DIGEST_SIZE) < 0) {
                printf("Could not allocate memory for authentication tag\n");
                goto exit;
        }

        /* IMB API: Allocate MB_MGR */
        mb_mgr = alloc_mb_mgr(0);

        if (mb_mgr == NULL) {
                printf("Could not allocate memory for IMB_MGR\n");
                goto exit;
        }

        /* IMB API: Initialize MB_MGR, detecting best implementation to use */
        init_mb_mgr_auto(mb_mgr, NULL);

        /* Prepare GCM keys (common for all buffers) */
        uint8_t key[KEY_SIZE];
	struct gcm_key_data gdata_key;

        /* IMB API: Expand AES keys and precompute GHASH keys for AES-GCM */
        IMB_AES128_GCM_PRE(mb_mgr, key, &gdata_key);

        /* Allocate memory for IV and AAD */
        uint8_t iv[BURST_SIZE][IV_SIZE];
        uint8_t aad[BURST_SIZE][AAD_SIZE];

        /* Prepare IMB_JOB's (one job per buffer) */
        IMB_JOB *jobs[BURST_SIZE];
        unsigned completed_jobs;
        unsigned total_jobs_rx = 0;
        unsigned n_jobs_left = TOTAL_NUM_JOBS;

        printf("Encrypting %lu buffers with AES-GCM\n", TOTAL_NUM_JOBS);
        while (n_jobs_left != 0) {
                const unsigned burst_size = (n_jobs_left < BURST_SIZE) ?
                                       n_jobs_left : BURST_SIZE;

                /* IMB API: Get next burst of IMB_JOB's */
                const unsigned n_jobs = IMB_GET_NEXT_BURST(mb_mgr, burst_size, jobs);

                /* If no jobs available, the manager needs to be flushed, to get some jobs out */
                if (n_jobs == 0) {
                        completed_jobs = IMB_FLUSH_BURST(mb_mgr, BURST_SIZE, jobs);

                        total_jobs_rx += completed_jobs;
                        n_jobs_left -= completed_jobs;
#ifdef DEBUG
                        for (i = 0; i < completed_jobs; i++) {
                                if (jobs[i]->status != IMB_STATUS_COMPLETED) {
                                        printf("Some jobs were not successful\n");
                                        goto exit;
                                }
                        }
#endif
                        continue;
                }

                /* Prepare jobs */
                for (i = 0; i < n_jobs; i++) {
                        /* Index for next buffer in src_bufs/dst_bufs arrays */
                        const unsigned buf_idx = (TOTAL_NUM_JOBS - n_jobs_left + i) % NUM_BUFS;

                        fill_job(jobs[i], src_bufs[buf_idx], dst_bufs[buf_idx],
                                 iv[i], &gdata_key, aad[i], auth_tags[buf_idx]);
#if IMB_VERSION(1, 3, 0) < IMB_VERSION_NUM
                        imb_set_session(mb_mgr, jobs[i]);
#endif
                }

#ifdef DEBUG
                /* IMB API: Submit jobs (internally checks if job fields are correct) */
                completed_jobs = IMB_SUBMIT_BURST(mb_mgr, n_jobs, jobs);

                /* IMB API: Get error number set (0 = all correct) */
                const int err = imb_get_errno(mb_mgr);

                /* IMB API: Get string for the error */
                if (err != 0) {
                        printf("submit_burst error %d : '%s'\n", err,
                               imb_get_strerror(err));
                        goto exit;
                }

                for (i = 0; i < completed_jobs; i++) {
                        if (jobs[i]->status != IMB_STATUS_COMPLETED) {
                                printf("Some jobs were not successful\n");
                                goto exit;
                        }
                }
#else
                /* IMB API: Submit jobs (does not check the job fields, so it is faster API) */
                completed_jobs = IMB_SUBMIT_BURST_NOCHECK(mb_mgr, n_jobs, jobs);

#endif
                n_jobs_left -= n_jobs;
                total_jobs_rx += completed_jobs;
        }

        if (total_jobs_rx != TOTAL_NUM_JOBS) {
                /* IMB API: Flush jobs (processes jobs not completed previously with
                 *          IMB_SUBMIT_BURST/IMB_SUBMIT_BURST_NOCHECK) */
                completed_jobs = IMB_FLUSH_BURST(mb_mgr, BURST_SIZE, jobs);

                total_jobs_rx += completed_jobs;
#ifdef DEBUG
                for (i = 0; i < completed_jobs; i++) {
                        if (jobs[i]->status != IMB_STATUS_COMPLETED) {
                                printf("Some jobs were not successful\n");
                                goto exit;
                        }
                }

#endif
        }

        if (total_jobs_rx != TOTAL_NUM_JOBS) {
                printf("Not all jobs could be completed (expected %lu, got %u)\n",
                       TOTAL_NUM_JOBS, total_jobs_rx);
                goto exit;
        }

        exit_status = EXIT_SUCCESS;

        printf("All buffers were successfully encrypted\n");
exit:
        for (i = 0; i < NUM_BUFS; i++) {
                free(src_bufs[i]);
                free(dst_bufs[i]);
                free(auth_tags[i]);
        }
        free_mb_mgr(mb_mgr);

        return exit_status;
}
