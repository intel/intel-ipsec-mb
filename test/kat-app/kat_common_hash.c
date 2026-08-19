/****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "kat_common_hash.h"

#define KAT_MAX_BURST_SIZE IMB_MAX_BURST_SIZE

void
kat_hash_job_init(struct IMB_JOB *job, const void *src, const size_t msg_len, const size_t tag_len)
{
        job->enc_keys = NULL;
        job->dec_keys = NULL;
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->dst = NULL;
        job->key_len_in_bytes = 0;
        job->auth_tag_output_len_in_bytes = tag_len;
        job->iv = NULL;
        job->iv_len_in_bytes = 0;
        job->src = src;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = msg_len;
        job->cipher_mode = IMB_CIPHER_NULL;
}

static int
kat_job_prepare_hash(struct IMB_JOB *job, const void *vector, const struct kat_hash_job_ops *ops)
{
        const struct mac_test *vec = vector;
        const size_t tag_size = (ops->tag_size != 0) ? ops->tag_size : vec->tagSize / 8;

        /* Common ownership: this helper allocates the tag buffer and always frees it. */
        job->auth_tag_output = malloc(tag_size);
        if (job->auth_tag_output == NULL)
                return -1;

        kat_hash_job_init(job, (const void *) vec->msg, vec->msgSize / 8, tag_size);
        if (ops->prepare(job, ops->ctx) < 0) {
                kat_hash_job_cleanup(job, ops->ctx);
                return -1;
        }

        return 0;
}

int
kat_hash_job_check(const struct IMB_JOB *job, const void *vector, const void *ctx)
{
        const struct mac_test *vec = vector;
        const struct kat_hash_job_ops *ops = ctx;
        const size_t tag_size = (ops->tag_size != 0) ? ops->tag_size : vec->tagSize / 8;

        if (job->status != IMB_STATUS_COMPLETED)
                return -1;

        if (memcmp(vec->tag, job->auth_tag_output, tag_size)) {
                hexdump(stderr, "Received", job->auth_tag_output, tag_size);
                hexdump(stderr, "Expected", vec->tag, tag_size);
                return -1;
        }

        return 0;
}

void
kat_hash_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        (void) ctx;
        free(job->auth_tag_output);
        job->auth_tag_output = NULL;
}

static int
kat_job_process_hash(struct IMB_JOB *job, const void *vec, const struct kat_hash_job_ops *ops)
{
        const int ret = kat_hash_job_check(job, vec, ops);

        /* Returned jobs are consumed here regardless of pass/fail status. */
        kat_hash_job_cleanup(job, ops->ctx);
        return ret;
}

int
kat_hash_test_submit_flush(struct IMB_MGR *mb_mgr, const void *vec, const uint32_t num_jobs,
                           const struct kat_hash_job_ops *ops)
{
        struct IMB_JOB *job;
        uint32_t jobs_rx = 0;
        int ret = -1;

        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (uint32_t i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (kat_job_prepare_hash(job, vec, ops) < 0)
                        goto end;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (kat_job_process_hash(job, vec, ops) < 0)
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (kat_job_process_hash(job, vec, ops) < 0)
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                kat_hash_job_cleanup(job, ops->ctx);
        }
        return ret;
}

int
kat_hash_test_burst(struct IMB_MGR *mb_mgr, const void *vec, const uint32_t num_jobs,
                    const struct kat_hash_job_ops *ops)
{
        struct IMB_JOB *job, *jobs[KAT_MAX_BURST_SIZE] = { NULL };
        uint32_t jobs_rx = 0, completed_jobs = 0, prepared_jobs = 0;
        int ret = -1;

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (uint32_t i = 0; i < num_jobs; i++) {
                if (kat_job_prepare_hash(jobs[i], vec, ops) < 0)
                        goto end;
                prepared_jobs++;
                imb_set_session(mb_mgr, jobs[i]);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        if (imb_get_errno(mb_mgr) != 0) {
                printf("submit_burst error %d : '%s'\n", imb_get_errno(mb_mgr),
                       imb_get_strerror(imb_get_errno(mb_mgr)));
                goto end;
        }

check_jobs:
        for (uint32_t i = 0; i < completed_jobs; i++) {
                job = jobs[i];
                if (job->status != IMB_STATUS_COMPLETED || kat_job_process_hash(job, vec, ops) < 0)
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs - jobs_rx, jobs);
                if (completed_jobs == 0) {
                        printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                        goto end;
                }
                goto check_jobs;
        }
        ret = 0;

end:
        completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);
        for (uint32_t i = 0; i < completed_jobs; i++) {
                kat_hash_job_cleanup(jobs[i], ops->ctx);
        }
        /* Only jobs prepared successfully own an auth_tag_output allocation. */
        for (uint32_t i = 0; i < prepared_jobs; i++) {
                kat_hash_job_cleanup(jobs[i], ops->ctx);
        }
        return ret;
}

int
kat_hash_test_hash_burst(struct IMB_MGR *mb_mgr, const void *vec, const uint32_t num_jobs,
                         const IMB_HASH_ALG hash_alg, const struct kat_hash_job_ops *ops)
{
        struct IMB_JOB jobs[KAT_MAX_BURST_SIZE] = { 0 };
        uint32_t completed_jobs = 0, prepared_jobs = 0;
        int ret = -1;

        for (uint32_t i = 0; i < num_jobs; i++) {
                if (kat_job_prepare_hash(&jobs[i], vec, ops) < 0)
                        goto end;
                prepared_jobs++;
        }

        completed_jobs = IMB_SUBMIT_HASH_BURST(mb_mgr, jobs, num_jobs, hash_alg);
        if (completed_jobs != num_jobs) {
                printf("submit_burst error: not enough jobs returned!\n");
                goto end;
        }

        for (uint32_t i = 0; i < num_jobs; i++) {
                if (jobs[i].status != IMB_STATUS_COMPLETED ||
                    kat_job_process_hash(&jobs[i], vec, ops) < 0)
                        goto end;
        }
        ret = 0;

end:
        for (uint32_t i = 0; i < prepared_jobs; i++) {
                kat_hash_job_cleanup(&jobs[i], ops->ctx);
        }
        return ret;
}
