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

static int
kat_hash_validate_vec_tab(const struct mac_test *const *vec_tab, const uint32_t vec_tab_num)
{
        if (vec_tab == NULL || vec_tab_num == 0) {
                printf("Invalid vec table configuration\n");
                return -1;
        }

        for (uint32_t i = 0; i < vec_tab_num; i++) {
                if (vec_tab[i] == NULL) {
                        printf("Invalid vec table configuration\n");
                        return -1;
                }
        }

        return 0;
}

static const struct mac_test *
kat_hash_get_vec(const struct mac_test *const *vec_tab, const uint32_t vec_tab_num,
                 const uint32_t vec_idx)
{
        if (vec_tab_num == 1)
                return vec_tab[0];

        return vec_tab[vec_idx % vec_tab_num];
}

/*
 * Initialize fields common to hash-only KAT jobs.
 * Algorithm-specific fields are caller-owned.
 */
static void
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
        job->user_data = NULL;
        job->user_data2 = NULL;
}

static int
kat_hash_job_check(const struct IMB_JOB *job, const struct mac_test *vec)
{
        const size_t tag_size = vec->tagSize / 8;

        if (job->status != IMB_STATUS_COMPLETED)
                return -1;

        if (memcmp(vec->tag, job->auth_tag_output, tag_size)) {
                hexdump(stderr, "Received", job->auth_tag_output, tag_size);
                hexdump(stderr, "Expected", vec->tag, tag_size);
                return -1;
        }

        return 0;
}

static void
kat_hash_job_cleanup(struct IMB_JOB *job, const struct kat_hash_job_ops *ops)
{
        if (ops->cleanup != NULL)
                ops->cleanup(job, ops->ctx);
        free(job->auth_tag_output);
        job->auth_tag_output = NULL;
}

static int
kat_job_prepare_hash(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                     const struct kat_hash_job_ops *ops)
{
        const size_t tag_size = vec->tagSize / 8;

        /* Common ownership: this helper allocates the tag buffer and always frees it. */
        job->auth_tag_output = malloc(tag_size);
        if (job->auth_tag_output == NULL)
                return -1;

        kat_hash_job_init(job, (const void *) vec->msg, vec->msgSize / 8, tag_size);

        if (ops->prepare != NULL && ops->prepare(mb_mgr, job, vec, ops->ctx) < 0) {
                kat_hash_job_cleanup(job, ops);
                return -1;
        }
        job->hash_alg = ops->hash_alg;

        return 0;
}

static int
kat_job_process_hash(struct IMB_JOB *job, const struct mac_test *const *vec_tab,
                     const uint32_t vec_tab_num, const struct kat_hash_job_ops *ops)
{
        const uint32_t vec_idx = (uint32_t) (uintptr_t) job->user_data2;
        const struct mac_test *vec = kat_hash_get_vec(vec_tab, vec_tab_num, vec_idx);
        const int ret = kat_hash_job_check(job, vec);

        /* Returned jobs are consumed here regardless of pass/fail status. */
        kat_hash_job_cleanup(job, ops);
        return ret;
}

int
kat_hash_test_submit_flush(struct IMB_MGR *mb_mgr, const struct mac_test *const *vec_tab,
                           const uint32_t vec_tab_num, const uint32_t num_jobs,
                           const struct kat_hash_job_ops *ops)
{
        struct IMB_JOB *job;
        uint32_t jobs_rx = 0;
        int ret = -1;

        if (ops == NULL) {
                printf("Invalid hash job operations\n");
                return -1;
        }

        if (num_jobs == 0) {
                printf("Invalid number of jobs: 0\n");
                return -1;
        }

        if (kat_hash_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;

        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (uint32_t i = 0; i < num_jobs; i++) {
                const struct mac_test *vec = kat_hash_get_vec(vec_tab, vec_tab_num, i);

                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (job == NULL) {
                        printf("Failed to get job\n");
                        goto end;
                }
                if (kat_job_prepare_hash(mb_mgr, job, vec, ops) < 0)
                        goto end;
                job->user_data2 = (void *) (uintptr_t) i;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (kat_job_process_hash(job, vec_tab, vec_tab_num, ops) < 0)
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (kat_job_process_hash(job, vec_tab, vec_tab_num, ops) < 0)
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                kat_hash_job_cleanup(job, ops);
        return ret;
}

int
kat_hash_test_burst(struct IMB_MGR *mb_mgr, const struct mac_test *const *vec_tab,
                    const uint32_t vec_tab_num, const uint32_t num_jobs,
                    const struct kat_hash_job_ops *ops)
{
        struct IMB_JOB *job, *jobs[KAT_MAX_BURST_SIZE] = { NULL };
        struct IMB_JOB *prepared[KAT_MAX_BURST_SIZE] = { NULL };
        uint32_t jobs_rx = 0, completed_jobs = 0, prepared_jobs = 0;
        int ret = -1;

        if (ops == NULL) {
                printf("Invalid hash job operations\n");
                return -1;
        }

        if (num_jobs == 0 || num_jobs > KAT_MAX_BURST_SIZE) {
                printf("Invalid number of burst jobs: %u\n", num_jobs);
                return -1;
        }

        if (kat_hash_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (uint32_t i = 0; i < num_jobs; i++) {
                const struct mac_test *vec = kat_hash_get_vec(vec_tab, vec_tab_num, i);

                if (kat_job_prepare_hash(mb_mgr, jobs[i], vec, ops) < 0)
                        goto end;
                jobs[i]->user_data2 = (void *) (uintptr_t) i;
                /* jobs[] gets overwritten by later flush calls; keep our own record. */
                prepared[prepared_jobs++] = jobs[i];
                imb_set_session(mb_mgr, jobs[i]);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        if (imb_get_errno(mb_mgr) != 0) {
                printf("submit_burst error %d : '%s'\n", imb_get_errno(mb_mgr),
                       imb_get_strerror(imb_get_errno(mb_mgr)));
                goto end;
        }

        while (jobs_rx < num_jobs) {
                for (uint32_t i = 0; i < completed_jobs; i++) {
                        job = jobs[i];
                        if (kat_job_process_hash(job, vec_tab, vec_tab_num, ops) < 0)
                                goto end;
                        jobs_rx++;
                }

                if (jobs_rx == num_jobs)
                        break;

                completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs - jobs_rx, jobs);
                if (completed_jobs == 0) {
                        printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                        goto end;
                }
        }
        /* Every prepared job was already cleaned up above via kat_job_process_hash(). */
        return 0;

end:
        /* Force outstanding jobs to completion before releasing their buffers. */
        while (IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs) != 0)
                ;
        for (uint32_t i = 0; i < prepared_jobs; i++) {
                if (prepared[i]->auth_tag_output != NULL)
                        kat_hash_job_cleanup(prepared[i], ops);
        }
        return ret;
}

int
kat_hash_test_hash_burst(struct IMB_MGR *mb_mgr, const struct mac_test *const *vec_tab,
                         const uint32_t vec_tab_num, const uint32_t num_jobs,
                         const struct kat_hash_job_ops *ops)
{
        struct IMB_JOB jobs[KAT_MAX_BURST_SIZE] = { 0 };
        uint32_t completed_jobs = 0, prepared_jobs = 0;
        int ret = -1;

        if (ops == NULL) {
                printf("Invalid hash job operations\n");
                return -1;
        }

        if (num_jobs == 0 || num_jobs > KAT_MAX_BURST_SIZE) {
                printf("Invalid number of burst jobs: %u\n", num_jobs);
                return -1;
        }

        if (kat_hash_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;

        for (uint32_t i = 0; i < num_jobs; i++) {
                const struct mac_test *vec = kat_hash_get_vec(vec_tab, vec_tab_num, i);

                if (kat_job_prepare_hash(mb_mgr, &jobs[i], vec, ops) < 0)
                        goto end;
                jobs[i].user_data2 = (void *) (uintptr_t) i;
                prepared_jobs++;
        }

        completed_jobs = IMB_SUBMIT_HASH_BURST(mb_mgr, jobs, num_jobs, ops->hash_alg);
        if (completed_jobs != num_jobs) {
                const int err = imb_get_errno(mb_mgr);

                printf("submit_hash_burst returned %u/%u jobs, error %d : '%s'\n", completed_jobs,
                       num_jobs, err, imb_get_strerror(err));
                goto end;
        }

        for (uint32_t i = 0; i < num_jobs; i++)
                if (kat_job_process_hash(&jobs[i], vec_tab, vec_tab_num, ops) < 0)
                        goto end;
        ret = 0;

end:
        for (uint32_t i = 0; i < prepared_jobs; i++) {
                if (jobs[i].auth_tag_output != NULL)
                        kat_hash_job_cleanup(&jobs[i], ops);
        }
        return ret;
}
