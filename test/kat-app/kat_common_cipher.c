/****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "kat_common_cipher.h"

#define KAT_MAX_BURST_SIZE IMB_MAX_BURST_SIZE

static int
kat_cipher_validate_vec_tab(const struct cipher_test *const *vec_tab, const uint32_t vec_tab_num)
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

static const struct cipher_test *
kat_cipher_get_vec(const struct cipher_test *const *vec_tab, const uint32_t vec_tab_num,
                   const uint32_t vec_idx)
{
        /* A single vector is reused across the whole batch. */
        if (vec_tab_num == 1)
                return vec_tab[0];

        /* Larger batches cycle through the supplied vector table. */
        return vec_tab[vec_idx % vec_tab_num];
}

static const void *
kat_cipher_get_src(const struct cipher_test *vec, const struct kat_cipher_job_ops *ops)
{
        if (ops->cipher_direction == IMB_DIR_ENCRYPT)
                return vec->msg;

        return vec->ct;
}

static const void *
kat_cipher_get_expected(const struct cipher_test *vec, const struct kat_cipher_job_ops *ops)
{
        if (ops->cipher_direction == IMB_DIR_ENCRYPT)
                return vec->ct;

        return vec->msg;
}

static void
kat_cipher_job_init(struct IMB_JOB *job, const struct cipher_test *vec,
                    const struct kat_cipher_job_ops *ops, uint8_t *target)
{
        const size_t msg_len = vec->msgSize / 8;

        job->enc_keys = NULL;
        job->dec_keys = NULL;
        job->cipher_direction = ops->cipher_direction;
        job->chain_order = ops->chain_order;
        job->dst = target;
        job->key_len_in_bytes = ops->key_len_in_bytes;
        job->auth_tag_output = NULL;
        job->auth_tag_output_len_in_bytes = 0;
        job->iv = NULL;
        job->iv_len_in_bytes = 0;
        job->src = ops->in_place ? target : kat_cipher_get_src(vec, ops);
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = msg_len;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = 0;
        job->cipher_mode = ops->cipher_mode;
        job->hash_alg = IMB_AUTH_NULL;
        /* user_data is reserved for resources owned by prepare(). */
        job->user_data = NULL;
        job->user_data2 = NULL;
}

static int
kat_cipher_job_check(const struct IMB_JOB *job, const struct cipher_test *vec,
                     const struct kat_cipher_job_ops *ops, const uint8_t *target)
{
        const size_t msg_len = vec->msgSize / 8;

        if (job->status != IMB_STATUS_COMPLETED)
                return -1;

        if (memcmp(kat_cipher_get_expected(vec, ops), target, msg_len)) {
                hexdump(stderr, "Received", target, msg_len);
                hexdump(stderr, "Expected", kat_cipher_get_expected(vec, ops), msg_len);
                return -1;
        }

        return 0;
}

static void
kat_cipher_job_cleanup(struct IMB_JOB *job, const struct kat_cipher_job_ops *ops)
{
        /* A cleanup callback is optional; if present it owns any job-local allocations created in
         * prepare().
         */
        if (ops->cleanup != NULL)
                ops->cleanup(job, ops->ctx);
        job->user_data = NULL;
}

static int
kat_cipher_prepare_job(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                       const struct kat_cipher_job_ops *ops, uint8_t *target)
{
        const size_t msg_len = vec->msgSize / 8;

        /* Initialize the common job fields first so the algorithm-specific prepare hook can fill in
         * only the fields it owns (for example IV and key schedule pointers).
         */
        kat_cipher_job_init(job, vec, ops, target);
        if (ops->in_place && msg_len != 0)
                memcpy(target, kat_cipher_get_src(vec, ops), msg_len);

        if (ops->prepare != NULL && ops->prepare(mb_mgr, job, vec, ops->ctx) < 0) {
                kat_cipher_job_cleanup(job, ops);
                return -1;
        }

        return 0;
}

static int
kat_cipher_job_process(struct IMB_JOB *job, const struct cipher_test *const *vec_tab,
                       const uint32_t vec_tab_num, const struct kat_cipher_job_ops *ops,
                       uint8_t **targets)
{
        const uint32_t vec_idx = (uint32_t) (uintptr_t) job->user_data2;
        const int ret = kat_cipher_job_check(job, kat_cipher_get_vec(vec_tab, vec_tab_num, vec_idx),
                                             ops, targets[vec_idx]);

        /* A returned job is consumed regardless of validation result. */
        kat_cipher_job_cleanup(job, ops);
        return ret;
}

static void
kat_cipher_free_targets(uint8_t **targets, const uint32_t num_jobs)
{
        if (targets != NULL) {
                for (uint32_t i = 0; i < num_jobs; i++)
                        free(targets[i]);
                free(targets);
        }
}

static uint8_t **
kat_cipher_alloc_targets(const struct cipher_test *const *vec_tab, const uint32_t vec_tab_num,
                         const uint32_t num_jobs)
{
        uint8_t **targets = calloc(num_jobs, sizeof(*targets));

        if (targets == NULL)
                return NULL;

        for (uint32_t i = 0; i < num_jobs; i++) {
                const struct cipher_test *vec = kat_cipher_get_vec(vec_tab, vec_tab_num, i);
                const size_t msg_len = vec->msgSize / 8;

                /* Every job needs an independent destination for out-of-order completion. */
                targets[i] = malloc(msg_len == 0 ? 1 : msg_len);
                if (targets[i] == NULL) {
                        kat_cipher_free_targets(targets, num_jobs);
                        return NULL;
                }
        }

        return targets;
}

int
kat_cipher_test_submit_flush(struct IMB_MGR *mb_mgr, const struct cipher_test *const *vec_tab,
                             const uint32_t vec_tab_num, const uint32_t num_jobs,
                             const struct kat_cipher_job_ops *ops)
{
        struct IMB_JOB *job;
        uint32_t jobs_rx = 0;
        int ret = -1;

        if (ops == NULL) {
                printf("Invalid cipher job operations\n");
                return -1;
        }

        if (num_jobs == 0) {
                printf("Invalid number of jobs: 0\n");
                return -1;
        }

        if (kat_cipher_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;

        uint8_t **targets = kat_cipher_alloc_targets(vec_tab, vec_tab_num, num_jobs);
        if (targets == NULL)
                return -1;

        /* Start with an empty scheduler so all returned jobs belong to this test. */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (uint32_t i = 0; i < num_jobs; i++) {
                const struct cipher_test *vec = kat_cipher_get_vec(vec_tab, vec_tab_num, i);

                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (job == NULL) {
                        printf("Failed to get job\n");
                        goto end;
                }
                if (kat_cipher_prepare_job(mb_mgr, job, vec, ops, targets[i]) < 0)
                        goto end;
                /* Preserve the submission slot when jobs complete out of order. */
                job->user_data2 = (void *) (uintptr_t) i;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (kat_cipher_job_process(job, vec_tab, vec_tab_num, ops, targets) < 0)
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (kat_cipher_job_process(job, vec_tab, vec_tab_num, ops, targets) < 0)
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
        /* Complete outstanding work before releasing job-owned resources. */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                kat_cipher_job_cleanup(job, ops);
        kat_cipher_free_targets(targets, num_jobs);
        return ret;
}

int
kat_cipher_test_generic_burst(struct IMB_MGR *mb_mgr, const struct cipher_test *const *vec_tab,
                              const uint32_t vec_tab_num, const uint32_t num_jobs,
                              const struct kat_cipher_job_ops *ops)
{
        struct IMB_JOB *job, *jobs[KAT_MAX_BURST_SIZE] = { NULL };
        struct IMB_JOB *prepared[KAT_MAX_BURST_SIZE] = { NULL };
        uint8_t processed[KAT_MAX_BURST_SIZE] = { 0 };
        uint32_t jobs_rx = 0, completed_jobs = 0, prepared_jobs = 0;
        int ret = -1;

        if (ops == NULL) {
                printf("Invalid cipher job operations\n");
                return -1;
        }

        if (num_jobs == 0 || num_jobs > KAT_MAX_BURST_SIZE) {
                printf("Invalid number of burst jobs: %u\n", num_jobs);
                return -1;
        }

        if (kat_cipher_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;

        uint8_t **targets = kat_cipher_alloc_targets(vec_tab, vec_tab_num, num_jobs);
        if (targets == NULL)
                return -1;

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (uint32_t i = 0; i < num_jobs; i++) {
                const struct cipher_test *vec = kat_cipher_get_vec(vec_tab, vec_tab_num, i);

                if (kat_cipher_prepare_job(mb_mgr, jobs[i], vec, ops, targets[i]) < 0)
                        goto end;
                jobs[i]->user_data2 = (void *) (uintptr_t) i;
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
                        const uint32_t job_idx = (uint32_t) (uintptr_t) jobs[i]->user_data2;

                        job = jobs[i];
                        processed[job_idx] = 1;
                        jobs_rx++;
                        if (kat_cipher_job_process(job, vec_tab, vec_tab_num, ops, targets) < 0)
                                goto end;
                }

                if (jobs_rx == num_jobs)
                        break;

                completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs - jobs_rx, jobs);
                if (completed_jobs == 0) {
                        printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                        goto end;
                }
        }
        ret = 0;

end:
        while (IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs) != 0)
                ;
        for (uint32_t i = 0; i < prepared_jobs; i++) {
                if (processed[i] == 0)
                        kat_cipher_job_cleanup(prepared[i], ops);
        }
        kat_cipher_free_targets(targets, num_jobs);
        return ret;
}

int
kat_cipher_test_burst(struct IMB_MGR *mb_mgr, const struct cipher_test *const *vec_tab,
                      const uint32_t vec_tab_num, const uint32_t num_jobs,
                      const struct kat_cipher_job_ops *ops)
{
        struct IMB_JOB jobs[KAT_MAX_BURST_SIZE] = { 0 };
        uint8_t processed[KAT_MAX_BURST_SIZE] = { 0 };
        uint8_t **targets;
        /* Preparation may fail partway through the batch. */
        uint32_t prepared_jobs = 0;
        int ret = -1;

        if (ops == NULL) {
                printf("Invalid cipher job operations\n");
                return -1;
        }

        if (num_jobs == 0 || num_jobs > KAT_MAX_BURST_SIZE) {
                printf("Invalid number of burst jobs: %u\n", num_jobs);
                return -1;
        }

        if (kat_cipher_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;

        targets = kat_cipher_alloc_targets(vec_tab, vec_tab_num, num_jobs);
        if (targets == NULL)
                return -1;

        for (uint32_t i = 0; i < num_jobs; i++) {
                const struct cipher_test *vec = kat_cipher_get_vec(vec_tab, vec_tab_num, i);

                if (kat_cipher_prepare_job(mb_mgr, &jobs[i], vec, ops, targets[i]) < 0)
                        goto end;
                jobs[i].user_data2 = (void *) (uintptr_t) i;
                prepared_jobs++;
        }

        const uint32_t completed =
                IMB_SUBMIT_CIPHER_BURST(mb_mgr, jobs, num_jobs, ops->cipher_mode,
                                        ops->cipher_direction, ops->key_len_in_bytes);

        if (completed != num_jobs) {
                const int err = imb_get_errno(mb_mgr);

                printf("submit_cipher_burst returned %u/%u jobs, error %d : '%s'\n", completed,
                       num_jobs, err, imb_get_strerror(err));
                goto end;
        }

        for (uint32_t i = 0; i < completed; i++) {
                if (kat_cipher_job_process(&jobs[i], vec_tab, vec_tab_num, ops, targets) < 0) {
                        processed[i] = 1;
                        goto end;
                }
                processed[i] = 1;
        }
        ret = 0;

end:
        /* Clean each prepared job exactly once. */
        for (uint32_t i = 0; i < prepared_jobs; i++) {
                if (processed[i] == 0)
                        kat_cipher_job_cleanup(&jobs[i], ops);
        }
        kat_cipher_free_targets(targets, num_jobs);
        return ret;
}