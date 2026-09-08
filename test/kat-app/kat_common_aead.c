/****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "kat_common_aead.h"

#define KAT_MAX_BURST_SIZE IMB_MAX_BURST_SIZE

static const struct aead_test *
kat_aead_get_vec(const struct aead_test *const *vec_tab, const uint32_t vec_tab_num,
                 const uint32_t vec_idx)
{
        return vec_tab_num == 1 ? vec_tab[0] : vec_tab[vec_idx % vec_tab_num];
}

static int
kat_aead_validate_vec_tab(const struct aead_test *const *vec_tab, const uint32_t vec_tab_num)
{
        if (vec_tab == NULL || vec_tab_num == 0)
                return -1;

        for (uint32_t i = 0; i < vec_tab_num; i++)
                if (vec_tab[i] == NULL)
                        return -1;

        return 0;
}

static void
kat_aead_job_init(struct IMB_JOB *job, const struct aead_test *vec,
                  const struct kat_aead_job_ops *ops, uint8_t *target, uint8_t *tag)
{
        const size_t msg_len = vec->msgSize / 8;

        /* Keep all shared job fields in one place so each algorithm only fills what it owns. */
        job->enc_keys = NULL;
        job->dec_keys = NULL;
        job->cipher_direction = ops->cipher_direction;
        job->chain_order = ops->chain_order;
        job->dst = target;
        job->key_len_in_bytes = ops->key_len_in_bytes;
        job->src = ops->in_place
                           ? target
                           : (ops->cipher_direction == IMB_DIR_ENCRYPT ? (const void *) vec->msg
                                                                       : (const void *) vec->ct);
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = msg_len;
        job->iv = (const uint8_t *) vec->iv;
        job->iv_len_in_bytes = vec->ivSize / 8;
        job->auth_tag_output = tag;
        job->auth_tag_output_len_in_bytes = vec->tagSize / 8;
        job->cipher_mode = ops->cipher_mode;
        job->hash_alg = ops->hash_alg;
        job->user_data = NULL;
        job->user_data2 = NULL;
}

static void
kat_aead_job_cleanup(struct IMB_JOB *job, const struct kat_aead_job_ops *ops)
{
        if (ops->cleanup != NULL)
                ops->cleanup(job, ops->ctx);
        free(job->dst);
        free(job->auth_tag_output);
        job->dst = NULL;
        job->auth_tag_output = NULL;
}

/* Round-trip tests use caller-owned staging buffers, so only the algorithm-specific resources are
 * released here. The caller still owns the ciphertext/plaintext/tag storage.
 */
static void
kat_aead_cleanup_resources(struct IMB_JOB *job, const struct kat_aead_job_ops *ops)
{
        if (ops->cleanup != NULL)
                ops->cleanup(job, ops->ctx);
        job->user_data = NULL;
}

static int
kat_aead_prepare_job(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct aead_test *vec,
                     const struct kat_aead_job_ops *ops)
{
        const size_t msg_len = vec->msgSize / 8;
        const size_t tag_len = vec->tagSize / 8;
        uint8_t *dst, *tag;

        dst = malloc(msg_len == 0 ? 1 : msg_len);
        tag = malloc(tag_len == 0 ? 1 : tag_len);
        if (dst == NULL || tag == NULL) {
                free(dst);
                free(tag);
                return -1;
        }

        kat_aead_job_init(job, vec, ops, dst, tag);
        if (ops->in_place && msg_len != 0) {
                const void *src = ops->cipher_direction == IMB_DIR_ENCRYPT ? vec->msg : vec->ct;

                memcpy(job->dst, src, msg_len);
        }

        if (ops->prepare != NULL && ops->prepare(mb_mgr, job, vec, ops->ctx) < 0) {
                kat_aead_job_cleanup(job, ops);
                return -1;
        }

        return 0;
}

static int
kat_aead_job_check(const struct IMB_JOB *job, const struct aead_test *vec,
                   const struct kat_aead_job_ops *ops)
{
        const size_t msg_len = vec->msgSize / 8;
        const void *expected = ops->cipher_direction == IMB_DIR_ENCRYPT ? vec->ct : vec->msg;

        /* Job completion status and output/tag validation are checked before the helper consumes
         * the completed work item.
         */
        if (job->status != IMB_STATUS_COMPLETED)
                return -1;
        if (memcmp(expected, job->dst, msg_len) != 0)
                return -1;
        if (memcmp(vec->tag, job->auth_tag_output, vec->tagSize / 8) != 0)
                return -1;

        return 0;
}

/* Perform one encrypt or decrypt operation with caller-owned staging buffers. The helper only
 * releases any job-local callback resources; the buffers passed in are owned by the caller.
 */
static int
kat_aead_round_trip_job(struct IMB_MGR *mb_mgr, const struct aead_test *vec,
                        const struct kat_aead_job_ops *ops, const void *src, void *dst, void *tag)
{
        IMB_JOB *job = IMB_GET_NEXT_JOB(mb_mgr);

        if (job == NULL)
                return -1;

        kat_aead_job_init(job, vec, ops, dst, tag);
        job->src = src;
        if (ops->prepare != NULL && ops->prepare(mb_mgr, job, vec, ops->ctx) < 0) {
                kat_aead_cleanup_resources(job, ops);
                return -1;
        }

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job == NULL || kat_aead_job_check(job, vec, ops) < 0) {
                if (job != NULL)
                        kat_aead_cleanup_resources(job, ops);
                return -1;
        }

        kat_aead_cleanup_resources(job, ops);
        return 0;
}

static int
kat_aead_process_job(struct IMB_JOB *job, const struct aead_test *const *vec_tab,
                     const uint32_t vec_tab_num, const struct kat_aead_job_ops *ops)
{
        const uint32_t vec_idx = (uint32_t) (uintptr_t) job->user_data2;
        const int ret =
                kat_aead_job_check(job, kat_aead_get_vec(vec_tab, vec_tab_num, vec_idx), ops);

        kat_aead_job_cleanup(job, ops);
        return ret;
}

static int
kat_aead_process_mixed_job(struct IMB_JOB *job, const struct aead_test *const *vec_tab,
                           const uint32_t vec_tab_num,
                           const struct kat_aead_job_ops *const *ops_tab)
{
        const uint32_t vec_idx = (uint32_t) (uintptr_t) job->user_data2;
        const struct kat_aead_job_ops *ops = ops_tab[vec_idx];
        const int ret =
                kat_aead_job_check(job, kat_aead_get_vec(vec_tab, vec_tab_num, vec_idx), ops);

        kat_aead_job_cleanup(job, ops);
        return ret;
}

/* Submit/flush test: one operation type is reused for all jobs. Each job allocates its own
 * output/tag storage and validates the returned result before the helper frees those buffers.
 */
int
kat_aead_test_submit_flush(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab,
                           const uint32_t vec_tab_num, const uint32_t num_jobs,
                           const struct kat_aead_job_ops *ops)
{
        IMB_JOB *job;
        uint32_t jobs_rx = 0;
        int ret = -1;

        if (ops == NULL || num_jobs == 0 || kat_aead_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;

        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (uint32_t i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (job == NULL)
                        goto end;
                if (kat_aead_prepare_job(mb_mgr, job, kat_aead_get_vec(vec_tab, vec_tab_num, i),
                                         ops) < 0)
                        goto end;
                job->user_data2 = (void *) (uintptr_t) i;
                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (kat_aead_process_job(job, vec_tab, vec_tab_num, ops) < 0)
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (kat_aead_process_job(job, vec_tab, vec_tab_num, ops) < 0)
                        goto end;
        }

        ret = jobs_rx == num_jobs ? 0 : -1;

end:
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                kat_aead_job_cleanup(job, ops);
        return ret;
}

/* Mixed submit/flush test: each job can use a different direction or chain order, but the helper
 * still owns the per-job output/tag storage created during prepare().
 */
int
kat_aead_test_submit_flush_mixed(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab,
                                 const uint32_t vec_tab_num, const uint32_t num_jobs,
                                 const struct kat_aead_job_ops *const *ops_tab)
{
        IMB_JOB *job;
        uint32_t jobs_rx = 0;
        int ret = -1;

        if (ops_tab == NULL || num_jobs == 0 || kat_aead_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;

        for (uint32_t i = 0; i < num_jobs; i++)
                if (ops_tab[i] == NULL)
                        return -1;

        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (uint32_t i = 0; i < num_jobs; i++) {
                const struct aead_test *vec = kat_aead_get_vec(vec_tab, vec_tab_num, i);

                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (job == NULL)
                        goto end;
                if (kat_aead_prepare_job(mb_mgr, job, vec, ops_tab[i]) < 0)
                        goto end;
                job->user_data2 = (void *) (uintptr_t) i;
                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (kat_aead_process_mixed_job(job, vec_tab, vec_tab_num, ops_tab) < 0)
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (kat_aead_process_mixed_job(job, vec_tab, vec_tab_num, ops_tab) < 0)
                        goto end;
        }

        ret = jobs_rx == num_jobs ? 0 : -1;

end:
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                const uint32_t vec_idx = (uint32_t) (uintptr_t) job->user_data2;

                kat_aead_job_cleanup(job, ops_tab[vec_idx]);
        }
        return ret;
}

/* AEAD burst path: prepare every job first, submit the full burst, and then consume completed jobs
 * in submission order while still validating each result against the correct vector.
 */
int
kat_aead_test_burst(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab,
                    const uint32_t vec_tab_num, const uint32_t num_jobs,
                    const struct kat_aead_job_ops *ops)
{
        IMB_JOB *jobs[KAT_MAX_BURST_SIZE] = { NULL };
        IMB_JOB *prepared[KAT_MAX_BURST_SIZE] = { NULL };
        uint32_t prepared_jobs = 0, jobs_rx = 0, completed_jobs;
        int ret = -1;

        if (ops == NULL || num_jobs == 0 || num_jobs > KAT_MAX_BURST_SIZE ||
            kat_aead_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;

        /* Fill the burst with a fresh set of jobs before submission so the burst API always sees a
         * clean queue.
         */
        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (uint32_t i = 0; i < num_jobs; i++) {
                /* Every prepared job keeps its own destination and tag buffer until validation. */
                if (kat_aead_prepare_job(mb_mgr, jobs[i], kat_aead_get_vec(vec_tab, vec_tab_num, i),
                                         ops) < 0)
                        goto end;
                jobs[i]->user_data2 = (void *) (uintptr_t) i;
                prepared[prepared_jobs++] = jobs[i];
                imb_set_session(mb_mgr, jobs[i]);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        while (jobs_rx < num_jobs) {
                for (uint32_t i = 0; i < completed_jobs; i++) {
                        /* A returned job is consumed regardless of validation result. */
                        if (kat_aead_process_job(jobs[i], vec_tab, vec_tab_num, ops) < 0)
                                goto end;
                        jobs_rx++;
                }
                if (jobs_rx == num_jobs)
                        break;
                completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs - jobs_rx, jobs);
                if (completed_jobs == 0)
                        goto end;
        }
        ret = 0;

end:
        while (IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs) != 0)
                ;
        for (uint32_t i = 0; i < prepared_jobs; i++)
                if (prepared[i]->dst != NULL)
                        kat_aead_job_cleanup(prepared[i], ops);
        return ret;
}

/* Round-trip validation for one vector: encrypt a temporary ciphertext/tag buffer, decrypt it to a
 * temporary plaintext buffer, and confirm the recovered plaintext and tag match the original.
 * The caller owns the staging buffers; this helper only allocates and frees its temporary arrays.
 */
int
kat_aead_test_round_trip(struct IMB_MGR *mb_mgr, const struct aead_test *vec,
                         const struct kat_aead_job_ops *encrypt_ops,
                         const struct kat_aead_job_ops *decrypt_ops)
{
        size_t msg_len, tag_len;
        uint8_t *ciphertext = NULL, *plaintext = NULL;
        uint8_t *encrypt_tag = NULL, *decrypt_tag = NULL;
        int ret = -1;

        if (mb_mgr == NULL || vec == NULL || encrypt_ops == NULL || decrypt_ops == NULL ||
            IMB_QUEUE_SIZE(mb_mgr) != 0)
                goto end;

        msg_len = vec->msgSize / 8;
        tag_len = vec->tagSize / 8;
        ciphertext = malloc(msg_len == 0 ? 1 : msg_len);
        plaintext = malloc(msg_len == 0 ? 1 : msg_len);
        encrypt_tag = malloc(tag_len == 0 ? 1 : tag_len);
        decrypt_tag = malloc(tag_len == 0 ? 1 : tag_len);
        if (ciphertext == NULL || plaintext == NULL || encrypt_tag == NULL || decrypt_tag == NULL)
                goto end;

        if (kat_aead_round_trip_job(mb_mgr, vec, encrypt_ops, vec->msg, ciphertext, encrypt_tag) <
            0)
                goto end;
        if (kat_aead_round_trip_job(mb_mgr, vec, decrypt_ops, ciphertext, plaintext, decrypt_tag) <
            0)
                goto end;
        if (memcmp(plaintext, vec->msg, msg_len) != 0 ||
            memcmp(encrypt_tag, decrypt_tag, tag_len) != 0)
                goto end;

        ret = 0;

end:
        free(ciphertext);
        free(plaintext);
        free(encrypt_tag);
        free(decrypt_tag);
        return ret;
}