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
                        goto mixed_end;
                if (kat_aead_prepare_job(mb_mgr, job, vec, ops_tab[i]) < 0)
                        goto mixed_end;
                job->user_data2 = (void *) (uintptr_t) i;
                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (kat_aead_process_mixed_job(job, vec_tab, vec_tab_num, ops_tab) < 0)
                                goto mixed_end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (kat_aead_process_mixed_job(job, vec_tab, vec_tab_num, ops_tab) < 0)
                        goto mixed_end;
        }

        ret = jobs_rx == num_jobs ? 0 : -1;
mixed_end:
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                const uint32_t vec_idx = (uint32_t) (uintptr_t) job->user_data2;

                kat_aead_job_cleanup(job, ops_tab[vec_idx]);
        }
        return ret;
}

/**
 * @brief Exercise an encrypt/decrypt round trip with one test vector and job.
 */
static int
kat_aead_test_round_trip(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab,
                         const uint32_t vec_tab_num, const uint32_t num_jobs,
                         const struct kat_aead_job_ops *ops,
                         const struct kat_aead_job_ops *decrypt_ops)
{
        size_t msg_len, tag_len;
        uint8_t *ciphertext = NULL, *plaintext = NULL;
        uint8_t *encrypt_tag = NULL, *decrypt_tag = NULL;
        int ret = -1;

        if (mb_mgr == NULL || vec_tab == NULL || vec_tab_num != 1 || vec_tab[0] == NULL ||
            ops == NULL || decrypt_ops == NULL || num_jobs != 1 || IMB_QUEUE_SIZE(mb_mgr) != 0)
                return -1;

        msg_len = vec_tab[0]->msgSize / 8;
        tag_len = vec_tab[0]->tagSize / 8;
        ciphertext = malloc(msg_len == 0 ? 1 : msg_len);
        plaintext = malloc(msg_len == 0 ? 1 : msg_len);
        encrypt_tag = malloc(tag_len == 0 ? 1 : tag_len);
        decrypt_tag = malloc(tag_len == 0 ? 1 : tag_len);

        if (ciphertext == NULL || plaintext == NULL || encrypt_tag == NULL || decrypt_tag == NULL)
                goto round_trip_end;

        if (kat_aead_round_trip_job(mb_mgr, vec_tab[0], ops, vec_tab[0]->msg, ciphertext,
                                    encrypt_tag) < 0)
                goto round_trip_end;

        if (kat_aead_round_trip_job(mb_mgr, vec_tab[0], decrypt_ops, ciphertext, plaintext,
                                    decrypt_tag) < 0)
                goto round_trip_end;

        if (memcmp(plaintext, vec_tab[0]->msg, msg_len) != 0 ||
            memcmp(encrypt_tag, decrypt_tag, tag_len) != 0)
                goto round_trip_end;

        ret = 0;

round_trip_end:
        free(ciphertext);
        free(plaintext);
        free(encrypt_tag);
        free(decrypt_tag);
        return ret;
}

/**
 * @brief Exercise the standard submit/flush AEAD job API.
 */
static int
kat_aead_test_submit_flush(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab,
                           const uint32_t vec_tab_num, const uint32_t num_jobs,
                           const struct kat_aead_job_ops *ops)
{
        IMB_JOB *job;
        uint32_t jobs_rx = 0;
        int ret = -1;

        if (ops == NULL || num_jobs == 0 || kat_aead_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;

        /* Start with an empty queue so returned jobs belong to this test. */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (uint32_t i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (job == NULL)
                        goto submit_end;

                if (kat_aead_prepare_job(mb_mgr, job, kat_aead_get_vec(vec_tab, vec_tab_num, i),
                                         ops) < 0)
                        goto submit_end;

                job->user_data2 = (void *) (uintptr_t) i;
                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (kat_aead_process_job(job, vec_tab, vec_tab_num, ops) < 0)
                                goto submit_end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (kat_aead_process_job(job, vec_tab, vec_tab_num, ops) < 0)
                        goto submit_end;
        }
        ret = jobs_rx == num_jobs ? 0 : -1;

submit_end:
        /* Release any jobs still queued after an error. */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                kat_aead_job_cleanup(job, ops);
        return ret;
}

/**
 * @brief Exercise a generic or CCM AEAD burst API.
 */
static int
kat_aead_test_burst(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab,
                    const uint32_t vec_tab_num, const uint32_t num_jobs,
                    const struct kat_aead_job_ops *ops, const enum kat_aead_test_mode mode)
{
        IMB_JOB *jobs[KAT_MAX_BURST_SIZE] = { NULL };
        IMB_JOB aead_jobs[KAT_MAX_BURST_SIZE] = { 0 };
        IMB_JOB *prepared[KAT_MAX_BURST_SIZE] = { NULL };
        uint32_t prepared_jobs = 0, jobs_rx = 0, completed_jobs;
        int ret = -1;

        if (ops == NULL || num_jobs == 0 || kat_aead_validate_vec_tab(vec_tab, vec_tab_num) < 0)
                return -1;
        if (num_jobs > KAT_MAX_BURST_SIZE)
                return -1;

        if (mode == KAT_AEAD_BURST)
                while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                        IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (uint32_t i = 0; i < num_jobs; i++) {
                IMB_JOB *job = mode == KAT_AEAD_CCM_BURST ? &aead_jobs[i] : jobs[i];

                if (kat_aead_prepare_job(mb_mgr, job, kat_aead_get_vec(vec_tab, vec_tab_num, i),
                                         ops) < 0)
                        goto burst_end;

                job->user_data2 = (void *) (uintptr_t) i;
                prepared[prepared_jobs++] = job;
                if (mode == KAT_AEAD_BURST)
                        imb_set_session(mb_mgr, job);
        }

        if (mode == KAT_AEAD_CCM_BURST) {
                completed_jobs =
                        IMB_SUBMIT_AEAD_BURST(mb_mgr, aead_jobs, num_jobs, ops->cipher_mode,
                                              ops->cipher_direction, ops->key_len_in_bytes);
                if (completed_jobs != num_jobs)
                        goto burst_end;
        } else {
                completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        }

        while (jobs_rx < num_jobs) {
                for (uint32_t i = 0; i < completed_jobs; i++) {
                        IMB_JOB *job = mode == KAT_AEAD_CCM_BURST ? &aead_jobs[i] : jobs[i];

                        if (kat_aead_process_job(job, vec_tab, vec_tab_num, ops) < 0)
                                goto burst_end;
                        jobs_rx++;
                }
                if (jobs_rx == num_jobs)
                        break;
                if (mode == KAT_AEAD_CCM_BURST)
                        goto burst_end;
                completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs - jobs_rx, jobs);
                if (completed_jobs == 0)
                        goto burst_end;
        }
        ret = 0;

burst_end:
        /* Generic bursts may leave work queued; AEAD bursts complete synchronously. */
        if (mode == KAT_AEAD_BURST)
                while (IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs) != 0)
                        ;

        for (uint32_t i = 0; i < prepared_jobs; i++)
                if (prepared[i]->dst != NULL)
                        kat_aead_job_cleanup(prepared[i], ops);
        return ret;
}

int
kat_aead_test(struct IMB_MGR *mb_mgr, const struct aead_test *const *vec_tab,
              const uint32_t vec_tab_num, const uint32_t num_jobs,
              const struct kat_aead_job_ops *ops, const struct kat_aead_job_ops *decrypt_ops,
              const enum kat_aead_test_mode mode)
{
        switch (mode) {
        case KAT_AEAD_ROUND_TRIP:
                return kat_aead_test_round_trip(mb_mgr, vec_tab, vec_tab_num, num_jobs, ops,
                                                decrypt_ops);
        case KAT_AEAD_SUBMIT_FLUSH:
                return kat_aead_test_submit_flush(mb_mgr, vec_tab, vec_tab_num, num_jobs, ops);
        case KAT_AEAD_BURST:
        case KAT_AEAD_CCM_BURST:
                return kat_aead_test_burst(mb_mgr, vec_tab, vec_tab_num, num_jobs, ops, mode);
        default:
                return -1;
        }
}

/**
 * @brief Exercise submit/flush with caller-owned custom job handling.
 */
int
kat_aead_test_custom_submit_flush(struct IMB_MGR *mb_mgr, const struct kat_custom_job_ops *ops,
                                  const uint32_t num_jobs)
{
        IMB_JOB *job;
        uint32_t jobs_rx = 0;
        int ret = -1;

        if (mb_mgr == NULL || ops == NULL || ops->prepare == NULL || num_jobs == 0)
                return -1;

        /* Do not consume jobs submitted by a previous test. */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (uint32_t i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (job == NULL)
                        goto end;
                if (ops->prepare(mb_mgr, job, ops->ctx) < 0) {
                        if (ops->cleanup != NULL)
                                ops->cleanup(job, ops->ctx);
                        goto end;
                }

                /* A full queue may return a completed job during submission. */
                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (job->status != IMB_STATUS_COMPLETED ||
                            (ops->validate != NULL && ops->validate(job, ops->ctx) < 0)) {
                                if (ops->cleanup != NULL)
                                        ops->cleanup(job, ops->ctx);
                                goto end;
                        }
                        if (ops->cleanup != NULL)
                                ops->cleanup(job, ops->ctx);
                }
        }

        /* Drain any jobs that were queued without completing during submission. */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (job->status != IMB_STATUS_COMPLETED ||
                    (ops->validate != NULL && ops->validate(job, ops->ctx) < 0)) {
                        if (ops->cleanup != NULL)
                                ops->cleanup(job, ops->ctx);
                        goto end;
                }
                if (ops->cleanup != NULL)
                        ops->cleanup(job, ops->ctx);
        }

        ret = jobs_rx == num_jobs ? 0 : -1;

end:
        /* Complete and release every remaining job before returning to the caller. */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                if (ops->cleanup != NULL)
                        ops->cleanup(job, ops->ctx);
        }
        return ret;
}
