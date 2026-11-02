/**********************************************************************
  Copyright(c) 2025-2026 Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h> /* for memcmp() */

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "aead_test.h"
#include "kat_common_aead.h"

int
snow5g_nca4_test(IMB_MGR *p_mgr);

static struct aead_test *snow5g_nca4_vectors;

static void
free_snow5g_nca4_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        snow5g_nca4_vectors = NULL;
}

static int
check_data(const uint8_t *test, const uint8_t *expected, uint64_t len, const char *data_name)
{
        int mismatch;
        int is_error = 0;

        if (len == 0)
                return is_error;

        if (test == NULL || expected == NULL || data_name == NULL)
                return 1;

        mismatch = memcmp(test, expected, len);
        if (mismatch) {
                uint64_t a;

                is_error = 1;
                printf("  expected results don't match %s \t\t", data_name);

                for (a = 0; a < len; a++) {
                        if (test[a] != expected[a]) {
                                printf(" '%x' != '%x' at %llx of %llx\n", test[a], expected[a],
                                       (unsigned long long) a, (unsigned long long) len);
                                break;
                        }
                }
        }
        return is_error;
}

static int
snow5g_nca4_job_prepare(IMB_MGR *mb_mgr, IMB_JOB *job, const struct aead_test *vec, const void *ctx)
{
        (void) mb_mgr;
        (void) ctx;
        job->enc_keys = (const void *) vec->key;
        job->dec_keys = (const void *) vec->key;
        job->u.NCA.aad = (const uint8_t *) vec->aad;
        job->u.NCA.aad_len_in_bytes = vec->aadSize / 8;
        return 0;
}

/* Specialized setup retained for the mixed and sequential coverage below. */
static void
fill_nca4_job(IMB_JOB *job, const struct aead_test *v, IMB_CIPHER_DIRECTION dir, const uint8_t *src,
              uint8_t *dst, uint8_t *tag)
{
        job->cipher_mode = IMB_CIPHER_SNOW5G_NCA4;
        job->hash_alg = IMB_AUTH_SNOW5G_NCA4;
        job->cipher_direction = dir;
        job->chain_order = dir == IMB_DIR_ENCRYPT ? IMB_ORDER_CIPHER_HASH : IMB_ORDER_HASH_CIPHER;
        job->enc_keys = (const void *) v->key;
        job->dec_keys = (const void *) v->key;
        job->key_len_in_bytes = 32;
        job->src = src;
        job->dst = dst;
        job->msg_len_to_cipher_in_bytes = v->msgSize / 8;
        job->cipher_start_src_offset_in_bytes = 0;
        job->iv = (const uint8_t *) v->iv;
        job->iv_len_in_bytes = 16;
        job->u.NCA.aad = (const uint8_t *) v->aad;
        job->u.NCA.aad_len_in_bytes = v->aadSize / 8;
        job->auth_tag_output = tag;
        job->auth_tag_output_len_in_bytes = v->tagSize / 8;
}

static void
test_snow5g_nca4_vectors(IMB_MGR *p_mgr, struct aead_test const *vector,
                         struct test_suite_context *ts)
{
        static const struct kat_aead_job_ops encrypt_ops = {
                .prepare = snow5g_nca4_job_prepare,
                .cipher_mode = IMB_CIPHER_SNOW5G_NCA4,
                .hash_alg = IMB_AUTH_SNOW5G_NCA4,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 32,
        };
        static const struct kat_aead_job_ops decrypt_ops = {
                .prepare = snow5g_nca4_job_prepare,
                .cipher_mode = IMB_CIPHER_SNOW5G_NCA4,
                .hash_alg = IMB_AUTH_SNOW5G_NCA4,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 32,
        };
        static const struct kat_aead_job_ops encrypt_in_place_ops = {
                .prepare = snow5g_nca4_job_prepare,
                .cipher_mode = IMB_CIPHER_SNOW5G_NCA4,
                .hash_alg = IMB_AUTH_SNOW5G_NCA4,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 32,
                .in_place = 1,
        };
        static const struct kat_aead_job_ops decrypt_in_place_ops = {
                .prepare = snow5g_nca4_job_prepare,
                .cipher_mode = IMB_CIPHER_SNOW5G_NCA4,
                .hash_alg = IMB_AUTH_SNOW5G_NCA4,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 32,
                .in_place = 1,
        };
        const struct kat_aead_job_ops *ops[] = { &encrypt_ops, &encrypt_in_place_ops, &decrypt_ops,
                                                 &decrypt_in_place_ops };
        for (size_t i = 0; i < DIM(ops); i++) {
                if (kat_aead_test(p_mgr, &vector, 1, 1, ops[i], NULL, KAT_AEAD_SUBMIT_FLUSH)) {
                        test_suite_update(ts, 0, 1);
                        return;
                }
                test_suite_update(ts, 1, 0);
        }
}

static void
test_snow5g_nca4_std_vectors(IMB_MGR *p_mgr, struct test_suite_context *ts,
                             const struct aead_test *v)
{

        printf("SNOW5G-NCA4 (%s API) standard test vectors:\n", "Direct/JOB");
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  Keylen:%zu IVlen:%zu "
                               "PTLen:%zu AADlen:%zu Tlen:%zu\n",
                               v->tcId, v->keySize / 8, v->ivSize / 8, v->msgSize / 8,
                               v->aadSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                test_snow5g_nca4_vectors(p_mgr, v, ts);
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_snow5g_nca4_submit_flush(IMB_MGR *mb_mgr, struct test_suite_context *ts,
                              const struct aead_test *v)
{
        uint8_t *out[2] = { NULL, NULL };
        uint8_t *tag[2] = { NULL, NULL };
        const uint64_t msg_len = v->msgSize / 8;
        const uint64_t tag_len = v->tagSize / 8;
        IMB_JOB *job;
        int i, completed = 0, err;

        for (i = 0; i < 2; i++) {
                out[i] = malloc(msg_len == 0 ? 1 : msg_len);
                tag[i] = malloc(tag_len);
                if (!out[i] || !tag[i]) {
                        fprintf(stderr, "failed to allocate memory\n");
                        test_suite_update(ts, 0, 1);
                        goto done;
                }
        }

        for (i = 0; i < 2; i++) {
                memset(out[i], 0, msg_len == 0 ? 1 : msg_len);
                memset(tag[i], 0, tag_len);
                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (!job) {
                        fprintf(stderr, "failed to get job\n");
                        test_suite_update(ts, 0, 1);
                        goto done;
                }
                fill_nca4_job(job, v, IMB_DIR_ENCRYPT, (const uint8_t *) v->msg, out[i], tag[i]);
                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        if (job->status != IMB_STATUS_COMPLETED) {
                                test_suite_update(ts, 0, 1);
                                goto done;
                        }
                        completed++;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                if (job->status != IMB_STATUS_COMPLETED) {
                        test_suite_update(ts, 0, 1);
                        goto done;
                }
                completed++;
        }

        if (completed != 2) {
                fprintf(stderr, "submit/flush: expected 2 completions, got %d\n", completed);
                test_suite_update(ts, 0, 1);
                goto done;
        }

        for (i = 0; i < 2; i++) {
                err = 0;
                if (msg_len > 0)
                        err |= check_data(out[i], (const uint8_t *) v->ct, msg_len,
                                          "submit/flush out");
                err |= check_data(tag[i], (const uint8_t *) v->tag, tag_len, "submit/flush tag");
                test_suite_update(ts, err == 0, err != 0);
        }
done:
        for (i = 0; i < 2; i++) {
                free(out[i]);
                free(tag[i]);
        }
}

static void
test_snow5g_nca4_mixed_submit_flush(IMB_MGR *mb_mgr, struct test_suite_context *ts,
                                    const struct aead_test *v)
{
        const struct aead_test *vec_tab[2] = { v, v };
        static const struct kat_aead_job_ops encrypt_ops = {
                .prepare = snow5g_nca4_job_prepare,
                .cipher_mode = IMB_CIPHER_SNOW5G_NCA4,
                .hash_alg = IMB_AUTH_SNOW5G_NCA4,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 32,
        };
        static const struct kat_aead_job_ops decrypt_ops = {
                .prepare = snow5g_nca4_job_prepare,
                .cipher_mode = IMB_CIPHER_SNOW5G_NCA4,
                .hash_alg = IMB_AUTH_SNOW5G_NCA4,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 32,
        };
        const struct kat_aead_job_ops *ops_tab[] = { &encrypt_ops, &decrypt_ops };
        const int failed = kat_aead_test_submit_flush_mixed(mb_mgr, vec_tab, 2, 2, ops_tab);

        test_suite_update(ts, failed == 0, failed != 0);
}

/* Per-vector context used to verify completed jobs */
struct seq_job_ctx {
        const struct aead_test *v;
        uint8_t *out;
        uint8_t *tag;
        IMB_CIPHER_DIRECTION direction;
};

static void
verify_seq_job(IMB_JOB *job, struct test_suite_context *ts)
{
        struct seq_job_ctx *ctx = (struct seq_job_ctx *) job->user_data;
        const struct aead_test *v = ctx->v;
        const uint64_t msg_len = v->msgSize / 8;
        const uint64_t tag_len = v->tagSize / 8;
        const uint8_t *expected = ctx->direction == IMB_DIR_ENCRYPT ? (const uint8_t *) v->ct
                                                                    : (const uint8_t *) v->msg;
        int err = 0;

        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "sequential: job failed, status:%d\n", job->status);
                test_suite_update(ts, 0, 1);
                return;
        }

        if (msg_len > 0)
                err |= check_data(ctx->out, expected, msg_len, "sequential out");
        err |= check_data(ctx->tag, (const uint8_t *) v->tag, tag_len, "sequential tag");
        test_suite_update(ts, err == 0, err != 0);
}

/* Test submitting all vectors without flushing between them, then flush the remaining ones
 * verifying the jobs as the complete */
static void
test_snow5g_nca4_submit_all_vectors(IMB_MGR *mb_mgr, struct test_suite_context *ts,
                                    const struct aead_test *vectors,
                                    const IMB_CIPHER_DIRECTION direction, const int in_place)
{
        /* Count vectors */
        size_t n_vec = 0;
        const struct aead_test *v;

        for (v = vectors; v->msg != NULL; v++)
                n_vec++;

        struct seq_job_ctx *ctxs = calloc(n_vec, sizeof(*ctxs));

        if (!ctxs) {
                fprintf(stderr, "failed to allocate context array\n");
                test_suite_update(ts, 0, 1);
                return;
        }

        if (!quiet_mode)
                printf("SNOW5G-NCA4 sequential all-vectors %s%s test:\n",
                       direction == IMB_DIR_ENCRYPT ? "encrypt" : "decrypt",
                       in_place ? " in-place" : "");

        /* Submit all vectors without flushing between them */
        for (size_t idx = 0; idx < n_vec; idx++) {
                v = &vectors[idx];

                const uint64_t msg_len = v->msgSize / 8;
                const uint64_t tag_len = v->tagSize / 8;
                struct seq_job_ctx *ctx = &ctxs[idx];
                IMB_JOB *job;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Vector %zu  Keylen:%zu IVlen:%zu "
                               "PTLen:%zu AADlen:%zu Tlen:%zu\n",
                               v->tcId, v->keySize / 8, v->ivSize / 8, msg_len, v->aadSize / 8,
                               tag_len);
#else
                        printf(".");
#endif
                }

                ctx->v = v;
                ctx->direction = direction;
                ctx->out = malloc(msg_len > 0 ? msg_len : 1);
                ctx->tag = malloc(tag_len);
                if (!ctx->out || !ctx->tag) {
                        fprintf(stderr, "failed to allocate memory\n");
                        test_suite_update(ts, 0, 1);
                        goto done;
                }
                memset(ctx->out, 0, msg_len > 0 ? msg_len : 1);
                memset(ctx->tag, 0, tag_len);
                const uint8_t *src = direction == IMB_DIR_ENCRYPT ? (const uint8_t *) v->msg
                                                                  : (const uint8_t *) v->ct;
                if (in_place && msg_len > 0) {
                        memcpy(ctx->out, src, msg_len);
                        src = ctx->out;
                }

                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (!job) {
                        fprintf(stderr, "failed to get job\n");
                        test_suite_update(ts, 0, 1);
                        goto done;
                }

                fill_nca4_job(job, v, direction, src, ctx->out, ctx->tag);
                job->user_data = ctx;
                job = IMB_SUBMIT_JOB(mb_mgr);

                /* Collect any job that completed immediately during submit */
                if (job != NULL)
                        verify_seq_job(job, ts);
        }

        /* Flush and verify remaining in-flight jobs */
        IMB_JOB *job;

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                verify_seq_job(job, ts);

        if (!quiet_mode)
                printf("\n");

done:
        for (size_t i = 0; i < n_vec; i++) {
                free(ctxs[i].out);
                free(ctxs[i].tag);
        }
        free(ctxs);
}

/* Scheduler thresholds the carried-lane schedules rely on.  They must match
 * NCA4_INIT_OVERLAP_ROUNDS and NCA4_CARRY_MIN_BYTES in
 * lib/avx512_t2/mb_mgr_snow5g_nca4_x2_submit_flush_vaes_avx512.asm. */
#define NCA4_INIT_OVERLAP_ROUNDS 15
#define NCA4_CARRY_MIN_BYTES     (NCA4_INIT_OVERLAP_ROUNDS * 16)
#define NCA4_BLOCK_BYTES         16

/** Role of a vector in a carried-lane schedule; sched_role_len has one row per role. */
enum sched_role {
        SCHED_LONG,  /**< msg_len >= NCA4_CARRY_MIN_BYTES: survives and is carried */
        SCHED_TINY,  /**< less than one block: retires in the call that pairs it */
        SCHED_SHORT, /**< fresh job initialised while the carried lane ciphers */
};

/** Message length range, in bytes, a vector must have for a role. */
static const struct {
        size_t min_len;
        size_t max_len;
} sched_role_len[] = {
        [SCHED_LONG] = { NCA4_CARRY_MIN_BYTES, SIZE_MAX },
        [SCHED_TINY] = { 1, NCA4_BLOCK_BYTES - 1 },
        [SCHED_SHORT] = { 1, NCA4_CARRY_MIN_BYTES - 1 },
};

#define SCHED_MAX_SLOTS 8

/**
 * @brief Pick a KAT vector for every slot of a schedule from its role.
 *
 * Each slot takes the first vector in table order whose message length fits the
 * role and that no earlier slot took; if the table has none left, an already
 * taken one is reused. With @p finish_in_submit set, the SCHED_LONG vector must
 * also be shorter than NCA4_CARRY_MIN_BYTES per SCHED_SHORT slot, so that the
 * overlaps wear it down below the carry threshold and it finishes inside a submit.
 *
 * @param [in]  vectors           KAT vectors, terminated by an entry without msg
 * @param [in]  roles             role of each slot, in submission order
 * @param [in]  n                 number of slots (at most SCHED_MAX_SLOTS)
 * @param [in]  finish_in_submit  non-zero if the carried job must finish in a submit
 * @param [out] sel               chosen vector of each slot, valid on success
 *
 * @return Status of the selection.
 * @retval 0 every slot got a vector
 * @retval -1 no vector fits some role (reported on stderr)
 */
static int
select_schedule_vectors(const struct aead_test *vectors, const enum sched_role *roles,
                        const size_t n, const int finish_in_submit, const struct aead_test **sel)
{
        size_t n_short = 0;

        for (size_t i = 0; i < n; i++)
                if (roles[i] == SCHED_SHORT)
                        n_short++;

        for (size_t i = 0; i < n; i++) {
                sel[i] = NULL;
                for (int reuse = 0; reuse < 2 && sel[i] == NULL; reuse++) {
                        for (const struct aead_test *v = vectors; v->msg != NULL; v++) {
                                const size_t len = v->msgSize / 8;
                                int taken = 0;

                                for (size_t j = 0; j < i; j++)
                                        taken |= (sel[j] == v);
                                if (len < sched_role_len[roles[i]].min_len ||
                                    len > sched_role_len[roles[i]].max_len || (taken && !reuse))
                                        continue;
                                if (roles[i] == SCHED_LONG && finish_in_submit &&
                                    len >= (size_t) NCA4_CARRY_MIN_BYTES * n_short)
                                        continue;
                                sel[i] = v;
                                break;
                        }
                }
                if (sel[i] == NULL) {
                        fprintf(stderr, "schedule: no vector for slot %zu (role %d)\n", i,
                                (int) roles[i]);
                        return -1;
                }
        }
        return 0;
}

/**
 * @brief Submit the selected vectors in order without flushing in between, then flush.
 *
 * Message lengths pick the scheduler path: a long job paired with a short one
 * is carried across submits, fresh jobs then land in whichever lane is free.
 * Every completed job is verified and the number of completions is checked.
 *
 * @param [in] mb_mgr    multi-buffer manager
 * @param [in] ts        test suite context, updated with the results
 * @param [in] sel       vectors to submit, one per job
 * @param [in] n         number of vectors
 * @param [in] direction IMB_DIR_ENCRYPT or IMB_DIR_DECRYPT
 * @param [in] in_place  non-zero to use the output buffer as input too
 */
static void
test_snow5g_nca4_schedule(IMB_MGR *mb_mgr, struct test_suite_context *ts,
                          const struct aead_test *const *sel, const size_t n,
                          const IMB_CIPHER_DIRECTION direction, const int in_place)
{
        struct seq_job_ctx *ctxs = calloc(n, sizeof(*ctxs));
        size_t submitted = 0;
        size_t completed = 0;
        IMB_JOB *job;

        if (!ctxs) {
                fprintf(stderr, "failed to allocate context array\n");
                test_suite_update(ts, 0, 1);
                return;
        }

        for (size_t idx = 0; idx < n; idx++) {
                const struct aead_test *v = sel[idx];
                struct seq_job_ctx *ctx = &ctxs[idx];

                const uint64_t msg_len = v->msgSize / 8;
                const uint64_t tag_len = v->tagSize / 8;

                ctx->v = v;
                ctx->direction = direction;
                ctx->out = malloc(msg_len > 0 ? msg_len : 1);
                ctx->tag = malloc(tag_len);
                if (!ctx->out || !ctx->tag) {
                        fprintf(stderr, "failed to allocate memory\n");
                        test_suite_update(ts, 0, 1);
                        goto done;
                }
                memset(ctx->out, 0, msg_len > 0 ? msg_len : 1);
                memset(ctx->tag, 0, tag_len);
                const uint8_t *src = direction == IMB_DIR_ENCRYPT ? (const uint8_t *) v->msg
                                                                  : (const uint8_t *) v->ct;
                if (in_place && msg_len > 0) {
                        memcpy(ctx->out, src, msg_len);
                        src = ctx->out;
                }

                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (!job) {
                        fprintf(stderr, "failed to get job\n");
                        test_suite_update(ts, 0, 1);
                        goto done;
                }
                fill_nca4_job(job, v, direction, src, ctx->out, ctx->tag);
                job->user_data = ctx;
                submitted++;
                for (job = IMB_SUBMIT_JOB(mb_mgr); job != NULL;
                     job = IMB_GET_COMPLETED_JOB(mb_mgr)) {
                        verify_seq_job(job, ts);
                        completed++;
                }
        }

done:
        /* Error exits must also drain the lanes: queued jobs point into ctxs. */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                verify_seq_job(job, ts);
                completed++;
        }
        if (completed != submitted) {
                fprintf(stderr, "schedule: expected %zu completions, got %zu\n", submitted,
                        completed);
                test_suite_update(ts, 0, 1);
        }
        for (size_t i = 0; i < n; i++) {
                free(ctxs[i].out);
                free(ctxs[i].tag);
        }
        free(ctxs);
}

/**
 * @brief Run the carried-lane schedules for both directions and in/out-of-place.
 *
 * A long job paired with a tiny one survives the call and is carried. Each
 * following short job is initialised while the carried lane ciphers
 * NCA4_INIT_OVERLAP_ROUNDS blocks, until the survivor has fewer than
 * NCA4_CARRY_MIN_BYTES left and is finished inside the same call. The trailing
 * job then finds both lanes free, so it is parked and completed by flush.
 * The vector of each slot is chosen from the KAT table by its role.
 *   - carry in lane 0, fresh jobs in lane 1: long, tiny, short x4
 *   - carry in lane 1, fresh jobs in lane 0: tiny, long, short x4
 *   - carried lane (at least NCA4_CARRY_MIN_BYTES) completed by flush: long, tiny
 *
 * @param [in] mb_mgr  multi-buffer manager
 * @param [in] ts      test suite context, updated with the results
 * @param [in] vectors KAT vectors, terminated by an entry without msg
 */
static void
test_snow5g_nca4_carry_schedules(IMB_MGR *mb_mgr, struct test_suite_context *ts,
                                 const struct aead_test *vectors)
{
        static const enum sched_role carry_lane0[] = { SCHED_LONG,  SCHED_TINY,  SCHED_SHORT,
                                                       SCHED_SHORT, SCHED_SHORT, SCHED_SHORT };
        static const enum sched_role carry_lane1[] = { SCHED_TINY,  SCHED_LONG,  SCHED_SHORT,
                                                       SCHED_SHORT, SCHED_SHORT, SCHED_SHORT };
        static const enum sched_role carry_flush[] = { SCHED_LONG, SCHED_TINY };
        const struct {
                const enum sched_role *roles;
                size_t n;
                int finish_in_submit;
        } sched[] = { { carry_lane0, DIM(carry_lane0), 1 },
                      { carry_lane1, DIM(carry_lane1), 1 },
                      { carry_flush, DIM(carry_flush), 0 } };
        const IMB_CIPHER_DIRECTION dirs[] = { IMB_DIR_ENCRYPT, IMB_DIR_DECRYPT };

        if (!quiet_mode)
                printf("SNOW5G-NCA4 carried-lane schedule test:\n");
        for (size_t s = 0; s < DIM(sched); s++) {
                const struct aead_test *sel[SCHED_MAX_SLOTS];

                if (select_schedule_vectors(vectors, sched[s].roles, sched[s].n,
                                            sched[s].finish_in_submit, sel) < 0) {
                        test_suite_update(ts, 0, 1);
                        continue;
                }
                for (size_t d = 0; d < DIM(dirs); d++)
                        for (int in_place = 0; in_place < 2; in_place++) {
                                if (!quiet_mode)
                                        printf(".");
                                test_snow5g_nca4_schedule(mb_mgr, ts, sel, sched[s].n, dirs[d],
                                                          in_place);
                        }
        }
        if (!quiet_mode)
                printf("\n");
}

int
snow5g_nca4_test(IMB_MGR *p_mgr)
{
        struct test_suite_context ts;
        const struct aead_test *v;
        int errors = 0;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_aead_vectors(kat_vector_dir, "snow5g_nca4_test.json", &snow5g_nca4_vectors,
                              &jctx) < 0)
                return 1;

        test_suite_start(&ts, "SNOW5G-NCA4");
        test_snow5g_nca4_std_vectors(p_mgr, &ts, snow5g_nca4_vectors);

        for (v = snow5g_nca4_vectors; v->msg != NULL; v++)
                if (v->msgSize > 0 && v->aadSize > 0) {
                        test_snow5g_nca4_submit_flush(p_mgr, &ts, v);
                        test_snow5g_nca4_mixed_submit_flush(p_mgr, &ts, v);
                }

        test_snow5g_nca4_submit_all_vectors(p_mgr, &ts, snow5g_nca4_vectors, IMB_DIR_ENCRYPT, 0);
        test_snow5g_nca4_submit_all_vectors(p_mgr, &ts, snow5g_nca4_vectors, IMB_DIR_DECRYPT, 1);
        test_snow5g_nca4_carry_schedules(p_mgr, &ts, snow5g_nca4_vectors);

        errors += test_suite_end(&ts);

        free_snow5g_nca4_vectors(jctx);
        return errors;
}
