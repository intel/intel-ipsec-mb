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

#define NCA4_MAX_BUF 128

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
                out[i] = malloc(NCA4_MAX_BUF);
                tag[i] = malloc(16);
                if (!out[i] || !tag[i]) {
                        fprintf(stderr, "failed to allocate memory\n");
                        test_suite_update(ts, 0, 1);
                        goto done;
                }
        }

        for (i = 0; i < 2; i++) {
                memset(out[i], 0, NCA4_MAX_BUF);
                memset(tag[i], 0, 16);
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
};

static void
verify_seq_job(IMB_JOB *job, struct test_suite_context *ts)
{
        struct seq_job_ctx *ctx = (struct seq_job_ctx *) job->user_data;
        const struct aead_test *v = ctx->v;
        const uint64_t msg_len = v->msgSize / 8;
        const uint64_t tag_len = v->tagSize / 8;
        int err = 0;

        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "sequential: job failed, status:%d\n", job->status);
                test_suite_update(ts, 0, 1);
                return;
        }

        if (msg_len > 0)
                err |= check_data(ctx->out, (const uint8_t *) v->ct, msg_len, "sequential out");
        err |= check_data(ctx->tag, (const uint8_t *) v->tag, tag_len, "sequential tag");
        test_suite_update(ts, err == 0, err != 0);
}

/* Test submitting all vectors without flushing between them, then flush the remaining ones
 * verifying the jobs as the complete */
static void
test_snow5g_nca4_submit_all_vectors(IMB_MGR *mb_mgr, struct test_suite_context *ts,
                                    const struct aead_test *vectors)
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
                printf("SNOW5G-NCA4 sequential all-vectors test:\n");

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
                ctx->out = malloc(msg_len > 0 ? msg_len : 1);
                ctx->tag = malloc(tag_len);
                if (!ctx->out || !ctx->tag) {
                        fprintf(stderr, "failed to allocate memory\n");
                        test_suite_update(ts, 0, 1);
                        goto done;
                }
                memset(ctx->out, 0, msg_len > 0 ? msg_len : 1);
                memset(ctx->tag, 0, tag_len);

                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (!job) {
                        fprintf(stderr, "failed to get job\n");
                        test_suite_update(ts, 0, 1);
                        goto done;
                }

                fill_nca4_job(job, v, IMB_DIR_ENCRYPT, (const uint8_t *) v->msg, ctx->out,
                              ctx->tag);
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

        test_snow5g_nca4_submit_all_vectors(p_mgr, &ts, snow5g_nca4_vectors);

        errors += test_suite_end(&ts);

        free_snow5g_nca4_vectors(jctx);
        return errors;
}
