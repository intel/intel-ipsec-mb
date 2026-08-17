/*****************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "mac_test.h"

int
snow5g_nia4_test(struct IMB_MGR *mb_mgr);

static struct mac_test *snow5g_nia4_vectors;

static void
free_snow5g_nia4_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        snow5g_nia4_vectors = NULL;
}

static int
snow5g_nia4_job_ok(const struct mac_test *vec, const struct IMB_JOB *job, const uint8_t *auth,
                   const uint8_t *padding, const size_t sizeof_padding)
{
        const size_t auth_len = job->auth_tag_output_len_in_bytes;

        if (job->status != IMB_STATUS_COMPLETED) {
                printf("%d Error status:%d", __LINE__, job->status);
                return 0;
        }
        /* hash checks */
        if (memcmp(padding, &auth[sizeof_padding + auth_len], sizeof_padding)) {
                printf("hash overwrite tail\n");
                hexdump(stderr, "Target", &auth[sizeof_padding + auth_len], sizeof_padding);
                return 0;
        }

        if (memcmp(padding, &auth[0], sizeof_padding)) {
                printf("hash overwrite head\n");
                hexdump(stderr, "Target", &auth[0], sizeof_padding);
                return 0;
        }

        if (memcmp(vec->tag, &auth[sizeof_padding], auth_len)) {
                printf("hash mismatched\n");
                hexdump(stderr, "Received", &auth[sizeof_padding], auth_len);
                hexdump(stderr, "Expected", vec->tag, auth_len);
                return 0;
        }
        return 1;
}

static int
test_snow5g_nia4(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs)
{
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        int i = 0, jobs_rx = 0, ret = -1;

        if (auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end2;
        }

        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                auths[i] = malloc(16 + (sizeof(padding) * 2));
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }

                memset(auths[i], -1, 16 + (sizeof(padding) * 2));
        }

        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        /**
         * Submit all jobs then flush any outstanding jobs
         */
        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;

                job->hash_alg = IMB_AUTH_SNOW5G_NIA4;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->u.NIA._key = (const void *) vec->key;
                job->u.NIA._iv = (const void *) vec->iv;
                job->src = (const void *) vec->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (!snow5g_nia4_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;

                if (!snow5g_nia4_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }

        ret = 0;

end:
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

static void
test_snow5g_nia4_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                             const int num_jobs)
{
        const struct mac_test *v = snow5g_nia4_vectors;

        if (!quiet_mode)
                printf("SNOW5G-NIA4 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard SNOW5G-NIA4 vector %zu Message length: %zu, "
                               "Tag length:%zu\n",
                               v->tcId, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_snow5g_nia4(mb_mgr, v, num_jobs)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

/* Per-vector context used to verify completed jobs */
struct nia4_seq_job_ctx {
        const struct mac_test *v;
        uint8_t *auth_buf; /* padded auth buffer: [padding | tag | padding] */
};

static void
verify_nia4_seq_job(struct IMB_JOB *job, struct test_suite_context *ctx)
{
        uint8_t padding[16];
        struct nia4_seq_job_ctx *jctx = (struct nia4_seq_job_ctx *) job->user_data;
        const struct mac_test *v = jctx->v;

        memset((void *) padding, -1, sizeof(padding));

        if (!snow5g_nia4_job_ok(v, job, jctx->auth_buf, padding, sizeof(padding)))
                test_suite_update(ctx, 0, 1);
        else
                test_suite_update(ctx, 1, 0);
}

/* Test submitting all vectors without flushing between them, then flush the remaining ones
 * verifying the jobs as the complete */
static void
test_snow5g_nia4_submit_all_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                                    const struct mac_test *vectors)
{
        /* Count vectors */
        size_t n_vec = 0;
        const struct mac_test *v;

        for (v = vectors; v->msg != NULL; v++)
                n_vec++;

        struct nia4_seq_job_ctx *jctxs = calloc(n_vec, sizeof(*jctxs));

        if (!jctxs) {
                fprintf(stderr, "failed to allocate context array\n");
                test_suite_update(ctx, 0, 1);
                return;
        }

        if (!quiet_mode)
                printf("SNOW5G-NIA4 sequential all-vectors test:\n");

        /* Submit all vectors without flushing between them */
        size_t idx = 0;

        for (v = vectors; v->msg != NULL; v++, idx++) {
                struct nia4_seq_job_ctx *jctx = &jctxs[idx];
                struct IMB_JOB *job;

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Vector %zu  Keylen:%zu PTLen:%zu Tlen:%zu\n", v->tcId,
                               v->keySize / 8, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                jctx->v = v;
                /* auth_buf layout: [16-byte head padding | tag | 16-byte tail padding] */
                jctx->auth_buf = malloc(16 + v->tagSize / 8 + 16);
                if (!jctx->auth_buf) {
                        fprintf(stderr, "failed to allocate auth buffer\n");
                        test_suite_update(ctx, 0, 1);
                        goto done;
                }
                memset(jctx->auth_buf, -1, 16 + v->tagSize / 8 + 16);

                job = IMB_GET_NEXT_JOB(mb_mgr);
                if (!job) {
                        fprintf(stderr, "failed to get job\n");
                        test_suite_update(ctx, 0, 1);
                        goto done;
                }

                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = IMB_AUTH_SNOW5G_NIA4;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->u.NIA._key = (const void *) v->key;
                job->u.NIA._iv = (const void *) v->iv;
                job->src = (const void *) v->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = jctx->auth_buf + 16;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;
                job->user_data = jctx;

                job = IMB_SUBMIT_JOB(mb_mgr);

                /* Collect any job that completed immediately during submit */
                if (job != NULL)
                        verify_nia4_seq_job(job, ctx);
        }

        /* Flush and verify remaining in-flight jobs */
        struct IMB_JOB *job;

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                verify_nia4_seq_job(job, ctx);

        if (!quiet_mode)
                printf("\n");

done:
        for (size_t i = 0; i < n_vec; i++)
                free(jctxs[i].auth_buf);
        free(jctxs);
}

int
snow5g_nia4_test(struct IMB_MGR *mb_mgr)
{
        int errors = 0;
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;

        if (load_mac_vectors(kat_vector_dir, "snow5g_nia4_test.json", &snow5g_nia4_vectors, &jctx) <
            0)
                return 1;

        /* SNOW5G-NIA4 with standard vectors */
        test_suite_start(&ctx, "SNOW5G-NIA4");
        for (size_t i = 0; i < test_num_jobs_size; i++)
                test_snow5g_nia4_std_vectors(mb_mgr, &ctx, test_num_jobs[i]);
        test_snow5g_nia4_submit_all_vectors(mb_mgr, &ctx, snow5g_nia4_vectors);
        errors += test_suite_end(&ctx);

        free_snow5g_nia4_vectors(jctx);
        return errors;
}
