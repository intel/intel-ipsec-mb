/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

/*
 * Chained NEA4/5/6 cipher + NIA4/5/6 MAC known answer tests.
 *
 * Vector order "hash_cipher" means the MAC is computed over the plaintext:
 * encrypt uses IMB_ORDER_HASH_CIPHER and decrypt uses IMB_ORDER_CIPHER_HASH.
 * Vector order "cipher_hash" means the MAC is computed over the ciphertext:
 * encrypt uses IMB_ORDER_CIPHER_HASH and decrypt uses IMB_ORDER_HASH_CIPHER.
 *
 * NIA4/5/6 always read the message from job->src +
 * hash_start_src_offset_in_bytes. With IMB_ORDER_CIPHER_HASH the MAC has to
 * cover the cipher output, which is only found at job->src when the operation
 * is in-place. All jobs are therefore tested in-place, and out-of-place jobs
 * are only tested when the job chain order is IMB_ORDER_HASH_CIPHER.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "utils.h"

#define NXA_KEY_SIZE     32
#define NXA_IV_SIZE      16
#define NXA_EXP_KEY_SIZE (15 * IMB_AES_BLOCK_SIZE)
#define NXA_MAX_TAG_SIZE 16
#define NXA_PAD_SIZE     16
#define NXA_MAX_OFFSET   15
#define NXA_PAD_BYTE     0xff

int
nxa_chained_test(struct IMB_MGR *mb_mgr);

/* Per-vector data prepared once: algorithm IDs and job-ready keys */
struct nxa_vec_ctx {
        DECLARE_ALIGNED(uint8_t cipher_key[NXA_EXP_KEY_SIZE], 16);
        DECLARE_ALIGNED(uint8_t mac_key[NXA_EXP_KEY_SIZE], 16);
        const struct chained_test *v;
        IMB_CIPHER_MODE cipher;
        IMB_HASH_ALG hash;
        int mac_over_ct;
};

/* Per-job buffers and test parameters */
struct nxa_job_buf {
        const struct nxa_vec_ctx *vc;
        IMB_CIPHER_DIRECTION dir;
        int in_place;
        int corrupt;
        size_t offset;
        uint8_t *dst_buf;
        uint8_t *src_buf;
        uint8_t tag[NXA_PAD_SIZE + NXA_MAX_TAG_SIZE + NXA_PAD_SIZE];
};

static int
nxa_is_padding(const uint8_t *p, const size_t len)
{
        for (size_t i = 0; i < len; i++)
                if (p[i] != NXA_PAD_BYTE)
                        return 0;

        return 1;
}

static IMB_CHAIN_ORDER
nxa_chain_order(const struct nxa_vec_ctx *vc, const IMB_CIPHER_DIRECTION dir)
{
        if (vc->mac_over_ct)
                return (dir == IMB_DIR_ENCRYPT) ? IMB_ORDER_CIPHER_HASH : IMB_ORDER_HASH_CIPHER;

        return (dir == IMB_DIR_ENCRYPT) ? IMB_ORDER_HASH_CIPHER : IMB_ORDER_CIPHER_HASH;
}

static int
nxa_oop_allowed(const struct nxa_vec_ctx *vc, const IMB_CIPHER_DIRECTION dir)
{
        return nxa_chain_order(vc, dir) == IMB_ORDER_HASH_CIPHER;
}

static int
nxa_vec_ctx_init(struct IMB_MGR *mb_mgr, struct nxa_vec_ctx *vc, const struct chained_test *v)
{
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        int expand_cipher_key = 0;
        int expand_mac_key = 0;

        vc->v = v;

        if (strcmp(v->cipherAlg, "SNOW5G-NEA4") == 0) {
                vc->cipher = IMB_CIPHER_SNOW5G_NEA4;
        } else if (strcmp(v->cipherAlg, "AES-NEA5") == 0) {
                vc->cipher = IMB_CIPHER_AES_NEA5;
                expand_cipher_key = 1;
        } else if (strcmp(v->cipherAlg, "ZUC-NEA6") == 0) {
                vc->cipher = IMB_CIPHER_ZUC_NEA6;
        } else {
                printf("NXA chained: unsupported cipherAlg '%s'\n", v->cipherAlg);
                return -1;
        }

        if (strcmp(v->macAlg, "SNOW5G-NIA4") == 0) {
                vc->hash = IMB_AUTH_SNOW5G_NIA4;
        } else if (strcmp(v->macAlg, "AES-NIA5") == 0) {
                vc->hash = IMB_AUTH_AES_NIA5;
                expand_mac_key = 1;
        } else if (strcmp(v->macAlg, "ZUC-NIA6") == 0) {
                vc->hash = IMB_AUTH_ZUC_NIA6;
        } else {
                printf("NXA chained: unsupported macAlg '%s'\n", v->macAlg);
                return -1;
        }

        if (v->cipherKeySize != NXA_KEY_SIZE * 8 || v->cipherIvSize != NXA_IV_SIZE * 8 ||
            v->macKeySize != NXA_KEY_SIZE * 8 || v->macIvSize != NXA_IV_SIZE * 8 ||
            v->tagSize == 0 || v->tagSize > NXA_MAX_TAG_SIZE * 8 || (v->tagSize % 8) != 0 ||
            v->msgSize == 0 || (v->msgSize % 8) != 0) {
                printf("NXA chained: unsupported sizes in vector #%zu\n", v->tcId);
                return -1;
        }

        vc->mac_over_ct = (strcmp(v->order, "cipher_hash") == 0);

        /* NEA5 and NIA5 take the AES-256 encryption key schedule */
        if (expand_cipher_key)
                IMB_AES_KEYEXP_256(mb_mgr, v->cipherKey, vc->cipher_key, dust);
        else
                memcpy(vc->cipher_key, v->cipherKey, NXA_KEY_SIZE);

        if (expand_mac_key)
                IMB_AES_KEYEXP_256(mb_mgr, v->macKey, vc->mac_key, dust);
        else
                memcpy(vc->mac_key, v->macKey, NXA_KEY_SIZE);

        return 0;
}

static void
nxa_buf_free(struct nxa_job_buf *b)
{
        free(b->dst_buf);
        free(b->src_buf);
        b->dst_buf = NULL;
        b->src_buf = NULL;
}

/*
 * Prepare job buffers. The destination buffer holds leading padding, the
 * cipher/hash offset, the message and trailing padding. For out-of-place jobs
 * the input is placed at the same offset in a separate source buffer.
 */
static int
nxa_buf_init(struct nxa_job_buf *b, const struct nxa_vec_ctx *vc, const IMB_CIPHER_DIRECTION dir,
             const int in_place, const int corrupt, const size_t offset)
{
        const size_t len = vc->v->msgSize / 8;
        const size_t dst_buf_len = NXA_PAD_SIZE + offset + len + NXA_PAD_SIZE;
        const uint8_t *in = (const uint8_t *) ((dir == IMB_DIR_ENCRYPT) ? vc->v->msg : vc->v->ct);
        uint8_t *in_buf;

        b->vc = vc;
        b->dir = dir;
        b->in_place = in_place;
        b->corrupt = corrupt;
        b->offset = offset;
        b->src_buf = NULL;
        memset(b->tag, NXA_PAD_BYTE, sizeof(b->tag));

        b->dst_buf = malloc(dst_buf_len);
        if (b->dst_buf == NULL)
                return -1;
        memset(b->dst_buf, NXA_PAD_BYTE, dst_buf_len);

        if (in_place) {
                in_buf = b->dst_buf + NXA_PAD_SIZE + offset;
        } else {
                b->src_buf = malloc(offset + len);
                if (b->src_buf == NULL) {
                        nxa_buf_free(b);
                        return -1;
                }
                memset(b->src_buf, NXA_PAD_BYTE, offset + len);
                in_buf = b->src_buf + offset;
        }

        memcpy(in_buf, in, len);
        if (corrupt)
                in_buf[len / 2] ^= 0x01;

        return 0;
}

static void
nxa_job_fill(struct IMB_MGR *mb_mgr, IMB_JOB *job, struct nxa_job_buf *b, const int set_session)
{
        const struct nxa_vec_ctx *vc = b->vc;
        const struct chained_test *v = vc->v;
        const uint64_t len = (uint64_t) (v->msgSize / 8);
        uint8_t *dst = b->dst_buf + NXA_PAD_SIZE + b->offset;

        job->cipher_direction = b->dir;
        job->chain_order = nxa_chain_order(vc, b->dir);
        job->cipher_mode = vc->cipher;
        job->hash_alg = vc->hash;

        job->enc_keys = vc->cipher_key;
        job->dec_keys = vc->cipher_key;
        job->key_len_in_bytes = NXA_KEY_SIZE;
        job->iv = (const uint8_t *) v->cipherIv;
        job->iv_len_in_bytes = NXA_IV_SIZE;

        job->src = b->in_place ? (dst - b->offset) : b->src_buf;
        job->dst = dst;
        job->cipher_start_src_offset_in_bytes = b->offset;
        job->msg_len_to_cipher_in_bytes = len;
        job->hash_start_src_offset_in_bytes = b->offset;
        job->msg_len_to_hash_in_bytes = len;

        job->u.NIA._key = vc->mac_key;
        job->u.NIA._iv = (const uint8_t *) v->macIv;
        job->auth_tag_output = b->tag + NXA_PAD_SIZE;
        job->auth_tag_output_len_in_bytes = v->tagSize / 8;
        job->user_data = b;

        if (set_session)
                imb_set_session(mb_mgr, job);
}

static const char *
nxa_job_label(const struct nxa_job_buf *b)
{
        if (b->dir == IMB_DIR_ENCRYPT)
                return b->in_place ? "encrypt in-place" : "encrypt out-of-place";

        return b->in_place ? "decrypt in-place" : "decrypt out-of-place";
}

static int
nxa_job_check(const IMB_JOB *job)
{
        const struct nxa_job_buf *b = (const struct nxa_job_buf *) job->user_data;
        const struct chained_test *v = b->vc->v;
        const size_t len = v->msgSize / 8;
        const size_t tag_len = v->tagSize / 8;
        const uint8_t *exp = (const uint8_t *) ((b->dir == IMB_DIR_ENCRYPT) ? v->ct : v->msg);
        const uint8_t *out = b->dst_buf + NXA_PAD_SIZE + b->offset;
        const uint8_t *tag = b->tag + NXA_PAD_SIZE;
        const int exp_match = v->resultValid && !b->corrupt;
        int tag_match;

        if (job->status != IMB_STATUS_COMPLETED) {
                printf("tcId %zu %s %s: job status %d\n", v->tcId, nxa_job_label(b),
                       b->corrupt ? "corrupted" : "", (int) job->status);
                return -1;
        }

        if (!nxa_is_padding(b->dst_buf, NXA_PAD_SIZE + b->offset)) {
                printf("tcId %zu %s: overwrite before output\n", v->tcId, nxa_job_label(b));
                return -1;
        }

        if (!nxa_is_padding(out + len, NXA_PAD_SIZE)) {
                printf("tcId %zu %s: overwrite after output\n", v->tcId, nxa_job_label(b));
                return -1;
        }

        if (!b->corrupt && memcmp(out, exp, len) != 0) {
                printf("tcId %zu %s: output mismatch\n", v->tcId, nxa_job_label(b));
                hexdump(stdout, "Received", out, len);
                hexdump(stdout, "Expected", exp, len);
                return -1;
        }

        if (!nxa_is_padding(b->tag, NXA_PAD_SIZE) || !nxa_is_padding(tag + tag_len, NXA_PAD_SIZE)) {
                printf("tcId %zu %s: tag buffer overwrite\n", v->tcId, nxa_job_label(b));
                return -1;
        }

        tag_match = (memcmp(tag, v->tag, tag_len) == 0);
        if (tag_match != exp_match) {
                printf("tcId %zu %s%s: tag %s\n", v->tcId, nxa_job_label(b),
                       b->corrupt ? " corrupted input" : "",
                       exp_match ? "mismatch" : "corruption not detected");
                hexdump(stdout, "Received", tag, tag_len);
                hexdump(stdout, "Expected", v->tag, tag_len);
                return -1;
        }

        return 0;
}

/* Submit num_jobs copies of one vector with IMB_SUBMIT_JOB and IMB_FLUSH_JOB */
static int
nxa_test_job_api(struct IMB_MGR *mb_mgr, const struct nxa_vec_ctx *vc,
                 const IMB_CIPHER_DIRECTION dir, const int in_place, const int corrupt,
                 const unsigned num_jobs)
{
        struct nxa_job_buf *bufs;
        IMB_JOB *job;
        unsigned i, jobs_rx = 0;
        int ret = -1;

        bufs = calloc(num_jobs, sizeof(*bufs));
        if (bufs == NULL)
                return -1;

        for (i = 0; i < num_jobs; i++)
                if (nxa_buf_init(&bufs[i], vc, dir, in_place, corrupt, 1 + (i % NXA_MAX_OFFSET)) <
                    0)
                        goto end;

        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                nxa_job_fill(mb_mgr, job, &bufs[i], 0);

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (nxa_job_check(job) < 0)
                                goto end;
                } else {
                        const int err = imb_get_errno(mb_mgr);

                        if (err != 0) {
                                printf("submit_job error %d : '%s'\n", err, imb_get_strerror(err));
                                goto end;
                        }
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (nxa_job_check(job) < 0)
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto end;
        }

        ret = 0;
end:
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++)
                nxa_buf_free(&bufs[i]);
        free(bufs);

        return ret;
}

static void
nxa_test_vectors_job_api(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                         const struct nxa_vec_ctx *vcs, const size_t num_vecs,
                         const unsigned num_jobs)
{
        static const IMB_CIPHER_DIRECTION dirs[] = { IMB_DIR_ENCRYPT, IMB_DIR_DECRYPT };

        if (!quiet_mode)
                printf("NEA/NIA chained test vectors (N jobs = %u):\n", num_jobs);

        for (size_t n = 0; n < num_vecs; n++) {
                const struct nxa_vec_ctx *vc = &vcs[n];

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Vector %zu %s + %s %s MsgSize:%zu TagSize:%zu\n", vc->v->tcId,
                               vc->v->cipherAlg, vc->v->macAlg, vc->v->order, vc->v->msgSize / 8,
                               vc->v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                for (size_t d = 0; d < DIM(dirs); d++) {
                        for (int in_place = 1; in_place >= 0; in_place--) {
                                if (!in_place && !nxa_oop_allowed(vc, dirs[d]))
                                        continue;

                                if (nxa_test_job_api(mb_mgr, vc, dirs[d], in_place, 0, num_jobs))
                                        test_suite_update(ctx, 0, 1);
                                else
                                        test_suite_update(ctx, 1, 0);
                        }

                        /* negative case: corrupted input must not match the tag */
                        if (vc->v->resultValid) {
                                if (nxa_test_job_api(mb_mgr, vc, dirs[d], 1, 1, num_jobs))
                                        test_suite_update(ctx, 0, 1);
                                else
                                        test_suite_update(ctx, 1, 0);
                        }
                }
        }

        if (!quiet_mode)
                printf("\n");
}

/* Submit one burst of jobs, each job may use a different cipher/MAC pair */
static int
nxa_test_burst_api(struct IMB_MGR *mb_mgr, struct nxa_job_buf *bufs, const uint32_t num_jobs)
{
        IMB_JOB *jobs[IMB_MAX_BURST_SIZE] = { NULL };
        uint32_t i, completed_jobs, jobs_rx = 0;
        int ret = -1;

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (i = 0; i < num_jobs; i++)
                nxa_job_fill(mb_mgr, jobs[i], &bufs[i], 1);

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        if (completed_jobs == 0) {
                const int err = imb_get_errno(mb_mgr);

                if (err != 0) {
                        printf("submit_burst error %d : '%s'\n", err, imb_get_strerror(err));
                        goto end;
                }
        }

        for (;;) {
                for (i = 0; i < completed_jobs; i++)
                        if (nxa_job_check(jobs[i]) < 0)
                                goto end;

                jobs_rx += completed_jobs;
                if (jobs_rx >= num_jobs)
                        break;

                completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs - jobs_rx, jobs);
                if (completed_jobs == 0) {
                        printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                        goto end;
                }
        }

        ret = 0;
end:
        while (IMB_FLUSH_BURST(mb_mgr, IMB_MAX_BURST_SIZE, jobs) > 0)
                ;

        return ret;
}

/*
 * Run all vectors through the burst API. Vectors are visited with a stride
 * co-prime to the vector count so each burst mixes cipher/MAC pairs, chain
 * orders, directions and in-place/out-of-place jobs.
 */
static void
nxa_test_vectors_burst_api(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                           const struct nxa_vec_ctx *vcs, const size_t num_vecs,
                           const uint32_t burst_size)
{
        struct nxa_job_buf bufs[IMB_MAX_BURST_SIZE];
        size_t stride = 37;
        size_t a, b;

        if (!quiet_mode)
                printf("NEA/NIA chained test vectors - Burst API (N jobs = %u):\n", burst_size);

        /* select the smallest stride >= 37 that is co-prime to num_vecs */
        for (;; stride++) {
                a = stride;
                b = num_vecs;
                while (b != 0) {
                        const size_t t = a % b;

                        a = b;
                        b = t;
                }
                if (a == 1)
                        break;
        }

        /* two passes so every vector is run for both directions */
        for (size_t pos = 0; pos < 2 * num_vecs; pos += burst_size) {
                uint32_t n = 0;
                int ret = -1;

                for (size_t k = pos; k < 2 * num_vecs && n < burst_size; k++, n++) {
                        const size_t j = k % num_vecs;
                        const struct nxa_vec_ctx *vc = &vcs[(j * stride) % num_vecs];
                        const IMB_CIPHER_DIRECTION dir =
                                ((j + k / num_vecs) & 1) ? IMB_DIR_DECRYPT : IMB_DIR_ENCRYPT;
                        const int in_place = (k % 3) != 0 || !nxa_oop_allowed(vc, dir);

                        if (nxa_buf_init(&bufs[n], vc, dir, in_place, 0, 1 + (k % NXA_MAX_OFFSET)) <
                            0)
                                goto burst_end;
                }

                if (!quiet_mode)
                        printf(".");

                ret = nxa_test_burst_api(mb_mgr, bufs, n);
        burst_end:
                for (uint32_t i = 0; i < n; i++)
                        nxa_buf_free(&bufs[i]);

                if (ret != 0)
                        test_suite_update(ctx, 0, 1);
                else
                        test_suite_update(ctx, 1, 0);
        }

        if (!quiet_mode)
                printf("\n");
}

int
nxa_chained_test(struct IMB_MGR *mb_mgr)
{
        static const unsigned job_counts[] = { 1, 3, 8, 17, TEST_MAX_NUM_JOBS };
        static const uint32_t burst_sizes[] = { TEST_MAX_NUM_JOBS, IMB_MAX_BURST_SIZE };
        struct test_json_alloc_ctx *jctx = NULL;
        struct chained_test *vectors = NULL;
        struct nxa_vec_ctx *vcs = NULL;
        struct test_suite_context ctx;
        size_t num_vecs = 0;
        int errors = 0;

        if (load_chained_vectors(kat_vector_dir, "nxa_chained_test.json", &vectors, &jctx) < 0 ||
            vectors == NULL)
                return 1;

        while (vectors[num_vecs].msg != NULL)
                num_vecs++;

        if (num_vecs == 0) {
                json_free_test_ctx(jctx);
                return 1;
        }

        vcs = test_aligned_alloc(64, num_vecs * sizeof(*vcs));
        if (vcs == NULL) {
                json_free_test_ctx(jctx);
                return 1;
        }

        for (size_t n = 0; n < num_vecs; n++) {
                if (nxa_vec_ctx_init(mb_mgr, &vcs[n], &vectors[n]) < 0) {
                        errors = 1;
                        goto end;
                }
        }

        test_suite_start(&ctx, "NXA-CHAINED");
        for (size_t i = 0; i < DIM(job_counts); i++)
                nxa_test_vectors_job_api(mb_mgr, &ctx, vcs, num_vecs, job_counts[i]);
        for (size_t i = 0; i < DIM(burst_sizes); i++)
                nxa_test_vectors_burst_api(mb_mgr, &ctx, vcs, num_vecs, burst_sizes[i]);
        errors += test_suite_end(&ctx);

end:
        test_aligned_free(vcs);
        json_free_test_ctx(jctx);

        return errors;
}
