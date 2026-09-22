/*****************************************************************************
 Copyright (c) 2020-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "aead_test.h"
#include "kat_common_aead.h"
#include "wycheproof_test.h"

#define AAD_SZ    24
#define DIGEST_SZ 16

int
chacha20_poly1305_test(struct IMB_MGR *mb_mgr);

static struct aead_test *chacha20_poly1305_vectors;

static void
free_chacha20_poly1305_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        chacha20_poly1305_vectors = NULL;
}

static int
chacha20_poly1305_job_prepare(IMB_MGR *mb_mgr, IMB_JOB *job, const struct aead_test *vec,
                              const void *ctx)
{
        (void) mb_mgr;
        (void) ctx;
        job->enc_keys = (const void *) vec->key;
        job->dec_keys = (const void *) vec->key;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
        job->u.CHACHA20_POLY1305.aad = (const void *) vec->aad;
        job->u.CHACHA20_POLY1305.aad_len_in_bytes = vec->aadSize / 8;
        return 0;
}

static void
test_chacha20_poly1305_vectors(IMB_MGR *p_mgr, const struct aead_test *vector,
                               struct test_suite_context *ts, const int num_jobs)
{
        static const struct kat_aead_job_ops encrypt_ops = {
                .prepare = chacha20_poly1305_job_prepare,
                .cipher_mode = IMB_CIPHER_CHACHA20_POLY1305,
                .hash_alg = IMB_AUTH_CHACHA20_POLY1305,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE,
                .in_place = 0,
        };
        static const struct kat_aead_job_ops encrypt_in_place_ops = {
                .prepare = chacha20_poly1305_job_prepare,
                .cipher_mode = IMB_CIPHER_CHACHA20_POLY1305,
                .hash_alg = IMB_AUTH_CHACHA20_POLY1305,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE,
                .in_place = 1,
        };
        static const struct kat_aead_job_ops decrypt_ops = {
                .prepare = chacha20_poly1305_job_prepare,
                .cipher_mode = IMB_CIPHER_CHACHA20_POLY1305,
                .hash_alg = IMB_AUTH_CHACHA20_POLY1305,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE,
                .in_place = 0,
        };
        static const struct kat_aead_job_ops decrypt_in_place_ops = {
                .prepare = chacha20_poly1305_job_prepare,
                .cipher_mode = IMB_CIPHER_CHACHA20_POLY1305,
                .hash_alg = IMB_AUTH_CHACHA20_POLY1305,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE,
                .in_place = 1,
        };

        const struct kat_aead_job_ops *ops[] = { &encrypt_ops, &encrypt_in_place_ops, &decrypt_ops,
                                                 &decrypt_in_place_ops };

        for (size_t i = 0; i < DIM(ops); i++) {
                if (kat_aead_test(p_mgr, &vector, 1, num_jobs, ops[i], NULL,
                                  KAT_AEAD_SUBMIT_FLUSH) < 0) {
                        test_suite_update(ts, 0, 1);
                        return;
                }
                test_suite_update(ts, 1, 0);

                if (kat_aead_test(p_mgr, &vector, 1, num_jobs, ops[i], NULL, KAT_AEAD_BURST) < 0) {
                        test_suite_update(ts, 0, 1);
                        return;
                }
                test_suite_update(ts, 1, 0);
        }

        if (num_jobs == 1) {
                if (kat_aead_test(p_mgr, &vector, 1, 1, &encrypt_ops, &decrypt_ops,
                                  KAT_AEAD_ROUND_TRIP) < 0) {
                        test_suite_update(ts, 0, 1);
                        return;
                }
                test_suite_update(ts, 1, 0);
        }
}

static void
test_aead_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs,
                  const struct aead_test *v)
{
        if (!quiet_mode)
                printf("AEAD Chacha20-Poly1305 vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Vector %zu, M len: %zu\n", v->tcId, v->msgSize / 8);
#else
                        printf(".");
#endif
                }

                test_chacha20_poly1305_vectors(mb_mgr, v, ctx, num_jobs);
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_single_job_sgl(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                    const uint32_t buffer_sz, const uint32_t seg_sz,
                    const IMB_CIPHER_DIRECTION cipher_dir)
{
        struct IMB_JOB *job;
        uint8_t *in_buffer = NULL;
        uint8_t **segments = NULL;
        uint8_t linear_digest[DIGEST_SZ];
        uint8_t sgl_digest[DIGEST_SZ];
        uint8_t key[IMB_CHACHA20_POLY1305_KEY_SIZE];
        unsigned i;
        uint8_t aad[AAD_SZ];
        uint8_t iv[IMB_CHACHA20_POLY1305_IV_SIZE];
        struct chacha20_poly1305_context_data chacha_ctx;
        uint32_t last_seg_sz = buffer_sz % seg_sz;
        struct IMB_SGL_IOV *sgl_segs = NULL;
        const uint32_t num_segments = DIV_ROUND_UP(buffer_sz, seg_sz);

        sgl_segs = malloc(sizeof(struct IMB_SGL_IOV) * num_segments);
        if (sgl_segs == NULL) {
                fprintf(stderr, "Could not allocate memory for SGL segments\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }

        if (last_seg_sz == 0)
                last_seg_sz = seg_sz;

        in_buffer = malloc(buffer_sz);
        if (in_buffer == NULL) {
                fprintf(stderr, "Could not allocate memory for input buffer\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }

        /*
         * Initialize tags with different values, to make sure the comparison
         * is false if they are not updated by the library
         */
        memset(sgl_digest, 0, DIGEST_SZ);
        memset(linear_digest, 0xFF, DIGEST_SZ);

        generate_random_buf(in_buffer, buffer_sz);
        generate_random_buf(key, IMB_CHACHA20_POLY1305_KEY_SIZE);
        generate_random_buf(iv, IMB_CHACHA20_POLY1305_IV_SIZE);
        generate_random_buf(aad, AAD_SZ);

        segments = malloc(num_segments * sizeof(*segments));
        if (segments == NULL) {
                fprintf(stderr, "Could not allocate memory for segments array\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }
        memset(segments, 0, num_segments * sizeof(*segments));

        for (i = 0; i < (num_segments - 1); i++) {
                segments[i] = malloc(seg_sz);
                if (segments[i] == NULL) {
                        fprintf(stderr, "Could not allocate memory for segment %u\n", i);
                        test_suite_update(ctx, 0, 1);
                        goto exit;
                }
                memcpy(segments[i], in_buffer + seg_sz * i, seg_sz);
                sgl_segs[i].in = segments[i];
                sgl_segs[i].out = segments[i];
                sgl_segs[i].len = seg_sz;
        }
        segments[i] = malloc(last_seg_sz);
        if (segments[i] == NULL) {
                fprintf(stderr, "Could not allocate memory for segment %u\n", i);
                test_suite_update(ctx, 0, 1);
                goto exit;
        }
        memcpy(segments[i], in_buffer + seg_sz * i, last_seg_sz);
        sgl_segs[i].in = segments[i];
        sgl_segs[i].out = segments[i];
        sgl_segs[i].len = last_seg_sz;

        /* Process linear (single segment) buffer */
        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = cipher_dir;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
        job->hash_alg = IMB_AUTH_CHACHA20_POLY1305;
        job->enc_keys = key;
        job->dec_keys = key;
        job->src = in_buffer;
        job->dst = in_buffer;
        job->key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE;

        job->u.CHACHA20_POLY1305.aad = aad;
        job->u.CHACHA20_POLY1305.aad_len_in_bytes = AAD_SZ;

        job->iv = iv;
        job->iv_len_in_bytes = IMB_CHACHA20_POLY1305_IV_SIZE;
        job->msg_len_to_cipher_in_bytes = buffer_sz;
        job->cipher_start_src_offset_in_bytes = 0;

        job->msg_len_to_hash_in_bytes = buffer_sz;
        job->hash_start_src_offset_in_bytes = 0;
        job->auth_tag_output = linear_digest;
        job->auth_tag_output_len_in_bytes = DIGEST_SZ;

        job = IMB_SUBMIT_JOB(mb_mgr);

        if (job->status == IMB_STATUS_COMPLETED)
                test_suite_update(ctx, 1, 0);
        else {
                fprintf(stderr, "job status returned as not successful"
                                " for the linear buffer\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }

        /* Process multi-segment buffer */
        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = cipher_dir;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305_SGL;
        job->hash_alg = IMB_AUTH_CHACHA20_POLY1305_SGL;
        job->enc_keys = key;
        job->dec_keys = key;
        job->key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE;

        job->u.CHACHA20_POLY1305.aad = aad;
        job->u.CHACHA20_POLY1305.aad_len_in_bytes = AAD_SZ;
        job->u.CHACHA20_POLY1305.ctx = &chacha_ctx;

        job->iv = iv;
        job->iv_len_in_bytes = IMB_CHACHA20_POLY1305_IV_SIZE;
        job->cipher_start_src_offset_in_bytes = 0;

        job->hash_start_src_offset_in_bytes = 0;
        job->auth_tag_output = sgl_digest;
        job->auth_tag_output_len_in_bytes = DIGEST_SZ;

        job->num_sgl_io_segs = num_segments;
        job->sgl_state = IMB_SGL_ALL;
        job->sgl_io_segs = sgl_segs;
        job = IMB_SUBMIT_JOB(mb_mgr);

        if (job->status == IMB_STATUS_COMPLETED) {
                for (i = 0; i < (num_segments - 1); i++) {
                        if (memcmp(in_buffer + i * seg_sz, segments[i], seg_sz) != 0) {
                                printf("ciphertext mismatched "
                                       "in segment number %u "
                                       "(segment size = %u)\n",
                                       i, seg_sz);
                                hexdump(stderr, "Linear output", in_buffer + i * seg_sz, seg_sz);
                                hexdump(stderr, "SGL output", segments[i], seg_sz);
                                test_suite_update(ctx, 0, 1);
                                goto exit;
                        }
                }
                /* Check last segment */
                if (memcmp(in_buffer + i * seg_sz, segments[i], last_seg_sz) != 0) {
                        printf("ciphertext mismatched "
                               "in segment number %u (segment size = %u)\n",
                               i, seg_sz);
                        hexdump(stderr, "Linear output", in_buffer + i * seg_sz, last_seg_sz);
                        hexdump(stderr, "SGL output", segments[i], last_seg_sz);
                        test_suite_update(ctx, 0, 1);
                }
                if (memcmp(sgl_digest, linear_digest, 16) != 0) {
                        printf("hash mismatched (segment size = %u)\n", seg_sz);
                        hexdump(stderr, "Linear digest", linear_digest, DIGEST_SZ);
                        hexdump(stderr, "SGL digest", sgl_digest, DIGEST_SZ);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        } else {
                fprintf(stderr, "job status returned as not successful"
                                " for the segmented buffer\n");
                test_suite_update(ctx, 0, 1);
        }

exit:
        free(sgl_segs);
        free(in_buffer);
        if (segments != NULL) {
                for (i = 0; i < num_segments; i++)
                        free(segments[i]);
                free(segments);
        }
}

static void
test_sgl(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const uint32_t buffer_sz,
         const uint32_t seg_sz, const IMB_CIPHER_DIRECTION cipher_dir, const unsigned job_api,
         const unsigned encrypt_on_update_only)
{
        struct IMB_JOB *job;
        uint8_t *in_buffer = NULL;
        uint8_t **segments = NULL;
        uint32_t *segment_sizes = NULL;
        uint32_t num_segments;
        uint8_t linear_digest[DIGEST_SZ];
        uint8_t sgl_digest[DIGEST_SZ];
        uint8_t key[IMB_CHACHA20_POLY1305_KEY_SIZE];
        unsigned int i, segments_to_update;
        uint8_t aad[AAD_SZ];
        uint8_t iv[IMB_CHACHA20_POLY1305_IV_SIZE];
        struct chacha20_poly1305_context_data chacha_ctx;
        uint32_t last_seg_sz = buffer_sz % seg_sz;

        num_segments = (buffer_sz + (seg_sz - 1)) / seg_sz;
        if (last_seg_sz == 0)
                last_seg_sz = seg_sz;

        in_buffer = malloc(buffer_sz);
        if (in_buffer == NULL) {
                fprintf(stderr, "Could not allocate memory for input buffer\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }

        /*
         * Initialize tags with different values, to make sure the comparison
         * is false if they are not updated by the library
         */
        memset(sgl_digest, 0, DIGEST_SZ);
        memset(linear_digest, 0xFF, DIGEST_SZ);

        generate_random_buf(in_buffer, buffer_sz);
        generate_random_buf(key, IMB_CHACHA20_POLY1305_KEY_SIZE);
        generate_random_buf(iv, IMB_CHACHA20_POLY1305_IV_SIZE);
        generate_random_buf(aad, AAD_SZ);

        segments = malloc(num_segments * sizeof(*segments));
        if (segments == NULL) {
                fprintf(stderr, "Could not allocate memory for segments array\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }
        memset(segments, 0, num_segments * sizeof(*segments));

        segment_sizes = malloc(num_segments * sizeof(*segment_sizes));
        if (segment_sizes == NULL) {
                fprintf(stderr, "Could not allocate memory for array of sizes\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }

        for (i = 0; i < (num_segments - 1); i++) {
                segments[i] = malloc(seg_sz);
                if (segments[i] == NULL) {
                        fprintf(stderr, "Could not allocate memory for segment %u\n", i);
                        test_suite_update(ctx, 0, 1);
                        goto exit;
                }
                memcpy(segments[i], in_buffer + seg_sz * i, seg_sz);
                segment_sizes[i] = seg_sz;
        }
        segments[i] = malloc(last_seg_sz);
        if (segments[i] == NULL) {
                fprintf(stderr, "Could not allocate memory for segment %u\n", i);
                test_suite_update(ctx, 0, 1);
                goto exit;
        }
        memcpy(segments[i], in_buffer + seg_sz * i, last_seg_sz);
        segment_sizes[i] = last_seg_sz;

        /* Process linear (single segment) buffer */
        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = cipher_dir;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
        job->hash_alg = IMB_AUTH_CHACHA20_POLY1305;
        job->enc_keys = key;
        job->dec_keys = key;
        job->src = in_buffer;
        job->dst = in_buffer;
        job->key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE;

        job->u.CHACHA20_POLY1305.aad = aad;
        job->u.CHACHA20_POLY1305.aad_len_in_bytes = AAD_SZ;

        job->iv = iv;
        job->iv_len_in_bytes = IMB_CHACHA20_POLY1305_IV_SIZE;
        job->msg_len_to_cipher_in_bytes = buffer_sz;
        job->cipher_start_src_offset_in_bytes = 0;

        job->msg_len_to_hash_in_bytes = buffer_sz;
        job->hash_start_src_offset_in_bytes = 0;
        job->auth_tag_output = linear_digest;
        job->auth_tag_output_len_in_bytes = DIGEST_SZ;

        job = IMB_SUBMIT_JOB(mb_mgr);

        if (job->status == IMB_STATUS_COMPLETED)
                test_suite_update(ctx, 1, 0);
        else {
                fprintf(stderr, "job status returned as not successful"
                                " for the linear buffer\n");
                test_suite_update(ctx, 0, 1);
                goto exit;
        }

        /* Process multi-segment buffer */
        if (job_api) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = cipher_dir;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305_SGL;
                job->hash_alg = IMB_AUTH_CHACHA20_POLY1305_SGL;
                job->enc_keys = key;
                job->dec_keys = key;
                job->key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE;

                job->u.CHACHA20_POLY1305.aad = aad;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = AAD_SZ;
                job->u.CHACHA20_POLY1305.ctx = &chacha_ctx;

                job->iv = iv;
                job->iv_len_in_bytes = IMB_CHACHA20_POLY1305_IV_SIZE;
                job->cipher_start_src_offset_in_bytes = 0;

                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = sgl_digest;
                job->auth_tag_output_len_in_bytes = DIGEST_SZ;

                if (encrypt_on_update_only) {
                        i = 0; /* Start update from segment 0 */
                        segments_to_update = num_segments;
                        job->src = NULL;
                        job->dst = NULL;
                        job->msg_len_to_cipher_in_bytes = 0;
                        job->msg_len_to_hash_in_bytes = 0;
                } else {
                        i = 1; /* Start update from segment 1 */
                        segments_to_update = num_segments - 1;
                        job->src = segments[0];
                        job->dst = segments[0];
                        job->msg_len_to_cipher_in_bytes = segment_sizes[0];
                        job->msg_len_to_hash_in_bytes = segment_sizes[0];
                }
                job->sgl_state = IMB_SGL_INIT;
                job = IMB_SUBMIT_JOB(mb_mgr);
        } else {
                IMB_CHACHA20_POLY1305_INIT(mb_mgr, key, &chacha_ctx, iv, aad, AAD_SZ);
                i = 0; /* Start update from segment 0 */
                segments_to_update = num_segments;
        }

        for (; i < segments_to_update; i++) {
                if (job_api) {
                        job = IMB_GET_NEXT_JOB(mb_mgr);
                        job->cipher_direction = cipher_dir;
                        job->chain_order = IMB_ORDER_HASH_CIPHER;
                        job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305_SGL;
                        job->hash_alg = IMB_AUTH_CHACHA20_POLY1305_SGL;
                        job->enc_keys = key;
                        job->dec_keys = key;
                        job->key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE;

                        job->u.CHACHA20_POLY1305.aad = aad;
                        job->u.CHACHA20_POLY1305.aad_len_in_bytes = AAD_SZ;
                        job->u.CHACHA20_POLY1305.ctx = &chacha_ctx;

                        job->iv = iv;
                        job->iv_len_in_bytes = IMB_CHACHA20_POLY1305_IV_SIZE;
                        job->cipher_start_src_offset_in_bytes = 0;

                        job->hash_start_src_offset_in_bytes = 0;
                        job->auth_tag_output = sgl_digest;
                        job->auth_tag_output_len_in_bytes = DIGEST_SZ;
                        job->src = segments[i];
                        job->dst = segments[i];
                        job->msg_len_to_cipher_in_bytes = segment_sizes[i];
                        job->msg_len_to_hash_in_bytes = segment_sizes[i];
                        job->sgl_state = IMB_SGL_UPDATE;
                        job = IMB_SUBMIT_JOB(mb_mgr);
                } else {
                        if (cipher_dir == IMB_DIR_ENCRYPT)
                                IMB_CHACHA20_POLY1305_ENC_UPDATE(mb_mgr, key, &chacha_ctx,
                                                                 segments[i], segments[i],
                                                                 segment_sizes[i]);
                        else
                                IMB_CHACHA20_POLY1305_DEC_UPDATE(mb_mgr, key, &chacha_ctx,
                                                                 segments[i], segments[i],
                                                                 segment_sizes[i]);
                }
        }

        if (job_api) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = cipher_dir;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305_SGL;
                job->hash_alg = IMB_AUTH_CHACHA20_POLY1305_SGL;
                job->enc_keys = key;
                job->dec_keys = key;
                job->key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE;

                job->u.CHACHA20_POLY1305.aad = aad;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = AAD_SZ;
                job->u.CHACHA20_POLY1305.ctx = &chacha_ctx;

                job->iv = iv;
                job->iv_len_in_bytes = IMB_CHACHA20_POLY1305_IV_SIZE;
                job->cipher_start_src_offset_in_bytes = 0;

                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = sgl_digest;
                job->auth_tag_output_len_in_bytes = DIGEST_SZ;
                if ((num_segments > 1) && (encrypt_on_update_only == 0)) {
                        job->src = segments[i];
                        job->dst = segments[i];
                        job->msg_len_to_cipher_in_bytes = segment_sizes[i];
                        job->msg_len_to_hash_in_bytes = segment_sizes[i];
                } else {
                        job->src = NULL;
                        job->dst = NULL;
                        job->msg_len_to_cipher_in_bytes = 0;
                        job->msg_len_to_hash_in_bytes = 0;
                }
                job->sgl_state = IMB_SGL_COMPLETE;
                job = IMB_SUBMIT_JOB(mb_mgr);
        } else {
                if (cipher_dir == IMB_DIR_ENCRYPT)
                        IMB_CHACHA20_POLY1305_ENC_FINALIZE(mb_mgr, &chacha_ctx, sgl_digest,
                                                           DIGEST_SZ);
                else
                        IMB_CHACHA20_POLY1305_DEC_FINALIZE(mb_mgr, &chacha_ctx, sgl_digest,
                                                           DIGEST_SZ);
        }

        if (job->status == IMB_STATUS_COMPLETED) {
                for (i = 0; i < (num_segments - 1); i++) {
                        if (memcmp(in_buffer + i * seg_sz, segments[i], seg_sz) != 0) {
                                printf("ciphertext mismatched "
                                       "in segment number %u "
                                       "(segment size = %u)\n",
                                       i, seg_sz);
                                hexdump(stderr, "Linear output", in_buffer + i * seg_sz, seg_sz);
                                hexdump(stderr, "SGL output", segments[i], seg_sz);
                                test_suite_update(ctx, 0, 1);
                                goto exit;
                        }
                }
                /* Check last segment */
                if (memcmp(in_buffer + i * seg_sz, segments[i], last_seg_sz) != 0) {
                        printf("ciphertext mismatched "
                               "in segment number %u (segment size = %u)\n",
                               i, seg_sz);
                        hexdump(stderr, "Linear output", in_buffer + i * seg_sz, last_seg_sz);
                        hexdump(stderr, "SGL output", segments[i], last_seg_sz);
                        test_suite_update(ctx, 0, 1);
                }
                if (memcmp(sgl_digest, linear_digest, DIGEST_SZ) != 0) {
                        printf("hash mismatched (segment size = %u)\n", seg_sz);
                        hexdump(stderr, "Linear digest", linear_digest, DIGEST_SZ);
                        hexdump(stderr, "SGL digest", sgl_digest, DIGEST_SZ);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        } else {
                fprintf(stderr, "job status returned as not successful"
                                " for the segmented buffer\n");
                test_suite_update(ctx, 0, 1);
        }

exit:
        free(in_buffer);
        if (segments != NULL) {
                for (i = 0; i < num_segments; i++)
                        free(segments[i]);
                free(segments);
        }
        free(segment_sizes);
}

#define BUF_SZ      2032
#define SEG_SZ_STEP 4
#define MAX_SEG_SZ  2048
int
chacha20_poly1305_test(struct IMB_MGR *mb_mgr)
{
        int i, errors = 0;
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *jctx = NULL;
        uint32_t seg_sz;

        if (load_aead_vectors(kat_vector_dir, "chacha20_poly1305_test.json",
                              &chacha20_poly1305_vectors, &jctx) < 0)
                return 1;

        test_suite_start(&ctx, "AEAD-CHACHA20-256-POLY1305");
        for (i = 1; i < 20; i++)
                test_aead_vectors(mb_mgr, &ctx, i, chacha20_poly1305_vectors);
        for (seg_sz = SEG_SZ_STEP; seg_sz <= MAX_SEG_SZ; seg_sz += SEG_SZ_STEP) {
                /* Job API */
                test_sgl(mb_mgr, &ctx, BUF_SZ, seg_sz, IMB_DIR_ENCRYPT, 1, 0);
                test_sgl(mb_mgr, &ctx, BUF_SZ, seg_sz, IMB_DIR_DECRYPT, 1, 0);
                test_sgl(mb_mgr, &ctx, BUF_SZ, seg_sz, IMB_DIR_ENCRYPT, 1, 1);
                test_sgl(mb_mgr, &ctx, BUF_SZ, seg_sz, IMB_DIR_DECRYPT, 1, 1);
                /* Single job SGL API */
                test_single_job_sgl(mb_mgr, &ctx, BUF_SZ, seg_sz, IMB_DIR_ENCRYPT);
                test_single_job_sgl(mb_mgr, &ctx, BUF_SZ, seg_sz, IMB_DIR_DECRYPT);
                /* Direct API */
                test_sgl(mb_mgr, &ctx, BUF_SZ, seg_sz, IMB_DIR_ENCRYPT, 0, 1);
                test_sgl(mb_mgr, &ctx, BUF_SZ, seg_sz, IMB_DIR_DECRYPT, 0, 1);
        }

        errors = test_suite_end(&ctx);

        free_chacha20_poly1305_vectors(jctx);
        errors += wycheproof_chacha20_poly1305_test(mb_mgr);

        return errors;
}
