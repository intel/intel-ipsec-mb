/*****************************************************************************
 Copyright (c) 2020-2023, Intel Corporation

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "aead_test.h"

#define AAD_SZ    24
#define DIGEST_SZ 16

int
chacha20_poly1305_test(struct IMB_MGR *mb_mgr);

extern const struct aead_test chacha20_poly1305_test_json[];

static int
aead_ok(const struct aead_test *vec, const size_t auth_len, const uint8_t *out_text,
        const IMB_CIPHER_DIRECTION cipher_dir, const uint8_t *auth, const uint8_t *padding,
        const size_t sizeof_padding)
{
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

        if (cipher_dir == IMB_DIR_ENCRYPT) {
                if (memcmp(vec->ct, out_text, vec->msgSize / 8)) {
                        printf("cipher text mismatched\n");
                        hexdump(stderr, "Received", out_text, vec->msgSize / 8);
                        hexdump(stderr, "Expected", (const void *) vec->ct, vec->msgSize / 8);
                        return 0;
                }
        } else {
                if (memcmp(vec->msg, out_text, vec->msgSize / 8)) {
                        printf("plain text mismatched\n");
                        hexdump(stderr, "Received", out_text, vec->msgSize / 8);
                        hexdump(stderr, "Expected", (const void *) vec->msg, vec->msgSize / 8);
                        return 0;
                }
        }

        if (memcmp(padding, out_text - sizeof_padding, sizeof_padding)) {
                printf("destination buffer under-run (memory before)\n");
                hexdump(stderr, "", out_text - sizeof_padding, sizeof_padding);
                return 0;
        }

        if (memcmp(padding, out_text + vec->msgSize / 8, sizeof_padding)) {
                printf("destination buffer overrun (memory after)\n");
                hexdump(stderr, "", out_text + vec->msgSize / 8, sizeof_padding);
                return 0;
        }
        return 1;
}

static int
test_aead(struct IMB_MGR *mb_mgr, const struct aead_test *vec, const int dir, const int num_jobs,
          const int in_place)
{
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        int i = 0, jobs_rx = 0, ret = -1;

        if (auths == NULL || targets == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end2;
        }
        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));
        memset(targets, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                auths[i] = malloc(DIGEST_SZ + (sizeof(padding) * 2));
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }

                memset(auths[i], -1, DIGEST_SZ + (sizeof(padding) * 2));
        }

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(vec->msgSize / 8 + (sizeof(padding) * 2));
                if (targets[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }
                memset(targets[i], -1, vec->msgSize / 8 + (sizeof(padding) * 2));

                if (in_place) {
                        if (dir == IMB_DIR_ENCRYPT)
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->msg,
                                       vec->msgSize / 8);
                        else
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->ct,
                                       vec->msgSize / 8);
                }
        }

        /* QUIC API */
        const void *src_ptr_array[IMB_MAX_JOBS];
        void *dst_ptr_array[IMB_MAX_JOBS];
        const void *aad_ptr_array[IMB_MAX_JOBS];
        void *tag_ptr_array[IMB_MAX_JOBS];
        const void *iv_ptr_array[IMB_MAX_JOBS];
        uint64_t len_array[IMB_MAX_JOBS];

        for (i = 0; i < num_jobs; i++) {
                if (in_place)
                        src_ptr_array[i] = targets[i] + sizeof(padding);
                else if (dir == IMB_DIR_ENCRYPT)
                        src_ptr_array[i] = (const void *) vec->msg;
                else
                        src_ptr_array[i] = (const void *) vec->ct;

                dst_ptr_array[i] = targets[i] + sizeof(padding);

                aad_ptr_array[i] = vec->aad;
                iv_ptr_array[i] = vec->iv;
                tag_ptr_array[i] = auths[i] + sizeof(padding);
                len_array[i] = vec->msgSize / 8;
        }

        imb_quic_chacha20_poly1305(mb_mgr, vec->key, dir, dst_ptr_array, src_ptr_array, len_array,
                                   iv_ptr_array, aad_ptr_array, vec->aadSize / 8, tag_ptr_array,
                                   num_jobs);

        for (i = 0; i < num_jobs; i++) {
                if (!aead_ok(vec, DIGEST_SZ, dst_ptr_array[i], dir, auths[i], padding,
                             sizeof(padding)))
                        goto end;
        }

        /* Reset the source buffers */
        for (i = 0; i < num_jobs; i++) {
                memset(targets[i], -1, vec->msgSize / 8 + (sizeof(padding) * 2));

                if (in_place) {
                        if (dir == IMB_DIR_ENCRYPT)
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->msg,
                                       vec->msgSize / 8);
                        else
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->ct,
                                       vec->msgSize / 8);
                }
        }

        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        /**
         * Submit all jobs then flush any outstanding jobs
         */
        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = dir;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
                job->hash_alg = IMB_AUTH_CHACHA20_POLY1305;
                job->enc_keys = vec->key;
                job->dec_keys = vec->key;
                job->key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE;

                job->u.CHACHA20_POLY1305.aad = (const void *) vec->aad;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = vec->aadSize / 8;

                if (in_place)
                        job->src = targets[i] + sizeof(padding);
                else if (dir == IMB_DIR_ENCRYPT)
                        job->src = (const void *) vec->msg;
                else
                        job->src = (const void *) vec->ct;
                job->dst = targets[i] + sizeof(padding);

                job->iv = (const void *) vec->iv;
                job->iv_len_in_bytes = IMB_CHACHA20_POLY1305_IV_SIZE;
                job->msg_len_to_cipher_in_bytes = vec->msgSize / 8;
                job->cipher_start_src_offset_in_bytes = 0;

                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = DIGEST_SZ;

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (job->status != IMB_STATUS_COMPLETED) {
                                const int errcode = imb_get_errno(mb_mgr);

                                printf("Error!: job status %d, errno %d => %s\n", job->status,
                                       errcode, imb_get_strerror(errcode));
                                goto end;
                        }

                        if (!aead_ok(vec, job->auth_tag_output_len_in_bytes, job->dst, dir,
                                     job->user_data, padding, sizeof(padding)))
                                goto end;
                } else {
                        int err = imb_get_errno(mb_mgr);

                        if (err != 0) {
                                printf("submit_job error %d : '%s'\n", err, imb_get_strerror(err));
                                goto end;
                        }
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;

                if (job->status != IMB_STATUS_COMPLETED) {
                        const int errcode = imb_get_errno(mb_mgr);

                        printf("Error!: job status %d, errno %d => %s\n", job->status, errcode,
                               imb_get_strerror(errcode));
                        goto end;
                }

                if (!aead_ok(vec, job->auth_tag_output_len_in_bytes, job->dst, dir, job->user_data,
                             padding, sizeof(padding)))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }

        /*
         * *******************************************
         * BURST API TEST
         * *******************************************
         */

        /* create job array */
        IMB_JOB *jobs[32] = { NULL };

        jobs_rx = 0;

        /* reset buffers */
        for (i = 0; i < num_jobs; i++) {
                memset(auths[i], -1, DIGEST_SZ + (sizeof(padding) * 2));
                memset(targets[i], -1, vec->msgSize / 8 + (sizeof(padding) * 2));

                if (in_place) {
                        if (dir == IMB_DIR_ENCRYPT)
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->msg,
                                       vec->msgSize / 8);
                        else
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->ct,
                                       vec->msgSize / 8);
                }
        }

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < (uint32_t) num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        /**
         * Set all job params before submitting burst
         */
        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];
                job->cipher_direction = dir;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
                job->hash_alg = IMB_AUTH_CHACHA20_POLY1305;
                job->enc_keys = vec->key;
                job->dec_keys = vec->key;
                job->key_len_in_bytes = IMB_CHACHA20_POLY1305_KEY_SIZE;

                job->u.CHACHA20_POLY1305.aad = vec->aad;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = vec->aadSize / 8;

                if (in_place)
                        job->src = targets[i] + sizeof(padding);
                else if (dir == IMB_DIR_ENCRYPT)
                        job->src = (const void *) vec->msg;
                else
                        job->src = (const void *) vec->ct;
                job->dst = targets[i] + sizeof(padding);

                job->iv = (const void *) vec->iv;
                job->iv_len_in_bytes = IMB_CHACHA20_POLY1305_IV_SIZE;
                job->msg_len_to_cipher_in_bytes = vec->msgSize / 8;
                job->cipher_start_src_offset_in_bytes = 0;

                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = DIGEST_SZ;

                job->user_data = auths[i];

                imb_set_session(mb_mgr, job);
        }

        uint32_t completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);

        if (completed_jobs != (uint32_t) num_jobs) {
                int err = imb_get_errno(mb_mgr);

                if (err != 0) {
                        printf("submit_burst error %d : '%s'\n", err, imb_get_strerror(err));
                        goto end;
                } else {
                        printf("submit_burst error: not enough "
                               "jobs returned!\n");
                        goto end;
                }
        }

        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %d status not complete!\n", i + 1);
                        goto end;
                }

                if (job->status != IMB_STATUS_COMPLETED) {
                        const int errcode = imb_get_errno(mb_mgr);

                        printf("Error!: job status %d, errno %d => %s\n", job->status, errcode,
                               imb_get_strerror(errcode));
                        goto end;
                }

                if (!aead_ok(vec, job->auth_tag_output_len_in_bytes, job->dst, dir, job->user_data,
                             padding, sizeof(padding)))
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs after burst, "
                       "received %d\n",
                       num_jobs, jobs_rx);
                goto end;
        }

        /*
         * *******************************************
         * END BURST API TEST
         * *******************************************
         */

        ret = 0;

end:
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        if (auths != NULL) {
                for (i = 0; i < num_jobs; i++) {
                        if (auths[i] != NULL)
                                free(auths[i]);
                }
        }

        if (targets != NULL) {
                for (i = 0; i < num_jobs; i++) {
                        if (targets[i] != NULL)
                                free(targets[i]);
                }
        }

end2:
        if (auths != NULL)
                free(auths);

        if (targets != NULL)
                free(targets);

        return ret;
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

                if (test_aead(mb_mgr, v, IMB_DIR_ENCRYPT, num_jobs, 1)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (test_aead(mb_mgr, v, IMB_DIR_DECRYPT, num_jobs, 1)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (test_aead(mb_mgr, v, IMB_DIR_ENCRYPT, num_jobs, 0)) {
                        printf("error #%zu encrypt out-of-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (test_aead(mb_mgr, v, IMB_DIR_DECRYPT, num_jobs, 0)) {
                        printf("error #%zu decrypt out-of-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
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
        uint32_t seg_sz;

        test_suite_start(&ctx, "AEAD-CHACHA20-256-POLY1305");
        for (i = 1; i < 20; i++)
                test_aead_vectors(mb_mgr, &ctx, i, chacha20_poly1305_test_json);
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

        return errors;
}
