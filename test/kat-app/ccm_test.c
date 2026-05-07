/*****************************************************************************
 Copyright (c) 2017-2024, Intel Corporation

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
#include "gcm_ctr_vectors_test.h"
#include "utils.h"
#include "aead_test.h"

int
ccm_test(struct IMB_MGR *mb_mgr);

static struct aead_test *ccm_128_vectors;
static struct aead_test *ccm_256_vectors;

/**
 * @brief Load AES-CCM vector sets from the configured kat-app JSON paths.
 *
 * @param ctx_128 receives context for ccm_128 vectors
 * @param ctx_256 receives context for ccm_256 vectors
 *
 * @return 0 on success or -1 on failure
 */
static int
load_ccm_vectors(struct test_json_alloc_ctx **ctx_128, struct test_json_alloc_ctx **ctx_256)
{
        char path[1024];
        int ret;
        const char *const ccm_128_file = "ccm_128_test.json";
        const char *const ccm_256_file = "ccm_256_test.json";

        if (kat_vector_dir == NULL) {
                fprintf(stderr, "Error: no vector directory set; use --vector-dir <DIR>\n");
                return -1;
        }

        ret = snprintf(path, sizeof(path), "%s/%s", kat_vector_dir, ccm_128_file);
        /* Treat truncation as failure; otherwise path would be silently invalid. */
        if (ret < 0 || ret >= (int) sizeof(path))
                return -1;
        if (json_load_aead_test(path, &ccm_128_vectors, ctx_128) < 0)
                return -1;

        ret = snprintf(path, sizeof(path), "%s/%s", kat_vector_dir, ccm_256_file);
        /* Treat truncation as failure; otherwise path would be silently invalid. */
        if (ret < 0 || ret >= (int) sizeof(path))
                goto err;
        if (json_load_aead_test(path, &ccm_256_vectors, ctx_256) < 0)
                goto err;

        return 0;

err:
        json_free_test_ctx(*ctx_128);
        json_free_test_ctx(*ctx_256);
        *ctx_128 = NULL;
        *ctx_256 = NULL;
        ccm_128_vectors = NULL;
        ccm_256_vectors = NULL;
        return -1;
}

/**
 * @brief Free AES-CCM vectors previously loaded by load_ccm_vectors().
 *
 * @param ctx_128 context for ccm_128 vectors
 * @param ctx_256 context for ccm_256 vectors
 */
static void
free_ccm_vectors(struct test_json_alloc_ctx *ctx_128, struct test_json_alloc_ctx *ctx_256)
{
        json_free_test_ctx(ctx_128);
        json_free_test_ctx(ctx_256);
        ccm_128_vectors = NULL;
        ccm_256_vectors = NULL;
}

static int
ccm_job_ok(const struct aead_test *vec, const struct IMB_JOB *job, const uint8_t *target,
           const uint8_t *padding, const uint8_t *auth, const size_t sizeof_padding, const int dir,
           const int in_place)
{
        if (job->status != IMB_STATUS_COMPLETED) {
                printf("%d Error status:%d", __LINE__, job->status);
                return 0;
        }

        /* cipher checks */
        if (in_place) {
                if (dir == IMB_DIR_ENCRYPT) {
                        if (memcmp((const void *) vec->ct, target + sizeof_padding,
                                   vec->msgSize / 8)) {
                                printf("cipher mismatched\n");
                                hexdump(stderr, "Received", target + sizeof_padding,
                                        vec->msgSize / 8);
                                hexdump(stderr, "Expected", (const void *) vec->ct,
                                        vec->msgSize / 8);
                                return 0;
                        }
                } else {
                        if (memcmp((const void *) vec->msg, target + sizeof_padding,
                                   vec->msgSize / 8)) {
                                printf("cipher mismatched\n");
                                hexdump(stderr, "Received", target + sizeof_padding,
                                        vec->msgSize / 8);
                                hexdump(stderr, "Expected", (const void *) vec->msg,
                                        vec->msgSize / 8);
                                return 0;
                        }
                }
        } else { /* out-of-place */
                if (dir == IMB_DIR_ENCRYPT) {
                        if (memcmp(vec->ct, target + sizeof_padding, vec->msgSize / 8)) {
                                printf("cipher mismatched\n");
                                hexdump(stderr, "Received", target + sizeof_padding,
                                        vec->msgSize / 8);
                                hexdump(stderr, "Expected", (const void *) vec->ct,
                                        vec->msgSize / 8);
                                return 0;
                        }
                } else {
                        if (memcmp(vec->msg, target + sizeof_padding, vec->msgSize / 8)) {
                                printf("cipher mismatched\n");
                                hexdump(stderr, "Received", target + sizeof_padding,
                                        vec->msgSize / 8);
                                hexdump(stderr, "Expected", (const void *) vec->msg,
                                        vec->msgSize / 8);
                                return 0;
                        }
                }
        }

        if (memcmp(padding, target, sizeof_padding)) {
                printf("cipher overwrite head\n");
                hexdump(stderr, "Target", target, sizeof_padding);
                return 0;
        }

        if (memcmp(padding, target + sizeof_padding + vec->msgSize / 8, sizeof_padding)) {
                printf("cipher overwrite tail\n");
                hexdump(stderr, "Target", target + sizeof_padding + vec->msgSize / 8,
                        sizeof_padding);
                return 0;
        }

        /* hash checks */
        if (memcmp(padding, &auth[sizeof_padding + vec->tagSize / 8], sizeof_padding)) {
                printf("hash overwrite tail\n");
                hexdump(stderr, "Target", &auth[sizeof_padding + vec->tagSize / 8], sizeof_padding);
                return 0;
        }

        if (memcmp(padding, &auth[0], sizeof_padding)) {
                printf("hash overwrite head\n");
                hexdump(stderr, "Target", &auth[0], sizeof_padding);
                return 0;
        }

        if (memcmp(vec->tag, &auth[sizeof_padding], vec->tagSize / 8)) {
                printf("hash mismatched\n");
                hexdump(stderr, "Received", &auth[sizeof_padding], vec->tagSize / 8);
                hexdump(stderr, "Expected", (const void *) vec->tag, vec->tagSize / 8);
                return 0;
        }
        return 1;
}

static int
test_ccm_aead_burst(struct IMB_MGR *mb_mgr, const struct aead_test *vec, const int dir,
                    const int in_place, const int num_jobs, const uint64_t key_length)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        struct IMB_JOB *job, jobs[IMB_MAX_BURST_SIZE];
        uint8_t padding[16];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        int i, completed_jobs, jobs_rx = 0, ret = -1;
        const int order = (dir == IMB_DIR_ENCRYPT) ? IMB_ORDER_HASH_CIPHER : IMB_ORDER_CIPHER_HASH;

        if (targets == NULL || auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end2;
        }

        memset(padding, -1, sizeof(padding));
        memset(targets, 0, num_jobs * sizeof(void *));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(vec->msgSize / 8 + (sizeof(padding) * 2));
                auths[i] = malloc(16 + (sizeof(padding) * 2));
                if (targets[i] == NULL || auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }

                memset(targets[i], -1, vec->msgSize / 8 + (sizeof(padding) * 2));
                memset(auths[i], -1, 16 + (sizeof(padding) * 2));

                if (in_place) {
                        if (dir == IMB_DIR_ENCRYPT)
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->msg,
                                       vec->msgSize / 8);
                        else
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->ct,
                                       vec->msgSize / 8);
                }
        }

        if (key_length == 16)
                IMB_AES_KEYEXP_128(mb_mgr, vec->key, expkey, dust);
        else
                IMB_AES_KEYEXP_256(mb_mgr, vec->key, expkey, dust);

        for (i = 0; i < num_jobs; i++) {
                job = &jobs[i];
                job->cipher_direction = dir;
                job->chain_order = order;
                if (in_place) {
                        job->dst = targets[i] + sizeof(padding);
                        job->src = targets[i] + sizeof(padding);
                } else {
                        if (dir == IMB_DIR_ENCRYPT) {
                                job->dst = targets[i] + sizeof(padding);
                                job->src = (const void *) vec->msg;
                        } else {
                                job->dst = targets[i] + sizeof(padding);
                                job->src = (const void *) vec->ct;
                        }
                }
                job->cipher_mode = IMB_CIPHER_CCM;
                job->enc_keys = expkey;
                job->dec_keys = expkey;
                job->key_len_in_bytes = key_length;
                job->iv = (const void *) vec->iv;
                job->iv_len_in_bytes = vec->ivSize / 8;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = vec->msgSize / 8;

                job->hash_alg = IMB_AUTH_AES_CCM;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;

                job->u.CCM.aad_len_in_bytes = vec->aadSize / 8;
                job->u.CCM.aad = (const void *) vec->aad;

                job->user_data = targets[i];
                job->user_data2 = auths[i];
        }

        completed_jobs =
                IMB_SUBMIT_AEAD_BURST(mb_mgr, jobs, num_jobs, IMB_CIPHER_CCM, dir, key_length);
        if (completed_jobs != num_jobs) {
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
                job = &jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %d status not complete!\n", i + 1);
                        goto end;
                }

                jobs_rx++;
                if (!ccm_job_ok(vec, job, job->user_data, padding, job->user_data2, sizeof(padding),
                                dir, in_place))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
        for (i = 0; i < num_jobs; i++) {
                if (targets[i] != NULL)
                        free(targets[i]);
                if (auths[i] != NULL)
                        free(auths[i]);
        }

end2:
        if (targets != NULL)
                free(targets);

        if (auths != NULL)
                free(auths);

        return ret;
}

static int
test_ccm(struct IMB_MGR *mb_mgr, const struct aead_test *vec, const int dir, const int in_place,
         const int num_jobs, const uint64_t key_length)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        int i = 0, jobs_rx = 0, ret = -1;
        const int order = (dir == IMB_DIR_ENCRYPT) ? IMB_ORDER_HASH_CIPHER : IMB_ORDER_CIPHER_HASH;

        if (targets == NULL || auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end2;
        }

        memset(padding, -1, sizeof(padding));
        memset(targets, 0, num_jobs * sizeof(void *));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(vec->msgSize / 8 + (sizeof(padding) * 2));
                auths[i] = malloc(16 + (sizeof(padding) * 2));
                if (targets[i] == NULL || auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }

                memset(targets[i], -1, vec->msgSize / 8 + (sizeof(padding) * 2));
                memset(auths[i], -1, 16 + (sizeof(padding) * 2));

                if (in_place) {
                        if (dir == IMB_DIR_ENCRYPT)
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->msg,
                                       vec->msgSize / 8);
                        else
                                memcpy(targets[i] + sizeof(padding), (const void *) vec->ct,
                                       vec->msgSize / 8);
                }
        }

        if (key_length == 16)
                IMB_AES_KEYEXP_128(mb_mgr, vec->key, expkey, dust);
        else
                IMB_AES_KEYEXP_256(mb_mgr, vec->key, expkey, dust);

        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = dir;
                job->chain_order = order;
                if (in_place) {
                        job->dst = targets[i] + sizeof(padding);
                        job->src = targets[i] + sizeof(padding);
                } else {
                        if (dir == IMB_DIR_ENCRYPT) {
                                job->dst = targets[i] + sizeof(padding);
                                job->src = (const void *) vec->msg;
                        } else {
                                job->dst = targets[i] + sizeof(padding);
                                job->src = (const void *) vec->ct;
                        }
                }
                job->cipher_mode = IMB_CIPHER_CCM;
                job->enc_keys = expkey;
                job->dec_keys = expkey;
                job->key_len_in_bytes = key_length;
                job->iv = (const void *) vec->iv;
                job->iv_len_in_bytes = vec->ivSize / 8;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = vec->msgSize / 8;

                job->hash_alg = IMB_AUTH_AES_CCM;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;

                job->u.CCM.aad_len_in_bytes = vec->aadSize / 8;
                job->u.CCM.aad = (const void *) vec->aad;

                job->user_data = targets[i];
                job->user_data2 = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (num_jobs < 4) {
                                printf("%d Unexpected return from submit_job\n", __LINE__);
                                goto end;
                        }
                        if (!ccm_job_ok(vec, job, job->user_data, padding, job->user_data2,
                                        sizeof(padding), dir, in_place))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;

                if (!ccm_job_ok(vec, job, job->user_data, padding, job->user_data2, sizeof(padding),
                                dir, in_place))
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
                if (targets[i] != NULL)
                        free(targets[i]);
                if (auths[i] != NULL)
                        free(auths[i]);
        }

end2:
        if (targets != NULL)
                free(targets);

        if (auths != NULL)
                free(auths);

        return ret;
}

static void
test_ccm_128_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs)
{
        const struct aead_test *v = ccm_128_vectors;

        if (!quiet_mode)
                printf("AES-CCM-128 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu NONCELen:%zu PktLen:%zu AADLen:%zu "
                               "Digestlen:%zu\n",
                               v->tcId, v->ivSize / 8, v->msgSize / 8, v->aadSize / 8,
                               v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_ENCRYPT, 1, num_jobs, IMB_KEY_128_BYTES)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_DECRYPT, 1, num_jobs, IMB_KEY_128_BYTES)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_ENCRYPT, 0, num_jobs, IMB_KEY_128_BYTES)) {
                        printf("error #%zu encrypt out-of-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_DECRYPT, 0, num_jobs, IMB_KEY_128_BYTES)) {
                        printf("error #%zu decrypt out-of-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm_aead_burst(mb_mgr, v, IMB_DIR_ENCRYPT, 1, num_jobs,
                                        IMB_KEY_128_BYTES)) {
                        printf("error #%zu encrypt in-place (aead burst)\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm_aead_burst(mb_mgr, v, IMB_DIR_DECRYPT, 1, num_jobs,
                                        IMB_KEY_128_BYTES)) {
                        printf("error #%zu decrypt in-place (aead burst)\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm_aead_burst(mb_mgr, v, IMB_DIR_ENCRYPT, 0, num_jobs,
                                        IMB_KEY_128_BYTES)) {
                        printf("error #%zu encrypt out-of-place (aead burst)\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm_aead_burst(mb_mgr, v, IMB_DIR_DECRYPT, 0, num_jobs,
                                        IMB_KEY_128_BYTES)) {
                        printf("error #%zu decrypt out-of-place (aead burst)\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_ccm_256_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs)
{
        const struct aead_test *v = ccm_256_vectors;

        if (!quiet_mode)
                printf("AES-CCM-256 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {

                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu NONCELen:%zu PktLen:%zu AADLen:%zu "
                               "Digestlen:%zu\n",
                               v->tcId, v->ivSize / 8, v->msgSize / 8, v->aadSize / 8,
                               v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_ENCRYPT, 1, num_jobs, IMB_KEY_256_BYTES)) {
                        printf("error #%zu encrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_DECRYPT, 1, num_jobs, IMB_KEY_256_BYTES)) {
                        printf("error #%zu decrypt in-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_ENCRYPT, 0, num_jobs, IMB_KEY_256_BYTES)) {
                        printf("error #%zu encrypt out-of-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm(mb_mgr, v, IMB_DIR_DECRYPT, 0, num_jobs, IMB_KEY_256_BYTES)) {
                        printf("error #%zu decrypt out-of-place\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm_aead_burst(mb_mgr, v, IMB_DIR_ENCRYPT, 1, num_jobs,
                                        IMB_KEY_256_BYTES)) {
                        printf("error #%zu encrypt in-place (aead burst)\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm_aead_burst(mb_mgr, v, IMB_DIR_DECRYPT, 1, num_jobs,
                                        IMB_KEY_256_BYTES)) {
                        printf("error #%zu decrypt in-place (aead burst)\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm_aead_burst(mb_mgr, v, IMB_DIR_ENCRYPT, 0, num_jobs,
                                        IMB_KEY_256_BYTES)) {
                        printf("error #%zu encrypt out-of-place (aead burst)\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_ccm_aead_burst(mb_mgr, v, IMB_DIR_DECRYPT, 0, num_jobs,
                                        IMB_KEY_256_BYTES)) {
                        printf("error #%zu decrypt out-of-place (aead burst)\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
ccm_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *ctx_128 = NULL;
        struct test_json_alloc_ctx *ctx_256 = NULL;
        int errors = 0;

        if (load_ccm_vectors(&ctx_128, &ctx_256) < 0)
                return 1;

        /* AES-CCM-128 tests */
        test_suite_start(&ctx, "AES-CCM-128");
        for (int i = 0; i <= 19; i++)
                test_ccm_128_std_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

        /* AES-CCM-256 tests */
        test_suite_start(&ctx, "AES-CCM-256");
        for (int i = 0; i <= 19; i++)
                test_ccm_256_std_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

        free_ccm_vectors(ctx_128, ctx_256);
        return errors;
}
