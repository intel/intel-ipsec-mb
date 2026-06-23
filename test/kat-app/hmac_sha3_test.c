/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

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
#include "mac_test.h"
#include "vector_utils.h"

int
hmac_sha3_test(struct IMB_MGR *mb_mgr);

struct hmac_sha3_variant {
        const char *name;
        IMB_HASH_ALG alg;
        size_t block_size;
        size_t digest_size;
        const struct mac_test *vecs;
};

static struct mac_test *hmac_sha3_224_vecs;
static struct mac_test *hmac_sha3_256_vecs;
static struct mac_test *hmac_sha3_384_vecs;
static struct mac_test *hmac_sha3_512_vecs;
static struct test_json_alloc_ctx *ctx_224;
static struct test_json_alloc_ctx *ctx_256;
static struct test_json_alloc_ctx *ctx_384;
static struct test_json_alloc_ctx *ctx_512;

static struct hmac_sha3_variant variants[] = {
        { "HMAC-SHA3-224", IMB_AUTH_HMAC_SHA3_224, IMB_SHA3_224_BLOCK_SIZE,
          IMB_SHA3_224_DIGEST_SIZE_IN_BYTES, NULL },
        { "HMAC-SHA3-256", IMB_AUTH_HMAC_SHA3_256, IMB_SHA3_256_BLOCK_SIZE,
          IMB_SHA3_256_DIGEST_SIZE_IN_BYTES, NULL },
        { "HMAC-SHA3-384", IMB_AUTH_HMAC_SHA3_384, IMB_SHA3_384_BLOCK_SIZE,
          IMB_SHA3_384_DIGEST_SIZE_IN_BYTES, NULL },
        { "HMAC-SHA3-512", IMB_AUTH_HMAC_SHA3_512, IMB_SHA3_512_BLOCK_SIZE,
          IMB_SHA3_512_DIGEST_SIZE_IN_BYTES, NULL },
};

static int
load_hmac_sha3_vectors(void)
{
        char path[1024];
        int ret;
        static const struct {
                const char *file;
                struct mac_test **vecs;
                struct test_json_alloc_ctx **ctx;
        } entries[] = {
                { "hmac_sha3_224_test.json", &hmac_sha3_224_vecs, &ctx_224 },
                { "hmac_sha3_256_test.json", &hmac_sha3_256_vecs, &ctx_256 },
                { "hmac_sha3_384_test.json", &hmac_sha3_384_vecs, &ctx_384 },
                { "hmac_sha3_512_test.json", &hmac_sha3_512_vecs, &ctx_512 },
        };
        size_t i;

        if (kat_vector_dir == NULL) {
                fprintf(stderr, "Error: no vector directory set; use --vector-dir <DIR>\n");
                return -1;
        }

        for (i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
                ret = snprintf(path, sizeof(path), "%s/%s", kat_vector_dir, entries[i].file);
                if (ret < 0 || ret >= (int) sizeof(path))
                        goto err;
                if (json_load_mac_test(path, entries[i].vecs, entries[i].ctx) < 0)
                        goto err;
        }

        variants[0].vecs = hmac_sha3_224_vecs;
        variants[1].vecs = hmac_sha3_256_vecs;
        variants[2].vecs = hmac_sha3_384_vecs;
        variants[3].vecs = hmac_sha3_512_vecs;
        return 0;

err:
        for (i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
                json_free_test_ctx(*entries[i].ctx);
                *entries[i].ctx = NULL;
                *entries[i].vecs = NULL;
        }
        return -1;
}

static void
free_hmac_sha3_vectors(void)
{
        json_free_test_ctx(ctx_224);
        json_free_test_ctx(ctx_256);
        json_free_test_ctx(ctx_384);
        json_free_test_ctx(ctx_512);
        ctx_224 = ctx_256 = ctx_384 = ctx_512 = NULL;
        hmac_sha3_224_vecs = hmac_sha3_256_vecs = NULL;
        hmac_sha3_384_vecs = hmac_sha3_512_vecs = NULL;
}

static int
hmac_sha3_job_ok(const struct mac_test *vec, const struct IMB_JOB *job, const uint8_t *auth,
                 const uint8_t *padding, const size_t sizeof_padding)
{
        if (job->status != IMB_STATUS_COMPLETED) {
                printf("line:%d job error status:%d ", __LINE__, job->status);
                return 0;
        }

        if (memcmp(padding, &auth[sizeof_padding + (vec->tagSize / 8)], sizeof_padding)) {
                printf("hash overwrite tail\n");
                hexdump(stderr, "Target", &auth[sizeof_padding + (vec->tagSize / 8)],
                        sizeof_padding);
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
                hexdump(stderr, "Expected", vec->tag, vec->tagSize / 8);
                return 0;
        }
        return 1;
}

static int
test_hmac_sha3(struct IMB_MGR *mb_mgr, const struct hmac_sha3_variant *var,
               const struct mac_test *vec, const uint32_t num_jobs)
{
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        uint32_t i = 0, jobs_rx = 0;
        int ret = -1;
        /* ipad/opad hold raw Keccak-rate-sized blocks (max 144 bytes for SHA3-224) */
        DECLARE_ALIGNED(uint8_t ipad_block[IMB_SHA3_MAX_BLOCK_SIZE], 16);
        DECLARE_ALIGNED(uint8_t opad_block[IMB_SHA3_MAX_BLOCK_SIZE], 16);

        if (auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                return ret;
        }

        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                const size_t alloc_len = (vec->tagSize / 8) + (sizeof(padding) * 2);

                auths[i] = malloc(alloc_len);
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }
                memset(auths[i], -1, alloc_len);
        }

        imb_hmac_ipad_opad(mb_mgr, var->alg, vec->key, vec->keySize / 8, ipad_block, opad_block);

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->enc_keys = NULL;
                job->dec_keys = NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->dst = NULL;
                job->key_len_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;
                job->iv = NULL;
                job->iv_len_in_bytes = 0;
                job->src = (const void *) vec->msg;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->u.HMAC._hashed_auth_key_xor_ipad = ipad_block;
                job->u.HMAC._hashed_auth_key_xor_opad = opad_block;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = var->alg;

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (!hmac_sha3_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (!hmac_sha3_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
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

        for (i = 0; i < num_jobs; i++) {
                if (auths[i] != NULL)
                        free(auths[i]);
        }

        if (auths != NULL)
                free(auths);

        return ret;
}

static int
test_hmac_sha3_burst(struct IMB_MGR *mb_mgr, const struct hmac_sha3_variant *var,
                     const struct mac_test *vec, const uint32_t num_jobs)
{
        struct IMB_JOB *job, *jobs[IMB_MAX_BURST_SIZE] = { NULL };
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        uint32_t i = 0, jobs_rx = 0;
        int ret = -1, err;
        DECLARE_ALIGNED(uint8_t ipad_block[IMB_SHA3_MAX_BLOCK_SIZE], 16);
        DECLARE_ALIGNED(uint8_t opad_block[IMB_SHA3_MAX_BLOCK_SIZE], 16);
        uint32_t completed_jobs = 0;

        if (auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                return ret;
        }

        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                const size_t alloc_len = (vec->tagSize / 8) + (sizeof(padding) * 2);

                auths[i] = malloc(alloc_len);
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }
                memset(auths[i], -1, alloc_len);
        }

        imb_hmac_ipad_opad(mb_mgr, var->alg, vec->key, vec->keySize / 8, ipad_block, opad_block);

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];
                job->enc_keys = NULL;
                job->dec_keys = NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->dst = NULL;
                job->key_len_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;
                job->iv = NULL;
                job->iv_len_in_bytes = 0;
                job->src = (const void *) vec->msg;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->u.HMAC._hashed_auth_key_xor_ipad = ipad_block;
                job->u.HMAC._hashed_auth_key_xor_opad = opad_block;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = var->alg;

                job->user_data = auths[i];

                imb_set_session(mb_mgr, job);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        err = imb_get_errno(mb_mgr);

        if (err != 0) {
                printf("submit_burst error %d : '%s'\n", err, imb_get_strerror(err));
                goto end;
        }

check_burst_jobs:
        for (i = 0; i < completed_jobs; i++) {
                job = jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %u status not complete!\n", i + 1);
                        goto end;
                }

                if (!hmac_sha3_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs - completed_jobs, jobs);
                if (completed_jobs == 0) {
                        printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                        goto end;
                }
                goto check_burst_jobs;
        }
        ret = 0;

end:
        for (i = 0; i < num_jobs; i++) {
                if (auths[i] != NULL)
                        free(auths[i]);
        }

        if (auths != NULL)
                free(auths);

        return ret;
}

static void
test_hmac_sha3_std_vectors(struct IMB_MGR *mb_mgr, const struct hmac_sha3_variant *var,
                           const uint32_t num_jobs, struct test_suite_context *ts)
{
        const struct mac_test *v = var->vecs;

        if (!quiet_mode)
                printf("%s standard test vectors (N jobs = %u):\n", var->name, num_jobs);
        while (v->msg != NULL) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Test Case %zu keySize:%zu "
                               "msgSize:%zu tagSize:%zu\n",
                               v->tcId, v->keySize / 8, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_hmac_sha3(mb_mgr, var, v, num_jobs)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else {
                        test_suite_update(ts, 1, 0);
                }
                if (test_hmac_sha3_burst(mb_mgr, var, v, num_jobs)) {
                        printf("error #%zu - burst API\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else {
                        test_suite_update(ts, 1, 0);
                }

                v++;
        }
        if (!quiet_mode)
                printf("\n");
}

int
hmac_sha3_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context ts;
        int errors = 0;
        uint32_t num_jobs;
        size_t i;

        if (load_hmac_sha3_vectors() < 0)
                return 1;

        test_suite_start(&ts, "HMAC-SHA3");
        for (i = 0; i < (sizeof(variants) / sizeof(variants[0])); i++)
                for (num_jobs = 1; num_jobs <= IMB_MAX_BURST_SIZE; num_jobs++)
                        test_hmac_sha3_std_vectors(mb_mgr, &variants[i], num_jobs, &ts);
        errors = test_suite_end(&ts);

        free_hmac_sha3_vectors();
        return errors;
}
