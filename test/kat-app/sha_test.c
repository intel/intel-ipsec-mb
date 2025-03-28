/*****************************************************************************
 Copyright (c) 2018-2024, Intel Corporation

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

int
sha_test(struct IMB_MGR *mb_mgr);

extern const struct mac_test sha_test_json[];

static int
sha_job_ok(const struct mac_test *vec, const struct IMB_JOB *job, const uint8_t *auth,
           const uint8_t *padding, const size_t sizeof_padding)
{
        if (job->status != IMB_STATUS_COMPLETED) {
                printf("line:%d job error status:%d ", __LINE__, job->status);
                return 0;
        }

        /* hash checks */
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

        if (memcmp((const void *) vec->tag, &auth[sizeof_padding], vec->tagSize / 8)) {
                printf("hash mismatched\n");
                hexdump(stderr, "Received", &auth[sizeof_padding], vec->tagSize / 8);
                hexdump(stderr, "Expected", (const void *) vec->tag, vec->tagSize / 8);
                return 0;
        }
        return 1;
}

static int
test_sha(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs, const int sha_type)
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
                const size_t alloc_len = vec->tagSize / 8 + (sizeof(padding) * 2);

                auths[i] = malloc(alloc_len);
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }
                memset(auths[i], -1, alloc_len);
        }

        /* empty the manager */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);

                memset(job, 0, sizeof(*job));
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;
                job->src = (const void *) vec->msg;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->cipher_mode = IMB_CIPHER_NULL;
                switch (sha_type) {
                case 1:
                        job->hash_alg = IMB_AUTH_SHA_1;
                        break;
                case 224:
                        job->hash_alg = IMB_AUTH_SHA_224;
                        break;
                case 256:
                        job->hash_alg = IMB_AUTH_SHA_256;
                        break;
                case 384:
                        job->hash_alg = IMB_AUTH_SHA_384;
                        break;
                case 512:
                default:
                        job->hash_alg = IMB_AUTH_SHA_512;
                        break;
                }

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (!sha_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (!sha_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
        /* empty the manager before next tests */
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

static int
test_sha_sb(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs,
            const int sha_type)
{
        uint8_t padding[16];
        uint8_t *auths;
        int i = 0, ret = -1;
        const size_t sizeof_padding = sizeof(padding);

        memset(padding, -1, sizeof_padding);

        const size_t alloc_len = vec->tagSize / 8 + (sizeof_padding * 2);

        auths = malloc(alloc_len);
        if (auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end;
        }
        memset(auths, -1, alloc_len);

        for (i = 0; i < num_jobs; i++) {
                switch (sha_type) {
                case 1:
                        IMB_SHA1(mb_mgr, vec->msg, vec->msgSize / 8, auths + sizeof_padding);
                        break;
                case 224:
                        IMB_SHA224(mb_mgr, vec->msg, vec->msgSize / 8, auths + sizeof_padding);
                        break;
                case 256:
                        IMB_SHA256(mb_mgr, vec->msg, vec->msgSize / 8, auths + sizeof_padding);
                        break;
                default:
                        fprintf(stderr, "SHA algorithm not supported\n");
                        goto end;
                }
                if (memcmp(auths + sizeof_padding, vec->tag, vec->tagSize / 8) != 0) {
                        fprintf(stderr, "hash mismatched\n");
                        goto end;
                }
                if (memcmp(padding, auths, sizeof_padding)) {
                        fprintf(stderr, "hash overwrite head\n");
                        goto end;
                }
                if (memcmp(padding, auths + vec->tagSize / 8 + sizeof_padding, sizeof_padding)) {
                        fprintf(stderr, "hash overwrite tail\n");
                        goto end;
                }
        }

        ret = 0;

end:
        if (auths != NULL)
                free(auths);

        return ret;
}

static int
test_sha_hash_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const int num_jobs,
                    const int sha_type)
{
        struct IMB_JOB *job, jobs[IMB_MAX_BURST_SIZE] = { 0 };
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        int i = 0, jobs_rx = 0, ret = -1;
        int completed_jobs = 0;
        IMB_HASH_ALG hash_alg;

        if (auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end2;
        }

        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));

        switch (sha_type) {
        case 1:
                hash_alg = IMB_AUTH_SHA_1;
                break;
        case 224:
                hash_alg = IMB_AUTH_SHA_224;
                break;
        case 256:
                hash_alg = IMB_AUTH_SHA_256;
                break;
        case 384:
                hash_alg = IMB_AUTH_SHA_384;
                break;
        case 512:
        default:
                hash_alg = IMB_AUTH_SHA_512;
                break;
        }

        for (i = 0; i < num_jobs; i++) {
                const size_t alloc_len = vec->tagSize / 8 + (sizeof(padding) * 2);

                auths[i] = malloc(alloc_len);
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }
                memset(auths[i], -1, alloc_len);
        }

        for (i = 0; i < num_jobs; i++) {
                job = &jobs[i];

                job->enc_keys = NULL;
                job->dec_keys = NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;
                job->src = (const void *) vec->msg;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->hash_alg = hash_alg;

                job->user_data = auths[i];
        }

        completed_jobs = IMB_SUBMIT_HASH_BURST(mb_mgr, jobs, num_jobs, hash_alg);
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
                        printf("job %u status not complete!\n", i + 1);
                        goto end;
                }

                if (!sha_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
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
test_sha_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *sha1_ctx,
                 struct test_suite_context *sha224_ctx, struct test_suite_context *sha256_ctx,
                 struct test_suite_context *sha384_ctx, struct test_suite_context *sha512_ctx,
                 const int num_jobs)
{
        struct test_suite_context *ctx;
        const struct mac_test *v = sha_test_json;
        int sha_type;

        if (!quiet_mode)
                printf("SHA standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++) {

                switch (v->tagSize) {
                case 160:
                        ctx = sha1_ctx;
                        sha_type = 1;
                        break;
                case 224:
                        ctx = sha224_ctx;
                        sha_type = 224;
                        break;
                case 256:
                        ctx = sha256_ctx;
                        sha_type = 256;
                        break;
                case 384:
                        ctx = sha384_ctx;
                        sha_type = 384;
                        break;
                case 512:
                        ctx = sha512_ctx;
                        sha_type = 512;
                        break;
                default:
                        ctx = sha1_ctx;
                        printf("error #%zu, invalid tag size\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                        continue;
                }
#ifdef DEBUG
                if (!quiet_mode) {
                        printf("SHA%d Test Case %zu "
                               "data_len:%zu digest_len:%zu\n",
                               sha_type, v->tcId, v->msgSize / 8, v->tagSize / 8);
                }
#endif
                if (test_sha(mb_mgr, v, num_jobs, sha_type)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (sha_type == 1 || sha_type == 224 || sha_type == 256) {
                        if (test_sha_sb(mb_mgr, v, num_jobs, sha_type)) {
                                printf("error #%zu\n", v->tcId);
                                test_suite_update(ctx, 0, 1);
                        } else {
                                test_suite_update(ctx, 1, 0);
                        }
                }
                if (test_sha_hash_burst(mb_mgr, v, num_jobs, sha_type)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
}

int
sha_test(struct IMB_MGR *mb_mgr)
{
        struct test_suite_context sha1_ctx, sha224_ctx, sha256_ctx;
        struct test_suite_context sha384_ctx, sha512_ctx;
        int errors;
        unsigned i;

        test_suite_start(&sha1_ctx, "SHA1");
        test_suite_start(&sha224_ctx, "SHA224");
        test_suite_start(&sha256_ctx, "SHA256");
        test_suite_start(&sha384_ctx, "SHA384");
        test_suite_start(&sha512_ctx, "SHA512");
        for (i = 1; i <= 17; i++) {
                test_sha_vectors(mb_mgr, &sha1_ctx, &sha224_ctx, &sha256_ctx, &sha384_ctx,
                                 &sha512_ctx, i);
        }
        errors = test_suite_end(&sha1_ctx);
        errors += test_suite_end(&sha224_ctx);
        errors += test_suite_end(&sha256_ctx);
        errors += test_suite_end(&sha384_ctx);
        errors += test_suite_end(&sha512_ctx);

        return errors;
}
