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
#include <assert.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "utils.h"
#include "mac_test.h"

#define max_burst_jobs 32

int
hmac_sha256_sha512_test(struct IMB_MGR *mb_mgr);

extern const struct mac_test hmac_sha224_test_kat_json[];
extern const struct mac_test hmac_sha256_test_kat_json[];
extern const struct mac_test hmac_sha384_test_kat_json[];
extern const struct mac_test hmac_sha512_test_kat_json[];

static int
hmac_shax_job_ok(const struct mac_test *vec, const struct IMB_JOB *job, const int sha_type,
                 const uint8_t *auth, const uint8_t *padding, const size_t sizeof_padding,
                 const size_t tag_size)
{
        const uint8_t *p_digest = NULL;

        switch (sha_type) {
        case 224:
        case 256:
        case 384:
        case 512:
                p_digest = (const void *) vec->tag;
                break;
        default:
                printf("line:%d wrong SHA type 'SHA-%d' ", __LINE__, sha_type);
                return 0;
                break;
        }

        if (job->status != IMB_STATUS_COMPLETED) {
                printf("line:%d job error status:%d ", __LINE__, job->status);
                return 0;
        }

        /* hash checks */
        if (memcmp(padding, &auth[sizeof_padding + tag_size], sizeof_padding)) {
                printf("hash overwrite tail\n");
                hexdump(stderr, "Target", &auth[sizeof_padding + tag_size], sizeof_padding);
                return 0;
        }

        if (memcmp(padding, &auth[0], sizeof_padding)) {
                printf("hash overwrite head\n");
                hexdump(stderr, "Target", &auth[0], sizeof_padding);
                return 0;
        }

        if (memcmp(p_digest, &auth[sizeof_padding], tag_size)) {
                printf("hash mismatched\n");
                hexdump(stderr, "Received", &auth[sizeof_padding], tag_size);
                hexdump(stderr, "Expected", p_digest, tag_size);
                return 0;
        }
        return 1;
}

static int
test_hmac_shax(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
               const int sha_type, const size_t tag_size)
{
        struct IMB_JOB *job;
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        uint32_t i = 0, jobs_rx = 0;
        int ret = -1;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        IMB_HASH_ALG hash_type;

        if (auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end2;
        }

        switch (sha_type) {
        case 224:
        case 256:
        case 384:
        case 512:
                break;
        default:
                fprintf(stderr, "Wrong SHA type selection 'SHA-%d'!\n", sha_type);
                goto end2;
        }

        switch (sha_type) {
        case 224:
                hash_type = IMB_AUTH_HMAC_SHA_224;
                break;
        case 256:
                hash_type = IMB_AUTH_HMAC_SHA_256;
                break;
        case 384:
                hash_type = IMB_AUTH_HMAC_SHA_384;
                break;
        case 512:
        default:
                hash_type = IMB_AUTH_HMAC_SHA_512;
                break;
        }

        memset(padding, -1, sizeof(padding));
        memset(auths, 0, num_jobs * sizeof(void *));

        for (i = 0; i < num_jobs; i++) {
                const size_t alloc_len = tag_size + (sizeof(padding) * 2);

                auths[i] = malloc(alloc_len);
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }
                memset(auths[i], -1, alloc_len);
        }
        imb_hmac_ipad_opad(mb_mgr, hash_type, vec->key, vec->keySize / 8, ipad_hash, opad_hash);

        /* empty the manager */
        while (IMB_FLUSH_JOB(mb_mgr) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->enc_keys = NULL;
                job->dec_keys = NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->dst = NULL;
                job->key_len_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = tag_size;
                job->iv = NULL;
                job->iv_len_in_bytes = 0;
                job->src = (const void *) vec->msg;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = 0;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
                job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
                job->cipher_mode = IMB_CIPHER_NULL;

                switch (sha_type) {
                case 224:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_224;
                        break;
                case 256:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_256;
                        break;
                case 384:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_384;
                        break;
                case 512:
                default:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_512;
                        break;
                }

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (!hmac_shax_job_ok(vec, job, sha_type, job->user_data, padding,
                                              sizeof(padding), tag_size))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (!hmac_shax_job_ok(vec, job, sha_type, job->user_data, padding, sizeof(padding),
                                      tag_size))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
        /* Flush unchecked jobs to prevent segfault*/
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
test_hmac_shax_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const uint32_t num_jobs,
                     const int sha_type)
{
        struct IMB_JOB *job, *jobs[max_burst_jobs] = { NULL };
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        uint32_t i = 0, jobs_rx = 0, completed_jobs = 0;
        int ret = -1, err;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        IMB_HASH_ALG hash_type;

        if (auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end2;
        }

        switch (sha_type) {
        case 224:
        case 256:
        case 384:
        case 512:
                break;
        default:
                fprintf(stderr, "Wrong SHA type selection 'SHA-%d'!\n", sha_type);
                goto end2;
        }

        switch (sha_type) {
        case 224:
                hash_type = IMB_AUTH_HMAC_SHA_224;
                break;
        case 256:
                hash_type = IMB_AUTH_HMAC_SHA_256;
                break;
        case 384:
                hash_type = IMB_AUTH_HMAC_SHA_384;
                break;
        case 512:
        default:
                hash_type = IMB_AUTH_HMAC_SHA_512;
                break;
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

        imb_hmac_ipad_opad(mb_mgr, hash_type, vec->key, vec->keySize / 8, ipad_hash, opad_hash);

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
                job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
                job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
                job->cipher_mode = IMB_CIPHER_NULL;

                switch (sha_type) {
                case 224:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_224;
                        break;
                case 256:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_256;
                        break;
                case 384:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_384;
                        break;
                case 512:
                default:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_512;
                        break;
                }

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

                if (!hmac_shax_job_ok(vec, job, sha_type, job->user_data, padding, sizeof(padding),
                                      vec->tagSize / 8))
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
        /* Flush unchecked jobs to prevent segfault*/
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
test_hmac_shax_hash_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec,
                          const uint32_t num_jobs, const int sha_type)
{
        struct IMB_JOB *job, jobs[max_burst_jobs] = { 0 };
        uint8_t padding[16];
        uint8_t **auths = NULL;
        uint32_t i = 0, jobs_rx = 0, completed_jobs = 0;
        int ret = -1;
        DECLARE_ALIGNED(uint8_t ipad_hash[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        IMB_HASH_ALG hash_type;

        if (num_jobs == 0)
                return 0;

        auths = malloc(num_jobs * sizeof(void *));
        if (auths == NULL) {
                fprintf(stderr, "Can't allocate buffer memory\n");
                goto end2;
        }

        switch (sha_type) {
        case 224:
        case 256:
        case 384:
        case 512:
                break;
        default:
                fprintf(stderr, "Wrong SHA type selection 'SHA-%d'!\n", sha_type);
                goto end2;
        }

        switch (sha_type) {
        case 224:
                hash_type = IMB_AUTH_HMAC_SHA_224;
                break;
        case 256:
                hash_type = IMB_AUTH_HMAC_SHA_256;
                break;
        case 384:
                hash_type = IMB_AUTH_HMAC_SHA_384;
                break;
        case 512:
        default:
                hash_type = IMB_AUTH_HMAC_SHA_512;
                break;
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

        imb_hmac_ipad_opad(mb_mgr, hash_type, vec->key, vec->keySize / 8, ipad_hash, opad_hash);

        for (i = 0; i < num_jobs; i++) {
                job = &jobs[i];
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
                job->u.HMAC._hashed_auth_key_xor_ipad = ipad_hash;
                job->u.HMAC._hashed_auth_key_xor_opad = opad_hash;
                job->cipher_mode = IMB_CIPHER_NULL;

                switch (sha_type) {
                case 224:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_224;
                        break;
                case 256:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_256;
                        break;
                case 384:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_384;
                        break;
                case 512:
                default:
                        job->hash_alg = IMB_AUTH_HMAC_SHA_512;
                        break;
                }

                job->user_data = auths[i];
        }

        completed_jobs = IMB_SUBMIT_HASH_BURST(mb_mgr, jobs, num_jobs, job->hash_alg);
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

                if (!hmac_shax_job_ok(vec, job, sha_type, job->user_data, padding, sizeof(padding),
                                      vec->tagSize / 8))
                        goto end;
                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                goto end;
        }
        ret = 0;

end:
        /* Flush unchecked jobs to prevent segfault*/
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
test_hmac_shax_std_vectors(struct IMB_MGR *mb_mgr, const int sha_type, const uint32_t num_jobs,
                           struct test_suite_context *ts)
{
        const struct mac_test *v;

        switch (sha_type) {
        case 224:
                v = hmac_sha224_test_kat_json;
                break;
        case 256:
                v = hmac_sha256_test_kat_json;
                break;
        case 384:
                v = hmac_sha384_test_kat_json;
                break;
        default:
                v = hmac_sha512_test_kat_json;
                break;
        }
        if (!quiet_mode)
                printf("HMAC-SHA%d standard test vectors (N jobs = %u):\n", sha_type, num_jobs);
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("RFC4231 Test Case %zu key_len:%zu "
                               "data_len:%zu\n",
                               v->tcId, v->keySize / 8, v->msgSize / 8);
#else
                        printf(".");
#endif
                }
                /* @todo add truncation functionality to hmac_sha224 to hmac_sha 512*/
                const int flag =
                        ((sha_type == 224 && (v->tagSize / 8) != IMB_SHA224_DIGEST_SIZE_IN_BYTES) ||
                         (sha_type == 256 && (v->tagSize / 8) != IMB_SHA256_DIGEST_SIZE_IN_BYTES) ||
                         (sha_type == 384 && (v->tagSize / 8) != IMB_SHA384_DIGEST_SIZE_IN_BYTES) ||
                         (sha_type == 512 && (v->tagSize / 8) != IMB_SHA512_DIGEST_SIZE_IN_BYTES));

                if (flag) {
#ifdef DEBUG
                        if (!quiet_mode)
                                printf("Skipped vector %zu, "
                                       "N/A for HMAC-SHA%d\n",
                                       v->tcId, sha_type);
#endif
                        continue;
                }
                if (test_hmac_shax(mb_mgr, v, num_jobs, sha_type, v->tagSize / 8)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else {
                        test_suite_update(ts, 1, 0);
                }
                if (test_hmac_shax_burst(mb_mgr, v, num_jobs, sha_type)) {
                        printf("error #%zu - burst API\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else {
                        test_suite_update(ts, 1, 0);
                }
                if (test_hmac_shax_hash_burst(mb_mgr, v, num_jobs, sha_type)) {
                        printf("error #%zu - hash-only burst API\n", v->tcId);
                        test_suite_update(ts, 0, 1);
                } else {
                        test_suite_update(ts, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
hmac_sha256_sha512_test(struct IMB_MGR *mb_mgr)
{
        const int sha_types_tab[] = { 224, 256, 384, 512 };
        static const char *const sha_names_tab[] = { "HMAC-SHA224", "HMAC-SHA256", "HMAC-SHA384",
                                                     "HMAC-SHA512" };
        struct test_suite_context ts_sha224, ts_sha256, ts_sha384, ts_sha512;
        unsigned i, num_jobs;
        int errors = 0;
        uint32_t tag_size;

        /* Initialize test suites and store in array */
        test_suite_start(&ts_sha224, sha_names_tab[0]);
        test_suite_start(&ts_sha256, sha_names_tab[1]);
        test_suite_start(&ts_sha384, sha_names_tab[2]);
        test_suite_start(&ts_sha512, sha_names_tab[3]);
        struct test_suite_context *sha_ts_tab[] = { &ts_sha224, &ts_sha256, &ts_sha384,
                                                    &ts_sha512 };

        for (i = 0; i < DIM(sha_types_tab); i++) {

                for (num_jobs = 1; num_jobs <= max_burst_jobs; num_jobs++)
                        test_hmac_shax_std_vectors(mb_mgr, sha_types_tab[i], num_jobs,
                                                   sha_ts_tab[i]);
        }

        const struct mac_test *vec_224 = hmac_sha224_test_kat_json;
        assert(vec_224->tagSize / 8 == 28);
        for (tag_size = 4; tag_size <= 28; tag_size++) {
                if (test_hmac_shax(mb_mgr, vec_224, IMB_MAX_BURST_SIZE, sha_types_tab[0],
                                   tag_size)) {
                        printf("error tag size: %u\n", tag_size);
                        test_suite_update(&ts_sha224, 0, 1);
                } else {
                        test_suite_update(&ts_sha224, 1, 0);
                }
        }

        const struct mac_test *vec_256 = hmac_sha256_test_kat_json;
        assert(vec_256->tagSize / 8 == 32);
        for (tag_size = 4; tag_size <= 32; tag_size++) {
                if (test_hmac_shax(mb_mgr, vec_256, IMB_MAX_BURST_SIZE, sha_types_tab[1],
                                   tag_size)) {
                        printf("error tag size: %u\n", tag_size);
                        test_suite_update(&ts_sha256, 0, 1);
                } else {
                        test_suite_update(&ts_sha256, 1, 0);
                }
        }

        const struct mac_test *vec_384 = hmac_sha384_test_kat_json;
        assert(vec_384->tagSize / 8 == 48);
        for (tag_size = 4; tag_size <= 48; tag_size++) {
                if (test_hmac_shax(mb_mgr, vec_384, IMB_MAX_BURST_SIZE, sha_types_tab[2],
                                   tag_size)) {
                        printf("error tag size: %u\n", tag_size);
                        test_suite_update(&ts_sha384, 0, 1);
                } else {
                        test_suite_update(&ts_sha384, 1, 0);
                }
        }

        const struct mac_test *vec_512 = hmac_sha512_test_kat_json;
        assert(vec_512->tagSize / 8 == 64);
        for (tag_size = 4; tag_size <= 64; tag_size++) {
                if (test_hmac_shax(mb_mgr, vec_512, IMB_MAX_BURST_SIZE, sha_types_tab[3],
                                   tag_size)) {
                        printf("error tag size: %u\n", tag_size);
                        test_suite_update(&ts_sha512, 0, 1);
                } else {
                        test_suite_update(&ts_sha512, 1, 0);
                }
        }

        /* End test suites */
        errors += test_suite_end(&ts_sha224);
        errors += test_suite_end(&ts_sha256);
        errors += test_suite_end(&ts_sha384);
        errors += test_suite_end(&ts_sha512);

        return errors;
}
