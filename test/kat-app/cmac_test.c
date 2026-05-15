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

enum cmac_type {
        CMAC_128 = 0,
        CMAC_256,
};

int
cmac_test(struct IMB_MGR *mb_mgr);

static struct mac_test *cmac_128_vectors;
static struct mac_test *cmac_256_vectors;

/**
 * @brief Load all CMAC vector sets used by the CMAC kat-app module.
 *
 * @param ctx_128 receives context for cmac_128 vectors
 * @param ctx_256 receives context for cmac_256 vectors
 *
 * @return 0 on success or -1 on failure
 */
static int
load_cmac_vectors(struct test_json_alloc_ctx **ctx_128, struct test_json_alloc_ctx **ctx_256)
{
        if (load_mac_vectors(kat_vector_dir, "cmac_128_test.json", &cmac_128_vectors, ctx_128) < 0)
                return -1;
        if (load_mac_vectors(kat_vector_dir, "cmac_256_test.json", &cmac_256_vectors, ctx_256) <
            0) {
                json_free_test_ctx(*ctx_128);
                *ctx_128 = NULL;
                cmac_128_vectors = NULL;
                return -1;
        }
        return 0;
}

/**
 * @brief Free all CMAC vector sets loaded by load_cmac_vectors().
 *
 * @param ctx_128 context for cmac_128 vectors
 * @param ctx_256 context for cmac_256 vectors
 */
static void
free_cmac_vectors(struct test_json_alloc_ctx *ctx_128, struct test_json_alloc_ctx *ctx_256)
{
        json_free_test_ctx(ctx_128);
        json_free_test_ctx(ctx_256);
}

static const struct cmac_subkeys {
        const char *key;
        const char *sub_key1;
        const char *sub_key2;
} cmac_128_subkeys[] = { { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                           "\xfb\xee\xd6\x18\x35\x71\x33\x66\x7c\x85\xe0\x8f\x72\x36\xa8\xde",
                           "\xf7\xdd\xac\x30\x6a\xe2\x66\xcc\xf9\x0b\xc1\x1e\xe4\x6d\x51\x3b" },
                         { NULL, NULL, NULL } };

static const struct cmac_subkeys cmac_256_subkeys[] = {
        { "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61"
          "\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
          "\xca\xd1\xed\x03\x29\x9e\xed\xac\x2e\x9a\x99\x80\x86\x21\x50\x2f",
          "\x95\xa3\xda\x06\x53\x3d\xdb\x58\x5d\x35\x33\x01\x0c\x42\xa0\xd9" },
        { "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61"
          "\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
          "\xca\xd1\xed\x03\x29\x9e\xed\xac\x2e\x9a\x99\x80\x86\x21\x50\x2f",
          "\x95\xa3\xda\x06\x53\x3d\xdb\x58\x5d\x35\x33\x01\x0c\x42\xa0\xd9" },
        { "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61"
          "\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
          "\xca\xd1\xed\x03\x29\x9e\xed\xac\x2e\x9a\x99\x80\x86\x21\x50\x2f",
          "\x95\xa3\xda\x06\x53\x3d\xdb\x58\x5d\x35\x33\x01\x0c\x42\xa0\xd9" },
        { "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61"
          "\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
          "\xca\xd1\xed\x03\x29\x9e\xed\xac\x2e\x9a\x99\x80\x86\x21\x50\x2f",
          "\x95\xa3\xda\x06\x53\x3d\xdb\x58\x5d\x35\x33\x01\x0c\x42\xa0\xd9" },
        { NULL, NULL, NULL }
};

static int
cmac_subkey_test(const struct cmac_subkeys *skeys, const uint32_t *skey1, const uint32_t *skey2)
{
        const size_t sub_key_size = IMB_AES_BLOCK_SIZE;

        if (memcmp(skeys->sub_key1, skey1, sub_key_size)) {
                printf("sub-key1 mismatched\n");
                hexdump(stderr, "Received", skey1, sub_key_size);
                hexdump(stderr, "Expected", (const void *) skeys->sub_key1, sub_key_size);
                return 0;
        }

        if (memcmp(skeys->sub_key2, skey2, sub_key_size)) {
                printf("sub-key2 mismatched\n");
                hexdump(stderr, "Received", skey2, sub_key_size);
                hexdump(stderr, "Expected", (const void *) skeys->sub_key2, sub_key_size);
                return 0;
        }
        return 1;
}

static int
cmac_job_ok(const struct mac_test *vec, const struct IMB_JOB *job, const uint8_t *auth,
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
test_cmac(struct IMB_MGR *mb_mgr, const struct mac_test *vec, const struct cmac_subkeys *subKeys,
          const int num_jobs, const enum cmac_type type)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        uint32_t skey1[4], skey2[4];
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

        if (type == CMAC_128) {
                IMB_AES_KEYEXP_128(mb_mgr, vec->key, expkey, dust);
                IMB_AES_CMAC_SUBKEY_GEN_128(mb_mgr, expkey, skey1, skey2);
        } else { /* AES-CMAC-256 */
                IMB_AES_KEYEXP_256(mb_mgr, vec->key, expkey, dust);
                IMB_AES_CMAC_SUBKEY_GEN_256(mb_mgr, expkey, skey1, skey2);
        }

        if (!cmac_subkey_test(subKeys, skey1, skey2))
                goto end;

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

                switch (type) {
                case CMAC_128:
                        job->hash_alg = IMB_AUTH_AES_CMAC;
                        job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                        break;
                case CMAC_256:
                        job->hash_alg = IMB_AUTH_AES_CMAC_256;
                        job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                        break;
                default:
                        printf("Invalid CMAC type specified\n");
                        goto end;
                }
                job->u.CMAC._key_expanded = expkey;
                job->u.CMAC._skey1 = skey1;
                job->u.CMAC._skey2 = skey2;
                job->src = (const void *) vec->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (num_jobs < 4) {
                                printf("%d Unexpected return from submit_job\n", __LINE__);
                                goto end;
                        }
                        if (!cmac_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;

                if (!cmac_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }

        /**
         * Submit each job and flush immediately
         */
        for (i = 0; i < num_jobs; i++) {
                struct IMB_JOB *first_job = NULL;

                job = IMB_GET_NEXT_JOB(mb_mgr);
                first_job = job;

                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;

                switch (type) {
                case CMAC_128:
                        job->hash_alg = IMB_AUTH_AES_CMAC;
                        job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                        break;
                case CMAC_256:
                        job->hash_alg = IMB_AUTH_AES_CMAC_256;
                        job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                        break;
                default:
                        printf("Invalid CMAC type specified\n");
                        goto end;
                }
                job->u.CMAC._key_expanded = expkey;
                job->u.CMAC._skey1 = skey1;
                job->u.CMAC._skey2 = skey2;
                job->src = (const void *) vec->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        printf("Received job, expected NULL\n");
                        goto end;
                }

                while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                        if (job != first_job) {
                                printf("Invalid return job received\n");
                                goto end;
                        }
                        if (!cmac_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
                                goto end;
                }
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

static int
test_cmac_hash_burst(struct IMB_MGR *mb_mgr, const struct mac_test *vec,
                     const struct cmac_subkeys *subKeys, const uint32_t num_jobs,
                     const enum cmac_type type)
{
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        uint32_t skey1[4], skey2[4];
        struct IMB_JOB *job, jobs[IMB_MAX_BURST_SIZE] = { 0 };
        uint8_t padding[16];
        uint8_t **auths = malloc(num_jobs * sizeof(void *));
        int ret = -1;
        uint32_t jobs_rx = 0, i, completed_jobs = 0;

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

        if (type == CMAC_128) {
                IMB_AES_KEYEXP_128(mb_mgr, vec->key, expkey, dust);
                IMB_AES_CMAC_SUBKEY_GEN_128(mb_mgr, expkey, skey1, skey2);
        } else { /* AES-CMAC-256 */
                IMB_AES_KEYEXP_256(mb_mgr, vec->key, expkey, dust);
                IMB_AES_CMAC_SUBKEY_GEN_256(mb_mgr, expkey, skey1, skey2);
        }

        if (!cmac_subkey_test(subKeys, skey1, skey2))
                goto end;

        /**
         * Submit all jobs
         */
        for (i = 0; i < num_jobs; i++) {
                job = &jobs[i];
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->cipher_mode = IMB_CIPHER_NULL;

                switch (type) {
                case CMAC_128:
                        job->hash_alg = IMB_AUTH_AES_CMAC;
                        job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                        break;
                case CMAC_256:
                        job->hash_alg = IMB_AUTH_AES_CMAC_256;
                        job->msg_len_to_hash_in_bytes = vec->msgSize / 8;
                        break;
                default:
                        printf("Invalid CMAC type specified\n");
                        goto end;
                }
                job->u.CMAC._key_expanded = expkey;
                job->u.CMAC._skey1 = skey1;
                job->u.CMAC._skey2 = skey2;
                job->src = (const void *) vec->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = vec->tagSize / 8;

                job->user_data = auths[i];
        }

        completed_jobs = IMB_SUBMIT_HASH_BURST(mb_mgr, jobs, num_jobs, jobs[0].hash_alg);
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

                if (!cmac_job_ok(vec, job, job->user_data, padding, sizeof(padding)))
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
test_cmac_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx, const int num_jobs)
{
        const struct mac_test *v = cmac_128_vectors;
        const struct cmac_subkeys *sk = cmac_128_subkeys;

        if (!quiet_mode)
                printf("AES-CMAC-128 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++, sk++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard CMAC-128 vector %zu Message length: %zu, "
                               "Tag length:%zu\n",
                               v->tcId, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_cmac(mb_mgr, v, sk, num_jobs, CMAC_128)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_cmac_hash_burst(mb_mgr, v, sk, num_jobs, CMAC_128)) {
                        printf("hash burst error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

static void
test_cmac_256_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                          const int num_jobs)
{
        const struct mac_test *v = cmac_256_vectors;
        const struct cmac_subkeys *sk = cmac_256_subkeys;

        if (!quiet_mode)
                printf("AES-CMAC-256 standard test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++, sk++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard CMAC-256 vector %zu Message length: %zu, "
                               "Tag length:%zu\n",
                               v->tcId, v->msgSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_cmac(mb_mgr, v, sk, num_jobs, CMAC_256)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
                if (test_cmac_hash_burst(mb_mgr, v, sk, num_jobs, CMAC_256)) {
                        printf("hash burst error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }
        }
        if (!quiet_mode)
                printf("\n");
}

int
cmac_test(struct IMB_MGR *mb_mgr)
{
        int i, errors = 0;
        struct test_suite_context ctx;
        struct test_json_alloc_ctx *ctx_128 = NULL;
        struct test_json_alloc_ctx *ctx_256 = NULL;

        if (load_cmac_vectors(&ctx_128, &ctx_256) < 0)
                return 1;

        /* CMAC 128 with standard vectors */
        test_suite_start(&ctx, "AES-CMAC-128");
        for (i = 1; i < IMB_MAX_BURST_SIZE; i++)
                test_cmac_std_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

        /* CMAC 256 with standard vectors */
        test_suite_start(&ctx, "AES-CMAC-256");
        for (i = 1; i < IMB_MAX_BURST_SIZE; i++)
                test_cmac_256_std_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

        free_cmac_vectors(ctx_128, ctx_256);
        cmac_128_vectors = NULL;
        cmac_256_vectors = NULL;

        return errors;
}
