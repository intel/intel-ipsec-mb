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
        CMAC_128_BITLEN,
        CMAC_256,
};

int
cmac_test(struct IMB_MGR *mb_mgr);

extern const struct mac_test cmac_128_test_json[];
extern const struct mac_test cmac_256_test_json[];
extern const struct mac_test cmac_3gpp_test_json[];

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

static const struct cmac_subkeys cmac_3gpp_subkeys[] = {
        { "\x2b\xd6\x45\x9f\x82\xc5\xb3\x00\x95\x2c\x49\x10\x48\x81\xff\x48",
          "\xdc\x84\xc2\x70\xb5\xbf\x83\xf9\x6f\x90\xbe\x18\x8d\x3f\x64\x18",
          "\xb9\x09\x84\xe1\x6b\x7f\x07\xf2\xdf\x21\x7c\x31\x1a\x7e\xc8\xb7" },
        { "\xd3\xc5\xd5\x92\x32\x7f\xb1\x1c\x40\x35\xc6\x68\x0a\xf8\xc6\xd1",
          "\x36\xe3\xe5\x32\x26\x52\x2b\xa6\xc0\xa4\x23\x6b\xcb\xbf\x0c\xe3",
          "\x6d\xc7\xca\x64\x4c\xa4\x57\x4d\x81\x48\x46\xd7\x97\x7e\x19\xc6" },
        { "\x7e\x5e\x94\x43\x1e\x11\xd7\x38\x28\xd7\x39\xcc\x6c\xed\x45\x73",
          "\xaf\x16\x8c\x50\x6a\xf0\x3c\xf3\xa4\x4a\xbf\x1a\x61\x34\xc1\x59",
          "\x5e\x2d\x18\xa0\xd5\xe0\x79\xe7\x48\x95\x7e\x34\xc2\x69\x82\x35" },
        { "\xd3\x41\x9b\xe8\x21\x08\x7a\xcd\x02\x12\x3a\x92\x48\x03\x33\x59",
          "\x0a\x9b\xa0\x10\x5b\x3d\x9a\x43\x47\xe6\x56\x15\x4e\x6d\x37\xc8",
          "\x15\x37\x40\x20\xb6\x7b\x34\x86\x8f\xcc\xac\x2a\x9c\xda\x6f\x90" },
        { "\x83\xfd\x23\xa2\x44\xa7\x4c\xf3\x58\xda\x30\x19\xf1\x72\x26\x35",
          "\x3b\xec\x38\xae\x79\x0d\x59\x58\xe0\x9b\x73\xab\x61\xbd\x48\x0f",
          "\x77\xd8\x71\x5c\xf2\x1a\xb2\xb1\xc1\x36\xe7\x56\xc3\x7a\x90\x1e" },
        { "\x68\x32\xa6\x5c\xff\x44\x73\x62\x1e\xbd\xd4\xba\x26\xa9\x21\xfe",
          "\xca\x02\x47\x87\x0f\xc2\x7f\xad\x1b\x17\xe1\xa1\x48\xb0\x2d\x8d",
          "\x94\x04\x8f\x0e\x1f\x84\xff\x5a\x36\x2f\xc3\x42\x91\x60\x5b\x9d" },
        { "\x5d\x0a\x80\xd8\x13\x4a\xe1\x96\x77\x82\x4b\x67\x1e\x83\x8a\xf4",
          "\x30\x65\xc4\x53\xf7\x72\x72\xe1\x79\xef\x65\x04\x7d\xc9\xfc\x3d",
          "\x60\xcb\x88\xa7\xee\xe4\xe5\xc2\xf3\xde\xca\x08\xfb\x93\xf8\x7a" },
        { "\xb3\x12\x0f\xfd\xb2\xcf\x6a\xf4\xe7\x3e\xaf\x2e\xf4\xeb\xec\x69",
          "\x58\xc8\xbb\x9a\xe4\x22\x92\xc3\xb1\x73\x90\xc8\xf5\x58\x58\xb6",
          "\xb1\x91\x77\x35\xc8\x45\x25\x87\x62\xe7\x21\x91\xea\xb0\xb1\x6c" },
        { NULL, NULL, NULL }
};

static int
cmac_subkey_test(const struct cmac_subkeys *skeys, uint32_t *skey1, uint32_t *skey2)
{
        uint32_t sub_key_size = sizeof(skey1);

        if (memcmp(skeys->sub_key1, skey1, sub_key_size)) {
                printf("sub-key1 mismatched\n");
                hexdump(stderr, "Received", &skey1, sub_key_size);
                hexdump(stderr, "Expected", (const void *) skeys->sub_key1, sub_key_size);
                return 0;
        }

        sub_key_size = sizeof(skey2);

        if (memcmp(skeys->sub_key2, skey2, sub_key_size)) {
                printf("sub-key2 mismatched\n");
                hexdump(stderr, "Received", &skey2, sub_key_size);
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

        if ((type == CMAC_128) || (type == CMAC_128_BITLEN)) {
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
                case CMAC_128_BITLEN:
                        job->hash_alg = IMB_AUTH_AES_CMAC_BITLEN;
                        /* check for std or 3gpp vectors
                           scale len if necessary */
                        job->msg_len_to_hash_in_bits = vec->msgSize;
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
                case CMAC_128_BITLEN:
                        job->hash_alg = IMB_AUTH_AES_CMAC_BITLEN;
                        /* check for std or 3gpp vectors
                           scale len if necessary */
                        job->msg_len_to_hash_in_bits = vec->msgSize;
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

        if ((type == CMAC_128) || (type == CMAC_128_BITLEN)) {
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
                case CMAC_128_BITLEN:
                        job->hash_alg = IMB_AUTH_AES_CMAC_BITLEN;
                        /* check for std or 3gpp vectors
                           scale len if necessary */
                        job->msg_len_to_hash_in_bits = vec->msgSize;
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
        const struct mac_test *v = cmac_128_test_json;
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
        const struct mac_test *v = cmac_256_test_json;
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

static void
test_cmac_bitlen_std_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                             const int num_jobs)
{
        const struct mac_test *v = cmac_128_test_json;
        const struct cmac_subkeys *sk = cmac_128_subkeys;

        if (!quiet_mode)
                printf("AES-CMAC-128 BITLEN standard test vectors "
                       "(N jobs = %d):\n",
                       num_jobs);
        for (; v->msg != NULL; v++, sk++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard bit length vector %zu Message length (bits): %zu, "
                               "Tag length:%zu\n",
                               v->tcId, v->msgSize, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_cmac(mb_mgr, v, sk, num_jobs, CMAC_128_BITLEN)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_cmac_hash_burst(mb_mgr, v, sk, num_jobs, CMAC_128_BITLEN)) {
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
test_cmac_bitlen_3gpp_vectors(struct IMB_MGR *mb_mgr, struct test_suite_context *ctx,
                              const int num_jobs)
{
        const struct mac_test *v = cmac_3gpp_test_json;
        const struct cmac_subkeys *sk = cmac_3gpp_subkeys;

        if (!quiet_mode)
                printf("AES-CMAC-128 BITLEN 3GPP test vectors (N jobs = %d):\n", num_jobs);
        for (; v->msg != NULL; v++, sk++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("3gpp vector %zu Message length (bits): %zu, "
                               "Tag length:%zu\n",
                               v->tcId, v->msgSize, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                if (test_cmac(mb_mgr, v, sk, num_jobs, CMAC_128_BITLEN)) {
                        printf("error #%zu\n", v->tcId);
                        test_suite_update(ctx, 0, 1);
                } else {
                        test_suite_update(ctx, 1, 0);
                }

                if (test_cmac_hash_burst(mb_mgr, v, sk, num_jobs, CMAC_128_BITLEN)) {
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

        /* CMAC 128 with standard vectors */
        test_suite_start(&ctx, "AES-CMAC-128");
        for (i = 1; i < IMB_MAX_BURST_SIZE; i++)
                test_cmac_std_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

        /* CMAC 128 BITLEN with standard vectors */
        test_suite_start(&ctx, "AES-CMAC-128-BIT-LENGTH");
        for (i = 1; i < IMB_MAX_BURST_SIZE; i++)
                test_cmac_bitlen_std_vectors(mb_mgr, &ctx, i);

        /* CMAC 128 BITLEN with 3GPP vectors */
        for (i = 1; i < IMB_MAX_BURST_SIZE; i++)
                test_cmac_bitlen_3gpp_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

        /* CMAC 256 with standard vectors */
        test_suite_start(&ctx, "AES-CMAC-256");
        for (i = 1; i < IMB_MAX_BURST_SIZE; i++)
                test_cmac_256_std_vectors(mb_mgr, &ctx, i);
        errors += test_suite_end(&ctx);

        return errors;
}
