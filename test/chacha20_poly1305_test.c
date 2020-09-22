/*****************************************************************************
 Copyright (c) 2020, Intel Corporation

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

int chacha20_poly1305_test(struct IMB_MGR *mb_mgr);

/*
 * Test vectors from RFC7539 https://tools.ietf.org/html/rfc7539
 */

/* 2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305 */
static const uint8_t plain_vec0[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
};

static const uint8_t cipher_vec0[] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
};

static const uint8_t aad_vec0[] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
};

static const uint8_t key_vec0[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

static const uint8_t iv_vec0[12] = {
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
};
static const uint8_t tag_vec0[16] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
};

/* A.5.  ChaCha20-Poly1305 AEAD Decryption */


static const uint8_t key_vec1[32] = {
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0
};

static const uint8_t cipher_vec1[] = {
        0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4,
        0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
        0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89,
        0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2,
        0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee,
        0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0,
        0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00,
        0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf,
        0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce,
        0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81,
        0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd,
        0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55,
        0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61,
        0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38,
        0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0,
        0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4,
        0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46,
        0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9,
        0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e,
        0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e,
        0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15,
        0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a,
        0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea,
        0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a,
        0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99,
        0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
        0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10,
        0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
        0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94,
        0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30,
        0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf,
        0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29,
        0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70,
        0x9b
};

static const uint8_t iv_vec1[12] = {
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08
};

static const uint8_t aad_vec1[] = {
        0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x4e, 0x91
};

static const uint8_t tag_vec1[16] = {
        0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22,
        0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38
};

static const uint8_t plain_vec1[] = {
        0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74,
        0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x73, 0x20,
        0x61, 0x72, 0x65, 0x20, 0x64, 0x72, 0x61, 0x66,
        0x74, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
        0x6e, 0x74, 0x73, 0x20, 0x76, 0x61, 0x6c, 0x69,
        0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x20,
        0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x20,
        0x6f, 0x66, 0x20, 0x73, 0x69, 0x78, 0x20, 0x6d,
        0x6f, 0x6e, 0x74, 0x68, 0x73, 0x20, 0x61, 0x6e,
        0x64, 0x20, 0x6d, 0x61, 0x79, 0x20, 0x62, 0x65,
        0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64,
        0x2c, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x63,
        0x65, 0x64, 0x2c, 0x20, 0x6f, 0x72, 0x20, 0x6f,
        0x62, 0x73, 0x6f, 0x6c, 0x65, 0x74, 0x65, 0x64,
        0x20, 0x62, 0x79, 0x20, 0x6f, 0x74, 0x68, 0x65,
        0x72, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
        0x6e, 0x74, 0x73, 0x20, 0x61, 0x74, 0x20, 0x61,
        0x6e, 0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x2e,
        0x20, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x69,
        0x6e, 0x61, 0x70, 0x70, 0x72, 0x6f, 0x70, 0x72,
        0x69, 0x61, 0x74, 0x65, 0x20, 0x74, 0x6f, 0x20,
        0x75, 0x73, 0x65, 0x20, 0x49, 0x6e, 0x74, 0x65,
        0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61,
        0x66, 0x74, 0x73, 0x20, 0x61, 0x73, 0x20, 0x72,
        0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65,
        0x20, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61,
        0x6c, 0x20, 0x6f, 0x72, 0x20, 0x74, 0x6f, 0x20,
        0x63, 0x69, 0x74, 0x65, 0x20, 0x74, 0x68, 0x65,
        0x6d, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20,
        0x74, 0x68, 0x61, 0x6e, 0x20, 0x61, 0x73, 0x20,
        0x2f, 0xe2, 0x80, 0x9c, 0x77, 0x6f, 0x72, 0x6b,
        0x20, 0x69, 0x6e, 0x20, 0x70, 0x72, 0x6f, 0x67,
        0x72, 0x65, 0x73, 0x73, 0x2e, 0x2f, 0xe2, 0x80,
        0x9d
};

struct aead_vector {
        const uint8_t *plain;
        const uint8_t *cipher;
        size_t msg_len;
        const uint8_t *aad;
        size_t aad_len;
        const uint8_t *iv;
        const uint8_t *key;
        const uint8_t *tag;
} aead_vectors[] = {
        {plain_vec0, cipher_vec0, sizeof(plain_vec0),
         aad_vec0, sizeof(aad_vec0), iv_vec0, key_vec0, tag_vec0},
        {plain_vec1, cipher_vec1, sizeof(plain_vec1),
         aad_vec1, sizeof(aad_vec1), iv_vec1, key_vec1, tag_vec1},
};

static int
aead_job_ok(struct IMB_MGR *mb_mgr,
            const struct aead_vector *vec,
            const struct IMB_JOB *job,
            const uint8_t *auth,
            const uint8_t *padding,
            const size_t sizeof_padding)
{
        const size_t auth_len = job->auth_tag_output_len_in_bytes;
        const uint8_t *out_text = (const uint8_t *) job->dst;

        if (job->status != STS_COMPLETED) {
                const int errcode = imb_get_errno(mb_mgr);

                printf("Error!: job status %d, errno %d => %s\n",
                       job->status, errcode, imb_get_strerror(errcode));
                return 0;
        }

        /* hash checks */
        if (memcmp(padding, &auth[sizeof_padding + auth_len],
                   sizeof_padding)) {
                printf("hash overwrite tail\n");
                hexdump(stderr, "Target",
                        &auth[sizeof_padding + auth_len], sizeof_padding);
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

        if (job->cipher_direction == IMB_DIR_ENCRYPT) {
                if (memcmp(vec->cipher, job->dst, vec->msg_len)) {
                        printf("cipher text mismatched\n");
                        hexdump(stderr, "Received", job->dst, vec->msg_len);
                        hexdump(stderr, "Expected", vec->cipher, vec->msg_len);
                        return 0;
                }
        } else {
                if (memcmp(vec->plain, job->dst, vec->msg_len)) {
                        printf("plain text mismatched\n");
                        hexdump(stderr, "Received", job->dst, vec->msg_len);
                        hexdump(stderr, "Expected", vec->plain, vec->msg_len);
                        return 0;
                }
        }

        if (memcmp(padding, out_text - sizeof_padding, sizeof_padding)) {
                printf("destination buffer under-run (memory before)\n");
                hexdump(stderr, "", out_text - sizeof_padding, sizeof_padding);
                return 0;
        }

        if (memcmp(padding, out_text + vec->msg_len, sizeof_padding)) {
                printf("destination buffer overrun (memory after)\n");
                hexdump(stderr, "", out_text + vec->msg_len,
                        sizeof_padding);
                return 0;
        }
        return 1;
}

static int
test_aead(struct IMB_MGR *mb_mgr,
          const struct aead_vector *vec,
          const int dir,
          const int num_jobs,
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
                auths[i] = malloc(16 + (sizeof(padding) * 2));
                if (auths[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }

                memset(auths[i], -1, 16 + (sizeof(padding) * 2));
        }

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(vec->msg_len + (sizeof(padding) * 2));
                if (targets[i] == NULL) {
                        fprintf(stderr, "Can't allocate buffer memory\n");
                        goto end;
                }
                memset(targets[i], -1, vec->msg_len + (sizeof(padding) * 2));

                if (in_place) {
                        if (dir == IMB_DIR_ENCRYPT)
                                memcpy(targets[i] + sizeof(padding),
                                       vec->plain, vec->msg_len);
                        else
                                memcpy(targets[i] + sizeof(padding),
                                       vec->cipher, vec->msg_len);
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
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
                job->key_len_in_bytes = 32;

                job->u.CHACHA20_POLY1305.aad = vec->aad;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = vec->aad_len;

                if (in_place)
                        job->src = targets[i] + sizeof(padding);
                else
                        if (dir == IMB_DIR_ENCRYPT)
                                job->src = vec->plain;
                        else
                                job->src = vec->cipher;
                job->dst = targets[i] + sizeof(padding);

                job->iv = vec->iv;
                job->iv_len_in_bytes = 12;
                job->msg_len_to_cipher_in_bytes = vec->msg_len;
                job->cipher_start_src_offset_in_bytes = 0;

                job->msg_len_to_hash_in_bytes = vec->msg_len;
                job->hash_start_src_offset_in_bytes = 0;
                job->auth_tag_output = auths[i] + sizeof(padding);
                job->auth_tag_output_len_in_bytes = 16;

                job->user_data = auths[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job) {
                        jobs_rx++;
                        if (!aead_job_ok(mb_mgr, vec, job, job->user_data,
                                         padding, sizeof(padding)))
                                goto end;
                } else {
                        int err = imb_get_errno(mb_mgr);

                        if (err != 0) {
                                printf("submit_job error %d : '%s'\n", err,
                                       imb_get_strerror(err));
                                goto end;
                        }
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;

                if (!aead_job_ok(mb_mgr, vec, job, job->user_data,
                                 padding, sizeof(padding)))
                        goto end;
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %d jobs, received %d\n", num_jobs, jobs_rx);
                goto end;
        }


        ret = 0;

 end:
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
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

static int
test_aead_vectors(struct IMB_MGR *mb_mgr,
                  const int num_jobs,
                  const struct aead_vector *vec_array,
                  const size_t vec_array_size,
                  const char *banner)
{
	size_t vect;
	int errors = 0;

	printf("%s (N jobs = %d):\n", banner, num_jobs);
	for (vect = 0; vect < vec_array_size; vect++) {
#ifdef DEBUG
		printf("Vector [%d/%d], M len: %d\n",
                       (int) vect + 1, (int) vec_array_size,
                       (int) vec_array[vect].msg_len);
#else
		printf(".");
#endif

                if (test_aead(mb_mgr, &vec_array[vect],
                              IMB_DIR_ENCRYPT, num_jobs, 1)) {
                        printf("error #%u encrypt in-place\n",
                               (unsigned) vect + 1);
                        errors++;
                }

                if (test_aead(mb_mgr, &vec_array[vect],
                              IMB_DIR_DECRYPT, num_jobs, 1)) {
                        printf("error #%u decrypt in-place\n",
                               (unsigned) vect + 1);
                        errors++;
                }

                if (test_aead(mb_mgr, &vec_array[vect],
                              IMB_DIR_ENCRYPT, num_jobs, 0)) {
                        printf("error #%u encrypt out-of-place\n",
                               (unsigned) vect + 1);
                        errors++;
                }

                if (test_aead(mb_mgr, &vec_array[vect],
                              IMB_DIR_DECRYPT, num_jobs, 0)) {
                        printf("error #%u decrypt out-of-place\n",
                               (unsigned) vect + 1);
                        errors++;
                }

	}
	printf("\n");
        return errors;
}


int
chacha20_poly1305_test(struct IMB_MGR *mb_mgr)
{
        int i, errors = 0;

        for (i = 1; i < 20; i++)
                errors += test_aead_vectors(mb_mgr, i, aead_vectors,
                                            DIM(aead_vectors),
                                            "AEAD Chacha20-Poly1305 vectors");

	if (0 == errors)
		printf("...Pass\n");
	else
		printf("...Fail\n");

	return errors;
}
