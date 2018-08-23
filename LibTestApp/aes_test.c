/*****************************************************************************
 Copyright (c) 2018, Intel Corporation

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

int aes_test(const enum arch_type arch, struct MB_MGR *mb_mgr);

struct aes_vector {
	const uint8_t *K;          /* key */
	const uint8_t *IV;         /* initialization vector */
	const uint8_t *P;          /* plain text */
	uint64_t       Plen;       /* plain text length */
	const uint8_t *C;          /* cipher text - same length as plain text */
        uint32_t      Klen;        /* key length */
};

/*
 *  AES Test vectors from
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

/*  128-bit */
static const uint8_t K1[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const uint8_t IV1[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t P1[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
static const uint8_t C1[] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
        0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
        0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
        0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};

/*  192-bit */
static const uint8_t K2[] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
};
static const uint8_t IV2[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t P2[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
static const uint8_t C2[] = {
        0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
        0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
        0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
        0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
        0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0,
        0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
        0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81,
        0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd
};

/*  256-bit */
static const uint8_t K3[] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
static const uint8_t IV3[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t P3[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
static const uint8_t C3[] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
        0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
        0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
        0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
        0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
        0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
        0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
        0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
};

static const struct aes_vector aes_vectors[] = {
        {K1, IV1, P1, sizeof(P1), C1, sizeof(K1)},
        {K2, IV2, P2, sizeof(P2), C2, sizeof(K2)},
        {K3, IV3, P3, sizeof(P3), C3, sizeof(K3)},
};

/*  DOCSIS: AES CFB */
static const uint8_t DK1[] = {
        0xe6, 0x60, 0x0f, 0xd8, 0x85, 0x2e, 0xf5, 0xab,
        0xe6, 0x60, 0x0f, 0xd8, 0x85, 0x2e, 0xf5, 0xab
};

static const uint8_t DIV1[] = {
        0x81, 0x0e, 0x52, 0x8e, 0x1c, 0x5f, 0xda, 0x1a,
        0x81, 0x0e, 0x52, 0x8e, 0x1c, 0x5f, 0xda, 0x1a
};

static const uint8_t DP1[] = {
        0x00, 0x01, 0x02, 0x88, 0xEE, 0x59, 0x7E
};

static const uint8_t DC1[] = {
        0xFC, 0x68, 0xA3, 0x55, 0x60, 0x37, 0xDC
};

/*  DOCSIS: AES CBC + CFB */
static const uint8_t DK2[] = {
        0xe6, 0x60, 0x0f, 0xd8, 0x85, 0x2e, 0xf5, 0xab,
        0xe6, 0x60, 0x0f, 0xd8, 0x85, 0x2e, 0xf5, 0xab
};

static const uint8_t DIV2[] = {
        0x81, 0x0e, 0x52, 0x8e, 0x1c, 0x5f, 0xda, 0x1a,
        0x81, 0x0e, 0x52, 0x8e, 0x1c, 0x5f, 0xda, 0x1a
};

static const uint8_t DP2[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0c, 0x0d, 0x0e, 0x91,
        0xd2, 0xd1, 0x9f
};

static const uint8_t DC2[] = {
        0x9d, 0xd1, 0x67, 0x4b, 0xba, 0x61, 0x10, 0x1b,
        0x56, 0x75, 0x64, 0x74, 0x36, 0x4f, 0x10, 0x1d,
        0x44, 0xd4, 0x73
};

/*  DOCSIS: AES CBC */
static const uint8_t DK3[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const uint8_t DIV3[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const uint8_t DP3[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const uint8_t DC3[] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
        0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
        0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
        0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};

static const struct aes_vector docsis_vectors[] = {
        {DK1, DIV1, DP1, sizeof(DP1), DC1, sizeof(DK1)},
        {DK2, DIV2, DP2, sizeof(DP2), DC2, sizeof(DK2)},
        {DK3, DIV3, DP3, sizeof(DP3), DC3, sizeof(DK3)},
};

static int
aes_job_ok(const struct JOB_AES_HMAC *job,
           const uint8_t *out_text,
           const uint8_t *target,
           const uint8_t *padding,
           const size_t sizeof_padding,
           const unsigned text_len)
{
        const int num = (const int)((uint64_t)job->user_data2);

        if (job->status != STS_COMPLETED) {
                printf("%d error status:%d, job %d",
                       __LINE__, job->status, num);
                return 0;
        }
        if (memcmp(out_text, target + sizeof_padding,
                   text_len)) {
                printf("%d mismatched\n", num);
                return 0;
        }
        if (memcmp(padding, target, sizeof_padding)) {
                printf("%d overwrite head\n", num);
                return 0;
        }
        if (memcmp(padding,
                   target + sizeof_padding + text_len,
                   sizeof_padding)) {
                printf("%d overwrite tail\n", num);
                return 0;
        }
        return 1;
}

static int
test_aes_many(struct MB_MGR *mb_mgr,
              void *enc_keys,
              void *dec_keys,
              const void *iv,
              const uint8_t *in_text,
              const uint8_t *out_text,
              unsigned text_len,
              int dir,
              int order,
              JOB_CIPHER_MODE cipher,
              const int in_place,
              const int key_len,
              const int num_jobs)
{
        struct JOB_AES_HMAC *job;
        uint8_t padding[16];
        uint8_t **targets = malloc(num_jobs * sizeof(void *));
        int i, jobs_rx = 0, ret = -1;

        assert(targets != NULL);

        memset(padding, -1, sizeof(padding));

        for (i = 0; i < num_jobs; i++) {
                targets[i] = malloc(text_len + (sizeof(padding) * 2));
                memset(targets[i], -1, text_len + (sizeof(padding) * 2));
                if (in_place) {
                        /* copy input text to the allocated buffer */
                        memcpy(targets[i] + sizeof(padding), in_text, text_len);
                }
        }

        /* flush the scheduler */
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = dir;
                job->chain_order = order;
                if (!in_place) {
                        job->dst = targets[i] + sizeof(padding);
                        job->src = in_text;
                } else {
                        job->dst = targets[i] + sizeof(padding);
                        job->src = targets[i] + sizeof(padding);
                }
                job->cipher_mode = cipher;
                job->aes_enc_key_expanded = enc_keys;
                job->aes_dec_key_expanded = dec_keys;
                job->aes_key_len_in_bytes = key_len;

                job->iv = iv;
                job->iv_len_in_bytes = 16;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = text_len;
                job->user_data = targets[i];
                job->user_data2 = (void *)((uint64_t)i);

                job->hash_alg = NULL_HASH;

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (!aes_job_ok(job, out_text, job->user_data, padding,
                                       sizeof(padding), text_len))
                                goto end;
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (!aes_job_ok(job, out_text, job->user_data, padding,
                               sizeof(padding), text_len))
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

        for (i = 0; i < num_jobs; i++)
                free(targets[i]);
        free(targets);
        return ret;
}

static int
test_aes_vectors(struct MB_MGR *mb_mgr, const int vec_cnt,
                 const struct aes_vector *vec_tab, const char *banner,
                 const JOB_CIPHER_MODE cipher, const int num_jobs)
{
	int vect, errors = 0;
        DECLARE_ALIGNED(uint32_t enc_keys[15*4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15*4], 16);

	printf("%s (N jobs = %d):\n", banner, num_jobs);
	for (vect = 0; vect < vec_cnt; vect++) {
#ifdef DEBUG
		printf("[%d/%d] Standard vector key_len:%d\n",
                       vect + 1, vec_cnt,
                       (int) vec_tab[vect].Klen);
#else
		printf(".");
#endif
                switch (vec_tab[vect].Klen) {
                case 16:
                        IMB_AES_KEYEXP_128(mb_mgr, vec_tab[vect].K, enc_keys,
                                           dec_keys);
                        break;
                case 24:
                        IMB_AES_KEYEXP_192(mb_mgr, vec_tab[vect].K, enc_keys,
                                           dec_keys);
                        break;
                case 32:
                default:
                        IMB_AES_KEYEXP_256(mb_mgr, vec_tab[vect].K, enc_keys,
                                           dec_keys);
                        break;
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys,
                             vec_tab[vect].IV,
                             vec_tab[vect].P, vec_tab[vect].C,
                             (unsigned) vec_tab[vect].Plen,
                             ENCRYPT, CIPHER_HASH, cipher, 0,
                             vec_tab[vect].Klen, num_jobs)) {
                        printf("error #%d encrypt\n", vect + 1);
                        errors++;
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys,
                             vec_tab[vect].IV,
                             vec_tab[vect].C, vec_tab[vect].P,
                             (unsigned) vec_tab[vect].Plen,
                             DECRYPT, HASH_CIPHER, cipher, 0,
                             vec_tab[vect].Klen, num_jobs)) {
                        printf("error #%d decrypt\n", vect + 1);
                        errors++;
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys,
                             vec_tab[vect].IV,
                             vec_tab[vect].P, vec_tab[vect].C,
                             (unsigned) vec_tab[vect].Plen,
                             ENCRYPT, CIPHER_HASH, cipher, 1,
                             vec_tab[vect].Klen, num_jobs)) {
                        printf("error #%d encrypt in-place\n", vect + 1);
                        errors++;
                }

                if (test_aes_many(mb_mgr, enc_keys, dec_keys,
                             vec_tab[vect].IV,
                             vec_tab[vect].C, vec_tab[vect].P,
                             (unsigned) vec_tab[vect].Plen,
                             DECRYPT, HASH_CIPHER, cipher, 1,
                             vec_tab[vect].Klen, num_jobs)) {
                        printf("error #%d decrypt in-place\n", vect + 1);
                        errors++;
                }
	}
	printf("\n");
	return errors;
}

int
aes_test(const enum arch_type arch,
         struct MB_MGR *mb_mgr)
{
        const int num_jobs_tab[] = {
                1, 3, 4, 5, 7, 8, 9, 15, 16, 17
        };
        unsigned i;
        int errors = 0;

        (void) arch; /* unused */

        for (i = 0; i < DIM(num_jobs_tab); i++)
                errors += test_aes_vectors(mb_mgr, DIM(aes_vectors),
                                           aes_vectors,
                                           "AES-CBC standard test vectors", CBC,
                                           num_jobs_tab[i]);
        for (i = 0; i < DIM(num_jobs_tab); i++)
                errors += test_aes_vectors(mb_mgr, DIM(docsis_vectors),
                                           docsis_vectors,
                                           "AES-DOCSIS standard test vectors",
                                           DOCSIS_SEC_BPI, num_jobs_tab[i]);
	if (0 == errors)
		printf("...Pass\n");
	else
		printf("...Fail\n");

	return errors;
}
