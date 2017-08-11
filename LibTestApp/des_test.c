/*
 * Copyright (c) 2017, Intel Corporation
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <mb_mgr.h>
#include <des.h>

#include "gcm_ctr_vectors_test.h"

#ifndef DIM
#define DIM(x) (sizeof(x) / sizeof(x[0]))
#endif

struct des_vector {
	const uint8_t* K;          /* key */
	const uint8_t* IV;         /* initialization vector */
	const uint8_t* P;          /* plain text */
	uint64_t       Plen;       /* plain text length */
	const uint8_t* C;          /* cipher text - same length as plain text */
};

/* CM-SP-SECv3.1-I07-170111 I.7 */
static const uint8_t K1[] = {
        0xe6, 0x60, 0x0f, 0xd8, 0x85, 0x2e, 0xf5, 0xab
};
static const uint8_t IV1[] = {
        0x81, 0x0e, 0x52, 0x8e, 0x1c, 0x5f, 0xda, 0x1a
};
static const uint8_t P1[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x88, 0x41, 0x65, 0x06
};
static const uint8_t C1[] = {
        0x0d, 0xda, 0x5a, 0xcb, 0xd0, 0x5e, 0x55, 0x67,
        0x9f, 0x04, 0xd1, 0xb6, 0x41, 0x3d, 0x4e, 0xed
};

static struct des_vector vectors[] = {
        {K1, IV1, P1, sizeof(P1), C1},
};

/* CM-SP-SECv3.1-I07-170111 I.7 */
static const uint8_t DK1[] = {
        0xe6, 0x60, 0x0f, 0xd8, 0x85, 0x2e, 0xf5, 0xab
};
static const uint8_t DIV1[] = {
        0x81, 0x0e, 0x52, 0x8e, 0x1c, 0x5f, 0xda, 0x1a
};
static const uint8_t DP1[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x88, 0x41, 0x65, 0x06
};
static const uint8_t DC1[] = {
        0x0d, 0xda, 0x5a, 0xcb, 0xd0, 0x5e, 0x55, 0x67,
        0x9f, 0x04, 0xd1, 0xb6, 0x41, 0x3d, 0x4e, 0xed
};

static const uint8_t DK2[] = {
        0xe6, 0x60, 0x0f, 0xd8, 0x85, 0x2e, 0xf5, 0xab
};
static const uint8_t DIV2[] = {
        0x81, 0x0e, 0x52, 0x8e, 0x1c, 0x5f, 0xda, 0x1a
};
static const uint8_t DP2[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x91,
        0xd2, 0xd1, 0x9f
};
static const uint8_t DC2[] = {
        0x0d, 0xda, 0x5a, 0xcb, 0xd0, 0x5e, 0x55, 0x67,
        0x51, 0x47, 0x46, 0x86, 0x8a, 0x71, 0xe5, 0x77,
        0xef, 0xac, 0x88
};

static struct des_vector docsis_vectors[] = {
        {DK1, DIV1, DP1, sizeof(DP1), DC1},
        {DK2, DIV2, DP2, sizeof(DP2), DC2},
};

static int
test_des(struct MB_MGR *mb_mgr,
         const uint64_t *ks,
         const void *iv,
         const uint8_t *in_text,
         const uint8_t *out_text,
         unsigned text_len,
         int dir,
         int order,
         JOB_CIPHER_MODE cipher)
{
        struct JOB_AES_HMAC *job;
        uint8_t padding[16];
        uint8_t *target = malloc(text_len + (sizeof(padding) * 2));
        int ret = -1;

        assert(target != NULL);
        
        memset(target, -1, text_len + (sizeof(padding) * 2));
        memset(padding, -1, sizeof(padding));

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        job->cipher_direction = dir;
        job->chain_order = order;
        job->dst = target + 16;
        job->src = in_text;
        job->cipher_mode = cipher;
        job->aes_enc_key_expanded = ks;
        job->aes_dec_key_expanded = ks;
        job->aes_key_len_in_bytes = 8;
        job->iv = iv;
        job->iv_len_in_bytes = 8;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = text_len;

        job->hash_alg = NULL_HASH;
        job->hashed_auth_key_xor_ipad = NULL;
        job->hashed_auth_key_xor_opad = NULL;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = 0;
        job->auth_tag_output = NULL;
        job->auth_tag_output_len_in_bytes = 0;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job) {
                printf("%d Unexpected return from submit_job\n", __LINE__);
                goto end;
        }
        job = IMB_FLUSH_JOB(mb_mgr);
        if (!job) {
                printf("%d Unexpected null return from flush_job\n", __LINE__);
                goto end;
        }
        if (job->status != STS_COMPLETED) {
                printf("%d Error status:%d", __LINE__, job->status);
                goto end;
        }
        if (memcmp(out_text, target + 16, text_len)) {
                printf("mismatched\n");
                goto end;
        }
        if (memcmp(padding, target, sizeof(padding))) {
                printf("overwrite head\n");
                goto end;
        }
        if (memcmp(padding, target + sizeof(padding) + text_len,  sizeof(padding))) {
                printf("overwrite tail\n");
                goto end;
        }
        ret = 0;
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL)
                ;
 end:
        free(target);
        return ret;
}

static int
test_des_vectors(struct MB_MGR *mb_mgr, const int vec_cnt,
                 const struct des_vector *vec_tab, const char *banner,
                 const JOB_CIPHER_MODE cipher)
{
	int vect, errors = 0;
        uint64_t ks[16];

	printf("%s:\n", banner);
	for (vect = 0; (vect < vec_cnt); vect++) {
#ifdef DEBUG
		printf("Standard vector %d/%d  PTLen:%d\n",
                       vect, vec_cnt - 1,
                       (int) vec_tab[vect].Plen);
#else
		printf(".");
#endif
                des_key_schedule(ks, vec_tab[vect].K);

                if (test_des(mb_mgr, ks, 
                             vec_tab[vect].IV,
                             vec_tab[vect].P, vec_tab[vect].C,
                             (unsigned) vec_tab[vect].Plen,
                             ENCRYPT, CIPHER_HASH, cipher)) {
                        printf("error #%d encrypt\n", vect + 1);
                        errors++;
                }

                if (test_des(mb_mgr, ks,
                             vec_tab[vect].IV,
                             vec_tab[vect].C, vec_tab[vect].P,
                             (unsigned) vec_tab[vect].Plen,
                             DECRYPT, HASH_CIPHER, cipher)) {
                        printf("error #%d decrypt\n", vect + 1);
                        errors++;
                }

	}
	printf("\n");
	return errors;
}


int
des_test(const enum arch_type arch,
         struct MB_MGR *mb_mgr)
{
        int errors;

        errors = test_des_vectors(mb_mgr, DIM(vectors), vectors,
                                  "DES standard test vectors", DES);

        errors += test_des_vectors(mb_mgr, DIM(docsis_vectors), docsis_vectors,
                                   "DOCSIS DES standard test vectors", DOCSIS_DES);

	if (0 == errors)
		printf("...Pass\n");
	else
		printf("...Fail\n");
        
	return errors;
}
