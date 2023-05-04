/**********************************************************************
  Copyright(c) 2023 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>		/* for memcmp() */

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "utils.h"

int gmac_test(struct IMB_MGR *mb_mgr);

/*
 * GMAC vectors
 */
static uint8_t K29[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static uint8_t IV29[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
};
static uint8_t P29[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};
static uint8_t T29[] =  {
        0xC5, 0x3A, 0xF9, 0xE8
};

#define C29 NULL
#define C29_len 0
#define A29 NULL
#define A29_len 0

static uint8_t K30[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static uint8_t IV30[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
};
static uint8_t P30[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};
static uint8_t T30[] =  {
        0x4C, 0x0C, 0x4F, 0x47, 0x2D, 0x78, 0xF6, 0xD8,
        0x03, 0x53, 0x20, 0x2F, 0x1A, 0xDF, 0x90, 0xD0
};

#define C30 NULL
#define C30_len 0
#define A30 NULL
#define A30_len 0

static uint8_t K31[] = {
        0xaa, 0x74, 0x0a, 0xbf, 0xad, 0xcd, 0xa7, 0x79,
        0x22, 0x0d, 0x3b, 0x40, 0x6c, 0x5d, 0x7e, 0xc0,
        0x9a, 0x77, 0xfe, 0x9d, 0x94, 0x10, 0x45, 0x39,
};
static uint8_t IV31[] = {
        0xab, 0x22, 0x65, 0xb4, 0xc1, 0x68, 0x95,
        0x55, 0x61, 0xf0, 0x43, 0x15
};
static uint8_t P31[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
};
static uint8_t T31[] =  {
        0xCF, 0x82, 0x80, 0x64, 0x02, 0x46, 0xF4, 0xFB,
        0x33, 0xAE, 0x1D, 0x90, 0xEA, 0x48, 0x83, 0xDB
};

#define C31 NULL
#define C31_len 0
#define A31 NULL
#define A31_len 0

static uint8_t K32[] = {
        0xb5, 0x48, 0xe4, 0x93, 0x4f, 0x5c, 0x64, 0xd3,
        0xc0, 0xf0, 0xb7, 0x8f, 0x7b, 0x4d, 0x88, 0x24,
        0xaa, 0xc4, 0x6b, 0x3c, 0x8d, 0x2c, 0xc3, 0x5e,
        0xe4, 0xbf, 0xb2, 0x54, 0xe4, 0xfc, 0xba, 0xf7,
};
static uint8_t IV32[] = {
        0x2e, 0xed, 0xe1, 0xdc, 0x64, 0x47, 0xc7,
        0xaf, 0xc4, 0x41, 0x53, 0x58,
};
static uint8_t P32[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01
};
static uint8_t T32[] =  {
        0x77, 0x46, 0x0D, 0x6F, 0xB1, 0x87, 0xDB, 0xA9,
        0x46, 0xAD, 0xCD, 0xFB, 0xB7, 0xF9, 0x13, 0xA1
};

#define C32 NULL
#define C32_len 0
#define A32 NULL
#define A32_len 0

static const struct gcm_ctr_vector gmac_vectors[] = {
	vector(29),
	vector(30),
	vector(31),
	vector(32),
};

static int check_data(const uint8_t *test, const uint8_t *expected,
                      uint64_t len, const char *data_name)
{
	int mismatch;
	int is_error = 0;

        if (len == 0)
                return is_error;

        if (test == NULL || expected == NULL || data_name == NULL)
                return 1;

	mismatch = memcmp(test, expected, len);
	if (mismatch) {
                uint64_t a;

		is_error = 1;
		printf("  expected results don't match %s \t\t", data_name);
                for (a = 0; a < len; a++) {
                        if (test[a] != expected[a]) {
                                printf(" '%x' != '%x' at %llx of %llx\n",
                                       test[a], expected[a],
                                       (unsigned long long) a,
                                       (unsigned long long) len);
                                break;
                        }
                }
	}
	return is_error;
}

static void
aes_gmac_job(IMB_MGR *mb_mgr,
             const uint8_t *k,
             struct gcm_key_data *gmac_key,
             const uint64_t key_len,
             const uint8_t *in, const uint64_t len,
             const uint8_t *iv, const uint64_t iv_len,
             uint8_t *auth_tag, const uint64_t auth_tag_len)
{
        IMB_JOB *job;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        if (!job) {
                fprintf(stderr, "failed to get job\n");
                return;
        }

        if (key_len == 16) {
                IMB_AES128_GCM_PRE(mb_mgr, k, gmac_key);
                job->hash_alg = IMB_AUTH_AES_GMAC_128;
        } else if (key_len == 24) {
                IMB_AES192_GCM_PRE(mb_mgr, k, gmac_key);
                job->hash_alg = IMB_AUTH_AES_GMAC_192;
        } else { /* key_len == 32 */
                IMB_AES256_GCM_PRE(mb_mgr, k, gmac_key);
                job->hash_alg = IMB_AUTH_AES_GMAC_256;
        }

        job->cipher_mode = IMB_CIPHER_NULL;
        job->u.GMAC._key = gmac_key;
        job->u.GMAC._iv = iv;
        job->u.GMAC.iv_len_in_bytes = iv_len;
        job->src = in;
        job->msg_len_to_hash_in_bytes = len;
        job->hash_start_src_offset_in_bytes = UINT64_C(0);
        job->auth_tag_output                  = auth_tag;
        job->auth_tag_output_len_in_bytes     = auth_tag_len;

        job = IMB_SUBMIT_JOB(mb_mgr);
        while (job) {
                if (job->status != IMB_STATUS_COMPLETED)
                        fprintf(stderr, "failed job, status:%d\n", job->status);
                job = IMB_GET_COMPLETED_JOB(mb_mgr);
        }
        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                if (job->status != IMB_STATUS_COMPLETED)
                        fprintf(stderr, "failed job, status:%d\n", job->status);
        }
}

#define MAX_SEG_SIZE 64
static void
gmac_test_vector(IMB_MGR *mb_mgr,
                 const struct gcm_ctr_vector *vector,
                 const uint64_t seg_size,
                 const unsigned job_api,
                 struct test_suite_context *ts128,
                 struct test_suite_context *ts192,
                 struct test_suite_context *ts256)
{
        struct gcm_key_data key;
        struct gcm_context_data ctx;
        const uint8_t *iv = vector->IV;
        const uint64_t iv_len = vector->IVlen;
        const uint64_t nb_segs = (vector->Plen / seg_size);
        const uint64_t last_partial_seg = (vector->Plen % seg_size);
        const uint8_t *in_ptr = vector->P;
        uint8_t T_test[16];
        struct test_suite_context *ts = ts128;

        if (vector->Klen ==  IMB_KEY_192_BYTES)
                ts = ts192;

        if (vector->Klen ==  IMB_KEY_256_BYTES)
                ts = ts256;

        memset(&key, 0, sizeof(struct gcm_key_data));
        if (job_api) {
                aes_gmac_job(mb_mgr, vector->K, &key, vector->Klen, in_ptr,
                             seg_size, iv, iv_len, T_test, vector->Tlen);
        } else {
                uint8_t in_seg[MAX_SEG_SIZE];
                uint32_t i;

                switch (vector->Klen) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_PRE(mb_mgr, vector->K, &key);
                        IMB_AES128_GMAC_INIT(mb_mgr, &key, &ctx, iv, iv_len);
                        in_ptr = vector->P;
                        for (i = 0; i < nb_segs; i++) {
                                memcpy(in_seg, in_ptr, seg_size);
                                IMB_AES128_GMAC_UPDATE(mb_mgr, &key, &ctx,
                                                       in_seg,
                                                       seg_size);
                                in_ptr += seg_size;
                        }

                        if (last_partial_seg != 0) {
                                memcpy(in_seg, in_ptr, last_partial_seg);
                                IMB_AES128_GMAC_UPDATE(mb_mgr, &key, &ctx,
                                                       in_seg,
                                                       last_partial_seg);
                        }

                        IMB_AES128_GMAC_FINALIZE(mb_mgr, &key, &ctx, T_test,
                                                 vector->Tlen);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_PRE(mb_mgr, vector->K, &key);
                        IMB_AES192_GMAC_INIT(mb_mgr, &key, &ctx, iv, iv_len);
                        in_ptr = vector->P;
                        for (i = 0; i < nb_segs; i++) {
                                memcpy(in_seg, in_ptr, seg_size);
                                IMB_AES192_GMAC_UPDATE(mb_mgr, &key, &ctx,
                                                       in_seg,
                                                       seg_size);
                                in_ptr += seg_size;
                        }

                        if (last_partial_seg != 0) {
                                memcpy(in_seg, in_ptr, last_partial_seg);
                                IMB_AES192_GMAC_UPDATE(mb_mgr, &key, &ctx,
                                                       in_seg,
                                                       last_partial_seg);
                        }

                        IMB_AES192_GMAC_FINALIZE(mb_mgr, &key, &ctx, T_test,
                                                 vector->Tlen);
                        break;
                case IMB_KEY_256_BYTES:
                default:
                        IMB_AES256_GCM_PRE(mb_mgr, vector->K, &key);
                        IMB_AES256_GMAC_INIT(mb_mgr, &key, &ctx, iv, iv_len);
                        in_ptr = vector->P;
                        for (i = 0; i < nb_segs; i++) {
                                memcpy(in_seg, in_ptr, seg_size);
                                IMB_AES256_GMAC_UPDATE(mb_mgr, &key, &ctx,
                                                       in_seg,
                                                       seg_size);
                                in_ptr += seg_size;
                        }

                        if (last_partial_seg != 0) {
                                memcpy(in_seg, in_ptr, last_partial_seg);
                                IMB_AES256_GMAC_UPDATE(mb_mgr, &key, &ctx,
                                                       in_seg,
                                                       last_partial_seg);
                        }

                        IMB_AES256_GMAC_FINALIZE(mb_mgr, &key, &ctx, T_test,
                                                 vector->Tlen);
                        break;
                }
        }

        if (check_data(T_test, vector->T, vector->Tlen, "generated tag (T)"))
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);
}

int gmac_test(IMB_MGR *mb_mgr)
{
        struct test_suite_context ts128, ts192, ts256;
	int errors = 0;
	const int vectors_cnt = DIM(gmac_vectors);
	int vect;

        test_suite_start(&ts128, "AES-GMAC-128");
        test_suite_start(&ts192, "AES-GMAC-192");
        test_suite_start(&ts256, "AES-GMAC-256");

	printf("GMAC test vectors:\n");
	for (vect = 0; vect < vectors_cnt; vect++) {
                const struct gcm_ctr_vector *vector = &gmac_vectors[vect];
                uint64_t seg_size;

                /* Using direct API, which allows SGL */
                for (seg_size = 1; seg_size <= MAX_SEG_SIZE; seg_size++)
                        gmac_test_vector(mb_mgr, vector, seg_size, 0,
                                         &ts128, &ts192, &ts256);

                /* Using job API */
                gmac_test_vector(mb_mgr, vector, vector->Plen, 1,
                                 &ts128, &ts192, &ts256);
        }
        errors += test_suite_end(&ts128);
        errors += test_suite_end(&ts192);
        errors += test_suite_end(&ts256);

        return errors;
}
