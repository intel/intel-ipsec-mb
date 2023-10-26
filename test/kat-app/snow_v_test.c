/**********************************************************************
  Copyright(c) 2021-2023 Intel Corporation All rights reserved.

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
#include <string.h> /* for memcmp() */
#include <assert.h>
#include <limits.h>

#include <intel-ipsec-mb.h>
#include "gcm_ctr_vectors_test.h"
#include "utils.h"
#include "cipher_test.h"

extern const struct cipher_test snow_v_test_json[];

int
snow_v_test(IMB_MGR *p_mgr);
/**
 * Test vectors for SNOW-V-GCM from 'A new SNOW stream cipher called SNOW-V',
 * Patrik Ekdahl1, Thomas Johansson2, Alexander Maximov1 and Jing Yang2
 **/
static const uint8_t ZERO_KEY[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t ZERO_IV[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t ZERO_PLAIN[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t SPEC_SNOW_V_GCM_AUTH_TAGs[][16] = {
        { 0x02, 0x9a, 0x62, 0x4c, 0xda, 0xa4, 0xd4, 0x6c, 0xb9, 0xa0, 0xef, 0x40, 0x46, 0x95, 0x6c,
          0x9f },
        { 0xfc, 0x7c, 0xac, 0x57, 0x4c, 0x49, 0xfe, 0xae, 0x61, 0x50, 0x31, 0x5b, 0x96, 0x85, 0x42,
          0x4c },
        { 0x5a, 0x5a, 0xa5, 0xfb, 0xd6, 0x35, 0xef, 0x1a, 0xe1, 0x29, 0x61, 0x42, 0x03, 0xe1, 0x03,
          0x84 },
        { 0x25, 0x0e, 0xc8, 0xd7, 0x7a, 0x02, 0x2c, 0x08, 0x7a, 0xdf, 0x08, 0xb6, 0x5a, 0xdc, 0xbb,
          0x1a },
};

static const uint8_t SPEC_SNOW_V_GCM_CIPHER[] = { 0xdd, 0x7e, 0x01, 0xb2, 0xb4, 0x24, 0xa2,
                                                  0xef, 0x82, 0x50, 0xdd, 0xfe, 0x4e, 0x31,
                                                  0xe7, 0xbf, 0xe6, 0x90, 0x23, 0x31, 0xec,
                                                  0x5c, 0xe3, 0x19, 0xd9, 0x0d };

static const uint8_t SPEC_SNOW_V_GCM_KEY[] = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                                               0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                                               0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a,
                                               0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa };

static const uint8_t SPEC_SNOW_V_GCM_IV[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                              0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };

static const uint8_t SPEC_SNOW_V_GCM_AAD[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                               0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };

static const uint8_t SPEC_SNOW_V_GCM_AAD_2[] = { 0x41, 0x41, 0x44, 0x20, 0x74, 0x65, 0x73, 0x74,
                                                 0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x21 };

static const uint8_t SPEC_SNOW_V_GCM_PLAIN[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                                                 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64,
                                                 0x65, 0x66, 0x20, 0x53, 0x6e, 0x6f, 0x77,
                                                 0x56, 0x2d, 0x41, 0x45, 0x41, 0x44, 0x20,
                                                 0x6d, 0x6f, 0x64, 0x65, 0x21 };

static const uint8_t SPEC_SNOW_V_GCM_CIPHER_V6[] = {
        0xdd, 0x7e, 0x01, 0xb2, 0xb4, 0x24, 0xa2, 0xef, 0x82, 0x50, 0x27, 0x07, 0xe8,
        0x7a, 0x32, 0xc1, 0x52, 0xb0, 0xd0, 0x18, 0x18, 0xfd, 0x7f, 0x12, 0x24, 0x3e,
        0xb5, 0xa1, 0x56, 0x59, 0xe9, 0x1b, 0x4c, 0x90, 0x7e, 0xa6, 0xa5, 0xb7, 0x3a,
        0x51, 0xde, 0x74, 0x7c, 0x3e, 0x9a, 0xd9, 0xee, 0x02, 0x9b
};

typedef struct snow_v_aead_test_vectors_s {
        const uint8_t *KEY;
        const uint8_t *IV;
        const uint8_t *aad;
        uint64_t aad_length_in_bytes;
        uint64_t length_in_bytes;
        const uint8_t *plaintext;
        const uint8_t *ciphertext;
} snow_v_aead_test_vectors_t;

static const snow_v_aead_test_vectors_t snow_v_aead_test_vectors[] = {
        /* == SNOW-V-GCM test vectors from spec #1 - #6 */
        { ZERO_KEY, ZERO_IV, NULL, 0, 0, ZERO_PLAIN, SPEC_SNOW_V_GCM_AUTH_TAGs[0] },
        { SPEC_SNOW_V_GCM_KEY, SPEC_SNOW_V_GCM_IV, NULL, 0, 0, ZERO_PLAIN,
          SPEC_SNOW_V_GCM_AUTH_TAGs[1] },
        { ZERO_KEY, ZERO_IV, SPEC_SNOW_V_GCM_AAD, 16, 0, ZERO_PLAIN, SPEC_SNOW_V_GCM_AUTH_TAGs[2] },
        { SPEC_SNOW_V_GCM_KEY, SPEC_SNOW_V_GCM_IV, SPEC_SNOW_V_GCM_AAD, 16, 0, ZERO_PLAIN,
          SPEC_SNOW_V_GCM_AUTH_TAGs[3] },
        { SPEC_SNOW_V_GCM_KEY, SPEC_SNOW_V_GCM_IV, NULL, 0, 10, SPEC_SNOW_V_GCM_AAD,
          SPEC_SNOW_V_GCM_CIPHER },
        { SPEC_SNOW_V_GCM_KEY, SPEC_SNOW_V_GCM_IV, SPEC_SNOW_V_GCM_AAD_2,
          sizeof(SPEC_SNOW_V_GCM_AAD_2), sizeof(SPEC_SNOW_V_GCM_PLAIN), SPEC_SNOW_V_GCM_PLAIN,
          SPEC_SNOW_V_GCM_CIPHER_V6 }
};

static uint32_t
compare(const uint8_t *result, const uint8_t *expected, const size_t size)
{
        if (memcmp(result, expected, size) != 0) {
                hexdump(stderr, "expected", expected, size);
                hexdump(stderr, "received", result, size);
                return 1;
        }
        return 0;
}

/* check for buffer under/over-write */
static uint32_t
check_buffer_over_under_write(uint8_t *result, const int pad_pattern, const size_t pad_size,
                              const size_t alloc_size)
{
        uint8_t *pad_block = malloc(pad_size);
        uint8_t error = 0;

        if (pad_block == NULL) {
                fprintf(stderr, "Error allocating %lu bytes!\n", (unsigned long) pad_size);
                exit(EXIT_FAILURE);
        }

        /* check for buffer under/over-write */
        memset(pad_block, pad_pattern, pad_size);

        if (memcmp(pad_block, result, pad_size) != 0) {
                hexdump(stderr, "underwrite detected", result, pad_size);
                error = 1;
        }

        if (memcmp(pad_block, &result[alloc_size - pad_size], pad_size) != 0) {
                hexdump(stderr, "overwrite detected", &result[alloc_size - pad_size], pad_size);
                error = 1;
        }

        free(pad_block);

        return error;
}

static void
snow_v_single_test(IMB_MGR *p_mgr, struct test_suite_context *ts, const void *key, const void *iv,
                   const void *plain, const size_t size, const void *expected)
{
        const size_t pad_size = 16;
        const size_t alloc_size = size + (2 * pad_size);
        const int pad_pattern = 0xa5;
        uint8_t *dst_ptr = NULL, *output = malloc(alloc_size);
        uint32_t pass = 0, fail = 0;
        struct IMB_JOB *job;

        if (output == NULL) {
                fprintf(stderr, "Error allocating %lu bytes!\n", (unsigned long) alloc_size);
                exit(EXIT_FAILURE);
        }

        dst_ptr = &output[pad_size];

        /* Prime padding blocks with a pattern */
        memset(output, pad_pattern, pad_size);
        memset(&output[alloc_size - pad_size], pad_pattern, pad_size);

        job = IMB_GET_NEXT_JOB(p_mgr);

        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_SNOW_V;
        job->hash_alg = IMB_AUTH_NULL;
        job->key_len_in_bytes = 32;
        job->iv_len_in_bytes = 16;
        job->cipher_start_src_offset_in_bytes = 0;

        job->enc_keys = key;
        job->iv = iv;
        job->dst = dst_ptr;
        job->src = plain;
        job->msg_len_to_cipher_in_bytes = size;

        job = IMB_SUBMIT_JOB(p_mgr);
        if (job == NULL) {
                const int err = imb_get_errno(p_mgr);

                if (err != 0)
                        printf("Error: %s!\n", imb_get_strerror(err));
                fail++;
        } else {
                int fail_found = 0;
                /* check for vector match */
                fail_found = compare(dst_ptr, expected, size);

                fail_found +=
                        check_buffer_over_under_write(output, pad_pattern, pad_size, alloc_size);

                if (fail_found)
                        fail++;
                else
                        pass++;
        }

        test_suite_update(ts, pass, fail);
        free(output);
}

static void
snow_v_aead_single_test(IMB_MGR *p_mgr, struct test_suite_context *ts, const uint8_t *key,
                        const uint8_t *iv, const uint8_t *aad, const uint8_t *plain,
                        const size_t size, const size_t aad_len, const uint8_t *expected,
                        int dir_encrypt) /* 1-encrypt, 0-decrypt */
{
        const size_t pad_size = 16;
        /* alloc space for auth tag after output */
        const size_t alloc_size = size + 16 + (2 * pad_size);
        const int pad_pattern = 0xa5;
        uint8_t *dst_ptr = NULL, *output = malloc(alloc_size);
        uint32_t pass = 0, fail = 0;
        struct IMB_JOB *job;

        if (output == NULL) {
                fprintf(stderr, "Error allocating %lu bytes!\n", (unsigned long) alloc_size);
                exit(EXIT_FAILURE);
        }

        dst_ptr = &output[pad_size];

        /* Prime padding blocks with a pattern */
        memset(output, pad_pattern, pad_size);
        memset(&output[alloc_size - pad_size], pad_pattern, pad_size);

        job = IMB_GET_NEXT_JOB(p_mgr);

        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->hash_alg = IMB_AUTH_SNOW_V_AEAD;
        job->cipher_mode = IMB_CIPHER_SNOW_V_AEAD;
        job->key_len_in_bytes = 32;
        job->iv_len_in_bytes = 16;
        job->cipher_start_src_offset_in_bytes = 0;
        job->enc_keys = key;
        job->iv = iv;
        if (dir_encrypt) {
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->dst = dst_ptr;
                job->src = plain;
        } else {
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->dst = dst_ptr;
                job->src = expected;
        }
        job->auth_tag_output = dst_ptr + size;
        job->auth_tag_output_len_in_bytes = 16;
        job->msg_len_to_cipher_in_bytes = size;

        job->u.SNOW_V_AEAD.aad = aad;
        job->u.SNOW_V_AEAD.aad_len_in_bytes = aad_len;

        job = IMB_SUBMIT_JOB(p_mgr);
        if (job == NULL) {
                const int err = imb_get_errno(p_mgr);

                if (err != 0)
                        printf("Error: %s!\n", imb_get_strerror(err));
                fail++;
        } else {
                int fail_found = compare(job->auth_tag_output, expected + size, 16);

                /* check for vector match */
                if (dir_encrypt)
                        fail_found += compare(dst_ptr, expected, size);
                else
                        fail_found += compare(dst_ptr, plain, size);

                fail_found +=
                        check_buffer_over_under_write(output, pad_pattern, pad_size, alloc_size);
                if (fail_found)
                        fail++;
                else
                        pass++;
        }

        test_suite_update(ts, pass, fail);
        free(output);
}

int
snow_v_test(IMB_MGR *p_mgr)
{
        struct test_suite_context ts_snow_v;
        struct test_suite_context ts_snow_v_aead;
        int errors = 0;
        uint64_t i;

        /* flush the scheduler */
        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        /* Test SNOW-V */
        printf("SNOW-V test vectors\n");
        test_suite_start(&ts_snow_v, "SNOW-V");
        for (const struct cipher_test *v = snow_v_test_json; v->msg != NULL; v++) {
                assert(v->keySize == (32 * CHAR_BIT));
                assert(v->ivSize == (16 * CHAR_BIT));
                assert((v->msgSize % CHAR_BIT) == 0);
                snow_v_single_test(p_mgr, &ts_snow_v, v->key, v->iv, v->msg, v->msgSize / CHAR_BIT,
                                   v->ct);
        }

        errors += test_suite_end(&ts_snow_v);

        /* Test SNOW-V-GCM */
        printf("SNOW-V-AEAD test vectors - ENCRYPT\n");
        test_suite_start(&ts_snow_v_aead, "SNOW-V-AEAD");

        for (i = 0; i < DIM(snow_v_aead_test_vectors); i++)
                snow_v_aead_single_test(p_mgr, &ts_snow_v_aead, snow_v_aead_test_vectors[i].KEY,
                                        snow_v_aead_test_vectors[i].IV,
                                        snow_v_aead_test_vectors[i].aad,
                                        snow_v_aead_test_vectors[i].plaintext,
                                        snow_v_aead_test_vectors[i].length_in_bytes,
                                        snow_v_aead_test_vectors[i].aad_length_in_bytes,
                                        snow_v_aead_test_vectors[i].ciphertext, 1);

        printf("SNOW-V-AEAD test vectors - DECRYPT\n");
        for (i = 0; i < DIM(snow_v_aead_test_vectors); i++)
                snow_v_aead_single_test(p_mgr, &ts_snow_v_aead, snow_v_aead_test_vectors[i].KEY,
                                        snow_v_aead_test_vectors[i].IV,
                                        snow_v_aead_test_vectors[i].aad,
                                        snow_v_aead_test_vectors[i].plaintext,
                                        snow_v_aead_test_vectors[i].length_in_bytes,
                                        snow_v_aead_test_vectors[i].aad_length_in_bytes,
                                        snow_v_aead_test_vectors[i].ciphertext, 0);
        errors += test_suite_end(&ts_snow_v_aead);

        return errors;
}
