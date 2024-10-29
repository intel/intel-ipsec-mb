/**********************************************************************
  Copyright(c) 2021-2024 Intel Corporation All rights reserved.

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
#include "utils.h"
#include "cipher_test.h"
#include "aead_test.h"

extern const struct cipher_test snow_v_test_json[];
extern const struct aead_test snow_v_aead_json[];

int
snow_v_test(IMB_MGR *p_mgr);

static uint32_t
compare(const void *result, const void *expected, const size_t size)
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
snow_v_aead_single_test(IMB_MGR *p_mgr, struct test_suite_context *ts, const struct aead_test *v,
                        const IMB_CIPHER_DIRECTION dir)
{
        assert(v != NULL);
        assert(v->msg != NULL);
        assert(v->keySize == (32 * CHAR_BIT));
        assert(v->ivSize == (16 * CHAR_BIT));
        assert(v->tagSize == (16 * CHAR_BIT));
        assert((v->msgSize % CHAR_BIT) == 0);
        assert((v->aadSize % CHAR_BIT) == 0);

        const size_t size = v->msgSize / CHAR_BIT;
        const size_t aad_len = v->aadSize / CHAR_BIT;

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
        job->enc_keys = (const void *) v->key;
        job->iv = (const void *) v->iv;
        job->dst = dst_ptr;
        job->cipher_direction = dir;
        if (dir == IMB_DIR_ENCRYPT)
                job->src = (const void *) v->msg;
        else
                job->src = (const void *) v->ct;
        job->auth_tag_output = dst_ptr + size;
        job->auth_tag_output_len_in_bytes = 16;
        job->msg_len_to_cipher_in_bytes = size;

        job->u.SNOW_V_AEAD.aad = v->aad;
        job->u.SNOW_V_AEAD.aad_len_in_bytes = aad_len;

        job = IMB_SUBMIT_JOB(p_mgr);
        if (job == NULL) {
                const int err = imb_get_errno(p_mgr);

                if (err != 0)
                        printf("Error: %s!\n", imb_get_strerror(err));
                fail++;
        } else {
                int fail_found = compare(job->auth_tag_output, v->tag, v->tagSize / CHAR_BIT);

                /* check for vector match */
                if (dir == IMB_DIR_ENCRYPT)
                        fail_found += compare(dst_ptr, v->ct, size);
                else
                        fail_found += compare(dst_ptr, v->msg, size);

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
        for (const struct aead_test *v = snow_v_aead_json; v->msg != NULL; v++)
                snow_v_aead_single_test(p_mgr, &ts_snow_v_aead, v, IMB_DIR_ENCRYPT);

        printf("SNOW-V-AEAD test vectors - DECRYPT\n");
        for (const struct aead_test *v = snow_v_aead_json; v->msg != NULL; v++)
                snow_v_aead_single_test(p_mgr, &ts_snow_v_aead, v, IMB_DIR_DECRYPT);

        errors += test_suite_end(&ts_snow_v_aead);

        return errors;
}
