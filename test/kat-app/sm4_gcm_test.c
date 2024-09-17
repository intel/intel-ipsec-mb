/**********************************************************************
  Copyright(c) 2024 Intel Corporation All rights reserved.

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

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "aead_test.h"

/* 0 - no extra messages, 1 - additional messages */
#define VERBOSE 0

#define AAD_SZ       24
#define IV_SZ        12
#define DIGEST_SZ    16
#define MAX_KEY_SZ   32
#define GCM_MAX_JOBS 32

int
sm4_gcm_test(IMB_MGR *p_mgr);

extern const struct aead_test sm4_gcm_test_json[];

static IMB_MGR *p_gcm_mgr = NULL;

static int
check_data(const uint8_t *test, const uint8_t *expected, uint64_t len, const char *data_name)
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
                                printf(" '%x' != '%x' at %llx of %llx\n", test[a], expected[a],
                                       (unsigned long long) a, (unsigned long long) len);
                                break;
                        }
                }
        }
        return is_error;
}

static int
sm4_gcm_job(IMB_MGR *mb_mgr, IMB_CIPHER_DIRECTION cipher_dir, const struct gcm_key_data *key,
            uint8_t *out, const uint8_t *in, const uint64_t len, const uint8_t *iv,
            const uint8_t *aad, const uint64_t aad_len, uint8_t *auth_tag,
            const uint64_t auth_tag_len)
{
        IMB_JOB *job;

        job = IMB_GET_NEXT_JOB(mb_mgr);
        if (!job) {
                fprintf(stderr, "failed to get job\n");
                return -1;
        }

        job->cipher_mode = IMB_CIPHER_SM4_GCM;
        job->chain_order =
                (cipher_dir == IMB_DIR_ENCRYPT) ? IMB_ORDER_CIPHER_HASH : IMB_ORDER_HASH_CIPHER;
        job->enc_keys = key;
        job->dec_keys = key;
        job->key_len_in_bytes = 16;
        job->src = in;
        job->dst = out;
        job->msg_len_to_cipher_in_bytes = len;
        job->cipher_start_src_offset_in_bytes = UINT64_C(0);
        job->iv = iv;
        job->iv_len_in_bytes = 12;
        job->u.GCM.aad = aad;
        job->u.GCM.aad_len_in_bytes = aad_len;
        job->auth_tag_output = auth_tag;
        job->auth_tag_output_len_in_bytes = auth_tag_len;
        job->cipher_direction = cipher_dir;
        job->hash_alg = IMB_AUTH_SM4_GCM;
        job = IMB_SUBMIT_JOB(mb_mgr);

        if (job->status != IMB_STATUS_COMPLETED) {
                fprintf(stderr, "failed job, status:%d\n", job->status);
                return -1;
        }

        return 0;
}

static void
test_gcm_vectors(struct aead_test const *vector, struct test_suite_context *ts)
{
        struct gcm_key_data gdata_key;
        int is_error = 0;
        /* Temporary array for the calculated vectors */
        uint8_t *ct_test = NULL;
        uint8_t *pt_test = NULL;
        uint8_t *T_test = NULL;
        uint8_t *T2_test = NULL;
        const uint8_t *iv = (const void *) vector->iv;

        if (vector->msgSize / 8 != 0) {
                /* Allocate space for the calculated ciphertext */
                ct_test = malloc(vector->msgSize / 8);
                if (ct_test == NULL) {
                        fprintf(stderr, "Can't allocate ciphertext memory\n");
                        goto test_gcm_vectors_exit;
                }
                memset(ct_test, 0, vector->msgSize / 8);
                /* Allocate space for the calculated plaintext */
                pt_test = malloc(vector->msgSize / 8);
                if (pt_test == NULL) {
                        fprintf(stderr, "Can't allocate plaintext memory\n");
                        goto test_gcm_vectors_exit;
                }
                memset(pt_test, 0, vector->msgSize / 8);
        }

        T_test = malloc(vector->tagSize / 8);
        if (T_test == NULL) {
                fprintf(stderr, "Can't allocate tag memory\n");
                goto test_gcm_vectors_exit;
        }
        memset(T_test, 0, vector->tagSize / 8);

        T2_test = malloc(vector->tagSize / 8);
        if (T2_test == NULL) {
                fprintf(stderr, "Can't allocate tag(2) memory\n");
                goto test_gcm_vectors_exit;
        }
        memset(T2_test, 0, vector->tagSize / 8);

        imb_sm4_gcm_pre(p_gcm_mgr, vector->key, &gdata_key);

        /*
         * Encrypt
         */
        if (sm4_gcm_job(p_gcm_mgr, IMB_DIR_ENCRYPT, &gdata_key, ct_test, (const void *) vector->msg,
                        vector->msgSize / 8, iv, (const void *) vector->aad, vector->aadSize / 8,
                        T_test, vector->tagSize / 8)) {
                test_suite_update(ts, 0, 1);
                goto test_gcm_vectors_exit;
        }
        is_error |= check_data(ct_test, (const void *) vector->ct, vector->msgSize / 8,
                               "encrypted cipher text (C)");
        is_error |= check_data(T_test, (const void *) vector->tag, vector->tagSize / 8, "tag (T)");
        if (is_error)
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);

        /* test of in-place encrypt */
        memory_copy(pt_test, (const void *) vector->msg, vector->msgSize / 8);
        if (sm4_gcm_job(p_gcm_mgr, IMB_DIR_ENCRYPT, &gdata_key, pt_test, pt_test,
                        vector->msgSize / 8, iv, (const void *) vector->aad, vector->aadSize / 8,
                        T_test, vector->tagSize / 8)) {
                test_suite_update(ts, 0, 1);
                goto test_gcm_vectors_exit;
        }
        is_error |= check_data(pt_test, (const void *) vector->ct, vector->msgSize / 8,
                               "encrypted cipher text(in-place)");
        if (is_error)
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);

        memory_set(ct_test, 0, vector->msgSize / 8);
        memory_set(T_test, 0, vector->tagSize / 8);

        /*
         * Decrypt
         */
        if (sm4_gcm_job(p_gcm_mgr, IMB_DIR_DECRYPT, &gdata_key, pt_test, (const void *) vector->ct,
                        vector->msgSize / 8, iv, (const void *) vector->aad, vector->aadSize / 8,
                        T_test, vector->tagSize / 8)) {
                test_suite_update(ts, 0, 1);
                goto test_gcm_vectors_exit;
        }
        is_error |= check_data(pt_test, (const void *) vector->msg, vector->msgSize / 8,
                               "decrypted plain text (P)");
        /*
         * GCM decryption outputs a 16 byte tag value
         * that must be verified against the expected tag value
         */
        is_error |= check_data(T_test, (const void *) vector->tag, vector->tagSize / 8,
                               "decrypted tag (T)");
        if (is_error)
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);

        /* test in in-place decrypt */
        memory_copy(ct_test, (const void *) vector->ct, vector->msgSize / 8);
        if (sm4_gcm_job(p_gcm_mgr, IMB_DIR_DECRYPT, &gdata_key, ct_test, ct_test,
                        vector->msgSize / 8, iv, (const void *) vector->aad, vector->aadSize / 8,
                        T_test, vector->tagSize / 8)) {
                test_suite_update(ts, 0, 1);
                goto test_gcm_vectors_exit;
        }
        is_error |= check_data(ct_test, (const void *) vector->msg, vector->msgSize / 8,
                               "plain text (P) - in-place");
        is_error |= check_data(T_test, (const void *) vector->tag, vector->tagSize / 8,
                               "decrypted tag (T) - in-place");
        if (is_error)
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);
        /* enc -> dec */
        if (sm4_gcm_job(p_gcm_mgr, IMB_DIR_ENCRYPT, &gdata_key, ct_test, (const void *) vector->msg,
                        vector->msgSize / 8, iv, (const void *) vector->aad, vector->aadSize / 8,
                        T_test, vector->tagSize / 8)) {
                test_suite_update(ts, 0, 1);
                goto test_gcm_vectors_exit;
        }

        memory_set(pt_test, 0, vector->msgSize / 8);

        if (sm4_gcm_job(p_gcm_mgr, IMB_DIR_DECRYPT, &gdata_key, pt_test, ct_test,
                        vector->msgSize / 8, iv, (const void *) vector->aad, vector->aadSize / 8,
                        T2_test, vector->tagSize / 8)) {
                test_suite_update(ts, 0, 1);
                goto test_gcm_vectors_exit;
        }
        is_error |= check_data(pt_test, (const void *) vector->msg, vector->msgSize / 8,
                               "self decrypted plain text (P)");
        is_error |= check_data(T_test, T2_test, vector->tagSize / 8, "self decrypted tag (T)");
        if (is_error)
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);

test_gcm_vectors_exit:
        if (NULL != ct_test)
                free(ct_test);
        if (NULL != pt_test)
                free(pt_test);
        if (NULL != T_test)
                free(T_test);
        if (NULL != T2_test)
                free(T2_test);
}

static void
test_gcm_std_vectors(struct test_suite_context *ts, const struct aead_test *v)
{

        printf("AES-GCM (%s API) standard test vectors:\n", "Direct/JOB");
        for (; v->msg != NULL; v++) {
                if (!quiet_mode) {
#ifdef DEBUG
                        printf("Standard vector %zu  Keylen:%zu IVlen:%zu "
                               "PTLen:%zu AADlen:%zu Tlen:%zu\n",
                               v->tcId, v->keySize / 8, v->ivSize / 8, v->msgSize / 8,
                               v->aadSize / 8, v->tagSize / 8);
#else
                        printf(".");
#endif
                }

                test_gcm_vectors(v, ts);
        }
        if (!quiet_mode)
                printf("\n");
}

int
sm4_gcm_test(IMB_MGR *p_mgr)
{
        struct test_suite_context ts;
        int errors = 0;

        p_gcm_mgr = p_mgr;

        test_suite_start(&ts, "SM4-GCM");
        test_gcm_std_vectors(&ts, sm4_gcm_test_json);

        errors += test_suite_end(&ts);

        return errors;
}
