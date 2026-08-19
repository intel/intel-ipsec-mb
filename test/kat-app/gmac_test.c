/**********************************************************************
  Copyright(c) 2023-2024 Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h> /* for memcmp() */

#include <intel-ipsec-mb.h>
#include "utils.h"
#include "mac_test.h"
#include "wycheproof_test.h"

int
gmac_test(struct IMB_MGR *mb_mgr);

static struct mac_test *gmac_vectors;

static void
free_gmac_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        gmac_vectors = NULL;
}

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

static void
aes_gmac_job(IMB_MGR *mb_mgr, const uint8_t *k, struct gcm_key_data *gmac_key,
             const uint64_t key_len, const uint8_t *in, const uint64_t len, const uint8_t *iv,
             const uint64_t iv_len, uint8_t *auth_tag, const uint64_t auth_tag_len)
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
        job->auth_tag_output = auth_tag;
        job->auth_tag_output_len_in_bytes = auth_tag_len;

        job = IMB_SUBMIT_JOB(mb_mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mb_mgr);
        if (job == NULL)
                fprintf(stderr, "No job retrieved\n");
        else if (job->status != IMB_STATUS_COMPLETED)
                fprintf(stderr, "failed job, status:%d\n", job->status);
}

#define MAX_SEG_SIZE 64
static void
gmac_test_vector(IMB_MGR *mb_mgr, const struct mac_test *vector, const uint64_t seg_size,
                 const unsigned job_api, struct test_suite_context *ts128,
                 struct test_suite_context *ts192, struct test_suite_context *ts256)
{
        struct gcm_key_data key;
        struct gcm_context_data ctx;
        const uint8_t *iv = (const void *) vector->iv;
        const uint64_t iv_len = vector->ivSize / 8;
        const uint64_t nb_segs = ((vector->msgSize / 8) / seg_size);
        const uint64_t last_partial_seg = ((vector->msgSize / 8) % seg_size);
        const uint8_t *in_ptr = (const void *) vector->msg;
        uint8_t T_test[16];
        struct test_suite_context *ts = ts128;

        if ((vector->keySize / 8) == IMB_KEY_192_BYTES)
                ts = ts192;

        if ((vector->keySize / 8) == IMB_KEY_256_BYTES)
                ts = ts256;

        memset(&key, 0, sizeof(struct gcm_key_data));
        if (job_api) {
                aes_gmac_job(mb_mgr, (const void *) vector->key, &key, vector->keySize / 8, in_ptr,
                             seg_size, iv, iv_len, T_test, vector->tagSize / 8);
        } else {
                uint8_t in_seg[MAX_SEG_SIZE];
                uint32_t i;

                switch (vector->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_PRE(mb_mgr, vector->key, &key);
                        IMB_AES128_GMAC_INIT(mb_mgr, &key, &ctx, iv, iv_len);
                        in_ptr = (const void *) vector->msg;
                        for (i = 0; i < nb_segs; i++) {
                                memcpy(in_seg, in_ptr, seg_size);
                                IMB_AES128_GMAC_UPDATE(mb_mgr, &key, &ctx, in_seg, seg_size);
                                in_ptr += seg_size;
                        }

                        if (last_partial_seg != 0) {
                                memcpy(in_seg, in_ptr, last_partial_seg);
                                IMB_AES128_GMAC_UPDATE(mb_mgr, &key, &ctx, in_seg,
                                                       last_partial_seg);
                        }

                        IMB_AES128_GMAC_FINALIZE(mb_mgr, &key, &ctx, T_test, vector->tagSize / 8);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_PRE(mb_mgr, vector->key, &key);
                        IMB_AES192_GMAC_INIT(mb_mgr, &key, &ctx, iv, iv_len);
                        in_ptr = (const void *) vector->msg;
                        for (i = 0; i < nb_segs; i++) {
                                memcpy(in_seg, in_ptr, seg_size);
                                IMB_AES192_GMAC_UPDATE(mb_mgr, &key, &ctx, in_seg, seg_size);
                                in_ptr += seg_size;
                        }

                        if (last_partial_seg != 0) {
                                memcpy(in_seg, in_ptr, last_partial_seg);
                                IMB_AES192_GMAC_UPDATE(mb_mgr, &key, &ctx, in_seg,
                                                       last_partial_seg);
                        }

                        IMB_AES192_GMAC_FINALIZE(mb_mgr, &key, &ctx, T_test, vector->tagSize / 8);
                        break;
                case IMB_KEY_256_BYTES:
                default:
                        IMB_AES256_GCM_PRE(mb_mgr, vector->key, &key);
                        IMB_AES256_GMAC_INIT(mb_mgr, &key, &ctx, iv, iv_len);
                        in_ptr = (const void *) vector->msg;
                        for (i = 0; i < nb_segs; i++) {
                                memcpy(in_seg, in_ptr, seg_size);
                                IMB_AES256_GMAC_UPDATE(mb_mgr, &key, &ctx, in_seg, seg_size);
                                in_ptr += seg_size;
                        }

                        if (last_partial_seg != 0) {
                                memcpy(in_seg, in_ptr, last_partial_seg);
                                IMB_AES256_GMAC_UPDATE(mb_mgr, &key, &ctx, in_seg,
                                                       last_partial_seg);
                        }

                        IMB_AES256_GMAC_FINALIZE(mb_mgr, &key, &ctx, T_test, vector->tagSize / 8);
                        break;
                }
        }

        if (check_data(T_test, (const void *) vector->tag, vector->tagSize / 8,
                       "generated tag (T)"))
                test_suite_update(ts, 0, 1);
        else
                test_suite_update(ts, 1, 0);
}

int
gmac_test(IMB_MGR *mb_mgr)
{
        struct test_suite_context ts128, ts192, ts256;
        struct test_json_alloc_ctx *jctx = NULL;
        int errors = 0;

        if (load_mac_vectors(kat_vector_dir, "gmac_test.json", &gmac_vectors, &jctx) < 0)
                return 1;

        test_suite_start(&ts128, "AES-GMAC-128");
        test_suite_start(&ts192, "AES-GMAC-192");
        test_suite_start(&ts256, "AES-GMAC-256");

        printf("GMAC test vectors:\n");
        const struct mac_test *vec = gmac_vectors;
        while (vec->msg != NULL) {
                uint64_t seg_size;

                /* Using direct API, which allows SGL */
                for (seg_size = 1; seg_size <= MAX_SEG_SIZE; seg_size++)
                        gmac_test_vector(mb_mgr, vec, seg_size, 0, &ts128, &ts192, &ts256);

                /* Using job API */
                gmac_test_vector(mb_mgr, vec, (vec->msgSize / 8), 1, &ts128, &ts192, &ts256);
                vec++;
        }
        errors += test_suite_end(&ts128);
        errors += test_suite_end(&ts192);
        errors += test_suite_end(&ts256);

        free_gmac_vectors(jctx);
        errors += wycheproof_gmac_test(mb_mgr);

        return errors;
}
