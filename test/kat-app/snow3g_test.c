/*****************************************************************************
 Copyright (c) 2009-2026, Intel Corporation
 Copyright (c) 2022, Nokia

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "intel-ipsec-mb.h"

#include "utils.h"

#include "cipher_test.h"
#include "mac_test.h"
#include "kat_common_hash.h"
#include "kat_common_cipher.h"

#define IMB_SNOW3G_PAD_LEN               16
#define IMB_SNOW3G_MAX_DATA_LEN          3048
#define IMB_SNOW3G_NUM_SUPPORTED_BUFFERS 16

static struct cipher_test *snow3g_f8_vectors;
static struct cipher_test *snow3g_f8_linear_vectors;

static int
load_snow3g_f8_vectors(struct test_json_alloc_ctx **ctx_f8, struct test_json_alloc_ctx **ctx_linear)
{
        if (load_cipher_vectors(kat_vector_dir, "snow3g_f8_test.json", &snow3g_f8_vectors, ctx_f8) <
            0)
                return -1;
        return load_cipher_vectors(kat_vector_dir, "snow3g_f8_linear_test.json",
                                   &snow3g_f8_linear_vectors, ctx_linear);
}

static void
free_snow3g_f8_vectors(struct test_json_alloc_ctx *ctx_f8, struct test_json_alloc_ctx *ctx_linear)
{
        json_free_test_ctx(ctx_f8);
        snow3g_f8_vectors = NULL;
        json_free_test_ctx(ctx_linear);
        snow3g_f8_linear_vectors = NULL;
}
static struct mac_test *snow3g_f9_vectors;

static void
free_snow3g_f9_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        snow3g_f9_vectors = NULL;
}

int
snow3g_test(struct IMB_MGR *mb_mgr);
static void
validate_snow3g_f8(struct IMB_MGR *mb_mgr, struct test_suite_context *uea2_ctx,
                   struct test_suite_context *uia2_ctx);
static void
validate_snow3g_f9(struct IMB_MGR *mb_mgr, struct test_suite_context *uea2_ctx,
                   struct test_suite_context *uia2_ctx);

struct cipher_iv_gen_params {
        size_t tcId;
        const char *count;
        const char *bearer;
        const char *dir;
};

struct hash_iv_gen_params {
        size_t tcId;
        const char *count;
        const char *fresh;
        const char *dir;
};

const struct cipher_iv_gen_params snow3g_iv_params_f8_json[] = {
        { 1, "\x00\x00\x00\x00", "\x00", "\x00" },
        { 3, "\x26\x6b\x55\xfa", "\x03", "\x01" },
        { 0, NULL, NULL, NULL }
};

const struct hash_iv_gen_params snow3g_iv_params_f9_json[] = {
        { 4, "\x41\x3e\x79\x14", "\xfd\xe8\x97\x03", "\x01" },
        { 5, "\x3c\x39\x6f\x29", "\x37\x77\x22\x6b", "\x01" },
        { 6, "\x3c\x39\x6f\x29", "\x37\x77\x22\x6b", "\x01" },
        { 0, NULL, NULL, NULL }
};

/******************************************************************************
 * @description - utility function to dump test buffers
 *
 * @param message [IN] - debug message to print
 * @param ptr [IN] - pointer to beginning of buffer.
 * @param len [IN] - length of buffer.
 ******************************************************************************/
static inline void
snow3g_hexdump(const char *message, const uint8_t *ptr, int len)
{
        int ctr;

        printf("%s:\n", message);
        for (ctr = 0; ctr < len; ctr++) {
                printf("0x%02X ", ptr[ctr]);
                if (!((ctr + 1) % 16))
                        printf("\n");
        }
        printf("\n");
        printf("\n");
}

struct snow3g_uia2_job_ctx {
        snow3g_key_schedule_t *key_sched;
        uint8_t *key;
        uint8_t *iv;
};

static int
snow3g_uia2_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct mac_test *vec,
                        void *ctx)
{
        struct snow3g_uia2_job_ctx *uia2 = calloc(1, sizeof(*uia2));
        const size_t key_sched_size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);

        (void) ctx;
        if (uia2 == NULL)
                return -1;

        job->user_data = uia2;
        if (key_sched_size == 0)
                return -1;

        uia2->key = test_aligned_alloc(16, vec->keySize / 8);
        uia2->iv = test_aligned_alloc(16, vec->ivSize / 8);
        uia2->key_sched = test_aligned_alloc(16, key_sched_size);
        if (uia2->key == NULL || uia2->iv == NULL || uia2->key_sched == NULL)
                return -1;

        memcpy(uia2->key, vec->key, vec->keySize / 8);
        memcpy(uia2->iv, vec->iv, vec->ivSize / 8);
        if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, uia2->key, uia2->key_sched) != 0)
                return -1;

        job->u.SNOW3G_UIA2._key = uia2->key_sched;
        job->u.SNOW3G_UIA2._iv = uia2->iv;
        return 0;
}

static void
snow3g_uia2_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct snow3g_uia2_job_ctx *uia2 = job->user_data;

        (void) ctx;
        if (uia2 != NULL) {
                test_aligned_free(uia2->key_sched);
                test_aligned_free(uia2->key);
                test_aligned_free(uia2->iv);
                free(uia2);
        }
        job->user_data = NULL;
}

/******************************************************************************
 * Validates SNOW3G F8 (UEA2) encryption/decryption using a given set of test
 * vectors, submitting batches from 1 up to the number of supported buffers.
 * Each job uses a different vector, exercising multi-key scheduling through
 * the shared cipher submit/flush helper.
 ******************************************************************************/
struct snow3g_uea2_job_ctx {
        snow3g_key_schedule_t *key_sched;
        uint8_t *key;
        uint8_t *iv;
};

static int
snow3g_uea2_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                        void *ctx)
{
        struct snow3g_uea2_job_ctx *uea2 = calloc(1, sizeof(*uea2));
        const size_t key_sched_size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);

        (void) ctx;
        if (uea2 == NULL)
                return -1;

        job->user_data = uea2;
        if (key_sched_size == 0)
                return -1;

        uea2->key = test_aligned_alloc(16, vec->keySize / 8);
        uea2->iv = test_aligned_alloc(16, vec->ivSize / 8);
        uea2->key_sched = test_aligned_alloc(16, key_sched_size);
        if (uea2->key == NULL || uea2->iv == NULL || uea2->key_sched == NULL)
                return -1;

        memcpy(uea2->key, vec->key, vec->keySize / 8);
        memcpy(uea2->iv, vec->iv, vec->ivSize / 8);
        if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, uea2->key, uea2->key_sched) != 0)
                return -1;

        job->enc_keys = uea2->key_sched;
        job->dec_keys = uea2->key_sched;
        job->iv = uea2->iv;
        job->iv_len_in_bytes = IMB_SNOW3G_IV_LEN_IN_BYTES;
        job->key_len_in_bytes = 16;
        return 0;
}

static void
snow3g_uea2_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct snow3g_uea2_job_ctx *uea2 = job->user_data;

        (void) ctx;
        if (uea2 != NULL) {
                test_aligned_free(uea2->key_sched);
                test_aligned_free(uea2->key);
                test_aligned_free(uea2->iv);
                free(uea2);
        }
        job->user_data = NULL;
}

static int
validate_snow3g_f8_vectors(struct IMB_MGR *mb_mgr, const struct cipher_test *testVectors)
{
        const struct cipher_test **vec_tab;
        const struct kat_cipher_job_ops enc_ops = {
                .prepare = snow3g_uea2_job_prepare,
                .cleanup = snow3g_uea2_job_cleanup,
                .cipher_mode = IMB_CIPHER_SNOW3G_UEA2,
                .cipher_direction = IMB_DIR_ENCRYPT,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = 16,
                .in_place = 0,
        };
        const struct kat_cipher_job_ops dec_ops = {
                .prepare = snow3g_uea2_job_prepare,
                .cleanup = snow3g_uea2_job_cleanup,
                .cipher_mode = IMB_CIPHER_SNOW3G_UEA2,
                .cipher_direction = IMB_DIR_DECRYPT,
                .chain_order = IMB_ORDER_HASH_CIPHER,
                .key_len_in_bytes = 16,
                .in_place = 0,
        };
        uint32_t num_vectors = 0;
        int ret = -1;

        if (testVectors == NULL)
                return -1;

        while (testVectors[num_vectors].msg != NULL)
                num_vectors++;

        if (num_vectors == 0)
                return -1;

        vec_tab = malloc(num_vectors * sizeof(*vec_tab));
        if (vec_tab == NULL)
                return -1;

        for (uint32_t i = 0; i < num_vectors; i++)
                vec_tab[i] = &testVectors[i];

        const uint32_t max_jobs = num_vectors < IMB_SNOW3G_NUM_SUPPORTED_BUFFERS
                                          ? num_vectors
                                          : IMB_SNOW3G_NUM_SUPPORTED_BUFFERS;

        for (uint32_t num_jobs = 1; num_jobs <= max_jobs; num_jobs++) {
                struct kat_cipher_job_ops enc_inplace = enc_ops;
                struct kat_cipher_job_ops dec_inplace = dec_ops;

                enc_inplace.in_place = 1;
                dec_inplace.in_place = 1;

                if (kat_cipher_test_submit_flush(mb_mgr, vec_tab, num_vectors, num_jobs, &enc_ops) <
                    0) {
                        printf("SNOW3G F8 encrypt, %u jobs\n", num_jobs);
                        goto end;
                }
                if (kat_cipher_test_submit_flush(mb_mgr, vec_tab, num_vectors, num_jobs, &dec_ops) <
                    0) {
                        printf("SNOW3G F8 decrypt, %u jobs\n", num_jobs);
                        goto end;
                }
                if (kat_cipher_test_submit_flush(mb_mgr, vec_tab, num_vectors, num_jobs,
                                                 &enc_inplace) < 0) {
                        printf("SNOW3G F8 encrypt in-place, %u jobs\n", num_jobs);
                        goto end;
                }
                if (kat_cipher_test_submit_flush(mb_mgr, vec_tab, num_vectors, num_jobs,
                                                 &dec_inplace) < 0) {
                        printf("SNOW3G F8 decrypt in-place, %u jobs\n", num_jobs);
                        goto end;
                }
        }

        ret = 0;
end:
        free(vec_tab);
        return ret;
}

static void
validate_snow3g_f8(struct IMB_MGR *mb_mgr, struct test_suite_context *uea2_ctx,
                   struct test_suite_context *uia2_ctx)
{
        int status = -1;

        (void) uia2_ctx;
#ifdef DEBUG
        printf("Testing SNOW3G F8 (UEA2):\n");
#endif
        if (validate_snow3g_f8_vectors(mb_mgr, snow3g_f8_vectors) != 0)
                goto exit;

        if (validate_snow3g_f8_vectors(mb_mgr, snow3g_f8_linear_vectors) != 0)
                goto exit;

        /* no errors detected */
        status = 0;

exit:
        if (status < 0)
                test_suite_update(uea2_ctx, 0, 1);
        else
                test_suite_update(uea2_ctx, 1, 0);
}

static void
validate_snow3g_f9(struct IMB_MGR *mb_mgr, struct test_suite_context *uea2_ctx,
                   struct test_suite_context *uia2_ctx)
{
        int numVectors = 0, i;
        const struct mac_test *testVectors = snow3g_f9_vectors;

        int status = -1;

        (void) uea2_ctx;
#ifdef DEBUG
        printf("Testing IMB_SNOW3G_F9_1_BUFFER:\n");
#endif

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                goto snow3g_f9_1_buffer_exit;
        }

        const struct kat_hash_job_ops ops = {
                .prepare = snow3g_uia2_job_prepare,
                .cleanup = snow3g_uia2_job_cleanup,
                .hash_alg = IMB_AUTH_SNOW3G_UIA2,
        };

        for (i = 0; i < numVectors; i++) {
                const struct mac_test *vec = &testVectors[i];

                for (unsigned j = 0; j < test_num_jobs_size; j++) {
                        if (kat_hash_test_submit_flush(mb_mgr, &vec, 1, test_num_jobs[j], &ops)) {
                                printf("IMB_SNOW3G_F9 JOB API vector num:%zu\n",
                                       testVectors[i].tcId);
                                goto snow3g_f9_1_buffer_exit;
                        }
                }
        } /* for numVectors */
        /* no errors detected */
        status = 0;

snow3g_f9_1_buffer_exit:
        if (status < 0)
                test_suite_update(uia2_ctx, 0, 1);
        else
                test_suite_update(uia2_ctx, 1, 0);
}

static int
validate_f8_iv_gen(void)
{
        uint32_t i, numParams = 0;
        uint8_t IV[16];

#ifdef DEBUG
        printf("Testing snow3g_f8_iv_gen:\n");
#endif
        const struct cipher_iv_gen_params *iv_params = snow3g_iv_params_f8_json;
        const struct cipher_test *testVectors = snow3g_f8_vectors;

        /* calculate number of iv_params entries */
        for (i = 0; iv_params[i].count != NULL; i++)
                numParams++;

        if (!numParams) {
                printf("No Snow3G test vectors found !\n");
                return 1;
        }

        /* skip first entry as it's not part of test data */
        for (i = 1; i < numParams; i++) {
                const size_t tc_idx = iv_params[i].tcId - 1; /* tcId is 1-based */

                memset(IV, 0, sizeof(IV));

                /* generate IV */
                if (snow3g_f8_iv_gen(*(const uint32_t *) iv_params[i].count,
                                     *(const uint8_t *) iv_params[i].bearer,
                                     *(const uint8_t *) iv_params[i].dir, &IV) < 0)
                        return 1;

                /* validate result */
                if (memcmp(IV, testVectors[tc_idx].iv, 16) != 0) {
                        printf("snow3g_f8_iv_gen vector num: %zu\n", testVectors[tc_idx].tcId);
                        snow3g_hexdump("Actual", IV, 16);
                        snow3g_hexdump("Expected", (const uint8_t *) testVectors[tc_idx].iv, 16);
                        return 1;
                }
        }

        return 0;
}

static int
validate_f9_iv_gen(void)
{
        uint32_t i, numVectors = 0;
        uint8_t IV[16];

#ifdef DEBUG
        printf("Testing snow3g_f9_iv_gen:\n");
#endif

        /* 6 test sets */
        const struct hash_iv_gen_params *iv_params = snow3g_iv_params_f9_json;
        const struct mac_test *testVectors = snow3g_f9_vectors;

        /* calculate number of vectors */
        for (i = 0; testVectors[i].msg != NULL; i++)
                numVectors++;

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return 1;
        }

        for (i = 0; i < numVectors; i++) {
                memset(IV, 0, sizeof(IV));

                /* generate IV */
                if (snow3g_f9_iv_gen(*(const uint32_t *) iv_params[i].count,
                                     *(const uint32_t *) iv_params[i].fresh,
                                     *(const uint8_t *) iv_params[i].dir, &IV) < 0)
                        return 1;

                /* validate result */
                if (memcmp(IV, testVectors[i].iv, 16) != 0) {
                        printf("snow3g_f9_iv_gen vector num: %zu\n", testVectors[i].tcId);
                        snow3g_hexdump("Actual", IV, 16);
                        snow3g_hexdump("Expected", (const uint8_t *) testVectors[i].iv, 16);
                        return 1;
                }
        }

        return 0;
}

int
snow3g_test(struct IMB_MGR *mb_mgr)
{
        int errors = 0;
        struct test_suite_context uea2_ctx;
        struct test_suite_context uia2_ctx;
        struct test_json_alloc_ctx *f9_jctx = NULL;
        struct test_json_alloc_ctx *f8_jctx = NULL;
        struct test_json_alloc_ctx *f8_linear_jctx = NULL;

        if (load_mac_vectors(kat_vector_dir, "snow3g_f9_test.json", &snow3g_f9_vectors, &f9_jctx) <
                    0 ||
            snow3g_f9_vectors == NULL)
                return 1;
        if (load_snow3g_f8_vectors(&f8_jctx, &f8_linear_jctx) < 0) {
                free_snow3g_f8_vectors(f8_jctx, f8_linear_jctx);
                free_snow3g_f9_vectors(f9_jctx);
                return 1;
        }

        test_suite_start(&uea2_ctx, "SNOW3G-UEA2");
        test_suite_start(&uia2_ctx, "SNOW3G-UIA2");

        if (validate_f8_iv_gen()) {
                printf("validate_snow3g_f8_iv_gen:: FAIL\n");
                test_suite_update(&uea2_ctx, 0, 1);
        } else
                test_suite_update(&uea2_ctx, 1, 0);
        if (validate_f9_iv_gen()) {
                printf("validate_snow3g_f9_iv_gen:: FAIL\n");
                test_suite_update(&uia2_ctx, 0, 1);
        } else
                test_suite_update(&uia2_ctx, 1, 0);

        /* validate job api */
        validate_snow3g_f8(mb_mgr, &uea2_ctx, &uia2_ctx);
        validate_snow3g_f9(mb_mgr, &uea2_ctx, &uia2_ctx);

        errors += test_suite_end(&uea2_ctx);
        errors += test_suite_end(&uia2_ctx);

        free_snow3g_f8_vectors(f8_jctx, f8_linear_jctx);
        free_snow3g_f9_vectors(f9_jctx);
        return errors;
}
