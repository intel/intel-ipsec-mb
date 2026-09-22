/*****************************************************************************
 Copyright (c) 2009-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

/*-----------------------------------------------------------------------
 * Zuc functional test
 *-----------------------------------------------------------------------
 *
 * A simple functional test for ZUC
 *
 *-----------------------------------------------------------------------*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <intel-ipsec-mb.h>

#include "gcm_ctr_vectors_test.h"
#include "utils.h"
#include "cipher_test.h"
#include "kat_common_cipher.h"

#define MAXBUFS     17
#define PASS_STATUS 0
#define FAIL_STATUS -1
#define DIM(_x)     (sizeof(_x) / sizeof(_x[0]))

#define MAX_BUFFER_LENGTH_IN_BITS  5670 /* biggest test is EIA test 5 */
#define MAX_BUFFER_LENGTH_IN_BYTES ((MAX_BUFFER_LENGTH_IN_BITS) + 7) / 8

enum api_type { TEST_SINGLE_JOB_API, TEST_BURST_JOB_API };

int
zuc_eea3_nea6_test(struct IMB_MGR *mb_mgr);

static struct cipher_test *zuc_eea3_128_vectors;

static void
free_zuc_eea3_128_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        zuc_eea3_128_vectors = NULL;
}

static struct cipher_test *zuc_nea6_vectors;

static void
free_zuc_nea6_vectors(struct test_json_alloc_ctx *ctx)
{
        json_free_test_ctx(ctx);
        zuc_nea6_vectors = NULL;
}

struct zuc_eea3_128_params {
        const uint32_t *count;
        const uint8_t *bearer;
        const uint8_t *direction;
};

static void
zuc_eea3_128_set_params(const struct cipher_test *v, struct zuc_eea3_128_params *p);

struct zuc_job_ctx {
        uint8_t *key;
        uint8_t *iv;
};

static int
zuc_job_prepare(struct IMB_MGR *mb_mgr, struct IMB_JOB *job, const struct cipher_test *vec,
                void *ctx)
{
        const IMB_CIPHER_MODE cipher_mode = *(const IMB_CIPHER_MODE *) ctx;
        const size_t key_len = vec->keySize / 8;
        struct zuc_job_ctx *job_ctx;

        (void) mb_mgr;
        if ((vec->keySize % 8) != 0 || (vec->ivSize % 8) != 0)
                return -1;

        job_ctx = calloc(1, sizeof(*job_ctx));
        if (job_ctx == NULL)
                return -1;

        job->user_data = job_ctx;
        job_ctx->key = test_aligned_alloc_copy(16, vec->key, key_len);
        job_ctx->iv = malloc(IMB_ZUC_IV_LEN_IN_BYTES);
        if (job_ctx->key == NULL || job_ctx->iv == NULL)
                return -1;

        if (cipher_mode == IMB_CIPHER_ZUC_EEA3 && (vec->ivSize / 8) != IMB_ZUC_IV_LEN_IN_BYTES) {
                struct zuc_eea3_128_params params = { 0 };

                zuc_eea3_128_set_params(vec, &params);
                zuc_eea3_iv_gen(*params.count, *params.bearer, *params.direction, job_ctx->iv);
        } else {
                memory_copy(job_ctx->iv, vec->iv, vec->ivSize / 8);
        }

        job->enc_keys = job_ctx->key;
        job->dec_keys = job_ctx->key;
        job->iv = job_ctx->iv;
        job->iv_len_in_bytes = IMB_ZUC_IV_LEN_IN_BYTES;
        return 0;
}

static void
zuc_job_cleanup(struct IMB_JOB *job, void *ctx)
{
        struct zuc_job_ctx *job_ctx = job->user_data;

        (void) ctx;
        if (job_ctx != NULL) {
                test_aligned_free(job_ctx->key);
                free(job_ctx->iv);
                free(job_ctx);
        }
        job->user_data = NULL;
}

int
validate_zuc_algorithm(struct IMB_MGR *mb_mgr, uint8_t *pSrcData, uint8_t *pDstData, uint8_t *pKeys,
                       uint8_t *pIV);
int
validate_zuc_EEA_n_block(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                         uint8_t **pKeys, uint8_t **pIV, uint32_t numBuffs,
                         const enum api_type type);

int
validate_zuc_NEA6(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData, uint8_t **pKeys,
                  uint8_t **pIV, uint32_t numBuffs, const enum api_type type);

/******************************************************************************
 * @ingroup zuc_functionalTest_app
 *
 * @description
 * This function allocates memory for buffers and set random data in each buffer
 *
 * pSrcData = pointers to the new source buffers
 * numOfBuffs = number of buffers
 * ************************************************/
static uint32_t
createData(uint8_t *pSrcData[MAXBUFS], uint32_t numOfBuffs)
{
        uint32_t i = 0;

        for (i = 0; i < numOfBuffs; i++) {
                pSrcData[i] = (uint8_t *) malloc(MAX_BUFFER_LENGTH_IN_BYTES);

                if (!pSrcData[i]) {
                        uint32_t j;

                        printf("malloc(pSrcData[i]): failed!\n");

                        for (j = 0; j < i; j++) {
                                free(pSrcData[j]);
                                pSrcData[j] = NULL;
                        }

                        return FAIL_STATUS;
                }
        }
        return PASS_STATUS;
}

/******************************************************************************
 * @ingroup zuc_functionalTest_app
 *
 * @description
 * This function creates source data and vector buffers.
 *
 * keyLen = key length
 * pKeys = array of pointers to the new key buffers
 * ivLen = vector length
 * pIV = array of pointers to the new vector buffers
 * numOfBuffs = number of buffers
 ************************************************/
static uint32_t
createKeyVecData(uint32_t keyLen, uint8_t *pKeys[MAXBUFS], uint32_t ivLen, uint8_t *pIV[MAXBUFS],
                 uint32_t numOfBuffs)
{
        uint32_t i = 0;

        for (i = 0; i < numOfBuffs; i++) {
                uint32_t j;

                pIV[i] = (uint8_t *) malloc(ivLen);

                if (!pIV[i]) {
                        printf("malloc(pIV[i]): failed!\n");

                        for (j = 0; j < i; j++) {
                                free(pIV[j]);
                                free(pKeys[j]);
                        }

                        return FAIL_STATUS;
                }

                pKeys[i] = malloc(keyLen);

                if (!pKeys[i]) {
                        printf("malloc(pKeys[i]): failed!\n");

                        for (j = 0; j <= i; j++) {
                                free(pIV[j]);

                                if (j < i)
                                        free(pKeys[j]);
                        }
                        return FAIL_STATUS;
                }
        }

        return PASS_STATUS;
}

/******************************************************************************
 * @ingroup zuc_benchmark_app
 *
 * @description
 * This function free memory pointed to by an array of pointers
 *
 * arr = array of memory pointers
 * length = length of pointer array (or number of pointers whose buffers
 * should be freed)
 * ************************************************/
static void
freePtrArray(uint8_t *pArr[MAXBUFS], uint32_t arrayLength)
{
        uint32_t i = 0;

        for (i = 0; i < arrayLength; i++)
                free(pArr[i]);
}

int
zuc_eea3_nea6_test(struct IMB_MGR *mb_mgr)
{

        const uint32_t numBuffs[] = { 4, 8, 9, 16, 17 };
        uint32_t i;
        int errors = 0;
        uint8_t *pKeys[MAXBUFS] = { 0 };
        uint8_t *pIV[MAXBUFS] = { 0 };
        uint8_t *pSrcData[MAXBUFS] = { 0 };
        uint8_t *pDstData[MAXBUFS] = { 0 };
        struct test_suite_context eea3_ctx;
        struct test_suite_context nea6_ctx;
        struct test_json_alloc_ctx *eea3_jctx = NULL;
        struct test_json_alloc_ctx *nea6_jctx = NULL;

        if (load_cipher_vectors(kat_vector_dir, "zuc_eea3_128_test.json", &zuc_eea3_128_vectors,
                                &eea3_jctx) < 0)
                return 1;
        if (load_cipher_vectors(kat_vector_dir, "zuc_nea6_test.json", &zuc_nea6_vectors,
                                &nea6_jctx) < 0) {
                free_zuc_eea3_128_vectors(eea3_jctx);
                return 1;
        }

        test_suite_start(&eea3_ctx, "ZUC-EEA3");
        test_suite_start(&nea6_ctx, "ZUC-NEA6");

        /*Create test data buffers + populate with random data*/
        if (createData(pSrcData, MAXBUFS)) {
                printf("createData() error\n");
                test_suite_update(&eea3_ctx, 0, 1);
                goto exit_zuc_eea3_nea6_test;
        }
        if (createData(pDstData, MAXBUFS)) {
                printf("createData() error\n");
                freePtrArray(pSrcData, MAXBUFS);
                test_suite_update(&eea3_ctx, 0, 1);
                goto exit_zuc_eea3_nea6_test;
        }

        /* Create random keys and vectors */
        /* Use NEA6 key length (32 bytes) to accommodate both EEA3 (16 bytes) and NEA6 (32 bytes) */
        if (createKeyVecData(IMB_ZUC_NEA6_KEY_LEN_IN_BYTES, pKeys, IMB_ZUC_IV_LEN_IN_BYTES, pIV,
                             MAXBUFS)) {
                printf("createKeyVecData() error\n");
                freePtrArray(pSrcData, MAXBUFS);
                freePtrArray(pDstData, MAXBUFS);
                test_suite_update(&eea3_ctx, 0, 1);
                goto exit_zuc_eea3_nea6_test;
        }

        /* Job API tests */
        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc_EEA_n_block(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                             TEST_SINGLE_JOB_API))
                        test_suite_update(&eea3_ctx, 0, 1);
                else
                        test_suite_update(&eea3_ctx, 1, 0);
        }

        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc_NEA6(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                      TEST_SINGLE_JOB_API))
                        test_suite_update(&nea6_ctx, 0, 1);
                else
                        test_suite_update(&nea6_ctx, 1, 0);
        }

        /* Burst job API tests */
        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc_EEA_n_block(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                             TEST_BURST_JOB_API))
                        test_suite_update(&eea3_ctx, 0, 1);
                else
                        test_suite_update(&eea3_ctx, 1, 0);
        }

        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc_NEA6(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                      TEST_BURST_JOB_API))
                        test_suite_update(&nea6_ctx, 0, 1);
                else
                        test_suite_update(&nea6_ctx, 1, 0);
        }

exit_zuc_eea3_nea6_test:
        freePtrArray(pKeys, MAXBUFS);    /*Free the key buffers*/
        freePtrArray(pIV, MAXBUFS);      /*Free the vector buffers*/
        freePtrArray(pSrcData, MAXBUFS); /*Free the source buffers*/
        freePtrArray(pDstData, MAXBUFS); /*Free the destination buffers*/

        errors += test_suite_end(&eea3_ctx);
        errors += test_suite_end(&nea6_ctx);

        free_zuc_eea3_128_vectors(eea3_jctx);
        free_zuc_nea6_vectors(nea6_jctx);
        return errors;
}

/**
 * Count, Bearer and Direction stored in vector IV field
 */
static void
zuc_eea3_128_set_params(const struct cipher_test *v, struct zuc_eea3_128_params *p)
{
        const uint8_t *params = (const uint8_t *) v->iv;

        p->count = (const uint32_t *) &params[0];
        p->bearer = &params[4];
        p->direction = &params[5];
}

static int
submit_and_verify(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData, uint8_t **pKeys,
                  uint8_t **pIV, const enum api_type type, IMB_CIPHER_DIRECTION dir,
                  const unsigned int var_bufs, const unsigned int num_buffers,
                  const uint32_t *buf_idx)
{
        const struct cipher_test *vec_tab[MAXBUFS];
        const struct cipher_test *vectors = zuc_eea3_128_vectors;
        IMB_CIPHER_MODE cipher_mode = IMB_CIPHER_ZUC_EEA3;
        const struct kat_cipher_job_ops ops = {
                .prepare = zuc_job_prepare,
                .cleanup = zuc_job_cleanup,
                .ctx = &cipher_mode,
                .cipher_mode = IMB_CIPHER_ZUC_EEA3,
                .cipher_direction = dir,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = IMB_ZUC_KEY_LEN_IN_BYTES,
                .in_place = 0,
        };

        (void) pSrcData;
        (void) pDstData;
        (void) pKeys;
        (void) pIV;
        (void) var_bufs;
        for (unsigned int i = 0; i < num_buffers; i++) {
                const struct cipher_test *vector = &vectors[buf_idx[i]];

                if ((vector->msgSize % 8) != 0) {
                        printf("Unsupported non-byte-aligned ZUC-EEA3 vector (tcId=%zu, "
                               "bits=%zu)\n",
                               vector->tcId, vector->msgSize);
                        return -1;
                }
                if ((vector->ivSize % 8) != 0) {
                        printf("Unsupported non-byte-aligned ZUC-EEA3 IV (tcId=%zu, bits=%zu)\n",
                               vector->tcId, vector->ivSize);
                        return -1;
                }
                vec_tab[i] = vector;
        }

        if (type == TEST_SINGLE_JOB_API)
                return kat_cipher_test_submit_flush(mb_mgr, vec_tab, num_buffers, num_buffers,
                                                    &ops);
        else
                return kat_cipher_test_generic_burst(mb_mgr, vec_tab, num_buffers, num_buffers,
                                                     &ops);
}

int
validate_zuc_EEA_n_block(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                         uint8_t **pKeys, uint8_t **pIV, uint32_t numBuffs,
                         const enum api_type type)
{
        uint32_t i, j, num_vectors = 0;
        int ret = 0;
        int retTmp;
        uint32_t buf_idx[MAXBUFS];
        const struct cipher_test *vectors = zuc_eea3_128_vectors;

        /* calculate number of vectors */
        for (i = 0; vectors[i].msg != NULL; i++)
                num_vectors++;

        if (num_vectors == 0) {
                printf("ZUC-EEA3 128 N block - No vectors found!\n");
                return -1;
        }

        assert(numBuffs > 0);
        for (i = 0; i < num_vectors; i++) {
                for (j = 0; j < numBuffs; j++)
                        buf_idx[j] = i;

                retTmp = submit_and_verify(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                           IMB_DIR_ENCRYPT, 0, numBuffs, buf_idx);
                if (retTmp < 0)
                        ret = retTmp;

                retTmp = submit_and_verify(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                           IMB_DIR_DECRYPT, 0, numBuffs, buf_idx);
                if (retTmp < 0)
                        ret = retTmp;
        }

        /* Get all test vectors and encrypt them together */
        for (i = 0; i < numBuffs; i++)
                buf_idx[i] = i % num_vectors;

        retTmp = submit_and_verify(mb_mgr, pSrcData, pDstData, pKeys, pIV, type, IMB_DIR_ENCRYPT, 1,
                                   numBuffs, buf_idx);
        if (retTmp < 0)
                ret = retTmp;

        retTmp = submit_and_verify(mb_mgr, pSrcData, pDstData, pKeys, pIV, type, IMB_DIR_DECRYPT, 1,
                                   numBuffs, buf_idx);
        if (retTmp < 0)
                ret = retTmp;

        return ret;
};

static int
submit_and_verify_zuc_nea6(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                           uint8_t **pKeys, uint8_t **pIV, const enum api_type type,
                           IMB_CIPHER_DIRECTION dir, const unsigned int var_bufs,
                           const unsigned int num_buffers, const uint32_t *buf_idx)
{
        const struct cipher_test *vec_tab[MAXBUFS];
        const struct cipher_test *vectors = zuc_nea6_vectors;
        IMB_CIPHER_MODE cipher_mode = IMB_CIPHER_ZUC_NEA6;
        const struct kat_cipher_job_ops ops = {
                .prepare = zuc_job_prepare,
                .cleanup = zuc_job_cleanup,
                .ctx = &cipher_mode,
                .cipher_mode = IMB_CIPHER_ZUC_NEA6,
                .cipher_direction = dir,
                .chain_order = IMB_ORDER_CIPHER_HASH,
                .key_len_in_bytes = IMB_ZUC_NEA6_KEY_LEN_IN_BYTES,
                .in_place = 0,
        };

        (void) pSrcData;
        (void) pDstData;
        (void) pKeys;
        (void) pIV;
        (void) var_bufs;
        for (unsigned int i = 0; i < num_buffers; i++) {
                const struct cipher_test *vector = &vectors[buf_idx[i]];

                if ((vector->msgSize % 8) != 0 || (vector->keySize % 8) != 0 ||
                    (vector->ivSize % 8) != 0) {
                        printf("Unsupported non-byte-aligned ZUC-NEA6 vector (tcId=%zu)\n",
                               vector->tcId);
                        return -1;
                }
                vec_tab[i] = vector;
        }

        if (type == TEST_SINGLE_JOB_API)
                return kat_cipher_test_submit_flush(mb_mgr, vec_tab, num_buffers, num_buffers,
                                                    &ops);
        else
                return kat_cipher_test_generic_burst(mb_mgr, vec_tab, num_buffers, num_buffers,
                                                     &ops);
}

int
validate_zuc_NEA6(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData, uint8_t **pKeys,
                  uint8_t **pIV, uint32_t numBuffs, const enum api_type type)
{
        uint32_t i, j, num_vectors = 0;
        int ret = 0;
        int retTmp;
        uint32_t buf_idx[MAXBUFS];
        const struct cipher_test *vectors = zuc_nea6_vectors;

        /* calculate number of vectors */
        for (i = 0; vectors[i].msg != NULL; i++)
                num_vectors++;

        if (num_vectors == 0) {
                printf("ZUC-EEA3 256 - No vectors found!\n");
                return -1;
        }

        assert(numBuffs > 0);
        for (i = 0; i < num_vectors; i++) {
                for (j = 0; j < numBuffs; j++)
                        buf_idx[j] = i;

                retTmp = submit_and_verify_zuc_nea6(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                                    IMB_DIR_ENCRYPT, 0, numBuffs, buf_idx);
                if (retTmp < 0)
                        ret = retTmp;

                retTmp = submit_and_verify_zuc_nea6(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                                    IMB_DIR_DECRYPT, 0, numBuffs, buf_idx);
                if (retTmp < 0)
                        ret = retTmp;
        }

        /* Get all test vectors and encrypt them together */
        for (i = 0; i < numBuffs; i++)
                buf_idx[i] = i % num_vectors;

        retTmp = submit_and_verify_zuc_nea6(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                            IMB_DIR_ENCRYPT, 1, numBuffs, buf_idx);
        if (retTmp < 0)
                ret = retTmp;

        retTmp = submit_and_verify_zuc_nea6(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                            IMB_DIR_DECRYPT, 1, numBuffs, buf_idx);
        if (retTmp < 0)
                ret = retTmp;

        return ret;
}
