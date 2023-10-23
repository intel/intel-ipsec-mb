/*****************************************************************************
 Copyright (c) 2009-2023, Intel Corporation

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
#include "mac_test.h"

#define MAXBUFS     17
#define PASS_STATUS 0
#define FAIL_STATUS -1
#define DIM(_x)     (sizeof(_x) / sizeof(_x[0]))

#define MAX_BUFFER_LENGTH_IN_BITS  5670 /* biggest test is EIA test 5 */
#define MAX_BUFFER_LENGTH_IN_BYTES ((MAX_BUFFER_LENGTH_IN_BITS) + 7) / 8

#define MAX_BURST_JOBS 32

enum api_type { TEST_DIRECT_API, TEST_SINGLE_JOB_API, TEST_BURST_JOB_API };

int
zuc_eia3_test(struct IMB_MGR *mb_mgr);

extern const struct mac_test zuc_eia3_128_test_json[];
extern const struct mac_test zuc_eia3_256_test_json[];

struct zuc_eia3_128_params {
        const uint32_t *count;
        const uint8_t *bearer;
        const uint8_t *direction;
};

int
validate_zuc_algorithm(struct IMB_MGR *mb_mgr, uint8_t *pSrcData, uint8_t *pDstData, uint8_t *pKeys,
                       uint8_t *pIV);
int
validate_zuc_EIA_1_block(struct IMB_MGR *mb_mgr, uint8_t *pSrcData, uint8_t *pDstData,
                         uint8_t *pKeys, uint8_t *pIV, const enum api_type type);
int
validate_zuc_EIA_n_block(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                         uint8_t **pKeys, uint8_t **pIV, uint32_t numBuffs,
                         const enum api_type type);
int
validate_zuc256_EIA3(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                     uint8_t **pKeys, uint8_t **pIV, uint32_t numBuffs, const enum api_type type);

static void
byte_hexdump(const char *message, const uint8_t *ptr, int len);

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
zuc_eia3_test(struct IMB_MGR *mb_mgr)
{

        const uint32_t numBuffs[] = { 4, 8, 9, 16, 17 };
        uint32_t i;
        int errors = 0;
        uint8_t *pKeys[MAXBUFS] = { 0 };
        uint8_t *pIV[MAXBUFS] = { 0 };
        uint8_t *pSrcData[MAXBUFS] = { 0 };
        uint8_t *pDstData[MAXBUFS] = { 0 };
        struct test_suite_context eia3_ctx;
        struct test_suite_context eia3_256_ctx;

        test_suite_start(&eia3_ctx, "ZUC-EIA3");
        test_suite_start(&eia3_256_ctx, "ZUC-EIA3-256");

        /*Create test data buffers + populate with random data*/
        if (createData(pSrcData, MAXBUFS)) {
                printf("createData() error\n");
                test_suite_update(&eia3_ctx, 0, 1);
                goto exit_zuc_eia3_test;
        }
        if (createData(pDstData, MAXBUFS)) {
                printf("createData() error\n");
                freePtrArray(pSrcData, MAXBUFS);
                test_suite_update(&eia3_ctx, 0, 1);
                goto exit_zuc_eia3_test;
        }

        /* Create random keys and vectors */
        if (createKeyVecData(IMB_ZUC256_KEY_LEN_IN_BYTES, pKeys, IMB_ZUC256_IV_LEN_IN_BYTES_MAX,
                             pIV, MAXBUFS)) {
                printf("createKeyVecData() error\n");
                freePtrArray(pSrcData, MAXBUFS);
                freePtrArray(pDstData, MAXBUFS);
                test_suite_update(&eia3_ctx, 0, 1);
                goto exit_zuc_eia3_test;
        }

        /* Direct API tests */
        if (validate_zuc_EIA_1_block(mb_mgr, pSrcData[0], pDstData[0], pKeys[0], pIV[0],
                                     TEST_DIRECT_API))
                test_suite_update(&eia3_ctx, 0, 1);
        else
                test_suite_update(&eia3_ctx, 1, 0);

        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc_EIA_n_block(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                             TEST_DIRECT_API))
                        test_suite_update(&eia3_ctx, 0, 1);
                else
                        test_suite_update(&eia3_ctx, 1, 0);
        }

        /* Job API tests */
        if (validate_zuc_EIA_1_block(mb_mgr, pSrcData[0], pDstData[0], pKeys[0], pIV[0],
                                     TEST_SINGLE_JOB_API))
                test_suite_update(&eia3_ctx, 0, 1);
        else
                test_suite_update(&eia3_ctx, 1, 0);

        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc_EIA_n_block(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                             TEST_SINGLE_JOB_API))
                        test_suite_update(&eia3_ctx, 0, 1);
                else
                        test_suite_update(&eia3_ctx, 1, 0);
        }

        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc256_EIA3(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                         TEST_SINGLE_JOB_API))
                        test_suite_update(&eia3_256_ctx, 0, 1);
                else
                        test_suite_update(&eia3_256_ctx, 1, 0);
        }

        /* Burst job API tests */
        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc256_EIA3(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                         TEST_BURST_JOB_API))
                        test_suite_update(&eia3_256_ctx, 0, 1);
                else
                        test_suite_update(&eia3_256_ctx, 1, 0);
        }

exit_zuc_eia3_test:
        freePtrArray(pKeys, MAXBUFS);    /*Free the key buffers*/
        freePtrArray(pIV, MAXBUFS);      /*Free the vector buffers*/
        freePtrArray(pSrcData, MAXBUFS); /*Free the source buffers*/
        freePtrArray(pDstData, MAXBUFS); /*Free the destination buffers*/

        errors += test_suite_end(&eia3_ctx);
        errors += test_suite_end(&eia3_256_ctx);

        return errors;
}

static inline int
submit_burst_eia3_jobs(struct IMB_MGR *mb_mgr, uint8_t **const keys, uint8_t **const iv,
                       uint8_t **const src, uint8_t **const tags, const uint32_t *lens,
                       const unsigned int num_jobs, const unsigned int key_sz,
                       const size_t *tag_lens, const size_t *iv_lens)
{
        IMB_JOB *job, *jobs[MAX_BURST_JOBS] = { NULL };
        unsigned int i;
        unsigned int jobs_rx = 0;
        uint32_t completed_jobs = 0;
        int err;

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->src = src[i];
                if (iv_lens[i] == IMB_ZUC256_IV_LEN_IN_BYTES_MIN) {
                        job->u.ZUC_EIA3._iv = NULL;
                        job->u.ZUC_EIA3._iv23 = iv[i];
                } else {
                        job->u.ZUC_EIA3._iv = iv[i];
                        job->u.ZUC_EIA3._iv23 = NULL;
                }
                job->u.ZUC_EIA3._key = keys[i];

                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bits = lens[i];
                if (key_sz == IMB_ZUC_KEY_LEN_IN_BYTES)
                        job->hash_alg = IMB_AUTH_ZUC_EIA3_BITLEN;
                else
                        job->hash_alg = IMB_AUTH_ZUC256_EIA3_BITLEN;
                job->auth_tag_output = tags[i];
                job->auth_tag_output_len_in_bytes = tag_lens[i];

                imb_set_session(mb_mgr, job);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        err = imb_get_errno(mb_mgr);

        if (err != 0) {
                printf("submit_burst error %d : '%s'\n", err, imb_get_strerror(err));
                return -1;
        }

check_eia3_burst_jobs:
        for (i = 0; i < completed_jobs; i++) {
                job = jobs[i];

                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("job %u status not complete!\n", i + 1);
                        return -1;
                }

                jobs_rx++;
        }

        if (jobs_rx != num_jobs) {
                completed_jobs = IMB_FLUSH_BURST(mb_mgr, num_jobs - completed_jobs, jobs);
                if (completed_jobs == 0) {
                        printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                        return -1;
                }
                goto check_eia3_burst_jobs;
        }
        return 0;
}

static inline int
submit_eia3_jobs(struct IMB_MGR *mb_mgr, uint8_t **const keys, uint8_t **const iv,
                 uint8_t **const src, uint8_t **const tags, const uint32_t *lens,
                 const unsigned int num_jobs, const unsigned int key_sz, const size_t *tag_lens,
                 const size_t *iv_lens)
{
        IMB_JOB *job;
        unsigned int i;
        unsigned int jobs_rx = 0;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->src = src[i];
                if (iv_lens[i] == IMB_ZUC256_IV_LEN_IN_BYTES_MIN) {
                        job->u.ZUC_EIA3._iv = NULL;
                        job->u.ZUC_EIA3._iv23 = iv[i];
                } else {
                        job->u.ZUC_EIA3._iv = iv[i];
                        job->u.ZUC_EIA3._iv23 = NULL;
                }
                job->u.ZUC_EIA3._key = keys[i];

                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bits = lens[i];
                if (key_sz == IMB_ZUC_KEY_LEN_IN_BYTES)
                        job->hash_alg = IMB_AUTH_ZUC_EIA3_BITLEN;
                else
                        job->hash_alg = IMB_AUTH_ZUC256_EIA3_BITLEN;
                job->auth_tag_output = tags[i];
                job->auth_tag_output_len_in_bytes = tag_lens[i];

                job = IMB_SUBMIT_JOB(mb_mgr);
                if (job != NULL) {
                        jobs_rx++;
                        if (job->status != IMB_STATUS_COMPLETED) {
                                printf("%d error status:%d, job %u", __LINE__, job->status, i);
                                return -1;
                        }
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr)) != NULL) {
                jobs_rx++;
                if (job->status != IMB_STATUS_COMPLETED) {
                        printf("%d error status:%d, job %u", __LINE__, job->status, i);
                        return -1;
                }
        }

        if (jobs_rx != num_jobs) {
                printf("Expected %u jobs, received %u\n", num_jobs, jobs_rx);
                return -1;
        }

        return 0;
}

/**
 * Count, Bearer and Direction stored in vector IV field
 */
static void
zuc_eia3_128_set_params(const struct mac_test *v, struct zuc_eia3_128_params *p)
{
        const uint8_t *params = (const uint8_t *) v->iv;

        p->count = (const uint32_t *) &params[0];
        p->bearer = &params[4];
        p->direction = &params[5];
}

int
validate_zuc_EIA_1_block(struct IMB_MGR *mb_mgr, uint8_t *pSrcData, uint8_t *pDstData,
                         uint8_t *pKeys, uint8_t *pIV, const enum api_type type)
{
        uint32_t i;
        int ret = 0;
        uint32_t bitLength;
        const struct mac_test *v = zuc_eia3_128_test_json;

        for (i = 0; v[i].msg != NULL; i++) {
                struct zuc_eia3_128_params p = { 0 };
                const size_t iv_len = v[i].ivSize / 8;
                const size_t tag_len = IMB_ZUC_DIGEST_LEN_IN_BYTES;

                memcpy(pKeys, v[i].key, IMB_ZUC_KEY_LEN_IN_BYTES);

                zuc_eia3_128_set_params(&v[i], &p);
                zuc_eia3_iv_gen(*p.count, *p.bearer, *p.direction, pIV);
                bitLength = (uint32_t) v[i].msgSize;

                const uint32_t byteLength = (bitLength + 7) / 8;

                memcpy(pSrcData, v[i].msg, byteLength);
                if (type == TEST_SINGLE_JOB_API)
                        submit_eia3_jobs(mb_mgr, &pKeys, &pIV, &pSrcData, &pDstData, &bitLength, 1,
                                         IMB_ZUC_KEY_LEN_IN_BYTES, &tag_len, &iv_len);
                else /* TEST_DIRECT_API */
                        IMB_ZUC_EIA3_1_BUFFER(mb_mgr, pKeys, pIV, pSrcData, bitLength,
                                              (uint32_t *) pDstData);
                const int retTmp = memcmp(pDstData, v[i].tag, v[i].tagSize / 8);
                if (retTmp) {
                        printf("Validate ZUC 1 block test %zu (Int): FAIL\n", v[i].tcId);
                        byte_hexdump("Expected", (const uint8_t *) v[i].tag,
                                     IMB_ZUC_DIGEST_LEN_IN_BYTES);
                        byte_hexdump("Found", pDstData, IMB_ZUC_DIGEST_LEN_IN_BYTES);
                        ret = retTmp;
                }
#ifdef DEBUG
                else {
                        if (!quiet_mode)
                                printf("ZUC-EIA3 128 1 block vector %zu Message length: %zu, "
                                       "Tag length: %zu\n",
                                       v[i].tcId, v[i].msgSize / 8, v[i].tagSize / 8);
                }
#endif
                fflush(stdout);
        }
        return ret;
};

int
validate_zuc_EIA_n_block(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                         uint8_t **pKeys, uint8_t **pIV, uint32_t numBuffs,
                         const enum api_type type)
{
        uint32_t i, j, num_vectors = 0;
        int retTmp, ret = 0;
        uint32_t byteLength;
        uint32_t bitLength[MAXBUFS];
        size_t iv_lens[MAXBUFS];
        size_t tag_lens[MAXBUFS];
        const struct mac_test *v = zuc_eia3_128_test_json;

        /* calculate number of test vectors */
        for (i = 0; v[i].msg != NULL; i++)
                num_vectors++;

        if (num_vectors == 0) {
                printf("ZUC-EIA3 128 N block - No vectors found!\n");
                return 1;
        }

        for (i = 0; i < num_vectors; i++) {
                for (j = 0; j < numBuffs; j++) {
                        struct zuc_eia3_128_params p = { 0 };
                        memcpy(pKeys[j], v[i].key, IMB_ZUC_KEY_LEN_IN_BYTES);

                        zuc_eia3_128_set_params(&v[i], &p);
                        zuc_eia3_iv_gen(*p.count, *p.bearer, *p.direction, pIV[j]);
                        bitLength[j] = (uint32_t) v[i].msgSize;
                        byteLength = (bitLength[j] + 7) / 8;
                        memcpy(pSrcData[j], v[i].msg, byteLength);
                        iv_lens[j] = IMB_ZUC_IV_LEN_IN_BYTES;
                        tag_lens[j] = v[i].tagSize / 8;
                }
                if (type == TEST_SINGLE_JOB_API)
                        submit_eia3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, bitLength,
                                         numBuffs, IMB_ZUC_KEY_LEN_IN_BYTES, tag_lens, iv_lens);
                else if (type == TEST_BURST_JOB_API)
                        submit_burst_eia3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, bitLength,
                                               numBuffs, IMB_ZUC_KEY_LEN_IN_BYTES, tag_lens,
                                               iv_lens);
                else /* TEST_BURST_JOB_API */
                        IMB_ZUC_EIA3_N_BUFFER(mb_mgr, (const void *const *) pKeys,
                                              (const void *const *) pIV,
                                              (const void *const *) pSrcData, bitLength,
                                              (uint32_t **) pDstData, numBuffs);

                for (j = 0; j < numBuffs; j++) {
                        retTmp = memcmp(pDstData[j], v[i].tag, IMB_ZUC_DIGEST_LEN_IN_BYTES);
                        if (retTmp) {
                                printf("ZUC-EIA3 128 N block #jobs: %d, vector %zu Message "
                                       "length: %zu, Tag length: %zu\n",
                                       numBuffs, v[i].tcId, v[i].msgSize / 8, v[i].tagSize / 8);
                                byte_hexdump("Expected", (const uint8_t *) v[i].tag,
                                             IMB_ZUC_DIGEST_LEN_IN_BYTES);
                                byte_hexdump("Found", pDstData[j], IMB_ZUC_DIGEST_LEN_IN_BYTES);
                                ret = retTmp;
                        }
#ifdef DEBUG
                        else {
                                if (!quiet_mode)
                                        printf("ZUC-EIA3 128 N block #jobs: %d, vector %zu Message "
                                               "length: %zu, Tag length: %zu\n",
                                               numBuffs, v[i].tcId, v[i].msgSize / 8,
                                               v[i].tagSize / 8);
                        }
#endif
                        fflush(stdout);
                }
        }

        /* Generate digests for n different test vectors,
         * grouping all available tests vectors in groups of N buffers */
        for (i = 0; i < numBuffs; i++) {
                const int vec_idx = i % num_vectors;
                struct zuc_eia3_128_params p = { 0 };
                memcpy(pKeys[i], v[vec_idx].key, IMB_ZUC_KEY_LEN_IN_BYTES);

                zuc_eia3_128_set_params(&v[vec_idx], &p);
                zuc_eia3_iv_gen(*p.count, *p.bearer, *p.direction, pIV[i]);
                bitLength[i] = (uint32_t) v[vec_idx].msgSize;
                byteLength = (bitLength[i] + 7) / 8;
                memcpy(pSrcData[i], v[vec_idx].msg, byteLength);
                iv_lens[i] = IMB_ZUC_IV_LEN_IN_BYTES;
                tag_lens[i] = v[vec_idx].tagSize / 8;
        }

        if (type == TEST_SINGLE_JOB_API)
                submit_eia3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, bitLength, numBuffs,
                                 IMB_ZUC_KEY_LEN_IN_BYTES, tag_lens, iv_lens);
        else if (type == TEST_BURST_JOB_API)
                submit_burst_eia3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, bitLength, numBuffs,
                                       IMB_ZUC_KEY_LEN_IN_BYTES, tag_lens, iv_lens);
        else /* TEST_BURST_JOB_API */
                IMB_ZUC_EIA3_N_BUFFER(mb_mgr, (const void *const *) pKeys,
                                      (const void *const *) pIV, (const void *const *) pSrcData,
                                      bitLength, (uint32_t **) pDstData, numBuffs);

        for (i = 0; i < numBuffs; i++) {
                const int vec_idx = i % num_vectors;
                retTmp = memcmp(pDstData[i], v[vec_idx].tag, v[vec_idx].tagSize / 8);
                if (retTmp) {
                        printf("ZUC-EIA3 128 N block #jobs: %d, vector %zu Message "
                               "length: %zu, Tag length: %zu\n",
                               numBuffs, v[vec_idx].tcId, v[vec_idx].msgSize / 8,
                               v[vec_idx].tagSize / 8);
                        byte_hexdump("Expected", (const uint8_t *) v[vec_idx].tag,
                                     IMB_ZUC_DIGEST_LEN_IN_BYTES);
                        byte_hexdump("Found", pDstData[i], IMB_ZUC_DIGEST_LEN_IN_BYTES);
                        ret = retTmp;
                }
#ifdef DEBUG
                else {
                        if (!quiet_mode)
                                printf("ZUC-EIA3 128 N block #jobs: %d, vector %zu Message "
                                       "length: %zu, Tag length: %zu\n",
                                       numBuffs, v[vec_idx].tcId, v[vec_idx].msgSize / 8,
                                       v[vec_idx].tagSize / 8);
                }
#endif
                fflush(stdout);
        }
        return ret;
};

static int
verify_tag_256(void *mac, const struct mac_test *vector, uint32_t n_jobs, uint32_t job_idx,
               const int multi_vector)
{
        int ret = memcmp(mac, vector->tag, vector->tagSize / 8);
        if (ret) {
                if (multi_vector) {
                        printf("Validate ZUC-256 n block multi-vector test "
                               "# jobs = %u, job idx: %u, test: %zu (Int - %zu bytes): FAIL\n",
                               n_jobs, job_idx, vector->tcId, vector->tagSize / 8);

                } else {
                        printf("Validate ZUC-256 n block test "
                               "# jobs = %u, job idx: %u, test: %zu (Int - %zu bytes): FAIL\n",
                               n_jobs, job_idx, vector->tcId, vector->tagSize / 8);
                }
                byte_hexdump("Expected", (const uint8_t *) vector->tag, (int) vector->tagSize / 8);
                byte_hexdump("Found", mac, (int) vector->tagSize / 8);
        }
#ifdef DEBUG
        else {
                if (!quiet_mode) {
                        if (multi_vector) {
                                printf("Validate ZUC-256 n block multi-vector test "
                                       "# jobs = %u, job idx: %u, test: %zu (Int - %zu bytes): "
                                       "PASS\n",
                                       n_jobs, job_idx, vector->tcId, vector->tagSize / 8);

                        } else {
                                printf("Validate ZUC-256 n block test "
                                       "# jobs = %u, job idx: %u, test: %zu (Int - %zu bytes): "
                                       "PASS\n",
                                       n_jobs, job_idx, vector->tcId, vector->tagSize / 8);
                        }
                }
        }
#endif
        fflush(stdout);

        return ret;
}

int
validate_zuc256_EIA3(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                     uint8_t **pKeys, uint8_t **pIV, uint32_t numBuffs, const enum api_type type)
{
        uint32_t i, j, num_vectors = 0;
        int retTmp, ret = 0;
        uint32_t byteLength;
        uint32_t bitLength[MAXBUFS];
        size_t iv_lens[MAXBUFS];
        size_t tag_lens[MAXBUFS];

        const struct mac_test *vector = zuc_eia3_256_test_json;

        /* calculate number of test vectors */
        for (i = 0; vector[i].msg != NULL; i++)
                num_vectors++;

        if (num_vectors == 0) {
                printf("ZUC-EIA3 256 N block - No vectors found!\n");
                return 1;
        }

        for (i = 0; i < num_vectors; i++) {
                for (j = 0; j < numBuffs; j++) {
                        /* copy data for N buffers / jobs */
                        memcpy(pKeys[j], vector[i].key, IMB_ZUC256_KEY_LEN_IN_BYTES);
                        memcpy(pIV[j], vector[i].iv, vector[i].ivSize / 8);
                        bitLength[j] = (uint32_t) vector[i].msgSize;
                        byteLength = (bitLength[j] + 7) / 8;
                        memcpy(pSrcData[j], vector[i].msg, byteLength);
                        iv_lens[j] = vector[i].ivSize / 8;
                        tag_lens[j] = vector[i].tagSize / 8;
                }
                if (type == TEST_SINGLE_JOB_API)
                        submit_eia3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, bitLength,
                                         numBuffs, IMB_ZUC256_KEY_LEN_IN_BYTES, tag_lens, iv_lens);
                else /* TEST_BURST_JOB_API */
                        submit_burst_eia3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, bitLength,
                                               numBuffs, IMB_ZUC256_KEY_LEN_IN_BYTES, tag_lens,
                                               iv_lens);

                for (j = 0; j < numBuffs; j++) {

                        retTmp = verify_tag_256(pDstData[j], &vector[i], numBuffs, j, 0);
                        if (retTmp)
                                ret = retTmp;
                }
        }

        /* Generate digests for n different test vectors,
         * grouping all available tests vectors in groups of N buffers */
        for (i = 0; i < numBuffs; i++) {
                const int vec_idx = i % num_vectors;
                memcpy(pKeys[i], vector[vec_idx].key, IMB_ZUC256_KEY_LEN_IN_BYTES);
                memcpy(pIV[i], vector[vec_idx].iv, vector[vec_idx].ivSize / 8);

                bitLength[i] = (uint32_t) vector[vec_idx].msgSize;
                byteLength = (bitLength[i] + 7) / 8;
                memcpy(pSrcData[i], vector[vec_idx].msg, byteLength);
                iv_lens[i] = vector[vec_idx].ivSize / 8;
                tag_lens[i] = vector[vec_idx].tagSize / 8;
        }

        if (type == TEST_SINGLE_JOB_API)
                submit_eia3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, bitLength, numBuffs,
                                 IMB_ZUC256_KEY_LEN_IN_BYTES, tag_lens, iv_lens);
        else /* TEST_BURST_JOB_API */
                submit_burst_eia3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, bitLength, numBuffs,
                                       IMB_ZUC256_KEY_LEN_IN_BYTES, tag_lens, iv_lens);

        for (i = 0; i < numBuffs; i++) {
                const int vec_idx = i % num_vectors;

                retTmp = verify_tag_256(pDstData[i], &vector[vec_idx], numBuffs, i, 1);
                if (retTmp)
                        ret = retTmp;
        }
        return ret;
};

/*****************************************************************************
 ** @description - utility function to dump test buffers$
 ** $
 ** @param message [IN] - debug message to print$
 ** @param ptr [IN] - pointer to beginning of buffer.$
 ** @param len [IN] - length of buffer.$
 *****************************************************************************/
static void
byte_hexdump(const char *message, const uint8_t *ptr, int len)
{
        int ctr;

        printf("%s:\n", message);
        for (ctr = 0; ctr < len; ctr++) {
                printf("0x%02X ", ptr[ctr] & 0xff);
                if (!((ctr + 1) % 16))
                        printf("\n");
        }
        printf("\n");
        printf("\n");
};
