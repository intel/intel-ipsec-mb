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
#include "cipher_test.h"

#define MAXBUFS     17
#define PASS_STATUS 0
#define FAIL_STATUS -1
#define DIM(_x)     (sizeof(_x) / sizeof(_x[0]))

#define MAX_BUFFER_LENGTH_IN_BITS  5670 /* biggest test is EIA test 5 */
#define MAX_BUFFER_LENGTH_IN_BYTES ((MAX_BUFFER_LENGTH_IN_BITS) + 7) / 8

enum api_type { TEST_DIRECT_API, TEST_SINGLE_JOB_API, TEST_BURST_JOB_API };

int
zuc_eea3_test(struct IMB_MGR *mb_mgr);

extern const struct cipher_test zuc_eea3_128_test_json[];
extern const struct cipher_test zuc_eea3_256_test_json[];

struct zuc_eea3_128_params {
        const uint32_t *count;
        const uint8_t *bearer;
        const uint8_t *direction;
};

int
validate_zuc_algorithm(struct IMB_MGR *mb_mgr, uint8_t *pSrcData, uint8_t *pDstData, uint8_t *pKeys,
                       uint8_t *pIV);
int
validate_zuc_EEA_1_block(struct IMB_MGR *mb_mgr, uint8_t *pSrcData, uint8_t *pDstData,
                         uint8_t *pKeys, uint8_t *pIV, const enum api_type type);
int
validate_zuc_EEA_4_block(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                         uint8_t **pKeys, uint8_t **pIV, enum api_type type);
int
validate_zuc_EEA_n_block(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                         uint8_t **pKeys, uint8_t **pIV, uint32_t numBuffs,
                         const enum api_type type);
int
validate_zuc256_EEA3(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                     uint8_t **pKeys, uint8_t **pIV, uint32_t numBuffs, const enum api_type type);

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
zuc_eea3_test(struct IMB_MGR *mb_mgr)
{

        const uint32_t numBuffs[] = { 4, 8, 9, 16, 17 };
        uint32_t i;
        int errors = 0;
        uint8_t *pKeys[MAXBUFS] = { 0 };
        uint8_t *pIV[MAXBUFS] = { 0 };
        uint8_t *pSrcData[MAXBUFS] = { 0 };
        uint8_t *pDstData[MAXBUFS] = { 0 };
        struct test_suite_context eea3_ctx;
        struct test_suite_context eea3_256_ctx;

        test_suite_start(&eea3_ctx, "ZUC-EEA3");
        test_suite_start(&eea3_256_ctx, "ZUC-EEA3-256");

        /*Create test data buffers + populate with random data*/
        if (createData(pSrcData, MAXBUFS)) {
                printf("createData() error\n");
                test_suite_update(&eea3_ctx, 0, 1);
                goto exit_zuc_eea3_test;
        }
        if (createData(pDstData, MAXBUFS)) {
                printf("createData() error\n");
                freePtrArray(pSrcData, MAXBUFS);
                test_suite_update(&eea3_ctx, 0, 1);
                goto exit_zuc_eea3_test;
        }

        /* Create random keys and vectors */
        if (createKeyVecData(IMB_ZUC256_KEY_LEN_IN_BYTES, pKeys, IMB_ZUC256_IV_LEN_IN_BYTES_MAX,
                             pIV, MAXBUFS)) {
                printf("createKeyVecData() error\n");
                freePtrArray(pSrcData, MAXBUFS);
                freePtrArray(pDstData, MAXBUFS);
                test_suite_update(&eea3_ctx, 0, 1);
                goto exit_zuc_eea3_test;
        }

        /* Direct API tests */
        if (validate_zuc_EEA_1_block(mb_mgr, pSrcData[0], pSrcData[0], pKeys[0], pIV[0],
                                     TEST_DIRECT_API))
                test_suite_update(&eea3_ctx, 0, 1);
        else
                test_suite_update(&eea3_ctx, 1, 0);

        if (validate_zuc_EEA_4_block(mb_mgr, pSrcData, pSrcData, pKeys, pIV, TEST_DIRECT_API))
                test_suite_update(&eea3_ctx, 0, 1);
        else
                test_suite_update(&eea3_ctx, 1, 0);

        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc_EEA_n_block(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                             TEST_DIRECT_API))
                        test_suite_update(&eea3_ctx, 0, 1);
                else
                        test_suite_update(&eea3_ctx, 1, 0);
        }

        /* Job API tests */
        if (validate_zuc_EEA_1_block(mb_mgr, pSrcData[0], pSrcData[0], pKeys[0], pIV[0],
                                     TEST_SINGLE_JOB_API))
                test_suite_update(&eea3_ctx, 0, 1);
        else
                test_suite_update(&eea3_ctx, 1, 0);

        if (validate_zuc_EEA_4_block(mb_mgr, pSrcData, pSrcData, pKeys, pIV, TEST_SINGLE_JOB_API))
                test_suite_update(&eea3_ctx, 0, 1);
        else
                test_suite_update(&eea3_ctx, 1, 0);

        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc_EEA_n_block(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                             TEST_SINGLE_JOB_API))
                        test_suite_update(&eea3_ctx, 0, 1);
                else
                        test_suite_update(&eea3_ctx, 1, 0);
        }

        for (i = 0; i < DIM(numBuffs); i++) {
                if (validate_zuc256_EEA3(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                         TEST_SINGLE_JOB_API))
                        test_suite_update(&eea3_256_ctx, 0, 1);
                else
                        test_suite_update(&eea3_256_ctx, 1, 0);
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
                if (validate_zuc256_EEA3(mb_mgr, pSrcData, pDstData, pKeys, pIV, numBuffs[i],
                                         TEST_BURST_JOB_API))
                        test_suite_update(&eea3_256_ctx, 0, 1);
                else
                        test_suite_update(&eea3_256_ctx, 1, 0);
        }

exit_zuc_eea3_test:
        freePtrArray(pKeys, MAXBUFS);    /*Free the key buffers*/
        freePtrArray(pIV, MAXBUFS);      /*Free the vector buffers*/
        freePtrArray(pSrcData, MAXBUFS); /*Free the source buffers*/
        freePtrArray(pDstData, MAXBUFS); /*Free the destination buffers*/

        errors += test_suite_end(&eea3_ctx);
        errors += test_suite_end(&eea3_256_ctx);

        return errors;
}

static inline int
submit_burst_eea3_jobs(struct IMB_MGR *mb_mgr, uint8_t **const keys, uint8_t **const ivs,
                       uint8_t **const src, uint8_t **const dst, const uint32_t *lens, int dir,
                       const unsigned int num_jobs, const unsigned int key_len,
                       const unsigned int *iv_lens)
{
        IMB_JOB *job, *jobs[IMB_MAX_BURST_SIZE] = { NULL };
        unsigned int i;
        unsigned int jobs_rx = 0;
        uint32_t completed_jobs = 0;
        int err;

        while (IMB_GET_NEXT_BURST(mb_mgr, num_jobs, jobs) < num_jobs)
                IMB_FLUSH_BURST(mb_mgr, num_jobs, jobs);

        for (i = 0; i < num_jobs; i++) {
                job = jobs[i];
                job->cipher_direction = dir;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_ZUC_EEA3;
                job->src = src[i];
                job->dst = dst[i];
                job->iv = ivs[i];
                job->iv_len_in_bytes = iv_lens[i];
                job->enc_keys = keys[i];
                job->key_len_in_bytes = key_len;

                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = lens[i];
                job->hash_alg = IMB_AUTH_NULL;

                imb_set_session(mb_mgr, job);
        }

        completed_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, jobs);
        err = imb_get_errno(mb_mgr);

        if (err != 0) {
                printf("submit_burst error %d : '%s'\n", err, imb_get_strerror(err));
                return -1;
        }

check_eea3_burst_jobs:
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
                goto check_eea3_burst_jobs;
        }

        return 0;
}

static inline int
submit_eea3_jobs(struct IMB_MGR *mb_mgr, uint8_t **const keys, uint8_t **const ivs,
                 uint8_t **const src, uint8_t **const dst, const uint32_t *lens, int dir,
                 const unsigned int num_jobs, const unsigned int key_len,
                 const unsigned int *iv_lens)
{
        IMB_JOB *job;
        unsigned int i;
        unsigned int jobs_rx = 0;

        for (i = 0; i < num_jobs; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                job->cipher_direction = dir;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_ZUC_EEA3;
                job->src = src[i];
                job->dst = dst[i];
                job->iv = ivs[i];
                job->iv_len_in_bytes = iv_lens[i];
                job->enc_keys = keys[i];
                job->key_len_in_bytes = key_len;

                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = lens[i];
                job->hash_alg = IMB_AUTH_NULL;

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

static int
test_output(const uint8_t *out, const uint8_t *ref, const uint32_t bytelen, const uint32_t bitlen,
            const char *err_msg)
{
        int ret = 0;
        uint32_t byteResidue;
        uint32_t bitResidue;

        if (bitlen % 8)
                /* Last byte is not a full byte */
                ret = memcmp(out, ref, bytelen - 1);
        else
                /* Last byte is a full byte */
                ret = memcmp(out, ref, bytelen);

        if (ret) {
                printf("%s : FAIL\n", err_msg);
                byte_hexdump("Expected", ref, bytelen);
                byte_hexdump("Found", out, bytelen);
                ret = -1;
                /*
                 * Check last partial byte if there is one and
                 * all previous full bytes are correct
                 */
        } else if (bitlen % 8) {
                bitResidue = (0xFF00 >> (bitlen % 8)) & 0x00FF;
                byteResidue = (ref[bitlen / 8] ^ out[bitlen / 8]) & bitResidue;
                if (byteResidue) {
                        printf("%s : FAIL\n", err_msg);
                        printf("Expected: 0x%02X (last byte)\n", 0xFF & ref[bitlen / 8]);
                        printf("Found: 0x%02X (last byte)\n", 0xFF & out[bitlen / 8]);
                        ret = -1;
                }
#ifdef DEBUG
                else {
                        if (!quiet_mode)
                                printf("%s : PASS\n", err_msg);
                }
#endif
        }
#ifdef DEBUG
        else {
                if (!quiet_mode)
                        printf("%s : PASS\n", err_msg);
        }
#endif
        fflush(stdout);

        return ret;
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

int
validate_zuc_EEA_1_block(struct IMB_MGR *mb_mgr, uint8_t *pSrcData, uint8_t *pDstData,
                         uint8_t *pKeys, uint8_t *pIV, const enum api_type type)
{
        uint32_t i;
        int ret = 0;
        const struct cipher_test *vectors = zuc_eea3_128_test_json;

        /* ZUC-128-EEA3 */
        for (i = 0; vectors[i].msg != NULL; i++) {
                char msg[50];
                int retTmp;
                uint32_t byteLength;
                const unsigned int iv_len = IMB_ZUC_IV_LEN_IN_BYTES;

                /* generate IV if params stored in vector */
                if ((vectors[i].ivSize / 8) != iv_len) {
                        struct zuc_eea3_128_params p = { 0 };

                        zuc_eea3_128_set_params(&vectors[i], &p);
                        zuc_eea3_iv_gen(*p.count, *p.bearer, *p.direction, pIV);
                } else
                        /* actual iv stored in vector */
                        memcpy(pIV, vectors[i].iv, IMB_ZUC_IV_LEN_IN_BYTES);

                memcpy(pKeys, vectors[i].key, IMB_ZUC_KEY_LEN_IN_BYTES);
                byteLength = (uint32_t) (vectors[i].msgSize + 7) / 8;
                memcpy(pSrcData, vectors[i].msg, byteLength);
                if (type == TEST_SINGLE_JOB_API)
                        submit_eea3_jobs(mb_mgr, &pKeys, &pIV, &pSrcData, &pDstData, &byteLength,
                                         IMB_DIR_ENCRYPT, 1, IMB_ZUC_KEY_LEN_IN_BYTES, &iv_len);
                else
                        IMB_ZUC_EEA3_1_BUFFER(mb_mgr, pKeys, pIV, pSrcData, pDstData, byteLength);

                snprintf(msg, sizeof(msg), "Validate ZUC 1 block test %zu (Enc):", vectors[i].tcId);
                retTmp = test_output(pDstData, (const uint8_t *) vectors[i].ct, byteLength,
                                     (uint32_t) vectors[i].msgSize, msg);
                if (retTmp < 0)
                        ret = retTmp;
        }

        return ret;
};

static int
submit_and_verify(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData, uint8_t **pKeys,
                  uint8_t **pIV, const enum api_type type, IMB_CIPHER_DIRECTION dir,
                  const unsigned int var_bufs, const unsigned int num_buffers,
                  const uint32_t *buf_idx)
{
        unsigned int i;
        uint32_t packetLen[MAXBUFS];
        int ret = 0;
        unsigned int iv_lens[MAXBUFS];
        const struct cipher_test *vectors = zuc_eea3_128_test_json;

        for (i = 0; i < num_buffers; i++) {
                const struct cipher_test *vector = &vectors[buf_idx[i]];

                packetLen[i] = (uint32_t) (vector->msgSize + 7) / 8;
                iv_lens[i] = IMB_ZUC_IV_LEN_IN_BYTES;

                /* generate IV if params stored in vector */
                if ((vector->ivSize / 8) != iv_lens[i]) {
                        struct zuc_eea3_128_params p = { 0 };

                        zuc_eea3_128_set_params(vector, &p);
                        zuc_eea3_iv_gen(*p.count, *p.bearer, *p.direction, pIV[i]);
                } else
                        /* actual iv stored in vector */
                        memcpy(pIV[i], vector->iv, IMB_ZUC_IV_LEN_IN_BYTES);

                memcpy(pKeys[i], vector->key, IMB_ZUC_KEY_LEN_IN_BYTES);
                if (dir == IMB_DIR_ENCRYPT)
                        memcpy(pSrcData[i], vector->msg, packetLen[i]);
                else
                        memcpy(pSrcData[i], vector->ct, packetLen[i]);
        }

        if (type == TEST_SINGLE_JOB_API)
                submit_eea3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, packetLen, dir,
                                 num_buffers, IMB_ZUC_KEY_LEN_IN_BYTES, iv_lens);
        else if (type == TEST_BURST_JOB_API)
                submit_burst_eea3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, packetLen, dir,
                                       num_buffers, IMB_ZUC_KEY_LEN_IN_BYTES, iv_lens);
        else {
                if (num_buffers == 4)
                        IMB_ZUC_EEA3_4_BUFFER(
                                mb_mgr, (const void *const *) pKeys, (const void *const *) pIV,
                                (const void *const *) pSrcData, (void **) pDstData, packetLen);
                else
                        IMB_ZUC_EEA3_N_BUFFER(mb_mgr, (const void *const *) pKeys,
                                              (const void *const *) pIV,
                                              (const void *const *) pSrcData, (void **) pDstData,
                                              packetLen, num_buffers);
        }

        for (i = 0; i < num_buffers; i++) {
                uint8_t *pDst8 = (uint8_t *) pDstData[i];
                int retTmp;
                char msg_start[50];
                char msg[100];
                const struct cipher_test *vector = &vectors[buf_idx[i]];

                if (var_bufs)
                        snprintf(msg_start, sizeof(msg_start), "Validate ZUC %c block multi-vector",
                                 num_buffers == 4 ? '4' : 'N');
                else
                        snprintf(msg_start, sizeof(msg_start), "Validate ZUC %c block",
                                 num_buffers == 4 ? '4' : 'N');

                if (dir == IMB_DIR_ENCRYPT) {
                        snprintf(msg, sizeof(msg), "%s test %zu, index %u (Enc):", msg_start,
                                 vector->tcId, i);
                        retTmp = test_output(pDst8, (const uint8_t *) vector->ct, packetLen[i],
                                             (uint32_t) vector->msgSize, msg);
                } else { /* DECRYPT */
                        snprintf(msg, sizeof(msg), "%s test %zu, index %u (Dec):", msg_start,
                                 vector->tcId, i);
                        retTmp = test_output(pDst8, (const uint8_t *) vector->msg, packetLen[i],
                                             (uint32_t) vector->msgSize, msg);
                }
                if (retTmp < 0)
                        ret = retTmp;
        }

        return ret;
}

static int
submit_and_verify_zuc256(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                         uint8_t **pKeys, uint8_t **pIV, const enum api_type type,
                         IMB_CIPHER_DIRECTION dir, const unsigned int var_bufs,
                         const unsigned int num_buffers, const uint32_t *buf_idx)
{
        unsigned int i;
        uint32_t packetLen[MAXBUFS];
        int ret = 0;
        unsigned int iv_lens[MAXBUFS];
        const struct cipher_test *vectors = zuc_eea3_256_test_json;

        for (i = 0; i < num_buffers; i++) {
                const struct cipher_test *vector = &vectors[buf_idx[i]];

                packetLen[i] = (uint32_t) (vector->msgSize + 7) / 8;
                memcpy(pKeys[i], vector->key, vector->keySize / 8);
                memcpy(pIV[i], vector->iv, vector->ivSize / 8);
                if (dir == IMB_DIR_ENCRYPT)
                        memcpy(pSrcData[i], vector->msg, packetLen[i]);
                else
                        memcpy(pSrcData[i], vector->ct, packetLen[i]);
                iv_lens[i] = (uint32_t) vector->ivSize / 8;
        }

        if (type == TEST_SINGLE_JOB_API)
                submit_eea3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, packetLen, dir,
                                 num_buffers, IMB_ZUC256_KEY_LEN_IN_BYTES, iv_lens);
        else if (type == TEST_BURST_JOB_API)
                submit_burst_eea3_jobs(mb_mgr, pKeys, pIV, pSrcData, pDstData, packetLen, dir,
                                       num_buffers, IMB_ZUC256_KEY_LEN_IN_BYTES, iv_lens);

        for (i = 0; i < num_buffers; i++) {
                uint8_t *pDst8 = (uint8_t *) pDstData[i];
                int retTmp;
                char msg_start[50];
                char msg[100];
                const struct cipher_test *vector = &vectors[buf_idx[i]];

                if (var_bufs)
                        snprintf(msg_start, sizeof(msg_start), "Validate ZUC-256 multi-vector");
                else
                        snprintf(msg_start, sizeof(msg_start), "Validate ZUC-256");

                if (dir == IMB_DIR_ENCRYPT) {
                        snprintf(msg, sizeof(msg), "%s test %zu, index %u (Enc):", msg_start,
                                 vector->tcId, i);
                        retTmp = test_output(pDst8, (const uint8_t *) vector->ct, packetLen[i],
                                             (uint32_t) vector->msgSize, msg);
                } else { /* DECRYPT */
                        snprintf(msg, sizeof(msg), "%s test %zu, index %u (Dec):", msg_start,
                                 vector->tcId, i);
                        retTmp = test_output(pDst8, (const uint8_t *) vector->msg, packetLen[i],
                                             (uint32_t) vector->msgSize, msg);
                }
                if (retTmp < 0)
                        ret = retTmp;
        }

        return ret;
}

int
validate_zuc_EEA_4_block(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                         uint8_t **pKeys, uint8_t **pIV, const enum api_type type)
{
        uint32_t i, j, num_vectors = 0;
        int ret = 0;
        int retTmp;
        uint32_t buf_idx[4];
        const struct cipher_test *vectors = zuc_eea3_128_test_json;

        /* calculate number of vectors */
        for (i = 0; vectors[i].msg != NULL; i++)
                num_vectors++;

        if (num_vectors == 0) {
                printf("ZUC-EEA3 128 4 block - No vectors found!\n");
                return -1;
        }

        for (i = 0; i < num_vectors; i++) {
                for (j = 0; j < 4; j++)
                        buf_idx[j] = i;

                retTmp = submit_and_verify(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                           IMB_DIR_ENCRYPT, 0, 4, buf_idx);
                if (retTmp < 0)
                        ret = retTmp;
                retTmp = submit_and_verify(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                           IMB_DIR_DECRYPT, 0, 4, buf_idx);
                if (retTmp < 0)
                        ret = retTmp;
        }

        /* Encrypt 4 different buffers, grouping all available test vectors
         * in groups of 4 */
        for (i = 0; i < num_vectors; i++) {
                for (j = 0; j < 4; j++)
                        buf_idx[j] = (i + j) % num_vectors;

                retTmp = submit_and_verify(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                           IMB_DIR_ENCRYPT, 1, 4, buf_idx);
                if (retTmp < 0)
                        ret = retTmp;
                retTmp = submit_and_verify(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                           IMB_DIR_DECRYPT, 1, 4, buf_idx);
                if (retTmp < 0)
                        ret = retTmp;
        }

        return ret;
};

int
validate_zuc_EEA_n_block(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                         uint8_t **pKeys, uint8_t **pIV, uint32_t numBuffs,
                         const enum api_type type)
{
        uint32_t i, j, num_vectors = 0;
        int ret = 0;
        int retTmp;
        uint32_t buf_idx[MAXBUFS];
        const struct cipher_test *vectors = zuc_eea3_128_test_json;

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

int
validate_zuc256_EEA3(struct IMB_MGR *mb_mgr, uint8_t **pSrcData, uint8_t **pDstData,
                     uint8_t **pKeys, uint8_t **pIV, uint32_t numBuffs, const enum api_type type)
{
        uint32_t i, j, num_vectors = 0;
        int ret = 0;
        int retTmp;
        uint32_t buf_idx[MAXBUFS];
        const struct cipher_test *vectors = zuc_eea3_256_test_json;

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

                retTmp = submit_and_verify_zuc256(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                                  IMB_DIR_ENCRYPT, 0, numBuffs, buf_idx);
                if (retTmp < 0)
                        ret = retTmp;

                retTmp = submit_and_verify_zuc256(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                                  IMB_DIR_DECRYPT, 0, numBuffs, buf_idx);
                if (retTmp < 0)
                        ret = retTmp;
        }

        /* Get all test vectors and encrypt them together */
        for (i = 0; i < numBuffs; i++)
                buf_idx[i] = i % num_vectors;

        retTmp = submit_and_verify_zuc256(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                          IMB_DIR_ENCRYPT, 1, numBuffs, buf_idx);
        if (retTmp < 0)
                ret = retTmp;

        retTmp = submit_and_verify_zuc256(mb_mgr, pSrcData, pDstData, pKeys, pIV, type,
                                          IMB_DIR_DECRYPT, 1, numBuffs, buf_idx);
        if (retTmp < 0)
                ret = retTmp;

        return ret;
}
