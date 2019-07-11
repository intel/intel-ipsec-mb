/*****************************************************************************
 Copyright (c) 2009-2019, Intel Corporation

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

#include "zuc_test_vectors.h"
#include "gcm_ctr_vectors_test.h"

#define MAXBUFS 9
#define PASS_STATUS 0
#define FAIL_STATUS -1

int zuc_test(const enum arch_type arch, struct MB_MGR *mb_mgr);

int validate_zuc_algorithm(struct MB_MGR *mb_mgr, uint8_t *pSrcData,
                           uint8_t *pDstData, uint8_t *pKeys, uint8_t *pIV);
int validate_zuc_EEA_1_block(struct MB_MGR *mb_mgr, uint8_t *pSrcData,
                             uint8_t *pDstData, uint8_t *pKeys, uint8_t *pIV);
int validate_zuc_EEA_4_block(struct MB_MGR *mb_mgr, uint8_t **pSrcData,
                             uint8_t **pDstData, uint8_t **pKeys,
                             uint8_t **pIV);
int validate_zuc_EEA_n_block(struct MB_MGR *mb_mgr, uint8_t **pSrcData,
                             uint8_t **pDstData, uint8_t **pKeys, uint8_t **pIV,
                             uint32_t numBuffs);
int validate_zuc_EIA_1_block(struct MB_MGR *mb_mgr, uint8_t *pSrcData,
                             uint8_t *pDstData, uint8_t *pKeys, uint8_t *pIV);
static void byte_hexdump(const char *message, const uint8_t *ptr, int len);

/******************************************************************************
 * @ingroup zuc_functionalTest_app
 *
 * @description
 * This function allocates memory for buffers and set random data in each buffer
 *
 * pSrcData = pointers to the new source buffers
 * numOfBuffs = number of buffers
 * ************************************************/
static uint32_t createData(uint8_t *pSrcData[MAXBUFS],
                                 uint32_t numOfBuffs)
{
        uint32_t i = 0, j = 0;

        for (i = 0; i < numOfBuffs; i++) {
                pSrcData[i] = (uint8_t *)malloc(MAX_BUFFER_LENGTH_IN_BYTES);

                if (!pSrcData[i]) {
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
static uint32_t createKeyVecData(uint32_t keyLen, uint8_t *pKeys[MAXBUFS],
                                 uint32_t ivLen, uint8_t *pIV[MAXBUFS],
                                 uint32_t numOfBuffs)
{
        uint32_t i = 0, j = 0;

        for (i = 0; i < numOfBuffs; i++) {
                pIV[i] = (uint8_t *)malloc(ivLen);

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
static void freePtrArray(uint8_t *pArr[MAXBUFS], uint32_t arrayLength)
{
        uint32_t i = 0;

        for (i = 0; i < arrayLength; i++)
                free(pArr[i]);
}

static uint32_t bswap4(const uint32_t val)
{
        return ((val >> 24) |             /**< A*/
                ((val & 0xff0000) >> 8) | /**< B*/
                ((val & 0xff00) << 8) |   /**< C*/
                (val << 24));             /**< D*/
}

int zuc_test(const enum arch_type arch, struct MB_MGR *mb_mgr)
{

        uint32_t numBuffs, a;
        uint32_t status = PASS_STATUS;
        uint8_t *pKeys[MAXBUFS];
        uint8_t *pIV[MAXBUFS];
        uint8_t *pSrcData[MAXBUFS];
        uint8_t *pDstData[MAXBUFS];

        /* Do not run the tests for aesni emulation */
        if (arch == ARCH_NO_AESNI)
                return 0;

        printf("Running Functional Tests\n");
        fflush(stdout);

        /*Create test data buffers + populate with random data*/
        if (createData(pSrcData, MAXBUFS)) {
                printf("createData() error\n");
                return FAIL_STATUS;
        }
        if (createData(pDstData, MAXBUFS)) {
                printf("createData() error\n");
                return FAIL_STATUS;
        }

        /*Create random keys and vectors*/
        if (createKeyVecData(ZUC_KEY_LEN_IN_BYTES, pKeys, ZUC_IV_LEN_IN_BYTES,
                             pIV, MAXBUFS)) {
                printf("createKeyVecData() error\n");
                freePtrArray(pSrcData, MAXBUFS);
                freePtrArray(pDstData, MAXBUFS);
                return FAIL_STATUS;
        }

        if (validate_zuc_algorithm(mb_mgr, pSrcData[0], pSrcData[0], pKeys[0],
                                   pIV[0]))
                status = 1;
        else
                printf("validate ZUC algorithm: PASS\n");

        if (validate_zuc_EEA_1_block(mb_mgr, pSrcData[0], pSrcData[0], pKeys[0],
                                     pIV[0]))
                status = 1;
        else
                printf("validate ZUC 1 block: PASS\n");

        if (validate_zuc_EEA_4_block(mb_mgr, pSrcData, pSrcData, pKeys, pIV))
                status = 1;
        else
                printf("validate ZUC 4 block: PASS\n");

        for (a = 0; a < 3; a++) {
                switch (a) {
                case 0:
                        numBuffs = 4;
                        break;
                case 1:
                        numBuffs = 8;
                        break;
                default:
                        numBuffs = 9;
                        break;
                }
                if (validate_zuc_EEA_n_block(mb_mgr, pSrcData, pDstData, pKeys,
                                             pIV, numBuffs))
                        status = 1;
                else
                        printf("validate ZUC n block buffers %d: PASS\n", a);
        }

        if (validate_zuc_EIA_1_block(mb_mgr, pSrcData[0], pDstData[0], pKeys[0],
                                     pIV[0]))
                status = 1;
        else
                printf("validate ZUC Integrity 1 block: PASS\n");

        freePtrArray(pKeys, MAXBUFS);    /*Free the key buffers*/
        freePtrArray(pIV, MAXBUFS);      /*Free the vector buffers*/
        freePtrArray(pSrcData, MAXBUFS); /*Free the source buffers*/
        freePtrArray(pDstData, MAXBUFS); /*Free the destination buffers*/
        if (status)
                return status;

        printf("The Functional Test application completed\n");
        return 0;
}

int validate_zuc_EEA_1_block(struct MB_MGR *mb_mgr, uint8_t *pSrcData,
                             uint8_t *pDstData, uint8_t *pKeys, uint8_t *pIV)
{
        uint32_t i, byteResidue;
        int retTmp, ret = 0;
        uint32_t byteLength;
        uint32_t bitResidue;

        for (i = 0; i < NUM_ZUC_EEA3_TESTS; i++) {
                memcpy(pKeys, testEEA3_vectors[i].CK, ZUC_KEY_LEN_IN_BYTES);
                zuc_eea3_iv_gen(testEEA3_vectors[i].count,
                                testEEA3_vectors[i].Bearer,
                                testEEA3_vectors[i].Direction,
                                pIV);
                byteLength = (testEEA3_vectors[i].length_in_bits + 7) / 8;
                memcpy(pSrcData, testEEA3_vectors[i].plaintext, byteLength);
                IMB_ZUC_EEA3_1_BUFFER(mb_mgr, pKeys, pIV, pSrcData, pDstData,
                                      byteLength);
                retTmp = memcmp(pDstData, testEEA3_vectors[i].ciphertext,
                                byteLength - 1);
                if (retTmp) {
                        printf("Validate ZUC 1 block  test %d (Enc): FAIL\n",
                               i + 1);
                        byte_hexdump("Expected", testEEA3_vectors[i].ciphertext,
                                     byteLength);
                        byte_hexdump("Found", pDstData, byteLength);
                        ret = retTmp;
                } else {
                        bitResidue =
                            (0xFF00 >>
                             (testEEA3_vectors[i].length_in_bits % 8)) &
                            0x00FF;
                        byteResidue =
                            (testEEA3_vectors[i].ciphertext
                                 [testEEA3_vectors[i].length_in_bits / 8] ^
                             pDstData[testEEA3_vectors[i].length_in_bits / 8]) &
                            bitResidue;
                        if (byteResidue) {
                                printf("Validate ZUC 1 block  test %d (Enc): "
                                       "FAIL\n",
                                       i + 1);
                                printf("Expected: 0x%02X (last byte)\n",
                                       0xFF &
                                           testEEA3_vectors[i]
                                               .ciphertext[testEEA3_vectors[i]
                                                               .length_in_bits /
                                                           8]);
                                printf("Found: 0x%02X (last byte)\n",
                                       0xFF & pDstData[testEEA3_vectors[i]
                                                           .length_in_bits /
                                                       8]);
                        } else
                                printf("Validate ZUC 1 block  test %d (Enc): "
                                       "PASS\n",
                                       i + 1);
                }
                fflush(stdout);
        }
        return ret;
};
int validate_zuc_EEA_4_block(struct MB_MGR *mb_mgr, uint8_t **pSrcData,
                             uint8_t **pDstData, uint8_t **pKeys, uint8_t **pIV)
{
        uint32_t i, j, packetLen[4], bitResidue, byteResidue;
        int retTmp, ret = 0;

        for (i = 0; i < NUM_ZUC_EEA3_TESTS; i++) {
                for (j = 0; j < 4; j++) {
                        packetLen[j] =
                            (testEEA3_vectors[i].length_in_bits + 7) / 8;
                        memcpy(pKeys[j], testEEA3_vectors[i].CK,
                               ZUC_KEY_LEN_IN_BYTES);
                        zuc_eea3_iv_gen(testEEA3_vectors[i].count,
                                        testEEA3_vectors[i].Bearer,
                                        testEEA3_vectors[i].Direction,
                                        pIV[j]);
                        memcpy(pSrcData[j], testEEA3_vectors[i].plaintext,
                               packetLen[j]);
                }
                IMB_ZUC_EEA3_4_BUFFER(mb_mgr, (const void * const *)pKeys,
                                      (const void * const *)pIV,
                                      (const void * const *)pSrcData,
                                      (void **)pDstData, packetLen);
                uint8_t *pDst8 = (uint8_t *)pDstData[0];

                retTmp = memcmp(pDst8, testEEA3_vectors[i].ciphertext,
                                (testEEA3_vectors[i].length_in_bits) / 8);
                if (retTmp) {
                        printf("Validate ZUC 4 block (Enc) test %d: FAIL\n",
                               i + 1);
                        byte_hexdump("Expected", testEEA3_vectors[i].ciphertext,
                                     (testEEA3_vectors[i].length_in_bits + 7) /
                                         8);
                        byte_hexdump("Found", pDst8,
                                     (testEEA3_vectors[i].length_in_bits + 7) /
                                         8);
                        ret = retTmp;
                } else {
                        bitResidue =
                            (0xFF00 >>
                             (testEEA3_vectors[i].length_in_bits % 8)) &
                            0x00FF;
                        byteResidue =
                            (testEEA3_vectors[i].ciphertext
                                 [testEEA3_vectors[i].length_in_bits / 8] ^
                             pDst8[testEEA3_vectors[i].length_in_bits / 8]) &
                            bitResidue;
                        if (byteResidue) {
                                ret = 1;
                                printf("Validate ZUC 4 block  test %d (Enc): "
                                       "FAIL\n",
                                       i + 1);
                                printf("Expected: 0x%02X (last byte)\n",
                                       0xFF &
                                           testEEA3_vectors[i]
                                               .ciphertext[testEEA3_vectors[i]
                                                               .length_in_bits /
                                                           8]);
                                printf("Found: 0x%02X (last byte)\n",
                                       0xFF & pDst8[testEEA3_vectors[i]
                                                        .length_in_bits /
                                                    8]);
                        } else
                                printf("Validate ZUC 4 block  test %d (Enc): "
                                       "PASS\n",
                                       i + 1);
                }
                fflush(stdout);
                for (j = 0; j < 4; j++) {
                        memcpy(pSrcData[j], testEEA3_vectors[i].ciphertext,
                               (testEEA3_vectors[i].length_in_bits + 7) / 8);
                }
                IMB_ZUC_EEA3_4_BUFFER(mb_mgr, (const void * const *)pKeys,
                                      (const void * const *)pIV,
                                      (const void * const *)pSrcData,
                                      (void **)pDstData, packetLen);
                pDst8 = (uint8_t *)pDstData[0];
                retTmp = memcmp(pDst8, testEEA3_vectors[i].plaintext,
                                (testEEA3_vectors[i].length_in_bits) / 8);
                if (retTmp) {
                        printf("Validate ZUC 4 block (Dec) test %d: FAIL\n",
                               i + 1);
                        byte_hexdump("Expected", testEEA3_vectors[i].plaintext,
                                     (testEEA3_vectors[i].length_in_bits + 7) /
                                         8);
                        byte_hexdump("Found", pDst8,
                                     (testEEA3_vectors[i].length_in_bits + 7) /
                                         8);
                        ret = retTmp;
                } else {
                        bitResidue =
                            (0xFF00 >>
                             (testEEA3_vectors[i].length_in_bits % 8)) &
                            0x00FF;
                        byteResidue =
                            (testEEA3_vectors[i]
                                 .plaintext[testEEA3_vectors[i].length_in_bits /
                                            8] ^
                             pDst8[testEEA3_vectors[i].length_in_bits / 8]) &
                            bitResidue;
                        if (byteResidue) {
                                ret = 1;
                                printf("Validate ZUC 4 block  test %d (Dec): "
                                       "FAIL\n",
                                       i + 1);
                                printf("Expected: 0x%02X (last byte)\n",
                                       0xFF &
                                           testEEA3_vectors[i]
                                               .plaintext[testEEA3_vectors[i]
                                                              .length_in_bits /
                                                          8]);
                                printf("Found: 0x%02X (last byte)\n",
                                       0xFF & pDst8[testEEA3_vectors[i]
                                                        .length_in_bits /
                                                    8]);
                        } else
                                printf("Validate ZUC 4 block  test %d (Dec): "
                                       "PASS\n",
                                       i + 1);
                }
                fflush(stdout);
        }
        return ret;
};

int validate_zuc_EEA_n_block(struct MB_MGR *mb_mgr, uint8_t **pSrcData,
                             uint8_t **pDstData, uint8_t **pKeys, uint8_t **pIV,
                             uint32_t numBuffs)
{
        uint32_t i, j, bitResidue, byteResidue;
        int retTmp, ret = 0;
        uint32_t packetLen[MAXBUFS];

        assert(numBuffs > 0);
        for (i = 0; i < NUM_ZUC_EEA3_TESTS; i++) {
                for (j = 0; j <= (numBuffs - 1); j++) {
                        memcpy(pKeys[j], testEEA3_vectors[i].CK,
                               ZUC_KEY_LEN_IN_BYTES);
                        zuc_eea3_iv_gen(testEEA3_vectors[i].count,
                                        testEEA3_vectors[i].Bearer,
                                        testEEA3_vectors[i].Direction,
                                        pIV[j]);
                        memcpy(pSrcData[j], testEEA3_vectors[i].plaintext,
                               (testEEA3_vectors[i].length_in_bits + 7) / 8);
                        packetLen[j] =
                            (testEEA3_vectors[i].length_in_bits + 7) / 8;
                }
                IMB_ZUC_EEA3_N_BUFFER(mb_mgr, (const void * const *)pKeys,
                                      (const void * const *)pIV,
                                      (const void * const *)pSrcData,
                                      (void **)pDstData, packetLen, numBuffs);
                uint8_t *pDst8 = (uint8_t *)pDstData[0];

                retTmp = memcmp(pDstData[0], testEEA3_vectors[i].ciphertext,
                                (testEEA3_vectors[i].length_in_bits) / 8);
                if (retTmp) {
                        printf("Validate ZUC n block (Enc) test %d, buffers: "
                               "%d: FAIL\n",
                               i + 1, numBuffs);
                        byte_hexdump("Expected", testEEA3_vectors[i].ciphertext,
                                     (testEEA3_vectors[i].length_in_bits + 7) /
                                         8);
                        byte_hexdump("Found", pDst8,
                                     (testEEA3_vectors[i].length_in_bits + 7) /
                                         8);
                        ret = retTmp;
                } else {
                        bitResidue =
                            (0xFF00 >>
                             (testEEA3_vectors[i].length_in_bits % 8)) &
                            0x00FF;
                        byteResidue =
                            (testEEA3_vectors[i].ciphertext
                                 [testEEA3_vectors[i].length_in_bits / 8] ^
                             pDst8[testEEA3_vectors[i].length_in_bits / 8]) &
                            bitResidue;
                        if (byteResidue) {
                                ret = 1;
                                printf("Validate ZUC n block (Enc)  test %d, "
                                       "buffers %d: FAIL\n",
                                       i + 1, numBuffs);
                                printf("Expected: 0x%02X (last byte)\n",
                                       0xFF &
                                           testEEA3_vectors[i]
                                               .ciphertext[testEEA3_vectors[i]
                                                               .length_in_bits /
                                                           8]);
                                printf("Found: 0x%02X (last byte)\n",
                                       0xFF & pDst8[testEEA3_vectors[i]
                                                        .length_in_bits /
                                                    8]);
                        } else
                                printf("Validate ZUC n block (Enc)  test %d, "
                                       "buffers %d: PASS\n",
                                       i + 1, numBuffs);
                }
                fflush(stdout);
                for (j = 0; j <= (numBuffs - 1); j++) {
                        memcpy(pSrcData[j], testEEA3_vectors[i].ciphertext,
                               (testEEA3_vectors[i].length_in_bits + 7) / 8);
                }
                IMB_ZUC_EEA3_N_BUFFER(mb_mgr, (const void * const *)pKeys,
                                      (const void * const *)pIV,
                                      (const void * const *)pSrcData,
                                      (void **)pDstData, packetLen, numBuffs);
                retTmp = memcmp(pDstData[0], testEEA3_vectors[i].plaintext,
                                (testEEA3_vectors[i].length_in_bits) / 8);
                if (retTmp) {
                        printf("Validate ZUC n block (Dec) test %d, buffers "
                               "%d: FAIL\n",
                               i + 1, numBuffs);
                        byte_hexdump("Expected", testEEA3_vectors[i].plaintext,
                                     (testEEA3_vectors[i].length_in_bits + 7) /
                                         8);
                        byte_hexdump("Found", pDstData[0],
                                     (testEEA3_vectors[i].length_in_bits + 7) /
                                         8);
                        ret = retTmp;
                } else {
                        bitResidue =
                            (0xFF00 >>
                             (testEEA3_vectors[i].length_in_bits % 8)) &
                            0x00FF;
                        byteResidue =
                            (testEEA3_vectors[i]
                                 .plaintext[testEEA3_vectors[i].length_in_bits /
                                            8] ^
                             pDst8[testEEA3_vectors[i].length_in_bits / 8]) &
                            bitResidue;
                        if (byteResidue) {
                                ret = 1;
                                printf("Validate ZUC n block (Dec) test %d, "
                                       "buffers %d : FAIL\n",
                                       i + 1, numBuffs);
                                printf("Expected: 0x%02X (last byte)\n",
                                       0xFF &
                                           testEEA3_vectors[i]
                                               .plaintext[testEEA3_vectors[i]
                                                              .length_in_bits /
                                                          8]);
                                printf("Found: 0x%02X (last byte)\n",
                                       0xFF & pDst8[testEEA3_vectors[i]
                                                        .length_in_bits /
                                                    8]);
                        } else
                                printf("Validate ZUC n block (Dec) test %d, "
                                       "buffers %d: PASS\n",
                                       i + 1, numBuffs);
                }
                fflush(stdout);
        }
        return ret;
};

int validate_zuc_EIA_1_block(struct MB_MGR *mb_mgr, uint8_t *pSrcData,
                             uint8_t *pDstData, uint8_t *pKeys, uint8_t *pIV)
{
        uint32_t i;
        int retTmp, ret = 0;
        uint32_t byteLength;

        for (i = 0; i < NUM_ZUC_EIA3_TESTS; i++) {
                memcpy(pKeys, testEIA3_vectors[i].CK, ZUC_KEY_LEN_IN_BYTES);

                zuc_eia3_iv_gen(testEIA3_vectors[i].count,
                                testEIA3_vectors[i].Bearer,
                                testEIA3_vectors[i].Direction,
                                pIV);
                byteLength = (testEIA3_vectors[i].length_in_bits + 7) / 8;
                memcpy(pSrcData, testEIA3_vectors[i].message, byteLength);
                IMB_ZUC_EIA3_1_BUFFER(mb_mgr, pKeys, pIV, pSrcData,
                                      testEIA3_vectors[i].length_in_bits,
                                      (uint32_t *)pDstData);
                retTmp =
                    memcmp(pDstData, &testEIA3_vectors[i].mac,
                           sizeof(((struct test128EIA3_vectors_t *)0)->mac));
                if (retTmp) {
                        printf("Validate ZUC 1 block  test %d (Int): FAIL\n",
                               i + 1);
                        byte_hexdump("Expected",
                                     (const uint8_t *)&testEIA3_vectors[i].mac,
                                     ZUC_DIGEST_LEN);
                        byte_hexdump("Found", pDstData, ZUC_DIGEST_LEN);
                        ret = retTmp;
                } else
                        printf("Validate ZUC 1 block  test %d (Int): PASS\n",
                               i + 1);
                fflush(stdout);
        }
        return ret;
};

int validate_zuc_algorithm(struct MB_MGR *mb_mgr, uint8_t *pSrcData,
                           uint8_t *pDstData, uint8_t *pKeys, uint8_t *pIV)
{
        uint32_t i;
        int ret = 0;
        union SwapBytes {
                uint8_t sbb[8];
                uint32_t sbw[2];
        } swapBytes;

        for (i = 0; i < NUM_ZUC_ALG_TESTS; i++) {
                memcpy(pKeys, testZUC_vectors[i].CK, ZUC_KEY_LEN_IN_BYTES);
                memcpy(pIV, testZUC_vectors[i].IV, ZUC_IV_LEN_IN_BYTES);
                memset(pSrcData, 0, 8);
                IMB_ZUC_EEA3_1_BUFFER(mb_mgr, pKeys, pIV, pSrcData, pDstData,
                                      8);
                swapBytes.sbw[0] = bswap4(testZUC_vectors[i].Z[0]);
                swapBytes.sbw[1] = bswap4(testZUC_vectors[i].Z[1]);
                ret = memcmp(pDstData, swapBytes.sbb, 8);
                if (ret)
                        printf("ZUC 1 algorithm test %d: FAIL\n", i);
                else
                        printf("ZUC 1 algorithm test %d: PASS\n", i);
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
static void byte_hexdump(const char *message, const uint8_t *ptr, int len)
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
