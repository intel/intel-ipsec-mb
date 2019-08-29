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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "intel-ipsec-mb.h"

#include "gcm_ctr_vectors_test.h"
#include "utils.h"

#include "snow3g_test_vectors.h"

#define SNOW3GIVLEN 8
cipher_test_vector_t *vecList[MAX_DATA_LEN];

int snow3g_test(const enum arch_type arch, struct MB_MGR *mb_mgr);
int validate_snow3g_f8_1_block(struct MB_MGR *mb_mgr);
int validate_snow3g_f8_2_block(struct MB_MGR *mb_mgr);
int validate_snow3g_f8_4_blocks(struct MB_MGR *mb_mgr);
int validate_snow3g_f8_n_blocks(struct MB_MGR *mb_mgr);
int validate_snow3g_f9(struct MB_MGR *mb_mgr);
int membitcmp(const uint8_t *input, const uint8_t *output,
              const uint32_t bitlength, const uint32_t offset);

/******************************************************************************
 * @description - utility function to dump test buffers
 *
 * @param message [IN] - debug message to print
 * @param ptr [IN] - pointer to beginning of buffer.
 * @param len [IN] - length of buffer.
 ******************************************************************************/
static inline void snow3g_hexdump(const char *message, uint8_t *ptr, int len)
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
}

int validate_snow3g_f8_1_block(struct MB_MGR *mb_mgr)
{
        int numVectors, i, length;
        size_t size = 0;
        cipher_test_vector_t *testVectors = snow3g_cipher_test_vectors[1];
        /* snow3g f8 test vectors are located at index 1 */
        numVectors = numSnow3gCipherTestVectors[1];

        snow3g_key_schedule_t *pKeySched = NULL;
        uint8_t *pKey = NULL;
        int keyLen = MAX_KEY_LEN;
        uint8_t srcBuff[MAX_DATA_LEN];
        uint8_t dstBuff[MAX_DATA_LEN];
        uint8_t *pIV;
        int ret = 1;

        printf("Testing IMB_SNOW3G_F8_1_BUFFER:\n");

        memset(srcBuff, 0, sizeof(srcBuff));
        memset(dstBuff, 0, sizeof(dstBuff));

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return ret;
        }

        pIV = malloc(SNOW3G_IV_LEN_IN_BYTES);
        if (!pIV) {
                printf("malloc(pIV):failed !\n");
                return ret;
        }

        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(pKey):failed !\n");
                free(pIV);
                return ret;
        }
        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size) {
                free(pIV);
                free(pKey);
                return ret;
        }

        pKeySched = malloc(size);
        if (!pKeySched) {
                printf("malloc(IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr)): failed ! "
                       "\n");
                free(pIV);
                free(pKey);
                return ret;
        }

        /*Copy the data for for Snow3g 1 Packet version*/
        for (i = 0; i < numVectors; i++) {

                length = testVectors[i].dataLenInBytes;

                memcpy(pKey, testVectors[i].key, testVectors[i].keyLenInBytes);
                memcpy(srcBuff, testVectors[i].plaintext, length);

                memcpy(dstBuff, testVectors[i].ciphertext, length);
                memcpy(pIV, testVectors[i].iv, testVectors[i].ivLenInBytes);

                /*setup the keysched to be used*/
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched) == -1) {
                        printf("CPU check failed\n");
                        goto snow3g_f8_1_buffer_exit;
                }

                /*Validate encrypt*/
                IMB_SNOW3G_F8_1_BUFFER(mb_mgr, pKeySched, pIV, srcBuff, srcBuff,
                                       length);

                /*check against the ciphertext in the vector against the
                 * encrypted plaintext*/
                if (memcmp(srcBuff, dstBuff, length) != 0) {
                        printf("IMB_SNOW3G_F8_1_BUFFER(Enc) vector:%d\n", i);
                        snow3g_hexdump("Actual:", srcBuff, length);
                        snow3g_hexdump("Expected:", dstBuff, length);
                        goto snow3g_f8_1_buffer_exit;
                }
                printf(".");

                memcpy(dstBuff, testVectors[i].plaintext, length);

                /*Validate Decrypt*/
                IMB_SNOW3G_F8_1_BUFFER(mb_mgr, pKeySched, pIV, srcBuff, srcBuff,
                                       length);

                if (memcmp(srcBuff, dstBuff, length) != 0) {
                        printf("IMB_SNOW3G_F8_1_BUFFER(Dec) vector:%d\n", i);
                        snow3g_hexdump("Actual:", srcBuff, length);
                        snow3g_hexdump("Expected:", dstBuff, length);
                        goto snow3g_f8_1_buffer_exit;
                }
                printf(".");
        } /* for numVectors */

        /* no errors detected */
        ret = 0;

snow3g_f8_1_buffer_exit:
        free(pIV);
        free(pKey);
        free(pKeySched);

        printf("\n");

        return ret;
}

/* Shift right a buffer by "offset" bits, "offset" < 8 */
static void buffer_shift_right(uint8_t *buffer, uint32_t length, uint8_t offset)
{
        uint8_t curr_byte, prev_byte;
        uint32_t length_in_bytes = (length * 8 + offset + 7) / 8;
        uint8_t lower_byte_mask = (1 << offset) - 1;
        unsigned i;

        prev_byte = buffer[0];
        buffer[0] >>= offset;

        for (i = 1; i < length_in_bytes; i++) {
                curr_byte = buffer[i];
                buffer[i] = ((prev_byte & lower_byte_mask) << (8 - offset)) |
                            (curr_byte >> offset);
                prev_byte = curr_byte;
        }
}

static int validate_snow3g_f8_1_bitblock(struct MB_MGR *mb_mgr)
{
        int numVectors, i, length;
        size_t size = 0;
        cipherbit_test_linear_vector_t *testVectors =
                &snow3g_f8_linear_bitvectors /*snow3g_cipher_test_vectors[1]*/;
        cipher_test_vector_t *testStandardVectors =
                snow3g_f8_vectors;  /* scipher_test_vectors[1]; */
        /* snow3g f8 test vectors are located at index 1 */
        numVectors = MAX_BIT_BUFFERS;  /* numSnow3gCipherTestVectors[3]; */

        snow3g_key_schedule_t *pKeySched = NULL;
        uint8_t *pKey = NULL;
        int keyLen = MAX_KEY_LEN;
        uint8_t srcBuff[MAX_DATA_LEN];
        uint8_t midBuff[MAX_DATA_LEN];
        uint8_t dstBuff[MAX_DATA_LEN];
        uint8_t *pIV;
        uint32_t bufferbytesize = 0;
        uint32_t offset = 0;
        uint32_t byteoffset = 0;
        int ret = 1;

        printf("Testing IMB_SNOW3G_F8_1_BUFFER_BIT:\n");

        memset(srcBuff, 0, sizeof(srcBuff));
        memset(midBuff, 0, sizeof(midBuff));
        memset(dstBuff, 0, sizeof(dstBuff));

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return ret;
        }
        for (i = 0; i < numVectors; i++)
                bufferbytesize += testVectors->dataLenInBits[i];

        bufferbytesize = (bufferbytesize + 7) / 8;
        pIV = malloc(SNOW3G_IV_LEN_IN_BYTES);
        if (!pIV) {
                printf("malloc(pIV):failed !\n");
                return ret;
        }

        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(pKey):failed !\n");
                free(pIV);
                return ret;
        }
        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size) {
                free(pIV);
                free(pKey);
                return ret;
        }

        pKeySched = malloc(size);
        if (!pKeySched) {
                printf("malloc(IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr)): failed ! "
                       "\n");
                free(pIV);
                free(pKey);
                return ret;
        }

        memcpy(srcBuff, testVectors->plaintext, bufferbytesize);
        memcpy(dstBuff, testVectors->ciphertext, bufferbytesize);

        /*Copy the data for for Snow3g 1 Packet version*/
        for (i = 0, offset = 0, byteoffset = 0; i < numVectors; i++) {

                memcpy(pKey, testVectors->key[i], testVectors->keyLenInBytes);
                memcpy(pIV, testVectors->iv[i], testVectors->ivLenInBytes);

                /*setup the keysched to be used*/
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched) == -1) {
                        printf("CPU check failed\n");
                        goto snow3g_f8_1_buffer_bit_exit;
                }

                /*Validate Encrypt*/
                IMB_SNOW3G_F8_1_BUFFER_BIT(
                        mb_mgr, pKeySched, pIV, srcBuff, midBuff,
                        testVectors->dataLenInBits[i], offset);

                /*check against the ciphertext in the vector against the
                 * encrypted plaintext*/
                if (membitcmp(midBuff, dstBuff, testVectors->dataLenInBits[i],
                              offset) != 0) {
                        printf("Test1: snow3g_f8_1_bitbuffer(Enc) buffer:%d "
                               "size:%d offset:%d\n",
                               i, testVectors->dataLenInBits[i], offset);
                        snow3g_hexdump("Actual:", &midBuff[byteoffset],
                                       (testVectors->dataLenInBits[i] + 7) / 8);
                        snow3g_hexdump("Expected:", &dstBuff[byteoffset],
                                       (testVectors->dataLenInBits[i] + 7) / 8);
                        goto snow3g_f8_1_buffer_bit_exit;
                }
                printf(".");

                /*Validate Decrypt*/
                IMB_SNOW3G_F8_1_BUFFER_BIT(mb_mgr, pKeySched, pIV, dstBuff,
                                           midBuff,
                                           testVectors->dataLenInBits[i],
                                           offset);

                if (membitcmp(midBuff /*dstBuff*/, srcBuff,
                              testVectors->dataLenInBits[i], offset) != 0) {
                        printf("Test2: snow3g_f8_1_bitbuffer(Dec) buffer:%d "
                               "size:%d offset:%d\n",
                               i, testVectors->dataLenInBits[i], offset);
                        snow3g_hexdump(
                                "Actual:", &/*dstBuff*/ midBuff[byteoffset],
                                (testVectors->dataLenInBits[i] + offset % 8 +
                                 7) / 8);
                        snow3g_hexdump("Expected:", &srcBuff[byteoffset],
                                       (testVectors->dataLenInBits[i] +
                                        offset % 8 + 7) / 8);
                        goto snow3g_f8_1_buffer_bit_exit;
                }
                printf(".");

                /* Another test with Standard 3GPP table */
                length = testStandardVectors[i].dataLenInBytes;
                memcpy(srcBuff, testStandardVectors[i].plaintext, length);

                memcpy(dstBuff, testStandardVectors[i].ciphertext, length);

                /*Validate Encrypt*/
                IMB_SNOW3G_F8_1_BUFFER_BIT(
                        mb_mgr, pKeySched, pIV, srcBuff, midBuff,
                        testStandardVectors[i].dataLenInBytes * 8, 0);

                /*check against the ciphertext in the vector against the
                 * encrypted plaintext*/
                if (membitcmp(midBuff, dstBuff,
                              testStandardVectors[i].dataLenInBytes * 8,
                              0) != 0) {
                        printf("Test3: snow3g_f8_1_bitbuffer(Enc) buffer:%d "
                               "size:%d offset:0\n",
                               i, testStandardVectors[i].dataLenInBytes * 8);
                        snow3g_hexdump("Actual:", &midBuff[0],
                                       testStandardVectors[i].dataLenInBytes);
                        snow3g_hexdump("Expected:", &dstBuff[0],
                                       testStandardVectors[i].dataLenInBytes);
                        goto snow3g_f8_1_buffer_bit_exit;
                }
                printf(".");

                /*Validate Decrypt*/
                IMB_SNOW3G_F8_1_BUFFER_BIT(
                        mb_mgr, pKeySched, pIV, midBuff, dstBuff,
                        testStandardVectors[i].dataLenInBytes * 8, 0);

                if (membitcmp(dstBuff, srcBuff,
                              testStandardVectors[i].dataLenInBytes * 8,
                              0) != 0) {
                        printf("Test4: snow3g_f8_1_bitbuffer(Dec) buffer:%d "
                               "size:%d offset:0\n",
                               i, testStandardVectors[i].dataLenInBytes * 8);
                        snow3g_hexdump("Actual:", &dstBuff[0],
                                       testStandardVectors[i].dataLenInBytes);
                        snow3g_hexdump("Expected:", &srcBuff[0],
                                       testStandardVectors[i].dataLenInBytes);
                        goto snow3g_f8_1_buffer_bit_exit;
                }
                printf(".");

                memcpy(srcBuff, testStandardVectors[i].plaintext, length);

                memcpy(dstBuff, testStandardVectors[i].ciphertext, length);

                buffer_shift_right(srcBuff,
                                   testStandardVectors[i].dataLenInBytes, 4);
                buffer_shift_right(dstBuff,
                                   testStandardVectors[i].dataLenInBytes, 4);

                /*Validate Encrypt*/
                IMB_SNOW3G_F8_1_BUFFER_BIT(
                        mb_mgr, pKeySched, pIV, srcBuff, midBuff,
                        testStandardVectors[i].dataLenInBytes * 8, 4);

                /*check against the ciphertext in the vector against the
                 * encrypted plaintext*/
                if (membitcmp(midBuff, dstBuff,
                              testStandardVectors[i].dataLenInBytes * 8,
                              4) != 0) {
                        printf("Test5:snow3g_f8_1_bitbuffer(Enc) buffer:%d "
                               "size:%d offset:4\n",
                               i, testStandardVectors[i].dataLenInBytes * 8);
                        snow3g_hexdump("Actual:", &midBuff[0],
                                       (testStandardVectors[i].dataLenInBytes *
                                        8 + 4 + 7) / 8);
                        snow3g_hexdump("Expected:", &dstBuff[0],
                                       (testStandardVectors[i].dataLenInBytes *
                                        8 + 4 + 7) / 8);
                        goto snow3g_f8_1_buffer_bit_exit;
                }
                printf(".");

                /*Validate Decrypt*/
                IMB_SNOW3G_F8_1_BUFFER_BIT(
                        mb_mgr, pKeySched, pIV, /*midBuff*/ dstBuff,
                        /*dstBuff*/ midBuff,
                        testStandardVectors[i].dataLenInBytes * 8, 4);

                if (membitcmp(midBuff /*dstBuff*/, srcBuff,
                              testStandardVectors[i].dataLenInBytes * 8,
                              4) != 0) {
                        printf("Test6: snow3g_f8_1_bitbuffer(Dec) buffer:%d "
                               "size:%d offset:4\n",
                               i, testStandardVectors[i].dataLenInBytes * 8);
                        snow3g_hexdump("Actual:", &dstBuff[0],
                                       (testStandardVectors[i].dataLenInBytes *
                                        8 + 4 + 7) / 8);
                        snow3g_hexdump("Expected:", &srcBuff[0],
                                (testStandardVectors[i].dataLenInBytes *
                                 8 + 4 + 7) / 8);
                        goto snow3g_f8_1_buffer_bit_exit;
                }
                printf(".");

                memcpy(srcBuff, testVectors->plaintext, bufferbytesize);
                memcpy(dstBuff, testVectors->ciphertext, bufferbytesize);
                memcpy(midBuff, testVectors->ciphertext, bufferbytesize);

                offset += testVectors->dataLenInBits[i];
                byteoffset = offset / 8;
        }  /* for numVectors */

        /* no errors detected */
        ret = 0;

snow3g_f8_1_buffer_bit_exit:
        free(pIV);
        free(pKey);
        free(pKeySched);

        printf("\n");

        return ret;
}

static int validate_snow3g_f8_2_blocks(struct MB_MGR *mb_mgr)
{
        int length, numVectors, i = 0, j = 0, numPackets = 2;
        size_t size = 0;
        cipher_test_vector_t *testVectors = snow3g_cipher_test_vectors[1];
        /* snow3g f8 test vectors are located at index 1 */
        numVectors = numSnow3gCipherTestVectors[1];

        snow3g_key_schedule_t *pKeySched = NULL;
        uint8_t *pKey =  NULL;
        int keyLen = MAX_KEY_LEN;
        uint8_t *srcBuff[MAX_DATA_LEN];
        uint8_t *dstBuff[MAX_DATA_LEN];
        uint8_t *IV[SNOW3G_IV_LEN_IN_BYTES];
        uint32_t packetLen[MAX_DATA_LEN];
        int ret = 1;

        printf("Testing IMB_SNOW3G_F8_2_BUFFER:\n");

        memset(srcBuff, 0, sizeof(srcBuff));
        memset(dstBuff, 0, sizeof(dstBuff));
        memset(IV, 0, sizeof(IV));

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return ret;
        }

        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(key):failed !\n");
                return ret;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size) {
                free(pKey);
                return ret;
        }

        pKeySched = malloc(size);
        if (!pKeySched) {
                printf("malloc(IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr)): failed ! "
                       "\n");
                free(pKey);
                return ret;
        }

        /* Test with all vectors */
        for (j = 0; j < numVectors; j++) {
                int k;

                length = testVectors[j].dataLenInBytes;

                /*	Create test Data for num Packets*/
                for (i = 0; i < numPackets; i++) {

                        packetLen[i] = length;
                        srcBuff[i] = malloc(length);
                        if (!srcBuff[i]) {
                                printf("malloc(srcBuff[%d]):failed !\n", i);
                                goto snow3g_f8_2_buffer_exit;
                        }
                        dstBuff[i] = malloc(length);
                        if (!dstBuff[i]) {
                                printf("malloc(dstBuff[%d]):failed !\n", i);
                                goto snow3g_f8_2_buffer_exit;
                        }
                        IV[i] = malloc(SNOW3G_IV_LEN_IN_BYTES);
                        if (!IV[i]) {
                                printf("malloc(IV[%d]):failed !\n", i);
                                goto snow3g_f8_2_buffer_exit;
                        }

                        memcpy(pKey, testVectors[j].key,
                               testVectors[j].keyLenInBytes);

                        memcpy(srcBuff[i], testVectors[j].plaintext, length);

                        memset(dstBuff[i], 0, length);

                        memcpy(IV[i], testVectors[j].iv,
                               testVectors[j].ivLenInBytes);
                }

                /*only 1 key is needed for snow3g 2 blocks*/
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched)) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                        goto snow3g_f8_2_buffer_exit;
                }

                /* TEST IN-PLACE ENCRYPTION/DECRYPTION */
                /*Test the encrypt*/
                IMB_SNOW3G_F8_2_BUFFER(mb_mgr, pKeySched, IV[0], IV[1],
                                       srcBuff[0], srcBuff[0], packetLen[0],
                                       srcBuff[1], srcBuff[1], packetLen[1]);

                /*compare the ciphertext with the encryped plaintext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(srcBuff[i], testVectors[j].ciphertext,
                                   packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_2_BUFFER(Enc) vector:%d "
                                       "buffer:%d\n", j, i);
                                snow3g_hexdump("Actual:", srcBuff[i],
                                               packetLen[0]);
                                snow3g_hexdump("Expected:",
                                               testVectors[j].ciphertext,
                                               packetLen[0]);
                                goto snow3g_f8_2_buffer_exit;
                        }
                        printf(".");
                }

                /* Set the source buffer with ciphertext, and clear destination
                 * buffer */
                for (i = 0; i < numPackets; i++)
                        memcpy(srcBuff[i], testVectors[j].ciphertext, length);

                /*Test the decrypt*/
                IMB_SNOW3G_F8_2_BUFFER(mb_mgr, pKeySched, IV[0], IV[1],
                                       srcBuff[0], srcBuff[0], packetLen[0],
                                       srcBuff[1], srcBuff[1], packetLen[1]);

                /*Compare the plaintext with the decrypted ciphertext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(srcBuff[i], testVectors[j].plaintext,
                                   packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_2_BUFFER(Dec) vector:%d "
                                       "buffer:%d\n", j, i);
                                snow3g_hexdump("Actual:", srcBuff[i],
                                               packetLen[0]);
                                snow3g_hexdump("Expected:",
                                               testVectors[j].plaintext,
                                               packetLen[i]);
                                goto snow3g_f8_2_buffer_exit;
                        }
                        printf(".");
                }

                /* TEST OUT-OF-PLACE ENCRYPTION/DECRYPTION */
                /*Test the encrypt*/
                IMB_SNOW3G_F8_2_BUFFER(mb_mgr, pKeySched, IV[0], IV[1],
                                       srcBuff[0], dstBuff[0], packetLen[0],
                                       srcBuff[1], dstBuff[1], packetLen[1]);

                /*compare the ciphertext with the encryped plaintext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(dstBuff[i], testVectors[j].ciphertext,
                                   packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_2_BUFFER(Enc) vector:%d "
                                       "buffer:%d\n",
                                       j, i);
                                snow3g_hexdump("Actual:", dstBuff[i],
                                               packetLen[0]);
                                snow3g_hexdump("Expected:",
                                               testVectors[j].ciphertext,
                                               packetLen[0]);
                                goto snow3g_f8_2_buffer_exit;
                        }
                        printf(".");
                }
                /* Set the source buffer with ciphertext, and clear destination
                 * buffer */
                for (i = 0; i < numPackets; i++) {
                        memcpy(srcBuff[i], testVectors[j].ciphertext, length);
                        memset(dstBuff[i], 0, length);
                }

                /*Test the decrypt*/
                IMB_SNOW3G_F8_2_BUFFER(mb_mgr, pKeySched, IV[0], IV[1],
                                       srcBuff[0], dstBuff[0], packetLen[0],
                                       srcBuff[1], dstBuff[1], packetLen[1]);

                /*Compare the plaintext with the decrypted ciphertext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(dstBuff[i], testVectors[j].plaintext,
                                   packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_2_BUFFER(Dec) vector:%d "
                                       "buffer:%d\n", j, i);
                                snow3g_hexdump("Actual:", dstBuff[i],
                                               packetLen[0]);
                                snow3g_hexdump("Expected:",
                                               testVectors[j].plaintext,
                                               packetLen[i]);
                                goto snow3g_f8_2_buffer_exit;
                        }
                        printf(".");
                }
                /* free buffers before next iteration */
                for (k = 0; k < numPackets; k++) {
                        if (srcBuff[k] != NULL) {
                                free(srcBuff[k]);
                                srcBuff[k] = NULL;
                        }
                        if (dstBuff[k] != NULL) {
                                free(dstBuff[k]);
                                dstBuff[k] = NULL;
                        }
                        if (IV[k] != NULL) {
                                free(IV[k]);
                                IV[k] = NULL;
                        }
                }
        }

        /* no errors detected */
        ret = 0;

snow3g_f8_2_buffer_exit:
        if (pKey != NULL)
                free(pKey);
        if (pKeySched != NULL)
                free(pKeySched);

        for (i = 0; i < numPackets; i++) {
                if (srcBuff[i] != NULL)
                        free(srcBuff[i]);
                if (dstBuff[i] != NULL)
                        free(dstBuff[i]);
                if (IV[i] != NULL)
                        free(IV[i]);
        }
        printf("\n");

        return ret;
}

int validate_snow3g_f8_4_blocks(struct MB_MGR *mb_mgr)
{
        int length, numVectors, i = 0, j = 0, numPackets = 4;
        size_t size = 0;
        cipher_test_vector_t *testVectors = snow3g_cipher_test_vectors[1];
        /* snow3g f8 test vectors are located at index 1 */
        numVectors = numSnow3gCipherTestVectors[1];

        snow3g_key_schedule_t *pKeySched = NULL;
        uint8_t *pKey = NULL;
        int keyLen = MAX_KEY_LEN;
        uint8_t *srcBuff[MAX_DATA_LEN];
        uint8_t *dstBuff[MAX_DATA_LEN];
        uint8_t *IV[SNOW3G_IV_LEN_IN_BYTES];
        uint32_t packetLen[MAX_DATA_LEN];
        int ret = 1;

        printf("Testing IMB_SNOW3G_F8_4_BUFFER:\n");

        memset(srcBuff, 0, sizeof(srcBuff));
        memset(dstBuff, 0, sizeof(dstBuff));
        memset(IV, 0, sizeof(IV));

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return ret;
        }

        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(key):failed !\n");
                return ret;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size) {
                free(pKey);
                return ret;
        }

        pKeySched = malloc(size);
        if (!pKeySched) {
                printf("malloc(IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr)): failed ! "
                       "\n");
                free(pKey);
                return ret;
        }

        /* Test with all vectors */
        for (j = 0; j < numVectors; j++) {
                /*vectors are in bits used to round up to bytes*/
                length = testVectors[j].dataLenInBytes;

                /* Create test Data for num Packets */
                for (i = 0; i < numPackets; i++) {

                        packetLen[i] = length;
                        srcBuff[i] = malloc(length);
                        if (!srcBuff[i]) {
                                printf("malloc(srcBuff[%d]):failed !\n", i);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        dstBuff[i] = malloc(length);
                        if (!dstBuff[i]) {
                                printf("malloc(dstBuff[%d]):failed !\n", i);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        IV[i] = malloc(SNOW3G_IV_LEN_IN_BYTES);
                        if (!IV[i]) {
                                printf("malloc(IV[%d]):failed !\n", i);
                                goto snow3g_f8_4_buffer_exit;
                        }

                        memcpy(pKey, testVectors[j].key,
                               testVectors[j].keyLenInBytes);

                        memcpy(srcBuff[i], testVectors[j].plaintext, length);

                        memset(dstBuff[i], 0, length);

                        memcpy(IV[i], testVectors[j].iv,
                               testVectors[j].ivLenInBytes);
                }

                /*only 1 key is needed for snow3g 4 blocks*/
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched)) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                        goto snow3g_f8_4_buffer_exit;
                }

                /* TEST IN-PLACE ENCRYPTION/DECRYPTION */
                /*Test the encrypt*/
                IMB_SNOW3G_F8_4_BUFFER(
                        mb_mgr, pKeySched, IV[0], IV[1], IV[2], IV[3],
                        srcBuff[0], srcBuff[0], packetLen[0], srcBuff[1],
                        srcBuff[1], packetLen[1], srcBuff[2], srcBuff[2],
                        packetLen[2], srcBuff[3], srcBuff[3], packetLen[3]);

                /*compare the ciphertext with the encryped plaintext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(srcBuff[i], testVectors[j].ciphertext,
                                   packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_4_BUFFER(Enc) vector:%d "
                                       "buffer:%d\n", j, i);
                                snow3g_hexdump("Actual:", srcBuff[i],
                                               packetLen[i]);
                                snow3g_hexdump("Expected:",
                                               testVectors[j].ciphertext,
                                               packetLen[i]);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        printf(".");
                }

                /* Set the source buffer with ciphertext, and clear destination
                 * buffer */
                for (i = 0; i < numPackets; i++)
                        memcpy(srcBuff[i], testVectors[j].ciphertext, length);

                /*Test the decrypt*/
                IMB_SNOW3G_F8_4_BUFFER(
                        mb_mgr, pKeySched, IV[0], IV[1], IV[2], IV[3],
                        srcBuff[0], srcBuff[0], packetLen[0], srcBuff[1],
                        srcBuff[1], packetLen[1], srcBuff[2], srcBuff[2],
                        packetLen[2], srcBuff[3], srcBuff[3], packetLen[3]);

                /*Compare the plaintext with the decrypted ciphertext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(srcBuff[i], testVectors[j].plaintext,
                                   packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_4_BUFFER(Dec) vector:%d "
                                       "buffer:%d\n", j, i);
                                snow3g_hexdump("Actual:", srcBuff[i],
                                               packetLen[i]);
                                snow3g_hexdump("Expected:",
                                               testVectors[j].plaintext,
                                               packetLen[i]);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        printf(".");
                }
                /* TEST OUT-OF-PLACE ENCRYPTION/DECRYPTION */
                /*Test the encrypt*/
                IMB_SNOW3G_F8_4_BUFFER(
                        mb_mgr, pKeySched, IV[0], IV[1], IV[2], IV[3],
                        srcBuff[0], dstBuff[0], packetLen[0], srcBuff[1],
                        dstBuff[1], packetLen[1], srcBuff[2], dstBuff[2],
                        packetLen[2], srcBuff[3], dstBuff[3], packetLen[3]);

                /*compare the ciphertext with the encryped plaintext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(dstBuff[i], testVectors[j].ciphertext,
                                   packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_4_BUFFER(Enc) vector:%d "
                                       "buffer:%d\n", j, i);
                                snow3g_hexdump("Actual:", dstBuff[i],
                                               packetLen[i]);
                                snow3g_hexdump("Expected:",
                                               testVectors[j].ciphertext,
                                               packetLen[i]);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        printf(".");
                }

                /* Set the source buffer with ciphertext, and clear destination
                 * buffer */
                for (i = 0; i < numPackets; i++) {
                        memcpy(srcBuff[i], testVectors[j].ciphertext, length);
                        memset(dstBuff[i], 0, length);
                }
                /*Test the decrypt*/
                IMB_SNOW3G_F8_4_BUFFER(
                        mb_mgr, pKeySched, IV[0], IV[1], IV[2], IV[3],
                        srcBuff[0], dstBuff[0], packetLen[0], srcBuff[1],
                        dstBuff[1], packetLen[1], srcBuff[2], dstBuff[2],
                        packetLen[2], srcBuff[3], dstBuff[3], packetLen[3]);

                /*Compare the plaintext with the decrypted ciphertext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(dstBuff[i], testVectors[j].plaintext,
                                   packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_4_BUFFER(Dec) vector:%d "
                                       "buffer:%d\n", j, i);
                                snow3g_hexdump("Actual:", dstBuff[i],
                                               packetLen[i]);
                                snow3g_hexdump("Expected:",
                                               testVectors[j].plaintext,
                                               packetLen[i]);
                                goto snow3g_f8_4_buffer_exit;
                        }
                        printf(".");
                }
                /* free buffers before next iteration */
                for (i = 0; i < numPackets; i++) {
                        if (srcBuff[i] != NULL) {
                                free(srcBuff[i]);
                                srcBuff[i] = NULL;
                        }
                        if (dstBuff[i] != NULL) {
                                free(dstBuff[i]);
                                dstBuff[i] = NULL;
                        }
                        if (IV[i] != NULL) {
                                free(IV[i]);
                                IV[i] = NULL;
                        }
                }
        }

        /*vectors are in bits used to round up to bytes*/
        length = testVectors[1].dataLenInBytes;

        /*Create test Data for num Packets*/
        for (i = 0; i < numPackets; i++) {
                /* Test for packets of different length. */
                packetLen[i] = length - (i * 12);
                srcBuff[i] = malloc(packetLen[i]);
                if (!srcBuff[i]) {
                        printf("malloc(srcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_4_buffer_exit;
                }
                dstBuff[i] = malloc(packetLen[i]);
                if (!dstBuff[i]) {
                        printf("malloc(dstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_4_buffer_exit;
                }
                IV[i] = malloc(SNOW3G_IV_LEN_IN_BYTES);
                if (!IV[i]) {
                        printf("malloc(IV[%d]):failed !\n", i);
                        goto snow3g_f8_4_buffer_exit;
                }
                memcpy(pKey, testVectors[1].key, testVectors[1].keyLenInBytes);

                memcpy(srcBuff[i], testVectors[1].plaintext, packetLen[i]);

                memset(dstBuff[i], 0, packetLen[i]);

                memcpy(IV[i], testVectors[1].iv, testVectors[1].ivLenInBytes);
        }

        /*only 1 key is needed for snow3g 4 blocks*/
        if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched)) {
                printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                goto snow3g_f8_4_buffer_exit;
        }

        /* Test the encrypt */
        IMB_SNOW3G_F8_4_BUFFER(mb_mgr, pKeySched, IV[0], IV[1], IV[2], IV[3],
                               srcBuff[0], dstBuff[0], packetLen[0], srcBuff[1],
                               dstBuff[1], packetLen[1], srcBuff[2], dstBuff[2],
                               packetLen[2], srcBuff[3], dstBuff[3],
                               packetLen[3]);

        /*compare the ciphertext with the encryped plaintext*/
        for (i = 0; i < numPackets; i++) {
                if (memcmp(dstBuff[i], testVectors[1].ciphertext,
                           packetLen[i]) != 0) {
                        printf("IMB_SNOW3G_F8_4_BUFFER(Enc, diff size) "
                               "vector:%d buffer:%d\n", 1, i);
                        snow3g_hexdump("Actual:", dstBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", testVectors[1].ciphertext,
                                       packetLen[i]);
                        goto snow3g_f8_4_buffer_exit;
                }
                printf(".");
        }

        /* no errors detected */
        ret = 0;

snow3g_f8_4_buffer_exit:
        if (pKey != NULL)
                free(pKey);
        if (pKeySched != NULL)
                free(pKeySched);

        for (i = 0; i < numPackets; i++) {
                if (srcBuff[i] != NULL)
                        free(srcBuff[i]);
                if (dstBuff[i] != NULL)
                        free(dstBuff[i]);
                if (IV[i] != NULL)
                        free(IV[i]);
        }
        printf("\n");

        return ret;
}

static int validate_snow3g_f8_8_blocks(struct MB_MGR *mb_mgr)
{
        int length, numVectors, i, j, numPackets = 8;
        size_t size = 0;
        cipher_test_vector_t *testVectors = snow3g_cipher_test_vectors[1];
        /* snow3g f8 test vectors are located at index 1 */
        numVectors = numSnow3gCipherTestVectors[1];

        snow3g_key_schedule_t *pKeySched = NULL;
        uint8_t *pKey = NULL;
        int keyLen = MAX_KEY_LEN;
        uint8_t *srcBuff[MAX_DATA_LEN];
        uint8_t *dstBuff[MAX_DATA_LEN];
        uint8_t *IV[SNOW3G_IV_LEN_IN_BYTES];
        uint32_t packetLen[MAX_DATA_LEN];
        int ret = 1;

        printf("Testing IMB_SNOW3G_F8_8_BUFFER:\n");

        memset(srcBuff, 0, sizeof(srcBuff));
        memset(dstBuff, 0, sizeof(dstBuff));
        memset(IV, 0, sizeof(IV));

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return ret;
        }

        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(key):failed !\n");
                return ret;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size) {
                free(pKey);
                return ret;
        }

        pKeySched = malloc(size);
        if (!pKeySched) {
                printf("malloc(IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr)): failed ! "
                       "\n");
                free(pKey);
                return ret;
        }

        /* Test with all vectors */
        for (j = 0; j < numVectors; j++) {
                int k;
                /*vectors are in bits used to round up to bytes*/
                length = testVectors[j].dataLenInBytes;

                /* Create test Data for num Packets*/
                for (i = 0; i < numPackets; i++) {

                        packetLen[i] = length;
                        srcBuff[i] = malloc(length);
                        if (!srcBuff[i]) {
                                printf("malloc(srcBuff[%d]):failed !\n", i);
                                goto snow3g_f8_8_buffer_exit;
                        }

                        dstBuff[i] = malloc(length);
                        if (!dstBuff[i]) {
                                printf("malloc(dstBuff[%d]):failed !\n", i);
                                goto snow3g_f8_8_buffer_exit;
                        }

                        IV[i] = malloc(SNOW3G_IV_LEN_IN_BYTES);
                        if (!IV[i]) {
                                printf("malloc(IV[%d]):failed !\n", i);
                                goto snow3g_f8_8_buffer_exit;
                        }

                        memcpy(pKey, testVectors[j].key,
                               testVectors[j].keyLenInBytes);

                        memcpy(srcBuff[i], testVectors[j].plaintext, length);

                        memcpy(dstBuff[i], testVectors[j].ciphertext, length);

                        memcpy(IV[i], testVectors[j].iv,
                               testVectors[j].ivLenInBytes);
                }

                /*only 1 key is needed for snow3g 8 blocks*/
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched)) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                        goto snow3g_f8_8_buffer_exit;
                }

                /*Test the encrypt*/
                IMB_SNOW3G_F8_8_BUFFER(
                        mb_mgr, pKeySched, IV[0], IV[1], IV[2], IV[3], IV[4],
                        IV[5], IV[6], IV[7], srcBuff[0], dstBuff[0],
                        packetLen[0], srcBuff[1], dstBuff[1], packetLen[1],
                        srcBuff[2], dstBuff[2], packetLen[2], srcBuff[3],
                        dstBuff[3], packetLen[3], srcBuff[4], dstBuff[4],
                        packetLen[4], srcBuff[5], dstBuff[5], packetLen[5],
                        srcBuff[6], dstBuff[6], packetLen[6], srcBuff[7],
                        dstBuff[7], packetLen[7]);

                /*compare the ciphertext with the encryped plaintext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(dstBuff[i], testVectors[j].ciphertext,
                                   packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_8_BUFFER(Enc) vector:%d "
                                       "buffer:%d\n", j, i);
                                snow3g_hexdump("Actual:", dstBuff[i],
                                               packetLen[i]);
                                snow3g_hexdump("Expected:",
                                               testVectors[j].ciphertext,
                                               packetLen[i]);
                                goto snow3g_f8_8_buffer_exit;
                        }
                        printf(".");
                }

                /*Test the decrypt*/
                IMB_SNOW3G_F8_8_BUFFER(
                        mb_mgr, pKeySched, IV[0], IV[1], IV[2], IV[3], IV[4],
                        IV[5], IV[6], IV[7], dstBuff[0], srcBuff[0],
                        packetLen[0], dstBuff[1], srcBuff[1], packetLen[1],
                        dstBuff[2], srcBuff[2], packetLen[2], dstBuff[3],
                        srcBuff[3], packetLen[3], dstBuff[4], srcBuff[4],
                        packetLen[4], dstBuff[5], srcBuff[5], packetLen[5],
                        dstBuff[6], srcBuff[6], packetLen[6], dstBuff[7],
                        srcBuff[7], packetLen[7]);

                /*Compare the plaintext with the decrypted ciphertext*/
                for (i = 0; i < numPackets; i++) {
                        if (memcmp(srcBuff[i], testVectors[j].plaintext,
                                   packetLen[i]) != 0) {
                                printf("IMB_SNOW3G_F8_8_BUFFER(Dec) vector:%d "
                                       "buffer:%d\n", j, i);
                                snow3g_hexdump("Actual:", srcBuff[i],
                                               packetLen[i]);
                                snow3g_hexdump("Expected:",
                                               testVectors[j].plaintext,
                                               packetLen[i]);
                                goto snow3g_f8_8_buffer_exit;
                        }
                        printf(".");
                }
                                /* free buffers before next iteration */
                for (k = 0; k < numPackets; k++) {
                        if (srcBuff[k] != NULL) {
                                free(srcBuff[k]);
                                srcBuff[k] = NULL;
                        }
                        if (dstBuff[k] != NULL) {
                                free(dstBuff[k]);
                                dstBuff[k] = NULL;
                        }
                        if (IV[k] != NULL) {
                                free(IV[k]);
                                IV[k] = NULL;
                        }
                }
        }

        /*vectors are in bits used to round up to bytes*/
        length = testVectors[1].dataLenInBytes;

        /*Create test Data for num Packets*/
        for (i = 0; i < numPackets; i++) {
                /* Test for packets of different length. */
                packetLen[i] = length - (i * 12);
                srcBuff[i] = malloc(packetLen[i]);
                if (!srcBuff[i]) {
                        printf("malloc(srcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_exit;
                }
                dstBuff[i] = malloc(packetLen[i]);
                if (!dstBuff[i]) {
                        printf("malloc(dstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_exit;
                }
                IV[i] = malloc(SNOW3G_IV_LEN_IN_BYTES);
                if (!IV[i]) {
                        printf("malloc(IV[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_exit;
                }
                memcpy(pKey, testVectors[1].key, testVectors[1].keyLenInBytes);

                memcpy(srcBuff[i], testVectors[1].plaintext, packetLen[i]);

                memset(dstBuff[i], 0, packetLen[i]);

                memcpy(IV[i], testVectors[1].iv, testVectors[1].ivLenInBytes);
        }

        /*only 1 key is needed for snow3g 8 blocks*/
        if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched)) {
                printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                goto snow3g_f8_8_buffer_exit;
        }

        /* Test the encrypt */
        IMB_SNOW3G_F8_8_BUFFER(
                mb_mgr, pKeySched, IV[0], IV[1], IV[2], IV[3], IV[4], IV[5],
                IV[6], IV[7], srcBuff[0], dstBuff[0], packetLen[0], srcBuff[1],
                dstBuff[1], packetLen[1], srcBuff[2], dstBuff[2], packetLen[2],
                srcBuff[3], dstBuff[3], packetLen[3], srcBuff[4], dstBuff[4],
                packetLen[4], srcBuff[5], dstBuff[5], packetLen[5], srcBuff[6],
                dstBuff[6], packetLen[6], srcBuff[7], dstBuff[7], packetLen[7]);

        /*compare the ciphertext with the encryped plaintext*/
        for (i = 0; i < numPackets; i++) {
                if (memcmp(dstBuff[i], testVectors[1].ciphertext,
                           packetLen[i]) != 0) {
                        printf("IMB_SNOW3G_F8_8_BUFFER(Enc, diff size) "
                               "vector:%d buffer:%d\n",
                               1, i);
                        snow3g_hexdump("Actual:", dstBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", testVectors[1].ciphertext,
                                       packetLen[i]);
                        goto snow3g_f8_8_buffer_exit;
                }
                printf(".");
        }
        /* no errors detected */
        ret = 0;

snow3g_f8_8_buffer_exit:
        if (pKey != NULL)
                free(pKey);
        if (pKeySched != NULL)
                free(pKeySched);

        for (i = 0; i < numPackets; i++) {
                if (srcBuff[i] != NULL)
                        free(srcBuff[i]);
                if (dstBuff[i] != NULL)
                        free(dstBuff[i]);
                if (IV[i] != NULL)
                        free(IV[i]);
        }
        printf("\n");

        return ret;
}

static int validate_snow3g_f8_8_blocks_multi_key(struct MB_MGR *mb_mgr)
{
        int length, numVectors, i, j, numPackets = 8;
        size_t size = 0;

        if (numPackets > NUM_SUPPORTED_BUFFERS) {
                printf("numPackets %d too large !\n", numPackets);
                printf("Setting to NUM_SUPPORTED_BUFFERS %d\n",
                       NUM_SUPPORTED_BUFFERS);
                numPackets = NUM_SUPPORTED_BUFFERS;
        }

        cipher_test_vector_t *testVectors = snow3g_cipher_test_vectors[1];
        /* snow3g f8 test vectors are located at index 1 */
        numVectors = numSnow3gCipherTestVectors[1];

        snow3g_key_schedule_t *pKeySched[MAX_DATA_LEN];
        uint8_t *pKey[MAX_DATA_LEN];
        uint8_t *srcBuff[MAX_DATA_LEN];
        uint8_t *dstBuff[MAX_DATA_LEN];
        uint8_t *IV[MAX_DATA_LEN];
        uint32_t packetLen[MAX_DATA_LEN];
        int ret = 1;

        printf("Testing IMB_SNOW3G_F8_8_BUFFER_MULTIKEY:\n");

        memset(srcBuff, 0, sizeof(srcBuff));
        memset(dstBuff, 0, sizeof(dstBuff));
        memset(IV, 0, sizeof(IV));
        memset(pKey, 0, sizeof(pKey));
        memset(packetLen, 0, sizeof(packetLen));
        memset(pKeySched, 0, sizeof(pKeySched));

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return ret;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size) {
                printf("snow3g_key_sched_multi_size() failure !\n");
                return ret;
        }

        for (i = 0; i < numPackets; i++) {
                j = i % numVectors;

                length = testVectors[j].dataLenInBytes;
                packetLen[i] = length;
                pKeySched[i] = malloc(size);
                if (!pKeySched[i]) {
                        printf("malloc(pKeySched[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
                srcBuff[i] = malloc(length);
                if (!srcBuff[i]) {
                        printf("malloc(srcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
                dstBuff[i] = malloc(length);
                if (!dstBuff[i]) {
                        printf("malloc(dstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
                pKey[i] = malloc(testVectors[j].keyLenInBytes);
                if (!pKey[i]) {
                        printf("malloc(pKey[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
                IV[i] = malloc(SNOW3G_IV_LEN_IN_BYTES);
                if (!IV[i]) {
                        printf("malloc(IV[%d]):failed !\n", i);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }

                memcpy(pKey[i], testVectors[j].key,
                       testVectors[j].keyLenInBytes);

                memcpy(srcBuff[i], testVectors[j].plaintext, length);

                memcpy(IV[i], testVectors[j].iv, testVectors[j].ivLenInBytes);

                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i])) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr) error\n");
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
        }

        /*Test the encrypt*/
        IMB_SNOW3G_F8_8_BUFFER_MULTIKEY(mb_mgr,
                                        (const snow3g_key_schedule_t * const *)
                                        pKeySched,
                                        (const void * const *)IV,
                                        (const void * const *)srcBuff,
                                        (void **)dstBuff,
                                        packetLen);

        /*compare the ciphertext with the encrypted plaintext*/
        for (i = 0; i < numPackets; i++) {
                j = i % numVectors;
                if (memcmp(dstBuff[i], testVectors[j].ciphertext,
                           packetLen[i]) != 0) {
                        printf("snow3g_f8_8_multi_buffer(Enc) vector:%d "
                               "buffer:%d\n",
                               j, i);
                        snow3g_hexdump("Actual:", dstBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", testVectors[j].ciphertext,
                                       packetLen[i]);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
                printf(".");
        }

        /*Test the decrypt*/
        IMB_SNOW3G_F8_8_BUFFER_MULTIKEY(
                mb_mgr, (const snow3g_key_schedule_t * const *) pKeySched,
                (const void * const *)IV, (const void * const *)dstBuff,
                (void **)srcBuff, packetLen);

        /*Compare the plaintext with the decrypted ciphertext*/
        for (i = 0; i < numPackets; i++) {
                j = i % numVectors;
                if (memcmp(srcBuff[i], testVectors[j].plaintext,
                           packetLen[i]) != 0) {
                        printf("snow3g_f8_8_multi_buffer(Dec) vector:%d "
                               "buffer:%d\n", j, i);
                        snow3g_hexdump("Actual:", srcBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", testVectors[j].plaintext,
                                       packetLen[i]);
                        goto snow3g_f8_8_buffer_multikey_exit;
                }
                printf(".");
        }
        /* no errors detected */
        ret = 0;

snow3g_f8_8_buffer_multikey_exit:
        for (i = 0; i < numPackets; i++) {
                if (srcBuff[i] != NULL)
                        free(srcBuff[i]);
                if (dstBuff[i] != NULL)
                        free(dstBuff[i]);
                if (IV[i] != NULL)
                        free(IV[i]);
                if (pKey[i] != NULL)
                        free(pKey[i]);
                if (pKeySched[i] != NULL)
                        free(pKeySched[i]);

        }
        printf("\n");

        return ret;
}

int validate_snow3g_f8_n_blocks(struct MB_MGR *mb_mgr)
{
        int length, numVectors, i, numPackets = 16;
        size_t size = 0;
        cipher_test_vector_t *testVectors = snow3g_cipher_test_vectors[1];
        /* snow3g f8 test vectors are located at index 1 */
        numVectors = numSnow3gCipherTestVectors[1];

        snow3g_key_schedule_t *pKeySched = NULL;
        uint8_t *pKey = NULL;
        int keyLen = MAX_KEY_LEN;
        uint8_t *srcBuff[NUM_SUPPORTED_BUFFERS];
        uint8_t *dstBuff[NUM_SUPPORTED_BUFFERS];
        uint8_t *IV[NUM_SUPPORTED_BUFFERS];
        uint32_t packetLen[MAX_DATA_LEN];
        int ret = 1;

        printf("Testing IMB_SNOW3G_F8_N_BUFFER:\n");

        memset(srcBuff, 0, sizeof(srcBuff));
        memset(dstBuff, 0, sizeof(dstBuff));
        memset(IV, 0, sizeof(IV));

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return ret;
        }

        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(key):failed !\n");
                return ret;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size) {
                free(pKey);
                return ret;
        }

        pKeySched = malloc(size);
        if (!pKeySched) {
                printf("malloc(pKeySched): failed !\n");
                free(pKey);
                return ret;
        }

        /*vectors are in bits used to round up to bytes*/
        length = testVectors[0].dataLenInBytes;

        /*	Create test Data for num Packets*/
        for (i = 0; i < numPackets; i++) {

                packetLen[i] = length;
                srcBuff[i] = malloc(length);
                if (!srcBuff[i]) {
                        printf("malloc(srcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_exit;
                }
                dstBuff[i] = malloc(length);
                if (!dstBuff[i]) {
                        printf("malloc(dstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_exit;
                }
                IV[i] = malloc(SNOW3G_IV_LEN_IN_BYTES);
                if (!IV[i]) {
                        printf("malloc(IV[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_exit;
                }

                memcpy(pKey, testVectors[0].key, testVectors[0].keyLenInBytes);
                memcpy(srcBuff[i], testVectors[0].plaintext, length);
                memcpy(IV[i], testVectors[0].iv, testVectors[0].ivLenInBytes);
        }

        if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched)) {
                printf("IMB_SNOW3G_INIT_KEY_SCHED() error\n");
                goto snow3g_f8_n_buffer_exit;
        }

        for (i = 0; i < NUM_SUPPORTED_BUFFERS; i++) {
                /*Test the encrypt*/
                IMB_SNOW3G_F8_N_BUFFER(mb_mgr, pKeySched,
                                       (const void * const *)IV,
                                       (const void * const *)srcBuff,
                                       (void **)dstBuff,
                                       packetLen, i + 1);
                if (dstBuff[0] == NULL) {
                        printf("N buffer failure\n");
                        goto snow3g_f8_n_buffer_exit;
                }

                /*Compare the data in the dstBuff with the cipher pattern*/
                if (memcmp(testVectors[0].ciphertext, dstBuff[i],
                           packetLen[i]) != 0) {
                        printf("IMB_SNOW3G_F8_N_BUFFER(Enc) , vector:%d\n", i);
                        snow3g_hexdump("Actual:", dstBuff[i], packetLen[0]);
                        snow3g_hexdump("Expected:", testVectors[0].ciphertext,
                                       packetLen[0]);
                        goto snow3g_f8_n_buffer_exit;
                }
                printf(".");

                /*Test the Decrypt*/
                IMB_SNOW3G_F8_N_BUFFER(mb_mgr, pKeySched,
                                       (const void * const *)IV,
                                       (const void * const *)dstBuff,
                                       (void **)srcBuff,
                                       packetLen, i + 1);
                if (srcBuff[0] == NULL) {
                        printf("N buffer failure\n");
                        goto snow3g_f8_n_buffer_exit;
                }

                /*Compare the data in the srcBuff with the dstBuff*/
                if (memcmp(srcBuff[i], testVectors[0].plaintext,
                           packetLen[i]) != 0) {
                        printf("snow3g_f8_n_buffer equal sizes, vector:%d\n",
                               i);
                        snow3g_hexdump("Actual:", srcBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", testVectors[0].plaintext,
                                       packetLen[0]);
                        goto snow3g_f8_n_buffer_exit;
                }
                printf(".");
        }
        /* no errors detected */
        ret = 0;

snow3g_f8_n_buffer_exit:
        if (pKey != NULL)
                free(pKey);
        if (pKeySched != NULL)
                free(pKeySched);

        for (i = 0; i < numPackets; i++) {
                if (srcBuff[i] != NULL)
                        free(srcBuff[i]);
                if (dstBuff[i] != NULL)
                        free(dstBuff[i]);
                if (IV[i] != NULL)
                        free(IV[i]);
        }
        printf("\n");

        return ret;
}

static int validate_snow3g_f8_n_blocks_multi(struct MB_MGR *mb_mgr)
{
        int length, numVectors, i, numPackets = NUM_SUPPORTED_BUFFERS;
        size_t size = 0;
        cipher_test_vector_t *testVectors = snow3g_cipher_test_vectors[1];
        /* snow3g f8 test vectors are located at index 1 */
        numVectors = numSnow3gCipherTestVectors[1];

        snow3g_key_schedule_t *pKeySched[MAX_DATA_LEN];
        uint8_t *pKey[MAX_DATA_LEN];
        uint8_t *srcBuff[MAX_DATA_LEN];
        uint8_t *dstBuff[MAX_DATA_LEN];
        uint8_t *IV[MAX_DATA_LEN];
        uint32_t packetLen[MAX_DATA_LEN];
        int ret = 1;

        printf("Testing IMB_SNOW3G_F8_N_BUFFER_MULTIKEY:\n");

        memset(srcBuff, 0, sizeof(srcBuff));
        memset(dstBuff, 0, sizeof(dstBuff));
        memset(IV, 0, sizeof(IV));
        memset(pKeySched, 0, sizeof(pKeySched));
        memset(pKey, 0, sizeof(pKey));

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return ret;
        }

        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size) {
                printf("snow3g_key_sched_multi_size() failure !\n");
                return ret;
        }

        for (i = 0; i < numPackets; i++) {
                length = testVectors[0].dataLenInBytes;
                packetLen[i] = length;
                pKeySched[i] = malloc(size);
                if (!pKeySched[i]) {
                        printf("malloc(pKeySched[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
                srcBuff[i] = malloc(length);
                if (!srcBuff[i]) {
                        printf("malloc(srcBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
                dstBuff[i] = malloc(length);
                if (!dstBuff[i]) {
                        printf("malloc(dstBuff[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
                pKey[i] = malloc(testVectors[0].keyLenInBytes);
                if (!pKey[i]) {
                        printf("malloc(pKey[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
                IV[i] = malloc(SNOW3G_IV_LEN_IN_BYTES);
                if (!IV[i]) {
                        printf("malloc(IV[%d]):failed !\n", i);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }

                memcpy(pKey[i], testVectors[0].key,
                       testVectors[0].keyLenInBytes);

                memcpy(srcBuff[i], testVectors[0].plaintext, length);

                memcpy(IV[i], testVectors[0].iv, testVectors[0].ivLenInBytes);

                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey[i], pKeySched[i])) {
                        printf("IMB_SNOW3G_INIT_KEY_SCHED() error\n");
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
        }

        for (i = 0; i < numPackets; i++) {
                /*Test the encrypt*/
                IMB_SNOW3G_F8_N_BUFFER_MULTIKEY(
                        mb_mgr,
                        (const snow3g_key_schedule_t * const *)pKeySched,
                        (const void * const *)IV,
                        (const void * const *)srcBuff,
                        (void **)dstBuff, packetLen, i + 1);

                if (dstBuff[0] == NULL) {
                        printf("N buffer failure\n");
                        goto snow3g_f8_n_buffer_multikey_exit;
                }

                /*Compare the data in the dstBuff with the cipher pattern*/
                if (memcmp(testVectors[0].ciphertext, dstBuff[i],
                           packetLen[i]) != 0) {
                        printf("IMB_SNOW3G_F8_N_BUFFER(Enc) , vector:%d "
                               "buffer: %d\n", 0, i);
                        snow3g_hexdump("Actual:", dstBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", testVectors[0].ciphertext,
                                       packetLen[i]);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
                printf(".");

                /*Test the Decrypt*/
                IMB_SNOW3G_F8_N_BUFFER_MULTIKEY(
                        mb_mgr,
                        (const snow3g_key_schedule_t * const *) pKeySched,
                        (const void * const *)IV,
                        (const void * const *)dstBuff,
                        (void **)srcBuff, packetLen, i + 1);

                if (srcBuff[0] == NULL) {
                        printf("N buffer failure\n");
                        goto snow3g_f8_n_buffer_multikey_exit;
                }

                /*Compare the data in the srcBuff with the dstBuff*/
                if (memcmp(srcBuff[i], testVectors[0].plaintext,
                           packetLen[i]) != 0) {
                        printf("snow3g_f8_n_buffer equal sizes, vector:%d "
                               "buffer: %d\n", 0, i);
                        snow3g_hexdump("Actual:", srcBuff[i], packetLen[i]);
                        snow3g_hexdump("Expected:", testVectors[0].plaintext,
                                       packetLen[i]);
                        goto snow3g_f8_n_buffer_multikey_exit;
                }
                printf(".");
        }
        /* no errors detected */
        ret = 0;

snow3g_f8_n_buffer_multikey_exit:
        for (i = 0; i < numPackets; i++) {
                if (srcBuff[i] != NULL)
                        free(srcBuff[i]);
                if (dstBuff[i] != NULL)
                        free(dstBuff[i]);
                if (IV[i] != NULL)
                        free(IV[i]);
                if (pKey[i] != NULL)
                        free(pKey[i]);
                if (pKeySched[i] != NULL)
                        free(pKeySched[i]);

        }
        printf("\n");

        return ret;
}

int validate_snow3g_f9(struct MB_MGR *mb_mgr)
{
        int numVectors, i, inputLen;
        size_t size = 0;
        hash_test_vector_t *testVectors = snow3g_hash_test_vectors[2];
        /* snow3g f9 test vectors are located at index 2 */
        numVectors = numSnow3gHashTestVectors[2];

        snow3g_key_schedule_t *pKeySched = NULL;
        uint8_t *pKey = NULL;
        int keyLen = MAX_KEY_LEN;
        uint8_t srcBuff[MAX_DATA_LEN];
        uint8_t digest[DIGEST_LEN];
        uint8_t *pIV;
        int ret = 1;

        printf("Testing IMB_SNOW3G_F9_1_BUFFER:\n");

        if (!numVectors) {
                printf("No Snow3G test vectors found !\n");
                return ret;
        }

        pIV = malloc(SNOW3G_IV_LEN_IN_BYTES);
        if (!pIV) {
                printf("malloc(pIV):failed !\n");
                return ret;
        }

        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(pKey):failed !\n");
                free(pIV);
                return ret;
        }
        size = IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr);
        if (!size) {
                free(pIV);
                free(pKey);
                return ret;
        }

        pKeySched = malloc(size);
        if (!pKeySched) {
                printf("malloc(IMB_SNOW3G_KEY_SCHED_SIZE(mb_mgr)): "
                       "failed !\n");
                free(pIV);
                free(pKey);
                return ret;
        }

        /*Get test data for for Snow3g 1 Packet version*/
        for (i = 0; i < numVectors; i++) {
                inputLen = (testVectors[i].lengthInBits + 7) / 8;

                memcpy(pKey, testVectors[i].key, testVectors[i].keyLenInBytes);
                memcpy(srcBuff, testVectors[i].input, inputLen);
                memcpy(pIV, testVectors[i].iv, testVectors[i].ivLenInBytes);

                /*Only 1 key sched is used*/
                if (IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, pKey, pKeySched)) {
                        printf("kasumi_init_f9_key_sched()error\n");
                        goto snow3g_f9_1_buffer_exit;
                }

                /*test the integrity for f9_user with IV*/
                IMB_SNOW3G_F9_1_BUFFER(mb_mgr, pKeySched, pIV, srcBuff,
                                       testVectors[i].lengthInBits, digest);

                /*Compare the digest with the expected in the vectors*/
                if (memcmp(digest, testVectors[i].exp_out, DIGEST_LEN) != 0) {
                        printf("IMB_SNOW3G_F9_1_BUFFER() vector num:%d\n", i);
                        snow3g_hexdump("Actual:", digest, DIGEST_LEN);
                        snow3g_hexdump("Expected:", testVectors[i].exp_out,
                                       DIGEST_LEN);
                        goto snow3g_f9_1_buffer_exit;
                }
                printf(".");

        } /* for numVectors */
        /* no errors detected */
        ret = 0;

snow3g_f9_1_buffer_exit:
        free(pIV);
        free(pKey);
        free(pKeySched);
        printf("\n");

        return ret;
}

static int validate_f8_iv_gen(void)
{
        uint32_t i;
        uint8_t IV[16];
        const uint32_t numVectors = MAX_BIT_BUFFERS;

        printf("Testing snow3g_f8_iv_gen:\n");

        /* skip first vector as it's not part of test data */
        for (i = 1; i < numVectors; i++) {
                cipher_iv_gen_params_t *iv_params =
                        &snow3g_f8_linear_bitvectors.iv_params[i];

                memset(IV, 0, sizeof(IV));

                /* generate IV */
                if (snow3g_f8_iv_gen(iv_params->count, iv_params->bearer,
                                     iv_params->dir, &IV) < 0)
                        return 1;

                /* validate result */
                if (memcmp(IV, snow3g_f8_linear_bitvectors.iv[i], 16) != 0) {
                        printf("snow3g_f8_iv_gen vector num: %d\n", i);
                        snow3g_hexdump("Actual", IV, 16);
                        snow3g_hexdump("Expected",
                                       snow3g_f8_linear_bitvectors.iv[i], 16);
                        return 1;
                } else
                        printf(".");
        }

        printf("\n");
        return 0;
}

static int validate_f9_iv_gen(void)
{
        uint32_t i;
        uint8_t IV[16];
        /* snow3g f9 test vectors are located at index 2 */
        const uint32_t numVectors = numSnow3gHashTestVectors[2];

        printf("Testing snow3g_f9_iv_gen:\n");

        /* 6 test sets */
        for (i = 0; i < numVectors; i++) {
                hash_iv_gen_params_t *iv_params =
                        &snow_f9_vectors[i].iv_params;

                memset(IV, 0, sizeof(IV));

                /* generate IV */
                if (snow3g_f9_iv_gen(iv_params->count, iv_params->fresh,
                                     iv_params->dir, &IV) < 0)
                        return 1;

                /* validate result */
                if (memcmp(IV, snow_f9_vectors[i].iv, 16) != 0) {
                        printf("snow3g_f9_iv_gen vector num: %d\n", i);
                        snow3g_hexdump("Actual", IV, 16);
                        snow3g_hexdump("Expected", snow_f9_vectors[i].iv, 16);
                        return 1;
                } else
                        printf(".");
        }

        printf("\n");
        return 0;
}

int snow3g_test(const enum arch_type arch, struct MB_MGR *mb_mgr)
{
        int status = 0;
        (void)(arch);


        if (validate_f8_iv_gen()) {
                printf("validate_snow3g_f8_iv_gen:: FAIL\n");
                status = 1;
        }
        if (validate_f9_iv_gen()) {
                printf("validate_snow3g_f9_iv_gen:: FAIL\n");
                status = 1;
        }

        if (validate_snow3g_f8_1_block(mb_mgr)) {
                printf("validate_snow3g_f8_1_block: FAIL\n");
                status = 1;
        }

        if (validate_snow3g_f8_1_bitblock(mb_mgr)) {
                printf("validate_snow3g_f8_1_bitblock: FAIL\n");
                status = 1;
        }

        if (validate_snow3g_f8_2_blocks(mb_mgr)) {
                printf("validate_snow3g_f8_2_blocks: FAIL\n");
                status = 1;
        }

        if (validate_snow3g_f8_4_blocks(mb_mgr)) {
                printf("validate_snow3g_f8_4_blocks: FAIL\n");
                status = 1;
        }

        if (validate_snow3g_f8_8_blocks(mb_mgr)) {
                printf("validate_snow3g_f8_8_blocks: FAIL\n");
                status = 1;
        }

        if (validate_snow3g_f8_8_blocks_multi_key(mb_mgr)) {
                printf("validate_snow3g_f8_8_blocks_multi_key: FAIL\n");
                status = 1;
        }

        if (validate_snow3g_f8_n_blocks(mb_mgr)) {
                printf("validate_snow3g_f8_n_blocks: FAIL\n");
                status = 1;
        }
        if (validate_snow3g_f8_n_blocks_multi(mb_mgr)) {
                printf("validate_snow3g_f8_n_blocks: FAIL\n");
                status = 1;
        }

        if (validate_snow3g_f9(mb_mgr)) {
                printf("validate_snow3g_f9: FAIL\n");
                status = 1;
        }

        if (!status)
                printf("ALL TESTS PASSED.\n");
        else
                printf("WE HAVE TEST FAILURES !\n");

        return status;
}

int membitcmp(const uint8_t *input, const uint8_t *output,
              const uint32_t bitlength, const uint32_t bitoffset)
{
        uint32_t bitresoffset;
        uint8_t bitresMask = ~((uint8_t)-1 << (8 - (bitoffset % 8)));
        uint32_t res = 0;
        uint32_t bytelengthfl = bitlength / 8;
        const uint8_t *srcfl = input + bitoffset / 8;
        const uint8_t *dstfl = output + bitoffset / 8;
        int index = 1;

        if (bitoffset % 8) {
                if ((*srcfl ^ *dstfl) & bitresMask) {
                        return 1;
                } else {
                        srcfl++;
                        dstfl++;
                }
        }
        bitresoffset = (bitlength + bitoffset) % 8;
        while (bytelengthfl--) {
                res = *srcfl++ ^ *dstfl++;
                if (res)
                        break;
                index++;
        }
        if ((bitresoffset) && (0 == bytelengthfl)) {
                res &= (uint8_t)-1 << (8 - bitresoffset);
                if (res)
                        return index;
        }
        return res;
}
