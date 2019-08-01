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
* KASUMI functional test
*-----------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <intel-ipsec-mb.h>

#include "gcm_ctr_vectors_test.h"
#include "kasumi_test_vectors.h"

#define KASUMIIVLEN 8
cipher_test_vector_t *vecList[MAX_DATA_LEN];

int kasumi_test(const enum arch_type arch, struct MB_MGR *mb_mgr);

static int membitcmp(const uint8_t *input, const uint8_t *output,
                     const uint32_t bitoffset, const uint32_t bitlength)
{
        uint32_t bitresoffset;
        uint8_t bitresMask = (uint8_t)-1 >> (bitoffset % CHAR_BIT);
        uint32_t res;
        uint32_t bytelengthfl = bitlength / CHAR_BIT;
        const uint8_t *srcfl = input + bitoffset / CHAR_BIT;
        const uint8_t *dstfl = output + bitoffset / CHAR_BIT;
        int index = 1;

        if (bitoffset % CHAR_BIT) {
                if ((*srcfl ^ *dstfl) & bitresMask)
                        return 1;
                else {
                        bytelengthfl--;
                        srcfl++;
                        dstfl++;
                }
        }
        bitresoffset = (bitlength + bitoffset) % CHAR_BIT;
        while (bytelengthfl--) {
                res = *srcfl ^ *dstfl;
                if (res) {
                        if (bytelengthfl != 1)
                                return index;
                        else if (bitresoffset < CHAR_BIT) {
                                if (res & ~((uint8_t)-1 << bitresoffset))
                                        return index;
                                else
                                        res = 0;
                        } else {
                                srcfl++;
                                dstfl++;
                                index++;
                        }
                } else {
                        srcfl++;
                        dstfl++;
                        index++;
                }
        }
        if (bitresoffset > CHAR_BIT)
                res = (*srcfl ^ *dstfl) &
                      ~((uint8_t)-1 >> (bitresoffset % CHAR_BIT));
        else if (bitresoffset == CHAR_BIT)
                res = (*srcfl ^ *dstfl) &
                      ~((uint8_t)-1 >> (bitoffset % CHAR_BIT));
        else
                res = 0;

        return res;
}

static inline void hexdump(const char *message, const uint8_t *ptr, int len)
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

static int validate_kasumi_f8_1_block(MB_MGR *mgr)
{
        int numKasumiTestVectors, i = 0;
        uint8_t *pKey = NULL;
        int keyLen = MAX_KEY_LEN;
        uint8_t srcBuff[MAX_DATA_LEN];
        uint8_t dstBuff[MAX_DATA_LEN];
        uint64_t IV;
        kasumi_key_sched_t *pKeySched = NULL;
        cipher_test_vector_t *kasumi_test_vectors = NULL;

        kasumi_test_vectors = kasumi_f8_vectors;
        numKasumiTestVectors = numCipherTestVectors[0];

        if (!numKasumiTestVectors) {
                printf("No Kasumi vectors found !\n");
                return 1;
        }
        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(pKey):failed !\n");
                return 1;
        }
        pKeySched = malloc(kasumi_key_sched_size());
        if (!pKeySched) {
                printf("malloc(kasumi_key_sched_size()): failed !\n");
                free(pKey);
                return 1;
        }

        /* Copy the data for for Kasumi_f8 1 Packet version */
        for (i = 0; i < numKasumiTestVectors; i++) {
                memcpy(pKey, kasumi_test_vectors[i].key,
                       kasumi_test_vectors[i].keyLenInBytes);
                memcpy(srcBuff, kasumi_test_vectors[i].plaintext,
                       kasumi_test_vectors[i].dataLenInBytes);
                memcpy(dstBuff, kasumi_test_vectors[i].ciphertext,
                       kasumi_test_vectors[i].dataLenInBytes);
                memcpy((uint8_t *)&IV, kasumi_test_vectors[i].iv,
                       kasumi_test_vectors[i].ivLenInBytes);

                /*setup the keysched to be used*/
                if (kasumi_init_f8_key_sched(pKey, pKeySched)) {
                        printf("kasumi_init_f8_key_sched()error\n");
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }

                /*Validate Encrpyt*/
                IMB_KASUMI_F8_1_BUFFER(mgr, pKeySched, IV, srcBuff, srcBuff,
                                       kasumi_test_vectors[i].dataLenInBytes);

                /*check against the cipher test in the vector against the
                 * encrypted
                 * plaintext*/
                if (memcmp(srcBuff, dstBuff,
                           kasumi_test_vectors[i].dataLenInBytes) != 0) {
                        printf("kasumi_f8_1_block(Enc)  vector:%d\n", i);
                        hexdump("Actual:", srcBuff,
                                kasumi_test_vectors[i].dataLenInBytes);
                        hexdump("Expected:", dstBuff,
                                kasumi_test_vectors[i].dataLenInBytes);
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }

                memcpy(dstBuff, kasumi_test_vectors[i].plaintext,
                       kasumi_test_vectors[i].dataLenInBytes);

                /*Validate Decrpyt*/
                IMB_KASUMI_F8_1_BUFFER(mgr, pKeySched, IV, srcBuff, srcBuff,
                                       kasumi_test_vectors[i].dataLenInBytes);

                if (memcmp(srcBuff, dstBuff,
                           kasumi_test_vectors[i].dataLenInBytes) != 0) {
                        printf("kasumi_f8_1_block(Dec)  vector:%d\n", i);
                        hexdump("Actual:", srcBuff,
                                kasumi_test_vectors[i].dataLenInBytes);
                        hexdump("Expected:", dstBuff,
                                kasumi_test_vectors[i].dataLenInBytes);
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }
        }

        free(pKey);
        free(pKeySched);
        printf("[%s]:  PASS, for %d single buffers.\n", __FUNCTION__, i);
        return 0;
}

/* Shift right a buffer by "offset" bits, "offset" < 8 */
static void buffer_shift_right(uint8_t *buffer, uint32_t length, uint8_t offset)
{
        uint8_t curr_byte, prev_byte;
        uint32_t length_in_bytes = (length + offset + 7) / CHAR_BIT;
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

static int validate_kasumi_f8_1_bitblock(MB_MGR *mgr)
{
        int numKasumiTestVectors, i = 0;
        kasumi_key_sched_t *pKeySched = NULL;
        const cipherbit_test_vector_t *kasumi_bit_vectors = NULL;

        kasumi_bit_vectors = kasumi_f8_bitvectors;
        numKasumiTestVectors = numCipherTestVectors[1];

        uint8_t *pKey = NULL;
        int keyLen = MAX_KEY_LEN;
        uint8_t srcBuff[MAX_DATA_LEN];
        uint8_t dstBuff[MAX_DATA_LEN];
        uint8_t wrkBuff[MAX_DATA_LEN];
        uint64_t IV;

        if (!numKasumiTestVectors) {
                printf("No Kasumi vectors found !\n");
                return 1;
        }
        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(pKey):failed !\n");
                return 1;
        }
        pKeySched = malloc(kasumi_key_sched_size());
        if (!pKeySched) {
                printf("malloc(kasumi_key_sched_size()): failed !\n");
                free(pKey);
                return 1;
        }

        /* Copy the data for for Kasumi_f8 1 Packet version*/
        for (i = 0; i < numKasumiTestVectors; i++) {
                memcpy(pKey, kasumi_bit_vectors[i].key,
                       kasumi_bit_vectors[i].keyLenInBytes);
                memcpy(srcBuff, kasumi_bit_vectors[i].plaintext,
                       (kasumi_bit_vectors[i].LenInBits + 7) / CHAR_BIT);
                memcpy(dstBuff, kasumi_bit_vectors[i].ciphertext,
                       (kasumi_bit_vectors[i].LenInBits + 7) / CHAR_BIT);
                memcpy((uint8_t *)&IV, kasumi_bit_vectors[i].iv,
                       kasumi_bit_vectors[i].ivLenInBytes);

                /* Setup the keysched to be used */
                if (kasumi_init_f8_key_sched(pKey, pKeySched)) {
                        printf("kasumi_init_f8_key_sched()error\n");
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }

                /* Validate Encrypt */
                IMB_KASUMI_F8_1_BUFFER_BIT(mgr, pKeySched, IV, srcBuff, wrkBuff,
                                           kasumi_bit_vectors[i].LenInBits, 0);

                /* Check against the cipher test in the vector against the
                 * encrypted plaintext */
                if (membitcmp(wrkBuff, dstBuff, 0,
                              kasumi_bit_vectors[i].LenInBits) != 0) {
                        printf("kasumi_f8_1_block(Enc) offset=0 vector:%d\n",
                               i);
                        hexdump("Actual:", wrkBuff,
                                (kasumi_bit_vectors[i].LenInBits + 7) /
                                    CHAR_BIT);
                        hexdump("Expected:", dstBuff,
                                (kasumi_bit_vectors[i].LenInBits + 7) /
                                    CHAR_BIT);
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }
                /*Validate Decrpyt*/
                IMB_KASUMI_F8_1_BUFFER_BIT(mgr, pKeySched, IV, wrkBuff, srcBuff,
                                           kasumi_bit_vectors[i].LenInBits, 0);

                memcpy(dstBuff, kasumi_bit_vectors[i].plaintext,
                       (kasumi_bit_vectors[i].LenInBits + 7) / CHAR_BIT);
                if (membitcmp(srcBuff, dstBuff, 0,
                              kasumi_bit_vectors[i].LenInBits) != 0) {
                        printf("kasumi_f8_1_block(Dec) offset=0 vector:%d\n",
                               i);
                        hexdump("Actual:", srcBuff,
                                (kasumi_bit_vectors[i].LenInBits + 7) /
                                    CHAR_BIT);
                        hexdump("Expected:", dstBuff,
                                (kasumi_bit_vectors[i].LenInBits + 7) /
                                    CHAR_BIT);
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }
                memcpy(srcBuff, kasumi_bit_vectors[i].plaintext,
                       (kasumi_bit_vectors[i].LenInBits + 7) / CHAR_BIT);
                buffer_shift_right(srcBuff,
                                   kasumi_bit_vectors[i].LenInBits, 4);
                memcpy(dstBuff, kasumi_bit_vectors[i].ciphertext,
                       (kasumi_bit_vectors[i].LenInBits + 7) / CHAR_BIT);
                buffer_shift_right(dstBuff,
                                   kasumi_bit_vectors[i].LenInBits, 4);

                /* Validate Encrypt */
                IMB_KASUMI_F8_1_BUFFER_BIT(mgr, pKeySched, IV, srcBuff, wrkBuff,
                                           kasumi_bit_vectors[i].LenInBits, 4);

                /* Check against the ciphertext in the vector against the
                 * encrypted plaintext */
                if (membitcmp(wrkBuff, dstBuff, 4,
                              kasumi_bit_vectors[i].LenInBits) != 0) {
                        printf("kasumi_f8_1_block(Enc) offset=4  vector:%d\n",
                               i);
                        hexdump("Actual:", wrkBuff,
                                (kasumi_bit_vectors[i].LenInBits + 7) /
                                    CHAR_BIT);
                        hexdump("Expected:", dstBuff,
                                (kasumi_bit_vectors[i].LenInBits + 7) /
                                    CHAR_BIT);
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }
                /*Validate Decrpyt*/
                IMB_KASUMI_F8_1_BUFFER_BIT(mgr, pKeySched, IV, wrkBuff, srcBuff,
                                           kasumi_bit_vectors[i].LenInBits, 4);

                memcpy(dstBuff, kasumi_bit_vectors[i].plaintext,
                       (kasumi_bit_vectors[i].LenInBits + 7) / CHAR_BIT);
                buffer_shift_right(dstBuff,
                                   kasumi_bit_vectors[i].LenInBits, 4);

                if (membitcmp(srcBuff, dstBuff, 4,
                              kasumi_bit_vectors[i].LenInBits) != 0) {
                        printf("kasumi_f8_1_block(Dec) offset=4 vector:%d\n",
                               i);
                        hexdump("Actual:", srcBuff,
                                (kasumi_bit_vectors[i].LenInBits + 7) /
                                    CHAR_BIT);
                        hexdump("Expected:", dstBuff,
                                (kasumi_bit_vectors[i].LenInBits + 7) /
                                    CHAR_BIT);
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }
        }

        free(pKey);
        free(pKeySched);
        printf("[%s]:  PASS, for %d single buffers.\n", __FUNCTION__, i);
        return 0;
}

static int validate_kasumi_f8_1_bitblock_offset(MB_MGR *mgr)
{
        int numKasumiTestVectors, i = 0;
        kasumi_key_sched_t *pKeySched = NULL;
        const cipherbit_test_linear_vector_t *kasumi_bit_vectors = NULL;

        kasumi_bit_vectors = &kasumi_f8_linear_bitvectors;
        numKasumiTestVectors = numCipherTestVectors[1];

        uint8_t *pKey = NULL;
        int keyLen = MAX_KEY_LEN;
        uint8_t srcBuff[MAX_DATA_LEN];
        uint8_t dstBuff[MAX_DATA_LEN];
        uint64_t IV;
        uint32_t bufferbytesize = 0;
        uint8_t wrkbuf[MAX_DATA_LEN];
        uint32_t offset = 0, byteoffset = 0, ret;

        if (!numKasumiTestVectors) {
                printf("No Kasumi vectors found !\n");
                return 1;
        }
        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(pKey):failed !\n");
                return 1;
        }
        pKeySched = malloc(kasumi_key_sched_size());
        if (!pKeySched) {
                printf("malloc(kasumi_key_sched_size()): failed !\n");
                free(pKey);
                return 1;
        }
        for (i = 0; i < numKasumiTestVectors; i++)
                bufferbytesize += kasumi_bit_vectors->LenInBits[i];

        bufferbytesize = (bufferbytesize + 7) / CHAR_BIT;
        memcpy(srcBuff, kasumi_bit_vectors->plaintext, bufferbytesize);
        memcpy(dstBuff, kasumi_bit_vectors->ciphertext, bufferbytesize);

        /* Copy the data for for Kasumi_f8 1 Packet version */
        for (i = 0, offset = 0, byteoffset = 0; i < numKasumiTestVectors; i++) {

                memcpy(pKey, &kasumi_bit_vectors->key[i][0],
                       kasumi_bit_vectors->keyLenInBytes);
                memcpy((uint8_t *)&IV, &kasumi_bit_vectors->iv[i][0],
                       kasumi_bit_vectors->ivLenInBytes);

                /* Setup the keysched to be used */
                if (kasumi_init_f8_key_sched(pKey, pKeySched)) {
                        printf("kasumi_init_f8_key_sched()error\n");
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }

                /* Validate Encrypt */
                IMB_KASUMI_F8_1_BUFFER_BIT(mgr, pKeySched, IV, srcBuff, wrkbuf,
                                           kasumi_bit_vectors->LenInBits[i],
                                           offset);

                /* Check against the ciphertext in the vector against the
                 * encrypted plaintext */
                ret = membitcmp(wrkbuf, dstBuff, offset,
                                kasumi_bit_vectors->LenInBits[i]);
                if (ret != 0) {
                        printf("kasumi_f8_1_block_linear(Enc)  vector:%d, "
                               "index:%d\n",
                               i, ret);
                        hexdump("Actual:", &wrkbuf[byteoffset],
                                (kasumi_bit_vectors->LenInBits[i] + 7) /
                                    CHAR_BIT);
                        hexdump("Expected:", &dstBuff[byteoffset],
                                (kasumi_bit_vectors->LenInBits[i] + 7) /
                                    CHAR_BIT);
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }
                offset += kasumi_bit_vectors->LenInBits[i];
                byteoffset = offset / CHAR_BIT;
        }
        for (i = 0, offset = 0, byteoffset = 0; i < numKasumiTestVectors; i++) {
                memcpy(pKey, &kasumi_bit_vectors->key[i][0],
                       kasumi_bit_vectors->keyLenInBytes);
                memcpy((uint8_t *)&IV, &kasumi_bit_vectors->iv[i][0],
                       kasumi_bit_vectors->ivLenInBytes);

                /* Setup the keysched to be used */
                if (kasumi_init_f8_key_sched(pKey, pKeySched)) {
                        printf("kasumi_init_f8_key_sched()error\n");
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }

                /* Validate Decrypt */
                IMB_KASUMI_F8_1_BUFFER_BIT(mgr, pKeySched, IV, dstBuff, wrkbuf,
                                           kasumi_bit_vectors->LenInBits[i],
                                           offset);

                ret = membitcmp(wrkbuf, srcBuff, offset,
                                kasumi_bit_vectors->LenInBits[i]);
                if (ret != 0) {
                        printf("kasumi_f8_1_block_linear(Dec)  "
                               "vector:%d,index:%d\n",
                               i, ret);
                        hexdump("Actual:", &wrkbuf[byteoffset],
                                (kasumi_bit_vectors->LenInBits[i] + 7) /
                                    CHAR_BIT);
                        hexdump("Expected:", &srcBuff[byteoffset],
                                (kasumi_bit_vectors->LenInBits[i] + 7) /
                                    CHAR_BIT);
                        free(pKey);
                        free(pKeySched);
                        return 1;
                }
                offset += kasumi_bit_vectors->LenInBits[i];
                byteoffset = offset / CHAR_BIT;
        }

        free(pKey);
        free(pKeySched);
        printf("[%s]:  PASS, for %d single buffers.\n", __FUNCTION__, i);
        return 0;
}

static int validate_kasumi_f8_2_blocks(MB_MGR *mgr)
{

        int numKasumiTestVectors, i = 0, numPackets = 2;
        const cipher_test_vector_t *kasumi_test_vectors = NULL;
        kasumi_key_sched_t *keySched = NULL;

        kasumi_test_vectors = cipher_test_vectors[0];
        numKasumiTestVectors = numCipherTestVectors[0];

        uint8_t *key = NULL;
        int keyLen = MAX_KEY_LEN;
        uint64_t iv[3];
        uint8_t *srcBuff[3] = {NULL};
        uint8_t *dstBuff[3] = {NULL};
        uint32_t packetLen[3];
        int ret = 1;

        if (!numKasumiTestVectors) {
                printf("No Kasumi vectors found !\n");
                goto exit;
        }

        key = malloc(keyLen);
        if (!key) {
                printf("malloc(key):failed !\n");
                goto exit;
        }

        keySched = malloc(kasumi_key_sched_size());
        if (!keySched) {
                printf("malloc(kasumi_key_sched_size()): failed !\n");
                goto exit;
        }

        /* Create test Data for num Packets + 1 */
        for (i = 0; i < numPackets + 1; i++) {
                packetLen[i] = kasumi_test_vectors[i].dataLenInBytes;
                srcBuff[i] = malloc(packetLen[i]);
                if (!srcBuff[i]) {
                        printf("malloc(srcBuff[%u]:failed !\n", i);
                        goto exit;
                }
                dstBuff[i] = malloc(packetLen[i]);
                if (!dstBuff[i]) {
                        printf("malloc(dstBuff[%u]:failed !\n", i);
                        goto exit;
                }

                memcpy(key, kasumi_test_vectors[i].key,
                       kasumi_test_vectors[i].keyLenInBytes);

                memcpy(srcBuff[i], kasumi_test_vectors[i].plaintext,
                       kasumi_test_vectors[i].dataLenInBytes);

                memcpy(dstBuff[i], kasumi_test_vectors[i].ciphertext,
                       kasumi_test_vectors[i].dataLenInBytes);

                memcpy(&iv[i], kasumi_test_vectors[i].iv,
                       kasumi_test_vectors[i].ivLenInBytes);
        }
        /* Only 1 key is needed for kasumi 2 blocks */
        if (kasumi_init_f8_key_sched(key, keySched)) {
                printf("kasumi_init_f8_key_sched()error\n");
                goto exit;
        }
        /* Test the encrypt */
        IMB_KASUMI_F8_2_BUFFER(mgr, keySched, iv[0], iv[1], srcBuff[0],
                               srcBuff[0], packetLen[0], srcBuff[1], srcBuff[1],
                               packetLen[1]);

        /* Compare the ciphertext with the encrypted plaintext */
        for (i = 0; i < numPackets; i++) {
                if (memcmp(srcBuff[i], kasumi_test_vectors[i].ciphertext,
                           packetLen[i]) != 0) {
                        printf("kasumi_f8_2_buffer(Enc)  vector:%d\n", i);
                        hexdump("Actual:", srcBuff[i], packetLen[i]);
                        hexdump("Expected:", kasumi_test_vectors[i].ciphertext,
                                packetLen[i]);
                        goto exit;
                }
        }
        for (i = 0; i < numPackets; i++)
                memcpy(srcBuff[i], kasumi_test_vectors[i].plaintext,
                       kasumi_test_vectors[i].dataLenInBytes);

        /* Test the encrypt reverse order */
        IMB_KASUMI_F8_2_BUFFER(mgr, keySched, iv[0], iv[1], srcBuff[1],
                               srcBuff[1], packetLen[1], srcBuff[0], srcBuff[0],
                               packetLen[0]);

        /* Compare the ciphertext with the encrypted plaintext */
        for (i = 0; i < numPackets; i++) {
                if (memcmp(srcBuff[i], kasumi_test_vectors[i].ciphertext,
                           packetLen[i]) != 0) {
                        printf("kasumi_f8_2_buffer(Enc)  vector:%d\n", i);
                        hexdump("Actual:", srcBuff[i], packetLen[i]);
                        hexdump("Expected:", kasumi_test_vectors[i].ciphertext,
                                packetLen[i]);
                        goto exit;
                }
        }
        for (i = 0; i < numPackets + 1; i++)
                memcpy(srcBuff[i], kasumi_test_vectors[i].plaintext,
                       kasumi_test_vectors[i].dataLenInBytes);

        /* Test the encrypt reverse order */
        IMB_KASUMI_F8_2_BUFFER(mgr, keySched, iv[0], iv[1], srcBuff[0],
                               srcBuff[0], packetLen[0], srcBuff[2], srcBuff[2],
                               packetLen[2]);

        /* Compare the ciphertext with the encrypted plaintext*/
        for (i = 0; i < numPackets + 1; i++) {
                if (i == 1)
                        continue;
                if (memcmp(srcBuff[i], kasumi_test_vectors[i].ciphertext,
                           packetLen[i]) != 0) {
                        printf("kasumi_f8_2_buffer(Enc)  vector:%d\n", i);
                        hexdump("Actual:", srcBuff[i], packetLen[i]);
                        hexdump("Expected:", kasumi_test_vectors[i].ciphertext,
                                packetLen[i]);
                        goto exit;
                }
        }

        /* Test the decrypt */
        IMB_KASUMI_F8_2_BUFFER(mgr, keySched, iv[0], iv[1], dstBuff[0],
                               dstBuff[0], packetLen[0], dstBuff[1], dstBuff[1],
                               packetLen[1]);

        /* Compare the plaintext with the decrypted ciphertext */
        for (i = 0; i < numPackets; i++) {
                if (memcmp(dstBuff[i], kasumi_test_vectors[i].plaintext,
                           packetLen[i]) != 0) {
                        printf("kasumi_f8_2_buffer(Dec)  vector:%d\n", i);
                        hexdump("Actual:", dstBuff[i], packetLen[i]);
                        hexdump("Expected:", kasumi_test_vectors[i].plaintext,
                                packetLen[i]);
                        goto exit;
                }
        }
        /* Test the decrypt reverse order */
        for (i = 0; i < numPackets; i++)
                memcpy(dstBuff[i], kasumi_test_vectors[i].ciphertext,
                       kasumi_test_vectors[i].dataLenInBytes);

        IMB_KASUMI_F8_2_BUFFER(mgr, keySched, iv[0], iv[1], dstBuff[1],
                               dstBuff[1], packetLen[1], dstBuff[0], dstBuff[0],
                               packetLen[0]);

        /* Compare the plaintext with the decrypted ciphertext */
        for (i = 0; i < numPackets; i++) {
                if (memcmp(dstBuff[i], kasumi_test_vectors[i].plaintext,
                           packetLen[i]) != 0) {
                        printf("kasumi_f8_2_buffer(Dec)  vector:%d\n", i);
                        hexdump("Actual:", dstBuff[i], packetLen[i]);
                        hexdump("Expected:", kasumi_test_vectors[i].plaintext,
                                packetLen[i]);
                        goto exit;
                }
        }

        ret = 0;

        printf("[%s]: PASS.\n", __FUNCTION__);
exit:
        free(key);
        free(keySched);
        for (i = 0; i < numPackets + 1; i++) {
                free(srcBuff[i]);
                free(dstBuff[i]);
        }
        return ret;
}

static int validate_kasumi_f8_3_blocks(MB_MGR *mgr)
{
        int numKasumiTestVectors, i = 0, numPackets = 3;
        const cipher_test_vector_t *kasumi_test_vectors = NULL;
        kasumi_key_sched_t *keySched = NULL;

        kasumi_test_vectors = cipher_test_vectors[0];
        numKasumiTestVectors = numCipherTestVectors[0];

        uint8_t *key = NULL;
        int keyLen = MAX_KEY_LEN;
        uint64_t iv[3];
        uint8_t *srcBuff[3] = {NULL};
        uint8_t *dstBuff[3] = {NULL};
        uint32_t packetLen;
        int ret = 1;

        if (!numKasumiTestVectors) {
                printf("No Kasumi vectors found !\n");
                goto exit;
        }

        key = malloc(keyLen);
        if (!key) {
                printf("malloc(key):failed !\n");
                goto exit;
        }

        keySched = malloc(kasumi_key_sched_size());
        if (!keySched) {
                printf("malloc(kasumi_key_sched_size()): failed !\n");
                goto exit;
        }

        packetLen = kasumi_test_vectors[0].dataLenInBytes;

        /* Create test Data for num Packets */
        for (i = 0; i < numPackets; i++) {
                srcBuff[i] = malloc(packetLen);
                if (!srcBuff[i]) {
                        printf("malloc(srcBuff[%u]:failed !\n", i);
                        goto exit;
                }
                dstBuff[i] = malloc(packetLen);
                if (!dstBuff[i]) {
                        printf("malloc(dstBuff[%u]:failed !\n", i);
                        goto exit;
                }

                memcpy(key, kasumi_test_vectors[0].key,
                       kasumi_test_vectors[0].keyLenInBytes);

                memcpy(srcBuff[i], kasumi_test_vectors[0].plaintext,
                       kasumi_test_vectors[0].dataLenInBytes);

                memcpy(dstBuff[i], kasumi_test_vectors[0].ciphertext,
                       kasumi_test_vectors[0].dataLenInBytes);

                memcpy(&iv[i], kasumi_test_vectors[0].iv,
                       kasumi_test_vectors[0].ivLenInBytes);
        }

        /* Only 1 key is needed for kasumi 3 blocks */
        if (kasumi_init_f8_key_sched(key, keySched)) {
                printf("kasumi_init_f8_key_sched()error\n");
                goto exit;
        }

        /* Test the encrypt */
        IMB_KASUMI_F8_3_BUFFER(mgr, keySched, iv[0], iv[1], iv[2], srcBuff[0],
                               srcBuff[0], srcBuff[1], srcBuff[1], srcBuff[2],
                               srcBuff[2], packetLen);

        /* Compare the ciphertext with the encrypted plaintext */
        for (i = 0; i < numPackets; i++) {
                if (memcmp(srcBuff[i], kasumi_test_vectors[0].ciphertext,
                           packetLen) != 0) {
                        printf("kasumi_f8_3_buffer(Enc)  vector:%d\n", i);
                        hexdump("Actual:", srcBuff[i], packetLen);
                        hexdump("Expected:", kasumi_test_vectors[0].ciphertext,
                                packetLen);
                        goto exit;
                }
        }

        /* Test the decrypt */
        IMB_KASUMI_F8_3_BUFFER(mgr, keySched, iv[0], iv[1], iv[2], dstBuff[0],
                           dstBuff[0], dstBuff[1], dstBuff[1], dstBuff[2],
                           dstBuff[2], packetLen);

        /* Compare the plaintext with the decrypted ciphertext */
        for (i = 0; i < numPackets; i++) {
                if (memcmp(dstBuff[i], kasumi_test_vectors[0].plaintext,
                           packetLen) != 0) {
                        printf("kasumi_f8_3_buffer(Dec)  vector:%d\n", i);
                        hexdump("Actual:", dstBuff[i], packetLen);
                        hexdump("Expected:", kasumi_test_vectors[0].plaintext,
                                packetLen);
                        goto exit;
                }
        }

        ret = 0;
        printf("[%s]: PASS.\n", __FUNCTION__);
exit:
        free(key);
        free(keySched);
        for (i = 0; i < numPackets; i++) {
                free(srcBuff[i]);
                free(dstBuff[i]);
        }
        return ret;
}

static int validate_kasumi_f8_4_blocks(MB_MGR *mgr)
{
        int numKasumiTestVectors, i = 0, numPackets = 4;
        const cipher_test_vector_t *kasumi_test_vectors = NULL;
        kasumi_key_sched_t *keySched = NULL;

        kasumi_test_vectors = cipher_test_vectors[0];
        numKasumiTestVectors = numCipherTestVectors[0];

        uint8_t *key = NULL;
        int keyLen = MAX_KEY_LEN;
        uint64_t iv[4];
        uint8_t *srcBuff[4] = {NULL};
        uint8_t *dstBuff[4] = {NULL};
        uint32_t packetLen;
        int ret = 1;

        if (!numKasumiTestVectors) {
                printf("No Kasumi vectors found !\n");
                goto exit;
        }

        key = malloc(keyLen);
        if (!key) {
                printf("malloc(key):failed !\n");
                goto exit;
        }

        keySched = malloc(kasumi_key_sched_size());
        if (!keySched) {
                printf("malloc(kasumi_key_sched_size()): failed !\n");
                goto exit;
        }

        packetLen = kasumi_test_vectors[0].dataLenInBytes;

        /* Create test Data for num Packets */
        for (i = 0; i < numPackets; i++) {
                srcBuff[i] = malloc(packetLen);
                if (!srcBuff[i]) {
                        printf("malloc(srcBuff[%u]:failed !\n", i);
                        goto exit;
                }
                dstBuff[i] = malloc(packetLen);
                if (!dstBuff[i]) {
                        printf("malloc(dstBuff[%u]:failed !\n", i);
                        goto exit;
                }

                memcpy(key, kasumi_test_vectors[0].key,
                       kasumi_test_vectors[0].keyLenInBytes);

                memcpy(srcBuff[i], kasumi_test_vectors[0].plaintext,
                       kasumi_test_vectors[0].dataLenInBytes);

                memcpy(dstBuff[i], kasumi_test_vectors[0].ciphertext,
                       kasumi_test_vectors[0].dataLenInBytes);

                memcpy(&iv[i], kasumi_test_vectors[0].iv,
                       kasumi_test_vectors[0].ivLenInBytes);
        }

        /* Only 1 key is needed for kasumi 4 blocks */
        if (kasumi_init_f8_key_sched(key, keySched)) {
                printf("kasumi_init_f8_key_sched()error\n");
                goto exit;
        }

        /* Test the encrypt */
        IMB_KASUMI_F8_4_BUFFER(mgr, keySched, iv[0], iv[1], iv[2], iv[3],
                               srcBuff[0], srcBuff[0], srcBuff[1], srcBuff[1],
                               srcBuff[2], srcBuff[2], srcBuff[3], srcBuff[3],
                               packetLen);

        /* Compare the ciphertext with the encrypted plaintext */
        for (i = 0; i < numPackets; i++) {
                if (memcmp(srcBuff[i], kasumi_test_vectors[0].ciphertext,
                           packetLen) != 0) {
                        printf("kasumi_f8_4_buffer(Enc)  vector:%d\n", i);
                        hexdump("Actual:", srcBuff[i], packetLen);
                        hexdump("Expected:", kasumi_test_vectors[0].ciphertext,
                                packetLen);
                        goto exit;
                }
        }

        /* Test the decrypt */
        IMB_KASUMI_F8_4_BUFFER(mgr, keySched, iv[0], iv[1], iv[2], iv[3],
                               dstBuff[0], dstBuff[0], dstBuff[1], dstBuff[1],
                               dstBuff[2], dstBuff[2], dstBuff[3], dstBuff[3],
                               packetLen);

        /*Compare the plaintext with the decrypted cipher text*/
        for (i = 0; i < numPackets; i++) {
                if (memcmp(dstBuff[i], kasumi_test_vectors[0].plaintext,
                           packetLen) != 0) {
                        printf("kasumi_f8_4_buffer(Dec)  vector:%d\n", i);
                        hexdump("Actual:", dstBuff[i], packetLen);
                        hexdump("Expected:", kasumi_test_vectors[0].plaintext,
                                packetLen);
                        goto exit;
                }
        }

        ret = 0;
        printf("[%s]: PASS.\n", __FUNCTION__);
exit:
        free(key);
        free(keySched);
        for (i = 0; i < numPackets; i++) {
                free(srcBuff[i]);
                free(dstBuff[i]);
        }
        return ret;
}

static int validate_kasumi_f8_n_blocks(MB_MGR *mgr)
{
        kasumi_key_sched_t *pKeySched = NULL;
        uint64_t IV[NUM_SUPPORTED_BUFFERS][NUM_SUPPORTED_BUFFERS];
        uint32_t buffLenInBytes[NUM_SUPPORTED_BUFFERS];
        uint8_t *srcBuff[NUM_SUPPORTED_BUFFERS][NUM_SUPPORTED_BUFFERS];
        uint8_t *dstBuff[NUM_SUPPORTED_BUFFERS][NUM_SUPPORTED_BUFFERS];
        uint8_t key[KASUMI_KEY_SIZE];
        int i = 0, j = 0;
        int ret = -1;

        /* Only one key is used */
        memset(key, 0xAA, KASUMI_KEY_SIZE);

        pKeySched = malloc(kasumi_key_sched_size());
        if (!pKeySched) {
                printf("malloc(kasumi_key_sched_size()): failed !\n");
                goto exit;
        }

        if (kasumi_init_f8_key_sched(key, pKeySched)) {
                printf("kasumi_init_f8_key_sched()error\n");
                goto exit;
        }

        /* Allocate memory for the buffers fill them with data */
        for (i = 0; i < NUM_SUPPORTED_BUFFERS; i++) {
                for (j = 0; j < NUM_SUPPORTED_BUFFERS; j++) {
                        srcBuff[i][j] = malloc(MAX_DATA_LEN);
                        if (!srcBuff[i][j]) {
                                printf("malloc(srcBuff[%u][%u]:failed !\n",
                                       i, j);
                                goto exit;
                        }
                        dstBuff[i][j] = malloc(MAX_DATA_LEN);
                        if (!dstBuff[i][j]) {
                                printf("malloc(dstBuff[%u][%u]:failed !\n",
                                       i, j);
                                goto exit;
                        }

                        memset(srcBuff[i][j], i, MAX_DATA_LEN);
                        memset(dstBuff[i][j], i, MAX_DATA_LEN);

                        IV[i][j] = (uint64_t)i;
                }
        }

        /* Testing multiple buffers of equal size */
        for (i = 0; i < NUM_SUPPORTED_BUFFERS; i++) {
                /* Testing Buffer sizes for 128 */
                buffLenInBytes[i] = 128;

                /* Test the encrypt */
                IMB_KASUMI_F8_N_BUFFER(mgr, pKeySched, IV[i],
                                       (const void **)srcBuff[i],
                                       (void **)srcBuff[i],
                                       buffLenInBytes, i + 1);
                if (srcBuff[i][0] == NULL) {
                        printf("N buffer failure\n");
                        goto exit;
                }

                /* Test the Decrypt */
                IMB_KASUMI_F8_N_BUFFER(mgr, pKeySched, IV[i],
                                       (const void **)srcBuff[i],
                                       (void **)srcBuff[i],
                                       buffLenInBytes, i + 1);
                if (srcBuff[i][0] == NULL) {
                        printf("N buffer failure\n");
                        goto exit;
                }

                for (j = 0; j <= i; j++) {
                        if (memcmp(srcBuff[i][j], dstBuff[i][j],
                                   buffLenInBytes[j]) != 0) {
                                printf("kasumi_f8_n_buffer equal sizes, "
                                       "numBuffs:%d\n",
                                       i);
                                hexdump("Actual:", srcBuff[i][j],
                                        buffLenInBytes[j]);
                                hexdump("Expected:", dstBuff[i][j],
                                        buffLenInBytes[j]);
                                goto exit;
                        }
                }
        }
        printf("[%s]: PASS, 1 to %d buffers of equal size.\n", __FUNCTION__,
               i);

        /* Reset input buffers with test data */
        for (i = 0; i < NUM_SUPPORTED_BUFFERS; i++) {
                for (j = 0; j < NUM_SUPPORTED_BUFFERS; j++) {
                        memset(srcBuff[i][j], i, MAX_DATA_LEN);
                        memset(dstBuff[i][j], i, MAX_DATA_LEN);

                        IV[i][j] = (uint64_t)i;
                }
        }

        /* Testing multiple buffers of increasing size */
        for (i = 0; i < NUM_SUPPORTED_BUFFERS; i++) {

                /* Testing different Buffer sizes*/
                buffLenInBytes[i] = i + 131 * 8;

                /* Test the encrypt */
                IMB_KASUMI_F8_N_BUFFER(mgr, pKeySched, IV[i],
                                       (const void **)srcBuff[i],
                                       (void **)srcBuff[i],
                                       buffLenInBytes, i + 1);
                if (srcBuff[i][0] == NULL) {
                        printf("N buffer failure\n");
                        goto exit;
                }

                /* Test the Decrypt */
                IMB_KASUMI_F8_N_BUFFER(mgr, pKeySched, IV[i],
                                       (const void **)srcBuff[i],
                                       (void **)srcBuff[i],
                                       buffLenInBytes, i + 1);
                if (srcBuff[i][0] == NULL) {
                        printf("N buffer failure\n");
                        goto exit;
                }

                for (j = 0; j <= i; j++) {
                        if (memcmp(srcBuff[i][j], dstBuff[i][j],
                                   buffLenInBytes[j]) != 0) {
                                printf("kasumi_f8_n_buffer increasing sizes, "
                                       "srcBuff[%d][%d]\n",
                                       i, j);
                                hexdump("Actual:", srcBuff[i][j],
                                        buffLenInBytes[j]);
                                hexdump("Expected:", dstBuff[i][j],
                                        buffLenInBytes[j]);
                                goto exit;
                        }
                }
        }

        printf("[%s]: PASS, 1 to %d buffers of increasing size.\n",
               __FUNCTION__, i);

        /* Reset input buffers with test data */
        for (i = 0; i < NUM_SUPPORTED_BUFFERS; i++) {
                for (j = 0; j < NUM_SUPPORTED_BUFFERS; j++) {
                        memset(srcBuff[i][j], i, MAX_DATA_LEN);
                        memset(dstBuff[i][j], i, MAX_DATA_LEN);

                        IV[i][j] = (uint64_t)i;
                }
        }

        /* Testing multiple buffers of decreasing size */
        for (i = 0; i < NUM_SUPPORTED_BUFFERS; i++) {

                /* Testing Buffer sizes from 3048 to 190 */
                buffLenInBytes[i] = MAX_DATA_LEN / (1 + i);

                /* Test the encrypt */
                IMB_KASUMI_F8_N_BUFFER(mgr, pKeySched, IV[i],
                                       (const void **)srcBuff[i],
                                       (void **)srcBuff[i],
                                       buffLenInBytes, i + 1);

                /* Test the Decrypt */
                IMB_KASUMI_F8_N_BUFFER(mgr, pKeySched, IV[i],
                                       (const void **)srcBuff[i],
                                       (void **)srcBuff[i],
                                       buffLenInBytes, i + 1);

                for (j = 0; j <= i; j++) {
                        if (memcmp(srcBuff[i][j], dstBuff[i][j],
                                   buffLenInBytes[j]) != 0) {
                                printf("kasumi_f8_n_buffer decreasing sizes, "
                                       "numBuffs:%d\n",
                                       i);
                                hexdump("Actual:", srcBuff[i][j],
                                        buffLenInBytes[j]);
                                hexdump("Expected:", dstBuff[i][j],
                                        buffLenInBytes[j]);
                                goto exit;
                        }
                }
        }

        ret = 0;
        printf("[%s]: PASS, 1 to %d buffers of decreasing size.\n",
               __FUNCTION__, i);
exit:
        /* free up test buffers */
        for (i = 0; i < NUM_SUPPORTED_BUFFERS; i++) {
                for (j = 0; j < NUM_SUPPORTED_BUFFERS; j++) {
                        free(srcBuff[i][j]);
                        free(dstBuff[i][j]);
                }
        }

        free(pKeySched);
        return ret;
}

static int validate_kasumi_f9(MB_MGR *mgr)
{
        kasumi_key_sched_t *pKeySched = NULL;
        uint8_t *pKey = NULL;
        int keyLen = 16;
        uint8_t srcBuff[MAX_DATA_LEN];
        uint8_t digest[KASUMI_DIGEST_SIZE];
        int numKasumiF9TestVectors, i;
        hash_test_vector_t *kasumiF9_test_vectors = NULL;
        int ret = 1;

        kasumiF9_test_vectors = kasumi_f9_vectors;
        numKasumiF9TestVectors = numHashTestVectors[0];

        if (!numKasumiF9TestVectors) {
                printf("No Kasumi vectors found !\n");
                goto exit;
        }
        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(pkey):failed!\n");
                goto exit;
        }

        pKeySched = malloc(kasumi_key_sched_size());
        if (!pKeySched) {
                printf("malloc (kasumi_key_sched_size()): failed !\n");
                goto exit;
        }

        /* Create the test Data */
        for (i = 0; i < numKasumiF9TestVectors; i++) {
                memcpy(pKey, kasumiF9_test_vectors[i].key,
                       kasumiF9_test_vectors[i].keyLenInBytes);

                memcpy(srcBuff, kasumiF9_test_vectors[i].input,
                       kasumiF9_test_vectors[i].lengthInBits);

                memcpy(digest, kasumiF9_test_vectors[i].exp_out,
                       KASUMI_DIGEST_SIZE);

                if (kasumi_init_f9_key_sched(pKey, pKeySched)) {
                        printf("kasumi_init_f9_key_sched()error\n");
                        goto exit;
                }

                /* Test F9 integrity */
                IMB_KASUMI_F9_1_BUFFER(mgr, pKeySched, srcBuff,
                                       kasumiF9_test_vectors[i].lengthInBits,
                                       digest);

                /* Compare the digest with the expected in the vectors */
                if (memcmp(digest, kasumiF9_test_vectors[i].exp_out,
                           KASUMI_DIGEST_SIZE) != 0) {
                        hexdump("Actual", digest, KASUMI_DIGEST_SIZE);
                        hexdump("Expected", kasumiF9_test_vectors[i].exp_out,
                                KASUMI_DIGEST_SIZE);
                        printf("F9 integrity %d Failed\n", i);
                        goto exit;
                }
        }

        ret = 0;
        printf("[%s]: PASS, for %d single buffers.\n", __FUNCTION__,
               numKasumiF9TestVectors);
exit:
        free(pKey);
        free(pKeySched);
        return ret;
}

static int validate_kasumi_f9_user(MB_MGR *mgr)
{
        int numKasumiF9IV_TestVectors = 0, i = 0;
        hash_iv_test_vector_t *kasumiF9_vectors = NULL;

        kasumiF9_vectors = kasumi_f9_IV_vectors;
        numKasumiF9IV_TestVectors = numHashTestVectors[1];

        kasumi_key_sched_t *pKeySched = NULL;
        uint8_t *pKey = NULL;
        int keyLen = MAX_KEY_LEN;

        uint64_t iv[MAX_IV_LEN];
        uint8_t srcBuff[MAX_DATA_LEN];
        uint8_t digest[KASUMI_DIGEST_SIZE];
        uint32_t direction;
        int ret = 1;

        if (!numKasumiF9IV_TestVectors) {
                printf("No Kasumi vectors found !\n");
                goto exit;
        }

        pKey = malloc(keyLen);
        if (!pKey) {
                printf("malloc(pkey):failed!\n");
                goto exit;
        }

        pKeySched = malloc(kasumi_key_sched_size());
        if (!pKeySched) {
                printf("malloc (kasumi_key_sched_size()): failed !\n");
                goto exit;
        }

        /* Create the test data */
        for (i = 0; i < numKasumiF9IV_TestVectors; i++) {
                memcpy(pKey, kasumiF9_vectors[i].key,
                       kasumiF9_vectors[i].keyLenInBytes);

                memcpy(srcBuff, kasumiF9_vectors[i].input,
                       (kasumiF9_vectors[i].lengthInBits + 7 / CHAR_BIT));

                memcpy(iv, kasumiF9_vectors[i].iv,
                       kasumiF9_vectors[i].ivLenInBytes);

                direction = kasumiF9_vectors[i].direction;

                /* Only 1 key sched is used */
                if (kasumi_init_f9_key_sched(pKey, pKeySched)) {
                        printf("kasumi_init_f9_key_sched()error\n");
                        goto exit;
                }
                /* Test the integrity for f9_user with IV */
                IMB_KASUMI_F9_1_BUFFER_USER(mgr, pKeySched, iv[0], srcBuff,
                                            kasumiF9_vectors[i].lengthInBits,
                                            digest, direction);

                /* Compare the digest with the expected in the vectors */
                if (memcmp(digest, kasumiF9_vectors[i].exp_out,
                           KASUMI_DIGEST_SIZE) != 0) {
                        hexdump("digest", digest, KASUMI_DIGEST_SIZE);
                        hexdump("exp_out", kasumiF9_vectors[i].exp_out,
                                KASUMI_DIGEST_SIZE);
                        printf("direction %d\n", direction);
                        printf("F9 integrity %d Failed\n", i);
                        goto exit;
                }
        }

        ret = 0;
        printf("[%s]:     PASS, for %d single buffers.\n", __FUNCTION__, i);
exit:
        free(pKey);
        free(pKeySched);
        return ret;
}

int kasumi_test(const enum arch_type arch, struct MB_MGR *mb_mgr)
{
        int status = 0;

        /* Do not run the tests for aesni emulation */
        if (arch == ARCH_NO_AESNI)
                return 0;

        if (validate_kasumi_f8_1_block(mb_mgr)) {
                printf("validate_kasumi_f8_1_block: FAIL\n");
                status = 1;
        }

        if (validate_kasumi_f8_1_bitblock(mb_mgr)) {
                printf("validate_kasumi_f8_1_bitblock: FAIL\n");
                status = 1;
        }
        if (validate_kasumi_f8_1_bitblock_offset(mb_mgr)) {
                printf("validate_kasumi_f8_1_bitblock_linear: FAIL\n");
                status = 1;
        }

        if (validate_kasumi_f8_2_blocks(mb_mgr)) {
                printf("validate_kasumi_f8_2_blocks: FAIL\n");
                status = 1;
        }
        if (validate_kasumi_f8_3_blocks(mb_mgr)) {
                printf("<F12>validate_kasumi_f8_3_blocks: FAIL\n");
                status = 1;
        }
        if (validate_kasumi_f8_4_blocks(mb_mgr)) {
                printf("validate_kasumi_f8_4_blocks: FAIL\n");
                status = 1;
        }

        if (validate_kasumi_f8_n_blocks(mb_mgr)) {
                printf("validate_kasumi_f8_n_blocks: FAIL\n");
                status = 1;
        }
        if (validate_kasumi_f9(mb_mgr)) {
                printf("validate_kasumi_f9: FAIL\n");
                status = 1;
        }
        if (validate_kasumi_f9_user(mb_mgr)) {
                printf("validate_kasumi_f9_user: FAIL\n");
                status = 1;
        }
        if (!status)
                printf("ALL TESTS PASSED.\n");
        else
                printf("WE HAVE TEST FAILURES !\n");

        return status;
}
