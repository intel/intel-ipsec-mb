/*******************************************************************************
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
*******************************************************************************/

/*-----------------------------------------------------------------------
* zuc_avx.c
*-----------------------------------------------------------------------
* An implementation of ZUC, the core algorithm for the
* 3GPP Confidentiality and Integrity algorithms.
*
*-----------------------------------------------------------------------*/

#include <string.h>

#include "include/zuc_internal.h"
#include "include/save_xmms.h"
#include "intel-ipsec-mb.h"

#define SAVE_XMMS       save_xmms_avx
#define RESTORE_XMMS    restore_xmms_avx

void zuc_eea3_1_buffer_avx(const void *pKey,
                           const void *pIv,
                           const void *pBufferIn,
                           void *pBufferOut,
                           const uint32_t length)
{
        DECLARE_ALIGNED(ZucState_t zucState, 64);
        DECLARE_ALIGNED(uint8_t keyStream[64], 64);
        /* buffer to store 64 bytes of keystream */
        DECLARE_ALIGNED(uint8_t tempSrc[64], 64);
        DECLARE_ALIGNED(uint8_t tempDst[64], 64);
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif

        const uint64_t *pIn64 = NULL;
        const uint8_t *pIn8 = NULL;
        uint8_t *pOut8 = NULL;
        uint64_t *pOut64 = NULL, *pKeyStream64 = NULL;
        uint64_t *pTemp64 = NULL, *pdstTemp64 = NULL;

        uint32_t numKeyStreamsPerPkt = length/ ZUC_KEYSTR_LEN;
        uint32_t numBytesLeftOver = length % ZUC_KEYSTR_LEN;

        /* need to set the LFSR state to zero */
        memset(&zucState, 0, sizeof(ZucState_t));

        /* initialize the zuc state */
        asm_ZucInitialization(pKey, pIv, &(zucState));

        /* Loop Over all the Quad-Words in input buffer and XOR with the 64bits
         * of generated keystream */
        pOut64 = (uint64_t *) pBufferOut;
        pIn64 = (const uint64_t *) pBufferIn;

        while (numKeyStreamsPerPkt--) {
                /* Generate the key stream 64 bytes at a time */
                asm_ZucGenKeystream64B((uint32_t *) &keyStream[0], &zucState);

                /* XOR The Keystream generated with the input buffer here */
                pKeyStream64 = (uint64_t *) keyStream;
                ZUC_XOR_KEYSTREAM(pIn64, pOut64, pKeyStream64);
        }

        /* Check for remaining 0 to 7 bytes */
        pIn8 = (const uint8_t *) pBufferIn;
        pOut8 = (uint8_t *) pBufferOut;
        if(numBytesLeftOver) {
                asm_ZucGenKeystream64B((uint32_t *) &keyStream[0], &zucState);

                /* copy the remaining bytes into temporary buffer and XOR with
                 * the 64-bytes of keystream. Then copy on the valid bytes back
                 * to the output buffer */

                memcpy(&tempSrc[0], &pIn8[length - numBytesLeftOver],
                       numBytesLeftOver);
                pKeyStream64 = (uint64_t *) &keyStream[0];
                pTemp64 = (uint64_t *) &tempSrc[0];
                pdstTemp64 = (uint64_t *) &tempDst[0];

                ZUC_XOR_KEYSTREAM(pTemp64, pdstTemp64 ,pKeyStream64);
                memcpy(&pOut8[length - numBytesLeftOver], &tempDst[0],
                       numBytesLeftOver);

        }
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}

void zuc_eea3_4_buffer_avx(const void *pKey[4], const void *pIv[4],
                           const void *pBufferIn[4], void *pBufferOut[4],
                           const uint32_t length[4])
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif

        DECLARE_ALIGNED(ZucState4_t state, 64);
        DECLARE_ALIGNED(ZucState_t singlePktState, 64);
        unsigned int i = 0;
        /* Calculate the minimum input packet size */
        uint32_t bytes1 = (length[0] < length[1] ?
                           length[0] : length[1]);
        uint32_t bytes2 = (length[2] < length[3] ?
                           length[2] : length[3]);
        /* min number of bytes */
        uint32_t bytes = (bytes1 < bytes2) ? bytes1 : bytes2;
        uint32_t numKeyStreamsPerPkt = bytes/ZUC_KEYSTR_LEN;
        uint32_t remainBytes[4] = {0};
        DECLARE_ALIGNED(uint8_t keyStr1[64], 64);
        DECLARE_ALIGNED(uint8_t keyStr2[64], 64);
        DECLARE_ALIGNED(uint8_t keyStr3[64], 64);
        DECLARE_ALIGNED(uint8_t keyStr4[64], 64);
        DECLARE_ALIGNED(uint8_t tempSrc[64], 64);
        DECLARE_ALIGNED(uint8_t tempDst[64], 64);
        /* structure to store the 4 keys */
        DECLARE_ALIGNED(ZucKey4_t keys, 64);
        /* strucutre to store the 4 IV's */
        DECLARE_ALIGNED(ZucIv4_t ivs, 64);
        uint32_t numBytesLeftOver = 0;
        const uint8_t *pTempBufInPtr = NULL;
        uint8_t *pTempBufOutPtr = NULL;

        const uint64_t *pIn64_0 = NULL;
        const uint64_t *pIn64_1 = NULL;
        const uint64_t *pIn64_2 = NULL;
        const uint64_t *pIn64_3 = NULL;
        uint64_t *pOut64_0 = NULL;
        uint64_t *pOut64_1 = NULL;
        uint64_t *pOut64_2 = NULL;
        uint64_t *pOut64_3 = NULL;
        uint64_t *pTempSrc64 = NULL;
        uint64_t *pTempDst64 = NULL;
        uint64_t *pKeyStream64 = NULL;

        /* rounded down minimum length */
        bytes = numKeyStreamsPerPkt * ZUC_KEYSTR_LEN;

        /* Need to set the LFSR state to zero */
        memset(&state, 0, sizeof(ZucState4_t));

        /* Calculate the number of bytes left over for each packet */
        for (i=0; i< 4; i++)
                remainBytes[i] = length[i] - bytes;

        /* Setup the Keys */
        keys.pKey1 = pKey[0];
        keys.pKey2 = pKey[1];
        keys.pKey3 = pKey[2];
        keys.pKey4 = pKey[3];

        /* setup the IV's */
        ivs.pIv1 = pIv[0];
        ivs.pIv2 = pIv[1];
        ivs.pIv3 = pIv[2];
        ivs.pIv4 = pIv[3];

        asm_ZucInitialization_4_avx( &keys,  &ivs, &state);

        pOut64_0 = (uint64_t *) pBufferOut[0];
        pOut64_1 = (uint64_t *) pBufferOut[1];
        pOut64_2 = (uint64_t *) pBufferOut[2];
        pOut64_3 = (uint64_t *) pBufferOut[3];

        pIn64_0 = (const uint64_t *) pBufferIn[0];
        pIn64_1 = (const uint64_t *) pBufferIn[1];
        pIn64_2 = (const uint64_t *) pBufferIn[2];
        pIn64_3 = (const uint64_t *) pBufferIn[3];

        /* Loop for 64 bytes at a time generating 4 key-streams per loop */
        while (numKeyStreamsPerPkt) {
                /* Generate 64 bytes at a time */
                asm_ZucGenKeystream64B_4_avx(&state,
                                             (uint32_t *) keyStr1,
                                             (uint32_t *) keyStr2,
                                             (uint32_t *) keyStr3,
                                             (uint32_t *) keyStr4);

                /* XOR the KeyStream with the input buffers and store in output
                 * buffer*/
                pKeyStream64 = (uint64_t *) keyStr1;
                ZUC_XOR_KEYSTREAM(pIn64_0, pOut64_0, pKeyStream64);

                pKeyStream64 = (uint64_t *) keyStr2;
                ZUC_XOR_KEYSTREAM(pIn64_1, pOut64_1, pKeyStream64);

                pKeyStream64 = (uint64_t *) keyStr3;
                ZUC_XOR_KEYSTREAM(pIn64_2, pOut64_2, pKeyStream64);

                pKeyStream64 = (uint64_t *) keyStr4;
                ZUC_XOR_KEYSTREAM(pIn64_3, pOut64_3, pKeyStream64);

                /* Update keystream count */
                numKeyStreamsPerPkt--;

        }

        /* process each packet separately for the remaining bytes */
        for (i = 0; i < 4; i++) {
                if (remainBytes[i]) {
                        /* need to copy the zuc state to single packet state */
                        singlePktState.lfsrState[0] = state.lfsrState[0][i];
                        singlePktState.lfsrState[1] = state.lfsrState[1][i];
                        singlePktState.lfsrState[2] = state.lfsrState[2][i];
                        singlePktState.lfsrState[3] = state.lfsrState[3][i];
                        singlePktState.lfsrState[4] = state.lfsrState[4][i];
                        singlePktState.lfsrState[5] = state.lfsrState[5][i];
                        singlePktState.lfsrState[6] = state.lfsrState[6][i];
                        singlePktState.lfsrState[7] = state.lfsrState[7][i];
                        singlePktState.lfsrState[8] = state.lfsrState[8][i];
                        singlePktState.lfsrState[9] = state.lfsrState[9][i];
                        singlePktState.lfsrState[10] = state.lfsrState[10][i];
                        singlePktState.lfsrState[11] = state.lfsrState[11][i];
                        singlePktState.lfsrState[12] = state.lfsrState[12][i];
                        singlePktState.lfsrState[13] = state.lfsrState[13][i];
                        singlePktState.lfsrState[14] = state.lfsrState[14][i];
                        singlePktState.lfsrState[15] = state.lfsrState[15][i];

                        singlePktState.fR1 = state.fR1[i];
                        singlePktState.fR2 = state.fR2[i];

                        singlePktState.bX0 = state.bX0[i];
                        singlePktState.bX1 = state.bX1[i];
                        singlePktState.bX2 = state.bX2[i];
                        singlePktState.bX3 = state.bX3[i];

                        numKeyStreamsPerPkt = remainBytes[i] / ZUC_KEYSTR_LEN;
                        numBytesLeftOver = remainBytes[i]  % ZUC_KEYSTR_LEN;

                        pTempBufInPtr = pBufferIn[i];
                        pTempBufOutPtr = pBufferOut[i];

                        /* update the output and input pointers here to point
                         * to the i'th buffers */
                        pOut64_0 = (uint64_t *) &pTempBufOutPtr[length[i] -
                                                                remainBytes[i]];
                        pIn64_0 = (const uint64_t *) &pTempBufInPtr[length[i] -
                                                                remainBytes[i]];

                        while (numKeyStreamsPerPkt--) {
                                /* Generate the key stream 64 bytes at a time */
                                asm_ZucGenKeystream64B((uint32_t *) keyStr1,
                                                       &singlePktState);
                                pKeyStream64 = (uint64_t *) keyStr1;
                                ZUC_XOR_KEYSTREAM(pIn64_0, pOut64_0,
                                                      pKeyStream64);
                        }


                        /* Check for remaining 0 to 7 bytes */
                        if (numBytesLeftOver) {
                                asm_ZucGenKeystream64B((uint32_t *) &keyStr1,
                                                       &singlePktState);
                                uint32_t offset = length[i] - numBytesLeftOver;

                                /* copy the remaining bytes into temporary
                                 * buffer and XOR with the 64-bytes of
                                 * keystream. Then copy on the valid bytes back
                                 * to the output buffer */
                                memcpy(&tempSrc[0], &pTempBufInPtr[offset],
                                       numBytesLeftOver);
                                memset(&tempSrc[numBytesLeftOver], 0,
                                       64 - numBytesLeftOver);

                                pKeyStream64 = (uint64_t *) &keyStr1[0];
                                pTempSrc64 = (uint64_t *) &tempSrc[0];
                                pTempDst64 = (uint64_t *) &tempDst[0];
                                ZUC_XOR_KEYSTREAM(pTempSrc64, pTempDst64,
                                                      pKeyStream64);

                                memcpy(&pTempBufOutPtr[offset],
                                       &tempDst[0], numBytesLeftOver);
                        }
                }
        }
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}


void zuc_eea3_n_buffer_avx(const void *pKey[], const void *pIv[],
                           const void *pBufferIn[], void *pBufferOut[],
                           const uint32_t length[],
                           const uint32_t numBuffers)
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif

        int i =0;
        int packetCount = numBuffers;

        while(packetCount >= 4) {
                packetCount -=4;
                zuc_eea3_4_buffer_avx(&pKey[i],
                                      &pIv[i],
                                      &pBufferIn[i],
                                      &pBufferOut[i],
                                      &length[i]);
                i+=4;
        }

        while(packetCount--) {
                zuc_eea3_1_buffer_avx(pKey[i],
                                      pIv[i],
                                      pBufferIn[i],
                                      pBufferOut[i],
                                      length[i]);
                i++;
        }
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}

static inline uint64_t rotate_left(uint64_t u, size_t r)
{
        return (((u) << (r)) | ((u) >> (64 - (r))));
}

static inline uint64_t load_uint64(const void *ptr)
{
        return *((const uint64_t *)ptr);
}

void zuc_eia3_1_buffer_avx(const void *pKey,
                           const void *pIv,
                           const void *pBufferIn,
                           const uint32_t lengthInBits,
                           uint32_t *pMacI)
{
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
        DECLARE_ALIGNED(ZucState_t zucState, 64);
        DECLARE_ALIGNED(uint32_t keyStream[16 * 2], 64);
        const uint32_t keyStreamLengthInBits = ZUC_KEYSTR_LEN * 8;
        /* generate a key-stream 2 words longer than the input message */
        const uint32_t N = lengthInBits + (2 * ZUC_WORD);
        uint32_t L = (N + 31) / ZUC_WORD;
        uint32_t *pZuc = (uint32_t *) &keyStream[0];
        uint32_t remainingBits = lengthInBits;
        uint32_t T = 0;
        const uint8_t *pIn8 = (const uint8_t *) pBufferIn;

        memset(&zucState, 0, sizeof(ZucState_t));

        asm_ZucInitialization(pKey, pIv, &(zucState));
        asm_ZucGenKeystream64B(pZuc, &zucState);

        /* loop over the message bits */
        while (remainingBits >= keyStreamLengthInBits) {
                remainingBits -=  keyStreamLengthInBits;
                L -= (keyStreamLengthInBits / 32);
                /* Generate the next key stream 8 bytes or 64 bytes */
                if (!remainingBits)
                        asm_ZucGenKeystream8B(&keyStream[16], &zucState);
                else
                        asm_ZucGenKeystream64B(&keyStream[16], &zucState);
                T = asm_Eia3Round64BAVX(T, &keyStream[0], pIn8);
                memcpy(&keyStream[0], &keyStream[16], 16 * sizeof(uint32_t));
                pIn8 = &pIn8[ZUC_KEYSTR_LEN];
        }

        /*
         * If remaining bits has more than 14 ZUC WORDS (double words),
         * keystream needs to have up to another 2 ZUC WORDS (8B)
         */
        if (remainingBits > (14 * 32))
                asm_ZucGenKeystream8B(&keyStream[16], &zucState);
        T ^= asm_Eia3RemainderAVX(&keyStream[0], pIn8, remainingBits);
        T ^= rotate_left(load_uint64(&keyStream[remainingBits / 32]),
                         remainingBits % 32);

        /* save the final MAC-I result */
        uint32_t keyBlock = keyStream[L - 1];
        *pMacI = bswap4(T ^ keyBlock);
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}
