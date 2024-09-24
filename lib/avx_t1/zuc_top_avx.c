/*******************************************************************************
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
#include "include/wireless_common.h"
#include "include/save_xmms.h"
#include "include/clear_regs_mem.h"
#include "intel-ipsec-mb.h"
#include "include/error.h"

#define SAVE_XMMS               save_xmms_avx
#define RESTORE_XMMS            restore_xmms_avx
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_avx

#define NUM_AVX_BUFS     4
#define KEYSTR_ROUND_LEN 16

IMB_DLL_LOCAL
void
_zuc_eea3_4_buffer_avx(const void *const pKey[NUM_AVX_BUFS], const void *const pIv[NUM_AVX_BUFS],
                       const void *const pBufferIn[NUM_AVX_BUFS], void *pBufferOut[NUM_AVX_BUFS],
                       const uint32_t length[NUM_AVX_BUFS])
{
        DECLARE_ALIGNED(ZucState4_t state, 16);
        DECLARE_ALIGNED(ZucState_t singlePktState, 16);
        unsigned int i;
        /* Calculate the minimum input packet size */
        uint32_t bytes1 = (length[0] < length[1] ? length[0] : length[1]);
        uint32_t bytes2 = (length[2] < length[3] ? length[2] : length[3]);
        /* min number of bytes */
        uint32_t bytes = (bytes1 < bytes2) ? bytes1 : bytes2;
        DECLARE_ALIGNED(uint16_t remainBytes[NUM_AVX_BUFS], 16) = { 0 };
        DECLARE_ALIGNED(uint8_t keyStr[NUM_AVX_BUFS][KEYSTR_ROUND_LEN], 64);
        /* structure to store the 4 keys */
        DECLARE_ALIGNED(ZucKey4_t keys, 64);
        /* structure to store the 4 IV's */
        DECLARE_ALIGNED(uint8_t ivs[NUM_AVX_BUFS * 32], 16);
        const uint8_t *pTempBufInPtr = NULL;
        uint8_t *pTempBufOutPtr = NULL;
        DECLARE_ALIGNED(const uint64_t *pIn64[NUM_AVX_BUFS], 16) = { NULL };
        DECLARE_ALIGNED(uint64_t * pOut64[NUM_AVX_BUFS], 16) = { NULL };
        uint64_t *pKeyStream64 = NULL;

        /*
         * Calculate the number of bytes left over for each packet,
         * and setup the Keys and IVs
         */
        for (i = 0; i < NUM_AVX_BUFS; i++) {
                remainBytes[i] = length[i];
                keys.pKeys[i] = pKey[i];
                memcpy(ivs + i * 32, pIv[i], 16);
        }

        asm_ZucInitialization_4_avx(&keys, ivs, &state);

        for (i = 0; i < NUM_AVX_BUFS; i++) {
                pOut64[i] = (uint64_t *) pBufferOut[i];
                pIn64[i] = (const uint64_t *) pBufferIn[i];
        }

        /* Encrypt common length of all buffers */
        asm_ZucCipher_4_avx(&state, pIn64, pOut64, remainBytes, (uint16_t) bytes);

        /* process each packet separately for the remaining bytes */
        for (i = 0; i < NUM_AVX_BUFS; i++) {
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

                        uint32_t numKeyStreamsPerPkt = remainBytes[i] / KEYSTR_ROUND_LEN;
                        const uint32_t numBytesLeftOver = remainBytes[i] % KEYSTR_ROUND_LEN;

                        pTempBufInPtr = pBufferIn[i];
                        pTempBufOutPtr = pBufferOut[i];

                        /* update the output and input pointers here to point
                         * to the i'th buffers */
                        pOut64[0] = (uint64_t *) &pTempBufOutPtr[length[i] - remainBytes[i]];
                        pIn64[0] = (const uint64_t *) &pTempBufInPtr[length[i] - remainBytes[i]];

                        while (numKeyStreamsPerPkt--) {
                                /* Generate the key stream 16 bytes at a time */
                                asm_ZucGenKeystream16B_avx((uint32_t *) keyStr[0], &singlePktState);
                                pKeyStream64 = (uint64_t *) keyStr[0];
                                asm_XorKeyStream16B_avx(pIn64[0], pOut64[0], pKeyStream64);
                                pIn64[0] += 2;
                                pOut64[0] += 2;
                        }

                        /* Check for remaining 0 to 15 bytes */
                        if (numBytesLeftOver) {
                                DECLARE_ALIGNED(uint8_t tempSrc[16], 64);
                                DECLARE_ALIGNED(uint8_t tempDst[16], 64);
                                uint64_t *pTempSrc64;
                                uint64_t *pTempDst64;
                                uint32_t offset = length[i] - numBytesLeftOver;
                                const uint64_t num4BRounds = ((numBytesLeftOver - 1) / 4) + 1;

                                asm_ZucGenKeystream_avx((uint32_t *) &keyStr[0], &singlePktState,
                                                        num4BRounds);
                                /* copy the remaining bytes into temporary
                                 * buffer and XOR with the 16 bytes of
                                 * keystream. Then copy on the valid bytes back
                                 * to the output buffer */
                                memcpy(&tempSrc[0], &pTempBufInPtr[offset], numBytesLeftOver);
                                memset(&tempSrc[numBytesLeftOver], 0, 16 - numBytesLeftOver);

                                pKeyStream64 = (uint64_t *) &keyStr[0][0];
                                pTempSrc64 = (uint64_t *) &tempSrc[0];
                                pTempDst64 = (uint64_t *) &tempDst[0];
                                asm_XorKeyStream16B_avx(pTempSrc64, pTempDst64, pKeyStream64);

                                memcpy(&pTempBufOutPtr[offset], &tempDst[0], numBytesLeftOver);
#ifdef SAFE_DATA
                                clear_mem(tempSrc, sizeof(tempSrc));
                                clear_mem(tempDst, sizeof(tempDst));
#endif
                        }
                }
        }
#ifdef SAFE_DATA
        /* Clear sensitive data in stack */
        clear_mem(keyStr, sizeof(keyStr));
        clear_mem(&singlePktState, sizeof(singlePktState));
        clear_mem(&state, sizeof(state));
        clear_mem(&keys, sizeof(keys));
#endif
}

IMB_DLL_LOCAL
void
_zuc_eia3_4_buffer_avx(const void *const pKey[NUM_AVX_BUFS], const void *const pIv[NUM_AVX_BUFS],
                       const void *const pBufferIn[NUM_AVX_BUFS],
                       const uint32_t lengthInBits[NUM_AVX_BUFS], uint32_t *pMacI[NUM_AVX_BUFS])
{
        unsigned int i;
        DECLARE_ALIGNED(ZucState4_t state, 64);
        DECLARE_ALIGNED(ZucState_t singlePktState, 64);
        DECLARE_ALIGNED(uint8_t keyStr[NUM_AVX_BUFS][2 * KEYSTR_ROUND_LEN], 64);
        /* structure to store the 4 keys */
        DECLARE_ALIGNED(ZucKey4_t keys, 64);
        /* structure to store the 4 IV's */
        DECLARE_ALIGNED(uint8_t ivs[NUM_AVX_BUFS * 32], 16);
        const uint8_t *pIn8[NUM_AVX_BUFS] = { NULL };
        uint32_t remainCommonBits;
        uint32_t numKeyStr = 0;
        uint32_t T[NUM_AVX_BUFS];
        const uint32_t keyStreamLengthInBits = KEYSTR_ROUND_LEN * 8;
        DECLARE_ALIGNED(uint32_t * pKeyStrArr[NUM_AVX_BUFS], 16) = { NULL };
        unsigned int allCommonBits;

        memset(keyStr, 0, sizeof(keyStr));
        memset(T, 0, sizeof(T));

        /* Check if all lengths are equal */
        if ((lengthInBits[0] == lengthInBits[1]) && (lengthInBits[0] == lengthInBits[2]) &&
            (lengthInBits[0] == lengthInBits[3])) {
                remainCommonBits = lengthInBits[0];
                allCommonBits = 1;
        } else {
                /* Calculate the minimum input packet size */
                uint32_t bits1 =
                        (lengthInBits[0] < lengthInBits[1] ? lengthInBits[0] : lengthInBits[1]);
                uint32_t bits2 =
                        (lengthInBits[2] < lengthInBits[3] ? lengthInBits[2] : lengthInBits[3]);

                remainCommonBits = (bits1 < bits2) ? bits1 : bits2;
                allCommonBits = 0;
        }

        for (i = 0; i < NUM_AVX_BUFS; i++) {
                pIn8[i] = (const uint8_t *) pBufferIn[i];
                pKeyStrArr[i] = (uint32_t *) &keyStr[i][0];
                keys.pKeys[i] = pKey[i];
                memcpy(ivs + i * 32, pIv[i], 16);
        }

        asm_ZucInitialization_4_avx(&keys, ivs, &state);

        /* Generate 16 bytes at a time */
        asm_ZucGenKeystream16B_4_avx(&state, pKeyStrArr);

        /* Point at the next 16 bytes of the key */
        for (i = 0; i < NUM_AVX_BUFS; i++)
                pKeyStrArr[i] = (uint32_t *) &keyStr[i][KEYSTR_ROUND_LEN];

        /* loop over the message bits */
        while (remainCommonBits >= keyStreamLengthInBits) {
                remainCommonBits -= keyStreamLengthInBits;
                numKeyStr++;
                /* Generate the next key stream 8 bytes or 16 bytes */
                if (!remainCommonBits && allCommonBits)
                        asm_ZucGenKeystream8B_4_avx(&state, pKeyStrArr);
                else
                        asm_ZucGenKeystream16B_4_avx(&state, pKeyStrArr);
                for (i = 0; i < NUM_AVX_BUFS; i++) {
                        asm_Eia3Round16B_avx(&T[i], keyStr[i], pIn8[i], 4);
                        pIn8[i] = &pIn8[i][KEYSTR_ROUND_LEN];
                }
        }

        /* Process each packet separately for the remaining bits */
        for (i = 0; i < NUM_AVX_BUFS; i++) {
                uint32_t remainBits = lengthInBits[i] - numKeyStr * keyStreamLengthInBits;
                uint32_t *keyStr32 = (uint32_t *) keyStr[i];

                /* If remaining bits are more than 8 bytes, we need to generate
                 * at least 8B more of keystream, so we need to copy
                 * the zuc state to single packet state first */
                if (remainBits > (2 * 32)) {
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
                }

                while (remainBits >= keyStreamLengthInBits) {
                        remainBits -= keyStreamLengthInBits;

                        /* Generate the next key stream 8 bytes or 16 bytes */
                        if (!remainBits)
                                asm_ZucGenKeystream8B_avx(&keyStr32[4], &singlePktState);
                        else
                                asm_ZucGenKeystream16B_avx(&keyStr32[4], &singlePktState);
                        asm_Eia3Round16B_avx(&T[i], keyStr32, pIn8[i], 4);
                        pIn8[i] = &pIn8[i][KEYSTR_ROUND_LEN];
                }

                /*
                 * If remaining bits has more than 2 ZUC WORDS (double words),
                 * keystream needs to have up to another 2 ZUC WORDS (8B)
                 */

                if (remainBits > (2 * 32))
                        asm_ZucGenKeystream8B_avx(&keyStr32[4], &singlePktState);

                asm_Eia3Remainder_avx(&T[i], keyStr32, pIn8[i], remainBits, 128, 4);
                /* save the final MAC-I result */
                *(pMacI[i]) = T[i];
        }

#ifdef SAFE_DATA
        /* Clear sensitive data (in registers and stack) */
        clear_mem(keyStr, sizeof(keyStr));
        clear_mem(&singlePktState, sizeof(singlePktState));
        clear_mem(&state, sizeof(state));
        clear_mem(&keys, sizeof(keys));
#endif
}
