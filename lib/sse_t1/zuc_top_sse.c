/*******************************************************************************
  Copyright (c) 2009-2024, Intel Corporation

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
 * zuc_sse.c
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
#include "include/arch_sse_type1.h"

#define SAVE_XMMS               save_xmms
#define RESTORE_XMMS            restore_xmms
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_sse

#define NUM_SSE_BUFS     4
#define KEYSTR_ROUND_LEN 16

static inline void
init_4(ZucKey4_t *keys, const uint8_t *ivs, ZucState4_t *state, const unsigned use_gfni)
{
        if (use_gfni)
                asm_ZucInitialization_4_gfni_sse(keys, ivs, state);
        else
                asm_ZucInitialization_4_sse(keys, ivs, state);
}

static inline void
eia3_round16B(void *T, const void *ks, const void *data, const unsigned use_gfni)
{
        if (use_gfni)
                asm_Eia3Round16B_gfni_sse(T, ks, data);
        else
                asm_Eia3Round16B_sse(T, ks, data);
}

static inline void
eia3_remainder(void *T, const void *ks, const void *data, const uint64_t n_bits,
               const unsigned use_gfni)
{
        if (use_gfni)
                asm_Eia3Remainder_gfni_sse(T, ks, data, n_bits);
        else
                asm_Eia3Remainder_sse(T, ks, data, n_bits);
}

static inline void
keygen_4(ZucState4_t *state, uint32_t **pKeyStrArr, const uint64_t numKeyStrBytes,
         const unsigned use_gfni)
{
        if (use_gfni) {
                if (numKeyStrBytes == 4)
                        asm_ZucGenKeystream4B_4_gfni_sse(state, pKeyStrArr);
                else if (numKeyStrBytes == 8)
                        asm_ZucGenKeystream8B_4_gfni_sse(state, pKeyStrArr);
                else /* 16 */
                        asm_ZucGenKeystream16B_4_gfni_sse(state, pKeyStrArr);
        } else {
                if (numKeyStrBytes == 4)
                        asm_ZucGenKeystream4B_4_sse(state, pKeyStrArr);
                else if (numKeyStrBytes == 8)
                        asm_ZucGenKeystream8B_4_sse(state, pKeyStrArr);
                else /* 16 */
                        asm_ZucGenKeystream16B_4_sse(state, pKeyStrArr);
        }
}

IMB_DLL_LOCAL
void
_zuc_eea3_4_buffer_sse(const void *const pKey[NUM_SSE_BUFS], const void *const pIv[NUM_SSE_BUFS],
                       const void *const pBufferIn[NUM_SSE_BUFS], void *pBufferOut[NUM_SSE_BUFS],
                       const uint32_t length[NUM_SSE_BUFS], const unsigned use_gfni)
{
        DECLARE_ALIGNED(ZucState4_t state, 64);
        DECLARE_ALIGNED(ZucState_t singlePktState, 64);
        unsigned int i;
        /* Calculate the minimum input packet size */
        uint32_t bytes1 = (length[0] < length[1] ? length[0] : length[1]);
        uint32_t bytes2 = (length[2] < length[3] ? length[2] : length[3]);
        /* min number of bytes */
        uint32_t bytes = (bytes1 < bytes2) ? bytes1 : bytes2;
        DECLARE_ALIGNED(uint16_t remainBytes[NUM_SSE_BUFS], 16) = { 0 };
        DECLARE_ALIGNED(uint8_t keyStr[NUM_SSE_BUFS][KEYSTR_ROUND_LEN], 64);
        /* structure to store the 4 keys */
        DECLARE_ALIGNED(ZucKey4_t keys, 64);
        /* structure to store the 4 IV's */
        DECLARE_ALIGNED(uint8_t ivs[NUM_SSE_BUFS * 32], 16);
        const uint8_t *pTempBufInPtr = NULL;
        uint8_t *pTempBufOutPtr = NULL;
        DECLARE_ALIGNED(const uint64_t *pIn64[NUM_SSE_BUFS], 64) = { NULL };
        DECLARE_ALIGNED(uint64_t * pOut64[NUM_SSE_BUFS], 64) = { NULL };
        uint64_t *pKeyStream64 = NULL;

        /*
         * Calculate the number of bytes left over for each packet,
         * and setup the Keys and IVs
         */
        for (i = 0; i < NUM_SSE_BUFS; i++) {
                remainBytes[i] = length[i];
                keys.pKeys[i] = pKey[i];
                memcpy(ivs + i * 16, pIv[i], 16);
        }

        init_4(&keys, ivs, &state, use_gfni);

        for (i = 0; i < NUM_SSE_BUFS; i++) {
                pOut64[i] = (uint64_t *) pBufferOut[i];
                pIn64[i] = (const uint64_t *) pBufferIn[i];
        }

        /* Encrypt common length of all buffers */
        if (use_gfni)
                asm_ZucCipher_4_gfni_sse(&state, pIn64, pOut64, remainBytes, (uint16_t) bytes);
        else
                asm_ZucCipher_4_sse(&state, pIn64, pOut64, remainBytes, (uint16_t) bytes);

        /* process each packet separately for the remaining bytes */
        for (i = 0; i < NUM_SSE_BUFS; i++) {
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
                                asm_ZucGenKeystream16B_sse((uint32_t *) keyStr[0], &singlePktState);
                                pKeyStream64 = (uint64_t *) keyStr[0];
                                asm_XorKeyStream16B_sse(pIn64[0], pOut64[0], pKeyStream64);
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

                                asm_ZucGenKeystream_sse((uint32_t *) &keyStr[0], &singlePktState,
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
                                asm_XorKeyStream16B_sse(pTempSrc64, pTempDst64, pKeyStream64);

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

void
zuc_eea3_1_buffer_sse(IMB_MGR *mgr, const void *pKey, const void *pIv, const void *pBufferIn,
                      void *pBufferOut, const uint32_t length)
{
        IMB_JOB *job;

#ifdef SAFE_PARAM
        imb_set_errno(NULL, 0);
        /* Check for NULL pointers */
        if (mgr == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }

        if (pKey == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }

        if (pIv == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_IV);
                return;
        }

        if (pBufferIn == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }

        if (pBufferOut == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_DST);
                return;
        }

        /* Check input data is in range of supported length */
        if (length < ZUC_MIN_BYTELEN || length > ZUC_MAX_BYTELEN) {
                imb_set_errno(NULL, IMB_ERR_CIPH_LEN);
                return;
        }
#endif
        if (IMB_FLUSH_JOB(mgr) != NULL) {
                imb_set_errno(mgr, IMB_ERR_QUEUE_SPACE);
                return;
        }

        job = IMB_GET_NEXT_JOB(mgr);
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_CIPHER_HASH;
        job->cipher_mode = IMB_CIPHER_ZUC_EEA3;
        job->enc_keys = pKey;
        job->key_len_in_bytes = IMB_ZUC_KEY_LEN_IN_BYTES;
        job->iv = (const uint8_t *) pIv;
        job->iv_len_in_bytes = IMB_ZUC_IV_LEN_IN_BYTES;
        job->src = (const uint8_t *) pBufferIn;
        job->dst = (uint8_t *) pBufferOut;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = length;
        job->hash_alg = IMB_AUTH_NULL;

        job = IMB_SUBMIT_JOB(mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mgr);
        if (job == NULL)
                imb_set_errno(mgr, IMB_ERR_NULL_JOB);
        else if (job->status != IMB_STATUS_COMPLETED)
                imb_set_errno(mgr, job->status);
}

static inline void
_zuc_eea3_4_buffer(const void *const pKey[NUM_SSE_BUFS], const void *const pIv[NUM_SSE_BUFS],
                   const void *const pBufferIn[NUM_SSE_BUFS], void *pBufferOut[NUM_SSE_BUFS],
                   const uint32_t length[NUM_SSE_BUFS], const unsigned use_gfni)
{
#ifndef LINUX
        DECLARE_ALIGNED(imb_uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif
#ifdef SAFE_PARAM
        unsigned int i;

        imb_set_errno(NULL, 0);

        /* Check for NULL pointers */
        if (pKey == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }

        if (pIv == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_IV);
                return;
        }

        if (pBufferIn == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }

        if (pBufferOut == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_DST);
                return;
        }

        if (length == NULL) {
                imb_set_errno(NULL, IMB_ERR_CIPH_LEN);
                return;
        }

        /* Check for NULL pointers and lengths for each buffer */
        for (i = 0; i < NUM_SSE_BUFS; i++) {
                if (pKey[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                        return;
                }

                if (pIv[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_IV);
                        return;
                }

                if (pBufferIn[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                        return;
                }

                if (pBufferOut[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_DST);
                        return;
                }

                /* Check input data is in range of supported length */
                if (length[i] < ZUC_MIN_BYTELEN || length[i] > ZUC_MAX_BYTELEN) {
                        imb_set_errno(NULL, IMB_ERR_CIPH_LEN);
                        return;
                }
        }
#endif

        _zuc_eea3_4_buffer_sse(pKey, pIv, pBufferIn, pBufferOut, length, use_gfni);

#ifdef SAFE_DATA
        /* Clear sensitive data in registers */
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}

void
zuc_eea3_4_buffer_sse(const void *const pKey[NUM_SSE_BUFS], const void *const pIv[NUM_SSE_BUFS],
                      const void *const pBufferIn[NUM_SSE_BUFS], void *pBufferOut[NUM_SSE_BUFS],
                      const uint32_t length[NUM_SSE_BUFS])
{
        _zuc_eea3_4_buffer(pKey, pIv, pBufferIn, pBufferOut, length, 0);
}

void
zuc_eea3_4_buffer_gfni_sse(const void *const pKey[NUM_SSE_BUFS],
                           const void *const pIv[NUM_SSE_BUFS],
                           const void *const pBufferIn[NUM_SSE_BUFS],
                           void *pBufferOut[NUM_SSE_BUFS], const uint32_t length[NUM_SSE_BUFS])
{
        _zuc_eea3_4_buffer(pKey, pIv, pBufferIn, pBufferOut, length, 1);
}

void
zuc_eea3_n_buffer_sse(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
                      const void *const pBufferIn[], void *pBufferOut[], const uint32_t length[],
                      const uint32_t numBuffers)
{
        IMB_JOB *job;
        uint32_t i;

#ifdef SAFE_PARAM
        imb_set_errno(NULL, 0);
        if (mgr == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
        if (pKey == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (pIv == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_IV);
                return;
        }
        if (pBufferIn == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }
        if (pBufferOut == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_DST);
                return;
        }
        if (length == NULL) {
                imb_set_errno(NULL, IMB_ERR_CIPH_LEN);
                return;
        }
        for (i = 0; i < numBuffers; i++) {
                if (pKey[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                        return;
                }
                if (pIv[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_IV);
                        return;
                }
                if (pBufferIn[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                        return;
                }
                if (pBufferOut[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_DST);
                        return;
                }
                if (length[i] < ZUC_MIN_BYTELEN || length[i] > ZUC_MAX_BYTELEN) {
                        imb_set_errno(NULL, IMB_ERR_CIPH_LEN);
                        return;
                }
        }
#endif
        if (IMB_FLUSH_JOB(mgr) != NULL) {
                imb_set_errno(mgr, IMB_ERR_QUEUE_SPACE);
                return;
        }

        uint32_t jobs_returned = 0;

        for (i = 0; i < numBuffers; i++) {
                job = IMB_GET_NEXT_JOB(mgr);
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_ZUC_EEA3;
                job->enc_keys = pKey[i];
                job->key_len_in_bytes = IMB_ZUC_KEY_LEN_IN_BYTES;
                job->iv = (const uint8_t *) pIv[i];
                job->iv_len_in_bytes = IMB_ZUC_IV_LEN_IN_BYTES;
                job->src = (const uint8_t *) pBufferIn[i];
                job->dst = (uint8_t *) pBufferOut[i];
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = length[i];
                job->hash_alg = IMB_AUTH_NULL;

                job = IMB_SUBMIT_JOB(mgr);
                if (job != NULL)
                        jobs_returned++;
        }

        while (IMB_FLUSH_JOB(mgr) != NULL)
                jobs_returned++;

        if (jobs_returned != numBuffers)
                imb_set_errno(mgr, IMB_ERR_NULL_JOB);
}

void
zuc_eea3_n_buffer_gfni_sse(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
                           const void *const pBufferIn[], void *pBufferOut[],
                           const uint32_t length[], const uint32_t numBuffers)
{
        zuc_eea3_n_buffer_sse(mgr, pKey, pIv, pBufferIn, pBufferOut, length, numBuffers);
}

void
zuc_eia3_1_buffer_sse(IMB_MGR *mgr, const void *pKey, const void *pIv, const void *pBufferIn,
                      const uint32_t lengthInBits, uint32_t *pMacI)
{
        IMB_JOB *job;

#ifdef SAFE_PARAM
        imb_set_errno(NULL, 0);
        /* Check for NULL pointers */
        if (mgr == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }

        if (pKey == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }

        if (pIv == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_IV);
                return;
        }

        if (pBufferIn == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }

        if (pMacI == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_AUTH);
                return;
        }

        /* Check input data is in range of supported length */
        if (lengthInBits < ZUC_MIN_BITLEN || lengthInBits > ZUC_MAX_BITLEN) {
                imb_set_errno(NULL, IMB_ERR_AUTH_LEN);
                return;
        }
#endif
        if (IMB_FLUSH_JOB(mgr) != NULL) {
                imb_set_errno(mgr, IMB_ERR_QUEUE_SPACE);
                return;
        }

        job = IMB_GET_NEXT_JOB(mgr);
        job->cipher_direction = IMB_DIR_ENCRYPT;
        job->chain_order = IMB_ORDER_CIPHER_HASH;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->key_len_in_bytes = IMB_ZUC_KEY_LEN_IN_BYTES;
        job->hash_alg = IMB_AUTH_ZUC_EIA3_BITLEN;
        job->src = (const uint8_t *) pBufferIn;
        job->u.ZUC_EIA3._key = (const uint8_t *) pKey;
        job->u.ZUC_EIA3._iv = (const uint8_t *) pIv;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bits = lengthInBits;
        job->auth_tag_output = (uint8_t *) pMacI;
        job->auth_tag_output_len_in_bytes = IMB_ZUC_DIGEST_LEN_IN_BYTES;

        job = IMB_SUBMIT_JOB(mgr);
        if (job == NULL)
                job = IMB_FLUSH_JOB(mgr);
        if (job == NULL)
                imb_set_errno(mgr, IMB_ERR_NULL_JOB);
        else if (job->status != IMB_STATUS_COMPLETED)
                imb_set_errno(mgr, job->status);
}

static inline void
_zuc_eia3_4_buffer_job(const void *const pKey[NUM_SSE_BUFS], const uint8_t *ivs,
                       const void *const pBufferIn[NUM_SSE_BUFS], uint32_t *pMacI[NUM_SSE_BUFS],
                       const uint16_t lengthInBits[NUM_SSE_BUFS],
                       const void *const job_in_lane[NUM_SSE_BUFS], const unsigned use_gfni)
{
        unsigned int i;
        DECLARE_ALIGNED(ZucState4_t state, 64);
        DECLARE_ALIGNED(ZucState_t singlePktState, 64);
        DECLARE_ALIGNED(uint8_t keyStr[NUM_SSE_BUFS][2 * KEYSTR_ROUND_LEN], 64);
        /* structure to store the 4 keys */
        DECLARE_ALIGNED(ZucKey4_t keys, 64);
        const uint8_t *pIn8[NUM_SSE_BUFS] = { NULL };
        uint32_t remainCommonBits;
        uint32_t dataDigested = 0;
        uint32_t T[NUM_SSE_BUFS] = { 0 };
        const uint32_t keyStreamLengthInBits = KEYSTR_ROUND_LEN * 8;
        DECLARE_ALIGNED(uint32_t * pKeyStrArr[NUM_SSE_BUFS], 16) = { NULL };
        unsigned int allCommonBits;

        memset(keyStr, 0, sizeof(keyStr));

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

        for (i = 0; i < NUM_SSE_BUFS; i++) {
                pIn8[i] = (const uint8_t *) pBufferIn[i];
                pKeyStrArr[i] = (uint32_t *) &keyStr[i][0];
                keys.pKeys[i] = pKey[i];
        }

        init_4(&keys, ivs, &state, use_gfni);
        if (use_gfni) {
                /* Generate 16 bytes at a time */
                asm_ZucGenKeystream16B_4_gfni_sse(&state, pKeyStrArr);
        } else {
                /* Generate 16 bytes at a time */
                asm_ZucGenKeystream16B_4_sse(&state, pKeyStrArr);
        }

        /* Point at the next 16 bytes of the key */
        for (i = 0; i < NUM_SSE_BUFS; i++)
                pKeyStrArr[i] = (uint32_t *) &keyStr[i][KEYSTR_ROUND_LEN];

        /* loop over the message bits */
        while (remainCommonBits >= keyStreamLengthInBits) {
                remainCommonBits -= keyStreamLengthInBits;
                dataDigested += keyStreamLengthInBits;
                /* Generate the next key stream 8 bytes or 16 bytes */
                if (use_gfni) {
                        if (!remainCommonBits && allCommonBits)
                                asm_ZucGenKeystream8B_4_gfni_sse(&state, pKeyStrArr);
                        else
                                asm_ZucGenKeystream16B_4_gfni_sse(&state, pKeyStrArr);
                } else {
                        if (!remainCommonBits && allCommonBits)
                                asm_ZucGenKeystream8B_4_sse(&state, pKeyStrArr);
                        else
                                asm_ZucGenKeystream16B_4_sse(&state, pKeyStrArr);
                }
                for (i = 0; i < NUM_SSE_BUFS; i++) {
                        if (job_in_lane[i] == NULL)
                                continue;
                        eia3_round16B(&T[i], keyStr[i], pIn8[i], use_gfni);
                        pIn8[i] = &pIn8[i][KEYSTR_ROUND_LEN];
                }
        }

        /* Process each packet separately for the remaining bits */
        for (i = 0; i < NUM_SSE_BUFS; i++) {
                if (job_in_lane[i] == NULL)
                        continue;

                uint32_t remainBits = lengthInBits[i] - dataDigested;
                const uint32_t N = remainBits + (2 * ZUC_WORD_BITS);
                uint32_t L = ((N + 31) / ZUC_WORD_BITS);

                /* 4 KS words are generated already */
                L = (L > 4) ? (L - 4) : 0;

                uint32_t *keyStr32 = (uint32_t *) keyStr[i];

                /* Copy the ZUC state to single packet state,
                 * if more KS is needed */
                if (L > 0) {
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
                        /* Generate the next key stream (16 bytes max) */
                        if (L > 3) {
                                asm_ZucGenKeystream16B_sse(&keyStr32[4], &singlePktState);
                                L -= 4;
                        } else {
                                asm_ZucGenKeystream_sse(&keyStr32[4], &singlePktState, L);
                                L = 0;
                        }
                        eia3_round16B(&T[i], keyStr32, pIn8[i], use_gfni);
                        pIn8[i] = &pIn8[i][KEYSTR_ROUND_LEN];
                }

                /* Generate final keystream if needed */
                if (L > 0)
                        asm_ZucGenKeystream_sse(&keyStr32[4], &singlePktState, L);

                eia3_remainder(&T[i], keyStr32, pIn8[i], remainBits, use_gfni);
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

void
zuc_eia3_4_buffer_job_no_gfni_sse(const void *const pKey[NUM_SSE_BUFS], const uint8_t *pIv,
                                  const void *const pBufferIn[NUM_SSE_BUFS],
                                  uint32_t *pMacI[NUM_SSE_BUFS],
                                  const uint16_t lengthInBits[NUM_SSE_BUFS],
                                  const void *const job_in_lane[NUM_SSE_BUFS])
{
        _zuc_eia3_4_buffer_job(pKey, pIv, pBufferIn, pMacI, lengthInBits, job_in_lane, 0);
}

void
zuc_eia3_4_buffer_job_gfni_sse(const void *const pKey[NUM_SSE_BUFS], const uint8_t *pIv,
                               const void *const pBufferIn[NUM_SSE_BUFS],
                               uint32_t *pMacI[NUM_SSE_BUFS],
                               const uint16_t lengthInBits[NUM_SSE_BUFS],
                               const void *const job_in_lane[NUM_SSE_BUFS])
{
        _zuc_eia3_4_buffer_job(pKey, pIv, pBufferIn, pMacI, lengthInBits, job_in_lane, 1);
}

void
zuc_eia3_n_buffer_sse(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
                      const void *const pBufferIn[], const uint32_t lengthInBits[],
                      uint32_t *pMacI[], const uint32_t numBuffers)
{
        IMB_JOB *job;
        uint32_t i;

#ifdef SAFE_PARAM
        imb_set_errno(NULL, 0);
        if (mgr == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
        if (pKey == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (pIv == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_IV);
                return;
        }
        if (pBufferIn == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }
        if (pMacI == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_AUTH);
                return;
        }
        if (lengthInBits == NULL) {
                imb_set_errno(NULL, IMB_ERR_AUTH_LEN);
                return;
        }
        for (i = 0; i < numBuffers; i++) {
                if (pKey[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                        return;
                }
                if (pIv[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_IV);
                        return;
                }
                if (pBufferIn[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                        return;
                }
                if (pMacI[i] == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_AUTH);
                        return;
                }
                if (lengthInBits[i] < ZUC_MIN_BITLEN || lengthInBits[i] > ZUC_MAX_BITLEN) {
                        imb_set_errno(NULL, IMB_ERR_AUTH_LEN);
                        return;
                }
        }
#endif
        if (IMB_FLUSH_JOB(mgr) != NULL) {
                imb_set_errno(mgr, IMB_ERR_QUEUE_SPACE);
                return;
        }

        uint32_t jobs_returned = 0;

        for (i = 0; i < numBuffers; i++) {
                job = IMB_GET_NEXT_JOB(mgr);
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->key_len_in_bytes = IMB_ZUC_KEY_LEN_IN_BYTES;
                job->hash_alg = IMB_AUTH_ZUC_EIA3_BITLEN;
                job->src = (const uint8_t *) pBufferIn[i];
                job->u.ZUC_EIA3._key = (const uint8_t *) pKey[i];
                job->u.ZUC_EIA3._iv = (const uint8_t *) pIv[i];
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bits = lengthInBits[i];
                job->auth_tag_output = (uint8_t *) pMacI[i];
                job->auth_tag_output_len_in_bytes = IMB_ZUC_DIGEST_LEN_IN_BYTES;

                job = IMB_SUBMIT_JOB(mgr);
                if (job != NULL)
                        jobs_returned++;
        }

        while (IMB_FLUSH_JOB(mgr) != NULL)
                jobs_returned++;

        if (jobs_returned != numBuffers)
                imb_set_errno(mgr, IMB_ERR_NULL_JOB);
}

void
zuc_eia3_n_buffer_gfni_sse(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
                           const void *const pBufferIn[], const uint32_t lengthInBits[],
                           uint32_t *pMacI[], const uint32_t numBuffers)
{
        zuc_eia3_n_buffer_sse(mgr, pKey, pIv, pBufferIn, lengthInBits, pMacI, numBuffers);
}

static void
shuffle(uint8_t H[16])
{
        uint32_t *H32 = (uint32_t *) H;
        for (int i = 0; i < 4; i++)
                H32[i] = bswap4(H32[i]);
}

static inline void
_zuc_nia6_4_buffer_job(const void *const pKey[NUM_SSE_BUFS], const uint8_t *ivs,
                       const void *const pBufferIn[NUM_SSE_BUFS], void *pMacI[NUM_SSE_BUFS],
                       const uint16_t lengthInBytes[NUM_SSE_BUFS],
                       const void *const job_in_lane[NUM_SSE_BUFS], const unsigned use_gfni)
{
        unsigned int i;
        DECLARE_ALIGNED(ZucState4_t state, 64);
        DECLARE_ALIGNED(uint8_t H[NUM_SSE_BUFS][16], 64);
        DECLARE_ALIGNED(uint8_t Q[NUM_SSE_BUFS][16], 64);
        DECLARE_ALIGNED(uint8_t P[NUM_SSE_BUFS][16], 64);
        DECLARE_ALIGNED(uint32_t * pKeyStrArr[NUM_SSE_BUFS], 16) = { NULL };
        uint8_t tag[NUM_SSE_BUFS][16];
        const uint8_t *pIn8[NUM_SSE_BUFS] = { NULL };
        /* structure to store the 4 keys */
        DECLARE_ALIGNED(ZucKey4_t keys, 64);

        for (i = 0; i < NUM_SSE_BUFS; i++) {
                pIn8[i] = (const uint8_t *) pBufferIn[i];
                keys.pKeys[i] = pKey[i];
        }

        /* Initialize ZUC state */
        if (use_gfni)
                asm_ZucNEA6Initialization_4_gfni_sse(&keys, ivs, &state);
        else
                asm_ZucNEA6Initialization_4_sse(&keys, ivs, &state);

        /* Generate H,Q,P keys */
        for (i = 0; i < NUM_SSE_BUFS; i++)
                pKeyStrArr[i] = (uint32_t *) H[i];
        keygen_4(&state, pKeyStrArr, 16, use_gfni);
        for (i = 0; i < NUM_SSE_BUFS; i++)
                pKeyStrArr[i] = (uint32_t *) Q[i];
        keygen_4(&state, pKeyStrArr, 16, use_gfni);
        for (i = 0; i < NUM_SSE_BUFS; i++)
                pKeyStrArr[i] = (uint32_t *) P[i];
        keygen_4(&state, pKeyStrArr, 16, use_gfni);

        for (i = 0; i < NUM_SSE_BUFS; i++) {
                struct gcm_key_data gdata_key;
                const IMB_JOB *job = job_in_lane[i];

                if (job == NULL)
                        continue;

                memset(tag[i], 0, 16);

                shuffle(H[i]);
                /* Precompute hash keys from H */
                polyval_pre_sse(H[i], &gdata_key);
                /* Digest message bytes */
                polyval_sse(&gdata_key, pIn8[i], lengthInBytes[i], tag[i]);

                /* XOR 16-byte lengths array with previous digest and hash with Q */
                uint64_t lengths[2] = { 0 };

                lengths[1] = lengthInBytes[i] * 8;

                uint64_t *tag64 = (uint64_t *) tag[i];
                tag64[0] ^= lengths[0];
                tag64[1] ^= lengths[1];

                shuffle(Q[i]);
                polyval_16B_sse(Q[i], tag64);

                /* XOR tag with P */
                shuffle(P[i]);
                for (int j = 0; j < 16; j++)
                        tag[i][j] ^= P[i][j];

                memcpy(pMacI[i], tag[i], job->auth_tag_output_len_in_bytes);
        }

#ifdef SAFE_DATA
        /* Clear sensitive data (in registers and stack) */
        clear_mem(H, sizeof(H));
        clear_mem(Q, sizeof(Q));
        clear_mem(P, sizeof(P));
        clear_mem(&state, sizeof(state));
        clear_mem(&keys, sizeof(keys));
#endif
}

void
zuc_nia6_4_buffer_job_no_gfni_sse(const void *const pKey[NUM_SSE_BUFS], const uint8_t *pIv,
                                  const void *const pBufferIn[NUM_SSE_BUFS],
                                  void *pMacI[NUM_SSE_BUFS],
                                  const uint16_t lengthInBytes[NUM_SSE_BUFS],
                                  const void *const job_in_lane[NUM_SSE_BUFS])
{
        _zuc_nia6_4_buffer_job(pKey, pIv, pBufferIn, pMacI, lengthInBytes, job_in_lane, 0);
}

void
zuc_nia6_4_buffer_job_gfni_sse(const void *const pKey[NUM_SSE_BUFS], const uint8_t *pIv,
                               const void *const pBufferIn[NUM_SSE_BUFS], void *pMacI[NUM_SSE_BUFS],
                               const uint16_t lengthInBytes[NUM_SSE_BUFS],
                               const void *const job_in_lane[NUM_SSE_BUFS])
{
        _zuc_nia6_4_buffer_job(pKey, pIv, pBufferIn, pMacI, lengthInBytes, job_in_lane, 1);
}

static inline void
_zuc_nca6_4_buffer_job(const void *const pKey[NUM_SSE_BUFS], const uint8_t *ivs,
                       const void *const pBufferIn[NUM_SSE_BUFS], void *pBufferOut[NUM_SSE_BUFS],
                       const uint16_t length[NUM_SSE_BUFS],
                       const IMB_JOB *const job_in_lane[NUM_SSE_BUFS], const unsigned use_gfni,
                       const IMB_CIPHER_DIRECTION dir)
{
        unsigned int i;
        DECLARE_ALIGNED(ZucState4_t state, 64);
        DECLARE_ALIGNED(uint16_t remainBytes[NUM_SSE_BUFS], 16) = { 0 };
        /* Calculate the minimum input packet size */
        uint16_t lengthInBytes[NUM_SSE_BUFS];

        for (i = 0; i < NUM_SSE_BUFS; i++) {
                if (length[i] == 1)
                        lengthInBytes[i] = (uint16_t) job_in_lane[i]->msg_len_to_cipher_in_bytes;
                else
                        lengthInBytes[i] = length[i];
        }
        const uint32_t bytes1 =
                (lengthInBytes[0] < lengthInBytes[1] ? lengthInBytes[0] : lengthInBytes[1]);
        const uint32_t bytes2 =
                (lengthInBytes[2] < lengthInBytes[3] ? lengthInBytes[2] : lengthInBytes[3]);
        /* min number of bytes */
        const uint32_t bytes = (bytes1 < bytes2) ? bytes1 : bytes2;
        DECLARE_ALIGNED(uint8_t H[NUM_SSE_BUFS][16], 64);
        DECLARE_ALIGNED(uint8_t Q[NUM_SSE_BUFS][16], 64);
        DECLARE_ALIGNED(uint8_t P[NUM_SSE_BUFS][16], 64);
        DECLARE_ALIGNED(uint32_t * pKeyStrArr[NUM_SSE_BUFS], 16) = { NULL };
        uint8_t tag[NUM_SSE_BUFS][16];
        DECLARE_ALIGNED(const uint64_t *pIn64[NUM_SSE_BUFS], 64) = { NULL };
        DECLARE_ALIGNED(uint64_t * pOut64[NUM_SSE_BUFS], 64) = { NULL };
        /* structure to store the 4 keys */
        DECLARE_ALIGNED(ZucKey4_t keys, 64);
        struct gcm_key_data gdata_key[NUM_SSE_BUFS];

        /*
         * Calculate the number of bytes left over for each packet,
         * and setup the Keys and IVs
         */
        for (i = 0; i < NUM_SSE_BUFS; i++) {
                remainBytes[i] = lengthInBytes[i];
                keys.pKeys[i] = pKey[i];
        }

        /* Initialize ZUC state */
        if (use_gfni)
                asm_ZucNEA6Initialization_4_gfni_sse(&keys, ivs, &state);
        else
                asm_ZucNEA6Initialization_4_sse(&keys, ivs, &state);

        /* Generate H,Q,P keys */
        for (i = 0; i < NUM_SSE_BUFS; i++)
                pKeyStrArr[i] = (uint32_t *) H[i];
        keygen_4(&state, pKeyStrArr, 16, use_gfni);
        for (i = 0; i < NUM_SSE_BUFS; i++)
                pKeyStrArr[i] = (uint32_t *) Q[i];
        keygen_4(&state, pKeyStrArr, 16, use_gfni);
        for (i = 0; i < NUM_SSE_BUFS; i++)
                pKeyStrArr[i] = (uint32_t *) P[i];
        keygen_4(&state, pKeyStrArr, 16, use_gfni);

        for (i = 0; i < NUM_SSE_BUFS; i++) {
                pOut64[i] = (uint64_t *) pBufferOut[i];
                pIn64[i] = (const uint64_t *) pBufferIn[i];
        }

        /* Set tags to zero */
        memset(tag, 0, 16 * NUM_SSE_BUFS);

        if (dir == IMB_DIR_DECRYPT) {
                for (i = 0; i < NUM_SSE_BUFS; i++) {
                        const IMB_JOB *job = job_in_lane[i];

                        if (job == NULL)
                                continue;

                        shuffle(H[i]);
                        /* Precompute hash keys from H */
                        polyval_pre_sse(H[i], &gdata_key[i]);

                        /* Digest AAD */
                        polyval_sse(&gdata_key[i], job->u.NCA.aad, job->u.NCA.aad_len_in_bytes,
                                    tag[i]);

                        /* Digest plaintext */
                        polyval_sse(&gdata_key[i], pBufferIn[i], lengthInBytes[i], tag[i]);
                }
        }
        /* Encrypt common length of all buffers */
        if (use_gfni)
                asm_ZucCipher_4_gfni_sse(&state, pIn64, pOut64, remainBytes, (uint16_t) bytes);
        else
                asm_ZucCipher_4_sse(&state, pIn64, pOut64, remainBytes, (uint16_t) bytes);

        for (i = 0; i < NUM_SSE_BUFS; i++) {
                const IMB_JOB *job = job_in_lane[i];

                if (job == NULL)
                        continue;

                /* Encrypt/decrypt remaining bytes */
                if (remainBytes[i]) {
                        DECLARE_ALIGNED(ZucState_t singlePktState, 64);
                        const uint8_t *pTempBufInPtr = NULL;
                        uint8_t *pTempBufOutPtr = NULL;
                        DECLARE_ALIGNED(uint8_t keyStr[KEYSTR_ROUND_LEN], 64);
                        uint64_t *pKeyStream64 = NULL;

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
                        pOut64[0] = (uint64_t *) &pTempBufOutPtr[lengthInBytes[i] - remainBytes[i]];
                        pIn64[0] = (const uint64_t
                                            *) &pTempBufInPtr[lengthInBytes[i] - remainBytes[i]];

                        while (numKeyStreamsPerPkt--) {
                                /* Generate the key stream 16 bytes at a time */
                                asm_ZucGenKeystream16B_sse((uint32_t *) keyStr, &singlePktState);
                                pKeyStream64 = (uint64_t *) keyStr;
                                asm_XorKeyStream16B_sse(pIn64[0], pOut64[0], pKeyStream64);
                                pIn64[0] += 2;
                                pOut64[0] += 2;
                        }

                        /* Check for remaining 0 to 15 bytes */
                        if (numBytesLeftOver) {
                                DECLARE_ALIGNED(uint8_t tempSrc[16], 64);
                                DECLARE_ALIGNED(uint8_t tempDst[16], 64);
                                uint64_t *pTempSrc64;
                                uint64_t *pTempDst64;
                                uint32_t offset = lengthInBytes[i] - numBytesLeftOver;
                                const uint64_t num4BRounds = ((numBytesLeftOver - 1) / 4) + 1;

                                asm_ZucGenKeystream_sse((uint32_t *) &keyStr[0], &singlePktState,
                                                        num4BRounds);
                                /* copy the remaining bytes into temporary
                                 * buffer and XOR with the 16 bytes of
                                 * keystream. Then copy on the valid bytes back
                                 * to the output buffer */
                                memcpy(&tempSrc[0], &pTempBufInPtr[offset], numBytesLeftOver);
                                memset(&tempSrc[numBytesLeftOver], 0, 16 - numBytesLeftOver);

                                pKeyStream64 = (uint64_t *) keyStr;
                                pTempSrc64 = (uint64_t *) &tempSrc[0];
                                pTempDst64 = (uint64_t *) &tempDst[0];
                                asm_XorKeyStream16B_sse(pTempSrc64, pTempDst64, pKeyStream64);

                                memcpy(&pTempBufOutPtr[offset], &tempDst[0], numBytesLeftOver);
#ifdef SAFE_DATA
                                clear_mem(tempSrc, sizeof(tempSrc));
                                clear_mem(tempDst, sizeof(tempDst));
#endif
                        }
                }

                if (dir == IMB_DIR_ENCRYPT) {
                        shuffle(H[i]);
                        /* Precompute hash keys from H */
                        polyval_pre_sse(H[i], &gdata_key[i]);

                        /* Digest AAD */
                        polyval_sse(&gdata_key[i], job->u.NCA.aad, job->u.NCA.aad_len_in_bytes,
                                    tag[i]);

                        /* Digest ciphertext (TODO: decrypt direction) */
                        polyval_sse(&gdata_key[i], pBufferOut[i], lengthInBytes[i], tag[i]);
                }

                /* XOR 16-byte lengths array with previous digest and hash with Q */
                uint64_t lengths[2] = { 0 };

                lengths[0] = lengthInBytes[i] * 8;
                lengths[1] = job->u.NCA.aad_len_in_bytes * 8;

                uint64_t *tag64 = (uint64_t *) tag[i];
                tag64[0] ^= lengths[0];
                tag64[1] ^= lengths[1];

                shuffle(Q[i]);
                polyval_16B_sse(Q[i], tag64);

                /* XOR tag with P */
                shuffle(P[i]);
                for (int j = 0; j < 16; j++)
                        tag[i][j] ^= P[i][j];

                memcpy(job->auth_tag_output, tag[i], job->auth_tag_output_len_in_bytes);
        }

#ifdef SAFE_DATA
        /* Clear sensitive data (in registers and stack) */
        clear_mem(H, sizeof(H));
        clear_mem(Q, sizeof(Q));
        clear_mem(P, sizeof(P));
        clear_mem(&state, sizeof(state));
        clear_mem(&keys, sizeof(keys));
#endif
}

void
zuc_nca6_4_buffer_job_no_gfni_sse(const void *const pKey[NUM_SSE_BUFS], const uint8_t *ivs,
                                  const void *const pBufferIn[NUM_SSE_BUFS],
                                  void *pBufferOut[NUM_SSE_BUFS],
                                  const uint16_t length[NUM_SSE_BUFS],
                                  const IMB_JOB *const job_in_lane[NUM_SSE_BUFS],
                                  const IMB_CIPHER_DIRECTION dir)
{
        _zuc_nca6_4_buffer_job(pKey, ivs, pBufferIn, pBufferOut, length, job_in_lane, 0, dir);
}

void
zuc_nca6_4_buffer_job_gfni_sse(const void *const pKey[NUM_SSE_BUFS], const uint8_t *ivs,
                               const void *const pBufferIn[NUM_SSE_BUFS],
                               void *pBufferOut[NUM_SSE_BUFS], const uint16_t length[NUM_SSE_BUFS],
                               const IMB_JOB *const job_in_lane[NUM_SSE_BUFS],
                               const IMB_CIPHER_DIRECTION dir)
{
        _zuc_nca6_4_buffer_job(pKey, ivs, pBufferIn, pBufferOut, length, job_in_lane, 1, dir);
}
