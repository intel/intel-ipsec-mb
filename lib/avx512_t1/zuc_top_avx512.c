/*******************************************************************************
  Copyright (c) 2020-2024, Intel Corporation

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
 * zuc_avx512_top.c
 *-----------------------------------------------------------------------
 * An implementation of ZUC, the core algorithm for the
 * 3GPP Confidentiality and Integrity algorithms.
 *
 *-----------------------------------------------------------------------*/

#include <string.h>

#include "include/arch_avx512_type2.h"
#include "include/zuc_internal.h"
#include "include/wireless_common.h"
#include "include/save_xmms.h"
#include "include/clear_regs_mem.h"
#include "intel-ipsec-mb.h"
#include "include/error.h"

#define SAVE_XMMS               save_xmms
#define RESTORE_XMMS            restore_xmms
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_zmms

#define NUM_AVX512_BUFS 16

static inline uint32_t
find_min_length32(const uint32_t length[NUM_AVX512_BUFS])
{
        /* Calculate the minimum input packet size */
        static const uint64_t lo_mask[2] = { 0x0d0c090805040100UL, 0xFFFFFFFFFFFFFFFFUL };
        static const uint64_t hi_mask[2] = { 0xFFFFFFFFFFFFFFFFUL, 0x0d0c090805040100UL };
        const __m128i shuf_hi_mask = _mm_loadu_si128((const __m128i *) hi_mask);
        const __m128i shuf_lo_mask = _mm_loadu_si128((const __m128i *) lo_mask);
        __m128i xmm_lengths1, xmm_lengths2;

        /* Calculate the minimum input packet size from packets 0-7 */
        xmm_lengths1 = _mm_loadu_si128((const __m128i *) length);
        xmm_lengths2 = _mm_loadu_si128((const __m128i *) &length[4]);

        xmm_lengths1 = _mm_shuffle_epi8(xmm_lengths1, shuf_lo_mask);
        xmm_lengths2 = _mm_shuffle_epi8(xmm_lengths2, shuf_hi_mask);

        /* Contains array of 16-bit lengths */
        xmm_lengths1 = _mm_or_si128(xmm_lengths1, xmm_lengths2);

        xmm_lengths1 = _mm_minpos_epu16(xmm_lengths1);

        const uint32_t min_length1 = (const uint32_t) _mm_extract_epi16(xmm_lengths1, 0);

        /* Calculate the minimum input packet size from packets 8-15 */
        xmm_lengths1 = _mm_loadu_si128((const __m128i *) &length[8]);
        xmm_lengths2 = _mm_loadu_si128((const __m128i *) &length[12]);

        xmm_lengths1 = _mm_shuffle_epi8(xmm_lengths1, shuf_lo_mask);
        xmm_lengths2 = _mm_shuffle_epi8(xmm_lengths2, shuf_hi_mask);

        /* Contains array of 16-bit lengths */
        xmm_lengths1 = _mm_or_si128(xmm_lengths1, xmm_lengths2);

        xmm_lengths1 = _mm_minpos_epu16(xmm_lengths1);

        const uint32_t min_length2 = (const uint32_t) _mm_extract_epi16(xmm_lengths1, 0);

        /* Calculate the minimum input packet size from all packets */
        return (min_length1 < min_length2) ? min_length1 : min_length2;
}

static inline uint16_t
find_min_length16(const uint16_t length[NUM_AVX512_BUFS])
{
        /* Load two groups of 8 uint16_t values */
        __m128i xmm_len1 = _mm_loadu_si128((const __m128i *) &length[0]);
        __m128i xmm_len2 = _mm_loadu_si128((const __m128i *) &length[8]);

        /* Find minimum in each half */
        xmm_len1 = _mm_minpos_epu16(xmm_len1);
        xmm_len2 = _mm_minpos_epu16(xmm_len2);

        /* Calculate the minimum input packet size from all packets */
        const uint16_t min1 = (uint16_t) _mm_extract_epi16(xmm_len1, 0);
        const uint16_t min2 = (uint16_t) _mm_extract_epi16(xmm_len2, 0);

        return (min1 < min2) ? min1 : min2;
}

static inline void
init_16(ZucKey16_t *keys, const uint8_t *ivs, ZucState16_t *state, const uint16_t lane_mask,
        const unsigned use_gfni)
{
        if (use_gfni)
                asm_ZucInitialization_16_gfni_avx512(keys, ivs, state, lane_mask);
        else
                asm_ZucInitialization_16_avx512(keys, ivs, state, lane_mask);
}

static inline void
keystr_64B_gen_16(ZucState16_t *state, uint32_t *pKeyStr, const unsigned key_off,
                  const unsigned use_gfni)
{
        if (use_gfni)
                asm_ZucGenKeystream64B_16_gfni_avx512(state, pKeyStr, key_off);
        else
                asm_ZucGenKeystream64B_16_avx512(state, pKeyStr, key_off);
}

static inline void
keystr_8B_gen_16(ZucState16_t *state, uint32_t *pKeyStr, const unsigned key_off,
                 const unsigned use_gfni)
{
        if (use_gfni)
                asm_ZucGenKeystream8B_16_gfni_avx512(state, pKeyStr, key_off);
        else
                asm_ZucGenKeystream8B_16_avx512(state, pKeyStr, key_off);
}

static inline void
cipher_16(ZucState16_t *pState, const uint64_t *pIn[16], uint64_t *pOut[16],
          const uint16_t lengths[16], const uint64_t minLength, const unsigned use_gfni)
{
        if (use_gfni)
                asm_ZucCipher_16_gfni_avx512(pState, pIn, pOut, lengths, minLength);
        else
                asm_ZucCipher_16_avx512(pState, pIn, pOut, lengths, minLength);
}

static inline void
round64B_16(uint32_t *T, const uint32_t *ks, const void **data, uint16_t *lens,
            const unsigned use_gfni)
{
        if (use_gfni)
                asm_Eia3Round64B_16_VPCLMUL(T, ks, data, lens);
        else
                asm_Eia3Round64BAVX512_16(T, ks, data, lens);
}

static inline void
_zuc_eea3_1_buffer_avx512(const void *pKey, const void *pIv, const void *pBufferIn,
                          void *pBufferOut, const uint32_t length)
{
        DECLARE_ALIGNED(ZucState_t zucState, 64);
        DECLARE_ALIGNED(uint8_t keyStream[64], 64);

        const uint64_t *pIn64 = NULL;
        uint64_t *pOut64 = NULL, *pKeyStream64 = NULL;
        uint64_t *pTemp64 = NULL, *pdstTemp64 = NULL;

        uint32_t numKeyStreamsPerPkt = length / ZUC_KEYSTR_LEN;
        uint32_t numBytesLeftOver = length % ZUC_KEYSTR_LEN;

        /* initialize the zuc state */
        asm_ZucInitialization_avx(pKey, pIv, &(zucState));

        /* Loop Over all the Quad-Words in input buffer and XOR with the 64bits
         * of generated keystream */
        pOut64 = (uint64_t *) pBufferOut;
        pIn64 = (const uint64_t *) pBufferIn;

        while (numKeyStreamsPerPkt--) {
                /* Generate the key stream 64 bytes at a time */
                asm_ZucGenKeystream64B_avx((uint32_t *) &keyStream[0], &zucState);

                /* XOR The Keystream generated with the input buffer here */
                pKeyStream64 = (uint64_t *) keyStream;
                asm_XorKeyStream64B_avx512(pIn64, pOut64, pKeyStream64);
                pIn64 += 8;
                pOut64 += 8;
        }

        /* Check for remaining 0 to 63 bytes */
        if (numBytesLeftOver) {
                /* buffer to store 64 bytes of keystream */
                DECLARE_ALIGNED(uint8_t tempSrc[64], 64);
                DECLARE_ALIGNED(uint8_t tempDst[64], 64);
                const uint8_t *pIn8 = (const uint8_t *) pBufferIn;
                uint8_t *pOut8 = (uint8_t *) pBufferOut;
                const uint64_t num4BRounds = ((numBytesLeftOver - 1) / 4) + 1;

                asm_ZucGenKeystream_avx((uint32_t *) &keyStream[0], &zucState, num4BRounds);

                /* copy the remaining bytes into temporary buffer and XOR with
                 * the 64-bytes of keystream. Then copy on the valid bytes back
                 * to the output buffer */

                memcpy(&tempSrc[0], &pIn8[length - numBytesLeftOver], numBytesLeftOver);
                pKeyStream64 = (uint64_t *) &keyStream[0];
                pTemp64 = (uint64_t *) &tempSrc[0];
                pdstTemp64 = (uint64_t *) &tempDst[0];

                asm_XorKeyStream64B_avx512(pTemp64, pdstTemp64, pKeyStream64);
                memcpy(&pOut8[length - numBytesLeftOver], &tempDst[0], numBytesLeftOver);

#ifdef SAFE_DATA
                clear_mem(tempSrc, sizeof(tempSrc));
                clear_mem(tempDst, sizeof(tempDst));
#endif
        }
#ifdef SAFE_DATA
        /* Clear sensitive data in stack */
        clear_mem(keyStream, sizeof(keyStream));
        clear_mem(&zucState, sizeof(zucState));
#endif
}

static inline void
_zuc_eea3_16_buffer_avx512(const void *const pKey[NUM_AVX512_BUFS],
                           const void *const pIv[NUM_AVX512_BUFS],
                           const void *const pBufferIn[NUM_AVX512_BUFS],
                           void *pBufferOut[NUM_AVX512_BUFS],
                           const uint32_t length[NUM_AVX512_BUFS], const unsigned use_gfni)
{
        DECLARE_ALIGNED(ZucState16_t state, 64);
        DECLARE_ALIGNED(ZucState_t singlePktState, 64);
        unsigned int i = 0;
        /* Calculate the minimum input packet size from all packets */
        uint16_t bytes = (uint16_t) find_min_length32(length);
        DECLARE_ALIGNED(uint16_t remainBytes[NUM_AVX512_BUFS], 32) = { 0 };
        DECLARE_ALIGNED(uint8_t keyStr[NUM_AVX512_BUFS][64], 64);
        /* structure to store the 16 keys */
        DECLARE_ALIGNED(ZucKey16_t keys, 64);
        /* structure to store the 16 IV's */
        DECLARE_ALIGNED(uint8_t ivs[NUM_AVX512_BUFS * 32], 16);

        DECLARE_ALIGNED(const uint64_t *pIn64[NUM_AVX512_BUFS], 64) = { NULL };
        DECLARE_ALIGNED(uint64_t * pOut64[NUM_AVX512_BUFS], 64) = { NULL };
        uint64_t *pKeyStream64 = NULL;

        /*
         * Calculate the number of bytes left over for each packet,
         * and setup the Keys and IVs
         */
        for (i = 0; i < NUM_AVX512_BUFS; i++) {
                remainBytes[i] = length[i];
                keys.pKeys[i] = pKey[i];
                memcpy(ivs + i * 16, pIv[i], 16);
        }

        init_16(&keys, ivs, &state, 0xFFFF, use_gfni);

        for (i = 0; i < NUM_AVX512_BUFS; i++) {
                pOut64[i] = (uint64_t *) pBufferOut[i];
                pIn64[i] = (const uint64_t *) pBufferIn[i];
        }

        cipher_16(&state, pIn64, pOut64, remainBytes, bytes, use_gfni);

        /* process each packet separately for the remaining bytes */
        for (i = 0; i < NUM_AVX512_BUFS; i++) {
                if (remainBytes[i]) {
                        /* need to copy the zuc state to single packet state */
                        for (unsigned j = 0; j <= 15; j++)
                                singlePktState.lfsrState[j] = state.lfsrState[j][i];

                        singlePktState.fR1 = state.fR1[i];
                        singlePktState.fR2 = state.fR2[i];

                        uint32_t numKeyStreamsPerPkt = remainBytes[i] / ZUC_KEYSTR_LEN;
                        const uint32_t numBytesLeftOver = remainBytes[i] % ZUC_KEYSTR_LEN;

                        const uint8_t *pTempBufInPtr = pBufferIn[i];
                        uint8_t *pTempBufOutPtr = pBufferOut[i];

                        /* update the output and input pointers here to point
                         * to the i'th buffers */
                        pOut64[0] = (uint64_t *) &pTempBufOutPtr[length[i] - remainBytes[i]];
                        pIn64[0] = (const uint64_t *) &pTempBufInPtr[length[i] - remainBytes[i]];

                        while (numKeyStreamsPerPkt--) {
                                /* Generate the key stream 64 bytes at a time */
                                asm_ZucGenKeystream64B_avx((uint32_t *) keyStr[0], &singlePktState);
                                pKeyStream64 = (uint64_t *) keyStr[0];
                                asm_XorKeyStream64B_avx512(pIn64[0], pOut64[0], pKeyStream64);
                                pIn64[0] += 8;
                                pOut64[0] += 8;
                        }

                        /* Check for remaining 0 to 63 bytes */
                        if (numBytesLeftOver) {
                                DECLARE_ALIGNED(uint8_t tempSrc[64], 64);
                                DECLARE_ALIGNED(uint8_t tempDst[64], 64);
                                uint64_t *pTempSrc64;
                                uint64_t *pTempDst64;
                                uint32_t offset = length[i] - numBytesLeftOver;
                                const uint64_t num4BRounds = ((numBytesLeftOver - 1) / 4) + 1;

                                asm_ZucGenKeystream_avx((uint32_t *) &keyStr[0], &singlePktState,
                                                        num4BRounds);
                                /* copy the remaining bytes into temporary
                                 * buffer and XOR with the 64-bytes of
                                 * keystream. Then copy on the valid bytes back
                                 * to the output buffer */
                                memcpy(&tempSrc[0], &pTempBufInPtr[offset], numBytesLeftOver);
                                memset(&tempSrc[numBytesLeftOver], 0, 64 - numBytesLeftOver);

                                pKeyStream64 = (uint64_t *) &keyStr[0][0];
                                pTempSrc64 = (uint64_t *) &tempSrc[0];
                                pTempDst64 = (uint64_t *) &tempDst[0];
                                asm_XorKeyStream64B_avx512(pTempSrc64, pTempDst64, pKeyStream64);

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
zuc_eea3_1_buffer_avx512(IMB_MGR *mgr, const void *pKey, const void *pIv, const void *pBufferIn,
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
_zuc_eea3_n_buffer(const void *const pKey[], const void *const pIv[], const void *const pBufferIn[],
                   void *pBufferOut[], const uint32_t length[], const uint32_t numBuffers,
                   const unsigned use_gfni)
{
#ifndef LINUX
        DECLARE_ALIGNED(imb_uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif

        unsigned int i;
        unsigned int packetCount = numBuffers;

#ifdef SAFE_PARAM
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

                /* Check input data is in range of supported length */
                if (length[i] < ZUC_MIN_BYTELEN || length[i] > ZUC_MAX_BYTELEN) {
                        imb_set_errno(NULL, IMB_ERR_CIPH_LEN);
                        return;
                }
        }
#endif
        i = 0;

        while (packetCount >= 16) {
                packetCount -= 16;
                _zuc_eea3_16_buffer_avx512(&pKey[i], &pIv[i], &pBufferIn[i], &pBufferOut[i],
                                           &length[i], use_gfni);
                i += 16;
        }

        while (packetCount >= 8) {
                packetCount -= 8;
                _zuc_eea3_8_buffer_avx2(&pKey[i], &pIv[i], &pBufferIn[i], &pBufferOut[i],
                                        &length[i]);
                i += 8;
        }

        while (packetCount >= 4) {
                packetCount -= 4;
                _zuc_eea3_4_buffer_sse(&pKey[i], &pIv[i], &pBufferIn[i], &pBufferOut[i], &length[i],
                                       use_gfni);
                i += 4;
        }

        while (packetCount--) {
                _zuc_eea3_1_buffer_avx512(pKey[i], pIv[i], pBufferIn[i], pBufferOut[i], length[i]);
                i++;
        }
#ifdef SAFE_DATA
        /* Clear sensitive data in registers */
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif
        _mm256_zeroupper();
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
}

void
zuc_eea3_n_buffer_avx512(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
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
zuc_eea3_n_buffer_gfni_avx512(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
                              const void *const pBufferIn[], void *pBufferOut[],
                              const uint32_t length[], const uint32_t numBuffers)
{
        zuc_eea3_n_buffer_avx512(mgr, pKey, pIv, pBufferIn, pBufferOut, length, numBuffers);
}

static inline void
_zuc_eia3_1_buffer_avx512(const void *pKey, const void *pIv, const void *pBufferIn,
                          const uint32_t lengthInBits, uint32_t *pMacI)
{
        DECLARE_ALIGNED(ZucState_t zucState, 64);
        DECLARE_ALIGNED(uint32_t keyStream[16 * 2], 64);
        const uint32_t keyStreamLengthInBits = ZUC_KEYSTR_LEN * 8;
        /* generate a key-stream 2 words longer than the input message */
        uint32_t *pZuc = (uint32_t *) &keyStream[0];
        uint32_t remainingBits = lengthInBits;
        uint32_t T = 0;
        const uint8_t *pIn8 = (const uint8_t *) pBufferIn;

        asm_ZucInitialization_avx(pKey, pIv, &(zucState));
        asm_ZucGenKeystream64B_avx(pZuc, &zucState);

        /* loop over the message bits */
        while (remainingBits >= keyStreamLengthInBits) {
                remainingBits -= keyStreamLengthInBits;
                /* Generate the next key stream 8 bytes or 64 bytes */
                if (!remainingBits)
                        asm_ZucGenKeystream8B_avx(&keyStream[16], &zucState);
                else
                        asm_ZucGenKeystream64B_avx(&keyStream[16], &zucState);
                asm_Eia3Round64BAVX512(&T, &keyStream[0], pIn8);
                /* Copy the last keystream generated
                 * to the first 64 bytes */
                memmove(&keyStream[0], &keyStream[16], 64);
                pIn8 = &pIn8[ZUC_KEYSTR_LEN];
        }

        /*
         * If remaining bits has more than 14 ZUC WORDS (double words),
         * keystream needs to have up to another 2 ZUC WORDS (8B)
         */
        if (remainingBits > (14 * 32))
                asm_ZucGenKeystream8B_avx(&keyStream[16], &zucState);
        asm_Eia3RemainderAVX512(&T, &keyStream[0], pIn8, remainingBits);
        *pMacI = T;
}

/*
 * Returns the offset of where the keystream starts for a specific buffer,
 * in memory. The keystream for each buffer is scattered in memory,
 * interleaving chunks of 16 bytes, with 128 bytes of keystream in total for
 * each buffer.
 * The memory is laid out in the following way:
 * [B_0[15:0] B_4[15:0] B_8[15:0] B_12[15:0]
 *  B_0[31:16] B_4[31:16] B_8[31:16] B_12[31:16]
 *  B_0[47:32] B_4[47:32] B_8[47:32] B_12[47:32]
 *  B_0[63:48] B_4[63:48] B_8[63:48] B_12[63:48]
 *  B_0[79:64] B_4[79:64] B_8[79:64] B_12[79:64]
 *  B_0[95:80] B_4[95:80] B_8[95:80] B_12[95:80]
 *  B_0[111:96] B_4[111:96] B_8[111:96] B_12[111:96]
 *  B_0[127:112] B_4[127:112] B_8[127:112] B_13[127:112]
 *  B_1[15:0] B_5[15:0] B_9[15:0] B_13[15:0]
 *  B_1[31:16] B_5[31:16] B_9[31:16] B_13[31:16]
 *  B_1[47:32] B_5[47:32] B_9[47:32] B_13[47:32]
 *  B_1[63:48] B_5[63:48] B_9[63:48] B_13[63:48]
 *  B_1[79:64] B_5[79:64] B_9[79:64] B_13[79:64]
 *  B_1[95:80] B_5[95:80] B_9[95:80] B_13[95:80]
 *  B_1[111:96] B_5[111:96] B_9[111:96] B_13[111:96]
 *  B_1[127:112] B_5[127:112] B_9[127:112] B_13[127:112]
 * ... ]
 */
static inline unsigned
get_start_key_addr(const unsigned buf_idx)
{
        const unsigned idx_l = buf_idx & 0x3;
        const unsigned idx_h = buf_idx >> 2;

        return idx_l * 128 + idx_h * 4;
}

static inline void
_zuc_eia3_16_buffer_avx512(const void *const pKey[NUM_AVX512_BUFS],
                           const void *const pIv[NUM_AVX512_BUFS],
                           const void *const pBufferIn[NUM_AVX512_BUFS],
                           const uint32_t lengthInBits[NUM_AVX512_BUFS],
                           uint32_t *pMacI[NUM_AVX512_BUFS], const unsigned use_gfni)
{
        unsigned int i = 0;
        DECLARE_ALIGNED(ZucState16_t state, 64);
        DECLARE_ALIGNED(ZucState_t singlePktState, 64);
        /* Calculate the minimum input packet size from all packets */
        uint32_t commonBits = find_min_length32(lengthInBits);
        DECLARE_ALIGNED(uint32_t keyStr[NUM_AVX512_BUFS * 2 * 16], 64);
        /* structure to store the 16 keys */
        DECLARE_ALIGNED(ZucKey16_t keys, 64);
        /* structure to store the 16 IV's */
        DECLARE_ALIGNED(uint8_t ivs[NUM_AVX512_BUFS * 32], 16);
        const uint8_t *pIn8[NUM_AVX512_BUFS] = { NULL };
        uint32_t remainCommonBits = commonBits;
        uint32_t numKeyStr = 0;
        uint32_t T[NUM_AVX512_BUFS] = { 0 };
        const uint32_t keyStreamLengthInBits = ZUC_KEYSTR_LEN * 8;
        DECLARE_ALIGNED(uint16_t lens[NUM_AVX512_BUFS], 32);

        for (i = 0; i < NUM_AVX512_BUFS; i++) {
                pIn8[i] = (const uint8_t *) pBufferIn[i];
                keys.pKeys[i] = pKey[i];
                memcpy(ivs + i * 16, pIv[i], 16);
                lens[i] = (uint16_t) lengthInBits[i];
        }

        init_16(&keys, ivs, &state, 0xFFFF, use_gfni);
        /* Generate 64 bytes at a time */
        keystr_64B_gen_16(&state, keyStr, 0, use_gfni);

        /* loop over the message bits */
        while (remainCommonBits >= keyStreamLengthInBits) {
                remainCommonBits -= keyStreamLengthInBits;
                numKeyStr++;
                /* Generate the next key stream 8 bytes or 64 bytes */
                if (!remainCommonBits)
                        keystr_8B_gen_16(&state, keyStr, 64, use_gfni);
                else
                        keystr_64B_gen_16(&state, keyStr, 64, use_gfni);
                round64B_16(T, keyStr, (const void **) pIn8, lens, use_gfni);
        }

        /* Process each packet separately for the remaining bits */
        for (i = 0; i < NUM_AVX512_BUFS; i++) {
                uint32_t remainBits = lengthInBits[i] - numKeyStr * keyStreamLengthInBits;
                uint32_t keyStr32[16 * 2];
                unsigned j;

                /*
                 * Copy 128 bytes of keystream scattered in chunks of 16 bytes
                 * to be in contiguous memory
                 */
                for (j = 0; j < 8; j++)
                        memmove(keyStr32 + j * 4, &keyStr[get_start_key_addr(i) + j * 16], 16);

                /* If remaining bits are more than 56 bytes, we need to generate
                 * at least 8B more of keystream, so we need to copy
                 * the zuc state to single packet state first */
                if (remainBits > (14 * 32)) {
                        for (unsigned j = 0; j <= 15; j++)
                                singlePktState.lfsrState[j] = state.lfsrState[j][i];

                        singlePktState.fR1 = state.fR1[i];
                        singlePktState.fR2 = state.fR2[i];
                }

                while (remainBits >= keyStreamLengthInBits) {
                        remainBits -= keyStreamLengthInBits;

                        /* Generate the next key stream 8 bytes or 64 bytes */
                        if (!remainBits)
                                asm_ZucGenKeystream8B_avx(&keyStr32[16], &singlePktState);
                        else
                                asm_ZucGenKeystream64B_avx(&keyStr32[16], &singlePktState);
                        asm_Eia3Round64BAVX512(&T[i], &keyStr32[0], pIn8[i]);
                        /* Copy the last keystream generated
                         * to the first 64 bytes */
                        memmove(keyStr32, &keyStr32[16], 64);
                        pIn8[i] = &pIn8[i][ZUC_KEYSTR_LEN];
                }

                /*
                 * If remaining bits has more than 14 ZUC WORDS (double words),
                 * keystream needs to have up to another 2 ZUC WORDS (8B)
                 */

                if (remainBits > (14 * 32))
                        asm_ZucGenKeystream8B_avx(&keyStr32[16], &singlePktState);

                asm_Eia3RemainderAVX512(&T[i], keyStr32, pIn8[i], remainBits);
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
zuc_eia3_1_buffer_avx512(IMB_MGR *mgr, const void *pKey, const void *pIv, const void *pBufferIn,
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
_zuc_eia3_n_buffer(const void *const pKey[], const void *const pIv[], const void *const pBufferIn[],
                   const uint32_t lengthInBits[], uint32_t *pMacI[], const uint32_t numBuffers,
                   const unsigned use_gfni)
{
#ifndef LINUX
        DECLARE_ALIGNED(imb_uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif

        unsigned int i;
        unsigned int packetCount = numBuffers;

#ifdef SAFE_PARAM
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

        if (pMacI == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_AUTH);
                return;
        }

        if (lengthInBits == NULL) {
                imb_set_errno(NULL, IMB_ERR_AUTH_LEN);
                return;
        }

        /* Check for NULL pointers and lengths for each buffer */
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

                /* Check input data is in range of supported length */
                if (lengthInBits[i] < ZUC_MIN_BITLEN || lengthInBits[i] > ZUC_MAX_BITLEN) {
                        imb_set_errno(NULL, IMB_ERR_AUTH_LEN);
                        return;
                }
        }
#endif
        i = 0;

        while (packetCount >= 16) {
                packetCount -= 16;
                _zuc_eia3_16_buffer_avx512(&pKey[i], &pIv[i], &pBufferIn[i], &lengthInBits[i],
                                           &pMacI[i], use_gfni);
                i += 16;
        }

        if (packetCount >= 8) {
                packetCount -= 8;
                _zuc_eia3_8_buffer_avx2(&pKey[i], &pIv[i], &pBufferIn[i], &lengthInBits[i],
                                        &pMacI[i]);
                i += 8;
        }

        if (packetCount >= 4) {
                packetCount -= 4;
                _zuc_eia3_4_buffer_sse(&pKey[i], &pIv[i], &pBufferIn[i], &lengthInBits[i],
                                       &pMacI[i], use_gfni);
                i += 4;
        }
        while (packetCount--) {
                _zuc_eia3_1_buffer_avx512(pKey[i], pIv[i], pBufferIn[i], lengthInBits[i], pMacI[i]);
                i++;
        }

        _mm256_zeroupper();

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
zuc_eia3_n_buffer_avx512(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
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
zuc_eia3_n_buffer_gfni_avx512(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
                              const void *const pBufferIn[], const uint32_t lengthInBits[],
                              uint32_t *pMacI[], const uint32_t numBuffers)
{
        zuc_eia3_n_buffer_avx512(mgr, pKey, pIv, pBufferIn, lengthInBits, pMacI, numBuffers);
}

void
zuc_nia6_16_buffer_job_gfni_avx512(const void *const pKey[NUM_AVX512_BUFS], const uint8_t *pIv,
                                   const void *const pBufferIn[NUM_AVX512_BUFS],
                                   void *pMacI[NUM_AVX512_BUFS],
                                   const uint16_t lengthInBytes[NUM_AVX512_BUFS],
                                   const void *const job_in_lane[NUM_AVX512_BUFS])
{
        DECLARE_ALIGNED(ZucState16_t state, 64);
        DECLARE_ALIGNED(uint32_t keyStr[2 * NUM_AVX512_BUFS * 16], 64);
        /* structure to store the 16 keys */
        DECLARE_ALIGNED(ZucKey16_t keys, 64);

        for (unsigned i = 0; i < NUM_AVX512_BUFS; i++) {
                keys.pKeys[i] = pKey[i];
        }

        /* Initialize ZUC state */
        asm_ZucNEA6Initialization_16_gfni_avx512(&keys, pIv, &state, 0xffff);

        /* Generate H,Q,P (3*16 bytes) keys */
        asm_ZucGenKeystream_16_gfni_avx512(&state, keyStr, 0, 12);

        /* Load shuffle mask for H, Q, P for each of the buffers */
        const __m128i shuf_mask =
                _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

        for (unsigned i = 0; i < NUM_AVX512_BUFS; i++) {
                const IMB_JOB *job = job_in_lane[i];

                if (job == NULL)
                        continue;

                /*
                 * Set H, Q, P pointers.
                 * Keystream is generated interleaved in blocks of 16 bytes,
                 * as it was designed for ZUC-EIA3. Refer to lines 559-580 for
                 * an explanation of the memory layout
                 */
                const uint32_t buf_idx = get_start_key_addr(i);

                /*
                 * H - First 16 bytes for each buffer
                 * Q - Bytes 64-79 for each buffer
                 * P - Bytes 128-143 for each buffer
                 */
                const uint64_t *ks_u64 = (const uint64_t *) &keyStr[buf_idx];
                __m128i HQP[3];

                HQP[0] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &ks_u64[0]), shuf_mask);
                HQP[1] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &ks_u64[8]), shuf_mask);
                HQP[2] =
                        _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &ks_u64[16]), shuf_mask);

                uint8_t tag[16];

                nia_vclmul_avx512(tag, HQP, (const void *) pBufferIn[i], lengthInBytes[i]);

                memcpy(pMacI[i], tag, job->auth_tag_output_len_in_bytes);
#ifdef SAFE_DATA
                /* Clear sensitive data (in registers and stack) */
                clear_mem(HQP, sizeof(HQP));
#endif
        }

#ifdef SAFE_DATA
        /* Clear sensitive data (in registers and stack) */
        clear_mem(&state, sizeof(state));
        clear_mem(&keys, sizeof(keys));
#endif
}

void
zuc_nca6_16_buffer_job_gfni_avx512(const void *const pKey[NUM_AVX512_BUFS], uint8_t *pIv,
                                   const void *const pBufferIn[NUM_AVX512_BUFS],
                                   void *pBufferOut[NUM_AVX512_BUFS],
                                   const uint16_t length[NUM_AVX512_BUFS],
                                   const IMB_JOB *const job_in_lane[NUM_AVX512_BUFS],
                                   const IMB_CIPHER_DIRECTION dir)
{
        unsigned int i;
        DECLARE_ALIGNED(ZucState16_t state, 64);
        DECLARE_ALIGNED(ZucState_t singlePktState, 64);
        DECLARE_ALIGNED(uint32_t keyStr[2 * NUM_AVX512_BUFS * 16], 64);
        DECLARE_ALIGNED(uint16_t remainBytes[NUM_AVX512_BUFS], 32) = { 0 };
        DECLARE_ALIGNED(ZucKey16_t keys, 64);
        DECLARE_ALIGNED(const uint64_t *pIn64[NUM_AVX512_BUFS], 64);
        DECLARE_ALIGNED(uint64_t * pOut64[NUM_AVX512_BUFS], 64);
        uint16_t bytes;
        DECLARE_ALIGNED(uint8_t singleKeyStr[ZUC_KEYSTR_LEN], 64);
        const __m128i shuf_mask =
                _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

        for (i = 0; i < NUM_AVX512_BUFS; i++) {
                keys.pKeys[i] = pKey[i];
                remainBytes[i] = length[i];
        }

        /* Find minimum cipher length across all lanes (null lanes have UINT16_MAX) */
        bytes = find_min_length16(length);
        if (bytes == UINT16_MAX)
                bytes = 0;

        /*
         * Copy real lane's IV to null lane slots so they are initialized with
         * the same ZUC state.  The IV stride in _zuc_args_IV is 16 bytes and
         * each IV occupies 16 bytes (one XMM register).
         */
        for (i = 0; i < NUM_AVX512_BUFS; i++)
                if (job_in_lane[i] != NULL)
                        break;
        if (i < NUM_AVX512_BUFS) {
                const unsigned int iv_len = 16;
                const uint8_t *real_iv = pIv + i * iv_len;

                for (unsigned j = 0; j < NUM_AVX512_BUFS; j++)
                        if (job_in_lane[j] == NULL)
                                memcpy(pIv + j * iv_len, real_iv, iv_len);
        }

        /* Initialize ZUC state */
        asm_ZucNEA6Initialization_16_gfni_avx512(&keys, pIv, &state, 0xffff);

        /* Generate H, Q, P keys (12 rounds = 3 * 16 bytes per buffer) */
        asm_ZucGenKeystream_16_gfni_avx512(&state, keyStr, 0, 12);

        /* Set up in/out pointers for all lanes */
        for (i = 0; i < NUM_AVX512_BUFS; i++) {
                pIn64[i] = (const uint64_t *) pBufferIn[i];
                pOut64[i] = (uint64_t *) pBufferOut[i];
                if (job_in_lane[i] == NULL)
                        remainBytes[i] = bytes;
        }

        /* Decrypt: compute POLYVAL on ciphertext before decrypting */
        if (dir == IMB_DIR_DECRYPT) {
                for (i = 0; i < NUM_AVX512_BUFS; i++) {
                        const IMB_JOB *job = job_in_lane[i];

                        if (job == NULL)
                                continue;

                        const uint32_t buf_idx = get_start_key_addr(i);
                        const uint64_t *ks_u64 = (const uint64_t *) &keyStr[buf_idx];
                        __m128i HQP[3];

                        HQP[0] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &ks_u64[0]),
                                                  shuf_mask);
                        HQP[1] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &ks_u64[8]),
                                                  shuf_mask);
                        HQP[2] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &ks_u64[16]),
                                                  shuf_mask);

                        uint8_t tag[16];

                        nca_vclmul_avx512(tag, HQP, (const void *) pBufferIn[i], length[i],
                                          job->u.NCA.aad, job->u.NCA.aad_len_in_bytes);

                        memcpy(job->auth_tag_output, tag, job->auth_tag_output_len_in_bytes);
#ifdef SAFE_DATA
                        clear_mem(HQP, sizeof(HQP));
#endif
                }
        }

        /* Encrypt/decrypt common minimum length across all real lanes */
        asm_ZucCipher_16_gfni_avx512(&state, pIn64, pOut64, remainBytes, (uint16_t) bytes);

        /* Per-lane: cipher remainder, POLYVAL for encrypt, tag finalization */
        for (i = 0; i < NUM_AVX512_BUFS; i++) {
                const IMB_JOB *job = job_in_lane[i];

                if (job == NULL)
                        continue;

                /* Handle remaining bytes for this lane */
                if (remainBytes[i]) {
                        for (unsigned j = 0; j <= 15; j++)
                                singlePktState.lfsrState[j] = state.lfsrState[j][i];

                        singlePktState.fR1 = state.fR1[i];
                        singlePktState.fR2 = state.fR2[i];

                        uint32_t numKeyStreamsPerPkt = remainBytes[i] / ZUC_KEYSTR_LEN;
                        const uint32_t numBytesLeftOver = remainBytes[i] % ZUC_KEYSTR_LEN;
                        const uint32_t processedBytes = length[i] - remainBytes[i];

                        const uint8_t *pTempBufInPtr = (const uint8_t *) pBufferIn[i];
                        uint8_t *pTempBufOutPtr = (uint8_t *) pBufferOut[i];

                        pOut64[0] = (uint64_t *) &pTempBufOutPtr[processedBytes];
                        pIn64[0] = (const uint64_t *) &pTempBufInPtr[processedBytes];

                        while (numKeyStreamsPerPkt--) {
                                asm_ZucGenKeystream64B_avx((uint32_t *) singleKeyStr,
                                                           &singlePktState);
                                asm_XorKeyStream64B_avx512(pIn64[0], pOut64[0],
                                                           (uint64_t *) singleKeyStr);
                                pIn64[0] += 8;
                                pOut64[0] += 8;
                        }

                        if (numBytesLeftOver) {
                                DECLARE_ALIGNED(uint8_t tempSrc[64], 64);
                                DECLARE_ALIGNED(uint8_t tempDst[64], 64);
                                const uint32_t offset = length[i] - numBytesLeftOver;
                                const uint64_t num4BRounds = ((numBytesLeftOver - 1) / 4) + 1;

                                asm_ZucGenKeystream_avx((uint32_t *) singleKeyStr, &singlePktState,
                                                        num4BRounds);

                                memcpy(&tempSrc[0], &pTempBufInPtr[offset], numBytesLeftOver);
                                memset(&tempSrc[numBytesLeftOver], 0, 64 - numBytesLeftOver);

                                asm_XorKeyStream64B_avx512((uint64_t *) tempSrc,
                                                           (uint64_t *) tempDst,
                                                           (uint64_t *) singleKeyStr);
                                memcpy(&pTempBufOutPtr[offset], &tempDst[0], numBytesLeftOver);
#ifdef SAFE_DATA
                                clear_mem(tempSrc, sizeof(tempSrc));
                                clear_mem(tempDst, sizeof(tempDst));
#endif
                        }
                }

                /* Encrypt: compute POLYVAL on ciphertext after encrypting */
                if (dir == IMB_DIR_ENCRYPT) {
                        const uint32_t buf_idx = get_start_key_addr(i);
                        const uint64_t *ks_u64 = (const uint64_t *) &keyStr[buf_idx];
                        __m128i HQP[3];

                        HQP[0] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &ks_u64[0]),
                                                  shuf_mask);
                        HQP[1] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &ks_u64[8]),
                                                  shuf_mask);
                        HQP[2] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &ks_u64[16]),
                                                  shuf_mask);

                        uint8_t tag[16];

                        nca_vclmul_avx512(tag, HQP, (const void *) pBufferOut[i], length[i],
                                          job->u.NCA.aad, job->u.NCA.aad_len_in_bytes);

                        memcpy(job->auth_tag_output, tag, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
                        clear_mem(HQP, sizeof(HQP));
#endif
                }
        }

#ifdef SAFE_DATA
        clear_mem(keyStr, sizeof(keyStr));
        clear_mem(singleKeyStr, sizeof(singleKeyStr));
        clear_mem(&singlePktState, sizeof(singlePktState));
        clear_mem(&state, sizeof(state));
        clear_mem(&keys, sizeof(keys));
#endif
}
