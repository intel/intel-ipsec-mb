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
