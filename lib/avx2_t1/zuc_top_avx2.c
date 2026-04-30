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

#define SAVE_XMMS               save_xmms
#define RESTORE_XMMS            restore_xmms
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_ymms

#define KEYSTR_ROUND_LEN 32

#define NUM_AVX2_BUFS 8

static inline void
init_8(ZucKey8_t *keys, const uint8_t *ivs, ZucState8_t *state, const unsigned use_gfni)
{
        if (use_gfni)
                asm_ZucInitialization_8_gfni_avx2(keys, ivs, state);
        else
                asm_ZucInitialization_8_avx2(keys, ivs, state);
}

static inline void
keygen_8(ZucState8_t *state, uint32_t **pKeyStrArr, const uint64_t numKeyStrBytes,
         const unsigned use_gfni)
{
        if (use_gfni) {
                if (numKeyStrBytes == 4)
                        asm_ZucGenKeystream4B_8_gfni_avx2(state, pKeyStrArr);
                else if (numKeyStrBytes == 8)
                        asm_ZucGenKeystream8B_8_gfni_avx2(state, pKeyStrArr);
                else if (numKeyStrBytes == 16)
                        asm_ZucGenKeystream16B_8_gfni_avx2(state, pKeyStrArr);
                else /* 32 */
                        asm_ZucGenKeystream32B_8_gfni_avx2(state, pKeyStrArr);
        } else {
                if (numKeyStrBytes == 4)
                        asm_ZucGenKeystream4B_8_avx2(state, pKeyStrArr);
                else if (numKeyStrBytes == 8)
                        asm_ZucGenKeystream8B_8_avx2(state, pKeyStrArr);
                else if (numKeyStrBytes == 16)
                        asm_ZucGenKeystream16B_8_avx2(state, pKeyStrArr);
                else /* 32 */
                        asm_ZucGenKeystream32B_8_avx2(state, pKeyStrArr);
        }
}

static inline uint16_t
find_min_length16(const uint16_t length[NUM_AVX2_BUFS], unsigned int *allCommonBits)
{
        static const uint16_t bcast_mask[8] = { 0x0001, 0x0001, 0x0001, 0x0001,
                                                0x0001, 0x0001, 0x0001, 0x0001 };

        __m128i xmm_lengths = _mm_loadu_si128((const __m128i *) length);
        __m128i shuf_mask = _mm_loadu_si128((const __m128i *) bcast_mask);
        /* Broadcast first word of the array */
        __m128i bcast_first = _mm_shuffle_epi8(xmm_lengths, shuf_mask);
        /* Compare if all lengths are the same value */
        __m128i res = _mm_cmpeq_epi16(xmm_lengths, bcast_first);
        *allCommonBits = (_mm_movemask_epi8(res) == 0xFFFF);

        xmm_lengths = _mm_minpos_epu16(xmm_lengths);

        return _mm_extract_epi16(xmm_lengths, 0);
}

void
zuc_eea3_1_buffer_avx2(IMB_MGR *mgr, const void *pKey, const void *pIv, const void *pBufferIn,
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

void
zuc_eea3_n_buffer_avx2(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
                       const void *const pBufferIn[], void *pBufferOut[], const uint32_t length[],
                       const uint32_t numBuffers)
{
        IMB_JOB *job;
        uint32_t i;

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
zuc_eia3_1_buffer_avx2(IMB_MGR *mgr, const void *pKey, const void *pIv, const void *pBufferIn,
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
_zuc_eia3_8_buffer_job(const void *const pKey[NUM_AVX2_BUFS], const uint8_t *ivs,
                       const void *const pBufferIn[NUM_AVX2_BUFS], uint32_t *pMacI[NUM_AVX2_BUFS],
                       const uint16_t lengthInBits[NUM_AVX2_BUFS],
                       const void *const job_in_lane[NUM_AVX2_BUFS], const unsigned use_gfni)
{
        unsigned int i = 0;
        DECLARE_ALIGNED(ZucState8_t state, 64);
        DECLARE_ALIGNED(ZucState_t singlePktState, 64);
        DECLARE_ALIGNED(uint8_t keyStr[NUM_AVX2_BUFS][2 * KEYSTR_ROUND_LEN], 64);
        /* structure to store the 8 keys */
        DECLARE_ALIGNED(ZucKey8_t keys, 64);
        const uint8_t *pIn8[NUM_AVX2_BUFS] = { NULL };
        uint32_t numKeyStr = 0;
        uint32_t T[NUM_AVX2_BUFS];
        const uint32_t keyStreamLengthInBits = KEYSTR_ROUND_LEN * 8;
        DECLARE_ALIGNED(uint32_t * pKeyStrArr[NUM_AVX2_BUFS], 32) = { NULL };
        unsigned int allCommonBits;
        uint32_t remainCommonBits = find_min_length16(lengthInBits, &allCommonBits);

        memset(T, 0, sizeof(T));
        for (i = 0; i < NUM_AVX2_BUFS; i++) {
                pIn8[i] = (const uint8_t *) pBufferIn[i];
                pKeyStrArr[i] = (uint32_t *) &keyStr[i][0];
                keys.pKeys[i] = pKey[i];
        }

        init_8(&keys, ivs, &state, use_gfni);

        /* Generate 32 bytes at a time */
        keygen_8(&state, pKeyStrArr, 32, use_gfni);

        /* Point at the next 32 bytes of the key */
        for (i = 0; i < NUM_AVX2_BUFS; i++)
                pKeyStrArr[i] = (uint32_t *) &keyStr[i][KEYSTR_ROUND_LEN];
        /* loop over the message bits */
        while (remainCommonBits >= keyStreamLengthInBits) {
                remainCommonBits -= keyStreamLengthInBits;
                numKeyStr++;
                /* Generate the next key stream 8 bytes or 32 bytes */
                if (!remainCommonBits && allCommonBits)
                        keygen_8(&state, pKeyStrArr, 8, use_gfni);
                else
                        keygen_8(&state, pKeyStrArr, 32, use_gfni);

                for (i = 0; i < NUM_AVX2_BUFS; i++) {
                        if (job_in_lane[i] == NULL)
                                continue;

                        asm_Eia3Round32B_avx(&T[i], &keyStr[i][0], pIn8[i]);
                        pIn8[i] = &pIn8[i][KEYSTR_ROUND_LEN];
                }
        }

        /* Process each packet separately for the remaining bits */
        for (i = 0; i < NUM_AVX2_BUFS; i++) {
                if (job_in_lane[i] == NULL)
                        continue;

                uint32_t remainBits = lengthInBits[i] - numKeyStr * keyStreamLengthInBits;
                uint32_t *keyStr32 = (uint32_t *) keyStr[i];

                /* If remaining bits are more than 24 bytes, we need to generate
                 * at least 8B more of keystream, so we need to copy
                 * the zuc state to single packet state first */
                if (remainBits > (6 * 32)) {
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

                        /* Generate the next key stream 8 bytes or 32 bytes */
                        if (!remainBits)
                                asm_ZucGenKeystream8B_avx(&keyStr32[8], &singlePktState);
                        else
                                asm_ZucGenKeystream32B_avx(&keyStr32[8], &singlePktState);
                        asm_Eia3Round32B_avx(&T[i], &keyStr32[0], pIn8[i]);
                        pIn8[i] = &pIn8[i][KEYSTR_ROUND_LEN];
                }

                /*
                 * If remaining bits has more than 6 ZUC WORDS (double words),
                 * keystream needs to have up to another 2 ZUC WORDS (8B)
                 */

                if (remainBits > (6 * 32))
                        asm_ZucGenKeystream8B_avx(&keyStr32[8], &singlePktState);

                asm_Eia3Remainder_avx(&T[i], keyStr32, pIn8[i], remainBits);

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
zuc_eia3_8_buffer_job_avx2(const void *const pKey[NUM_AVX2_BUFS], const uint8_t *pIv,
                           const void *const pBufferIn[NUM_AVX2_BUFS],
                           uint32_t *pMacI[NUM_AVX2_BUFS],
                           const uint16_t lengthInBits[NUM_AVX2_BUFS],
                           const void *const job_in_lane[NUM_AVX2_BUFS])
{
        _zuc_eia3_8_buffer_job(pKey, pIv, pBufferIn, pMacI, lengthInBits, job_in_lane, 0);
}

void
zuc_eia3_8_buffer_job_gfni_avx2(const void *const pKey[NUM_AVX2_BUFS], const uint8_t *pIv,
                                const void *const pBufferIn[NUM_AVX2_BUFS],
                                uint32_t *pMacI[NUM_AVX2_BUFS],
                                const uint16_t lengthInBits[NUM_AVX2_BUFS],
                                const void *const job_in_lane[NUM_AVX2_BUFS])
{
        _zuc_eia3_8_buffer_job(pKey, pIv, pBufferIn, pMacI, lengthInBits, job_in_lane, 1);
}

void
zuc_eia3_n_buffer_avx2(IMB_MGR *mgr, const void *const pKey[], const void *const pIv[],
                       const void *const pBufferIn[], const uint32_t lengthInBits[],
                       uint32_t *pMacI[], const uint32_t numBuffers)
{
        IMB_JOB *job;
        uint32_t i;

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
