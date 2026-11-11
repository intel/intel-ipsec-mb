/*******************************************************************************
  Copyright (c) 2009-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
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
#include "include/clear_regs_mem.h"
#include "intel-ipsec-mb.h"
#include "include/error.h"
#include "include/arch_sse_type1.h"

#define NUM_SSE_BUFS     4
#define KEYSTR_ROUND_LEN 16

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

static void
shuffle(uint8_t H[16])
{
        uint32_t *H32 = (uint32_t *) H;
        for (int i = 0; i < 4; i++)
                H32[i] = bswap4(H32[i]);
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
        DECLARE_ALIGNED(uint32_t *pKeyStrArr[NUM_SSE_BUFS], 16) = { NULL };
        DECLARE_ALIGNED(const uint64_t *pIn64[NUM_SSE_BUFS], 64) = { NULL };
        DECLARE_ALIGNED(uint64_t *pOut64[NUM_SSE_BUFS], 64) = { NULL };
        /* structure to store the 4 keys */
        DECLARE_ALIGNED(ZucKey4_t keys, 64);

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

        if (dir == IMB_DIR_DECRYPT) {
                for (i = 0; i < NUM_SSE_BUFS; i++) {
                        const IMB_JOB *job = job_in_lane[i];
                        uint8_t hqp[3 * 16];
                        uint8_t tag[16];

                        if (job == NULL)
                                continue;

                        shuffle(H[i]);
                        shuffle(Q[i]);
                        shuffle(P[i]);
                        memcpy(&hqp[0], H[i], 16);
                        memcpy(&hqp[16], Q[i], 16);
                        memcpy(&hqp[32], P[i], 16);

                        nca_clmul_sse(tag, hqp, pBufferIn[i], lengthInBytes[i], job->u.NCA.aad,
                                      job->u.NCA.aad_len_in_bytes);
                        memcpy(job->auth_tag_output, tag, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
                        clear_mem(hqp, sizeof(hqp));
#endif
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
                        uint8_t hqp[3 * 16];
                        uint8_t tag[16];

                        shuffle(H[i]);
                        shuffle(Q[i]);
                        shuffle(P[i]);
                        memcpy(&hqp[0], H[i], 16);
                        memcpy(&hqp[16], Q[i], 16);
                        memcpy(&hqp[32], P[i], 16);

                        nca_clmul_sse(tag, hqp, pBufferOut[i], lengthInBytes[i], job->u.NCA.aad,
                                      job->u.NCA.aad_len_in_bytes);
                        memcpy(job->auth_tag_output, tag, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
                        clear_mem(hqp, sizeof(hqp));
#endif
                }
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
