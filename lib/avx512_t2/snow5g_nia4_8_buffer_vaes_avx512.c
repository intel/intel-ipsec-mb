/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

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

/*
 * SNOW5G-NIA4 8-buffer AVX512 implementation
 * 1. Initialize all 8 SNOW5G states in parallel using ASM
 * 2. Generate H,Q,P keystream for all 8 buffers
 * 3. Process POLYVAL for each buffer
 */

#include <string.h>
#include <immintrin.h>

#include "intel-ipsec-mb.h"
#include "include/wireless_common.h"
#include "include/clear_regs_mem.h"
#include "include/error.h"

#define NUM_AVX512_BUFS 8

/*
 * External ASM function for parallel 8-buffer HQP generation
 * This function:
 *   1. Initializes 8 SNOW5G states from keys and IVs
 *   2. Runs 17 init rounds (15 + 2 with key XOR) with keystream feedback
 *   3. Generates 3 keystream blocks (H, Q, P) for all 8 lanes in parallel
 *
 * Arguments:
 *   pKey     - Array of 8 key pointers (256-bit keys)
 *   pIv      - Base of IV array (8 x 16 bytes)
 *   hqp      - Output buffer (8 x 48 bytes)
 *              Layout: hqp[lane*48 + 0..15]=H, [16..31]=Q, [32..47]=P
 */
extern void
generate_hqp_snow5g_nia4_x8_vaes_avx512(const void *const pKey[NUM_AVX512_BUFS], const uint8_t *pIv,
                                        uint8_t *hqp);

extern void
polyval_pre_vclmul_avx512(const void *key, struct gcm_key_data *gdata);

extern void
polyval_vclmul_avx512(const struct gcm_key_data *gdata, const void *src, const uint64_t len,
                      void *tag);

extern void
polyval_16B_vclmul_avx512(const void *key, void *tag);

/* Forward declaration */
IMB_DLL_LOCAL void
snow5g_nia4_8_buffer_job_vaes_avx512(const void *const pKey[NUM_AVX512_BUFS], const uint8_t *pIv,
                                     const void *const pBufferIn[NUM_AVX512_BUFS],
                                     void *pMacI[NUM_AVX512_BUFS],
                                     const uint16_t lengthInBytes[NUM_AVX512_BUFS],
                                     const void *const job_in_lane[NUM_AVX512_BUFS]);

/* Process 8 SNOW5G-NIA4 authentication jobs in parallel */
IMB_DLL_LOCAL void
snow5g_nia4_8_buffer_job_vaes_avx512(const void *const pKey[NUM_AVX512_BUFS], const uint8_t *pIv,
                                     const void *const pBufferIn[NUM_AVX512_BUFS],
                                     void *pMacI[NUM_AVX512_BUFS],
                                     const uint16_t lengthInBytes[NUM_AVX512_BUFS],
                                     const void *const job_in_lane[NUM_AVX512_BUFS])
{
        /* HQP array: 8 buffers x 48 bytes (H[16] + Q[16] + P[16]) */
        DECLARE_ALIGNED(uint8_t HQP[NUM_AVX512_BUFS * 48], 64);

        /* Generate H, Q, P for all 8 buffers in parallel */
        generate_hqp_snow5g_nia4_x8_vaes_avx512(pKey, pIv, HQP);

        /* Process POLYVAL for each buffer */
        for (unsigned i = 0; i < NUM_AVX512_BUFS; i++) {
                const IMB_JOB *job = job_in_lane[i];

                if (job == NULL)
                        continue;

                const uint8_t *H = &HQP[i * 48];
                const uint8_t *Q = &HQP[i * 48 + 16];
                const uint8_t *P = &HQP[i * 48 + 32];
                DECLARE_ALIGNED(uint8_t digest[16], 16);
                struct gcm_key_data gdata_key;
                __m128i digest_xmm;

                /* POLYVAL: precompute keys, hash message */
                _mm_store_si128((__m128i *) digest, _mm_setzero_si128());
                polyval_pre_vclmul_avx512(H, &gdata_key);
                polyval_vclmul_avx512(&gdata_key, pBufferIn[i], lengthInBytes[i], digest);

                /* XOR with length encoding, hash with Q */
                digest_xmm = _mm_xor_si128(_mm_load_si128((const __m128i *) digest),
                                           _mm_set_epi64x((uint64_t) lengthInBytes[i] * 8, 0));
                _mm_store_si128((__m128i *) digest, digest_xmm);
                polyval_16B_vclmul_avx512(Q, digest);

                /* Final tag = digest XOR P */
                digest_xmm = _mm_xor_si128(_mm_load_si128((const __m128i *) digest),
                                           _mm_load_si128((const __m128i *) P));
                memcpy(pMacI[i], &digest_xmm, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
                clear_mem(&gdata_key, sizeof(gdata_key));
#endif
        }

#ifdef SAFE_DATA
        clear_mem(HQP, sizeof(HQP));
        clear_scratch_xmms_avx();
#endif
}
