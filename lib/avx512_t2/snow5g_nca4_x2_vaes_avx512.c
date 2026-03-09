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

#include <string.h>
#include <immintrin.h>

#include "intel-ipsec-mb.h"
#include "include/wireless_common.h"
#include "include/clear_regs_mem.h"
#include "include/error.h"
#include "include/arch_avx512_type2.h"

#define NUM_NCA4_BUFS 2

static inline void
tag_finalize(const uint8_t *Q, const uint8_t *P, uint8_t *digest, const IMB_JOB *job)
{
        const uint64_t msg_len_bits = job->msg_len_to_cipher_in_bytes * 8;
        const uint64_t aad_len_bits = job->u.NCA.aad_len_in_bytes * 8;
        __m128i d = _mm_xor_si128(_mm_load_si128((const __m128i *) digest),
                                  _mm_set_epi64x(aad_len_bits, msg_len_bits));
        _mm_store_si128((__m128i *) digest, d);
        polyval_16B_vclmul_avx512(Q, digest);
        d = _mm_xor_si128(_mm_load_si128((const __m128i *) digest),
                          _mm_load_si128((const __m128i *) P));
        memcpy(job->auth_tag_output, &d, job->auth_tag_output_len_in_bytes);
}

IMB_DLL_LOCAL void
snow5g_nca4_x2_job_vaes_avx512(const void *const pKey[NUM_NCA4_BUFS], const uint8_t *pIv,
                               const void *const pBufferIn[NUM_NCA4_BUFS],
                               void *pBufferOut[NUM_NCA4_BUFS],
                               const void *const job_in_lane[NUM_NCA4_BUFS], const int decrypt);

IMB_DLL_LOCAL void
snow5g_nca4_x2_job_vaes_avx512(const void *const pKey[NUM_NCA4_BUFS], const uint8_t *pIv,
                               const void *const pBufferIn[NUM_NCA4_BUFS],
                               void *pBufferOut[NUM_NCA4_BUFS],
                               const void *const job_in_lane[NUM_NCA4_BUFS], const int decrypt)
{
        DECLARE_ALIGNED(uint8_t HQP[NUM_NCA4_BUFS * 48], 64);
        DECLARE_ALIGNED(uint8_t states[NUM_NCA4_BUFS * 160], 64);

        generate_hqp_snow5g_nca4_x2_vaes_avx512(pKey, pIv, HQP, states);

        DECLARE_ALIGNED(uint8_t digests[NUM_NCA4_BUFS * 16], 16);
        DECLARE_ALIGNED(struct gcm_key_data gdata_keys[NUM_NCA4_BUFS], 16);

        uint64_t lens[NUM_NCA4_BUFS] = { 0, 0 };
        for (unsigned i = 0; i < NUM_NCA4_BUFS; i++) {
                const IMB_JOB *job = (const IMB_JOB *) job_in_lane[i];

                if (job == NULL)
                        continue;

                _mm_store_si128((__m128i *) &digests[i * 16], _mm_setzero_si128());
                polyval_pre_vclmul_avx512(&HQP[i * 48], &gdata_keys[i]);

                if (job->u.NCA.aad_len_in_bytes != 0)
                        polyval_vclmul_avx512(&gdata_keys[i], job->u.NCA.aad,
                                              job->u.NCA.aad_len_in_bytes, &digests[i * 16]);

                if (decrypt)
                        polyval_vclmul_avx512(&gdata_keys[i], pBufferIn[i],
                                              job->msg_len_to_cipher_in_bytes, &digests[i * 16]);

                lens[i] = job->msg_len_to_cipher_in_bytes;
        }

        if (lens[0] && lens[1])
                snow5g_nca4_cipher_x2(states, pBufferIn, pBufferOut, lens[0], lens[1]);
        else if (lens[0])
                snow5g_nca4_cipher_x1(states, pBufferIn, pBufferOut, lens[0]);
        else if (lens[1]) /* lane 0: AAD-only (no plaintext), lane 1: has data */
                snow5g_nca4_cipher_x2(states, pBufferIn, pBufferOut, 0, lens[1]);

        for (unsigned i = 0; i < NUM_NCA4_BUFS; i++) {
                const IMB_JOB *job = (const IMB_JOB *) job_in_lane[i];

                if (job == NULL)
                        continue;

                if (!decrypt && job->msg_len_to_cipher_in_bytes > 0)
                        polyval_vclmul_avx512(&gdata_keys[i], pBufferOut[i],
                                              job->msg_len_to_cipher_in_bytes, &digests[i * 16]);

                tag_finalize(&HQP[i * 48 + 16], &HQP[i * 48 + 32], &digests[i * 16], job);
        }

#ifdef SAFE_DATA
        clear_mem(HQP, sizeof(HQP));
        clear_mem(states, sizeof(states));
        clear_mem(digests, sizeof(digests));
        clear_mem(&gdata_keys, sizeof(gdata_keys));
        clear_scratch_xmms_avx();
#endif
}
