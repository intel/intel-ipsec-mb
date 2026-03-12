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

#define NUM_NIA4_BUFS 2

IMB_DLL_LOCAL void
snow5g_nia4_x2_job_vaes_avx512(const void *const pKey[NUM_NIA4_BUFS], const uint8_t *pIv,
                               const void *const pBufferIn[NUM_NIA4_BUFS],
                               void *pMacI[NUM_NIA4_BUFS],
                               const uint16_t lengthInBytes[NUM_NIA4_BUFS],
                               const void *const job_in_lane[NUM_NIA4_BUFS]);

IMB_DLL_LOCAL void
snow5g_nia4_x2_job_vaes_avx512(const void *const pKey[NUM_NIA4_BUFS], const uint8_t *pIv,
                               const void *const pBufferIn[NUM_NIA4_BUFS],
                               void *pMacI[NUM_NIA4_BUFS],
                               const uint16_t lengthInBytes[NUM_NIA4_BUFS],
                               const void *const job_in_lane[NUM_NIA4_BUFS])
{
        DECLARE_ALIGNED(uint8_t HQP[NUM_NIA4_BUFS * 48], 64);
        DECLARE_ALIGNED(uint8_t states[NUM_NIA4_BUFS * 160], 64);

        generate_hqp_snow5g_nca4_x2_vaes_avx512(pKey, pIv, HQP, states);

        for (unsigned i = 0; i < NUM_NIA4_BUFS; i++) {
                const IMB_JOB *job = job_in_lane[i];

                if (job == NULL)
                        continue;

                DECLARE_ALIGNED(uint8_t digest[16], 16);
                struct gcm_key_data gdata;

                _mm_store_si128((__m128i *) digest, _mm_setzero_si128());
                polyval_pre_vclmul_avx512(&HQP[i * 48], &gdata);
                polyval_vclmul_avx512(&gdata, pBufferIn[i], lengthInBytes[i], digest);

                __m128i d = _mm_load_si128((const __m128i *) digest);
                d = _mm_xor_si128(d, _mm_set_epi64x((uint64_t) lengthInBytes[i] * 8, 0));
                _mm_store_si128((__m128i *) digest, d);
                polyval_16B_vclmul_avx512(&HQP[i * 48 + 16], digest);
                d = _mm_xor_si128(_mm_load_si128((const __m128i *) digest),
                                  _mm_load_si128((const __m128i *) &HQP[i * 48 + 32]));
                memcpy(pMacI[i], &d, job->auth_tag_output_len_in_bytes);

#ifdef SAFE_DATA
                clear_mem(digest, sizeof(digest));
                clear_mem(&gdata, sizeof(gdata));
#endif
        }

#ifdef SAFE_DATA
        clear_mem(HQP, sizeof(HQP));
        clear_mem(states, sizeof(states));
        clear_scratch_xmms_avx();
#endif
}
