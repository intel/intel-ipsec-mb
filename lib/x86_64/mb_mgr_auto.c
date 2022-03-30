/*******************************************************************************
  Copyright (c) 2020-2022, Intel Corporation

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

#include "intel-ipsec-mb.h"
#include "cpu_feature.h"
#include "include/noaesni.h"
#include "error.h"

/**
 * @brief Automatically initialize most performant
 *        Multi-buffer manager based on CPU features
 *
 * @param [in]  state Pointer to MB_MGR struct
 * @param [out] arch Pointer to arch enum to be set (can be NULL)
 */
void
init_mb_mgr_auto(IMB_MGR *state, IMB_ARCH *arch)
{
        IMB_ARCH arch_detected = IMB_ARCH_NONE;
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
#endif
        if ((state->features & IMB_CPUFLAGS_AVX512) == IMB_CPUFLAGS_AVX512) {
                init_mb_mgr_avx512(state);
                arch_detected = IMB_ARCH_AVX512;
                goto init_mb_mgr_auto_ret;
        }
        if ((state->features & IMB_CPUFLAGS_AVX2) == IMB_CPUFLAGS_AVX2) {
                init_mb_mgr_avx2(state);
                arch_detected = IMB_ARCH_AVX2;
                goto init_mb_mgr_auto_ret;
        }

        if ((state->features & IMB_CPUFLAGS_AVX) == IMB_CPUFLAGS_AVX) {
                init_mb_mgr_avx(state);
                arch_detected = IMB_ARCH_AVX;
                goto init_mb_mgr_auto_ret;
        }

        if ((state->features & IMB_CPUFLAGS_SSE) == IMB_CPUFLAGS_SSE) {
                init_mb_mgr_sse(state);
                arch_detected = IMB_ARCH_SSE;
                goto init_mb_mgr_auto_ret;
        }

#ifdef AESNI_EMU
        if ((state->features & IMB_CPUFLAGS_NO_AESNI) == IMB_CPUFLAGS_NO_AESNI) {
                init_mb_mgr_sse_no_aesni(state);
                arch_detected = IMB_ARCH_NOAESNI;
                goto init_mb_mgr_auto_ret;
        }
#endif
        imb_set_errno(state, ENODEV);

 init_mb_mgr_auto_ret:
        if (arch != NULL)
                *arch = arch_detected;
}
