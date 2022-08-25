/*******************************************************************************
 Copyright (c) 2012-2022, Intel Corporation

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
#include "include/ipsec_ooo_mgr.h"
#include "include/cpu_feature.h"
#include "include/aesni_emu.h"
#include "include/error.h"
#include "include/arch_x86_64.h"

IMB_DLL_LOCAL void
init_mb_mgr_avx2_internal(IMB_MGR *state, const int reset_mgrs)
{
#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
#endif

        if (!(state->features & IMB_FEATURE_AESNI)) {
                fallback_no_aesni(state, 1);
                return;
        }

        /* reset error status */
        imb_set_errno(state, 0);

        state->features = cpu_feature_adjust(state->flags,
                                             cpu_feature_detect());

        if ((state->features & IMB_CPUFLAGS_AVX2_T2) ==
            IMB_CPUFLAGS_AVX2_T2)
                init_mb_mgr_avx2_t2_internal(state, reset_mgrs);
        else
                init_mb_mgr_avx2_t1_internal(state, reset_mgrs);
}

void
init_mb_mgr_avx2(IMB_MGR *state)
{
        init_mb_mgr_avx2_internal(state, 1);

        if (!self_test(state))
                imb_set_errno(state, IMB_ERR_SELFTEST);
}

IMB_JOB *submit_job_avx2(IMB_MGR *state)
{
        return IMB_SUBMIT_JOB(state);
}

IMB_JOB *flush_job_avx2(IMB_MGR *state)
{
        return IMB_FLUSH_JOB(state);
}

uint32_t queue_size_avx2(IMB_MGR *state)
{
        return IMB_QUEUE_SIZE(state);
}

IMB_JOB *submit_job_nocheck_avx2(IMB_MGR *state)
{
        return IMB_SUBMIT_JOB_NOCHECK(state);
}

IMB_JOB *get_next_job_avx2(IMB_MGR *state)
{
        return IMB_GET_NEXT_JOB(state);
}

IMB_JOB *get_completed_job_avx2(IMB_MGR *state)
{
        return IMB_GET_COMPLETED_JOB(state);
}
