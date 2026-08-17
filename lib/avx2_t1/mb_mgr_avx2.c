/*******************************************************************************
 Copyright (c) 2012-2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "intel-ipsec-mb.h"
#include "include/ipsec_ooo_mgr.h"
#include "include/cpu_feature.h"
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

        /* Check minimum CPU flags needed for AVX2 interface */
        if ((state->features & IMB_CPUFLAGS_AVX2) != IMB_CPUFLAGS_AVX2) {
                imb_set_errno(state, IMB_ERR_MISSING_CPUFLAGS_INIT_MGR);
                return;
        }

#ifdef SMX_NI
        if ((state->features & IMB_CPUFLAGS_AVX2_T4) == IMB_CPUFLAGS_AVX2_T4) {
                init_mb_mgr_avx2_t4_internal(state, reset_mgrs);
                return;
        }
#endif
#ifdef AVX_IFMA
        if ((state->features & IMB_CPUFLAGS_AVX2_T3) == IMB_CPUFLAGS_AVX2_T3) {
                init_mb_mgr_avx2_t3_internal(state, reset_mgrs);
                return;
        }
#endif
        if ((state->features & IMB_CPUFLAGS_AVX2_T2) == IMB_CPUFLAGS_AVX2_T2) {
                init_mb_mgr_avx2_t2_internal(state, reset_mgrs);
                return;
        }

        init_mb_mgr_avx2_t1_internal(state, reset_mgrs);
}

void
init_mb_mgr_avx2(IMB_MGR *state)
{
        init_mb_mgr_avx2_internal(state, 1);

        if (!self_test(state))
                imb_set_errno(state, IMB_ERR_SELFTEST);
}

IMB_JOB *
submit_job_avx2(IMB_MGR *state)
{
        return IMB_SUBMIT_JOB(state);
}

IMB_JOB *
flush_job_avx2(IMB_MGR *state)
{
        return IMB_FLUSH_JOB(state);
}

uint32_t
queue_size_avx2(IMB_MGR *state)
{
        return IMB_QUEUE_SIZE(state);
}

IMB_JOB *
submit_job_nocheck_avx2(IMB_MGR *state)
{
        return IMB_SUBMIT_JOB_NOCHECK(state);
}

IMB_JOB *
get_next_job_avx2(IMB_MGR *state)
{
        return IMB_GET_NEXT_JOB(state);
}

IMB_JOB *
get_completed_job_avx2(IMB_MGR *state)
{
        return IMB_GET_COMPLETED_JOB(state);
}
