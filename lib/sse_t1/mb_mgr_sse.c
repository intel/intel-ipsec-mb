/*******************************************************************************
  Copyright (c) 2012-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "intel-ipsec-mb.h"
#include "include/ipsec_ooo_mgr.h"
#include "include/error.h"
#include "include/cpu_feature.h"
#include "include/arch_x86_64.h"

IMB_DLL_LOCAL void
init_mb_mgr_sse_internal(IMB_MGR *state, const int reset_mgrs)
{
#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
#endif

        /* Check minimum CPU flags needed for SSE interface */
        if ((state->features & IMB_CPUFLAGS_SSE) != IMB_CPUFLAGS_SSE) {
                imb_set_errno(state, IMB_ERR_MISSING_CPUFLAGS_INIT_MGR);
                return;
        }

        if ((state->features & IMB_CPUFLAGS_SSE_T3) == IMB_CPUFLAGS_SSE_T3)
                init_mb_mgr_sse_t3_internal(state, reset_mgrs);
        else if ((state->features & IMB_CPUFLAGS_SSE_T2) == IMB_CPUFLAGS_SSE_T2)
                init_mb_mgr_sse_t2_internal(state, reset_mgrs);
        else
                init_mb_mgr_sse_t1_internal(state, reset_mgrs);
}

void
init_mb_mgr_sse(IMB_MGR *state)
{
#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
#endif

        /* reset error status */
        imb_set_errno(state, 0);

        init_mb_mgr_sse_internal(state, 1);

        /*
         * Skip the self-test if the manager could not be initialized
         * (e.g. missing CPU features). The previous self-test state,
         * including a fail-closed one, is left untouched.
         */
        if (state->imb_errno != 0)
                return;

        if (!self_test(state))
                self_test_fail_closed(state);
}

IMB_JOB *
submit_job_sse(IMB_MGR *state)
{
        return IMB_SUBMIT_JOB(state);
}

IMB_JOB *
flush_job_sse(IMB_MGR *state)
{
        return IMB_FLUSH_JOB(state);
}

uint32_t
queue_size_sse(IMB_MGR *state)
{
        return IMB_QUEUE_SIZE(state);
}

IMB_JOB *
submit_job_nocheck_sse(IMB_MGR *state)
{
        return IMB_SUBMIT_JOB_NOCHECK(state);
}

IMB_JOB *
get_next_job_sse(IMB_MGR *state)
{
        return IMB_GET_NEXT_JOB(state);
}

IMB_JOB *
get_completed_job_sse(IMB_MGR *state)
{
        return IMB_GET_COMPLETED_JOB(state);
}
