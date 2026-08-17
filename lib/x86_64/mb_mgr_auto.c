/*******************************************************************************
  Copyright (c) 2020-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "intel-ipsec-mb.h"
#include "cpu_feature.h"
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

        if ((state->features & IMB_CPUFLAGS_SSE) == IMB_CPUFLAGS_SSE) {
                init_mb_mgr_sse(state);
                arch_detected = IMB_ARCH_SSE;
                goto init_mb_mgr_auto_ret;
        }

        imb_set_errno(state, IMB_ERR_MISSING_CPUFLAGS_INIT_MGR);

init_mb_mgr_auto_ret:
        if (arch != NULL)
                *arch = arch_detected;
}
