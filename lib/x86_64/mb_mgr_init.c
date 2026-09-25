/*******************************************************************************
  Copyright (c) 2012-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * Architecture selection entry points.
 *
 * These functions decide, based on the detected CPU features, whether a given
 * architecture may be used. They must therefore be safe to execute on any CPU
 * meeting the library baseline (SSE4.2), including CPUs that do not support
 * the architecture being checked.
 *
 * For that reason they live in lib/x86_64 which is built with the baseline
 * compiler flags. Keeping them in the per-architecture directories would let
 * the compiler emit AVX2/AVX512 class instructions (e.g. BMI1 'andn' for the
 * feature mask test itself) into the gating code and crash with an invalid
 * opcode before the CPU feature check had a chance to run.
 */

#include "intel-ipsec-mb.h"
#include "include/ipsec_ooo_mgr.h"
#include "include/error.h"
#include "include/cpu_feature.h"
#include "include/arch_x86_64.h" /* self-test */

/**
 * @brief Runs the self-test after a successful manager initialization
 *
 * The self-test is skipped if the manager could not be initialized
 * (e.g. missing CPU features). The previous self-test state, including
 * a fail-closed one, is left untouched.
 *
 * @param [in] state pointer to initialized IMB_MGR structure
 */
static void
init_mb_mgr_self_test(IMB_MGR *state)
{
        if (state->imb_errno != 0)
                return;

        if (!self_test(state))
                self_test_fail_closed(state);
}

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

        init_mb_mgr_self_test(state);
}

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
#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
#endif

        /* reset error status */
        imb_set_errno(state, 0);

        init_mb_mgr_avx2_internal(state, 1);

        init_mb_mgr_self_test(state);
}

IMB_DLL_LOCAL void
init_mb_mgr_avx512_internal(IMB_MGR *state, const int reset_mgrs)
{
#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
#endif

        /* Check minimum CPU flags needed for AVX512 interface */
        if ((state->features & IMB_CPUFLAGS_AVX512) != IMB_CPUFLAGS_AVX512) {
                imb_set_errno(state, IMB_ERR_MISSING_CPUFLAGS_INIT_MGR);
                return;
        }

        if ((state->features & IMB_CPUFLAGS_AVX512_T2) == IMB_CPUFLAGS_AVX512_T2)
                init_mb_mgr_avx512_t2_internal(state, reset_mgrs);
        else
                init_mb_mgr_avx512_t1_internal(state, reset_mgrs);
}

void
init_mb_mgr_avx512(IMB_MGR *state)
{
#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
#endif

        /* reset error status */
        imb_set_errno(state, 0);

        init_mb_mgr_avx512_internal(state, 1);

        init_mb_mgr_self_test(state);
}

IMB_DLL_LOCAL void
init_mb_mgr_avx10_internal(IMB_MGR *state, const int reset_mgrs)
{
#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
#endif

        /* Check minimum CPU flags needed for AVX10 interface */
        if ((state->features & IMB_CPUFLAGS_AVX10) != IMB_CPUFLAGS_AVX10) {
                imb_set_errno(state, IMB_ERR_MISSING_CPUFLAGS_INIT_MGR);
                return;
        }

#ifdef SMX_NI
        init_mb_mgr_avx10_t1_internal(state, reset_mgrs);
#else
        /* If SM4/SM3/SHA512-NI instructions are not supported by the assembler, fallback to
         * AVX512-T2 implementations */
        init_mb_mgr_avx512_t2_internal(state, reset_mgrs);
#endif
}

void
init_mb_mgr_avx10(IMB_MGR *state)
{
#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
#endif

        /* reset error status */
        imb_set_errno(state, 0);

        init_mb_mgr_avx10_internal(state, 1);

        init_mb_mgr_self_test(state);
}
