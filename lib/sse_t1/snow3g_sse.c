/*******************************************************************************
  Copyright (c) 2019-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#define SSE
#define SNOW3G_INIT_KEY_SCHED   snow3g_init_key_sched_sse
#define SNOW3G_KEY_SCHED_SIZE   snow3g_key_sched_size_sse
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_sse

#include "include/snow3g_common.h"
#include "include/ipsec_ooo_mgr.h"

IMB_DLL_LOCAL void
submit_job_snow3g_uea2_sse(MB_MGR_SNOW3G_OOO *, IMB_JOB *);
IMB_DLL_LOCAL void flush_job_snow3g_uea2_sse(MB_MGR_SNOW3G_OOO);
