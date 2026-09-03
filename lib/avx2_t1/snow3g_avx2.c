/*******************************************************************************
  Copyright (c) 2019-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifdef _WIN32
/* use AVX implementation on Windows for now */
#define AVX
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_avx
#else
#define AVX2
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_ymms
#endif
#define SNOW3G_F9_1_BUFFER    snow3g_f9_1_buffer_avx2
#define SNOW3G_INIT_KEY_SCHED snow3g_init_key_sched_avx2
#define SNOW3G_KEY_SCHED_SIZE snow3g_key_sched_size_avx2

#include "include/snow3g_common.h"
