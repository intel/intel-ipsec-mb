/*******************************************************************************
  Copyright (c) 2021-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifdef _WIN32
/* use AVX implementation on Windows for now */
#define AVX
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_avx
#else
#define AVX512
/* SNOW3G-UEA2 direct functions use up to AVX2 implementations */
#define AVX2
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_zmms
#endif

#define SNOW3G_F8_1_BUFFER    snow3g_f8_1_buffer_avx512
#define SNOW3G_F9_1_BUFFER    snow3g_f9_1_buffer_avx512
#define SNOW3G_INIT_KEY_SCHED snow3g_init_key_sched_avx512
#define SNOW3G_KEY_SCHED_SIZE snow3g_key_sched_size_avx512

#include "include/snow3g_common.h"
