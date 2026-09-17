/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <limits.h>

#define AVX512
#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_avx
#define KASUMI_F8_1_BUFFER      kasumi_f8_1_buffer_avx512
#define KASUMI_F9_1_BUFFER      kasumi_f9_1_buffer_avx512
#include "include/kasumi_common_avx.h"
