/*******************************************************************************
  Copyright (c) 2021-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#define AVX512
#define SNOW3G_INIT_KEY_SCHED snow3g_init_key_sched_avx512
#define SNOW3G_KEY_SCHED_SIZE snow3g_key_sched_size_avx512

#include "include/snow3g_common.h"
