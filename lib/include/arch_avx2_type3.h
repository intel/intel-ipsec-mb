/*******************************************************************************
  Copyright (c) 2023-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/* AVX_IFMA */

#ifndef IMB_ASM_AVX2_T3_H
#define IMB_ASM_AVX2_T3_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

void
poly1305_mac_fma_avx2(IMB_JOB *job);

IMB_DLL_EXPORT void
set_suite_id_avx2_t3(IMB_MGR *state, IMB_JOB *job);

#endif /* IMB_ASM_AVX2_T3_H */
