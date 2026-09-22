/*******************************************************************************
  Copyright (c) 2022-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/* ARCH SSE TYPE 3: SSE4.2, AESNI, PCLMULQDQ, CMOV, BSWAP, SHANI, GFNI */

#ifndef IMB_ASM_SSE_T3_H
#define IMB_ASM_SSE_T3_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

/* moved from MB MGR */

IMB_JOB *
submit_job_zuc_eea3_gfni_sse(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_eea3_gfni_sse(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_nea6_gfni_sse(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_nea6_gfni_sse(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_eia3_gfni_sse(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_eia3_gfni_sse(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_nia6_gfni_sse(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_nia6_gfni_sse(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_nca6_gfni_sse(MB_MGR_ZUC_OOO *state, IMB_JOB *job, IMB_CIPHER_DIRECTION dir);
IMB_JOB *
flush_job_zuc_nca6_gfni_sse(MB_MGR_ZUC_OOO *state, IMB_CIPHER_DIRECTION dir);

IMB_DLL_EXPORT void
set_suite_id_sse_t3(IMB_MGR *state, IMB_JOB *job);

#endif /* IMB_ASM_SSE_T3_H */
