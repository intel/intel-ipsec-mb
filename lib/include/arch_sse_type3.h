/*******************************************************************************
  Copyright (c) 2022-2024, Intel Corporation

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

      * Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
      * Neither the name of Intel Corporation nor the names of its contributors
        may be used to endorse or promote products derived from this software
        without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
submit_job_zuc_eia3_gfni_sse(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_eia3_gfni_sse(MB_MGR_ZUC_OOO *state);

IMB_DLL_EXPORT void
set_suite_id_sse_t3(IMB_MGR *state, IMB_JOB *job);

#endif /* IMB_ASM_SSE_T3_H */
