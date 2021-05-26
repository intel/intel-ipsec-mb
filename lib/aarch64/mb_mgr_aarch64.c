/**********************************************************************
  Copyright(c) 2021 Arm Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Arm Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "intel-ipsec-mb.h"
#include "include/snow3g.h"

#include "include/cpu_feature.h"
#include "include/error.h"
#include "clear_regs_mem_aarch64.h"
#include "include/noaesni.h"

/* ====================================================================== */

#define SUBMIT_JOB               submit_job_aarch64
#define FLUSH_JOB                flush_job_aarch64
#define SUBMIT_JOB_NOCHECK       submit_job_nocheck_aarch64
#define GET_NEXT_JOB             get_next_job_aarch64
#define GET_COMPLETED_JOB        get_completed_job_aarch64

#define QUEUE_SIZE               queue_size_aarch64

/* ====================================================================== */

#define SUBMIT_JOB_HASH          SUBMIT_JOB_HASH_AARCH64
#define FLUSH_JOB_HASH           FLUSH_JOB_HASH_AARCH64

/* ====================================================================== */

void
init_mb_mgr_aarch64(IMB_MGR *state)
{
#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
#endif

        /* reset error status */
        imb_set_errno(state, 0);

        state->features = cpu_feature_adjust(state->flags,
                                             cpu_feature_detect());

        if (!(state->features & IMB_FEATURE_AESNI)) {
                init_mb_mgr_aarch64_no_aesni(state);
                return;
        }

        /* Init "in order" components */
        state->next_job = 0;
        state->earliest_job = -1;

        /* set AARCH64 handlers */
        state->get_next_job                = get_next_job_aarch64;
        state->submit_job                  = submit_job_aarch64;
        state->submit_job_nocheck          = submit_job_nocheck_aarch64;
        state->get_completed_job           = get_completed_job_aarch64;
        state->flush_job                   = flush_job_aarch64;
        state->queue_size                  = queue_size_aarch64;

        state->snow3g_f8_1_buffer_bit      = snow3g_f8_1_buffer_bit_aarch64;
        state->snow3g_f8_1_buffer          = snow3g_f8_1_buffer_aarch64;
        state->snow3g_f8_2_buffer          = snow3g_f8_2_buffer_aarch64;
        state->snow3g_f8_4_buffer          = snow3g_f8_4_buffer_aarch64;
        state->snow3g_f8_8_buffer          = snow3g_f8_8_buffer_aarch64;
        state->snow3g_f8_n_buffer          = snow3g_f8_n_buffer_aarch64;
        state->snow3g_f8_8_buffer_multikey = snow3g_f8_8_buffer_multikey_aarch64;
        state->snow3g_f8_n_buffer_multikey = snow3g_f8_n_buffer_multikey_aarch64;
        state->snow3g_f9_1_buffer          = snow3g_f9_1_buffer_aarch64;
        state->snow3g_init_key_sched       = snow3g_init_key_sched_aarch64;
        state->snow3g_key_sched_size       = snow3g_key_sched_size_aarch64;
}

#include "mb_mgr_code_aarch64.h"
