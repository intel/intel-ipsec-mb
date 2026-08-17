/*******************************************************************************
  Copyright (c) 2012-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef SNOW3G_SUBMIT_H
#define SNOW3G_SUBMIT_H

#include "intel-ipsec-mb.h"
#include "mb_mgr.h"

static inline IMB_JOB *
def_submit_snow3g_uea2_job(IMB_MGR *state, IMB_JOB *job)
{
        const snow3g_key_schedule_t *key = job->enc_keys;
        const uint32_t bytelen = (uint32_t) job->msg_len_to_cipher_in_bytes;
        const uint32_t byteoff = (uint32_t) job->cipher_start_src_offset_in_bytes;
        const void *src = job->src + byteoff;
        void *dst = job->dst + byteoff;

        CALL_SNOW3G_F8_1_BUFFER(state, key, job->iv, src, dst, bytelen);

        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

#endif /* SNOW3G_SUBMIT_H */
