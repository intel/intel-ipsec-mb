/*******************************************************************************
  Copyright (c) 2022-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "intel-ipsec-mb.h"
#include "mb_mgr.h"

#ifndef JOB_API_KASUMI_H
#define JOB_API_KASUMI_H

__forceinline IMB_JOB *
submit_kasumi_uea1_job(IMB_MGR *state, IMB_JOB *job)
{
        const kasumi_key_sched_t *key = job->enc_keys;
        const uint64_t iv = *(const uint64_t *) job->iv;
        const uint32_t msg_bytelen = (const uint32_t) job->msg_len_to_cipher_in_bytes;
        const uint32_t msg_byteoff = (const uint32_t) job->cipher_start_src_offset_in_bytes;
        const void *src = job->src + msg_byteoff;

        CALL_KASUMI_F8_1_BUFFER(state, key, iv, src, job->dst, msg_bytelen);

        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

#endif /* JOB_API_KASUMI_H */
