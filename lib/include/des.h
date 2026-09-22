/*******************************************************************************
  Copyright (c) 2017-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef IMB_DES_H
#define IMB_DES_H

#include <stdint.h>
#include "arch_sse_type1.h"

/* ========================================================================= */
/* DES and 3DES inline function for use in mb_mgr_code.h                     */
/* ========================================================================= */

/**
 * @brief DES cipher encryption
 *
 * @param job description of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline IMB_JOB *
DES_CBC_ENC(IMB_JOB *job)
{
        IMB_ASSERT(!(job->status & IMB_STATUS_COMPLETED_CIPHER));
        des_enc_cbc_sse(job->src + job->cipher_start_src_offset_in_bytes, job->dst,
                        job->msg_len_to_cipher_in_bytes & (~(IMB_DES_BLOCK_SIZE - 1)),
                        job->enc_keys, (const uint64_t *) job->iv);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/**
 * @brief DES cipher decryption
 *
 * @param job description of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline IMB_JOB *
DES_CBC_DEC(IMB_JOB *job)
{
        IMB_ASSERT(!(job->status & IMB_STATUS_COMPLETED_CIPHER));
        des_dec_cbc_sse(job->src + job->cipher_start_src_offset_in_bytes, job->dst,
                        job->msg_len_to_cipher_in_bytes & (~(IMB_DES_BLOCK_SIZE - 1)),
                        job->dec_keys, (const uint64_t *) job->iv);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/**
 * @brief 3DES cipher encryption
 *
 * @param job description of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline IMB_JOB *
DES3_CBC_ENC(IMB_JOB *job)
{
        const void *const *ks_ptr = (const void *const *) job->enc_keys;

        IMB_ASSERT(!(job->status & IMB_STATUS_COMPLETED_CIPHER));
        des3_enc_cbc_sse(job->src + job->cipher_start_src_offset_in_bytes, job->dst,
                         job->msg_len_to_cipher_in_bytes & (~(IMB_DES_BLOCK_SIZE - 1)), ks_ptr[0],
                         ks_ptr[1], ks_ptr[2], (const uint64_t *) job->iv);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/**
 * @brief 3DES cipher decryption
 *
 * @param job description of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline IMB_JOB *
DES3_CBC_DEC(IMB_JOB *job)
{
        const void *const *ks_ptr = (const void *const *) job->dec_keys;

        IMB_ASSERT(!(job->status & IMB_STATUS_COMPLETED_CIPHER));
        des3_dec_cbc_sse(job->src + job->cipher_start_src_offset_in_bytes, job->dst,
                         job->msg_len_to_cipher_in_bytes & (~(IMB_DES_BLOCK_SIZE - 1)), ks_ptr[0],
                         ks_ptr[1], ks_ptr[2], (const uint64_t *) job->iv);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

#endif /* IMB_DES_H */
