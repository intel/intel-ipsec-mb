/*******************************************************************************
  Copyright (c) 2022-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "intel-ipsec-mb.h"
#include "include/docsis_common.h"

#ifndef JOB_API_DOCSIS_H
#define JOB_API_DOCSIS_H

__forceinline IMB_JOB *
submit_docsis_enc_job(IMB_MGR *state, IMB_JOB *job, const uint64_t key_sz)
{
        if (16 == key_sz) {
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis128_crc32_sec_ooo;

                        return SUBMIT_JOB_DOCSIS128_SEC_CRC_ENC(p_ooo, job);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis128_sec_ooo;

                        return SUBMIT_JOB_DOCSIS128_SEC_ENC(p_ooo, job);
                }
        } else { /* 32 */
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis256_crc32_sec_ooo;

                        return SUBMIT_JOB_DOCSIS256_SEC_CRC_ENC(p_ooo, job);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis256_sec_ooo;

                        return SUBMIT_JOB_DOCSIS256_SEC_ENC(p_ooo, job);
                }
        }
}

__forceinline IMB_JOB *
flush_docsis_enc_job(IMB_MGR *state, IMB_JOB *job, const uint64_t key_sz)
{
        if (16 == key_sz) {
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis128_crc32_sec_ooo;

                        return FLUSH_JOB_DOCSIS128_SEC_CRC_ENC(p_ooo);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis128_sec_ooo;

                        return FLUSH_JOB_DOCSIS128_SEC_ENC(p_ooo);
                }
        } else { /* 32 */
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis256_crc32_sec_ooo;

                        return FLUSH_JOB_DOCSIS256_SEC_CRC_ENC(p_ooo);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis256_sec_ooo;

                        return FLUSH_JOB_DOCSIS256_SEC_ENC(p_ooo);
                }
        }
}

__forceinline IMB_JOB *
submit_docsis_dec_job(IMB_MGR *state, IMB_JOB *job, const uint64_t key_sz)
{
        if (16 == key_sz) {
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis128_crc32_sec_ooo;

                        return SUBMIT_JOB_DOCSIS128_SEC_CRC_DEC(p_ooo, job);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis128_sec_ooo;

                        return SUBMIT_JOB_DOCSIS128_SEC_DEC(p_ooo, job);
                }
        } else { /* 32 */
                if (job->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis256_crc32_sec_ooo;

                        return SUBMIT_JOB_DOCSIS256_SEC_CRC_DEC(p_ooo, job);
                } else {
                        MB_MGR_DOCSIS_AES_OOO *p_ooo = state->docsis256_sec_ooo;

                        return SUBMIT_JOB_DOCSIS256_SEC_DEC(p_ooo, job);
                }
        }
}

#endif /* JOB_API_DOCSIS_H */
