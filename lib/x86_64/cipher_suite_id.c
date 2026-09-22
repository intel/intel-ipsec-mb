/*******************************************************************************
  Copyright (c) 2023-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "intel-ipsec-mb.h"
#include "include/error.h"
#include "include/arch_x86_64.h"
#include "include/mb_mgr_job_check.h"

IMB_DLL_EXPORT uint32_t
imb_set_session(IMB_MGR *state, IMB_JOB *job)
{
        struct {
                uint16_t key_len;
                uint16_t hash_alg;
                uint16_t cipher_mode;
                uint16_t cipher_dir;
                uint64_t counter;
        } extract;
        static uint64_t counter = 1;

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return 0;
        }
        if (job == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_JOB);
                return 0;
        }
        if (is_job_invalid_light(state, job->cipher_mode, job->hash_alg, job->cipher_direction,
                                 job->key_len_in_bytes))
                return 0; /* errno is set inside is_job_invalid() */
        imb_set_errno(state, 0);
#endif
        /* Fill in suite_id[] structure in \a job */
        state->set_suite_id(state, job);

        /**
         * Calculate and set session_id in \a job
         * Set up extract structure:
         * - collect session specific data
         * - plus counter value (secures different ID for the same
         *   cipher suite params)
         * Session ID is CRC calculated on the extract structure.
         */
        extract.key_len = (uint16_t) job->key_len_in_bytes;
        extract.hash_alg = (uint16_t) job->hash_alg;
        extract.cipher_mode = (uint16_t) job->cipher_mode;
        extract.cipher_dir = (uint16_t) job->cipher_direction;
        extract.counter = atomic_uint64_inc(&counter);

        const uint32_t id = state->crc32_wimax_ofdma_data(&extract, sizeof(extract));

        job->session_id = id;
        return id;
}
