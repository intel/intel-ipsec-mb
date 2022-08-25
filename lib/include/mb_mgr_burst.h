/*******************************************************************************
  Copyright (c) 2022, Intel Corporation

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

#ifndef MB_MGR_BURST_H
#define MB_MGR_BURST_H

/* synchronous cipher and hash burst API */

#include "intel-ipsec-mb.h"
#include "include/error.h"
#include "include/mb_mgr_job_check.h" /* is_job_invalid() */

__forceinline
uint32_t submit_aes_cbc_burst_enc(IMB_MGR *state,
                                  IMB_JOB *jobs,
                                  const uint32_t n_jobs,
                                  const IMB_KEY_SIZE_BYTES key_size,
                                  const int run_check)
{
        uint32_t completed_jobs = 0;

        if (run_check) {
                uint32_t i;

                /* validate jobs */
                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        /* validate job */
                        if (is_job_invalid(state, job,
                                           IMB_CIPHER_CBC, IMB_AUTH_NULL,
                                           IMB_DIR_ENCRYPT, key_size)) {
                                job->status = IMB_STATUS_INVALID_ARGS;
                                return 0;
                        }
                }
        }

        if (key_size == IMB_KEY_128_BYTES) {
                MB_MGR_AES_OOO *aes_ooo = state->aes128_ooo;
                uint32_t i;

                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        job = SUBMIT_JOB_AES_CBC_128_ENC(aes_ooo, job);
                        if (job != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }

                if (completed_jobs != n_jobs) {
                        IMB_JOB *job = NULL;

                        while((job = FLUSH_JOB_AES_CBC_128_ENC(aes_ooo))
                              != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
        } else if (key_size == IMB_KEY_192_BYTES) {
                MB_MGR_AES_OOO *aes_ooo = state->aes192_ooo;
                uint32_t i;

                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        job = SUBMIT_JOB_AES_CBC_192_ENC(aes_ooo, job);
                        if (job != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }

                if (completed_jobs != n_jobs) {
                        IMB_JOB *job = NULL;

                        while((job = FLUSH_JOB_AES_CBC_192_ENC(aes_ooo))
                              != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
        } else { /* assume 256-bit key */
                MB_MGR_AES_OOO *aes_ooo = state->aes256_ooo;
                uint32_t i;

                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        job = SUBMIT_JOB_AES_CBC_256_ENC(aes_ooo, job);
                        if (job != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }

                if (completed_jobs != n_jobs) {
                        IMB_JOB *job = NULL;

                        while((job = FLUSH_JOB_AES_CBC_256_ENC(aes_ooo))
                              != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
        }

        return completed_jobs;
}

__forceinline
uint32_t submit_aes_cbc_burst_dec(IMB_MGR *state,
                                  IMB_JOB *jobs,
                                  const uint32_t n_jobs,
                                  const IMB_KEY_SIZE_BYTES key_size,
                                  const int run_check)
{
        (void) state;

        if (run_check) {
                uint32_t i;

                /* validate jobs */
                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        /* validate job */
                        if (is_job_invalid(state, job,
                                           IMB_CIPHER_CBC, IMB_AUTH_NULL,
                                           IMB_DIR_DECRYPT, key_size)) {
                                job->status = IMB_STATUS_INVALID_ARGS;
                                return 0;
                        }
                }
        }

        if (key_size == IMB_KEY_128_BYTES) {
                uint32_t i;

                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        AES_CBC_DEC_128(job->src +
                                        job->cipher_start_src_offset_in_bytes,
                                        job->iv,
                                        job->dec_keys,
                                        job->dst,
                                        job->msg_len_to_cipher_in_bytes &
                                        (~15));
                        job->status = IMB_STATUS_COMPLETED;
                }
        } else if (key_size == IMB_KEY_192_BYTES) {
                uint32_t i;

                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        AES_CBC_DEC_192(job->src +
                                        job->cipher_start_src_offset_in_bytes,
                                        job->iv,
                                        job->dec_keys,
                                        job->dst,
                                        job->msg_len_to_cipher_in_bytes &
                                        (~15));
                        job->status = IMB_STATUS_COMPLETED;
                }
        } else  /* assume 256-bit key */ {
                uint32_t i;

                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        AES_CBC_DEC_256(job->src +
                                        job->cipher_start_src_offset_in_bytes,
                                        job->iv,
                                        job->dec_keys,
                                        job->dst,
                                        job->msg_len_to_cipher_in_bytes &
                                        (~15));
                        job->status = IMB_STATUS_COMPLETED;
                }
        }

        return n_jobs;
}

__forceinline
uint32_t submit_aes_ctr_burst(IMB_MGR *state,
                              IMB_JOB *jobs,
                              const uint32_t n_jobs,
                              const IMB_KEY_SIZE_BYTES key_size,
                              const int run_check)
{
        if (run_check) {
                uint32_t i;

                /* validate jobs */
                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        /* validate job */
                        if (is_job_invalid(state, job,
                                           IMB_CIPHER_CNTR, IMB_AUTH_NULL,
                                           IMB_DIR_ENCRYPT, key_size)) {
                                job->status = IMB_STATUS_INVALID_ARGS;
                                return 0;
                        }
                }
        }

        if (key_size == IMB_KEY_128_BYTES) {
                uint32_t i;

                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

#ifdef SUBMIT_JOB_AES_CTR_128
                        SUBMIT_JOB_AES_CTR_128(job);
#else
                        AES_CTR_128(job->src +
                                    job->cipher_start_src_offset_in_bytes,
                                    job->iv,
                                    job->enc_keys,
                                    job->dst,
                                    job->msg_len_to_cipher_in_bytes,
                                    job->iv_len_in_bytes);
#endif
                        job->status = IMB_STATUS_COMPLETED;
                }
        } else if (key_size == IMB_KEY_192_BYTES) {
                uint32_t i;

                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

#ifdef SUBMIT_JOB_AES_CTR_192
                        SUBMIT_JOB_AES_CTR_192(job);
#else
                        AES_CTR_192(job->src +
                                    job->cipher_start_src_offset_in_bytes,
                                    job->iv,
                                    job->enc_keys,
                                    job->dst,
                                    job->msg_len_to_cipher_in_bytes,
                                    job->iv_len_in_bytes);
#endif
                        job->status = IMB_STATUS_COMPLETED;
                }
        } else  /* assume 256-bit key */ {
                uint32_t i;

                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

#ifdef SUBMIT_JOB_AES_CTR_256
                        SUBMIT_JOB_AES_CTR_256(job);
#else
                        AES_CTR_256(job->src +
                                    job->cipher_start_src_offset_in_bytes,
                                    job->iv,
                                    job->enc_keys,
                                    job->dst,
                                    job->msg_len_to_cipher_in_bytes,
                                    job->iv_len_in_bytes);
#endif
                        job->status = IMB_STATUS_COMPLETED;
                }
        }

        return n_jobs;
}

__forceinline
uint32_t submit_cipher_burst_and_check(IMB_MGR *state, IMB_JOB *jobs,
                                       const uint32_t n_jobs,
                                       const IMB_CIPHER_MODE cipher,
                                       const IMB_CIPHER_DIRECTION dir,
                                       const IMB_KEY_SIZE_BYTES key_size,
                                       const int run_check)
{
        /* reset error status */
        imb_set_errno(state, 0);

        if (run_check)
                if (jobs == NULL) {
                        imb_set_errno(state, IMB_ERR_NULL_BURST);
                        return 0;
                }

        switch (cipher) {
        case IMB_CIPHER_CBC:
                if (dir == IMB_DIR_ENCRYPT)
                        return submit_aes_cbc_burst_enc(state, jobs, n_jobs,
                                                        key_size, run_check);
                else
                        return submit_aes_cbc_burst_dec(state, jobs, n_jobs,
                                                        key_size, run_check);
        case IMB_CIPHER_CNTR:
                return submit_aes_ctr_burst(state, jobs, n_jobs,
                                            key_size, run_check);
        default:
                break;
        }

        /* unsupported cipher mode */
        imb_set_errno(state, IMB_ERR_CIPH_MODE);

        return 0;
}

uint32_t
SUBMIT_CIPHER_BURST(IMB_MGR *state, IMB_JOB *jobs,
                    const uint32_t n_jobs,
                    const IMB_CIPHER_MODE cipher,
                    const IMB_CIPHER_DIRECTION dir,
                    const IMB_KEY_SIZE_BYTES key_size)
{
        return submit_cipher_burst_and_check(state, jobs, n_jobs,
                                             cipher, dir, key_size, 1);
}

uint32_t
SUBMIT_CIPHER_BURST_NOCHECK(IMB_MGR *state, IMB_JOB *jobs,
                            const uint32_t n_jobs,
                            const IMB_CIPHER_MODE cipher,
                            const IMB_CIPHER_DIRECTION dir,
                            const IMB_KEY_SIZE_BYTES key_size)
{
        return submit_cipher_burst_and_check(state, jobs, n_jobs,
                                             cipher, dir, key_size, 0);
}

__forceinline
uint32_t submit_burst_hmac_sha_x(IMB_MGR *state,
                                 IMB_JOB *jobs,
                                 const uint32_t n_jobs,
                                 const int run_check,
                                 const IMB_HASH_ALG hash_alg)
{
        uint32_t i, completed_jobs = 0;

        if (run_check) {
                /* validate jobs */
                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        /* validate job */
                        if (is_job_invalid(state, job,
                                           IMB_CIPHER_NULL,
                                           hash_alg,
                                           IMB_DIR_ENCRYPT,
                                           job->key_len_in_bytes)) {
                                job->status = IMB_STATUS_INVALID_ARGS;
                                return 0;
                        }
                }
        }

        if (hash_alg == IMB_AUTH_HMAC_SHA_1) {
                /* submit all jobs */
                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        job = SUBMIT_JOB_HMAC(state->hmac_sha_1_ooo, job);
                        if (job != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
                /* flush any outstanding jobs */
                if (completed_jobs != n_jobs) {
                        IMB_JOB *job = NULL;

                        while ((job = FLUSH_JOB_HMAC(state->hmac_sha_1_ooo))
                               != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
        } else if (hash_alg == IMB_AUTH_HMAC_SHA_224) {
                /* submit all jobs */
                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        job = SUBMIT_JOB_HMAC_SHA_224(state->hmac_sha_224_ooo,
                                                      job);
                        if (job != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
                /* flush any outstanding jobs */
                if (completed_jobs != n_jobs) {
                        IMB_JOB *job = NULL;

                        while ((job =
                                FLUSH_JOB_HMAC_SHA_224(state->hmac_sha_224_ooo))
                               != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
        } else if (hash_alg == IMB_AUTH_HMAC_SHA_256) {
                /* submit all jobs */
                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        job = SUBMIT_JOB_HMAC_SHA_256(state->hmac_sha_256_ooo,
                                                      job);
                        if (job != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
                /* flush any outstanding jobs */
                if (completed_jobs != n_jobs) {
                        IMB_JOB *job = NULL;

                        while ((job =
                                FLUSH_JOB_HMAC_SHA_256(state->hmac_sha_256_ooo))
                               != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
        } else if (hash_alg == IMB_AUTH_HMAC_SHA_384) {
                /* submit all jobs */
                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        job = SUBMIT_JOB_HMAC_SHA_384(state->hmac_sha_384_ooo,
                                                      job);
                        if (job != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
                /* flush any outstanding jobs */
                if (completed_jobs != n_jobs) {
                        IMB_JOB *job = NULL;

                        while ((job =
                                FLUSH_JOB_HMAC_SHA_384(state->hmac_sha_384_ooo))
                               != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
        } else if (hash_alg == IMB_AUTH_HMAC_SHA_512) {
                /* submit all jobs */
                for (i = 0; i < n_jobs; i++) {
                        IMB_JOB *job = &jobs[i];

                        job = SUBMIT_JOB_HMAC_SHA_512(state->hmac_sha_512_ooo,
                                                      job);
                        if (job != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
                /* flush any outstanding jobs */
                if (completed_jobs != n_jobs) {
                        IMB_JOB *job = NULL;

                        while ((job =
                                FLUSH_JOB_HMAC_SHA_512(state->hmac_sha_512_ooo))
                               != NULL) {
                                job->status = IMB_STATUS_COMPLETED;
                                completed_jobs++;
                        }
                }
        }

        return completed_jobs;
}

__forceinline
uint32_t submit_hash_burst_and_check(IMB_MGR *state, IMB_JOB *jobs,
                                     const uint32_t n_jobs,
                                     const IMB_HASH_ALG hash,
                                     const int run_check)
{
        /* reset error status */
        imb_set_errno(state, 0);

        if (run_check) {
                if (jobs == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_JOB);
                        return 0;
                }
        }

        switch (hash) {
        case IMB_AUTH_HMAC_SHA_1:
                return submit_burst_hmac_sha_x(state, jobs, n_jobs, run_check,
                                               IMB_AUTH_HMAC_SHA_1);
        case IMB_AUTH_HMAC_SHA_224:
                return submit_burst_hmac_sha_x(state, jobs, n_jobs, run_check,
                                               IMB_AUTH_HMAC_SHA_224);
        case IMB_AUTH_HMAC_SHA_256:
                return submit_burst_hmac_sha_x(state, jobs, n_jobs, run_check,
                                               IMB_AUTH_HMAC_SHA_256);
        case IMB_AUTH_HMAC_SHA_384:
                return submit_burst_hmac_sha_x(state, jobs, n_jobs, run_check,
                                               IMB_AUTH_HMAC_SHA_384);
        case IMB_AUTH_HMAC_SHA_512:
                return submit_burst_hmac_sha_x(state, jobs, n_jobs, run_check,
                                               IMB_AUTH_HMAC_SHA_512);
        default:
                break;
        }

        /* unsupported hash alg */
        imb_set_errno(state, IMB_ERR_HASH_ALGO);

        return 0;
}

uint32_t
SUBMIT_HASH_BURST(IMB_MGR *state, IMB_JOB *jobs,
                  const uint32_t n_jobs,
                  const IMB_HASH_ALG hash)
{
        return submit_hash_burst_and_check(state, jobs, n_jobs, hash, 1);
}

uint32_t
SUBMIT_HASH_BURST_NOCHECK(IMB_MGR *state, IMB_JOB *jobs,
                          const uint32_t n_jobs,
                          const IMB_HASH_ALG hash)
{
        return submit_hash_burst_and_check(state, jobs, n_jobs, hash, 0);
}

#endif /* MB_MGR_BURST_H */
