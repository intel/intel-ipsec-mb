/*******************************************************************************
  Copyright (c) 2019, Intel Corporation

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

/**
 * DOCSIS AES (AES128 CBC + AES128 CFB) and DOCSIS DES (DES CBC + DES CFB).
 * JOB submit and flush helper functions to be used from mb_mgr_code.h
 *
 * @note These need to be defined prior to including this file:
 *           ETHERNET_FCS, AES_CFB_ONE, SUBMIT_JOB_AES128_DEC and
 *           SUBMIT_JOB_AES128_ENC.
 *
 * @note The file defines the following:
 *           DOCSIS_LAST_BLOCK, DOCSIS_FIRST_BLOCK,
 *           SUBMIT_JOB_DOCSIS_SEC_ENC, FLUSH_JOB_DOCSIS_SEC_ENC,
 *           SUBMIT_JOB_DOCSIS_SEC_DEC,
 *           SUBMIT_JOB_DOCSIS_SEC_CRC_ENC, FLUSH_JOB_DOCSIS_SEC_CRC_ENC,
 *           SUBMIT_JOB_DOCSIS_SEC_CRC_DEC,
 *           DOCSIS_DES_ENC and DOCSIS_DES_DEC.
 */

#ifndef DOCSIS_COMMON_H
#define DOCSIS_COMMON_H

#include <stdint.h>
#include "include/des.h"

/* ========================================================================= */
/* DOCSIS SEC BPI / AES  (AES128-CBC + AES128-CFB) */
/* ========================================================================= */

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

/**
 * @brief Encrypts/decrypts the last partial block for DOCSIS SEC v3.1 BPI
 *
 * The last partial block is encrypted/decrypted using AES CFB128.
 * IV is always the last complete cipher-text block.
 *
 * @note It is assumed that length is bigger than one AES 128 block.
 *
 * @param job description of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline
JOB_AES_HMAC *
DOCSIS_LAST_BLOCK(JOB_AES_HMAC *job)
{
        const void *iv = NULL;
        uint64_t offset = 0;
        uint64_t partial_bytes = 0;

        if (job == NULL)
                return job;

        IMB_ASSERT((job->cipher_direction == DECRYPT) ||
                   (job->status & STS_COMPLETED_AES));

        partial_bytes = job->msg_len_to_cipher_in_bytes & (AES_BLOCK_SIZE - 1);
        offset = job->msg_len_to_cipher_in_bytes & (~(AES_BLOCK_SIZE - 1));

        if (!partial_bytes)
                return job;

        /* in either case IV has to be the last cipher-text block */
        if (job->cipher_direction == ENCRYPT)
                iv = job->dst + offset - AES_BLOCK_SIZE;
        else
                iv = job->src + job->cipher_start_src_offset_in_bytes +
                        offset - AES_BLOCK_SIZE;

        IMB_ASSERT(partial_bytes <= AES_BLOCK_SIZE);
        AES_CFB_128_ONE(job->dst + offset,
                        job->src + job->cipher_start_src_offset_in_bytes +
                        offset,
                        iv, job->aes_enc_key_expanded, partial_bytes);

        return job;
}

/**
 * @brief Encrypts/decrypts the first and only partial block for
 *        DOCSIS SEC v3.1 BPI
 *
 * The first partial block is encrypted/decrypted using AES CFB128.
 *
 * @param job description of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline
JOB_AES_HMAC *
DOCSIS_FIRST_BLOCK(JOB_AES_HMAC *job)
{
        IMB_ASSERT(!(job->status & STS_COMPLETED_AES));
        IMB_ASSERT(job->msg_len_to_cipher_in_bytes <= AES_BLOCK_SIZE);
        AES_CFB_128_ONE(job->dst,
                        job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv, job->aes_enc_key_expanded,
                        job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return job;
}

/**
 * @brief JOB submit helper function for DOCSIS SEC encryption
 *
 * @param state OOO manager structure
 * @param job description of performed crypto operation
 *
 * @return Pointer to completed JOB or NULL
 */
__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_DOCSIS_SEC_ENC(MB_MGR_AES_OOO *state, JOB_AES_HMAC *job)
{
        if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {
                JOB_AES_HMAC *tmp = SUBMIT_JOB_AES128_ENC(state, job);

                return DOCSIS_LAST_BLOCK(tmp);
        } else
                return DOCSIS_FIRST_BLOCK(job);
}

/**
 * @brief JOB flush helper function for DOCSIS SEC encryption
 *
 * @param state OOO manager structure
 *
 * @return Pointer to completed JOB or NULL
 */
__forceinline
JOB_AES_HMAC *
FLUSH_JOB_DOCSIS_SEC_ENC(MB_MGR_AES_OOO *state)
{
        JOB_AES_HMAC *tmp = FLUSH_JOB_AES128_ENC(state);

        return DOCSIS_LAST_BLOCK(tmp);
}

/**
 * @brief JOB submit helper function for DOCSIS SEC decryption
 *
 * @param state OOO manager structure (unused here)
 * @param job description of performed crypto operation
 *
 * @return Pointer to completed JOB or NULL
 */
__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_DOCSIS_SEC_DEC(MB_MGR_AES_OOO *state, JOB_AES_HMAC *job)
{
        (void) state;

        if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {
                DOCSIS_LAST_BLOCK(job);
                return SUBMIT_JOB_AES128_DEC(job);
        } else
                return DOCSIS_FIRST_BLOCK(job);
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_DOCSIS_SEC_CRC_ENC(MB_MGR_AES_OOO *state, JOB_AES_HMAC *job)
{
        if (job->msg_len_to_hash_in_bytes >= DOCSIS_CRC32_MIN_ETH_PDU_SIZE) {
                uint32_t *p_crc = (uint32_t *) job->auth_tag_output;

                (*p_crc) =
                        ETHERNET_FCS(job->src +
                                     job->hash_start_src_offset_in_bytes,
                                     job->msg_len_to_hash_in_bytes,
                                     job->src +
                                     job->hash_start_src_offset_in_bytes +
                                     job->msg_len_to_hash_in_bytes);
        }
        return SUBMIT_JOB_DOCSIS_SEC_ENC(state, job);
}

__forceinline
JOB_AES_HMAC *
FLUSH_JOB_DOCSIS_SEC_CRC_ENC(MB_MGR_AES_OOO *state)
{
        /**
         * CRC has been already calculated.
         * Normal cipher flush only required.
         */
        return FLUSH_JOB_DOCSIS_SEC_ENC(state);
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_DOCSIS_SEC_CRC_DEC(MB_MGR_AES_OOO *state, JOB_AES_HMAC *job)
{
        (void) state;

        if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {
                DOCSIS_LAST_BLOCK(job);
                job = SUBMIT_JOB_AES128_DEC(job);
        } else {
                job = DOCSIS_FIRST_BLOCK(job);
        }

        if (job->msg_len_to_hash_in_bytes >= DOCSIS_CRC32_MIN_ETH_PDU_SIZE) {
                uint32_t *p_crc = (uint32_t *) job->auth_tag_output;

                (*p_crc) =
                        ETHERNET_FCS(job->src +
                                     job->hash_start_src_offset_in_bytes,
                                     job->msg_len_to_hash_in_bytes,
                                     NULL);
        }

        return job;
}

/* ========================================================================= */
/* DES, 3DES and DOCSIS DES (DES CBC + DES CFB) */
/* ========================================================================= */

/**
 * @brief DOCSIS DES cipher encryption
 *
 * @param job description of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline
JOB_AES_HMAC *
DOCSIS_DES_ENC(JOB_AES_HMAC *job)
{
        IMB_ASSERT(!(job->status & STS_COMPLETED_AES));
        docsis_des_enc_basic(job->src + job->cipher_start_src_offset_in_bytes,
                             job->dst,
                             (int) job->msg_len_to_cipher_in_bytes,
                             job->aes_enc_key_expanded,
                             (const uint64_t *)job->iv);
        job->status |= STS_COMPLETED_AES;
        return job;
}

/**
 * @brief DOCSIS DES cipher decryption
 *
 * @param job description of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline
JOB_AES_HMAC *
DOCSIS_DES_DEC(JOB_AES_HMAC *job)
{
        IMB_ASSERT(!(job->status & STS_COMPLETED_AES));
        docsis_des_dec_basic(job->src + job->cipher_start_src_offset_in_bytes,
                             job->dst,
                             (int) job->msg_len_to_cipher_in_bytes,
                             job->aes_dec_key_expanded,
                             (const uint64_t *)job->iv);
        job->status |= STS_COMPLETED_AES;
        return job;
}

#endif /* DOCSIS_COMMON_H */
