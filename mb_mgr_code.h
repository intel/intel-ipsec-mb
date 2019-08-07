/*******************************************************************************
  Copyright (c) 2012-2018, Intel Corporation

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

/*
 * This contains the bulk of the mb_mgr code, with #define's to build
 * an SSE, AVX, AVX2 or AVX512 version (see mb_mgr_sse.c, mb_mgr_avx.c, etc.)
 *
 * get_next_job() returns a job object. This must be filled in and returned
 * via submit_job() before get_next_job() is called again.
 *
 * submit_job() and flush_job() returns a job object. This job object ceases
 * to be usable at the next call to get_next_job()
 */

#include <string.h> /* memcpy(), memset() */

/*
 * JOBS() and ADV_JOBS() moved into mb_mgr_code.h
 * get_next_job() and get_completed_job() API's are no longer inlines.
 * For binary compatibility they have been made proper symbols.
 */
__forceinline
JOB_AES_HMAC *JOBS(MB_MGR *state, const int offset)
{
        char *cp = (char *)state->jobs;

        return (JOB_AES_HMAC *)(cp + offset);
}

__forceinline
void ADV_JOBS(int *ptr)
{
        *ptr += sizeof(JOB_AES_HMAC);
        if (*ptr >= (int) (MAX_JOBS * sizeof(JOB_AES_HMAC)))
                *ptr = 0;
}

/* ========================================================================= */
/* Lower level "out of order" schedulers */
/* ========================================================================= */

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES128_DEC(JOB_AES_HMAC *job)
{
        AES_CBC_DEC_128(job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv,
                        job->aes_dec_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= STS_COMPLETED_AES;
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES192_DEC(JOB_AES_HMAC *job)
{
        AES_CBC_DEC_192(job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv,
                        job->aes_dec_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES256_DEC(JOB_AES_HMAC *job)
{
        AES_CBC_DEC_256(job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv,
                        job->aes_dec_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_ECB_128_ENC(JOB_AES_HMAC *job)
{
        AES_ECB_ENC_128(job->src + job->cipher_start_src_offset_in_bytes,
                        job->aes_enc_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= STS_COMPLETED_AES;
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_ECB_192_ENC(JOB_AES_HMAC *job)
{
        AES_ECB_ENC_192(job->src + job->cipher_start_src_offset_in_bytes,
                        job->aes_enc_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= STS_COMPLETED_AES;
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_ECB_256_ENC(JOB_AES_HMAC *job)
{
        AES_ECB_ENC_256(job->src + job->cipher_start_src_offset_in_bytes,
                        job->aes_enc_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= STS_COMPLETED_AES;
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_ECB_128_DEC(JOB_AES_HMAC *job)
{
        AES_ECB_DEC_128(job->src + job->cipher_start_src_offset_in_bytes,
                        job->aes_dec_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= STS_COMPLETED_AES;
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_ECB_192_DEC(JOB_AES_HMAC *job)
{
        AES_ECB_DEC_192(job->src + job->cipher_start_src_offset_in_bytes,
                        job->aes_dec_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= STS_COMPLETED_AES;
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_ECB_256_DEC(JOB_AES_HMAC *job)
{
        AES_ECB_DEC_256(job->src + job->cipher_start_src_offset_in_bytes,
                        job->aes_dec_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= STS_COMPLETED_AES;
        return job;
}

/* ========================================================================= */
/* Custom hash / cipher */
/* ========================================================================= */

__forceinline
JOB_AES_HMAC *
JOB_CUSTOM_CIPHER(JOB_AES_HMAC *job)
{
        if (!(job->status & STS_COMPLETED_AES)) {
                if (job->cipher_func(job))
                        job->status = STS_INTERNAL_ERROR;
                else
                        job->status |= STS_COMPLETED_AES;
        }
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_CUSTOM_CIPHER(JOB_AES_HMAC *job)
{
        return JOB_CUSTOM_CIPHER(job);
}

__forceinline
JOB_AES_HMAC *
FLUSH_JOB_CUSTOM_CIPHER(JOB_AES_HMAC *job)
{
        return JOB_CUSTOM_CIPHER(job);
}

__forceinline
JOB_AES_HMAC *
JOB_CUSTOM_HASH(JOB_AES_HMAC *job)
{
        if (!(job->status & STS_COMPLETED_HMAC)) {
                if (job->hash_func(job))
                        job->status = STS_INTERNAL_ERROR;
                else
                        job->status |= STS_COMPLETED_HMAC;
        }
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_CUSTOM_HASH(JOB_AES_HMAC *job)
{
        return JOB_CUSTOM_HASH(job);
}

__forceinline
JOB_AES_HMAC *
FLUSH_JOB_CUSTOM_HASH(JOB_AES_HMAC *job)
{
        return JOB_CUSTOM_HASH(job);
}

/* ========================================================================= */
/* DOCSIS AES (AES128 CBC + AES128 CFB) */
/* ========================================================================= */

#define AES_BLOCK_SIZE 16

/**
 * @brief Encrypts/decrypts the last partial block for DOCSIS SEC v3.1 BPI
 *
 * The last partial block is encrypted/decrypted using AES CFB128.
 * IV is always the next last ciphered block.
 *
 * @note It is assumed that length is bigger than one AES 128 block.
 *
 * @param job desriptor of performed crypto operation
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

        /* in either case IV has to be next last ciphered block */
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
 * @param job desriptor of performed crypto operation
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

/* ========================================================================= */
/* DES, 3DES and DOCSIS DES (DES CBC + DES CFB) */
/* ========================================================================= */

/**
 * @brief DOCSIS DES cipher encryption
 *
 * @param job desriptor of performed crypto operation
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
 * @param job desriptor of performed crypto operation
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

/**
 * @brief DES cipher encryption
 *
 * @param job desriptor of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline
JOB_AES_HMAC *
DES_CBC_ENC(JOB_AES_HMAC *job)
{
        IMB_ASSERT(!(job->status & STS_COMPLETED_AES));
        des_enc_cbc_basic(job->src + job->cipher_start_src_offset_in_bytes,
                          job->dst,
                          job->msg_len_to_cipher_in_bytes &
                          (~(DES_BLOCK_SIZE - 1)),
                          job->aes_enc_key_expanded, (const uint64_t *)job->iv);
        job->status |= STS_COMPLETED_AES;
        return job;
}

/**
 * @brief DES cipher decryption
 *
 * @param job desriptor of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline
JOB_AES_HMAC *
DES_CBC_DEC(JOB_AES_HMAC *job)
{
        IMB_ASSERT(!(job->status & STS_COMPLETED_AES));
        des_dec_cbc_basic(job->src + job->cipher_start_src_offset_in_bytes,
                          job->dst,
                          job->msg_len_to_cipher_in_bytes &
                          (~(DES_BLOCK_SIZE - 1)),
                          job->aes_dec_key_expanded, (const uint64_t *)job->iv);
        job->status |= STS_COMPLETED_AES;
        return job;
}

/**
 * @brief 3DES cipher encryption
 *
 * @param job desriptor of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline
JOB_AES_HMAC *
DES3_CBC_ENC(JOB_AES_HMAC *job)
{
        const void * const *ks_ptr =
                (const void * const *)job->aes_enc_key_expanded;

        IMB_ASSERT(!(job->status & STS_COMPLETED_AES));
        des3_enc_cbc_basic(job->src + job->cipher_start_src_offset_in_bytes,
                           job->dst,
                           job->msg_len_to_cipher_in_bytes &
                           (~(DES_BLOCK_SIZE - 1)),
                           ks_ptr[0], ks_ptr[1], ks_ptr[2],
                           (const uint64_t *)job->iv);
        job->status |= STS_COMPLETED_AES;
        return job;
}

/**
 * @brief 3DES cipher decryption
 *
 * @param job desriptor of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline
JOB_AES_HMAC *
DES3_CBC_DEC(JOB_AES_HMAC *job)
{
        const void * const *ks_ptr =
                (const void * const *)job->aes_dec_key_expanded;

        IMB_ASSERT(!(job->status & STS_COMPLETED_AES));
        des3_dec_cbc_basic(job->src + job->cipher_start_src_offset_in_bytes,
                           job->dst,
                           job->msg_len_to_cipher_in_bytes &
                           (~(DES_BLOCK_SIZE - 1)),
                           ks_ptr[0], ks_ptr[1], ks_ptr[2],
                           (const uint64_t *)job->iv);
        job->status |= STS_COMPLETED_AES;
        return job;
}

/* ========================================================================= */
/* Cipher submit & flush functions */
/* ========================================================================= */
__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_ENC(MB_MGR *state, JOB_AES_HMAC *job)
{
        if (CBC == job->cipher_mode) {
                if (16 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES128_ENC(&state->aes128_ooo, job);
                } else if (24 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES192_ENC(&state->aes192_ooo, job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES256_ENC(&state->aes256_ooo, job);
                }
        } else if (CNTR == job->cipher_mode) {
                return SUBMIT_JOB_AES_CNTR(job);
        } else if (CNTR_BITLEN == job->cipher_mode) {
                return SUBMIT_JOB_AES_CNTR_BIT(job);
        } else if (ECB == job->cipher_mode) {
                if (16 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES_ECB_128_ENC(job);
                } else if (24 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES_ECB_192_ENC(job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES_ECB_256_ENC(job);
                }
        } else if (DOCSIS_SEC_BPI == job->cipher_mode) {
                if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {
                        JOB_AES_HMAC *tmp;

                        tmp = SUBMIT_JOB_AES128_ENC(&state->docsis_sec_ooo,
                                                    job);
                        return DOCSIS_LAST_BLOCK(tmp);
                } else
                        return DOCSIS_FIRST_BLOCK(job);
        } else if (PON_AES_CNTR == job->cipher_mode) {
                if (job->msg_len_to_cipher_in_bytes == 0)
                        return SUBMIT_JOB_PON_ENC_NO_CTR(job);
                else
                        return SUBMIT_JOB_PON_ENC(job);
#ifndef NO_GCM
        } else if (GCM == job->cipher_mode) {
                return SUBMIT_JOB_AES_GCM_ENC(state, job);
#endif /* NO_GCM */
        } else if (CUSTOM_CIPHER == job->cipher_mode) {
                return SUBMIT_JOB_CUSTOM_CIPHER(job);
        } else if (DES == job->cipher_mode) {
#ifdef SUBMIT_JOB_DES_CBC_ENC
                return SUBMIT_JOB_DES_CBC_ENC(&state->des_enc_ooo, job);
#else
                return DES_CBC_ENC(job);
#endif /* SUBMIT_JOB_DES_CBC_ENC */
        } else if (DOCSIS_DES == job->cipher_mode) {
#ifdef SUBMIT_JOB_DOCSIS_DES_ENC
                return SUBMIT_JOB_DOCSIS_DES_ENC(&state->docsis_des_enc_ooo,
                                                 job);
#else
                return DOCSIS_DES_ENC(job);
#endif /* SUBMIT_JOB_DOCSIS_DES_ENC */
        } else if (DES3 == job->cipher_mode) {
#ifdef SUBMIT_JOB_3DES_CBC_ENC
                return SUBMIT_JOB_3DES_CBC_ENC(&state->des3_enc_ooo, job);
#else
                return DES3_CBC_ENC(job);
#endif
        } else if (CCM == job->cipher_mode) {
                return AES_CNTR_CCM_128(job);
        } else { /* assume NULL_CIPHER */
                job->status |= STS_COMPLETED_AES;
                return job;
        }
}

__forceinline
JOB_AES_HMAC *
FLUSH_JOB_AES_ENC(MB_MGR *state, JOB_AES_HMAC *job)
{
        if (CBC == job->cipher_mode) {
                if (16 == job->aes_key_len_in_bytes) {
                        return FLUSH_JOB_AES128_ENC(&state->aes128_ooo);
                } else if (24 == job->aes_key_len_in_bytes) {
                        return FLUSH_JOB_AES192_ENC(&state->aes192_ooo);
                } else  { /* assume 32 */
                        return FLUSH_JOB_AES256_ENC(&state->aes256_ooo);
                }
#ifndef NO_GCM
        } else if (GCM == job->cipher_mode) {
                return FLUSH_JOB_AES_GCM_ENC(state, job);
#endif /* NO_GCM */
        } else if (DOCSIS_SEC_BPI == job->cipher_mode) {
                JOB_AES_HMAC *tmp;

                tmp = FLUSH_JOB_AES128_ENC(&state->docsis_sec_ooo);
                return DOCSIS_LAST_BLOCK(tmp);
#ifdef FLUSH_JOB_DES_CBC_ENC
        } else if (DES == job->cipher_mode) {
                return FLUSH_JOB_DES_CBC_ENC(&state->des_enc_ooo);
#endif /* FLUSH_JOB_DES_CBC_ENC */
#ifdef FLUSH_JOB_3DES_CBC_ENC
        } else if (DES3 == job->cipher_mode) {
                return FLUSH_JOB_3DES_CBC_ENC(&state->des3_enc_ooo);
#endif /* FLUSH_JOB_3DES_CBC_ENC */
#ifdef FLUSH_JOB_DOCSIS_DES_ENC
        } else if (DOCSIS_DES == job->cipher_mode) {
                return FLUSH_JOB_DOCSIS_DES_ENC(&state->docsis_des_enc_ooo);
#endif /* FLUSH_JOB_DOCSIS_DES_ENC */
        } else if (CUSTOM_CIPHER == job->cipher_mode) {
                return FLUSH_JOB_CUSTOM_CIPHER(job);
        } else { /* assume CNTR/CNTR_BITLEN, ECB, CCM or NULL_CIPHER */
                return NULL;
        }
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_DEC(MB_MGR *state, JOB_AES_HMAC *job)
{
        if (CBC == job->cipher_mode) {
                if (16 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES128_DEC(job);
                } else if (24 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES192_DEC(job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES256_DEC(job);
                }
        } else if (CNTR == job->cipher_mode) {
                return SUBMIT_JOB_AES_CNTR(job);
        } else if (CNTR_BITLEN == job->cipher_mode) {
                return SUBMIT_JOB_AES_CNTR_BIT(job);
        } else if (ECB == job->cipher_mode) {
                if (16 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES_ECB_128_DEC(job);
                } else if (24 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES_ECB_192_DEC(job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES_ECB_256_DEC(job);
                }
        } else if (DOCSIS_SEC_BPI == job->cipher_mode) {
                if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {
                        DOCSIS_LAST_BLOCK(job);
                        return SUBMIT_JOB_AES128_DEC(job);
                } else {
                        return DOCSIS_FIRST_BLOCK(job);
                }
        } else if (PON_AES_CNTR == job->cipher_mode) {
                if (job->msg_len_to_cipher_in_bytes == 0)
                        return SUBMIT_JOB_PON_DEC_NO_CTR(job);
                else
                        return SUBMIT_JOB_PON_DEC(job);
#ifndef NO_GCM
        } else if (GCM == job->cipher_mode) {
                return SUBMIT_JOB_AES_GCM_DEC(state, job);
#endif /* NO_GCM */
        } else if (DES == job->cipher_mode) {
#ifdef SUBMIT_JOB_DES_CBC_DEC
                return SUBMIT_JOB_DES_CBC_DEC(&state->des_dec_ooo, job);
#else
                (void) state;
                return DES_CBC_DEC(job);
#endif /* SUBMIT_JOB_DES_CBC_DEC */
        } else if (DOCSIS_DES == job->cipher_mode) {
#ifdef SUBMIT_JOB_DOCSIS_DES_DEC
                return SUBMIT_JOB_DOCSIS_DES_DEC(&state->docsis_des_dec_ooo,
                                                 job);
#else
                return DOCSIS_DES_DEC(job);
#endif /* SUBMIT_JOB_DOCSIS_DES_DEC */
        } else if (DES3 == job->cipher_mode) {
#ifdef SUBMIT_JOB_3DES_CBC_DEC
                return SUBMIT_JOB_3DES_CBC_DEC(&state->des3_dec_ooo, job);
#else
                return DES3_CBC_DEC(job);
#endif
        } else if (CUSTOM_CIPHER == job->cipher_mode) {
                return SUBMIT_JOB_CUSTOM_CIPHER(job);
        } else if (CCM == job->cipher_mode) {
                return AES_CNTR_CCM_128(job);
        } else {
                /* assume NULL_CIPHER */
                job->status |= STS_COMPLETED_AES;
                return job;
        }
}

__forceinline
JOB_AES_HMAC *
FLUSH_JOB_AES_DEC(MB_MGR *state, JOB_AES_HMAC *job)
{
#ifndef NO_GCM
        if (GCM == job->cipher_mode)
                return FLUSH_JOB_AES_GCM_DEC(state, job);
#endif /* NO_GCM */
#ifdef FLUSH_JOB_DES_CBC_DEC
        if (DES == job->cipher_mode)
                return FLUSH_JOB_DES_CBC_DEC(&state->des_dec_ooo);
#endif /* FLUSH_JOB_DES_CBC_DEC */
#ifdef FLUSH_JOB_3DES_CBC_DEC
        if (DES3 == job->cipher_mode)
                return FLUSH_JOB_3DES_CBC_DEC(&state->des3_dec_ooo);
#endif /* FLUSH_JOB_3DES_CBC_DEC */
#ifdef FLUSH_JOB_DOCSIS_DES_DEC
        if (DOCSIS_DES == job->cipher_mode)
                return FLUSH_JOB_DOCSIS_DES_DEC(&state->docsis_des_dec_ooo);
#endif /* FLUSH_JOB_DOCSIS_DES_DEC */
        (void) state;
        return NULL;
}

/* ========================================================================= */
/* Hash submit & flush functions */
/* ========================================================================= */

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_HASH(MB_MGR *state, JOB_AES_HMAC *job)
{
#ifdef VERBOSE
        printf("--------Enter SUBMIT_JOB_HASH --------------\n");
#endif
        switch (job->hash_alg) {
        case SHA1:
#ifdef HASH_USE_SHAEXT
                if (state->features & IMB_FEATURE_SHANI)
                        return SUBMIT_JOB_HMAC_NI(&state->hmac_sha_1_ooo, job);
#endif
                return SUBMIT_JOB_HMAC(&state->hmac_sha_1_ooo, job);
        case SHA_224:
#ifdef HASH_USE_SHAEXT
                if (state->features & IMB_FEATURE_SHANI)
                        return SUBMIT_JOB_HMAC_SHA_224_NI
                                (&state->hmac_sha_224_ooo, job);
#endif
                return SUBMIT_JOB_HMAC_SHA_224(&state->hmac_sha_224_ooo, job);
        case SHA_256:
#ifdef HASH_USE_SHAEXT
                if (state->features & IMB_FEATURE_SHANI)
                        return SUBMIT_JOB_HMAC_SHA_256_NI
                                (&state->hmac_sha_256_ooo, job);
#endif
                return SUBMIT_JOB_HMAC_SHA_256(&state->hmac_sha_256_ooo, job);
        case SHA_384:
                return SUBMIT_JOB_HMAC_SHA_384(&state->hmac_sha_384_ooo, job);
        case SHA_512:
                return SUBMIT_JOB_HMAC_SHA_512(&state->hmac_sha_512_ooo, job);
        case AES_XCBC:
                return SUBMIT_JOB_AES_XCBC(&state->aes_xcbc_ooo, job);
        case MD5:
                return SUBMIT_JOB_HMAC_MD5(&state->hmac_md5_ooo, job);
        case CUSTOM_HASH:
                return SUBMIT_JOB_CUSTOM_HASH(job);
        case AES_CCM:
                return SUBMIT_JOB_AES_CCM_AUTH(&state->aes_ccm_ooo, job);
        case AES_CMAC:
                /*
                 * CMAC OOO MGR assumes job len in bits
                 * (for CMAC length is provided in bytes)
                 */
                job->msg_len_to_hash_in_bits =
                        job->msg_len_to_hash_in_bytes * 8;
                return SUBMIT_JOB_AES_CMAC_AUTH(&state->aes_cmac_ooo, job);
        case AES_CMAC_BITLEN:
                return SUBMIT_JOB_AES_CMAC_AUTH(&state->aes_cmac_ooo, job);
        case PLAIN_SHA1:
                IMB_SHA1(state,
                         job->src + job->hash_start_src_offset_in_bytes,
                         job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                job->status |= STS_COMPLETED_HMAC;
                return job;
        case PLAIN_SHA_224:
                IMB_SHA224(state,
                           job->src + job->hash_start_src_offset_in_bytes,
                           job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                job->status |= STS_COMPLETED_HMAC;
                return job;
        case PLAIN_SHA_256:
                IMB_SHA256(state,
                           job->src + job->hash_start_src_offset_in_bytes,
                           job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                job->status |= STS_COMPLETED_HMAC;
                return job;
        case PLAIN_SHA_384:
                IMB_SHA384(state,
                           job->src + job->hash_start_src_offset_in_bytes,
                           job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                job->status |= STS_COMPLETED_HMAC;
                return job;
        case PLAIN_SHA_512:
                IMB_SHA512(state,
                           job->src + job->hash_start_src_offset_in_bytes,
                           job->msg_len_to_hash_in_bytes, job->auth_tag_output);
                job->status |= STS_COMPLETED_HMAC;
                return job;
        default: /* assume GCM, PON_CRC_BIP or NULL_HASH */
                job->status |= STS_COMPLETED_HMAC;
                return job;
        }
}

__forceinline
JOB_AES_HMAC *
FLUSH_JOB_HASH(MB_MGR *state, JOB_AES_HMAC *job)
{
        switch (job->hash_alg) {
        case SHA1:
#ifdef HASH_USE_SHAEXT
                if (state->features & IMB_FEATURE_SHANI)
                        return FLUSH_JOB_HMAC_NI(&state->hmac_sha_1_ooo);
#endif
                return FLUSH_JOB_HMAC(&state->hmac_sha_1_ooo);
        case SHA_224:
#ifdef HASH_USE_SHAEXT
                if (state->features & IMB_FEATURE_SHANI)
                        return FLUSH_JOB_HMAC_SHA_224_NI
                                (&state->hmac_sha_224_ooo);
#endif
                return FLUSH_JOB_HMAC_SHA_224(&state->hmac_sha_224_ooo);
        case SHA_256:
#ifdef HASH_USE_SHAEXT
                if (state->features & IMB_FEATURE_SHANI)
                        return FLUSH_JOB_HMAC_SHA_256_NI
                                (&state->hmac_sha_256_ooo);
#endif
                return FLUSH_JOB_HMAC_SHA_256(&state->hmac_sha_256_ooo);
        case SHA_384:
                return FLUSH_JOB_HMAC_SHA_384(&state->hmac_sha_384_ooo);
        case SHA_512:
                return FLUSH_JOB_HMAC_SHA_512(&state->hmac_sha_512_ooo);
        case AES_XCBC:
                return FLUSH_JOB_AES_XCBC(&state->aes_xcbc_ooo);
        case MD5:
                return FLUSH_JOB_HMAC_MD5(&state->hmac_md5_ooo);
        case CUSTOM_HASH:
                return FLUSH_JOB_CUSTOM_HASH(job);
        case AES_CCM:
                return FLUSH_JOB_AES_CCM_AUTH(&state->aes_ccm_ooo);
        case AES_CMAC:
        case AES_CMAC_BITLEN:
                return FLUSH_JOB_AES_CMAC_AUTH(&state->aes_cmac_ooo);
        default: /* assume GCM or NULL_HASH */
                if (!(job->status & STS_COMPLETED_HMAC)) {
                        job->status |= STS_COMPLETED_HMAC;
                        return job;
                }
                /* if HMAC is complete then return NULL */
                return NULL;
        }
}


/* ========================================================================= */
/* Job submit & flush functions */
/* ========================================================================= */

#ifdef DEBUG
#ifdef _WIN32
#define INVALID_PRN(_fmt, ...)                                          \
        fprintf(stderr, "%s():%d: " _fmt, __FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define INVALID_PRN(_fmt, ...)                                          \
        fprintf(stderr, "%s():%d: " _fmt, __func__, __LINE__, __VA_ARGS__)
#endif
#else
#define INVALID_PRN(_fmt, ...)
#endif

__forceinline int
is_job_invalid(const JOB_AES_HMAC *job)
{
        const uint64_t auth_tag_len_fips[] = {
                0,  /* INVALID selection */
                20, /* SHA1 */
                28, /* SHA_224 */
                32, /* SHA_256 */
                48, /* SHA_384 */
                64, /* SHA_512 */
                12, /* AES_XCBC */
                16, /* MD5 */
                0,  /* NULL_HASH */
#ifndef NO_GCM
                16, /* AES_GMAC */
#endif
                0,  /* CUSTOM HASH */
                0,  /* AES_CCM */
                16, /* AES_CMAC */
        };
        const uint64_t auth_tag_len_ipsec[] = {
                0,  /* INVALID selection */
                12, /* SHA1 */
                14, /* SHA_224 */
                16, /* SHA_256 */
                24, /* SHA_384 */
                32, /* SHA_512 */
                12, /* AES_XCBC */
                12, /* MD5 */
                0,  /* NULL_HASH */
#ifndef NO_GCM
                16, /* AES_GMAC */
#endif
                0,  /* CUSTOM HASH */
                0,  /* AES_CCM */
                16, /* AES_CMAC */
                20, /* PLAIN_SHA1 */
                28, /* PLAIN_SHA_224 */
                32, /* PLAIN_SHA_256 */
                48, /* PLAIN_SHA_384 */
                64, /* PLAIN_SHA_512 */
                4,  /* AES_CMAC 3GPP */
        };

        switch (job->cipher_mode) {
        case CBC:
                if (job->src == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->dst == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->cipher_direction == ENCRYPT &&
                    job->aes_enc_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->cipher_direction == DECRYPT &&
                    job->aes_dec_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_key_len_in_bytes != UINT64_C(16) &&
                    job->aes_key_len_in_bytes != UINT64_C(24) &&
                    job->aes_key_len_in_bytes != UINT64_C(32)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes & UINT64_C(15)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(16)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
        case ECB:
                if (job->src == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->dst == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_enc_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_key_len_in_bytes != UINT64_C(16) &&
                    job->aes_key_len_in_bytes != UINT64_C(24) &&
                    job->aes_key_len_in_bytes != UINT64_C(32)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes & UINT64_C(15)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(0)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
        case CNTR:
        case CNTR_BITLEN:
                if (job->src == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->dst == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_enc_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_key_len_in_bytes != UINT64_C(16) &&
                    job->aes_key_len_in_bytes != UINT64_C(24) &&
                    job->aes_key_len_in_bytes != UINT64_C(32)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(16) &&
                    job->iv_len_in_bytes != UINT64_C(12)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                /*
                 * msg_len_to_cipher_in_bits is used with CNTR_BITLEN, but it is
                 * effectively the same field as msg_len_to_cipher_in_bytes,
                 * since it is part of the same union
                 */
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
        case NULL_CIPHER:
                /*
                 * No checks required for this mode
                 * @note NULL cipher doesn't perform memory copy operation
                 *       from source to destination
                 */
                break;
        case DOCSIS_SEC_BPI:
                if (job->src == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->dst == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_enc_key_expanded == NULL) {
                        /* it has to be set regardless of direction (AES-CFB) */
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->cipher_direction == DECRYPT &&
                    job->aes_dec_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_key_len_in_bytes != UINT64_C(16)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(16)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
#ifndef NO_GCM
        case GCM:
                if (job->src == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->dst == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                /* Same key structure used for encrypt and decrypt */
                if (job->cipher_direction == ENCRYPT &&
                    job->aes_enc_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->cipher_direction == DECRYPT &&
                    job->aes_dec_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_key_len_in_bytes != UINT64_C(16) &&
                    job->aes_key_len_in_bytes != UINT64_C(24) &&
                    job->aes_key_len_in_bytes != UINT64_C(32)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(12)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->hash_alg != AES_GMAC) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
#endif /* !NO_GCM */
        case CUSTOM_CIPHER:
                /* no checks here */
                if (job->cipher_func == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
        case DES:
                if (job->src == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->dst == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->cipher_direction == ENCRYPT &&
                    job->aes_enc_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->cipher_direction == DECRYPT &&
                    job->aes_dec_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_key_len_in_bytes != UINT64_C(8)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes & UINT64_C(7)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(8)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
        case DOCSIS_DES:
                if (job->src == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->dst == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->cipher_direction == ENCRYPT &&
                    job->aes_enc_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->cipher_direction == DECRYPT &&
                    job->aes_dec_key_expanded == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_key_len_in_bytes != UINT64_C(8)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(8)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
        case CCM:
                if (job->msg_len_to_cipher_in_bytes != 0) {
                        if (job->src == NULL) {
                                INVALID_PRN("cipher_mode:%d\n",
                                            job->cipher_mode);
                                return 1;
                        }
                        if (job->dst == NULL) {
                                INVALID_PRN("cipher_mode:%d\n",
                                            job->cipher_mode);
                                return 1;
                        }
                }
                if (job->iv == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_enc_key_expanded == NULL) {
                        /* AES-CTR and CBC-MAC use only encryption keys */
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                /* currently only AES-CCM-128 is supported */
                if (job->aes_key_len_in_bytes != UINT64_C(16)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                /*
                 * From RFC3610:
                 *     Nonce length = 15 - L
                 *     Valid L values are: 2 to 8
                 * Then valid nonce lengths 13 to 7 (inclusive).
                 */
                if (job->iv_len_in_bytes > UINT64_C(13) ||
                    job->iv_len_in_bytes < UINT64_C(7)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->hash_alg != AES_CCM) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
        case DES3:
                if (job->src == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->dst == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->aes_key_len_in_bytes != UINT64_C(24)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes & UINT64_C(7)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(8)) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->cipher_direction == ENCRYPT) {
                        const void * const *ks_ptr =
                                (const void * const *)job->aes_enc_key_expanded;

                        if (ks_ptr == NULL) {
                                INVALID_PRN("cipher_mode:%d\n",
                                            job->cipher_mode);
                                return 1;
                        }
                        if (ks_ptr[0] == NULL || ks_ptr[1] == NULL ||
                            ks_ptr[2] == NULL) {
                                INVALID_PRN("cipher_mode:%d\n",
                                            job->cipher_mode);
                                return 1;
                        }
                } else {
                        const void * const *ks_ptr =
                                (const void * const *)job->aes_dec_key_expanded;

                        if (ks_ptr == NULL) {
                                INVALID_PRN("cipher_mode:%d\n",
                                            job->cipher_mode);
                                return 1;
                        }
                        if (ks_ptr[0] == NULL || ks_ptr[1] == NULL ||
                            ks_ptr[2] == NULL) {
                                INVALID_PRN("cipher_mode:%d\n",
                                            job->cipher_mode);
                                return 1;
                        }
                }
                break;
        case PON_AES_CNTR:
                /*
                 * CRC and cipher are done together. A few assumptions:
                 * - CRC and cipher start offsets are the same
                 * - last 4 bytes (32 bits) of the buffer is CRC
                 * - updated CRC value is put into the source buffer
                 *   (encryption only)
                 * - CRC length is msg_len_to_cipher_in_bytes - 4 bytes
                 * - msg_len_to_cipher_in_bytes is aligned to 4 bytes
                 * - If msg_len_to_cipher_in_bytes is 0, IV and key pointers
                 *   are not required, as encryption is not done
                 */
                if (job->src == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->dst == NULL) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->hash_alg != PON_CRC_BIP) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                /*
                 * If message length to cipher != 0, AES-CTR is performed and
                 * key and IV require to be set properly
                 */
                if (job->msg_len_to_cipher_in_bytes != UINT64_C(0)) {
                        /* message size needs to be aligned to 4 bytes */
                        if ((job->msg_len_to_cipher_in_bytes & 3) != 0) {
                                INVALID_PRN("cipher_mode:%d\n",
                                            job->cipher_mode);
                                return 1;
                        }

                        if (job->aes_key_len_in_bytes != UINT64_C(16)) {
                                INVALID_PRN("cipher_mode:%d\n",
                                            job->cipher_mode);
                                return 1;
                        }
                        if (job->iv_len_in_bytes != UINT64_C(16)) {
                                INVALID_PRN("cipher_mode:%d\n",
                                            job->cipher_mode);
                                return 1;
                        }
                }
                break;
        default:
                INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                return 1;
        }

        switch (job->hash_alg) {
        case SHA1:
        case AES_XCBC:
        case MD5:
        case SHA_224:
        case SHA_256:
        case SHA_384:
        case SHA_512:
                if (job->src == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[job->hash_alg] &&
                    job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_fips[job->hash_alg]) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes == 0) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                break;
        case NULL_HASH:
                break;
#ifndef NO_GCM
        case AES_GMAC:
                if (job->src == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes < UINT64_C(4) ||
                    job->auth_tag_output_len_in_bytes > UINT64_C(16)) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                                return 1;
                }
                if (job->cipher_mode != GCM) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                                return 1;
                }
                if (job->auth_tag_output == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                /*
                 * msg_len_to_hash_in_bytes not checked against zero.
                 * It is not used for AES-GCM & GMAC - see
                 * SUBMIT_JOB_AES_GCM_ENC and SUBMIT_JOB_AES_GCM_DEC functions.
                 */
                break;
#endif /* !NO_GCM */
        case CUSTOM_HASH:
                if (job->hash_func == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                break;
        case AES_CCM:
                if (job->msg_len_to_hash_in_bytes != 0 && job->src == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->u.CCM.aad_len_in_bytes > 46) {
                        /* 3 x AES_BLOCK - 2 bytes for AAD len */
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if ((job->u.CCM.aad_len_in_bytes > 0) &&
                    (job->u.CCM.aad == NULL)) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                /* M can be any even number from 4 to 16 */
                if (job->auth_tag_output_len_in_bytes < UINT64_C(4) ||
                    job->auth_tag_output_len_in_bytes > UINT64_C(16) ||
                    ((job->auth_tag_output_len_in_bytes & 1) != 0)) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                                return 1;
                }
                if (job->cipher_mode != CCM) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                /*
                 * AES-CCM allows for only one message for
                 * cipher and uthentication.
                 * AAD can be used to extend authentication over
                 * clear text fields.
                 */
                if (job->msg_len_to_cipher_in_bytes !=
                    job->msg_len_to_hash_in_bytes) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->cipher_start_src_offset_in_bytes !=
                    job->hash_start_src_offset_in_bytes) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                break;
        case AES_CMAC:
        case AES_CMAC_BITLEN:
                /*
                 * WARNING: When using AES_CMAC_BITLEN, length of message
                 * is passed in bits, using job->msg_len_to_hash_in_bits
                 * (unlike "normal" AES_CMAC, where is passed in bytes,
                 * using job->msg_len_to_hash_in_bytes).
                 */
                if (job->src == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if ((job->u.CMAC._key_expanded == NULL) ||
                    (job->u.CMAC._skey1 == NULL) ||
                    (job->u.CMAC._skey2 == NULL)) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                /* T is 128 bits but 96 bits is also allowed due to
                 * IPsec use case (RFC 4494) and 32 bits for CMAC 3GPP.
                 */
                if (job->auth_tag_output_len_in_bytes < UINT64_C(4) ||
                    job->auth_tag_output_len_in_bytes > UINT64_C(16)) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                break;
        case PLAIN_SHA1:
        case PLAIN_SHA_224:
        case PLAIN_SHA_256:
        case PLAIN_SHA_384:
        case PLAIN_SHA_512:
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[job->hash_alg]) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->src == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                break;
        case PON_CRC_BIP:
                /*
                 * Authentication tag in PON is BIP 32-bit value only
                 * CRC is done together with cipher,
                 * its initial value is read from the source buffer and
                 * updated value put into the destination buffer.
                 * - msg_len_to_hash_in_bytes is aligned to 4 bytes
                 */
                if (((job->msg_len_to_hash_in_bytes & UINT64_C(3)) != 0) ||
                    (job->msg_len_to_hash_in_bytes < UINT64_C(12)))  {
                        /*
                         * Length aligned to 4-bytes (and at least 12 bytes,
                         * including 8-byte XGEM header and 4-byte CRC)
                         */
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes != UINT64_C(8)) {
                        /* 64-bits:
                         * - BIP 32-bits
                         * - CRC 32-bits
                         */
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->cipher_mode != PON_AES_CNTR) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                break;
        default:
                INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                return 1;
        }
        return 0;
}

__forceinline
JOB_AES_HMAC *SUBMIT_JOB_AES(MB_MGR *state, JOB_AES_HMAC *job)
{
	if (job->cipher_direction == ENCRYPT)
		job = SUBMIT_JOB_AES_ENC(state, job);
	else
		job = SUBMIT_JOB_AES_DEC(state, job);

	return job;
}

__forceinline
JOB_AES_HMAC *FLUSH_JOB_AES(MB_MGR *state, JOB_AES_HMAC *job)
{
	if (job->cipher_direction == ENCRYPT)
		job = FLUSH_JOB_AES_ENC(state, job);
	else
		job = FLUSH_JOB_AES_DEC(state, job);

	return job;
}

/* submit a half-completed job, based on the status */
__forceinline
JOB_AES_HMAC *RESUBMIT_JOB(MB_MGR *state, JOB_AES_HMAC *job)
{
        while (job != NULL && job->status < STS_COMPLETED) {
                if (job->status == STS_COMPLETED_HMAC)
                        job = SUBMIT_JOB_AES(state, job);
                else /* assumed job->status = STS_COMPLETED_AES */
                        job = SUBMIT_JOB_HASH(state, job);
        }

	return job;
}

__forceinline
JOB_AES_HMAC *submit_new_job(MB_MGR *state, JOB_AES_HMAC *job)
{
	if (job->chain_order == CIPHER_HASH)
		job = SUBMIT_JOB_AES(state, job);
	else
		job = SUBMIT_JOB_HASH(state, job);

        job = RESUBMIT_JOB(state, job);
	return job;
}

__forceinline
void complete_job(MB_MGR *state, JOB_AES_HMAC *job)
{
        if (job->chain_order == CIPHER_HASH) {
                /* while() loop optimized for cipher_hash order */
                while (job->status < STS_COMPLETED) {
                        JOB_AES_HMAC *tmp = FLUSH_JOB_AES(state, job);

                        if (tmp == NULL)
                                tmp = FLUSH_JOB_HASH(state, job);

                        (void) RESUBMIT_JOB(state, tmp);
                }
        } else {
                /* while() loop optimized for hash_cipher order */
                while (job->status < STS_COMPLETED) {
                        JOB_AES_HMAC *tmp = FLUSH_JOB_HASH(state, job);

                        if (tmp == NULL)
                                tmp = FLUSH_JOB_AES(state, job);

                        (void) RESUBMIT_JOB(state, tmp);
                }
        }
}

__forceinline
JOB_AES_HMAC *
submit_job_and_check(MB_MGR *state, const int run_check)
{
        JOB_AES_HMAC *job = NULL;
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif

        job = JOBS(state, state->next_job);

        if (run_check) {
                if (is_job_invalid(job)) {
                        job->status = STS_INVALID_ARGS;
                } else {
                        job->status = STS_BEING_PROCESSED;
                        job = submit_new_job(state, job);
                }
        } else {
                job->status = STS_BEING_PROCESSED;
                job = submit_new_job(state, job);
        }

        if (state->earliest_job < 0) {
                /* state was previously empty */
                if (job == NULL)
                        state->earliest_job = state->next_job;
                ADV_JOBS(&state->next_job);
#ifndef LINUX
                RESTORE_XMMS(xmm_save);
#endif
                return job;
        }

        ADV_JOBS(&state->next_job);

        if (state->earliest_job == state->next_job) {
                /* Full */
                job = JOBS(state, state->earliest_job);
                complete_job(state, job);
                ADV_JOBS(&state->earliest_job);
#ifndef LINUX
                RESTORE_XMMS(xmm_save);
#endif
                return job;
        }

        /* not full */
#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
        job = JOBS(state, state->earliest_job);
        if (job->status < STS_COMPLETED)
                return NULL;

        ADV_JOBS(&state->earliest_job);
        return job;
}

JOB_AES_HMAC *
SUBMIT_JOB(MB_MGR *state)
{
        return submit_job_and_check(state, 1);
}

JOB_AES_HMAC *
SUBMIT_JOB_NOCHECK(MB_MGR *state)
{
        return submit_job_and_check(state, 0);
}

JOB_AES_HMAC *
FLUSH_JOB(MB_MGR *state)
{
        JOB_AES_HMAC *job;
#ifndef LINUX
        DECLARE_ALIGNED(uint128_t xmm_save[10], 16);
#endif

        if (state->earliest_job < 0)
                return NULL; /* empty */

#ifndef LINUX
        SAVE_XMMS(xmm_save);
#endif
        job = JOBS(state, state->earliest_job);
        complete_job(state, job);

        ADV_JOBS(&state->earliest_job);

        if (state->earliest_job == state->next_job)
                state->earliest_job = -1; /* becomes empty */

#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
        return job;
}

/* ========================================================================= */
/* ========================================================================= */

uint32_t
QUEUE_SIZE(MB_MGR *state)
{
        int a, b;

        if (state->earliest_job < 0)
                return 0;
        a = state->next_job / sizeof(JOB_AES_HMAC);
        b = state->earliest_job / sizeof(JOB_AES_HMAC);
        return ((a-b) & (MAX_JOBS-1));
}

JOB_AES_HMAC *
GET_COMPLETED_JOB(MB_MGR *state)
{
        JOB_AES_HMAC *job;

        if (state->earliest_job < 0)
                return NULL;

        job = JOBS(state, state->earliest_job);
        if (job->status < STS_COMPLETED)
                return NULL;

        ADV_JOBS(&state->earliest_job);

        if (state->earliest_job == state->next_job)
                state->earliest_job = -1;

        return job;
}

JOB_AES_HMAC *
GET_NEXT_JOB(MB_MGR *state)
{
        return JOBS(state, state->next_job);
}
