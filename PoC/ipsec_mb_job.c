/*
 * Copyright (c) 2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Author: Shuzo Ichiyoshi
 */

#include "ipsec_mb.h"
#include "ipsec_mb_api.h"

#if 1
# include <string.h>
# define MEMCMP(_p0, _p1, _s)	memcmp((_p0), (_p1), (_s))
# define MEMCPY(_d, _s, _z)	memcpy((_d), (_s), (_z))
#endif

/*
 *
 */
__forceinline enum JOB_STS
verify_tag(struct JOB_AES_HMAC *job)
{
	if (MEMCMP(job->verify_tag, job->chk_tag_p,
                   job->auth_tag_output_len_in_bytes)) {
                job->current_stage = 0;	/* for break job */
                return STS_AUTH_FAILED;
        } else {
                return STS_COMPLETED_HMAC;
        }
}

/******************************************************************************
 * AES128 CBC mode
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_aes128_cbc_enc(union MB_MGR_JOB_STATE *state,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        return JOB_SUBMIT_aes128_cbc_enc(&state->aes_ooo, job);
}

static struct JOB_AES_HMAC *
flush_aes128_cbc_enc(union MB_MGR_JOB_STATE *state)
{
        return JOB_FLUSH_aes128_cbc_enc(&state->aes_ooo);
}

static struct JOB_AES_HMAC *
submit_aes128_cbc_dec(union MB_MGR_JOB_STATE *state __unused,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        /* msg_len_to_cipher_in_bytes mask for DOCSIS */
        AES128_cbc_dec((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                       job->iv,
                       job->aes_dec_key_expanded,
                       job->dst,
                       job->msg_len_to_cipher_in_bytes & (~(AES_BLOCK_SIZE - 1)));
        job->status |= STS_COMPLETED_AES;
        return job;
}

static void
init_aes128_cbc_state(union MB_MGR_JOB_STATE *state)
{
        TRACE("state:%p\n", state);
        init_aes_ooo(&state->aes_ooo);
}

/******************************************************************************
 * AES192 CBC mode
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_aes192_cbc_enc(union MB_MGR_JOB_STATE *state,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        return JOB_SUBMIT_aes128_cbc_enc(&state->aes_ooo, job);
}

static struct JOB_AES_HMAC *
flush_aes192_cbc_enc(union MB_MGR_JOB_STATE *state)
{
        return JOB_FLUSH_aes128_cbc_enc(&state->aes_ooo);
}

static struct JOB_AES_HMAC *
submit_aes192_cbc_dec(union MB_MGR_JOB_STATE *state __unused,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        AES128_cbc_dec((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                       job->iv,
                       job->aes_dec_key_expanded,
                       job->dst,
                       job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return job;
}

static void
init_aes192_cbc_state(union MB_MGR_JOB_STATE *state)
{
        TRACE("state:%p\n", state);
        init_aes_ooo(&state->aes_ooo);
}

/******************************************************************************
 * AES256 CBC mode
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_aes256_cbc_enc(union MB_MGR_JOB_STATE *state,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        return JOB_SUBMIT_aes128_cbc_enc(&state->aes_ooo, job);
}

static struct JOB_AES_HMAC *
flush_aes256_cbc_enc(union MB_MGR_JOB_STATE *state)
{
        return JOB_FLUSH_aes128_cbc_enc(&state->aes_ooo);
}

static struct JOB_AES_HMAC *
submit_aes256_cbc_dec(union MB_MGR_JOB_STATE *state __unused,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        AES128_cbc_dec((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                       job->iv,
                       job->aes_dec_key_expanded,
                       job->dst,
                       job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return job;
}

static void
init_aes256_cbc_state(union MB_MGR_JOB_STATE *state)
{
        TRACE("state:%p\n", state);
        init_aes_ooo(&state->aes_ooo);
}

/******************************************************************************
 * AES128 CTR mode
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_aes128_ctr(union MB_MGR_JOB_STATE *state __unused,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        AES128_ctr((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                   job->iv,
                   job->aes_enc_key_expanded,
                   job->dst,
                   job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return job;
}

/******************************************************************************
 * AES192 CTR mode
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_aes192_ctr(union MB_MGR_JOB_STATE *state __unused,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        AES192_ctr((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                   job->iv,
                   job->aes_enc_key_expanded,
                   job->dst,
                   job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return job;
}

/******************************************************************************
 * AES256 CTR mode
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_aes256_ctr(union MB_MGR_JOB_STATE *state __unused,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        AES256_ctr((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                   job->iv,
                   job->aes_enc_key_expanded,
                   job->dst,
                   job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return job;
}

/******************************************************************************
 * AES128 GCM mode
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_aes128_gcm_enc(union MB_MGR_JOB_STATE *state __unused,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        AES128_gcm_enc(job->aes_enc_key_expanded,
                       job->gmac.key,
                       job->dst,
                       (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                       job->msg_len_to_cipher_in_bytes,
                       job->iv,
                       job->aad, job->aad_len_in_bytes,
                       job->auth_tag_output, job->auth_tag_output_len_in_bytes);
        job->status = STS_COMPLETED;
        TRACE("completed job:%u\n", job->seq_num);
        return job;
}

static struct JOB_AES_HMAC *
submit_aes128_gcm_dec(union MB_MGR_JOB_STATE *state __unused,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        job->chk_tag_p = job->auth_tag_output;
        AES128_gcm_dec(job->aes_dec_key_expanded,
                       job->gmac.key,
                       job->dst,
                       (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                       job->msg_len_to_cipher_in_bytes,
                       job->iv,
                       job->aad, job->aad_len_in_bytes,
                       job->verify_tag, job->auth_tag_output_len_in_bytes);
        if (MEMCMP(job->verify_tag, job->chk_tag_p,
                   job->auth_tag_output_len_in_bytes))
                job->status = STS_AUTH_FAILED;
        else
                job->status = STS_COMPLETED;
        TRACE("completed job:%u\n", job->seq_num);
        return job;
}

/******************************************************************************
 * AES192 GCM mode
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_aes192_gcm_enc(union MB_MGR_JOB_STATE *state __unused,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        AES192_gcm_enc(job->aes_enc_key_expanded,
                       job->gmac.key,
                       job->dst,
                       (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                       job->msg_len_to_cipher_in_bytes,
                       job->iv,
                       job->aad, job->aad_len_in_bytes,
                       job->auth_tag_output, job->auth_tag_output_len_in_bytes);
        job->status = STS_COMPLETED;
        TRACE("completed job:%u\n", job->seq_num);
        return job;
}

static struct JOB_AES_HMAC *
submit_aes192_gcm_dec(union MB_MGR_JOB_STATE *state __unused,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        job->chk_tag_p = job->auth_tag_output;
        AES192_gcm_dec(job->aes_dec_key_expanded,
                       job->gmac.key,
                       job->dst,
                       (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                       job->msg_len_to_cipher_in_bytes,
                       job->iv,
                       job->aad, job->aad_len_in_bytes,
                       job->verify_tag, job->auth_tag_output_len_in_bytes);
        if (MEMCMP(job->verify_tag, job->chk_tag_p,
                   job->auth_tag_output_len_in_bytes))
                job->status = STS_AUTH_FAILED;
        else
                job->status = STS_COMPLETED;
        TRACE("completed job:%u\n", job->seq_num);
        return job;
}

/******************************************************************************
 * AES256 GCM mode
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_aes256_gcm_enc(union MB_MGR_JOB_STATE *state __unused,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        AES256_gcm_enc(job->aes_enc_key_expanded,
                       job->gmac.key,
                       job->dst,
                       (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                       job->msg_len_to_cipher_in_bytes,
                       job->iv,
                       job->aad, job->aad_len_in_bytes,
                       job->auth_tag_output,
                       job->auth_tag_output_len_in_bytes);
        job->status = STS_COMPLETED;
        TRACE("completed job:%u\n", job->seq_num);
        return job;
}

static struct JOB_AES_HMAC *
submit_aes256_gcm_dec(union MB_MGR_JOB_STATE *state __unused,
                      struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        job->chk_tag_p = job->auth_tag_output;
        AES256_gcm_dec(job->aes_dec_key_expanded,
                       job->gmac.key,
                       job->dst,
                       (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                       job->msg_len_to_cipher_in_bytes,
                       job->iv,
                       job->aad, job->aad_len_in_bytes,
                       job->verify_tag, job->auth_tag_output_len_in_bytes);
        if (MEMCMP(job->verify_tag, job->chk_tag_p,
                   job->auth_tag_output_len_in_bytes))
                job->status = STS_AUTH_FAILED;
        else
                job->status = STS_COMPLETED;
        TRACE("completed job:%u\n", job->seq_num);
        return job;
}

/******************************************************************************
 * DOCSIS
 ******************************************************************************/
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
struct JOB_AES_HMAC *
DOCSIS_LAST_BLOCK(struct JOB_AES_HMAC *job)
{
        if (job) {
                UINT64 offset;
                UINT64 partial_bytes;

                partial_bytes = job->msg_len_to_cipher_in_bytes & (AES_BLOCK_SIZE - 1);
                offset = job->msg_len_to_cipher_in_bytes & (~(AES_BLOCK_SIZE - 1));

                if (partial_bytes) {
                        const union AES_IV *iv;

                        /* in either case IV has to be next last ciphered block */
                        if (job->cipher_direction == ENCRYPT)
                                iv = (const union AES_IV *) (((const UINT8 *) (job->dst)) +
                                                             offset - AES_BLOCK_SIZE);
                        else
                                iv = (const union AES_IV *) (((const UINT8 *) job->src) +
                                                             job->cipher_start_src_offset_in_bytes +
                                                             offset - AES_BLOCK_SIZE);

                        AES128_cfb_one(((UINT8 *) job->dst) + offset,
                                       ((const UINT8 *) job->src) + job->cipher_start_src_offset_in_bytes + offset,
                                       iv,
                                       job->aes_enc_key_expanded,
                                       partial_bytes);
                }
        }
        return job;
}

/**
 * @brief Encrypts/decrypts the first and only partial block for DOCSIS SEC v3.1 BPI
 *
 * The first partial block is encrypted/decrypted using AES CFB128.
 *
 * @param job desriptor of performed crypto operation
 * @return It always returns value passed in \a job
 */
__forceinline
struct JOB_AES_HMAC *
DOCSIS_FIRST_BLOCK(struct JOB_AES_HMAC *job)
{
        AES128_cfb_one(job->dst,
                       ((const UINT8 *) job->src) + job->cipher_start_src_offset_in_bytes,
                       job->iv,
                       job->aes_enc_key_expanded,
                       job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return job;
}

static struct JOB_AES_HMAC *
submit_docsis_enc(union MB_MGR_JOB_STATE *state,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {
                job = submit_aes128_cbc_enc(state, job);
                return DOCSIS_LAST_BLOCK(job);
        }
        return DOCSIS_FIRST_BLOCK(job);
}

static struct JOB_AES_HMAC *
flush_docsis_enc(union MB_MGR_JOB_STATE *state)
{
        struct JOB_AES_HMAC *job;

        job = flush_aes128_cbc_enc(state);
        return DOCSIS_LAST_BLOCK(job);

}

static struct JOB_AES_HMAC *
submit_docsis_dec(union MB_MGR_JOB_STATE *state,
                  struct JOB_AES_HMAC *job)
{
        if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {
                DOCSIS_LAST_BLOCK(job);
                return submit_aes128_cbc_dec(state, job);
        }
        return DOCSIS_FIRST_BLOCK(job);
}

/******************************************************************************
 * NULL Cipher
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_null_cipher(union MB_MGR_JOB_STATE *state __unused,
                   struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        if (job->dst != (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes) {
                MEMCPY(job->dst,
                       (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes,
                       job->msg_len_to_cipher_in_bytes);
        }
        job->status |= STS_COMPLETED_AES;
        return job;
}

/******************************************************************************
 * HMAC_SHA1
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_sha1_enc(union MB_MGR_JOB_STATE *state,
                struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        return JOB_SUBMIT_sha1(&state->sha1_ooo, job);
}

static struct JOB_AES_HMAC *
flush_sha1_enc(union MB_MGR_JOB_STATE *state)
{
        return JOB_flush_sha1(&state->sha1_ooo);
}

static struct JOB_AES_HMAC *
submit_sha1_dec(union MB_MGR_JOB_STATE *state,
                struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        job->chk_tag_p = job->auth_tag_output;
        job->auth_tag_output = job->verify_tag;

        job = JOB_SUBMIT_sha1(&state->sha1_ooo, job);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static struct JOB_AES_HMAC *
flush_sha1_dec(union MB_MGR_JOB_STATE *state)
{
        struct JOB_AES_HMAC *job;

        job = JOB_flush_sha1(&state->sha1_ooo);
        if (job)
                job->status |= verify_tag(job);
        return job;
}


static void
init_sha1_state(union MB_MGR_JOB_STATE *state)
{
        TRACE("state:%p\n", state);
        init_sha1_ooo(&state->sha1_ooo);
}

/******************************************************************************
 * HMAC_SHA224
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_sha224_enc(union MB_MGR_JOB_STATE *state,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        return JOB_SUBMIT_sha224(&state->sha256_ooo, job);
}

static struct JOB_AES_HMAC *
flush_sha224_enc(union MB_MGR_JOB_STATE *state)
{
        return JOB_FLUSH_sha224(&state->sha256_ooo);
}

static struct JOB_AES_HMAC *
submit_sha224_dec(union MB_MGR_JOB_STATE *state,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        job->chk_tag_p = job->auth_tag_output;
        job->auth_tag_output = job->verify_tag;

        job = JOB_SUBMIT_sha224(&state->sha256_ooo, job);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static struct JOB_AES_HMAC *
flush_sha224_dec(union MB_MGR_JOB_STATE *state)
{
        struct JOB_AES_HMAC *job;

        job = JOB_FLUSH_sha224(&state->sha256_ooo);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static void
init_sha224_state(union MB_MGR_JOB_STATE *state)
{
        TRACE("state:%p\n", state);
        init_sha224_ooo(&state->sha256_ooo);
}

/******************************************************************************
 * HMAC_SHA256
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_sha256_enc(union MB_MGR_JOB_STATE *state,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        return JOB_SUBMIT_sha256(&state->sha256_ooo, job);
}

static struct JOB_AES_HMAC *
flush_sha256_enc(union MB_MGR_JOB_STATE *state)
{
        return JOB_FLUSH_sha256(&state->sha256_ooo);
}

static struct JOB_AES_HMAC *
submit_sha256_dec(union MB_MGR_JOB_STATE *state,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        job->chk_tag_p = job->auth_tag_output;
        job->auth_tag_output = job->verify_tag;

        job = JOB_SUBMIT_sha256(&state->sha256_ooo, job);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static struct JOB_AES_HMAC *
flush_sha256_dec(union MB_MGR_JOB_STATE *state)
{
        struct JOB_AES_HMAC *job;

        job = JOB_FLUSH_sha256(&state->sha256_ooo);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static void
init_sha256_state(union MB_MGR_JOB_STATE *state)
{
        TRACE("state:%p\n", state);
        init_sha256_ooo(&state->sha256_ooo);
}

/******************************************************************************
 * HMAC_SHA384
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_sha384_enc(union MB_MGR_JOB_STATE *state,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        return JOB_SUBMIT_sha384(&state->sha512_ooo, job);
}

static struct JOB_AES_HMAC *
flush_sha384_enc(union MB_MGR_JOB_STATE *state)
{
        return JOB_FLUSH_sha384(&state->sha512_ooo);
}

static struct JOB_AES_HMAC *
submit_sha384_dec(union MB_MGR_JOB_STATE *state,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        job->chk_tag_p = job->auth_tag_output;
        job->auth_tag_output = job->verify_tag;

        job = JOB_SUBMIT_sha384(&state->sha512_ooo, job);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static struct JOB_AES_HMAC *
flush_sha384_dec(union MB_MGR_JOB_STATE *state)
{
        struct JOB_AES_HMAC *job;

        job = JOB_FLUSH_sha384(&state->sha512_ooo);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static void
init_sha384_state(union MB_MGR_JOB_STATE *state)
{
        TRACE("state:%p\n", state);
        init_sha384_ooo(&state->sha512_ooo);
}

/******************************************************************************
 * HMAC_SHA512
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_sha512_enc(union MB_MGR_JOB_STATE *state,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        return JOB_SUBMIT_sha512(&state->sha512_ooo, job);
}

static struct JOB_AES_HMAC *
flush_sha512_enc(union MB_MGR_JOB_STATE *state)
{
        return JOB_FLUSH_sha512(&state->sha512_ooo);
}

static struct JOB_AES_HMAC *
submit_sha512_dec(union MB_MGR_JOB_STATE *state,
                  struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        job->chk_tag_p = job->auth_tag_output;
        job->auth_tag_output = job->verify_tag;

        job = JOB_SUBMIT_sha512(&state->sha512_ooo, job);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static struct JOB_AES_HMAC *
flush_sha512_dec(union MB_MGR_JOB_STATE *state)
{
        struct JOB_AES_HMAC *job;

        job = JOB_FLUSH_sha512(&state->sha512_ooo);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static void
init_sha512_state(union MB_MGR_JOB_STATE *state)
{
        TRACE("state:%p\n", state);
        init_sha512_ooo(&state->sha512_ooo);
}

/******************************************************************************
 * HMAC_MD5 (not yet)
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_md5_enc(union MB_MGR_JOB_STATE *state,
               struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        return JOB_SUBMIT_md5(&state->md5_ooo, job);
}

static struct JOB_AES_HMAC *
flush_md5_enc(union MB_MGR_JOB_STATE *state)
{
        return JOB_FLUSH_md5(&state->md5_ooo);
}

static struct JOB_AES_HMAC *
submit_md5_dec(union MB_MGR_JOB_STATE *state,
               struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        job->chk_tag_p = job->auth_tag_output;
        job->auth_tag_output = job->verify_tag;

        job = JOB_SUBMIT_md5(&state->md5_ooo, job);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static struct JOB_AES_HMAC *
flush_md5_dec(union MB_MGR_JOB_STATE *state)
{
        struct JOB_AES_HMAC *job;

        job = JOB_FLUSH_md5(&state->md5_ooo);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static void
init_md5_state(union MB_MGR_JOB_STATE *state)
{
        TRACE("state:%p\n", state);
        init_md5_ooo(&state->md5_ooo);
}

/******************************************************************************
 * AES_XCBC
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_xcbc_enc(union MB_MGR_JOB_STATE *state,
                struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        return JOB_SUBMIT_aes_xcbc(&state->xcbc_ooo, job);
}

static struct JOB_AES_HMAC *
flush_xcbc_enc(union MB_MGR_JOB_STATE *state)
{
        return JOB_FLUSH_aes_xcbc(&state->xcbc_ooo);
}

static struct JOB_AES_HMAC *
submit_xcbc_dec(union MB_MGR_JOB_STATE *state,
                struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);

        job->chk_tag_p = job->auth_tag_output;
        job->auth_tag_output = job->verify_tag;

        job = JOB_SUBMIT_aes_xcbc(&state->xcbc_ooo, job);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static struct JOB_AES_HMAC *
flush_xcbc_dec(union MB_MGR_JOB_STATE *state)
{
        struct JOB_AES_HMAC *job;

        job = JOB_FLUSH_aes_xcbc(&state->xcbc_ooo);
        if (job)
                job->status |= verify_tag(job);
        return job;
}

static void
init_xcbc_state(union MB_MGR_JOB_STATE *state)
{
        TRACE("state:%p\n", state);
        init_xcbc_ooo(&state->xcbc_ooo);
}

/******************************************************************************
 * NULL Authentication
 ******************************************************************************/
static struct JOB_AES_HMAC *
submit_null_auth(union MB_MGR_JOB_STATE *state __unused,
                 struct JOB_AES_HMAC *job)
{
        TRACE("entry job:%u\n", job->seq_num);
        job->status |= STS_COMPLETED_HMAC;
        return job;
}

/******************************************************************************
 * Operations Table
 ******************************************************************************/
const struct JOB_TASK_INFO job_task_info[] = {
        [JOB_TASK_INVALID] = {
                .name                   = "invalid",
                .state_id               = JOB_STATE_INVALID,
        },
        [JOB_TASK_AES128_CBC] = {
                .name                   = "AES128_CBC",
                .state_id               = JOB_STATE_AES128,
                .state_initializer      = init_aes128_cbc_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_cbc_enc,
                                .flush  = flush_aes128_cbc_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_cbc_dec,
                        },
                }
        },
        [JOB_TASK_AES192_CBC] = {
                .name                   = "AES192_CBC",
                .state_id               = JOB_STATE_AES192,
                .state_initializer      = init_aes192_cbc_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_cbc_enc,
                                .flush  = flush_aes192_cbc_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_cbc_dec,
                        },
                }
        },
        [JOB_TASK_AES256_CBC] = {
                .name                   = "AES256_CBC",
                .state_id               = JOB_STATE_AES256,
                .state_initializer            = init_aes256_cbc_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_cbc_enc,
                                .flush  = flush_aes256_cbc_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_cbc_dec,
                        },
                }
        },
        [JOB_TASK_AES128_CTR] = {
                .name                   = "AES128_CTR",
                .state_id               = JOB_STATE_INVALID,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_ctr,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_ctr,
                        },
                }
        },
        [JOB_TASK_AES192_CTR] = {
                .name                   = "AES192_CTR",
                .state_id               = JOB_STATE_INVALID,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_ctr,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_ctr,
                        },
                }
        },
        [JOB_TASK_AES256_CTR] = {
                .name                   = "AES256_CTR",
                .state_id               = JOB_STATE_INVALID,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_ctr,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_ctr,
                        },
                }
        },
        [JOB_TASK_AES128_GCM] = {
                .name                   = "AES128_GCM",
                .state_id               = JOB_STATE_INVALID,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_gcm_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_gcm_dec,
                        },
                }
        },
        [JOB_TASK_AES192_GCM] = {
                .name                   = "AES192_GCM",
                .state_id               = JOB_STATE_INVALID,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_gcm_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_gcm_dec,
                        },
                }
        },
        [JOB_TASK_AES256_GCM] = {
                .name                   = "AES256_GCM",
                .state_id               = JOB_STATE_INVALID,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_gcm_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_gcm_dec,
                        },
                }
        },
        [JOB_TASK_DOCSIS] = {
                .name                   = "DOCSIS",
                .state_id               = JOB_STATE_DOCSIS,

                /* same settings as AES128 CBC */
                .state_initializer      = init_aes128_cbc_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_docsis_enc,
                                .flush  = flush_docsis_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_docsis_dec,
                        },
                }
        },
        [JOB_TASK_NULL_CIPHER] = {
                .name                   = "NULL_CIPHER",
                .state_id               = JOB_STATE_INVALID,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                }
        },
        [JOB_TASK_SHA1] = {
                .name                   = "SHA1",
                .state_id               = JOB_STATE_SHA1,
                .state_initializer      = init_sha1_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha1_enc,
                                .flush  = flush_sha1_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha1_dec,
                                .flush  = flush_sha1_dec,
                        },
                }
        },
        [JOB_TASK_SHA224] = {
                .name                   = "SHA224",
                .state_id               = JOB_STATE_SHA224,
                .state_initializer      = init_sha224_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha224_enc,
                                .flush  = flush_sha224_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha224_dec,
                                .flush  = flush_sha224_dec,
                        },
                }
        },
        [JOB_TASK_SHA256] = {
                .name                   = "SHA256",
                .state_id               = JOB_STATE_SHA256,
                .state_initializer      = init_sha256_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha256_enc,
                                .flush  = flush_sha256_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha256_dec,
                                .flush  = flush_sha256_dec,
                        },
                }
        },
        [JOB_TASK_SHA384] = {
                .name                   = "SHA384",
                .state_id               = JOB_STATE_SHA384,
                .state_initializer      = init_sha384_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha384_enc,
                                .flush  = flush_sha384_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha384_dec,
                                .flush  = flush_sha384_dec,
                        },
                }
        },
        [JOB_TASK_SHA512] = {
                .name                   = "SHA512",
                .state_id               = JOB_STATE_SHA512,
                .state_initializer      = init_sha512_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha512_enc,
                                .flush  = flush_sha512_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha512_dec,
                                .flush  = flush_sha512_dec,
                        },
                }
        },
        [JOB_TASK_MD5] = {
                .name                   = "MD5",
                .state_id               = JOB_STATE_MD5,
                .state_initializer      = init_md5_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_md5_enc,
                                .flush  = flush_md5_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_md5_dec,
                                .flush  = flush_md5_dec,
                        },
                }
        },
        [JOB_TASK_XCBC] = {
                .name                   = "XCBC",
                .state_id               = JOB_STATE_XCBC,
                .state_initializer      = init_xcbc_state,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_xcbc_enc,
                                .flush  = flush_xcbc_enc,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_xcbc_dec,
                                .flush  = flush_xcbc_dec,
                        },
                }
        },
        [JOB_TASK_NULL_HASH] = {
                .name                   = "NULL_HASH",
                .state_id               = JOB_STATE_INVALID,
                .dir_func = {
                        [ENCRYPT - 1] = {
                                .submit = submit_null_auth,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_null_auth,
                        },
                }
        },
};

/*
 * return:
 *	OK:0
 *	NG:other
 */
int
_ipsec_mb_setup_job(struct JOB_AES_HMAC *job)
{
        int cipher_stage, auth_stage;
        enum JOB_TASK cipher_task, auth_task;
        int start_stage = -1;

        job->current_stage = -1;
        job->status = STS_INVALID_ARGS;

        switch (job->cipher_mode) {
        case CBC:
                switch (job->aes_key_len_in_bytes) {
                case AES_128_BYTES:
                        cipher_task = JOB_TASK_AES128_CBC;
                        break;
                case AES_192_BYTES:
                        cipher_task = JOB_TASK_AES192_CBC;
                        break;
                case AES_256_BYTES:
                        cipher_task = JOB_TASK_AES256_CBC;
                        break;
                default:
                        TRACE("invalid AES key length:%u\n",
                              (unsigned) job->aes_key_len_in_bytes);
                        return -1;
                }
                break;

        case CNTR:
                switch (job->aes_key_len_in_bytes) {
                case AES_128_BYTES:
                        cipher_task = JOB_TASK_AES128_CTR;
                        break;
                case AES_192_BYTES:
                        cipher_task = JOB_TASK_AES192_CTR;
                        break;
                case AES_256_BYTES:
                        cipher_task = JOB_TASK_AES256_CTR;
                        break;
                default:
                        TRACE("invalid AES key length:%u\n",
                              (unsigned) job->aes_key_len_in_bytes);
                        return -1;
                }
                break;

        case GCM:
                switch (job->aes_key_len_in_bytes) {
                case AES_128_BYTES:
                        cipher_task = JOB_TASK_AES128_GCM;
                        break;
                case AES_192_BYTES:
                        cipher_task = JOB_TASK_AES192_GCM;
                        break;
                case AES_256_BYTES:
                        cipher_task = JOB_TASK_AES256_GCM;
                        break;
                default:
                        TRACE("invalid AES key length:%u\n",
                              (unsigned) job->aes_key_len_in_bytes);
                        return -1;
                }
                if (job->hash_alg != GMAC_AES) {
                        TRACE("invalid GMAC:%d\n", job->hash_alg);
                        return -1;
                }
                /* GCM ia oneshot */
                cipher_stage = 0;
                break;

        case DOCSIS_SEC_BPI:
                switch (job->aes_key_len_in_bytes) {
                case AES_128_BYTES:
                        cipher_task = JOB_TASK_DOCSIS;
                        break;
                case AES_192_BYTES:
                case AES_256_BYTES:
                default:
                        TRACE("invalid DOCSIS AES key length:%u\n",
                              (unsigned) job->aes_key_len_in_bytes);
                        return -1;
                }
                break;

        case NULL_CIPHER:
                /* DST == SRT check */
                cipher_task = JOB_TASK_NULL_CIPHER;
                break;

        default:
                TRACE("invalid cipher mode:%d\n", job->cipher_mode);
                return -1;
        }

        /* auth params */
        switch (job->hash_alg) {
        case SHA1:
                if (job->auth_tag_output_len_in_bytes != 12) {
                        TRACE("invalid SHA1 tag len:%u\n",
                              (unsigned) job->auth_tag_output_len_in_bytes);
                        return -1;
                }
                auth_task = JOB_TASK_SHA1;
                break;

        case SHA_256:
                if (job->auth_tag_output_len_in_bytes != 16) {
                        TRACE("invalid SHA256 tag len:%u\n",
                              (unsigned) job->auth_tag_output_len_in_bytes);
                        return -1;
                }
                auth_task = JOB_TASK_SHA256;
                break;

        case SHA_384:
                if (job->auth_tag_output_len_in_bytes != 24) {
                        TRACE("invalid SHA384 tag len:%u\n",
                              (unsigned) job->auth_tag_output_len_in_bytes);
                        return -1;
                }
                auth_task = JOB_TASK_SHA384;
                break;

        case SHA_512:
                if (job->auth_tag_output_len_in_bytes != 32) {
                        TRACE("invalid SHA512 tag len:%u\n",
                              (unsigned) job->auth_tag_output_len_in_bytes);
                        return -1;
                }
                auth_task = JOB_TASK_SHA512;
                break;

        case AES_XCBC:
                if (job->auth_tag_output_len_in_bytes != 12) {
                        TRACE("invalid XCBC tag len:%u\n",
                              (unsigned) job->auth_tag_output_len_in_bytes);
                        return -1;
                }
                auth_task = JOB_TASK_XCBC;
                break;

        case NULL_HASH:
                if (job->auth_tag_output_len_in_bytes != 0) {
                        TRACE("invalid NULL tag len:%u\n",
                              (unsigned) job->auth_tag_output_len_in_bytes);
                        return -1;
                }
                auth_task = JOB_TASK_NULL_HASH;
                break;

        case GMAC_AES:
                if (job->auth_tag_output_len_in_bytes != 8 &&
                    job->auth_tag_output_len_in_bytes != 12 &&
                    job->auth_tag_output_len_in_bytes != 16) {
                        TRACE("invalid GMAC tag len:%u\n",
                              (unsigned) job->auth_tag_output_len_in_bytes);
                        return -1;
                }
                if (job->cipher_mode == GCM) {
                        auth_task = JOB_TASK_INVALID;
                } else {
                        /* not supported GMAC only */
                        TRACE("not GCM:%d\n", job->cipher_mode);
                        return -1;
                }
                break;

        case SHA_224:
                if (job->auth_tag_output_len_in_bytes != 14) {
                        TRACE("invalid SHA224 tag len:%u\n",
                              (unsigned) job->auth_tag_output_len_in_bytes);
                        return -1;
                }
                auth_task = JOB_TASK_SHA224;
                break;

        case MD5:
                if (job->auth_tag_output_len_in_bytes != 12) {
                        TRACE("invalid MD5 tag len:%u\n",
                              (unsigned) job->auth_tag_output_len_in_bytes);
                        return -1;
                }
                auth_task = JOB_TASK_MD5;
                break;

        default:
                TRACE("invalid hash_alg:%d\n", job->hash_alg);
                return -1;
        }

        if (cipher_task == JOB_TASK_INVALID) {
                if (auth_task == JOB_TASK_INVALID) {
                        TRACE("invalid tasks\n");
                        return -1;
                }
                auth_stage = 0;
                start_stage = 0;

                TRACE("auth:%s stage:%d\n",
                      job_task_info[auth_task].name, auth_stage);

                job->stage_task[auth_stage] = auth_task;
        } else {
                if (auth_task == JOB_TASK_INVALID) {
                        cipher_stage = 0;
                        start_stage = 0;
                } else {
                        switch (job->cipher_direction) {
                        case ENCRYPT:
                                cipher_stage = 1;	/* first stage */
                                auth_stage   = 0;
                                break;
                        case DECRYPT:
                                auth_stage   = 1;
                                cipher_stage = 0;	/* sencond stage */
                                break;
                        default:
                                TRACE("invalid dir:%d\n", job->cipher_direction);
                                return -1;
                        }
                        start_stage = 1;

                        TRACE("auth:%s stage:%d\n",
                              job_task_info[auth_task].name, auth_stage);

                        job->stage_task[auth_stage] = auth_task;
                }

                TRACE("cipher:%s stage:%d\n",
                      job_task_info[cipher_task].name, cipher_stage);

                job->stage_task[cipher_stage] = cipher_task;
        }

        job->status = STS_BEING_PROCESSED;
        job->current_stage = start_stage;
        return 0;
}

/*
 * initialize states
 */
int
ipsec_mb_init_mgr(struct MB_MGR *mgr)
{
        for (unsigned i = 0; i < ARRAYOF(job_task_info); i++) {
                if (job_task_info[i].state_initializer) {
                        enum JOB_STATE state_id = job_task_info[i].state_id;

                        TRACE("task:%u state:%d\n", i, state_id);
                        job_task_info[i].state_initializer(&mgr->states[state_id]);
                }
        }

        for (unsigned i = 0; i < ARRAYOF(mgr->jobs); i++)
                mgr->jobs[i].seq_num = i;
        mgr->next  = 0;
        mgr->depth = 0;
        return 0;
}



