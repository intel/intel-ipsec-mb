/*
 * Copyright (c) 2012-2017, Intel Corporation
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


// This contains the bulk of the mb_mgr code, with #define's to build
// an SSE, AVX, AVX2 or AVX512 version (see mb_mgr_sse.c, mb_mgr_avx.c, etc.)

// get_next_job() returns a job object. This must be filled in and returned
// via submit_job() before get_next_job() is called again.
// submit_job() and flush_job() returns a job object. This job object ceases
// to be usable at the next call to get_next_job()

// Assume JOBS() and ADV_JOBS() from mb_mgr_code.h are available

////////////////////////////////////////////////////////////////////////


JOB_AES_HMAC* SUBMIT_JOB_AES128_DEC(JOB_AES_HMAC* job);
JOB_AES_HMAC* SUBMIT_JOB_AES192_DEC(JOB_AES_HMAC* job);
JOB_AES_HMAC* SUBMIT_JOB_AES256_DEC(JOB_AES_HMAC* job);
JOB_AES_HMAC* SUBMIT_JOB_AES128_CNTR(JOB_AES_HMAC* job);
JOB_AES_HMAC* SUBMIT_JOB_AES192_CNTR(JOB_AES_HMAC* job);
JOB_AES_HMAC* SUBMIT_JOB_AES256_CNTR(JOB_AES_HMAC* job);

////////////////////////////////////////////////////////////////////////

#ifndef NO_GCM
__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_GCM_DEC(JOB_AES_HMAC *job)
{
      DECLARE_ALIGNED(struct gcm_context_data ctx, 16);

      if (16 == job->aes_key_len_in_bytes)
              AES_GCM_DEC_128(job->aes_dec_key_expanded,
                              &ctx,
                              job->dst,
                              job->src + job->cipher_start_src_offset_in_bytes,
                              job->msg_len_to_cipher_in_bytes,
                              job->iv,
                              job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                              job->auth_tag_output, job->auth_tag_output_len_in_bytes);
      else if (24 == job->aes_key_len_in_bytes)
              AES_GCM_DEC_192(job->aes_dec_key_expanded,
                              &ctx,
                              job->dst,
                              job->src + job->cipher_start_src_offset_in_bytes,
                              job->msg_len_to_cipher_in_bytes,
                              job->iv,
                              job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                              job->auth_tag_output, job->auth_tag_output_len_in_bytes);
      else
              AES_GCM_DEC_256(job->aes_dec_key_expanded,
                              &ctx,
                              job->dst,
                              job->src + job->cipher_start_src_offset_in_bytes,
                              job->msg_len_to_cipher_in_bytes,
                              job->iv,
                              job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                              job->auth_tag_output, job->auth_tag_output_len_in_bytes);

      job->status = STS_COMPLETED;
      return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_GCM_ENC(JOB_AES_HMAC *job)
{
      DECLARE_ALIGNED(struct gcm_context_data ctx, 16);

      if (16 == job->aes_key_len_in_bytes)
              AES_GCM_ENC_128(job->aes_dec_key_expanded,
                              &ctx,
                              job->dst,
                              job->src + job->cipher_start_src_offset_in_bytes,
                              job->msg_len_to_cipher_in_bytes,
                              job->iv,
                              job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                              job->auth_tag_output, job->auth_tag_output_len_in_bytes);
      else if (24 == job->aes_key_len_in_bytes)
              AES_GCM_ENC_192(job->aes_dec_key_expanded,
                              &ctx,
                              job->dst,
                              job->src + job->cipher_start_src_offset_in_bytes,
                              job->msg_len_to_cipher_in_bytes,
                              job->iv,
                              job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                              job->auth_tag_output, job->auth_tag_output_len_in_bytes);
      else
              AES_GCM_ENC_256(job->aes_dec_key_expanded,
                              &ctx,
                              job->dst,
                              job->src + job->cipher_start_src_offset_in_bytes,
                              job->msg_len_to_cipher_in_bytes,
                              job->iv,
                              job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                              job->auth_tag_output, job->auth_tag_output_len_in_bytes);

      job->status = STS_COMPLETED;
      return job;
}
#endif /* !NO_GCM */

#ifndef NO_ADDON
__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_CIPHER_ADDON(MB_MGR *state,
                        JOB_AES_HMAC *job)
{
        return job->cipher_func(state, job);
}

__forceinline
JOB_AES_HMAC *
FLUSH_JOB_CIPHER_ADDON(MB_MGR *state,
                       JOB_AES_HMAC *job)
{
        return job->cipher_func(state, job);
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_HASH_ADDON(MB_MGR *state,
                      JOB_AES_HMAC *job)
{
        return job->hash_func(state, job);
}

__forceinline
JOB_AES_HMAC *
FLUSH_JOB_HASH_ADDON(MB_MGR *state,
                     JOB_AES_HMAC *job)
{
        return job->hash_func(state, job);
}
#endif /* NO_ADDON */

////////////////////////////////////////////////////////////////////////

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
        UINT64 offset = 0;
        UINT64 partial_bytes = 0;

        if (job == NULL)
                return job;

        assert((job->cipher_direction == DECRYPT) || (job->status & STS_COMPLETED_AES));

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

        assert(partial_bytes <= AES_BLOCK_SIZE);
        AES_CFB_128_ONE(job->dst + offset,
                        job->src + job->cipher_start_src_offset_in_bytes + offset,
                        iv, job->aes_enc_key_expanded, partial_bytes);

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
JOB_AES_HMAC *
DOCSIS_FIRST_BLOCK(JOB_AES_HMAC *job)
{
        assert(!(job->status & STS_COMPLETED_AES));
        assert(job->msg_len_to_cipher_in_bytes <= AES_BLOCK_SIZE);
        AES_CFB_128_ONE(job->dst,
                        job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv, job->aes_enc_key_expanded,
                        job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return job;
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_ENC(MB_MGR *state, JOB_AES_HMAC *job)
{
        if (CBC == job->cipher_mode) {
                if (16 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES128_ENC(&state->aes128_ooo, job);
                } else if (24 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES192_ENC(&state->aes192_ooo, job);
                } else { // assume 32
                        return SUBMIT_JOB_AES256_ENC(&state->aes256_ooo, job);
                }
        } else if (CNTR == job->cipher_mode) {
                if (16 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES128_CNTR(job);
                } else if (24 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES192_CNTR(job);
                } else { // assume 32
                        return SUBMIT_JOB_AES256_CNTR(job);
                }
        } else if (DOCSIS_SEC_BPI == job->cipher_mode) {
                if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {
                        JOB_AES_HMAC *tmp;

                        tmp = SUBMIT_JOB_AES128_ENC(&state->docsis_sec_ooo, job);
                        return DOCSIS_LAST_BLOCK(tmp);
                } else
                        return DOCSIS_FIRST_BLOCK(job);
#ifndef NO_GCM
        } else if (GCM == job->cipher_mode) {
                return SUBMIT_JOB_AES_GCM_ENC(job);
#endif /* NO_GCM */
#ifndef NO_ADDON
        } else if (CIPHER_ADDON == job->cipher_mode) {
                return SUBMIT_JOB_CIPHER_ADDON(state, job);
#endif /* !NO_ADDON */
        } else { // assume NUL_CIPHER
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
                } else  {// assume 32
                        return FLUSH_JOB_AES256_ENC(&state->aes256_ooo);
                }
        } else if (DOCSIS_SEC_BPI == job->cipher_mode) {
                JOB_AES_HMAC *tmp;

                tmp = FLUSH_JOB_AES128_ENC(&state->docsis_sec_ooo);
                return DOCSIS_LAST_BLOCK(tmp);
#ifndef NO_ADDON
        } else if (CIPHER_ADDON == job->cipher_mode) {
                return FLUSH_JOB_CIPHER_ADDON(state, job);
#endif /* !NO_ADDON */
        } else { // assume CNTR or NULL_CIPHER
                return NULL;
        }
}

__forceinline
JOB_AES_HMAC *
SUBMIT_JOB_AES_DEC(MB_MGR *state,
                   JOB_AES_HMAC *job)
{
        (void) state;
        if (CBC == job->cipher_mode) {
                if (16 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES128_DEC(job);
                } else if (24 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES192_DEC(job);
                } else { // assume 32
                        return SUBMIT_JOB_AES256_DEC(job);
                }
        } else if (CNTR == job->cipher_mode) {
                if (16 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES128_CNTR(job);
                } else if (24 == job->aes_key_len_in_bytes) {
                        return SUBMIT_JOB_AES192_CNTR(job);
                } else { // assume 32
                        return SUBMIT_JOB_AES256_CNTR(job);
                }
        } else if (DOCSIS_SEC_BPI == job->cipher_mode) {
                if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {
                        DOCSIS_LAST_BLOCK(job);
                        return SUBMIT_JOB_AES128_DEC(job);
                } else {
                        return DOCSIS_FIRST_BLOCK(job);
                }
#ifndef NO_GCM
        } else if (GCM == job->cipher_mode) {
                return SUBMIT_JOB_AES_GCM_DEC(job);
#endif /* NO_GCM */
#ifndef NO_ADDON
        } else if (CIPHER_ADDON == job->cipher_mode) {
                return SUBMIT_JOB_CIPHER_ADDON(state, job);
#endif /* !NO_ADDON */
        } else {
                job->status |= STS_COMPLETED_AES;
                return job;
        }
}

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
                if (HASH_USE_SHAEXT == SHA_EXT_PRESENT)
                        return SUBMIT_JOB_HMAC_NI(&state->hmac_sha_1_ooo, job);
#endif
                return SUBMIT_JOB_HMAC(&state->hmac_sha_1_ooo, job);
        case SHA_224:
#ifdef HASH_USE_SHAEXT
                if (HASH_USE_SHAEXT == SHA_EXT_PRESENT)
                        return SUBMIT_JOB_HMAC_SHA_224_NI(&state->hmac_sha_224_ooo, job);
#endif
                return SUBMIT_JOB_HMAC_SHA_224(&state->hmac_sha_224_ooo, job);
        case SHA_256:
#ifdef HASH_USE_SHAEXT
                if (HASH_USE_SHAEXT == SHA_EXT_PRESENT)
                        return SUBMIT_JOB_HMAC_SHA_256_NI(&state->hmac_sha_256_ooo, job);
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
#ifndef NO_ADDON
        case HASH_ADDON:
                return SUBMIT_JOB_HASH_ADDON(state, job);
#endif /* !NO_ADDON */
        default: // assume NULL_HASH
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
                if (HASH_USE_SHAEXT == SHA_EXT_PRESENT)
                        return FLUSH_JOB_HMAC_NI(&state->hmac_sha_1_ooo);
#endif
                return FLUSH_JOB_HMAC(&state->hmac_sha_1_ooo);
        case SHA_224:
#ifdef HASH_USE_SHAEXT
                if (HASH_USE_SHAEXT == SHA_EXT_PRESENT)
                        return FLUSH_JOB_HMAC_SHA_224_NI(&state->hmac_sha_224_ooo);
#endif
                return FLUSH_JOB_HMAC_SHA_224(&state->hmac_sha_224_ooo);
        case SHA_256:
#ifdef HASH_USE_SHAEXT
                if (HASH_USE_SHAEXT == SHA_EXT_PRESENT)
                        return FLUSH_JOB_HMAC_SHA_256_NI(&state->hmac_sha_256_ooo);
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
#ifndef NO_ADDON
        case HASH_ADDON:
                return FLUSH_JOB_HASH_ADDON(state, job);
#endif /* !NO_ADDON */
        default: // assume NULL_HASH
                job->status |= STS_COMPLETED_HMAC;
                return job;
        }
}


////////////////////////////////////////////////////////////////////////

#ifdef DEBUG
#ifdef _WIN32
#define INVALID_PRN(_fmt, ...) fprintf(stderr, "%s():%d: " _fmt, __FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define INVALID_PRN(_fmt, ...) fprintf(stderr, "%s():%d: " _fmt, __func__, __LINE__, __VA_ARGS__)
#endif
#else
#define INVALID_PRN(_fmt, ...)
#endif

__forceinline int
is_job_invalid(const JOB_AES_HMAC *job)
{
        const UINT64 auth_tag_len_max[] = {
                0,  /* INVALID selection */
                12, /* SHA1 */
                14, /* SHA_224 */
                16, /* SHA_256 */
                24, /* SHA_384 */
                32, /* SHA_512 */
                12, /* AES_XCBC */
                12, /* MD5 */
                0,  /* NULL_HASH */
                16, /* AES_GMAC */
        };

        switch (job->cipher_mode) {
        case CBC:
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
        case CNTR:
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
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
        case NULL_CIPHER:
                /* NULL_CIPHER only allowed in HASH_CIPHER */
                if (job->chain_order != HASH_CIPHER)
                        return 1;
                /* XXX: not copy src to dst */
                break;
        case DOCSIS_SEC_BPI:
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
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                break;
#endif /* !NO_GCM */
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
                if (job->auth_tag_output_len_in_bytes != auth_tag_len_max[job->hash_alg]) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes == 0) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                break;
        case NULL_HASH:
                break;
#ifndef NO_GCM
        case AES_GMAC:
                if (job->auth_tag_output_len_in_bytes != UINT64_C(8) &&
                    job->auth_tag_output_len_in_bytes != UINT64_C(12) &&
                    job->auth_tag_output_len_in_bytes != UINT64_C(16)) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                                return 1;
                }
                if (job->cipher_mode != GCM) {
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
        default:
                INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                return 1;
        }

        switch (job->chain_order) {
        case CIPHER_HASH:
                if (job->cipher_direction != ENCRYPT) {
                        INVALID_PRN("chain_order:%d\n", job->chain_order);
                        return 1;
                }
                break;
        case HASH_CIPHER:
                if (job->cipher_mode != NULL_CIPHER) {
                        if (job->cipher_direction != DECRYPT) {
                                INVALID_PRN("chain_order:%d\n", job->chain_order);
                                return 1;
                        }
                }
                break;
        default:
                INVALID_PRN("chain_order:%d\n", job->chain_order);
                return 1;
        }

        return 0;
}

__forceinline
JOB_AES_HMAC *submit_new_job(MB_MGR *state, JOB_AES_HMAC *job)
{
        if (job->chain_order == CIPHER_HASH) {
                // assume job->cipher_direction == ENCRYPT
                job = SUBMIT_JOB_AES_ENC(state, job);
                if (job) {
                        job = SUBMIT_JOB_HASH(state, job);
                        if (job && (job->chain_order == HASH_CIPHER)) {
                                SUBMIT_JOB_AES_DEC(state, job);
                        }
                } // end if job
        } else { // job->chain_order == HASH_CIPHER
                // assume job->cipher_direction == DECRYPT
                job = SUBMIT_JOB_HASH(state, job);
                if (job && (job->chain_order == HASH_CIPHER)) {
                        SUBMIT_JOB_AES_DEC(state, job);
                }
        }
        return job;
}

__forceinline
void complete_job(MB_MGR *state, JOB_AES_HMAC *job)
{
        JOB_AES_HMAC *tmp = NULL;

        while (job->status < STS_COMPLETED) {
                if (job->chain_order == CIPHER_HASH) {
                        // assume job->cipher_direction == ENCRYPT
                        tmp = FLUSH_JOB_AES_ENC(state, job);
                        if (tmp) {
                                tmp = SUBMIT_JOB_HASH(state, tmp);
                        } else {
                                tmp = FLUSH_JOB_HASH(state, job);
                        }
                        if (tmp && (tmp->chain_order == HASH_CIPHER)) {
                                SUBMIT_JOB_AES_DEC(state, tmp);
                        }
                } else { // job->chain_order == HASH_CIPHER
                        // assume job->cipher_direction == DECRYPT
                        tmp = FLUSH_JOB_HASH(state, job);
                        assert(tmp);
                        if (tmp->chain_order == HASH_CIPHER) {
                                SUBMIT_JOB_AES_DEC(state, tmp);
                        }
                }
        }
}

__forceinline
JOB_AES_HMAC *
submit_job_and_check(MB_MGR *state, const int run_check)
{
        JOB_AES_HMAC *job = NULL;
#ifndef LINUX
        DECLARE_ALIGNED(UINT128 xmm_save[10], 16);
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
                // state was previously empty
                state->earliest_job = state->next_job;
                ADV_JOBS(&state->next_job);
#ifndef LINUX
                RESTORE_XMMS(xmm_save);
#endif
                return NULL;	// if we were empty, nothing to return
        }

        ADV_JOBS(&state->next_job);

        if (state->earliest_job == state->next_job) {
                // Full
                job = JOBS(state, state->earliest_job);
                complete_job(state, job);
                ADV_JOBS(&state->earliest_job);
#ifndef LINUX
                RESTORE_XMMS(xmm_save);
#endif
                return job;
        }

        // not full
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
        DECLARE_ALIGNED(UINT128 xmm_save[10], 16);
#endif

        if (state->earliest_job < 0)
                return NULL; // empty

#ifndef LINUX
        SAVE_XMMS(xmm_save);
#endif
        job = JOBS(state, state->earliest_job);
        complete_job(state, job);

        ADV_JOBS(&state->earliest_job);

        if (state->earliest_job == state->next_job)
                state->earliest_job = -1; // becomes empty

#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
        return job;
}

////////////////////////////////////////////////////////////////////////
/// Lower level "out of order" schedulers
////////////////////////////////////////////////////////////////////////

#if !defined(AVX2) && !defined(AVX512)
// AVX2 does not change the AES code, so the AVX2 version uses AVX code here
// AVX512 uses AVX2 code at the moment

JOB_AES_HMAC *
SUBMIT_JOB_AES128_DEC(JOB_AES_HMAC *job)
{
        assert((job->cipher_mode == DOCSIS_SEC_BPI) ||
               ((job->msg_len_to_cipher_in_bytes & 15) == 0));
        assert(job->iv_len_in_bytes == 16);
        AES_CBC_DEC_128(job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv,
                        job->aes_dec_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= STS_COMPLETED_AES;
        return (job);
}

JOB_AES_HMAC *
SUBMIT_JOB_AES192_DEC(JOB_AES_HMAC *job)
{
        assert((job->msg_len_to_cipher_in_bytes & 15) == 0);
        assert(job->iv_len_in_bytes == 16);
        AES_CBC_DEC_192(job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv,
                        job->aes_dec_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return (job);
}

JOB_AES_HMAC *
SUBMIT_JOB_AES256_DEC(JOB_AES_HMAC *job)
{
        assert((job->msg_len_to_cipher_in_bytes & 15) == 0);
        assert(job->iv_len_in_bytes == 16);
        AES_CBC_DEC_256(job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv,
                        job->aes_dec_key_expanded,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return (job);
}

JOB_AES_HMAC *
SUBMIT_JOB_AES128_CNTR(JOB_AES_HMAC *job)
{
        assert((job->iv_len_in_bytes == 16) || (job->iv_len_in_bytes == 12));
        AES_CNTR_128(job->src + job->cipher_start_src_offset_in_bytes,
                     job->iv,
                     job->aes_enc_key_expanded,
                     job->dst,
                     job->msg_len_to_cipher_in_bytes,
                     job->iv_len_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return (job);
}

JOB_AES_HMAC *
SUBMIT_JOB_AES192_CNTR(JOB_AES_HMAC *job)
{
        assert((job->iv_len_in_bytes == 16) || (job->iv_len_in_bytes == 12));
        AES_CNTR_192(job->src + job->cipher_start_src_offset_in_bytes,
                     job->iv,
                     job->aes_enc_key_expanded,
                     job->dst,
                     job->msg_len_to_cipher_in_bytes,
                     job->iv_len_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return (job);
}

JOB_AES_HMAC *
SUBMIT_JOB_AES256_CNTR(JOB_AES_HMAC *job)
{
        assert((job->iv_len_in_bytes == 16) || (job->iv_len_in_bytes == 12));
        AES_CNTR_256(job->src + job->cipher_start_src_offset_in_bytes,
                     job->iv,
                     job->aes_enc_key_expanded,
                     job->dst,
                     job->msg_len_to_cipher_in_bytes,
                     job->iv_len_in_bytes);
        job->status |= STS_COMPLETED_AES;
        return (job);
}
#endif


////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

UINT32
QUEUE_SIZE(MB_MGR *state)
{
        int a, b;

        if (state->earliest_job < 0)
                return 0;
        a = state->next_job / sizeof(JOB_AES_HMAC);
        b = state->earliest_job / sizeof(JOB_AES_HMAC);
        return ((a-b) & (MAX_JOBS-1));
}
