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

#ifndef _MB_MGR_CODE_H_
#define _MB_MGR_CODE_H_

#include "save_xmms.h"
#include "asm.h"

// This contains the bulk of the mb_mgr code, with #define's to build
// an SSE, AVX, AVX2 or AVX512 version (see mb_mgr_sse.c, mb_mgr_avx.c, etc.)

// get_next_job() returns a job object. This must be filled in and returned
// via submit_job() before get_next_job() is called again.
// submit_job() and flush_job() returns a job object. This job object ceases
// to be usable at the next call to get_next_job()

// Assume JOBS() and ADV_JOBS() from mb_mgr_code.h are available

// LENGTH IN BYTES

////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////

#define AES_BLOCK_SIZE 16

#ifndef LINUX
# define XMM_BUFF(buff)
# define SAVE_XMMS(ARCH, buff)
# define RESTORE_XMMS(ARCH, buff)
#else /* !LINUX */
# define XMM_BUFF(buff)                 DECLARE_ALIGNED(UINT128 buff[10], 16)
# define SAVE_XMMS(ARCH, buff)	        save_xmms_##ARCH(buff)
# define RESTORE_XMMS(ARCH, buff)       restore_xmms_##ARCH(buff)
#endif /* !LINUX */

#if defined(DEBUG)
# define INVALID_PRN(_fmt, ...)	fprintf(stderr, "%s():%d: "_fmt, __func__, __LINE__, __VA_ARGS__)
#else
# define INVALID_PRN(_fmt, ...)
#endif

__forceinline int
is_job_invalid(const JOB_AES_HMAC *job)
{
        const uint64_t auth_tag_len_max[] = {
                0,  /* invalid alg */
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
                break;
        case NULL_CIPHER:
#if 0
                if (job->aes_key_len_in_bytes) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
                if (job->iv_len_in_bytes) {
                        INVALID_PRN("cipher_mode:%d\n", job->cipher_mode);
                        return 1;
                }
#endif
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
                break;
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
                if (job->auth_tag_output_len_in_bytes != auth_tag_len_max[job->hash_alg]) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
                }
                break;
        case NULL_HASH:
#if 0
                if (job->auth_tag_output_len_in_bytes || job->msg_len_to_hash_in_bytes) {
                        INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
        }
#endif
                break;
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
                break;
        default:
                INVALID_PRN("hash_alg:%d\n", job->hash_alg);
                        return 1;
        }

        if ((job->chain_order == CIPHER_HASH) || (job->chain_order == HASH_CIPHER))
        return 0;

        INVALID_PRN("chain_order:%d\n", job->chain_order);
        return 1;
}

#define FUNC_GENERATE_DOCSIS(ARCH)                                      \
__forceinline JOB_AES_HMAC *                                            \
docsis_last_block_##ARCH(JOB_AES_HMAC *job)                             \
{                                                                       \
        const void *iv = NULL;                                          \
        UINT64 offset = 0;                                              \
        UINT64 partial_bytes = 0;                                       \
        if (job == NULL)                                                \
                return job;                                             \
        assert((job->cipher_direction == DECRYPT) ||                    \
               (job->status & STS_COMPLETED_AES));                      \
        partial_bytes = job->msg_len_to_cipher_in_bytes & (AES_BLOCK_SIZE - 1); \
        offset = job->msg_len_to_cipher_in_bytes & (~(AES_BLOCK_SIZE - 1)); \
        if (!partial_bytes)                                             \
                return job;                                             \
        if (job->cipher_direction == ENCRYPT)                           \
                iv = job->dst + offset - AES_BLOCK_SIZE;                \
        else                                                            \
                iv = job->src + job->cipher_start_src_offset_in_bytes + \
                        offset - AES_BLOCK_SIZE;                        \
        assert(partial_bytes <= AES_BLOCK_SIZE);                        \
        aes_cfb_128_one_##ARCH(job->dst + offset,                       \
                               job->src + job->cipher_start_src_offset_in_bytes + offset, \
                               iv, job->aes_enc_key_expanded, partial_bytes); \
        return job;                                                     \
}                                                                       \
__forceinline JOB_AES_HMAC *                                            \
docsis_first_block_##ARCH(JOB_AES_HMAC *job)                            \
{                                                                       \
        assert(!(job->status & STS_COMPLETED_AES));                     \
        assert(job->msg_len_to_cipher_in_bytes <= AES_BLOCK_SIZE);      \
        aes_cfb_128_one_##ARCH(job->dst,                                \
                               job->src + job->cipher_start_src_offset_in_bytes, \
                               job->iv, job->aes_enc_key_expanded,      \
                               job->msg_len_to_cipher_in_bytes);        \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \

#define FUNC_GENERATE_AES_CBC(ARCH)                                     \
__forceinline JOB_AES_HMAC *                                            \
submit_job_aes128_dec_##ARCH(JOB_AES_HMAC *job)                         \
{                                                                       \
        assert((job->cipher_mode == DOCSIS_SEC_BPI) ||                  \
               ((job->msg_len_to_cipher_in_bytes & 15) == 0));          \
        assert(job->iv_len_in_bytes == 16);                             \
        aes_cbc_dec_128_##ARCH(                                         \
                job->src + job->cipher_start_src_offset_in_bytes,       \
                job->iv,                                                \
                job->aes_dec_key_expanded,                              \
                job->dst,                                               \
                job->msg_len_to_cipher_in_bytes & (~15));               \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \
__forceinline JOB_AES_HMAC *                                            \
submit_job_aes192_dec_##ARCH(JOB_AES_HMAC *job)                         \
{                                                                       \
        assert((job->msg_len_to_cipher_in_bytes & 15) == 0);            \
        assert(job->iv_len_in_bytes == 16);                             \
        aes_cbc_dec_192_##ARCH(job->src + job->cipher_start_src_offset_in_bytes, \
                               job->iv,                                 \
                               job->aes_dec_key_expanded,               \
                               job->dst,                                \
                               job->msg_len_to_cipher_in_bytes);        \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \
__forceinline JOB_AES_HMAC *                                            \
submit_job_aes256_dec_##ARCH(JOB_AES_HMAC *job)                         \
{                                                                       \
        assert((job->msg_len_to_cipher_in_bytes & 15) == 0);            \
        assert(job->iv_len_in_bytes == 16);                             \
        aes_cbc_dec_256_##ARCH(job->src + job->cipher_start_src_offset_in_bytes, \
                               job->iv,                                 \
                               job->aes_dec_key_expanded,               \
                               job->dst,                                \
                               job->msg_len_to_cipher_in_bytes);        \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \

#define FUNC_GENERATE_AES_CNTR(ARCH)                                    \
__forceinline JOB_AES_HMAC *                                            \
submit_job_aes128_cntr_##ARCH(JOB_AES_HMAC *job)                        \
{                                                                       \
        assert(job->iv_len_in_bytes == 16 || job->iv_len_in_bytes == 12); \
        aes_cntr_128_##ARCH(job->src + job->cipher_start_src_offset_in_bytes, \
                            job->iv,                                    \
                            job->aes_enc_key_expanded,                  \
                            job->dst,                                   \
                            job->msg_len_to_cipher_in_bytes);           \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \
__forceinline JOB_AES_HMAC *                                            \
submit_job_aes192_cntr_##ARCH(JOB_AES_HMAC *job)                        \
{                                                                       \
        assert(job->iv_len_in_bytes == 16 || job->iv_len_in_bytes == 12); \
        aes_cntr_192_##ARCH(job->src + job->cipher_start_src_offset_in_bytes, \
                            job->iv,                                    \
                            job->aes_enc_key_expanded,                  \
                            job->dst,                                   \
                            job->msg_len_to_cipher_in_bytes);           \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \
__forceinline JOB_AES_HMAC *                                            \
submit_job_aes256_cntr_##ARCH(JOB_AES_HMAC *job)                        \
{                                                                       \
        assert(job->iv_len_in_bytes == 16 || job->iv_len_in_bytes == 12); \
        aes_cntr_256_##ARCH(job->src + job->cipher_start_src_offset_in_bytes, \
                            job->iv,                                    \
                            job->aes_enc_key_expanded,                  \
                            job->dst,                                   \
                            job->msg_len_to_cipher_in_bytes);           \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \

#define FUNC_GENERATE_JOB_CIPHER(ARCH)                                  \
__forceinline JOB_AES_HMAC *                                            \
submit_job_aes_enc_##ARCH(MB_MGR *state, JOB_AES_HMAC *job)             \
{                                                                       \
        switch (job->cipher_mode) {                                     \
        case CBC:                                                       \
                if (16 == job->aes_key_len_in_bytes) {                  \
                        return submit_job_aes128_enc_##ARCH(&state->aes128_ooo, job); \
                } else if (24 == job->aes_key_len_in_bytes) {           \
                        return submit_job_aes192_enc_##ARCH(&state->aes192_ooo, job); \
                }                                                       \
                return submit_job_aes256_enc_##ARCH(&state->aes256_ooo, job); \
        case CNTR:                                                      \
                if (16 == job->aes_key_len_in_bytes) {                  \
                        return submit_job_aes128_cntr_##ARCH(job);      \
                } else if (24 == job->aes_key_len_in_bytes) {           \
                        return submit_job_aes192_cntr_##ARCH(job);      \
                }                                                       \
                return submit_job_aes256_cntr_##ARCH(job);              \
        case DOCSIS_SEC_BPI:                                            \
                if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) { \
                        JOB_AES_HMAC *tmp;                              \
                        tmp = submit_job_aes128_enc_##ARCH(&state->docsis_sec_ooo, job); \
                        return docsis_last_block_##ARCH(tmp);           \
                }                                                       \
                return docsis_first_block_##ARCH(job);                  \
        case GCM:                                                       \
                if (16 == job->aes_key_len_in_bytes) {                  \
                        return submit_job_aes128_gcm_enc_##ARCH(job);   \
                } else if (24 == job->aes_key_len_in_bytes) {           \
                        return submit_job_aes192_gcm_enc_##ARCH(job);   \
        }                                                               \
                return submit_job_aes256_gcm_enc_##ARCH(job);           \
        default:                                                        \
        job->status |= STS_COMPLETED_AES;                               \
                break;                                                  \
        }                                                               \
        return job;                                                     \
}                                                                       \
__forceinline JOB_AES_HMAC *                                            \
submit_job_aes_dec_##ARCH(MB_MGR *state, JOB_AES_HMAC *job)             \
{                                                                       \
        (void) state; /* unused */                                      \
        switch (job->cipher_mode) {                                     \
        case CBC:                                                       \
                if (16 == job->aes_key_len_in_bytes) {                  \
                        return submit_job_aes128_dec_##ARCH(job);       \
                } else if (24 == job->aes_key_len_in_bytes) {           \
                        return submit_job_aes192_dec_##ARCH(job);       \
                }                                                       \
                return submit_job_aes256_dec_##ARCH(job);               \
        case CNTR:                                                      \
                if (16 == job->aes_key_len_in_bytes) {                  \
                        return submit_job_aes128_cntr_##ARCH(job);      \
                } else if (24 == job->aes_key_len_in_bytes) {           \
                        return submit_job_aes192_cntr_##ARCH(job);      \
                }                                                       \
                return submit_job_aes256_cntr_##ARCH(job);              \
        case DOCSIS_SEC_BPI:                                            \
                if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) { \
                        docsis_last_block_##ARCH(job);                  \
                        return submit_job_aes128_dec_##ARCH(job);       \
                }                                                       \
                return docsis_first_block_##ARCH(job);                  \
        case GCM:                                                       \
                if (16 == job->aes_key_len_in_bytes) {                  \
                        return submit_job_aes128_gcm_dec_##ARCH(job);   \
                } else if (24 == job->aes_key_len_in_bytes) {           \
                        return submit_job_aes192_gcm_dec_##ARCH(job);   \
        }                                                               \
                return submit_job_aes256_gcm_dec_##ARCH(job);           \
        default:                                                        \
        job->status |= STS_COMPLETED_AES;                               \
                break;                                                  \
        }                                                               \
        return job;                                                     \
}                                                                       \
__forceinline JOB_AES_HMAC *                                            \
flush_job_aes_enc_##ARCH(MB_MGR *state, JOB_AES_HMAC *job)              \
{                                                                       \
        if (CBC == job->cipher_mode) {                                  \
                if (16 == job->aes_key_len_in_bytes) {                  \
                        return flush_job_aes128_enc_##ARCH(&state->aes128_ooo); \
                } else if (24 == job->aes_key_len_in_bytes) {           \
                        return flush_job_aes192_enc_##ARCH(&state->aes192_ooo); \
                }                                                       \
                return flush_job_aes256_enc_##ARCH(&state->aes256_ooo); \
        } else if (DOCSIS_SEC_BPI == job->cipher_mode) {                \
                JOB_AES_HMAC *tmp;                                      \
                tmp = flush_job_aes128_enc_##ARCH(&state->docsis_sec_ooo); \
                return docsis_last_block_##ARCH(tmp);                   \
        }                                                               \
        return NULL;                                                    \
}                                                                       \

#define FUNC_GENERATE_JOB_HASH(ARCH)                                    \
__forceinline JOB_AES_HMAC *                                            \
submit_job_hash_##ARCH(MB_MGR *state, JOB_AES_HMAC *job)                \
{                                                                       \
        switch (job->hash_alg) {                                        \
        case SHA1:                                                      \
                return submit_job_hmac_NI_##ARCH(&state->hmac_sha_1_ooo, job); \
        case SHA_224:                                                   \
                return submit_job_hmac_sha_224_NI_##ARCH(&state->hmac_sha_224_ooo, job); \
        case SHA_256:                                                   \
                return submit_job_hmac_sha_256_NI_##ARCH(&state->hmac_sha_256_ooo, job); \
        case SHA_384:                                                   \
                return submit_job_hmac_sha_384_##ARCH(&state->hmac_sha_384_ooo, job); \
        case SHA_512:                                                   \
                return submit_job_hmac_sha_512_##ARCH(&state->hmac_sha_512_ooo, job); \
        case AES_XCBC:                                                  \
                return submit_job_aes_xcbc_##ARCH(&state->aes_xcbc_ooo, job); \
        case MD5:                                                       \
                return submit_job_hmac_md5_##ARCH(&state->hmac_md5_ooo, job); \
        case AES_GMAC:                                                  \
                return submit_job_aes_dec_##ARCH(state, job);           \
        default:                                                        \
                job->status |= STS_COMPLETED_HMAC;                      \
                break;                                                  \
        }                                                               \
        return job;                                                     \
}                                                                       \
__forceinline JOB_AES_HMAC *                                            \
flush_job_hash_##ARCH(MB_MGR *state, JOB_AES_HMAC *job)                 \
{                                                                       \
        switch (job->hash_alg) {                                        \
        case SHA1:                                                      \
                return flush_job_hmac_NI_##ARCH(&state->hmac_sha_1_ooo); \
        case SHA_224:                                                   \
                return flush_job_hmac_sha_224_NI_##ARCH(&state->hmac_sha_224_ooo); \
        case SHA_256:                                                   \
                return flush_job_hmac_sha_256_NI_##ARCH(&state->hmac_sha_256_ooo); \
        case SHA_384:                                                   \
                return flush_job_hmac_sha_384_##ARCH(&state->hmac_sha_384_ooo); \
        case SHA_512:                                                   \
                return flush_job_hmac_sha_512_##ARCH(&state->hmac_sha_512_ooo); \
        case AES_XCBC:                                                  \
                return flush_job_aes_xcbc_##ARCH(&state->aes_xcbc_ooo); \
        case MD5:                                                       \
                return flush_job_hmac_md5_##ARCH(&state->hmac_md5_ooo); \
        default:                                                        \
                job->status |= STS_COMPLETED_HMAC;                      \
                break;                                                  \
        }                                                               \
        return job;                                                     \
}                                                                       \

#define FUNC_GENERATE_COMPLETE_JOB(ARCH)                                \
__forceinline void                                                      \
complete_job_##ARCH(MB_MGR *state, JOB_AES_HMAC *job)                   \
{                                                                       \
        JOB_AES_HMAC *tmp = NULL;                                       \
        while (job->status < STS_COMPLETED) {                           \
                if (job->chain_order == CIPHER_HASH) {                  \
                        tmp = flush_job_aes_enc_##ARCH(state, job);     \
                        if (tmp) {                                      \
                                tmp = submit_job_hash_##ARCH(state, tmp); \
                        } else {                                        \
                                tmp = flush_job_hash_##ARCH(state, job); \
                        }                                               \
                        if (tmp && (tmp->chain_order == HASH_CIPHER)) { \
                                submit_job_aes_dec_##ARCH(state, tmp);  \
                        }                                               \
                } else {                                                \
                        tmp = flush_job_hash_##ARCH(state, job);        \
                        assert(tmp);                                    \
                        if (tmp->chain_order == HASH_CIPHER) {          \
                                submit_job_aes_dec_##ARCH(state, tmp);  \
                        }                                               \
                }                                                       \
        }                                                               \
}                                                                       \

#define FUNC_GENERATE_SUBMIT_NEW_JOB(ARCH)                              \
__forceinline JOB_AES_HMAC *                                            \
submit_new_job_##ARCH(MB_MGR *state, JOB_AES_HMAC *job)                 \
{                                                                       \
        do {                                                            \
                if (job->chain_order == CIPHER_HASH) {                  \
                        if (job->status & STS_COMPLETED_AES) {          \
                                job = submit_job_hash_##ARCH(state, job); \
                        } else {                                        \
                                job = submit_job_aes_enc_##ARCH(state, job); \
                        }                                               \
                } else {                                                \
                        if (job->status & STS_COMPLETED_HMAC) {         \
                                job = submit_job_aes_dec_##ARCH(state, job); \
                        } else {                                        \
                                job = submit_job_hash_##ARCH(state, job); \
                }                                                       \
        }                                                               \
        } while (job && job->status < STS_COMPLETED);                   \
        return job;                                                     \
}                                                                       \

#define _FUNC_GENERATE_SUBMIT_JOB(ARCH)                                 \
JOB_AES_HMAC *                                                          \
submit_job_##ARCH(MB_MGR *state)                                        \
{                                                                       \
        JOB_AES_HMAC *job;                                              \
        XMM_BUFF(xmm_save);                                             \
        SAVE_XMMS(ARCH, xmm_save);                                      \
        job = JOBS(state, state->next_job);                             \
        if (is_job_invalid(job)) {                                      \
                job->status = STS_INVALID_ARGS;                         \
        } else {                                                        \
                job->status = STS_BEING_PROCESSED;                      \
                job = submit_new_job_##ARCH(state, job);                \
        }                                                               \
        if (state->earliest_job < 0) {                                  \
                state->earliest_job = state->next_job;                  \
                ADV_JOBS(&state->next_job);                             \
                RESTORE_XMMS(ARCH, xmm_save);                           \
                return NULL;                                            \
        }                                                               \
        ADV_JOBS(&state->next_job);                                     \
        if (state->earliest_job == state->next_job) {                   \
                job = JOBS(state, state->earliest_job);                 \
                complete_job_##ARCH(state, job);                        \
                ADV_JOBS(&state->earliest_job);                         \
                RESTORE_XMMS(ARCH, xmm_save);                           \
                return job;                                             \
        }                                                               \
        RESTORE_XMMS(ARCH, xmm_save);                                   \
        job = JOBS(state, state->earliest_job);                         \
        if (job->status < STS_COMPLETED)                                \
                return NULL;                                            \
        ADV_JOBS(&state->earliest_job);                                 \
        return job;                                                     \
}                                                                       \

#define FUNC_GENERATE_SUBMIT_JOB(ARCH) _FUNC_GENERATE_SUBMIT_JOB(ARCH)

#define _FUNC_GENERATE_FLUSH_JOB(ARCH)                                  \
JOB_AES_HMAC *                                                          \
flush_job_##ARCH(MB_MGR *state)                                         \
{                                                                       \
        JOB_AES_HMAC *job;                                              \
        XMM_BUFF(xmm_save);                                             \
        if (state->earliest_job < 0)                                    \
                return NULL;                                            \
        SAVE_XMMS(ARCH, xmm_save);                                      \
        job = JOBS(state, state->earliest_job);                         \
        complete_job_##ARCH(state, job);                                \
        ADV_JOBS(&state->earliest_job);                                 \
        if (state->earliest_job == state->next_job)                     \
                state->earliest_job = -1;                               \
        RESTORE_XMMS(ARCH, xmm_save);                                   \
        return job;                                                     \
}                                                                       \

#define FUNC_GENERATE_FLUSH_JOB(ARCH) _FUNC_GENERATE_FLUSH_JOB(ARCH)


#define FUNC_GENERATE_QUEUE_SIZE(ARCH)                                  \
UINT32                                                                  \
queue_size_##ARCH(MB_MGR *state)                                        \
{                                                                       \
        int a, b;                                                       \
        if (state->earliest_job < 0)                                    \
                return 0;                                               \
        a = state->next_job / sizeof(JOB_AES_HMAC);                     \
        b = state->earliest_job / sizeof(JOB_AES_HMAC);                 \
        return ((a-b) & (MAX_JOBS-1));                                  \
}                                                                       \

#define FUNC_GENERATE(ARCH)                     \
        FUNC_GENERATE_DOCSIS(ARCH)              \
        FUNC_GENERATE_AES_CBC(ARCH)             \
        FUNC_GENERATE_AES_CNTR(ARCH)            \
        FUNC_GENERATE_JOB_CIPHER(ARCH)          \
        FUNC_GENERATE_JOB_HASH(ARCH)            \
        FUNC_GENERATE_SUBMIT_NEW_JOB(ARCH)      \
        FUNC_GENERATE_COMPLETE_JOB(ARCH)        \
        FUNC_GENERATE_SUBMIT_JOB(ARCH)          \
        FUNC_GENERATE_FLUSH_JOB(ARCH)           \
        FUNC_GENERATE_QUEUE_SIZE(ARCH)          \

#endif /* !_MB_MGR_CODE_H_ */
