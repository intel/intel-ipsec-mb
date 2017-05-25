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

#if 1
# include <string.h>
# define MEMCMP(_p0, _p1, _s)	memcmp((_p0), (_p1), (_s))
# define MEMCPY(_d, _s, _z)	memcpy((_d), (_s), (_z))
#endif

#if defined(DEBUG)
# include <stdio.h>
# define TRACE(fmt, ...) fprintf(stdout, "%s:%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
# define ERROR(fmt, ...) fprintf(stdout, "%s:%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
# define TRACE(fmt, ...)
# define ERROR(fmt, ...)
#endif

#include "mb_mgr.h"
#include "asm.h"
#include "save_xmms.h"

#define SWAP(_a, _b)	do { typeof(_a) _c = (_a); (_a) = (_b); (_b) = (_c); } while (0)


/*
 * asm function prototypes
 */

/* SSE */
extern void aes_cfb_128_one_sse(void *out, const void *in, const void *iv,
                                const void *keys, UINT64 len);

extern struct JOB_AES_HMAC *
submit_job_aes128_enc_sse(struct MB_MGR_AES_OOO *state,
                          struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *
submit_job_aes192_enc_sse(struct MB_MGR_AES_OOO *state,
                          struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *
submit_job_aes256_enc_sse(struct MB_MGR_AES_OOO *state,
                          struct JOB_AES_HMAC *job);

extern struct JOB_AES_HMAC *
flush_job_aes128_enc_sse(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *
flush_job_aes192_enc_sse(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *
flush_job_aes256_enc_sse(struct MB_MGR_AES_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sse(MB_MGR_HMAC_SHA_1_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sse(MB_MGR_HMAC_SHA_1_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_ni_sse(MB_MGR_HMAC_SHA_1_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_ni_sse(MB_MGR_HMAC_SHA_1_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_224_sse(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_224_sse(MB_MGR_HMAC_SHA_256_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_224_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_224_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_256_sse(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_256_sse(MB_MGR_HMAC_SHA_256_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_256_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_256_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_384_sse(MB_MGR_HMAC_SHA_512_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_384_sse(MB_MGR_HMAC_SHA_512_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_512_sse(MB_MGR_HMAC_SHA_512_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_512_sse(MB_MGR_HMAC_SHA_512_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_md5_sse(MB_MGR_HMAC_MD5_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_md5_sse(MB_MGR_HMAC_MD5_OOO *state);

extern JOB_AES_HMAC *
submit_job_aes_xcbc_sse(MB_MGR_AES_XCBC_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_aes_xcbc_sse(MB_MGR_AES_XCBC_OOO *state);


/* AVX */
extern void aes_cfb_128_one_avx(void *out, const void *in, const void *iv,
                                const void *keys, UINT64 len);

extern struct JOB_AES_HMAC *
submit_job_aes128_enc_avx(struct MB_MGR_AES_OOO *state,
                          struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *
submit_job_aes192_enc_avx(struct MB_MGR_AES_OOO *state,
                          struct JOB_AES_HMAC *job);
extern struct JOB_AES_HMAC *
submit_job_aes256_enc_avx(struct MB_MGR_AES_OOO *state,
                          struct JOB_AES_HMAC *job);

extern struct JOB_AES_HMAC *
flush_job_aes128_enc_avx(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *
flush_job_aes192_enc_avx(struct MB_MGR_AES_OOO *state);
extern struct JOB_AES_HMAC *
flush_job_aes256_enc_avx(struct MB_MGR_AES_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_avx(MB_MGR_HMAC_SHA_1_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_avx(MB_MGR_HMAC_SHA_1_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_224_avx(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_224_avx(MB_MGR_HMAC_SHA_256_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_256_avx(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_256_avx(MB_MGR_HMAC_SHA_256_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_384_avx(MB_MGR_HMAC_SHA_512_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_384_avx(MB_MGR_HMAC_SHA_512_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_512_avx(MB_MGR_HMAC_SHA_512_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_512_avx(MB_MGR_HMAC_SHA_512_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_md5_avx(MB_MGR_HMAC_MD5_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_md5_avx(MB_MGR_HMAC_MD5_OOO *state);

extern JOB_AES_HMAC *
submit_job_aes_xcbc_avx(MB_MGR_AES_XCBC_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_aes_xcbc_avx(MB_MGR_AES_XCBC_OOO *state);

/* AVX2 */
extern JOB_AES_HMAC *
submit_job_hmac_avx2(MB_MGR_HMAC_SHA_1_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_avx2(MB_MGR_HMAC_SHA_1_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_224_avx2(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_224_avx2(MB_MGR_HMAC_SHA_256_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_256_avx2(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_256_avx2(MB_MGR_HMAC_SHA_256_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_384_avx2(MB_MGR_HMAC_SHA_512_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_384_avx2(MB_MGR_HMAC_SHA_512_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_512_avx2(MB_MGR_HMAC_SHA_512_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_512_avx2(MB_MGR_HMAC_SHA_512_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_md5_avx2(MB_MGR_HMAC_MD5_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_md5_avx2(MB_MGR_HMAC_MD5_OOO *state);

/* AVX512 */
extern JOB_AES_HMAC *
submit_job_hmac_avx512(MB_MGR_HMAC_SHA_1_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_avx512(MB_MGR_HMAC_SHA_1_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_224_avx512(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_224_avx512(MB_MGR_HMAC_SHA_256_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_256_avx512(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_256_avx512(MB_MGR_HMAC_SHA_256_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_384_avx512(MB_MGR_HMAC_SHA_512_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_384_avx512(MB_MGR_HMAC_SHA_512_OOO *state);

extern JOB_AES_HMAC *
submit_job_hmac_sha_512_avx512(MB_MGR_HMAC_SHA_512_OOO *state, JOB_AES_HMAC *job);
extern JOB_AES_HMAC *
flush_job_hmac_sha_512_avx512(MB_MGR_HMAC_SHA_512_OOO *state);

/*
 * verify decode tag vs encode tag
 */
__forceinline enum JOB_STS
verify_tag(struct JOB_AES_HMAC *job)
{
	if (job->enable_tag_cmp) {
                /* restore TAG */
                if (job->enable_esn) {
                        BE32 *esn_high = job->encode_tag_p;
                        *esn_high = job->esn_high;
                }

                if (MEMCMP(job->decode_tag, job->encode_tag_p,
                           job->auth_tag_output_len_in_bytes)) {
                        job->current_stage = 0;	/* for break job */
                        return STS_AUTH_FAILED;
                }
        }
        return STS_COMPLETED_HMAC;
}

/******************************************************************************
 * AES128 CBC mode
 ******************************************************************************/

#define FUNC_GENERATE_AES128_CBC(ARCH)                                  \
static struct JOB_AES_HMAC *                                            \
submit_aes128_cbc_enc_##ARCH(union MB_MGR_JOB_STATE *state,             \
                              struct JOB_AES_HMAC *job)                 \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        return submit_job_aes128_enc_##ARCH(&state->aes128_ooo, job);   \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_aes128_cbc_enc_##ARCH (union MB_MGR_JOB_STATE *state)             \
{                                                                       \
        TRACE("\n");                                                    \
        return flush_job_aes128_enc_##ARCH(&state->aes128_ooo);         \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_aes128_cbc_dec_##ARCH(union MB_MGR_JOB_STATE *state __unused,    \
                             struct JOB_AES_HMAC *job)                  \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        /* msg_len_to_cipher_in_bytes mask for DOCSIS */                \
        aes_cbc_dec_128_##ARCH((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                               job->iv,                                 \
                               job->aes_dec_key_expanded,               \
                               job->dst,                                \
                               job->msg_len_to_cipher_in_bytes & (~(AES_BLOCK_SIZE - 1))); \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_AES128_CBC(sse)
FUNC_GENERATE_AES128_CBC(avx)

/******************************************************************************
 * AES192 CBC mode
 ******************************************************************************/
#define FUNC_GENERATE_AES192_CBC(ARCH)                                  \
static struct JOB_AES_HMAC *                                            \
submit_aes192_cbc_enc_##ARCH(union MB_MGR_JOB_STATE *state,             \
                             struct JOB_AES_HMAC *job)                  \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        return submit_job_aes192_enc_##ARCH(&state->aes192_ooo, job);   \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_aes192_cbc_enc_##ARCH(union MB_MGR_JOB_STATE *state)              \
{                                                                       \
        TRACE("\n");                                                    \
        return flush_job_aes192_enc_##ARCH(&state->aes192_ooo);         \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_aes192_cbc_dec_##ARCH(union MB_MGR_JOB_STATE *state __unused,    \
                             struct JOB_AES_HMAC *job)                  \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        aes_cbc_dec_192_##ARCH((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                               job->iv,                                 \
                               job->aes_dec_key_expanded,               \
                               job->dst,                                \
                               job->msg_len_to_cipher_in_bytes);        \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_AES192_CBC(sse)
FUNC_GENERATE_AES192_CBC(avx)

/******************************************************************************
 * AES256 CBC mode
 ******************************************************************************/
#define FUNC_GENERATE_AES256_CBC(ARCH)                                  \
static struct JOB_AES_HMAC *                                            \
submit_aes256_cbc_enc_##ARCH(union MB_MGR_JOB_STATE *state,             \
                             struct JOB_AES_HMAC *job)                  \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        return submit_job_aes256_enc_##ARCH(&state->aes256_ooo, job);   \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_aes256_cbc_enc_##ARCH(union MB_MGR_JOB_STATE *state)              \
{                                                                       \
        TRACE("\n");                                                    \
        return flush_job_aes256_enc_##ARCH(&state->aes256_ooo);         \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_aes256_cbc_dec_##ARCH(union MB_MGR_JOB_STATE *state __unused,    \
                             struct JOB_AES_HMAC *job)                  \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        aes_cbc_dec_256_##ARCH((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                               job->iv,                                 \
                               job->aes_dec_key_expanded,               \
                               job->dst,                                \
                               job->msg_len_to_cipher_in_bytes);        \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_AES256_CBC(sse)
FUNC_GENERATE_AES256_CBC(avx)

/******************************************************************************
 * AES128 CTR mode
 ******************************************************************************/
#define FUNC_GENERATE_AES128_CTR(ARCH)                                  \
static struct JOB_AES_HMAC *                                            \
submit_aes128_ctr_##ARCH(union MB_MGR_JOB_STATE *state __unused,        \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        aes_cntr_128_##ARCH((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                            job->iv,                                    \
                            job->aes_enc_key_expanded,                  \
                            job->dst,                                   \
                            job->msg_len_to_cipher_in_bytes);           \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_AES128_CTR(sse)
FUNC_GENERATE_AES128_CTR(avx)

/******************************************************************************
 * AES192 CTR mode
 ******************************************************************************/
#define FUNC_GENERATE_AES192_CTR(ARCH)                                  \
static struct JOB_AES_HMAC *                                            \
submit_aes192_ctr_##ARCH(union MB_MGR_JOB_STATE *state __unused,        \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        aes_cntr_192_##ARCH((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                            job->iv,                                    \
                            job->aes_enc_key_expanded,                  \
                            job->dst,                                   \
                            job->msg_len_to_cipher_in_bytes);           \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_AES192_CTR(sse)
FUNC_GENERATE_AES192_CTR(avx)

/******************************************************************************
 * AES256 CTR mode
 ******************************************************************************/
#define FUNC_GENERATE_AES256_CTR(ARCH)                                  \
static struct JOB_AES_HMAC *                                            \
submit_aes256_ctr_##ARCH(union MB_MGR_JOB_STATE *state __unused,        \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        aes_cntr_256_##ARCH((const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                            job->iv,                                    \
                            job->aes_enc_key_expanded,                  \
                            job->dst,                                   \
                            job->msg_len_to_cipher_in_bytes);           \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_AES256_CTR(sse)
FUNC_GENERATE_AES256_CTR(avx)

/******************************************************************************
 * AES128 GCM mode
 ******************************************************************************/
#define FUNC_GENERATE_AES128_GCM(ARCH)                                  \
static struct JOB_AES_HMAC *                                            \
submit_aes128_gcm_enc_##ARCH(union MB_MGR_JOB_STATE *state __unused,    \
                             struct JOB_AES_HMAC *job)                  \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        aes_gcm_enc_128_##ARCH(job->aes_enc_key_expanded,               \
                               &job->gcm_context,                       \
                               job->dst,                                \
                               (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                               job->msg_len_to_cipher_in_bytes,         \
                               job->iv,                                 \
                               job->aad, job->aad_len_in_bytes,         \
                               job->auth_tag_output, job->auth_tag_output_len_in_bytes); \
        job->status = STS_COMPLETED;                                    \
        TRACE("completed job:%u\n", job->seq_num);                      \
        return job;                                                     \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_aes128_gcm_dec_##ARCH(union MB_MGR_JOB_STATE *state __unused,    \
                          struct JOB_AES_HMAC *job)                     \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        void *tag_output;                                               \
        if (job->enable_tag_cmp) {                                      \
                job->encode_tag_p = job->auth_tag_output;               \
                tag_output = job->decode_tag;                           \
        } else {                                                        \
                tag_output = job->auth_tag_output;                      \
        }                                                               \
        aes_gcm_dec_128_##ARCH(job->aes_dec_key_expanded,               \
                               &job->gcm_context,                       \
                               job->dst,                                \
                               (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                               job->msg_len_to_cipher_in_bytes,         \
                               job->iv,                                 \
                               job->aad, job->aad_len_in_bytes,         \
                               tag_output, job->auth_tag_output_len_in_bytes); \
        if (job->enable_tag_cmp && MEMCMP(job->decode_tag, job->encode_tag_p, \
                                          job->auth_tag_output_len_in_bytes)) { \
                job->status = STS_AUTH_FAILED;                          \
        } else {                                                        \
                job->status = STS_COMPLETED;                            \
        }                                                               \
        TRACE("completed job:%u\n", job->seq_num);                      \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_AES128_GCM(sse)
FUNC_GENERATE_AES128_GCM(avx_gen2)
FUNC_GENERATE_AES128_GCM(avx_gen4)

/******************************************************************************
 * AES192 GCM mode
 ******************************************************************************/
#define FUNC_GENERATE_AES192_GCM(ARCH)                                  \
static struct JOB_AES_HMAC *                                            \
submit_aes192_gcm_enc_##ARCH(union MB_MGR_JOB_STATE *state __unused,    \
                             struct JOB_AES_HMAC *job)                  \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        aes_gcm_enc_192_##ARCH(job->aes_enc_key_expanded,               \
                               &job->gcm_context,                       \
                               job->dst,                                \
                               (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                               job->msg_len_to_cipher_in_bytes,         \
                               job->iv,                                 \
                               job->aad, job->aad_len_in_bytes,         \
                               job->auth_tag_output, job->auth_tag_output_len_in_bytes); \
        job->status = STS_COMPLETED;                                    \
        TRACE("completed job:%u\n", job->seq_num);                      \
        return job;                                                     \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_aes192_gcm_dec_##ARCH(union MB_MGR_JOB_STATE *state __unused,    \
                             struct JOB_AES_HMAC *job)                  \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        void *tag_output;                                               \
        if (job->enable_tag_cmp) {                                      \
                job->encode_tag_p = job->auth_tag_output;               \
                tag_output = job->decode_tag;                           \
        } else {                                                        \
                tag_output = job->auth_tag_output;                      \
        }                                                               \
        aes_gcm_dec_192_##ARCH(job->aes_dec_key_expanded,               \
                               &job->gcm_context,                       \
                               job->dst,                                \
                               (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                               job->msg_len_to_cipher_in_bytes,         \
                               job->iv,                                 \
                               job->aad, job->aad_len_in_bytes,         \
                               tag_output, job->auth_tag_output_len_in_bytes); \
        if (job->enable_tag_cmp && MEMCMP(job->decode_tag, job->encode_tag_p, \
                                          job->auth_tag_output_len_in_bytes)) { \
                job->status = STS_AUTH_FAILED;                          \
        } else {                                                        \
                job->status = STS_COMPLETED;                            \
        }                                                               \
        TRACE("completed job:%u\n", job->seq_num);                      \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_AES192_GCM(sse)
FUNC_GENERATE_AES192_GCM(avx_gen2)
FUNC_GENERATE_AES192_GCM(avx_gen4)

/******************************************************************************
 * AES256 GCM mode
 ******************************************************************************/
#define FUNC_GENERATE_AES256_GCM(ARCH)                                  \
static struct JOB_AES_HMAC *                                            \
submit_aes256_gcm_enc_##ARCH(union MB_MGR_JOB_STATE *state __unused,    \
                             struct JOB_AES_HMAC *job)                  \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        aes_gcm_enc_256_##ARCH(job->aes_enc_key_expanded,               \
                               &job->gcm_context,                       \
                               job->dst,                                \
                               (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                               job->msg_len_to_cipher_in_bytes,         \
                               job->iv,                                 \
                               job->aad, job->aad_len_in_bytes,         \
                               job->auth_tag_output,                    \
                               job->auth_tag_output_len_in_bytes);      \
        job->status = STS_COMPLETED;                                    \
        TRACE("completed job:%u\n", job->seq_num);                      \
        return job;                                                     \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_aes256_gcm_dec_##ARCH(union MB_MGR_JOB_STATE *state __unused,    \
                             struct JOB_AES_HMAC *job)                  \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        void *tag_output;                                               \
        if (job->enable_tag_cmp) {                                      \
                job->encode_tag_p = job->auth_tag_output;               \
                tag_output = job->decode_tag;                           \
        } else {                                                        \
                tag_output = job->auth_tag_output;                      \
        }                                                               \
        aes_gcm_dec_256_##ARCH(job->aes_dec_key_expanded,               \
                               &job->gcm_context,                       \
                               job->dst,                                \
                               (const UINT8 *) (job->src) + job->cipher_start_src_offset_in_bytes, \
                               job->msg_len_to_cipher_in_bytes,         \
                               job->iv,                                 \
                               job->aad, job->aad_len_in_bytes,         \
                               tag_output, job->auth_tag_output_len_in_bytes); \
        if (job->enable_tag_cmp && MEMCMP(job->decode_tag, job->encode_tag_p, \
                                          job->auth_tag_output_len_in_bytes)) { \
                job->status = STS_AUTH_FAILED;                          \
        } else {                                                        \
                job->status = STS_COMPLETED;                            \
        }                                                               \
        TRACE("completed job:%u\n", job->seq_num);                      \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_AES256_GCM(sse)
FUNC_GENERATE_AES256_GCM(avx_gen2)
FUNC_GENERATE_AES256_GCM(avx_gen4)

/******************************************************************************
 * DOCSIS
 ******************************************************************************/
#define FUNC_GENERATE_DOCSIS(ARCH)                                      \
__forceinline struct JOB_AES_HMAC *                                     \
DOCSIS_LAST_BLOCK_##ARCH(struct JOB_AES_HMAC *job)                      \
{                                                                       \
        if (job) {                                                      \
                UINT64 offset;                                          \
                UINT64 partial_bytes;                                   \
                partial_bytes = job->msg_len_to_cipher_in_bytes & (AES_BLOCK_SIZE - 1); \
                offset = job->msg_len_to_cipher_in_bytes & (~(AES_BLOCK_SIZE - 1)); \
                if (partial_bytes) {                                    \
                        const union AES_IV *iv;                         \
                        /* in either case IV has to be next last ciphered block */ \
                        if (job->cipher_direction == ENCRYPT)           \
                                iv = (const union AES_IV *) (((const UINT8 *) (job->dst)) + \
                                                             offset - AES_BLOCK_SIZE); \
                        else                                            \
                                iv = (const union AES_IV *) (((const UINT8 *) job->src) + \
                                                             job->cipher_start_src_offset_in_bytes + \
                                                             offset - AES_BLOCK_SIZE); \
                        aes_cfb_128_one_##ARCH(((UINT8 *) job->dst) + offset, \
                                               ((const UINT8 *) job->src) + job->cipher_start_src_offset_in_bytes + offset, \
                                               iv,                      \
                                               job->aes_enc_key_expanded, \
                                               partial_bytes);          \
                }                                                       \
        }                                                               \
        return job;                                                     \
}                                                                       \
__forceinline struct JOB_AES_HMAC *                                     \
 DOCSIS_FIRST_BLOCK_##ARCH(struct JOB_AES_HMAC *job)                    \
{                                                                       \
        aes_cfb_128_one_##ARCH(job->dst,                                \
                               ((const UINT8 *) job->src) + job->cipher_start_src_offset_in_bytes, \
                               job->iv,                                 \
                               job->aes_enc_key_expanded,               \
                               job->msg_len_to_cipher_in_bytes);        \
        job->status |= STS_COMPLETED_AES;                               \
        return job;                                                     \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_docsis_enc_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {        \
                job = submit_aes128_cbc_enc_##ARCH(state, job);         \
                return DOCSIS_LAST_BLOCK_##ARCH(job);                   \
        }                                                               \
        return DOCSIS_FIRST_BLOCK_##ARCH(job);                          \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_docsis_enc_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                       \
        struct JOB_AES_HMAC *job;                                       \
        job = flush_aes128_cbc_enc_##ARCH(state);                       \
        return DOCSIS_LAST_BLOCK_##ARCH(job);                           \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_docsis_dec_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        if (job->msg_len_to_cipher_in_bytes >= AES_BLOCK_SIZE) {        \
                DOCSIS_LAST_BLOCK_##ARCH(job);                          \
                return submit_aes128_cbc_dec_##ARCH(state, job);        \
        }                                                               \
        return DOCSIS_FIRST_BLOCK_##ARCH(job);                          \
}                                                                       \

FUNC_GENERATE_DOCSIS(sse)
FUNC_GENERATE_DOCSIS(avx)

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
#define FUNC_GENERATE_SHA1(ARCH)                                      \
static struct JOB_AES_HMAC *                                          \
submit_sha1_enc_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                       struct JOB_AES_HMAC *job)                      \
{                                                                     \
        TRACE("entry job:%u\n", job->seq_num);                        \
        return submit_job_hmac_##ARCH(&state->hmac_sha_1_ooo, job);   \
}                                                                     \
static struct JOB_AES_HMAC *                                          \
flush_sha1_enc_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                     \
        return flush_job_hmac_##ARCH(&state->hmac_sha_1_ooo);         \
}                                                                     \
static struct JOB_AES_HMAC *                                          \
submit_sha1_dec_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                       struct JOB_AES_HMAC *job)                      \
{                                                                     \
        TRACE("entry job:%u\n", job->seq_num);                        \
        job = submit_job_hmac_##ARCH(&state->hmac_sha_1_ooo, job);    \
        if (job)                                                      \
                job->status |= verify_tag(job);                       \
        return job;                                                   \
}                                                                     \
static struct JOB_AES_HMAC *                                          \
flush_sha1_dec_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                     \
        struct JOB_AES_HMAC *job;                                     \
        job = flush_job_hmac_##ARCH(&state->hmac_sha_1_ooo);          \
        if (job)                                                      \
                job->status |= verify_tag(job);                       \
        return job;                                                   \
}                                                                     \

FUNC_GENERATE_SHA1(sse)
FUNC_GENERATE_SHA1(ni_sse)
FUNC_GENERATE_SHA1(avx)
FUNC_GENERATE_SHA1(avx2)
FUNC_GENERATE_SHA1(avx512)

/******************************************************************************
 * HMAC_SHA224
 ******************************************************************************/
#define FUNC_GENERATE_SHA224(ARCH)                                      \
static struct JOB_AES_HMAC *                                            \
submit_sha224_enc_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        return submit_job_hmac_sha_224_##ARCH(&state->hmac_sha_224_ooo, job); \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_sha224_enc_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                       \
        return flush_job_hmac_sha_224_##ARCH(&state->hmac_sha_224_ooo);  \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_sha224_dec_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                      struct JOB_AES_HMAC *job)                         \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        job = submit_job_hmac_sha_224_##ARCH(&state->hmac_sha_224_ooo, job); \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_sha224_dec_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                       \
        struct JOB_AES_HMAC *job;                                       \
        job = flush_job_hmac_sha_224_##ARCH(&state->hmac_sha_224_ooo);  \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_SHA224(sse)
FUNC_GENERATE_SHA224(ni_sse)
FUNC_GENERATE_SHA224(avx)
FUNC_GENERATE_SHA224(avx2)
FUNC_GENERATE_SHA224(avx512)

/******************************************************************************
 * HMAC_SHA256
 ******************************************************************************/
#define FUNC_GENERATE_SHA256(ARCH)                                      \
static struct JOB_AES_HMAC *                                            \
submit_sha256_enc_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        return submit_job_hmac_sha_256_##ARCH(&state->hmac_sha_256_ooo, job); \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_sha256_enc_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                       \
        return flush_job_hmac_sha_256_##ARCH(&state->hmac_sha_256_ooo); \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_sha256_dec_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        job = submit_job_hmac_sha_256_##ARCH(&state->hmac_sha_256_ooo, job); \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_sha256_dec_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                       \
        struct JOB_AES_HMAC *job;                                       \
        job = flush_job_hmac_sha_256_##ARCH(&state->hmac_sha_256_ooo);  \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_SHA256(sse)
FUNC_GENERATE_SHA256(ni_sse)
FUNC_GENERATE_SHA256(avx)
FUNC_GENERATE_SHA256(avx2)
FUNC_GENERATE_SHA256(avx512)

/******************************************************************************
 * HMAC_SHA384
 ******************************************************************************/
#define FUNC_GENERATE_SHA384(ARCH)                                      \
static struct JOB_AES_HMAC *                                            \
submit_sha384_enc_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        return submit_job_hmac_sha_384_##ARCH(&state->hmac_sha_384_ooo, job); \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_sha384_enc_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                       \
        return flush_job_hmac_sha_384_##ARCH(&state->hmac_sha_384_ooo); \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_sha384_dec_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        job = submit_job_hmac_sha_384_##ARCH(&state->hmac_sha_384_ooo, job); \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_sha384_dec_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                       \
        struct JOB_AES_HMAC *job;                                       \
        job = flush_job_hmac_sha_384_##ARCH(&state->hmac_sha_384_ooo);  \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_SHA384(sse)
FUNC_GENERATE_SHA384(avx)
FUNC_GENERATE_SHA384(avx2)
FUNC_GENERATE_SHA384(avx512)

/******************************************************************************
 * HMAC_SHA512
 ******************************************************************************/
#define FUNC_GENERATE_SHA512(ARCH)                                      \
static struct JOB_AES_HMAC *                                            \
submit_sha512_enc_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        return submit_job_hmac_sha_512_##ARCH(&state->hmac_sha_512_ooo, job); \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_sha512_enc_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                       \
        return flush_job_hmac_sha_512_##ARCH(&state->hmac_sha_512_ooo); \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_sha512_dec_##ARCH(union MB_MGR_JOB_STATE *state,                 \
                         struct JOB_AES_HMAC *job)                      \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        job = submit_job_hmac_sha_512_##ARCH(&state->hmac_sha_512_ooo, job); \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_sha512_dec_##ARCH(union MB_MGR_JOB_STATE *state)                  \
{                                                                       \
        struct JOB_AES_HMAC *job;                                       \
        job = flush_job_hmac_sha_512_##ARCH(&state->hmac_sha_512_ooo);  \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_SHA512(sse)
FUNC_GENERATE_SHA512(avx)
FUNC_GENERATE_SHA512(avx2)
FUNC_GENERATE_SHA512(avx512)

/******************************************************************************
 * HMAC_MD5 (not yet)
 ******************************************************************************/
#define FUNC_GENERATE_MD5(ARCH)                                         \
static struct JOB_AES_HMAC *                                            \
submit_md5_enc_##ARCH(union MB_MGR_JOB_STATE *state,                    \
                      struct JOB_AES_HMAC *job)                         \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        return submit_job_hmac_md5_##ARCH(&state->hmac_md5_ooo, job);   \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_md5_enc_##ARCH(union MB_MGR_JOB_STATE *state)                     \
{                                                                       \
        return flush_job_hmac_md5_##ARCH(&state->hmac_md5_ooo);         \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_md5_dec_##ARCH(union MB_MGR_JOB_STATE *state,                    \
                      struct JOB_AES_HMAC *job)                         \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        job = submit_job_hmac_md5_##ARCH(&state->hmac_md5_ooo, job);    \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_md5_dec_##ARCH(union MB_MGR_JOB_STATE *state)                     \
{                                                                       \
        struct JOB_AES_HMAC *job;                                       \
        job = flush_job_hmac_md5_##ARCH(&state->hmac_md5_ooo);          \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_MD5(sse)
FUNC_GENERATE_MD5(avx)
FUNC_GENERATE_MD5(avx2)

/******************************************************************************
 * AES_XCBC
 ******************************************************************************/
#define FUNC_GENERATE_XCBC(ARCH)                                        \
static struct JOB_AES_HMAC *                                            \
submit_xcbc_enc_##ARCH(union MB_MGR_JOB_STATE *state,                   \
                       struct JOB_AES_HMAC *job)                        \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        return submit_job_aes_xcbc_##ARCH(&state->aes_xcbc_ooo, job);   \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_xcbc_enc_##ARCH(union MB_MGR_JOB_STATE *state)                    \
{                                                                       \
        return flush_job_aes_xcbc_##ARCH(&state->aes_xcbc_ooo);         \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
submit_xcbc_dec_##ARCH(union MB_MGR_JOB_STATE *state,                   \
                       struct JOB_AES_HMAC *job)                        \
{                                                                       \
        TRACE("entry job:%u\n", job->seq_num);                          \
        job = submit_job_aes_xcbc_##ARCH(&state->aes_xcbc_ooo, job);    \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \
static struct JOB_AES_HMAC *                                            \
flush_xcbc_dec_##ARCH(union MB_MGR_JOB_STATE *state)                    \
{                                                                       \
        struct JOB_AES_HMAC *job;                                       \
        job = flush_job_aes_xcbc_##ARCH(&state->aes_xcbc_ooo);          \
        if (job)                                                        \
                job->status |= verify_tag(job);                         \
        return job;                                                     \
}                                                                       \

FUNC_GENERATE_XCBC(sse)
FUNC_GENERATE_XCBC(avx)

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
 * Task handler
 ******************************************************************************/
/*
 * SSE handler
 */
static const struct job_task_handler job_task_handler_SSE[] = {
        [JOB_TASK_INVALID] = {
                .name                   = "SSE invalid",
        },
        [JOB_TASK_AES128_CBC] = {
                .name                   = "SSE AES128_CBC",
                .state_id               = JOB_STATE_AES128,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_cbc_enc_sse,
                                .flush  = flush_aes128_cbc_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_cbc_dec_sse,
                        },
                }
        },
        [JOB_TASK_AES192_CBC] = {
                .name                   = "SSE AES192_CBC",
                .state_id               = JOB_STATE_AES192,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_cbc_enc_sse,
                                .flush  = flush_aes192_cbc_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_cbc_dec_sse,
                        },
                }
        },
        [JOB_TASK_AES256_CBC] = {
                .name                   = "SSE AES256_CBC",
                .state_id               = JOB_STATE_AES256,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_cbc_enc_sse,
                                .flush  = flush_aes256_cbc_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_cbc_dec_sse,
                        },
                }
        },
        [JOB_TASK_AES128_CTR] = {
                .name                   = "SSE AES128_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_ctr_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_ctr_sse,
                        },
                }
        },
        [JOB_TASK_AES192_CTR] = {
                .name                   = "SSE AES192_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_ctr_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_ctr_sse,
                        },
                }
        },
        [JOB_TASK_AES256_CTR] = {
                .name                   = "SSE AES256_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_ctr_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_ctr_sse,
                        },
                }
        },
        [JOB_TASK_AES128_GCM] = {
                .name                   = "SSE AES128_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_gcm_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_gcm_dec_sse,
                        },
                }
        },
        [JOB_TASK_AES192_GCM] = {
                .name                   = "SSE AES192_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_gcm_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_gcm_dec_sse,
                        },
                }
        },
        [JOB_TASK_AES256_GCM] = {
                .name                   = "SSE AES256_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_gcm_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_gcm_dec_sse,
                        },
                }
        },
        [JOB_TASK_DOCSIS] = {
                .name                   = "SSE DOCSIS",
                .state_id               = JOB_STATE_DOCSIS,

                /* same settings as AES128 CBC */
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_docsis_enc_sse,
                                .flush  = flush_docsis_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_docsis_dec_sse,
                        },
                }
        },
        [JOB_TASK_NULL_CIPHER] = {
                .name                   = "SSE NULL_CIPHER",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                }
        },
        [JOB_TASK_SHA1] = {
                .name                   = "SSE SHA1",
                .state_id               = JOB_STATE_SHA1,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha1_enc_sse,
                                .flush  = flush_sha1_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha1_dec_sse,
                                .flush  = flush_sha1_dec_sse,
                        },
                }
        },
        [JOB_TASK_SHA224] = {
                .name                   = "SSE SHA224",
                .state_id               = JOB_STATE_SHA224,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha224_enc_sse,
                                .flush  = flush_sha224_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha224_dec_sse,
                                .flush  = flush_sha224_dec_sse,
                        },
                }
        },
        [JOB_TASK_SHA256] = {
                .name                   = "SSE SHA256",
                .state_id               = JOB_STATE_SHA256,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha256_enc_sse,
                                .flush  = flush_sha256_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha256_dec_sse,
                                .flush  = flush_sha256_dec_sse,
                        },
                }
        },
        [JOB_TASK_SHA384] = {
                .name                   = "SSE SHA384",
                .state_id               = JOB_STATE_SHA384,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha384_enc_sse,
                                .flush  = flush_sha384_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha384_dec_sse,
                                .flush  = flush_sha384_dec_sse,
                        },
                }
        },
        [JOB_TASK_SHA512] = {
                .name                   = "SSE SHA512",
                .state_id               = JOB_STATE_SHA512,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha512_enc_sse,
                                .flush  = flush_sha512_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha512_dec_sse,
                                .flush  = flush_sha512_dec_sse,
                        },
                }
        },
        [JOB_TASK_MD5] = {
                .name                   = "SSE MD5",
                .state_id               = JOB_STATE_MD5,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_md5_enc_sse,
                                .flush  = flush_md5_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_md5_dec_sse,
                                .flush  = flush_md5_dec_sse,
                        },
                }
        },
        [JOB_TASK_XCBC] = {
                .name                   = "SSE XCBC",
                .state_id               = JOB_STATE_XCBC,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_xcbc_enc_sse,
                                .flush  = flush_xcbc_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_xcbc_dec_sse,
                                .flush  = flush_xcbc_dec_sse,
                        },
                }
        },
        [JOB_TASK_NULL_HASH] = {
                .name                   = "SSE NULL_HASH",
                .direction = {
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
 * SSE with SHANI handler
 */
static const struct job_task_handler job_task_handler_SSE_SHANI[] = {
        [JOB_TASK_INVALID] = {
                .name                   = "SSE invalid",
        },
        [JOB_TASK_AES128_CBC] = {
                .name                   = "SSE AES128_CBC",
                .state_id               = JOB_STATE_AES128,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_cbc_enc_sse,
                                .flush  = flush_aes128_cbc_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_cbc_dec_sse,
                        },
                }
        },
        [JOB_TASK_AES192_CBC] = {
                .name                   = "SSE AES192_CBC",
                .state_id               = JOB_STATE_AES192,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_cbc_enc_sse,
                                .flush  = flush_aes192_cbc_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_cbc_dec_sse,
                        },
                }
        },
        [JOB_TASK_AES256_CBC] = {
                .name                   = "SSE AES256_CBC",
                .state_id               = JOB_STATE_AES256,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_cbc_enc_sse,
                                .flush  = flush_aes256_cbc_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_cbc_dec_sse,
                        },
                }
        },
        [JOB_TASK_AES128_CTR] = {
                .name                   = "SSE AES128_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_ctr_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_ctr_sse,
                        },
                }
        },
        [JOB_TASK_AES192_CTR] = {
                .name                   = "SSE AES192_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_ctr_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_ctr_sse,
                        },
                }
        },
        [JOB_TASK_AES256_CTR] = {
                .name                   = "SSE AES256_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_ctr_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_ctr_sse,
                        },
                }
        },
        [JOB_TASK_AES128_GCM] = {
                .name                   = "SSE AES128_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_gcm_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_gcm_dec_sse,
                        },
                }
        },
        [JOB_TASK_AES192_GCM] = {
                .name                   = "SSE AES192_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_gcm_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_gcm_dec_sse,
                        },
                }
        },
        [JOB_TASK_AES256_GCM] = {
                .name                   = "SSE AES256_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_gcm_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_gcm_dec_sse,
                        },
                }
        },
        [JOB_TASK_DOCSIS] = {
                .name                   = "SSE DOCSIS",
                .state_id               = JOB_STATE_DOCSIS,

                /* same settings as AES128 CBC */
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_docsis_enc_sse,
                                .flush  = flush_docsis_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_docsis_dec_sse,
                        },
                }
        },
        [JOB_TASK_NULL_CIPHER] = {
                .name                   = "SSE NULL_CIPHER",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                }
        },
        [JOB_TASK_SHA1] = {
                .name                   = "SSE-SHANI SHA1",
                .state_id               = JOB_STATE_SHA1,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha1_enc_ni_sse,
                                .flush  = flush_sha1_enc_ni_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha1_dec_ni_sse,
                                .flush  = flush_sha1_dec_ni_sse,
                        },
                }
        },
        [JOB_TASK_SHA224] = {
                .name                   = "SSE-SHANI SHA224",
                .state_id               = JOB_STATE_SHA224,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha224_enc_ni_sse,
                                .flush  = flush_sha224_enc_ni_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha224_dec_ni_sse,
                                .flush  = flush_sha224_dec_ni_sse,
                        },
                }
        },
        [JOB_TASK_SHA256] = {
                .name                   = "SSE-SHANI SHA256",
                .state_id               = JOB_STATE_SHA256,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha256_enc_ni_sse,
                                .flush  = flush_sha256_enc_ni_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha256_dec_ni_sse,
                                .flush  = flush_sha256_dec_ni_sse,
                        },
                }
        },
        [JOB_TASK_SHA384] = {
                .name                   = "SSE SHA384",
                .state_id               = JOB_STATE_SHA384,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha384_enc_sse,
                                .flush  = flush_sha384_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha384_dec_sse,
                                .flush  = flush_sha384_dec_sse,
                        },
                }
        },
        [JOB_TASK_SHA512] = {
                .name                   = "SSE SHA512",
                .state_id               = JOB_STATE_SHA512,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha512_enc_sse,
                                .flush  = flush_sha512_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha512_dec_sse,
                                .flush  = flush_sha512_dec_sse,
                        },
                }
        },
        [JOB_TASK_MD5] = {
                .name                   = "SSE MD5",
                .state_id               = JOB_STATE_MD5,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_md5_enc_sse,
                                .flush  = flush_md5_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_md5_dec_sse,
                                .flush  = flush_md5_dec_sse,
                        },
                }
        },
        [JOB_TASK_XCBC] = {
                .name                   = "SSE XCBC",
                .state_id               = JOB_STATE_XCBC,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_xcbc_enc_sse,
                                .flush  = flush_xcbc_enc_sse,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_xcbc_dec_sse,
                                .flush  = flush_xcbc_dec_sse,
                        },
                }
        },
        [JOB_TASK_NULL_HASH] = {
                .name                   = "SSE NULL_HASH",
                .direction = {
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
 * AVX handler
 */
static const struct job_task_handler job_task_handler_AVX[] = {
        [JOB_TASK_INVALID] = {
                .name                   = "AVX invalid",
        },
        [JOB_TASK_AES128_CBC] = {
                .name                   = "AVX AES128_CBC",
                .state_id               = JOB_STATE_AES128,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_cbc_enc_avx,
                                .flush  = flush_aes128_cbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_cbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_AES192_CBC] = {
                .name                   = "AVX AES192_CBC",
                .state_id               = JOB_STATE_AES192,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_cbc_enc_avx,
                                .flush  = flush_aes192_cbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_cbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_AES256_CBC] = {
                .name                   = "AVX AES256_CBC",
                .state_id               = JOB_STATE_AES256,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_cbc_enc_avx,
                                .flush  = flush_aes256_cbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_cbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_AES128_CTR] = {
                .name                   = "AVX AES128_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_ctr_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_ctr_avx,
                        },
                }
        },
        [JOB_TASK_AES192_CTR] = {
                .name                   = "AVX AES192_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_ctr_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_ctr_avx,
                        },
                }
        },
        [JOB_TASK_AES256_CTR] = {
                .name                   = "AVX AES256_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_ctr_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_ctr_avx,
                        },
                }
        },
        [JOB_TASK_AES128_GCM] = {
                .name                   = "AVX AES128_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_gcm_enc_avx_gen2,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_gcm_dec_avx_gen2,
                        },
                }
        },
        [JOB_TASK_AES192_GCM] = {
                .name                   = "AVX AES192_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_gcm_enc_avx_gen2,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_gcm_dec_avx_gen2,
                        },
                }
        },
        [JOB_TASK_AES256_GCM] = {
                .name                   = "AVX AES256_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_gcm_enc_avx_gen2,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_gcm_dec_avx_gen2,
                        },
                }
        },
        [JOB_TASK_DOCSIS] = {
                .name                   = "AVX DOCSIS",
                .state_id               = JOB_STATE_DOCSIS,

                /* same settings as AES128 CBC */
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_docsis_enc_avx,
                                .flush  = flush_docsis_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_docsis_dec_avx,
                        },
                }
        },
        [JOB_TASK_NULL_CIPHER] = {
                .name                   = "AVX NULL_CIPHER",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                }
        },
        [JOB_TASK_SHA1] = {
                .name                   = "AVX SHA1",
                .state_id               = JOB_STATE_SHA1,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha1_enc_avx,
                                .flush  = flush_sha1_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha1_dec_avx,
                                .flush  = flush_sha1_dec_avx,
                        },
                }
        },
        [JOB_TASK_SHA224] = {
                .name                   = "AVX SHA224",
                .state_id               = JOB_STATE_SHA224,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha224_enc_avx,
                                .flush  = flush_sha224_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha224_dec_avx,
                                .flush  = flush_sha224_dec_avx,
                        },
                }
        },
        [JOB_TASK_SHA256] = {
                .name                   = "AVX SHA256",
                .state_id               = JOB_STATE_SHA256,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha256_enc_avx,
                                .flush  = flush_sha256_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha256_dec_avx,
                                .flush  = flush_sha256_dec_avx,
                        },
                }
        },
        [JOB_TASK_SHA384] = {
                .name                   = "AVX SHA384",
                .state_id               = JOB_STATE_SHA384,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha384_enc_avx,
                                .flush  = flush_sha384_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha384_dec_avx,
                                .flush  = flush_sha384_dec_avx,
                        },
                }
        },
        [JOB_TASK_SHA512] = {
                .name                   = "AVX SHA512",
                .state_id               = JOB_STATE_SHA512,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha512_enc_avx,
                                .flush  = flush_sha512_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha512_dec_avx,
                                .flush  = flush_sha512_dec_avx,
                        },
                }
        },
        [JOB_TASK_MD5] = {
                .name                   = "AVX MD5",
                .state_id               = JOB_STATE_MD5,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_md5_enc_avx,
                                .flush  = flush_md5_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_md5_dec_avx,
                                .flush  = flush_md5_dec_avx,
                        },
                }
        },
        [JOB_TASK_XCBC] = {
                .name                   = "AVX XCBC",
                .state_id               = JOB_STATE_XCBC,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_xcbc_enc_avx,
                                .flush  = flush_xcbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_xcbc_dec_avx,
                                .flush  = flush_xcbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_NULL_HASH] = {
                .name                   = "AVX NULL_HASH",
                .direction = {
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
 * AVX2 handler
 */
static const struct job_task_handler job_task_handler_AVX2[] = {
        [JOB_TASK_INVALID] = {
                .name                   = "AVX2 invalid",
        },
        [JOB_TASK_AES128_CBC] = {
                .name                   = "AVX2 AES128_CBC",
                .state_id               = JOB_STATE_AES128,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_cbc_enc_avx,
                                .flush  = flush_aes128_cbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_cbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_AES192_CBC] = {
                .name                   = "AVX2 AES192_CBC",
                .state_id               = JOB_STATE_AES192,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_cbc_enc_avx,
                                .flush  = flush_aes192_cbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_cbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_AES256_CBC] = {
                .name                   = "AVX2 AES256_CBC",
                .state_id               = JOB_STATE_AES256,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_cbc_enc_avx,
                                .flush  = flush_aes256_cbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_cbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_AES128_CTR] = {
                .name                   = "AVX2 AES128_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_ctr_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_ctr_avx,
                        },
                }
        },
        [JOB_TASK_AES192_CTR] = {
                .name                   = "AVX2 AES192_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_ctr_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_ctr_avx,
                        },
                }
        },
        [JOB_TASK_AES256_CTR] = {
                .name                   = "AVX2 AES256_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_ctr_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_ctr_avx,
                        },
                }
        },
        [JOB_TASK_AES128_GCM] = {
                .name                   = "AVX2 AES128_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_gcm_enc_avx_gen4,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_gcm_dec_avx_gen4,
                        },
                }
        },
        [JOB_TASK_AES192_GCM] = {
                .name                   = "AVX2 AES192_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_gcm_enc_avx_gen4,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_gcm_dec_avx_gen4,
                        },
                }
        },
        [JOB_TASK_AES256_GCM] = {
                .name                   = "AVX2 AES256_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_gcm_enc_avx_gen4,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_gcm_dec_avx_gen4,
                        },
                }
        },
        [JOB_TASK_DOCSIS] = {
                .name                   = "AVX2 DOCSIS",
                .state_id               = JOB_STATE_DOCSIS,

                /* same settings as AES128 CBC */
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_docsis_enc_avx,
                                .flush  = flush_docsis_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_docsis_dec_avx,
                        },
                }
        },
        [JOB_TASK_NULL_CIPHER] = {
                .name                   = "AVX2 NULL_CIPHER",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                }
        },
        [JOB_TASK_SHA1] = {
                .name                   = "AVX2 SHA1",
                .state_id               = JOB_STATE_SHA1,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha1_enc_avx2,
                                .flush  = flush_sha1_enc_avx2,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha1_dec_avx2,
                                .flush  = flush_sha1_dec_avx2,
                        },
                }
        },
        [JOB_TASK_SHA224] = {
                .name                   = "AVX2 SHA224",
                .state_id               = JOB_STATE_SHA224,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha224_enc_avx2,
                                .flush  = flush_sha224_enc_avx2,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha224_dec_avx2,
                                .flush  = flush_sha224_dec_avx2,
                        },
                }
        },
        [JOB_TASK_SHA256] = {
                .name                   = "AVX2 SHA256",
                .state_id               = JOB_STATE_SHA256,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha256_enc_avx2,
                                .flush  = flush_sha256_enc_avx2,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha256_dec_avx2,
                                .flush  = flush_sha256_dec_avx2,
                        },
                }
        },
        [JOB_TASK_SHA384] = {
                .name                   = "AVX2 SHA384",
                .state_id               = JOB_STATE_SHA384,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha384_enc_avx2,
                                .flush  = flush_sha384_enc_avx2,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha384_dec_avx2,
                                .flush  = flush_sha384_dec_avx2,
                        },
                }
        },
        [JOB_TASK_SHA512] = {
                .name                   = "AVX2 SHA512",
                .state_id               = JOB_STATE_SHA512,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha512_enc_avx2,
                                .flush  = flush_sha512_enc_avx2,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha512_dec_avx2,
                                .flush  = flush_sha512_dec_avx2,
                        },
                }
        },
        [JOB_TASK_MD5] = {
                .name                   = "AVX2 MD5",
                .state_id               = JOB_STATE_MD5,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_md5_enc_avx2,
                                .flush  = flush_md5_enc_avx2,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_md5_dec_avx2,
                                .flush  = flush_md5_dec_avx2,
                        },
                }
        },
        [JOB_TASK_XCBC] = {
                .name                   = "AVX2 XCBC",
                .state_id               = JOB_STATE_XCBC,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_xcbc_enc_avx,
                                .flush  = flush_xcbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_xcbc_dec_avx,
                                .flush  = flush_xcbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_NULL_HASH] = {
                .name                   = "AVX2 NULL_HASH",
                .direction = {
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
 * AVX512 handler
 */
static const struct job_task_handler job_task_handler_AVX512[] = {
        [JOB_TASK_INVALID] = {
                .name                   = "AVX512 invalid",
        },
        [JOB_TASK_AES128_CBC] = {
                .name                   = "AVX512 AES128_CBC",
                .state_id               = JOB_STATE_AES128,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_cbc_enc_avx,
                                .flush  = flush_aes128_cbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_cbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_AES192_CBC] = {
                .name                   = "AVX512 AES192_CBC",
                .state_id               = JOB_STATE_AES192,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_cbc_enc_avx,
                                .flush  = flush_aes192_cbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_cbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_AES256_CBC] = {
                .name                   = "AVX512 AES256_CBC",
                .state_id               = JOB_STATE_AES256,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_cbc_enc_avx,
                                .flush  = flush_aes256_cbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_cbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_AES128_CTR] = {
                .name                   = "AVX512 AES128_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_ctr_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_ctr_avx,
                        },
                }
        },
        [JOB_TASK_AES192_CTR] = {
                .name                   = "AVX512 AES192_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_ctr_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_ctr_avx,
                        },
                }
        },
        [JOB_TASK_AES256_CTR] = {
                .name                   = "AVX512 AES256_CTR",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_ctr_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_ctr_avx,
                        },
                }
        },
        [JOB_TASK_AES128_GCM] = {
                .name                   = "AVX512 AES128_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes128_gcm_enc_avx_gen4,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes128_gcm_dec_avx_gen4,
                        },
                }
        },
        [JOB_TASK_AES192_GCM] = {
                .name                   = "AVX512 AES192_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes192_gcm_enc_avx_gen4,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes192_gcm_dec_avx_gen4,
                        },
                }
        },
        [JOB_TASK_AES256_GCM] = {
                .name                   = "AVX512 AES256_GCM",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_aes256_gcm_enc_avx_gen4,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_aes256_gcm_dec_avx_gen4,
                        },
                }
        },
        [JOB_TASK_DOCSIS] = {
                .name                   = "AVX512 DOCSIS",
                .state_id               = JOB_STATE_DOCSIS,

                /* same settings as AES128 CBC */
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_docsis_enc_avx,
                                .flush  = flush_docsis_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_docsis_dec_avx,
                        },
                }
        },
        [JOB_TASK_NULL_CIPHER] = {
                .name                   = "AVX512 NULL_CIPHER",
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_null_cipher,
                        },
                }
        },
        [JOB_TASK_SHA1] = {
                .name                   = "AVX512 SHA1",
                .state_id               = JOB_STATE_SHA1,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha1_enc_avx512,
                                .flush  = flush_sha1_enc_avx512,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha1_dec_avx512,
                                .flush  = flush_sha1_dec_avx512,
                        },
                }
        },
        [JOB_TASK_SHA224] = {
                .name                   = "AVX512 SHA224",
                .state_id               = JOB_STATE_SHA224,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha224_enc_avx512,
                                .flush  = flush_sha224_enc_avx512,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha224_dec_avx512,
                                .flush  = flush_sha224_dec_avx512,
                        },
                }
        },
        [JOB_TASK_SHA256] = {
                .name                   = "AVX512 SHA256",
                .state_id               = JOB_STATE_SHA256,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha256_enc_avx512,
                                .flush  = flush_sha256_enc_avx512,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha256_dec_avx512,
                                .flush  = flush_sha256_dec_avx512,
                        },
                }
        },
        [JOB_TASK_SHA384] = {
                .name                   = "AVX512 SHA384",
                .state_id               = JOB_STATE_SHA384,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha384_enc_avx512,
                                .flush  = flush_sha384_enc_avx512,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha384_dec_avx512,
                                .flush  = flush_sha384_dec_avx512,
                        },
                }
        },
        [JOB_TASK_SHA512] = {
                .name                   = "AVX512 SHA512",
                .state_id               = JOB_STATE_SHA512,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_sha512_enc_avx512,
                                .flush  = flush_sha512_enc_avx512,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_sha512_dec_avx512,
                                .flush  = flush_sha512_dec_avx512,
                        },
                }
        },
        [JOB_TASK_MD5] = {
                .name                   = "AVX512 MD5",
                .state_id               = JOB_STATE_MD5,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_md5_enc_avx2,
                                .flush  = flush_md5_enc_avx2,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_md5_dec_avx2,
                                .flush  = flush_md5_dec_avx2,
                        },
                }
        },
        [JOB_TASK_XCBC] = {
                .name                   = "AVX512 XCBC",
                .state_id               = JOB_STATE_XCBC,
                .direction = {
                        [ENCRYPT - 1] = {
                                .submit = submit_xcbc_enc_avx,
                                .flush  = flush_xcbc_enc_avx,
                        },
                        [DECRYPT - 1] = {
                                .submit = submit_xcbc_dec_avx,
                                .flush  = flush_xcbc_dec_avx,
                        },
                }
        },
        [JOB_TASK_NULL_HASH] = {
                .name                   = "AVX512 NULL_HASH",
                .direction = {
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
 * no validity checking
 * return:
 *	OK:0
 *	NG:other
 */
static inline void
setup_job(struct JOB_AES_HMAC *job,
          enum JOB_TASK first_task,
          enum JOB_TASK second_task)
{
        if (first_task == second_task) {
                job->current_stage = 0;
                job->stage_task[0] = first_task;
        } else {
                job->current_stage = 1;
                job->stage_task[1] = first_task;
                job->stage_task[0] = second_task;
        }

        if (job->enable_esn) {
                BE32 *esn_high = job->auth_tag_output;

                job->msg_len_to_hash_in_bytes += sizeof(*esn_high);
                SWAP(job->esn_high, *esn_high);
        }

        if (job->cipher_direction == DECRYPT && job->enable_tag_cmp) {
                job->encode_tag_p = job->auth_tag_output;
                job->auth_tag_output = job->decode_tag;
        }

        job->status = STS_BEING_PROCESSED;
}

/*
 *
 */
struct cipher_key_task {
        enum JOB_TASK task[4];	/* key length(bits): 128, 192, 256, 0 */
};

static const struct cipher_key_task cipher_key_task_tbl[] = {
        [CBC] = {
                .task = {
                        JOB_TASK_AES128_CBC,
                        JOB_TASK_AES192_CBC,
                        JOB_TASK_AES256_CBC,
                        JOB_TASK_INVALID,
                },
        },
        [CNTR] = {
                .task = {
                        JOB_TASK_AES128_CTR,
                        JOB_TASK_AES192_CTR,
                        JOB_TASK_AES256_CTR,
                        JOB_TASK_INVALID,
                },
        },
        [NULL_CIPHER] = {
                .task = {
                        JOB_TASK_INVALID,
                        JOB_TASK_INVALID,
                        JOB_TASK_INVALID,
                        JOB_TASK_NULL_CIPHER,
                },
        },
        [DOCSIS_SEC_BPI] = {
                .task = {
                        JOB_TASK_DOCSIS,
                        JOB_TASK_INVALID,
                        JOB_TASK_INVALID,
                        JOB_TASK_INVALID,
                },
        },
        [GCM] = {
                .task = {
                        JOB_TASK_AES128_GCM,
                        JOB_TASK_AES192_GCM,
                        JOB_TASK_AES256_GCM,
                        JOB_TASK_INVALID,
                },
        },
};


struct hash_auth_task {
        enum JOB_TASK task;
        unsigned tag_max;
        unsigned no_expand_esn;
};

static const struct hash_auth_task auth_task_tbl[] = {
        [SHA1]      = {
                .task    = JOB_TASK_SHA1,
                .tag_max = SHA1_DIGEST_SIZE,
        },
        [SHA_224]   = {
                .task    = JOB_TASK_SHA224,
                .tag_max = SHA_224_DIGEST_SIZE,
        },
        [SHA_256]   = {
                .task    = JOB_TASK_SHA256,
                .tag_max = SHA_256_DIGEST_SIZE,
        },
        [SHA_384]   = {
                .task    = JOB_TASK_SHA384,
                .tag_max = SHA_384_DIGEST_SIZE,
        },
        [SHA_512]   = {
                .task    = JOB_TASK_SHA512,
                .tag_max = SHA_512_DIGEST_SIZE,
        },
        [AES_XCBC]  = {
                .task    = JOB_TASK_XCBC,
                .tag_max = AES_XCBC_DIGEST_SIZE,
        },
        [MD5]       = {
                .task    = JOB_TASK_MD5,
                .tag_max = MD5_DIGEST_SIZE,
        },
        [NULL_HASH] = {
                .task    = JOB_TASK_NULL_HASH,
                .tag_max = 0,
                .no_expand_esn = 1,
        },
        [GCM_AES]   = {
                .tag_max = GCM_DIGEST_SIZE,
                .no_expand_esn = 1,
        },
};

/*
 * return:
 *	OK:0
 *	NG:other
 */
static int
_ipsec_mb_setup_job(struct JOB_AES_HMAC *job)
{
        enum JOB_TASK first_task = JOB_TASK_INVALID,
                     second_task = JOB_TASK_INVALID;
        int cipher_key_type;

        job->current_stage = -1;
        job->status = STS_INVALID_ARGS;

        switch (job->aes_key_len_in_bytes) {
        case AES_128_BYTES:
                cipher_key_type = 0;
                break;
        case AES_192_BYTES:
                cipher_key_type = 1;
                break;
        case AES_256_BYTES:
                cipher_key_type = 2;
                break;
        case 0:
                cipher_key_type = 3;
                break;
        default:
                ERROR("invalid AES key length:%u\n",
                      (unsigned) job->aes_key_len_in_bytes);
                return -1;
        }

        if (job->cipher_mode > 0 && job->cipher_mode < CIPHER_MODE_NUMOF) {
                first_task = cipher_key_task_tbl[job->cipher_mode].task[cipher_key_type];
        }

        if (first_task == JOB_TASK_INVALID) {
                ERROR("invalid cipher mode:%d key len:%u\n",
                      job->cipher_mode, (unsigned) job->aes_key_len_in_bytes);
                return -1;
        }

        if (job->hash_alg > 0 && job->hash_alg < HASH_ALG_NUMOF) {
                if (job->auth_tag_output_len_in_bytes > auth_task_tbl[job->hash_alg].tag_max) {
                        ERROR("invalid tag len:%u\n",
                              (unsigned) job->auth_tag_output_len_in_bytes);
                       return -1;
                }
                if (job->auth_tag_output_len_in_bytes == 0)
                        job->enable_tag_cmp = 0;
                if (auth_task_tbl[job->hash_alg].no_expand_esn)
                        job->enable_esn = 0;
                second_task = auth_task_tbl[job->hash_alg].task;
                if (second_task == JOB_TASK_INVALID)
                        second_task = first_task; /* for GCM */
        }

        if (second_task == JOB_TASK_INVALID) {
                ERROR("invalid hash algorithm:%d\n", job->hash_alg);
                return -1;
        }

        switch (job->cipher_direction) {
        case DECRYPT:
                SWAP(first_task, second_task);
                /* FALLTHROUGH */
        case ENCRYPT:
                break;

        default:
                ERROR("invalid direction:%d\n", job->cipher_direction);
                return -1;
        }

        setup_job(job, first_task, second_task);
        return 0;
}

__forceinline struct JOB_AES_HMAC *
_ipsec_mb_submit_new_job(struct MB_MGR *mgr,
                         struct JOB_AES_HMAC *job)
{
        while (job->current_stage >= 0) {
                union MB_MGR_JOB_STATE *state;
                const struct job_task_handler *handler =
                        &mgr->handler[job->stage_task[job->current_stage]];

                state = &mgr->states[handler->state_id];
                job = handler->direction[job->cipher_direction - 1].submit(state, job);
                if (!job)
                        break;

                job->current_stage -= 1;
        }
        return job;
}

__forceinline void
_ipsec_mb_do_complete_job(struct MB_MGR *mgr,
                          struct JOB_AES_HMAC *job)
{
        while (job->current_stage >= 0) {
                struct JOB_AES_HMAC *next;
                union MB_MGR_JOB_STATE *state;
                const struct job_task_handler *handler =
                        &mgr->handler[job->stage_task[job->current_stage]];

                state = &mgr->states[handler->state_id];
                next = handler->direction[job->cipher_direction - 1].flush(state);

                while (next) {
                        next->current_stage -= 1;
                        if (next->current_stage < 0)
                                break;

                        handler = &mgr->handler[job->stage_task[next->current_stage]];
                        state = &mgr->states[handler->state_id];
                        next = handler->direction[next->cipher_direction - 1].submit(state, next);
                }
        }
}

/*
 * get head of FIFO job (earliest job)
 */
__forceinline struct JOB_AES_HMAC *
_ipsec_mb_head_job(struct MB_MGR *mgr)
{
        if (mgr->depth) {
                unsigned head = mgr->next - mgr->depth;

                head &= (MAX_JOBS - 1);
                return &mgr->jobs[head];
        }
        return NULL;
}

/*
 * Submit Job Raw
 * return completed or rejected Job
 */
__forceinline struct JOB_AES_HMAC *
_ipsec_mb_submit_job_raw(struct MB_MGR *mgr,
                         struct JOB_AES_HMAC *job)
{
        mgr->next += 1;
        mgr->next &= (MAX_JOBS - 1);
        mgr->depth += 1;

        SAVE_VEC_REGS(mgr);

        job = _ipsec_mb_submit_new_job(mgr, job);
        if (job) {
                if (_ipsec_mb_head_job(mgr) == job) {
                        mgr->depth -= 1;
                } else {
                        job = NULL;
                }
        }

        if (mgr->depth == MAX_JOBS) {
                job = _ipsec_mb_head_job(mgr);

                _ipsec_mb_do_complete_job(mgr, job);
                mgr->depth -= 1;
        }

        RESTORE_VEC_REGS(mgr);
        return job;
}

/******************************************************************************
 * API
 ******************************************************************************/
/*
 * enable_tag_cmp: MUST be off at non-linux
 */
struct JOB_AES_HMAC *
ipsec_mb_submit_job_NAPI(struct MB_MGR *mgr,
                         int enable_tag_cmp,
                         BE32 *esn_high_p)
{
        struct JOB_AES_HMAC *job = ipsec_mb_get_next_job(mgr);

        job->enable_tag_cmp = enable_tag_cmp;

        if (esn_high_p) {
                job->enable_esn = 1;
                job->esn_high = *esn_high_p;
        } else {
                job->enable_esn = 0;
        }

        if (_ipsec_mb_setup_job(job)) {
                job->status = STS_INVALID_ARGS;
                return job;
        }
        return _ipsec_mb_submit_job_raw(mgr, job);
}

struct JOB_AES_HMAC *
ipsec_mb_get_completed_job(struct MB_MGR *mgr)
{
        struct JOB_AES_HMAC *job;

        job = _ipsec_mb_head_job(mgr);
        if (job) {
                if (job->current_stage < 0) {
                        mgr->depth -= 1;
                } else {
                        job = NULL;
                }
        }
        return job;
}

struct JOB_AES_HMAC *
ipsec_mb_flush_job(struct MB_MGR *mgr)
{
        struct JOB_AES_HMAC *job;

        job = _ipsec_mb_head_job(mgr);
        if (job) {
                SAVE_VEC_REGS(mgr);

                _ipsec_mb_do_complete_job(mgr, job);
                mgr->depth -= 1;

                RESTORE_VEC_REGS(mgr);
        }
        return job;
}

/*
 * init
 */
struct cpuid_regs {
        UINT32 eax;
        UINT32 ebx;
        UINT32 ecx;
        UINT32 edx;
};

/*
 * A C wrapper for CPUID opcode
 *
 * Parameters:
 *    [in] leaf    - CPUID leaf number (EAX)
 *    [in] subleaf - CPUID sub-leaf number (ECX)
 *    [out] out    - registers structure to store results of CPUID into
 */
static void
__mbcpuid(const unsigned leaf, const unsigned subleaf,
        struct cpuid_regs *out)
{
#ifdef _WIN32
        /* Windows */
        int regs[4];

        __cpuidex(regs, leaf, subleaf);
        out->eax = regs[0];
        out->ebx = regs[1];
        out->ecx = regs[2];
        out->edx = regs[3];
#else
        /* Linux */
#ifdef __x86_64__
        asm volatile("mov %4, %%eax\n\t"
                     "mov %5, %%ecx\n\t"
                     "cpuid\n\t"
                     "mov %%eax, %0\n\t"
                     "mov %%ebx, %1\n\t"
                     "mov %%ecx, %2\n\t"
                     "mov %%edx, %3\n\t"
                     : "=g" (out->eax), "=g" (out->ebx), "=g" (out->ecx),
                       "=g" (out->edx)
                     : "g" (leaf), "g" (subleaf)
                     : "%eax", "%ebx", "%ecx", "%edx");
#else
        asm volatile("push %%ebx\n\t"
                     "mov %4, %%eax\n\t"
                     "mov %5, %%ecx\n\t"
                     "cpuid\n\t"
                     "mov %%eax, %0\n\t"
                     "mov %%ebx, %1\n\t"
                     "mov %%ecx, %2\n\t"
                     "mov %%edx, %3\n\t"
                     "pop %%ebx\n\t"
                     : "=g" (out->eax), "=g" (out->ebx), "=g" (out->ecx),
                       "=g" (out->edx)
                     : "g" (leaf), "g" (subleaf)
                     : "%eax", "%ecx", "%edx");
#endif
#endif /* Linux */
}

/*
 * Uses CPUID instruction to detected presence of SHA extensions.
 *
 * Return value:
 *     0 - SHA extensions not present
 *     1 - SHA extensions present
 */
static inline int
sha_extensions_supported(void)
{
        struct cpuid_regs r;

        /* Check highest leaf number. If less then 7 then SHA not supported. */
        __mbcpuid(0x0, 0x0, &r);
        if (r.eax < 0x7)
                return 0;
        /* Check presence of SHA extensions in the extended feature flags */
        __mbcpuid(0x7, 0x0, &r);
        if (r.ebx & (1 << 29))
                return 1;
        return 0;
}

enum SHA_EXTENSION_USAGE sse_sha_ext_usage = SHA_EXT_DETECT;

void
init_mb_mgr_sse(struct MB_MGR *mgr)
{
#ifdef HASH_USE_SHAEXT
        switch (sse_sha_ext_usage) {
        case SHA_EXT_PRESENT:
                break;
        case SHA_EXT_NOT_PRESENT:
                break;
        case SHA_EXT_DETECT:
        default:
                if (sha_extensions_supported())
                        sse_sha_ext_usage = SHA_EXT_PRESENT;
                else
                        sse_sha_ext_usage = SHA_EXT_NOT_PRESENT;
                break;
        }
#endif /* HASH_USE_SHAEXT */

        _init_mb_mgr_sse(mgr, sse_sha_ext_usage);

        mgr->handler = job_task_handler_SSE;
#ifdef HASH_USE_SHAEXT
        if (sse_sha_ext_usage == SHA_EXT_PRESENT)
                mgr->handler = job_task_handler_SSE_SHANI;
#endif /* HASH_USE_SHAEXT */
}

void
init_mb_mgr_avx(struct MB_MGR *mgr)
{
        _init_mb_mgr_avx(mgr);
        mgr->handler = job_task_handler_AVX;
}

void
init_mb_mgr_avx2(struct MB_MGR *mgr)
{
        _init_mb_mgr_avx2(mgr);
        mgr->handler = job_task_handler_AVX2;
}

void
init_mb_mgr_avx512(struct MB_MGR *mgr)
{
        _init_mb_mgr_avx512(mgr);
        mgr->handler = job_task_handler_AVX512;
}
