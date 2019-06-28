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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AVX512
#include "intel-ipsec-mb.h"
#include "include/zuc_internal.h"

#include "save_xmms.h"
#include "asm.h"
#include "des.h"
#include "gcm.h"
#include "cpu_feature.h"
#include "noaesni.h"

JOB_AES_HMAC *submit_job_aes128_enc_avx(MB_MGR_AES_OOO *state,
                                        JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_aes128_enc_avx(MB_MGR_AES_OOO *state);

JOB_AES_HMAC *submit_job_aes192_enc_avx(MB_MGR_AES_OOO *state,
                                        JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_aes192_enc_avx(MB_MGR_AES_OOO *state);

JOB_AES_HMAC *submit_job_aes256_enc_avx(MB_MGR_AES_OOO *state,
                                        JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_aes256_enc_avx(MB_MGR_AES_OOO *state);

JOB_AES_HMAC *submit_job_aes_xcbc_avx(MB_MGR_AES_XCBC_OOO *state,
                                      JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_aes_xcbc_avx(MB_MGR_AES_XCBC_OOO *state);

JOB_AES_HMAC *submit_job_des_cbc_enc_avx512(MB_MGR_DES_OOO *state,
                                            JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_des_cbc_enc_avx512(MB_MGR_DES_OOO *state);

JOB_AES_HMAC *submit_job_des_cbc_dec_avx512(MB_MGR_DES_OOO *state,
                                            JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_des_cbc_dec_avx512(MB_MGR_DES_OOO *state);

JOB_AES_HMAC *submit_job_3des_cbc_enc_avx512(MB_MGR_DES_OOO *state,
                                             JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_3des_cbc_enc_avx512(MB_MGR_DES_OOO *state);

JOB_AES_HMAC *submit_job_3des_cbc_dec_avx512(MB_MGR_DES_OOO *state,
                                             JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_3des_cbc_dec_avx512(MB_MGR_DES_OOO *state);

JOB_AES_HMAC *submit_job_docsis_des_enc_avx512(MB_MGR_DES_OOO *state,
                                               JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_docsis_des_enc_avx512(MB_MGR_DES_OOO *state);

JOB_AES_HMAC *submit_job_docsis_des_dec_avx512(MB_MGR_DES_OOO *state,
                                               JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_docsis_des_dec_avx512(MB_MGR_DES_OOO *state);

JOB_AES_HMAC *submit_job_aes_cntr_avx(JOB_AES_HMAC *job);

#define SAVE_XMMS save_xmms_avx
#define RESTORE_XMMS restore_xmms_avx
#define SUBMIT_JOB_AES128_ENC submit_job_aes128_enc_avx
#define SUBMIT_JOB_AES128_DEC submit_job_aes128_dec_avx
#define FLUSH_JOB_AES128_ENC  flush_job_aes128_enc_avx

#define SUBMIT_JOB_AES192_ENC submit_job_aes192_enc_avx
#define SUBMIT_JOB_AES192_DEC submit_job_aes192_dec_avx
#define FLUSH_JOB_AES192_ENC  flush_job_aes192_enc_avx

#define SUBMIT_JOB_AES256_ENC submit_job_aes256_enc_avx
#define SUBMIT_JOB_AES256_DEC submit_job_aes256_dec_avx
#define FLUSH_JOB_AES256_ENC  flush_job_aes256_enc_avx

#define SUBMIT_JOB_AES_ECB_128_ENC submit_job_aes_ecb_128_enc_avx
#define SUBMIT_JOB_AES_ECB_128_DEC submit_job_aes_ecb_128_dec_avx
#define SUBMIT_JOB_AES_ECB_192_ENC submit_job_aes_ecb_192_enc_avx
#define SUBMIT_JOB_AES_ECB_192_DEC submit_job_aes_ecb_192_dec_avx
#define SUBMIT_JOB_AES_ECB_256_ENC submit_job_aes_ecb_256_enc_avx
#define SUBMIT_JOB_AES_ECB_256_DEC submit_job_aes_ecb_256_dec_avx

#define SUBMIT_JOB_AES_CNTR   submit_job_aes_cntr_avx512

#define AES_CBC_DEC_128       aes_cbc_dec_128_avx512
#define AES_CBC_DEC_192       aes_cbc_dec_192_avx512
#define AES_CBC_DEC_256       aes_cbc_dec_256_avx512

#define AES_CNTR_128       aes_cntr_128_avx
#define AES_CNTR_192       aes_cntr_192_avx
#define AES_CNTR_256       aes_cntr_256_avx
#define AES_CNTR_CCM_128   aes_cntr_ccm_128_avx

#define AES_ECB_ENC_128       aes_ecb_enc_128_avx
#define AES_ECB_ENC_192       aes_ecb_enc_192_avx
#define AES_ECB_ENC_256       aes_ecb_enc_256_avx
#define AES_ECB_DEC_128       aes_ecb_dec_128_avx
#define AES_ECB_DEC_192       aes_ecb_dec_192_avx
#define AES_ECB_DEC_256       aes_ecb_dec_256_avx

#define SUBMIT_JOB_PON_ENC submit_job_pon_enc_avx
#define SUBMIT_JOB_PON_DEC submit_job_pon_dec_avx

#define SUBMIT_JOB_AES_XCBC   submit_job_aes_xcbc_avx
#define FLUSH_JOB_AES_XCBC    flush_job_aes_xcbc_avx

#define SUBMIT_JOB_AES128_DEC submit_job_aes128_dec_avx
#define SUBMIT_JOB_AES192_DEC submit_job_aes192_dec_avx
#define SUBMIT_JOB_AES256_DEC submit_job_aes256_dec_avx

#define SUBMIT_JOB_DES_CBC_ENC submit_job_des_cbc_enc_avx512
#define FLUSH_JOB_DES_CBC_ENC  flush_job_des_cbc_enc_avx512

#define SUBMIT_JOB_DES_CBC_DEC submit_job_des_cbc_dec_avx512
#define FLUSH_JOB_DES_CBC_DEC flush_job_des_cbc_dec_avx512

#define SUBMIT_JOB_3DES_CBC_ENC submit_job_3des_cbc_enc_avx512
#define FLUSH_JOB_3DES_CBC_ENC  flush_job_3des_cbc_enc_avx512

#define SUBMIT_JOB_3DES_CBC_DEC submit_job_3des_cbc_dec_avx512
#define FLUSH_JOB_3DES_CBC_DEC flush_job_3des_cbc_dec_avx512

#define SUBMIT_JOB_DOCSIS_DES_ENC submit_job_docsis_des_enc_avx512
#define FLUSH_JOB_DOCSIS_DES_ENC  flush_job_docsis_des_enc_avx512

#define SUBMIT_JOB_DOCSIS_DES_DEC submit_job_docsis_des_dec_avx512
#define FLUSH_JOB_DOCSIS_DES_DEC flush_job_docsis_des_dec_avx512

#define SUBMIT_JOB_AES_ENC SUBMIT_JOB_AES_ENC_AVX512
#define FLUSH_JOB_AES_ENC  FLUSH_JOB_AES_ENC_AVX512
#define SUBMIT_JOB_AES_DEC SUBMIT_JOB_AES_DEC_AVX512

JOB_AES_HMAC *submit_job_hmac_avx512(MB_MGR_HMAC_SHA_1_OOO *state,
                                     JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_avx512(MB_MGR_HMAC_SHA_1_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sha_224_avx512(MB_MGR_HMAC_SHA_256_OOO *state,
                                             JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sha_224_avx512(MB_MGR_HMAC_SHA_256_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sha_256_avx512(MB_MGR_HMAC_SHA_256_OOO *state,
                                             JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sha_256_avx512(MB_MGR_HMAC_SHA_256_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sha_384_avx512(MB_MGR_HMAC_SHA_512_OOO *state,
                                             JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sha_384_avx512(MB_MGR_HMAC_SHA_512_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sha_512_avx512(MB_MGR_HMAC_SHA_512_OOO *state,
                                             JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sha_512_avx512(MB_MGR_HMAC_SHA_512_OOO *state);

JOB_AES_HMAC *submit_job_hmac_md5_avx2(MB_MGR_HMAC_MD5_OOO *state,
                                       JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_md5_avx2(MB_MGR_HMAC_MD5_OOO *state);

JOB_AES_HMAC *submit_job_aes_cmac_auth_avx(MB_MGR_CMAC_OOO *state,
                                           JOB_AES_HMAC *job);

JOB_AES_HMAC *flush_job_aes_cmac_auth_avx(MB_MGR_CMAC_OOO *state);

JOB_AES_HMAC *submit_job_aes_ccm_auth_avx(MB_MGR_CCM_OOO *state,
                                           JOB_AES_HMAC *job);

JOB_AES_HMAC *flush_job_aes_ccm_auth_avx(MB_MGR_CCM_OOO *state);

#define SUBMIT_JOB_HMAC               submit_job_hmac_avx512
#define FLUSH_JOB_HMAC                flush_job_hmac_avx512
#define SUBMIT_JOB_HMAC_SHA_224       submit_job_hmac_sha_224_avx512
#define FLUSH_JOB_HMAC_SHA_224        flush_job_hmac_sha_224_avx512
#define SUBMIT_JOB_HMAC_SHA_256       submit_job_hmac_sha_256_avx512
#define FLUSH_JOB_HMAC_SHA_256        flush_job_hmac_sha_256_avx512
#define SUBMIT_JOB_HMAC_SHA_384       submit_job_hmac_sha_384_avx512
#define FLUSH_JOB_HMAC_SHA_384        flush_job_hmac_sha_384_avx512
#define SUBMIT_JOB_HMAC_SHA_512       submit_job_hmac_sha_512_avx512
#define FLUSH_JOB_HMAC_SHA_512        flush_job_hmac_sha_512_avx512
#define SUBMIT_JOB_HMAC_MD5           submit_job_hmac_md5_avx2
#define FLUSH_JOB_HMAC_MD5            flush_job_hmac_md5_avx2

#ifndef NO_GCM
#define AES_GCM_DEC_128   aes_gcm_dec_128_avx512
#define AES_GCM_ENC_128   aes_gcm_enc_128_avx512
#define AES_GCM_DEC_192   aes_gcm_dec_192_avx512
#define AES_GCM_ENC_192   aes_gcm_enc_192_avx512
#define AES_GCM_DEC_256   aes_gcm_dec_256_avx512
#define AES_GCM_ENC_256   aes_gcm_enc_256_avx512

#define SUBMIT_JOB_AES_GCM_DEC submit_job_aes_gcm_dec_avx512
#define FLUSH_JOB_AES_GCM_DEC  flush_job_aes_gcm_dec_avx512
#define SUBMIT_JOB_AES_GCM_ENC submit_job_aes_gcm_enc_avx512
#define FLUSH_JOB_AES_GCM_ENC  flush_job_aes_gcm_enc_avx512
#endif /* NO_GCM */

/* ====================================================================== */

#define SUBMIT_JOB         submit_job_avx512
#define FLUSH_JOB          flush_job_avx512
#define QUEUE_SIZE         queue_size_avx512
#define SUBMIT_JOB_NOCHECK submit_job_nocheck_avx512
#define GET_NEXT_JOB       get_next_job_avx512
#define GET_COMPLETED_JOB  get_completed_job_avx512

/* ====================================================================== */

#define SUBMIT_JOB_HASH    SUBMIT_JOB_HASH_AVX512
#define FLUSH_JOB_HASH     FLUSH_JOB_HASH_AVX512

/* ====================================================================== */

#define AES_CFB_128_ONE    aes_cfb_128_one_avx512

void aes128_cbc_mac_x8(AES_ARGS *args, uint64_t len);

#define AES128_CBC_MAC     aes128_cbc_mac_x8

#define FLUSH_JOB_AES_CCM_AUTH     flush_job_aes_ccm_auth_avx
#define SUBMIT_JOB_AES_CCM_AUTH    submit_job_aes_ccm_auth_avx

#define FLUSH_JOB_AES_CMAC_AUTH    flush_job_aes_cmac_auth_avx
#define SUBMIT_JOB_AES_CMAC_AUTH   submit_job_aes_cmac_auth_avx

/* ====================================================================== */

/*
 * GCM submit / flush API for AVX512 arch
 */
#ifndef NO_GCM
static JOB_AES_HMAC *
plain_submit_gcm_dec_avx512(MB_MGR *state, JOB_AES_HMAC *job)
{
        DECLARE_ALIGNED(struct gcm_context_data ctx, 16);
        (void) state;

        if (16 == job->aes_key_len_in_bytes)
                AES_GCM_DEC_128(job->aes_dec_key_expanded, &ctx, job->dst,
                                job->src +
                                job->cipher_start_src_offset_in_bytes,
                                job->msg_len_to_cipher_in_bytes,
                                job->iv,
                                job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                                job->auth_tag_output,
                                job->auth_tag_output_len_in_bytes);
        else if (24 == job->aes_key_len_in_bytes)
                AES_GCM_DEC_192(job->aes_dec_key_expanded, &ctx, job->dst,
                                job->src +
                                job->cipher_start_src_offset_in_bytes,
                                job->msg_len_to_cipher_in_bytes,
                                job->iv,
                                job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                                job->auth_tag_output,
                                job->auth_tag_output_len_in_bytes);
        else /* assume 32 bytes */
                AES_GCM_DEC_256(job->aes_dec_key_expanded, &ctx, job->dst,
                                job->src +
                                job->cipher_start_src_offset_in_bytes,
                                job->msg_len_to_cipher_in_bytes,
                                job->iv,
                                job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                                job->auth_tag_output,
                                job->auth_tag_output_len_in_bytes);

        job->status = STS_COMPLETED;
        return job;
}

static JOB_AES_HMAC *
plain_flush_gcm_dec_avx512(MB_MGR *state, JOB_AES_HMAC *job)
{
        (void) state;
        (void) job;
        return NULL;
}

static JOB_AES_HMAC *
plain_submit_gcm_enc_avx512(MB_MGR *state, JOB_AES_HMAC *job)
{
        DECLARE_ALIGNED(struct gcm_context_data ctx, 16);
        (void) state;

        if (16 == job->aes_key_len_in_bytes)
                AES_GCM_ENC_128(job->aes_enc_key_expanded, &ctx, job->dst,
                                job->src +
                                job->cipher_start_src_offset_in_bytes,
                                job->msg_len_to_cipher_in_bytes, job->iv,
                                job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                                job->auth_tag_output,
                                job->auth_tag_output_len_in_bytes);
        else if (24 == job->aes_key_len_in_bytes)
                AES_GCM_ENC_192(job->aes_enc_key_expanded, &ctx, job->dst,
                                job->src +
                                job->cipher_start_src_offset_in_bytes,
                                job->msg_len_to_cipher_in_bytes, job->iv,
                                job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                                job->auth_tag_output,
                                job->auth_tag_output_len_in_bytes);
        else /* assume 32 bytes */
                AES_GCM_ENC_256(job->aes_enc_key_expanded, &ctx, job->dst,
                                job->src +
                                job->cipher_start_src_offset_in_bytes,
                                job->msg_len_to_cipher_in_bytes, job->iv,
                                job->u.GCM.aad, job->u.GCM.aad_len_in_bytes,
                                job->auth_tag_output,
                                job->auth_tag_output_len_in_bytes);

        job->status = STS_COMPLETED;
        return job;
}

static JOB_AES_HMAC *
plain_flush_gcm_enc_avx512(MB_MGR *state, JOB_AES_HMAC *job)
{
        (void) state;
        (void) job;
        return NULL;
}

static JOB_AES_HMAC *
vaes_submit_gcm_dec_avx512(MB_MGR *s, JOB_AES_HMAC *job)
{
        if (16 == job->aes_key_len_in_bytes)
                return aes_gcm_dec_128_submit_vaes_avx512(&s->gcm128_dec_ooo,
                                                          job);
        else if (24 == job->aes_key_len_in_bytes)
                return aes_gcm_dec_192_submit_vaes_avx512(&s->gcm192_dec_ooo,
                                                          job);
        else /* assume 32 bytes */
                return aes_gcm_dec_256_submit_vaes_avx512(&s->gcm256_dec_ooo,
                                                          job);
}

static JOB_AES_HMAC *
vaes_flush_gcm_dec_avx512(MB_MGR *s, JOB_AES_HMAC *job)
{
        if (16 == job->aes_key_len_in_bytes)
                return aes_gcm_dec_128_flush_vaes_avx512(&s->gcm128_dec_ooo);
        else if (24 == job->aes_key_len_in_bytes)
                return aes_gcm_dec_192_flush_vaes_avx512(&s->gcm192_dec_ooo);
        else /* assume 32 bytes */
                return aes_gcm_dec_256_flush_vaes_avx512(&s->gcm256_dec_ooo);
}

static JOB_AES_HMAC *
vaes_submit_gcm_enc_avx512(MB_MGR *s, JOB_AES_HMAC *job)
{
        if (16 == job->aes_key_len_in_bytes)
                return aes_gcm_enc_128_submit_vaes_avx512(&s->gcm128_enc_ooo,
                                                          job);
        else if (24 == job->aes_key_len_in_bytes)
                return aes_gcm_enc_192_submit_vaes_avx512(&s->gcm192_enc_ooo,
                                                          job);
        else /* assume 32 bytes */
                return aes_gcm_enc_256_submit_vaes_avx512(&s->gcm256_enc_ooo,
                                                          job);
}

static JOB_AES_HMAC *
vaes_flush_gcm_enc_avx512(MB_MGR *s, JOB_AES_HMAC *job)
{
        if (16 == job->aes_key_len_in_bytes)
                return aes_gcm_enc_128_flush_vaes_avx512(&s->gcm128_enc_ooo);
        else if (24 == job->aes_key_len_in_bytes)
                return aes_gcm_enc_192_flush_vaes_avx512(&s->gcm192_enc_ooo);
        else /* assume 32 bytes */
                return aes_gcm_enc_256_flush_vaes_avx512(&s->gcm256_enc_ooo);
}

static JOB_AES_HMAC *(*submit_job_aes_gcm_enc_avx512)
        (MB_MGR *state, JOB_AES_HMAC *job) = plain_submit_gcm_enc_avx512;
static JOB_AES_HMAC *(*flush_job_aes_gcm_enc_avx512)
        (MB_MGR *state, JOB_AES_HMAC *job) = plain_flush_gcm_enc_avx512;
static JOB_AES_HMAC *(*submit_job_aes_gcm_dec_avx512)
        (MB_MGR *state, JOB_AES_HMAC *job) = plain_submit_gcm_dec_avx512;
static JOB_AES_HMAC *(*flush_job_aes_gcm_dec_avx512)
        (MB_MGR *state, JOB_AES_HMAC *job) = plain_flush_gcm_dec_avx512;

#endif /* NO_GCM */

static JOB_AES_HMAC *(*submit_job_aes_cntr_avx512)
        (JOB_AES_HMAC *job) = submit_job_aes_cntr_avx;

static JOB_AES_HMAC *
vaes_submit_cntr_avx512(JOB_AES_HMAC *job)
{
        if (16 == job->aes_key_len_in_bytes)
                aes_cntr_128_submit_vaes_avx512(job);
        else if (24 == job->aes_key_len_in_bytes)
                aes_cntr_192_submit_vaes_avx512(job);
        else /* assume 32 bytes */
                aes_cntr_256_submit_vaes_avx512(job);

        job->status |= STS_COMPLETED_AES;
        return job;
}

/* ====================================================================== */

static void
(*aes_cbc_dec_128_avx512) (const void *in, const uint8_t *IV,
                           const void *keys, void *out,
                           uint64_t len_bytes) = aes_cbc_dec_128_avx;
static void
(*aes_cbc_dec_192_avx512) (const void *in, const uint8_t *IV,
                           const void *keys, void *out,
                           uint64_t len_bytes) = aes_cbc_dec_192_avx;
static void
(*aes_cbc_dec_256_avx512) (const void *in, const uint8_t *IV,
                           const void *keys, void *out,
                           uint64_t len_bytes) = aes_cbc_dec_256_avx;

void
init_mb_mgr_avx512(MB_MGR *state)
{
        unsigned int j;
        uint8_t *p;
        size_t size;

        state->features = cpu_feature_adjust(state->flags,
                                             cpu_feature_detect());

        if (!(state->features & IMB_FEATURE_AESNI)) {
                init_mb_mgr_sse_no_aesni(state);
                return;
        }
        if ((state->features & IMB_FEATURE_VAES) == IMB_FEATURE_VAES) {
                aes_cbc_dec_128_avx512 = aes_cbc_dec_128_vaes_avx512;
                aes_cbc_dec_192_avx512 = aes_cbc_dec_192_vaes_avx512;
                aes_cbc_dec_256_avx512 = aes_cbc_dec_256_vaes_avx512;
        }

        /* Init AES out-of-order fields */
        memset(state->aes128_ooo.lens, 0xFF,
               sizeof(state->aes128_ooo.lens));
        memset(&state->aes128_ooo.lens[0], 0,
               sizeof(state->aes128_ooo.lens[0]) * 8);
        memset(state->aes128_ooo.job_in_lane, 0,
               sizeof(state->aes128_ooo.job_in_lane));
        state->aes128_ooo.unused_lanes = 0xF76543210;
        state->aes128_ooo.num_lanes_inuse = 0;

        memset(state->aes192_ooo.lens, 0xFF,
               sizeof(state->aes192_ooo.lens));
        memset(&state->aes192_ooo.lens[0], 0,
               sizeof(state->aes192_ooo.lens[0]) * 8);
        memset(state->aes192_ooo.job_in_lane, 0,
               sizeof(state->aes192_ooo.job_in_lane));
        state->aes192_ooo.unused_lanes = 0xF76543210;
        state->aes192_ooo.num_lanes_inuse = 0;

        memset(&state->aes256_ooo.lens, 0xFF,
               sizeof(state->aes256_ooo.lens));
        memset(&state->aes256_ooo.lens[0], 0,
               sizeof(state->aes256_ooo.lens[0]) * 8);
        memset(state->aes256_ooo.job_in_lane, 0,
               sizeof(state->aes256_ooo.job_in_lane));
        state->aes256_ooo.unused_lanes = 0xF76543210;
        state->aes256_ooo.num_lanes_inuse = 0;

        /* DOCSIS SEC BPI (AES CBC + AES CFB for partial block)
         * uses same settings as AES128 CBC.
         */
        memset(state->docsis_sec_ooo.lens, 0xFF,
               sizeof(state->docsis_sec_ooo.lens));
        memset(&state->docsis_sec_ooo.lens[0], 0,
               sizeof(state->docsis_sec_ooo.lens[0]) * 8);
        memset(state->docsis_sec_ooo.job_in_lane, 0,
               sizeof(state->docsis_sec_ooo.job_in_lane));
        state->docsis_sec_ooo.unused_lanes = 0xF76543210;
        state->docsis_sec_ooo.num_lanes_inuse = 0;


        /* DES, 3DES and DOCSIS DES (DES CBC + DES CFB for partial block) */
        /* - separate DES OOO for encryption */
        for (j = 0; j < AVX512_NUM_DES_LANES; j++) {
                state->des_enc_ooo.lens[j] = 0;
                state->des_enc_ooo.job_in_lane[j] = NULL;
        }
        state->des_enc_ooo.unused_lanes = 0xFEDCBA9876543210;
        state->des_enc_ooo.num_lanes_inuse = 0;
        memset(&state->des_enc_ooo.args, 0, sizeof(state->des_enc_ooo.args));

        /* - separate DES OOO for decryption */
        for (j = 0; j < AVX512_NUM_DES_LANES; j++) {
                state->des_dec_ooo.lens[j] = 0;
                state->des_dec_ooo.job_in_lane[j] = NULL;
        }
        state->des_dec_ooo.unused_lanes = 0xFEDCBA9876543210;
        state->des_dec_ooo.num_lanes_inuse = 0;
        memset(&state->des_dec_ooo.args, 0, sizeof(state->des_dec_ooo.args));

        /* - separate 3DES OOO for encryption */
        for (j = 0; j < AVX512_NUM_DES_LANES; j++) {
                state->des3_enc_ooo.lens[j] = 0;
                state->des3_enc_ooo.job_in_lane[j] = NULL;
        }
        state->des3_enc_ooo.unused_lanes = 0xFEDCBA9876543210;
        state->des3_enc_ooo.num_lanes_inuse = 0;
        memset(&state->des3_enc_ooo.args, 0, sizeof(state->des3_enc_ooo.args));

        /* - separate 3DES OOO for decryption */
        for (j = 0; j < AVX512_NUM_DES_LANES; j++) {
                state->des3_dec_ooo.lens[j] = 0;
                state->des3_dec_ooo.job_in_lane[j] = NULL;
        }
        state->des3_dec_ooo.unused_lanes = 0xFEDCBA9876543210;
        state->des3_dec_ooo.num_lanes_inuse = 0;
        memset(&state->des3_dec_ooo.args, 0, sizeof(state->des3_dec_ooo.args));

        /* - separate DOCSIS DES OOO for encryption */
        for (j = 0; j < AVX512_NUM_DES_LANES; j++) {
                state->docsis_des_enc_ooo.lens[j] = 0;
                state->docsis_des_enc_ooo.job_in_lane[j] = NULL;
        }
        state->docsis_des_enc_ooo.unused_lanes = 0xFEDCBA9876543210;
        state->docsis_des_enc_ooo.num_lanes_inuse = 0;
        memset(&state->docsis_des_enc_ooo.args, 0,
               sizeof(state->docsis_des_enc_ooo.args));

        /* - separate DES OOO for decryption */
        for (j = 0; j < AVX512_NUM_DES_LANES; j++) {
                state->docsis_des_dec_ooo.lens[j] = 0;
                state->docsis_des_dec_ooo.job_in_lane[j] = NULL;
        }
        state->docsis_des_dec_ooo.unused_lanes = 0xFEDCBA9876543210;
        state->docsis_des_dec_ooo.num_lanes_inuse = 0;
        memset(&state->docsis_des_dec_ooo.args, 0,
               sizeof(state->docsis_des_dec_ooo.args));

        /* Init HMAC/SHA1 out-of-order fields */
        state->hmac_sha_1_ooo.lens[0] = 0;
        state->hmac_sha_1_ooo.lens[1] = 0;
        state->hmac_sha_1_ooo.lens[2] = 0;
        state->hmac_sha_1_ooo.lens[3] = 0;
        state->hmac_sha_1_ooo.lens[4] = 0;
        state->hmac_sha_1_ooo.lens[5] = 0;
        state->hmac_sha_1_ooo.lens[6] = 0;
        state->hmac_sha_1_ooo.lens[7] = 0;
        state->hmac_sha_1_ooo.lens[8] = 0;
        state->hmac_sha_1_ooo.lens[9] = 0;
        state->hmac_sha_1_ooo.lens[10] = 0;
        state->hmac_sha_1_ooo.lens[11] = 0;
        state->hmac_sha_1_ooo.lens[12] = 0;
        state->hmac_sha_1_ooo.lens[13] = 0;
        state->hmac_sha_1_ooo.lens[14] = 0;
        state->hmac_sha_1_ooo.lens[15] = 0;
        state->hmac_sha_1_ooo.unused_lanes = 0xFEDCBA9876543210;
        state->hmac_sha_1_ooo.num_lanes_inuse = 0;
        for (j = 0; j < AVX512_NUM_SHA1_LANES; j++) {
                state->hmac_sha_1_ooo.ldata[j].job_in_lane = NULL;
                state->hmac_sha_1_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->hmac_sha_1_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64 + 7);
                p = state->hmac_sha_1_ooo.ldata[j].outer_block;
                memset(p + 5*4 + 1,
                       0x00,
                       64 - 5*4 - 1 - 2);
                p[5 * 4] = 0x80;
                p[64 - 2] = 0x02;
                p[64 - 1] = 0xA0;
        }

        /* Init HMAC/SHA224 out-of-order fields */
        state->hmac_sha_224_ooo.lens[0] = 0;
        state->hmac_sha_224_ooo.lens[1] = 0;
        state->hmac_sha_224_ooo.lens[2] = 0;
        state->hmac_sha_224_ooo.lens[3] = 0;
        state->hmac_sha_224_ooo.lens[4] = 0;
        state->hmac_sha_224_ooo.lens[5] = 0;
        state->hmac_sha_224_ooo.lens[6] = 0;
        state->hmac_sha_224_ooo.lens[7] = 0;
        state->hmac_sha_224_ooo.lens[8] = 0;
        state->hmac_sha_224_ooo.lens[9] = 0;
        state->hmac_sha_224_ooo.lens[10] = 0;
        state->hmac_sha_224_ooo.lens[11] = 0;
        state->hmac_sha_224_ooo.lens[12] = 0;
        state->hmac_sha_224_ooo.lens[13] = 0;
        state->hmac_sha_224_ooo.lens[14] = 0;
        state->hmac_sha_224_ooo.lens[15] = 0;
        state->hmac_sha_224_ooo.unused_lanes = 0xFEDCBA9876543210;
        state->hmac_sha_224_ooo.num_lanes_inuse = 0;
        /* sha256 and sha224 are very similar except for
         * digest constants and output size
         */
        for (j = 0; j < AVX512_NUM_SHA256_LANES; j++) {
                state->hmac_sha_224_ooo.ldata[j].job_in_lane = NULL;

                p = state->hmac_sha_224_ooo.ldata[j].extra_block;
                size = sizeof(state->hmac_sha_224_ooo.ldata[j].extra_block);
                memset (p, 0x00, size);
                p[64] = 0x80;

                p = state->hmac_sha_224_ooo.ldata[j].outer_block;
                size = sizeof(state->hmac_sha_224_ooo.ldata[j].outer_block);
                memset(p, 0x00, size);
                p[7 * 4] = 0x80;  /* digest 7 words long */
                p[64 - 2] = 0x02; /* length in little endian = 0x02E0 */
                p[64 - 1] = 0xE0;
        }

        /* Init HMAC/SHA256 out-of-order fields */
        state->hmac_sha_256_ooo.lens[0] = 0;
        state->hmac_sha_256_ooo.lens[1] = 0;
        state->hmac_sha_256_ooo.lens[2] = 0;
        state->hmac_sha_256_ooo.lens[3] = 0;
        state->hmac_sha_256_ooo.lens[4] = 0;
        state->hmac_sha_256_ooo.lens[5] = 0;
        state->hmac_sha_256_ooo.lens[6] = 0;
        state->hmac_sha_256_ooo.lens[7] = 0;
        state->hmac_sha_256_ooo.lens[8] = 0;
        state->hmac_sha_256_ooo.lens[9] = 0;
        state->hmac_sha_256_ooo.lens[10] = 0;
        state->hmac_sha_256_ooo.lens[11] = 0;
        state->hmac_sha_256_ooo.lens[12] = 0;
        state->hmac_sha_256_ooo.lens[13] = 0;
        state->hmac_sha_256_ooo.lens[14] = 0;
        state->hmac_sha_256_ooo.lens[15] = 0;
        state->hmac_sha_256_ooo.unused_lanes = 0xFEDCBA9876543210;
        state->hmac_sha_256_ooo.num_lanes_inuse = 0;
        for (j = 0; j < AVX512_NUM_SHA256_LANES; j++) {
                state->hmac_sha_256_ooo.ldata[j].job_in_lane = NULL;
                state->hmac_sha_256_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->hmac_sha_256_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64 + 7);
                /* hmac related */
                p = state->hmac_sha_256_ooo.ldata[j].outer_block;
                memset(p + 8*4 + 1,
                       0x00,
                       64 - 8*4 - 1 - 2);
                p[8 * 4] = 0x80;  /* 8 digest words */
                p[64 - 2] = 0x03; /* length */
                p[64 - 1] = 0x00;
        }

        /* Init HMAC/SHA384 out-of-order fields */
        state->hmac_sha_384_ooo.lens[0] = 0;
        state->hmac_sha_384_ooo.lens[1] = 0;
        state->hmac_sha_384_ooo.lens[2] = 0;
        state->hmac_sha_384_ooo.lens[3] = 0;
        state->hmac_sha_384_ooo.lens[4] = 0;
        state->hmac_sha_384_ooo.lens[5] = 0;
        state->hmac_sha_384_ooo.lens[6] = 0;
        state->hmac_sha_384_ooo.lens[7] = 0;
        state->hmac_sha_384_ooo.unused_lanes = 0xF76543210;
        for (j = 0; j < AVX512_NUM_SHA512_LANES; j++) {
                MB_MGR_HMAC_SHA_512_OOO *ctx = &state->hmac_sha_384_ooo;

                ctx->ldata[j].job_in_lane = NULL;
                ctx->ldata[j].extra_block[SHA_384_BLOCK_SIZE] = 0x80;
                memset(ctx->ldata[j].extra_block + (SHA_384_BLOCK_SIZE + 1),
                       0x00, SHA_384_BLOCK_SIZE + 7);
                p = ctx->ldata[j].outer_block;
                /* special end point because this length is constant */
                memset(p + SHA384_DIGEST_SIZE_IN_BYTES  + 1, 0x00,
                       SHA_384_BLOCK_SIZE -
                       SHA384_DIGEST_SIZE_IN_BYTES  - 1 - 2);
                /* mark the end */
                p[SHA384_DIGEST_SIZE_IN_BYTES] = 0x80;
                /* hmac outer block length always of fixed size,
                 * it is OKey length, a whole message block length, 1024 bits,
                 * with padding plus the length of the inner digest,
                 * which is 384 bits, 1408 bits == 0x0580.
                 * The input message block needs to be converted to big endian
                 * within the sha implementation before use.
                 */
                p[SHA_384_BLOCK_SIZE - 2] = 0x05;
                p[SHA_384_BLOCK_SIZE - 1] = 0x80;
        }

        /* Init HMAC/SHA512 out-of-order fields */
        state->hmac_sha_512_ooo.lens[0] = 0;
        state->hmac_sha_512_ooo.lens[1] = 0;
        state->hmac_sha_512_ooo.lens[2] = 0;
        state->hmac_sha_512_ooo.lens[3] = 0;
        state->hmac_sha_512_ooo.lens[4] = 0;
        state->hmac_sha_512_ooo.lens[5] = 0;
        state->hmac_sha_512_ooo.lens[6] = 0;
        state->hmac_sha_512_ooo.lens[7] = 0;
        state->hmac_sha_512_ooo.unused_lanes = 0xF76543210;
        for (j = 0; j < AVX512_NUM_SHA512_LANES; j++) {
                MB_MGR_HMAC_SHA_512_OOO *ctx = &state->hmac_sha_512_ooo;

                ctx->ldata[j].job_in_lane = NULL;
                ctx->ldata[j].extra_block[SHA_512_BLOCK_SIZE] = 0x80;
                memset(ctx->ldata[j].extra_block + (SHA_512_BLOCK_SIZE + 1),
                       0x00, SHA_512_BLOCK_SIZE + 7);
                p = ctx->ldata[j].outer_block;
                /* special end point because this length is constant */
                memset(p + SHA512_DIGEST_SIZE_IN_BYTES  + 1, 0x00,
                       SHA_512_BLOCK_SIZE -
                       SHA512_DIGEST_SIZE_IN_BYTES  - 1 - 2);
                /* mark the end */
                p[SHA512_DIGEST_SIZE_IN_BYTES] = 0x80;
                /* hmac outer block length always of fixed size,
                 * it is OKey length, a whole message block length, 1024 bits,
                 * with padding plus the length of the inner digest,
                 * which is 512 bits, 1536 bits == 0x600.
                 * The input message block needs to be converted to big endian
                 * within the sha implementation before use.
                 */
                p[SHA_512_BLOCK_SIZE - 2] = 0x06;
                p[SHA_512_BLOCK_SIZE - 1] = 0x00;
        }

        /* Init HMAC/MD5 out-of-order fields */
        state->hmac_md5_ooo.lens[0] = 0;
        state->hmac_md5_ooo.lens[1] = 0;
        state->hmac_md5_ooo.lens[2] = 0;
        state->hmac_md5_ooo.lens[3] = 0;
        state->hmac_md5_ooo.lens[4] = 0;
        state->hmac_md5_ooo.lens[5] = 0;
        state->hmac_md5_ooo.lens[6] = 0;
        state->hmac_md5_ooo.lens[7] = 0;
        state->hmac_md5_ooo.lens[8] = 0;
        state->hmac_md5_ooo.lens[9] = 0;
        state->hmac_md5_ooo.lens[10] = 0;
        state->hmac_md5_ooo.lens[11] = 0;
        state->hmac_md5_ooo.lens[12] = 0;
        state->hmac_md5_ooo.lens[13] = 0;
        state->hmac_md5_ooo.lens[14] = 0;
        state->hmac_md5_ooo.lens[15] = 0;
        state->hmac_md5_ooo.unused_lanes = 0xFEDCBA9876543210;
        state->hmac_md5_ooo.num_lanes_inuse = 0;
        for (j = 0; j < AVX512_NUM_MD5_LANES; j++) {
                state->hmac_md5_ooo.ldata[j].job_in_lane = NULL;

                p = state->hmac_md5_ooo.ldata[j].extra_block;
                size = sizeof(state->hmac_md5_ooo.ldata[j].extra_block);
                memset (p, 0x00, size);
                p[64] = 0x80;

                p = state->hmac_md5_ooo.ldata[j].outer_block;
                size = sizeof(state->hmac_md5_ooo.ldata[j].outer_block);
                memset(p, 0x00, size);
                p[4 * 4] = 0x80;
                p[64 - 7] = 0x02;
                p[64 - 8] = 0x80;
        }

        /* Init AES/XCBC OOO fields */
        state->aes_xcbc_ooo.lens[0] = 0;
        state->aes_xcbc_ooo.lens[1] = 0;
        state->aes_xcbc_ooo.lens[2] = 0;
        state->aes_xcbc_ooo.lens[3] = 0;
        state->aes_xcbc_ooo.lens[4] = 0;
        state->aes_xcbc_ooo.lens[5] = 0;
        state->aes_xcbc_ooo.lens[6] = 0;
        state->aes_xcbc_ooo.lens[7] = 0;
        state->aes_xcbc_ooo.unused_lanes = 0xF76543210;
        for (j = 0; j < 8 ; j++) {
                state->aes_xcbc_ooo.ldata[j].job_in_lane = NULL;
                state->aes_xcbc_ooo.ldata[j].final_block[16] = 0x80;
                memset(state->aes_xcbc_ooo.ldata[j].final_block + 17, 0x00, 15);
        }

        /* Init AES-CCM auth out-of-order fields */
        for (j = 0; j < 8; j++) {
                state->aes_ccm_ooo.init_done[j] = 0;
                state->aes_ccm_ooo.lens[j] = 0;
                state->aes_ccm_ooo.job_in_lane[j] = NULL;
        }
        state->aes_ccm_ooo.unused_lanes = 0xF76543210;

        /* Init AES-CMAC auth out-of-order fields */
        for (j = 0; j < 8; j++) {
                state->aes_cmac_ooo.init_done[j] = 0;
                state->aes_cmac_ooo.lens[j] = 0;
                state->aes_cmac_ooo.job_in_lane[j] = NULL;
        }
        state->aes_cmac_ooo.unused_lanes = 0xF76543210;

#ifndef NO_GCM
        /* init GCM MB manager in case VAES & VPCLMULQDQ are detected */
        for (j = 0; j < 4; j++) {
                state->gcm128_enc_ooo.lens[j] = 0;
                state->gcm128_enc_ooo.job_in_lane[j] = NULL;
                state->gcm128_enc_ooo.args.ctx[j] =
                        &state->gcm128_enc_ooo.ctxs[j];

                state->gcm192_enc_ooo.lens[j] = 0;
                state->gcm192_enc_ooo.job_in_lane[j] = NULL;
                state->gcm192_enc_ooo.args.ctx[j] =
                        &state->gcm192_enc_ooo.ctxs[j];

                state->gcm256_enc_ooo.lens[j] = 0;
                state->gcm256_enc_ooo.job_in_lane[j] = NULL;
                state->gcm256_enc_ooo.args.ctx[j] =
                        &state->gcm256_enc_ooo.ctxs[j];

                state->gcm128_dec_ooo.lens[j] = 0;
                state->gcm128_dec_ooo.job_in_lane[j] = NULL;
                state->gcm128_dec_ooo.args.ctx[j] =
                        &state->gcm128_dec_ooo.ctxs[j];

                state->gcm192_dec_ooo.lens[j] = 0;
                state->gcm192_dec_ooo.job_in_lane[j] = NULL;
                state->gcm192_dec_ooo.args.ctx[j] =
                        &state->gcm192_dec_ooo.ctxs[j];

                state->gcm256_dec_ooo.lens[j] = 0;
                state->gcm256_dec_ooo.job_in_lane[j] = NULL;
                state->gcm256_dec_ooo.args.ctx[j] =
                        &state->gcm256_dec_ooo.ctxs[j];
        }
        state->gcm128_enc_ooo.unused_lanes = 0xF3210;
        state->gcm192_enc_ooo.unused_lanes = 0xF3210;
        state->gcm256_enc_ooo.unused_lanes = 0xF3210;
        state->gcm128_dec_ooo.unused_lanes = 0xF3210;
        state->gcm192_dec_ooo.unused_lanes = 0xF3210;
        state->gcm256_dec_ooo.unused_lanes = 0xF3210;

#endif /* NO_GCM */

        /* Init "in order" components */
        state->next_job = 0;
        state->earliest_job = -1;

        /* set handlers */
        state->get_next_job        = get_next_job_avx512;
        state->submit_job          = submit_job_avx512;
        state->submit_job_nocheck  = submit_job_nocheck_avx512;
        state->get_completed_job   = get_completed_job_avx512;
        state->flush_job           = flush_job_avx512;
        state->queue_size          = queue_size_avx512;
        state->keyexp_128          = aes_keyexp_128_avx512;
        state->keyexp_192          = aes_keyexp_192_avx512;
        state->keyexp_256          = aes_keyexp_256_avx512;
        state->cmac_subkey_gen_128 = aes_cmac_subkey_gen_avx512;
        state->xcbc_keyexp         = aes_xcbc_expand_key_avx512;
        state->des_key_sched       = des_key_schedule;
        state->sha1_one_block      = sha1_one_block_avx512;
        state->sha1                = sha1_avx512;
        state->sha224_one_block    = sha224_one_block_avx512;
        state->sha224              = sha224_avx512;
        state->sha256_one_block    = sha256_one_block_avx512;
        state->sha256              = sha256_avx512;
        state->sha384_one_block    = sha384_one_block_avx512;
        state->sha384              = sha384_avx512;
        state->sha512_one_block    = sha512_one_block_avx512;
        state->sha512              = sha512_avx512;
        state->md5_one_block       = md5_one_block_avx512;
        state->aes128_cfb_one      = aes_cfb_128_one_avx512;

        state->eea3_1_buffer       = zuc_eea3_1_buffer_avx;
        state->eea3_4_buffer       = zuc_eea3_4_buffer_avx;
        state->eea3_n_buffer       = zuc_eea3_n_buffer_avx;
        state->eia3_1_buffer       = zuc_eia3_1_buffer_avx;

        if ((state->features & IMB_FEATURE_VAES) == IMB_FEATURE_VAES)
                submit_job_aes_cntr_avx512 = vaes_submit_cntr_avx512;
#ifndef NO_GCM
        if ((state->features & (IMB_FEATURE_VAES | IMB_FEATURE_VPCLMULQDQ)) ==
            (IMB_FEATURE_VAES | IMB_FEATURE_VPCLMULQDQ)) {
                state->gcm128_enc          = aes_gcm_enc_128_vaes_avx512;
                state->gcm192_enc          = aes_gcm_enc_192_vaes_avx512;
                state->gcm256_enc          = aes_gcm_enc_256_vaes_avx512;
                state->gcm128_dec          = aes_gcm_dec_128_vaes_avx512;
                state->gcm192_dec          = aes_gcm_dec_192_vaes_avx512;
                state->gcm256_dec          = aes_gcm_dec_256_vaes_avx512;
                state->gcm128_init         = aes_gcm_init_128_vaes_avx512;
                state->gcm192_init         = aes_gcm_init_192_vaes_avx512;
                state->gcm256_init         = aes_gcm_init_256_vaes_avx512;
                state->gcm128_enc_update   = aes_gcm_enc_128_update_vaes_avx512;
                state->gcm192_enc_update   = aes_gcm_enc_192_update_vaes_avx512;
                state->gcm256_enc_update   = aes_gcm_enc_256_update_vaes_avx512;
                state->gcm128_dec_update   = aes_gcm_dec_128_update_vaes_avx512;
                state->gcm192_dec_update   = aes_gcm_dec_192_update_vaes_avx512;
                state->gcm256_dec_update   = aes_gcm_dec_256_update_vaes_avx512;
                state->gcm128_enc_finalize =
                        aes_gcm_enc_128_finalize_vaes_avx512;
                state->gcm192_enc_finalize =
                        aes_gcm_enc_192_finalize_vaes_avx512;
                state->gcm256_enc_finalize =
                        aes_gcm_enc_256_finalize_vaes_avx512;
                state->gcm128_dec_finalize =
                        aes_gcm_dec_128_finalize_vaes_avx512;
                state->gcm192_dec_finalize =
                        aes_gcm_dec_192_finalize_vaes_avx512;
                state->gcm256_dec_finalize =
                        aes_gcm_dec_256_finalize_vaes_avx512;
                state->gcm128_precomp      = aes_gcm_precomp_128_vaes_avx512;
                state->gcm192_precomp      = aes_gcm_precomp_192_vaes_avx512;
                state->gcm256_precomp      = aes_gcm_precomp_256_vaes_avx512;
                state->gcm128_pre          = aes_gcm_pre_128_vaes_avx512;
                state->gcm192_pre          = aes_gcm_pre_192_vaes_avx512;
                state->gcm256_pre          = aes_gcm_pre_256_vaes_avx512;

                submit_job_aes_gcm_enc_avx512 = vaes_submit_gcm_enc_avx512;
                flush_job_aes_gcm_enc_avx512  = vaes_flush_gcm_enc_avx512;
                submit_job_aes_gcm_dec_avx512 = vaes_submit_gcm_dec_avx512;
                flush_job_aes_gcm_dec_avx512  = vaes_flush_gcm_dec_avx512;
        } else {
                state->gcm128_enc          = aes_gcm_enc_128_avx512;
                state->gcm192_enc          = aes_gcm_enc_192_avx512;
                state->gcm256_enc          = aes_gcm_enc_256_avx512;
                state->gcm128_dec          = aes_gcm_dec_128_avx512;
                state->gcm192_dec          = aes_gcm_dec_192_avx512;
                state->gcm256_dec          = aes_gcm_dec_256_avx512;
                state->gcm128_init         = aes_gcm_init_128_avx512;
                state->gcm192_init         = aes_gcm_init_192_avx512;
                state->gcm256_init         = aes_gcm_init_256_avx512;
                state->gcm128_enc_update   = aes_gcm_enc_128_update_avx512;
                state->gcm192_enc_update   = aes_gcm_enc_192_update_avx512;
                state->gcm256_enc_update   = aes_gcm_enc_256_update_avx512;
                state->gcm128_dec_update   = aes_gcm_dec_128_update_avx512;
                state->gcm192_dec_update   = aes_gcm_dec_192_update_avx512;
                state->gcm256_dec_update   = aes_gcm_dec_256_update_avx512;
                state->gcm128_enc_finalize = aes_gcm_enc_128_finalize_avx512;
                state->gcm192_enc_finalize = aes_gcm_enc_192_finalize_avx512;
                state->gcm256_enc_finalize = aes_gcm_enc_256_finalize_avx512;
                state->gcm128_dec_finalize = aes_gcm_dec_128_finalize_avx512;
                state->gcm192_dec_finalize = aes_gcm_dec_192_finalize_avx512;
                state->gcm256_dec_finalize = aes_gcm_dec_256_finalize_avx512;
                state->gcm128_precomp      = aes_gcm_precomp_128_avx512;
                state->gcm192_precomp      = aes_gcm_precomp_192_avx512;
                state->gcm256_precomp      = aes_gcm_precomp_256_avx512;
                state->gcm128_pre          = aes_gcm_pre_128_avx512;
                state->gcm192_pre          = aes_gcm_pre_192_avx512;
                state->gcm256_pre          = aes_gcm_pre_256_avx512;
        }
#endif
}

#include "mb_mgr_code.h"
