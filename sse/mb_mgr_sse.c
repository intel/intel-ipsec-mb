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

#define CLEAR_SCRATCH_SIMD_REGS clear_scratch_xmms_sse

#include "intel-ipsec-mb.h"
#include "include/kasumi_internal.h"
#include "include/zuc_internal.h"
#include "include/snow3g.h"
#include "include/gcm.h"

#include "save_xmms.h"
#include "asm.h"
#include "include/des.h"
#include "cpu_feature.h"
#include "noaesni.h"

JOB_AES_HMAC *submit_job_aes128_enc_sse(MB_MGR_AES_OOO *state,
                                        JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_aes128_enc_sse(MB_MGR_AES_OOO *state);

JOB_AES_HMAC *submit_job_aes192_enc_sse(MB_MGR_AES_OOO *state,
                                        JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_aes192_enc_sse(MB_MGR_AES_OOO *state);

JOB_AES_HMAC *submit_job_aes256_enc_sse(MB_MGR_AES_OOO *state,
                                        JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_aes256_enc_sse(MB_MGR_AES_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sse(MB_MGR_HMAC_SHA_1_OOO *state,
                                  JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sse(MB_MGR_HMAC_SHA_1_OOO *state);

JOB_AES_HMAC *submit_job_hmac_ni_sse(MB_MGR_HMAC_SHA_1_OOO *state,
                                     JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_ni_sse(MB_MGR_HMAC_SHA_1_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sha_224_sse(MB_MGR_HMAC_SHA_256_OOO *state,
                                          JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sha_224_sse(MB_MGR_HMAC_SHA_256_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sha_224_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state,
                                             JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sha_224_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sha_256_sse(MB_MGR_HMAC_SHA_256_OOO *state,
                                          JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sha_256_sse(MB_MGR_HMAC_SHA_256_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sha_256_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state,
                                             JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sha_256_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sha_384_sse(MB_MGR_HMAC_SHA_512_OOO *state,
                                          JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sha_384_sse(MB_MGR_HMAC_SHA_512_OOO *state);

JOB_AES_HMAC *submit_job_hmac_sha_512_sse(MB_MGR_HMAC_SHA_512_OOO *state,
                                          JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_sha_512_sse(MB_MGR_HMAC_SHA_512_OOO *state);

JOB_AES_HMAC *submit_job_hmac_md5_sse(MB_MGR_HMAC_MD5_OOO *state,
                                      JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_hmac_md5_sse(MB_MGR_HMAC_MD5_OOO *state);


JOB_AES_HMAC *submit_job_aes_xcbc_sse(MB_MGR_AES_XCBC_OOO *state,
                                      JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_aes_xcbc_sse(MB_MGR_AES_XCBC_OOO *state);

JOB_AES_HMAC *submit_job_aes_cmac_auth_sse(MB_MGR_CMAC_OOO *state,
                                           JOB_AES_HMAC *job);

JOB_AES_HMAC *flush_job_aes_cmac_auth_sse(MB_MGR_CMAC_OOO *state);

JOB_AES_HMAC *submit_job_aes_ccm_auth_sse(MB_MGR_CCM_OOO *state,
                                           JOB_AES_HMAC *job);

JOB_AES_HMAC *flush_job_aes_ccm_auth_sse(MB_MGR_CCM_OOO *state);

JOB_AES_HMAC *submit_job_aes_cntr_sse(JOB_AES_HMAC *job);

JOB_AES_HMAC *submit_job_aes_cntr_bit_sse(JOB_AES_HMAC *job);

JOB_AES_HMAC *submit_job_zuc_eea3_sse(MB_MGR_ZUC_OOO *state,
                                        JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_zuc_eea3_sse(MB_MGR_ZUC_OOO *state);

JOB_AES_HMAC *submit_job_zuc_eia3_sse(MB_MGR_ZUC_OOO *state,
                                        JOB_AES_HMAC *job);
JOB_AES_HMAC *flush_job_zuc_eia3_sse(MB_MGR_ZUC_OOO *state);

#define SAVE_XMMS               save_xmms
#define RESTORE_XMMS            restore_xmms

#define SUBMIT_JOB_AES128_ENC submit_job_aes128_enc_sse
#define SUBMIT_JOB_AES128_DEC submit_job_aes128_dec_sse
#define FLUSH_JOB_AES128_ENC  flush_job_aes128_enc_sse
#define SUBMIT_JOB_AES192_ENC submit_job_aes192_enc_sse
#define SUBMIT_JOB_AES192_DEC submit_job_aes192_dec_sse
#define FLUSH_JOB_AES192_ENC  flush_job_aes192_enc_sse
#define SUBMIT_JOB_AES256_ENC submit_job_aes256_enc_sse
#define SUBMIT_JOB_AES256_DEC submit_job_aes256_dec_sse
#define FLUSH_JOB_AES256_ENC  flush_job_aes256_enc_sse
#define SUBMIT_JOB_AES_ECB_128_ENC submit_job_aes_ecb_128_enc_sse
#define SUBMIT_JOB_AES_ECB_128_DEC submit_job_aes_ecb_128_dec_sse
#define SUBMIT_JOB_AES_ECB_192_ENC submit_job_aes_ecb_192_enc_sse
#define SUBMIT_JOB_AES_ECB_192_DEC submit_job_aes_ecb_192_dec_sse
#define SUBMIT_JOB_AES_ECB_256_ENC submit_job_aes_ecb_256_enc_sse
#define SUBMIT_JOB_AES_ECB_256_DEC submit_job_aes_ecb_256_dec_sse
#define SUBMIT_JOB_HMAC       submit_job_hmac_sse
#define FLUSH_JOB_HMAC        flush_job_hmac_sse
#define SUBMIT_JOB_HMAC_NI    submit_job_hmac_ni_sse
#define FLUSH_JOB_HMAC_NI     flush_job_hmac_ni_sse
#define SUBMIT_JOB_HMAC_SHA_224       submit_job_hmac_sha_224_sse
#define FLUSH_JOB_HMAC_SHA_224        flush_job_hmac_sha_224_sse
#define SUBMIT_JOB_HMAC_SHA_224_NI    submit_job_hmac_sha_224_ni_sse
#define FLUSH_JOB_HMAC_SHA_224_NI     flush_job_hmac_sha_224_ni_sse
#define SUBMIT_JOB_HMAC_SHA_256       submit_job_hmac_sha_256_sse
#define FLUSH_JOB_HMAC_SHA_256        flush_job_hmac_sha_256_sse
#define SUBMIT_JOB_HMAC_SHA_256_NI    submit_job_hmac_sha_256_ni_sse
#define FLUSH_JOB_HMAC_SHA_256_NI     flush_job_hmac_sha_256_ni_sse
#define SUBMIT_JOB_HMAC_SHA_384       submit_job_hmac_sha_384_sse
#define FLUSH_JOB_HMAC_SHA_384        flush_job_hmac_sha_384_sse
#define SUBMIT_JOB_HMAC_SHA_512       submit_job_hmac_sha_512_sse
#define FLUSH_JOB_HMAC_SHA_512        flush_job_hmac_sha_512_sse
#define SUBMIT_JOB_HMAC_MD5   submit_job_hmac_md5_sse
#define FLUSH_JOB_HMAC_MD5    flush_job_hmac_md5_sse
#define SUBMIT_JOB_AES_XCBC   submit_job_aes_xcbc_sse
#define FLUSH_JOB_AES_XCBC    flush_job_aes_xcbc_sse

#define SUBMIT_JOB_AES_CNTR   submit_job_aes_cntr_sse
#define SUBMIT_JOB_AES_CNTR_BIT   submit_job_aes_cntr_bit_sse

#define SUBMIT_JOB_ZUC_EEA3   submit_job_zuc_eea3_sse
#define FLUSH_JOB_ZUC_EEA3    flush_job_zuc_eea3_sse
#define SUBMIT_JOB_ZUC_EIA3   submit_job_zuc_eia3_sse
#define FLUSH_JOB_ZUC_EIA3    flush_job_zuc_eia3_sse

#define AES_CBC_DEC_128       aes_cbc_dec_128_sse
#define AES_CBC_DEC_192       aes_cbc_dec_192_sse
#define AES_CBC_DEC_256       aes_cbc_dec_256_sse

#define AES_CNTR_128       aes_cntr_128_sse
#define AES_CNTR_192       aes_cntr_192_sse
#define AES_CNTR_256       aes_cntr_256_sse

#define AES_CNTR_CCM_128   aes_cntr_ccm_128_sse

#define AES_ECB_ENC_128       aes_ecb_enc_128_sse
#define AES_ECB_ENC_192       aes_ecb_enc_192_sse
#define AES_ECB_ENC_256       aes_ecb_enc_256_sse
#define AES_ECB_DEC_128       aes_ecb_dec_128_sse
#define AES_ECB_DEC_192       aes_ecb_dec_192_sse
#define AES_ECB_DEC_256       aes_ecb_dec_256_sse

#define SUBMIT_JOB_PON_ENC        submit_job_pon_enc_sse
#define SUBMIT_JOB_PON_DEC        submit_job_pon_dec_sse
#define SUBMIT_JOB_PON_ENC_NO_CTR submit_job_pon_enc_no_ctr_sse
#define SUBMIT_JOB_PON_DEC_NO_CTR submit_job_pon_dec_no_ctr_sse

#ifndef NO_GCM
#define AES_GCM_DEC_128   aes_gcm_dec_128_sse
#define AES_GCM_ENC_128   aes_gcm_enc_128_sse
#define AES_GCM_DEC_192   aes_gcm_dec_192_sse
#define AES_GCM_ENC_192   aes_gcm_enc_192_sse
#define AES_GCM_DEC_256   aes_gcm_dec_256_sse
#define AES_GCM_ENC_256   aes_gcm_enc_256_sse

#define AES_GCM_DEC_IV_128   aes_gcm_dec_var_iv_128_sse
#define AES_GCM_ENC_IV_128   aes_gcm_enc_var_iv_128_sse
#define AES_GCM_DEC_IV_192   aes_gcm_dec_var_iv_192_sse
#define AES_GCM_ENC_IV_192   aes_gcm_enc_var_iv_192_sse
#define AES_GCM_DEC_IV_256   aes_gcm_dec_var_iv_256_sse
#define AES_GCM_ENC_IV_256   aes_gcm_enc_var_iv_256_sse

#define SUBMIT_JOB_AES_GCM_DEC submit_job_aes_gcm_dec_sse
#define FLUSH_JOB_AES_GCM_DEC  flush_job_aes_gcm_dec_sse
#define SUBMIT_JOB_AES_GCM_ENC submit_job_aes_gcm_enc_sse
#define FLUSH_JOB_AES_GCM_ENC  flush_job_aes_gcm_enc_sse
#endif /* NO_GCM */

/* ====================================================================== */

#define SUBMIT_JOB         submit_job_sse
#define FLUSH_JOB          flush_job_sse
#define SUBMIT_JOB_NOCHECK submit_job_nocheck_sse
#define GET_NEXT_JOB       get_next_job_sse
#define GET_COMPLETED_JOB  get_completed_job_sse

#define SUBMIT_JOB_AES128_DEC submit_job_aes128_dec_sse
#define SUBMIT_JOB_AES192_DEC submit_job_aes192_dec_sse
#define SUBMIT_JOB_AES256_DEC submit_job_aes256_dec_sse
#define QUEUE_SIZE queue_size_sse

/* ====================================================================== */

#define SUBMIT_JOB_AES_ENC SUBMIT_JOB_AES_ENC_SSE
#define FLUSH_JOB_AES_ENC  FLUSH_JOB_AES_ENC_SSE
#define SUBMIT_JOB_AES_DEC SUBMIT_JOB_AES_DEC_SSE
#define SUBMIT_JOB_HASH    SUBMIT_JOB_HASH_SSE
#define FLUSH_JOB_HASH     FLUSH_JOB_HASH_SSE

/* ====================================================================== */

#define AES_CFB_128_ONE    aes_cfb_128_one_sse

void aes128_cbc_mac_x4(AES_ARGS *args, uint64_t len);

#define AES128_CBC_MAC     aes128_cbc_mac_x4

#define FLUSH_JOB_AES_CCM_AUTH     flush_job_aes_ccm_auth_sse
#define SUBMIT_JOB_AES_CCM_AUTH    submit_job_aes_ccm_auth_sse

#define FLUSH_JOB_AES_CMAC_AUTH    flush_job_aes_cmac_auth_sse
#define SUBMIT_JOB_AES_CMAC_AUTH   submit_job_aes_cmac_auth_sse

/* ====================================================================== */

/*
 * Used to decide if SHA1/SHA256 SIMD or SHA1NI OOO scheduler should be
 * called.
 */
#define HASH_USE_SHAEXT 1


/* ====================================================================== */

uint32_t ethernet_fcs_sse(const void *msg, uint64_t len, const void *tag_ouput);

#define ETHERNET_FCS ethernet_fcs_sse

/* ====================================================================== */

/*
 * GCM submit / flush API for SSE arch
 */
#ifndef NO_GCM
static JOB_AES_HMAC *
submit_job_aes_gcm_dec_sse(MB_MGR *state, JOB_AES_HMAC *job)
{
        DECLARE_ALIGNED(struct gcm_context_data ctx, 16);
        (void) state;

        if (16 == job->aes_key_len_in_bytes) {
                AES_GCM_DEC_IV_128(job->aes_dec_key_expanded,
                                   &ctx, job->dst,
                                   job->src +
                                   job->cipher_start_src_offset_in_bytes,
                                   job->msg_len_to_cipher_in_bytes,
                                   job->iv, job->iv_len_in_bytes,
                                   job->u.GCM.aad,
                                   job->u.GCM.aad_len_in_bytes,
                                   job->auth_tag_output,
                                   job->auth_tag_output_len_in_bytes);
        } else if (24 == job->aes_key_len_in_bytes) {
                AES_GCM_DEC_IV_192(job->aes_dec_key_expanded,
                                   &ctx, job->dst,
                                   job->src +
                                   job->cipher_start_src_offset_in_bytes,
                                   job->msg_len_to_cipher_in_bytes,
                                   job->iv, job->iv_len_in_bytes,
                                   job->u.GCM.aad,
                                   job->u.GCM.aad_len_in_bytes,
                                   job->auth_tag_output,
                                   job->auth_tag_output_len_in_bytes);
        } else { /* assume 32 bytes */
                AES_GCM_DEC_IV_256(job->aes_dec_key_expanded,
                                   &ctx, job->dst,
                                   job->src +
                                   job->cipher_start_src_offset_in_bytes,
                                   job->msg_len_to_cipher_in_bytes,
                                   job->iv, job->iv_len_in_bytes,
                                   job->u.GCM.aad,
                                   job->u.GCM.aad_len_in_bytes,
                                   job->auth_tag_output,
                                   job->auth_tag_output_len_in_bytes);
        }

        job->status = STS_COMPLETED;
        return job;
}

static JOB_AES_HMAC *
flush_job_aes_gcm_dec_sse(MB_MGR *state, JOB_AES_HMAC *job)
{
        (void) state;
        (void) job;
        return NULL;
}

static JOB_AES_HMAC *
submit_job_aes_gcm_enc_sse(MB_MGR *state, JOB_AES_HMAC *job)
{
        DECLARE_ALIGNED(struct gcm_context_data ctx, 16);
        (void) state;

        if (16 == job->aes_key_len_in_bytes) {
                AES_GCM_ENC_IV_128(job->aes_enc_key_expanded,
                                   &ctx, job->dst,
                                   job->src +
                                   job->cipher_start_src_offset_in_bytes,
                                   job->msg_len_to_cipher_in_bytes,
                                   job->iv, job->iv_len_in_bytes,
                                   job->u.GCM.aad,
                                   job->u.GCM.aad_len_in_bytes,
                                   job->auth_tag_output,
                                   job->auth_tag_output_len_in_bytes);
        } else if (24 == job->aes_key_len_in_bytes) {
                AES_GCM_ENC_IV_192(job->aes_enc_key_expanded,
                                   &ctx, job->dst,
                                   job->src +
                                   job->cipher_start_src_offset_in_bytes,
                                   job->msg_len_to_cipher_in_bytes,
                                   job->iv, job->iv_len_in_bytes,
                                   job->u.GCM.aad,
                                   job->u.GCM.aad_len_in_bytes,
                                   job->auth_tag_output,
                                   job->auth_tag_output_len_in_bytes);
        } else { /* assume 32 bytes */
                AES_GCM_ENC_IV_256(job->aes_enc_key_expanded,
                                   &ctx, job->dst,
                                   job->src +
                                   job->cipher_start_src_offset_in_bytes,
                                   job->msg_len_to_cipher_in_bytes,
                                   job->iv, job->iv_len_in_bytes,
                                   job->u.GCM.aad,
                                   job->u.GCM.aad_len_in_bytes,
                                   job->auth_tag_output,
                                   job->auth_tag_output_len_in_bytes);
        }

        job->status = STS_COMPLETED;
        return job;
}

static JOB_AES_HMAC *
flush_job_aes_gcm_enc_sse(MB_MGR *state, JOB_AES_HMAC *job)
{
        (void) state;
        (void) job;
        return NULL;
}
#endif /* NO_GCM */

IMB_DLL_LOCAL JOB_AES_HMAC *
submit_job_aes_cntr_sse(JOB_AES_HMAC *job)
{
        if (16 == job->aes_key_len_in_bytes)
                AES_CNTR_128(job->src + job->cipher_start_src_offset_in_bytes,
                             job->iv,
                             job->aes_enc_key_expanded,
                             job->dst,
                             job->msg_len_to_cipher_in_bytes,
                             job->iv_len_in_bytes);
        else if (24 == job->aes_key_len_in_bytes)
                AES_CNTR_192(job->src + job->cipher_start_src_offset_in_bytes,
                             job->iv,
                             job->aes_enc_key_expanded,
                             job->dst,
                             job->msg_len_to_cipher_in_bytes,
                             job->iv_len_in_bytes);
        else /* assume 32 bytes */
                AES_CNTR_256(job->src + job->cipher_start_src_offset_in_bytes,
                             job->iv,
                             job->aes_enc_key_expanded,
                             job->dst,
                             job->msg_len_to_cipher_in_bytes,
                             job->iv_len_in_bytes);

        job->status |= STS_COMPLETED_AES;
        return job;
}

IMB_DLL_LOCAL JOB_AES_HMAC *
submit_job_aes_cntr_bit_sse(JOB_AES_HMAC *job)
{
        if (16 == job->aes_key_len_in_bytes)
                aes_cntr_bit_128_sse(job->src +
                                     job->cipher_start_src_offset_in_bytes,
                                     job->iv,
                                     job->aes_enc_key_expanded,
                                     job->dst,
                                     job->msg_len_to_cipher_in_bits,
                                     job->iv_len_in_bytes);
        else if (24 == job->aes_key_len_in_bytes)
                aes_cntr_bit_192_sse(job->src +
                                     job->cipher_start_src_offset_in_bytes,
                                     job->iv,
                                     job->aes_enc_key_expanded,
                                     job->dst,
                                     job->msg_len_to_cipher_in_bits,
                                     job->iv_len_in_bytes);
        else /* assume 32 bytes */
                aes_cntr_bit_256_sse(job->src +
                                     job->cipher_start_src_offset_in_bytes,
                                     job->iv,
                                     job->aes_enc_key_expanded,
                                     job->dst,
                                     job->msg_len_to_cipher_in_bits,
                                     job->iv_len_in_bytes);

        job->status |= STS_COMPLETED_AES;
        return job;
}

/* ====================================================================== */

void
init_mb_mgr_sse(MB_MGR *state)
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

        /* Init AES out-of-order fields */
        memset(state->aes128_ooo.lens, 0xFF,
               sizeof(state->aes128_ooo.lens));
        memset(&state->aes128_ooo.lens[0], 0,
               sizeof(state->aes128_ooo.lens[0]) * 4);
        memset(state->aes128_ooo.job_in_lane, 0,
               sizeof(state->aes128_ooo.job_in_lane));
        state->aes128_ooo.unused_lanes = 0xFF03020100;
        state->aes128_ooo.num_lanes_inuse = 0;


        memset(state->aes192_ooo.lens, 0xFF,
               sizeof(state->aes192_ooo.lens));
        memset(&state->aes192_ooo.lens[0], 0,
               sizeof(state->aes192_ooo.lens[0]) * 4);
        memset(state->aes192_ooo.job_in_lane, 0,
               sizeof(state->aes192_ooo.job_in_lane));
        state->aes192_ooo.unused_lanes = 0xFF03020100;
        state->aes192_ooo.num_lanes_inuse = 0;


        memset(state->aes256_ooo.lens, 0xFF,
               sizeof(state->aes256_ooo.lens));
        memset(&state->aes256_ooo.lens[0], 0,
               sizeof(state->aes256_ooo.lens[0]) * 4);
        memset(state->aes256_ooo.job_in_lane, 0,
               sizeof(state->aes256_ooo.job_in_lane));
        state->aes256_ooo.unused_lanes = 0xFF03020100;
        state->aes256_ooo.num_lanes_inuse = 0;


        /* DOCSIS SEC BPI uses same settings as AES128 CBC */
        memset(state->docsis_sec_ooo.lens, 0xFF,
               sizeof(state->docsis_sec_ooo.lens));
        memset(&state->docsis_sec_ooo.lens[0], 0,
               sizeof(state->docsis_sec_ooo.lens[0]) * 4);
        memset(state->docsis_sec_ooo.job_in_lane, 0,
               sizeof(state->docsis_sec_ooo.job_in_lane));
        state->docsis_sec_ooo.unused_lanes = 0xFF03020100;
        state->docsis_sec_ooo.num_lanes_inuse = 0;

        memset(state->docsis_crc32_sec_ooo.lens, 0xFF,
               sizeof(state->docsis_crc32_sec_ooo.lens));
        memset(&state->docsis_crc32_sec_ooo.lens[0], 0,
               sizeof(state->docsis_crc32_sec_ooo.lens[0]) * 4);
        memset(state->docsis_crc32_sec_ooo.job_in_lane, 0,
               sizeof(state->docsis_crc32_sec_ooo.job_in_lane));
        state->docsis_crc32_sec_ooo.unused_lanes = 0xFF03020100;
        state->docsis_crc32_sec_ooo.num_lanes_inuse = 0;

        /* Init ZUC out-of-order fields */
        memset(state->zuc_eea3_ooo.lens, 0xFF,
               sizeof(state->zuc_eea3_ooo.lens));
        memset(&state->zuc_eea3_ooo.lens[0], 0,
               sizeof(state->zuc_eea3_ooo.lens[0]) * 4);
        memset(state->zuc_eea3_ooo.job_in_lane, 0,
               sizeof(state->zuc_eea3_ooo.job_in_lane));
        state->zuc_eea3_ooo.unused_lanes = 0xFF03020100;
        state->zuc_eea3_ooo.num_lanes_inuse = 0;

        memset(state->zuc_eia3_ooo.lens, 0xFF,
               sizeof(state->zuc_eia3_ooo.lens));
        memset(&state->zuc_eia3_ooo.lens[0], 0,
               sizeof(state->zuc_eia3_ooo.lens[0]) * 4);
        memset(state->zuc_eia3_ooo.job_in_lane, 0,
               sizeof(state->zuc_eia3_ooo.job_in_lane));
        state->zuc_eia3_ooo.unused_lanes = 0xFF03020100;
        state->zuc_eia3_ooo.num_lanes_inuse = 0;

        /* Init HMAC/SHA1 out-of-order fields */
        state->hmac_sha_1_ooo.lens[0] = 0;
        state->hmac_sha_1_ooo.lens[1] = 0;
        state->hmac_sha_1_ooo.lens[2] = 0;
        state->hmac_sha_1_ooo.lens[3] = 0;
        state->hmac_sha_1_ooo.lens[4] = 0xFFFF;
        state->hmac_sha_1_ooo.lens[5] = 0xFFFF;
        state->hmac_sha_1_ooo.lens[6] = 0xFFFF;
        state->hmac_sha_1_ooo.lens[7] = 0xFFFF;
        state->hmac_sha_1_ooo.unused_lanes = 0xFF03020100;
        for (j = 0; j < SSE_NUM_SHA1_LANES; j++) {
                state->hmac_sha_1_ooo.ldata[j].job_in_lane = NULL;
                state->hmac_sha_1_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->hmac_sha_1_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64+7);
                p = state->hmac_sha_1_ooo.ldata[j].outer_block;
                memset(p + 5*4 + 1,
                       0x00,
                       64 - 5*4 - 1 - 2);
                p[5*4] = 0x80;
                p[64-2] = 0x02;
                p[64-1] = 0xA0;
        }

#ifdef HASH_USE_SHAEXT
        if (state->features & IMB_FEATURE_SHANI) {
                /* Init HMAC/SHA1 NI out-of-order fields */
                state->hmac_sha_1_ooo.lens[0] = 0;
                state->hmac_sha_1_ooo.lens[1] = 0;
                state->hmac_sha_1_ooo.lens[2] = 0xFFFF;
                state->hmac_sha_1_ooo.lens[3] = 0xFFFF;
                state->hmac_sha_1_ooo.lens[4] = 0xFFFF;
                state->hmac_sha_1_ooo.lens[5] = 0xFFFF;
                state->hmac_sha_1_ooo.lens[6] = 0xFFFF;
                state->hmac_sha_1_ooo.lens[7] = 0xFFFF;
                state->hmac_sha_1_ooo.unused_lanes = 0xFF0100;
        }
#endif /* HASH_USE_SHAEXT */

        /* Init HMAC/SHA224 out-of-order fields */
        state->hmac_sha_224_ooo.lens[0] = 0;
        state->hmac_sha_224_ooo.lens[1] = 0;
        state->hmac_sha_224_ooo.lens[2] = 0;
        state->hmac_sha_224_ooo.lens[3] = 0;
        state->hmac_sha_224_ooo.lens[4] = 0xFFFF;
        state->hmac_sha_224_ooo.lens[5] = 0xFFFF;
        state->hmac_sha_224_ooo.lens[6] = 0xFFFF;
        state->hmac_sha_224_ooo.lens[7] = 0xFFFF;
        state->hmac_sha_224_ooo.unused_lanes = 0xFF03020100;
        for (j = 0; j < SSE_NUM_SHA256_LANES; j++) {
                state->hmac_sha_224_ooo.ldata[j].job_in_lane = NULL;

                p = state->hmac_sha_224_ooo.ldata[j].extra_block;
                size = sizeof(state->hmac_sha_224_ooo.ldata[j].extra_block);
                memset (p, 0x00, size);
                p[64] = 0x80;

                p = state->hmac_sha_224_ooo.ldata[j].outer_block;
                size = sizeof(state->hmac_sha_224_ooo.ldata[j].outer_block);
                memset(p, 0x00, size);
                p[7*4] = 0x80;  /* digest 7 words long */
                p[64-2] = 0x02; /* length in little endian = 0x02E0 */
                p[64-1] = 0xE0;
        }
#ifdef HASH_USE_SHAEXT
        if (state->features & IMB_FEATURE_SHANI) {
                /* Init HMAC/SHA224 NI out-of-order fields */
                state->hmac_sha_224_ooo.lens[0] = 0;
                state->hmac_sha_224_ooo.lens[1] = 0;
                state->hmac_sha_224_ooo.lens[2] = 0xFFFF;
                state->hmac_sha_224_ooo.lens[3] = 0xFFFF;
                state->hmac_sha_224_ooo.lens[4] = 0xFFFF;
                state->hmac_sha_224_ooo.lens[5] = 0xFFFF;
                state->hmac_sha_224_ooo.lens[6] = 0xFFFF;
                state->hmac_sha_224_ooo.lens[7] = 0xFFFF;
                state->hmac_sha_224_ooo.unused_lanes = 0xFF0100;
        }
#endif /* HASH_USE_SHAEXT */

        /* Init HMAC/SHA_256 out-of-order fields */
        state->hmac_sha_256_ooo.lens[0] = 0;
        state->hmac_sha_256_ooo.lens[1] = 0;
        state->hmac_sha_256_ooo.lens[2] = 0;
        state->hmac_sha_256_ooo.lens[3] = 0;
        state->hmac_sha_256_ooo.lens[4] = 0xFFFF;
        state->hmac_sha_256_ooo.lens[5] = 0xFFFF;
        state->hmac_sha_256_ooo.lens[6] = 0xFFFF;
        state->hmac_sha_256_ooo.lens[7] = 0xFFFF;
        state->hmac_sha_256_ooo.unused_lanes = 0xFF03020100;
        for (j = 0; j < SSE_NUM_SHA256_LANES; j++) {
                state->hmac_sha_256_ooo.ldata[j].job_in_lane = NULL;
                state->hmac_sha_256_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->hmac_sha_256_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64+7);
                p = state->hmac_sha_256_ooo.ldata[j].outer_block;
                memset(p + 8*4 + 1,
                       0x00,
                       64 - 8*4 - 1 - 2); /* digest is 8*4 bytes long */
                p[8*4] = 0x80;
                p[64-2] = 0x03; /* length of (opad (64*8) bits + 256 bits)
                                 * in hex is 0x300 */
                p[64-1] = 0x00;
        }
#ifdef HASH_USE_SHAEXT
        if (state->features & IMB_FEATURE_SHANI) {
                /* Init HMAC/SHA256 NI out-of-order fields */
                state->hmac_sha_256_ooo.lens[0] = 0;
                state->hmac_sha_256_ooo.lens[1] = 0;
                state->hmac_sha_256_ooo.lens[2] = 0xFFFF;
                state->hmac_sha_256_ooo.lens[3] = 0xFFFF;
                state->hmac_sha_256_ooo.lens[4] = 0xFFFF;
                state->hmac_sha_256_ooo.lens[5] = 0xFFFF;
                state->hmac_sha_256_ooo.lens[6] = 0xFFFF;
                state->hmac_sha_256_ooo.lens[7] = 0xFFFF;
                state->hmac_sha_256_ooo.unused_lanes = 0xFF0100;
        }
#endif /* HASH_USE_SHAEXT */

        /* Init HMAC/SHA384 out-of-order fields */
        state->hmac_sha_384_ooo.lens[0] = 0;
        state->hmac_sha_384_ooo.lens[1] = 0;
        state->hmac_sha_384_ooo.lens[2] = 0xFFFF;
        state->hmac_sha_384_ooo.lens[3] = 0xFFFF;
        state->hmac_sha_384_ooo.lens[4] = 0xFFFF;
        state->hmac_sha_384_ooo.lens[5] = 0xFFFF;
        state->hmac_sha_384_ooo.lens[6] = 0xFFFF;
        state->hmac_sha_384_ooo.lens[7] = 0xFFFF;
        state->hmac_sha_384_ooo.unused_lanes = 0xFF0100;
        for (j = 0; j < SSE_NUM_SHA512_LANES; j++) {
                MB_MGR_HMAC_SHA_512_OOO *ctx = &state->hmac_sha_384_ooo;

                ctx->ldata[j].job_in_lane = NULL;
                ctx->ldata[j].extra_block[SHA_384_BLOCK_SIZE] = 0x80;
                memset(ctx->ldata[j].extra_block + (SHA_384_BLOCK_SIZE + 1),
                       0x00, SHA_384_BLOCK_SIZE + 7);

                p = ctx->ldata[j].outer_block;
                memset(p + SHA384_DIGEST_SIZE_IN_BYTES  + 1, 0x00,
                       /* special end point because this length is constant */
                       SHA_384_BLOCK_SIZE -
                       SHA384_DIGEST_SIZE_IN_BYTES - 1 - 2);
                p[SHA384_DIGEST_SIZE_IN_BYTES] = 0x80; /* mark the end */
                /*
                 * hmac outer block length always of fixed size, it is OKey
                 * length, a whole message block length, 1024 bits, with padding
                 * plus the length of the inner digest, which is 384 bits
                 * 1408 bits == 0x0580. The input message block needs to be
                 * converted to big endian within the sha implementation
                 * before use.
                 */
                p[SHA_384_BLOCK_SIZE - 2] = 0x05;
                p[SHA_384_BLOCK_SIZE - 1] = 0x80;
        }

        /* Init HMAC/SHA512 out-of-order fields */
        state->hmac_sha_512_ooo.lens[0] = 0;
        state->hmac_sha_512_ooo.lens[1] = 0;
        state->hmac_sha_512_ooo.lens[2] = 0xFFFF;
        state->hmac_sha_512_ooo.lens[3] = 0xFFFF;
        state->hmac_sha_512_ooo.lens[4] = 0xFFFF;
        state->hmac_sha_512_ooo.lens[5] = 0xFFFF;
        state->hmac_sha_512_ooo.lens[6] = 0xFFFF;
        state->hmac_sha_512_ooo.lens[7] = 0xFFFF;
        state->hmac_sha_512_ooo.unused_lanes = 0xFF0100;
        for (j = 0; j < SSE_NUM_SHA512_LANES; j++) {
                MB_MGR_HMAC_SHA_512_OOO *ctx = &state->hmac_sha_512_ooo;

                ctx->ldata[j].job_in_lane = NULL;
                ctx->ldata[j].extra_block[SHA_512_BLOCK_SIZE] = 0x80;
                memset(ctx->ldata[j].extra_block + (SHA_512_BLOCK_SIZE + 1),
                       0x00, SHA_512_BLOCK_SIZE + 7);

                p = ctx->ldata[j].outer_block;
                memset(p + SHA512_DIGEST_SIZE_IN_BYTES  + 1, 0x00,
                       /* special end point because this length is constant */
                       SHA_512_BLOCK_SIZE -
                       SHA512_DIGEST_SIZE_IN_BYTES  - 1 - 2);
                p[SHA512_DIGEST_SIZE_IN_BYTES] = 0x80; /* mark the end */
                /*
                 * hmac outer block length always of fixed size, it is OKey
                 * length, a whole message block length, 1024 bits, with padding
                 * plus the length of the inner digest, which is 512 bits
                 * 1536 bits == 0x600. The input message block needs to be
                 * converted to big endian within the sha implementation
                 * before use.
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
        state->hmac_md5_ooo.lens[8] = 0xFFFF;
        state->hmac_md5_ooo.lens[9] = 0xFFFF;
        state->hmac_md5_ooo.lens[10] = 0xFFFF;
        state->hmac_md5_ooo.lens[11] = 0xFFFF;
        state->hmac_md5_ooo.lens[12] = 0xFFFF;
        state->hmac_md5_ooo.lens[13] = 0xFFFF;
        state->hmac_md5_ooo.lens[14] = 0xFFFF;
        state->hmac_md5_ooo.lens[15] = 0xFFFF;
        state->hmac_md5_ooo.unused_lanes = 0xF76543210;
        for (j = 0; j < SSE_NUM_MD5_LANES; j++) {
                state->hmac_md5_ooo.ldata[j].job_in_lane = NULL;

                p = state->hmac_md5_ooo.ldata[j].extra_block;
                size = sizeof(state->hmac_md5_ooo.ldata[j].extra_block);
                memset (p, 0x00, size);
                p[64] = 0x80;

                p = state->hmac_md5_ooo.ldata[j].outer_block;
                size = sizeof(state->hmac_md5_ooo.ldata[j].outer_block);
                memset(p, 0x00, size);
                p[4*4] = 0x80;
                p[64-7] = 0x02;
                p[64-8] = 0x80;
        }

        /* Init AES/XCBC OOO fields */
        state->aes_xcbc_ooo.lens[0] = 0;
        state->aes_xcbc_ooo.lens[1] = 0;
        state->aes_xcbc_ooo.lens[2] = 0;
        state->aes_xcbc_ooo.lens[3] = 0;
        state->aes_xcbc_ooo.lens[4] = 0xFFFF;
        state->aes_xcbc_ooo.lens[5] = 0xFFFF;
        state->aes_xcbc_ooo.lens[6] = 0xFFFF;
        state->aes_xcbc_ooo.lens[7] = 0xFFFF;
        state->aes_xcbc_ooo.unused_lanes = 0xFF03020100;
        for (j = 0; j < 4; j++) {
                state->aes_xcbc_ooo.ldata[j].job_in_lane = NULL;
                state->aes_xcbc_ooo.ldata[j].final_block[16] = 0x80;
                memset(state->aes_xcbc_ooo.ldata[j].final_block + 17, 0x00, 15);
        }

        /* Init AES-CCM auth out-of-order fields */
        for (j = 0; j < 4; j++) {
                state->aes_ccm_ooo.init_done[j] = 0;
                state->aes_ccm_ooo.lens[j] = 0;
                state->aes_ccm_ooo.job_in_lane[j] = NULL;
        }
        for (; j < 8; j++)
                state->aes_ccm_ooo.lens[j] = 0xFFFF;

        state->aes_ccm_ooo.unused_lanes = 0xF3210;

        /* Init AES-CMAC auth out-of-order fields */
        state->aes_cmac_ooo.lens[0] = 0;
        state->aes_cmac_ooo.lens[1] = 0;
        state->aes_cmac_ooo.lens[2] = 0;
        state->aes_cmac_ooo.lens[3] = 0;
        state->aes_cmac_ooo.lens[4] = 0xFFFF;
        state->aes_cmac_ooo.lens[5] = 0xFFFF;
        state->aes_cmac_ooo.lens[6] = 0xFFFF;
        state->aes_cmac_ooo.lens[7] = 0xFFFF;
        for (j = 0; j < 4; j++) {
                state->aes_cmac_ooo.init_done[j] = 0;
                state->aes_cmac_ooo.job_in_lane[j] = NULL;
        }
        state->aes_cmac_ooo.unused_lanes = 0xF3210;

        /* Init "in order" components */
        state->next_job = 0;
        state->earliest_job = -1;

        /* set SSE handlers */
        state->get_next_job        = get_next_job_sse;
        state->submit_job          = submit_job_sse;
        state->submit_job_nocheck  = submit_job_nocheck_sse;
        state->get_completed_job   = get_completed_job_sse;
        state->flush_job           = flush_job_sse;
        state->queue_size          = queue_size_sse;
        state->keyexp_128          = aes_keyexp_128_sse;
        state->keyexp_192          = aes_keyexp_192_sse;
        state->keyexp_256          = aes_keyexp_256_sse;
        state->cmac_subkey_gen_128 = aes_cmac_subkey_gen_sse;
        state->xcbc_keyexp         = aes_xcbc_expand_key_sse;
        state->des_key_sched       = des_key_schedule;
        state->sha1_one_block      = sha1_one_block_sse;
        state->sha1                = sha1_sse;
        state->sha224_one_block    = sha224_one_block_sse;
        state->sha224              = sha224_sse;
        state->sha256_one_block    = sha256_one_block_sse;
        state->sha256              = sha256_sse;
        state->sha384_one_block    = sha384_one_block_sse;
        state->sha384              = sha384_sse;
        state->sha512_one_block    = sha512_one_block_sse;
        state->sha512              = sha512_sse;
        state->md5_one_block       = md5_one_block_sse;
        state->aes128_cfb_one      = aes_cfb_128_one_sse;

        state->eea3_1_buffer       = zuc_eea3_1_buffer_sse;
        state->eea3_4_buffer       = zuc_eea3_4_buffer_sse;
        state->eea3_n_buffer       = zuc_eea3_n_buffer_sse;
        state->eia3_1_buffer       = zuc_eia3_1_buffer_sse;
        state->eia3_n_buffer       = zuc_eia3_n_buffer_sse;

        state->f8_1_buffer         = kasumi_f8_1_buffer_sse;
        state->f8_1_buffer_bit     = kasumi_f8_1_buffer_bit_sse;
        state->f8_2_buffer         = kasumi_f8_2_buffer_sse;
        state->f8_3_buffer         = kasumi_f8_3_buffer_sse;
        state->f8_4_buffer         = kasumi_f8_4_buffer_sse;
        state->f8_n_buffer         = kasumi_f8_n_buffer_sse;
        state->f9_1_buffer         = kasumi_f9_1_buffer_sse;
        state->f9_1_buffer_user    = kasumi_f9_1_buffer_user_sse;
        state->kasumi_init_f8_key_sched = kasumi_init_f8_key_sched_sse;
        state->kasumi_init_f9_key_sched = kasumi_init_f9_key_sched_sse;
        state->kasumi_key_sched_size = kasumi_key_sched_size_sse;

        state->snow3g_f8_1_buffer_bit = snow3g_f8_1_buffer_bit_sse;
        state->snow3g_f8_1_buffer  = snow3g_f8_1_buffer_sse;
        state->snow3g_f8_2_buffer  = snow3g_f8_2_buffer_sse;
        state->snow3g_f8_4_buffer  = snow3g_f8_4_buffer_sse;
        state->snow3g_f8_8_buffer  = snow3g_f8_8_buffer_sse;
        state->snow3g_f8_n_buffer  = snow3g_f8_n_buffer_sse;
        state->snow3g_f8_8_buffer_multikey = snow3g_f8_8_buffer_multikey_sse;
        state->snow3g_f8_n_buffer_multikey = snow3g_f8_n_buffer_multikey_sse;
        state->snow3g_f9_1_buffer = snow3g_f9_1_buffer_sse;
        state->snow3g_init_key_sched = snow3g_init_key_sched_sse;
        state->snow3g_key_sched_size = snow3g_key_sched_size_sse;

#ifndef NO_GCM
        state->gcm128_enc          = aes_gcm_enc_128_sse;
        state->gcm192_enc          = aes_gcm_enc_192_sse;
        state->gcm256_enc          = aes_gcm_enc_256_sse;
        state->gcm128_dec          = aes_gcm_dec_128_sse;
        state->gcm192_dec          = aes_gcm_dec_192_sse;
        state->gcm256_dec          = aes_gcm_dec_256_sse;
        state->gcm128_init         = aes_gcm_init_128_sse;
        state->gcm192_init         = aes_gcm_init_192_sse;
        state->gcm256_init         = aes_gcm_init_256_sse;
        state->gcm128_init_var_iv  = aes_gcm_init_var_iv_128_sse;
        state->gcm192_init_var_iv  = aes_gcm_init_var_iv_192_sse;
        state->gcm256_init_var_iv  = aes_gcm_init_var_iv_256_sse;
        state->gcm128_enc_update   = aes_gcm_enc_128_update_sse;
        state->gcm192_enc_update   = aes_gcm_enc_192_update_sse;
        state->gcm256_enc_update   = aes_gcm_enc_256_update_sse;
        state->gcm128_dec_update   = aes_gcm_dec_128_update_sse;
        state->gcm192_dec_update   = aes_gcm_dec_192_update_sse;
        state->gcm256_dec_update   = aes_gcm_dec_256_update_sse;
        state->gcm128_enc_finalize = aes_gcm_enc_128_finalize_sse;
        state->gcm192_enc_finalize = aes_gcm_enc_192_finalize_sse;
        state->gcm256_enc_finalize = aes_gcm_enc_256_finalize_sse;
        state->gcm128_dec_finalize = aes_gcm_dec_128_finalize_sse;
        state->gcm192_dec_finalize = aes_gcm_dec_192_finalize_sse;
        state->gcm256_dec_finalize = aes_gcm_dec_256_finalize_sse;
        state->gcm128_precomp      = aes_gcm_precomp_128_sse;
        state->gcm192_precomp      = aes_gcm_precomp_192_sse;
        state->gcm256_precomp      = aes_gcm_precomp_256_sse;
        state->gcm128_pre          = aes_gcm_pre_128_sse;
        state->gcm192_pre          = aes_gcm_pre_192_sse;
        state->gcm256_pre          = aes_gcm_pre_256_sse;
        state->ghash               = ghash_sse;
#endif
}

#include "mb_mgr_code.h"
