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

#ifndef MB_MGR_JOB_API_H
#define MB_MGR_JOB_API_H

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

#include <stdint.h>

#include "include/clear_regs_mem.h"
#include "include/des.h"
#include "intel-ipsec-mb.h"
#include "include/error.h"
#include "include/snow3g_submit.h"
#include "include/job_api_gcm.h"
#include "include/job_api_snowv.h"
#include "include/job_api_kasumi.h"
#include "include/mb_mgr_job_check.h" /* is_job_invalid() */

#define CRC(func, state, job) *((uint32_t *)job->auth_tag_output) = \
                func(state, job->src + job->hash_start_src_offset_in_bytes, \
                     job->msg_len_to_hash_in_bytes)

/* ========================================================================= */
/* AES-CBC */
/* ========================================================================= */

__forceinline IMB_JOB *SUBMIT_JOB_AES_CBC_128_DEC(IMB_JOB *job)
{
        AES_CBC_DEC_128(job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv,
                        job->dec_keys,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_AES_CBC_192_DEC(IMB_JOB *job)
{
        AES_CBC_DEC_192(job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv,
                        job->dec_keys,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_AES_CBC_256_DEC(IMB_JOB *job)
{
        AES_CBC_DEC_256(job->src + job->cipher_start_src_offset_in_bytes,
                        job->iv,
                        job->dec_keys,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/* ========================================================================= */
/* AES-ECB */
/* ========================================================================= */

__forceinline IMB_JOB *SUBMIT_JOB_AES_ECB_128_ENC(IMB_JOB *job)
{
        AES_ECB_ENC_128(job->src + job->cipher_start_src_offset_in_bytes,
                        job->enc_keys,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_AES_ECB_192_ENC(IMB_JOB *job)
{
        AES_ECB_ENC_192(job->src + job->cipher_start_src_offset_in_bytes,
                        job->enc_keys,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_AES_ECB_256_ENC(IMB_JOB *job)
{
        AES_ECB_ENC_256(job->src + job->cipher_start_src_offset_in_bytes,
                        job->enc_keys,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_AES_ECB_128_DEC(IMB_JOB *job)
{
        AES_ECB_DEC_128(job->src + job->cipher_start_src_offset_in_bytes,
                        job->dec_keys,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_AES_ECB_192_DEC(IMB_JOB *job)
{
        AES_ECB_DEC_192(job->src + job->cipher_start_src_offset_in_bytes,
                        job->dec_keys,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_AES_ECB_256_DEC(IMB_JOB *job)
{
        AES_ECB_DEC_256(job->src + job->cipher_start_src_offset_in_bytes,
                        job->dec_keys,
                        job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/* ========================================================================= */
/* AES-CBCS */
/* ========================================================================= */

__forceinline IMB_JOB * SUBMIT_JOB_AES128_CBCS_1_9_DEC(IMB_JOB *job)
{
        AES_CBCS_1_9_DEC_128(job->src + job->cipher_start_src_offset_in_bytes,
                             job->iv,
                             job->dec_keys,
                             job->dst,
                             job->msg_len_to_cipher_in_bytes & (~15),
                             job->cipher_fields.CBCS.next_iv);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/* ========================================================================= */
/* DOCSIS - it has to be below AES DEC */
/* ========================================================================= */

#include "include/job_api_docsis.h"

/* ========================================================================= */
/* AES-GCM */
/* ========================================================================= */
__forceinline IMB_JOB *SUBMIT_JOB_AES_GCM_DEC(IMB_MGR *state, IMB_JOB *job)
{
        DECLARE_ALIGNED(struct gcm_context_data ctx, 16);
        (void) state;

        if (16 == job->key_len_in_bytes) {
                AES_GCM_DEC_IV_128(job->dec_keys,
                                   &ctx, job->dst,
                                   job->src +
                                   job->cipher_start_src_offset_in_bytes,
                                   job->msg_len_to_cipher_in_bytes,
                                   job->iv, job->iv_len_in_bytes,
                                   job->u.GCM.aad,
                                   job->u.GCM.aad_len_in_bytes,
                                   job->auth_tag_output,
                                   job->auth_tag_output_len_in_bytes);
        } else if (24 == job->key_len_in_bytes) {
                AES_GCM_DEC_IV_192(job->dec_keys,
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
                AES_GCM_DEC_IV_256(job->dec_keys,
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

        job->status = IMB_STATUS_COMPLETED;
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_AES_GCM_ENC(IMB_MGR *state, IMB_JOB *job)
{
        DECLARE_ALIGNED(struct gcm_context_data ctx, 16);
        (void) state;

        if (16 == job->key_len_in_bytes) {
                AES_GCM_ENC_IV_128(job->enc_keys,
                                   &ctx, job->dst,
                                   job->src +
                                   job->cipher_start_src_offset_in_bytes,
                                   job->msg_len_to_cipher_in_bytes,
                                   job->iv, job->iv_len_in_bytes,
                                   job->u.GCM.aad,
                                   job->u.GCM.aad_len_in_bytes,
                                   job->auth_tag_output,
                                   job->auth_tag_output_len_in_bytes);
        } else if (24 == job->key_len_in_bytes) {
                AES_GCM_ENC_IV_192(job->enc_keys,
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
                AES_GCM_ENC_IV_256(job->enc_keys,
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

        job->status = IMB_STATUS_COMPLETED;
        return job;
}
/* ========================================================================= */
/* AES-CTR */
/* ========================================================================= */
__forceinline IMB_JOB *SUBMIT_JOB_AES_CTR(IMB_JOB *job)
{
        if (IMB_KEY_128_BYTES == job->key_len_in_bytes) {
#ifdef SUBMIT_JOB_AES_CTR_128
                SUBMIT_JOB_AES_CTR_128(job);
#else
                AES_CTR_128(job->src + job->cipher_start_src_offset_in_bytes,
                            job->iv,
                            job->enc_keys,
                            job->dst,
                            job->msg_len_to_cipher_in_bytes,
                            job->iv_len_in_bytes);
#endif
        } else if (IMB_KEY_192_BYTES == job->key_len_in_bytes) {
#ifdef SUBMIT_JOB_AES_CTR_192
                SUBMIT_JOB_AES_CTR_192(job);
#else
                AES_CTR_192(job->src + job->cipher_start_src_offset_in_bytes,
                            job->iv,
                            job->enc_keys,
                            job->dst,
                            job->msg_len_to_cipher_in_bytes,
                            job->iv_len_in_bytes);
#endif
        } else /* assume 256-bit key */ {
#ifdef SUBMIT_JOB_AES_CTR_256
                SUBMIT_JOB_AES_CTR_256(job);
#else
                AES_CTR_256(job->src + job->cipher_start_src_offset_in_bytes,
                            job->iv,
                            job->enc_keys,
                            job->dst,
                            job->msg_len_to_cipher_in_bytes,
                            job->iv_len_in_bytes);
#endif
        }

        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_AES_CTR_BIT(IMB_JOB *job)
{
        if (IMB_KEY_128_BYTES == job->key_len_in_bytes) {
#ifdef SUBMIT_JOB_AES_CTR_128_BIT
                SUBMIT_JOB_AES_CTR_128_BIT(job);
#else
                AES_CTR_128_BIT(job->src +
                                job->cipher_start_src_offset_in_bytes,
                                job->iv,
                                job->enc_keys,
                                job->dst,
                                job->msg_len_to_cipher_in_bits,
                                job->iv_len_in_bytes);
#endif
        } else if (IMB_KEY_192_BYTES == job->key_len_in_bytes) {
#ifdef SUBMIT_JOB_AES_CTR_192_BIT
                SUBMIT_JOB_AES_CTR_192_BIT(job);
#else
                AES_CTR_192_BIT(job->src +
                                job->cipher_start_src_offset_in_bytes,
                                job->iv,
                                job->enc_keys,
                                job->dst,
                                job->msg_len_to_cipher_in_bits,
                                job->iv_len_in_bytes);
#endif
        } else /* assume 256-bit key */ {
#ifdef SUBMIT_JOB_AES_CTR_256_BIT
                SUBMIT_JOB_AES_CTR_256_BIT(job);
#else
                AES_CTR_256_BIT(job->src +
                                job->cipher_start_src_offset_in_bytes,
                                job->iv,
                                job->enc_keys,
                                job->dst,
                                job->msg_len_to_cipher_in_bits,
                                job->iv_len_in_bytes);
#endif
        }

        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/* ========================================================================= */
/* Custom hash / cipher */
/* ========================================================================= */

__forceinline IMB_JOB *JOB_CUSTOM_CIPHER(IMB_JOB *job)
{
        if (!(job->status & IMB_STATUS_COMPLETED_CIPHER)) {
                if (job->cipher_func(job))
                        job->status = IMB_STATUS_INTERNAL_ERROR;
                else
                        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        }
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_CUSTOM_CIPHER(IMB_JOB *job)
{
        return JOB_CUSTOM_CIPHER(job);
}

__forceinline IMB_JOB *FLUSH_JOB_CUSTOM_CIPHER(IMB_JOB *job)
{
        return JOB_CUSTOM_CIPHER(job);
}

__forceinline IMB_JOB *JOB_CUSTOM_HASH(IMB_JOB *job)
{
        if (!(job->status & IMB_STATUS_COMPLETED_AUTH)) {
                if (job->hash_func(job))
                        job->status = IMB_STATUS_INTERNAL_ERROR;
                else
                        job->status |= IMB_STATUS_COMPLETED_AUTH;
        }
        return job;
}

__forceinline IMB_JOB *SUBMIT_JOB_CUSTOM_HASH(IMB_JOB *job)
{
        return JOB_CUSTOM_HASH(job);
}

__forceinline IMB_JOB *FLUSH_JOB_CUSTOM_HASH(IMB_JOB *job)
{
        return JOB_CUSTOM_HASH(job);
}

/* ========================================================================= */
/* Cipher submit & flush functions */
/* ========================================================================= */
__forceinline IMB_JOB *SUBMIT_JOB_CIPHER_ENC(IMB_MGR *state, IMB_JOB *job)
{
        if (IMB_CIPHER_GCM == job->cipher_mode) {
                return SUBMIT_JOB_AES_GCM_ENC(state, job);
        } else if (IMB_CIPHER_GCM_SGL == job->cipher_mode) {
                return submit_gcm_sgl_enc(state, job);
        } else if (IMB_CIPHER_CBC == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        MB_MGR_AES_OOO *aes128_ooo = state->aes128_ooo;

                        return SUBMIT_JOB_AES_CBC_128_ENC(aes128_ooo, job);
                } else if (24 == job->key_len_in_bytes) {
                        MB_MGR_AES_OOO *aes192_ooo = state->aes192_ooo;

                        return SUBMIT_JOB_AES_CBC_192_ENC(aes192_ooo, job);
                } else { /* assume 32 */
                        MB_MGR_AES_OOO *aes256_ooo = state->aes256_ooo;

                        return SUBMIT_JOB_AES_CBC_256_ENC(aes256_ooo, job);
                }
        } else if (IMB_CIPHER_CNTR == job->cipher_mode) {
                return SUBMIT_JOB_AES_CTR(job);
        } else if (IMB_CIPHER_CNTR_BITLEN == job->cipher_mode) {
                return SUBMIT_JOB_AES_CTR_BIT(job);
        } else if (IMB_CIPHER_ECB == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        return SUBMIT_JOB_AES_ECB_128_ENC(job);
                } else if (24 == job->key_len_in_bytes) {
                        return SUBMIT_JOB_AES_ECB_192_ENC(job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES_ECB_256_ENC(job);
                }
        } else if (IMB_CIPHER_DOCSIS_SEC_BPI == job->cipher_mode) {
                return submit_docsis_enc_job(state, job);
        } else if (IMB_CIPHER_PON_AES_CNTR == job->cipher_mode) {
                if (job->msg_len_to_cipher_in_bytes == 0)
                        return SUBMIT_JOB_PON_ENC_NO_CTR(job);
                else
                        return SUBMIT_JOB_PON_ENC(job);
        } else if (IMB_CIPHER_CUSTOM == job->cipher_mode) {
                return SUBMIT_JOB_CUSTOM_CIPHER(job);
        } else if (IMB_CIPHER_DES == job->cipher_mode) {
#ifdef SUBMIT_JOB_DES_CBC_ENC
                MB_MGR_DES_OOO *des_enc_ooo = state->des_enc_ooo;

                return SUBMIT_JOB_DES_CBC_ENC(des_enc_ooo, job);
#else
                return DES_CBC_ENC(job);
#endif /* SUBMIT_JOB_DES_CBC_ENC */
        } else if (IMB_CIPHER_CHACHA20 == job->cipher_mode) {
                return SUBMIT_JOB_CHACHA20_ENC_DEC(job);
        } else if (IMB_CIPHER_CHACHA20_POLY1305 == job->cipher_mode) {
                return SUBMIT_JOB_CHACHA20_POLY1305(state, job);
        } else if (IMB_CIPHER_CHACHA20_POLY1305_SGL == job->cipher_mode) {
                return SUBMIT_JOB_CHACHA20_POLY1305_SGL(state, job);
        } else if (IMB_CIPHER_DOCSIS_DES == job->cipher_mode) {
#ifdef SUBMIT_JOB_DOCSIS_DES_ENC
                MB_MGR_DES_OOO *docsis_des_enc_ooo = state->docsis_des_enc_ooo;

                return SUBMIT_JOB_DOCSIS_DES_ENC(docsis_des_enc_ooo,
                                                 job);
#else
                return DOCSIS_DES_ENC(job);
#endif /* SUBMIT_JOB_DOCSIS_DES_ENC */
        } else if (IMB_CIPHER_DES3 == job->cipher_mode) {
#ifdef SUBMIT_JOB_3DES_CBC_ENC
                MB_MGR_DES_OOO *des3_enc_ooo = state->des3_enc_ooo;

                return SUBMIT_JOB_3DES_CBC_ENC(des3_enc_ooo, job);
#else
                return DES3_CBC_ENC(job);
#endif
        } else if (IMB_CIPHER_CCM == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        return AES_CNTR_CCM_128(job);
                } else { /* assume 32 */
                        return AES_CNTR_CCM_256(job);
                }
        } else if (IMB_CIPHER_ZUC_EEA3 == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        MB_MGR_ZUC_OOO *zuc_eea3_ooo = state->zuc_eea3_ooo;

                        return SUBMIT_JOB_ZUC_EEA3(zuc_eea3_ooo, job);
                } else { /* assume 32 */
                        MB_MGR_ZUC_OOO *zuc256_eea3_ooo =
                                state->zuc256_eea3_ooo;

                        return SUBMIT_JOB_ZUC256_EEA3(zuc256_eea3_ooo, job);
                }
        } else if (IMB_CIPHER_SNOW3G_UEA2_BITLEN == job->cipher_mode) {
#ifdef SUBMIT_JOB_SNOW3G_UEA2
                return SUBMIT_JOB_SNOW3G_UEA2(state, job);
#else
                return def_submit_snow3g_uea2_job(state, job);
#endif
        } else if (IMB_CIPHER_KASUMI_UEA1_BITLEN == job->cipher_mode) {
                return submit_kasumi_uea1_job(state, job);
        } else if (IMB_CIPHER_CBCS_1_9 == job->cipher_mode) {
                MB_MGR_AES_OOO *aes128_cbcs_ooo = state->aes128_cbcs_ooo;

                return SUBMIT_JOB_AES128_CBCS_1_9_ENC(aes128_cbcs_ooo, job);
        } else if (IMB_CIPHER_SNOW_V == job->cipher_mode) {
                return SUBMIT_JOB_SNOW_V(job);
        } else if (IMB_CIPHER_SNOW_V_AEAD == job->cipher_mode) {
                return submit_snow_v_aead_job(state, job);
        } else { /* assume IMB_CIPHER_NULL */
                job->status |= IMB_STATUS_COMPLETED_CIPHER;
                return job;
        }
}

__forceinline IMB_JOB *FLUSH_JOB_CIPHER_ENC(IMB_MGR *state, IMB_JOB *job)
{
        if (IMB_CIPHER_CBC == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        MB_MGR_AES_OOO *aes128_ooo = state->aes128_ooo;

                        return FLUSH_JOB_AES_CBC_128_ENC(aes128_ooo);
                } else if (24 == job->key_len_in_bytes) {
                        MB_MGR_AES_OOO *aes192_ooo = state->aes192_ooo;

                        return FLUSH_JOB_AES_CBC_192_ENC(aes192_ooo);
                } else  { /* assume 32 */
                        MB_MGR_AES_OOO *aes256_ooo = state->aes256_ooo;

                        return FLUSH_JOB_AES_CBC_256_ENC(aes256_ooo);
                }
        } else if (IMB_CIPHER_DOCSIS_SEC_BPI == job->cipher_mode) {
                return flush_docsis_enc_job(state, job);
#ifdef FLUSH_JOB_DES_CBC_ENC
        } else if (IMB_CIPHER_DES == job->cipher_mode) {
                MB_MGR_DES_OOO *des_enc_ooo = state->des_enc_ooo;

                return FLUSH_JOB_DES_CBC_ENC(des_enc_ooo);
#endif /* FLUSH_JOB_DES_CBC_ENC */
#ifdef FLUSH_JOB_3DES_CBC_ENC
        } else if (IMB_CIPHER_DES3 == job->cipher_mode) {
                MB_MGR_DES_OOO *des3_enc_ooo = state->des3_enc_ooo;

                return FLUSH_JOB_3DES_CBC_ENC(des3_enc_ooo);
#endif /* FLUSH_JOB_3DES_CBC_ENC */
#ifdef FLUSH_JOB_DOCSIS_DES_ENC
        } else if (IMB_CIPHER_DOCSIS_DES == job->cipher_mode) {
                MB_MGR_DES_OOO *docsis_des_enc_ooo = state->docsis_des_enc_ooo;

                return FLUSH_JOB_DOCSIS_DES_ENC(docsis_des_enc_ooo);
#endif /* FLUSH_JOB_DOCSIS_DES_ENC */
        } else if (IMB_CIPHER_CUSTOM == job->cipher_mode) {
                return FLUSH_JOB_CUSTOM_CIPHER(job);
        } else if (IMB_CIPHER_ZUC_EEA3 == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        MB_MGR_ZUC_OOO *zuc_eea3_ooo = state->zuc_eea3_ooo;

                        return FLUSH_JOB_ZUC_EEA3(zuc_eea3_ooo);
                } else { /* assume 32 */
                        MB_MGR_ZUC_OOO *zuc256_eea3_ooo =
                                state->zuc256_eea3_ooo;

                        return FLUSH_JOB_ZUC256_EEA3(zuc256_eea3_ooo);
                }
        } else if (IMB_CIPHER_CBCS_1_9 == job->cipher_mode) {
                MB_MGR_AES_OOO *aes128_cbcs_ooo = state->aes128_cbcs_ooo;

                return FLUSH_JOB_AES128_CBCS_1_9_ENC(aes128_cbcs_ooo);
#ifdef FLUSH_JOB_SNOW3G_UEA2
        } else if (IMB_CIPHER_SNOW3G_UEA2_BITLEN == job->cipher_mode) {
                return FLUSH_JOB_SNOW3G_UEA2(state);
#endif
        /**
         * assume IMB_CIPHER_CNTR/CNTR_BITLEN, IMB_CIPHER_ECB,
         * IMB_CIPHER_CCM, IMB_CIPHER_NULL or IMB_CIPHER_GCM
         */
        } else {
                return NULL;
        }
}

__forceinline IMB_JOB *SUBMIT_JOB_CIPHER_DEC(IMB_MGR *state, IMB_JOB *job)
{
        if (IMB_CIPHER_GCM == job->cipher_mode) {
                return SUBMIT_JOB_AES_GCM_DEC(state, job);
        } else if (IMB_CIPHER_GCM_SGL == job->cipher_mode) {
                return submit_gcm_sgl_dec(state, job);
        } else if (IMB_CIPHER_CBC == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        return SUBMIT_JOB_AES_CBC_128_DEC(job);
                } else if (24 == job->key_len_in_bytes) {
                        return SUBMIT_JOB_AES_CBC_192_DEC(job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES_CBC_256_DEC(job);
                }
        } else if (IMB_CIPHER_CNTR == job->cipher_mode) {
                return SUBMIT_JOB_AES_CTR(job);
        } else if (IMB_CIPHER_CNTR_BITLEN == job->cipher_mode) {
                return SUBMIT_JOB_AES_CTR_BIT(job);
        } else if (IMB_CIPHER_ECB == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        return SUBMIT_JOB_AES_ECB_128_DEC(job);
                } else if (24 == job->key_len_in_bytes) {
                        return SUBMIT_JOB_AES_ECB_192_DEC(job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES_ECB_256_DEC(job);
                }
        } else if (IMB_CIPHER_DOCSIS_SEC_BPI == job->cipher_mode) {
                return submit_docsis_dec_job(state, job);
        } else if (IMB_CIPHER_PON_AES_CNTR == job->cipher_mode) {
                if (job->msg_len_to_cipher_in_bytes == 0)
                        return SUBMIT_JOB_PON_DEC_NO_CTR(job);
                else
                        return SUBMIT_JOB_PON_DEC(job);
        } else if (IMB_CIPHER_DES == job->cipher_mode) {
#ifdef SUBMIT_JOB_DES_CBC_DEC
                MB_MGR_DES_OOO *des_dec_ooo = state->des_dec_ooo;

                return SUBMIT_JOB_DES_CBC_DEC(des_dec_ooo, job);
#else
                (void) state;
                return DES_CBC_DEC(job);
#endif /* SUBMIT_JOB_DES_CBC_DEC */
        } else if (IMB_CIPHER_CHACHA20 == job->cipher_mode) {
                return SUBMIT_JOB_CHACHA20_ENC_DEC(job);
        } else if (IMB_CIPHER_CHACHA20_POLY1305 == job->cipher_mode) {
                return SUBMIT_JOB_CHACHA20_POLY1305(state, job);
        } else if (IMB_CIPHER_CHACHA20_POLY1305_SGL == job->cipher_mode) {
                return SUBMIT_JOB_CHACHA20_POLY1305_SGL(state, job);
        } else if (IMB_CIPHER_DOCSIS_DES == job->cipher_mode) {
#ifdef SUBMIT_JOB_DOCSIS_DES_DEC
                MB_MGR_DES_OOO *docsis_des_dec_ooo = state->docsis_des_dec_ooo;

                return SUBMIT_JOB_DOCSIS_DES_DEC(docsis_des_dec_ooo,
                                                 job);
#else
                return DOCSIS_DES_DEC(job);
#endif /* SUBMIT_JOB_DOCSIS_DES_DEC */
        } else if (IMB_CIPHER_DES3 == job->cipher_mode) {
#ifdef SUBMIT_JOB_3DES_CBC_DEC
                MB_MGR_DES_OOO *des3_dec_ooo = state->des3_dec_ooo;

                return SUBMIT_JOB_3DES_CBC_DEC(des3_dec_ooo, job);
#else
                return DES3_CBC_DEC(job);
#endif
        } else if (IMB_CIPHER_CUSTOM == job->cipher_mode) {
                return SUBMIT_JOB_CUSTOM_CIPHER(job);
        } else if (IMB_CIPHER_CCM == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        return AES_CNTR_CCM_128(job);
                } else { /* assume 32 */
                        return AES_CNTR_CCM_256(job);
                }
        } else if (IMB_CIPHER_ZUC_EEA3 == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        MB_MGR_ZUC_OOO *zuc_eea3_ooo = state->zuc_eea3_ooo;

                        return SUBMIT_JOB_ZUC_EEA3(zuc_eea3_ooo, job);
                } else { /* assume 32 */
                        MB_MGR_ZUC_OOO *zuc256_eea3_ooo =
                                state->zuc256_eea3_ooo;

                        return SUBMIT_JOB_ZUC256_EEA3(zuc256_eea3_ooo, job);
                }
        } else if (IMB_CIPHER_SNOW3G_UEA2_BITLEN == job->cipher_mode) {
#ifdef SUBMIT_JOB_SNOW3G_UEA2
                return SUBMIT_JOB_SNOW3G_UEA2(state, job);
#else
                return def_submit_snow3g_uea2_job(state, job);
#endif
        } else if (IMB_CIPHER_KASUMI_UEA1_BITLEN == job->cipher_mode) {
                return submit_kasumi_uea1_job(state, job);
        } else if (IMB_CIPHER_CBCS_1_9 == job->cipher_mode) {
                return SUBMIT_JOB_AES128_CBCS_1_9_DEC(job);
        } else if (IMB_CIPHER_SNOW_V == job->cipher_mode) {
                return SUBMIT_JOB_SNOW_V(job);
        } else if (IMB_CIPHER_SNOW_V_AEAD == job->cipher_mode) {
                return submit_snow_v_aead_job(state, job);
        } else {
                /* assume IMB_CIPHER_NULL */
                job->status |= IMB_STATUS_COMPLETED_CIPHER;
                return job;
        }
}

__forceinline IMB_JOB *FLUSH_JOB_CIPHER_DEC(IMB_MGR *state, IMB_JOB *job)
{
#ifdef FLUSH_JOB_SNOW3G_UEA2
        if (IMB_CIPHER_SNOW3G_UEA2_BITLEN == job->cipher_mode)
                return FLUSH_JOB_SNOW3G_UEA2(state);
#endif

#ifdef FLUSH_JOB_DES_CBC_DEC
        if (IMB_CIPHER_DES == job->cipher_mode) {
                MB_MGR_DES_OOO *des_dec_ooo = state->des_dec_ooo;

                return FLUSH_JOB_DES_CBC_DEC(des_dec_ooo);
        }
#endif /* FLUSH_JOB_DES_CBC_DEC */

#ifdef FLUSH_JOB_3DES_CBC_DEC
        if (IMB_CIPHER_DES3 == job->cipher_mode) {
                MB_MGR_DES_OOO *des3_dec_ooo = state->des3_dec_ooo;

                return FLUSH_JOB_3DES_CBC_DEC(des3_dec_ooo);
        }
#endif /* FLUSH_JOB_3DES_CBC_DEC */

#ifdef FLUSH_JOB_DOCSIS_DES_DEC

        if (IMB_CIPHER_DOCSIS_DES == job->cipher_mode) {
                MB_MGR_DES_OOO *docsis_des_dec_ooo = state->docsis_des_dec_ooo;

                return FLUSH_JOB_DOCSIS_DES_DEC(docsis_des_dec_ooo);
        }
#endif /* FLUSH_JOB_DOCSIS_DES_DEC */

        if (IMB_CIPHER_ZUC_EEA3 == job->cipher_mode) {
                if (16 == job->key_len_in_bytes) {
                        MB_MGR_ZUC_OOO *zuc_eea3_ooo = state->zuc_eea3_ooo;

                        return FLUSH_JOB_ZUC_EEA3(zuc_eea3_ooo);
                } else { /* assume 32 */
                        MB_MGR_ZUC_OOO *zuc256_eea3_ooo =
                                state->zuc256_eea3_ooo;

                        return FLUSH_JOB_ZUC256_EEA3(zuc256_eea3_ooo);
                }
        }

        return NULL;
}

/* ========================================================================= */
/* Hash submit & flush functions */
/* ========================================================================= */

__forceinline
IMB_JOB *
SUBMIT_JOB_HASH(IMB_MGR *state, IMB_JOB *job)
{
        MB_MGR_HMAC_SHA_1_OOO *hmac_sha_1_ooo = state->hmac_sha_1_ooo;
        MB_MGR_HMAC_SHA_256_OOO *hmac_sha_224_ooo = state->hmac_sha_224_ooo;
        MB_MGR_HMAC_SHA_256_OOO *hmac_sha_256_ooo = state->hmac_sha_256_ooo;
        MB_MGR_HMAC_SHA_512_OOO *hmac_sha_384_ooo = state->hmac_sha_384_ooo;
        MB_MGR_HMAC_SHA_512_OOO *hmac_sha_512_ooo = state->hmac_sha_512_ooo;
        MB_MGR_HMAC_MD5_OOO *hmac_md5_ooo = state->hmac_md5_ooo;
        MB_MGR_AES_XCBC_OOO *aes_xcbc_ooo = state->aes_xcbc_ooo;
        MB_MGR_CCM_OOO *aes_ccm_ooo = state->aes_ccm_ooo;
	MB_MGR_CCM_OOO *aes256_ccm_ooo = state->aes256_ccm_ooo;
        MB_MGR_CMAC_OOO *aes_cmac_ooo = state->aes_cmac_ooo;
	MB_MGR_CMAC_OOO *aes256_cmac_ooo = state->aes256_cmac_ooo;
        MB_MGR_ZUC_OOO *zuc_eia3_ooo = state->zuc_eia3_ooo;
        MB_MGR_ZUC_OOO *zuc256_eia3_ooo = state->zuc256_eia3_ooo;
        MB_MGR_SHA_1_OOO *sha_1_ooo = state->sha_1_ooo;
        MB_MGR_SHA_256_OOO *sha_224_ooo = state->sha_224_ooo;
        MB_MGR_SHA_256_OOO *sha_256_ooo = state->sha_256_ooo;
        MB_MGR_SHA_512_OOO *sha_384_ooo = state->sha_384_ooo;
        MB_MGR_SHA_512_OOO *sha_512_ooo = state->sha_512_ooo;
#if (defined(SAFE_LOOKUP) || defined(AVX512)) && !defined(SSE_AESNI_EMU)
        MB_MGR_SNOW3G_OOO *snow3g_uia2_ooo = state->snow3g_uia2_ooo;
#endif


        switch (job->hash_alg) {
        case IMB_AUTH_HMAC_SHA_1:
                return SUBMIT_JOB_HMAC(hmac_sha_1_ooo, job);
        case IMB_AUTH_HMAC_SHA_224:
                return SUBMIT_JOB_HMAC_SHA_224(hmac_sha_224_ooo, job);
        case IMB_AUTH_HMAC_SHA_256:
                return SUBMIT_JOB_HMAC_SHA_256(hmac_sha_256_ooo, job);
        case IMB_AUTH_HMAC_SHA_384:
                return SUBMIT_JOB_HMAC_SHA_384(hmac_sha_384_ooo, job);
        case IMB_AUTH_HMAC_SHA_512:
                return SUBMIT_JOB_HMAC_SHA_512(hmac_sha_512_ooo, job);
        case IMB_AUTH_AES_XCBC:
                return SUBMIT_JOB_AES_XCBC(aes_xcbc_ooo, job);
        case IMB_AUTH_MD5:
                return SUBMIT_JOB_HMAC_MD5(hmac_md5_ooo, job);
        case IMB_AUTH_CUSTOM:
                return SUBMIT_JOB_CUSTOM_HASH(job);
        case IMB_AUTH_AES_CCM:
                if (16 == job->key_len_in_bytes) {
                        return SUBMIT_JOB_AES128_CCM_AUTH(aes_ccm_ooo, job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES256_CCM_AUTH(aes256_ccm_ooo, job);
                }
        case IMB_AUTH_AES_CMAC:
                /*
                 * CMAC OOO MGR assumes job len in bits
                 * (for CMAC length is provided in bytes)
                 */
                job->msg_len_to_hash_in_bits =
                        job->msg_len_to_hash_in_bytes * 8;
                return SUBMIT_JOB_AES128_CMAC_AUTH(aes_cmac_ooo, job);
        case IMB_AUTH_AES_CMAC_BITLEN:
                return SUBMIT_JOB_AES128_CMAC_AUTH(aes_cmac_ooo, job);
        case IMB_AUTH_AES_CMAC_256:
                job->msg_len_to_hash_in_bits =
                        job->msg_len_to_hash_in_bytes * 8;
                return SUBMIT_JOB_AES256_CMAC_AUTH(aes256_cmac_ooo, job);
        case IMB_AUTH_SHA_1:
                return SUBMIT_JOB_SHA1(sha_1_ooo, job);
        case IMB_AUTH_SHA_224:
                return SUBMIT_JOB_SHA224(sha_224_ooo, job);
        case IMB_AUTH_SHA_256:
                return SUBMIT_JOB_SHA256(sha_256_ooo, job);
        case IMB_AUTH_SHA_384:
                return SUBMIT_JOB_SHA384(sha_384_ooo, job);
        case IMB_AUTH_SHA_512:
                return SUBMIT_JOB_SHA512(sha_512_ooo, job);
        case IMB_AUTH_ZUC_EIA3_BITLEN:
                return SUBMIT_JOB_ZUC_EIA3(zuc_eia3_ooo, job);
        case IMB_AUTH_ZUC256_EIA3_BITLEN:
                return SUBMIT_JOB_ZUC256_EIA3(zuc256_eia3_ooo, job,
                                        job->auth_tag_output_len_in_bytes);
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
#if (defined(SAFE_LOOKUP) || defined(AVX512)) && !defined(SSE_AESNI_EMU)
                return SUBMIT_JOB_SNOW3G_UIA2(snow3g_uia2_ooo, job);
#else
                IMB_SNOW3G_F9_1_BUFFER(state, (const snow3g_key_schedule_t *)
                               job->u.SNOW3G_UIA2._key,
                               job->u.SNOW3G_UIA2._iv,
                               job->src + job->hash_start_src_offset_in_bytes,
                               job->msg_len_to_hash_in_bits,
                               job->auth_tag_output);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
#endif
        case IMB_AUTH_KASUMI_UIA1:
                IMB_KASUMI_F9_1_BUFFER(state, (const kasumi_key_sched_t *)
                               job->u.KASUMI_UIA1._key,
                               job->src + job->hash_start_src_offset_in_bytes,
                               (const uint32_t) job->msg_len_to_hash_in_bytes,
                               job->auth_tag_output);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_AES_GMAC_128:
                process_gmac(state, job, IMB_KEY_128_BYTES);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_AES_GMAC_192:
                process_gmac(state, job, IMB_KEY_192_BYTES);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_AES_GMAC_256:
                process_gmac(state, job, IMB_KEY_256_BYTES);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_POLY1305:
                POLY1305_MAC(job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC32_ETHERNET_FCS:
                CRC(IMB_CRC32_ETHERNET_FCS, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC32_SCTP:
                CRC(IMB_CRC32_SCTP, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC32_WIMAX_OFDMA_DATA:
                CRC(IMB_CRC32_WIMAX_OFDMA_DATA, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC24_LTE_A:
                CRC(IMB_CRC24_LTE_A, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC24_LTE_B:
                CRC(IMB_CRC24_LTE_B, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC16_X25:
                CRC(IMB_CRC16_X25, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC16_FP_DATA:
                CRC(IMB_CRC16_FP_DATA, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC11_FP_HEADER:
                CRC(IMB_CRC11_FP_HEADER, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC10_IUUP_DATA:
                CRC(IMB_CRC10_IUUP_DATA, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC8_WIMAX_OFDMA_HCS:
                CRC(IMB_CRC8_WIMAX_OFDMA_HCS, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC7_FP_HEADER:
                CRC(IMB_CRC7_FP_HEADER, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_CRC6_IUUP_HEADER:
                CRC(IMB_CRC6_IUUP_HEADER, state, job);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        case IMB_AUTH_GHASH:
                return process_ghash(state, job);
        default:
                /**
                 * assume IMB_AUTH_GCM, IMB_AUTH_PON_CRC_BIP,
                 * IMB_AUTH_SNOW_V_AEAD or IMB_AUTH_NULL
                 */
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        }
}

__forceinline
IMB_JOB *
FLUSH_JOB_HASH(IMB_MGR *state, IMB_JOB *job)
{
        MB_MGR_HMAC_SHA_1_OOO *hmac_sha_1_ooo = state->hmac_sha_1_ooo;
        MB_MGR_HMAC_SHA_256_OOO *hmac_sha_224_ooo = state->hmac_sha_224_ooo;
        MB_MGR_HMAC_SHA_256_OOO *hmac_sha_256_ooo = state->hmac_sha_256_ooo;
        MB_MGR_HMAC_SHA_512_OOO *hmac_sha_384_ooo = state->hmac_sha_384_ooo;
        MB_MGR_HMAC_SHA_512_OOO *hmac_sha_512_ooo = state->hmac_sha_512_ooo;
        MB_MGR_HMAC_MD5_OOO *hmac_md5_ooo = state->hmac_md5_ooo;
        MB_MGR_AES_XCBC_OOO *aes_xcbc_ooo = state->aes_xcbc_ooo;
        MB_MGR_CCM_OOO *aes_ccm_ooo = state->aes_ccm_ooo;
	MB_MGR_CCM_OOO *aes256_ccm_ooo = state->aes256_ccm_ooo;
        MB_MGR_CMAC_OOO *aes_cmac_ooo = state->aes_cmac_ooo;
	MB_MGR_CMAC_OOO *aes256_cmac_ooo = state->aes256_cmac_ooo;
        MB_MGR_ZUC_OOO *zuc_eia3_ooo = state->zuc_eia3_ooo;
        MB_MGR_ZUC_OOO *zuc256_eia3_ooo = state->zuc256_eia3_ooo;
        MB_MGR_SHA_1_OOO *sha_1_ooo = state->sha_1_ooo;
        MB_MGR_SHA_256_OOO *sha_224_ooo = state->sha_224_ooo;
        MB_MGR_SHA_256_OOO *sha_256_ooo = state->sha_256_ooo;
        MB_MGR_SHA_512_OOO *sha_384_ooo = state->sha_384_ooo;
        MB_MGR_SHA_512_OOO *sha_512_ooo = state->sha_512_ooo;
#if (defined(SAFE_LOOKUP) || defined(AVX512)) && !defined(SSE_AESNI_EMU)
        MB_MGR_SNOW3G_OOO *snow3g_uia2_ooo = state->snow3g_uia2_ooo;
#endif

        switch (job->hash_alg) {
        case IMB_AUTH_HMAC_SHA_1:
                return FLUSH_JOB_HMAC(hmac_sha_1_ooo);
        case IMB_AUTH_HMAC_SHA_224:
                return FLUSH_JOB_HMAC_SHA_224(hmac_sha_224_ooo);
        case IMB_AUTH_HMAC_SHA_256:
                return FLUSH_JOB_HMAC_SHA_256(hmac_sha_256_ooo);
        case IMB_AUTH_HMAC_SHA_384:
                return FLUSH_JOB_HMAC_SHA_384(hmac_sha_384_ooo);
        case IMB_AUTH_HMAC_SHA_512:
                return FLUSH_JOB_HMAC_SHA_512(hmac_sha_512_ooo);
        case IMB_AUTH_SHA_1:
                return FLUSH_JOB_SHA1(sha_1_ooo, job);
        case IMB_AUTH_SHA_224:
                return FLUSH_JOB_SHA224(sha_224_ooo, job);
        case IMB_AUTH_SHA_256:
                return FLUSH_JOB_SHA256(sha_256_ooo, job);
        case IMB_AUTH_SHA_384:
                return FLUSH_JOB_SHA384(sha_384_ooo, job);
        case IMB_AUTH_SHA_512:
                return FLUSH_JOB_SHA512(sha_512_ooo, job);
        case IMB_AUTH_AES_XCBC:
                return FLUSH_JOB_AES_XCBC(aes_xcbc_ooo);
        case IMB_AUTH_MD5:
                return FLUSH_JOB_HMAC_MD5(hmac_md5_ooo);
        case IMB_AUTH_CUSTOM:
                return FLUSH_JOB_CUSTOM_HASH(job);
        case IMB_AUTH_AES_CCM:
                if (16 == job->key_len_in_bytes) {
                        return FLUSH_JOB_AES128_CCM_AUTH(aes_ccm_ooo);
                } else { /* assume 32 */
                        return FLUSH_JOB_AES256_CCM_AUTH(aes256_ccm_ooo);
                }
        case IMB_AUTH_AES_CMAC:
        case IMB_AUTH_AES_CMAC_BITLEN:
                return FLUSH_JOB_AES128_CMAC_AUTH(aes_cmac_ooo);
        case IMB_AUTH_AES_CMAC_256:
                return FLUSH_JOB_AES256_CMAC_AUTH(aes256_cmac_ooo);
        case IMB_AUTH_ZUC_EIA3_BITLEN:
                return FLUSH_JOB_ZUC_EIA3(zuc_eia3_ooo);
        case IMB_AUTH_ZUC256_EIA3_BITLEN:
                return FLUSH_JOB_ZUC256_EIA3(zuc256_eia3_ooo,
                                             job->auth_tag_output_len_in_bytes);
#if (defined(SAFE_LOOKUP) || defined(AVX512)) && !defined(SSE_AESNI_EMU)
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                return FLUSH_JOB_SNOW3G_UIA2(snow3g_uia2_ooo);
#endif
        default: /* assume GCM or IMB_AUTH_NULL */
                if (!(job->status & IMB_STATUS_COMPLETED_AUTH)) {
                        job->status |= IMB_STATUS_COMPLETED_AUTH;
                        return job;
                }
                /* if HMAC is complete then return NULL */
                return NULL;
        }
}

/* ========================================================================= */
/* Job submit & flush functions */
/* ========================================================================= */

__forceinline
IMB_JOB *SUBMIT_JOB_CIPHER(IMB_MGR *state, IMB_JOB *job)
{
	if (job->cipher_direction == IMB_DIR_ENCRYPT)
		job = SUBMIT_JOB_CIPHER_ENC(state, job);
	else
		job = SUBMIT_JOB_CIPHER_DEC(state, job);

	return job;
}

__forceinline
IMB_JOB *FLUSH_JOB_CIPHER(IMB_MGR *state, IMB_JOB *job)
{
	if (job->cipher_direction == IMB_DIR_ENCRYPT)
		job = FLUSH_JOB_CIPHER_ENC(state, job);
	else
		job = FLUSH_JOB_CIPHER_DEC(state, job);

	return job;
}

/* submit a half-completed job, based on the status */
__forceinline
IMB_JOB *RESUBMIT_JOB(IMB_MGR *state, IMB_JOB *job)
{
        while (job != NULL && job->status < IMB_STATUS_COMPLETED) {
                if (job->status == IMB_STATUS_COMPLETED_AUTH)
                        job = SUBMIT_JOB_CIPHER(state, job);
                else /* assumed job->status = IMB_STATUS_COMPLETED_CIPHER */
                        job = SUBMIT_JOB_HASH(state, job);
        }

	return job;
}

__forceinline
IMB_JOB *submit_new_job(IMB_MGR *state, IMB_JOB *job)
{
	if (job->chain_order == IMB_ORDER_CIPHER_HASH)
		job = SUBMIT_JOB_CIPHER(state, job);
	else
		job = SUBMIT_JOB_HASH(state, job);

        job = RESUBMIT_JOB(state, job);
	return job;
}

__forceinline
uint32_t complete_job(IMB_MGR *state, IMB_JOB *job)
{
        uint32_t completed_jobs = 0;

        /**
         * complete as many jobs as necessary
         * until specified 'job' has completed
         */
        if (job->chain_order == IMB_ORDER_CIPHER_HASH) {
                /* while() loop optimized for cipher_hash order */
                while (job->status < IMB_STATUS_COMPLETED) {
                        IMB_JOB *tmp = FLUSH_JOB_CIPHER(state, job);

                        if (tmp == NULL)
                                tmp = FLUSH_JOB_HASH(state, job);

                        (void) RESUBMIT_JOB(state, tmp);
                        completed_jobs++;
                }
        } else {
                /* while() loop optimized for hash_cipher order */
                while (job->status < IMB_STATUS_COMPLETED) {
                        IMB_JOB *tmp = FLUSH_JOB_HASH(state, job);

                        if (tmp == NULL)
                                tmp = FLUSH_JOB_CIPHER(state, job);

                        (void) RESUBMIT_JOB(state, tmp);
                        completed_jobs++;
                }
        }

        return completed_jobs;
}

__forceinline
IMB_JOB *
submit_job_and_check(IMB_MGR *state, const int run_check)
{
        IMB_JOB *job = NULL;

        /* reset error status */
        imb_set_errno(state, 0);

        if (run_check) {
                if (state == NULL) {
                        imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                        return NULL;
                }
        }

#ifndef LINUX
        DECLARE_ALIGNED(imb_uint128_t xmm_save[10], 16);

        SAVE_XMMS(xmm_save);
#endif

        job = JOBS(state, state->next_job);

        if (run_check) {
                if (is_job_invalid(state, job,
                                   job->cipher_mode, job->hash_alg,
                                   job->cipher_direction,
                                   job->key_len_in_bytes)) {
                        job->status = IMB_STATUS_INVALID_ARGS;
                } else {
                        job->status = IMB_STATUS_BEING_PROCESSED;
                        job = submit_new_job(state, job);
                }
        } else {
                job->status = IMB_STATUS_BEING_PROCESSED;
                job = submit_new_job(state, job);
        }

        if (state->earliest_job < 0) {
                /* state was previously empty */
                if (job == NULL)
                        state->earliest_job = state->next_job;
                ADV_JOBS(&state->next_job);
                goto exit;
        }

        ADV_JOBS(&state->next_job);

        if (state->earliest_job == state->next_job) {
                /* Full */
                job = JOBS(state, state->earliest_job);
                (void) complete_job(state, job);
                ADV_JOBS(&state->earliest_job);
                goto exit;
        }

        /* not full */
        job = JOBS(state, state->earliest_job);
        if (job->status < IMB_STATUS_COMPLETED) {
                job = NULL;
                goto exit;
        }

        ADV_JOBS(&state->earliest_job);
exit:

#ifndef LINUX
        RESTORE_XMMS(xmm_save);
#endif
        return job;
}

IMB_JOB *
SUBMIT_JOB(IMB_MGR *state)
{
        return submit_job_and_check(state, 1);
}

IMB_JOB *
SUBMIT_JOB_NOCHECK(IMB_MGR *state)
{
        return submit_job_and_check(state, 0);
}

IMB_JOB *
FLUSH_JOB(IMB_MGR *state)
{
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return NULL;
        }
#endif
        IMB_JOB *job;
#ifndef LINUX
        DECLARE_ALIGNED(imb_uint128_t xmm_save[10], 16);
#endif
        if (state->earliest_job < 0)
                return NULL; /* empty */

#ifndef LINUX
        SAVE_XMMS(xmm_save);
#endif
        job = JOBS(state, state->earliest_job);
        (void) complete_job(state, job);

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
QUEUE_SIZE(IMB_MGR *state)
{
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return 0;
        }
#endif
        return queue_sz(state);
}

IMB_JOB *
GET_COMPLETED_JOB(IMB_MGR *state)
{
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return NULL;
        }
#endif
        IMB_JOB *job;

        if (state->earliest_job < 0)
                return NULL;

        job = JOBS(state, state->earliest_job);
        if (job->status < IMB_STATUS_COMPLETED)
                return NULL;

        ADV_JOBS(&state->earliest_job);

        if (state->earliest_job == state->next_job)
                state->earliest_job = -1;

        return job;
}

IMB_JOB *
GET_NEXT_JOB(IMB_MGR *state)
{
        /* reset error status */
        imb_set_errno(state, 0);

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return NULL;
        }
#endif

        return JOBS(state, state->next_job);
}

#endif /* MB_MGR_JOB_API_H */
