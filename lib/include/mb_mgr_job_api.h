/*******************************************************************************
  Copyright (c) 2022-2023, Intel Corporation

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

#define CRC(func, state, job)                                                                      \
        *((uint32_t *) job->auth_tag_output) =                                                     \
                func(state, job->src + job->hash_start_src_offset_in_bytes,                        \
                     job->msg_len_to_hash_in_bytes)

/* ========================================================================= */
/* AES-CBC */
/* ========================================================================= */

__forceinline IMB_JOB *
SUBMIT_JOB_AES_CBC_128_DEC(IMB_JOB *job)
{
        AES_CBC_DEC_128(job->src + job->cipher_start_src_offset_in_bytes, job->iv, job->dec_keys,
                        job->dst, job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_AES_CBC_192_DEC(IMB_JOB *job)
{
        AES_CBC_DEC_192(job->src + job->cipher_start_src_offset_in_bytes, job->iv, job->dec_keys,
                        job->dst, job->msg_len_to_cipher_in_bytes);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_AES_CBC_256_DEC(IMB_JOB *job)
{
        AES_CBC_DEC_256(job->src + job->cipher_start_src_offset_in_bytes, job->iv, job->dec_keys,
                        job->dst, job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/* ========================================================================= */
/* AES-ECB */
/* ========================================================================= */

__forceinline IMB_JOB *
SUBMIT_JOB_AES_ECB_128_ENC(IMB_JOB *job)
{
        AES_ECB_ENC_128(job->src + job->cipher_start_src_offset_in_bytes, job->enc_keys, job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_AES_ECB_192_ENC(IMB_JOB *job)
{
        AES_ECB_ENC_192(job->src + job->cipher_start_src_offset_in_bytes, job->enc_keys, job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_AES_ECB_256_ENC(IMB_JOB *job)
{
        AES_ECB_ENC_256(job->src + job->cipher_start_src_offset_in_bytes, job->enc_keys, job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_AES_ECB_128_DEC(IMB_JOB *job)
{
        AES_ECB_DEC_128(job->src + job->cipher_start_src_offset_in_bytes, job->dec_keys, job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_AES_ECB_192_DEC(IMB_JOB *job)
{
        AES_ECB_DEC_192(job->src + job->cipher_start_src_offset_in_bytes, job->dec_keys, job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_AES_ECB_256_DEC(IMB_JOB *job)
{
        AES_ECB_DEC_256(job->src + job->cipher_start_src_offset_in_bytes, job->dec_keys, job->dst,
                        job->msg_len_to_cipher_in_bytes & (~15));
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/* ========================================================================= */
/* AES-CBCS */
/* ========================================================================= */

__forceinline IMB_JOB *
SUBMIT_JOB_AES128_CBCS_1_9_DEC(IMB_JOB *job)
{
        AES_CBCS_1_9_DEC_128(job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                             job->dec_keys, job->dst, job->msg_len_to_cipher_in_bytes & (~15),
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
__forceinline IMB_JOB *
SUBMIT_JOB_AES_GCM_DEC(IMB_MGR *state, IMB_JOB *job, const uint64_t key_sz)
{
        if (16 == key_sz)
                return AES_GCM_DEC_IV_128(state, job);
        else if (24 == key_sz)
                return AES_GCM_DEC_IV_192(state, job);
        else
                return AES_GCM_DEC_IV_256(state, job);
}

__forceinline IMB_JOB *
SUBMIT_JOB_AES_GCM_ENC(IMB_MGR *state, IMB_JOB *job, const uint64_t key_sz)
{
        if (16 == key_sz)
                return AES_GCM_ENC_IV_128(state, job);
        else if (24 == key_sz)
                return AES_GCM_ENC_IV_192(state, job);
        else
                return AES_GCM_ENC_IV_256(state, job);
}

/* ========================================================================= */
/* AES-CTR */
/* ========================================================================= */
__forceinline IMB_JOB *
SUBMIT_JOB_AES_CTR(IMB_JOB *job, const uint64_t key_sz)
{
        if (IMB_KEY_128_BYTES == key_sz) {
#ifdef SUBMIT_JOB_AES_CTR_128
                SUBMIT_JOB_AES_CTR_128(job);
#else
                AES_CTR_128(job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                            job->enc_keys, job->dst, job->msg_len_to_cipher_in_bytes,
                            job->iv_len_in_bytes);
#endif
        } else if (IMB_KEY_192_BYTES == key_sz) {
#ifdef SUBMIT_JOB_AES_CTR_192
                SUBMIT_JOB_AES_CTR_192(job);
#else
                AES_CTR_192(job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                            job->enc_keys, job->dst, job->msg_len_to_cipher_in_bytes,
                            job->iv_len_in_bytes);
#endif
        } else /* assume 256-bit key */ {
#ifdef SUBMIT_JOB_AES_CTR_256
                SUBMIT_JOB_AES_CTR_256(job);
#else
                AES_CTR_256(job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                            job->enc_keys, job->dst, job->msg_len_to_cipher_in_bytes,
                            job->iv_len_in_bytes);
#endif
        }

        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_AES_CTR_BIT(IMB_JOB *job, const uint64_t key_sz)
{
        if (IMB_KEY_128_BYTES == key_sz) {
#ifdef SUBMIT_JOB_AES_CTR_128_BIT
                SUBMIT_JOB_AES_CTR_128_BIT(job);
#else
                AES_CTR_128_BIT(job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                                job->enc_keys, job->dst, job->msg_len_to_cipher_in_bits,
                                job->iv_len_in_bytes);
#endif
        } else if (IMB_KEY_192_BYTES == key_sz) {
#ifdef SUBMIT_JOB_AES_CTR_192_BIT
                SUBMIT_JOB_AES_CTR_192_BIT(job);
#else
                AES_CTR_192_BIT(job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                                job->enc_keys, job->dst, job->msg_len_to_cipher_in_bits,
                                job->iv_len_in_bytes);
#endif
        } else /* assume 256-bit key */ {
#ifdef SUBMIT_JOB_AES_CTR_256_BIT
                SUBMIT_JOB_AES_CTR_256_BIT(job);
#else
                AES_CTR_256_BIT(job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                                job->enc_keys, job->dst, job->msg_len_to_cipher_in_bits,
                                job->iv_len_in_bytes);
#endif
        }

        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/* ========================================================================= */
/* SM4 */
/* ========================================================================= */
__forceinline IMB_JOB *
SUBMIT_JOB_SM4_ECB_ENC(IMB_JOB *job)
{
        SM4_ECB(job->src + job->cipher_start_src_offset_in_bytes, job->dst,
                job->msg_len_to_cipher_in_bytes & (~15), job->enc_keys);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_SM4_ECB_DEC(IMB_JOB *job)
{
        SM4_ECB(job->src + job->cipher_start_src_offset_in_bytes, job->dst,
                job->msg_len_to_cipher_in_bytes & (~15), job->dec_keys);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_SM4_CBC_ENC(IMB_JOB *job)
{
        SM4_CBC_ENC(job->src + job->cipher_start_src_offset_in_bytes, job->dst,
                    job->msg_len_to_cipher_in_bytes & (~15), job->enc_keys, job->iv);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_SM4_CBC_DEC(IMB_JOB *job)
{
        SM4_CBC_DEC(job->src + job->cipher_start_src_offset_in_bytes, job->dst,
                    job->msg_len_to_cipher_in_bytes & (~15), job->dec_keys, job->iv);
        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/* ========================================================================= */
/* AES-CFB ENC*/
/* ========================================================================= */
__forceinline IMB_JOB *
SUBMIT_JOB_AES_CFB_ENC(IMB_JOB *job, const uint64_t key_sz)
{
        if (IMB_KEY_128_BYTES == key_sz) {
#ifdef SUBMIT_JOB_AES_CFB_128_ENC
                SUBMIT_JOB_AES_CFB_128_ENC(job);
#else
                AES_CFB_128_ENC(job->dst, job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                                job->enc_keys, job->msg_len_to_cipher_in_bytes);
#endif
        } else if (IMB_KEY_192_BYTES == key_sz) {
#ifdef SUBMIT_JOB_AES_CFB_192_ENC
                SUBMIT_JOB_AES_CFB_192_ENC(job);
#else
                AES_CFB_192_ENC(job->dst, job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                                job->enc_keys, job->msg_len_to_cipher_in_bytes);
#endif
        } else /* assume 256-bit key */ {
#ifdef SUBMIT_JOB_AES_CFB_256_ENC
                SUBMIT_JOB_AES_CFB_256_ENC(job);
#else
                AES_CFB_256_ENC(job->dst, job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                                job->enc_keys, job->msg_len_to_cipher_in_bytes);
#endif
        }

        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/* ========================================================================= */
/* AES-CFB DEC */
/* ========================================================================= */
__forceinline IMB_JOB *
SUBMIT_JOB_AES_CFB_DEC(IMB_JOB *job, const uint64_t key_sz)
{
        if (IMB_KEY_128_BYTES == key_sz) {
#ifdef SUBMIT_JOB_AES_CFB_128_DEC
                SUBMIT_JOB_AES_CFB_128_DEC(job);
#else
                AES_CFB_128_DEC(job->dst, job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                                job->dec_keys, job->msg_len_to_cipher_in_bytes);
#endif
        } else if (IMB_KEY_192_BYTES == key_sz) {
#ifdef SUBMIT_JOB_AES_CFB_192_DEC
                SUBMIT_JOB_AES_CFB_192_DEC(job);
#else
                AES_CFB_192_DEC(job->dst, job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                                job->dec_keys, job->msg_len_to_cipher_in_bytes);
#endif
        } else /* assume 256-bit key */ {
#ifdef SUBMIT_JOB_AES_CFB_256_DEC
                SUBMIT_JOB_AES_CFB_256_DEC(job);
#else
                AES_CFB_256_DEC(job->dst, job->src + job->cipher_start_src_offset_in_bytes, job->iv,
                                job->dec_keys, job->msg_len_to_cipher_in_bytes);
#endif
        }

        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        return job;
}

/* ========================================================================= */
/* Custom hash / cipher */
/* ========================================================================= */

__forceinline IMB_JOB *
JOB_CUSTOM_CIPHER(IMB_JOB *job)
{
        if (!(job->status & IMB_STATUS_COMPLETED_CIPHER)) {
                if (job->cipher_func(job))
                        job->status = IMB_STATUS_INTERNAL_ERROR;
                else
                        job->status |= IMB_STATUS_COMPLETED_CIPHER;
        }
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_CUSTOM_CIPHER(IMB_JOB *job)
{
        return JOB_CUSTOM_CIPHER(job);
}

__forceinline IMB_JOB *
FLUSH_JOB_CUSTOM_CIPHER(IMB_JOB *job)
{
        return JOB_CUSTOM_CIPHER(job);
}

__forceinline IMB_JOB *
JOB_CUSTOM_HASH(IMB_JOB *job)
{
        if (!(job->status & IMB_STATUS_COMPLETED_AUTH)) {
                if (job->hash_func(job))
                        job->status = IMB_STATUS_INTERNAL_ERROR;
                else
                        job->status |= IMB_STATUS_COMPLETED_AUTH;
        }
        return job;
}

__forceinline IMB_JOB *
SUBMIT_JOB_CUSTOM_HASH(IMB_JOB *job)
{
        return JOB_CUSTOM_HASH(job);
}

__forceinline IMB_JOB *
FLUSH_JOB_CUSTOM_HASH(IMB_JOB *job)
{
        return JOB_CUSTOM_HASH(job);
}

/* ========================================================================= */
/* Cipher submit & flush functions */
/* ========================================================================= */
__forceinline IMB_JOB *
SUBMIT_JOB_CIPHER_ENC(IMB_MGR *state, IMB_JOB *job, const IMB_CIPHER_MODE cipher_mode,
                      const uint64_t key_sz)
{
        if (IMB_CIPHER_GCM == cipher_mode) {
                return SUBMIT_JOB_AES_GCM_ENC(state, job, key_sz);
        } else if (IMB_CIPHER_GCM_SGL == cipher_mode) {
                return submit_gcm_sgl_enc(state, job, key_sz);
        } else if (IMB_CIPHER_CBC == cipher_mode) {
                if (16 == key_sz) {
                        MB_MGR_AES_OOO *aes128_ooo = state->aes128_ooo;

                        return SUBMIT_JOB_AES_CBC_128_ENC(aes128_ooo, job);
                } else if (24 == key_sz) {
                        MB_MGR_AES_OOO *aes192_ooo = state->aes192_ooo;

                        return SUBMIT_JOB_AES_CBC_192_ENC(aes192_ooo, job);
                } else { /* assume 32 */
                        MB_MGR_AES_OOO *aes256_ooo = state->aes256_ooo;

                        return SUBMIT_JOB_AES_CBC_256_ENC(aes256_ooo, job);
                }
        } else if (IMB_CIPHER_CNTR == cipher_mode) {
                return SUBMIT_JOB_AES_CTR(job, key_sz);
        } else if (IMB_CIPHER_CNTR_BITLEN == cipher_mode) {
                return SUBMIT_JOB_AES_CTR_BIT(job, key_sz);
        } else if (IMB_CIPHER_ECB == cipher_mode) {
                if (16 == key_sz) {
                        return SUBMIT_JOB_AES_ECB_128_ENC(job);
                } else if (24 == key_sz) {
                        return SUBMIT_JOB_AES_ECB_192_ENC(job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES_ECB_256_ENC(job);
                }
        } else if (IMB_CIPHER_DOCSIS_SEC_BPI == cipher_mode) {
                return submit_docsis_enc_job(state, job, key_sz);
        } else if (IMB_CIPHER_PON_AES_CNTR == cipher_mode) {
                if (job->msg_len_to_cipher_in_bytes == 0)
                        return SUBMIT_JOB_PON_ENC_NO_CTR(job);
                else
                        return SUBMIT_JOB_PON_ENC(job);
        } else if (IMB_CIPHER_CUSTOM == cipher_mode) {
                return SUBMIT_JOB_CUSTOM_CIPHER(job);
        } else if (IMB_CIPHER_DES == cipher_mode) {
#ifdef SUBMIT_JOB_DES_CBC_ENC
                MB_MGR_DES_OOO *des_enc_ooo = state->des_enc_ooo;

                return SUBMIT_JOB_DES_CBC_ENC(des_enc_ooo, job);
#else
                return DES_CBC_ENC(job);
#endif /* SUBMIT_JOB_DES_CBC_ENC */
        } else if (IMB_CIPHER_CHACHA20 == cipher_mode) {
                return SUBMIT_JOB_CHACHA20_ENC_DEC(job);
        } else if (IMB_CIPHER_CHACHA20_POLY1305 == cipher_mode) {
                return SUBMIT_JOB_CHACHA20_POLY1305(state, job);
        } else if (IMB_CIPHER_CHACHA20_POLY1305_SGL == cipher_mode) {
                return SUBMIT_JOB_CHACHA20_POLY1305_SGL(state, job);
        } else if (IMB_CIPHER_DOCSIS_DES == cipher_mode) {
#ifdef SUBMIT_JOB_DOCSIS_DES_ENC
                MB_MGR_DES_OOO *docsis_des_enc_ooo = state->docsis_des_enc_ooo;

                return SUBMIT_JOB_DOCSIS_DES_ENC(docsis_des_enc_ooo, job);
#else
                return DOCSIS_DES_ENC(job);
#endif /* SUBMIT_JOB_DOCSIS_DES_ENC */
        } else if (IMB_CIPHER_DES3 == cipher_mode) {
#ifdef SUBMIT_JOB_3DES_CBC_ENC
                MB_MGR_DES_OOO *des3_enc_ooo = state->des3_enc_ooo;

                return SUBMIT_JOB_3DES_CBC_ENC(des3_enc_ooo, job);
#else
                return DES3_CBC_ENC(job);
#endif
        } else if (IMB_CIPHER_CCM == cipher_mode) {
                if (16 == key_sz) {
                        return AES_CNTR_CCM_128(job);
                } else { /* assume 32 */
                        return AES_CNTR_CCM_256(job);
                }
        } else if (IMB_CIPHER_ZUC_EEA3 == cipher_mode) {
                if (16 == key_sz) {
                        MB_MGR_ZUC_OOO *zuc_eea3_ooo = state->zuc_eea3_ooo;

                        return SUBMIT_JOB_ZUC_EEA3(zuc_eea3_ooo, job);
                } else { /* assume 32 */
                        MB_MGR_ZUC_OOO *zuc256_eea3_ooo = state->zuc256_eea3_ooo;

                        return SUBMIT_JOB_ZUC256_EEA3(zuc256_eea3_ooo, job);
                }
        } else if (IMB_CIPHER_SNOW3G_UEA2_BITLEN == cipher_mode) {
#ifdef SUBMIT_JOB_SNOW3G_UEA2
                return SUBMIT_JOB_SNOW3G_UEA2(state, job);
#else
                return def_submit_snow3g_uea2_job(state, job);
#endif
        } else if (IMB_CIPHER_KASUMI_UEA1_BITLEN == cipher_mode) {
                return submit_kasumi_uea1_job(state, job);
        } else if (IMB_CIPHER_CBCS_1_9 == cipher_mode) {
                MB_MGR_AES_OOO *aes128_cbcs_ooo = state->aes128_cbcs_ooo;

                return SUBMIT_JOB_AES128_CBCS_1_9_ENC(aes128_cbcs_ooo, job);
        } else if (IMB_CIPHER_SNOW_V == cipher_mode) {
                return SUBMIT_JOB_SNOW_V(job);
        } else if (IMB_CIPHER_SNOW_V_AEAD == cipher_mode) {
                return submit_snow_v_aead_job(state, job);
        } else if (IMB_CIPHER_SM4_ECB == cipher_mode) {
                return SUBMIT_JOB_SM4_ECB_ENC(job);
        } else if (IMB_CIPHER_SM4_CBC == cipher_mode) {
                return SUBMIT_JOB_SM4_CBC_ENC(job);
        } else if (IMB_CIPHER_CFB == cipher_mode) {
                return SUBMIT_JOB_AES_CFB_ENC(job, key_sz);
        } else { /* assume IMB_CIPHER_NULL */
                job->status |= IMB_STATUS_COMPLETED_CIPHER;
                return job;
        }
}

__forceinline IMB_JOB *
FLUSH_JOB_CIPHER_ENC(IMB_MGR *state, IMB_JOB *job, const IMB_CIPHER_MODE cipher_mode,
                     const uint64_t key_sz)
{
        if (IMB_CIPHER_CBC == cipher_mode) {
                if (16 == key_sz) {
                        MB_MGR_AES_OOO *aes128_ooo = state->aes128_ooo;

                        return FLUSH_JOB_AES_CBC_128_ENC(aes128_ooo);
                } else if (24 == key_sz) {
                        MB_MGR_AES_OOO *aes192_ooo = state->aes192_ooo;

                        return FLUSH_JOB_AES_CBC_192_ENC(aes192_ooo);
                } else { /* assume 32 */
                        MB_MGR_AES_OOO *aes256_ooo = state->aes256_ooo;

                        return FLUSH_JOB_AES_CBC_256_ENC(aes256_ooo);
                }
        } else if (IMB_CIPHER_DOCSIS_SEC_BPI == cipher_mode) {
                return flush_docsis_enc_job(state, job, key_sz);
#ifdef FLUSH_JOB_DES_CBC_ENC
        } else if (IMB_CIPHER_DES == cipher_mode) {
                MB_MGR_DES_OOO *des_enc_ooo = state->des_enc_ooo;

                return FLUSH_JOB_DES_CBC_ENC(des_enc_ooo);
#endif /* FLUSH_JOB_DES_CBC_ENC */
#ifdef FLUSH_JOB_3DES_CBC_ENC
        } else if (IMB_CIPHER_DES3 == cipher_mode) {
                MB_MGR_DES_OOO *des3_enc_ooo = state->des3_enc_ooo;

                return FLUSH_JOB_3DES_CBC_ENC(des3_enc_ooo);
#endif /* FLUSH_JOB_3DES_CBC_ENC */
#ifdef FLUSH_JOB_DOCSIS_DES_ENC
        } else if (IMB_CIPHER_DOCSIS_DES == cipher_mode) {
                MB_MGR_DES_OOO *docsis_des_enc_ooo = state->docsis_des_enc_ooo;

                return FLUSH_JOB_DOCSIS_DES_ENC(docsis_des_enc_ooo);
#endif /* FLUSH_JOB_DOCSIS_DES_ENC */
        } else if (IMB_CIPHER_CUSTOM == cipher_mode) {
                return FLUSH_JOB_CUSTOM_CIPHER(job);
        } else if (IMB_CIPHER_ZUC_EEA3 == cipher_mode) {
                if (16 == key_sz) {
                        MB_MGR_ZUC_OOO *zuc_eea3_ooo = state->zuc_eea3_ooo;

                        return FLUSH_JOB_ZUC_EEA3(zuc_eea3_ooo);
                } else { /* assume 32 */
                        MB_MGR_ZUC_OOO *zuc256_eea3_ooo = state->zuc256_eea3_ooo;

                        return FLUSH_JOB_ZUC256_EEA3(zuc256_eea3_ooo);
                }
        } else if (IMB_CIPHER_CBCS_1_9 == cipher_mode) {
                MB_MGR_AES_OOO *aes128_cbcs_ooo = state->aes128_cbcs_ooo;

                return FLUSH_JOB_AES128_CBCS_1_9_ENC(aes128_cbcs_ooo);
#ifdef FLUSH_JOB_SNOW3G_UEA2
        } else if (IMB_CIPHER_SNOW3G_UEA2_BITLEN == cipher_mode) {
                return FLUSH_JOB_SNOW3G_UEA2(state);
#endif
                /**
                 * assume IMB_CIPHER_CNTR/CNTR_BITLEN, IMB_CIPHER_ECB,
                 * IMB_CIPHER_CCM, IMB_CIPHER_NULL, IMB_CIPHER_CFB
                 * or IMB_CIPHER_GCM
                 */
        } else {
                return NULL;
        }
}

__forceinline IMB_JOB *
SUBMIT_JOB_CIPHER_DEC(IMB_MGR *state, IMB_JOB *job, const IMB_CIPHER_MODE cipher_mode,
                      const uint64_t key_sz)
{
        if (IMB_CIPHER_GCM == cipher_mode) {
                return SUBMIT_JOB_AES_GCM_DEC(state, job, key_sz);
        } else if (IMB_CIPHER_GCM_SGL == cipher_mode) {
                return submit_gcm_sgl_dec(state, job, key_sz);
        } else if (IMB_CIPHER_CBC == cipher_mode) {
                if (16 == key_sz) {
                        return SUBMIT_JOB_AES_CBC_128_DEC(job);
                } else if (24 == key_sz) {
                        return SUBMIT_JOB_AES_CBC_192_DEC(job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES_CBC_256_DEC(job);
                }
        } else if (IMB_CIPHER_CNTR == cipher_mode) {
                return SUBMIT_JOB_AES_CTR(job, key_sz);
        } else if (IMB_CIPHER_CNTR_BITLEN == cipher_mode) {
                return SUBMIT_JOB_AES_CTR_BIT(job, key_sz);
        } else if (IMB_CIPHER_ECB == cipher_mode) {
                if (16 == key_sz) {
                        return SUBMIT_JOB_AES_ECB_128_DEC(job);
                } else if (24 == key_sz) {
                        return SUBMIT_JOB_AES_ECB_192_DEC(job);
                } else { /* assume 32 */
                        return SUBMIT_JOB_AES_ECB_256_DEC(job);
                }
        } else if (IMB_CIPHER_DOCSIS_SEC_BPI == cipher_mode) {
                return submit_docsis_dec_job(state, job, key_sz);
        } else if (IMB_CIPHER_PON_AES_CNTR == cipher_mode) {
                if (job->msg_len_to_cipher_in_bytes == 0)
                        return SUBMIT_JOB_PON_DEC_NO_CTR(job);
                else
                        return SUBMIT_JOB_PON_DEC(job);
        } else if (IMB_CIPHER_DES == cipher_mode) {
#ifdef SUBMIT_JOB_DES_CBC_DEC
                MB_MGR_DES_OOO *des_dec_ooo = state->des_dec_ooo;

                return SUBMIT_JOB_DES_CBC_DEC(des_dec_ooo, job);
#else
                (void) state;
                return DES_CBC_DEC(job);
#endif /* SUBMIT_JOB_DES_CBC_DEC */
        } else if (IMB_CIPHER_CHACHA20 == cipher_mode) {
                return SUBMIT_JOB_CHACHA20_ENC_DEC(job);
        } else if (IMB_CIPHER_CHACHA20_POLY1305 == cipher_mode) {
                return SUBMIT_JOB_CHACHA20_POLY1305(state, job);
        } else if (IMB_CIPHER_CHACHA20_POLY1305_SGL == cipher_mode) {
                return SUBMIT_JOB_CHACHA20_POLY1305_SGL(state, job);
        } else if (IMB_CIPHER_DOCSIS_DES == cipher_mode) {
#ifdef SUBMIT_JOB_DOCSIS_DES_DEC
                MB_MGR_DES_OOO *docsis_des_dec_ooo = state->docsis_des_dec_ooo;

                return SUBMIT_JOB_DOCSIS_DES_DEC(docsis_des_dec_ooo, job);
#else
                return DOCSIS_DES_DEC(job);
#endif /* SUBMIT_JOB_DOCSIS_DES_DEC */
        } else if (IMB_CIPHER_DES3 == cipher_mode) {
#ifdef SUBMIT_JOB_3DES_CBC_DEC
                MB_MGR_DES_OOO *des3_dec_ooo = state->des3_dec_ooo;

                return SUBMIT_JOB_3DES_CBC_DEC(des3_dec_ooo, job);
#else
                return DES3_CBC_DEC(job);
#endif
        } else if (IMB_CIPHER_CUSTOM == cipher_mode) {
                return SUBMIT_JOB_CUSTOM_CIPHER(job);
        } else if (IMB_CIPHER_CCM == cipher_mode) {
                if (16 == key_sz) {
                        return AES_CNTR_CCM_128(job);
                } else { /* assume 32 */
                        return AES_CNTR_CCM_256(job);
                }
        } else if (IMB_CIPHER_ZUC_EEA3 == cipher_mode) {
                if (16 == key_sz) {
                        MB_MGR_ZUC_OOO *zuc_eea3_ooo = state->zuc_eea3_ooo;

                        return SUBMIT_JOB_ZUC_EEA3(zuc_eea3_ooo, job);
                } else { /* assume 32 */
                        MB_MGR_ZUC_OOO *zuc256_eea3_ooo = state->zuc256_eea3_ooo;

                        return SUBMIT_JOB_ZUC256_EEA3(zuc256_eea3_ooo, job);
                }
        } else if (IMB_CIPHER_SNOW3G_UEA2_BITLEN == cipher_mode) {
#ifdef SUBMIT_JOB_SNOW3G_UEA2
                return SUBMIT_JOB_SNOW3G_UEA2(state, job);
#else
                return def_submit_snow3g_uea2_job(state, job);
#endif
        } else if (IMB_CIPHER_KASUMI_UEA1_BITLEN == cipher_mode) {
                return submit_kasumi_uea1_job(state, job);
        } else if (IMB_CIPHER_CBCS_1_9 == cipher_mode) {
                return SUBMIT_JOB_AES128_CBCS_1_9_DEC(job);
        } else if (IMB_CIPHER_SNOW_V == cipher_mode) {
                return SUBMIT_JOB_SNOW_V(job);
        } else if (IMB_CIPHER_SNOW_V_AEAD == cipher_mode) {
                return submit_snow_v_aead_job(state, job);
        } else if (IMB_CIPHER_SM4_ECB == cipher_mode) {
                return SUBMIT_JOB_SM4_ECB_DEC(job);
        } else if (IMB_CIPHER_SM4_CBC == cipher_mode) {
                return SUBMIT_JOB_SM4_CBC_DEC(job);
        } else if (IMB_CIPHER_CFB == cipher_mode) {
                return SUBMIT_JOB_AES_CFB_DEC(job, key_sz);
        } else {
                /* assume IMB_CIPHER_NULL */
                job->status |= IMB_STATUS_COMPLETED_CIPHER;
                return job;
        }
}

__forceinline IMB_JOB *
FLUSH_JOB_CIPHER_DEC(IMB_MGR *state, IMB_JOB *job, const IMB_CIPHER_MODE cipher_mode,
                     const uint64_t key_sz)
{
        (void) job;

#ifdef FLUSH_JOB_SNOW3G_UEA2
        if (IMB_CIPHER_SNOW3G_UEA2_BITLEN == cipher_mode)
                return FLUSH_JOB_SNOW3G_UEA2(state);
#endif

#ifdef FLUSH_JOB_DES_CBC_DEC
        if (IMB_CIPHER_DES == cipher_mode) {
                MB_MGR_DES_OOO *des_dec_ooo = state->des_dec_ooo;

                return FLUSH_JOB_DES_CBC_DEC(des_dec_ooo);
        }
#endif /* FLUSH_JOB_DES_CBC_DEC */

#ifdef FLUSH_JOB_3DES_CBC_DEC
        if (IMB_CIPHER_DES3 == cipher_mode) {
                MB_MGR_DES_OOO *des3_dec_ooo = state->des3_dec_ooo;

                return FLUSH_JOB_3DES_CBC_DEC(des3_dec_ooo);
        }
#endif /* FLUSH_JOB_3DES_CBC_DEC */

#ifdef FLUSH_JOB_DOCSIS_DES_DEC

        if (IMB_CIPHER_DOCSIS_DES == cipher_mode) {
                MB_MGR_DES_OOO *docsis_des_dec_ooo = state->docsis_des_dec_ooo;

                return FLUSH_JOB_DOCSIS_DES_DEC(docsis_des_dec_ooo);
        }
#endif /* FLUSH_JOB_DOCSIS_DES_DEC */

        if (IMB_CIPHER_ZUC_EEA3 == cipher_mode) {
                if (16 == key_sz) {
                        MB_MGR_ZUC_OOO *zuc_eea3_ooo = state->zuc_eea3_ooo;

                        return FLUSH_JOB_ZUC_EEA3(zuc_eea3_ooo);
                } else { /* assume 32 */
                        MB_MGR_ZUC_OOO *zuc256_eea3_ooo = state->zuc256_eea3_ooo;

                        return FLUSH_JOB_ZUC256_EEA3(zuc256_eea3_ooo);
                }
        }

        return NULL;
}

/* ========================================================================= */
/* Generate specialized submit cipher functions and create a table */
/* ========================================================================= */

/* ========================= */
/* ======== DECRYPT ======== */
/* ========================= */

/* AES-CBC */
static IMB_JOB *
submit_cipher_dec_aes_cbc_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CBC, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_cbc_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CBC, IMB_KEY_192_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_cbc_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CBC, IMB_KEY_256_BYTES);
}

/* AES-CTR */
static IMB_JOB *
submit_cipher_dec_aes_ctr_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_ctr_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR, IMB_KEY_192_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_ctr_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR, IMB_KEY_256_BYTES);
}

/* NULL */
static IMB_JOB *
submit_cipher_dec_null(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_NULL, IMB_KEY_128_BYTES);
}

/* AES DOCSIS */
static IMB_JOB *
submit_cipher_dec_aes_docsis_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_DOCSIS_SEC_BPI, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_docsis_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_DOCSIS_SEC_BPI, IMB_KEY_256_BYTES);
}

/* AES-GCM */
#define submit_cipher_dec_aes_gcm_128 AES_GCM_DEC_IV_128
#define submit_cipher_dec_aes_gcm_192 AES_GCM_DEC_IV_192
#define submit_cipher_dec_aes_gcm_256 AES_GCM_DEC_IV_256

/* CUSTOM */
static IMB_JOB *
submit_cipher_dec_custom(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CUSTOM, IMB_KEY_128_BYTES);
}

/* DES */
static IMB_JOB *
submit_cipher_dec_des_cbc_64(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_DES, IMB_KEY_64_BYTES);
}

/* DES DOCSIS */
static IMB_JOB *
submit_cipher_dec_des_docsis_64(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_DOCSIS_DES, IMB_KEY_64_BYTES);
}

/* AES-CCM */
static IMB_JOB *
submit_cipher_dec_aes_ccm_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CCM, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_ccm_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CCM, IMB_KEY_256_BYTES);
}

/* 3DES */
static IMB_JOB *
submit_cipher_dec_des3_cbc_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_DES3, IMB_KEY_192_BYTES);
}

/* PON AES-CTR */
static IMB_JOB *
submit_cipher_dec_aes_ctr_pon_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_PON_AES_CNTR, IMB_KEY_128_BYTES);
}

/* AES-ECB */
static IMB_JOB *
submit_cipher_dec_aes_ecb_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_ECB, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_ecb_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_ECB, IMB_KEY_192_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_ecb_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_ECB, IMB_KEY_256_BYTES);
}

/* AES-CTR BITS */
static IMB_JOB *
submit_cipher_dec_aes_ctr_128_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_ctr_192_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_192_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_ctr_256_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_256_BYTES);
}

/* ZUC EEA3 */
static IMB_JOB *
submit_cipher_dec_zuc_eea3_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_ZUC_EEA3, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_dec_zuc_eea3_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_ZUC_EEA3, IMB_KEY_256_BYTES);
}

/* SNOW3G UEA2 */
static IMB_JOB *
submit_cipher_dec_snow3g_uea2_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_SNOW3G_UEA2_BITLEN, IMB_KEY_128_BYTES);
}

/* KASUMI F8 UEA1 */
static IMB_JOB *
submit_cipher_dec_kasumi_uea1_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_KASUMI_UEA1_BITLEN, IMB_KEY_128_BYTES);
}

/* AES-CBCS-1-9 */
static IMB_JOB *
submit_cipher_dec_aes_cbcs_1_9(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CBCS_1_9, IMB_KEY_128_BYTES);
}

/* CHACHA20 */
static IMB_JOB *
submit_cipher_dec_chacha20(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CHACHA20, IMB_KEY_256_BYTES);
}

/* CHACHA20-POLY1305 */
static IMB_JOB *
submit_cipher_dec_chacha20_poly1305(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CHACHA20_POLY1305, IMB_KEY_256_BYTES);
}

/* CHACHA20-POLY1305 SGL */
static IMB_JOB *
submit_cipher_dec_chacha20_poly1305_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CHACHA20_POLY1305_SGL,
                                     IMB_KEY_256_BYTES);
}

/* SNOW-V */
static IMB_JOB *
submit_cipher_dec_snow_v(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_SNOW_V, IMB_KEY_256_BYTES);
}

/* SNOW-V AEAD */
static IMB_JOB *
submit_cipher_dec_snow_v_aead(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_SNOW_V_AEAD, IMB_KEY_256_BYTES);
}

/* AES-GCM SGL */
static IMB_JOB *
submit_cipher_dec_aes_gcm_128_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_gcm_192_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_192_BYTES);
}

static IMB_JOB *
submit_cipher_dec_aes_gcm_256_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_256_BYTES);
}

/* SM4-ECB */
static IMB_JOB *
submit_cipher_dec_sm4_ecb(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_SM4_ECB, IMB_KEY_128_BYTES);
}

/* SM4-CBC */
static IMB_JOB *
submit_cipher_dec_sm4_cbc(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_SM4_CBC, IMB_KEY_128_BYTES);
}

/* AES-CFB 128 */
static IMB_JOB *
submit_cipher_dec_cfb_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CFB, IMB_KEY_128_BYTES);
}

/* AES-CFB 192 */
static IMB_JOB *
submit_cipher_dec_cfb_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CFB, IMB_KEY_192_BYTES);
}

/* AES-CFB 256 */
static IMB_JOB *
submit_cipher_dec_cfb_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CFB, IMB_KEY_256_BYTES);
}

/* ========================= */
/* ======== ENCRYPT ======== */
/* ========================= */

/* AES-CBC */
static IMB_JOB *
submit_cipher_enc_aes_cbc_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CBC, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_cbc_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CBC, IMB_KEY_192_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_cbc_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CBC, IMB_KEY_256_BYTES);
}

/* AES-CTR */
static IMB_JOB *
submit_cipher_enc_aes_ctr_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_ctr_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR, IMB_KEY_192_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_ctr_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR, IMB_KEY_256_BYTES);
}

/* NULL */
static IMB_JOB *
submit_cipher_enc_null(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_NULL, IMB_KEY_128_BYTES);
}

/* AES DOCSIS */
static IMB_JOB *
submit_cipher_enc_aes_docsis_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_DOCSIS_SEC_BPI, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_docsis_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_DOCSIS_SEC_BPI, IMB_KEY_256_BYTES);
}

/* AES-GCM */
#define submit_cipher_enc_aes_gcm_128 AES_GCM_ENC_IV_128
#define submit_cipher_enc_aes_gcm_192 AES_GCM_ENC_IV_192
#define submit_cipher_enc_aes_gcm_256 AES_GCM_ENC_IV_256

/* CUSTOM */
static IMB_JOB *
submit_cipher_enc_custom(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CUSTOM, IMB_KEY_128_BYTES);
}

/* DES */
static IMB_JOB *
submit_cipher_enc_des_cbc_64(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_DES, IMB_KEY_64_BYTES);
}

/* DES DOCSIS */
static IMB_JOB *
submit_cipher_enc_des_docsis_64(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_DOCSIS_DES, IMB_KEY_64_BYTES);
}

/* AES-CCM */
static IMB_JOB *
submit_cipher_enc_aes_ccm_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CCM, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_ccm_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CCM, IMB_KEY_256_BYTES);
}

/* 3DES */
static IMB_JOB *
submit_cipher_enc_des3_cbc_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_DES3, IMB_KEY_192_BYTES);
}

/* PON AES-CTR */
static IMB_JOB *
submit_cipher_enc_aes_ctr_pon_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_PON_AES_CNTR, IMB_KEY_128_BYTES);
}

/* AES-ECB */
static IMB_JOB *
submit_cipher_enc_aes_ecb_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_ECB, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_ecb_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_ECB, IMB_KEY_192_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_ecb_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_ECB, IMB_KEY_256_BYTES);
}

/* AES-CTR BITS */
static IMB_JOB *
submit_cipher_enc_aes_ctr_128_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_ctr_192_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_192_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_ctr_256_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_256_BYTES);
}

/* ZUC EEA3 */
static IMB_JOB *
submit_cipher_enc_zuc_eea3_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_ZUC_EEA3, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_enc_zuc_eea3_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_ZUC_EEA3, IMB_KEY_256_BYTES);
}

/* SNOW3G UEA2 */
static IMB_JOB *
submit_cipher_enc_snow3g_uea2_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_SNOW3G_UEA2_BITLEN, IMB_KEY_128_BYTES);
}

/* KASUMI F8 UEA1 */
static IMB_JOB *
submit_cipher_enc_kasumi_uea1_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_KASUMI_UEA1_BITLEN, IMB_KEY_128_BYTES);
}

/* AES-CBCS-1-9 */
static IMB_JOB *
submit_cipher_enc_aes_cbcs_1_9(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CBCS_1_9, IMB_KEY_128_BYTES);
}

/* CHACHA20 */
static IMB_JOB *
submit_cipher_enc_chacha20(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CHACHA20, IMB_KEY_256_BYTES);
}

/* CHACHA20-POLY1305 */
static IMB_JOB *
submit_cipher_enc_chacha20_poly1305(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CHACHA20_POLY1305, IMB_KEY_256_BYTES);
}

/* CHACHA20-POLY1305 SGL */
static IMB_JOB *
submit_cipher_enc_chacha20_poly1305_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CHACHA20_POLY1305_SGL,
                                     IMB_KEY_256_BYTES);
}

/* SNOW-V */
static IMB_JOB *
submit_cipher_enc_snow_v(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_SNOW_V, IMB_KEY_256_BYTES);
}

/* SNOW-V AEAD */
static IMB_JOB *
submit_cipher_enc_snow_v_aead(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_SNOW_V_AEAD, IMB_KEY_256_BYTES);
}

/* AES-GCM SGL */
static IMB_JOB *
submit_cipher_enc_aes_gcm_128_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_128_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_gcm_192_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_192_BYTES);
}

static IMB_JOB *
submit_cipher_enc_aes_gcm_256_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_256_BYTES);
}

/* SM4-ECB */
static IMB_JOB *
submit_cipher_enc_sm4_ecb(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_SM4_ECB, IMB_KEY_128_BYTES);
}

/* SM4-CBC */
static IMB_JOB *
submit_cipher_enc_sm4_cbc(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_SM4_CBC, IMB_KEY_128_BYTES);
}
/* AES-CFB */
static IMB_JOB *
submit_cipher_enc_cfb_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CFB, IMB_KEY_128_BYTES);
}

/* AES-CFB */
static IMB_JOB *
submit_cipher_enc_cfb_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CFB, IMB_KEY_192_BYTES);
}
/* AES-CFB */
static IMB_JOB *
submit_cipher_enc_cfb_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CFB, IMB_KEY_256_BYTES);
}
/*
 * Four entries per algorithm (different key sizes),
 * algorithms in the same order IMB_CIPHER_MODE
 *     index 0 - key size from 0 to 64-bits
 *     index 1 - key size from 65 to 128-bits
 *     index 2 - key size from 129 to 192-bits
 *     index 3 - key size from 193 to 256-bits
 */
typedef IMB_JOB *(*submit_flush_fn_t)(IMB_MGR *, IMB_JOB *);

#define ENCRYPT_DECRYPT_GAP 32

static const submit_flush_fn_t tab_submit_cipher[] = {
        /* ========================= */
        /* === DECRYPT DIRECTION === */
        /* ========================= */

        /* [0] keep empty - enums start from value 1 */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [1] AES-CBC */
        submit_cipher_dec_null,
        submit_cipher_dec_aes_cbc_128,
        submit_cipher_dec_aes_cbc_192,
        submit_cipher_dec_aes_cbc_256,
        /* [2] AES-CBC */
        submit_cipher_dec_null,
        submit_cipher_dec_aes_ctr_128,
        submit_cipher_dec_aes_ctr_192,
        submit_cipher_dec_aes_ctr_256,
        /* [3] NULL */
        submit_cipher_dec_null,
        submit_cipher_dec_null,
        submit_cipher_dec_null,
        submit_cipher_dec_null,
        /* [4] DOCSIS SEC BPI */
        submit_cipher_dec_null,
        submit_cipher_dec_aes_docsis_128,
        submit_cipher_dec_null,
        submit_cipher_dec_aes_docsis_256,
        /* [5] AES-GCM */
        submit_cipher_dec_null,
        submit_cipher_dec_aes_gcm_128,
        submit_cipher_dec_aes_gcm_192,
        submit_cipher_dec_aes_gcm_256,
        /* [6] CUSTOM */
        submit_cipher_dec_custom,
        submit_cipher_dec_custom,
        submit_cipher_dec_custom,
        submit_cipher_dec_custom,
        /* [7] DES */
        submit_cipher_dec_des_cbc_64,
        submit_cipher_dec_des_cbc_64,
        submit_cipher_dec_des_cbc_64,
        submit_cipher_dec_des_cbc_64,
        /* [8] DOCSIS DES */
        submit_cipher_dec_des_docsis_64,
        submit_cipher_dec_des_docsis_64,
        submit_cipher_dec_des_docsis_64,
        submit_cipher_dec_des_docsis_64,
        /* [9] AES-CCM */
        submit_cipher_dec_null,
        submit_cipher_dec_aes_ccm_128,
        submit_cipher_dec_null,
        submit_cipher_dec_aes_ccm_256,
        /* [10] 3DES */
        submit_cipher_dec_des3_cbc_192,
        submit_cipher_dec_des3_cbc_192,
        submit_cipher_dec_des3_cbc_192,
        submit_cipher_dec_des3_cbc_192,
        /* [11] PON AES-CTR */
        submit_cipher_dec_aes_ctr_pon_128,
        submit_cipher_dec_aes_ctr_pon_128,
        submit_cipher_dec_aes_ctr_pon_128,
        submit_cipher_dec_aes_ctr_pon_128,
        /* [12] AES-ECB */
        submit_cipher_dec_null,
        submit_cipher_dec_aes_ecb_128,
        submit_cipher_dec_aes_ecb_192,
        submit_cipher_dec_aes_ecb_256,
        /* [13] AES-CTR BITLEN */
        submit_cipher_dec_null,
        submit_cipher_dec_aes_ctr_128_bit,
        submit_cipher_dec_aes_ctr_192_bit,
        submit_cipher_dec_aes_ctr_256_bit,
        /* [14] ZUC EEA3 */
        submit_cipher_dec_null,
        submit_cipher_dec_zuc_eea3_128,
        submit_cipher_dec_null,
        submit_cipher_dec_zuc_eea3_256,
        /* [15] SNOW3G UEA2 */
        submit_cipher_dec_snow3g_uea2_bit,
        submit_cipher_dec_snow3g_uea2_bit,
        submit_cipher_dec_snow3g_uea2_bit,
        submit_cipher_dec_snow3g_uea2_bit,
        /* [16] KASUMI F8 UEA1 */
        submit_cipher_dec_kasumi_uea1_bit,
        submit_cipher_dec_kasumi_uea1_bit,
        submit_cipher_dec_kasumi_uea1_bit,
        submit_cipher_dec_kasumi_uea1_bit,
        /* [17] AES-CBCS-1-9 */
        submit_cipher_dec_aes_cbcs_1_9,
        submit_cipher_dec_aes_cbcs_1_9,
        submit_cipher_dec_aes_cbcs_1_9,
        submit_cipher_dec_aes_cbcs_1_9,
        /* [18] CHACHA20 */
        submit_cipher_dec_chacha20,
        submit_cipher_dec_chacha20,
        submit_cipher_dec_chacha20,
        submit_cipher_dec_chacha20,
        /* [19] CHACHA20-POLY1305 */
        submit_cipher_dec_chacha20_poly1305,
        submit_cipher_dec_chacha20_poly1305,
        submit_cipher_dec_chacha20_poly1305,
        submit_cipher_dec_chacha20_poly1305,
        /* [20] CHACHA20-POLY1305 SGL */
        submit_cipher_dec_chacha20_poly1305_sgl,
        submit_cipher_dec_chacha20_poly1305_sgl,
        submit_cipher_dec_chacha20_poly1305_sgl,
        submit_cipher_dec_chacha20_poly1305_sgl,
        /* [21] SNOW-V */
        submit_cipher_dec_snow_v,
        submit_cipher_dec_snow_v,
        submit_cipher_dec_snow_v,
        submit_cipher_dec_snow_v,
        /* [22] SNOW-V AEAD */
        submit_cipher_dec_snow_v_aead,
        submit_cipher_dec_snow_v_aead,
        submit_cipher_dec_snow_v_aead,
        submit_cipher_dec_snow_v_aead,
        /* [23] AES-GCM SGL */
        submit_cipher_dec_null,
        submit_cipher_dec_aes_gcm_128_sgl,
        submit_cipher_dec_aes_gcm_192_sgl,
        submit_cipher_dec_aes_gcm_256_sgl,
        /* [24] SM4-ECB */
        submit_cipher_dec_null,
        submit_cipher_dec_sm4_ecb,
        submit_cipher_dec_null,
        submit_cipher_dec_null,
        /* [25] SM4-CBC */
        submit_cipher_dec_null,
        submit_cipher_dec_sm4_cbc,
        submit_cipher_dec_null,
        submit_cipher_dec_null,
        /* [26] AES-CFB */
        submit_cipher_dec_null,
        submit_cipher_dec_cfb_128,
        submit_cipher_dec_cfb_192,
        submit_cipher_dec_cfb_256,
        /* add new cipher decrypt here */
        /* [27] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [28] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [29] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [30] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [31] NULL */
        NULL,
        NULL,
        NULL,
        NULL,

        /* ========================= */
        /* === ENCRYPT DIRECTION === */
        /* ========================= */

        /* [0] keep empty - enums start from value 1 */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [1] AES-CBC */
        submit_cipher_enc_null,
        submit_cipher_enc_aes_cbc_128,
        submit_cipher_enc_aes_cbc_192,
        submit_cipher_enc_aes_cbc_256,
        /* [2] AES-CBC */
        submit_cipher_enc_null,
        submit_cipher_enc_aes_ctr_128,
        submit_cipher_enc_aes_ctr_192,
        submit_cipher_enc_aes_ctr_256,
        /* [3] NULL */
        submit_cipher_enc_null,
        submit_cipher_enc_null,
        submit_cipher_enc_null,
        submit_cipher_enc_null,
        /* [4] DOCSIS SEC BPI */
        submit_cipher_enc_null,
        submit_cipher_enc_aes_docsis_128,
        submit_cipher_enc_null,
        submit_cipher_enc_aes_docsis_256,
        /* [5] AES-GCM */
        submit_cipher_enc_null,
        submit_cipher_enc_aes_gcm_128,
        submit_cipher_enc_aes_gcm_192,
        submit_cipher_enc_aes_gcm_256,
        /* [6] CUSTOM */
        submit_cipher_enc_custom,
        submit_cipher_enc_custom,
        submit_cipher_enc_custom,
        submit_cipher_enc_custom,
        /* [7] DES */
        submit_cipher_enc_des_cbc_64,
        submit_cipher_enc_des_cbc_64,
        submit_cipher_enc_des_cbc_64,
        submit_cipher_enc_des_cbc_64,
        /* [8] DOCSIS DES */
        submit_cipher_enc_des_docsis_64,
        submit_cipher_enc_des_docsis_64,
        submit_cipher_enc_des_docsis_64,
        submit_cipher_enc_des_docsis_64,
        /* [9] AES-CCM */
        submit_cipher_enc_null,
        submit_cipher_enc_aes_ccm_128,
        submit_cipher_enc_null,
        submit_cipher_enc_aes_ccm_256,
        /* [10] 3DES */
        submit_cipher_enc_des3_cbc_192,
        submit_cipher_enc_des3_cbc_192,
        submit_cipher_enc_des3_cbc_192,
        submit_cipher_enc_des3_cbc_192,
        /* [11] PON AES-CTR */
        submit_cipher_enc_aes_ctr_pon_128,
        submit_cipher_enc_aes_ctr_pon_128,
        submit_cipher_enc_aes_ctr_pon_128,
        submit_cipher_enc_aes_ctr_pon_128,
        /* [12] AES-ECB */
        submit_cipher_enc_null,
        submit_cipher_enc_aes_ecb_128,
        submit_cipher_enc_aes_ecb_192,
        submit_cipher_enc_aes_ecb_256,
        /* [13] AES-CTR BITLEN */
        submit_cipher_enc_null,
        submit_cipher_enc_aes_ctr_128_bit,
        submit_cipher_enc_aes_ctr_192_bit,
        submit_cipher_enc_aes_ctr_256_bit,
        /* [14] ZUC EEA3 */
        submit_cipher_enc_null,
        submit_cipher_enc_zuc_eea3_128,
        submit_cipher_enc_null,
        submit_cipher_enc_zuc_eea3_256,
        /* [15] SNOW3G UEA2 */
        submit_cipher_enc_snow3g_uea2_bit,
        submit_cipher_enc_snow3g_uea2_bit,
        submit_cipher_enc_snow3g_uea2_bit,
        submit_cipher_enc_snow3g_uea2_bit,
        /* [16] KASUMI F8 UEA1 */
        submit_cipher_enc_kasumi_uea1_bit,
        submit_cipher_enc_kasumi_uea1_bit,
        submit_cipher_enc_kasumi_uea1_bit,
        submit_cipher_enc_kasumi_uea1_bit,
        /* [17] AES-CBCS-1-9 */
        submit_cipher_enc_aes_cbcs_1_9,
        submit_cipher_enc_aes_cbcs_1_9,
        submit_cipher_enc_aes_cbcs_1_9,
        submit_cipher_enc_aes_cbcs_1_9,
        /* [18] CHACHA20 */
        submit_cipher_enc_chacha20,
        submit_cipher_enc_chacha20,
        submit_cipher_enc_chacha20,
        submit_cipher_enc_chacha20,
        /* [19] CHACHA20-POLY1305 */
        submit_cipher_enc_chacha20_poly1305,
        submit_cipher_enc_chacha20_poly1305,
        submit_cipher_enc_chacha20_poly1305,
        submit_cipher_enc_chacha20_poly1305,
        /* [20] CHACHA20-POLY1305 SGL */
        submit_cipher_enc_chacha20_poly1305_sgl,
        submit_cipher_enc_chacha20_poly1305_sgl,
        submit_cipher_enc_chacha20_poly1305_sgl,
        submit_cipher_enc_chacha20_poly1305_sgl,
        /* [21] SNOW-V */
        submit_cipher_enc_snow_v,
        submit_cipher_enc_snow_v,
        submit_cipher_enc_snow_v,
        submit_cipher_enc_snow_v,
        /* [22] SNOW-V AEAD */
        submit_cipher_enc_snow_v_aead,
        submit_cipher_enc_snow_v_aead,
        submit_cipher_enc_snow_v_aead,
        submit_cipher_enc_snow_v_aead,
        /* [23] AES-GCM SGL */
        submit_cipher_enc_null,
        submit_cipher_enc_aes_gcm_128_sgl,
        submit_cipher_enc_aes_gcm_192_sgl,
        submit_cipher_enc_aes_gcm_256_sgl,
        /* [24] SM4-ECB */
        submit_cipher_enc_null,
        submit_cipher_enc_sm4_ecb,
        submit_cipher_enc_null,
        submit_cipher_enc_null,
        /* [25] SM4-CBC */
        submit_cipher_enc_null,
        submit_cipher_enc_sm4_cbc,
        submit_cipher_enc_null,
        submit_cipher_enc_null,
        /* [26] AES-CFB */
        submit_cipher_enc_null,
        submit_cipher_enc_cfb_128,
        submit_cipher_enc_cfb_192,
        submit_cipher_enc_cfb_256,
        /* add new cipher encrypt here */
        /* [27] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [28] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [29] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [30] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [31] NULL */
        NULL,
        NULL,
        NULL,
        NULL,

};

/* ========================================================================= */
/* Generate specialized flush cipher functions and create a table */
/* ========================================================================= */

/* ========================= */
/* ======== DECRYPT ======== */
/* ========================= */

/* AES-CBC */
static IMB_JOB *
flush_cipher_dec_aes_cbc_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CBC, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_cbc_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CBC, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_cbc_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CBC, IMB_KEY_256_BYTES);
}

/* AES-CTR */
static IMB_JOB *
flush_cipher_dec_aes_ctr_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_ctr_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_ctr_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR, IMB_KEY_256_BYTES);
}

/* NULL */
static IMB_JOB *
flush_cipher_dec_null(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_NULL, IMB_KEY_128_BYTES);
}

/* AES DOCSIS */
static IMB_JOB *
flush_cipher_dec_aes_docsis_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_DOCSIS_SEC_BPI, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_docsis_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_DOCSIS_SEC_BPI, IMB_KEY_256_BYTES);
}

/* AES-GCM */
static IMB_JOB *
flush_cipher_dec_aes_gcm_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_GCM, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_gcm_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_GCM, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_gcm_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_GCM, IMB_KEY_256_BYTES);
}

/* CUSTOM */
static IMB_JOB *
flush_cipher_dec_custom(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CUSTOM, IMB_KEY_128_BYTES);
}

/* DES */
static IMB_JOB *
flush_cipher_dec_des_cbc_64(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_DES, IMB_KEY_64_BYTES);
}

/* DES DOCSIS */
static IMB_JOB *
flush_cipher_dec_des_docsis_64(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_DOCSIS_DES, IMB_KEY_64_BYTES);
}

/* AES-CCM */
static IMB_JOB *
flush_cipher_dec_aes_ccm_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CCM, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_ccm_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CCM, IMB_KEY_256_BYTES);
}

/* 3DES */
static IMB_JOB *
flush_cipher_dec_des3_cbc_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_DES3, IMB_KEY_192_BYTES);
}

/* PON AES-CTR */
static IMB_JOB *
flush_cipher_dec_aes_ctr_pon_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_PON_AES_CNTR, IMB_KEY_128_BYTES);
}

/* AES-ECB */
static IMB_JOB *
flush_cipher_dec_aes_ecb_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_ECB, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_ecb_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_ECB, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_ecb_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_ECB, IMB_KEY_256_BYTES);
}

/* AES-CTR BITS */
static IMB_JOB *
flush_cipher_dec_aes_ctr_128_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_ctr_192_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_ctr_256_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_256_BYTES);
}

/* ZUC EEA3 */
static IMB_JOB *
flush_cipher_dec_zuc_eea3_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_ZUC_EEA3, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_dec_zuc_eea3_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_ZUC_EEA3, IMB_KEY_256_BYTES);
}

/* SNOW3G UEA2 */
static IMB_JOB *
flush_cipher_dec_snow3g_uea2_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_SNOW3G_UEA2_BITLEN, IMB_KEY_128_BYTES);
}

/* KASUMI F8 UEA1 */
static IMB_JOB *
flush_cipher_dec_kasumi_uea1_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_KASUMI_UEA1_BITLEN, IMB_KEY_128_BYTES);
}

/* AES-CBCS-1-9 */
static IMB_JOB *
flush_cipher_dec_aes_cbcs_1_9(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CBCS_1_9, IMB_KEY_128_BYTES);
}

/* CHACHA20 */
static IMB_JOB *
flush_cipher_dec_chacha20(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CHACHA20, IMB_KEY_256_BYTES);
}

/* CHACHA20-POLY1305 */
static IMB_JOB *
flush_cipher_dec_chacha20_poly1305(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CHACHA20_POLY1305, IMB_KEY_256_BYTES);
}

/* CHACHA20-POLY1305 SGL */
static IMB_JOB *
flush_cipher_dec_chacha20_poly1305_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CHACHA20_POLY1305_SGL,
                                    IMB_KEY_256_BYTES);
}

/* SNOW-V */
static IMB_JOB *
flush_cipher_dec_snow_v(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_SNOW_V, IMB_KEY_256_BYTES);
}

/* SNOW-V AEAD */
static IMB_JOB *
flush_cipher_dec_snow_v_aead(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_SNOW_V_AEAD, IMB_KEY_256_BYTES);
}

/* AES-GCM SGL */
static IMB_JOB *
flush_cipher_dec_aes_gcm_128_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_gcm_192_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_dec_aes_gcm_256_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_256_BYTES);
}

/* SM4-ECB */
static IMB_JOB *
flush_cipher_dec_sm4_ecb(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_SM4_ECB, IMB_KEY_128_BYTES);
}

/* SM4-CBC */
static IMB_JOB *
flush_cipher_dec_sm4_cbc(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_SM4_CBC, IMB_KEY_128_BYTES);
}

/* AES-CBC */
static IMB_JOB *
flush_cipher_dec_cfb_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CFB, IMB_KEY_128_BYTES);
}
static IMB_JOB *
flush_cipher_dec_cfb_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CFB, IMB_KEY_192_BYTES);
}
static IMB_JOB *
flush_cipher_dec_cfb_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_DEC(state, job, IMB_CIPHER_CFB, IMB_KEY_256_BYTES);
}
/* ========================= */
/* ======== ENCRYPT ======== */
/* ========================= */

/* AES-CBC */
static IMB_JOB *
flush_cipher_enc_aes_cbc_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CBC, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_cbc_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CBC, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_cbc_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CBC, IMB_KEY_256_BYTES);
}

/* AES-CTR */
static IMB_JOB *
flush_cipher_enc_aes_ctr_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_ctr_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_ctr_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR, IMB_KEY_256_BYTES);
}

/* NULL */
static IMB_JOB *
flush_cipher_enc_null(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_NULL, IMB_KEY_128_BYTES);
}

/* AES DOCSIS */
static IMB_JOB *
flush_cipher_enc_aes_docsis_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_DOCSIS_SEC_BPI, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_docsis_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_DOCSIS_SEC_BPI, IMB_KEY_256_BYTES);
}

/* AES-GCM */
static IMB_JOB *
flush_cipher_enc_aes_gcm_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_GCM, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_gcm_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_GCM, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_gcm_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_GCM, IMB_KEY_256_BYTES);
}

/* CUSTOM */
static IMB_JOB *
flush_cipher_enc_custom(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CUSTOM, IMB_KEY_128_BYTES);
}

/* DES */
static IMB_JOB *
flush_cipher_enc_des_cbc_64(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_DES, IMB_KEY_64_BYTES);
}

/* DES DOCSIS */
static IMB_JOB *
flush_cipher_enc_des_docsis_64(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_DOCSIS_DES, IMB_KEY_64_BYTES);
}

/* AES-CCM */
static IMB_JOB *
flush_cipher_enc_aes_ccm_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CCM, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_ccm_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CCM, IMB_KEY_256_BYTES);
}

/* 3DES */
static IMB_JOB *
flush_cipher_enc_des3_cbc_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_DES3, IMB_KEY_192_BYTES);
}

/* PON AES-CTR */
static IMB_JOB *
flush_cipher_enc_aes_ctr_pon_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_PON_AES_CNTR, IMB_KEY_128_BYTES);
}

/* AES-ECB */
static IMB_JOB *
flush_cipher_enc_aes_ecb_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_ECB, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_ecb_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_ECB, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_ecb_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_ECB, IMB_KEY_256_BYTES);
}

/* AES-CTR BITS */
static IMB_JOB *
flush_cipher_enc_aes_ctr_128_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_ctr_192_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_ctr_256_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CNTR_BITLEN, IMB_KEY_256_BYTES);
}

/* ZUC EEA3 */
static IMB_JOB *
flush_cipher_enc_zuc_eea3_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_ZUC_EEA3, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_enc_zuc_eea3_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_ZUC_EEA3, IMB_KEY_256_BYTES);
}

/* SNOW3G UEA2 */
static IMB_JOB *
flush_cipher_enc_snow3g_uea2_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_SNOW3G_UEA2_BITLEN, IMB_KEY_128_BYTES);
}

/* KASUMI F8 UEA1 */
static IMB_JOB *
flush_cipher_enc_kasumi_uea1_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_KASUMI_UEA1_BITLEN, IMB_KEY_128_BYTES);
}

/* AES-CBCS-1-9 */
static IMB_JOB *
flush_cipher_enc_aes_cbcs_1_9(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CBCS_1_9, IMB_KEY_128_BYTES);
}

/* CHACHA20 */
static IMB_JOB *
flush_cipher_enc_chacha20(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CHACHA20, IMB_KEY_256_BYTES);
}

/* CHACHA20-POLY1305 */
static IMB_JOB *
flush_cipher_enc_chacha20_poly1305(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CHACHA20_POLY1305, IMB_KEY_256_BYTES);
}

/* CHACHA20-POLY1305 SGL */
static IMB_JOB *
flush_cipher_enc_chacha20_poly1305_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CHACHA20_POLY1305_SGL,
                                    IMB_KEY_256_BYTES);
}

/* SNOW-V */
static IMB_JOB *
flush_cipher_enc_snow_v(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_SNOW_V, IMB_KEY_256_BYTES);
}

/* SNOW-V AEAD */
static IMB_JOB *
flush_cipher_enc_snow_v_aead(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_SNOW_V_AEAD, IMB_KEY_256_BYTES);
}

/* AES-GCM SGL */
static IMB_JOB *
flush_cipher_enc_aes_gcm_128_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_128_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_gcm_192_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_192_BYTES);
}

static IMB_JOB *
flush_cipher_enc_aes_gcm_256_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_GCM_SGL, IMB_KEY_256_BYTES);
}

/* SM4-ECB */
static IMB_JOB *
flush_cipher_enc_sm4_ecb(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_SM4_ECB, IMB_KEY_128_BYTES);
}

/* SM4-CBC */
static IMB_JOB *
flush_cipher_enc_sm4_cbc(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_SM4_CBC, IMB_KEY_128_BYTES);
}

/* AES-CBC */
static IMB_JOB *
flush_cipher_enc_cfb_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CFB, IMB_KEY_128_BYTES);
}
static IMB_JOB *
flush_cipher_enc_cfb_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CFB, IMB_KEY_192_BYTES);
}
static IMB_JOB *
flush_cipher_enc_cfb_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_CIPHER_ENC(state, job, IMB_CIPHER_CFB, IMB_KEY_256_BYTES);
}
/*
 * Four entries per algorithm (different key sizes),
 * algorithms in the same order IMB_CIPHER_MODE
 *     index 0 - key size from 0 to 64-bits
 *     index 1 - key size from 65 to 128-bits
 *     index 2 - key size from 129 to 192-bits
 *     index 3 - key size from 193 to 256-bits
 */
static const submit_flush_fn_t tab_flush_cipher[] = {
        /* ========================= */
        /* === DECRYPT DIRECTION === */
        /* ========================= */
        /* [0] keep empty - enums start from value 1 */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [1] AES-CBC */
        flush_cipher_dec_null,
        flush_cipher_dec_aes_cbc_128,
        flush_cipher_dec_aes_cbc_192,
        flush_cipher_dec_aes_cbc_256,
        /* [2] AES-CBC */
        flush_cipher_dec_null,
        flush_cipher_dec_aes_ctr_128,
        flush_cipher_dec_aes_ctr_192,
        flush_cipher_dec_aes_ctr_256,
        /* [3] NULL */
        flush_cipher_dec_null,
        flush_cipher_dec_null,
        flush_cipher_dec_null,
        flush_cipher_dec_null,
        /* [4] DOCSIS SEC BPI */
        flush_cipher_dec_null,
        flush_cipher_dec_aes_docsis_128,
        flush_cipher_dec_null,
        flush_cipher_dec_aes_docsis_256,
        /* [5] AES-GCM */
        flush_cipher_dec_null,
        flush_cipher_dec_aes_gcm_128,
        flush_cipher_dec_aes_gcm_192,
        flush_cipher_dec_aes_gcm_256,
        /* [6] CUSTOM */
        flush_cipher_dec_custom,
        flush_cipher_dec_custom,
        flush_cipher_dec_custom,
        flush_cipher_dec_custom,
        /* [7] DES */
        flush_cipher_dec_des_cbc_64,
        flush_cipher_dec_des_cbc_64,
        flush_cipher_dec_des_cbc_64,
        flush_cipher_dec_des_cbc_64,
        /* [8] DOCSIS DES */
        flush_cipher_dec_des_docsis_64,
        flush_cipher_dec_des_docsis_64,
        flush_cipher_dec_des_docsis_64,
        flush_cipher_dec_des_docsis_64,
        /* [9] AES-CCM */
        flush_cipher_dec_null,
        flush_cipher_dec_aes_ccm_128,
        flush_cipher_dec_null,
        flush_cipher_dec_aes_ccm_256,
        /* [10] 3DES */
        flush_cipher_dec_des3_cbc_192,
        flush_cipher_dec_des3_cbc_192,
        flush_cipher_dec_des3_cbc_192,
        flush_cipher_dec_des3_cbc_192,
        /* [11] PON AES-CTR */
        flush_cipher_dec_aes_ctr_pon_128,
        flush_cipher_dec_aes_ctr_pon_128,
        flush_cipher_dec_aes_ctr_pon_128,
        flush_cipher_dec_aes_ctr_pon_128,
        /* [12] AES-ECB */
        flush_cipher_dec_null,
        flush_cipher_dec_aes_ecb_128,
        flush_cipher_dec_aes_ecb_192,
        flush_cipher_dec_aes_ecb_256,
        /* [13] AES-CTR BITLEN */
        flush_cipher_dec_null,
        flush_cipher_dec_aes_ctr_128_bit,
        flush_cipher_dec_aes_ctr_192_bit,
        flush_cipher_dec_aes_ctr_256_bit,
        /* [14] ZUC EEA3 */
        flush_cipher_dec_null,
        flush_cipher_dec_zuc_eea3_128,
        flush_cipher_dec_null,
        flush_cipher_dec_zuc_eea3_256,
        /* [15] SNOW3G UEA2 */
        flush_cipher_dec_snow3g_uea2_bit,
        flush_cipher_dec_snow3g_uea2_bit,
        flush_cipher_dec_snow3g_uea2_bit,
        flush_cipher_dec_snow3g_uea2_bit,
        /* [16] KASUMI F8 UEA1 */
        flush_cipher_dec_kasumi_uea1_bit,
        flush_cipher_dec_kasumi_uea1_bit,
        flush_cipher_dec_kasumi_uea1_bit,
        flush_cipher_dec_kasumi_uea1_bit,
        /* [17] AES-CBCS-1-9 */
        flush_cipher_dec_aes_cbcs_1_9,
        flush_cipher_dec_aes_cbcs_1_9,
        flush_cipher_dec_aes_cbcs_1_9,
        flush_cipher_dec_aes_cbcs_1_9,
        /* [18] CHACHA20 */
        flush_cipher_dec_chacha20,
        flush_cipher_dec_chacha20,
        flush_cipher_dec_chacha20,
        flush_cipher_dec_chacha20,
        /* [19] CHACHA20-POLY1305 */
        flush_cipher_dec_chacha20_poly1305,
        flush_cipher_dec_chacha20_poly1305,
        flush_cipher_dec_chacha20_poly1305,
        flush_cipher_dec_chacha20_poly1305,
        /* [20] CHACHA20-POLY1305 SGL */
        flush_cipher_dec_chacha20_poly1305_sgl,
        flush_cipher_dec_chacha20_poly1305_sgl,
        flush_cipher_dec_chacha20_poly1305_sgl,
        flush_cipher_dec_chacha20_poly1305_sgl,
        /* [21] SNOW-V */
        flush_cipher_dec_snow_v,
        flush_cipher_dec_snow_v,
        flush_cipher_dec_snow_v,
        flush_cipher_dec_snow_v,
        /* [22] SNOW-V AEAD */
        flush_cipher_dec_snow_v_aead,
        flush_cipher_dec_snow_v_aead,
        flush_cipher_dec_snow_v_aead,
        flush_cipher_dec_snow_v_aead,
        /* [23] AES-GCM SGL */
        flush_cipher_dec_null,
        flush_cipher_dec_aes_gcm_128_sgl,
        flush_cipher_dec_aes_gcm_192_sgl,
        flush_cipher_dec_aes_gcm_256_sgl,
        /* [24] SM4-ECB */
        flush_cipher_dec_null,
        flush_cipher_dec_sm4_ecb,
        flush_cipher_dec_null,
        flush_cipher_dec_null,
        /* [25] SM4-CBC */
        flush_cipher_dec_null,
        flush_cipher_dec_sm4_cbc,
        flush_cipher_dec_null,
        flush_cipher_dec_null,
        /* [26] AES-CFB */
        flush_cipher_dec_null,
        flush_cipher_dec_cfb_128,
        flush_cipher_dec_cfb_192,
        flush_cipher_dec_cfb_256,
        /* add new cipher decrypt here */
        /* [27] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [28] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [29] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [30] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [31] NULL */
        NULL,
        NULL,
        NULL,
        NULL,

        /* ========================= */
        /* === ENCRYPT DIRECTION === */
        /* ========================= */

        /* [0] keep empty - enums start from value 1 */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [1] AES-CBC */
        flush_cipher_enc_null,
        flush_cipher_enc_aes_cbc_128,
        flush_cipher_enc_aes_cbc_192,
        flush_cipher_enc_aes_cbc_256,
        /* [2] AES-CBC */
        flush_cipher_enc_null,
        flush_cipher_enc_aes_ctr_128,
        flush_cipher_enc_aes_ctr_192,
        flush_cipher_enc_aes_ctr_256,
        /* [3] NULL */
        flush_cipher_enc_null,
        flush_cipher_enc_null,
        flush_cipher_enc_null,
        flush_cipher_enc_null,
        /* [4] DOCSIS SEC BPI */
        flush_cipher_enc_null,
        flush_cipher_enc_aes_docsis_128,
        flush_cipher_enc_null,
        flush_cipher_enc_aes_docsis_256,
        /* [5] AES-GCM */
        flush_cipher_enc_null,
        flush_cipher_enc_aes_gcm_128,
        flush_cipher_enc_aes_gcm_192,
        flush_cipher_enc_aes_gcm_256,
        /* [6] CUSTOM */
        flush_cipher_enc_custom,
        flush_cipher_enc_custom,
        flush_cipher_enc_custom,
        flush_cipher_enc_custom,
        /* [7] DES */
        flush_cipher_enc_des_cbc_64,
        flush_cipher_enc_des_cbc_64,
        flush_cipher_enc_des_cbc_64,
        flush_cipher_enc_des_cbc_64,
        /* [8] DOCSIS DES */
        flush_cipher_enc_des_docsis_64,
        flush_cipher_enc_des_docsis_64,
        flush_cipher_enc_des_docsis_64,
        flush_cipher_enc_des_docsis_64,
        /* [9] AES-CCM */
        flush_cipher_enc_null,
        flush_cipher_enc_aes_ccm_128,
        flush_cipher_enc_null,
        flush_cipher_enc_aes_ccm_256,
        /* [10] 3DES */
        flush_cipher_enc_des3_cbc_192,
        flush_cipher_enc_des3_cbc_192,
        flush_cipher_enc_des3_cbc_192,
        flush_cipher_enc_des3_cbc_192,
        /* [11] PON AES-CTR */
        flush_cipher_enc_aes_ctr_pon_128,
        flush_cipher_enc_aes_ctr_pon_128,
        flush_cipher_enc_aes_ctr_pon_128,
        flush_cipher_enc_aes_ctr_pon_128,
        /* [12] AES-ECB */
        flush_cipher_enc_null,
        flush_cipher_enc_aes_ecb_128,
        flush_cipher_enc_aes_ecb_192,
        flush_cipher_enc_aes_ecb_256,
        /* [13] AES-CTR BITLEN */
        flush_cipher_enc_null,
        flush_cipher_enc_aes_ctr_128_bit,
        flush_cipher_enc_aes_ctr_192_bit,
        flush_cipher_enc_aes_ctr_256_bit,
        /* [14] ZUC EEA3 */
        flush_cipher_enc_null,
        flush_cipher_enc_zuc_eea3_128,
        flush_cipher_enc_null,
        flush_cipher_enc_zuc_eea3_256,
        /* [15] SNOW3G UEA2 */
        flush_cipher_enc_snow3g_uea2_bit,
        flush_cipher_enc_snow3g_uea2_bit,
        flush_cipher_enc_snow3g_uea2_bit,
        flush_cipher_enc_snow3g_uea2_bit,
        /* [16] KASUMI F8 UEA1 */
        flush_cipher_enc_kasumi_uea1_bit,
        flush_cipher_enc_kasumi_uea1_bit,
        flush_cipher_enc_kasumi_uea1_bit,
        flush_cipher_enc_kasumi_uea1_bit,
        /* [17] AES-CBCS-1-9 */
        flush_cipher_enc_aes_cbcs_1_9,
        flush_cipher_enc_aes_cbcs_1_9,
        flush_cipher_enc_aes_cbcs_1_9,
        flush_cipher_enc_aes_cbcs_1_9,
        /* [18] CHACHA20 */
        flush_cipher_enc_chacha20,
        flush_cipher_enc_chacha20,
        flush_cipher_enc_chacha20,
        flush_cipher_enc_chacha20,
        /* [19] CHACHA20-POLY1305 */
        flush_cipher_enc_chacha20_poly1305,
        flush_cipher_enc_chacha20_poly1305,
        flush_cipher_enc_chacha20_poly1305,
        flush_cipher_enc_chacha20_poly1305,
        /* [20] CHACHA20-POLY1305 SGL */
        flush_cipher_enc_chacha20_poly1305_sgl,
        flush_cipher_enc_chacha20_poly1305_sgl,
        flush_cipher_enc_chacha20_poly1305_sgl,
        flush_cipher_enc_chacha20_poly1305_sgl,
        /* [21] SNOW-V */
        flush_cipher_enc_snow_v,
        flush_cipher_enc_snow_v,
        flush_cipher_enc_snow_v,
        flush_cipher_enc_snow_v,
        /* [22] SNOW-V AEAD */
        flush_cipher_enc_snow_v_aead,
        flush_cipher_enc_snow_v_aead,
        flush_cipher_enc_snow_v_aead,
        flush_cipher_enc_snow_v_aead,
        /* [23] AES-GCM SGL */
        flush_cipher_enc_null,
        flush_cipher_enc_aes_gcm_128_sgl,
        flush_cipher_enc_aes_gcm_192_sgl,
        flush_cipher_enc_aes_gcm_256_sgl,
        /* [24] SM4-ECB */
        flush_cipher_enc_null,
        flush_cipher_enc_sm4_ecb,
        flush_cipher_enc_null,
        flush_cipher_enc_null,
        /* [25] SM4-CBC */
        flush_cipher_enc_null,
        flush_cipher_enc_sm4_cbc,
        flush_cipher_enc_null,
        flush_cipher_enc_null,
        /* [26] AES-CFB */
        flush_cipher_enc_null,
        flush_cipher_enc_cfb_128,
        flush_cipher_enc_cfb_192,
        flush_cipher_enc_cfb_256,
        /* add new cipher encrypt here */
        /* [27] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [28] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [29] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [30] NULL */
        NULL,
        NULL,
        NULL,
        NULL,
        /* [31] NULL */
        NULL,
        NULL,
        NULL,
        NULL,

};

/* ========================================================================= */
/* Hash submit & flush functions */
/* ========================================================================= */

__forceinline IMB_JOB *
SUBMIT_JOB_HASH_EX(IMB_MGR *state, IMB_JOB *job, const IMB_HASH_ALG hash_alg)
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
        MB_MGR_ZUC_OOO *zuc256_eia3_8B_ooo = state->zuc256_eia3_8B_ooo;
        MB_MGR_ZUC_OOO *zuc256_eia3_16B_ooo = state->zuc256_eia3_16B_ooo;
        MB_MGR_SHA_1_OOO *sha_1_ooo = state->sha_1_ooo;
        MB_MGR_SHA_256_OOO *sha_224_ooo = state->sha_224_ooo;
        MB_MGR_SHA_256_OOO *sha_256_ooo = state->sha_256_ooo;
        MB_MGR_SHA_512_OOO *sha_384_ooo = state->sha_384_ooo;
        MB_MGR_SHA_512_OOO *sha_512_ooo = state->sha_512_ooo;
#if (defined(SAFE_LOOKUP) || defined(AVX512)) && !defined(SSE_AESNI_EMU)
        MB_MGR_SNOW3G_OOO *snow3g_uia2_ooo = state->snow3g_uia2_ooo;
#endif

        switch (hash_alg) {
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
        case IMB_AUTH_HMAC_SM3:
                return SUBMIT_JOB_HMAC_SM3(job);
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
                job->msg_len_to_hash_in_bits = job->msg_len_to_hash_in_bytes * 8;
                return SUBMIT_JOB_AES128_CMAC_AUTH(aes_cmac_ooo, job);
        case IMB_AUTH_AES_CMAC_BITLEN:
                return SUBMIT_JOB_AES128_CMAC_AUTH(aes_cmac_ooo, job);
        case IMB_AUTH_AES_CMAC_256:
                job->msg_len_to_hash_in_bits = job->msg_len_to_hash_in_bytes * 8;
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
                if (job->auth_tag_output_len_in_bytes == 4)
                        return SUBMIT_JOB_ZUC256_EIA3(zuc256_eia3_ooo, job, 4);
                if (job->auth_tag_output_len_in_bytes == 8)
                        return SUBMIT_JOB_ZUC256_EIA3(zuc256_eia3_8B_ooo, job, 8);
                else /* tag size == 16 */
                        return SUBMIT_JOB_ZUC256_EIA3(zuc256_eia3_16B_ooo, job, 16);
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
#if (defined(SAFE_LOOKUP) || defined(AVX512)) && !defined(SSE_AESNI_EMU)
                return SUBMIT_JOB_SNOW3G_UIA2(snow3g_uia2_ooo, job);
#else
                IMB_SNOW3G_F9_1_BUFFER(
                        state, (const snow3g_key_schedule_t *) job->u.SNOW3G_UIA2._key,
                        job->u.SNOW3G_UIA2._iv, job->src + job->hash_start_src_offset_in_bytes,
                        job->msg_len_to_hash_in_bits, job->auth_tag_output);
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
#endif
        case IMB_AUTH_KASUMI_UIA1:
                IMB_KASUMI_F9_1_BUFFER(state, (const kasumi_key_sched_t *) job->u.KASUMI_UIA1._key,
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
        case IMB_AUTH_SM3:
                return SUBMIT_JOB_SM3(job);
        default:
                /**
                 * assume IMB_AUTH_GCM, IMB_AUTH_PON_CRC_BIP,
                 * IMB_AUTH_SNOW_V_AEAD or IMB_AUTH_NULL
                 */
                job->status |= IMB_STATUS_COMPLETED_AUTH;
                return job;
        }
}

__forceinline IMB_JOB *
FLUSH_JOB_HASH_EX(IMB_MGR *state, IMB_JOB *job, const IMB_HASH_ALG hash_alg)
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
        MB_MGR_ZUC_OOO *zuc256_eia3_8B_ooo = state->zuc256_eia3_8B_ooo;
        MB_MGR_ZUC_OOO *zuc256_eia3_16B_ooo = state->zuc256_eia3_16B_ooo;
        MB_MGR_SHA_1_OOO *sha_1_ooo = state->sha_1_ooo;
        MB_MGR_SHA_256_OOO *sha_224_ooo = state->sha_224_ooo;
        MB_MGR_SHA_256_OOO *sha_256_ooo = state->sha_256_ooo;
        MB_MGR_SHA_512_OOO *sha_384_ooo = state->sha_384_ooo;
        MB_MGR_SHA_512_OOO *sha_512_ooo = state->sha_512_ooo;
#if (defined(SAFE_LOOKUP) || defined(AVX512)) && !defined(SSE_AESNI_EMU)
        MB_MGR_SNOW3G_OOO *snow3g_uia2_ooo = state->snow3g_uia2_ooo;
#endif

        switch (hash_alg) {
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
                if (job->auth_tag_output_len_in_bytes == 4)
                        return FLUSH_JOB_ZUC256_EIA3(zuc256_eia3_ooo, 4);
                if (job->auth_tag_output_len_in_bytes == 8)
                        return FLUSH_JOB_ZUC256_EIA3(zuc256_eia3_8B_ooo, 8);
                else /* tag size == 16 */
                        return FLUSH_JOB_ZUC256_EIA3(zuc256_eia3_16B_ooo, 16);
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
/* Generate specialized hash submit functions and create a table */
/* ========================================================================= */

static IMB_JOB *
submit_hash_hmac_sha1(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SHA_1);
}

static IMB_JOB *
submit_hash_hmac_sha224(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SHA_224);
}

static IMB_JOB *
submit_hash_hmac_sha256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SHA_256);
}

static IMB_JOB *
submit_hash_hmac_sha384(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SHA_384);
}

static IMB_JOB *
submit_hash_hmac_sha512(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SHA_512);
}

static IMB_JOB *
submit_hash_aes_xcbc(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_AES_XCBC);
}

static IMB_JOB *
submit_hash_hmac_md5(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_MD5);
}

static IMB_JOB *
submit_hash_null(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_NULL);
}

static IMB_JOB *
submit_hash_aes_gmac(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_AES_GMAC);
}

static IMB_JOB *
submit_hash_custom(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CUSTOM);
}

static IMB_JOB *
submit_hash_aes_ccm(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_AES_CCM);
}

static IMB_JOB *
submit_hash_aes_cmac(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_AES_CMAC);
}

static IMB_JOB *
submit_hash_sha1(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_SHA_1);
}

static IMB_JOB *
submit_hash_sha224(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_SHA_224);
}

static IMB_JOB *
submit_hash_sha256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_SHA_256);
}

static IMB_JOB *
submit_hash_sha384(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_SHA_384);
}

static IMB_JOB *
submit_hash_sha512(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_SHA_512);
}

static IMB_JOB *
submit_hash_aes_cmac_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_AES_CMAC_BITLEN);
}

static IMB_JOB *
submit_hash_pon_crc_bip(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_PON_CRC_BIP);
}

static IMB_JOB *
submit_hash_zuc_eia3_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_ZUC_EIA3_BITLEN);
}

static IMB_JOB *
submit_hash_docsis_crc32(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_DOCSIS_CRC32);
}

static IMB_JOB *
submit_hash_snow3g_uia2_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_SNOW3G_UIA2_BITLEN);
}

static IMB_JOB *
submit_hash_kasumi_uia1(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_KASUMI_UIA1);
}

static IMB_JOB *
submit_hash_aes_gmac_128(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_AES_GMAC_128);
}

static IMB_JOB *
submit_hash_aes_gmac_192(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_AES_GMAC_192);
}

static IMB_JOB *
submit_hash_aes_gmac_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_AES_GMAC_256);
}

static IMB_JOB *
submit_hash_aes_cmac_256(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_AES_CMAC_256);
}

static IMB_JOB *
submit_hash_poly1305(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_POLY1305);
}

static IMB_JOB *
submit_hash_chacha20_poly1305(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CHACHA20_POLY1305);
}

static IMB_JOB *
submit_hash_chacha20_poly1305_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CHACHA20_POLY1305_SGL);
}

static IMB_JOB *
submit_hash_zuc256_eia3_bit(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_ZUC256_EIA3_BITLEN);
}

static IMB_JOB *
submit_hash_snow_v_aead(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_SNOW_V_AEAD);
}

static IMB_JOB *
submit_hash_gcm_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_GCM_SGL);
}

static IMB_JOB *
submit_hash_crc32_ethernet_fcs(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC32_ETHERNET_FCS);
}

static IMB_JOB *
submit_hash_crc32_sctp(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC32_SCTP);
}

static IMB_JOB *
submit_hash_crc32_wimax_ofdma(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC32_WIMAX_OFDMA_DATA);
}

static IMB_JOB *
submit_hash_crc24_lte_a(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC24_LTE_A);
}

static IMB_JOB *
submit_hash_crc24_lte_b(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC24_LTE_B);
}

static IMB_JOB *
submit_hash_crc16_x25(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC16_X25);
}

static IMB_JOB *
submit_hash_crc16_fp_data(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC16_FP_DATA);
}

static IMB_JOB *
submit_hash_crc11_fp_header(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC11_FP_HEADER);
}

static IMB_JOB *
submit_hash_crc10_iuup_data(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC10_IUUP_DATA);
}

static IMB_JOB *
submit_hash_crc8_wimax_odma(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC8_WIMAX_OFDMA_HCS);
}

static IMB_JOB *
submit_hash_crc7_fp_header(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC7_FP_HEADER);
}

static IMB_JOB *
submit_hash_crc6_iuup_header(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_CRC6_IUUP_HEADER);
}

static IMB_JOB *
submit_hash_ghash(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_GHASH);
}

static IMB_JOB *
submit_hash_sm3(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_SM3);
}

static IMB_JOB *
submit_hash_hmac_sm3(IMB_MGR *state, IMB_JOB *job)
{
        return SUBMIT_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SM3);
}

static const submit_flush_fn_t tab_submit_hash[] = {
        /* [0] invalid entry */
        NULL,
        /* [1] HMAC-SHA1 */
        submit_hash_hmac_sha1,
        /* [2] HMAC-SHA224 */
        submit_hash_hmac_sha224,
        /* [3] HMAC-SHA256 */
        submit_hash_hmac_sha256,
        /* [4] HMAC-SHA384 */
        submit_hash_hmac_sha384,
        /* [5] HMAC-SHA512 */
        submit_hash_hmac_sha512,
        /* [6] AES-XCBC */
        submit_hash_aes_xcbc,
        /* [7] HMAC-MD5 */
        submit_hash_hmac_md5,
        /* [8] NULL */
        submit_hash_null,
        /* [9] AES-GMAC */
        submit_hash_aes_gmac,
        /* [10] CUSTOM */
        submit_hash_custom,
        /* [11] AES-CCM */
        submit_hash_aes_ccm,
        /* [12] AES-CMAC */
        submit_hash_aes_cmac,
        /* [13] SHA1 */
        submit_hash_sha1,
        /* [14] SHA224 */
        submit_hash_sha224,
        /* [15] SHA256 */
        submit_hash_sha256,
        /* [16] SHA384 */
        submit_hash_sha384,
        /* [17] SHA512 */
        submit_hash_sha512,
        /* [18] AES-CMAC BIT */
        submit_hash_aes_cmac_bit,
        /* [19] PON CRC BIP */
        submit_hash_pon_crc_bip,
        /* [20] ZUC EIA3 BIT */
        submit_hash_zuc_eia3_bit,
        /* [21] DOCSIS CRC32 */
        submit_hash_docsis_crc32,
        /* [22] SNOW3G UIA2 BIT */
        submit_hash_snow3g_uia2_bit,
        /* [23] KASUMI UIA1 */
        submit_hash_kasumi_uia1,
        /* [24] AES-GMAC-128 */
        submit_hash_aes_gmac_128,
        /* [25] AES-GMAC-192 */
        submit_hash_aes_gmac_192,
        /* [26] AES-GMAC-256 */
        submit_hash_aes_gmac_256,
        /* [27] AES-CMAC-256 */
        submit_hash_aes_cmac_256,
        /* [28] POLY1305 */
        submit_hash_poly1305,
        /* [29] CHACHA20-POLY1305 */
        submit_hash_chacha20_poly1305,
        /* [30] CHACHA20-POLY1305 SGL */
        submit_hash_chacha20_poly1305_sgl,
        /* [31] ZUC256 EIA3 */
        submit_hash_zuc256_eia3_bit,
        /* [32] SNOW-V AEAD */
        submit_hash_snow_v_aead,
        /* [33] GCM SGL */
        submit_hash_gcm_sgl,
        /* [34] CRC32 ETHERNET FCS */
        submit_hash_crc32_ethernet_fcs,
        /* [35] CRC32 SCTP */
        submit_hash_crc32_sctp,
        /* [36] CRC32 WIMAX OFDMA DATA */
        submit_hash_crc32_wimax_ofdma,
        /* [37] CRC24 LTE A */
        submit_hash_crc24_lte_a,
        /* [38] CRC24 LTE B */
        submit_hash_crc24_lte_b,
        /* [39] CRC16 X25 */
        submit_hash_crc16_x25,
        /* [40] CRC16 FP DATA */
        submit_hash_crc16_fp_data,
        /* [41] CRC11 FP HEADER */
        submit_hash_crc11_fp_header,
        /* [42] CRC10 IUUP DATA */
        submit_hash_crc10_iuup_data,
        /* [43] CRC8 WIMAX OFDMA HCS */
        submit_hash_crc8_wimax_odma,
        /* [44] CRC7 FP HEADER */
        submit_hash_crc7_fp_header,
        /* [45] CRC6 IUUP HEADER */
        submit_hash_crc6_iuup_header,
        /* [46] GHASH */
        submit_hash_ghash,
        /* [47] SM3 */
        submit_hash_sm3,
        /* [48] HMAC-SM3 */
        submit_hash_hmac_sm3,
        /* add new hash algorithms here */
};

/* ========================================================================= */
/* Generate specialized hash flush functions and create a table */
/* ========================================================================= */

static IMB_JOB *
flush_hash_hmac_sha1(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SHA_1);
}

static IMB_JOB *
flush_hash_hmac_sha224(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SHA_224);
}

static IMB_JOB *
flush_hash_hmac_sha256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SHA_256);
}

static IMB_JOB *
flush_hash_hmac_sha384(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SHA_384);
}

static IMB_JOB *
flush_hash_hmac_sha512(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SHA_512);
}

static IMB_JOB *
flush_hash_aes_xcbc(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_AES_XCBC);
}

static IMB_JOB *
flush_hash_hmac_md5(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_MD5);
}

static IMB_JOB *
flush_hash_null(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_NULL);
}

static IMB_JOB *
flush_hash_aes_gmac(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_AES_GMAC);
}

static IMB_JOB *
flush_hash_custom(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CUSTOM);
}

static IMB_JOB *
flush_hash_aes_ccm(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_AES_CCM);
}

static IMB_JOB *
flush_hash_aes_cmac(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_AES_CMAC);
}

static IMB_JOB *
flush_hash_sha1(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_SHA_1);
}

static IMB_JOB *
flush_hash_sha224(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_SHA_224);
}

static IMB_JOB *
flush_hash_sha256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_SHA_256);
}

static IMB_JOB *
flush_hash_sha384(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_SHA_384);
}

static IMB_JOB *
flush_hash_sha512(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_SHA_512);
}

static IMB_JOB *
flush_hash_aes_cmac_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_AES_CMAC_BITLEN);
}

static IMB_JOB *
flush_hash_pon_crc_bip(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_PON_CRC_BIP);
}

static IMB_JOB *
flush_hash_zuc_eia3_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_ZUC_EIA3_BITLEN);
}

static IMB_JOB *
flush_hash_docsis_crc32(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_DOCSIS_CRC32);
}

static IMB_JOB *
flush_hash_snow3g_uia2_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_SNOW3G_UIA2_BITLEN);
}

static IMB_JOB *
flush_hash_kasumi_uia1(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_KASUMI_UIA1);
}

static IMB_JOB *
flush_hash_aes_gmac_128(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_AES_GMAC_128);
}

static IMB_JOB *
flush_hash_aes_gmac_192(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_AES_GMAC_192);
}

static IMB_JOB *
flush_hash_aes_gmac_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_AES_GMAC_256);
}

static IMB_JOB *
flush_hash_aes_cmac_256(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_AES_CMAC_256);
}

static IMB_JOB *
flush_hash_poly1305(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_POLY1305);
}

static IMB_JOB *
flush_hash_chacha20_poly1305(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CHACHA20_POLY1305);
}

static IMB_JOB *
flush_hash_chacha20_poly1305_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CHACHA20_POLY1305_SGL);
}

static IMB_JOB *
flush_hash_zuc256_eia3_bit(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_ZUC256_EIA3_BITLEN);
}

static IMB_JOB *
flush_hash_snow_v_aead(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_SNOW_V_AEAD);
}

static IMB_JOB *
flush_hash_gcm_sgl(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_GCM_SGL);
}

static IMB_JOB *
flush_hash_crc32_ethernet_fcs(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC32_ETHERNET_FCS);
}

static IMB_JOB *
flush_hash_crc32_sctp(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC32_SCTP);
}

static IMB_JOB *
flush_hash_crc32_wimax_ofdma(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC32_WIMAX_OFDMA_DATA);
}

static IMB_JOB *
flush_hash_crc24_lte_a(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC24_LTE_A);
}

static IMB_JOB *
flush_hash_crc24_lte_b(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC24_LTE_B);
}

static IMB_JOB *
flush_hash_crc16_x25(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC16_X25);
}

static IMB_JOB *
flush_hash_crc16_fp_data(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC16_FP_DATA);
}

static IMB_JOB *
flush_hash_crc11_fp_header(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC11_FP_HEADER);
}

static IMB_JOB *
flush_hash_crc10_iuup_data(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC10_IUUP_DATA);
}

static IMB_JOB *
flush_hash_crc8_wimax_odma(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC8_WIMAX_OFDMA_HCS);
}

static IMB_JOB *
flush_hash_crc7_fp_header(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC7_FP_HEADER);
}

static IMB_JOB *
flush_hash_crc6_iuup_header(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_CRC6_IUUP_HEADER);
}

static IMB_JOB *
flush_hash_ghash(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_GHASH);
}

static IMB_JOB *
flush_hash_sm3(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_SM3);
}

static IMB_JOB *
flush_hash_hmac_sm3(IMB_MGR *state, IMB_JOB *job)
{
        return FLUSH_JOB_HASH_EX(state, job, IMB_AUTH_HMAC_SM3);
}

static const submit_flush_fn_t tab_flush_hash[] = {
        /* [0] invalid entry */
        NULL,
        /* [1] HMAC-SHA1 */
        flush_hash_hmac_sha1,
        /* [2] HMAC-SHA224 */
        flush_hash_hmac_sha224,
        /* [3] HMAC-SHA256 */
        flush_hash_hmac_sha256,
        /* [4] HMAC-SHA384 */
        flush_hash_hmac_sha384,
        /* [5] HMAC-SHA512 */
        flush_hash_hmac_sha512,
        /* [6] AES-XCBC */
        flush_hash_aes_xcbc,
        /* [7] HMAC-MD5 */
        flush_hash_hmac_md5,
        /* [8] NULL */
        flush_hash_null,
        /* [9] AES-GMAC */
        flush_hash_aes_gmac,
        /* [10] CUSTOM */
        flush_hash_custom,
        /* [11] AES-CCM */
        flush_hash_aes_ccm,
        /* [12] AES-CMAC */
        flush_hash_aes_cmac,
        /* [13] SHA1 */
        flush_hash_sha1,
        /* [14] SHA224 */
        flush_hash_sha224,
        /* [15] SHA256 */
        flush_hash_sha256,
        /* [16] SHA384 */
        flush_hash_sha384,
        /* [17] SHA512 */
        flush_hash_sha512,
        /* [18] AES-CMAC BIT */
        flush_hash_aes_cmac_bit,
        /* [19] PON CRC BIP */
        flush_hash_pon_crc_bip,
        /* [20] ZUC EIA3 BIT */
        flush_hash_zuc_eia3_bit,
        /* [21] DOCSIS CRC32 */
        flush_hash_docsis_crc32,
        /* [22] SNOW3G UIA2 BIT */
        flush_hash_snow3g_uia2_bit,
        /* [23] KASUMI UIA1 */
        flush_hash_kasumi_uia1,
        /* [24] AES-GMAC-128 */
        flush_hash_aes_gmac_128,
        /* [25] AES-GMAC-192 */
        flush_hash_aes_gmac_192,
        /* [26] AES-GMAC-256 */
        flush_hash_aes_gmac_256,
        /* [27] AES-CMAC-256 */
        flush_hash_aes_cmac_256,
        /* [28] POLY1305 */
        flush_hash_poly1305,
        /* [29] CHACHA20-POLY1305 */
        flush_hash_chacha20_poly1305,
        /* [30] CHACHA20-POLY1305 SGL */
        flush_hash_chacha20_poly1305_sgl,
        /* [31] ZUC256 EIA3 */
        flush_hash_zuc256_eia3_bit,
        /* [32] SNOW-V AEAD */
        flush_hash_snow_v_aead,
        /* [33] GCM SGL */
        flush_hash_gcm_sgl,
        /* [34] CRC32 ETHERNET FCS */
        flush_hash_crc32_ethernet_fcs,
        /* [35] CRC32 SCTP */
        flush_hash_crc32_sctp,
        /* [36] CRC32 WIMAX OFDMA DATA */
        flush_hash_crc32_wimax_ofdma,
        /* [37] CRC24 LTE A */
        flush_hash_crc24_lte_a,
        /* [38] CRC24 LTE B */
        flush_hash_crc24_lte_b,
        /* [39] CRC16 X25 */
        flush_hash_crc16_x25,
        /* [40] CRC16 FP DATA */
        flush_hash_crc16_fp_data,
        /* [41] CRC11 FP HEADER */
        flush_hash_crc11_fp_header,
        /* [42] CRC10 IUUP DATA */
        flush_hash_crc10_iuup_data,
        /* [43] CRC8 WIMAX OFDMA HCS */
        flush_hash_crc8_wimax_odma,
        /* [44] CRC7 FP HEADER */
        flush_hash_crc7_fp_header,
        /* [45] CRC6 IUUP HEADER */
        flush_hash_crc6_iuup_header,
        /* [46] GHASH */
        flush_hash_ghash,
        /* [47] SM3 */
        flush_hash_sm3,
        /* [48] HMAC-SM3 */
        flush_hash_hmac_sm3,
        /* add new hash algorithms here */
};

__forceinline IMB_JOB *
SUBMIT_JOB_HASH(IMB_MGR *state, IMB_JOB *job)
{
        return tab_submit_hash[job->hash_alg](state, job);
}

__forceinline IMB_JOB *
FLUSH_JOB_HASH(IMB_MGR *state, IMB_JOB *job)
{
        return tab_flush_hash[job->hash_alg](state, job);
}

/* ========================================================================= */
/* Job submit & flush functions */
/* ========================================================================= */

__forceinline unsigned
calc_cipher_tab_index(const IMB_JOB *job)
{
        /*
         * See include/mb_mgr_job_api.h for cipher table organization
         * - cipher_mode x 4, four key sizes per cipher mode
         * - map key_len_in_bytes into 0, 1, 2 & 3 index values
         * - encrypt_direction_bit x (ENCRYPT_DECRYPT_GAP x 4)
         */
        return (job->cipher_mode << 2) + (((job->key_len_in_bytes - 1) >> 3) & 3) +
               ((job->cipher_direction & IMB_DIR_ENCRYPT) << 7);
}

__forceinline IMB_JOB *
SUBMIT_JOB_CIPHER(IMB_MGR *state, IMB_JOB *job)
{
        const unsigned idx = calc_cipher_tab_index(job);

        IMB_ASSERT(ENCRYPT_DECRYPT_GAP >= IMB_CIPHER_NUM);

        return tab_submit_cipher[idx](state, job);
}

__forceinline IMB_JOB *
FLUSH_JOB_CIPHER(IMB_MGR *state, IMB_JOB *job)
{
        const unsigned idx = calc_cipher_tab_index(job);

        return tab_flush_cipher[idx](state, job);
}

/* submit a half-completed job, based on the status */
__forceinline IMB_JOB *
RESUBMIT_JOB(IMB_MGR *state, IMB_JOB *job)
{
        while (job != NULL && job->status < IMB_STATUS_COMPLETED) {
                if (job->status == IMB_STATUS_COMPLETED_AUTH)
                        job = SUBMIT_JOB_CIPHER(state, job);
                else /* assumed job->status = IMB_STATUS_COMPLETED_CIPHER */
                        job = SUBMIT_JOB_HASH(state, job);
        }

        return job;
}

__forceinline IMB_JOB *
submit_new_job(IMB_MGR *state, IMB_JOB *job)
{
        if (job->cipher_mode == IMB_CIPHER_GCM)
                return SUBMIT_JOB_CIPHER(state, job);

        if (job->chain_order == IMB_ORDER_CIPHER_HASH)
                job = SUBMIT_JOB_CIPHER(state, job);
        else
                job = SUBMIT_JOB_HASH(state, job);

        job = RESUBMIT_JOB(state, job);
        return job;
}

__forceinline uint32_t
complete_job(IMB_MGR *state, IMB_JOB *job)
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

__forceinline IMB_JOB *
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
                if (is_job_invalid(state, job, job->cipher_mode, job->hash_alg,
                                   job->cipher_direction, job->key_len_in_bytes)) {
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
/* Async burst job submit & flush functions */
/* ========================================================================= */

__forceinline void
set_cipher_suite_id(IMB_JOB *job, uint32_t id[2])
{
        const unsigned c_idx = calc_cipher_tab_index(job);
        const unsigned h_idx = (unsigned) job->hash_alg;

        id[0] = c_idx;
        id[1] = h_idx;
}

__forceinline IMB_JOB *
CALL_SUBMIT_CIPHER(IMB_MGR *state, IMB_JOB *job)
{
        const unsigned c_idx = job->suite_id[0];

        return tab_submit_cipher[c_idx](state, job);
}

__forceinline IMB_JOB *
CALL_FLUSH_CIPHER(IMB_MGR *state, IMB_JOB *job)
{
        const unsigned c_idx = job->suite_id[0];

        return tab_flush_cipher[c_idx](state, job);
}

__forceinline IMB_JOB *
CALL_SUBMIT_HASH(IMB_MGR *state, IMB_JOB *job)
{
        const unsigned h_idx = job->suite_id[1];

        return tab_submit_hash[h_idx](state, job);
}

__forceinline IMB_JOB *
CALL_FLUSH_HASH(IMB_MGR *state, IMB_JOB *job)
{
        const unsigned h_idx = job->suite_id[1];

        return tab_flush_hash[h_idx](state, job);
}

IMB_DLL_EXPORT void
SET_SUITE_ID_FN(IMB_MGR *state, IMB_JOB *job)
{
        (void) state;
        set_cipher_suite_id(job, job->suite_id);
}

__forceinline IMB_JOB *
RESUBMIT_BURST_JOB(IMB_MGR *state, IMB_JOB *job)
{
        while (job != NULL && job->status < IMB_STATUS_COMPLETED) {
                if (job->status == IMB_STATUS_COMPLETED_AUTH)
                        job = CALL_SUBMIT_CIPHER(state, job);
                else /* assumed job->status = IMB_STATUS_COMPLETED_CIPHER */
                        job = CALL_SUBMIT_HASH(state, job);
        }

        return job;
}

__forceinline IMB_JOB *
submit_new_burst_job(IMB_MGR *state, IMB_JOB *job)
{
        if (job->cipher_mode == IMB_CIPHER_GCM)
                return CALL_SUBMIT_CIPHER(state, job);

        if (job->chain_order == IMB_ORDER_CIPHER_HASH)
                job = CALL_SUBMIT_CIPHER(state, job);
        else
                job = CALL_SUBMIT_HASH(state, job);

        job = RESUBMIT_BURST_JOB(state, job);
        return job;
}

__forceinline uint32_t
complete_burst_job(IMB_MGR *state, IMB_JOB *job)
{
        uint32_t completed_jobs = 0;

        /**
         * complete as many jobs as necessary
         * until specified 'job' has completed
         */
        if (job->chain_order == IMB_ORDER_CIPHER_HASH) {
                /* while() loop optimized for cipher_hash order */
                while (job->status < IMB_STATUS_COMPLETED) {
                        IMB_JOB *tmp = CALL_FLUSH_CIPHER(state, job);

                        if (tmp == NULL)
                                tmp = CALL_FLUSH_HASH(state, job);

                        (void) RESUBMIT_BURST_JOB(state, tmp);
                        completed_jobs++;
                }
        } else {
                /* while() loop optimized for hash_cipher order */
                while (job->status < IMB_STATUS_COMPLETED) {
                        IMB_JOB *tmp = CALL_FLUSH_HASH(state, job);

                        if (tmp == NULL)
                                tmp = CALL_FLUSH_CIPHER(state, job);

                        (void) RESUBMIT_BURST_JOB(state, tmp);
                        completed_jobs++;
                }
        }

        return completed_jobs;
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
