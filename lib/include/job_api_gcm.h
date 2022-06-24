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

#include "intel-ipsec-mb.h"

#ifndef JOB_API_GCM_H
#define JOB_API_GCM_H

__forceinline
IMB_JOB *
submit_gcm_sgl_enc(IMB_MGR *state, IMB_JOB *job)
{
        switch (job->key_len_in_bytes) {
        case IMB_KEY_128_BYTES:
                if (job->sgl_state == IMB_SGL_INIT)
                        IMB_AES128_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                else if (job->sgl_state == IMB_SGL_UPDATE)
                        IMB_AES128_GCM_ENC_UPDATE(state, job->enc_keys,
                                               job->u.GCM.ctx,
                                               job->dst, job->src,
                                               job->msg_len_to_cipher_in_bytes);
                else if (job->sgl_state == IMB_SGL_COMPLETE)
                        IMB_AES128_GCM_ENC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                else { /* IMB_SGL_ALL */
                        unsigned int i;

                        IMB_AES128_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                        for (i = 0; i < job->num_sgl_io_segs; i++)
                                IMB_AES128_GCM_ENC_UPDATE(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->sgl_io_segs[i].out,
                                                   job->sgl_io_segs[i].in,
                                                   job->sgl_io_segs[i].len);
                        IMB_AES128_GCM_ENC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                }
                break;
        case IMB_KEY_192_BYTES:
                if (job->sgl_state == IMB_SGL_INIT)
                        IMB_AES192_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                else if (job->sgl_state == IMB_SGL_UPDATE)
                        IMB_AES192_GCM_ENC_UPDATE(state, job->enc_keys,
                                               job->u.GCM.ctx,
                                               job->dst, job->src,
                                               job->msg_len_to_cipher_in_bytes);
                else if (job->sgl_state == IMB_SGL_COMPLETE)
                        IMB_AES192_GCM_ENC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                else { /* IMB_SGL_ALL */
                        unsigned int i;

                        IMB_AES192_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                        for (i = 0; i < job->num_sgl_io_segs; i++)
                                IMB_AES192_GCM_ENC_UPDATE(state, job->enc_keys,
                                                    job->u.GCM.ctx,
                                                   job->sgl_io_segs[i].out,
                                                   job->sgl_io_segs[i].in,
                                                   job->sgl_io_segs[i].len);
                        IMB_AES192_GCM_ENC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                }
                break;
        case IMB_KEY_256_BYTES:
        default:
                if (job->sgl_state == IMB_SGL_INIT)
                        IMB_AES256_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                else if (job->sgl_state == IMB_SGL_UPDATE)
                        IMB_AES256_GCM_ENC_UPDATE(state, job->enc_keys,
                                               job->u.GCM.ctx,
                                               job->dst, job->src,
                                               job->msg_len_to_cipher_in_bytes);
                else if (job->sgl_state == IMB_SGL_COMPLETE)
                        IMB_AES256_GCM_ENC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                else { /* IMB_SGL_ALL */
                        unsigned int i;

                        IMB_AES256_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                        for (i = 0; i < job->num_sgl_io_segs; i++)
                                IMB_AES256_GCM_ENC_UPDATE(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->sgl_io_segs[i].out,
                                                   job->sgl_io_segs[i].in,
                                                   job->sgl_io_segs[i].len);
                        IMB_AES256_GCM_ENC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                }
                break;
        }

        job->status = IMB_STATUS_COMPLETED;

        return job;
}

__forceinline
IMB_JOB *
submit_gcm_sgl_dec(IMB_MGR *state, IMB_JOB *job)
{
        switch (job->key_len_in_bytes) {
        case IMB_KEY_128_BYTES:
                if (job->sgl_state == IMB_SGL_INIT)
                        IMB_AES128_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                else if (job->sgl_state == IMB_SGL_UPDATE)
                        IMB_AES128_GCM_DEC_UPDATE(state, job->enc_keys,
                                               job->u.GCM.ctx,
                                               job->dst, job->src,
                                               job->msg_len_to_cipher_in_bytes);
                else if (job->sgl_state == IMB_SGL_COMPLETE)
                        IMB_AES128_GCM_DEC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                else { /* IMB_SGL_ALL */
                        unsigned int i;

                        IMB_AES128_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                        for (i = 0; i < job->num_sgl_io_segs; i++)
                                IMB_AES128_GCM_DEC_UPDATE(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->sgl_io_segs[i].out,
                                                   job->sgl_io_segs[i].in,
                                                   job->sgl_io_segs[i].len);
                        IMB_AES128_GCM_ENC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                }
                break;
        case IMB_KEY_192_BYTES:
                if (job->sgl_state == IMB_SGL_INIT)
                        IMB_AES192_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                else if (job->sgl_state == IMB_SGL_UPDATE)
                        IMB_AES192_GCM_DEC_UPDATE(state, job->enc_keys,
                                               job->u.GCM.ctx,
                                               job->dst, job->src,
                                               job->msg_len_to_cipher_in_bytes);
                else if (job->sgl_state == IMB_SGL_COMPLETE)
                        IMB_AES192_GCM_DEC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                else { /* IMB_SGL_ALL */
                        unsigned int i;

                        IMB_AES192_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                        for (i = 0; i < job->num_sgl_io_segs; i++)
                                IMB_AES192_GCM_DEC_UPDATE(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->sgl_io_segs[i].out,
                                                   job->sgl_io_segs[i].in,
                                                   job->sgl_io_segs[i].len);
                        IMB_AES192_GCM_ENC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                }
                break;
        case IMB_KEY_256_BYTES:
        default:
                if (job->sgl_state == IMB_SGL_INIT)
                        IMB_AES256_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                else if (job->sgl_state == IMB_SGL_UPDATE)
                        IMB_AES256_GCM_DEC_UPDATE(state, job->enc_keys,
                                               job->u.GCM.ctx,
                                               job->dst, job->src,
                                               job->msg_len_to_cipher_in_bytes);
                else if (job->sgl_state == IMB_SGL_COMPLETE)
                        IMB_AES256_GCM_DEC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                else { /* IMB_SGL_ALL */
                        unsigned int i;

                        IMB_AES256_GCM_INIT_VAR_IV(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->iv,
                                                   job->iv_len_in_bytes,
                                                   job->u.GCM.aad,
                                                   job->u.GCM.aad_len_in_bytes);
                        for (i = 0; i < job->num_sgl_io_segs; i++)
                                IMB_AES256_GCM_DEC_UPDATE(state, job->enc_keys,
                                                   job->u.GCM.ctx,
                                                   job->sgl_io_segs[i].out,
                                                   job->sgl_io_segs[i].in,
                                                   job->sgl_io_segs[i].len);
                        IMB_AES256_GCM_ENC_FINALIZE(state, job->enc_keys,
                                             job->u.GCM.ctx,
                                             job->auth_tag_output,
                                             job->auth_tag_output_len_in_bytes);
                }
                break;
        }

        job->status = IMB_STATUS_COMPLETED;

        return job;
}

__forceinline
void
process_gmac(IMB_MGR *state, IMB_JOB *job, const IMB_KEY_SIZE_BYTES key_size)
{
        struct gcm_context_data ctx;
        const struct gcm_key_data *key = job->u.GMAC._key;
        const uint8_t *iv = job->u.GMAC._iv;
        const uint64_t iv_len = job->u.GMAC.iv_len_in_bytes;
        const uint8_t *src = job->src + job->hash_start_src_offset_in_bytes;
        const uint64_t src_len = job->msg_len_to_hash_in_bytes;

        if (key_size == IMB_KEY_128_BYTES) {
                IMB_AES128_GMAC_INIT(state, key, &ctx, iv, iv_len);
                IMB_AES128_GMAC_UPDATE(state, key, &ctx, src, src_len);
                IMB_AES128_GMAC_FINALIZE(state, key, &ctx,
                                         job->auth_tag_output,
                                         job->auth_tag_output_len_in_bytes);
        } else if (key_size == IMB_KEY_192_BYTES) {
                IMB_AES192_GMAC_INIT(state, key, &ctx, iv, iv_len);
                IMB_AES192_GMAC_UPDATE(state, key, &ctx, src, src_len);
                IMB_AES192_GMAC_FINALIZE(state, key, &ctx,
                                         job->auth_tag_output,
                                         job->auth_tag_output_len_in_bytes);
        } else { /* key_size == 256 */
                IMB_AES256_GMAC_INIT(state, key, &ctx, iv, iv_len);
                IMB_AES256_GMAC_UPDATE(state, key, &ctx, src, src_len);
                IMB_AES256_GMAC_FINALIZE(state, key, &ctx,
                                         job->auth_tag_output,
                                         job->auth_tag_output_len_in_bytes);
        }
}

__forceinline IMB_JOB *process_ghash(IMB_MGR *state, IMB_JOB *job)
{
        /* copy initial tag value to the destination */
        memcpy(job->auth_tag_output, job->u.GHASH._init_tag,
               job->auth_tag_output_len_in_bytes);

        /* compute new tag value */
        IMB_GHASH(state, job->u.GHASH._key,
                  job->src + job->hash_start_src_offset_in_bytes,
                  job->msg_len_to_hash_in_bytes,
                  job->auth_tag_output, job->auth_tag_output_len_in_bytes);

        job->status |= IMB_STATUS_COMPLETED_AUTH;
        return job;
}

#endif /* JOB_API_GCM_H */
