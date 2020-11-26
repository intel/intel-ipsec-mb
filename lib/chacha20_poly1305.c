/*******************************************************************************
  Copyright (c) 2020, Intel Corporation

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

#include <stdlib.h>
#include <stdint.h>

#include "intel-ipsec-mb.h"
#include "include/clear_regs_mem.h"
#include "include/chacha20_poly1305.h"

__forceinline
void init_chacha20_poly1305(IMB_JOB *job, const IMB_ARCH arch)
{
        struct chacha20_poly1305_context_data *ctx =
                                                job->u.CHACHA20_POLY1305.ctx;
        const uint64_t hash_len = job->msg_len_to_hash_in_bytes;

        (void) arch; /* TODO: use arch */

        ctx->hash[0] = 0;
        ctx->hash[1] = 0;
        ctx->hash[2] = 0;
        ctx->aad_len = job->u.CHACHA20_POLY1305.aad_len_in_bytes;
        ctx->hash_len = hash_len;
        ctx->last_block_count = 0;
        ctx->remain_ks_bytes = 0;

        poly1305_key_gen_sse(job, ctx->poly_key);

        /* Calculate hash over AAD */
        poly1305_aead_update(job->u.CHACHA20_POLY1305.aad,
                             ctx->aad_len,
                             ctx->hash, ctx->poly_key);

        if (job->cipher_direction == IMB_DIR_ENCRYPT) {
                submit_job_chacha20_enc_dec_ks_sse(job, ctx->last_ks,
                                                   &ctx->remain_ks_bytes,
                                                   &ctx->last_block_count);

                /* compute hash after cipher on encrypt */
                poly1305_aead_update(job->dst, hash_len, ctx->hash,
                                     ctx->poly_key);
        } else {
                /* compute hash first on decrypt */
                poly1305_aead_update(job->src +
                                     job->hash_start_src_offset_in_bytes,
                                     hash_len, ctx->hash, ctx->poly_key);

                submit_job_chacha20_enc_dec_ks_sse(job, ctx->last_ks,
                                                   &ctx->remain_ks_bytes,
                                                   &ctx->last_block_count);
        }
}

__forceinline
void update_chacha20_poly1305(IMB_JOB *job, const IMB_ARCH arch)
{
        struct chacha20_poly1305_context_data *ctx =
                                                job->u.CHACHA20_POLY1305.ctx;
        const uint64_t hash_len = job->msg_len_to_hash_in_bytes;

        (void) arch; /* TODO: use arch */

        /* Increment total hash length */
        ctx->hash_len += hash_len;

        if (job->cipher_direction == IMB_DIR_ENCRYPT) {
                submit_job_chacha20_enc_dec_ks_sse(job, ctx->last_ks,
                                                   &ctx->remain_ks_bytes,
                                                   &ctx->last_block_count);

                /* compute hash after cipher on encrypt */
                poly1305_aead_update(job->dst, hash_len, ctx->hash,
                                     ctx->poly_key);
        } else {
                /* compute hash first on decrypt */
                poly1305_aead_update(job->src +
                                     job->hash_start_src_offset_in_bytes,
                                     hash_len, ctx->hash, ctx->poly_key);

                submit_job_chacha20_enc_dec_ks_sse(job, ctx->last_ks,
                                                   &ctx->remain_ks_bytes,
                                                   &ctx->last_block_count);
        }
}

__forceinline
void complete_chacha20_poly1305(IMB_JOB *job, const IMB_ARCH arch)
{
        struct chacha20_poly1305_context_data *ctx =
                                                job->u.CHACHA20_POLY1305.ctx;
        const uint64_t hash_len = job->msg_len_to_hash_in_bytes;
        uint64_t last[2];

        (void) arch; /* TODO: use arch */

        /* Increment total hash length */
        ctx->hash_len += hash_len;

        if (hash_len != 0) {
                if (job->cipher_direction == IMB_DIR_ENCRYPT) {
                        submit_job_chacha20_enc_dec_ks_sse(job, ctx->last_ks,
                                                   &ctx->remain_ks_bytes,
                                                   &ctx->last_block_count);

                        /* compute hash after cipher on encrypt */
                        poly1305_aead_update(job->dst, hash_len, ctx->hash,
                                             ctx->poly_key);
                } else {
                        /* compute hash first on decrypt */
                        poly1305_aead_update(job->src +
                                    job->hash_start_src_offset_in_bytes,
                                    hash_len, ctx->hash, ctx->poly_key);

                        submit_job_chacha20_enc_dec_ks_sse(job, ctx->last_ks,
                                                   &ctx->remain_ks_bytes,
                                                   &ctx->last_block_count);
                }
        }

        /*
         * Construct extra block with AAD and message lengths for
         * authentication
         */
        last[0] = ctx->aad_len;
        last[1] = ctx->hash_len;
        poly1305_aead_update(last, sizeof(last), ctx->hash, ctx->poly_key);

        /* Finalize AEAD Poly1305 (final reduction and +S) */
        poly1305_aead_complete(ctx->hash, ctx->poly_key, job->auth_tag_output);

        job->status |= STS_COMPLETED;
}

__forceinline
IMB_JOB *aead_chacha20_poly1305_sgl(IMB_JOB *job, const IMB_ARCH arch)
{
        switch (job->sgl_state) {
        case IMB_SGL_INIT:
                init_chacha20_poly1305(job, arch);
                break;
        case IMB_SGL_UPDATE:
                update_chacha20_poly1305(job, arch);
                break;
        case IMB_SGL_COMPLETE:
        default:
                complete_chacha20_poly1305(job, arch);
        }

        return job;
}

__forceinline
IMB_JOB *aead_chacha20_poly1305(IMB_JOB *job, const IMB_ARCH arch)
{
        DECLARE_ALIGNED(uint8_t ks[16*64], 64);
        uint64_t hash[3] = {0, 0, 0};
        const uint64_t aad_len = job->u.CHACHA20_POLY1305.aad_len_in_bytes;
        const uint64_t hash_len = job->msg_len_to_hash_in_bytes;
        uint64_t cipher_len = job->msg_len_to_cipher_in_bytes;
        uint64_t last[2];

        if (job->cipher_direction == IMB_DIR_ENCRYPT) {
                switch (arch) {
                case IMB_ARCH_SSE:
                        submit_job_chacha20_enc_dec_sse(job);
                        poly1305_key_gen_sse(job, ks);
                        break;
                case IMB_ARCH_AVX:
                        submit_job_chacha20_enc_dec_avx(job);
                        poly1305_key_gen_avx(job, ks);
                        break;
                case IMB_ARCH_AVX2:
                        submit_job_chacha20_enc_dec_avx2(job);
                        poly1305_key_gen_avx(job, ks);
                        break;
                case IMB_ARCH_AVX512:
                default:
                        submit_job_chacha20_poly_enc_avx512(job, ks);
                }

                /* Calculate hash over AAD */
                poly1305_aead_update(job->u.CHACHA20_POLY1305.aad, aad_len,
                                     hash, ks);

                /* compute hash after cipher on encrypt */
                poly1305_aead_update(job->dst, hash_len, hash, ks);
        } else {
                uint64_t len_to_gen;

                /* generate key for authentication */
                switch (arch) {
                case IMB_ARCH_SSE:
                        poly1305_key_gen_sse(job, ks);
                        break;
                case IMB_ARCH_AVX:
                case IMB_ARCH_AVX2:
                        poly1305_key_gen_avx(job, ks);
                        break;
                case IMB_ARCH_AVX512:
                default:
                        len_to_gen = (cipher_len >= (1024 - 64)) ?
                                                1024 : (cipher_len + 64);
                        gen_keystr_poly_key_avx512(job->enc_keys, job->iv,
                                                   len_to_gen, ks);
                }

                /* Calculate hash over AAD */
                poly1305_aead_update(job->u.CHACHA20_POLY1305.aad, aad_len,
                                     hash, ks);

                /* compute hash first on decrypt */
                poly1305_aead_update(job->src +
                                     job->hash_start_src_offset_in_bytes,
                                     hash_len, hash, ks);

                switch (arch) {
                case IMB_ARCH_SSE:
                        submit_job_chacha20_enc_dec_sse(job);
                        break;
                case IMB_ARCH_AVX:
                        submit_job_chacha20_enc_dec_avx(job);
                        break;
                case IMB_ARCH_AVX2:
                        submit_job_chacha20_enc_dec_avx2(job);
                        break;
                case IMB_ARCH_AVX512:
                default:
                        /* Skip first 64 bytes of KS, as that's used only
                           for Poly key */
                        submit_job_chacha20_poly_dec_avx512(job, ks + 64,
                                                            len_to_gen - 64);
                }
        }

        /*
         * Construct extra block with AAD and message lengths for
         * authentication
         */
        last[0] = aad_len;
        last[1] = hash_len;
        poly1305_aead_update(last, sizeof(last), hash, ks);

        /* Finalize AEAD Poly1305 (final reduction and +S) */
        poly1305_aead_complete(hash, ks, job->auth_tag_output);

        job->status |= STS_COMPLETED;

        return job;
}

IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_sse(IMB_JOB *job)
{
        return aead_chacha20_poly1305(job, IMB_ARCH_SSE);
}

IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_avx(IMB_JOB *job)
{
        return aead_chacha20_poly1305(job, IMB_ARCH_AVX);
}

IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_avx2(IMB_JOB *job)
{
        return aead_chacha20_poly1305(job, IMB_ARCH_AVX2);
}

IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_avx512(IMB_JOB *job)
{
        return aead_chacha20_poly1305(job, IMB_ARCH_AVX512);
}

IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_sgl_sse(IMB_JOB *job)
{
        return aead_chacha20_poly1305_sgl(job, IMB_ARCH_SSE);
}

IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_sgl_avx(IMB_JOB *job)
{
        return aead_chacha20_poly1305_sgl(job, IMB_ARCH_AVX);
}

IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_sgl_avx2(IMB_JOB *job)
{
        return aead_chacha20_poly1305_sgl(job, IMB_ARCH_AVX2);
}

IMB_DLL_LOCAL
IMB_JOB *aead_chacha20_poly1305_sgl_avx512(IMB_JOB *job)
{
        return aead_chacha20_poly1305_sgl(job, IMB_ARCH_AVX512);
}
