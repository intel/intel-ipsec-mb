/*******************************************************************************
  Copyright (c) 2023, Intel Corporation

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

#ifndef IMB_ASM_AVX2_T4_H
#define IMB_ASM_AVX2_T4_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

IMB_DLL_EXPORT void
set_suite_id_avx2_t4(IMB_MGR *state, IMB_JOB *job);

/* SM4 */
void
sm4_ecb_ni_avx2(const void *in, void *out, const int size, const void *exp_keys);

void
sm4_set_key_ni_avx2(const void *pKey, void *exp_enc_keys, void *exp_dec_keys);

/* SM3 */
void
sm3_msg_ni_avx2(void *tag, const uint64_t tag_length, const void *msg, const uint64_t msg_length);
IMB_JOB *
sm3_hmac_submit_ni_avx2(IMB_JOB *job);
IMB_JOB *
sm3_msg_submit_ni_avx2(IMB_JOB *job);

/* SHA512 */
IMB_DLL_EXPORT void
sha384_ni_avx2(const void *data, const uint64_t length, void *digest);
IMB_DLL_EXPORT void
sha384_one_block_ni_avx2(const void *data, void *digest);

IMB_DLL_EXPORT void
sha512_one_block_ni_avx2(const void *data, void *digest);
IMB_DLL_EXPORT void
sha512_ni_avx2(const void *data, const uint64_t length, void *digest);

void
sha512_ni_block_avx2(const void *input, void *);
void
sha512_update_ni_x1(uint64_t digest[8], const void *input, uint64_t num_blocks);

IMB_JOB *
submit_job_sha384_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);
IMB_JOB *
submit_job_sha512_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_sha384_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_sha512_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);

#endif /* IMB_ASM_AVX2_T4_H */
