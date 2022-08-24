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

/* AVX2 + AESNI + PCLMULQDQ */

#ifndef IMB_ASM_AVX2_T1_H
#define IMB_ASM_AVX2_T1_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

/* SHA */
void call_sha1_x8_avx2_from_c(SHA1_ARGS *args, uint32_t size_in_blocks);
void call_sha256_oct_avx2_from_c(SHA256_ARGS *args, uint32_t size_in_blocks);
void call_sha512_x4_avx2_from_c(SHA512_ARGS *args, uint64_t size_in_blocks);

/* moved from MB MGR */
IMB_JOB *submit_job_zuc_eea3_avx2(MB_MGR_ZUC_OOO *state,
                                  IMB_JOB *job);
IMB_JOB *flush_job_zuc_eea3_avx2(MB_MGR_ZUC_OOO *state);

IMB_JOB *flush_job_zuc256_eea3_avx2(MB_MGR_ZUC_OOO *state);

IMB_JOB *submit_job_zuc256_eea3_avx2(MB_MGR_ZUC_OOO *state,
                                     IMB_JOB *job);

IMB_JOB *submit_job_zuc_eia3_avx2(MB_MGR_ZUC_OOO *state,
                                  IMB_JOB *job);
IMB_JOB *flush_job_zuc_eia3_avx2(MB_MGR_ZUC_OOO *state);

IMB_JOB *submit_job_zuc256_eia3_avx2(MB_MGR_ZUC_OOO *state,
                                     IMB_JOB *job,
                                     const uint64_t tag_sz);
IMB_JOB *flush_job_zuc256_eia3_avx2(MB_MGR_ZUC_OOO *state,
                                    const uint64_t tag_sz);

IMB_JOB *submit_job_sha1_avx2(MB_MGR_SHA_1_OOO *state,
                              IMB_JOB *job);
IMB_JOB *flush_job_sha1_avx2(MB_MGR_SHA_1_OOO *state,
                             IMB_JOB *job);

IMB_JOB *submit_job_sha224_avx2(MB_MGR_SHA_256_OOO *state,
                                IMB_JOB *job);
IMB_JOB *flush_job_sha224_avx2(MB_MGR_SHA_256_OOO *state,
                               IMB_JOB *job);

IMB_JOB *submit_job_sha256_avx2(MB_MGR_SHA_256_OOO *state,
                                IMB_JOB *job);
IMB_JOB *flush_job_sha256_avx2(MB_MGR_SHA_256_OOO *state,
                               IMB_JOB *job);

IMB_JOB *submit_job_sha384_avx2(MB_MGR_SHA_512_OOO *state,
                                IMB_JOB *job);
IMB_JOB *flush_job_sha384_avx2(MB_MGR_SHA_512_OOO *state,
                               IMB_JOB *job);

IMB_JOB *submit_job_sha512_avx2(MB_MGR_SHA_512_OOO *state,
                                IMB_JOB *job);
IMB_JOB *flush_job_sha512_avx2(MB_MGR_SHA_512_OOO *state,
                               IMB_JOB *job);

void aes_cmac_256_subkey_gen_avx2(const void *key_exp,
                                  void *key1, void *key2);

IMB_JOB *submit_job_chacha20_enc_dec_avx2(IMB_JOB *job);

IMB_JOB *submit_job_hmac_avx2(MB_MGR_HMAC_SHA_1_OOO *state,
                              IMB_JOB *job);
IMB_JOB *flush_job_hmac_avx2(MB_MGR_HMAC_SHA_1_OOO *state);

IMB_JOB *submit_job_hmac_sha_224_avx2(MB_MGR_HMAC_SHA_256_OOO *state,
                                      IMB_JOB *job);
IMB_JOB *flush_job_hmac_sha_224_avx2(MB_MGR_HMAC_SHA_256_OOO *state);

IMB_JOB *submit_job_hmac_sha_256_avx2(MB_MGR_HMAC_SHA_256_OOO *state,
                                      IMB_JOB *job);
IMB_JOB *flush_job_hmac_sha_256_avx2(MB_MGR_HMAC_SHA_256_OOO *state);

IMB_JOB *submit_job_hmac_sha_384_avx2(MB_MGR_HMAC_SHA_512_OOO *state,
                                      IMB_JOB *job);
IMB_JOB *flush_job_hmac_sha_384_avx2(MB_MGR_HMAC_SHA_512_OOO *state);

IMB_JOB *submit_job_hmac_sha_512_avx2(MB_MGR_HMAC_SHA_512_OOO *state,
                                      IMB_JOB *job);
IMB_JOB *flush_job_hmac_sha_512_avx2(MB_MGR_HMAC_SHA_512_OOO *state);

IMB_JOB *submit_job_hmac_md5_avx2(MB_MGR_HMAC_MD5_OOO *state,
                                  IMB_JOB *job);
IMB_JOB *flush_job_hmac_md5_avx2(MB_MGR_HMAC_MD5_OOO *state);

#endif /* IMB_ASM_AVX2_T1_H */
