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

/* AVX512 + AESNI + PCLMULQDQ */

#ifndef IMB_ASM_AVX512_T1_H
#define IMB_ASM_AVX512_T1_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

IMB_JOB *submit_job_des_cbc_enc_avx512(MB_MGR_DES_OOO *state,
                                       IMB_JOB *job);
IMB_JOB *flush_job_des_cbc_enc_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *submit_job_des_cbc_dec_avx512(MB_MGR_DES_OOO *state,
                                       IMB_JOB *job);
IMB_JOB *flush_job_des_cbc_dec_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *submit_job_3des_cbc_enc_avx512(MB_MGR_DES_OOO *state,
                                        IMB_JOB *job);
IMB_JOB *flush_job_3des_cbc_enc_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *submit_job_3des_cbc_dec_avx512(MB_MGR_DES_OOO *state,
                                        IMB_JOB *job);
IMB_JOB *flush_job_3des_cbc_dec_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *submit_job_docsis_des_enc_avx512(MB_MGR_DES_OOO *state,
                                          IMB_JOB *job);
IMB_JOB *flush_job_docsis_des_enc_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *submit_job_docsis_des_dec_avx512(MB_MGR_DES_OOO *state,
                                          IMB_JOB *job);
IMB_JOB *flush_job_docsis_des_dec_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *submit_job_zuc_eea3_no_gfni_avx512(MB_MGR_ZUC_OOO *state,
                                            IMB_JOB *job);
IMB_JOB *flush_job_zuc_eea3_no_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *submit_job_zuc_eia3_no_gfni_avx512(MB_MGR_ZUC_OOO *state,
                                            IMB_JOB *job);
IMB_JOB *flush_job_zuc_eia3_no_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *submit_job_zuc256_eea3_no_gfni_avx512(MB_MGR_ZUC_OOO *state,
                                               IMB_JOB *job);
IMB_JOB *flush_job_zuc256_eea3_no_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *submit_job_zuc256_eia3_no_gfni_avx512(MB_MGR_ZUC_OOO *state,
                                               IMB_JOB *job,
                                               const uint64_t tag_sz);
IMB_JOB *flush_job_zuc256_eia3_no_gfni_avx512(MB_MGR_ZUC_OOO *state,
                                              const uint64_t tag_sz);

IMB_JOB *submit_job_sha1_avx512(MB_MGR_SHA_1_OOO *state,
                                IMB_JOB *job);
IMB_JOB *flush_job_sha1_avx512(MB_MGR_SHA_1_OOO *state,
                               IMB_JOB *job);

IMB_JOB *submit_job_sha224_avx512(MB_MGR_SHA_256_OOO *state,
                                  IMB_JOB *job);
IMB_JOB *flush_job_sha224_avx512(MB_MGR_SHA_256_OOO *state,
                                 IMB_JOB *job);

IMB_JOB *submit_job_sha256_avx512(MB_MGR_SHA_256_OOO *state,
                                  IMB_JOB *job);
IMB_JOB *flush_job_sha256_avx512(MB_MGR_SHA_256_OOO *state,
                                 IMB_JOB *job);

IMB_JOB *submit_job_sha384_avx512(MB_MGR_SHA_512_OOO *state,
                                  IMB_JOB *job);
IMB_JOB *flush_job_sha384_avx512(MB_MGR_SHA_512_OOO *state,
                                 IMB_JOB *job);

IMB_JOB *submit_job_sha512_avx512(MB_MGR_SHA_512_OOO *state,
                                  IMB_JOB *job);
IMB_JOB *flush_job_sha512_avx512(MB_MGR_SHA_512_OOO *state,
                                 IMB_JOB *job);

IMB_JOB *submit_job_snow3g_uea2_avx512(MB_MGR_SNOW3G_OOO *state,
                                       IMB_JOB *job);

IMB_JOB *flush_job_snow3g_uea2_avx512(MB_MGR_SNOW3G_OOO *state);

IMB_JOB *submit_job_snow3g_uia2_avx512(MB_MGR_SNOW3G_OOO *state,
                                       IMB_JOB *job);

IMB_JOB *flush_job_snow3g_uia2_avx512(MB_MGR_SNOW3G_OOO *state);

void aes_cmac_256_subkey_gen_avx512(const void *key_exp,
                                    void *key1, void *key2);

IMB_JOB *submit_job_hmac_avx512(MB_MGR_HMAC_SHA_1_OOO *state,
                                IMB_JOB *job);
IMB_JOB *flush_job_hmac_avx512(MB_MGR_HMAC_SHA_1_OOO *state);

IMB_JOB *submit_job_hmac_sha_224_avx512(MB_MGR_HMAC_SHA_256_OOO *state,
                                        IMB_JOB *job);
IMB_JOB *flush_job_hmac_sha_224_avx512(MB_MGR_HMAC_SHA_256_OOO *state);

IMB_JOB *submit_job_hmac_sha_256_avx512(MB_MGR_HMAC_SHA_256_OOO *state,
                                        IMB_JOB *job);
IMB_JOB *flush_job_hmac_sha_256_avx512(MB_MGR_HMAC_SHA_256_OOO *state);

IMB_JOB *submit_job_hmac_sha_384_avx512(MB_MGR_HMAC_SHA_512_OOO *state,
                                        IMB_JOB *job);
IMB_JOB *flush_job_hmac_sha_384_avx512(MB_MGR_HMAC_SHA_512_OOO *state);

IMB_JOB *submit_job_hmac_sha_512_avx512(MB_MGR_HMAC_SHA_512_OOO *state,
                                        IMB_JOB *job);
IMB_JOB *flush_job_hmac_sha_512_avx512(MB_MGR_HMAC_SHA_512_OOO *state);

void poly1305_mac_plain_avx512(IMB_JOB *job);

IMB_JOB *submit_job_chacha20_enc_dec_avx512(IMB_JOB *job);

void aes_docsis128_dec_crc32_avx512(IMB_JOB *job);
void aes_docsis256_dec_crc32_avx512(IMB_JOB *job);
IMB_JOB *
submit_job_aes_docsis128_enc_crc32_avx512(MB_MGR_DOCSIS_AES_OOO *state,
                                          IMB_JOB *job);
IMB_JOB *
flush_job_aes_docsis128_enc_crc32_avx512(MB_MGR_DOCSIS_AES_OOO *state);

IMB_JOB *
submit_job_aes_docsis256_enc_crc32_avx512(MB_MGR_DOCSIS_AES_OOO *state,
                                          IMB_JOB *job);
IMB_JOB *
flush_job_aes_docsis256_enc_crc32_avx512(MB_MGR_DOCSIS_AES_OOO *state);

/* SHA */
void call_sha1_x16_avx512_from_c(SHA1_ARGS *args, uint32_t size_in_blocks);
void call_sha256_x16_avx512_from_c(SHA256_ARGS *args, uint32_t size_in_blocks);
void call_sha512_x8_avx512_from_c(SHA512_ARGS *args, uint64_t size_in_blocks);

#endif /* IMB_ASM_AVX512_T1_H */


