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

/* ARCH SSE TYPE 3: SSE4.2, AESNI, PCLMULQDQ, CMOV, BSWAP, SHANI, GFNI */

#ifndef IMB_ASM_SSE_T3_H
#define IMB_ASM_SSE_T3_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

/* AES-CBC */
void aes_cbc_enc_128_x8_sse(AES_ARGS *args, uint64_t len_in_bytes);
void aes_cbc_enc_192_x8_sse(AES_ARGS *args, uint64_t len_in_bytes);
void aes_cbc_enc_256_x8_sse(AES_ARGS *args, uint64_t len_in_bytes);

void aes_cbc_dec_128_by8_sse(const void *in, const uint8_t *IV,
                             const void *keys, void *out, uint64_t len_bytes);
void aes_cbc_dec_192_by8_sse(const void *in, const uint8_t *IV,
                             const void *keys, void *out, uint64_t len_bytes);
void aes_cbc_dec_256_by8_sse(const void *in, const uint8_t *IV,
                             const void *keys, void *out, uint64_t len_bytes);

/* AES-ECB */
void aes_ecb_enc_256_by8_sse(const void *in, const void *keys,
                             void *out, uint64_t len_bytes);
void aes_ecb_enc_192_by8_sse(const void *in, const void *keys,
                             void *out, uint64_t len_bytes);
void aes_ecb_enc_128_by8_sse(const void *in, const void *keys,
                             void *out, uint64_t len_bytes);

void aes_ecb_dec_256_by8_sse(const void *in, const void *keys,
                             void *out, uint64_t len_bytes);
void aes_ecb_dec_192_by8_sse(const void *in, const void *keys,
                             void *out, uint64_t len_bytes);
void aes_ecb_dec_128_by8_sse(const void *in, const void *keys,
                             void *out, uint64_t len_bytes);

/* moved from MB MGR */

IMB_JOB *submit_job_aes128_enc_x8_sse(MB_MGR_AES_OOO *state,
                                      IMB_JOB *job);
IMB_JOB *flush_job_aes128_enc_x8_sse(MB_MGR_AES_OOO *state);

IMB_JOB *submit_job_aes192_enc_x8_sse(MB_MGR_AES_OOO *state,
                                      IMB_JOB *job);
IMB_JOB *flush_job_aes192_enc_x8_sse(MB_MGR_AES_OOO *state);

IMB_JOB *submit_job_aes256_enc_x8_sse(MB_MGR_AES_OOO *state,
                                      IMB_JOB *job);
IMB_JOB *flush_job_aes256_enc_x8_sse(MB_MGR_AES_OOO *state);

IMB_JOB *submit_job_aes128_cmac_auth_x8_sse(MB_MGR_CMAC_OOO *state,
                                            IMB_JOB *job);

IMB_JOB *flush_job_aes128_cmac_auth_x8_sse(MB_MGR_CMAC_OOO *state);

IMB_JOB *submit_job_aes256_cmac_auth_x8_sse(MB_MGR_CMAC_OOO *state,
                                            IMB_JOB *job);

IMB_JOB *flush_job_aes256_cmac_auth_x8_sse(MB_MGR_CMAC_OOO *state);

IMB_JOB *submit_job_aes128_ccm_auth_x8_sse(MB_MGR_CCM_OOO *state,
                                           IMB_JOB *job);

IMB_JOB *flush_job_aes128_ccm_auth_x8_sse(MB_MGR_CCM_OOO *state);

IMB_JOB *submit_job_aes256_ccm_auth_x8_sse(MB_MGR_CCM_OOO *state,
                                           IMB_JOB *job);

IMB_JOB *flush_job_aes256_ccm_auth_x8_sse(MB_MGR_CCM_OOO *state);

IMB_JOB *submit_job_zuc_eea3_gfni_sse(MB_MGR_ZUC_OOO *state,
                                      IMB_JOB *job);
IMB_JOB *flush_job_zuc_eea3_gfni_sse(MB_MGR_ZUC_OOO *state);

IMB_JOB *submit_job_zuc256_eea3_gfni_sse(MB_MGR_ZUC_OOO *state,
                                         IMB_JOB *job);
IMB_JOB *flush_job_zuc256_eea3_gfni_sse(MB_MGR_ZUC_OOO *state);

IMB_JOB *submit_job_zuc_eia3_gfni_sse(MB_MGR_ZUC_OOO *state,
                                      IMB_JOB *job);
IMB_JOB *flush_job_zuc_eia3_gfni_sse(MB_MGR_ZUC_OOO *state);

IMB_JOB *submit_job_zuc256_eia3_gfni_sse(MB_MGR_ZUC_OOO *state,
                                         IMB_JOB *job,
                                         const uint64_t tag_sz);
IMB_JOB *flush_job_zuc256_eia3_gfni_sse(MB_MGR_ZUC_OOO *state,
                                        const uint64_t tag_sz);

#endif /* IMB_ASM_SSE_T3_H */
