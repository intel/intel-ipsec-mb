/*******************************************************************************
  Copyright (c) 2012-2022, Intel Corporation

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

/* AVX512 + VAES + VPCLMULQDQ + GFNI + FMA */

#ifndef IMB_ASM_AVX512_T2_H
#define IMB_ASM_AVX512_T2_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

/* Define interface to base asm code */

/* AES-CBC */
void aes_cbc_dec_128_vaes_avx512(const void *in, const uint8_t *IV,
                                 const void *keys, void *out,
                                 uint64_t len_bytes);
void aes_cbc_dec_192_vaes_avx512(const void *in, const uint8_t *IV,
                                 const void *keys, void *out,
                                 uint64_t len_bytes);
void aes_cbc_dec_256_vaes_avx512(const void *in, const uint8_t *IV,
                                 const void *keys, void *out,
                                 uint64_t len_bytes);

/* AES-CTR */
void aes_cntr_128_submit_vaes_avx512(IMB_JOB *job);
void aes_cntr_192_submit_vaes_avx512(IMB_JOB *job);
void aes_cntr_256_submit_vaes_avx512(IMB_JOB *job);

/* AES-CTR-BITLEN */
void aes_cntr_bit_128_submit_vaes_avx512(IMB_JOB *job);
void aes_cntr_bit_192_submit_vaes_avx512(IMB_JOB *job);
void aes_cntr_bit_256_submit_vaes_avx512(IMB_JOB *job);

/* AES-ECB */
void aes_ecb_enc_256_vaes_avx512(const void *in, const void *keys,
                         void *out, uint64_t len_bytes);
void aes_ecb_enc_192_vaes_avx512(const void *in, const void *keys,
                         void *out, uint64_t len_bytes);
void aes_ecb_enc_128_vaes_avx512(const void *in, const void *keys,
                         void *out, uint64_t len_bytes);

void aes_ecb_dec_256_vaes_avx512(const void *in, const void *keys,
                                 void *out, uint64_t len_bytes);
void aes_ecb_dec_192_vaes_avx512(const void *in, const void *keys,
                                 void *out, uint64_t len_bytes);
void aes_ecb_dec_128_vaes_avx512(const void *in, const void *keys,
                                 void *out, uint64_t len_bytes);

/* AES-CBCS */
void aes_cbcs_1_9_dec_128_vaes_avx512(const void *in, const uint8_t *IV,
                                      const void *keys, void *out,
                                      uint64_t len_bytes, void *next_iv);

/* moved from MB MGR */

IMB_JOB *submit_job_pon_enc_vaes_avx512(IMB_JOB *job);
IMB_JOB *submit_job_pon_dec_vaes_avx512(IMB_JOB *job);

IMB_JOB *submit_job_pon_enc_no_ctr_vaes_avx512(IMB_JOB *job);
IMB_JOB *submit_job_pon_dec_no_ctr_vaes_avx512(IMB_JOB *job);

IMB_JOB *submit_job_aes_xcbc_vaes_avx512(MB_MGR_AES_XCBC_OOO *state,
                                         IMB_JOB *job);
IMB_JOB *flush_job_aes_xcbc_vaes_avx512(MB_MGR_AES_XCBC_OOO *state);

IMB_JOB *submit_job_aes128_enc_vaes_avx512(MB_MGR_AES_OOO *state,
                                           IMB_JOB *job);

IMB_JOB *flush_job_aes128_enc_vaes_avx512(MB_MGR_AES_OOO *state);

IMB_JOB *submit_job_aes192_enc_vaes_avx512(MB_MGR_AES_OOO *state,
                                           IMB_JOB *job);

IMB_JOB *flush_job_aes192_enc_vaes_avx512(MB_MGR_AES_OOO *state);

IMB_JOB *submit_job_aes256_enc_vaes_avx512(MB_MGR_AES_OOO *state,
                                           IMB_JOB *job);

IMB_JOB *flush_job_aes256_enc_vaes_avx512(MB_MGR_AES_OOO *state);

IMB_JOB *submit_job_zuc_eea3_gfni_avx512(MB_MGR_ZUC_OOO *state,
                                         IMB_JOB *job);
IMB_JOB *flush_job_zuc_eea3_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *submit_job_zuc_eia3_gfni_avx512(MB_MGR_ZUC_OOO *state,
                                         IMB_JOB *job);
IMB_JOB *flush_job_zuc_eia3_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *submit_job_zuc256_eea3_gfni_avx512(MB_MGR_ZUC_OOO *state,
                                            IMB_JOB *job);
IMB_JOB *flush_job_zuc256_eea3_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *aes_cntr_ccm_128_vaes_avx512(IMB_JOB *job);

IMB_JOB *aes_cntr_ccm_256_vaes_avx512(IMB_JOB *job);

IMB_JOB *submit_job_zuc256_eia3_gfni_avx512(MB_MGR_ZUC_OOO *state,
                                         IMB_JOB *job,
                                         const uint64_t tag_sz);
IMB_JOB *flush_job_zuc256_eia3_gfni_avx512(MB_MGR_ZUC_OOO *state,
                                        const uint64_t tag_sz);

IMB_JOB *submit_job_aes128_cbcs_1_9_enc_vaes_avx512(MB_MGR_AES_OOO *state,
                                                    IMB_JOB *job);
IMB_JOB *flush_job_aes128_cbcs_1_9_enc_vaes_avx512(MB_MGR_AES_OOO *state);

IMB_JOB *submit_job_snow3g_uea2_vaes_avx512(MB_MGR_SNOW3G_OOO *state,
                                            IMB_JOB *job);

IMB_JOB *flush_job_snow3g_uea2_vaes_avx512(MB_MGR_SNOW3G_OOO *state);

IMB_JOB *submit_job_snow3g_uia2_vaes_avx512(MB_MGR_SNOW3G_OOO *state,
                                            IMB_JOB *job);

IMB_JOB *flush_job_snow3g_uia2_vaes_avx512(MB_MGR_SNOW3G_OOO *state);

IMB_JOB *submit_job_aes128_cmac_auth_vaes_avx512(MB_MGR_CMAC_OOO *state,
                                                 IMB_JOB *job);

IMB_JOB *flush_job_aes128_cmac_auth_vaes_avx512(MB_MGR_CMAC_OOO *state);

IMB_JOB *submit_job_aes256_cmac_auth_vaes_avx512(MB_MGR_CMAC_OOO *state,
                                                 IMB_JOB *job);

IMB_JOB *flush_job_aes256_cmac_auth_vaes_avx512(MB_MGR_CMAC_OOO *state);

IMB_JOB *submit_job_aes128_ccm_auth_vaes_avx512(MB_MGR_CCM_OOO *state,
                                                IMB_JOB *job);

IMB_JOB *flush_job_aes128_ccm_auth_vaes_avx512(MB_MGR_CCM_OOO *state);

IMB_JOB *submit_job_aes256_ccm_auth_vaes_avx512(MB_MGR_CCM_OOO *state,
                                                IMB_JOB *job);

IMB_JOB *flush_job_aes256_ccm_auth_vaes_avx512(MB_MGR_CCM_OOO *state);

void poly1305_mac_fma_avx512(IMB_JOB *job);

uint32_t ethernet_fcs_avx512(const void *msg, const uint64_t len);
uint32_t ethernet_fcs_avx512_local(const void *msg, const uint64_t len,
                                   const void *tag_ouput);
uint32_t crc16_x25_avx512(const void *msg, const uint64_t len);
uint32_t crc32_sctp_avx512(const void *msg, const uint64_t len);
uint32_t crc24_lte_a_avx512(const void *msg, const uint64_t len);
uint32_t crc24_lte_b_avx512(const void *msg, const uint64_t len);
uint32_t crc16_fp_data_avx512(const void *msg, const uint64_t len);
uint32_t crc11_fp_header_avx512(const void *msg, const uint64_t len);
uint32_t crc7_fp_header_avx512(const void *msg, const uint64_t len);
uint32_t crc10_iuup_data_avx512(const void *msg, const uint64_t len);
uint32_t crc6_iuup_header_avx512(const void *msg, const uint64_t len);
uint32_t crc32_wimax_ofdma_data_avx512(const void *msg, const uint64_t len);
uint32_t crc8_wimax_ofdma_hcs_avx512(const void *msg, const uint64_t len);

void snow3g_f9_1_buffer_vaes_avx512(const snow3g_key_schedule_t *pHandle,
                                    const void *pIV,
                                    const void *pBufferIn,
                                    const uint64_t lengthInBits,
                                    void *pDigest);


void aes_docsis128_dec_crc32_vaes_avx512(IMB_JOB *job);
void aes_docsis256_dec_crc32_vaes_avx512(IMB_JOB *job);

IMB_JOB *
submit_job_aes_docsis128_enc_crc32_vaes_avx512(MB_MGR_DOCSIS_AES_OOO *state,
                                               IMB_JOB *job);
IMB_JOB *
flush_job_aes_docsis128_enc_crc32_vaes_avx512(MB_MGR_DOCSIS_AES_OOO *state);

IMB_JOB *
submit_job_aes_docsis256_enc_crc32_vaes_avx512(MB_MGR_DOCSIS_AES_OOO *state,
                                               IMB_JOB *job);
IMB_JOB *
flush_job_aes_docsis256_enc_crc32_vaes_avx512(MB_MGR_DOCSIS_AES_OOO *state);


#endif /* IMB_ASM_AVX512_T2_H */

