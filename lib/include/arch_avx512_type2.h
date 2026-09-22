/*******************************************************************************
  Copyright (c) 2012-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/* AVX512 + VAES + VPCLMULQDQ + GFNI + FMA */

#ifndef IMB_ASM_AVX512_T2_H
#define IMB_ASM_AVX512_T2_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

/* Define interface to base asm code */

/* AES-CBC */
void
aes_cbc_dec_128_vaes_avx512(const void *in, const uint8_t *IV, const void *keys, void *out,
                            uint64_t len_bytes);
void
aes_cbc_dec_192_vaes_avx512(const void *in, const uint8_t *IV, const void *keys, void *out,
                            uint64_t len_bytes);
void
aes_cbc_dec_256_vaes_avx512(const void *in, const uint8_t *IV, const void *keys, void *out,
                            uint64_t len_bytes);

/* AES-CTR */
void
aes_cntr_128_submit_vaes_avx512(IMB_JOB *job);
void
aes_cntr_192_submit_vaes_avx512(IMB_JOB *job);
void
aes_cntr_256_submit_vaes_avx512(IMB_JOB *job);

/* AES-ECB */
void
aes_ecb_enc_256_vaes_avx512(const void *in, const void *keys, void *out, uint64_t len_bytes);
void
aes_ecb_enc_192_vaes_avx512(const void *in, const void *keys, void *out, uint64_t len_bytes);
void
aes_ecb_enc_128_vaes_avx512(const void *in, const void *keys, void *out, uint64_t len_bytes);

void
aes_ecb_dec_256_vaes_avx512(const void *in, const void *keys, void *out, uint64_t len_bytes);
void
aes_ecb_dec_192_vaes_avx512(const void *in, const void *keys, void *out, uint64_t len_bytes);
void
aes_ecb_dec_128_vaes_avx512(const void *in, const void *keys, void *out, uint64_t len_bytes);

/* AES-CFB */
void
aes_cfb_dec_128_vaes_avx512(const void *out, const void *in, const void *IV, const void *keys,
                            uint64_t len_bytes);

void
aes_cfb_dec_192_vaes_avx512(const void *out, const void *in, const void *IV, const void *keys,
                            uint64_t len_bytes);
void
aes_cfb_dec_256_vaes_avx512(const void *out, const void *in, const void *IV, const void *keys,
                            uint64_t len_bytes);

/* NIA */
IMB_DLL_LOCAL void
nia_vclmul_avx512(void *digest, const void *hqp, const void *msg, const uint64_t msg_len);

/* NCA */
IMB_DLL_LOCAL void
nca_vclmul_avx512(void *digest, const void *hqp, const void *msg, const uint64_t msg_len,
                  const void *aad, const uint64_t aad_len);

/* AES-NxA5 */
void
generate_hqp_vaes_avx512(const void *aes_expanded_keys, const void *iv, uint8_t HQP[]);

/* moved from MB MGR */

IMB_JOB *
submit_job_pon_enc_vaes_avx512(IMB_JOB *job);
IMB_JOB *
submit_job_pon_dec_vaes_avx512(IMB_JOB *job);

IMB_JOB *
submit_job_pon_enc_no_ctr_vaes_avx512(IMB_JOB *job);
IMB_JOB *
submit_job_pon_dec_no_ctr_vaes_avx512(IMB_JOB *job);

IMB_JOB *
submit_job_aes_xcbc_vaes_avx512(MB_MGR_AES_XCBC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes_xcbc_vaes_avx512(MB_MGR_AES_XCBC_OOO *state);

IMB_JOB *
submit_job_aes128_enc_vaes_avx512(MB_MGR_AES_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes128_enc_vaes_avx512(MB_MGR_AES_OOO *state);

IMB_JOB *
submit_job_aes192_enc_vaes_avx512(MB_MGR_AES_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes192_enc_vaes_avx512(MB_MGR_AES_OOO *state);

IMB_JOB *
submit_job_aes256_enc_vaes_avx512(MB_MGR_AES_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes256_enc_vaes_avx512(MB_MGR_AES_OOO *state);

IMB_JOB *
submit_job_zuc_eea3_gfni_avx512(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_eea3_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_nea6_gfni_avx512(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_nea6_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_eia3_gfni_avx512(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_eia3_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_nia6_gfni_avx512(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_nia6_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_nca6_gfni_avx512(MB_MGR_ZUC_OOO *state, IMB_JOB *job, IMB_CIPHER_DIRECTION dir);
IMB_JOB *
flush_job_zuc_nca6_gfni_avx512(MB_MGR_ZUC_OOO *state, IMB_CIPHER_DIRECTION dir);

IMB_JOB *
aes_cntr_ccm_128_vaes_avx512(IMB_JOB *job);

IMB_JOB *
aes_cntr_ccm_256_vaes_avx512(IMB_JOB *job);

IMB_JOB *
submit_job_snow3g_uea2_vaes_avx512(MB_MGR_SNOW3G_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_snow3g_uea2_vaes_avx512(MB_MGR_SNOW3G_OOO *state);

IMB_JOB *
submit_job_snow3g_uia2_vaes_avx512(MB_MGR_SNOW3G_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_snow3g_uia2_vaes_avx512(MB_MGR_SNOW3G_OOO *state);

IMB_JOB *
submit_job_aes128_cmac_auth_vaes_avx512(MB_MGR_CMAC_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes128_cmac_auth_vaes_avx512(MB_MGR_CMAC_OOO *state);

IMB_JOB *
submit_job_aes256_cmac_auth_vaes_avx512(MB_MGR_CMAC_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes256_cmac_auth_vaes_avx512(MB_MGR_CMAC_OOO *state);

IMB_JOB *
submit_job_aes128_ccm_auth_vaes_avx512(MB_MGR_CCM_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes128_ccm_auth_vaes_avx512(MB_MGR_CCM_OOO *state);

IMB_JOB *
submit_job_aes256_ccm_auth_vaes_avx512(MB_MGR_CCM_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes256_ccm_auth_vaes_avx512(MB_MGR_CCM_OOO *state);

IMB_JOB *
submit_job_aes128_cfb_enc_vaes_avx512(MB_MGR_AES_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes128_cfb_enc_vaes_avx512(MB_MGR_AES_OOO *state);

IMB_JOB *
submit_job_aes192_cfb_enc_vaes_avx512(MB_MGR_AES_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes192_cfb_enc_vaes_avx512(MB_MGR_AES_OOO *state);

IMB_JOB *
submit_job_aes256_cfb_enc_vaes_avx512(MB_MGR_AES_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes256_cfb_enc_vaes_avx512(MB_MGR_AES_OOO *state);
void
poly1305_mac_fma_avx512(IMB_JOB *job);

uint32_t
ethernet_fcs_avx512(const void *msg, const uint64_t len);
uint32_t
ethernet_fcs_avx512_local(const void *msg, const uint64_t len, const void *tag_ouput);
uint32_t
crc16_x25_avx512(const void *msg, const uint64_t len);
uint32_t
crc32_sctp_avx512(const void *msg, const uint64_t len);
uint32_t
crc24_lte_a_avx512(const void *msg, const uint64_t len);
uint32_t
crc24_lte_b_avx512(const void *msg, const uint64_t len);
uint32_t
crc16_fp_data_avx512(const void *msg, const uint64_t len);
uint32_t
crc11_fp_header_avx512(const void *msg, const uint64_t len);
uint32_t
crc7_fp_header_avx512(const void *msg, const uint64_t len);
uint32_t
crc10_iuup_data_avx512(const void *msg, const uint64_t len);
uint32_t
crc6_iuup_header_avx512(const void *msg, const uint64_t len);
uint32_t
crc32_wimax_ofdma_data_avx512(const void *msg, const uint64_t len);
uint32_t
crc8_wimax_ofdma_hcs_avx512(const void *msg, const uint64_t len);

/* SNOW5G VAES AVX512 external functions */
extern IMB_JOB *
submit_job_snow5g_nea4_vaes_avx512(MB_MGR_SNOW5G_OOO *state, IMB_JOB *job);
extern IMB_JOB *
flush_job_snow5g_nea4_vaes_avx512(MB_MGR_SNOW5G_OOO *state);

extern IMB_JOB *
submit_job_snow5g_nia4_vaes_avx512(MB_MGR_SNOW5G_OOO *state, IMB_JOB *job);
extern IMB_JOB *
flush_job_snow5g_nia4_vaes_avx512(MB_MGR_SNOW5G_OOO *state);

extern IMB_JOB *
submit_job_snow5g_nca4_enc_vaes_avx512(MB_MGR_SNOW5G_OOO *state, IMB_JOB *job);
extern IMB_JOB *
flush_job_snow5g_nca4_enc_vaes_avx512(MB_MGR_SNOW5G_OOO *state);
extern IMB_JOB *
submit_job_snow5g_nca4_dec_vaes_avx512(MB_MGR_SNOW5G_OOO *state, IMB_JOB *job);
extern IMB_JOB *
flush_job_snow5g_nca4_dec_vaes_avx512(MB_MGR_SNOW5G_OOO *state);

void
aes_docsis128_dec_crc32_vaes_avx512(IMB_JOB *job);
void
aes_docsis256_dec_crc32_vaes_avx512(IMB_JOB *job);

IMB_JOB *
submit_job_aes_docsis128_enc_crc32_vaes_avx512(MB_MGR_DOCSIS_AES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes_docsis128_enc_crc32_vaes_avx512(MB_MGR_DOCSIS_AES_OOO *state);

IMB_JOB *
submit_job_aes_docsis256_enc_crc32_vaes_avx512(MB_MGR_DOCSIS_AES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes_docsis256_enc_crc32_vaes_avx512(MB_MGR_DOCSIS_AES_OOO *state);

IMB_DLL_EXPORT void
set_suite_id_avx512_t2(IMB_MGR *state, IMB_JOB *job);

#endif /* IMB_ASM_AVX512_T2_H */
