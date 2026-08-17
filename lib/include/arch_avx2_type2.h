/*******************************************************************************
  Copyright (c) 2022-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/* AVX2 + VAES + PCLMULQDQ */

#ifndef IMB_ASM_AVX2_T2_H
#define IMB_ASM_AVX2_T2_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

/* AES-ECB */
void
aes_ecb_enc_256_vaes_avx2(const void *in, const void *keys, void *out, uint64_t len_bytes);
void
aes_ecb_enc_192_vaes_avx2(const void *in, const void *keys, void *out, uint64_t len_bytes);
void
aes_ecb_enc_128_vaes_avx2(const void *in, const void *keys, void *out, uint64_t len_bytes);

void
aes_ecb_dec_256_vaes_avx2(const void *in, const void *keys, void *out, uint64_t len_bytes);
void
aes_ecb_dec_192_vaes_avx2(const void *in, const void *keys, void *out, uint64_t len_bytes);
void
aes_ecb_dec_128_vaes_avx2(const void *in, const void *keys, void *out, uint64_t len_bytes);

/* moved from MB MGR */
IMB_JOB *
submit_job_zuc_eea3_gfni_avx2(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_eea3_gfni_avx2(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_nea6_gfni_avx2(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_nea6_gfni_avx2(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_eia3_gfni_avx2(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_eia3_gfni_avx2(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_aes128_cfb_enc_vaes_avx2(MB_MGR_AES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes128_cfb_enc_vaes_avx2(MB_MGR_AES_OOO *state);
IMB_JOB *
submit_job_aes192_cfb_enc_vaes_avx2(MB_MGR_AES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes192_cfb_enc_vaes_avx2(MB_MGR_AES_OOO *state);
IMB_JOB *
submit_job_aes256_cfb_enc_vaes_avx2(MB_MGR_AES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes256_cfb_enc_vaes_avx2(MB_MGR_AES_OOO *state);

/* AES-CTR */
void
aes_cntr_256_vaes_avx2(const void *in, const void *IV, const void *keys, void *out,
                       uint64_t len_bytes, uint64_t IV_len);
void
aes_cntr_192_vaes_avx2(const void *in, const void *IV, const void *keys, void *out,
                       uint64_t len_bytes, uint64_t IV_len);
void
aes_cntr_128_vaes_avx2(const void *in, const void *IV, const void *keys, void *out,
                       uint64_t len_bytes, uint64_t IV_len);

/* AES-CFB */
void
aes_cfb_dec_128_vaes_avx2(const void *out, const void *in, const void *IV, const void *keys,
                          uint64_t len_bytes);
void
aes_cfb_dec_192_vaes_avx2(const void *out, const void *in, const void *IV, const void *keys,
                          uint64_t len_bytes);
void
aes_cfb_dec_256_vaes_avx2(const void *out, const void *in, const void *IV, const void *keys,
                          uint64_t len_bytes);

/* AES-CBC */
void
aes_cbc_dec_128_vaes_avx2(const void *in, const void *IV, const void *keys, const void *out,
                          uint64_t len_bytes);
void
aes_cbc_dec_192_vaes_avx2(const void *in, const void *IV, const void *keys, const void *out,
                          uint64_t len_bytes);
void
aes_cbc_dec_256_vaes_avx2(const void *in, const void *IV, const void *keys, const void *out,
                          uint64_t len_bytes);
IMB_JOB *
submit_job_aes128_cbc_enc_vaes_avx2(MB_MGR_AES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes128_cbc_enc_vaes_avx2(MB_MGR_AES_OOO *state);
IMB_JOB *
submit_job_aes192_cbc_enc_vaes_avx2(MB_MGR_AES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes192_cbc_enc_vaes_avx2(MB_MGR_AES_OOO *state);
IMB_JOB *
submit_job_aes256_cbc_enc_vaes_avx2(MB_MGR_AES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes256_cbc_enc_vaes_avx2(MB_MGR_AES_OOO *state);

/* AES-CMAC */
IMB_JOB *
submit_job_aes128_cmac_auth_vaes_avx2(MB_MGR_CMAC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes128_cmac_auth_vaes_avx2(MB_MGR_CMAC_OOO *state);
IMB_JOB *
submit_job_aes256_cmac_auth_vaes_avx2(MB_MGR_CMAC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes256_cmac_auth_vaes_avx2(MB_MGR_CMAC_OOO *state);

/* AES-CCM */
IMB_JOB *
aes_cntr_ccm_128_vaes_avx2(IMB_JOB *job);
IMB_JOB *
aes_cntr_ccm_256_vaes_avx2(IMB_JOB *job);

IMB_JOB *
submit_job_aes128_ccm_auth_vaes_avx2(MB_MGR_CCM_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes128_ccm_auth_vaes_avx2(MB_MGR_CCM_OOO *state);

IMB_JOB *
submit_job_aes256_ccm_auth_vaes_avx2(MB_MGR_CCM_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_aes256_ccm_auth_vaes_avx2(MB_MGR_CCM_OOO *state);

IMB_DLL_EXPORT void
set_suite_id_avx2_t2(IMB_MGR *state, IMB_JOB *job);

/* CRC */
uint32_t
crc32_vclmul_avx2(const uint32_t init_crc, const void *msg, const uint64_t len,
                  const void *const_ptr);
uint32_t
crc32_refl_vclmul_avx2(const uint32_t init_crc, const void *msg, const uint64_t len,
                       const void *const_ptr);
uint32_t
crc16_x25_avx2(const void *msg, const uint64_t len);
uint32_t
crc32_sctp_avx2(const void *msg, const uint64_t len);
uint32_t
crc24_lte_a_avx2(const void *msg, const uint64_t len);
uint32_t
crc24_lte_b_avx2(const void *msg, const uint64_t len);
uint32_t
crc16_fp_data_avx2(const void *msg, const uint64_t len);
uint32_t
crc11_fp_header_avx2(const void *msg, const uint64_t len);
uint32_t
crc7_fp_header_avx2(const void *msg, const uint64_t len);
uint32_t
crc10_iuup_data_avx2(const void *msg, const uint64_t len);
uint32_t
crc6_iuup_header_avx2(const void *msg, const uint64_t len);
uint32_t
crc32_wimax_ofdma_data_avx2(const void *msg, const uint64_t len);
uint32_t
crc8_wimax_ofdma_hcs_avx2(const void *msg, const uint64_t len);

uint32_t
ethernet_fcs_avx2(const void *msg, const uint64_t len);
uint32_t
ethernet_fcs_avx2_local(const void *msg, const uint64_t len, const void *tag_ouput);

#endif /* IMB_ASM_AVX2_T2_H */
