/*******************************************************************************
  Copyright (c) 2022-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef OOO_MGR_RESET_H
#define OOO_MGR_RESET_H

IMB_DLL_LOCAL void
ooo_mgr_aes_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL void
ooo_mgr_docsis_aes_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL void
ooo_mgr_cmac_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL void
ooo_mgr_ccm_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_aes_xcbc_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_hmac_sha1_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_hmac_sha224_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_hmac_sha256_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_hmac_sha384_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_hmac_sha512_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_hmac_md5_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_zuc_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_sha1_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_sha256_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_sha512_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_sha3_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_des_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_snow3g_reset(void *p_ooo_mgr, const unsigned num_lanes);

IMB_DLL_LOCAL
void
ooo_mgr_snow5g_reset(void *p_ooo_mgr, const unsigned num_lanes);

#endif /* OOO_MGR_RESET_H */
