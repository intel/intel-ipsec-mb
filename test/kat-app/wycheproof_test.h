/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef WYCHEPROOF_TEST_H_
#define WYCHEPROOF_TEST_H_

#include <intel-ipsec-mb.h>

/**
 * Project Wycheproof test vector suites.
 *
 * Unlike the other KAT vector sets, these carry a mix of valid and invalid
 * (negative) vectors. A negative vector passes when the library either rejects
 * the operation or produces a result that does not match the vector's tag.
 * Vectors using parameters the library does not support are skipped.
 *
 * Each function below is called by the matching algorithm test module so that
 * the coverage is reported as part of that algorithm's KAT test type.
 */

/**
 * @brief Runs the Wycheproof AES-GCM AEAD vectors
 *
 * @param [in] mb_mgr pointer to initialized IMB_MGR structure
 *
 * @return Number of failed test suites
 * @retval 0 all vectors passed
 */
int
wycheproof_gcm_test(IMB_MGR *mb_mgr);

/**
 * @brief Runs the Wycheproof AES-CCM AEAD vectors
 *
 * @param [in] mb_mgr pointer to initialized IMB_MGR structure
 *
 * @return Number of failed test suites
 * @retval 0 all vectors passed
 */
int
wycheproof_ccm_test(IMB_MGR *mb_mgr);

/**
 * @brief Runs the Wycheproof CHACHA20-POLY1305 AEAD vectors
 *
 * @param [in] mb_mgr pointer to initialized IMB_MGR structure
 *
 * @return Number of failed test suites
 * @retval 0 all vectors passed
 */
int
wycheproof_chacha20_poly1305_test(IMB_MGR *mb_mgr);

/**
 * @brief Runs the Wycheproof AES-CMAC vectors
 *
 * @param [in] mb_mgr pointer to initialized IMB_MGR structure
 *
 * @return Number of failed test suites
 * @retval 0 all vectors passed
 */
int
wycheproof_cmac_test(IMB_MGR *mb_mgr);

/**
 * @brief Runs the Wycheproof AES-GMAC vectors
 *
 * @param [in] mb_mgr pointer to initialized IMB_MGR structure
 *
 * @return Number of failed test suites
 * @retval 0 all vectors passed
 */
int
wycheproof_gmac_test(IMB_MGR *mb_mgr);

/**
 * @brief Runs the Wycheproof HMAC-SHA1 vectors
 *
 * @param [in] mb_mgr pointer to initialized IMB_MGR structure
 *
 * @return Number of failed test suites
 * @retval 0 all vectors passed
 */
int
wycheproof_hmac_sha1_test(IMB_MGR *mb_mgr);

/**
 * @brief Runs the Wycheproof HMAC-SHA224 vectors
 *
 * @param [in] mb_mgr pointer to initialized IMB_MGR structure
 *
 * @return Number of failed test suites
 * @retval 0 all vectors passed
 */
int
wycheproof_hmac_sha224_test(IMB_MGR *mb_mgr);

/**
 * @brief Runs the Wycheproof HMAC-SHA256 vectors
 *
 * @param [in] mb_mgr pointer to initialized IMB_MGR structure
 *
 * @return Number of failed test suites
 * @retval 0 all vectors passed
 */
int
wycheproof_hmac_sha256_test(IMB_MGR *mb_mgr);

/**
 * @brief Runs the Wycheproof HMAC-SHA384 vectors
 *
 * @param [in] mb_mgr pointer to initialized IMB_MGR structure
 *
 * @return Number of failed test suites
 * @retval 0 all vectors passed
 */
int
wycheproof_hmac_sha384_test(IMB_MGR *mb_mgr);

/**
 * @brief Runs the Wycheproof HMAC-SHA512 vectors
 *
 * @param [in] mb_mgr pointer to initialized IMB_MGR structure
 *
 * @return Number of failed test suites
 * @retval 0 all vectors passed
 */
int
wycheproof_hmac_sha512_test(IMB_MGR *mb_mgr);

#endif /* WYCHEPROOF_TEST_H_ */
