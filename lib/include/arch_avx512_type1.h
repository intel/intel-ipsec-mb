/*******************************************************************************
  Copyright (c) 2022-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/* AVX512 + AESNI + PCLMULQDQ */

#ifndef IMB_ASM_AVX512_T1_H
#define IMB_ASM_AVX512_T1_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

IMB_JOB *
submit_job_des_cbc_enc_avx512(MB_MGR_DES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_des_cbc_enc_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *
submit_job_des_cbc_dec_avx512(MB_MGR_DES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_des_cbc_dec_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *
submit_job_3des_cbc_enc_avx512(MB_MGR_DES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_3des_cbc_enc_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *
submit_job_3des_cbc_dec_avx512(MB_MGR_DES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_3des_cbc_dec_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *
submit_job_docsis_des_enc_avx512(MB_MGR_DES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_docsis_des_enc_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *
submit_job_docsis_des_dec_avx512(MB_MGR_DES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_docsis_des_dec_avx512(MB_MGR_DES_OOO *state);

IMB_JOB *
submit_job_zuc_eea3_no_gfni_avx512(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_eea3_no_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_nea6_no_gfni_avx512(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_nea6_no_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_zuc_eia3_no_gfni_avx512(MB_MGR_ZUC_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_zuc_eia3_no_gfni_avx512(MB_MGR_ZUC_OOO *state);

IMB_JOB *
submit_job_sha1_avx512(MB_MGR_SHA_1_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_sha1_avx512(MB_MGR_SHA_1_OOO *state, IMB_JOB *job);

IMB_JOB *
submit_job_sha224_avx512(MB_MGR_SHA_256_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_sha224_avx512(MB_MGR_SHA_256_OOO *state, IMB_JOB *job);

IMB_JOB *
submit_job_sha256_avx512(MB_MGR_SHA_256_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_sha256_avx512(MB_MGR_SHA_256_OOO *state, IMB_JOB *job);

IMB_JOB *
submit_job_sha384_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_sha384_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);

IMB_JOB *
submit_job_sha512_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_sha512_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);

IMB_JOB *
submit_job_snow3g_uea2_avx512(MB_MGR_SNOW3G_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_snow3g_uea2_avx512(MB_MGR_SNOW3G_OOO *state);

IMB_JOB *
submit_job_snow3g_uia2_avx512(MB_MGR_SNOW3G_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_snow3g_uia2_avx512(MB_MGR_SNOW3G_OOO *state);

void
aes_cmac_256_subkey_gen_avx512(const void *key_exp, void *key1, void *key2);

IMB_JOB *
submit_job_hmac_avx512(MB_MGR_HMAC_SHA_1_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_hmac_avx512(MB_MGR_HMAC_SHA_1_OOO *state);

IMB_JOB *
submit_job_hmac_sha_224_avx512(MB_MGR_HMAC_SHA_256_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_hmac_sha_224_avx512(MB_MGR_HMAC_SHA_256_OOO *state);

IMB_JOB *
submit_job_hmac_sha_256_avx512(MB_MGR_HMAC_SHA_256_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_hmac_sha_256_avx512(MB_MGR_HMAC_SHA_256_OOO *state);

IMB_JOB *
submit_job_hmac_sha_384_avx512(MB_MGR_HMAC_SHA_512_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_hmac_sha_384_avx512(MB_MGR_HMAC_SHA_512_OOO *state);

IMB_JOB *
submit_job_hmac_sha_512_avx512(MB_MGR_HMAC_SHA_512_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_hmac_sha_512_avx512(MB_MGR_HMAC_SHA_512_OOO *state);

void
poly1305_mac_plain_avx512(IMB_JOB *job);

IMB_JOB *
submit_job_chacha20_enc_dec_avx512(IMB_JOB *job);

void
aes_docsis128_dec_crc32_avx512(IMB_JOB *job);
void
aes_docsis256_dec_crc32_avx512(IMB_JOB *job);
IMB_JOB *
submit_job_aes_docsis128_enc_crc32_avx512(MB_MGR_DOCSIS_AES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes_docsis128_enc_crc32_avx512(MB_MGR_DOCSIS_AES_OOO *state);

IMB_JOB *
submit_job_aes_docsis256_enc_crc32_avx512(MB_MGR_DOCSIS_AES_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_aes_docsis256_enc_crc32_avx512(MB_MGR_DOCSIS_AES_OOO *state);

/* SHA */
void
call_sha1_x16_avx512_from_c(SHA1_ARGS *args, uint32_t size_in_blocks);
void
call_sha256_x16_avx512_from_c(SHA256_ARGS *args, uint32_t size_in_blocks);
void
call_sha512_x8_avx512_from_c(SHA512_ARGS *args, uint64_t size_in_blocks);

IMB_DLL_EXPORT void
sha1_avx512(const void *data, const uint64_t length, void *digest);
IMB_DLL_EXPORT void
sha1_one_block_avx512(const void *data, void *digest);
IMB_DLL_EXPORT void
sha224_avx512(const void *data, const uint64_t length, void *digest);
IMB_DLL_EXPORT void
sha224_one_block_avx512(const void *data, void *digest);
IMB_DLL_EXPORT void
sha256_avx512(const void *data, const uint64_t length, void *digest);
IMB_DLL_EXPORT void
sha256_one_block_avx512(const void *data, void *digest);
IMB_DLL_EXPORT void
sha384_avx512(const void *data, const uint64_t length, void *digest);
IMB_DLL_EXPORT void
sha384_one_block_avx512(const void *data, void *digest);
IMB_DLL_EXPORT void
sha512_avx512(const void *data, const uint64_t length, void *digest);
IMB_DLL_EXPORT void
sha512_one_block_avx512(const void *data, void *digest);

IMB_DLL_EXPORT void
set_suite_id_avx512_t1(IMB_MGR *state, IMB_JOB *job);

/* SHA3 / SHAKE AVX-512 ASM functions (sha3_avx512.asm) */
IMB_DLL_LOCAL void
sha3_224_avx512(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output);
IMB_DLL_LOCAL void
sha3_256_avx512(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output);
IMB_DLL_LOCAL void
sha3_384_avx512(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output);
IMB_DLL_LOCAL void
sha3_512_avx512(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output);
/**
 * @brief Authenticate data buffer with SHAKE128 (XOF, variable-length output).
 *
 * @param [in]  input         Data buffer to be authenticated
 * @param [in]  inputByteLen  Length of the data to be authenticated in bytes
 * @param [out] output        Digest output
 * @param [in]  outputByteLen Requested digest length in bytes
 */
IMB_DLL_LOCAL void
shake128_avx512(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output,
                uint64_t outputByteLen);
/**
 * @brief Authenticate data buffer with SHAKE256 (XOF, variable-length output).
 *
 * @param [in]  input         Data buffer to be authenticated
 * @param [in]  inputByteLen  Length of the data to be authenticated in bytes
 * @param [out] output        Digest output
 * @param [in]  outputByteLen Requested digest length in bytes
 */
IMB_DLL_LOCAL void
shake256_avx512(const uint8_t *input, const uint64_t inputByteLen, uint8_t *output,
                uint64_t outputByteLen);

/*
 * HMAC-SHA3 single-buffer AVX-512 ASM function (hmac_sha3_avx512.asm).
 * One entry point serves HMAC-SHA3-224/256/384/512; the rate and digest size
 * are derived from job->hash_alg at run time.
 */
IMB_DLL_LOCAL IMB_JOB *
hmac_sha3_submit_avx512(IMB_JOB *job);

/*
 * hmac_sha3_avx512.asm derives the algorithm rate from
 * (job->hash_alg - HMAC_SHA3_ALG_FIRST), with HMAC_SHA3_ALG_FIRST hard-coded
 * to 58. Fail the build if IMB_HASH_ALG is reordered or the four HMAC-SHA3
 * values stop being contiguous, rather than silently mis-indexing at run time.
 */
#define HMAC_SHA3_ALG_FIRST 58

_Static_assert((int) IMB_AUTH_HMAC_SHA3_224 == HMAC_SHA3_ALG_FIRST &&
                       (int) IMB_AUTH_HMAC_SHA3_256 == HMAC_SHA3_ALG_FIRST + 1 &&
                       (int) IMB_AUTH_HMAC_SHA3_384 == HMAC_SHA3_ALG_FIRST + 2 &&
                       (int) IMB_AUTH_HMAC_SHA3_512 == HMAC_SHA3_ALG_FIRST + 3,
               "HMAC-SHA3 IMB_HASH_ALG values changed, "
               "update HMAC_SHA3_ALG_FIRST in hmac_sha3_avx512.asm");

/* SHA3 / SHAKE multi-buffer submit / flush (sha3_mb_avx512.asm)
 *
 * One pair of functions serves SHA3-224/256/384/512 and SHAKE128/256.
 * The sponge rate/domain-separation and output length are derived from
 * job->hash_alg and job->auth_tag_output_len_in_bytes.
 */
IMB_DLL_LOCAL IMB_JOB *
submit_job_sha3_avx512(MB_MGR_SHA3_OOO *state, IMB_JOB *job);
IMB_DLL_LOCAL IMB_JOB *
flush_job_sha3_avx512(MB_MGR_SHA3_OOO *state, IMB_JOB *job);

#endif /* IMB_ASM_AVX512_T1_H */
