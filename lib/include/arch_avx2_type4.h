/*******************************************************************************
  Copyright (c) 2023-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef IMB_ASM_AVX2_T4_H
#define IMB_ASM_AVX2_T4_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

IMB_DLL_EXPORT void
set_suite_id_avx2_t4(IMB_MGR *state, IMB_JOB *job);

/* SM4 */
void
sm4_ecb_ni_avx2(const void *in, void *out, const uint64_t size, const void *exp_keys);
void
sm4_cbc_enc_ni_avx2(const void *in, void *out, const uint64_t size, const void *exp_enc_keys,
                    const void *iv);
void
sm4_cbc_dec_ni_avx2(const void *in, void *out, const uint64_t size, const void *exp_dec_keys,
                    const void *iv);
void
sm4_ctr_ni_avx2(const void *in, void *out, const uint64_t size, const void *exp_enc_keys,
                const void *iv, const uint64_t iv_len);
void
sm4_set_key_ni_avx2(const void *pKey, void *exp_enc_keys, void *exp_dec_keys);

/* SM3 */

/* digest layout is shared with the SM3 base implementation (see sm3_base_init()) */
void
sm3_update_ni_x1(void *digest, const void *input, const uint64_t num_blocks);

/* one block SM3 computation for IPAD / OPAD usage only */
void
sm3_one_block_ni_avx2(const void *data, void *digest);
/* SM3 API for use in HMAC-SM3 when key is longer than the block size */
void
sm3_ni_avx2(const void *data, const uint64_t length, void *digest);

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

IMB_JOB *
flush_job_hmac_sha_384_ni_avx2(MB_MGR_HMAC_SHA_512_OOO *state);
IMB_JOB *
flush_job_hmac_sha_512_ni_avx2(MB_MGR_HMAC_SHA_512_OOO *state);

IMB_JOB *
submit_job_hmac_sha_384_ni_avx2(MB_MGR_HMAC_SHA_512_OOO *state, IMB_JOB *job);
IMB_JOB *
submit_job_hmac_sha_512_ni_avx2(MB_MGR_HMAC_SHA_512_OOO *state, IMB_JOB *job);

void
call_sha512_ni_x2_avx2_from_c(SHA512_ARGS *args, uint64_t size_in_blocks);

#endif /* IMB_ASM_AVX2_T4_H */
