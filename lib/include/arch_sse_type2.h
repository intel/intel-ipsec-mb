/*******************************************************************************
  Copyright (c) 2022-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/* ARCH SSE TYPE 2: SSE4.2, AESNI, PCLMULQDQ, CMOV, BSWAP, SHANI */

#ifndef IMB_ARCH_SSE_TYPE2_H
#define IMB_ARCH_SSE_TYPE2_H

#include "intel-ipsec-mb.h"
#include "ipsec_ooo_mgr.h"

/* SHA */
void
call_sha1_ni_x2_sse_from_c(SHA1_ARGS *args, uint32_t size_in_blocks);
void
call_sha256_ni_x2_sse_from_c(SHA256_ARGS *args, uint32_t size_in_blocks);

void
sha1_ni_block_sse(const void *, void *);
void
sha1_ni_update_sse(const void *, void *, uint64_t);
void
sha256_ni_block_sse(const void *, void *);
void
sha256_ni_update_sse(const void *, void *, uint64_t num_blocks);

IMB_DLL_EXPORT void
sha1_sse_shani(const void *data, const uint64_t length, void *digest);
IMB_DLL_EXPORT void
sha1_one_block_sse_shani(const void *data, void *digest);

IMB_DLL_EXPORT void
sha224_sse_shani(const void *data, const uint64_t length, void *digest);
IMB_DLL_EXPORT void
sha224_one_block_sse_shani(const void *data, void *digest);

IMB_DLL_EXPORT void
sha256_sse_shani(const void *data, const uint64_t length, void *digest);
IMB_DLL_EXPORT void
sha256_one_block_sse_shani(const void *data, void *digest);

/* Moved from MB MGR */

IMB_JOB *
submit_job_hmac_ni_sse(MB_MGR_HMAC_SHA_1_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_hmac_ni_sse(MB_MGR_HMAC_SHA_1_OOO *state);

IMB_JOB *
submit_job_hmac_sha_224_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_hmac_sha_224_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state);

IMB_JOB *
submit_job_hmac_sha_256_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_hmac_sha_256_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state);

IMB_JOB *
submit_job_sha1_ni_sse(MB_MGR_SHA_1_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_sha1_ni_sse(MB_MGR_SHA_1_OOO *state, IMB_JOB *job);

IMB_JOB *
submit_job_sha224_ni_sse(MB_MGR_SHA_256_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_sha224_ni_sse(MB_MGR_SHA_256_OOO *state, IMB_JOB *job);

IMB_JOB *
submit_job_sha256_ni_sse(MB_MGR_SHA_256_OOO *state, IMB_JOB *job);

IMB_JOB *
flush_job_sha256_ni_sse(MB_MGR_SHA_256_OOO *state, IMB_JOB *job);

IMB_DLL_EXPORT void
set_suite_id_sse_t2(IMB_MGR *state, IMB_JOB *job);

#endif /* IMB_ARCH_SSE_TYPE2_H */
