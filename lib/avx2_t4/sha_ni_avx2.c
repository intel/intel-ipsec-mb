/*******************************************************************************
  Copyright (c) 2020-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "include/sha_generic.h"
#include "include/sha_mb_mgr.h"
#include "include/arch_avx2_type4.h"

/* ========================================================================== */
/* One block SHA384 computation for IPAD / OPAD usage only */
void
sha384_one_block_ni_avx2(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_AVX2_SHANI, 384 /* SHA384 */);
}

/* ========================================================================== */
/*
 * SHA384 API for use in HMAC-SHA384 when key is longer than the block size
 */
void
sha384_ni_avx2(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_AVX2_SHANI, 384, IMB_SHA_384_BLOCK_SIZE,
                    SHA384_PAD_SIZE);
}

/* ========================================================================== */
/* One block SHA512 computation for IPAD / OPAD usage only */
void
sha512_one_block_ni_avx2(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_AVX2_SHANI, 512 /* SHA512 */);
}

/* ========================================================================== */
/*
 * SHA512 API for use in HMAC-SHA512 when key is longer than the block size
 */
void
sha512_ni_avx2(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_AVX2_SHANI, 512, IMB_SHA_512_BLOCK_SIZE,
                    SHA512_PAD_SIZE);
}

/* ========================================================================== */
/*
 * SHA384 MB API for JOB API
 */
IMB_JOB *
submit_job_sha384_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
#ifdef SMX_NI
        return submit_flush_job_sha_512(state, job, 2, 1, 384, IMB_SHA_384_BLOCK_SIZE,
                                        SHA384_PAD_SIZE, call_sha512_ni_x2_avx2_from_c, 1);
#else
        (void) state;
        (void) job;
        return NULL;
#endif /* ifdef SMX_NI */
}

IMB_JOB *
flush_job_sha384_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
#ifdef SMX_NI
        return submit_flush_job_sha_512(state, job, 2, 0, 384, IMB_SHA_384_BLOCK_SIZE,
                                        SHA384_PAD_SIZE, call_sha512_ni_x2_avx2_from_c, 1);
#else
        (void) state;
        (void) job;
        return NULL;
#endif /* ifdef SMX_NI */
}

/* ========================================================================== */
/*
 * SHA512 MB API for JOB API
 */
IMB_JOB *
submit_job_sha512_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
#ifdef SMX_NI
        return submit_flush_job_sha_512(state, job, 2, 1, 512, IMB_SHA_512_BLOCK_SIZE,
                                        SHA512_PAD_SIZE, call_sha512_ni_x2_avx2_from_c, 1);
#else
        (void) state;
        (void) job;
        return NULL;
#endif /* ifdef SMX_NI */
}

IMB_JOB *
flush_job_sha512_ni_avx2(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
#ifdef SMX_NI
        return submit_flush_job_sha_512(state, job, 2, 0, 512, IMB_SHA_512_BLOCK_SIZE,
                                        SHA512_PAD_SIZE, call_sha512_ni_x2_avx2_from_c, 1);
#else
        (void) state;
        (void) job;
        return NULL;
#endif /* ifdef SMX_NI */
}
