/*******************************************************************************
  Copyright (c) 2022-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "include/sha_mb_mgr.h"
#include "include/arch_avx512_type1.h"

IMB_JOB *
submit_job_sha384_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_sha384_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);

IMB_JOB *
submit_job_sha512_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);
IMB_JOB *
flush_job_sha512_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job);

/* ========================================================================== */
/*
 * SHA1 MB API
 */

IMB_DLL_LOCAL
IMB_JOB *
submit_job_sha1_avx512(MB_MGR_SHA_1_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_1(state, job, 16, 1, 1, IMB_SHA1_BLOCK_SIZE, SHA1_PAD_SIZE,
                                      call_sha1_x16_avx512_from_c, 0);
}

IMB_DLL_LOCAL
IMB_JOB *
flush_job_sha1_avx512(MB_MGR_SHA_1_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_1(state, job, 16, 0, 1, IMB_SHA1_BLOCK_SIZE, SHA1_PAD_SIZE,
                                      call_sha1_x16_avx512_from_c, 0);
}

/* ========================================================================== */
/*
 * SHA224 MB API
 */

IMB_DLL_LOCAL
IMB_JOB *
submit_job_sha224_avx512(MB_MGR_SHA_256_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_256(state, job, 16, 1, 224, IMB_SHA_256_BLOCK_SIZE,
                                        SHA224_PAD_SIZE, call_sha256_x16_avx512_from_c, 0);
}

IMB_DLL_LOCAL
IMB_JOB *
flush_job_sha224_avx512(MB_MGR_SHA_256_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_256(state, job, 16, 0, 224, IMB_SHA_256_BLOCK_SIZE,
                                        SHA224_PAD_SIZE, call_sha256_x16_avx512_from_c, 0);
}

/* ========================================================================== */
/*
 * SHA256 MB API
 */

IMB_DLL_LOCAL
IMB_JOB *
submit_job_sha256_avx512(MB_MGR_SHA_256_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_256(state, job, 16, 1, 256, IMB_SHA_256_BLOCK_SIZE,
                                        SHA256_PAD_SIZE, call_sha256_x16_avx512_from_c, 0);
}

IMB_DLL_LOCAL
IMB_JOB *
flush_job_sha256_avx512(MB_MGR_SHA_256_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_256(state, job, 16, 0, 256, IMB_SHA_256_BLOCK_SIZE,
                                        SHA256_PAD_SIZE, call_sha256_x16_avx512_from_c, 0);
}

/* ========================================================================== */
/*
 * SHA384 MB API
 */

IMB_DLL_LOCAL
IMB_JOB *
submit_job_sha384_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_512(state, job, 8, 1, 384, IMB_SHA_512_BLOCK_SIZE,
                                        SHA384_PAD_SIZE, call_sha512_x8_avx512_from_c, 0);
}

IMB_DLL_LOCAL
IMB_JOB *
flush_job_sha384_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_512(state, job, 8, 0, 384, IMB_SHA_512_BLOCK_SIZE,
                                        SHA384_PAD_SIZE, call_sha512_x8_avx512_from_c, 0);
}

/* ========================================================================== */
/*
 * SHA512 MB API
 */

IMB_DLL_LOCAL
IMB_JOB *
submit_job_sha512_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_512(state, job, 8, 1, 512, IMB_SHA_512_BLOCK_SIZE,
                                        SHA512_PAD_SIZE, call_sha512_x8_avx512_from_c, 0);
}

IMB_DLL_LOCAL
IMB_JOB *
flush_job_sha512_avx512(MB_MGR_SHA_512_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_512(state, job, 8, 0, 512, IMB_SHA_512_BLOCK_SIZE,
                                        SHA512_PAD_SIZE, call_sha512_x8_avx512_from_c, 0);
}
