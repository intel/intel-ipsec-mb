/*******************************************************************************
  Copyright (c) 2022-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "include/sha_mb_mgr.h"
#include "include/arch_sse_type2.h"

/* ========================================================================== */
/*
 * SHA1-NI MB API
 */

IMB_DLL_LOCAL
IMB_JOB *
submit_job_sha1_ni_sse(MB_MGR_SHA_1_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_1(state, job, 2, 1, 1, IMB_SHA1_BLOCK_SIZE, SHA1_PAD_SIZE,
                                      call_sha1_ni_x2_sse_from_c, 1);
}

IMB_DLL_LOCAL
IMB_JOB *
flush_job_sha1_ni_sse(MB_MGR_SHA_1_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_1(state, job, 2, 0, 1, IMB_SHA1_BLOCK_SIZE, SHA1_PAD_SIZE,
                                      call_sha1_ni_x2_sse_from_c, 1);
}

/* ========================================================================== */
/*
 * SHA224-NI MB API
 */

IMB_DLL_LOCAL
IMB_JOB *
submit_job_sha224_ni_sse(MB_MGR_SHA_256_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_256(state, job, 2, 1, 224, IMB_SHA_256_BLOCK_SIZE,
                                        SHA224_PAD_SIZE, call_sha256_ni_x2_sse_from_c, 1);
}

IMB_DLL_LOCAL
IMB_JOB *
flush_job_sha224_ni_sse(MB_MGR_SHA_256_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_256(state, job, 2, 0, 224, IMB_SHA_256_BLOCK_SIZE,
                                        SHA224_PAD_SIZE, call_sha256_ni_x2_sse_from_c, 1);
}

/* ========================================================================== */
/*
 * SHA256-NI MB API
 */

IMB_DLL_LOCAL
IMB_JOB *
submit_job_sha256_ni_sse(MB_MGR_SHA_256_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_256(state, job, 2, 1, 256, IMB_SHA_256_BLOCK_SIZE,
                                        SHA256_PAD_SIZE, call_sha256_ni_x2_sse_from_c, 1);
}

IMB_DLL_LOCAL
IMB_JOB *
flush_job_sha256_ni_sse(MB_MGR_SHA_256_OOO *state, IMB_JOB *job)
{
        return submit_flush_job_sha_256(state, job, 2, 0, 256, IMB_SHA_256_BLOCK_SIZE,
                                        SHA256_PAD_SIZE, call_sha256_ni_x2_sse_from_c, 1);
}
