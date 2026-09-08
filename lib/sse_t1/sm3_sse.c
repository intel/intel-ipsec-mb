/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "intel-ipsec-mb.h"
#include "include/arch_sse_type1.h"

/* ========================================================================== */
/* One block SM3 computation for IPAD / OPAD usage only */

void
sm3_one_block_sse(const void *data, void *digest)
{
        sm3_base_init(digest);
        sm3_base_update(digest, data, 1);
}

/* ========================================================================== */
/*
 * SM3 API for use in HMAC-SM3 when key is longer than the block size
 */

void
sm3_sse(const void *data, const uint64_t length, void *digest)
{
        sm3_msg_sse(digest, IMB_SM3_DIGEST_SIZE, data, length);
}
