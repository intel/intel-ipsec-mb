/*******************************************************************************
  Copyright (c) 2023-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "include/sha_generic.h"
#include "include/arch_sse_type2.h"

/* ========================================================================== */
/* One block SHA1 computation for IPAD / OPAD usage only */

void
sha1_one_block_sse_shani(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_SSE_SHANI, 1 /* SHA1 */);
}

/* ========================================================================== */
/* One block SHA224 computation for IPAD / OPAD usage only */
void
sha224_one_block_sse_shani(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_SSE_SHANI, 224 /* SHA224 */);
}

/* ========================================================================== */
/* ========================================================================== */
/* One block SHA256 computation for IPAD / OPAD usage only */
void
sha256_one_block_sse_shani(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_SSE_SHANI, 256 /* SHA256 */);
}

/* ========================================================================== */
/*
 * SHA1 API for use in HMAC-SHA1 when key is longer than the block size
 */

void
sha1_sse_shani(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_SSE_SHANI, 1, IMB_SHA1_BLOCK_SIZE, SHA1_PAD_SIZE);
}

/* ========================================================================== */
/*
 * SHA224 API for use in HMAC-SHA224 when key is longer than the block size
 */
void
sha224_sse_shani(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_SSE_SHANI, 224, IMB_SHA_256_BLOCK_SIZE,
                    SHA224_PAD_SIZE);
}
/* ========================================================================== */
/*
 * SHA256 API for use in HMAC-SHA256 when key is longer than the block size
 */
void
sha256_sse_shani(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_SSE_SHANI, 256, IMB_SHA_256_BLOCK_SIZE,
                    SHA256_PAD_SIZE);
}
