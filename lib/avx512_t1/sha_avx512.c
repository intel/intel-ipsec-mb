/*******************************************************************************
  Copyright (c) 2020-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "include/sha_generic.h"
#include "include/arch_avx512_type1.h"

/* ========================================================================== */
/* One block SHA1 computation for IPAD / OPAD usage only */
void
sha1_one_block_avx512(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_AVX, 1 /* SHA1 */);
}

/* ========================================================================== */
/*
 * SHA1 API for use in HMAC-SHA1 when key is longer than the block size
 */
void
sha1_avx512(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_AVX, 1, IMB_SHA1_BLOCK_SIZE, SHA1_PAD_SIZE);
}

/* ========================================================================== */
/* One block SHA224 computation for IPAD / OPAD usage only */
void
sha224_one_block_avx512(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_AVX, 224 /* SHA224 */);
}

/* ========================================================================== */
/*
 * SHA224 API for use in HMAC-SHA224 when key is longer than the block size
 */
void
sha224_avx512(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_AVX, 224, IMB_SHA_256_BLOCK_SIZE, SHA224_PAD_SIZE);
}

/* ========================================================================== */
/* One block SHA256 computation for IPAD / OPAD usage only */
void
sha256_one_block_avx512(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_AVX, 256 /* SHA256 */);
}

/* ========================================================================== */
/*
 * SHA256 API for use in HMAC-SHA256 when key is longer than the block size
 */
void
sha256_avx512(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_AVX, 256, IMB_SHA_256_BLOCK_SIZE, SHA256_PAD_SIZE);
}

/* ========================================================================== */
/* One block SHA384 computation for IPAD / OPAD usage only */
void
sha384_one_block_avx512(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_AVX, 384 /* SHA384 */);
}

/* ========================================================================== */
/*
 * SHA384 API for use in HMAC-SHA384 when key is longer than the block size
 */
void
sha384_avx512(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_AVX, 384, IMB_SHA_384_BLOCK_SIZE, SHA384_PAD_SIZE);
}

/* ========================================================================== */
/* One block SHA512 computation for IPAD / OPAD usage only */
void
sha512_one_block_avx512(const void *data, void *digest)
{
        sha_generic_1block(data, digest, ARCH_AVX, 512 /* SHA512 */);
}

/* ========================================================================== */
/*
 * SHA512 API for use in HMAC-SHA512 when key is longer than the block size
 */
void
sha512_avx512(const void *data, const uint64_t length, void *digest)
{
        sha_generic(data, length, digest, ARCH_AVX, 512, IMB_SHA_512_BLOCK_SIZE, SHA512_PAD_SIZE);
}
