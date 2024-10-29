/*******************************************************************************
  Copyright (c) 2023-2024, Intel Corporation

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

      * Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
      * Neither the name of Intel Corporation nor the names of its contributors
        may be used to endorse or promote products derived from this software
        without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
