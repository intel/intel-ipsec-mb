/*******************************************************************************
  Copyright (c) 2020-2024, Intel Corporation

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

#ifndef IMB_SHA_GENERIC_H
#define IMB_SHA_GENERIC_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "ipsec_ooo_mgr.h"
#include "constants.h"
#include "include/clear_regs_mem.h"
#include "include/error.h"
#include "include/arch_sse_type1.h"
#include "include/arch_sse_type2.h"
#include "include/arch_avx2_type4.h"

enum arch_type { ARCH_SSE = 0, ARCH_SSE_SHANI, ARCH_AVX, ARCH_AVX2_SHANI };

/* ========================================================================== */
/*
 * Various utility functions for SHA API
 */
__forceinline uint32_t
bswap4(const uint32_t val)
{
#ifdef LINUX
        return __builtin_bswap32(val);
#else
        return _byteswap_ulong(val);
#endif
}

__forceinline uint64_t
bswap8(const uint64_t val)
{
#ifdef LINUX
        return __builtin_bswap64(val);
#else
        return _byteswap_uint64(val);
#endif
}

__forceinline void
store8_be(void *outp, const uint64_t val)
{
        *((uint64_t *) outp) = bswap8(val);
}

__forceinline void
var_memcpy(void *dst, const void *src, const uint64_t len)
{
        uint64_t i;
        const uint8_t *src8 = (const uint8_t *) src;
        uint8_t *dst8 = (uint8_t *) dst;

        for (i = 0; i < len; i++)
                dst8[i] = src8[i];
}

__forceinline void
copy_bswap4_array(void *dst, const void *src, const size_t num)
{
        uint32_t *outp = (uint32_t *) dst;
        const uint32_t *inp = (const uint32_t *) src;
        size_t i;

        for (i = 0; i < num; i++)
                outp[i] = bswap4(inp[i]);
}

__forceinline void
copy_bswap8_array(void *dst, const void *src, const size_t num)
{
        uint64_t *outp = (uint64_t *) dst;
        const uint64_t *inp = (const uint64_t *) src;
        size_t i;

        for (i = 0; i < num; i++)
                outp[i] = bswap8(inp[i]);
}

__forceinline void
sha_generic_one_block(const void *inp, void *digest, const enum arch_type arch, const int sha_type)
{
        if (sha_type == 1) {
                IMB_ASSERT(arch != ARCH_AVX2_SHANI);
                if (arch == ARCH_AVX || arch == ARCH_SSE)
                        sha1_block_sse(inp, digest);
                else /* arch == ARCH_SSE_SHANI */
                        sha1_ni_block_sse(inp, digest);
        } else if (sha_type == 224) {
                IMB_ASSERT(arch != ARCH_AVX2_SHANI);
                if (arch == ARCH_AVX || arch == ARCH_SSE)
                        sha224_block_sse(inp, digest);
                else /* arch == ARCH_SSE_SHANI */
                        sha256_ni_block_sse(inp, digest);
        } else if (sha_type == 256) {
                IMB_ASSERT(arch != ARCH_AVX2_SHANI);
                if (arch == ARCH_AVX || arch == ARCH_SSE)
                        sha256_block_sse(inp, digest);
                else /* arch == ARCH_SSE_SHANI */
                        sha256_ni_block_sse(inp, digest);
        } else if (sha_type == 384) {
                IMB_ASSERT(arch != ARCH_SSE_SHANI);
                if (arch == ARCH_AVX)
                        sha384_block_sse(inp, digest);
#ifdef SMX_NI
                else if (arch == ARCH_SSE)
                        sha384_block_sse(inp, digest);
                else /* arch == ARCH_AVX2_SHANI */
                        sha512_ni_block_avx2(inp, digest);
#else
                else
                        sha384_block_sse(inp, digest);
#endif
        } else if (sha_type == 512) {
                IMB_ASSERT(arch != ARCH_SSE_SHANI);
                if (arch == ARCH_AVX)
                        sha512_block_sse(inp, digest);
#ifdef SMX_NI
                else if (arch == ARCH_SSE)
                        sha512_block_sse(inp, digest);
                else /* arch == ARCH_AVX2_SHANI */
                        sha512_ni_block_avx2(inp, digest);
#else
                else
                        sha512_block_sse(inp, digest);
#endif
        }
}

__forceinline void
sha1_init_digest(void *p)
{
        uint32_t *p_digest = (uint32_t *) p;

        p_digest[0] = H0;
        p_digest[1] = H1;
        p_digest[2] = H2;
        p_digest[3] = H3;
        p_digest[4] = H4;
}

__forceinline void
sha224_init_digest(void *p)
{
        uint32_t *p_digest = (uint32_t *) p;

        p_digest[0] = SHA224_H0;
        p_digest[1] = SHA224_H1;
        p_digest[2] = SHA224_H2;
        p_digest[3] = SHA224_H3;
        p_digest[4] = SHA224_H4;
        p_digest[5] = SHA224_H5;
        p_digest[6] = SHA224_H6;
        p_digest[7] = SHA224_H7;
}

__forceinline void
sha256_init_digest(void *p)
{
        uint32_t *p_digest = (uint32_t *) p;

        p_digest[0] = SHA256_H0;
        p_digest[1] = SHA256_H1;
        p_digest[2] = SHA256_H2;
        p_digest[3] = SHA256_H3;
        p_digest[4] = SHA256_H4;
        p_digest[5] = SHA256_H5;
        p_digest[6] = SHA256_H6;
        p_digest[7] = SHA256_H7;
}

__forceinline void
sha384_init_digest(void *p)
{
        uint64_t *p_digest = (uint64_t *) p;

        p_digest[0] = SHA384_H0;
        p_digest[1] = SHA384_H1;
        p_digest[2] = SHA384_H2;
        p_digest[3] = SHA384_H3;
        p_digest[4] = SHA384_H4;
        p_digest[5] = SHA384_H5;
        p_digest[6] = SHA384_H6;
        p_digest[7] = SHA384_H7;
}

__forceinline void
sha512_init_digest(void *p)
{
        uint64_t *p_digest = (uint64_t *) p;

        p_digest[0] = SHA512_H0;
        p_digest[1] = SHA512_H1;
        p_digest[2] = SHA512_H2;
        p_digest[3] = SHA512_H3;
        p_digest[4] = SHA512_H4;
        p_digest[5] = SHA512_H5;
        p_digest[6] = SHA512_H6;
        p_digest[7] = SHA512_H7;
}

__forceinline void
sha_generic_init(void *digest, const int sha_type)
{
        if (sha_type == 1)
                sha1_init_digest(digest);
        else if (sha_type == 224)
                sha224_init_digest(digest);
        else if (sha_type == 256)
                sha256_init_digest(digest);
        else if (sha_type == 384)
                sha384_init_digest(digest);
        else if (sha_type == 512)
                sha512_init_digest(digest);
}

__forceinline void
sha_generic_write_digest(void *dst, const void *src, const int sha_type)
{
        if (sha_type == 1)
                copy_bswap4_array(dst, src, NUM_SHA_DIGEST_WORDS);
        else if (sha_type == 224)
                copy_bswap4_array(dst, src, NUM_SHA_224_DIGEST_WORDS);
        else if (sha_type == 256)
                copy_bswap4_array(dst, src, NUM_SHA_256_DIGEST_WORDS);
        else if (sha_type == 384)
                copy_bswap8_array(dst, src, NUM_SHA_384_DIGEST_WORDS);
        else if (sha_type == 512)
                copy_bswap8_array(dst, src, NUM_SHA_512_DIGEST_WORDS);
}

__forceinline void
sha_generic(const void *data, const uint64_t length, void *digest, const enum arch_type arch,
            const int sha_type, const uint64_t blk_size, const uint64_t pad_size)
{
#ifdef SAFE_PARAM
        imb_set_errno(NULL, 0);
        if (data == NULL && length != 0) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }
        if (digest == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_AUTH);
                return;
        }
#endif

        uint8_t cb[IMB_SHA_512_BLOCK_SIZE]; /* biggest possible */
        union {
                uint32_t digest1[NUM_SHA_256_DIGEST_WORDS];
                uint64_t digest2[NUM_SHA_512_DIGEST_WORDS];
        } local_digest;
        void *ld = (void *) &local_digest;
        const uint8_t *inp = (const uint8_t *) data;
        uint64_t idx, r;

        sha_generic_init(ld, sha_type);

        for (idx = 0; (idx + blk_size) <= length; idx += blk_size)
                sha_generic_one_block(&inp[idx], ld, arch, sha_type);

        r = length % blk_size;

        memset(cb, 0, sizeof(cb));
        var_memcpy(cb, &inp[idx], r);
        cb[r] = 0x80;

        if (r >= (blk_size - pad_size)) {
                /* length will be encoded in the next block */
                sha_generic_one_block(cb, ld, arch, sha_type);
                memset(cb, 0, sizeof(cb));
        }

        store8_be(&cb[blk_size - 8], length * 8 /* bit length */);
        sha_generic_one_block(cb, ld, arch, sha_type);

        sha_generic_write_digest(digest, ld, sha_type);
#ifdef SAFE_DATA
        clear_mem(cb, sizeof(cb));
        clear_mem(&local_digest, sizeof(local_digest));
        clear_scratch_gps();
        if (arch == ARCH_AVX || arch == ARCH_AVX2_SHANI)
                clear_scratch_xmms_avx();
        else
                clear_scratch_xmms_sse();
#endif
}

__forceinline void
sha_generic_1block(const void *data, void *digest, const enum arch_type arch, const int sha_type)
{
#ifdef SAFE_PARAM
        imb_set_errno(NULL, 0);
        if (data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_SRC);
                return;
        }
        if (digest == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_AUTH);
                return;
        }
#endif
        sha_generic_init(digest, sha_type);
        sha_generic_one_block(data, digest, arch, sha_type);
#ifdef SAFE_DATA
        clear_scratch_gps();
        if (arch == ARCH_AVX || arch == ARCH_AVX2_SHANI)
                clear_scratch_xmms_avx();
        else
                clear_scratch_xmms_sse();
#endif
}

#endif /* IMB_SHA_GENERIC_H */
