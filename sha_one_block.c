/*******************************************************************************
  Copyright (c) 2018, Intel Corporation

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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "intel-ipsec-mb.h"
#include "constants.h"

extern void sha1_block_sse(const void *, void *);
extern void sha1_block_avx(const void *, void *);


/* ========================================================================== */
/* One block SHA1 computation for IPAD / OPAD usage only */

__forceinline
void sha1_init_digest(void *p)
{
        uint32_t *p_digest = (uint32_t *)p;

        p_digest[0] = H0;
        p_digest[1] = H1;
        p_digest[2] = H2;
        p_digest[3] = H3;
        p_digest[4] = H4;
}

void sha1_one_block_sse(const void *data, void *digest)
{
        if (data == NULL || digest == NULL)
                return;

        sha1_init_digest(digest);
        sha1_block_sse(data, digest);
}

void sha1_one_block_avx(const void *data, void *digest)
{
        if (data == NULL || digest == NULL)
                return;

        sha1_init_digest(digest);
        sha1_block_avx(data, digest);
}

void sha1_one_block_avx2(const void *data, void *digest)
{
        sha1_one_block_avx(data, digest);
}

void sha1_one_block_avx512(const void *data, void *digest)
{
        sha1_one_block_avx(data, digest);
}

/* ========================================================================== */
/*
 * SHA1 computation for use in HMAC-SHA1
 * when key is longer than the block size
 */

__forceinline
uint32_t
bswap4(const uint32_t val)
{
        return ((val >> 24) |             /**< A*/
                ((val & 0xff0000) >> 8) | /**< B*/
                ((val & 0xff00) << 8) |   /**< C*/
                (val << 24));             /**< D*/
}

__forceinline
void
store8_be(void *outp, const uint64_t val)
{
        uint32_t *out = (uint32_t *) outp;

        out[0] = bswap4((uint32_t) (val >> 32));
        out[1] = bswap4((uint32_t) val);
}

__forceinline
void
bswap4_array(void *digest, const size_t num)
{
        uint32_t *outp = (uint32_t *) digest;
        size_t i;

        for (i = 0; i < num; i++)
                outp[i] = bswap4(outp[i]);
}

#define SHA1_BLOCK_SIZE 64
#define SHA1_LENGTH_IDX 56

__forceinline
void
sha1_generic(const void *data,
             const uint64_t length,
             void *digest,
             const int is_avx)
{
        const uint8_t *inp = (const uint8_t *)data;
        const uint64_t bit_length = length * 8;
        uint8_t cb[SHA1_BLOCK_SIZE];
        uint64_t idx, r;

        if (data == NULL || digest == NULL)
                return;

        sha1_init_digest(digest);

        for (idx = 0; (idx + SHA1_BLOCK_SIZE) <= length; idx += SHA1_BLOCK_SIZE)
                if (is_avx)
                        sha1_block_avx(&inp[idx], digest);
                else
                        sha1_block_sse(&inp[idx], digest);

        r = length % SHA1_BLOCK_SIZE;

        memset(cb, 0, sizeof(cb));
        memcpy(cb, &inp[idx], r);
        cb[r] = 0x80;

        if (r >= SHA1_LENGTH_IDX) {
                /* length will be encoded in the next block */
                if (is_avx)
                        sha1_block_avx(cb, digest);
                else
                        sha1_block_sse(cb, digest);
                memset(cb, 0, sizeof(cb));
        }

        store8_be(&cb[SHA1_LENGTH_IDX], bit_length);

        if (is_avx)
                sha1_block_avx(cb, digest);
        else
                sha1_block_sse(cb, digest);

        bswap4_array(digest, 5);
}

void sha1_sse(const void *data, const uint64_t length, void *digest)
{
        sha1_generic(data, length, digest, 0 /* SSE */ );
}

void sha1_avx(const void *data, const uint64_t length, void *digest)
{
        sha1_generic(data, length, digest, 1 /* AVX */ );
}

void sha1_avx2(const void *data, const uint64_t length, void *digest)
{
        sha1_generic(data, length, digest, 1 /* AVX */ );
}

void sha1_avx512(const void *data, const uint64_t length, void *digest)
{
        sha1_generic(data, length, digest, 1 /* AVX */ );
}
