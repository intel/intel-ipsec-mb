/*******************************************************************************
  Copyright (c) 2023, Intel Corporation

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

#include "intel-ipsec-mb.h"
#include <string.h>
#include "include/error.h"
#include "include/sm3.h"
#include "include/clear_regs_mem.h"

/* https://datatracker.ietf.org/doc/html/draft-shen-sm3-hash */

#ifdef LINUX
#define BSWAP32 __builtin_bswap32
#define BSWAP64 __builtin_bswap64
#else
#define BSWAP32 _byteswap_ulong
#define BSWAP64 _byteswap_uint64
#endif

/**
 * @note \a outp needs to be of volatile type to avoid the operation being
 * optimized out in some scenarios
 */
__forceinline void
store8_be(volatile void *outp, const uint64_t val)
{
        *((volatile uint64_t *) outp) = BSWAP64(val);
}

__forceinline uint32_t
XOR3(const uint32_t x, const uint32_t y, const uint32_t z)
{
        return x ^ y ^ z;
}

__forceinline uint32_t
FF0(const uint32_t x, const uint32_t y, const uint32_t z)
{
        return XOR3(x, y, z);
}

__forceinline uint32_t
GG0(const uint32_t x, const uint32_t y, const uint32_t z)
{
        return XOR3(x, y, z);
}

__forceinline uint32_t
FF1(const uint32_t x, const uint32_t y, const uint32_t z)
{
        return (x & y) | ((x | y) & z);
}

__forceinline uint32_t
GG1(const uint32_t x, const uint32_t y, const uint32_t z)
{
        return z ^ (x & (y ^ z));
}

__forceinline uint32_t
ROL32(const uint32_t a, const unsigned b)
{
        return (a << b) | (a >> (32 - b));
}

__forceinline uint32_t
P0(const uint32_t x)
{
        return x ^ ROL32(x, 9) ^ ROL32(x, 17);
}

__forceinline uint32_t
P1(const uint32_t x)
{
        return x ^ ROL32(x, 15) ^ ROL32(x, 23);
}

static const uint32_t K[64] = {
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e,
        0xe6228cbc, 0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39,
        0x11465e73, 0x228cbce6, 0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879,
        0xb14f50f3, 0x629ea1e7, 0xc53d43ce, 0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
        0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5, 0x7a879d8a, 0xf50f3b14, 0xea1e7629,
        0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d, 0x879d8a7a, 0x0f3b14f5,
        0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43, 0x9d8a7a87,
        0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
        0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762,
        0x3d43cec5
};

static void
sm3_init(uint32_t digest[8])
{
        digest[0] = 0x7380166f;
        digest[1] = 0x4914b2b9;
        digest[2] = 0x172442d7;
        digest[3] = 0xda8a0600;
        digest[4] = 0xa96f30bc;
        digest[5] = 0x163138aa;
        digest[6] = 0xe38dee4d;
        digest[7] = 0xb0fb0e4e;
}

static void
sm3_update(uint32_t digest[8], const void *input, uint64_t num_blocks)
{
        const uint32_t *data = (const uint32_t *) input;
        volatile uint32_t W[68];

        while (num_blocks--) {
                /* prepare W[] - read data first */
                for (int i = 0; i < 16; i++)
                        W[i] = BSWAP32(data[i]);

                /* expand W[] */
                for (int i = 16; i < 68; i++)
                        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROL32(W[i - 3], 15)) ^
                               ROL32(W[i - 13], 7) ^ W[i - 6];

                /* read current digest */
                register uint32_t A = digest[0];
                register uint32_t B = digest[1];
                register uint32_t C = digest[2];
                register uint32_t D = digest[3];
                register uint32_t E = digest[4];
                register uint32_t F = digest[5];
                register uint32_t G = digest[6];
                register uint32_t H = digest[7];

                /* compress */
                for (int i = 0; i < 16; i++) {
                        const uint32_t SS1 = ROL32((ROL32(A, 12) + E + K[i]), 7);
                        const uint32_t SS2 = SS1 ^ ROL32(A, 12);
                        const uint32_t TT1 = FF0(A, B, C) + D + SS2 + (W[i] ^ W[i + 4]);
                        const uint32_t TT2 = GG0(E, F, G) + H + SS1 + W[i];

                        D = C;
                        C = ROL32(B, 9);
                        B = A;
                        A = TT1;
                        H = G;
                        G = ROL32(F, 19);
                        F = E;
                        E = P0(TT2);
                }

                for (int i = 16; i < 64; i++) {
                        const uint32_t SS1 = ROL32((ROL32(A, 12) + E + K[i]), 7);
                        const uint32_t SS2 = SS1 ^ ROL32(A, 12);
                        const uint32_t TT1 = FF1(A, B, C) + D + SS2 + (W[i] ^ W[i + 4]);
                        const uint32_t TT2 = GG1(E, F, G) + H + SS1 + W[i];

                        D = C;
                        C = ROL32(B, 9);
                        B = A;
                        A = TT1;
                        H = G;
                        G = ROL32(F, 19);
                        F = E;
                        E = P0(TT2);
                }

                /* update digest and move data pointer */
                digest[0] ^= A;
                digest[1] ^= B;
                digest[2] ^= C;
                digest[3] ^= D;
                digest[4] ^= E;
                digest[5] ^= F;
                digest[6] ^= G;
                digest[7] ^= H;

                data += (IMB_SM3_BLOCK_SIZE / sizeof(uint32_t));
        }

#ifdef SAFE_DATA
        force_memset_zero_vol(W, sizeof(W));
#endif
}

void
sm3_msg(void *tag, const uint64_t tag_length, const void *msg, const uint64_t msg_length)
{
        uint32_t digest[8];
        uint8_t block[IMB_SM3_BLOCK_SIZE];

        sm3_init(digest);
        sm3_update(digest, msg, msg_length / IMB_SM3_BLOCK_SIZE);

        const uint64_t partial_bytes = msg_length % IMB_SM3_BLOCK_SIZE;
        const uint8_t *trail = &((const uint8_t *) msg)[msg_length - partial_bytes];

        memset(block, 0, sizeof(block));
        memcpy(block, trail, partial_bytes);
        block[partial_bytes] = 0x80;

        if (partial_bytes >= (IMB_SM3_BLOCK_SIZE - 8)) {
                /*
                 * length field doesn't fit into this block
                 * - compute digest on the current block
                 * - clear the block for the length to be put into it next
                 */
                sm3_update(digest, block, 1);
                memset(block, 0, sizeof(block));
        }

        store8_be(&block[IMB_SM3_BLOCK_SIZE - 8], msg_length * 8 /* bit length */);

        sm3_update(digest, block, 1);

        for (unsigned i = 0; i < IMB_DIM(digest); i++)
                digest[i] = BSWAP32(digest[i]);

        memcpy(tag, digest, tag_length);

#ifdef SAFE_DATA
        clear_scratch_xmms_sse();
        clear_mem(block, sizeof(block));
#endif
}

void
sm3_one_block(void *tag, const void *msg)
{
        uint32_t digest[8];

        sm3_init(digest);
        sm3_update(digest, msg, 1);

        memcpy(tag, digest, IMB_SM3_DIGEST_SIZE);

#ifdef SAFE_DATA
        clear_mem(digest, sizeof(digest));
        clear_scratch_xmms_sse();
#endif
}

void
sm3_hmac_msg(void *tag, const uint64_t tag_length, const void *msg, const uint64_t msg_length,
             const void *ipad, const void *opad)
{
        uint32_t digest[8];
        uint8_t block[IMB_SM3_BLOCK_SIZE];
        uint32_t *block32 = (uint32_t *) block;

        /* Initialize internal digest with IPAD */
        memcpy(digest, ipad, IMB_SM3_DIGEST_SIZE);

        /* Digest full blocks */
        sm3_update(digest, msg, msg_length / IMB_SM3_BLOCK_SIZE);

        const uint64_t partial_bytes = msg_length % IMB_SM3_BLOCK_SIZE;
        const uint8_t *trail = &((const uint8_t *) msg)[msg_length - partial_bytes];

        /* Prepare last one or two blocks (depending on size of last partial block) */
        memset(block, 0, sizeof(block));
        memcpy(block, trail, partial_bytes);
        block[partial_bytes] = 0x80;

        if (partial_bytes >= (IMB_SM3_BLOCK_SIZE - 8)) {
                /*
                 * length field doesn't fit into this block
                 * - compute digest on the current block
                 * - clear the block for the length to be put into it next
                 */
                sm3_update(digest, block, 1);
                memset(block, 0, sizeof(block));
        }

        /* Store message length plus block size (from IPAD) at the end of the block */
        store8_be(&block[IMB_SM3_BLOCK_SIZE - 8],
                  (IMB_SM3_BLOCK_SIZE + msg_length) * 8 /* bit length */);

        sm3_update(digest, block, 1);

        memset(block, 0, sizeof(block));
        for (unsigned i = 0; i < IMB_DIM(digest); i++)
                block32[i] = BSWAP32(digest[i]);

        block[IMB_SM3_DIGEST_SIZE] = 0x80;
        /* Store length of inner hash plus block size (from OPAD) at the end of the block */
        store8_be(&block[IMB_SM3_BLOCK_SIZE - 8],
                  (IMB_SM3_BLOCK_SIZE + IMB_SM3_DIGEST_SIZE) * 8 /* bit length */);

        /* Initialize internal digest with OPAD */
        memcpy(digest, opad, IMB_SM3_DIGEST_SIZE);

        sm3_update(digest, block, 1);

        for (unsigned i = 0; i < IMB_DIM(digest); i++)
                digest[i] = BSWAP32(digest[i]);

        memcpy(tag, digest, tag_length);

#ifdef SAFE_DATA
        clear_scratch_xmms_sse();
        clear_mem(block, sizeof(block));
#endif
}
