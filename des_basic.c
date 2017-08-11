/*
 * Copyright (c) 2017, Intel Corporation
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* basic DES implementation */

#include <stdint.h>
#include <string.h>

#include "des.h"
#include "des_utils.h"
#include "os.h"


__forceinline uint64_t initial_permutation(const uint64_t in)
{
        static const uint8_t ip_table_fips46_3[] = {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9,  1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
        };
        return permute_64b(reflect64(in), ip_table_fips46_3, IMB_DIM(ip_table_fips46_3));
}

__forceinline uint64_t final_permutation(const uint64_t in)
{
        static const uint8_t fp_table_fips46_3[] = {
                40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41,  9, 49, 17, 57, 25,
        };

        return reflect64(permute_64b(in, fp_table_fips46_3, IMB_DIM(fp_table_fips46_3)));
}

/* 1st part of DES round
 * - permutes and exands R(32 bits) into 48 bits
 */
__forceinline
uint64_t e_phase(const uint32_t R)
{
        /* E BIT-SELECTION TABLE FIPS46-3 */
        static const uint8_t e_table_fips46_3[] = {
                32,  1,  2,  3,  4,  5,
                 4,  5,  6,  7,  8,  9,
                 8,  9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32,  1
        };

        return permute_64b(R, e_table_fips46_3, IMB_DIM(e_table_fips46_3));
}

__forceinline
uint64_t e_phase_new(const uint32_t R)
{
        /* E BIT-SELECTION TABLE from FIPS46-3.
         * Modified to also do 8x6 to 8x8 expansion.
         * Note: bit 63 will be always zero and
         *       it's used to clear 2MSB of each byte
         */
        static const uint8_t e_table_fips46_3_new[] = {
                32,  1,  2,  3,  4,  5, 63, 63,
                 4,  5,  6,  7,  8,  9, 63, 63,
                 8,  9, 10, 11, 12, 13, 63, 63,
                12, 13, 14, 15, 16, 17, 63, 63,
                16, 17, 18, 19, 20, 21, 63, 63,
                20, 21, 22, 23, 24, 25, 63, 63,
                24, 25, 26, 27, 28, 29, 63, 63,
                28, 29, 30, 31, 32,  1, 63, 63
        };

        return permute_64b(R, e_table_fips46_3_new, IMB_DIM(e_table_fips46_3_new));
}

/* 6 bits in
 * in[5]in[0] -> row index
 * in[4]in[3]in[2]in[1] -> column
 */
__forceinline
uint32_t s_function(const uint8_t in, const uint8_t *s_table)
{
        /* bits 5:4 identify the row */
        const int row = ((in & 1) << 5) | ((in & 0x20) >> 1);
        /* bits 3:0 identify column */
        const int column = reflect_4b((in >> 1) & 0xf);

        return (uint32_t) reflect_4b(s_table[row + column]);
}

/* S1 primitive function */
__forceinline uint32_t s1(const uint8_t in)
{
        /* Columns 0 - 15 x Rows 0 - 3 */
        static const uint8_t s1_table_fips46_3[] = {
                14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,  7,
                 0, 15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,  8,
                 4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,  0,
                15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13
        };

        return s_function(in, s1_table_fips46_3) << (0 * 4);
}

/* S2 primitive function */
__forceinline uint32_t s2(const uint8_t in)
{
        /* Columns 0 - 15 x Rows 0 - 3 */
        static const uint8_t s2_table_fips46_3[] = {
                15,  1,  8, 14,  6, 11,  3,  4,  9, 7,  2, 13, 12, 0,  5, 10,
                 3, 13,  4,  7, 15,  2,  8, 14, 12, 0,  1, 10,  6, 9, 11,  5,
                 0, 14,  7, 11, 10,  4, 13,  1,  5, 8, 12,  6,  9, 3,  2, 15,
                13,  8, 10,  1,  3, 15,  4,  2, 11, 6,  7, 12,  0, 5, 14,  9
        };

        return s_function(in, s2_table_fips46_3) << (1 * 4);
}

/* S3 primitive function */
__forceinline uint32_t s3(const uint8_t in)
{
        /* Columns 0 - 15 x Rows 0 - 3 */
        static const uint8_t s3_table_fips46_3[] = {
                10,  0,  9, 14, 6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
                13,  7,  0,  9, 3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
                13,  6,  4,  9, 8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
                 1, 10, 13,  0, 6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
        };

        return s_function(in, s3_table_fips46_3) << (2 * 4);
}

/* S4 primitive function */
__forceinline uint32_t s4(const uint8_t in)
{
        /* Columns 0 - 15 x Rows 0 - 3 */
        static const uint8_t s4_table_fips46_3[] = {
                7 , 13, 14, 3, 0 , 6 , 9 , 10,  1 , 2, 8, 5 , 11, 12, 4 , 15,
                13,  8, 11, 5, 6 , 15, 0 , 3 ,  4 , 7, 2, 12, 1 , 10, 14, 9,
                10,  6, 9 , 0, 12, 11, 7 , 13,  15, 1, 3, 14, 5 , 2 , 8 , 4,
                3 , 15, 0 , 6, 10, 1 , 13, 8 ,  9 , 4, 5, 11, 12, 7 , 2 , 14
        };

        return s_function(in, s4_table_fips46_3) << (3 * 4);
}

/* S5 primitive function */
__forceinline uint32_t s5(const uint8_t in)
{
        /* Columns 0 - 15 x Rows 0 - 3 */
        static const uint8_t s5_table_fips46_3[] = {
                2 , 12, 4 , 1 , 7 , 10, 11, 6 , 8 , 5 , 3 , 15, 13, 0, 14, 9,
                14, 11, 2 , 12, 4 , 7 , 13, 1 , 5 , 0 , 15, 10, 3 , 9, 8 , 6,
                4 , 2 , 1 , 11, 10, 13, 7 , 8 , 15, 9 , 12, 5 , 6 , 3, 0 , 14,
                11, 8 , 12,  7, 1 , 14, 2 , 13, 6 , 15, 0 , 9 , 10, 4, 5 , 3,
        };

        return s_function(in, s5_table_fips46_3) << (4 * 4);
}

/* S6 primitive function */
__forceinline uint32_t s6(const uint8_t in)
{
        /* Columns 0 - 15 x Rows 0 - 3 */
        static const uint8_t s6_table_fips46_3[] = {
                12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
                10, 15, 4,  2,  7, 12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
                9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
                4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13
        };

        return s_function(in, s6_table_fips46_3) << (5 * 4);
}

/* S7 primitive function */
__forceinline uint32_t s7(const uint8_t in)
{
        /* Columns 0 - 15 x Rows 0 - 3 */
        static const uint8_t s7_table_fips46_3[] = {
                4 , 11,  2, 14, 15,  0, 8 , 13, 3 , 12, 9, 7 , 5 , 10, 6, 1,
                13, 0 , 11, 7 , 4 ,  9, 1 , 10, 14, 3 , 5, 12, 2 , 15, 8, 6,
                1 , 4 , 11, 13, 12,  3, 7 , 14, 10, 15, 6, 8 , 0 , 5 , 9, 2,
                6 , 11, 13, 8 , 1 ,  4, 10, 7 , 9 , 5 , 0, 15, 14, 2 , 3, 12
        };

        return s_function(in, s7_table_fips46_3) << (6 * 4);
}

/* S8 primitive function */
__forceinline uint32_t s8(const uint8_t in)
{
        /* Columns 0 - 15 x Rows 0 - 3 */
        static const uint8_t s8_table_fips46_3[] = {
                13, 2 , 8 , 4, 6 , 15, 11, 1 , 10,  9 , 3 , 14, 5 , 0 , 12, 7,
                1 , 15, 13, 8, 10, 3 , 7 , 4 , 12,  5 , 6 , 11, 0 , 14, 9 , 2,
                7 , 11, 4 , 1, 9 , 12, 14, 2 , 0 ,  6 , 10, 13, 15, 3 , 5 , 8,
                2 , 1 , 14, 7, 4 , 10, 8 , 13, 15,  12, 9 , 0 , 3 , 5 , 6 , 11
        };

        return s_function(in, s8_table_fips46_3) << (7 * 4);
}

/* P phase */
__forceinline
uint32_t p_phase(const uint32_t in)
{
        static const uint8_t p_table_fips46_3[] = {
                16,  7, 20, 21,
                29, 12, 28, 17,
                 1, 15, 23, 26,
                 5, 18, 31, 10,
                 2,  8, 24, 14,
                32, 27,  3,  9,
                19, 13, 30,  6,
                22, 11,  4, 25
        };

        return permute_32b(in, p_table_fips46_3, IMB_DIM(p_table_fips46_3));
}

__forceinline
uint32_t fRK(const uint32_t R, const uint64_t K)
{
        uint64_t x;
        uint32_t y;

        /* e_pahse_new(x) is equal to E() transform and expansion:
         *     x = e_phase(R);  
         *     x = expand_8x6_to_8x8(x);
         * The expansion is required so that K format matches output of E().
         */
        x = e_phase_new(R) ^ K;

        /* s-box: 48 bits -> 32 bits */
        y = s1((uint8_t)x) |
                s2((uint8_t)(x >> (8 * 1))) |
                s3((uint8_t)(x >> (8 * 2))) |
                s4((uint8_t)(x >> (8 * 3))) |
                s5((uint8_t)(x >> (8 * 4))) |
                s6((uint8_t)(x >> (8 * 5))) |
                s7((uint8_t)(x >> (8 * 6))) |
                s8((uint8_t)(x >> (8 * 7)));

        /* 32 bits -> 32 bits permutation */
        y = p_phase(y);

        return y;
}

__forceinline
uint64_t enc_dec_1(const uint64_t data, const uint64_t *ks, const int enc)
{
        uint64_t d;
        uint32_t l, r;

        d = initial_permutation(data);
        l = (uint32_t) (d);
        r = (uint32_t) (d >> 32);
        
        if (enc) {
                l ^= fRK(r, ks[0]);
                r ^= fRK(l, ks[1]);
                l ^= fRK(r, ks[2]);
                r ^= fRK(l, ks[3]);
                l ^= fRK(r, ks[4]);
                r ^= fRK(l, ks[5]);
                l ^= fRK(r, ks[6]);
                r ^= fRK(l, ks[7]);
                l ^= fRK(r, ks[8]);
                r ^= fRK(l, ks[9]);
                l ^= fRK(r, ks[10]);
                r ^= fRK(l, ks[11]);
                l ^= fRK(r, ks[12]);
                r ^= fRK(l, ks[13]);
                l ^= fRK(r, ks[14]);
                r ^= fRK(l, ks[15]);
        } else {
                l ^= fRK(r, ks[15]);     /* l: l0 -> r1/l2 */
                r ^= fRK(l, ks[14]);     /* r: r0 -> r2 */
                l ^= fRK(r, ks[13]);
                r ^= fRK(l, ks[12]);
                l ^= fRK(r, ks[11]);
                r ^= fRK(l, ks[10]);
                l ^= fRK(r, ks[9]);
                r ^= fRK(l, ks[8]);
                l ^= fRK(r, ks[7]);
                r ^= fRK(l, ks[6]);
                l ^= fRK(r, ks[5]);
                r ^= fRK(l, ks[4]);
                l ^= fRK(r, ks[3]);
                r ^= fRK(l, ks[2]);
                l ^= fRK(r, ks[1]);
                r ^= fRK(l, ks[0]);
        }

        d = r | (((uint64_t) l) << 32);
        d = final_permutation(d);
        return d;
}

void
des_enc_cbc_basic(const void *input, void *output, const int size,
                  const uint64_t *ks, const uint64_t *ivec)
{
        const uint64_t *in = input;
        uint64_t *out = output;
        const int nblocks = size / 8;
        int n;
        uint64_t iv = *ivec;

        IMB_ASSERT(size >= 0);
        IMB_ASSERT(input != NULL);
        IMB_ASSERT(output != NULL);
        IMB_ASSERT(ks != NULL);
        IMB_ASSERT(ivec != NULL);

        for (n = 0; n < nblocks; n++)
                out[n] = iv = enc_dec_1(in[n] ^ iv, ks, 1 /* encrypt */);

        /* *ivec = iv; */
        iv = 0;
}

void
des_dec_cbc_basic(const void *input, void *output, const int size,
                  const uint64_t *ks, const uint64_t *ivec)
{
        const uint64_t *in = input;
        uint64_t *out = output;
        const int nblocks = size / 8;
        int n;
        uint64_t iv = *ivec;

        IMB_ASSERT(size >= 0);
        IMB_ASSERT(input != NULL);
        IMB_ASSERT(output != NULL);
        IMB_ASSERT(ks != NULL);
        IMB_ASSERT(ivec != NULL);

        for (n = 0; n < nblocks; n++) {
                out[n] = enc_dec_1(in[n], ks, 0 /* decrypt */) ^ iv;
                iv = in[n];
        }

        /* *ivec = iv; */
        iv = 0;
}

void des_cfb_one_basic(const void *input, void *output, const int size,
                       const uint64_t *ks, const uint64_t *ivec)
{
        union {
                uint8_t b8[sizeof(uint64_t)];
                uint64_t b64;
        } u;
        uint64_t t;

        IMB_ASSERT(size <= 8 && size >= 0);
        IMB_ASSERT(input != NULL);
        IMB_ASSERT(output != NULL);
        IMB_ASSERT(ks != NULL);
        IMB_ASSERT(ivec != NULL);

        u.b64 = UINT64_C(0);
        memcpy(u.b8, input, size);

        t = enc_dec_1(*ivec, ks, 1 /* encrypt */);
        u.b64 ^= t;

        memcpy(output, u.b8, size);
}
