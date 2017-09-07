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

/* AVX512 DES CBC implementation and DCOSIS DES implementation */

/*
 * Authors:
 *   Shay Gueron (1, 2), Regev Shemy (2), Tomasz kantecki (2)
 *   (1) University of Haifa, Israel
 *   (2) Intel Corporation
 */

#include <x86intrin.h>
#include <string.h>

#include "mb_mgr.h"
#include "asm_types.h"
#include "os.h"
#include "des.h"
#include "des_x16_avx512.h"

static const DECLARE_ALIGNED(uint32_t p_mask_values[16 * 19], 64) = {
        0x04000000, 0x04000000, 0x04000000, 0x04000000,
        0x04000000, 0x04000000, 0x04000000, 0x04000000,
        0x04000000, 0x04000000, 0x04000000, 0x04000000,
        0x04000000, 0x04000000, 0x04000000, 0x04000000,
        0x40240202, 0x40240202, 0x40240202, 0x40240202,
        0x40240202, 0x40240202, 0x40240202, 0x40240202,
        0x40240202, 0x40240202, 0x40240202, 0x40240202,
        0x40240202, 0x40240202, 0x40240202, 0x40240202,
        0x00001110, 0x00001110, 0x00001110, 0x00001110,
        0x00001110, 0x00001110, 0x00001110, 0x00001110,
        0x00001110, 0x00001110, 0x00001110, 0x00001110,
        0x00001110, 0x00001110, 0x00001110, 0x00001110,
        0x01088000, 0x01088000, 0x01088000, 0x01088000,
        0x01088000, 0x01088000, 0x01088000, 0x01088000,
        0x01088000, 0x01088000, 0x01088000, 0x01088000,
        0x01088000, 0x01088000, 0x01088000, 0x01088000,
        0x00000001, 0x00000001, 0x00000001, 0x00000001,
        0x00000001, 0x00000001, 0x00000001, 0x00000001,
        0x00000001, 0x00000001, 0x00000001, 0x00000001,
        0x00000001, 0x00000001, 0x00000001, 0x00000001,
        0x0081000C, 0x0081000C, 0x0081000C, 0x0081000C,
        0x0081000C, 0x0081000C, 0x0081000C, 0x0081000C,
        0x0081000C, 0x0081000C, 0x0081000C, 0x0081000C,
        0x0081000C, 0x0081000C, 0x0081000C, 0x0081000C,
        0x00000020, 0x00000020, 0x00000020, 0x00000020,
        0x00000020, 0x00000020, 0x00000020, 0x00000020,
        0x00000020, 0x00000020, 0x00000020, 0x00000020,
        0x00000020, 0x00000020, 0x00000020, 0x00000020,
        0x00000040, 0x00000040, 0x00000040, 0x00000040,
        0x00000040, 0x00000040, 0x00000040, 0x00000040,
        0x00000040, 0x00000040, 0x00000040, 0x00000040,
        0x00000040, 0x00000040, 0x00000040, 0x00000040,
        0x00400400, 0x00400400, 0x00400400, 0x00400400,
        0x00400400, 0x00400400, 0x00400400, 0x00400400,
        0x00400400, 0x00400400, 0x00400400, 0x00400400,
        0x00400400, 0x00400400, 0x00400400, 0x00400400,
        0x00000800, 0x00000800, 0x00000800, 0x00000800,
        0x00000800, 0x00000800, 0x00000800, 0x00000800,
        0x00000800, 0x00000800, 0x00000800, 0x00000800,
        0x00000800, 0x00000800, 0x00000800, 0x00000800,
        0x00002000, 0x00002000, 0x00002000, 0x00002000,
        0x00002000, 0x00002000, 0x00002000, 0x00002000,
        0x00002000, 0x00002000, 0x00002000, 0x00002000,
        0x00002000, 0x00002000, 0x00002000, 0x00002000,
        0x00100000, 0x00100000, 0x00100000, 0x00100000,
        0x00100000, 0x00100000, 0x00100000, 0x00100000,
        0x00100000, 0x00100000, 0x00100000, 0x00100000,
        0x00100000, 0x00100000, 0x00100000, 0x00100000,
        0x00004000, 0x00004000, 0x00004000, 0x00004000,
        0x00004000, 0x00004000, 0x00004000, 0x00004000,
        0x00004000, 0x00004000, 0x00004000, 0x00004000,
        0x00004000, 0x00004000, 0x00004000, 0x00004000,
        0x00020000, 0x00020000, 0x00020000, 0x00020000,
        0x00020000, 0x00020000, 0x00020000, 0x00020000,
        0x00020000, 0x00020000, 0x00020000, 0x00020000,
        0x00020000, 0x00020000, 0x00020000, 0x00020000,
        0x02000000, 0x02000000, 0x02000000, 0x02000000,
        0x02000000, 0x02000000, 0x02000000, 0x02000000,
        0x02000000, 0x02000000, 0x02000000, 0x02000000,
        0x02000000, 0x02000000, 0x02000000, 0x02000000,
        0x08000000, 0x08000000, 0x08000000, 0x08000000,
        0x08000000, 0x08000000, 0x08000000, 0x08000000,
        0x08000000, 0x08000000, 0x08000000, 0x08000000,
        0x08000000, 0x08000000, 0x08000000, 0x08000000,
        0x00000080, 0x00000080, 0x00000080, 0x00000080,
        0x00000080, 0x00000080, 0x00000080, 0x00000080,
        0x00000080, 0x00000080, 0x00000080, 0x00000080,
        0x00000080, 0x00000080, 0x00000080, 0x00000080,
        0x20000000, 0x20000000, 0x20000000, 0x20000000,
        0x20000000, 0x20000000, 0x20000000, 0x20000000,
        0x20000000, 0x20000000, 0x20000000, 0x20000000,
        0x20000000, 0x20000000, 0x20000000, 0x20000000,
        0x90000000, 0x90000000, 0x90000000, 0x90000000,
        0x90000000, 0x90000000, 0x90000000, 0x90000000,
        0x90000000, 0x90000000, 0x90000000, 0x90000000,
        0x90000000, 0x90000000, 0x90000000, 0x90000000
};

static const DECLARE_ALIGNED(uint32_t init_perm_consts[16 * 5], 64) = {
        0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f,
        0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f,
        0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f,
        0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f,
        0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff,
        0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff,
        0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff,
        0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff,
        0x33333333, 0x33333333, 0x33333333, 0x33333333,
        0x33333333, 0x33333333, 0x33333333, 0x33333333,
        0x33333333, 0x33333333, 0x33333333, 0x33333333,
        0x33333333, 0x33333333, 0x33333333, 0x33333333,
        0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff,
        0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff,
        0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff,
        0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff,
        0x55555555, 0x55555555, 0x55555555, 0x55555555,
        0x55555555, 0x55555555, 0x55555555, 0x55555555,
        0x55555555, 0x55555555, 0x55555555, 0x55555555,
        0x55555555, 0x55555555, 0x55555555, 0x55555555
};

/* S-Box table */
static const DECLARE_ALIGNED(uint16_t S_box_flipped[8 * 64], 64) = {
        /* SBOX0 */
        0x07, 0x02, 0x0c, 0x0f, 0x04, 0x0b, 0x0a, 0x0c,
        0x0b, 0x07, 0x06, 0x09, 0x0d, 0x04, 0x00, 0x0a, 
        0x02, 0x08, 0x05, 0x03, 0x0f, 0x06, 0x09, 0x05,
        0x08, 0x01, 0x03, 0x0e, 0x01, 0x0d, 0x0e, 0x00, 
        0x00, 0x0f, 0x05, 0x0a, 0x07, 0x02, 0x09, 0x05,
        0x0e, 0x01, 0x03, 0x0c, 0x0b, 0x08, 0x0c, 0x06, 
        0x0f, 0x03, 0x06, 0x0d, 0x04, 0x09, 0x0a, 0x00,
        0x02, 0x04, 0x0d, 0x07, 0x08, 0x0e, 0x01, 0x0b, 
        /* SBOX1 */
        0x0f, 0x00, 0x09, 0x0a, 0x06, 0x05, 0x03, 0x09,
        0x01, 0x0e, 0x04, 0x03, 0x0c, 0x0b, 0x0a, 0x04, 
        0x08, 0x07, 0x0e, 0x01, 0x0d, 0x02, 0x00, 0x0c,
        0x07, 0x0d, 0x0b, 0x06, 0x02, 0x08, 0x05, 0x0f, 
        0x0c, 0x0b, 0x03, 0x0d, 0x0f, 0x0c, 0x06, 0x00,
        0x02, 0x05, 0x08, 0x0e, 0x01, 0x02, 0x0d, 0x07, 
        0x0b, 0x01, 0x00, 0x06, 0x04, 0x0f, 0x09, 0x0a,
        0x0e, 0x08, 0x05, 0x03, 0x07, 0x04, 0x0a, 0x09, 
        /* SBOX2 */
        0x05, 0x0b, 0x08, 0x0d, 0x06, 0x01, 0x0d, 0x0a,
        0x09, 0x02, 0x03, 0x04, 0x0f, 0x0c, 0x04, 0x07, 
        0x00, 0x06, 0x0b, 0x08, 0x0c, 0x0f, 0x02, 0x05,
        0x07, 0x09, 0x0e, 0x03, 0x0a, 0x00, 0x01, 0x0e, 
        0x0b, 0x08, 0x04, 0x02, 0x0c, 0x06, 0x03, 0x0d,
        0x00, 0x0b, 0x0a, 0x07, 0x06, 0x01, 0x0f, 0x04, 
        0x0e, 0x05, 0x01, 0x0f, 0x02, 0x09, 0x0d, 0x0a,
        0x09, 0x00, 0x07, 0x0c, 0x05, 0x0e, 0x08, 0x03, 
        /* SBOX3 */
        0x0e, 0x05, 0x08, 0x0f, 0x00, 0x03, 0x0d, 0x0a,
        0x07, 0x09, 0x01, 0x0c, 0x09, 0x0e, 0x02, 0x01, 
        0x0b, 0x06, 0x04, 0x08, 0x06, 0x0d, 0x03, 0x04,
        0x0c, 0x00, 0x0a, 0x07, 0x05, 0x0b, 0x0f, 0x02, 
        0x0b, 0x0c, 0x02, 0x09, 0x06, 0x05, 0x08, 0x03,
        0x0d, 0x00, 0x04, 0x0a, 0x00, 0x0b, 0x07, 0x04, 
        0x01, 0x0f, 0x0e, 0x02, 0x0f, 0x08, 0x05, 0x0e,
        0x0a, 0x06, 0x03, 0x0d, 0x0c, 0x01, 0x09, 0x07, 
        /* SBOX4 */
        0x04, 0x02, 0x01, 0x0f, 0x0e, 0x05, 0x0b, 0x06,
        0x02, 0x08, 0x0c, 0x03, 0x0d, 0x0e, 0x07, 0x00, 
        0x03, 0x04, 0x0a, 0x09, 0x05, 0x0b, 0x00, 0x0c,
        0x08, 0x0d, 0x0f, 0x0a, 0x06, 0x01, 0x09, 0x07, 
        0x07, 0x0d, 0x0a, 0x06, 0x02, 0x08, 0x0c, 0x05,
        0x04, 0x03, 0x0f, 0x00, 0x0b, 0x04, 0x01, 0x0a, 
        0x0d, 0x01, 0x00, 0x0f, 0x0e, 0x07, 0x09, 0x02,
        0x03, 0x0e, 0x05, 0x09, 0x08, 0x0b, 0x06, 0x0c, 
        /* SBOX5 */
        0x03, 0x09, 0x00, 0x0e, 0x09, 0x04, 0x07, 0x08,
        0x05, 0x0f, 0x0c, 0x02, 0x06, 0x03, 0x0a, 0x0d, 
        0x08, 0x07, 0x0b, 0x00, 0x04, 0x01, 0x0e, 0x0b,
        0x0f, 0x0a, 0x02, 0x05, 0x01, 0x0c, 0x0d, 0x06, 
        0x05, 0x02, 0x06, 0x0d, 0x0e, 0x09, 0x00, 0x06,
        0x02, 0x04, 0x0b, 0x08, 0x09, 0x0f, 0x0c, 0x01, 
        0x0f, 0x0c, 0x08, 0x07, 0x03, 0x0a, 0x0d, 0x00,
        0x04, 0x03, 0x07, 0x0e, 0x0a, 0x05, 0x01, 0x0b, 
        /* SBOX6 */
        0x02, 0x08, 0x0c, 0x05, 0x0f, 0x03, 0x0a, 0x00,
        0x04, 0x0d, 0x09, 0x06, 0x01, 0x0e, 0x06, 0x09, 
        0x0d, 0x02, 0x03, 0x0f, 0x00, 0x0c, 0x05, 0x0a,
        0x07, 0x0b, 0x0e, 0x01, 0x0b, 0x07, 0x08, 0x04, 
        0x0b, 0x06, 0x07, 0x09, 0x02, 0x08, 0x04, 0x07,
        0x0d, 0x0b, 0x0a, 0x00, 0x08, 0x05, 0x01, 0x0c, 
        0x00, 0x0d, 0x0c, 0x0a, 0x09, 0x02, 0x0f, 0x04,
        0x0e, 0x01, 0x03, 0x0f, 0x05, 0x0e, 0x06, 0x03, 
        /* SBOX7 */
        0x0b, 0x0e, 0x05, 0x00, 0x06, 0x09, 0x0a, 0x0f,
        0x01, 0x02, 0x0c, 0x05, 0x0d, 0x07, 0x03, 0x0a, 
        0x04, 0x0d, 0x09, 0x06, 0x0f, 0x03, 0x00, 0x0c,
        0x02, 0x08, 0x07, 0x0b, 0x08, 0x04, 0x0e, 0x01, 
        0x08, 0x04, 0x03, 0x0f, 0x05, 0x02, 0x00, 0x0c,
        0x0b, 0x07, 0x06, 0x09, 0x0e, 0x01, 0x09, 0x06, 
        0x0f, 0x08, 0x0a, 0x03, 0x0c, 0x05, 0x07, 0x0a,
        0x01, 0x0e, 0x0d, 0x00, 0x02, 0x0b, 0x04, 0x0d
};

/* Used in DOCSIS DES partial block scheduling 16 x 32bit of value 1 */
static const DECLARE_ALIGNED(uint32_t vec_ones_32b[AVX512_NUM_DES_LANES], 64) = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

__forceinline
void
permute_operation(__m512i *pa, __m512i *pb,
                  const unsigned n_shift, const __m512i mask)
{
        __m512i t = _mm512_xor_si512(*pb, _mm512_srli_epi32(*pa, n_shift));

        t = _mm512_and_si512(t, mask);
        *pb = _mm512_xor_si512(*pb, t);
        *pa = _mm512_xor_si512(*pa, _mm512_slli_epi32(t, n_shift));
}

/**
 * @brief Initial permutation
 *
 * @param pl pointer to vector of L words
 * @param pr pointer to vector of R words
 */
__forceinline
void ip_z(__m512i *pl, __m512i *pr)
{
        const __m512i *c = (const __m512i *)init_perm_consts;

        permute_operation(pr, pl, 4, c[0]);
        permute_operation(pl, pr, 16, c[1]);
        permute_operation(pr, pl, 2, c[2]);
        permute_operation(pl, pr, 8, c[3]);
        permute_operation(pr, pl, 1, c[4]);
}

/**
 * @brief Final permutation
 *
 * @param pl pointer to vector of L words
 * @param pr pointer to vector of R words
 */
__forceinline
void fp_z(__m512i *pl, __m512i *pr)
{
        const __m512i *c = (const __m512i *)init_perm_consts;

        permute_operation(pl, pr, 1, c[4]);
        permute_operation(pr, pl, 8, c[3]);
        permute_operation(pl, pr, 2, c[2]);
        permute_operation(pr, pl, 16, c[1]);
        permute_operation(pl, pr, 4, c[0]);
}

/**
 * @brief P permutation function
 *
 * @param in vector of 16 x 32bits from S phase
 *
 * @return Vector of permuted 32bits words
 */
__forceinline
__m512i
p_phase(const __m512i in)
{
        __m512i out, t0, t1, x4, x5, x6, x7;
        const __m512i *p_con = (const __m512i *)p_mask_values;

        t0 = _mm512_ror_epi32(in, 3);
        t1 = _mm512_ror_epi32(in, 5);
        x4 = _mm512_and_si512(t0, p_con[0]);
        x5 = _mm512_and_si512(t1, p_con[1]);
        x6 = _mm512_or_si512(x4, x5);

        t0 = _mm512_ror_epi32(in,24);
        t1 = _mm512_ror_epi32(in,26);
        x4 = _mm512_and_si512(t0, p_con[2]);
        x5 = _mm512_and_si512(t1, p_con[3]);
        x7 = _mm512_or_si512(x4, x5);
        out = _mm512_or_si512(x6, x7);

        t0 = _mm512_ror_epi32(in,15);
        t1 = _mm512_ror_epi32(in,17);
        x4 = _mm512_and_si512(t0, p_con[4]);
        x5 = _mm512_and_si512(t1, p_con[5]);
        x6 = _mm512_or_si512(x4, x5);

        t0 = _mm512_ror_epi32(in,6);
        t1 = _mm512_ror_epi32(in,21);
        x4 = _mm512_and_si512(t0, p_con[6]);
        x5 = _mm512_and_si512(t1, p_con[7]);
        x7 = _mm512_or_si512(x4, x5);
        x6 = _mm512_or_si512(x6, x7);
        out = _mm512_or_si512(x6, out);

        t0 = _mm512_ror_epi32(in,12);
        t1 = _mm512_ror_epi32(in,14);
        x4 = _mm512_and_si512(t0, p_con[8]);
        x5 = _mm512_and_si512(t1, p_con[9]);
        x6 = _mm512_or_si512(x4, x5);

        t0 = _mm512_ror_epi32(in,4);
        t1 = _mm512_ror_epi32(in,11);
        x4 = _mm512_and_si512(t0, p_con[10]);
        x5 = _mm512_and_si512(t1, p_con[11]);
        x7 = _mm512_or_si512(x4, x5);
        x6 = _mm512_or_si512(x6, x7);
        out = _mm512_or_si512(x6, out);

        t0 = _mm512_ror_epi32(in,16);
        t1 = _mm512_ror_epi32(in,22);
        x4 = _mm512_and_si512(t0, p_con[12]);
        x5 = _mm512_and_si512(t1, p_con[13]);
        x6 = _mm512_or_si512(x4, x5);

        t0 = _mm512_ror_epi32(in,19);
        t1 = _mm512_ror_epi32(in,10);
        x4 = _mm512_and_si512(t0, p_con[14]);
        x5 = _mm512_and_si512(t1, p_con[15]);
        x7 = _mm512_or_si512(x4, x5);
        x6 = _mm512_or_si512(x6, x7);
        out = _mm512_or_si512(x6, out);

        t0 = _mm512_ror_epi32(in,9);
        t1 = _mm512_ror_epi32(in,13);
        x4 = _mm512_and_si512(t0, p_con[16]);
        x5 = _mm512_and_si512(t1, p_con[17]);
        x6 = _mm512_or_si512(x4, x5);
        out = _mm512_or_si512(x6, out);

        t0 = _mm512_ror_epi32(in,25);
        x4 = _mm512_and_si512(t0, p_con[18]);
        out = _mm512_or_si512(out, x4);

        return out;
}

/**
 * @brief E function
 *
 * Expands 16x32-bit words into 16x48-bit words
 * plus XOR's result with the key schedule.
 * The output is adjusted to be friendly as S phase input.
 *
 * @param in vector of 16 x 32bit words
 * @param out0a place to store output vector
 * @param out0b place to store output vector
 * @param out1a place to store output vector
 * @param out1b place to store output vector
 * @param k0 vector of key schedule words
 * @param k1 vector of key schedule words
 *
 */
__forceinline
void
e_phase(const __m512i in,
        __m512i *out0a, __m512i *out0b, __m512i *out1a, __m512i *out1b,
        const __m512i k0, const __m512i k1)
{
        static const DECLARE_ALIGNED(uint32_t and_eu[16], 64) = {
                UINT32_C(0x3f003f00), UINT32_C(0x3f003f00),
                UINT32_C(0x3f003f00), UINT32_C(0x3f003f00),
                UINT32_C(0x3f003f00), UINT32_C(0x3f003f00),
                UINT32_C(0x3f003f00), UINT32_C(0x3f003f00),
                UINT32_C(0x3f003f00), UINT32_C(0x3f003f00),
                UINT32_C(0x3f003f00), UINT32_C(0x3f003f00),
                UINT32_C(0x3f003f00), UINT32_C(0x3f003f00),
                UINT32_C(0x3f003f00), UINT32_C(0x3f003f00)
        };
        static const DECLARE_ALIGNED(uint32_t and_ed[16], 64) = {
                UINT32_C(0x003f003f), UINT32_C(0x003f003f),
                UINT32_C(0x003f003f), UINT32_C(0x003f003f),
                UINT32_C(0x003f003f), UINT32_C(0x003f003f),
                UINT32_C(0x003f003f), UINT32_C(0x003f003f),
                UINT32_C(0x003f003f), UINT32_C(0x003f003f),
                UINT32_C(0x003f003f), UINT32_C(0x003f003f),
                UINT32_C(0x003f003f), UINT32_C(0x003f003f),
                UINT32_C(0x003f003f), UINT32_C(0x003f003f),
        };
        static const DECLARE_ALIGNED(uint64_t idx_e[8], 64) = {
                UINT64_C(0x0d0c090805040100), UINT64_C(0x0f0e0b0a07060302),
                UINT64_C(0x1d1c191815141110), UINT64_C(0x1f1e1b1a17161312),
                UINT64_C(0x2d2c292825242120), UINT64_C(0x2f2e2b2a27262322),
                UINT64_C(0x3d3c393835343130), UINT64_C(0x3f3e3b3a37363332)
        };
        const __m512i *p_and_eu = (const __m512i *)and_eu;
        const __m512i *p_and_ed = (const __m512i *)and_ed;
        const __m512i *p_idx_e = (const __m512i *)idx_e;
        __m512i t0, t1;

        t0 = _mm512_ror_epi32(in, 31);
        t1 = _mm512_ror_epi32(in, 3);
        t0 = _mm512_shuffle_epi8(t0, *p_idx_e);
        t1 = _mm512_shuffle_epi8(t1, *p_idx_e);
        *out0a = _mm512_unpacklo_epi8(t0, t1);
        *out1a = _mm512_unpackhi_epi8(t0, t1);
        *out0a = _mm512_xor_si512(*out0a, k0);
        *out1a = _mm512_xor_si512(*out1a, k1);
        *out0b = _mm512_srli_epi16(_mm512_and_si512(*out0a, *p_and_eu), 8);
        *out0a = _mm512_and_si512(*out0a, *p_and_ed);
        *out1b = _mm512_srli_epi16(_mm512_and_si512(*out1a, *p_and_eu), 8);
        *out1a = _mm512_and_si512(*out1a, *p_and_ed);
}

/**
 * @brief S-box function
 *
 * @param out0a output vector from E function
 * @param out0b output vector from E function
 * @param out1a output vector from E function
 * @param out1b output vector from E function
 *
 * @return Output of S-box function, 16 x 32 bits
 */
__forceinline
__m512i
s_phase(const __m512i in0a, const __m512i in0b,
        const __m512i in1a, const __m512i in1b)
{
        static const DECLARE_ALIGNED(uint64_t reg_values16bit_7[8], 64) = {
                UINT64_C(0x001f001f001f001f), UINT64_C(0x001f001f001f001f),
                UINT64_C(0x001f001f001f001f), UINT64_C(0x001f001f001f001f),
                UINT64_C(0x001f001f001f001f), UINT64_C(0x001f001f001f001f),
                UINT64_C(0x001f001f001f001f), UINT64_C(0x001f001f001f001f)
        };
        static const DECLARE_ALIGNED(uint64_t shuffle_reg[8], 64) = {
                UINT64_C(0x0705060403010200), UINT64_C(0x0f0d0e0c0b090a08),
                UINT64_C(0x1715161413111210), UINT64_C(0x1f1d1e1c1b191a18),
                UINT64_C(0x2725262423212220), UINT64_C(0x2f2d2e2c2b292a28),
                UINT64_C(0x3735363433313230), UINT64_C(0x3f3d3e3c3b393a38)
        };
        const __m512i *p_reg_v16bit_7 = (const __m512i *)reg_values16bit_7;
        const __m512i *p_shuffle_reg = (const __m512i *)shuffle_reg;
        const __mmask32 perm_k0 = 0x55555555;
        const __mmask32 perm_k1 = 0xaaaaaaaa;
        __m512i t0, t1, t2, t3, x0, x1, out;
        __mmask32 taken_a;
        const __m512i *p_sbox = (const __m512i *)S_box_flipped;

        t0 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k0, in0a, p_sbox[0]);
        t1 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k0, in0a, p_sbox[1]);
        t2 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k1, in0a, p_sbox[4]);
        t3 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k1, in0a, p_sbox[5]);
        t0 = _mm512_xor_si512(t2, t0);
        t1 = _mm512_xor_si512(t3, t1);
        taken_a = _mm512_cmp_epu16_mask(in0a, *p_reg_v16bit_7, 0x2);
        x0 = _mm512_mask_blend_epi16(taken_a, t1, t0);

        t0 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k0, in0b, p_sbox[2]);
        t1 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k0, in0b, p_sbox[3]);
        t2 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k1, in0b, p_sbox[6]);
        t3 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k1, in0b, p_sbox[7]);
        t0 = _mm512_xor_si512(t2, t0);
        t1 = _mm512_xor_si512(t3, t1);
        taken_a = _mm512_cmp_epu16_mask(in0b, *p_reg_v16bit_7, 0x2);
        x1 = _mm512_slli_epi16(_mm512_mask_blend_epi16(taken_a, t1, t0),4);
        out = _mm512_xor_si512(x0,x1);

        t0 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k0, in1a, p_sbox[8]);
        t1 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k0, in1a, p_sbox[9]);
        t2 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k1, in1a, p_sbox[12]);
        t3 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k1, in1a, p_sbox[13]);
        t0 = _mm512_xor_si512(t2, t0);
        t1 = _mm512_xor_si512(t3, t1);
        taken_a = _mm512_cmp_epu16_mask(in1a, *p_reg_v16bit_7, 0x2);
        x0 = _mm512_mask_blend_epi16(taken_a, t1, t0);

        t0 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k0, in1b, p_sbox[10]);
        t1 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k0, in1b, p_sbox[11]);
        t2 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k1, in1b, p_sbox[14]);
        t3 = _mm512_mask_permutexvar_epi16(_mm512_setzero_si512(),
                                           perm_k1, in1b, p_sbox[15]);
        t0 = _mm512_xor_si512(t2, t0);
        t1 = _mm512_xor_si512(t3, t1);
        taken_a = _mm512_cmp_epu16_mask(in1b, *p_reg_v16bit_7, 0x2);
        x1 = _mm512_slli_epi16(_mm512_mask_blend_epi16 (taken_a, t1, t0),4);

        x0 = _mm512_xor_si512(x0, x1);
        x0 = _mm512_slli_epi16(x0, 8);
        out = _mm512_xor_si512(x0, out);
        out = _mm512_shuffle_epi8(out, *p_shuffle_reg);

        return out;
}

/**
 * @brief DES encryption/decryption function
 *
 * @param p_r0 pointer to vecotr of R words (in/out)
 * @param p_l0 pointer to vecotr of L words (in/out)
 * @param ks pointer to the transposed key schedules
 * @param do_decrypt if not zero indicates decryption is to be done,
 *        otherwise encryption is performed.
 */
__forceinline
void
des_enc_dec(__m512i *p_r0, __m512i *p_l0,
            const __m512i *ks, const int do_decrypt)
{
        int rounds;

        ip_z(p_r0, p_l0);

        if (!do_decrypt) {
                /* encrypt */
                for (rounds = 0; rounds < 8; rounds++) {
                        __m512i out1, out2, x11, x12, x13, x14;

                        e_phase(*p_r0, &x11, &x12, &x13, &x14,
                                ks[rounds*4], ks[rounds*4 + 1]);
                        out1 = s_phase(x11, x12, x13, x14);
                        out2 = p_phase(out1);
                        *p_l0 = _mm512_xor_si512(*p_l0, out2);

                        e_phase(*p_l0, &x11, &x12, &x13, &x14,
                                ks[rounds*4 + 2], ks[rounds*4 + 3]);
                        out1 = s_phase(x11, x12, x13, x14);
                        out2 = p_phase(out1);
                        *p_r0 = _mm512_xor_si512(*p_r0, out2);
                }
        } else {
                /* decrypt */
		for (rounds = 7; rounds >= 0; rounds--) {
                        __m512i out1, out2, x11, x12, x13, x14;

			e_phase(*p_r0, &x11, &x12, &x13, &x14,
                                ks[rounds*4 + 2], ks[rounds*4 + 3]);
			out1 = s_phase(x11, x12, x13, x14);
			out2 = p_phase(out1);
			*p_l0 = _mm512_xor_si512(*p_l0, out2);

			e_phase(*p_l0, &x11, &x12, &x13, &x14,
                                ks[rounds*4], ks[rounds*4 + 1]);
			out1 = s_phase(x11, x12, x13, x14);
			out2 = p_phase(out1);
			*p_r0 = _mm512_xor_si512(*p_r0, out2);
		}
        }

        fp_z(p_r0, p_l0);
}

/**
 * @brief Transposes 16 x 64 bytes of input data for DES usage.
 *
 * The transposition happens as follows (32 bits words):
 * Input
 * LANE0 (in00): W00 W01 W02 W03 W04 W05 W06 W07 W08 W09 W0A W0B W0C W0D W0E W0F
 * LANE1 (in01): W10 W11 W12 W13 W14 W15 W16 W17 W18 W19 W1A W1B W1C W1D W1E W1F
 * LANE2 (in02): W20 W21 ...
 * ...
 * LANEF (in15): WF0 WF1 WF2 WF3 WF4 WF5 WF6 WF7 WF8 WF9 WFA WFB WFC WFD WFE WFF
 *
 * Output
 * R0 (pr0): W00 W10 W20 W30 W40 W50 W60 W70 W80 W90 WA0 WB0 WC0 WD0 WE0 WF0
 * L0 (pl0): W01 W11 W21 W31 W41 W51 W61 W71 W81 W91 WA1 WB1 WC1 WD1 WE1 WF1
 * R1 (pr1): W02 W12 W22 ...
 * ...
 * L7 (pl7): W0F W1F W2F W3F W4F W5F W6F W7F W8F W9F WAF WBF WCF WDF WEF WFF
 *
 * @param in00 input 64 bytes from lane 0
 * @param in01 input 64 bytes from lane 1
 * @param in02 input 64 bytes from lane 2
 * @param in03 input 64 bytes from lane 3
 * @param in04 input 64 bytes from lane 4
 * @param in05 input 64 bytes from lane 5
 * @param in06 input 64 bytes from lane 6
 * @param in07 input 64 bytes from lane 7
 * @param in08 input 64 bytes from lane 8
 * @param in09 input 64 bytes from lane 9
 * @param in10 input 64 bytes from lane 10
 * @param in11 input 64 bytes from lane 11
 * @param in12 input 64 bytes from lane 12
 * @param in13 input 64 bytes from lane 13
 * @param in14 input 64 bytes from lane 14
 * @param in15 input 64 bytes from lane 15
 * @param pr0 place to store transposed vector R0
 * @param pl0 place to store transposed vector L0
 * @param pr1 place to store transposed vector R1
 * @param pl1 place to store transposed vector L1
 * @param pr2 place to store transposed vector R2
 * @param pl2 place to store transposed vector L2
 * @param pr3 place to store transposed vector R3
 * @param pl3 place to store transposed vector L3
 * @param pr4 place to store transposed vector R4
 * @param pl4 place to store transposed vector L4
 * @param pr5 place to store transposed vector R5
 * @param pl5 place to store transposed vector L5
 * @param pr6 place to store transposed vector R6
 * @param pl6 place to store transposed vector L6
 * @param pr7 place to store transposed vector R7
 * @param pl7 place to store transposed vector L7
 */
__forceinline
void
transpose_in(__m512i in00, __m512i in01, __m512i in02, __m512i in03,
             __m512i in04, __m512i in05, __m512i in06, __m512i in07,
             __m512i in08, __m512i in09, __m512i in10, __m512i in11,
             __m512i in12, __m512i in13, __m512i in14, __m512i in15,
             __m512i *pr0, __m512i *pl0, __m512i *pr1, __m512i *pl1,
             __m512i *pr2, __m512i *pl2, __m512i *pr3, __m512i *pl3,
             __m512i *pr4, __m512i *pl4, __m512i *pr5, __m512i *pl5,
             __m512i *pr6, __m512i *pl6, __m512i *pr7, __m512i *pl7)
{
	__m512i k0, k1, k2, k3, k4, k5;
        __m512i t0, t1, t2, t3;

        k0 = _mm512_unpacklo_epi32(in00, in01);
        k1 = _mm512_unpackhi_epi32(in00, in01);
        t0 = _mm512_unpacklo_epi32(in02, in03);
        t1 = _mm512_unpackhi_epi32(in02, in03);
        in00 = _mm512_unpacklo_epi32(in04, in05);
        in01 = _mm512_unpackhi_epi32(in04, in05);
        in02 = _mm512_unpacklo_epi32(in06, in07);
        in03 = _mm512_unpackhi_epi32(in06, in07);

        k2 = _mm512_unpacklo_epi64(k0, t0);
        k3 = _mm512_unpacklo_epi64(k1, t1);
        t2 = _mm512_unpackhi_epi64(k0, t0);
        t3 = _mm512_unpackhi_epi64(k1, t1);
        k0 = _mm512_unpacklo_epi64(in00, in02);
        k1 = _mm512_unpackhi_epi64(in00, in02);
        t0 = _mm512_unpacklo_epi64(in01, in03);
        t1 = _mm512_unpackhi_epi64(in01, in03);

        k4 = _mm512_unpacklo_epi32(in08, in09);
        k5 = _mm512_unpackhi_epi32(in08, in09);
        in04 = _mm512_unpacklo_epi32(in10, in11);
        in05 = _mm512_unpackhi_epi32(in10, in11);
        in06 = _mm512_unpacklo_epi32(in12, in13);
        in07 = _mm512_unpackhi_epi32(in12, in13);
        in10 = _mm512_unpacklo_epi32(in14, in15);
        in11 = _mm512_unpackhi_epi32(in14, in15);

        in12 = _mm512_unpacklo_epi64(k4, in04); 
        in13 = _mm512_unpackhi_epi64(k4, in04);
        in14 = _mm512_unpacklo_epi64(k5, in05); 
        in15 = _mm512_unpackhi_epi64(k5, in05);
        in00 = _mm512_unpacklo_epi64(in06, in10);
        in01 = _mm512_unpackhi_epi64(in06, in10);
        in02 = _mm512_unpacklo_epi64(in07, in11);
        in03 = _mm512_unpackhi_epi64(in07, in11);

        in08 = _mm512_shuffle_i64x2(k2, k0, 0x44);
        in09 = _mm512_shuffle_i64x2(k2, k0, 0xee);
        k4 = _mm512_shuffle_i64x2(in12, in00, 0x44);
        in04 = _mm512_shuffle_i64x2(in12, in00, 0xee);
        *pr0 = _mm512_shuffle_i64x2(in08, k4, 0x88);
        *pr2 = _mm512_shuffle_i64x2(in08, k4, 0xdd);
        *pr4 = _mm512_shuffle_i64x2(in09, in04, 0x88);
        *pr6 = _mm512_shuffle_i64x2(in09, in04, 0xdd);

        in00 = _mm512_shuffle_i64x2(t2, k1, 0x44);
        in12 = _mm512_shuffle_i64x2(t2, k1, 0xee);
        k0 = _mm512_shuffle_i64x2(in13, in01, 0x44);
        in04 = _mm512_shuffle_i64x2(in13, in01, 0xee); 
        *pl0 = _mm512_shuffle_i64x2(in00, k0, 0x88);  
        *pl2 = _mm512_shuffle_i64x2(in00, k0, 0xdd);  
        *pl4 = _mm512_shuffle_i64x2(in12, in04, 0x88); 
        *pl6 = _mm512_shuffle_i64x2(in12, in04, 0xdd); 		

        in08 = _mm512_shuffle_i64x2(k3, t0, 0x44);
        in09 = _mm512_shuffle_i64x2(k3, t0, 0xee);
        in00 = _mm512_shuffle_i64x2(in14, in02, 0x44);
        in04 = _mm512_shuffle_i64x2(in14, in02, 0xee);
        *pr1 = _mm512_shuffle_i64x2(in08, in00, 0x88);
        *pr3 = _mm512_shuffle_i64x2(in08, in00, 0xdd);
        *pr5 = _mm512_shuffle_i64x2(in09, in04, 0x88);
        *pr7 = _mm512_shuffle_i64x2(in09, in04, 0xdd);

        in08 = _mm512_shuffle_i64x2(t3, t1, 0x44); 
        in09 = _mm512_shuffle_i64x2(t3, t1, 0xee);
        in00 = _mm512_shuffle_i64x2(in15, in03, 0x44);
        in04 = _mm512_shuffle_i64x2(in15, in03, 0xee);
        *pl1 = _mm512_shuffle_i64x2(in08, in00, 0x88); 
        *pl3 = _mm512_shuffle_i64x2(in08, in00, 0xdd); 
        *pl5 = _mm512_shuffle_i64x2(in09, in04, 0x88); 
        *pl7 = _mm512_shuffle_i64x2(in09, in04, 0xdd);
}

/**
 * @brief Symmetric function to transpose in operation
 *
 * The transposition happens as follows (32 bits words):
 * Input
 * R0 (pr0): W00 W10 W20 W30 W40 W50 W60 W70 W80 W90 WA0 WB0 WC0 WD0 WE0 WF0
 * L0 (pl0): W01 W11 W21 W31 W41 W51 W61 W71 W81 W91 WA1 WB1 WC1 WD1 WE1 WF1
 * R1 (pr1): W02 W12 W22 ...
 * ...
 * L7 (pl7): W0F W1F W2F W3F W4F W5F W6F W7F W8F W9F WAF WBF WCF WDF WEF WFF
 *
 * Output
 * LANE0 (in00): W00 W01 W02 W03 W04 W05 W06 W07 W08 W09 W0A W0B W0C W0D W0E W0F
 * LANE1 (in01): W10 W11 W12 W13 W14 W15 W16 W17 W18 W19 W1A W1B W1C W1D W1E W1F
 * LANE2 (in02): W20 W21 ...
 * ...
 * LANEF (in15): WF0 WF1 WF2 WF3 WF4 WF5 WF6 WF7 WF8 WF9 WFA WFB WFC WFD WFE WFF
 *
 * @param pr0 vector R0 and place to store lane 0
 * @param pl0 vector L0 and place to store lane 1
 * @param pr1 vector R1 and place to store lane 2
 * @param pl1 vector L1 and place to store lane 3
 * @param pr2 vector R2 and place to store lane 4
 * @param pl2 vector L2 and place to store lane 5
 * @param pr3 vector R3 and place to store lane 6
 * @param pl3 vector L3 and place to store lane 7
 * @param pr4 vector R4 and place to store lane 8
 * @param pl4 vector L4 and place to store lane 9
 * @param pr5 vector R5 and place to store lane 10
 * @param pl5 vector L5 and place to store lane 11
 * @param pr6 vector R6 and place to store lane 12
 * @param pl6 vector L6 and place to store lane 13
 * @param pr7 vector R7 and place to store lane 14
 * @param pl7 vector L7 and place to store lane 15
 */
__forceinline
void
transpose_out(__m512i *pr0, __m512i *pl0, __m512i *pr1, __m512i *pl1,
              __m512i *pr2, __m512i *pl2, __m512i *pr3, __m512i *pl3,
              __m512i *pr4, __m512i *pl4, __m512i *pr5, __m512i *pl5,
              __m512i *pr6, __m512i *pl6, __m512i *pr7, __m512i *pl7)
{
	__m512i x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
        __m512i k0, k1, t0, t1;

        x0 = _mm512_unpacklo_epi32(*pl0, *pr0);
        x1 = _mm512_unpackhi_epi32(*pl0, *pr0);
        x2 = _mm512_unpacklo_epi32(*pl1, *pr1);
        x3 = _mm512_unpackhi_epi32(*pl1, *pr1);
        x4 = _mm512_unpacklo_epi32(*pl2, *pr2);
        x5 = _mm512_unpackhi_epi32(*pl2, *pr2);
        x6 = _mm512_unpacklo_epi32(*pl3, *pr3);
        x7 = _mm512_unpackhi_epi32(*pl3, *pr3);

        k0 = _mm512_unpacklo_epi64(x0, x2); 
        k1 = _mm512_unpacklo_epi64(x1, x3);
        t0 = _mm512_unpackhi_epi64(x0, x2);
        t1 = _mm512_unpackhi_epi64(x1, x3);
        x0 = _mm512_unpacklo_epi64(x4, x6);
        x1 = _mm512_unpackhi_epi64(x4, x6);
        x2 = _mm512_unpacklo_epi64(x5, x7);
        x3 = _mm512_unpackhi_epi64(x5, x7);

        x8 = _mm512_unpacklo_epi32(*pl4, *pr4);
        x9 = _mm512_unpackhi_epi32(*pl4, *pr4);
        x10 =_mm512_unpacklo_epi32(*pl5, *pr5);
        x11 =_mm512_unpackhi_epi32(*pl5, *pr5);
        x12 =_mm512_unpacklo_epi32(*pl6, *pr6);
        x13 =_mm512_unpackhi_epi32(*pl6, *pr6);
        x14 =_mm512_unpacklo_epi32(*pl7, *pr7);
        x15 =_mm512_unpackhi_epi32(*pl7, *pr7);
		
        x4 =_mm512_unpacklo_epi64(x8, x10); 
        x5 =_mm512_unpackhi_epi64(x8, x10);
        x6 =_mm512_unpacklo_epi64(x9, x11); 
        x7 =_mm512_unpackhi_epi64(x9, x11);
        x8 =_mm512_unpacklo_epi64(x12, x14);
        x9 =_mm512_unpackhi_epi64(x12, x14);
        x10 =_mm512_unpacklo_epi64(x13, x15);
        x11 =_mm512_unpackhi_epi64(x13, x15);
		
        x12 = _mm512_shuffle_i64x2(k0, x0, 0x44);
        x13 = _mm512_shuffle_i64x2(k0, x0, 0xee);
        x14 = _mm512_shuffle_i64x2(x4, x8, 0x44);
        x15 = _mm512_shuffle_i64x2(x4, x8, 0xee);
        *pr0 = _mm512_shuffle_i64x2(x12, x14, 0x88);
        *pr2 = _mm512_shuffle_i64x2(x12, x14, 0xdd);
        *pr4 = _mm512_shuffle_i64x2(x13, x15, 0x88);
        *pr6 = _mm512_shuffle_i64x2(x13, x15, 0xdd);
		
        x0 = _mm512_shuffle_i64x2(t0, x1, 0x44);
        x12 = _mm512_shuffle_i64x2(t0, x1, 0xee);
        k0 = _mm512_shuffle_i64x2(x5, x9, 0x44);
        x4 = _mm512_shuffle_i64x2(x5, x9, 0xee); 
        *pl0 = _mm512_shuffle_i64x2(x0, k0, 0x88);  
        *pl2 = _mm512_shuffle_i64x2(x0, k0, 0xdd);  
        *pl4 = _mm512_shuffle_i64x2(x12, x4, 0x88); 
        *pl6 = _mm512_shuffle_i64x2(x12, x4, 0xdd); 
		
        x8 = _mm512_shuffle_i64x2(k1, x2, 0x44); 
        x9 = _mm512_shuffle_i64x2(k1, x2, 0xee); 
        x0 = _mm512_shuffle_i64x2(x6, x10, 0x44);
        x4 = _mm512_shuffle_i64x2(x6, x10, 0xee);
        *pr1 = _mm512_shuffle_i64x2(x8, x0, 0x88); 
        *pr3 = _mm512_shuffle_i64x2(x8, x0, 0xdd); 
        *pr5 = _mm512_shuffle_i64x2(x9, x4, 0x88); 
        *pr7 = _mm512_shuffle_i64x2(x9, x4, 0xdd); 
		
        x8 = _mm512_shuffle_i64x2(t1, x3, 0x44); 
        x9 = _mm512_shuffle_i64x2(t1, x3, 0xee); 
        x0 = _mm512_shuffle_i64x2(x7, x11, 0x44);
        x4 = _mm512_shuffle_i64x2(x7, x11, 0xee);
        *pl1 = _mm512_shuffle_i64x2(x8, x0, 0x88); 
        *pl3 = _mm512_shuffle_i64x2(x8, x0, 0xdd); 
        *pl5 = _mm512_shuffle_i64x2(x9, x4, 0x88); 
        *pl7 = _mm512_shuffle_i64x2(x9, x4, 0xdd);
}

/**
 * @brief Transposes 16 x 8 bytes of input data for DES usage.
 *
 * The function reads up to 8 bytes from each lane.
 * The transposition happens as follows (32 bits words):
 * Input
 * LANE0 (in[0]): W00 W01 
 * LANE1 (in[1]): W10 W11 
 * LANE2 (in[2]): W20 W21 
 * ...
 * LANEF (in[15]): WF0 WF1
 *
 * Output
 * R0 (pr0): W00 W10 W20 W30 W40 W50 W60 W70 W80 W90 WA0 WB0 WC0 WD0 WE0 WF0
 * L0 (pl0): W01 W11 W21 W31 W41 W51 W61 W71 W81 W91 WA1 WB1 WC1 WD1 WE1 WF1
 *
 * @param pr0 place to store transposed vector R0
 * @param pl0 place to store transposed vector L0
 * @param in array of 16 input pointers to read data from
 * @param mask array of 16 masks to be used for masked load
 */
__forceinline
void
transpose_in_one(__m512i *pr0, __m512i *pl0,
                 const uint8_t **in, const uint32_t *mask)
{
	__m512i k0, k1, k2, k4;
        __m512i t0, t2;
        __m512i in00, in01, in02, in03, in04, in05, in06, in07;
        __m512i in08, in09, in10, in11, in12, in13, in14, in15;
        
        in00 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[0], (const void *)in[0]);
        in01 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[1], (const void *)in[1]);
        in02 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[2], (const void *)in[2]);
        in03 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[3], (const void *)in[3]);
        in04 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[4], (const void *)in[4]);
        in05 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[5], (const void *)in[5]);
        in06 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[6], (const void *)in[6]);
        in07 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[7], (const void *)in[7]);
        in08 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[8], (const void *)in[8]);
        in09 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[9], (const void *)in[9]);
        in10 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[10], (const void *)in[10]);
        in11 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[11], (const void *)in[11]);
        in12 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[12], (const void *)in[12]);
        in13 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[13], (const void *)in[13]);
        in14 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[14], (const void *)in[14]);
        in15 = _mm512_mask_loadu_epi8(_mm512_setzero_si512(), (uint64_t) mask[15], (const void *)in[15]);

        k0 = _mm512_unpacklo_epi32(in00, in01);
        k1 = _mm512_unpackhi_epi32(in00, in01);
        t0 = _mm512_unpacklo_epi32(in02, in03);
        in00 = _mm512_unpacklo_epi32(in04, in05);
        in01 = _mm512_unpackhi_epi32(in04, in05);
        in02 = _mm512_unpacklo_epi32(in06, in07);

        k2 = _mm512_unpacklo_epi64(k0, t0);
        t2 = _mm512_unpackhi_epi64(k0, t0);
        k0 = _mm512_unpacklo_epi64(in00, in02);
        k1 = _mm512_unpackhi_epi64(in00, in02);

        k4 = _mm512_unpacklo_epi32(in08, in09);
        in04 = _mm512_unpacklo_epi32(in10, in11);
        in06 = _mm512_unpacklo_epi32(in12, in13);
        in10 = _mm512_unpacklo_epi32(in14, in15);

        in12 = _mm512_unpacklo_epi64(k4, in04); 
        in13 = _mm512_unpackhi_epi64(k4, in04);
        in00 = _mm512_unpacklo_epi64(in06, in10);
        in01 = _mm512_unpackhi_epi64(in06, in10);

        in08 = _mm512_shuffle_i64x2(k2, k0, 0x44);
        k4 = _mm512_shuffle_i64x2(in12, in00, 0x44);
        *pr0 = _mm512_shuffle_i64x2(in08, k4, 0x88);

        in00 = _mm512_shuffle_i64x2(t2, k1, 0x44);
        k0 = _mm512_shuffle_i64x2(in13, in01, 0x44);
        *pl0 = _mm512_shuffle_i64x2(in00, k0, 0x88);  
}

/**
 * @brief Transposes R0 and L0 vectors back onto lanes.
 *
 * The transposition happens as follows (32 bits words):
 * Input
 * R0 (pr0): W00 W10 W20 W30 W40 W50 W60 W70 W80 W90 WA0 WB0 WC0 WD0 WE0 WF0
 * L0 (pl0): W01 W11 W21 W31 W41 W51 W61 W71 W81 W91 WA1 WB1 WC1 WD1 WE1 WF1
 *
 * Output
 * LANE0 (in[0]): W00 W01 
 * LANE1 (in[1]): W10 W11 
 * LANE2 (in[2]): W20 W21 
 * ...
 * LANEF (in[15]): WF0 WF1
 *
 * @param r0 R0 vector
 * @param l0 L0 vector
 * @param out array of 16 output pointers to write data to
 * @param mask array of 16 masks to be used for masked store
 */
__forceinline
void
transpose_out_one(const __m512i r0, const __m512i l0,
                  uint8_t **out, const uint32_t *mask)
{
        __m512i pr0, pr1, pr2, pr3, pr4, pr5, pr6, pr7;
        __m512i pl0, pl1, pl2, pl3, pl4, pl5, pl6, pl7;
	__m512i x0, x1, x8, x9, x12, x13;
        __m512i k0, k1, t0, t1;

        const __m512i zero_reg = _mm512_setzero_si512();
        
        x0 = _mm512_unpacklo_epi32(l0, r0);
        x1 = _mm512_unpackhi_epi32(l0, r0);

        k0 = _mm512_unpacklo_epi64(x0, zero_reg);
        k1 = _mm512_unpacklo_epi64(x1, zero_reg);
        t0 = _mm512_unpackhi_epi64(x0, zero_reg);
        t1 = _mm512_unpackhi_epi64(x1, zero_reg);

        x12 = _mm512_shuffle_i64x2(k0, zero_reg, 0x44);
        x13 = _mm512_shuffle_i64x2(k0, zero_reg, 0xee);
        pr0 = _mm512_shuffle_i64x2(x12, zero_reg, 0x88);
        pr2 = _mm512_shuffle_i64x2(x12, zero_reg, 0xdd);
        pr4 = _mm512_shuffle_i64x2(x13, zero_reg, 0x88);
        pr6 = _mm512_shuffle_i64x2(x13, zero_reg, 0xdd);
		
        x0 = _mm512_shuffle_i64x2(t0, zero_reg, 0x44);
        x12 = _mm512_shuffle_i64x2(t0, zero_reg, 0xee);
        pl0 = _mm512_shuffle_i64x2(x0, zero_reg, 0x88);  
        pl2 = _mm512_shuffle_i64x2(x0, zero_reg, 0xdd);  
        pl4 = _mm512_shuffle_i64x2(x12, zero_reg, 0x88); 
        pl6 = _mm512_shuffle_i64x2(x12, zero_reg, 0xdd); 
		
        x8 = _mm512_shuffle_i64x2(k1, zero_reg, 0x44); 
        x9 = _mm512_shuffle_i64x2(k1, zero_reg, 0xee); 
        pr1 = _mm512_shuffle_i64x2(x8, zero_reg, 0x88); 
        pr3 = _mm512_shuffle_i64x2(x8, zero_reg, 0xdd); 
        pr5 = _mm512_shuffle_i64x2(x9, zero_reg, 0x88); 
        pr7 = _mm512_shuffle_i64x2(x9, zero_reg, 0xdd); 
		
        x8 = _mm512_shuffle_i64x2(t1, zero_reg, 0x44); 
        x9 = _mm512_shuffle_i64x2(t1, zero_reg, 0xee); 
        pl1 = _mm512_shuffle_i64x2(x8, zero_reg, 0x88); 
        pl3 = _mm512_shuffle_i64x2(x8, zero_reg, 0xdd); 
        pl5 = _mm512_shuffle_i64x2(x9, zero_reg, 0x88); 
        pl7 = _mm512_shuffle_i64x2(x9, zero_reg, 0xdd);

        _mm512_mask_storeu_epi8((void *)out[0], (uint64_t) mask[0], pr0);
        _mm512_mask_storeu_epi8((void *)out[1], (uint64_t) mask[1], pl0);
        _mm512_mask_storeu_epi8((void *)out[2], (uint64_t) mask[2], pr1);
        _mm512_mask_storeu_epi8((void *)out[3], (uint64_t) mask[3], pl1);
        _mm512_mask_storeu_epi8((void *)out[4], (uint64_t) mask[4], pr2);
        _mm512_mask_storeu_epi8((void *)out[5], (uint64_t) mask[5], pl2);
        _mm512_mask_storeu_epi8((void *)out[6], (uint64_t) mask[6], pr3);
        _mm512_mask_storeu_epi8((void *)out[7], (uint64_t) mask[7], pl3);
        _mm512_mask_storeu_epi8((void *)out[8], (uint64_t) mask[8], pr4);
        _mm512_mask_storeu_epi8((void *)out[9], (uint64_t) mask[9], pl4);
        _mm512_mask_storeu_epi8((void *)out[10], (uint64_t) mask[10], pr5);
        _mm512_mask_storeu_epi8((void *)out[11], (uint64_t) mask[11], pl5);
        _mm512_mask_storeu_epi8((void *)out[12], (uint64_t) mask[12], pr6);
        _mm512_mask_storeu_epi8((void *)out[13], (uint64_t) mask[13], pl6);
        _mm512_mask_storeu_epi8((void *)out[14], (uint64_t) mask[14], pr7);
        _mm512_mask_storeu_epi8((void *)out[15], (uint64_t) mask[15], pl7);
}

/**
 * @brief Initializes key schedule and IV for DES operations
 *
 * Both IV and key schedule need to be transposed.
 * IV at the moment is kept transposed (manager looks after it).
 * Key schedule is transposed here.
 *
 * @param data DES operation arguments for 16 lanes
 * @param p_ks pointer to memory area to store transposed key schedule
 * @param p_iv0 pointer to store transposed IV (low words)
 * @param p_iv1 pointer to store transposed IV (high words)
 */
__forceinline
void
des_x16_init(const DES_ARGS_x16 *data, __m512i *p_ks,
             __m512i *p_iv0, __m512i *p_iv1)
{
        if (p_ks != NULL) {
                /* transpose and set up key schedule */
                transpose_in(_mm512_loadu_si512((const __m512i *)(data->keys[0])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[1])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[2])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[3])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[4])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[5])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[6])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[7])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[8])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[9])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[10])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[11])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[12])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[13])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[14])),
                             _mm512_loadu_si512((const __m512i *)(data->keys[15])),
                             &p_ks[0],  &p_ks[1],  &p_ks[2],  &p_ks[3],
                             &p_ks[4],  &p_ks[5],  &p_ks[6],  &p_ks[7],
                             &p_ks[8],  &p_ks[9],  &p_ks[10], &p_ks[11],
                             &p_ks[12], &p_ks[13], &p_ks[14], &p_ks[15]);

                transpose_in(_mm512_loadu_si512((const __m512i *)(data->keys[0] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[1] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[2] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[3] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[4] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[5] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[6] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[7] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[8] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[9] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[10] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[11] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[12] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[13] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[14] + 64)),
                             _mm512_loadu_si512((const __m512i *)(data->keys[15] + 64)),
                             &p_ks[16], &p_ks[17], &p_ks[18], &p_ks[19],
                             &p_ks[20], &p_ks[21], &p_ks[22], &p_ks[23],
                             &p_ks[24], &p_ks[25], &p_ks[26], &p_ks[27],
                             &p_ks[28], &p_ks[29], &p_ks[30], &p_ks[31]);
        }

        /* load IV that is already in transposed format (submit & flush) */
        *p_iv0 = _mm512_loadu_si512((const __m512i *)&data->IV[0]);
        *p_iv1 = _mm512_loadu_si512((const __m512i *)&data->IV[AVX512_NUM_DES_LANES]);
}

/**
 * @brief Completes DES operation
 *
 * Updates \a data for the next operation:
 * - update in/out pointers
 * - write back IV
 *
 * @param data DES operation arguments for 16 lanes
 * @param p_ks pointer to memory area to store transposed key schedule
 * @param p_iv0 pointer to store transposed IV (low words)
 * @param p_iv1 pointer to store transposed IV (high words)
 */
__forceinline
void
des_x16_finish(DES_ARGS_x16 *data, const __m512i iv0, __m512i iv1,
               const uint32_t data_length)
{
        uint32_t i;

        /* update pointers */
        for (i = 0; i < AVX512_NUM_DES_LANES; i++) {
                data->in[i] += data_length;
                data->out[i] += data_length;
        }

        /* store IV in transposed format */
        _mm512_storeu_si512((void *)&data->IV[0], iv0);
        _mm512_storeu_si512((void *)&data->IV[AVX512_NUM_DES_LANES], iv1);
}

/**
 * @brief DES CFB one block encryption/decryption as part of DOCSIS DES.
 *
 * The function also checks if there are any lanes egligble for
 * CFB partial block processing.
 *
 * @param data DES operation arguments for 16 lanes
 * @param ks pointre to already transposed key schedule
 * @param do_enc if non-zero perform encryption, decryption otherwise
 */
__forceinline
void
des_x16_cfb_one_avx512(DES_ARGS_x16 *data, const __m512i *ks, const int do_enc)
{
        const __m512i *p_vec_ones_32b = (const __m512i *) vec_ones_32b;
        uint32_t mask32_tab[AVX512_NUM_DES_LANES];
        DES_ARGS_x16 cfb_data;
        __m512i iv0, iv1, r0, l0;
        uint32_t nz_partial_len_mask;
        uint32_t last_block_mask;
        uint32_t i;

        cfb_data = *data;

        r0 = _mm512_loadu_si512((const void *)&cfb_data.partial_len[0]);
        nz_partial_len_mask = _mm512_cmp_epi32_mask(r0, _mm512_setzero_si512(),
                                                    _MM_CMPINT_NE);
        if (do_enc) {
                /* For encyrption case we need to make sure that
                 * all full blocks are complete before proceeding
                 * with CFB partial block.
                 * To do that current out position is compared against
                 * calculated last full block position.
                 */
                __m512i out1, out2, last1, last2;
                uint32_t out_eq_last1, out_eq_last2;

                out1 = _mm512_loadu_si512((const __m512i *)&cfb_data.out[0]);
                out2 = _mm512_loadu_si512((const __m512i *)&cfb_data.out[8]);

                last1 = _mm512_loadu_si512((const __m512i *)&cfb_data.last_out[0]);
                last2 = _mm512_loadu_si512((const __m512i *)&cfb_data.last_out[8]);

                out_eq_last1 = _mm512_cmp_epi64_mask(out1, last1, _MM_CMPINT_EQ);
                out_eq_last2 = _mm512_cmp_epi64_mask(out2, last2, _MM_CMPINT_EQ);
                nz_partial_len_mask &= (out_eq_last1 | (out_eq_last2 << 8));
        }

        if (!nz_partial_len_mask)
                return;

        /* Calculate ((1 << partial_bytes) - 1)
         * in order to get the mask loads and stores
         */
        l0 = _mm512_maskz_sllv_epi32(nz_partial_len_mask, *p_vec_ones_32b, r0);
        l0 = _mm512_maskz_sub_epi32(nz_partial_len_mask, l0, *p_vec_ones_32b);
        _mm512_storeu_si512((void *)mask32_tab, l0);

        /* clear selected partial lens not to do them twice */
        _mm512_mask_storeu_epi32((void *)&data->partial_len[0],
                                 nz_partial_len_mask, _mm512_setzero_si512());

        /* calculate last block case mask
         * set up IV, in and out for the last block case
         */
        r0 = _mm512_loadu_si512((const __m512i *)&cfb_data.block_len[0]);
        last_block_mask =
                _mm512_cmp_epi32_mask(r0, _mm512_setzero_si512(), _MM_CMPINT_NE);
        last_block_mask &= nz_partial_len_mask;

        if (last_block_mask) {
                /* First block case requires no modifications.
                 * Last block needs in and out to be set differently (decryption).
                 * IV has to be set differently and this piece off code
                 * seems difficult to vectorize so it stayed in scalar form.
                 */
                if (!do_enc) {
                        r0 = _mm512_loadu_si512((const __m512i *)&cfb_data.last_out[0]);
                        l0 = _mm512_loadu_si512((const __m512i *)&cfb_data.last_out[8]);
                        _mm512_mask_storeu_epi64((void *)&cfb_data.out[0],
                                                 last_block_mask & 0xff, r0);
                        _mm512_mask_storeu_epi64((void *)&cfb_data.out[8],
                                                 (last_block_mask >> 8) & 0xff,
                                                 l0);

                        r0 = _mm512_loadu_si512((const __m512i *)&cfb_data.last_in[0]);
                        l0 = _mm512_loadu_si512((const __m512i *)&cfb_data.last_in[8]);
                        _mm512_mask_storeu_epi64((void *)&cfb_data.in[0],
                                                 last_block_mask & 0xff, r0);
                        _mm512_mask_storeu_epi64((void *)&cfb_data.in[8],
                                                 (last_block_mask >> 8) & 0xff,
                                                 l0);
                }

                /* non-vector part */
                for (i = 0; last_block_mask != 0; i++, last_block_mask >>= 1) {
                        const uint32_t *p_iv;

                        if ((last_block_mask & 1) == 0)
                                continue;

                        if (do_enc)
                                p_iv = (const uint32_t *)(cfb_data.last_out[i] - 8);
                        else
                                p_iv = (const uint32_t *)(cfb_data.last_in[i] - 8);

                        cfb_data.IV[i] = p_iv[0];
                        cfb_data.IV[i + AVX512_NUM_DES_LANES] = p_iv[1];
                }
        }

        /* Now CFB computations */
        des_x16_init(&cfb_data, NULL, &iv0, &iv1);
        transpose_in_one(&r0, &l0, &cfb_data.in[0], &mask32_tab[0]);
        des_enc_dec(&iv0, &iv1, ks, 0);
        iv1 = _mm512_xor_si512(r0, iv1);
        iv0 = _mm512_xor_si512(l0, iv0);
        r0 = iv0;
        l0 = iv1;
        transpose_out_one(r0, l0, &cfb_data.out[0], &mask32_tab[0]);
}

/**
 * @brief Computes bit mask for DES block masked loads and stores
 *
 * - computes min between 64 and \a bytes_left
 * - divides the result by DES block size (8 bytes) 
 * - the result is number of set bits in the mask
 *
 * @param bytes_left number of bytes left to process
 * @return (1 << (min(64, bytes_left) / 8)) - 1
 */
__forceinline
uint8_t
get_mask8(const uint32_t bytes_left)
{
        int32_t x = (int32_t) bytes_left;
        const int32_t y = 64;

        /* min of 64 and bytes_left */
        x = y + ((x - y) & ((x - y) >> 31));

        /* divide by block size, 8 bytes */
        x >>= 3;
        return (UINT32_C(1) << x) - UINT32_C(1);
}

/**
 * @brief DES CBC/DOCSIS DES encryption
 *
 * @param data DES operation arguments for 16 lanes
 * @param data_length number of bytes to process on all lanes.
 *        It has to be multiple of block size.
 * @param is_docsis if zero then do plain DES CBC, DOCSIS DES otherwise
 */
__forceinline
void
generic_des_x16_cbc_enc_avx512(DES_ARGS_x16 *data,
                               const uint32_t data_length,
                               const int is_docsis)
{
        __m512i ks[(DES_KEY_SCHED_SIZE * AVX512_NUM_DES_LANES) / sizeof(__m512i)];
	__m512i iv0, iv1;
	uint32_t len;

        des_x16_init(data, ks, &iv0, &iv1);

	for (len = 0; len < data_length; len += 64) {
                __m512i r0, l0, r1, l1, r2, l2, r3, l3,
                        r4, l4, r5, l5, r6, l6, r7, l7;
                const uint8_t mask = get_mask8(data_length - len);

                transpose_in(_mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[0] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[1] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[2] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[3] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[4] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[5] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[6] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[7] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[8] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[9] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[10] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[11] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[12] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[13] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[14] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[15] + len)),
                             &r0, &l0, &r1, &l1, &r2, &l2, &r3, &l3,
                             &r4, &l4, &r5, &l5, &r6, &l6, &r7, &l7);

		r0 = _mm512_xor_si512(r0, iv0);
		l0 = _mm512_xor_si512(l0, iv1);

		des_enc_dec(&r0, &l0, ks, 0);
		r1 = _mm512_xor_si512(r1, l0);
		l1 = _mm512_xor_si512(l1, r0);

		des_enc_dec(&r1, &l1, ks, 0);
		r2 = _mm512_xor_si512(r2, l1);
		l2 = _mm512_xor_si512(l2, r1);

		des_enc_dec(&r2, &l2, ks, 0);
		r3 = _mm512_xor_si512(r3, l2);
		l3 = _mm512_xor_si512(l3, r2);

		des_enc_dec(&r3, &l3, ks, 0);
		r4 = _mm512_xor_si512(r4, l3);
		l4 = _mm512_xor_si512(l4, r3);

		des_enc_dec(&r4, &l4, ks, 0);
		r5 = _mm512_xor_si512(r5, l4);
		l5 = _mm512_xor_si512(l5, r4);

		des_enc_dec(&r5, &l5, ks, 0);
		r6 = _mm512_xor_si512(r6, l5);
		l6 = _mm512_xor_si512(l6, r5);

		des_enc_dec(&r6, &l6, ks, 0);
		r7 = _mm512_xor_si512(r7, l6);
		l7 = _mm512_xor_si512(l7, r6);

		des_enc_dec(&r7, &l7, ks, 0);
		iv0 = l7;
		iv1 = r7;

                transpose_out(&r0, &l0, &r1, &l1, &r2, &l2, &r3, &l3,
                              &r4, &l4, &r5, &l5, &r6, &l6, &r7, &l7);

		_mm512_mask_storeu_epi64((void *)(data->out[0] + len), mask, r0);
		_mm512_mask_storeu_epi64((void *)(data->out[1] + len), mask, l0); 
		_mm512_mask_storeu_epi64((void *)(data->out[2] + len), mask, r1); 
		_mm512_mask_storeu_epi64((void *)(data->out[3] + len), mask, l1);
		_mm512_mask_storeu_epi64((void *)(data->out[4] + len), mask, r2);
		_mm512_mask_storeu_epi64((void *)(data->out[5] + len), mask, l2);
		_mm512_mask_storeu_epi64((void *)(data->out[6] + len), mask, r3);
		_mm512_mask_storeu_epi64((void *)(data->out[7] + len), mask, l3);
		_mm512_mask_storeu_epi64((void *)(data->out[8] + len), mask, r4);
		_mm512_mask_storeu_epi64((void *)(data->out[9] + len), mask, l4);
		_mm512_mask_storeu_epi64((void *)(data->out[10] + len), mask, r5);
		_mm512_mask_storeu_epi64((void *)(data->out[11] + len), mask, l5);
		_mm512_mask_storeu_epi64((void *)(data->out[12] + len), mask, r6);
		_mm512_mask_storeu_epi64((void *)(data->out[13] + len), mask, l6);
		_mm512_mask_storeu_epi64((void *)(data->out[14] + len), mask, r7);
		_mm512_mask_storeu_epi64((void *)(data->out[15] + len), mask, l7);
	}

        des_x16_finish(data, iv0, iv1, data_length);

        if (is_docsis)
                des_x16_cfb_one_avx512(data, ks, 1);
}

/**
 * @brief DES CBC/DOCSIS DES decryption
 *
 * @param data DES operation arguments for 16 lanes
 * @param data_length number of bytes to process on all lanes.
 *        It has to be multiple of block size.
 * @param is_docsis if zero do plain DES CBC decryption, otherwise DOCSIS DES
 */
__forceinline
void
generic_des_x16_cbc_dec_avx512(DES_ARGS_x16 *data, const uint32_t data_length,
                               const int is_docsis)
{
        __m512i ks[(DES_KEY_SCHED_SIZE * AVX512_NUM_DES_LANES) / sizeof(__m512i)];
	__m512i iv0, iv1;
	uint32_t len;

        des_x16_init(data, ks, &iv0, &iv1);

        if (is_docsis)
                des_x16_cfb_one_avx512(data, ks, 0);

	for (len = 0; len < data_length; len += 64) {
                __m512i r0, l0, r1, l1, r2, l2, r3, l3,
                        r4, l4, r5, l5, r6, l6, r7, l7;
                __m512i iv0_1, iv1_1;
                const uint8_t mask = get_mask8(data_length - len);

                transpose_in(_mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[0] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[1] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[2] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[3] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[4] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[5] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[6] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[7] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[8] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[9] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[10] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[11] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[12] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[13] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[14] + len)),
                             _mm512_mask_loadu_epi64(_mm512_setzero_si512(), mask, (const void *)(data->in[15] + len)),
                             &r0, &l0, &r1, &l1, &r2, &l2, &r3, &l3,
                             &r4, &l4, &r5, &l5, &r6, &l6, &r7, &l7);

                iv0_1 = r0;
                iv1_1 = l0;
		des_enc_dec(&r0, &l0, ks, 1);
		r0 = _mm512_xor_si512(r0, iv1);
		l0 = _mm512_xor_si512(l0, iv0);
                iv0 = iv0_1;
                iv1 = iv1_1;

                iv0_1 = r1;
                iv1_1 = l1;
		des_enc_dec(&r1, &l1, ks, 1);
		r1 = _mm512_xor_si512(r1, iv1);
		l1 = _mm512_xor_si512(l1, iv0);
                iv0 = iv0_1;
                iv1 = iv1_1;

                iv0_1 = r2;
                iv1_1 = l2;
		des_enc_dec(&r2, &l2, ks, 1);
		r2 = _mm512_xor_si512(r2, iv1);
		l2 = _mm512_xor_si512(l2, iv0);
                iv0 = iv0_1;
                iv1 = iv1_1;

                iv0_1 = r3;
                iv1_1 = l3;
		des_enc_dec(&r3, &l3, ks, 1);
		r3 = _mm512_xor_si512(r3, iv1);
		l3 = _mm512_xor_si512(l3, iv0);
                iv0 = iv0_1;
                iv1 = iv1_1;

                iv0_1 = r4;
                iv1_1 = l4;
		des_enc_dec(&r4, &l4, ks, 1);
		r4 = _mm512_xor_si512(r4, iv1);
		l4 = _mm512_xor_si512(l4, iv0);
                iv0 = iv0_1;
                iv1 = iv1_1;

                iv0_1 = r5;
                iv1_1 = l5;
		des_enc_dec(&r5, &l5, ks, 1);
		r5 = _mm512_xor_si512(r5, iv1);
		l5 = _mm512_xor_si512(l5, iv0);
                iv0 = iv0_1;
                iv1 = iv1_1;

                iv0_1 = r6;
                iv1_1 = l6;
		des_enc_dec(&r6, &l6, ks, 1);
		r6 = _mm512_xor_si512(r6, iv1);
		l6 = _mm512_xor_si512(l6, iv0);
                iv0 = iv0_1;
                iv1 = iv1_1;

                iv0_1 = r7;
                iv1_1 = l7;
		des_enc_dec(&r7, &l7, ks, 1);
		r7 = _mm512_xor_si512(r7, iv1);
		l7 = _mm512_xor_si512(l7, iv0);
                iv0 = iv0_1;
                iv1 = iv1_1;

                transpose_out(&r0, &l0, &r1, &l1, &r2, &l2, &r3, &l3,
                              &r4, &l4, &r5, &l5, &r6, &l6, &r7, &l7);

		_mm512_mask_storeu_epi64((void *)(data->out[0] + len), mask, r0);
		_mm512_mask_storeu_epi64((void *)(data->out[1] + len), mask, l0); 
		_mm512_mask_storeu_epi64((void *)(data->out[2] + len), mask, r1); 
		_mm512_mask_storeu_epi64((void *)(data->out[3] + len), mask, l1);
		_mm512_mask_storeu_epi64((void *)(data->out[4] + len), mask, r2);
		_mm512_mask_storeu_epi64((void *)(data->out[5] + len), mask, l2);
		_mm512_mask_storeu_epi64((void *)(data->out[6] + len), mask, r3);
		_mm512_mask_storeu_epi64((void *)(data->out[7] + len), mask, l3);
		_mm512_mask_storeu_epi64((void *)(data->out[8] + len), mask, r4);
		_mm512_mask_storeu_epi64((void *)(data->out[9] + len), mask, l4);
		_mm512_mask_storeu_epi64((void *)(data->out[10] + len), mask, r5);
		_mm512_mask_storeu_epi64((void *)(data->out[11] + len), mask, l5);
		_mm512_mask_storeu_epi64((void *)(data->out[12] + len), mask, r6);
		_mm512_mask_storeu_epi64((void *)(data->out[13] + len), mask, l6);
		_mm512_mask_storeu_epi64((void *)(data->out[14] + len), mask, r7);
		_mm512_mask_storeu_epi64((void *)(data->out[15] + len), mask, l7);
	}

        des_x16_finish(data, iv0, iv1, data_length);
}

void des_x16_cbc_enc_avx512(DES_ARGS_x16 *data, const uint32_t data_length)
{
        generic_des_x16_cbc_enc_avx512(data, data_length, 0);
}

void des_x16_cbc_dec_avx512(DES_ARGS_x16 *data, const uint32_t data_length)
{
        generic_des_x16_cbc_dec_avx512(data, data_length, 0);
}

void docsis_des_x16_enc_avx512(DES_ARGS_x16 *data, const uint32_t data_length)
{
        generic_des_x16_cbc_enc_avx512(data, data_length, 1);
}

void docsis_des_x16_dec_avx512(DES_ARGS_x16 *data, const uint32_t data_length)
{
        generic_des_x16_cbc_dec_avx512(data, data_length, 1);
}
