/**********************************************************************
  Copyright(c) 2021 Arm Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Arm Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/
#ifndef SNOW3G_COMMON_H
#define SNOW3G_COMMON_H

#include <stdio.h> /* printf() */
#include <string.h> /* memset(), memcpy() */
#include <stdint.h>

#include "intel-ipsec-mb.h"
#include "include/wireless_common.h"
#include "snow3g.h"
#include "snow3g_tables.h"
#include "constant_lookup_aarch64.h"
#include "clear_regs_mem_aarch64.h"
#ifdef NO_AESNI
#include "include/aesni_emu.h"
#endif

#define CLEAR_MEM clear_mem
#define CLEAR_VAR clear_var

#define MAX_KEY_LEN (16)
#define SNOW3G_4_BYTES (4)
#define SNOW3G_8_BYTES (8)
#define SNOW3G_8_BITS (8)
#define SNOW3G_16_BYTES (16)
#define SNOW3G_16_BITS (16)

#define SNOW3G_BLOCK_SIZE (8)

#define SNOW3G_KEY_LEN_IN_BYTES (16) /* 128b */
#define SNOW3G_IV_LEN_IN_BYTES (16)  /* 128b */

#define SNOW3GCONSTANT (0x1b)

/* Range of input data for SNOW3G is from 1 to 2^32 bits */
#define SNOW3G_MIN_LEN 1
#define SNOW3G_MAX_BITLEN (UINT32_MAX)
#define SNOW3G_MAX_BYTELEN (UINT32_MAX / 8)

typedef union SafeBuffer {
        uint64_t b64;
        uint32_t b32[2];
        uint8_t b8[SNOW3G_8_BYTES];
} SafeBuf;

typedef struct snow3gKeyState1_s {
        /* 16 LFSR stages */
        uint32_t LFSR_S[16];
        /* 3 FSM states */
        uint32_t FSM_R3;
        uint32_t FSM_R2;
        uint32_t FSM_R1;
} DECLARE_ALIGNED(snow3gKeyState1_t, 16);

typedef struct snow3gKeyState4_s {
        /* 16 LFSR stages */
        uint32x4_t LFSR_X[16];
        /* 3 FSM states */
        uint32x4_t FSM_X[3];
        uint32_t iLFSR_X;
} snow3gKeyState4_t;

/**
 * @brief Finds minimum 32-bit value in an array
 * @return Min 32-bit value
 */
static inline uint32_t
length_find_min(const uint32_t *out_array, const size_t dim_array)
{
        size_t i;
        uint32_t min = 0;

        if (dim_array > 0)
                min  = out_array[0];

        for (i = 1; i < dim_array; i++)
                if (out_array[i] < min)
                        min = out_array[i];

        return min;
}

/**
 * @brief Subtracts \a subv from a vector of 32-bit words
 */
static inline void
length_sub(uint32_t *out_array, const size_t dim_array, const uint32_t subv)
{
        size_t i;

        for (i = 0; i < dim_array; i++)
                out_array[i] -= subv;
}

/**
 * @brief Checks vector of length values against 0 and SNOW3G_MAX_BYTELEN values
 * @retval 0 incorrect length value found
 * @retval 1 all OK
 */
static inline uint32_t
length_check(const uint32_t *out_array, const size_t dim_array)
{
        size_t i;

        for (i = 0; i < dim_array; i++) {
                if ((out_array[i] == 0) ||
                    (out_array[i] > SNOW3G_MAX_BYTELEN))
                        return 0;
        }

        return 1;
}

/**
 * @brief Copies 4 32-bit length values into an array
 */
static inline void
length_copy_4(uint32_t *out_array,
              const uint32_t length1, const uint32_t length2,
              const uint32_t length3, const uint32_t length4)
{
        out_array[0] = length1;
        out_array[1] = length2;
        out_array[2] = length3;
        out_array[3] = length4;
}

/**
 * @brief Copies 8 32-bit length values into an array
 */
static inline void
length_copy_8(uint32_t *out_array,
              const uint32_t length1, const uint32_t length2,
              const uint32_t length3, const uint32_t length4,
              const uint32_t length5, const uint32_t length6,
              const uint32_t length7, const uint32_t length8)
{
        out_array[0] = length1;
        out_array[1] = length2;
        out_array[2] = length3;
        out_array[3] = length4;
        out_array[4] = length5;
        out_array[5] = length6;
        out_array[6] = length7;
        out_array[7] = length8;
}

/**
 * @brief Checks vector of pointers against NULL
 * @retval 0 incorrect pointer found
 * @retval 1 all OK
 */
static inline int
ptr_check(void *out_array[], const size_t dim_array)
{
        size_t i;

        for (i = 0; i < dim_array; i++)
                if (out_array[i] == NULL)
                        return 0;

        return 1;
}

/**
 * @brief Checks vector of const pointers against NULL
 * @retval 0 incorrect pointer found
 * @retval 1 all OK
 */
static inline int
cptr_check(const void * const out_array[], const size_t dim_array)
{
        size_t i;

        for (i = 0; i < dim_array; i++)
                if (out_array[i] == NULL)
                        return 0;

        return 1;
}

/**
 * @brief Copies 4 pointers into an array
 */
static inline void
ptr_copy_4(void *out_array[],
           void *ptr1, void *ptr2, void *ptr3, void *ptr4)
{
        out_array[0] = ptr1;
        out_array[1] = ptr2;
        out_array[2] = ptr3;
        out_array[3] = ptr4;
}

/**
 * @brief Copies 4 const pointers into an array
 */
static inline void
cptr_copy_4(const void *out_array[],
            const void *ptr1, const void *ptr2,
            const void *ptr3, const void *ptr4)
{
        out_array[0] = ptr1;
        out_array[1] = ptr2;
        out_array[2] = ptr3;
        out_array[3] = ptr4;
}

/**
 * @brief Copies 8 pointers into an array
 */
static inline void
ptr_copy_8(void *out_array[],
           void *ptr1, void *ptr2, void *ptr3, void *ptr4,
           void *ptr5, void *ptr6, void *ptr7, void *ptr8)
{
        out_array[0] = ptr1;
        out_array[1] = ptr2;
        out_array[2] = ptr3;
        out_array[3] = ptr4;
        out_array[4] = ptr5;
        out_array[5] = ptr6;
        out_array[6] = ptr7;
        out_array[7] = ptr8;
}

/**
 * @brief Copies 8 const pointers into an array
 */
static inline void
cptr_copy_8(const void *out_array[],
            const void *ptr1, const void *ptr2,
            const void *ptr3, const void *ptr4,
            const void *ptr5, const void *ptr6,
            const void *ptr7, const void *ptr8)
{
        out_array[0] = ptr1;
        out_array[1] = ptr2;
        out_array[2] = ptr3;
        out_array[3] = ptr4;
        out_array[4] = ptr5;
        out_array[5] = ptr6;
        out_array[6] = ptr7;
        out_array[7] = ptr8;
}

/**
 * @brief Wrapper for safe lookup of 16 indexes in 256x8-bit table
 * @param[in] indexes  vector of 16x8-bit indexes to be looked up
 * @param[in] lut      pointer to a 256x8-bit table
 * @return 16x8-bit values looked in \a lut using 16x8-bit \a indexes
 */
static inline uint8x16_t lut16x8b_256(const uint8x16_t indexes, const void *lut)
{
        return lookup_16x8bit_neon(indexes, lut);
}

/**
 * @brief LFSR array shift by 2 positions
 * @param[in/out] pCtx  key state context structure
 */
static inline void ShiftTwiceLFSR_1(snow3gKeyState1_t *pCtx)
{
        int i;

        for (i = 0; i < 14; i++)
                pCtx->LFSR_S[i] = pCtx->LFSR_S[i + 2];
}

/**
 * @brief SNOW3G S2 mix column correction function
 *
 * Mix column AES GF() reduction poly is 0x1B and SNOW3G reduction poly is 0x69.
 * The fix-up value is 0x1B ^ 0x69 = 0x72 and needs to be applied on selected
 * bytes of the 32-bit word.
 *
 * 'aese' operation does not perform mix column operation and allows to
 * determine the fix-up value to be applied on result of 'aese + aesmc'
 * in order to produce correct result for SNOW3G.
 *
 * This function implements more scalable SIMD method to apply the fix-up value
 * for multiple stream at the same time.
 *
 * a = \a no_mixc bit-31
 * b = \a no_mixc bit-23
 * c = \a no_mixc bit-15
 * d = \a no_mixc bit-7
 *
 * mask0_f(), mask1_f(), mask2_f() and mask3_f() functions
 * specify if corresponding byte of \a mixc word, i.e. 0, 1, 2 or 3
 * respectively, should be corrected.
 * Definition of the functions:
 *     mask0_f(a, b, c, d) = c'd + cd' => c xor d
 *     mask1_f(a, b, c, d) = b'c + bc' => b xor c
 *     mask2_f(a, b, c, d) = a'b + ab' => a xor b
 *     mask3_f(a, b, c, d) = a'd + ad' => d xor a
 * The above are resolved through SIMD instructions: and, cmlt and
 * xor. As the result mask is obtained with 0xff byte value at positions
 * that require 0x72 fix up value to be applied.
 *
 * @param no_mixc result of 'aese' operation, 4 x 32-bit words
 * @param mixc    result of 'aese + aesmc' operation, 4 x 32-bit words
 *
 * @return corrected \a mixc for SNOW3G S2, 4 x 32-bit words
 */
static inline uint32x4_t s2_mixc_fixup_4(const uint8x16_t no_mixc, const uint8x16_t mixc)
{
        const uint32_t ror8[4] = {0x00030201, 0x04070605, 0x080b0a09, 0x0c0f0e0d};
        uint8x16_t pattern, pattern_shuf, idx, mask, fixup;

        pattern = vcltzq_s8(vreinterpretq_s8_u8(no_mixc));
        idx = vreinterpretq_u8_u32(vld1q_u32(ror8));
        pattern_shuf = vqtbl1q_u8(pattern, idx);

        mask = vdupq_n_u8(0x72);
        pattern = pattern ^ pattern_shuf;

        fixup = mask & pattern;
        return vreinterpretq_u32_u8(veorq_u8(fixup, mixc));

}

/**
 * @brief SNOW3G S2 mix column correction function
 *
 * @param no_mixc result of 'aese' operation, 32-bit word index 0 only
 * @param mixc    result of 'aese + aesmc' operation, 32-bit word index 0 only
 *
 * @return corrected \a mixc 32-bit word for SNOW3G S2
 */
static inline uint32_t
s2_mixc_fixup_scalar(const uint8x16_t no_mixc, const uint8x16_t mixc)
{
        return vgetq_lane_u32(s2_mixc_fixup_4(no_mixc, mixc), 0);
}

/**
 * @brief Sbox S1 maps a 32bit input to a 32bit output
 *
 * @param[in] x  32-bit word to be passed through S1 box
 *
 * @return \a x transformed through S1 box
 */
static inline uint32_t S1_box(const uint32_t x)
{
#ifdef NO_AESNI
        union xmm_reg key, v;

        key.qword[0] = key.qword[1] = 0;

        v.dword[0] = v.dword[1] =
                v.dword[2] = v.dword[3] = x;

        emulate_AESENC(&v, &key);
        return v.dword[0];
#else
        uint32x4_t dup_x;
        uint8x16_t new_x, key, tmp;
        dup_x = vdupq_n_u32(x);
        key = vdupq_n_u8(0);
        new_x = vreinterpretq_u8_u32(dup_x);
        tmp = vaeseq_u8(new_x, key);
        tmp = vaesmcq_u8(tmp);

        return vgetq_lane_u32(vreinterpretq_u32_u8(tmp),0);
#endif
}

/**
 * @brief Sbox S1 maps a 2x32bit input to a 2x32bit output
 *
 * @param[in] x1  32-bit word to be passed through S1 box
 * @param[in] x2  32-bit word to be passed through S1 box
 */
static inline void S1_box_2(uint32_t *x1, uint32_t *x2)
{
#ifdef NO_AESNI
        /* reuse S1_box() for NO_AESNI path */
        *x1 = S1_box(*x1);
        *x2 = S1_box(*x2);
#else
        const uint8x16_t m_zero = vdupq_n_u8(0);
        uint32x4_t m1, m2;
        uint8x16_t r1, r2;

        m1 = vdupq_n_u32(*x1);
        r1 = vaeseq_u8(vreinterpretq_u8_u32(m1), m_zero);
        r1 = vaesmcq_u8(r1);
        m2 = vdupq_n_u32(*x2);
        r2 = vaeseq_u8(vreinterpretq_u8_u32(m2), m_zero);
        r2 = vaesmcq_u8(r2);

        *x1 = vgetq_lane_u32(vreinterpretq_u32_u8(r1), 0);
        *x2 = vgetq_lane_u32(vreinterpretq_u32_u8(r2), 0);
#endif
}

/**
 * @brief Sbox S1 maps a 4x32bit input to a 4x32bit output
 *
 * @param[in] x  vector of 4 32-bit words to be passed through S1 box
 *
 * @return 4x32-bits from \a x transformed through S1 box
 */
static inline uint32x4_t S1_box_4(const uint32x4_t x)
{
#ifdef NO_AESNI
        union xmm_reg key, v, vt;

        key.qword[0] = key.qword[1] = 0;

        /*
         * - Broadcast 32-bit word across XMM
         * - Perform AES operations
         */
        vt.dword[0] = vt.dword[1] = vt.dword[2] = vt.dword[3] = vgetq_lane_u32(x, 0);
        emulate_AESENC(&vt, &key);
        v.dword[0] = vt.dword[0];

        vt.dword[0] = vt.dword[1] = vt.dword[2] = vt.dword[3] = vgetq_lane_u32(x, 1);
        emulate_AESENC(&vt, &key);
        v.dword[1] = vt.dword[0];

        vt.dword[0] = vt.dword[1] = vt.dword[2] = vt.dword[3] = vgetq_lane_u32(x, 2);
        emulate_AESENC(&vt, &key);
        v.dword[2] = vt.dword[0];

        vt.dword[0] = vt.dword[1] = vt.dword[2] = vt.dword[3] = vgetq_lane_u32(x, 3);
        emulate_AESENC(&vt, &key);
        v.dword[3] = vt.dword[0];

        return vld1q_u32(&v.dword[0]);
#else
        const uint8x16_t m_zero = vdupq_n_u8(0);
        uint8x16_t m1, m2, m3, m4;
        uint32x4_t r1, r2;

        m1 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x, 0)));
        m2 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x, 1)));
        m3 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x, 2)));
        m4 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x, 3)));

        m1 = vaeseq_u8(m1, m_zero);
        m1 = vaesmcq_u8(m1);
        m2 = vaeseq_u8(m2, m_zero);
        m2 = vaesmcq_u8(m2);
        m3 = vaeseq_u8(m3, m_zero);
        m3 = vaesmcq_u8(m3);
        m4 = vaeseq_u8(m4, m_zero);
        m4 = vaesmcq_u8(m4);

        /*
         * Put results of AES operations back into
         * two vectors of 32-bit words
         *
         * First step:
         * r1 = [ 0-31 m1 | 0-31 m2 | 32-63 m1 | 32-63 m2 ]
         * r2 = [ 0-31 m3 | 0-31 m4 | 32-63 m3 | 32-63 m4 ]
         */
        r1 = vzip1q_u32(vreinterpretq_u32_u8(m1), vreinterpretq_u32_u8(m2));
        r2 = vzip1q_u32(vreinterpretq_u32_u8(m3), vreinterpretq_u32_u8(m4));
        r1 = vreinterpretq_u32_u64(vzip1q_u64(vreinterpretq_u64_u32(r1),
                                                vreinterpretq_u64_u32(r2)));
        /*
         * The last step:
         * r1 = [ 0-63 m1 | 0-63 m3 ] =>
         *      [ 0-31 m1 | 0-31 m2 | 0-31 m3 | 0-31 m4 ]
         */

        return r1;
#endif
}

/**
 * @brief Sbox S2 maps a 32-bit input to a 32-bit output
 *
 * @param[in] x  32-bit word to be passed through S2 box
 *
 * @return \a x transformed through S2 box
 */
static inline uint32_t S2_box(const uint32_t x)
{
#ifdef NO_AESNI
        /* Perform invSR(SQ(x)) transform */
        const uint32x4_t par_lut = vreinterpretq_u32_u8(
                            lut16x8b_256(vreinterpretq_u8_u32(vdupq_n_u32(x)),
                                         snow3g_invSR_SQ));
        const uint32_t new_x = vgetq_lane_u32(par_lut, 0);
        union xmm_reg key, v, v_fixup;

        key.qword[0] = key.qword[1] = 0;

        v.dword[0] = v.dword[1] =
                v.dword[2] = v.dword[3] = new_x;

        v_fixup = v;

        emulate_AESENC(&v, &key);
        emulate_AESENCLAST(&v_fixup, &key);

        const uint8x16_t ret_mixc = vreinterpretq_u8_u32(
                                vld1q_u32(&v.dword[0]));
        const uint8x16_t ret_nomixc = vreinterpretq_u8_u32(
                                vld1q_u32(&v_fixup.dword[0]));

        return s2_mixc_fixup_scalar(ret_nomixc, ret_mixc);
#else

#ifndef SAFE_LOOKUP
        const uint8_t *w3 = (const uint8_t *)&snow3g_table_S2[x & 0xff];
        const uint8_t *w1 = (const uint8_t *)&snow3g_table_S2[(x >> 16) & 0xff];
        const uint8_t *w2 = (const uint8_t *)&snow3g_table_S2[(x >> 8) & 0xff];
        const uint8_t *w0 = (const uint8_t *)&snow3g_table_S2[(x >> 24) & 0xff];

        return *((const uint32_t *)&w3[3]) ^
                *((const uint32_t *)&w1[1]) ^
                *((const uint32_t *)&w2[2]) ^
                *((const uint32_t *)&w0[0]);

#else
        uint32x4_t par_lut;
        uint8x16_t m, key, ret_nomixc, ret_mixc;

        /* Perform invSR(SQ(x)) transform */
        par_lut = vreinterpretq_u32_u8(
                  lut16x8b_256(vreinterpretq_u8_u32(vdupq_n_u32(x)),
                               snow3g_invSR_SQ));

        m = vreinterpretq_u8_u32(vdupq_n_u32((vgetq_lane_u32(par_lut, 0))));
        key = vdupq_n_u8(0);

        ret_nomixc = vaeseq_u8(m, key);
        ret_mixc = vaesmcq_u8(ret_nomixc);

        return s2_mixc_fixup_scalar(ret_nomixc, ret_mixc);
#endif

#endif
}

/**
 * @brief Sbox S2 maps a 2x32bit input to a 2x32bit output
 *
 * @param[in/out] x1  32-bit word to be passed through S2 box
 * @param[in/out] x2  32-bit word to be passed through S2 box
 */
static inline void S2_box_2(uint32_t *x1, uint32_t *x2)
{
#if defined(NO_AESNI) || !defined(SAFE_LOOKUP)
        *x1 = S2_box(*x1);
        *x2 = S2_box(*x2);
#else
        /* Perform invSR(SQ(x)) transform through a lookup table */
        const uint8x16_t m_zero = vdupq_n_u8(0);
        uint32x4_t x_vec, ret_nomixc, ret_mixc, res;

        x_vec = vdupq_n_u32(x1[0]);
        x_vec = vsetq_lane_u32(x2[0], x_vec, 1);

        const uint32x4_t new_x = vreinterpretq_u32_u8(
                                 lut16x8b_256(vreinterpretq_u8_u32(x_vec),
                                              snow3g_invSR_SQ));
        uint8x16_t m1, m2, f1, f2;

        m1 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(new_x, 0)));
        m2 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(new_x, 1)));

        f1 = vaeseq_u8(m1, m_zero); // no_mixc
        m1 = vaesmcq_u8(f1);
        f2 = vaeseq_u8(m2, m_zero);
        m2 = vaesmcq_u8(f2);
        /*
         * Put results of AES operations back into one vector
         * for further fix up
         */
        ret_nomixc = vzip1q_u32(vreinterpretq_u32_u8(f1), vreinterpretq_u32_u8(f2));
        ret_mixc = vzip1q_u32(vreinterpretq_u32_u8(m1), vreinterpretq_u32_u8(m2));

        res = s2_mixc_fixup_4(vreinterpretq_u8_u32(ret_nomixc), vreinterpretq_u8_u32(ret_mixc));

        *x1 = vgetq_lane_u32(res, 0);
        *x2 = vgetq_lane_u32(res, 1);
#endif
}

/**
 * @brief Sbox S2 maps a 4x32bit input to a 4x32bit output
 *
 * @param[in] x  vector of 4 32-bit words to be passed through S2 box
 *
 * @return 4x32-bits from \a x transformed through S2 box
 */
static inline uint32x4_t S2_box_4(const uint32x4_t x)
{
        /* Perform invSR(SQ(x)) transform through a lookup table */
        const uint32x4_t new_x = vreinterpretq_u32_u8(
                                 lut16x8b_256(vreinterpretq_u8_u32(x),
                                              snow3g_invSR_SQ));

        /* use AESNI operations for the rest of the S2 box */
#ifdef NO_AESNI
        union xmm_reg key, v, f;
        union xmm_reg vt, ft;

        key.qword[0] = key.qword[1] = 0;

        /*
         * - Broadcast 32-bit word across XMM and
         *   perform AES operations
         * - Save result 32-bit words in v and f vectors.
         *   'f' is used for fix-up of mixed columns only
         */
        vt.dword[0] = vt.dword[1] = vt.dword[2] = vt.dword[3] =
                                                vgetq_lane_u32(new_x, 0);
        ft = vt;
        emulate_AESENC(&vt, &key);
        emulate_AESENCLAST(&ft, &key);
        v.dword[0] = vt.dword[0];
        f.dword[0] = ft.dword[0];

        vt.dword[0] = vt.dword[1] = vt.dword[2] = vt.dword[3] =
                                                vgetq_lane_u32(new_x, 1);
        ft = vt;
        emulate_AESENC(&vt, &key);
        emulate_AESENCLAST(&ft, &key);
        v.dword[1] = vt.dword[0];
        f.dword[1] = ft.dword[0];

        vt.dword[0] = vt.dword[1] = vt.dword[2] = vt.dword[3] =
                                                vgetq_lane_u32(new_x, 2);
        ft = vt;
        emulate_AESENC(&vt, &key);
        emulate_AESENCLAST(&ft, &key);
        v.dword[2] = vt.dword[0];
        f.dword[2] = ft.dword[0];

        vt.dword[0] = vt.dword[1] = vt.dword[2] = vt.dword[3] =
                                                vgetq_lane_u32(new_x, 3);
        ft = vt;
        emulate_AESENC(&vt, &key);
        emulate_AESENCLAST(&ft, &key);
        v.dword[3] = vt.dword[0];
        f.dword[3] = ft.dword[0];

        return s2_mixc_fixup_4(vreinterpretq_u8_u32(vld1q_u32(&f.dword[0])),
                                vreinterpretq_u8_u32(vld1q_u32(&v.dword[0])));
#else
        const uint8x16_t zero = vdupq_n_u8(0);
        uint8x16_t m1, m2, m3, m4, f1, f2, f3, f4, mixc, no_mixc;
        uint32x4_t r1, r2;

        m1 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(new_x, 0)));
        m2 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(new_x, 1)));
        m3 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(new_x, 2)));
        m4 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(new_x, 3)));

        f1 = vaeseq_u8(m1, zero); // no_mixc
        m1 = vaesmcq_u8(f1);
        f2 = vaeseq_u8(m2, zero);
        m2 = vaesmcq_u8(f2);
        f3 = vaeseq_u8(m3, zero);
        m3 = vaesmcq_u8(f3);
        f4 = vaeseq_u8(m4, zero);
        m4 = vaesmcq_u8(f4);

        /*
         * Put results of AES operations back into
         * two vectors of 32-bit words
         *
         * First step:
         * m1 = [ 0-31 m1 | 0-31 m2 | 32-63 m1 | 32-63 m2 ]
         * m3 = [ 0-31 m3 | 0-31 m4 | 32-63 m3 | 32-63 m4 ]
         */
        /*
         * The last step:
         * m1 = [ 0-63 m1 | 0-63 m3 ] =>
         *      [ 0-31 m1 | 0-31 m2 | 0-31 m3 | 0-31 m4 ]
         * f1 = [ 0-63 f1 | 0-63 f3 ] =>
         *      [ 0-31 f1 | 0-31 f2 | 0-31 f3 | 0-31 f4 ]
         */
        r1 = vzip1q_u32(vreinterpretq_u32_u8(m1), vreinterpretq_u32_u8(m2));
        r2 = vzip1q_u32(vreinterpretq_u32_u8(m3), vreinterpretq_u32_u8(m4));
        mixc = vreinterpretq_u8_u64(vzip1q_u64(vreinterpretq_u64_u32(r1),
                                                vreinterpretq_u64_u32(r2)));

        r1 = vzip1q_u32(vreinterpretq_u32_u8(f1), vreinterpretq_u32_u8(f2));
        r2 = vzip1q_u32(vreinterpretq_u32_u8(f3), vreinterpretq_u32_u8(f4));
        no_mixc = vreinterpretq_u8_u64(vzip1q_u64(vreinterpretq_u64_u32(r1),
                                                 vreinterpretq_u64_u32(r2)));

        return s2_mixc_fixup_4(no_mixc, mixc);
#endif
}

/**
 * @brief Sbox S2 maps a 2x4x32bit input to a 2x4x32bit output
 *
 * @param[in/out] in_out1  vector of 4 32-bit words to be passed through S2 box
 * @param[in/out] in_out2  vector of 4 32-bit words to be passed through S2 box
 */
static inline void S2_box_2x4(uint32x4_t *in_out1, uint32x4_t *in_out2)
{
#ifdef NO_AESNI
        *in_out1 = S2_box_4(*in_out1);
        *in_out2 = S2_box_4(*in_out2);
#else
        /*
         * Perform invSR(SQ(x)) transform through a lookup table and
         * use AES operations for the rest of the S2 box
         */
        const uint8x16_t zero = vdupq_n_u8(0);
        const uint32x4_t x1 = vreinterpretq_u32_u8(
                              lut16x8b_256(vreinterpretq_u8_u32(*in_out1),
                                           snow3g_invSR_SQ));
        uint8x16_t m1, m2, m3, m4, f1, f2, f3, f4;
        uint8x16_t m5, m6, m7, m8, f5, f6, f7, f8;
        uint8x16_t mixc, no_mixc;
        uint32x4_t r1, r2;

        m1 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x1, 0)));
        m2 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x1, 1)));
        m3 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x1, 2)));
        m4 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x1, 3)));

        /* start shuffling next 128 bits of data */
        const uint32x4_t x2 = vreinterpretq_u32_u8(
                              lut16x8b_256(vreinterpretq_u8_u32(*in_out2),
                                           snow3g_invSR_SQ));

        m5 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x2, 0)));
        m6 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x2, 1)));
        m7 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x2, 2)));
        m8 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(x2, 3)));

        f1 = vaeseq_u8(m1, zero); // no_mixc
        m1 = vaesmcq_u8(f1);
        f2 = vaeseq_u8(m2, zero);
        m2 = vaesmcq_u8(f2);
        f3 = vaeseq_u8(m3, zero);
        m3 = vaesmcq_u8(f3);
        f4 = vaeseq_u8(m4, zero);
        m4 = vaesmcq_u8(f4);

        r1 = vzip1q_u32(vreinterpretq_u32_u8(m1), vreinterpretq_u32_u8(m2));
        r2 = vzip1q_u32(vreinterpretq_u32_u8(m3), vreinterpretq_u32_u8(m4));
        mixc = vreinterpretq_u8_u64(vzip1q_u64(vreinterpretq_u64_u32(r1),
                                                vreinterpretq_u64_u32(r2)));

        r1 = vzip1q_u32(vreinterpretq_u32_u8(f1), vreinterpretq_u32_u8(f2));
        r2 = vzip1q_u32(vreinterpretq_u32_u8(f3), vreinterpretq_u32_u8(f4));
        no_mixc = vreinterpretq_u8_u64(vzip1q_u64(vreinterpretq_u64_u32(r1),
                                                 vreinterpretq_u64_u32(r2)));

        *in_out1 = s2_mixc_fixup_4(no_mixc, mixc);

        /* start encrypting next 128 bits */
        f5 = vaeseq_u8(m5, zero); // no_mixc
        m5 = vaesmcq_u8(f5);
        f6 = vaeseq_u8(m6, zero);
        m6 = vaesmcq_u8(f6);
        f7 = vaeseq_u8(m7, zero);
        m7 = vaesmcq_u8(f7);
        f8 = vaeseq_u8(m8, zero);
        m8 = vaesmcq_u8(f8);

        r1 = vzip1q_u32(vreinterpretq_u32_u8(m5), vreinterpretq_u32_u8(m6));
        r2 = vzip1q_u32(vreinterpretq_u32_u8(m7), vreinterpretq_u32_u8(m8));
        mixc = vreinterpretq_u8_u64(vzip1q_u64(vreinterpretq_u64_u32(r1),
                                                vreinterpretq_u64_u32(r2)));

        r1 = vzip1q_u32(vreinterpretq_u32_u8(f5), vreinterpretq_u32_u8(f6));
        r2 = vzip1q_u32(vreinterpretq_u32_u8(f7), vreinterpretq_u32_u8(f8));
        no_mixc = vreinterpretq_u8_u64(vzip1q_u64(vreinterpretq_u64_u32(r1),
                                                 vreinterpretq_u64_u32(r2)));

        *in_out2 = s2_mixc_fixup_4(no_mixc, mixc);
#endif
}

/**
 * @brief MULalpha SNOW3G operation on 4 8-bit values at the same time
 *
 * Function picks the right byte from the register to run MULalpha operation on.
 * MULalpha is implemented through 8 16-byte tables and pshufb is used to
 * look the tables up. This approach is possible because
 * MULalpha operation has linear nature.
 * Final operation result is calculated via byte re-arrangement on
 * the lookup results and an XOR operation.
 *
 * @param [in] L0       4 x 32-bit LFSR[0]
 * @return 4 x 32-bit MULalpha(L0 >> 24)
 */
static inline
uint32x4_t MULa_4(const uint32x4_t L0)
{
#ifdef SAFE_LOOKUP
        const uint8_t gather_clear_mask[]= {
                        0x03,0x07,0x0b,0x0f,0xff,0xff,0xff,0xff,
                        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
                        };
        const uint8x16_t low_nibble_mask = vdupq_n_u8(0x0f);
        const uint8x16_t clear_mask = vld1q_u8(gather_clear_mask);
        uint8x16_t th, tl, b0, b1, b2, b3;

        th = vqtbl1q_u8(vreinterpretq_u8_u32(L0), clear_mask);

        tl = th & low_nibble_mask;
        b0 = vld1q_u8(snow3g_MULa_byte0_low);
        b1 = vld1q_u8(snow3g_MULa_byte1_low);
        b2 = vld1q_u8(snow3g_MULa_byte2_low);
        b3 = vld1q_u8(snow3g_MULa_byte3_low);

        b0 = vqtbl1q_u8(b0, tl);
        b1 = vqtbl1q_u8(b1, tl);
        b2 = vqtbl1q_u8(b2, tl);
        b3 = vqtbl1q_u8(b3, tl);

        b0 = vzip1q_u8(b0, b1);
        b2 = vzip1q_u8(b2, b3);
        tl = vreinterpretq_u8_u16(vzip1q_u16(vreinterpretq_u16_u8(b0),
                                             vreinterpretq_u16_u8(b2)));

        b0 = vld1q_u8(snow3g_MULa_byte0_hi);
        b1 = vld1q_u8(snow3g_MULa_byte1_hi);
        b2 = vld1q_u8(snow3g_MULa_byte2_hi);
        b3 = vld1q_u8(snow3g_MULa_byte3_hi);

        th = vshrq_n_u8(th, 4) & low_nibble_mask;

        b0 = vqtbl1q_u8(b0, th);
        b1 = vqtbl1q_u8(b1, th);
        b2 = vqtbl1q_u8(b2, th);
        b3 = vqtbl1q_u8(b3, th);

        b0 = vzip1q_u8(b0, b1);
        b2 = vzip1q_u8(b2, b3);
        th = vreinterpretq_u8_u16(vzip1q_u16(vreinterpretq_u16_u8(b0),
                                             vreinterpretq_u16_u8(b2)));

        return vreinterpretq_u32_u8(th ^ tl);
#else
        const uint8_t L0IDX0 = vgetq_lane_u8(vreinterpretq_u8_u32(L0), 3);
        const uint8_t L0IDX1 = vgetq_lane_u8(vreinterpretq_u8_u32(L0), 7);
        const uint8_t L0IDX2 = vgetq_lane_u8(vreinterpretq_u8_u32(L0), 11);
        const uint8_t L0IDX3 = vgetq_lane_u8(vreinterpretq_u8_u32(L0), 15);

        uint32x4_t ret;
        uint32_t x0, x1, x2, x3;

        x0 = snow3g_table_A_mul[L0IDX0];
        x1 = snow3g_table_A_mul[L0IDX1];
        x2 = snow3g_table_A_mul[L0IDX2];
        x3 = snow3g_table_A_mul[L0IDX3];

        ret = vdupq_n_u32(x0);
        ret = vsetq_lane_u32(x1, ret, 1);
        ret = vsetq_lane_u32(x2, ret, 2);
        ret = vsetq_lane_u32(x3, ret, 3);
        return ret;
#endif
}

/**
 * @brief MULalpha SNOW3G operation on 2 8-bit values at the same time
 *
 * @param [in/out] L0_1  On input, 32-bit LFSR[0].
 *                       On output, 32-bit MULalpha(L0 >> 24)
 * @param [in/out] L0_2  On input, 32-bit LFSR[0].
 *                       On output, 32-bit MULalpha(L0 >> 24)
 */
static inline
void MULa_2(uint32_t *L0_1, uint32_t *L0_2)
{
#ifdef SAFE_LOOKUP
        uint32x4_t in, out;

        in = vdupq_n_u32(*L0_1);
        in = vsetq_lane_u32(*L0_2, in, 1);
        out = MULa_4(in);

        *L0_1 = vgetq_lane_u32(out, 0);
        *L0_2 = vgetq_lane_u32(out, 1);
#else
        *L0_1 = snow3g_table_A_mul[*L0_1 >> 24];
        *L0_2 = snow3g_table_A_mul[*L0_2 >> 24];
#endif
}

/**
 * @brief MULalpha SNOW3G operation on a 8-bit value.
 *
 * @param [in] L0       32-bit LFSR[0]
 * @return 32-bit MULalpha(L0 >> 24)
 */
static inline
uint32_t MULa(const uint32_t L0)
{
#ifdef SAFE_LOOKUP
        const uint32x4_t L0_vec = vdupq_n_u32(L0);

        return vgetq_lane_u32(MULa_4(L0_vec), 0);
#else
        return snow3g_table_A_mul[L0 >> 24];
#endif
}

/**
 * @brief DIValpha SNOW3G operation on 4 8-bit values at the same time
 *
 * Function picks the right byte from the register to run DIValpha operation on.
 * DIValpha is implemented through 8 16-byte tables and pshufb is used to
 * look the tables up. This approach is possible because
 * DIValpha operation has linear nature.
 * Final operation result is calculated via byte re-arrangement on
 * the lookup results and an XOR operation.
 *
 * @param [in] L11      4 x 32-bit LFSR[11]
 * @return 4 x 32-bit DIValpha(L11 & 0xff)
 */
static inline
uint32x4_t DIVa_4(const uint32x4_t L11)
{
#ifdef SAFE_LOOKUP
        const uint8_t gather_clear_mask[]= {
                        0x00,0x04,0x08,0x0c,0xff,0xff,0xff,0xff,
                        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
                        };
        const uint8x16_t low_nibble_mask = vdupq_n_u8(0x0f);
        const uint8x16_t clear_mask = vld1q_u8(gather_clear_mask);
        uint8x16_t th, tl, b0, b1, b2, b3;

        th = vqtbl1q_u8(vreinterpretq_u8_u32(L11), clear_mask);

        tl = th & low_nibble_mask;
        b0 = vld1q_u8(snow3g_DIVa_byte0_low);
        b1 = vld1q_u8(snow3g_DIVa_byte1_low);
        b2 = vld1q_u8(snow3g_DIVa_byte2_low);
        b3 = vld1q_u8(snow3g_DIVa_byte3_low);

        b0 = vqtbl1q_u8(b0, tl);
        b1 = vqtbl1q_u8(b1, tl);
        b2 = vqtbl1q_u8(b2, tl);
        b3 = vqtbl1q_u8(b3, tl);

        b0 = vzip1q_u8(b0, b1);
        b2 = vzip1q_u8(b2, b3);
        tl = vreinterpretq_u8_u16(vzip1q_u16(vreinterpretq_u16_u8(b0),
                                             vreinterpretq_u16_u8(b2)));

        b0 = vld1q_u8(snow3g_DIVa_byte0_hi);
        b1 = vld1q_u8(snow3g_DIVa_byte1_hi);
        b2 = vld1q_u8(snow3g_DIVa_byte2_hi);
        b3 = vld1q_u8(snow3g_DIVa_byte3_hi);

        th = vshrq_n_u8(th, 4) & low_nibble_mask;

        b0 = vqtbl1q_u8(b0, th);
        b1 = vqtbl1q_u8(b1, th);
        b2 = vqtbl1q_u8(b2, th);
        b3 = vqtbl1q_u8(b3, th);

        b0 = vzip1q_u8(b0, b1);
        b2 = vzip1q_u8(b2, b3);
        th = vreinterpretq_u8_u16(vzip1q_u16(vreinterpretq_u16_u8(b0),
                                             vreinterpretq_u16_u8(b2)));

        return vreinterpretq_u32_u8(th ^ tl);
#else
        const uint8_t L11IDX0 = vgetq_lane_u8(vreinterpretq_u8_u32(L11), 0);
        const uint8_t L11IDX1 = vgetq_lane_u8(vreinterpretq_u8_u32(L11), 4);
        const uint8_t L11IDX2 = vgetq_lane_u8(vreinterpretq_u8_u32(L11), 8);
        const uint8_t L11IDX3 = vgetq_lane_u8(vreinterpretq_u8_u32(L11), 12);

        uint32x4_t ret;
        uint32_t x0, x1, x2, x3;

        x0 = snow3g_table_A_div[L11IDX0];
        x1 = snow3g_table_A_div[L11IDX1];
        x2 = snow3g_table_A_div[L11IDX2];
        x3 = snow3g_table_A_div[L11IDX3];

        ret = vdupq_n_u32(x0);
        ret = vsetq_lane_u32(x1, ret, 1);
        ret = vsetq_lane_u32(x2, ret, 2);
        ret = vsetq_lane_u32(x3, ret, 3);

        return ret;
#endif
}

/**
 * @brief DIValpha SNOW3G operation on 2 8-bit values at the same time
 *
 * @param [in/out] L11_1 On input, 32-bit LFSR[11].
 *                       On output, 32-bit DIValpha(L11 & 0xff)
 * @param [in/out] L11_2 On input, 32-bit LFSR[11].
 *                       On output, 32-bit DIValpha(L11 & 0xff)
 */
static inline
void DIVa_2(uint32_t *L11_1, uint32_t *L11_2)
{
#ifdef SAFE_LOOKUP
        uint32x4_t in, out;

        in = vdupq_n_u32(*L11_1);
        in = vsetq_lane_u32(*L11_2, in, 1);
        out = DIVa_4(in);

        *L11_1 = vgetq_lane_u32(out, 0);
        *L11_2 = vgetq_lane_u32(out, 1);
#else
        *L11_1 = snow3g_table_A_div[*L11_1 & 0xff];
        *L11_2 = snow3g_table_A_div[*L11_2 & 0xff];
#endif
}

/**
 * @brief DIValpha SNOW3G operation on a 8-bit value.
 *
 * @param [in] L11       32-bit LFSR[11]
 * @return 32-bit DIValpha(L11 & 0xff)
 */
static inline
uint32_t DIVa(const uint32_t L11)
{
#ifdef SAFE_LOOKUP
        const uint32x4_t L11_vec = vdupq_n_u32(L11);

        return vgetq_lane_u32(DIVa_4(L11_vec), 0);
#else
        return snow3g_table_A_div[L11 & 0xff];
#endif
}

/**
 * @brief ClockFSM function as defined in SNOW3G standard
 *
 * The FSM has 2 input words S5 and S15 from the LFSR
 * produces a 32 bit output word F.
 *
 * @param[in/out] pCtx  context structure
 */
static inline uint32_t ClockFSM_1(snow3gKeyState1_t *pCtx)
{
        const uint32_t F = (pCtx->LFSR_S[15] + pCtx->FSM_R1) ^ pCtx->FSM_R2;
        const uint32_t R = (pCtx->FSM_R3 ^ pCtx->LFSR_S[5]) + pCtx->FSM_R2;

        pCtx->FSM_R3 = S2_box(pCtx->FSM_R2);
        pCtx->FSM_R2 = S1_box(pCtx->FSM_R1);
        pCtx->FSM_R1 = R;

        return F;
}

/**
 * @brief ClockLFSR function as defined in SNOW3G standard
 * @param[in/out] pCtx  context structure
 */
static inline void ClockLFSR_1(snow3gKeyState1_t *pCtx)
{
        const uint32_t S0 = pCtx->LFSR_S[0];
        const uint32_t S11 = pCtx->LFSR_S[11];
        const uint32_t V = pCtx->LFSR_S[2] ^
                MULa(S0) ^
                DIVa(S11) ^
                (S0 << 8) ^
                (S11 >> 8);
        unsigned i;

        /* LFSR array shift by 1 position */
        for (i = 0; i < 15; i++)
                pCtx->LFSR_S[i] = pCtx->LFSR_S[i + 1];

        pCtx->LFSR_S[15] = V;
}

/**
 * @brief Initializes the key schedule for 1 buffer for SNOW3G f8/f9.
 *
 * @param[in/out]  pCtx        Context where the scheduled keys are stored
 * @param[in]      pKeySched   Key schedule
 * @param[in]      pIV         IV
 */
static inline void
snow3gStateInitialize_1(snow3gKeyState1_t *pCtx,
                        const snow3g_key_schedule_t *pKeySched,
                        const void *pIV)
{
        uint32_t FSM1, FSM2, FSM3;
        const uint32_t *pIV32 = pIV;
        int i;

        /* LFSR initialisation */
        for (i = 0; i < 4; i++) {
                const uint32_t K = pKeySched->k[i];
                const uint32_t L = ~K;

                pCtx->LFSR_S[i + 4] = K;
                pCtx->LFSR_S[i + 12] = K;
                pCtx->LFSR_S[i + 0] = L;
                pCtx->LFSR_S[i + 8] = L;
        }

        pCtx->LFSR_S[15] ^= BSWAP32(pIV32[3]);
        pCtx->LFSR_S[12] ^= BSWAP32(pIV32[2]);
        pCtx->LFSR_S[10] ^= BSWAP32(pIV32[1]);
        pCtx->LFSR_S[9] ^= BSWAP32(pIV32[0]);

        /* FSM initialization */
        FSM2 = 0;
        FSM3 = 0;
        FSM1 = 0;

        for (i = 0; i < 16; i++) {
                const uint32_t L0 = pCtx->LFSR_S[0];
                const uint32_t L1 = pCtx->LFSR_S[1];
                const uint32_t L11 = pCtx->LFSR_S[11];
                const uint32_t L12 = pCtx->LFSR_S[12];
                uint32_t MULa_L0 = L0;
                uint32_t MULa_L1 = L1;
                uint32_t DIVa_L11 = L11;
                uint32_t DIVa_L12 = L12;

                MULa_2(&MULa_L0, &MULa_L1);
                DIVa_2(&DIVa_L11, &DIVa_L12);

                /* clock FSM + clock LFSR + clockFSM + clock LFSR */
                const uint32_t F0 =
                        (pCtx->LFSR_S[15] + FSM1) ^ FSM2; /* (s15 + R1) ^ R2 */

                const uint32_t V0 =
                        pCtx->LFSR_S[2] ^
                        MULa_L0 ^ /* MUL(s0,0 ) */
                        DIVa_L11 ^ /* DIV(s11,3 )*/
                        (L0 << 8) ^ /*  (s0,1 || s0,2 || s0,3 || 0x00) */
                        (L11 >> 8) ^ /* (0x00 || s11,0 || s11,1 || s11,2 ) */
                        F0;

                const uint32_t R0 =
                        (FSM3 ^ pCtx->LFSR_S[5]) + FSM2; /* R2 + (R3 ^ s5 ) */

                uint32_t s1_box_step1 = FSM1;
                uint32_t s1_box_step2 = R0;

                S1_box_2(&s1_box_step1, &s1_box_step2);

                uint32_t s2_box_step1 = FSM2;
                uint32_t s2_box_step2 = s1_box_step1; /* S1_box(R0) */

                S2_box_2(&s2_box_step1, &s2_box_step2);

                FSM1 = (s2_box_step1 ^ pCtx->LFSR_S[6]) + s1_box_step1;

                const uint32_t F1 = (V0 + R0) ^ s1_box_step1;

                const uint32_t V1 = pCtx->LFSR_S[3] ^
                             MULa_L1 ^
                             DIVa_L12 ^
                             (L1 << 8) ^ (L12 >> 8) ^ F1;

                FSM2 = s1_box_step2;
                FSM3 = s2_box_step2;

                /* shift LFSR twice */
                ShiftTwiceLFSR_1(pCtx);

                pCtx->LFSR_S[14] = V0;
                pCtx->LFSR_S[15] = V1;
        }

        /* set FSM into scheduling structure */
        pCtx->FSM_R3 = FSM3;
        pCtx->FSM_R2 = FSM2;
        pCtx->FSM_R1 = FSM1;
}

/**
 * @brief Generates 5 words of key stream used in the initial stages of F9.
 *
 * @param[in]     pCtx        Context where the scheduled keys are stored
 * @param[in/out] pKeyStream  Pointer to the generated keystream
 */
static inline void snow3g_f9_keystream_words(snow3gKeyState1_t *pCtx,
                                             uint32_t *pKeyStream)
{
        int i;

        (void) ClockFSM_1(pCtx);
        ClockLFSR_1(pCtx);

        for (i = 0; i < 5; i++) {
                pKeyStream[i] = ClockFSM_1(pCtx) ^ pCtx->LFSR_S[0];
                ClockLFSR_1(pCtx);
        }
}

/**
 * @brief LFSR array shift by one (4 lanes)
 * @param[in]     pCtx       Context where the scheduled keys are stored
 */
static inline void ShiftLFSR_4(snow3gKeyState4_t *pCtx)
{
        pCtx->iLFSR_X = (pCtx->iLFSR_X + 1) & 15;
}

/**
 * @brief GF2 modular reduction 128-bits to 64-bits
 *
 * SNOW3GCONSTANT/0x1b reduction polynomial applied.
 *
 * @param[in] m   128-bit input
 * @return 128-bit output (only least significant 64-bits are valid)
 */
static inline poly64x2_t reduce128_to_64(const poly64x2_t m)
{
        const poly64x1_t p = vdup_n_p64((poly64_t)SNOW3GCONSTANT);
        poly64x2_t x, t;

        /* start reduction */
        /* top 64-bits of m x p */
        x = (poly64x2_t)vmull_p64(vgetq_lane_p64(m, 1), (poly64_t)p);
        t = m ^ x;

        /*
         * repeat multiply and xor in case
         * 'x' product was bigger than 64 bits
         */
        x = (poly64x2_t)vmull_p64(vgetq_lane_p64(x, 1), (poly64_t)p);
        t = t ^ x;

        return t;
}

/**
 * @brief GF2 modular multiplication 64-bits x 64-bits with reduction
 *
 * Implements MUL64 function from the standard.
 * SNOW3GCONSTANT/0x1b reduction polynomial applied.
 *
 * @param[in] a   64-bit input
 * @param[in] b   64-bit input
 * @return 64-bit output
 */
static inline uint64_t multiply_and_reduce64(uint64_t a, uint64_t b)
{
        poly64x2_t m;

        m = (poly64x2_t)vmull_p64(a, b);  /*  m = a x b */

        m = reduce128_to_64(m); /* reduction */

        return vgetq_lane_u64(vreinterpretq_u64_p64(m), 0);
}

/**
 * @brief ClockLFSR sub-function as defined in SNOW3G standard (4 lanes)
 *
 * @param[in] L0        LFSR[0]
 * @param[in] L11       LFSR[11]
 * @return table_Alpha_div[LFSR[11] & 0xff] ^ table_Alpha_mul[LFSR[0] & 0xff]
 */
static inline uint32x4_t C0_C11_4(const uint32x4_t L0, const uint32x4_t L11)
{
        const uint32x4_t SL11 = DIVa_4(L11);
        const uint32x4_t SL0 = MULa_4(L0);

        return SL11 ^ SL0;
}

/**
 * @brief ClockLFSR function as defined in SNOW3G standard (4 lanes)
 *
 * S =  table_Alpha_div[LFSR[11] & 0xff]
 *       ^ table_Alpha_mul[LFSR[0] >> 24]
 *       ^ LFSR[2] ^ LFSR[0] << 8 ^ LFSR[11] >> 8
 *
 * @param[in]     pCtx       Context where the scheduled keys are stored
 */
static inline void ClockLFSR_4(snow3gKeyState4_t *pCtx)
{
        uint32x4_t S, T, U;


        U = pCtx->LFSR_X[pCtx->iLFSR_X];
        S = pCtx->LFSR_X[(pCtx->iLFSR_X + 11) & 15];
        const uint32x4_t X2 = C0_C11_4(U, S);

        T = vshlq_n_u32(U, 8);
        S = vshrq_n_u32(S, 8);
        U = T ^ pCtx->LFSR_X[(pCtx->iLFSR_X + 2) & 15];
        ShiftLFSR_4(pCtx);

        S = S ^ U;
        S = S ^ X2;
        pCtx->LFSR_X[(pCtx->iLFSR_X + 15) & 15] = S;
}

/**
 * @brief ClockFSM function as defined in SNOW3G standard
 *
 * It operates on 4 packets/lanes at a time
 *
 * @param[in]     pCtx       Context where the scheduled keys are stored
 * @return 4 x 4bytes of key stream
 */
static inline uint32x4_t ClockFSM_4(snow3gKeyState4_t *pCtx)
{
        const uint32_t iLFSR_X = pCtx->iLFSR_X;
        const uint32x4_t F =
                pCtx->LFSR_X[(iLFSR_X + 15) & 15] + pCtx->FSM_X[0];
        const uint32x4_t R =
                vaddq_u32(pCtx->LFSR_X[(iLFSR_X + 5) & 15] ^ pCtx->FSM_X[2],
                              pCtx->FSM_X[1]);

        const uint32x4_t ret = F ^ pCtx->FSM_X[1];

        pCtx->FSM_X[2] = S2_box_4(pCtx->FSM_X[1]);
        pCtx->FSM_X[1] = S1_box_4(pCtx->FSM_X[0]);
        pCtx->FSM_X[0] = R;

        return ret;
}

/**
 * @brief Generates 4 bytes of key stream 1 buffer at a time
 *
 * @param[in]     pCtx       Context where the scheduled keys are stored
 * @return 4 bytes of key stream
 */
static inline uint32_t snow3g_keystream_1_4(snow3gKeyState1_t *pCtx)
{
        const uint32_t F = ClockFSM_1(pCtx);
        const uint32_t ks = F ^ pCtx->LFSR_S[0];

        ClockLFSR_1(pCtx);
        return ks;
}

/**
 * @brief Generates 8 bytes of key stream for 1 buffer at a time
 *
 * @param[in] pCtx Context where the scheduled keys are stored
 * @return 8 bytes of a key stream
 */
static inline uint64_t snow3g_keystream_1_8(snow3gKeyState1_t *pCtx)
{
        /*
         * Merged clock FSM + clock LFSR + clock FSM + clockLFSR
         * in order to avoid redundancies in function processing
         * and less instruction immediate dependencies
         */
        const uint32_t L0 = pCtx->LFSR_S[0];
        const uint32_t L1 = pCtx->LFSR_S[1];
        const uint32_t L11 = pCtx->LFSR_S[11];
        const uint32_t L12 = pCtx->LFSR_S[12];
        uint32_t MULa_L0 = L0;
        uint32_t MULa_L1 = L1;
        uint32_t DIVa_L11 = L11;
        uint32_t DIVa_L12 = L12;

        MULa_2(&MULa_L0, &MULa_L1);
        DIVa_2(&DIVa_L11, &DIVa_L12);

        const uint32_t V0 =
                pCtx->LFSR_S[2] ^
                MULa_L0 ^
                DIVa_L11 ^
                (L0 << 8) ^
                (L11 >> 8);

        const uint32_t V1 =
                pCtx->LFSR_S[3] ^
                MULa_L1 ^
                DIVa_L12 ^
                (L1 << 8) ^
                (L12 >> 8);

        const uint32_t F0 =
                (pCtx->LFSR_S[15] + pCtx->FSM_R1) ^ L0 ^ pCtx->FSM_R2;
        const uint32_t R0 =
                (pCtx->FSM_R3 ^ pCtx->LFSR_S[5]) + pCtx->FSM_R2;

        uint32_t s1_box_step1 = pCtx->FSM_R1;
        uint32_t s1_box_step2 = R0;

        S1_box_2(&s1_box_step1, &s1_box_step2);

        uint32_t s2_box_step1 = pCtx->FSM_R2;
        uint32_t s2_box_step2 = s1_box_step1;

        S2_box_2(&s2_box_step1, &s2_box_step2);

        /*
         * At this stage FSM_R mapping is as follows:
         *    FSM_R2 = s1_box_step1
         *    FSM_R3 = s2_box_step1
         */
        const uint32_t F1 = (V0 + R0) ^ L1 ^ s1_box_step1;

        pCtx->FSM_R3 = s2_box_step2;
        pCtx->FSM_R2 = s1_box_step2;
        pCtx->FSM_R1 = (s2_box_step1 ^ pCtx->LFSR_S[6]) + s1_box_step1;

        /* Shift LFSR twice */
        ShiftTwiceLFSR_1(pCtx);

        /* key stream mode LFSR update */
        pCtx->LFSR_S[14] = V0;
        pCtx->LFSR_S[15] = V1;

        return (((uint64_t) F0) << 32) | ((uint64_t) F1);
}


/**
 * @brief Generates 4 bytes of key stream 4 buffers at a time
 *
 * @param[in]      pCtx         Context where the scheduled keys are stored
 * @param[in/out]  pKeyStream   Pointer to generated key stream
 */
static inline uint32x4_t snow3g_keystream_4_4(snow3gKeyState4_t *pCtx)
{
        const uint32x4_t keyStream =
                        ClockFSM_4(pCtx) ^ pCtx->LFSR_X[pCtx->iLFSR_X];

        ClockLFSR_4(pCtx);
        return keyStream;
}

/**
 * @brief Generates 8 bytes of key stream 4 buffers at a time
 *
 * @param[in]      pCtx         Context where the scheduled keys are stored
 * @param[in/out]  pKeyStreamLo Pointer to lower end of generated key stream
 * @param[in/out]  pKeyStreamHi Pointer to higher end of generated key stream
 */
static inline void snow3g_keystream_4_8(snow3gKeyState4_t *pCtx,
                                        uint32x4_t *pKeyStreamLo,
                                        uint32x4_t *pKeyStreamHi)
{
        const uint32x4_t L0 = pCtx->LFSR_X[pCtx->iLFSR_X];
        const uint32x4_t L2 = pCtx->LFSR_X[(pCtx->iLFSR_X + 2) & 15];
        const uint32x4_t L11 = pCtx->LFSR_X[(pCtx->iLFSR_X + 11) & 15];

        const uint32x4_t L1= pCtx->LFSR_X[(pCtx->iLFSR_X + 1) & 15];
        const uint32x4_t L3 = pCtx->LFSR_X[(pCtx->iLFSR_X + 3) & 15];
        const uint32x4_t L12 = pCtx->LFSR_X[(pCtx->iLFSR_X + 12) & 15];

        const uint32x4_t L5 = pCtx->LFSR_X[(pCtx->iLFSR_X + 5) & 15];
        const uint32x4_t L6 = pCtx->LFSR_X[(pCtx->iLFSR_X + 6) & 15];
        const uint32x4_t L15 = pCtx->LFSR_X[(pCtx->iLFSR_X + 15) & 15];

        const uint32x4_t V0 = veorq_u32(veorq_u32(C0_C11_4(L0, L11), L2),
                                        veorq_u32(vshlq_n_u32(L0, 8),
                                                  vshrq_n_u32(L11, 8)));

        const uint32x4_t V1 = veorq_u32(veorq_u32(C0_C11_4(L1, L12), L3),
                                        veorq_u32(vshlq_n_u32(L1, 8),
                                                  vshrq_n_u32(L12, 8)));

        /* ======== first set of 4 bytes */

        const uint32x4_t s1_box_step1 = S1_box_4(pCtx->FSM_X[0]); /* do early */

        const uint32x4_t R0 = vaddq_u32(veorq_u32(L5, pCtx->FSM_X[2]),
                                        pCtx->FSM_X[1]);

        const uint32x4_t F0 = veorq_u32(vaddq_u32(L15, pCtx->FSM_X[0]),
                                        pCtx->FSM_X[1]);
        const uint32x4_t L = F0 ^ L0;

        const uint32x4_t F1 = veorq_u32(vaddq_u32(V0, R0), s1_box_step1);
        const uint32x4_t H = F1 ^ L1;

        /* Merge L & H sets for output */
        *pKeyStreamLo = vzip1q_u32(H, L);
        *pKeyStreamHi = vzip2q_u32(H, L);

        uint32x4_t s2_box_step1 = pCtx->FSM_X[1];
        uint32x4_t s2_box_step2 = s1_box_step1;

        S2_box_2x4(&s2_box_step1, &s2_box_step2);

        /*
         * At this stage FSM_X mapping is as follows:
         *    FSM_X[2] = s2_box_step1
         *    FSM_X[1] = s1_box_step1
         *    FSM_X[0] = R0
         */

        /* Shift LFSR twice */
        pCtx->iLFSR_X = (pCtx->iLFSR_X + 2) & 15;

        /* LFSR Update */
        pCtx->LFSR_X[(pCtx->iLFSR_X + 14) & 15] = V0;
        pCtx->LFSR_X[(pCtx->iLFSR_X + 15) & 15] = V1;

        const uint32x4_t s1_box_step2 = S1_box_4(R0);

        const uint32x4_t R1 = vaddq_u32(veorq_u32(L6, s2_box_step1),
                                        s1_box_step1);

        /* Final FSM_X update
         *    FSM_X[2] = s2_box_step2
         *    FSM_X[1] = s1_box_step2
         *    FSM_X[0] = R1
         */
        pCtx->FSM_X[2] = s2_box_step2;
        pCtx->FSM_X[1] = s1_box_step2;
        pCtx->FSM_X[0] = R1;
}

/**
 * @brief Generates 16 bytes of key stream 4 buffers at a time
 *
 * @param[in]     pCtx         Context where the scheduled keys are stored
 * @param[in/out] pKeyStream   Pointer to store generated key stream
 */
static inline void snow3g_keystream_4_16(snow3gKeyState4_t *pCtx,
                                         uint32x4_t pKeyStream[4])
{
        static const uint64_t sm[2] = {
                /* mask for byte swapping 64-bit words */
                0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL
        };
        uint32x4_t ksL1, ksL2, ksH1, ksH2;

        snow3g_keystream_4_8(pCtx, &ksL1, &ksH1);
        snow3g_keystream_4_8(pCtx, &ksL2, &ksH2);

        const uint8x16_t swapMask = vreinterpretq_u8_u64(vld1q_u64(sm));

        pKeyStream[0] = vreinterpretq_u32_u8(vqtbl1q_u8(
                                        vreinterpretq_u8_u64(vzip1q_u64(
                                                vreinterpretq_u64_u32(ksL1),
                                                vreinterpretq_u64_u32(ksL2))),
                                        swapMask));
        pKeyStream[1] = vreinterpretq_u32_u8(vqtbl1q_u8(
                                        vreinterpretq_u8_u64(vzip2q_u64(
                                                vreinterpretq_u64_u32(ksL1),
                                                vreinterpretq_u64_u32(ksL2))),
                                        swapMask));
        pKeyStream[2] = vreinterpretq_u32_u8(vqtbl1q_u8(
                                        vreinterpretq_u8_u64(vzip1q_u64(
                                                vreinterpretq_u64_u32(ksH1),
                                                vreinterpretq_u64_u32(ksH2))),
                                        swapMask));
        pKeyStream[3] = vreinterpretq_u32_u8(vqtbl1q_u8(
                                        vreinterpretq_u8_u64(vzip2q_u64(
                                                vreinterpretq_u64_u32(ksH1),
                                                vreinterpretq_u64_u32(ksH2))),
                                        swapMask));
}

/**
 * @brief Initializes the key schedule for 4 buffers for SNOW3G f8/f9.
 *
 * @param [in]      pCtx        Context where the scheduled keys are stored
 * @param [in]      pKeySched   Key schedule
 * @param [in]      pIV1        IV for buffer 1
 * @param [in]      pIV2        IV for buffer 2
 * @param [in]      pIV3        IV for buffer 3
 * @param [in]      pIV4        IV for buffer 4
 */
static inline void
snow3gStateInitialize_4(snow3gKeyState4_t *pCtx,
                        const snow3g_key_schedule_t *pKeySched,
                        const void *pIV1, const void *pIV2,
                        const void *pIV3, const void *pIV4)
{
        uint32x4_t R, S, T, U;
        uint32x4_t T0, T1;
        int i;

        /* Initialize the LFSR table from constants, Keys, and IV */

        /* Load complete 128b IV into register */
        static const uint64_t sm[2] = {
                0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL
        };

        R = vld1q_u32(pIV1);
        S = vld1q_u32(pIV2);
        T = vld1q_u32(pIV3);
        U = vld1q_u32(pIV4);

        /* initialize the array block */
        for (i = 0; i < 4; i++) {
                const uint32_t K = pKeySched->k[i];
                const uint32_t L = ~K;
                const uint32x4_t VK = vdupq_n_u32(K);
                const uint32x4_t VL = vdupq_n_u32(L);

                pCtx->LFSR_X[i + 4] =
                        pCtx->LFSR_X[i + 12] = VK;
                pCtx->LFSR_X[i + 0] =
                        pCtx->LFSR_X[i + 8] = VL;
        }
        /* Update the schedule structure with IVs */
        /* Store the 4 IVs in LFSR by a column/row matrix swap
         * after endianness correction */

        /* endianness swap */
        const uint64x2_t swapMask = vld1q_u64(sm);

        R = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(R),
                                        vreinterpretq_u8_u64(swapMask)));
        S = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(S),
                                        vreinterpretq_u8_u64(swapMask)));
        T = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(T),
                                        vreinterpretq_u8_u64(swapMask)));
        U = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(U),
                                        vreinterpretq_u8_u64(swapMask)));

        /* row/column dword inversion */
        T0 = vzip1q_u32(R, S);
        R = vzip2q_u32(R, S);
        T1 = vzip1q_u32(T, U);
        T = vzip2q_u32(T, U);

        /* row/column qword inversion */
        U = vreinterpretq_u32_u64(vzip2q_u64(vreinterpretq_u64_u32(R),
                                        vreinterpretq_u64_u32(T)));
        T = vreinterpretq_u32_u64(vzip1q_u64(vreinterpretq_u64_u32(R),
                                        vreinterpretq_u64_u32(T)));
        S = vreinterpretq_u32_u64(vzip2q_u64(vreinterpretq_u64_u32(T0),
                                        vreinterpretq_u64_u32(T1)));
        R = vreinterpretq_u32_u64(vzip1q_u64(vreinterpretq_u64_u32(T0),
                                        vreinterpretq_u64_u32(T1)));

        /* IV ^ LFSR */
        pCtx->LFSR_X[15] = pCtx->LFSR_X[15] ^ U;
        pCtx->LFSR_X[12] = pCtx->LFSR_X[12] ^ T;
        pCtx->LFSR_X[10] = pCtx->LFSR_X[10] ^ S;
        pCtx->LFSR_X[9] = pCtx->LFSR_X[9] ^ R;
        pCtx->iLFSR_X = 0;

        /* FSM initialization */
        pCtx->FSM_X[0] = pCtx->FSM_X[1] =
                pCtx->FSM_X[2] = vdupq_n_u32(0);

        /* Initialisation rounds */
        for (i = 0; i < 32; i++) {
                T1 = ClockFSM_4(pCtx);

                ClockLFSR_4(pCtx);
                pCtx->LFSR_X[(pCtx->iLFSR_X + 15) & 15] =
                        pCtx->LFSR_X[(pCtx->iLFSR_X + 15) & 15] ^ T1;
        }
}


static inline void
preserve_bits(uint64_t *KS,
              const uint8_t *pcBufferOut, const uint8_t *pcBufferIn,
              SafeBuf *safeOutBuf, SafeBuf *safeInBuf,
              const uint8_t bit_len, const uint8_t byte_len)
{
        const uint64_t mask = UINT64_MAX << (SNOW3G_BLOCK_SIZE * 8 - bit_len);

        /* Clear the last bits of the key stream and the input
         * (input only in out-of-place case) */
        *KS &= mask;
        if (pcBufferIn != pcBufferOut) {
                const uint64_t swapMask = BSWAP64(mask);

                safeInBuf->b64 &= swapMask;

                /*
                 * Merge the last bits from the output, to be preserved,
                 * in the key stream, to be XOR'd with the input
                 * (which last bits are 0, maintaining the output bits)
                 */
                memcpy_keystrm(safeOutBuf->b8, pcBufferOut, byte_len);
                *KS |= BSWAP64(safeOutBuf->b64 & ~swapMask);
        }
}

/**
 * @brief Core SNOW3G F8 bit algorithm for the 3GPP confidentiality algorithm
 *
 * @param[in]    pCtx          Context where the scheduled keys are stored
 * @param[in]    pIn           Input buffer
 * @param[out]   pOut          Output buffer
 * @param[in]    lengthInBits  length in bits of the data to be encrypted
 * @param[in]    offsetinBits  offset in input buffer, where data are valid
 */
static inline void f8_snow3g_bit(snow3gKeyState1_t *pCtx,
                                 const void *pIn,
                                 void *pOut,
                                 const uint32_t lengthInBits,
                                 const uint32_t offsetInBits)
{
        const uint8_t *pBufferIn = pIn;
        uint8_t *pBufferOut = pOut;
        uint32_t cipherLengthInBits = lengthInBits;
        uint64_t shiftrem = 0;
        uint64_t KS8, KS8bit; /* 8 bytes of key stream */
        const uint8_t *pcBufferIn = pBufferIn + (offsetInBits / 8);
        uint8_t *pcBufferOut = pBufferOut + (offsetInBits / 8);
        /* Offset into the first byte (0 - 7 bits) */
        uint32_t remainOffset = offsetInBits % 8;
        uint32_t byteLength = (cipherLengthInBits + 7) / 8;
        SafeBuf safeInBuf = {0};
        SafeBuf safeOutBuf = {0};

        /* Now run the block cipher */

        /* Start with potential partial block (due to offset and length) */
        KS8 = snow3g_keystream_1_8(pCtx);
        KS8bit = KS8 >> remainOffset;

        /* Only one block to encrypt */
        if (cipherLengthInBits < (64 - remainOffset)) {
                byteLength = (cipherLengthInBits + 7) / 8;
                memcpy_keystrm(safeInBuf.b8, pcBufferIn, byteLength);
                /*
                 * If operation is Out-of-place and there is offset
                 * to be applied, "remainOffset" bits from the output buffer
                 * need to be preserved (only applicable to first byte,
                 * since remainOffset is up to 7 bits)
                 */
                if ((pIn != pOut) && remainOffset) {
                        const uint8_t mask8 = (uint8_t)
                                (1 << (8 - remainOffset)) - 1;

                        safeInBuf.b8[0] = (safeInBuf.b8[0] & mask8) |
                                (pcBufferOut[0] & ~mask8);
                }
                /* If last byte is a partial byte, the last bits of the output
                 * need to be preserved */
                const uint8_t bitlen_with_off = remainOffset +
                        cipherLengthInBits;

                if ((bitlen_with_off & 0x7) != 0)
                        preserve_bits(&KS8bit, pcBufferOut, pcBufferIn,
                                      &safeOutBuf, &safeInBuf,
                                      bitlen_with_off, byteLength);

                xor_keystrm_rev(safeOutBuf.b8, safeInBuf.b8, KS8bit);
                memcpy_keystrm(pcBufferOut, safeOutBuf.b8, byteLength);
                return;
        }
        /*
         * If operation is Out-of-place and there is offset
         * to be applied, "remainOffset" bits from the output buffer
         * need to be preserved (only applicable to first byte,
         * since remainOffset is up to 7 bits)
         */
        if ((pIn != pOut) && remainOffset) {
                const uint8_t mask8 = (uint8_t)(1 << (8 - remainOffset)) - 1;

                memcpy_keystrm(safeInBuf.b8, pcBufferIn, 8);
                safeInBuf.b8[0] = (safeInBuf.b8[0] & mask8) |
                        (pcBufferOut[0] & ~mask8);
                xor_keystrm_rev(pcBufferOut, safeInBuf.b8, KS8bit);
                pcBufferIn += SNOW3G_BLOCK_SIZE;
        } else {
                /* At least 64 bits to produce (including offset) */
                pcBufferIn = xor_keystrm_rev(pcBufferOut, pcBufferIn, KS8bit);
        }

        if (remainOffset != 0)
                shiftrem = KS8 << (64 - remainOffset);
        cipherLengthInBits -= SNOW3G_BLOCK_SIZE * 8 - remainOffset;
        pcBufferOut += SNOW3G_BLOCK_SIZE;

        while (cipherLengthInBits) {
                /* produce the next block of key stream */
                KS8 = snow3g_keystream_1_8(pCtx);
                KS8bit = (KS8 >> remainOffset) | shiftrem;
                if (remainOffset != 0)
                        shiftrem = KS8 << (64 - remainOffset);
                if (cipherLengthInBits >= SNOW3G_BLOCK_SIZE * 8) {
                        pcBufferIn = xor_keystrm_rev(pcBufferOut,
                                                     pcBufferIn, KS8bit);
                        cipherLengthInBits -= SNOW3G_BLOCK_SIZE * 8;
                        pcBufferOut += SNOW3G_BLOCK_SIZE;
                        /* loop variant */
                } else {
                        /* end of the loop, handle the last bytes */
                        byteLength = (cipherLengthInBits + 7) / 8;
                        memcpy_keystrm(safeInBuf.b8, pcBufferIn,
                                       byteLength);

                        /* If last byte is a partial byte, the last bits
                         * of the output need to be preserved */
                        if ((cipherLengthInBits & 0x7) != 0)
                                preserve_bits(&KS8bit, pcBufferOut, pcBufferIn,
                                              &safeOutBuf, &safeInBuf,
                                              cipherLengthInBits, byteLength);

                        xor_keystrm_rev(safeOutBuf.b8, safeInBuf.b8, KS8bit);
                        memcpy_keystrm(pcBufferOut, safeOutBuf.b8, byteLength);
                        cipherLengthInBits = 0;
                }
        }
#ifdef SAFE_DATA
        CLEAR_VAR(&KS8, sizeof(KS8));
        CLEAR_VAR(&KS8bit, sizeof(KS8bit));
        CLEAR_MEM(&safeInBuf, sizeof(safeInBuf));
        CLEAR_MEM(&safeOutBuf, sizeof(safeOutBuf));
#endif
}

/**
 * @brief Core SNOW3G F8 algorithm for the 3GPP confidentiality algorithm
 *
 * @param[in]  pCtx           Context where the scheduled keys are stored
 * @param[in]  pIn            Input buffer
 * @param[out] pOut           Output buffer
 * @param[in]  lengthInBytes  length in bytes of the data to be encrypted
 */
static inline void f8_snow3g(snow3gKeyState1_t *pCtx,
                             const void *pIn,
                             void *pOut,
                             const uint32_t lengthInBytes)
{
        uint32_t qwords = lengthInBytes / SNOW3G_8_BYTES; /* number of qwords */
        const uint32_t words = lengthInBytes & 4; /* remaining word if not 0 */
        const uint32_t bytes = lengthInBytes & 3; /* remaining bytes */
        uint32_t KS4;                       /* 4 bytes of key stream */
        uint64_t KS8;                       /* 8 bytes of key stream */
        const uint8_t *pBufferIn = pIn;
        uint8_t *pBufferOut = pOut;

        /* process 64 bits at a time */
        while (qwords--) {
                /* generate key stream 8 bytes at a time */
                KS8 = snow3g_keystream_1_8(pCtx);

                /* xor key stream 8 bytes at a time */
                pBufferIn = xor_keystrm_rev(pBufferOut, pBufferIn, KS8);
                pBufferOut += SNOW3G_8_BYTES;
        }

        /* check for remaining 0 to 7 bytes */
        if (0 != words) {
                if (bytes) {
                        /* 5 to 7 last bytes, process 8 bytes */
                        uint8_t buftemp[8];
                        uint8_t safeBuff[8];

                        memset(safeBuff, 0, SNOW3G_8_BYTES);
                        KS8 = snow3g_keystream_1_8(pCtx);
                        memcpy_keystrm(safeBuff, pBufferIn, 4 + bytes);
                        xor_keystrm_rev(buftemp, safeBuff, KS8);
                        memcpy_keystrm(pBufferOut, buftemp, 4 + bytes);
#ifdef SAFE_DATA
                        CLEAR_MEM(&safeBuff, sizeof(safeBuff));
                        CLEAR_MEM(&buftemp, sizeof(buftemp));
#endif
                } else {
                        /* exactly 4 last bytes */
                        KS4 = snow3g_keystream_1_4(pCtx);
                        xor_keystream_reverse_32(pBufferOut, pBufferIn, KS4);
                }
        } else if (0 != bytes) {
                /* 1 to 3 last bytes */
                uint8_t buftemp[4];
                uint8_t safeBuff[4];

                memset(safeBuff, 0, SNOW3G_4_BYTES);
                KS4 = snow3g_keystream_1_4(pCtx);
                memcpy_keystream_32(safeBuff, pBufferIn, bytes);
                xor_keystream_reverse_32(buftemp, safeBuff, KS4);
                memcpy_keystream_32(pBufferOut, buftemp, bytes);
#ifdef SAFE_DATA
                CLEAR_MEM(&safeBuff, sizeof(safeBuff));
                CLEAR_MEM(&buftemp, sizeof(buftemp));
#endif
        }

#ifdef SAFE_DATA
        CLEAR_VAR(&KS4, sizeof(KS4));
        CLEAR_VAR(&KS8, sizeof(KS8));
#endif
}

/**
 * @brief Extracts one state from a 4 buffer state structure.
 *
 * @param[in]  pSrcState   Pointer to the source state
 * @param[in]  pDstState   Pointer to the destination state
 * @param[in]  NumBuffer   Buffer number
 */
static inline void snow3gStateConvert_4(const snow3gKeyState4_t *pSrcState,
                                        snow3gKeyState1_t *pDstState,
                                        const uint32_t NumBuffer)
{
        const uint32_t iLFSR_X = pSrcState->iLFSR_X;
        const uint32x4_t *LFSR_X = pSrcState->LFSR_X;
        uint32_t i;

        for (i = 0; i < 16; i++) {
                const uint32_t *pLFSR_X =
                        (const uint32_t *) &LFSR_X[(i + iLFSR_X) & 15];

                pDstState->LFSR_S[i] = pLFSR_X[NumBuffer];
        }

        const uint32_t *pFSM_X0 = (const uint32_t *)&pSrcState->FSM_X[0];
        const uint32_t *pFSM_X1 = (const uint32_t *)&pSrcState->FSM_X[1];
        const uint32_t *pFSM_X2 = (const uint32_t *)&pSrcState->FSM_X[2];

        pDstState->FSM_R1 = pFSM_X0[NumBuffer];
        pDstState->FSM_R2 = pFSM_X1[NumBuffer];
        pDstState->FSM_R3 = pFSM_X2[NumBuffer];
}

/**
 * @brief Provides size of key schedule structure
 * @return Key schedule structure in bytes
 */
size_t SNOW3G_KEY_SCHED_SIZE(void)
{
        return sizeof(snow3g_key_schedule_t);
}

/**
 * @brief Key schedule initialisation
 * @param[in]  pKey  pointer to a 16-byte key
 * @param[out] pCtx  pointer to key schedule structure
 * @return Operation status
 * @retval 0 all OK
 * @retval -1 parameter error
 */
int SNOW3G_INIT_KEY_SCHED(const void *pKey, snow3g_key_schedule_t *pCtx)
{
#ifdef SAFE_PARAM
        if ((pKey == NULL) || (pCtx == NULL))
                return -1;
#endif

        const uint32_t *pKey32 = pKey;

        pCtx->k[3] = BSWAP32(pKey32[0]);
        pCtx->k[2] = BSWAP32(pKey32[1]);
        pCtx->k[1] = BSWAP32(pKey32[2]);
        pCtx->k[0] = BSWAP32(pKey32[3]);

        return 0;
}

/**
 * @brief Single buffer F8 encrypt/decrypt
 *
 * Single buffer enc/dec with IV and precomputed key schedule
 *
 * @param[in]  pHandle       pointer to precomputed key schedule
 * @param[in]  pIV           pointer to IV
 * @param[in]  pBufferIn     pointer to an input buffer
 * @param[out] pBufferOut    pointer to an output buffer
 * @param[in]  lengthInBytes message length in bits
 */
void SNOW3G_F8_1_BUFFER(const snow3g_key_schedule_t *pHandle,
                        const void *pIV,
                        const void *pBufferIn,
                        void  *pBufferOut,
                        const uint32_t lengthInBytes)
{
#ifdef SAFE_PARAM
        if ((pHandle == NULL) || (pIV == NULL) ||
            (pBufferIn == NULL) || (pBufferOut == NULL) ||
            (lengthInBytes == 0) || (lengthInBytes > SNOW3G_MAX_BYTELEN))
                return;
#endif
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        snow3gKeyState1_t ctx;

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_1(&ctx, pHandle, pIV);

        /* Clock FSM and LFSR once, ignore the key stream */
        (void) snow3g_keystream_1_4(&ctx);

        f8_snow3g(&ctx, pBufferIn, pBufferOut, lengthInBytes);

#ifdef SAFE_DATA
        CLEAR_MEM(&ctx, sizeof(ctx));
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */
}

/**
 * @brief Single bit-length buffer F8 encrypt/decrypt
 * @param[in] pHandle      pointer to precomputed key schedule
 * @param[in] pIV          pointer to IV
 * @param[in] pBufferIn    pointer to an input buffer
 * @param[out] pBufferOut  pointer to an output buffer
 * @param[in] lengthInBits message length in bits
 * @param[in] offsetInBits message offset in bits
 */
void SNOW3G_F8_1_BUFFER_BIT(const snow3g_key_schedule_t *pHandle,
                            const void *pIV,
                            const void *pBufferIn,
                            void *pBufferOut,
                            const uint32_t lengthInBits,
                            const uint32_t offsetInBits)
{
#ifdef SAFE_PARAM
        if ((pHandle == NULL) || (pIV == NULL) ||
            (pBufferIn == NULL) || (pBufferOut == NULL) ||
            (lengthInBits == 0))
                return;
#endif
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        snow3gKeyState1_t ctx;

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_1(&ctx, pHandle, pIV);

        /* Clock FSM and LFSR once, ignore the key stream */
        (void) snow3g_keystream_1_4(&ctx);

        f8_snow3g_bit(&ctx, pBufferIn, pBufferOut, lengthInBits, offsetInBits);

#ifdef SAFE_DATA
        CLEAR_MEM(&ctx, sizeof(ctx));
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */
}

/**
 * @brief Two buffer F8 encrypt/decrypt with the same key schedule
 *
 * Two buffers enc/dec with the same key schedule.
 * The 2 IVs are independent and are passed as an array of pointers.
 * Each buffer and data length are separate.
 *
 * @param[in] pHandle      pointer to precomputed key schedule
 * @param[in] pIV1         pointer to IV
 * @param[in] pIV2         pointer to IV
 * @param[in] pBufIn1      pointer to an input buffer
 * @param[in] pBufOut1     pointer to an output buffer
 * @param[in] lenInBytes1  message size in bytes
 * @param[in] pBufIn2      pointer to an input buffer
 * @param[in] pBufOut2     pointer to an output buffer
 * @param[in] lenInBytes2  message size in bytes
 */
void SNOW3G_F8_2_BUFFER(const snow3g_key_schedule_t *pHandle,
                        const void *pIV1,
                        const void *pIV2,
                        const void *pBufIn1,
                        void *pBufOut1,
                        const uint32_t lenInBytes1,
                        const void *pBufIn2,
                        void *pBufOut2,
                        const uint32_t lenInBytes2)
{
#ifdef SAFE_PARAM
        if ((pHandle == NULL) || (pIV1 == NULL) || (pIV2 == NULL) ||
            (pBufIn1 == NULL) || (pBufOut1 == NULL) ||
            (pBufIn2 == NULL) || (pBufOut2 == NULL) ||
            (lenInBytes1 == 0) || (lenInBytes1 > SNOW3G_MAX_BYTELEN) ||
            (lenInBytes2 == 0) || (lenInBytes2 > SNOW3G_MAX_BYTELEN))
                return;
#endif
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        snow3gKeyState1_t ctx1, ctx2;

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_1(&ctx1, pHandle, pIV1);

        /* Clock FSM and LFSR once, ignore the key stream */
        (void) snow3g_keystream_1_4(&ctx1);

        /* data processing for packet 1 */
        f8_snow3g(&ctx1, pBufIn1, pBufOut1, lenInBytes1);

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_1(&ctx2, pHandle, pIV2);

        /* Clock FSM and LFSR once, ignore the key stream */
        (void) snow3g_keystream_1_4(&ctx2);

        /* data processing for packet 2 */
        f8_snow3g(&ctx2, pBufIn2, pBufOut2, lenInBytes2);

#ifdef SAFE_DATA
        CLEAR_MEM(&ctx1, sizeof(ctx1));
        CLEAR_MEM(&ctx2, sizeof(ctx2));
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

}

/**
 * @brief Four buffer F8 encrypt/decrypt with the same key schedule
 *
 * Four packets enc/dec with the same key schedule.
 * The 4 IVs are independent and are passed as an array of pointers.
 * Each buffer and data length are separate.
 *
 * @param[in] pHandle         pointer to precomputed key schedule
 * @param[in] pIV1            pointer to IV
 * @param[in] pIV2            pointer to IV
 * @param[in] pIV3            pointer to IV
 * @param[in] pIV4            pointer to IV
 * @param[in] pBufferIn1      pointer to an input buffer
 * @param[in] pBufferOut1     pointer to an output buffer
 * @param[in] lengthInBytes1  message size in bytes
 * @param[in] pBufferIn2      pointer to an input buffer
 * @param[in] pBufferOut2     pointer to an output buffer
 * @param[in] lengthInBytes2  message size in bytes
 * @param[in] pBufferIn3      pointer to an input buffer
 * @param[in] pBufferOut3     pointer to an output buffer
 * @param[in] lengthInBytes3  message size in bytes
 * @param[in] pBufferIn4      pointer to an input buffer
 * @param[in] pBufferOut4     pointer to an output buffer
 * @param[in] lengthInBytes4  message size in bytes
 */
void SNOW3G_F8_4_BUFFER(const snow3g_key_schedule_t *pHandle,
                        const void *pIV1,
                        const void *pIV2,
                        const void *pIV3,
                        const void *pIV4,
                        const void *pBufferIn1,
                        void *pBufferOut1,
                        const uint32_t lengthInBytes1,
                        const void *pBufferIn2,
                        void *pBufferOut2,
                        const uint32_t lengthInBytes2,
                        const void *pBufferIn3,
                        void *pBufferOut3,
                        const uint32_t lengthInBytes3,
                        const void *pBufferIn4,
                        void *pBufferOut4,
                        const uint32_t lengthInBytes4)
{
        const size_t num_lanes = 4;
        snow3gKeyState4_t ctx;
        uint32_t lenInBytes[4];
        uint8_t *pBufferOut[4];
        const uint8_t *pBufferIn[4];
        uint32_t bytes, qwords, i;

        length_copy_4(lenInBytes, lengthInBytes1, lengthInBytes2,
                      lengthInBytes3, lengthInBytes4);

        cptr_copy_4((const void **)pBufferIn,
                    pBufferIn1, pBufferIn2, pBufferIn3, pBufferIn4);

        ptr_copy_4((void **)pBufferOut, pBufferOut1, pBufferOut2,
                   pBufferOut3, pBufferOut4);

#ifdef SAFE_PARAM
        if ((pHandle == NULL) ||
            (pIV1 == NULL) || (pIV2 == NULL) ||
            (pIV3 == NULL) || (pIV4 == NULL))
                return;

        if (!cptr_check((const void * const *)pBufferIn, num_lanes) ||
            !ptr_check((void **)pBufferOut, num_lanes) ||
            !length_check(lenInBytes, num_lanes))
                return;
#endif

#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        /* find min common length */
        bytes = length_find_min(lenInBytes, num_lanes);
        qwords = bytes / SNOW3G_8_BYTES;

        /* subtract min common length from all buffers */
        length_sub(lenInBytes, num_lanes, qwords * SNOW3G_8_BYTES);

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_4(&ctx, pHandle, pIV1, pIV2, pIV3, pIV4);

        /* Clock FSM and LFSR once, ignore the key stream */
        (void) snow3g_keystream_4_4(&ctx);

        /* generates 8 bytes at a time on all streams */
        while (qwords >= 2) {
                uint32x4_t ks[4];

                snow3g_keystream_4_16(&ctx, ks);

                for (i = 0; i < num_lanes; i++) {
                        const uint32x4_t in = vld1q_u32((const uint32_t *)pBufferIn[i]);

                        vst1q_u32((uint32_t *)pBufferOut[i], in ^ ks[i]);

                        pBufferOut[i] += (2 * SNOW3G_8_BYTES);
                        pBufferIn[i] += (2 * SNOW3G_8_BYTES);
                }

                qwords = qwords - 2;
        }

        while (qwords--) {
                uint32x4_t H, L; /* 4 bytes of key stream */

                snow3g_keystream_4_8(&ctx, &L, &H);

                pBufferIn[0] = xor_keystrm_rev(pBufferOut[0], pBufferIn[0],
                                vgetq_lane_u64(vreinterpretq_u64_u32(L), 0));
                pBufferIn[1] = xor_keystrm_rev(pBufferOut[1], pBufferIn[1],
                                vgetq_lane_u64(vreinterpretq_u64_u32(L), 1));
                pBufferIn[2] = xor_keystrm_rev(pBufferOut[2], pBufferIn[2],
                                vgetq_lane_u64(vreinterpretq_u64_u32(H), 0));
                pBufferIn[3] = xor_keystrm_rev(pBufferOut[3], pBufferIn[3],
                                vgetq_lane_u64(vreinterpretq_u64_u32(H), 1));

                for (i = 0; i < num_lanes; i++)
                        pBufferOut[i] += SNOW3G_8_BYTES;
        }

        /* process the remaining of each buffer
         *  - extract the LFSR and FSM structures
         *  - Continue process 1 buffer
         */
        for (i = 0; i < num_lanes; i++) {
                snow3gKeyState1_t ctx_t;

                if (lenInBytes[i] == 0)
                        continue;
                snow3gStateConvert_4(&ctx, &ctx_t, i);
                f8_snow3g(&ctx_t, pBufferIn[i], pBufferOut[i], lenInBytes[i]);
        }
#ifdef SAFE_DATA
        CLEAR_MEM(&ctx, sizeof(ctx));
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */
}

/**
 * @brief Multiple-key 8 buffer F8 encrypt/decrypt
 *
 * Eight packets enc/dec with eight respective key schedules.
 * The 8 IVs are independent and are passed as an array of pointers.
 * Each buffer and data length are separate.
 *
 * @param[in] pKey          pointer to an array of key schedules
 * @param[in] IV            pointer to an array of IV's
 * @param[in] pBufferIn     pointer to an array of input buffers
 * @param[out] pBufferOut   pointer to an array of output buffers
 * @param[in] lengthInBytes pointer to an array of message lengths in bytes
 */
void SNOW3G_F8_8_BUFFER_MULTIKEY(const snow3g_key_schedule_t * const pKey[],
                                 const void * const IV[],
                                 const void * const BufferIn[],
                                 void *BufferOut[],
                                 const uint32_t lengthInBytes[])
{
        const size_t num_lanes = 8;

#ifdef SAFE_PARAM
        if ((pKey == NULL) || (IV == NULL) || (BufferIn == NULL) ||
            (BufferOut == NULL) || (lengthInBytes == NULL))
                return;

        if (!ptr_check(BufferOut, num_lanes) || !cptr_check(IV, num_lanes) ||
            !cptr_check((const void * const *)pKey, num_lanes) ||
            !cptr_check(BufferIn, num_lanes) ||
            !length_check(lengthInBytes, num_lanes))
                return;
#endif
        for (uint32_t i = 0; i < num_lanes; i++)
                SNOW3G_F8_1_BUFFER(pKey[i], IV[i], BufferIn[i], BufferOut[i],
                                   lengthInBytes[i]);
#ifdef SAFE_DATA
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif

}

/**
 * @brief 8 buffer F8 encrypt/decrypt with the same key schedule
 *
 * Eight packets enc/dec with the same key schedule.
 * The 8 IVs are independent and are passed as an array of pointers.
 * Each buffer and data length are separate.
 *
 * @param[in] pHandle         pointer to precomputed key schedule
 * @param[in] pIV1            pointer to IV
 * @param[in] pIV2            pointer to IV
 * @param[in] pIV3            pointer to IV
 * @param[in] pIV4            pointer to IV
 * @param[in] pIV5            pointer to IV
 * @param[in] pIV6            pointer to IV
 * @param[in] pIV7            pointer to IV
 * @param[in] pIV8            pointer to IV
 * @param[in] pBufIn1         pointer to an input buffer
 * @param[in] pBufOut1        pointer to an output buffer
 * @param[in] lenInBytes1     message size in bytes
 * @param[in] pBufIn2         pointer to an input buffer
 * @param[in] pBufOut2        pointer to an output buffer
 * @param[in] lenInBytes2     message size in bytes
 * @param[in] pBufIn3         pointer to an input buffer
 * @param[in] pBufOut3        pointer to an output buffer
 * @param[in] lenInBytes3     message size in bytes
 * @param[in] pBufIn4         pointer to an input buffer
 * @param[in] pBufOut4        pointer to an output buffer
 * @param[in] lenInBytes4     message size in bytes
 * @param[in] pBufIn5         pointer to an input buffer
 * @param[in] pBufOut5        pointer to an output buffer
 * @param[in] lenInBytes5     message size in bytes
 * @param[in] pBufIn6         pointer to an input buffer
 * @param[in] pBufOut6        pointer to an output buffer
 * @param[in] lenInBytes6     message size in bytes
 * @param[in] pBufIn7         pointer to an input buffer
 * @param[in] pBufOut7        pointer to an output buffer
 * @param[in] lenInBytes7     message size in bytes
 * @param[in] pBufIn8         pointer to an input buffer
 * @param[in] pBufOut8        pointer to an output buffer
 * @param[in] lenInBytes8     message size in bytes
 */
void SNOW3G_F8_8_BUFFER(const snow3g_key_schedule_t *pHandle,
                        const void *pIV1,
                        const void *pIV2,
                        const void *pIV3,
                        const void *pIV4,
                        const void *pIV5,
                        const void *pIV6,
                        const void *pIV7,
                        const void *pIV8,
                        const void *pBufIn1,
                        void *pBufOut1,
                        const uint32_t lenInBytes1,
                        const void *pBufIn2,
                        void *pBufOut2,
                        const uint32_t lenInBytes2,
                        const void *pBufIn3,
                        void *pBufOut3,
                        const uint32_t lenInBytes3,
                        const void *pBufIn4,
                        void *pBufOut4,
                        const uint32_t lenInBytes4,
                        const void *pBufIn5,
                        void *pBufOut5,
                        const uint32_t lenInBytes5,
                        const void *pBufIn6,
                        void *pBufOut6,
                        const uint32_t lenInBytes6,
                        const void *pBufIn7,
                        void *pBufOut7,
                        const uint32_t lenInBytes7,
                        const void *pBufIn8,
                        void *pBufOut8,
                        const uint32_t lenInBytes8)
{
        uint32_t lengthInBytes[8];
        const uint8_t *pBufferIn[8];
        const void *pIV[8];
        uint8_t *pBufferOut[8];

        length_copy_8(lengthInBytes,
                      lenInBytes1, lenInBytes2, lenInBytes3, lenInBytes4,
                      lenInBytes5, lenInBytes6, lenInBytes7, lenInBytes8);

        cptr_copy_8((const void **)pBufferIn,
                    pBufIn1, pBufIn2, pBufIn3, pBufIn4,
                    pBufIn5, pBufIn6, pBufIn7, pBufIn8);

        cptr_copy_8(pIV, pIV1, pIV2, pIV3, pIV4, pIV5, pIV6, pIV7, pIV8);

        ptr_copy_8((void **)pBufferOut,
                   pBufOut1, pBufOut2, pBufOut3, pBufOut4,
                   pBufOut5, pBufOut6, pBufOut7, pBufOut8);

#ifdef SAFE_PARAM
        const size_t num_lanes = 8;

        if (pHandle == NULL)
                return;

        if (!length_check(lengthInBytes, num_lanes) ||
            !cptr_check((const void * const *)pBufferIn, num_lanes) ||
            !cptr_check(pIV, num_lanes) ||
            !ptr_check((void **)pBufferOut, num_lanes))
                return;
#endif

        SNOW3G_F8_4_BUFFER(pHandle,
                           pIV[0], pIV[1], pIV[2], pIV[3],
                           pBufferIn[0], pBufferOut[0], lengthInBytes[0],
                           pBufferIn[1], pBufferOut[1], lengthInBytes[1],
                           pBufferIn[2], pBufferOut[2], lengthInBytes[2],
                           pBufferIn[3], pBufferOut[3], lengthInBytes[3]);

        SNOW3G_F8_4_BUFFER(pHandle,
                           pIV[4], pIV[5], pIV[6], pIV[7],
                           pBufferIn[4], pBufferOut[4], lengthInBytes[4],
                           pBufferIn[5], pBufferOut[5], lengthInBytes[5],
                           pBufferIn[6], pBufferOut[6], lengthInBytes[6],
                           pBufferIn[7], pBufferOut[7], lengthInBytes[7]);
}

/**
 * @brief Single-key N buffer F8 encrypt/decrypt
 *
 * Performs F8 enc/dec on N packets.
 * The input IV's are passed in Little Endian format.
 * The KeySchedule is in Little Endian format.
 *
 * @param[in] pCtx          pointer to a key schedule
 * @param[in] IV            pointer to an array of IV's
 * @param[in] pBufferIn     pointer to an array of input buffers
 * @param[out] pBufferOut   pointer to an array of output buffers
 * @param[in] bufLenInBytes pointer to an array of message lengths in bytes
 * @param[in] packetCount   number of packets to process (N)
 */
void SNOW3G_F8_N_BUFFER(const snow3g_key_schedule_t *pCtx,
                        const void * const IV[],
                        const void * const pBufferIn[],
                        void *pBufferOut[],
                        const uint32_t bufLenInBytes[],
                        const uint32_t packetCount)
{
#ifdef SAFE_PARAM
        if ((pCtx == NULL) || (IV == NULL) || (pBufferIn == NULL) ||
            (pBufferOut == NULL) || (bufLenInBytes == NULL))
                return;

        if (!cptr_check(IV, packetCount) ||
            !cptr_check(pBufferIn, packetCount) ||
            !ptr_check(pBufferOut, packetCount) ||
            !length_check(bufLenInBytes, packetCount))
                return;
#endif

#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        if (packetCount > NUM_PACKETS_16) {
                pBufferOut[0] = NULL;
                printf("packetCount too high (%d)\n", packetCount);
                return;
        }

        uint32_t packet_index, inner_index, pktCnt = packetCount;
        int sortNeeded = 0, tempLen = 0;
        uint8_t *srctempbuff;
        uint8_t *dsttempbuff;
        uint8_t *ivtempbuff;
        uint8_t *pSrcBuf[NUM_PACKETS_16] = {NULL};
        uint8_t *pDstBuf[NUM_PACKETS_16] = {NULL};
        uint8_t *pIV[NUM_PACKETS_16] = {NULL};
        uint32_t lensBuf[NUM_PACKETS_16] = {0};

        memcpy((void *)lensBuf, bufLenInBytes, packetCount * sizeof(uint32_t));
        memcpy((void *)pSrcBuf, pBufferIn, packetCount * sizeof(void *));
        memcpy((void *)pDstBuf, pBufferOut, packetCount * sizeof(void *));
        memcpy((void *)pIV, IV, packetCount * sizeof(void *));

        packet_index = packetCount;

        while (packet_index--) {

                /* check if all packets are sorted by decreasing length */
                if (packet_index > 0 && lensBuf[packet_index - 1] <
                    lensBuf[packet_index]) {
                        /* this packet array is not correctly sorted */
                        sortNeeded = 1;
                }
        }

        if (sortNeeded) {

                /* sort packets in decreasing buffer size from [0] to
                   [n]th packet, ** where buffer[0] will contain longest
                   buffer and buffer[n] will contain the shortest buffer.
                   4 arrays are swapped :
                   - pointers to input buffers
                   - pointers to output buffers
                   - pointers to input IV's
                   - input buffer lengths */
                packet_index = packetCount;
                while (packet_index--) {

                        inner_index = packet_index;
                        while (inner_index--) {

                                if (lensBuf[packet_index] >
                                    lensBuf[inner_index]) {

                                        /* swap buffers to arrange in
                                           descending order from [0]. */
                                        srctempbuff = pSrcBuf[packet_index];
                                        dsttempbuff = pDstBuf[packet_index];
                                        ivtempbuff = pIV[packet_index];
                                        tempLen = lensBuf[packet_index];

                                        pSrcBuf[packet_index] =
                                                pSrcBuf[inner_index];
                                        pDstBuf[packet_index] =
                                                pDstBuf[inner_index];
                                        pIV[packet_index] = pIV[inner_index];
                                        lensBuf[packet_index] =
                                                lensBuf[inner_index];

                                        pSrcBuf[inner_index] = srctempbuff;
                                        pDstBuf[inner_index] = dsttempbuff;
                                        pIV[inner_index] = ivtempbuff;
                                        lensBuf[inner_index] = tempLen;
                                }
                        } /* for inner packet index (inner bubble-sort) */
                }         /* for outer packet index (outer bubble-sort) */
        }                 /* if sortNeeded */

        packet_index = 0;
        /* process 8 buffers at-a-time */
       /* process 4 buffers at-a-time */
        while (pktCnt >= 4) {
                pktCnt -= 4;
                SNOW3G_F8_4_BUFFER(pCtx, pIV[packet_index + 0],
                                   pIV[packet_index + 1],
                                   pIV[packet_index + 2],
                                   pIV[packet_index + 3],
                                   pSrcBuf[packet_index + 0],
                                   pDstBuf[packet_index + 0],
                                   lensBuf[packet_index + 0],
                                   pSrcBuf[packet_index + 1],
                                   pDstBuf[packet_index + 1],
                                   lensBuf[packet_index + 1],
                                   pSrcBuf[packet_index + 2],
                                   pDstBuf[packet_index + 2],
                                   lensBuf[packet_index + 2],
                                   pSrcBuf[packet_index + 3],
                                   pDstBuf[packet_index + 3],
                                   lensBuf[packet_index + 3]);
                packet_index += 4;
        }

        /* process 2 packets at-a-time */
        while (pktCnt >= 2) {
                pktCnt -= 2;
                SNOW3G_F8_2_BUFFER(pCtx, pIV[packet_index + 0],
                                   pIV[packet_index + 1],
                                   pSrcBuf[packet_index + 0],
                                   pDstBuf[packet_index + 0],
                                   lensBuf[packet_index + 0],
                                   pSrcBuf[packet_index + 1],
                                   pDstBuf[packet_index + 1],
                                   lensBuf[packet_index + 1]);
                packet_index += 2;
        }

        /* remaining packets are processed 1 at a time */
        while (pktCnt--) {
                SNOW3G_F8_1_BUFFER(pCtx, pIV[packet_index + 0],
                                   pSrcBuf[packet_index + 0],
                                   pDstBuf[packet_index + 0],
                                   lensBuf[packet_index + 0]);
                packet_index++;
        }
}

/**
 * @brief Multi-key N buffer F8 encrypt/decrypt
 *
 * Performs F8 enc/dec on N packets.
 * The input IV's are passed in Little Endian format.
 * The KeySchedule is in Little Endian format.
 *
 * @param[in]  pCtx          pointer to an array of key schedules
 * @param[in]  IV            pointer to an array of IV's
 * @param[in]  pBufferIn     pointer to an array of input buffers
 * @param[out] pBufferOut    pointer to an array of output buffers
 * @param[in]  bufLenInBytes pointer to an array of message lengths in bytes
 * @param[in]  packetCount   number of packets to process (N)
 */
void SNOW3G_F8_N_BUFFER_MULTIKEY(const snow3g_key_schedule_t * const pCtx[],
                                 const void * const IV[],
                                 const void * const pBufferIn[],
                                 void *pBufferOut[],
                                 const uint32_t bufLenInBytes[],
                                 const uint32_t packetCount)
{
#ifdef SAFE_PARAM
        uint32_t i;

        if ((pCtx == NULL) || (IV == NULL) || (pBufferIn == NULL) ||
            (pBufferOut == NULL) || (bufLenInBytes == NULL))
                return;

        for (i = 0; i < packetCount; i++)
                if ((pCtx[i] == NULL) || (IV[i] == NULL) ||
                    (pBufferIn[i] == NULL) || (pBufferOut[i] == NULL) ||
                    (bufLenInBytes[i] == 0) ||
                    (bufLenInBytes[i] > SNOW3G_MAX_BYTELEN))
                        return;
#endif
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        if (packetCount > NUM_PACKETS_16) {
                pBufferOut[0] = NULL;
                printf("packetCount too high (%d)\n", packetCount);
                return;
        }

        uint32_t packet_index, inner_index, pktCnt = packetCount;
        int sortNeeded = 0, tempLen = 0;
        uint8_t *srctempbuff;
        uint8_t *dsttempbuff;
        uint8_t *ivtempbuff;
        snow3g_key_schedule_t *pCtxBuf[NUM_PACKETS_16] = {NULL};
        uint8_t *pSrcBuf[NUM_PACKETS_16] = {NULL};
        uint8_t *pDstBuf[NUM_PACKETS_16] = {NULL};
        uint8_t *pIV[NUM_PACKETS_16] = {NULL};
        uint32_t lensBuf[NUM_PACKETS_16] = {0};
        snow3g_key_schedule_t *tempCtx;

        memcpy((void *)pCtxBuf, pCtx, packetCount * sizeof(void *));
        memcpy((void *)lensBuf, bufLenInBytes, packetCount * sizeof(uint32_t));
        memcpy((void *)pSrcBuf, pBufferIn, packetCount * sizeof(void *));
        memcpy((void *)pDstBuf, pBufferOut, packetCount * sizeof(void *));
        memcpy((void *)pIV, IV, packetCount * sizeof(void *));

        packet_index = packetCount;

        while (packet_index--) {

                /* check if all packets are sorted by decreasing length */
                if (packet_index > 0 && lensBuf[packet_index - 1] <
                    lensBuf[packet_index]) {
                        /* this packet array is not correctly sorted */
                        sortNeeded = 1;
                }
        }

        if (sortNeeded) {
                /* sort packets in decreasing buffer size from [0] to [n]th
                   packet, where buffer[0] will contain longest buffer and
                   buffer[n] will contain the shortest buffer.
                   4 arrays are swapped :
                   - pointers to input buffers
                   - pointers to output buffers
                   - pointers to input IV's
                   - input buffer lengths */
                packet_index = packetCount;
                while (packet_index--) {
                        inner_index = packet_index;
                        while (inner_index--) {
                                if (lensBuf[packet_index] >
                                    lensBuf[inner_index]) {
                                        /* swap buffers to arrange in
                                           descending order from [0]. */
                                        srctempbuff = pSrcBuf[packet_index];
                                        dsttempbuff = pDstBuf[packet_index];
                                        ivtempbuff = pIV[packet_index];
                                        tempLen = lensBuf[packet_index];
                                        tempCtx = pCtxBuf[packet_index];

                                        pSrcBuf[packet_index] =
                                                pSrcBuf[inner_index];
                                        pDstBuf[packet_index] =
                                                pDstBuf[inner_index];
                                        pIV[packet_index] = pIV[inner_index];
                                        lensBuf[packet_index] =
                                                lensBuf[inner_index];
                                        pCtxBuf[packet_index] =
                                                pCtxBuf[inner_index];

                                        pSrcBuf[inner_index] = srctempbuff;
                                        pDstBuf[inner_index] = dsttempbuff;
                                        pIV[inner_index] = ivtempbuff;
                                        lensBuf[inner_index] = tempLen;
                                        pCtxBuf[inner_index] = tempCtx;
                                }
                        } /* for inner packet index (inner bubble-sort) */
                }         /* for outer packet index (outer bubble-sort) */
        }                 /* if sortNeeded */

        packet_index = 0;
        /* process 8 buffers at-a-time */
        /* @todo process 4 buffers at-a-time */
        /* @todo process 2 packets at-a-time */
        /* remaining packets are processed 1 at a time */
        while (pktCnt--) {
                SNOW3G_F8_1_BUFFER(pCtxBuf[packet_index + 0],
                                   pIV[packet_index + 0],
                                   pSrcBuf[packet_index + 0],
                                   pDstBuf[packet_index + 0],
                                   lensBuf[packet_index + 0]);
                packet_index++;
        }
}

/**
 * @brief Single buffer bit-length F9 function
 *
 * Single buffer digest with IV and precomputed key schedule.
 *
 * @param[in] pHandle      pointer to precomputed key schedule
 * @param[in] pIV          pointer to IV
 * @param[in] pBufferIn    pointer to an input buffer
 * @param[in] lengthInBits message length in bits
 * @param[out] pDigest     pointer to store the F9 digest
 */
void SNOW3G_F9_1_BUFFER(const snow3g_key_schedule_t *pHandle,
                        const void *pIV,
                        const void *pBufferIn,
                        const uint64_t lengthInBits,
                        void *pDigest)
{
#ifdef SAFE_PARAM
        if ((pHandle == NULL) || (pIV == NULL) ||
            (pBufferIn == NULL) || (pDigest == NULL) ||
            (lengthInBits == 0) || (lengthInBits > SNOW3G_MAX_BITLEN))
                return;
#endif
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        snow3gKeyState1_t ctx;
        uint32_t z[5];
        uint64_t lengthInQwords, E, P;
        uint64_t i;
        const uint64_t *inputBuffer;

        inputBuffer = (const uint64_t *)pBufferIn;

        /* Initialize the SNOW3G key schedule */
        snow3gStateInitialize_1(&ctx, pHandle, pIV);

        /*Generate 5 key stream words*/
        snow3g_f9_keystream_words(&ctx, &z[0]);

        P = ((uint64_t)z[0] << 32) | ((uint64_t)z[1]);

        lengthInQwords = lengthInBits / 64;

        E = 0;
        i = 0;

        if (lengthInQwords > 8) {
                /* compute P^2, P^3 and P^4 and put into p1p2 & p3p4 */
                const uint64_t P2 = multiply_and_reduce64(P, P);
                const uint64_t P3 = multiply_and_reduce64(P2, P);
                const uint64_t P4 = multiply_and_reduce64(P3, P);
                const uint64_t bs[2] = {0x0001020304050607ULL,
                                        0x08090a0b0c0d0e0fULL};
                const uint8x16_t bswap2x64 = vreinterpretq_u8_u64(vld1q_u64(bs));
                uint64_t ch[2] = {0xffffffffffffffffULL, 0};
                const poly64x2_t clear_hi64 = vld1q_p64((poly64_t *)ch);
                const uint64_t *m_ptr = &inputBuffer[i];
                poly64x2_t EV = vdupq_n_p64(0);

                for (; (i + 3) < lengthInQwords; i+= 4) {
                        uint64_t m0, m1, m2, m3;
                        uint64x2_t M1_t, M2_t;
                        poly64x2_t t1, t2, t3;
                        /* load 2 x 128-bits and byte swap 64-bit words */
                        M1_t = vld1q_u64(m_ptr);
                        m_ptr +=2;
                        M2_t = vld1q_u64(m_ptr);
                        m_ptr +=2;
                        M1_t = vreinterpretq_u64_u8(vqtbl1q_u8(
                                       vreinterpretq_u8_u64(M1_t), bswap2x64));
                        M2_t = vreinterpretq_u64_u8(vqtbl1q_u8(
                                       vreinterpretq_u8_u64(M2_t), bswap2x64));
                        m0 = vgetq_lane_u64(M1_t, 0);
                        m1 = vgetq_lane_u64(M1_t, 1);
                        m2 = vgetq_lane_u64(M2_t, 0);
                        m3 = vgetq_lane_u64(M2_t, 1);

                        /* add current EV to the first word of the message */
                        m0 = m0 ^ vgetq_lane_u64(vreinterpretq_u64_p64(EV), 0);
                        m1 = m1 ^ vgetq_lane_u64(vreinterpretq_u64_p64(EV), 1);

                        /* t1 = (M0 x P4) + (M1 x P3) + (M2 x P2) + (M3 x P1) */
                        t1 = (poly64x2_t)vmull_p64(m2, P2);
                        t2 = (poly64x2_t)vmull_p64(m3, P);

                        t1 = t1 ^ t2;

                        t2 = (poly64x2_t)vmull_p64(m0, P4);
                        t3 = (poly64x2_t)vmull_p64(m1, P3);

                        t2 = t2 ^ t3;
                        t1 = t2 ^ t1;

                        /* reduce 128-bit product */
                        EV = reduce128_to_64(t1);

                        /* clear top 64-bits for the subsequent add/xor */
                        EV = EV & clear_hi64;
                }

                for (; (i + 1) < lengthInQwords; i+= 2) {
                        poly64x2_t t1, t2;
                        uint64x2_t M_t;

                        /* load 128-bits and byte swap 64-bit words */
                        M_t = vld1q_u64(m_ptr);
                        m_ptr += 2;
                        M_t = vreinterpretq_u64_u8(vqtbl1q_u8(
                                        vreinterpretq_u8_u64(M_t), bswap2x64));

                        /* add current EV to the first word of the message */
                        M_t = M_t ^ EV;

                        poly64_t M0 = vgetq_lane_u64(M_t, 0);
                        poly64_t M1 = vgetq_lane_u64(M_t, 1);

                        /* t1 = (M0 x P2) + (M1 x P1) */
                        t1 = (poly64x2_t)vmull_p64(M0, P2);
                        t2 = (poly64x2_t)vmull_p64(M1, P);
                        t1 = t1 ^ t2;

                        /* reduce 128-bit product */
                        EV = reduce128_to_64(t1);

                        /* clear top 64-bits for the subsequent add/xor */
                        EV = EV & clear_hi64;
                }
                E = vgetq_lane_u64(vreinterpretq_u64_p64(EV), 0);
        }

        {
                /* all blocks except the last one */
                uint64_t V;
                for (; i < lengthInQwords; i++) {
                        V = BSWAP64(inputBuffer[i]);
                        E = multiply_and_reduce64(E ^ V, P);
                }
#ifdef SAFE_DATA
                CLEAR_VAR(&V, sizeof(V));
#endif
        }

                /* last bits of last block if any left */
        uint64_t rem_bits = lengthInBits % 64;
        if (rem_bits) {
                uint64_t V;
                /* last bytes, do not go past end of buffer */
                memcpy(&V, &inputBuffer[i], (rem_bits + 7) / 8);
                V = BSWAP64(V);
                /* mask extra bits */
                V &= (((uint64_t)-1) << (64 - rem_bits));
                E = multiply_and_reduce64(E ^ V, P);
#ifdef SAFE_DATA
                CLEAR_VAR(&V, sizeof(V));
#endif
        }

        /* Multiply by Q */
        E = multiply_and_reduce64(E ^ lengthInBits,
                                  (((uint64_t)z[2] << 32) | ((uint64_t)z[3])));

        /* Final MAC */
        *(uint32_t *)pDigest =
                (uint32_t)BSWAP64(E ^ ((uint64_t)z[4] << 32));

#ifdef SAFE_DATA
        CLEAR_VAR(&E, sizeof(E));
        CLEAR_VAR(&P, sizeof(P));
        CLEAR_MEM(&z, sizeof(z));
        CLEAR_MEM(&ctx, sizeof(ctx));
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */
}
#endif /* SNOW3G_COMMON_H */
