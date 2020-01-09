/*******************************************************************************
  Copyright (c) 2009-2019, Intel Corporation

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

/*-----------------------------------------------------------------------
 *
 * An implementation of SNOW 3G, the core algorithm for the
 * 3GPP Confidentiality and Integrity algorithms.
 *
 *-----------------------------------------------------------------------*/

#ifndef SNOW3G_COMMON_H
#define SNOW3G_COMMON_H

#include <stdio.h> /* printf() */
#include <string.h> /* memset(), memcpy() */
#include <stdint.h>

#include "intel-ipsec-mb.h"
#include "wireless_common.h"
#include "include/snow3g.h"
#include "include/snow3g_tables.h"
#ifdef NO_AESNI
#include "include/aesni_emu.h"
#endif

#include "clear_regs_mem.h"

#define CLEAR_MEM clear_mem
#define CLEAR_VAR clear_var

/* -------------------------------------------------------------------
 * PREVIOUSLY SNOW3G INTERNAL
 * ------------------------------------------------------------------ */

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
        __m128i LFSR_X[16];
        /* 3 FSM states */
        __m128i FSM_X[3];
        uint32_t iLFSR_X;
} snow3gKeyState4_t;

#ifdef AVX2
typedef struct snow3gKeyState8_s {
        /* 16 LFSR stages */
        __m256i LFSR_X[16];
        /* 3 FSM states */
        __m256i FSM_X[3];
        uint32_t iLFSR_X;
} snow3gKeyState8_t;
#endif /* AVX2 */

/* -------------------------------------------------------------------
 * combined S-Box processing for reduced instruction dependencies
 *
 * S1_S2_4    : 2 S-Box , 4 packets at a time
 *
 * ------------------------------------------------------------------ */

#ifdef AVX2
static inline __m256i _mm256_loadu_2xm128i(const void *hi, const void *lo)
{
        const __m128i lo128 = _mm_loadu_si128((const __m128i *) lo);
        const __m128i hi128 = _mm_loadu_si128((const __m128i *) hi);

        return _mm256_inserti128_si256(_mm256_castsi128_si256(lo128), hi128, 1);
}

#endif /* AVX2 */

/* -------------------------------------------------------------------
 * LFSR array shift by 2 positions
 * ------------------------------------------------------------------ */
static inline void ShiftTwiceLFSR_1(snow3gKeyState1_t *pCtx)
{
        int i;

        for (i = 0; i < 14; i++)
                pCtx->LFSR_S[i] = pCtx->LFSR_S[i + 2];
}

/* -------------------------------------------------------------------
 * Sbox S1 maps a 32bit input to a 32bit output
 * ------------------------------------------------------------------ */
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
        __m128i m;

        /*
         * Because of mix column operation the 32-bit word has to be
         * broadcasted across the 128-bit vector register for S1/AESENC
         */
        m = _mm_shuffle_epi32(_mm_cvtsi32_si128(x), 0);
        m = _mm_aesenc_si128(m, _mm_setzero_si128());
        return _mm_cvtsi128_si32(m);
#endif
}

/* -------------------------------------------------------------------
 * Sbox S2 maps a 32bit input to a 32bit output
 * ------------------------------------------------------------------ */
static inline uint32_t S2_box(const uint32_t x)
{
#if defined (NO_AESNI) || defined (SAFE_LOOKUP)
        return SNOW3G_SAFE_LOOKUP_W3(snow3g_table_S2, x & 0xff,
                                     sizeof(snow3g_table_S2)) ^
                SNOW3G_SAFE_LOOKUP_W0(snow3g_table_S2, (x >> 24) & 0xff,
                                      sizeof(snow3g_table_S2)) ^
                SNOW3G_SAFE_LOOKUP_W1(snow3g_table_S2, (x >> 16) & 0xff,
                                      sizeof(snow3g_table_S2)) ^
                SNOW3G_SAFE_LOOKUP_W2(snow3g_table_S2, (x >> 8) & 0xff,
                                      sizeof(snow3g_table_S2));
#else
        const uint8_t *w3 = (const uint8_t *)&snow3g_table_S2[x & 0xff];
        const uint8_t *w1 = (const uint8_t *)&snow3g_table_S2[(x >> 16) & 0xff];
        const uint8_t *w2 = (const uint8_t *)&snow3g_table_S2[(x >> 8) & 0xff];
        const uint8_t *w0 = (const uint8_t *)&snow3g_table_S2[(x >> 24) & 0xff];

        return *((const uint32_t *)&w3[3]) ^
                *((const uint32_t *)&w1[1]) ^
                *((const uint32_t *)&w2[2]) ^
                *((const uint32_t *)&w0[0]);
#endif
}

/* -------------------------------------------------------------------
 * ClockFSM function as defined in snow3g standard
 * The FSM has 2 input words S5 and S15 from the LFSR
 * produces a 32 bit output word F
 * ------------------------------------------------------------------ */
static inline uint32_t ClockFSM_1(snow3gKeyState1_t *pCtx)
{
        const uint32_t F = (pCtx->LFSR_S[15] + pCtx->FSM_R1) ^ pCtx->FSM_R2;
        const uint32_t R = (pCtx->FSM_R3 ^ pCtx->LFSR_S[5]) + pCtx->FSM_R2;

        pCtx->FSM_R3 = S2_box(pCtx->FSM_R2);
        pCtx->FSM_R2 = S1_box(pCtx->FSM_R1);
        pCtx->FSM_R1 = R;

        return F;
}

/* -------------------------------------------------------------------
 * ClockLFSR functin as defined in snow3g standard
 * ------------------------------------------------------------------ */
static inline void ClockLFSR_1(snow3gKeyState1_t *pCtx)
{
        const uint32_t S0 = pCtx->LFSR_S[0];
        const uint32_t S11 = pCtx->LFSR_S[11];
        const uint32_t V = pCtx->LFSR_S[2] ^
                snow3g_table_A_mul[S0 >> 24] ^
                snow3g_table_A_div[S11 & 0xff] ^
                (S0 << 8) ^
                (S11 >> 8);
        unsigned i;

        /* LFSR array shift by 1 position */
        for (i = 0; i < 15; i++)
                pCtx->LFSR_S[i] = pCtx->LFSR_S[i + 1];

        pCtx->LFSR_S[15] = V;
}

/**
 *******************************************************************************
 * @description
 * This function initializes the key schedule for 1 buffer for snow3g f8/f9.
 *
 * @param[in]       pCtx        Context where the scheduled keys are stored
 * @param [in]      pKeySched    Key schedule
 * @param [in]      pIV          IV
 *
 ******************************************************************************/
static inline void
snow3gStateInitialize_1(snow3gKeyState1_t *pCtx,
                        const snow3g_key_schedule_t *pKeySched,
                        const void *pIV)
{
        uint32_t K, L;
        int i;
        uint32_t V0, V1;
        uint32_t F0, F1;
        uint32_t L0, L1, L11, L12;
        uint32_t R0, R1;
        uint32_t FSM2, FSM3, FSM4;
        const uint32_t *pIV32 = pIV;

        /* LFSR initialisation */
        for (i = 0; i < 4; i++) {
                K = pKeySched->k[i];
                L = ~K;
                pCtx->LFSR_S[i + 4] = K;
                pCtx->LFSR_S[i + 12] = K;
                pCtx->LFSR_S[i + 0] = L;
                pCtx->LFSR_S[i + 8] = L;
        }

        pCtx->LFSR_S[15] ^= BSWAP32(pIV32[3]);
        pCtx->LFSR_S[12] ^= BSWAP32(pIV32[2]);
        pCtx->LFSR_S[10] ^= BSWAP32(pIV32[1]);
        pCtx->LFSR_S[9] ^= BSWAP32(pIV32[0]);

        /* FSM initialialization */
        FSM2 = 0x0;
        FSM3 = 0x0;
        FSM4 = 0x0;
        R1 = 0x0;
        V1 = pCtx->LFSR_S[15];

        for (i = 0; i < 16; i++) {
                /* clock FSM + clock LFSR + clockFSM + clock LFSR */
                L0 = pCtx->LFSR_S[0];
                L1 = pCtx->LFSR_S[1];
                V0 = pCtx->LFSR_S[2];
                F0 = V1 + R1; /**  (s15 +  R1) **/
                V1 = pCtx->LFSR_S[3];
                V0 ^= snow3g_table_A_mul[L0 >> 24]; /* MUL(s0,0 ) */
                F0 ^= FSM2;                         /** (s15 + R1) ^ R2 **/
                V1 ^= snow3g_table_A_mul[L1 >> 24];
                L11 = pCtx->LFSR_S[11];
                L12 = pCtx->LFSR_S[12];
                R0 = FSM3 ^ pCtx->LFSR_S[5];          /*** (R3 ^ s5 ) ***/
                V0 ^= snow3g_table_A_div[L11 & 0xff]; /* DIV(s11,3 )*/
                R0 += FSM2;                           /*** R2 + (R3 ^ s5 ) ***/
                V1 ^= snow3g_table_A_div[L12 & 0xff];
                V0 ^= L0 << 8; /*  (s0,1 || s0,2 || s0,3 || 0x00) */
                V1 ^= L1 << 8;
                V0 ^= L11 >> 8; /* (0x00 || s11,0 || s11,1 || s11,2 ) */
                V1 ^= L12 >> 8;
                FSM3 = S2_box(FSM2);
                FSM2 = S1_box(R1);
                FSM4 = S1_box(R0);
                V0 ^= F0; /* ^F */
                R1 = FSM3 ^ pCtx->LFSR_S[6];
                F1 = V0 + R0;
                F1 ^= FSM2;
                R1 += FSM2;
                FSM3 = S2_box(FSM2);
                FSM2 = FSM4;
                V1 ^= F1;

                /* shift LFSR twice */
                ShiftTwiceLFSR_1(pCtx);

                pCtx->LFSR_S[14] = V0;
                pCtx->LFSR_S[15] = V1;
        }

        /* set FSM into scheduling structure */
        pCtx->FSM_R3 = FSM3;
        pCtx->FSM_R2 = FSM2;
        pCtx->FSM_R1 = R1;
}

/**
 *******************************************************************************
 * @description
 * This function generates 5 words of keystream used in the initial stages
 * of snow3g F9.
 *
 * @param[in]       pCtx                         Context where the scheduled
 *keys are stored
 * @param[in/out]   pKeyStream          Pointer to the generated keystream
 *
 ******************************************************************************/
static inline void snow3g_f9_keystream_words(snow3gKeyState1_t *pCtx,
                                             uint32_t *pKeyStream)
{
        int i;

        (void) ClockFSM_1(pCtx);
        ClockLFSR_1(pCtx);

        for (i = 0; i < 5; i++) {
                const uint32_t F = ClockFSM_1(pCtx);

                pKeyStream[i] = F ^ pCtx->LFSR_S[0];
                ClockLFSR_1(pCtx);
        }
}

/* -------------------------------------------------------------------
 * LFSR array shift by 1 position, 4 packets at a time
 * ------------------------------------------------------------------ */

#ifdef AVX2
/* LFSR array shift */
static inline void ShiftLFSR_8(snow3gKeyState8_t *pCtx)
{
        pCtx->iLFSR_X = (pCtx->iLFSR_X + 1) & 15;
}
#endif /* AVX2 */

/* LFSR array shift */
static inline void ShiftLFSR_4(snow3gKeyState4_t *pCtx)
{
        pCtx->iLFSR_X = (pCtx->iLFSR_X + 1) % 16;
}

/*---------------------------------------------------------
 * @description
 * Gf2 modular multiplication/reduction
 *
 *---------------------------------------------------------*/
static inline uint64_t multiply_and_reduce64(uint64_t a, uint64_t b)
{
        uint64_t msk;
        uint64_t res = 0;
        uint64_t i = 64;

        while (i--) {
                msk = ((int64_t)res >> 63) & SNOW3GCONSTANT;
                res <<= 1;
                res ^= msk;
                msk = ((int64_t)b >> 63) & a;
                b <<= 1;
                res ^= msk;
        }
        return res;
}

#ifdef AVX2
/* -------------------------------------------------------------------
 * ClockLFSR sub-function as defined in snow3g standard
 * S = LFSR[2]
 *       ^ table_Alpha_div[LFSR[11] & 0xff]
 *       ^ table_Alpha_mul[LFSR[0] & 0xff]
 * ------------------------------------------------------------------ */
static void C0_C11_8(__m256i *S, const __m256i *L0, const __m256i *L11)
{
        __m256i mask, Sx, B11, B0, offset;

        offset = _mm256_set1_epi32(3);
        mask = _mm256_setr_epi32(0xF0F0F000, 0xF0F0F004, 0xF0F0F008, 0xF0F0F00C,
                                 0xF0F0F000, 0xF0F0F004, 0xF0F0F008,
                                 0xF0F0F00C);
        B11 = _mm256_shuffle_epi8(*L11, mask);
        *S = _mm256_i32gather_epi32(snow3g_table_A_div, B11, 4);

        mask = _mm256_add_epi32(mask, offset);
        B0 = _mm256_shuffle_epi8(*L0, mask);
        Sx = _mm256_i32gather_epi32(snow3g_table_A_mul, B0, 4);
        *S = _mm256_xor_si256(*S, Sx);
}
#endif /* AVX2 */

/* -------------------------------------------------------------------
 * ClockLFSR sub-function as defined in snow3g standard
 * S = LFSR[2]
 *       ^ table_Alpha_div[LFSR[11] & 0xff]
 *       ^ table_Alpha_mul[LFSR[0] & 0xff]
 * ------------------------------------------------------------------ */
static inline void C0_C11_4(uint32_t *S, const __m128i *L0, const __m128i *L11)
{
        unsigned B11[4], B0[4];

        B11[0] = _mm_extract_epi8(*L11, 0);
        B11[1] = _mm_extract_epi8(*L11, 4);
        B11[2] = _mm_extract_epi8(*L11, 8);
        B11[3] = _mm_extract_epi8(*L11, 12);

        S[0] = snow3g_table_A_div[B11[0]];
        S[1] = snow3g_table_A_div[B11[1]];
        S[2] = snow3g_table_A_div[B11[2]];
        S[3] = snow3g_table_A_div[B11[3]];

        B0[0] = _mm_extract_epi8(*L0, 3);
        B0[1] = _mm_extract_epi8(*L0, 7);
        B0[2] = _mm_extract_epi8(*L0, 11);
        B0[3] = _mm_extract_epi8(*L0, 15);

        S[0] ^= snow3g_table_A_mul[B0[0]];
        S[1] ^= snow3g_table_A_mul[B0[1]];
        S[2] ^= snow3g_table_A_mul[B0[2]];
        S[3] ^= snow3g_table_A_mul[B0[3]];
}

#ifdef AVX2
/* -------------------------------------------------------------------
 * ClockLFSR function as defined in snow3g standard
 * S =  table_Alpha_div[LFSR[11] & 0xff]
 *       ^ table_Alpha_mul[LFSR[0] >> 24]
 *       ^ LFSR[2] ^ LFSR[0] << 8 ^ LFSR[11] >> 8
 * ------------------------------------------------------------------ */
static inline void ClockLFSR_8(snow3gKeyState8_t *pCtx)
{
        __m256i X2;
        __m256i S, T, U;

        U = pCtx->LFSR_X[pCtx->iLFSR_X];
        S = pCtx->LFSR_X[(pCtx->iLFSR_X + 11) % 16];

        C0_C11_8(&X2, &U, &S);

        T = _mm256_slli_epi32(U, 8);
        S = _mm256_srli_epi32(S, 8);
        U = _mm256_xor_si256(T, pCtx->LFSR_X[(pCtx->iLFSR_X + 2) % 16]);

        ShiftLFSR_8(pCtx);

        S = _mm256_xor_si256(S, U);
        S = _mm256_xor_si256(S, X2);
        pCtx->LFSR_X[(pCtx->iLFSR_X + 15) % 16] = S;
}
#endif /* AVX2 */

/* -------------------------------------------------------------------
 * ClockLFSR function as defined in snow3g standard
 * S =  table_Alpha_div[LFSR[11] & 0xff]
 *       ^ table_Alpha_mul[LFSR[0] >> 24]
 *       ^ LFSR[2] ^ LFSR[0] << 8 ^ LFSR[11] >> 8
 * ------------------------------------------------------------------ */
static inline void ClockLFSR_4(snow3gKeyState4_t *pCtx)
{
        uint32_t X2[4];
        __m128i S, T, U;

        U = pCtx->LFSR_X[pCtx->iLFSR_X];
        S = pCtx->LFSR_X[(pCtx->iLFSR_X + 11) % 16];
        C0_C11_4(X2, &U, &S);

        T = _mm_slli_epi32(U, 8);
        S = _mm_srli_epi32(S, 8);
        U = _mm_xor_si128(T, pCtx->LFSR_X[(pCtx->iLFSR_X + 2) % 16]);
        ShiftLFSR_4(pCtx);

        /*
         * One load is equivalent to previous 4 x 32-bit insert operations
         */
        T = _mm_loadu_si128((const __m128i *) &X2[0]);
        S = _mm_xor_si128(S, U);
        S = _mm_xor_si128(S, T);
        pCtx->LFSR_X[(pCtx->iLFSR_X + 15) % 16] = S;
}

#ifdef AVX2
/* -------------------------------------------------------------------
 * ClockFSM function as defined in snow3g standard
 * 8 packets at a time
 * ------------------------------------------------------------------ */
static inline void ClockFSM_8(snow3gKeyState8_t *pCtx, __m256i *data)
{
        static const uint32_t start_shuf_mask[8] = {
                0xF0F0F000, 0xF0F0F004, 0xF0F0F008, 0xF0F0F00C,
                0xF0F0F000, 0xF0F0F004, 0xF0F0F008, 0xF0F0F00C
        };
        static const uint32_t add_epi32_one[8] = {
                0x00000001, 0x00000001, 0x00000001, 0x00000001,
                0x00000001, 0x00000001, 0x00000001, 0x00000001
        };
        const uint32_t iLFSR_X_5 = (pCtx->iLFSR_X + 5) & 15;
        const uint32_t iLFSR_X_15 = (pCtx->iLFSR_X + 15) & 15;
        __m256i S2T0, S2T1, S2T2, S2T3;
        __m256i shuffle_mask, gather_mask;

        const __m256i F =
                _mm256_add_epi32(pCtx->LFSR_X[iLFSR_X_15], pCtx->FSM_X[0]);

        *data = _mm256_xor_si256(F, pCtx->FSM_X[1]);

        const __m256i R =
                _mm256_add_epi32(_mm256_xor_si256(pCtx->LFSR_X[iLFSR_X_5],
                                                  pCtx->FSM_X[2]),
                                 pCtx->FSM_X[1]);

        const __m256i offset =
                _mm256_loadu_si256((const __m256i *) add_epi32_one);

        shuffle_mask = _mm256_loadu_si256((const __m256i *) start_shuf_mask);
        gather_mask = _mm256_shuffle_epi8(pCtx->FSM_X[1], shuffle_mask);
        S2T0 = _mm256_i32gather_epi32(S2_T0, gather_mask, 4);

        shuffle_mask = _mm256_add_epi32(shuffle_mask, offset);
        gather_mask = _mm256_shuffle_epi8(pCtx->FSM_X[1], shuffle_mask);
        S2T1 = _mm256_i32gather_epi32(S2_T1, gather_mask, 4);

        shuffle_mask = _mm256_add_epi32(shuffle_mask, offset);
        gather_mask = _mm256_shuffle_epi8(pCtx->FSM_X[1], shuffle_mask);
        S2T2 = _mm256_i32gather_epi32(S2_T2, gather_mask, 4);

        shuffle_mask = _mm256_add_epi32(shuffle_mask, offset);
        gather_mask = _mm256_shuffle_epi8(pCtx->FSM_X[1], shuffle_mask);
        S2T3 = _mm256_i32gather_epi32(S2_T3, gather_mask, 4);

        S2T0 = _mm256_xor_si256(S2T0, S2T1);
        S2T2 = _mm256_xor_si256(S2T2, S2T3);
        pCtx->FSM_X[2] = _mm256_xor_si256(S2T0, S2T2);

        const __m256i T = pCtx->FSM_X[0];

        pCtx->FSM_X[1] =
                _mm256_set_epi32(S1_box(_mm256_extract_epi32(T, 7)),
                                 S1_box(_mm256_extract_epi32(T, 6)),
                                 S1_box(_mm256_extract_epi32(T, 5)),
                                 S1_box(_mm256_extract_epi32(T, 4)),
                                 S1_box(_mm256_extract_epi32(T, 3)),
                                 S1_box(_mm256_extract_epi32(T, 2)),
                                 S1_box(_mm256_extract_epi32(T, 1)),
                                 S1_box(_mm256_extract_epi32(T, 0)));

        pCtx->FSM_X[0] = R;
}
#endif /* AVX2 */

/* -------------------------------------------------------------------
 * ClockFSM function as defined in snow3g standard
 * 4 packets at a time
 * ------------------------------------------------------------------ */
static inline void ClockFSM_4(snow3gKeyState4_t *pCtx, __m128i *data)
{
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:4556)
#endif
        const uint32_t iLFSR_X = pCtx->iLFSR_X;
        const __m128i F =
                _mm_add_epi32(pCtx->LFSR_X[(iLFSR_X + 15) % 16],
                              pCtx->FSM_X[0]);
        const __m128i R =
                _mm_add_epi32(_mm_xor_si128(pCtx->LFSR_X[(iLFSR_X + 5) % 16],
                                            pCtx->FSM_X[2]),
                              pCtx->FSM_X[1]);

        *data = _mm_xor_si128(F, pCtx->FSM_X[1]);

        const uint32_t FSM1_L3 = S1_box(_mm_cvtsi128_si32(pCtx->FSM_X[0]));
        const uint32_t FSM2_L3 = S2_box(_mm_cvtsi128_si32(pCtx->FSM_X[1]));
        const uint32_t FSM1_L2 = S1_box(_mm_extract_epi32(pCtx->FSM_X[0], 1));
        const uint32_t FSM2_L2 = S2_box(_mm_extract_epi32(pCtx->FSM_X[1], 1));
        const uint32_t FSM1_L1 = S1_box(_mm_extract_epi32(pCtx->FSM_X[0], 2));
        const uint32_t FSM2_L1 = S2_box(_mm_extract_epi32(pCtx->FSM_X[1], 2));
        const uint32_t FSM1_L0 = S1_box(_mm_extract_epi32(pCtx->FSM_X[0], 3));
        const uint32_t FSM2_L0 = S2_box(_mm_extract_epi32(pCtx->FSM_X[1], 3));

        pCtx->FSM_X[2] = _mm_set_epi32(FSM2_L3, FSM2_L2, FSM2_L1, FSM2_L0);
        pCtx->FSM_X[1] = _mm_set_epi32(FSM1_L3, FSM1_L2, FSM1_L1, FSM1_L0);
        pCtx->FSM_X[0] = R;

#ifdef _WIN32
#pragma warning(pop)
#endif
}

/**
*******************************************************************************
* @description
* This function generates 4 bytes of keystream 1 buffer at a time
*
* @param[in]     pCtx       Context where the scheduled keys are stored
* @return 4 bytes of keystream
*
*******************************************************************************/
static inline uint32_t snow3g_keystream_1_4(snow3gKeyState1_t *pCtx)
{
        const uint32_t F = ClockFSM_1(pCtx);
        const uint32_t ks = F ^ pCtx->LFSR_S[0];

        ClockLFSR_1(pCtx);
        return ks;
}

/**
*******************************************************************************
* @description
* This function generates 8 bytes of keystream 1 buffer at a time
*
* @param[in]            pCtx         Context where the scheduled keys are stored
* @param[in/out]        pKeyStream   Pointer to generated keystream
*
*******************************************************************************/
static inline void snow3g_keystream_1_8(snow3gKeyState1_t *pCtx,
                                        uint64_t *pKeyStream)
{
        uint64_t F;
        uint32_t FSM4;
        uint32_t V0, V1;
        uint32_t F0, F1;
        uint32_t R0, R1;
        uint32_t L0, L1, L11, L12;

        /* Merged clock FSM + clock LFSR + clock FSM + clockLFSR
         * in order to avoid redundancies in function processing
         * and less instruction immediate dependencies
         */
        L0 = pCtx->LFSR_S[0];
        V0 = pCtx->LFSR_S[2];
        L1 = pCtx->LFSR_S[1];
        V1 = pCtx->LFSR_S[3];
        R1 = pCtx->FSM_R1;
        L11 = pCtx->LFSR_S[11];
        L12 = pCtx->LFSR_S[12];
        V0 ^= snow3g_table_A_mul[L0 >> 24];
        V1 ^= snow3g_table_A_mul[L1 >> 24];
        V0 ^= snow3g_table_A_div[L11 & 0xff];
        V1 ^= snow3g_table_A_div[L12 & 0xff];
        V0 ^= L0 << 8;
        V1 ^= L1 << 8;
        V0 ^= L11 >> 8;
        V1 ^= L12 >> 8;
        F0 = pCtx->LFSR_S[15] + R1;
        F0 ^= L0;
        F0 ^= pCtx->FSM_R2;
        R0 = pCtx->FSM_R3 ^ pCtx->LFSR_S[5];
        R0 += pCtx->FSM_R2;

        pCtx->FSM_R3 = S2_box(pCtx->FSM_R2);
        pCtx->FSM_R2 = S1_box(R1);
        FSM4 = S1_box(R0);
        R1 = pCtx->FSM_R3 ^ pCtx->LFSR_S[6];
        F1 = V0 + R0;
        F1 ^= L1;
        F1 ^= pCtx->FSM_R2;
        R1 += pCtx->FSM_R2;
        pCtx->FSM_R3 = S2_box(pCtx->FSM_R2);
        pCtx->FSM_R2 = FSM4;
        pCtx->FSM_R1 = R1;

        /* Shift LFSR twice */
        ShiftTwiceLFSR_1(pCtx);

        /* keystream mode LFSR update */
        pCtx->LFSR_S[14] = V0;
        pCtx->LFSR_S[15] = V1;

        F = F0;
        F <<= 32;
        F |= (uint64_t)F1;

        *pKeyStream = F;
}

#ifdef AVX2
/**
*******************************************************************************
* @description
* This function generates 8 bytes of keystream 8 buffers at a time
*
* @param[in]            pCtx         Context where the scheduled keys are stored
* @param[in/out]        pKeyStream   Pointer to generated keystream
*
*******************************************************************************/
static inline void snow3g_keystream_8_8(snow3gKeyState8_t *pCtx,
                                        __m256i *pKeyStreamLo,
                                        __m256i *pKeyStreamHi)
{
        __m256i H, L;

        /* first set of 4 bytes */
        ClockFSM_8(pCtx, &L);
        L = _mm256_xor_si256(L, pCtx->LFSR_X[pCtx->iLFSR_X]);
        ClockLFSR_8(pCtx);

        /* second set of 4 bytes */
        ClockFSM_8(pCtx, &H);
        H = _mm256_xor_si256(H, pCtx->LFSR_X[pCtx->iLFSR_X]);
        ClockLFSR_8(pCtx);

        /* merge the 2 sets */
        *pKeyStreamLo = _mm256_unpacklo_epi32(H, L);
        *pKeyStreamHi = _mm256_unpackhi_epi32(H, L);
}

/**
*******************************************************************************
* @description
* This function generates 4 bytes of keystream 8 buffers at a time
*
* @param[in]            pCtx         Context where the scheduled keys are stored
* @param[in/out]        pKeyStream   Pointer to generated keystream
*
*******************************************************************************/
static inline void snow3g_keystream_8_4(snow3gKeyState8_t *pCtx,
                                        __m256i *pKeyStream)
{
        __m256i F;

        ClockFSM_8(pCtx, &F);
        *pKeyStream = _mm256_xor_si256(F, pCtx->LFSR_X[pCtx->iLFSR_X]);
        ClockLFSR_8(pCtx);
}

/**
*****************************************************************************
* @description
* This function generates 32 bytes of keystream 8 buffers at a time
*
* @param[in]            pCtx         Context where the scheduled keys are stored
* @param[in/out]        pKeyStream   Array of generated keystreams
*
******************************************************************************/
static inline void snow3g_keystream_8_32(snow3gKeyState8_t *pCtx,
                                         __m256i *pKeyStream)
{

        __m256i temp[8];

        /** produces the next 4 bytes for each buffer */
        int i;

        /** Byte reversal on each KS */
        static const __m256i mask1 = {
                0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
                0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL
        };
        /** Reversal, shifted 4 bytes right */
        static const __m256i mask2 = {
                0x0405060708090a0bULL, 0x0c0d0e0f00010203ULL,
                0x0405060708090a0bULL, 0x0c0d0e0f00010203ULL
        };
        /** Reversal, shifted 8 bytes right */
        static const __m256i mask3 = {
                0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL,
                0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL
        };
        /** Reversal, shifted 12 bytes right */
        static const __m256i mask4 = {
                0x0c0d0e0f00010203ULL, 0x0405060708090a0bULL,
                0x0c0d0e0f00010203ULL, 0x0405060708090a0bULL
        };

        snow3g_keystream_8_4(pCtx, &temp[0]);
        snow3g_keystream_8_4(pCtx, &temp[1]);
        snow3g_keystream_8_4(pCtx, &temp[2]);
        snow3g_keystream_8_4(pCtx, &temp[3]);
        snow3g_keystream_8_4(pCtx, &temp[4]);
        snow3g_keystream_8_4(pCtx, &temp[5]);
        snow3g_keystream_8_4(pCtx, &temp[6]);
        snow3g_keystream_8_4(pCtx, &temp[7]);

        temp[0] = _mm256_shuffle_epi8(temp[0], mask1);
        temp[1] = _mm256_shuffle_epi8(temp[1], mask2);
        temp[2] = _mm256_shuffle_epi8(temp[2], mask3);
        temp[3] = _mm256_shuffle_epi8(temp[3], mask4);
        temp[4] = _mm256_shuffle_epi8(temp[4], mask1);
        temp[5] = _mm256_shuffle_epi8(temp[5], mask2);
        temp[6] = _mm256_shuffle_epi8(temp[6], mask3);
        temp[7] = _mm256_shuffle_epi8(temp[7], mask4);

        __m256i blended[8];
        /* blends KS together: 128bit slice consists
           of 4 32-bit words for one packet */
        blended[0] = _mm256_blend_epi32(temp[0], temp[1], 0xaa);
        blended[1] = _mm256_blend_epi32(temp[0], temp[1], 0x55);
        blended[2] = _mm256_blend_epi32(temp[2], temp[3], 0xaa);
        blended[3] = _mm256_blend_epi32(temp[2], temp[3], 0x55);
        blended[4] = _mm256_blend_epi32(temp[4], temp[5], 0xaa);
        blended[5] = _mm256_blend_epi32(temp[4], temp[5], 0x55);
        blended[6] = _mm256_blend_epi32(temp[6], temp[7], 0xaa);
        blended[7] = _mm256_blend_epi32(temp[6], temp[7], 0x55);

        temp[0] = _mm256_blend_epi32(blended[0], blended[2], 0xcc);
        temp[1] = _mm256_blend_epi32(blended[1], blended[3], 0x99);
        temp[2] = _mm256_blend_epi32(blended[0], blended[2], 0x33);
        temp[3] = _mm256_blend_epi32(blended[1], blended[3], 0x66);
        temp[4] = _mm256_blend_epi32(blended[4], blended[6], 0xcc);
        temp[5] = _mm256_blend_epi32(blended[5], blended[7], 0x99);
        temp[6] = _mm256_blend_epi32(blended[4], blended[6], 0x33);
        temp[7] = _mm256_blend_epi32(blended[5], blended[7], 0x66);

        /** sorts 32 bit words back into order */
        blended[0] = temp[0];
        blended[1] = _mm256_shuffle_epi32(temp[1], 0x39);
        blended[2] = _mm256_shuffle_epi32(temp[2], 0x4e);
        blended[3] = _mm256_shuffle_epi32(temp[3], 0x93);
        blended[4] = temp[4];
        blended[5] = _mm256_shuffle_epi32(temp[5], 0x39);
        blended[6] = _mm256_shuffle_epi32(temp[6], 0x4e);
        blended[7] = _mm256_shuffle_epi32(temp[7], 0x93);

        for (i = 0; i < 4; i++) {
                pKeyStream[i] = _mm256_permute2x128_si256(blended[i],
                                                          blended[i + 4], 0x20);
                pKeyStream[i + 4] = _mm256_permute2x128_si256(
                        blended[i], blended[i + 4], 0x31);
        }
}

#endif /* AVX2 */

/**
*******************************************************************************
* @description
* This function generates 4 bytes of keystream 4 buffers at a time
*
* @param[in]            pCtx         Context where the scheduled keys are stored
* @param[in/out]        pKeyStream   Pointer to generated keystream
*
*******************************************************************************/
static inline void snow3g_keystream_4_4(snow3gKeyState4_t *pCtx,
                                        __m128i *pKeyStream)
{
        __m128i F;

        ClockFSM_4(pCtx, &F);
        *pKeyStream = _mm_xor_si128(F, pCtx->LFSR_X[pCtx->iLFSR_X]);
        ClockLFSR_4(pCtx);
}

/**
*******************************************************************************
* @description
* This function generates 8 bytes of keystream 4 buffers at a time
*
* @param[in]            pCtx         Context where the scheduled keys are stored
* @param[in/out]        pKeyStreamLo Pointer to lower end of generated keystream
* @param[in/out]        pKeyStreamHi Pointer to higer end of generated keystream
*
*******************************************************************************/
static inline void snow3g_keystream_4_8(snow3gKeyState4_t *pCtx,
                                        __m128i *pKeyStreamLo,
                                        __m128i *pKeyStreamHi)
{
        __m128i H, L;

        /* first set of 4 bytes */
        ClockFSM_4(pCtx, &L);
        L = _mm_xor_si128(L, pCtx->LFSR_X[pCtx->iLFSR_X]);
        ClockLFSR_4(pCtx);

        /* second set of 4 bytes */
        ClockFSM_4(pCtx, &H);
        H = _mm_xor_si128(H, pCtx->LFSR_X[pCtx->iLFSR_X]);
        ClockLFSR_4(pCtx);

        /* merge the 2 sets */
        *pKeyStreamLo = _mm_unpacklo_epi32(H, L);
        *pKeyStreamHi = _mm_unpackhi_epi32(H, L);
}

/**
*******************************************************************************
* @description
* This function initializes the key schedule for 4 buffers for snow3g f8/f9.
*
*       @param [in]      pCtx        Context where the scheduled keys are stored
*       @param [in]      pKeySched   Key schedule
*       @param [in]      pIV1        IV for buffer 1
*       @param [in]      pIV2        IV for buffer 2
*       @param [in]      pIV3        IV for buffer 3
*       @param [in]      pIV4        IV for buffer 4
*
*******************************************************************************/
static inline void
snow3gStateInitialize_4(snow3gKeyState4_t *pCtx,
                        const snow3g_key_schedule_t *pKeySched,
                        const void *pIV1, const void *pIV2,
                        const void *pIV3, const void *pIV4)
{
        uint32_t K, L;
        int i;
        __m128i R, S, T, U;
        __m128i V0, V1, T0, T1;

        /* Initialize the LFSR table from constants, Keys, and IV */

        /* Load complete 128b IV into register (SSE2)*/
        static const uint64_t sm[2] = {
                0x0405060700010203ULL, 0x0c0d0e0f08090a0bULL
        };
        const __m128i *swapMask = (const __m128i *) sm;

        R = _mm_loadu_si128((const __m128i *)pIV1);
        S = _mm_loadu_si128((const __m128i *)pIV2);
        T = _mm_loadu_si128((const __m128i *)pIV3);
        U = _mm_loadu_si128((const __m128i *)pIV4);

        /* initialize the array block (SSE4) */
        for (i = 0; i < 4; i++) {
                K = pKeySched->k[i];
                L = ~K;
                V0 = _mm_set1_epi32(K);
                V1 = _mm_set1_epi32(L);
                pCtx->LFSR_X[i + 4] = V0;
                pCtx->LFSR_X[i + 12] = V0;
                pCtx->LFSR_X[i + 0] = V1;
                pCtx->LFSR_X[i + 8] = V1;
        }
        /* Update the schedule structure with IVs */
        /* Store the 4 IVs in LFSR by a column/row matrix swap
         * after endianness correction */

        /* endianness swap (SSSE3) */
        R = _mm_shuffle_epi8(R, *swapMask);
        S = _mm_shuffle_epi8(S, *swapMask);
        T = _mm_shuffle_epi8(T, *swapMask);
        U = _mm_shuffle_epi8(U, *swapMask);

        /* row/column dword inversion (SSE2) */
        T0 = _mm_unpacklo_epi32(R, S);
        R = _mm_unpackhi_epi32(R, S);
        T1 = _mm_unpacklo_epi32(T, U);
        T = _mm_unpackhi_epi32(T, U);

        /* row/column qword inversion (SSE2) */
        U = _mm_unpackhi_epi64(R, T);
        T = _mm_unpacklo_epi64(R, T);
        S = _mm_unpackhi_epi64(T0, T1);
        R = _mm_unpacklo_epi64(T0, T1);

        /*IV ^ LFSR (SSE2) */
        pCtx->LFSR_X[15] = _mm_xor_si128(pCtx->LFSR_X[15], U);
        pCtx->LFSR_X[12] = _mm_xor_si128(pCtx->LFSR_X[12], T);
        pCtx->LFSR_X[10] = _mm_xor_si128(pCtx->LFSR_X[10], S);
        pCtx->LFSR_X[9] = _mm_xor_si128(pCtx->LFSR_X[9], R);
        pCtx->iLFSR_X = 0;
        /* FSM initialization (SSE2) */
        S = _mm_setzero_si128();
        for (i = 0; i < 3; i++)
                pCtx->FSM_X[i] = S;

        /* Initialisation rounds */
        for (i = 0; i < 32; i++) {
                ClockFSM_4(pCtx, &S);
                ClockLFSR_4(pCtx);
                pCtx->LFSR_X[(pCtx->iLFSR_X + 15) % 16] = _mm_xor_si128(
                        pCtx->LFSR_X[(pCtx->iLFSR_X + 15) % 16], S);
        }
}

#ifdef AVX2
/**
*******************************************************************************
* @description
* This function intializes the key schedule for 8 buffers with
* individual keys, for snow3g f8/f9.
*
*       @param [in]      pCtx            Context where scheduled keys are stored
*       @param [in]      pKeySched       Key schedule
*       @param [in]      pIV1            IV for buffer 1
*       @param [in]      pIV2            IV for buffer 2
*       @param [in]      pIV3            IV for buffer 3
*       @param [in]      pIV4            IV for buffer 4
*       @param [in]      pIV5            IV for buffer 5
*       @param [in]      pIV6            IV for buffer 6
*       @param [in]      pIV7            IV for buffer 7
*       @param [in]      pIV8            IV for buffer 8
*
*******************************************************************************/
static inline void
snow3gStateInitialize_8_multiKey(snow3gKeyState8_t *pCtx,
                                 const snow3g_key_schedule_t * const KeySched[],
                                 const void * const pIV[])
{
        DECLARE_ALIGNED(uint32_t k[8], 32);
        DECLARE_ALIGNED(uint32_t l[8], 32);
        __m256i *K = (__m256i *)k;
        __m256i *L = (__m256i *)l;

        int i, j;
        __m256i mR, mS, mT, mU, T0, T1;

        /* Initialize the LFSR table from constants, Keys, and IV */

        /* Load complete 256b IV into register (SSE2)*/
        static const __m256i swapMask = {
                0x0405060700010203ULL, 0x0c0d0e0f08090a0bULL,
                0x0405060700010203ULL, 0x0c0d0e0f08090a0bULL
        };
        mR = _mm256_loadu_2xm128i(pIV[4], pIV[0]);
        mS = _mm256_loadu_2xm128i(pIV[5], pIV[1]);
        mT = _mm256_loadu_2xm128i(pIV[6], pIV[2]);
        mU = _mm256_loadu_2xm128i(pIV[7], pIV[3]);

        /* initialize the array block (SSE4) */
        for (i = 0; i < 4; i++) {
                for (j = 0; j < 8; j++) {
                        k[j] = KeySched[j]->k[i];
                        l[j] = ~k[j];
                }

                pCtx->LFSR_X[i + 4] = *K;
                pCtx->LFSR_X[i + 12] = *K;
                pCtx->LFSR_X[i + 0] = *L;
                pCtx->LFSR_X[i + 8] = *L;
        }

        /* Update the schedule structure with IVs */
        /* Store the 4 IVs in LFSR by a column/row matrix swap
         * after endianness correction */

        /* endianness swap (SSSE3) */
        mR = _mm256_shuffle_epi8(mR, swapMask);
        mS = _mm256_shuffle_epi8(mS, swapMask);
        mT = _mm256_shuffle_epi8(mT, swapMask);
        mU = _mm256_shuffle_epi8(mU, swapMask);

        /* row/column dword inversion (SSE2) */
        T0 = _mm256_unpacklo_epi32(mR, mS);
        mR = _mm256_unpackhi_epi32(mR, mS);
        T1 = _mm256_unpacklo_epi32(mT, mU);
        mT = _mm256_unpackhi_epi32(mT, mU);

        /* row/column qword inversion (SSE2) */
        mU = _mm256_unpackhi_epi64(mR, mT);
        mT = _mm256_unpacklo_epi64(mR, mT);
        mS = _mm256_unpackhi_epi64(T0, T1);
        mR = _mm256_unpacklo_epi64(T0, T1);

        /*IV ^ LFSR (SSE2) */
        pCtx->LFSR_X[15] = _mm256_xor_si256(pCtx->LFSR_X[15], mU);
        pCtx->LFSR_X[12] = _mm256_xor_si256(pCtx->LFSR_X[12], mT);
        pCtx->LFSR_X[10] = _mm256_xor_si256(pCtx->LFSR_X[10], mS);
        pCtx->LFSR_X[9] = _mm256_xor_si256(pCtx->LFSR_X[9], mR);
        pCtx->iLFSR_X = 0;
        /* FSM initialization (SSE2) */
        mS = _mm256_setzero_si256();
        for (i = 0; i < 3; i++)
                pCtx->FSM_X[i] = mS;

        /* Initialisation rounds */
        for (i = 0; i < 32; i++) {
                ClockFSM_8(pCtx, &mS);
                ClockLFSR_8(pCtx);
                pCtx->LFSR_X[(pCtx->iLFSR_X + 15) % 16] = _mm256_xor_si256(
                        pCtx->LFSR_X[(pCtx->iLFSR_X + 15) % 16], mS);
        }
}

/**
*******************************************************************************
* @description
* This function initializes the key schedule for 8 buffers for snow3g f8/f9.
*
*       @param [in]     pCtx         Context where the scheduled keys are stored
*       @param [in]     pKeySched    Key schedule
*       @param [in]     pIV1         IV for buffer 1
*       @param [in]     pIV2         IV for buffer 2
*       @param [in]     pIV3         IV for buffer 3
*       @param [in]     pIV4         IV for buffer 4
*       @param [in]     pIV5         IV for buffer 5
*       @param [in]     pIV6         IV for buffer 6
*       @param [in]     pIV7         IV for buffer 7
*       @param [in]     pIV8         IV for buffer 8
*
*******************************************************************************/
static inline void
snow3gStateInitialize_8(snow3gKeyState8_t *pCtx,
                        const snow3g_key_schedule_t *pKeySched,
                        const void *pIV1, const void *pIV2,
                        const void *pIV3, const void *pIV4,
                        const void *pIV5, const void *pIV6,
                        const void *pIV7, const void *pIV8)
{
        uint32_t K, L;
        int i;
        __m256i mR, mS, mT, mU, V0, V1, T0, T1;

        /* Initialize the LFSR table from constants, Keys, and IV */

        /* Load complete 256b IV into register (SSE2)*/
        static const __m256i swapMask = {
                0x0405060700010203ULL, 0x0c0d0e0f08090a0bULL,
                0x0405060700010203ULL, 0x0c0d0e0f08090a0bULL
        };

        mR = _mm256_loadu_2xm128i(pIV5, pIV1);
        mS = _mm256_loadu_2xm128i(pIV6, pIV2);
        mT = _mm256_loadu_2xm128i(pIV7, pIV3);
        mU = _mm256_loadu_2xm128i(pIV8, pIV4);

        /* initialize the array block (SSE4) */
        for (i = 0; i < 4; i++) {
                K = pKeySched->k[i];
                L = ~K;
                V0 = _mm256_set1_epi32(K);
                V1 = _mm256_set1_epi32(L);
                pCtx->LFSR_X[i + 4] = V0;
                pCtx->LFSR_X[i + 12] = V0;
                pCtx->LFSR_X[i + 0] = V1;
                pCtx->LFSR_X[i + 8] = V1;
        }

        /* Update the schedule structure with IVs */
        /* Store the 4 IVs in LFSR by a column/row matrix swap
         * after endianness correction */

        /* endianness swap (SSSE3) */
        mR = _mm256_shuffle_epi8(mR, swapMask);
        mS = _mm256_shuffle_epi8(mS, swapMask);
        mT = _mm256_shuffle_epi8(mT, swapMask);
        mU = _mm256_shuffle_epi8(mU, swapMask);

        /* row/column dword inversion (SSE2) */
        T0 = _mm256_unpacklo_epi32(mR, mS);
        mR = _mm256_unpackhi_epi32(mR, mS);
        T1 = _mm256_unpacklo_epi32(mT, mU);
        mT = _mm256_unpackhi_epi32(mT, mU);

        /* row/column qword inversion (SSE2) */
        mU = _mm256_unpackhi_epi64(mR, mT);
        mT = _mm256_unpacklo_epi64(mR, mT);
        mS = _mm256_unpackhi_epi64(T0, T1);
        mR = _mm256_unpacklo_epi64(T0, T1);

        /*IV ^ LFSR (SSE2) */
        pCtx->LFSR_X[15] = _mm256_xor_si256(pCtx->LFSR_X[15], mU);
        pCtx->LFSR_X[12] = _mm256_xor_si256(pCtx->LFSR_X[12], mT);
        pCtx->LFSR_X[10] = _mm256_xor_si256(pCtx->LFSR_X[10], mS);
        pCtx->LFSR_X[9] = _mm256_xor_si256(pCtx->LFSR_X[9], mR);
        pCtx->iLFSR_X = 0;
        /* FSM initialization (SSE2) */
        mS = _mm256_setzero_si256();
        for (i = 0; i < 3; i++)
                pCtx->FSM_X[i] = mS;

        /* Initialisation rounds */
        for (i = 0; i < 32; i++) {
                ClockFSM_8(pCtx, &mS);
                ClockLFSR_8(pCtx);
                pCtx->LFSR_X[(pCtx->iLFSR_X + 15) % 16] = _mm256_xor_si256(
                        pCtx->LFSR_X[(pCtx->iLFSR_X + 15) % 16], mS);
        }
}
#endif /* AVX2 */

static inline void
preserve_bits(uint64_t *KS,
              const uint8_t *pcBufferOut, const uint8_t *pcBufferIn,
              SafeBuf *safeOutBuf, SafeBuf *safeInBuf,
              const uint8_t bit_len, const uint8_t byte_len)
{
        const uint64_t mask = UINT64_MAX << (SNOW3G_BLOCK_SIZE * 8 - bit_len);

        /* Clear the last bits of the keystream and the input
         * (input only in out-of-place case) */
        *KS &= mask;
        if (pcBufferIn != pcBufferOut) {
                const uint64_t swapMask = BSWAP64(mask);

                safeInBuf->b64 &= swapMask;

                /*
                 * Merge the last bits from the output, to be preserved,
                 * in the keystream, to be XOR'd with the input
                 * (which last bits are 0, maintaining the output bits)
                 */
                memcpy_keystrm(safeOutBuf->b8, pcBufferOut, byte_len);
                *KS |= BSWAP64(safeOutBuf->b64 & ~swapMask);
        }
}

/**
*******************************************************************************
* @description
* This function is the core snow3g bit algorithm
* for the 3GPP confidentiality algorithm
*
* @param[in]    pCtx                Context where the scheduled keys are stored
* @param[in]    pBufferIn           Input buffer
* @param[out]   pBufferOut          Output buffer
* @param[in]    cipherLengthInBits  length in bits of the data to be encrypted
* @param[in]    bitOffset           offset in input buffer, where data are valid
*
*******************************************************************************/
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
        uint64_t KS8, KS8bit; /* 8 bytes of keystream */
        const uint8_t *pcBufferIn = pBufferIn + (offsetInBits / 8);
        uint8_t *pcBufferOut = pBufferOut + (offsetInBits / 8);
        /* Offset into the first byte (0 - 7 bits) */
        uint32_t remainOffset = offsetInBits % 8;
        uint32_t byteLength = (cipherLengthInBits + 7) / 8;
        SafeBuf safeInBuf = {0};
        SafeBuf safeOutBuf = {0};

        /* Now run the block cipher */

        /* Start with potential partial block (due to offset and length) */
        snow3g_keystream_1_8(pCtx, &KS8);
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
                /* produce the next block of keystream */
                snow3g_keystream_1_8(pCtx, &KS8);
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
*******************************************************************************
* @description
* This function is the core snow3g algorithm for
* the 3GPP confidentiality and integrity algorithm.
*
* @param[in]       pCtx            Context where the scheduled keys are stored
* @param[in]       pBufferIn       Input buffer
* @param[out]      pBufferOut      Output buffer
* @param[in]       lengthInBytes   length in bytes of the data to be encrypted
*
*******************************************************************************/
static inline void f8_snow3g(snow3gKeyState1_t *pCtx,
                             const void *pIn,
                             void *pOut,
                             const uint32_t lengthInBytes)
{
        uint32_t qwords = lengthInBytes / SNOW3G_8_BYTES; /* number of qwords */
        uint32_t words = lengthInBytes & 4; /* remaining word if not 0 */
        uint32_t bytes = lengthInBytes & 3; /* remaining bytes */
        uint32_t KS4;                       /* 4 bytes of keystream */
        uint64_t KS8;                       /* 8 bytes of keystream */
        const uint8_t *pBufferIn = pIn;
        uint8_t *pBufferOut = pOut;

        /* process 64 bits at a time */
        while (qwords--) {
                /* generate keystream 8 bytes at a time */
                snow3g_keystream_1_8(pCtx, &KS8);

                /* xor keystream 8 bytes at a time */
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
                        snow3g_keystream_1_8(pCtx, &KS8);
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

#ifdef AVX2
/**
*******************************************************************************
* @description
* This function converts the state from a 4 buffer state structure to 1
* buffer state structure.
*
* @param[in]    pSrcState               Pointer to the source state
* @param[in]    pDstState               Pointer to the destination state
* @param[in]    NumBuffers              Number of buffers
*
*******************************************************************************/
static inline void snow3gStateConvert_8(snow3gKeyState8_t *pSrcState,
                                        snow3gKeyState1_t *pDstState,
                                        uint32_t NumBuffers)
{
        uint32_t T = 0, iLFSR_X = pSrcState->iLFSR_X;
        __m256i *LFSR_X = pSrcState->LFSR_X;
        int i;

        for (i = 0; i < 16; i++) {
                switch (NumBuffers) {
                case 0:
                        T = _mm256_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 0);
                        break;
                case 1:
                        T = _mm256_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 1);
                        break;
                case 2:
                        T = _mm256_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 2);
                        break;
                case 3:
                        T = _mm256_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 3);
                        break;
                case 4:
                        T = _mm256_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 4);
                        break;
                case 5:
                        T = _mm256_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 5);
                        break;
                case 6:
                        T = _mm256_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 6);
                        break;
                case 7:
                        T = _mm256_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 7);
                        break;
                }
                pDstState->LFSR_S[i] = T;
        }
        i = 0;
        switch (NumBuffers) {
        case 0:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 0);
                break;
        case 1:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 1);
                break;
        case 2:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 2);
                break;
        case 3:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 3);
                break;
        case 4:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 4);
                break;
        case 5:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 5);
                break;
        case 6:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 6);
                break;
        case 7:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 7);
                break;
        }
        pDstState->FSM_R1 = T;

        i = 1;
        switch (NumBuffers) {
        case 0:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 0);
                break;
        case 1:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 1);
                break;
        case 2:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 2);
                break;
        case 3:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 3);
                break;
        case 4:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 4);
                break;
        case 5:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 5);
                break;
        case 6:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 6);
                break;
        case 7:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 7);
                break;
        }
        pDstState->FSM_R2 = T;

        i = 2;
        switch (NumBuffers) {
        case 0:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 0);
                break;
        case 1:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 1);
                break;
        case 2:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 2);
                break;
        case 3:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 3);
                break;
        case 4:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 4);
                break;
        case 5:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 5);
                break;
        case 6:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 6);
                break;
        case 7:
                T = _mm256_extract_epi32(pSrcState->FSM_X[i], 7);
                break;
        }
        pDstState->FSM_R3 = T;
}
#endif /* AVX2 */

/**
*******************************************************************************
* @description
* This function converts the state from a 4 buffer state structure to 1
* buffer state structure.
*
* @param[in]    pSrcState               Pointer to the source state
* @param[in]    pDstState               Pointer to the destination state
* @param[in]    NumBuffers              Number of buffers
*
*******************************************************************************/
static inline void snow3gStateConvert_4(snow3gKeyState4_t *pSrcState,
                                        snow3gKeyState1_t *pDstState,
                                        uint32_t NumBuffers)
{
        uint32_t i;
        uint32_t T = 0, iLFSR_X = pSrcState->iLFSR_X;
        __m128i *LFSR_X = pSrcState->LFSR_X;

        for (i = 0; i < 16; i++) {
                switch (NumBuffers) {
                case 0:
                        T = _mm_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 0);
                        break;
                case 1:
                        T = _mm_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 1);
                        break;
                case 2:
                        T = _mm_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 2);
                        break;
                case 3:
                        T = _mm_extract_epi32(LFSR_X[(i + iLFSR_X) % 16], 3);
                        break;
                }
                pDstState->LFSR_S[i] = T;
        }

        i = 0;
        switch (NumBuffers) {
        case 0:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 0);
                break;
        case 1:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 1);
                break;
        case 2:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 2);
                break;
        case 3:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 3);
                break;
        }
        pDstState->FSM_R1 = T;

        i = 1;
        switch (NumBuffers) {
        case 0:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 0);
                break;
        case 1:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 1);
                break;
        case 2:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 2);
                break;
        case 3:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 3);
                break;
        }
        pDstState->FSM_R2 = T;

        i = 2;
        switch (NumBuffers) {
        case 0:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 0);
                break;
        case 1:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 1);
                break;
        case 2:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 2);
                break;
        case 3:
                T = _mm_extract_epi32(pSrcState->FSM_X[i], 3);
                break;
        }
        pDstState->FSM_R3 = T;
}

/*---------------------------------------------------------
 * f8()
 * Initializations and Context size definitions
 *---------------------------------------------------------*/
size_t SNOW3G_KEY_SCHED_SIZE(void) { return sizeof(snow3g_key_schedule_t); }

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

/*---------------------------------------------------------
 * @description
 *      Snow3G F8 1 buffer:
 *      Single buffer enc/dec with IV and precomputed key schedule
 *---------------------------------------------------------*/
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

        /* Clock FSM and LFSR once, ignore the keystream */
        (void) snow3g_keystream_1_4(&ctx);

        f8_snow3g(&ctx, pBufferIn, pBufferOut, lengthInBytes);

#ifdef SAFE_DATA
        CLEAR_MEM(&ctx, sizeof(ctx));
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */
}

/*---------------------------------------------------------
 * @description
 *      Snow3G F8 bit 1 buffer:
 *      Single buffer enc/dec with IV and precomputed key schedule
 *---------------------------------------------------------*/
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

        /* Clock FSM and LFSR once, ignore the keystream */
        (void) snow3g_keystream_1_4(&ctx);

        f8_snow3g_bit(&ctx, pBufferIn, pBufferOut, lengthInBits, offsetInBits);

#ifdef SAFE_DATA
        CLEAR_MEM(&ctx, sizeof(ctx));
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */
}

/*---------------------------------------------------------
 * @description
 *      Snow3G F8 2 buffer:
 *      Two buffers enc/dec with the same key schedule.
 *      The 3 IVs are independent and are passed as an array of pointers.
 *      Each buffer and data length are separate.
 *---------------------------------------------------------*/
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

        /* Clock FSM and LFSR once, ignore the keystream */
        (void) snow3g_keystream_1_4(&ctx1);

        /* data processing for packet 1 */
        f8_snow3g(&ctx1, pBufIn1, pBufOut1, lenInBytes1);

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_1(&ctx2, pHandle, pIV2);

        /* Clock FSM and LFSR once, ignore the keystream */
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

/*---------------------------------------------------------
 * @description
 *      Snow3G F8 4 buffer:
 *      Four packets enc/dec with the same key schedule.
 *      The 4 IVs are independent and are passed as an array of pointers.
 *      Each buffer and data length are separate.
 *---------------------------------------------------------*/
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
#ifdef SAFE_PARAM
        if ((pHandle == NULL) ||
            (pIV1 == NULL) || (pIV2 == NULL) ||
            (pIV3 == NULL) || (pIV4 == NULL) ||
            (pBufferIn1 == NULL) || (pBufferOut1 == NULL) ||
            (pBufferIn2 == NULL) || (pBufferOut2 == NULL) ||
            (pBufferIn3 == NULL) || (pBufferOut3 == NULL) ||
            (pBufferIn4 == NULL) || (pBufferOut4 == NULL) ||
            (lengthInBytes1 == 0) || (lengthInBytes1 > SNOW3G_MAX_BYTELEN) ||
            (lengthInBytes2 == 0) || (lengthInBytes2 > SNOW3G_MAX_BYTELEN) ||
            (lengthInBytes3 == 0) || (lengthInBytes3 > SNOW3G_MAX_BYTELEN) ||
            (lengthInBytes4 == 0) || (lengthInBytes4 > SNOW3G_MAX_BYTELEN))
                return;
#endif
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        snow3gKeyState4_t ctx;
        __m128i H, L; /* 4 bytes of keystream */
        uint32_t lenInBytes1 = lengthInBytes1;
        uint32_t lenInBytes2 = lengthInBytes2;
        uint32_t lenInBytes3 = lengthInBytes3;
        uint32_t lenInBytes4 = lengthInBytes4;
        uint32_t bytes1 =
                (lenInBytes1 < lenInBytes2 ? lenInBytes1
                 : lenInBytes2); /* number of bytes */
        uint32_t bytes2 =
                (lenInBytes3 < lenInBytes4 ? lenInBytes3
                 : lenInBytes4);    /* number of bytes */
        /* min num of bytes */
        uint32_t bytes = (bytes1 < bytes2) ? bytes1 : bytes2;
        uint32_t qwords = bytes / SNOW3G_8_BYTES;
        uint8_t *pBufOut1 = pBufferOut1;
        uint8_t *pBufOut2 = pBufferOut2;
        uint8_t *pBufOut3 = pBufferOut3;
        uint8_t *pBufOut4 = pBufferOut4;
        const uint8_t *pBufIn1 = pBufferIn1;
        const uint8_t *pBufIn2 = pBufferIn2;
        const uint8_t *pBufIn3 = pBufferIn3;
        const uint8_t *pBufIn4 = pBufferIn4;

        bytes = qwords * SNOW3G_8_BYTES; /* rounded down minimum length */

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_4(&ctx, pHandle, pIV1, pIV2, pIV3, pIV4);

        /* Clock FSM and LFSR once, ignore the keystream */
        snow3g_keystream_4_4(&ctx, &L);

        lenInBytes1 -= bytes;
        lenInBytes2 -= bytes;
        lenInBytes3 -= bytes;
        lenInBytes4 -= bytes;

        /* generates 4 bytes at a time on all streams */
        while (qwords--) {
                snow3g_keystream_4_8(&ctx, &L, &H);
                pBufIn1 = xor_keystrm_rev(pBufOut1, pBufIn1,
                                          _mm_extract_epi64(L, 0));
                pBufIn2 = xor_keystrm_rev(pBufOut2, pBufIn2,
                                          _mm_extract_epi64(L, 1));
                pBufIn3 = xor_keystrm_rev(pBufOut3, pBufIn3,
                                          _mm_extract_epi64(H, 0));
                pBufIn4 = xor_keystrm_rev(pBufOut4, pBufIn4,
                                          _mm_extract_epi64(H, 1));

                pBufOut1 += SNOW3G_8_BYTES;
                pBufOut2 += SNOW3G_8_BYTES;
                pBufOut3 += SNOW3G_8_BYTES;
                pBufOut4 += SNOW3G_8_BYTES;
        }

        /* process the remaining of each buffer
         *  - extract the LFSR and FSM structures
         *  - Continue process 1 buffer
         */
        if (lenInBytes1) {
                snow3gKeyState1_t ctx1;

                snow3gStateConvert_4(&ctx, &ctx1, 0);
                f8_snow3g(&ctx1, pBufIn1, pBufOut1, lenInBytes1);
        }

        if (lenInBytes2) {
                snow3gKeyState1_t ctx2;

                snow3gStateConvert_4(&ctx, &ctx2, 1);
                f8_snow3g(&ctx2, pBufIn2, pBufOut2, lenInBytes2);
        }

        if (lenInBytes3) {
                snow3gKeyState1_t ctx3;

                snow3gStateConvert_4(&ctx, &ctx3, 2);
                f8_snow3g(&ctx3, pBufIn3, pBufOut3, lenInBytes3);
        }

        if (lenInBytes4) {
                snow3gKeyState1_t ctx4;

                snow3gStateConvert_4(&ctx, &ctx4, 3);
                f8_snow3g(&ctx4, pBufIn4, pBufOut4, lenInBytes4);
        }

#ifdef SAFE_DATA
        H = _mm_setzero_si128();
        L = _mm_setzero_si128();
        CLEAR_MEM(&ctx, sizeof(ctx));
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

}

#ifdef AVX2
/*---------------------------------------------------------
 * @description
 *      Snow3G 8 buffer ks 8 multi:
 *      Processes 8 packets 8 bytes at a time.
 *      Uses individual key schedule for each buffer.
 *---------------------------------------------------------*/
static inline void
snow3g_8_buffer_ks_8_multi(uint32_t bytes,
                           const snow3g_key_schedule_t * const pKey[],
                           const void * const IV[],
                           const void * const pBufferIn[],
                           void *pBufferOut[], const uint32_t *lengthInBytes)
{
        const uint32_t qwords = bytes / SNOW3G_8_BYTES;
        __m256i H, L; /* 8 bytes of keystream */
        snow3gKeyState8_t ctx;
        int i;
        const uint8_t *tBufferIn[8];
        uint8_t *tBufferOut[8];
        uint32_t tLenInBytes[8];

        bytes = qwords * SNOW3G_8_BYTES; /* rounded down minimum length */

        for (i = 0; i < 8; i++) {
                tBufferIn[i] = pBufferIn[i];
                tBufferOut[i] = pBufferOut[i];
                tLenInBytes[i] = lengthInBytes[i];
        }

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_8_multiKey(&ctx, pKey, IV);

        /* Clock FSM and LFSR once, ignore the keystream */
        snow3g_keystream_8_4(&ctx, &L);

        for (i = 0; i < 8; i++)
                tLenInBytes[i] -= bytes;

        /* generates 8 sets at a time on all streams */
        for (i = qwords; i != 0; i--) {
                int j;

                snow3g_keystream_8_8(&ctx, &L, &H);

                tBufferIn[0] = xor_keystrm_rev(tBufferOut[0], tBufferIn[0],
                                               _mm256_extract_epi64(L, 0));
                tBufferIn[1] = xor_keystrm_rev(tBufferOut[1], tBufferIn[1],
                                               _mm256_extract_epi64(L, 1));
                tBufferIn[2] = xor_keystrm_rev(tBufferOut[2], tBufferIn[2],
                                               _mm256_extract_epi64(H, 0));
                tBufferIn[3] = xor_keystrm_rev(tBufferOut[3], tBufferIn[3],
                                               _mm256_extract_epi64(H, 1));
                tBufferIn[4] = xor_keystrm_rev(tBufferOut[4], tBufferIn[4],
                                               _mm256_extract_epi64(L, 2));
                tBufferIn[5] = xor_keystrm_rev(tBufferOut[5], tBufferIn[5],
                                               _mm256_extract_epi64(L, 3));
                tBufferIn[6] = xor_keystrm_rev(tBufferOut[6], tBufferIn[6],
                                               _mm256_extract_epi64(H, 2));
                tBufferIn[7] = xor_keystrm_rev(tBufferOut[7], tBufferIn[7],
                                               _mm256_extract_epi64(H, 3));

                for (j = 0; j < 8; j++)
                        tBufferOut[j] += SNOW3G_8_BYTES;
        }

        /* process the remaining of each buffer
         *  - extract the LFSR and FSM structures
         *  - Continue process 1 buffer
         */
        for (i = 0; i < 8; i++) {
                snow3gKeyState1_t t_ctx;

                if (tLenInBytes[i] == 0)
                        continue;

                snow3gStateConvert_8(&ctx, &t_ctx, i);
                f8_snow3g(&t_ctx, tBufferIn[i], tBufferOut[i], tLenInBytes[i]);
        }

#ifdef SAFE_DATA
        H = _mm256_setzero_si256();
        L = _mm256_setzero_si256();
        CLEAR_MEM(&ctx, sizeof(ctx));
#endif /* SAFE_DATA */
}

/*---------------------------------------------------------
 * @description
 *      Snow3G 8 buffer ks 32 multi:
 *      Processes 8 packets 32 bytes at a time.
 *      Uses individual key schedule for each buffer.
 *---------------------------------------------------------*/
static inline void
snow3g_8_buffer_ks_32_multi(uint32_t bytes,
                            const snow3g_key_schedule_t * const pKey[],
                            const void * const IV[],
                            const void * const pBufferIn[],
                            void *pBufferOut[], const uint32_t *lengthInBytes)
{

        snow3gKeyState8_t ctx;
        uint32_t i;

        const uint8_t *tBufferIn[8];
        uint8_t *tBufferOut[8];
        uint32_t tLenInBytes[8];

        for (i = 0; i < 8; i++) {
                tBufferIn[i] = pBufferIn[i];
                tBufferOut[i] = pBufferOut[i];
                tLenInBytes[i] = lengthInBytes[i];
        }

        uint32_t blocks = bytes / 32;

        bytes = blocks * 32; /* rounded down minimum length */

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_8_multiKey(&ctx, pKey, IV);

        /* Clock FSM and LFSR once, ignore the keystream */
        __m256i ks[8];

        snow3g_keystream_8_4(&ctx, ks);

        for (i = 0; i < 8; i++)
                tLenInBytes[i] -= bytes;

        __m256i in[8];

        /* generates 8 sets at a time on all streams */
        for (i = 0; i < blocks; i++) {
                int j;

                in[0] = _mm256_loadu_si256((const __m256i *)tBufferIn[0]);
                in[1] = _mm256_loadu_si256((const __m256i *)tBufferIn[1]);
                in[2] = _mm256_loadu_si256((const __m256i *)tBufferIn[2]);
                in[3] = _mm256_loadu_si256((const __m256i *)tBufferIn[3]);
                in[4] = _mm256_loadu_si256((const __m256i *)tBufferIn[4]);
                in[5] = _mm256_loadu_si256((const __m256i *)tBufferIn[5]);
                in[6] = _mm256_loadu_si256((const __m256i *)tBufferIn[6]);
                in[7] = _mm256_loadu_si256((const __m256i *)tBufferIn[7]);

                snow3g_keystream_8_32(&ctx, ks);

                _mm256_storeu_si256((__m256i *)tBufferOut[0],
                                    _mm256_xor_si256(in[0], ks[0]));
                _mm256_storeu_si256((__m256i *)tBufferOut[1],
                                    _mm256_xor_si256(in[1], ks[1]));
                _mm256_storeu_si256((__m256i *)tBufferOut[2],
                                    _mm256_xor_si256(in[2], ks[2]));
                _mm256_storeu_si256((__m256i *)tBufferOut[3],
                                    _mm256_xor_si256(in[3], ks[3]));
                _mm256_storeu_si256((__m256i *)tBufferOut[4],
                                    _mm256_xor_si256(in[4], ks[4]));
                _mm256_storeu_si256((__m256i *)tBufferOut[5],
                                    _mm256_xor_si256(in[5], ks[5]));
                _mm256_storeu_si256((__m256i *)tBufferOut[6],
                                    _mm256_xor_si256(in[6], ks[6]));
                _mm256_storeu_si256((__m256i *)tBufferOut[7],
                                    _mm256_xor_si256(in[7], ks[7]));

                for (j = 0; j < 8; j++) {
                        tBufferIn[i] += 32;
                        tBufferOut[i] += 32;
                }
        }

        /* process the remaining of each buffer
         *  - extract the LFSR and FSM structures
         *  - Continue process 1 buffer
         */
        for (i = 0; i < 8; i++) {
                snow3gKeyState1_t t_ctx;

                if (tLenInBytes[i] == 0)
                        continue;

                snow3gStateConvert_8(&ctx, &t_ctx, i);
                f8_snow3g(&t_ctx, tBufferIn[i], tBufferOut[i], tLenInBytes[i]);
        }

#ifdef SAFE_DATA
        CLEAR_MEM(&ctx, sizeof(ctx));
        CLEAR_MEM(&ks, sizeof(ks));
        CLEAR_MEM(&in, sizeof(in));
#endif /* SAFE_DATA */
}

/*---------------------------------------------------------
 * @description
 *      Snow3G 8 buffer ks 8 multi:
 *      Processes 8 packets 8 bytes at a time.
 *      Uses same key schedule for each buffer.
 *---------------------------------------------------------*/
static inline void
snow3g_8_buffer_ks_8(uint32_t bytes,
                     const snow3g_key_schedule_t *pHandle,
                     const void *pIV1,
                     const void *pIV2,
                     const void *pIV3,
                     const void *pIV4,
                     const void *pIV5,
                     const void *pIV6,
                     const void *pIV7,
                     const void *pIV8,
                     const void *pBufferIn1, void *pBufferOut1,
                     const uint32_t lengthInBytes1,
                     const void *pBufferIn2, void *pBufferOut2,
                     const uint32_t lengthInBytes2,
                     const void *pBufferIn3, void *pBufferOut3,
                     const uint32_t lengthInBytes3,
                     const void *pBufferIn4, void *pBufferOut4,
                     const uint32_t lengthInBytes4,
                     const void *pBufferIn5, void *pBufferOut5,
                     const uint32_t lengthInBytes5,
                     const void *pBufferIn6, void *pBufferOut6,
                     const uint32_t lengthInBytes6,
                     const void *pBufferIn7, void *pBufferOut7,
                     const uint32_t lengthInBytes7,
                     const void *pBufferIn8, void *pBufferOut8,
                     const uint32_t lengthInBytes8)
{
        const uint32_t qwords = bytes / SNOW3G_8_BYTES;
        __m256i H, L; /* 8 bytes of keystream */
        snow3gKeyState8_t ctx;
        int i;
        uint32_t lenInBytes1 = lengthInBytes1;
        uint32_t lenInBytes2 = lengthInBytes2;
        uint32_t lenInBytes3 = lengthInBytes3;
        uint32_t lenInBytes4 = lengthInBytes4;
        uint32_t lenInBytes5 = lengthInBytes5;
        uint32_t lenInBytes6 = lengthInBytes6;
        uint32_t lenInBytes7 = lengthInBytes7;
        uint32_t lenInBytes8 = lengthInBytes8;
        uint8_t *pBufOut1 = pBufferOut1;
        uint8_t *pBufOut2 = pBufferOut2;
        uint8_t *pBufOut3 = pBufferOut3;
        uint8_t *pBufOut4 = pBufferOut4;
        uint8_t *pBufOut5 = pBufferOut5;
        uint8_t *pBufOut6 = pBufferOut6;
        uint8_t *pBufOut7 = pBufferOut7;
        uint8_t *pBufOut8 = pBufferOut8;
        const uint8_t *pBufIn1 = pBufferIn1;
        const uint8_t *pBufIn2 = pBufferIn2;
        const uint8_t *pBufIn3 = pBufferIn3;
        const uint8_t *pBufIn4 = pBufferIn4;
        const uint8_t *pBufIn5 = pBufferIn5;
        const uint8_t *pBufIn6 = pBufferIn6;
        const uint8_t *pBufIn7 = pBufferIn7;
        const uint8_t *pBufIn8 = pBufferIn8;

        bytes = qwords * SNOW3G_8_BYTES; /* rounded down minimum length */

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_8(&ctx, pHandle, pIV1, pIV2, pIV3,
                                pIV4, pIV5, pIV6, pIV7, pIV8);

        /* Clock FSM and LFSR once, ignore the keystream */
        snow3g_keystream_8_4(&ctx, &L);

        lenInBytes1 -= bytes;
        lenInBytes2 -= bytes;
        lenInBytes3 -= bytes;
        lenInBytes4 -= bytes;
        lenInBytes5 -= bytes;
        lenInBytes6 -= bytes;
        lenInBytes7 -= bytes;
        lenInBytes8 -= bytes;

        /* generates 8 sets at a time on all streams */
        for (i = qwords; i != 0; i--) {
                snow3g_keystream_8_8(&ctx, &L, &H);

                pBufIn1 = xor_keystrm_rev(pBufOut1, pBufIn1,
                                          _mm256_extract_epi64(L, 0));
                pBufIn2 = xor_keystrm_rev(pBufOut2, pBufIn2,
                                          _mm256_extract_epi64(L, 1));
                pBufIn3 = xor_keystrm_rev(pBufOut3, pBufIn3,
                                          _mm256_extract_epi64(H, 0));
                pBufIn4 = xor_keystrm_rev(pBufOut4, pBufIn4,
                                          _mm256_extract_epi64(H, 1));
                pBufIn5 = xor_keystrm_rev(pBufOut5, pBufIn5,
                                          _mm256_extract_epi64(L, 2));
                pBufIn6 = xor_keystrm_rev(pBufOut6, pBufIn6,
                                          _mm256_extract_epi64(L, 3));
                pBufIn7 = xor_keystrm_rev(pBufOut7, pBufIn7,
                                          _mm256_extract_epi64(H, 2));
                pBufIn8 = xor_keystrm_rev(pBufOut8, pBufIn8,
                                          _mm256_extract_epi64(H, 3));

                pBufOut1 += SNOW3G_8_BYTES;
                pBufOut2 += SNOW3G_8_BYTES;
                pBufOut3 += SNOW3G_8_BYTES;
                pBufOut4 += SNOW3G_8_BYTES;
                pBufOut5 += SNOW3G_8_BYTES;
                pBufOut6 += SNOW3G_8_BYTES;
                pBufOut7 += SNOW3G_8_BYTES;
                pBufOut8 += SNOW3G_8_BYTES;
        }

        /* process the remaining of each buffer
         *  - extract the LFSR and FSM structures
         *  - Continue process 1 buffer
         */
        if (lenInBytes1) {
                snow3gKeyState1_t ctx1;

                snow3gStateConvert_8(&ctx, &ctx1, 0);
                f8_snow3g(&ctx1, pBufIn1, pBufOut1, lenInBytes1);
        }

        if (lenInBytes2) {
                snow3gKeyState1_t ctx2;

                snow3gStateConvert_8(&ctx, &ctx2, 1);
                f8_snow3g(&ctx2, pBufIn2, pBufOut2, lenInBytes2);
        }

        if (lenInBytes3) {
                snow3gKeyState1_t ctx3;

                snow3gStateConvert_8(&ctx, &ctx3, 2);
                f8_snow3g(&ctx3, pBufIn3, pBufOut3, lenInBytes3);
        }

        if (lenInBytes4) {
                snow3gKeyState1_t ctx4;

                snow3gStateConvert_8(&ctx, &ctx4, 3);
                f8_snow3g(&ctx4, pBufIn4, pBufOut4, lenInBytes4);
        }

        if (lenInBytes5) {
                snow3gKeyState1_t ctx5;

                snow3gStateConvert_8(&ctx, &ctx5, 4);
                f8_snow3g(&ctx5, pBufIn5, pBufOut5, lenInBytes5);
        }

        if (lenInBytes6) {
                snow3gKeyState1_t ctx6;

                snow3gStateConvert_8(&ctx, &ctx6, 5);
                f8_snow3g(&ctx6, pBufIn6, pBufOut6, lenInBytes6);
        }

        if (lenInBytes7) {
                snow3gKeyState1_t ctx7;

                snow3gStateConvert_8(&ctx, &ctx7, 6);
                f8_snow3g(&ctx7, pBufIn7, pBufOut7, lenInBytes7);
        }

        if (lenInBytes8) {
                snow3gKeyState1_t ctx8;

                snow3gStateConvert_8(&ctx, &ctx8, 7);
                f8_snow3g(&ctx8, pBufIn8, pBufOut8, lenInBytes8);
        }

#ifdef SAFE_DATA
        H = _mm256_setzero_si256();
        L = _mm256_setzero_si256();
        CLEAR_MEM(&ctx, sizeof(ctx));
#endif /* SAFE_DATA */
}

/*---------------------------------------------------------
 * @description
 *      Snow3G 8 buffer ks 32 multi:
 *      Processes 8 packets 32 bytes at a time.
 *      Uses same key schedule for each buffer.
 *---------------------------------------------------------*/
static inline void
snow3g_8_buffer_ks_32(uint32_t bytes,
                      const snow3g_key_schedule_t *pKey,
                      const void *pIV1, const void *pIV2,
                      const void *pIV3, const void *pIV4,
                      const void *pIV5, const void *pIV6,
                      const void *pIV7, const void *pIV8,
                      const void *pBufferIn1, void *pBufferOut1,
                      const uint32_t lengthInBytes1,
                      const void *pBufferIn2, void *pBufferOut2,
                      const uint32_t lengthInBytes2,
                      const void *pBufferIn3, void *pBufferOut3,
                      const uint32_t lengthInBytes3,
                      const void *pBufferIn4, void *pBufferOut4,
                      const uint32_t lengthInBytes4,
                      const void *pBufferIn5, void *pBufferOut5,
                      const uint32_t lengthInBytes5,
                      const void *pBufferIn6, void *pBufferOut6,
                      const uint32_t lengthInBytes6,
                      const void *pBufferIn7, void *pBufferOut7,
                      const uint32_t lengthInBytes7,
                      const void *pBufferIn8, void *pBufferOut8,
                      const uint32_t lengthInBytes8)
{
        snow3gKeyState8_t ctx;
        uint32_t i;
        uint32_t lenInBytes1 = lengthInBytes1;
        uint32_t lenInBytes2 = lengthInBytes2;
        uint32_t lenInBytes3 = lengthInBytes3;
        uint32_t lenInBytes4 = lengthInBytes4;
        uint32_t lenInBytes5 = lengthInBytes5;
        uint32_t lenInBytes6 = lengthInBytes6;
        uint32_t lenInBytes7 = lengthInBytes7;
        uint32_t lenInBytes8 = lengthInBytes8;
        uint8_t *pBufOut1 = pBufferOut1;
        uint8_t *pBufOut2 = pBufferOut2;
        uint8_t *pBufOut3 = pBufferOut3;
        uint8_t *pBufOut4 = pBufferOut4;
        uint8_t *pBufOut5 = pBufferOut5;
        uint8_t *pBufOut6 = pBufferOut6;
        uint8_t *pBufOut7 = pBufferOut7;
        uint8_t *pBufOut8 = pBufferOut8;
        const uint8_t *pBufIn1 = pBufferIn1;
        const uint8_t *pBufIn2 = pBufferIn2;
        const uint8_t *pBufIn3 = pBufferIn3;
        const uint8_t *pBufIn4 = pBufferIn4;
        const uint8_t *pBufIn5 = pBufferIn5;
        const uint8_t *pBufIn6 = pBufferIn6;
        const uint8_t *pBufIn7 = pBufferIn7;
        const uint8_t *pBufIn8 = pBufferIn8;

        uint32_t blocks = bytes / 32;

        bytes = blocks * 32; /* rounded down minimum length */

        /* Initialize the schedule from the IV */
        snow3gStateInitialize_8(&ctx, pKey, pIV1, pIV2, pIV3, pIV4, pIV5, pIV6,
                                pIV7, pIV8);

        /* Clock FSM and LFSR once, ignore the keystream */
        __m256i ks[8];

        snow3g_keystream_8_4(&ctx, ks);

        lenInBytes1 -= bytes;
        lenInBytes2 -= bytes;
        lenInBytes3 -= bytes;
        lenInBytes4 -= bytes;
        lenInBytes5 -= bytes;
        lenInBytes6 -= bytes;
        lenInBytes7 -= bytes;
        lenInBytes8 -= bytes;

        __m256i in[8];

        /* generates 8 sets at a time on all streams */
        for (i = 0; i < blocks; i++) {

                in[0] = _mm256_loadu_si256((const __m256i *)pBufIn1);
                in[1] = _mm256_loadu_si256((const __m256i *)pBufIn2);
                in[2] = _mm256_loadu_si256((const __m256i *)pBufIn3);
                in[3] = _mm256_loadu_si256((const __m256i *)pBufIn4);
                in[4] = _mm256_loadu_si256((const __m256i *)pBufIn5);
                in[5] = _mm256_loadu_si256((const __m256i *)pBufIn6);
                in[6] = _mm256_loadu_si256((const __m256i *)pBufIn7);
                in[7] = _mm256_loadu_si256((const __m256i *)pBufIn8);

                snow3g_keystream_8_32(&ctx, ks);

                _mm256_storeu_si256((__m256i *)pBufOut1,
                                    _mm256_xor_si256(in[0], ks[0]));
                _mm256_storeu_si256((__m256i *)pBufOut2,
                                    _mm256_xor_si256(in[1], ks[1]));
                _mm256_storeu_si256((__m256i *)pBufOut3,
                                    _mm256_xor_si256(in[2], ks[2]));
                _mm256_storeu_si256((__m256i *)pBufOut4,
                                    _mm256_xor_si256(in[3], ks[3]));
                _mm256_storeu_si256((__m256i *)pBufOut5,
                                    _mm256_xor_si256(in[4], ks[4]));
                _mm256_storeu_si256((__m256i *)pBufOut6,
                                    _mm256_xor_si256(in[5], ks[5]));
                _mm256_storeu_si256((__m256i *)pBufOut7,
                                    _mm256_xor_si256(in[6], ks[6]));
                _mm256_storeu_si256((__m256i *)pBufOut8,
                                    _mm256_xor_si256(in[7], ks[7]));

                pBufIn1 += 32;
                pBufIn2 += 32;
                pBufIn3 += 32;
                pBufIn4 += 32;
                pBufIn5 += 32;
                pBufIn6 += 32;
                pBufIn7 += 32;
                pBufIn8 += 32;

                pBufOut1 += 32;
                pBufOut2 += 32;
                pBufOut3 += 32;
                pBufOut4 += 32;
                pBufOut5 += 32;
                pBufOut6 += 32;
                pBufOut7 += 32;
                pBufOut8 += 32;
        }

        /* process the remaining of each buffer
         *  - extract the LFSR and FSM structures
         *  - Continue process 1 buffer
         */
        if (lenInBytes1) {
                snow3gKeyState1_t ctx1;

                snow3gStateConvert_8(&ctx, &ctx1, 0);
                f8_snow3g(&ctx1, pBufIn1, pBufOut1, lenInBytes1);
        }

        if (lenInBytes2) {
                snow3gKeyState1_t ctx2;

                snow3gStateConvert_8(&ctx, &ctx2, 1);
                f8_snow3g(&ctx2, pBufIn2, pBufOut2, lenInBytes2);
        }

        if (lenInBytes3) {
                snow3gKeyState1_t ctx3;

                snow3gStateConvert_8(&ctx, &ctx3, 2);
                f8_snow3g(&ctx3, pBufIn3, pBufOut3, lenInBytes3);
        }

        if (lenInBytes4) {
                snow3gKeyState1_t ctx4;

                snow3gStateConvert_8(&ctx, &ctx4, 3);
                f8_snow3g(&ctx4, pBufIn4, pBufOut4, lenInBytes4);
        }

        if (lenInBytes5) {
                snow3gKeyState1_t ctx5;

                snow3gStateConvert_8(&ctx, &ctx5, 4);
                f8_snow3g(&ctx5, pBufIn5, pBufOut5, lenInBytes5);
        }

        if (lenInBytes6) {
                snow3gKeyState1_t ctx6;

                snow3gStateConvert_8(&ctx, &ctx6, 5);
                f8_snow3g(&ctx6, pBufIn6, pBufOut6, lenInBytes6);
        }

        if (lenInBytes7) {
                snow3gKeyState1_t ctx7;

                snow3gStateConvert_8(&ctx, &ctx7, 6);
                f8_snow3g(&ctx7, pBufIn7, pBufOut7, lenInBytes7);
        }

        if (lenInBytes8) {
                snow3gKeyState1_t ctx8;

                snow3gStateConvert_8(&ctx, &ctx8, 7);
                f8_snow3g(&ctx8, pBufIn8, pBufOut8, lenInBytes8);
        }

#ifdef SAFE_DATA
        CLEAR_MEM(&ctx, sizeof(ctx));
        CLEAR_MEM(&ks, sizeof(ks));
        CLEAR_MEM(&in, sizeof(in));
#endif /* SAFE_DATA */
}
#endif /* AVX2 */

/*---------------------------------------------------------
 * @description
 *      Snow3G F8 8 buffer, multi-key:
 *      Eight packets enc/dec with eight respective key schedules.
 *      The 8 IVs are independent and are passed as an array of pointers.
 *      Each buffer and data length are separate.
 *---------------------------------------------------------*/
void SNOW3G_F8_8_BUFFER_MULTIKEY(const snow3g_key_schedule_t * const pKey[],
                                 const void * const IV[],
                                 const void * const BufferIn[],
                                 void *BufferOut[],
                                 const uint32_t lengthInBytes[])
{
        int i;

#ifdef SAFE_PARAM
        if ((pKey == NULL) || (IV == NULL) || (BufferIn == NULL) ||
            (BufferOut == NULL) || (lengthInBytes == NULL))
                return;

        for (i = 0; i < 8; i++)
                if ((pKey[i] == NULL) || (IV[i] == NULL) ||
                    (BufferIn[i] == NULL) || (BufferOut[i] == NULL) ||
                    (lengthInBytes[i] == 0) ||
                    (lengthInBytes[i] > SNOW3G_MAX_BYTELEN))
                        return;
#endif

#ifndef AVX2
        /* basic C workaround for lack of non AVX2 implementation */
        for (i = 0; i < 8; i++)
                SNOW3G_F8_1_BUFFER(pKey[i], IV[i], BufferIn[i], BufferOut[i],
                                   lengthInBytes[i]);
#else
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        uint32_t bytes = lengthInBytes[0];

        /* find min byte lenght */
        for (i = 1; i < 8; i++)
                if (lengthInBytes[i] < bytes)
                        bytes = lengthInBytes[i];

        if (bytes % 32) {
                snow3g_8_buffer_ks_8_multi(bytes, pKey, IV, BufferIn, BufferOut,
                                           lengthInBytes);
        } else {
                snow3g_8_buffer_ks_32_multi(bytes, pKey, IV, BufferIn,
                                            BufferOut, lengthInBytes);
        }
#ifdef SAFE_DATA
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif
#endif /* AVX2 */
}

/*---------------------------------------------------------
 * @description
 *      Snow3G F8 8 buffer:
 *      Eight packets enc/dec with the same key schedule.
 *      The 8 IVs are independent and are passed as an array of pointers.
 *      Each buffer and data length are separate.
 *      Uses AVX instructions.
 *---------------------------------------------------------*/
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
#ifdef SAFE_PARAM
        if ((pHandle == NULL) ||
            (pIV1 == NULL) || (pIV2 == NULL) ||
            (pIV3 == NULL) || (pIV4 == NULL) ||
            (pIV5 == NULL) || (pIV6 == NULL) ||
            (pIV7 == NULL) || (pIV8 == NULL) ||
            (pBufIn1 == NULL) || (pBufOut1 == NULL) ||
            (pBufIn2 == NULL) || (pBufOut2 == NULL) ||
            (pBufIn3 == NULL) || (pBufOut3 == NULL) ||
            (pBufIn4 == NULL) || (pBufOut4 == NULL) ||
            (pBufIn5 == NULL) || (pBufOut5 == NULL) ||
            (pBufIn6 == NULL) || (pBufOut6 == NULL) ||
            (pBufIn7 == NULL) || (pBufOut7 == NULL) ||
            (pBufIn8 == NULL) || (pBufOut8 == NULL) ||
            (lenInBytes1 == 0) || (lenInBytes1 > SNOW3G_MAX_BYTELEN) ||
            (lenInBytes2 == 0) || (lenInBytes2 > SNOW3G_MAX_BYTELEN) ||
            (lenInBytes3 == 0) || (lenInBytes3 > SNOW3G_MAX_BYTELEN) ||
            (lenInBytes4 == 0) || (lenInBytes4 > SNOW3G_MAX_BYTELEN) ||
            (lenInBytes5 == 0) || (lenInBytes5 > SNOW3G_MAX_BYTELEN) ||
            (lenInBytes6 == 0) || (lenInBytes6 > SNOW3G_MAX_BYTELEN) ||
            (lenInBytes7 == 0) || (lenInBytes7 > SNOW3G_MAX_BYTELEN) ||
            (lenInBytes8 == 0) || (lenInBytes8 > SNOW3G_MAX_BYTELEN))
                return;
#endif

#ifdef AVX2
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        uint32_t bytes1 =
                (lenInBytes1 < lenInBytes2 ? lenInBytes1
                                           : lenInBytes2); /* number of bytes */
        uint32_t bytes2 =
                (lenInBytes3 < lenInBytes4 ? lenInBytes3
                                           : lenInBytes4); /* number of bytes */
        uint32_t bytes3 =
                (lenInBytes5 < lenInBytes6 ? lenInBytes5
                                           : lenInBytes6); /* number of bytes */
        uint32_t bytes4 =
                (lenInBytes7 < lenInBytes8 ? lenInBytes7
                                           : lenInBytes8); /* number of bytes */
        uint32_t bytesq1 =
                (bytes1 < bytes2) ? bytes1 : bytes2; /* min number of bytes */
        uint32_t bytesq2 = (bytes3 < bytes4) ? bytes3 : bytes4;
        uint32_t bytes = (bytesq1 < bytesq2) ? bytesq1 : bytesq2;

        if (bytes % 32) {
                snow3g_8_buffer_ks_8(
                        bytes, pHandle, pIV1, pIV2, pIV3, pIV4, pIV5, pIV6,
                        pIV7, pIV8, pBufIn1, pBufOut1, lenInBytes1, pBufIn2,
                        pBufOut2, lenInBytes2, pBufIn3, pBufOut3, lenInBytes3,
                        pBufIn4, pBufOut4, lenInBytes4, pBufIn5, pBufOut5,
                        lenInBytes5, pBufIn6, pBufOut6, lenInBytes6, pBufIn7,
                        pBufOut7, lenInBytes7, pBufIn8, pBufOut8, lenInBytes8);
        } else {
                snow3g_8_buffer_ks_32(
                        bytes, pHandle, pIV1, pIV2, pIV3, pIV4, pIV5, pIV6,
                        pIV7, pIV8, pBufIn1, pBufOut1, lenInBytes1, pBufIn2,
                        pBufOut2, lenInBytes2, pBufIn3, pBufOut3, lenInBytes3,
                        pBufIn4, pBufOut4, lenInBytes4, pBufIn5, pBufOut5,
                        lenInBytes5, pBufIn6, pBufOut6, lenInBytes6, pBufIn7,
                        pBufOut7, lenInBytes7, pBufIn8, pBufOut8, lenInBytes8);
        }
#ifdef SAFE_DATA
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif
#else  /* ~AVX2 */
        SNOW3G_F8_2_BUFFER(pHandle, pIV1, pIV2, pBufIn1, pBufOut1, lenInBytes1,
                           pBufIn2, pBufOut2, lenInBytes2);

        SNOW3G_F8_2_BUFFER(pHandle, pIV3, pIV4, pBufIn3, pBufOut3, lenInBytes3,
                           pBufIn4, pBufOut4, lenInBytes4);

        SNOW3G_F8_2_BUFFER(pHandle, pIV5, pIV6, pBufIn5, pBufOut5, lenInBytes5,
                           pBufIn6, pBufOut6, lenInBytes6);

        SNOW3G_F8_2_BUFFER(pHandle, pIV7, pIV8, pBufIn7, pBufOut7, lenInBytes7,
                           pBufIn8, pBufOut8, lenInBytes8);
#endif /* AVX */
}

/******************************************************************************
 * @description
 *      Snow3G F8 multi packet:
 *      Performs F8 enc/dec on [n] packets. The operation is performed in-place.
 *      The input IV's are passed in Little Endian format.
 *      The KeySchedule is in Little Endian format.
 ******************************************************************************/
void SNOW3G_F8_N_BUFFER(const snow3g_key_schedule_t *pCtx,
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
                if ((IV[i] == NULL) || (pBufferIn[i] == NULL) ||
                    (pBufferOut[i] == NULL) || (bufLenInBytes[i] == 0) ||
                    (bufLenInBytes[i] > SNOW3G_MAX_BYTELEN))
                        return;
#endif
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        if (packetCount > 16) {
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
#ifdef AVX2
        while (pktCnt >= 8) {
                pktCnt -= 8;
                SNOW3G_F8_8_BUFFER(pCtx, pIV[packet_index],
                                   pIV[packet_index + 1],
                                   pIV[packet_index + 2],
                                   pIV[packet_index + 3],
                                   pIV[packet_index + 4],
                                   pIV[packet_index + 5],
                                   pIV[packet_index + 6],
                                   pIV[packet_index + 7],
                                   pSrcBuf[packet_index],
                                   pDstBuf[packet_index],
                                   lensBuf[packet_index],
                                   pSrcBuf[packet_index + 1],
                                   pDstBuf[packet_index + 1],
                                   lensBuf[packet_index + 1],
                                   pSrcBuf[packet_index + 2],
                                   pDstBuf[packet_index + 2],
                                   lensBuf[packet_index + 2],
                                   pSrcBuf[packet_index + 3],
                                   pDstBuf[packet_index + 3],
                                   lensBuf[packet_index + 3],
                                   pSrcBuf[packet_index + 4],
                                   pDstBuf[packet_index + 4],
                                   lensBuf[packet_index + 4],
                                   pSrcBuf[packet_index + 5],
                                   pDstBuf[packet_index + 5],
                                   lensBuf[packet_index + 5],
                                   pSrcBuf[packet_index + 6],
                                   pDstBuf[packet_index + 6],
                                   lensBuf[packet_index + 6],
                                   pSrcBuf[packet_index + 7],
                                   pDstBuf[packet_index + 7],
                                   lensBuf[packet_index + 7]);
                packet_index += 8;
        }
#endif
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

        if (packetCount > 16) {
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
#ifdef AVX2
        while (pktCnt >= 8) {
                pktCnt -= 8;
                SNOW3G_F8_8_BUFFER_MULTIKEY(
                        (const snow3g_key_schedule_t * const *)
                        &pCtxBuf[packet_index],
                        (const void * const *)&pIV[packet_index],
                        (const void * const *)&pSrcBuf[packet_index],
                        (void **)&pDstBuf[packet_index],
                        &lensBuf[packet_index]);
                packet_index += 8;
        }
#endif
        /* TODO process 4 buffers at-a-time */
        /* TODO process 2 packets at-a-time */
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

/*---------------------------------------------------------
 * @description
 *      Snow3G F9 1 buffer
 *      Single buffer digest with IV and precomputed key schedule
 *---------------------------------------------------------*/
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
        uint64_t lengthInQwords, E, V, P;
        uint64_t i, rem_bits;
        const uint64_t *inputBuffer;

        inputBuffer = (const uint64_t *)pBufferIn;

        /* Initialize the snow3g key schedule */
        snow3gStateInitialize_1(&ctx, pHandle, pIV);

        /*Generate 5 keystream words*/
        snow3g_f9_keystream_words(&ctx, &z[0]);

        P = ((uint64_t)z[0] << 32) | ((uint64_t)z[1]);

        lengthInQwords = lengthInBits / 64;

        E = 0;
        /* all blocks except the last one */
        for (i = 0; i < lengthInQwords; i++) {
                V = BSWAP64(inputBuffer[i]);
                E = multiply_and_reduce64(E ^ V, P);
        }

        /* last bits of last block if any left */
        rem_bits = lengthInBits % 64;
        if (rem_bits) {
                /* last bytes, do not go past end of buffer */
                memcpy(&V, &inputBuffer[i], (rem_bits + 7) / 8);
                V = BSWAP64(V);
                V &= (((uint64_t)-1) << (64 - rem_bits)); /* mask extra bits */
                E = multiply_and_reduce64(E ^ V, P);
        }

        /* Multiply by Q */
        E = multiply_and_reduce64(E ^ lengthInBits,
                                  (((uint64_t)z[2] << 32) | ((uint64_t)z[3])));

        /* Final MAC */
        *(uint32_t *)pDigest =
                (uint32_t)BSWAP64(E ^ ((uint64_t)z[4] << 32));
#ifdef SAFE_DATA
        CLEAR_VAR(&E, sizeof(E));
        CLEAR_VAR(&V, sizeof(V));
        CLEAR_VAR(&P, sizeof(P));
        CLEAR_MEM(&z, sizeof(z));
        CLEAR_MEM(&ctx, sizeof(ctx));
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */
}

#endif /* SNOW3G_COMMON_H */
