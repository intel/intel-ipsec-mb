/*******************************************************************************
  Copyright (c) 2009-2026, Intel Corporation

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

/*---------------------------------------------------------
 * Kasumi_internal.h
 *---------------------------------------------------------*/

#ifndef _KASUMI_INTERNAL_H_
#define _KASUMI_INTERNAL_H_

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "intel-ipsec-mb.h"
#include "wireless_common.h"
#include "include/clear_regs_mem.h"
#include "include/constant_lookup.h"
#include "memcpy.h"
#include "error.h"
#include "kasumi_interface.h"
#include "include/arch_avx2_type1.h"
#include "include/arch_avx512_type1.h"

/*---------------------------------------------------------------------
 * Kasumi Inner S-Boxes
 *---------------------------------------------------------------------*/

/* Table version based on a small table, no cache trash */
static const uint16_t sso_kasumi_S7e[] = {
        0x6c00, 0x6601, 0x7802, 0x7603, 0x2404, 0x4e05, 0xb006, 0xce07, 0x5c08, 0x1e09, 0x6a0a,
        0xac0b, 0x1c0c, 0x3e0d, 0xea0e, 0x5c0f, 0x4e10, 0xc011, 0x6a12, 0xc213, 0x0214, 0xac15,
        0xae16, 0x3617, 0x6e18, 0xa019, 0x681a, 0x001b, 0x0a1c, 0xe41d, 0xc41e, 0x9c1f, 0x2a20,
        0x5021, 0xb622, 0xd823, 0x2024, 0x3225, 0x3826, 0x2e27, 0x9a28, 0xac29, 0x042a, 0xa62b,
        0x882c, 0xd62d, 0xd22e, 0x082f, 0x4830, 0x9631, 0xf432, 0x1c33, 0x4634, 0xb035, 0x7636,
        0xa637, 0xea38, 0x7039, 0x543a, 0x783b, 0xdc3c, 0x6e3d, 0xae3e, 0xba3f, 0x6a40, 0x6a41,
        0x1c42, 0x9043, 0x3a44, 0x5e45, 0x8c46, 0x7447, 0x7c48, 0x5449, 0x384a, 0x1c4b, 0xa44c,
        0xe84d, 0x604e, 0x304f, 0x4050, 0xc451, 0x8652, 0xac53, 0x1654, 0xb655, 0x1856, 0x0657,
        0x0658, 0xa259, 0xf25a, 0x785b, 0xf85c, 0x785d, 0x845e, 0x3a5f, 0x0c60, 0xfc61, 0xf062,
        0x9c63, 0x5e64, 0xc265, 0x6666, 0x7667, 0x9a68, 0x4669, 0x746a, 0xb46b, 0x506c, 0xe06d,
        0x3a6e, 0x866f, 0x6070, 0x3471, 0x3c72, 0xd673, 0x3474, 0x4c75, 0xa476, 0x7277, 0xa478,
        0xd479, 0xea7a, 0xa47b, 0x487c, 0x147d, 0x8a7e, 0xf87f, 0x6c00, 0x6601, 0x7802, 0x7603,
        0x2404, 0x4e05, 0xb006, 0xce07, 0x5c08, 0x1e09, 0x6a0a, 0xac0b, 0x1c0c, 0x3e0d, 0xea0e,
        0x5c0f, 0x4e10, 0xc011, 0x6a12, 0xc213, 0x0214, 0xac15, 0xae16, 0x3617, 0x6e18, 0xa019,
        0x681a, 0x001b, 0x0a1c, 0xe41d, 0xc41e, 0x9c1f, 0x2a20, 0x5021, 0xb622, 0xd823, 0x2024,
        0x3225, 0x3826, 0x2e27, 0x9a28, 0xac29, 0x042a, 0xa62b, 0x882c, 0xd62d, 0xd22e, 0x082f,
        0x4830, 0x9631, 0xf432, 0x1c33, 0x4634, 0xb035, 0x7636, 0xa637, 0xea38, 0x7039, 0x543a,
        0x783b, 0xdc3c, 0x6e3d, 0xae3e, 0xba3f, 0x6a40, 0x6a41, 0x1c42, 0x9043, 0x3a44, 0x5e45,
        0x8c46, 0x7447, 0x7c48, 0x5449, 0x384a, 0x1c4b, 0xa44c, 0xe84d, 0x604e, 0x304f, 0x4050,
        0xc451, 0x8652, 0xac53, 0x1654, 0xb655, 0x1856, 0x0657, 0x0658, 0xa259, 0xf25a, 0x785b,
        0xf85c, 0x785d, 0x845e, 0x3a5f, 0x0c60, 0xfc61, 0xf062, 0x9c63, 0x5e64, 0xc265, 0x6666,
        0x7667, 0x9a68, 0x4669, 0x746a, 0xb46b, 0x506c, 0xe06d, 0x3a6e, 0x866f, 0x6070, 0x3471,
        0x3c72, 0xd673, 0x3474, 0x4c75, 0xa476, 0x7277, 0xa478, 0xd479, 0xea7a, 0xa47b, 0x487c,
        0x147d, 0x8a7e, 0xf87f
};

static const uint16_t sso_kasumi_S9e[] = {
        0x4ea7, 0xdeef, 0x42a1, 0xf77b, 0x0f87, 0x9d4e, 0x1209, 0xa552, 0x4c26, 0xc4e2, 0x6030,
        0xcd66, 0x89c4, 0x0381, 0xb45a, 0x1b8d, 0x6eb7, 0xfafd, 0x2693, 0x974b, 0x3f9f, 0xa954,
        0x6633, 0xd56a, 0x6532, 0xe9f4, 0x0d06, 0xa452, 0xb0d8, 0x3e9f, 0xc964, 0x62b1, 0x5eaf,
        0xe2f1, 0xd3e9, 0x4a25, 0x9cce, 0x2211, 0x0000, 0x9b4d, 0x582c, 0xfcfe, 0xf57a, 0x743a,
        0x1e8f, 0xb8dc, 0xa251, 0x2190, 0xbe5f, 0x0603, 0x773b, 0xeaf5, 0x6c36, 0xd6eb, 0xb4da,
        0x2b95, 0xb1d8, 0x1108, 0x58ac, 0xddee, 0xe773, 0x4522, 0x1f8f, 0x984c, 0x4aa5, 0x8ac5,
        0x178b, 0xf279, 0x0301, 0xc1e0, 0x4fa7, 0xa8d4, 0xe0f0, 0x381c, 0x9dce, 0x60b0, 0x2d96,
        0xf7fb, 0x4120, 0xbedf, 0xebf5, 0x2f97, 0xf2f9, 0x1309, 0xb259, 0x74ba, 0xbadd, 0x59ac,
        0x48a4, 0x944a, 0x71b8, 0x88c4, 0x95ca, 0x4ba5, 0xbd5e, 0x46a3, 0xd0e8, 0x3c9e, 0x0c86,
        0xc562, 0x1a0d, 0xf4fa, 0xd7eb, 0x1c8e, 0x7ebf, 0x8a45, 0x82c1, 0x53a9, 0x3098, 0xc6e3,
        0xdd6e, 0x0e87, 0xb158, 0x592c, 0x2914, 0xe4f2, 0x6bb5, 0x8140, 0xe271, 0x2d16, 0x160b,
        0xe6f3, 0xae57, 0x7b3d, 0x4824, 0xba5d, 0xe1f0, 0x361b, 0xcfe7, 0x7dbe, 0xc5e2, 0x5229,
        0x8844, 0x389c, 0x93c9, 0x0683, 0x8d46, 0x2793, 0xa753, 0x2814, 0x4e27, 0xe673, 0x75ba,
        0xf87c, 0xb7db, 0x0180, 0xf9fc, 0x6a35, 0xe070, 0x54aa, 0xbfdf, 0x2e97, 0xfc7e, 0x52a9,
        0x9249, 0x190c, 0x2f17, 0x8341, 0x50a8, 0xd96c, 0xd76b, 0x4924, 0x5c2e, 0xe7f3, 0x1389,
        0x8f47, 0x8944, 0x3018, 0x91c8, 0x170b, 0x3a9d, 0x99cc, 0xd1e8, 0x55aa, 0x6b35, 0xcae5,
        0x6fb7, 0xf5fa, 0xa0d0, 0x1f0f, 0xbb5d, 0x2391, 0x65b2, 0xd8ec, 0x2010, 0xa2d1, 0xcf67,
        0x6834, 0x7038, 0xf078, 0x8ec7, 0x2b15, 0xa3d1, 0x41a0, 0xf8fc, 0x3f1f, 0xecf6, 0x0c06,
        0xa653, 0x6331, 0x49a4, 0xb359, 0x3299, 0xedf6, 0x8241, 0x7a3d, 0xe8f4, 0x351a, 0x5aad,
        0xbcde, 0x45a2, 0x8643, 0x0582, 0xe170, 0x0b05, 0xca65, 0xb9dc, 0x4723, 0x86c3, 0x5dae,
        0x6231, 0x9e4f, 0x4ca6, 0x954a, 0x3118, 0xff7f, 0xeb75, 0x0080, 0xfd7e, 0x3198, 0x369b,
        0xdfef, 0xdf6f, 0x0984, 0x2512, 0xd66b, 0x97cb, 0x43a1, 0x7c3e, 0x8dc6, 0x0884, 0xc2e1,
        0x96cb, 0x793c, 0xd4ea, 0x1c0e, 0x5b2d, 0xb65b, 0xeff7, 0x3d1e, 0x51a8, 0xa6d3, 0xb75b,
        0x6733, 0x188c, 0xed76, 0x4623, 0xce67, 0xfa7d, 0x57ab, 0x2613, 0xacd6, 0x8bc5, 0x2492,
        0xe5f2, 0x753a, 0x79bc, 0xcce6, 0x0100, 0x9349, 0x8cc6, 0x3b1d, 0x6432, 0xe874, 0x9c4e,
        0x359a, 0x140a, 0x9acd, 0xfdfe, 0x56ab, 0xcee7, 0x5a2d, 0x168b, 0xa7d3, 0x3a1d, 0xac56,
        0xf3f9, 0x4020, 0x9048, 0x341a, 0xad56, 0x2c96, 0x7339, 0xd5ea, 0x5faf, 0xdcee, 0x379b,
        0x8b45, 0x2a95, 0xb3d9, 0x5028, 0xee77, 0x5cae, 0xc763, 0x72b9, 0xd2e9, 0x0b85, 0x8e47,
        0x81c0, 0x2311, 0xe974, 0x6e37, 0xdc6e, 0x64b2, 0x8542, 0x180c, 0xabd5, 0x1188, 0xe371,
        0x7cbe, 0x0201, 0xda6d, 0xef77, 0x1289, 0x6ab5, 0xb058, 0x964b, 0x6934, 0x0904, 0xc9e4,
        0xc462, 0x2110, 0xe572, 0x2713, 0x399c, 0xde6f, 0xa150, 0x7d3e, 0x0804, 0xf1f8, 0xd9ec,
        0x0703, 0x6130, 0x9a4d, 0xa351, 0x67b3, 0x2a15, 0xcb65, 0x5f2f, 0x994c, 0xc7e3, 0x2412,
        0x5e2f, 0xaa55, 0x3219, 0xe3f1, 0xb5da, 0x4321, 0xc864, 0x1b0d, 0x5128, 0xbdde, 0x1d0e,
        0xd46a, 0x3e1f, 0xd068, 0x63b1, 0xa854, 0x3d9e, 0xcde6, 0x158a, 0xc060, 0xc663, 0x349a,
        0xffff, 0x2894, 0x3b9d, 0xd369, 0x3399, 0xfeff, 0x44a2, 0xaed7, 0x5d2e, 0x92c9, 0x150a,
        0xbf5f, 0xaf57, 0x2090, 0x73b9, 0xdb6d, 0xd86c, 0x552a, 0xf6fb, 0x4422, 0x6cb6, 0xfbfd,
        0x148a, 0xa4d2, 0x9f4f, 0x0a85, 0x6f37, 0xc160, 0x9148, 0x1a8d, 0x198c, 0xb55a, 0xf67b,
        0x7f3f, 0x85c2, 0x3319, 0x5bad, 0xc8e4, 0x77bb, 0xc3e1, 0xb85c, 0x2994, 0xcbe5, 0x4da6,
        0xf0f8, 0x5329, 0x2e17, 0xaad5, 0x0482, 0xa5d2, 0x2c16, 0xb2d9, 0x371b, 0x8c46, 0x4d26,
        0xd168, 0x47a3, 0xfe7f, 0x7138, 0xf379, 0x0e07, 0xa9d4, 0x84c2, 0x0402, 0xea75, 0x4f27,
        0x9fcf, 0x0502, 0xc0e0, 0x7fbf, 0xeef7, 0x76bb, 0xa050, 0x1d8e, 0x391c, 0xc361, 0xd269,
        0x0d86, 0x572b, 0xafd7, 0xadd6, 0x70b8, 0x7239, 0x90c8, 0xb95c, 0x7e3f, 0x98cc, 0x78bc,
        0x4221, 0x87c3, 0xc261, 0x3c1e, 0x6d36, 0xb6db, 0xbc5e, 0x40a0, 0x0281, 0xdbed, 0x8040,
        0x66b3, 0x0f07, 0xcc66, 0x7abd, 0x9ecf, 0xe472, 0x2592, 0x6db6, 0xbbdd, 0x0783, 0xf47a,
        0x80c0, 0x542a, 0xfb7d, 0x0a05, 0x2291, 0xec76, 0x68b4, 0x83c1, 0x4b25, 0x8743, 0x1088,
        0xf97c, 0x562b, 0x8442, 0x783c, 0x8fc7, 0xab55, 0x7bbd, 0x94ca, 0x61b0, 0x1008, 0xdaed,
        0x1e0f, 0xf178, 0x69b4, 0xa1d0, 0x763b, 0x9bcd
};

/* KASUMI cipher definitions */
#define NUM_KASUMI_ROUNDS (8) /* 8 rounds in the kasumi spec */
#define QWORDSIZEINBITS   (64)
#define QWORDSIZEINBYTES  (8)
#define LAST_PADDING_BIT  (1)

/*--------- 16 bit rotate left ------------------------------------------*/
#define ROL16(a, b) (uint16_t)((a << b) | (a >> (16 - b)))

/*----- a 64-bit structure to help with kasumi endian issues -----*/
typedef union _ku64 {
        uint64_t b64[1];
        uint32_t b32[2];
        uint16_t b16[4];
        uint8_t b8[8];
} kasumi_union_t;

typedef union SafeBuffer {
        uint64_t b64;
        uint32_t b32[2];
        uint8_t b8[IMB_KASUMI_BLOCK_SIZE];
} SafeBuf;

/*---------------------------------------------------------------------
 * Inline 16-bit left rotation
 *---------------------------------------------------------------------*/

#define ROL16(a, b) (uint16_t)((a << b) | (a >> (16 - b)))

static inline uint16_t
FIp1(uint16_t data, const uint16_t key1, const uint16_t key2, const uint16_t key3)
{
#ifdef AVX512
        return KASUMI_FI_AVX512(data, key1, key2, key3);
#elif defined(AVX2)
        return KASUMI_FI_AVX2(data, key1, key2, key3);
#else
        uint16_t datal, datah;

        data ^= key1;
        datal = LOOKUP16_SSE(sso_kasumi_S7e, (uint8_t) data, 256);
        datah = LOOKUP16_SSE(sso_kasumi_S9e, data >> 7, 512);
        data = datal ^ datah;
        data ^= key2;
        datal = LOOKUP16_SSE(sso_kasumi_S7e, data >> 9, 256);
        datah = LOOKUP16_SSE(sso_kasumi_S9e, data & 0x1FF, 512);
        data = datal ^ datah;
        data ^= key3;
        return data;
#endif
}

static inline void
FLpi(const uint16_t key1, const uint16_t key2, uint16_t *res_h, uint16_t *res_l)
{
        uint16_t l, r;

        r = (*res_l) & key1;
        r = (*res_h) ^ ROL16(r, 1);
        l = r | key2;
        *res_h = (*res_l) ^ ROL16(l, 1);
        *res_l = r;
}

static inline void
FLp1(const uint16_t *index, uint16_t *h, uint16_t *l)
{
        uint16_t ka = *(index + 0);
        uint16_t kb = *(index + 1);

        FLpi(ka, kb, h, l);
}

static inline void
FOp1(const uint16_t *index, uint16_t *h, uint16_t *l)
{
        *h = FIp1(*h, *(index + 2), *(index + 3), *l);
        *l = FIp1(*l, *(index + 4), *(index + 5), *h);
        *h = FIp1(*h, *(index + 6), *(index + 7), *l);
}

/**
 *******************************************************************************
 * @description
 * This function performs the Kasumi operation on the given block using the key
 * that is already scheduled in the context
 *
 * @param[in]       pContext     Context where the scheduled keys are stored
 * @param[in/out]   pData        Block to be enc/dec
 *
 ******************************************************************************/
static void
kasumi_1_block(const uint16_t *context, uint16_t *data)
{
        const uint16_t *end = context + KASUMI_KEY_SCHEDULE_SIZE;

        /* 4 iterations odd/even */
        do {
                uint16_t temp_l = data[3], temp_h = data[2];

                FLp1(context, &temp_h, &temp_l);
                FOp1(context, &temp_h, &temp_l);
                context += 8;
                data[1] ^= temp_l;
                data[0] ^= temp_h;

                temp_h = data[1];
                temp_l = data[0];
                FOp1(context, &temp_h, &temp_l);
                FLp1(context, &temp_h, &temp_l);
                context += 8;
                data[3] ^= temp_h;
                data[2] ^= temp_l;
        } while (context < end);
}

/*---------------------------------------------------------------------
 * kasumi_key_schedule_sk()
 * Build the key schedule. Most "key" operations use 16-bit
 *
 * Context is a flat array of 64 uint16. The context is built in the same order
 * it will be used.
 *---------------------------------------------------------------------*/
static inline void
kasumi_key_schedule_sk(uint16_t *context, const void *pKey)
{

        /* Kasumi constants*/
        static const uint16_t C[] = {
                0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210
        };

        uint16_t k[8], kprime[8], n;
        const uint8_t *pk = (const uint8_t *) pKey;

        /* Build K[] and K'[] keys */
        for (n = 0; n < 8; n++, pk += 2) {
                k[n] = (pk[0] << 8) + pk[1];
                kprime[n] = k[n] ^ C[n];
        }

        /*
         * Finally construct the various sub keys [Kli1, KlO ...) in the right
         * order for easy usage at run-time
         */
        for (n = 0; n < 8; n++) {
                context[0] = ROL16(k[n], 1);
                context[1] = kprime[(n + 2) & 0x7];
                context[2] = ROL16(k[(n + 1) & 0x7], 5);
                context[3] = kprime[(n + 4) & 0x7];
                context[4] = ROL16(k[(n + 5) & 0x7], 8);
                context[5] = kprime[(n + 3) & 0x7];
                context[6] = ROL16(k[(n + 6) & 0x7], 13);
                context[7] = kprime[(n + 7) & 0x7];
                context += 8;
        }
#ifdef SAFE_DATA
        clear_mem(k, sizeof(k));
        clear_mem(kprime, sizeof(kprime));
#endif
}

/*---------------------------------------------------------------------
 * kasumi_compute_sched()
 * Generic ksaumi key sched init function.
 *
 *---------------------------------------------------------------------*/
static inline int
kasumi_compute_sched(const uint8_t modifier, const void *const pKey, void *pCtx)
{
#ifdef SAFE_PARAM
        /* Check for NULL pointers */
        imb_set_errno(NULL, 0);
        if (pKey == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return -1;
        }
        if (pCtx == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return -1;
        }
#endif
        uint32_t i = 0;
        const uint8_t *const key = (const uint8_t *const) pKey;
        uint8_t ModKey[IMB_KASUMI_KEY_SIZE] = { 0 }; /* Modified key */
        kasumi_key_sched_t *pLocalCtx = (kasumi_key_sched_t *) pCtx;

        /* Construct the modified key*/
        for (i = 0; i < IMB_KASUMI_KEY_SIZE; i++)
                ModKey[i] = (uint8_t) key[i] ^ modifier;

        kasumi_key_schedule_sk(pLocalCtx->sk16, pKey);
        kasumi_key_schedule_sk(pLocalCtx->msk16, ModKey);

#ifdef SAFE_DATA
        clear_mem(ModKey, sizeof(ModKey));
        CLEAR_SCRATCH_GPS();
        CLEAR_SCRATCH_SIMD_REGS();
#endif
        return 0;
}

/*---------------------------------------------------------------------
 * kasumi_key_sched_size()
 * Get the size of a kasumi key sched context.
 *
 *---------------------------------------------------------------------*/
static inline size_t
kasumi_key_sched_size(void)
{
        /*
         * There are two keys that need to be scheduled: the original one and
         * the modified one (xored with the relevant modifier)
         */
        return sizeof(kasumi_key_sched_t);
}

/*---------------------------------------------------------------------
 * kasumi_init_f8_key_sched()
 * Compute the kasumi f8 key schedule.
 *
 *---------------------------------------------------------------------*/

static inline int
kasumi_init_f8_key_sched(const void *const pKey, kasumi_key_sched_t *pCtx)
{
        return kasumi_compute_sched(0x55, pKey, pCtx);
}

/*---------------------------------------------------------------------
 * kasumi_init_f9_key_sched()
 * Compute the kasumi f9 key schedule.
 *
 *---------------------------------------------------------------------*/

static inline int
kasumi_init_f9_key_sched(const void *const pKey, kasumi_key_sched_t *pCtx)
{
        return kasumi_compute_sched(0xAA, pKey, pCtx);
}

static inline void
kasumi_f8_1_buffer(const kasumi_key_sched_t *pCtx, const uint64_t IV, const void *pIn, void *pOut,
                   const uint32_t length)
{
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        uint32_t blkcnt;
        kasumi_union_t a, b; /* the modifier */
        const uint8_t *pBufferIn = (const uint8_t *) pIn;
        uint8_t *pBufferOut = (uint8_t *) pOut;
        uint32_t lengthInBytes = length;

        /* IV Endianness  */
        a.b64[0] = BSWAP64(IV);

        /* First encryption to create modifier */
        kasumi_1_block(pCtx->msk16, a.b16);

        /* Final initialisation steps */
        blkcnt = 0;
        b.b64[0] = a.b64[0];

        /* Now run the block cipher */
        while (lengthInBytes) {
                /* KASUMI it to produce the next block of keystream */
                kasumi_1_block(pCtx->sk16, b.b16);

                if (lengthInBytes > IMB_KASUMI_BLOCK_SIZE) {
                        pBufferIn = xor_keystrm_rev(pBufferOut, pBufferIn, b.b64[0]);
                        pBufferOut += IMB_KASUMI_BLOCK_SIZE;
                        /* loop variant */
                        /* done another 64 bits */
                        lengthInBytes -= IMB_KASUMI_BLOCK_SIZE;

                        /* apply the modifier and update the block count */
                        b.b64[0] ^= a.b64[0];
                        b.b16[0] ^= (uint16_t) ++blkcnt;
                } else if (lengthInBytes < IMB_KASUMI_BLOCK_SIZE) {
                        SafeBuf safeInBuf = { 0 };

                        /* end of the loop, handle the last bytes */
                        memcpy_keystrm(safeInBuf.b8, pBufferIn, lengthInBytes);
                        xor_keystrm_rev(b.b8, safeInBuf.b8, b.b64[0]);
                        memcpy_keystrm(pBufferOut, b.b8, lengthInBytes);
                        lengthInBytes = 0;
#ifdef SAFE_DATA
                        clear_mem(&safeInBuf, sizeof(safeInBuf));
#endif
                } else {
                        /* lengthInBytes == IMB_KASUMI_BLOCK_SIZE */
                        xor_keystrm_rev(pBufferOut, pBufferIn, b.b64[0]);
                        lengthInBytes = 0;
                }
        }
#ifdef SAFE_DATA
        /* Clear sensitive data in stack */
        clear_mem(&a, sizeof(a));
        clear_mem(&b, sizeof(b));
#endif
}

static inline void
preserve_bits(kasumi_union_t *c, const uint8_t *pcBufferOut, const uint8_t *pcBufferIn,
              SafeBuf *safeOutBuf, SafeBuf *safeInBuf, const uint8_t bit_len,
              const uint8_t byte_len)
{
        const uint64_t mask = UINT64_MAX << (IMB_KASUMI_BLOCK_SIZE * 8 - bit_len);

        /* Clear the last bits of the keystream and the input
         * (input only in out-of-place case) */
        c->b64[0] &= mask;
        if (pcBufferIn != pcBufferOut) {
                const uint64_t swapMask = BSWAP64(mask);

                safeInBuf->b64 &= swapMask;

                /*
                 * Merge the last bits from the output, to be preserved,
                 * in the keystream, to be XOR'd with the input
                 * (which last bits are 0, maintaining the output bits)
                 */
                memcpy_keystrm(safeOutBuf->b8, pcBufferOut, byte_len);
                c->b64[0] |= BSWAP64(safeOutBuf->b64 & ~swapMask);
        }
}

static inline void
kasumi_f8_1_buffer_bit(const kasumi_key_sched_t *pCtx, const uint64_t IV, const void *pIn,
                       void *pOut, const uint32_t lengthInBits, const uint32_t offsetInBits)
{
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        const uint8_t *pBufferIn = (const uint8_t *) pIn;
        uint8_t *pBufferOut = (uint8_t *) pOut;
        uint32_t cipherLengthInBits = lengthInBits;
        uint32_t blkcnt;
        uint64_t shiftrem = 0;
        kasumi_union_t a, b, c; /* the modifier */
        const uint8_t *pcBufferIn = pBufferIn + (offsetInBits / 8);
        uint8_t *pcBufferOut = pBufferOut + (offsetInBits / 8);
        /* Offset into the first byte (0 - 7 bits) */
        uint32_t remainOffset = offsetInBits % 8;
        SafeBuf safeOutBuf = { 0 };
        SafeBuf safeInBuf = { 0 };

        /* IV Endianness  */
        a.b64[0] = BSWAP64(IV);

        /* First encryption to create modifier */
        kasumi_1_block(pCtx->msk16, a.b16);

        /* Final initialisation steps */
        blkcnt = 0;
        b.b64[0] = a.b64[0];
        /* Now run the block cipher */

        /* Start with potential partial block (due to offset and length) */
        kasumi_1_block(pCtx->sk16, b.b16);
        c.b64[0] = b.b64[0] >> remainOffset;
        /* Only one block to encrypt */
        if (cipherLengthInBits < (64 - remainOffset)) {
                const uint32_t byteLength = (cipherLengthInBits + 7) / 8;

                memcpy_keystrm(safeInBuf.b8, pcBufferIn, byteLength);
                /*
                 * If operation is Out-of-place and there is offset
                 * to be applied, "remainOffset" bits from the output buffer
                 * need to be preserved (only applicable to first byte,
                 * since remainOffset is up to 7 bits)
                 */
                if ((pIn != pOut) && remainOffset) {
                        const uint8_t mask8 = (const uint8_t)(1 << (8 - remainOffset)) - 1;

                        safeInBuf.b8[0] = (safeInBuf.b8[0] & mask8) | (pcBufferOut[0] & ~mask8);
                }

                /* If last byte is a partial byte, the last bits of the output
                 * need to be preserved */
                const uint8_t bitlen_with_off = remainOffset + cipherLengthInBits;

                if ((bitlen_with_off & 0x7) != 0) {
                        preserve_bits(&c, pcBufferOut, pcBufferIn, &safeOutBuf, &safeInBuf,
                                      bitlen_with_off, byteLength);
                }
                xor_keystrm_rev(safeOutBuf.b8, safeInBuf.b8, c.b64[0]);
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
                const uint8_t mask8 = (const uint8_t)(1 << (8 - remainOffset)) - 1;

                memcpy_keystrm(safeInBuf.b8, pcBufferIn, 8);
                safeInBuf.b8[0] = (safeInBuf.b8[0] & mask8) | (pcBufferOut[0] & ~mask8);
                xor_keystrm_rev(pcBufferOut, safeInBuf.b8, c.b64[0]);
                pcBufferIn += IMB_KASUMI_BLOCK_SIZE;
        } else {
                /* At least 64 bits to produce (including offset) */
                pcBufferIn = xor_keystrm_rev(pcBufferOut, pcBufferIn, c.b64[0]);
        }

        if (remainOffset != 0)
                shiftrem = b.b64[0] << (64 - remainOffset);
        cipherLengthInBits -= IMB_KASUMI_BLOCK_SIZE * 8 - remainOffset;
        pcBufferOut += IMB_KASUMI_BLOCK_SIZE;
        /* apply the modifier and update the block count */
        b.b64[0] ^= a.b64[0];
        b.b16[0] ^= (uint16_t) ++blkcnt;

        while (cipherLengthInBits) {
                /* KASUMI it to produce the next block of keystream */
                kasumi_1_block(pCtx->sk16, b.b16);
                c.b64[0] = (b.b64[0] >> remainOffset) | shiftrem;
                if (remainOffset != 0)
                        shiftrem = b.b64[0] << (64 - remainOffset);
                if (cipherLengthInBits >= IMB_KASUMI_BLOCK_SIZE * 8) {
                        pcBufferIn = xor_keystrm_rev(pcBufferOut, pcBufferIn, c.b64[0]);
                        cipherLengthInBits -= IMB_KASUMI_BLOCK_SIZE * 8;
                        pcBufferOut += IMB_KASUMI_BLOCK_SIZE;
                        /* loop variant */

                        /* apply the modifier and update the block count */
                        b.b64[0] ^= a.b64[0];
                        b.b16[0] ^= (uint16_t) ++blkcnt;
                } else {
                        /* end of the loop, handle the last bytes */
                        const uint32_t byteLength = (cipherLengthInBits + 7) / 8;

                        memcpy_keystrm(safeInBuf.b8, pcBufferIn, byteLength);

                        /* If last byte is a partial byte, the last bits
                         * of the output need to be preserved */
                        if ((cipherLengthInBits & 0x7) != 0)
                                preserve_bits(&c, pcBufferOut, pcBufferIn, &safeOutBuf, &safeInBuf,
                                              cipherLengthInBits, byteLength);
                        xor_keystrm_rev(safeOutBuf.b8, safeInBuf.b8, c.b64[0]);
                        memcpy_keystrm(pcBufferOut, safeOutBuf.b8, byteLength);
                        cipherLengthInBits = 0;
                }
        }
#ifdef SAFE_DATA
        /* Clear sensitive data in stack */
        clear_mem(&a, sizeof(a));
        clear_mem(&b, sizeof(b));
        clear_mem(&c, sizeof(c));
        clear_mem(&safeInBuf, sizeof(safeInBuf));
        clear_mem(&safeOutBuf, sizeof(safeOutBuf));
#endif
}

static inline void
kasumi_f9_1_buffer(const kasumi_key_sched_t *pCtx, const void *dataIn, const uint32_t length,
                   void *pDigest)
{
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        kasumi_union_t a, b, mask;
        const uint64_t *pIn = (const uint64_t *) dataIn;
        uint32_t lengthInBytes = length;

        /* Init */
        a.b64[0] = 0;
        b.b64[0] = 0;
        mask.b64[0] = -1;

        /* Now run kasumi for all 8 byte blocks */
        while (lengthInBytes >= 8) {

                a.b64[0] ^= BSWAP64(*(pIn++));

                /* KASUMI it */
                kasumi_1_block(pCtx->sk16, a.b16);

                /* loop variant */
                lengthInBytes -= 8; /* done another 64 bits */

                /* update */
                b.b64[0] ^= a.b64[0];
        }

        if (lengthInBytes) {
                SafeBuf safeBuf = { 0 };

                /* Not a whole 8 byte block remaining */
                mask.b64[0] = ~(mask.b64[0] >> (BYTESIZE * lengthInBytes));
                safe_memcpy(&safeBuf.b64, pIn, lengthInBytes);
                mask.b64[0] &= BSWAP64(safeBuf.b64);
                a.b64[0] ^= mask.b64[0];

                /* KASUMI it */
                kasumi_1_block(pCtx->sk16, a.b16);

                /* update */
                b.b64[0] ^= a.b64[0];
#ifdef SAFE_DATA
                /* Clear sensitive data in stack */
                clear_mem(&safeBuf, sizeof(safeBuf));
#endif
        }

        /* Kasumi b */
        kasumi_1_block(pCtx->msk16, b.b16);

        /* swap result */
        *(uint32_t *) pDigest = bswap4(b.b32[1]);
#ifdef SAFE_DATA
        /* Clear sensitive data in stack */
        clear_mem(&a, sizeof(a));
        clear_mem(&b, sizeof(b));
        clear_mem(&mask, sizeof(mask));
#endif
}

/*---------------------------------------------------------
 * @description
 *       Kasumi F9 1 packet with user config:
 *       Single packet digest with user defined IV, and precomputed key schedule.
 *
 *       IV = swap32(count) << 32 | swap32(fresh)
 *
 *---------------------------------------------------------*/

static inline void
kasumi_f9_1_buffer_user(const kasumi_key_sched_t *pCtx, const uint64_t IV, const void *pDataIn,
                        const uint32_t length, void *pDigest, const uint32_t direction)
{
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        kasumi_union_t a, b, mask, message, temp;
        uint32_t lengthInBits = length;
        const uint64_t *pIn = (const uint64_t *) pDataIn;
        kasumi_union_t safebuff;

        a.b64[0] = 0;
        b.b64[0] = 0;

        /* Use the count and fresh for first round */
        a.b64[0] = BSWAP64(IV);
        /* KASUMI it */
        kasumi_1_block(pCtx->sk16, a.b16);
        /* update */
        b.b64[0] = a.b64[0];

        /* Now run kasumi for all 8 byte blocks */
        while (lengthInBits >= QWORDSIZEINBITS) {
                a.b64[0] ^= BSWAP64(*(pIn++));
                /* KASUMI it */
                kasumi_1_block(pCtx->sk16, a.b16);
                /* loop variant */
                lengthInBits -= 64; /* done another 64 bits */
                /* update */
                b.b64[0] ^= a.b64[0];
        }

        /* Is there any non 8 byte blocks remaining ? */
        if (lengthInBits == 0) {
                /* last block is : direct + 1 + 62 0's */
                a.b64[0] ^= ((uint64_t) direction + direction + LAST_PADDING_BIT)
                            << (QWORDSIZEINBITS - 2);
                kasumi_1_block(pCtx->sk16, a.b16);
                /* update */
                b.b64[0] ^= a.b64[0];
        } else if (lengthInBits <= (QWORDSIZEINBITS - 2)) {
                /* last block is : message + direction + LAST_PADDING_BITS(1) +
                 * less than 62 0's */
                mask.b64[0] = -1;
                temp.b64[0] = 0;
                message.b64[0] = 0;
                mask.b64[0] = ~(mask.b64[0] >> lengthInBits);
                /*round up and copy last lengthInBits */
                safe_memcpy(&safebuff.b64[0], pIn, (lengthInBits + 7) / 8);
                message.b64[0] = BSWAP64(safebuff.b64[0]);
                temp.b64[0] = mask.b64[0] & message.b64[0];
                temp.b64[0] |= ((uint64_t) direction + direction + LAST_PADDING_BIT)
                               << ((QWORDSIZEINBITS - 2) - lengthInBits);
                a.b64[0] ^= temp.b64[0];
                /* KASUMI it */
                kasumi_1_block(pCtx->sk16, a.b16);

                /* update */
                b.b64[0] ^= a.b64[0];
        } else if (lengthInBits == (QWORDSIZEINBITS - 1)) {
                /* next block is : message + direct  */
                /* last block is : 1 + 63 0's */
                a.b64[0] ^= direction | (~1 & BSWAP64(*(pIn++)));
                /* KASUMI it */
                kasumi_1_block(pCtx->sk16, a.b16);
                /* update */
                b.b64[0] ^= a.b64[0];
                a.b8[QWORDSIZEINBYTES - 1] ^= (LAST_PADDING_BIT) << (QWORDSIZEINBYTES - 1);
                /* KASUMI it */
                kasumi_1_block(pCtx->sk16, a.b16);
                /* update */
                b.b64[0] ^= a.b64[0];
        }
        /* Kasumi b */
        kasumi_1_block(pCtx->msk16, b.b16);

        /* swap result */
        *(uint32_t *) pDigest = bswap4(b.b32[1]);
#ifdef SAFE_DATA
        /* Clear sensitive data in stack */
        clear_mem(&a, sizeof(a));
        clear_mem(&b, sizeof(b));
        clear_mem(&mask, sizeof(mask));
        clear_mem(&message, sizeof(message));
        clear_mem(&temp, sizeof(temp));
        clear_mem(&safebuff, sizeof(safebuff));
#endif
}

#endif /*_KASUMI_INTERNAL_H_*/
