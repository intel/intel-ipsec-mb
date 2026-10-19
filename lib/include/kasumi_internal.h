/*******************************************************************************
  Copyright (c) 2009-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*---------------------------------------------------------
 * Kasumi_internal.h
 *---------------------------------------------------------*/

#ifndef _KASUMI_INTERNAL_H_
#define _KASUMI_INTERNAL_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "intel-ipsec-mb.h"
#include "wireless_common.h"
#include "include/clear_regs_mem.h"
#include "error.h"
#include "kasumi_interface.h"
#include "include/arch_avx2_type1.h"
#include "include/arch_avx512_type2.h"
#include "include/arch_sse_type1.h"

/* KASUMI cipher definitions */
#define NUM_KASUMI_ROUNDS (8) /* 8 rounds in the kasumi spec */
#define QWORDSIZEINBITS   (64)
#define QWORDSIZEINBYTES  (8)
#define LAST_PADDING_BIT  (1)

/*----- a 64-bit structure to help with kasumi endian issues -----*/
typedef union _ku64 {
        uint64_t b64[1];
        uint32_t b32[2];
        uint16_t b16[4];
        uint8_t b8[8];
} kasumi_union_t;

/*---------------------------------------------------------------------
 * Inline 16-bit left rotation
 *---------------------------------------------------------------------*/

#define ROL16(a, b) (uint16_t)((a << b) | (a >> (16 - b)))

static inline void
kasumi_update(const uint16_t *context, void *data)
{
#ifdef AVX2
        kasumi_update_avx2(context, data);
#elif defined(AVX512) || defined(AVX10)
        kasumi_update_avx512(context, data);
#else
        kasumi_update_sse(context, data);
#endif
}

static inline void
kasumi_f8_update(const uint16_t *context, uint64_t state[3], const void *in, void *out,
                 const uint64_t length)
{
#ifdef AVX2
        kasumi_f8_update_avx2(context, state, in, out, length);
#elif defined(AVX512) || defined(AVX10)
        kasumi_f8_update_avx512(context, state, in, out, length);
#else
        kasumi_f8_update_sse(context, state, in, out, length);
#endif
}

static inline void
kasumi_f9_update(const uint16_t *context, uint64_t state[2], const void *in, const uint64_t length)
{
#ifdef AVX2
        kasumi_f9_update_avx2(context, state, in, length);
#elif defined(AVX512) || defined(AVX10)
        kasumi_f9_update_avx512(context, state, in, length);
#else
        kasumi_f9_update_sse(context, state, in, length);
#endif
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
                return IMB_ERR_NULL_KEY;
        }
        if (pCtx == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return IMB_ERR_NULL_EXP_KEY;
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

        /* All ISAs share this buffer-level flow; update wrappers select the implementation. */
        if (length == 0)
                return;

        kasumi_union_t state[3]; /* modifier A, keystream block B, block count */

        /* Initialize the modifier and seed the F8 chaining state. */
        state[0].b64[0] = BSWAP64(IV);
        kasumi_update(pCtx->msk16, state[0].b16);
        state[1].b64[0] = state[0].b64[0];
        state[2].b64[0] = 0;

        kasumi_f8_update(pCtx->sk16, state[0].b64, pIn, pOut, length);
#ifdef SAFE_DATA
        clear_mem(state, sizeof(state));
#endif
}

static inline void
kasumi_f9_1_buffer(const kasumi_key_sched_t *pCtx, const void *dataIn, const uint32_t length,
                   void *pDigest)
{
#ifdef SAFE_DATA
        CLEAR_SCRATCH_SIMD_REGS();
#endif /* SAFE_DATA */

        /* All ISAs share this flow; the update wrapper handles full and partial blocks. */
        kasumi_union_t state[2];

        /* Initialize accumulators A and B. */
        state[0].b64[0] = 0;
        state[1].b64[0] = 0;
        if (length != 0)
                kasumi_f9_update(pCtx->sk16, state[0].b64, dataIn, length);

        /* Finalize the accumulated value with the modified key. */
        kasumi_update(pCtx->msk16, state[1].b16);
        *(uint32_t *) pDigest = bswap4(state[1].b32[1]);
#ifdef SAFE_DATA
        clear_mem(state, sizeof(state));
#endif
}

#endif /*_KASUMI_INTERNAL_H_*/
