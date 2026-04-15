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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "intel-ipsec-mb.h"
#include "wireless_common.h"
#include "include/clear_regs_mem.h"
#include "memcpy.h"
#include "error.h"
#include "kasumi_interface.h"
#include "include/arch_avx2_type1.h"
#include "include/arch_avx512_type1.h"
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

typedef union SafeBuffer {
        uint64_t b64;
        uint32_t b32[2];
        uint8_t b8[IMB_KASUMI_BLOCK_SIZE];
} SafeBuf;

/*---------------------------------------------------------------------
 * Inline 16-bit left rotation
 *---------------------------------------------------------------------*/

#define ROL16(a, b) (uint16_t)((a << b) | (a >> (16 - b)))

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
#ifdef AVX2
        kasumi_1_block_avx2(context, data);
#elif defined(AVX512) || defined(AVX10)
        kasumi_1_block_avx512(context, data);
#else
        kasumi_1_block_sse(context, data);
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

#endif /*_KASUMI_INTERNAL_H_*/
