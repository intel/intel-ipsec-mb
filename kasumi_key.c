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

#include <stdint.h>
#include <stdlib.h>

#include "include/kasumi_internal.h"
#include "intel-ipsec-mb.h"

/*---------------------------------------------------------------------
* kasumi_key_schedule_sk()
* Build the key schedule. Most "key" operations use 16-bit
*
* Context is a flat array of 64 uint16. The context is built in the same order
* it will be used.
*---------------------------------------------------------------------*/
static void
kasumi_key_schedule_sk(uint16_t *context, const uint8_t *pKey)
{

        /* Kasumi constants*/
        static uint16_t C[] = {0x0123, 0x4567, 0x89AB, 0xCDEF,
                               0xFEDC, 0xBA98, 0x7654, 0x3210};

        uint16_t k[8], kprime[8], k16, n;
        uint16_t *flat = context;
        const uint8_t *pk = pKey;

        /* Build K[] and K'[] keys */
        for (n = 0; n < 8; n++, pk += 2) {
                k16 = (pk[0] << 8) + pk[1];
                k[n] = k16;
                kprime[n] = k16 ^ C[n];
        }

        /*
         * Finally construct the various sub keys [Kli1, KlO ...) in the right
         * order for easy usage at run-time
         */
        for (n = 0; n < 8; n++) {
                flat[0] = ROL16(k[n], 1);
                flat[1] = kprime[(n + 2) & 0x7];
                flat[2] = ROL16(k[(n + 1) & 0x7], 5);
                flat[3] = kprime[(n + 4) & 0x7];
                flat[4] = ROL16(k[(n + 5) & 0x7], 8);
                flat[5] = kprime[(n + 3) & 0x7];
                flat[6] = ROL16(k[(n + 6) & 0x7], 13);
                flat[7] = kprime[(n + 7) & 0x7];
                flat += 8;
        }
}

/*---------------------------------------------------------------------
* kasumi_key_sched_size()
* Get the size of a kasumi key sched context.
*
*---------------------------------------------------------------------*/
uint32_t
kasumi_key_sched_size(void)
{
        /*
         * There are two keys that need to be scheduled: the original one and
         * the modified one (xored with the relevant modifier)
         */
        return sizeof(kasumi_key_sched_t);
}

/*---------------------------------------------------------------------
* kasumi_compute_sched()
* Generic ksaumi key sched init function.
*
*---------------------------------------------------------------------*/
static uint32_t
kasumi_compute_sched(const uint8_t modifier,
                     const uint8_t *const pKey, void *pCtx)
{
        uint32_t i = 0;
        uint8_t ModKey[KASUMI_KEY_SIZE] = {0}; /* Modified key */
        kasumi_key_sched_t *pLocalCtx = (kasumi_key_sched_t *)pCtx;

        /* Construct the modified key*/
        for (i = 0; i < KASUMI_KEY_SIZE; i++)
                ModKey[i] = (uint8_t)pKey[i] ^ modifier;

        kasumi_key_schedule_sk(pLocalCtx->sk16, pKey);
        kasumi_key_schedule_sk(pLocalCtx->msk16, ModKey);

        return 0;
}

/*---------------------------------------------------------------------
* kasumi_init_f8_key_sched()
* Compute the kasumi f8 key schedule.
*
*---------------------------------------------------------------------*/

uint32_t
kasumi_init_f8_key_sched(const uint8_t *const pKey,
                         kasumi_key_sched_t *pCtx)
{
        return kasumi_compute_sched(0x55, pKey, pCtx);
}

/*---------------------------------------------------------------------
* kasumi_init_f9_key_sched()
* Compute the kasumi f9 key schedule.
*
*---------------------------------------------------------------------*/

uint32_t
kasumi_init_f9_key_sched(const uint8_t *const pKey,
                         kasumi_key_sched_t *pCtx)
{
        return kasumi_compute_sched(0xAA, pKey, pCtx);
}
