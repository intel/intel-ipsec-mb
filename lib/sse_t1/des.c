/*******************************************************************************
  Copyright (c) 2017-2026, Intel Corporation

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

/* basic DES implementation */

#include <stdint.h>
#include <string.h>

#include "intel-ipsec-mb.h"
#include "include/des.h"
#include "include/des_utils.h"
#include "include/clear_regs_mem.h"
#include "include/constant_lookup.h"
#include "include/memcpy.h"
#include "include/arch_sse_type1.h"

IMB_DLL_LOCAL
void
des_enc_cbc_sse(const void *input, void *output, const int size, const uint64_t *ks,
                const uint64_t *p_iv)
{
#ifdef SAFE_PARAM
        if ((input == NULL) || (output == NULL) || (ks == NULL) || (p_iv == NULL) || (size < 0))
                return;
#else
        IMB_ASSERT(size >= 0);
        IMB_ASSERT(input != NULL);
        IMB_ASSERT(output != NULL);
        IMB_ASSERT(ks != NULL);
        IMB_ASSERT(p_iv != NULL);
#endif
        const uint64_t *in = input;
        uint64_t *out = output;
        const int nblocks = size / 8;
        int n;

        if (size == 0)
                return;

        DECLARE_ALIGNED(uint64_t ks_sse[16], 64);

        convert_ks_for_sse(ks_sse, ks);

        uint64_t iv = *p_iv;

        for (n = 0; n < nblocks; n++)
                out[n] = iv = des_enc_dec_1_sse(in[n] ^ iv, ks_sse, 1 /* encrypt */);

#ifdef SAFE_DATA
        clear_mem(ks_sse, sizeof(ks_sse));
#endif
}

IMB_DLL_LOCAL
void
des_dec_cbc_sse(const void *input, void *output, const int size, const uint64_t *ks,
                const uint64_t *p_iv)
{
#ifdef SAFE_PARAM
        if ((input == NULL) || (output == NULL) || (ks == NULL) || (p_iv == NULL) || (size < 0))
                return;
#else
        IMB_ASSERT(size >= 0);
        IMB_ASSERT(input != NULL);
        IMB_ASSERT(output != NULL);
        IMB_ASSERT(ks != NULL);
        IMB_ASSERT(p_iv != NULL);
#endif
        const uint64_t *in = input;
        uint64_t *out = output;
        const int nblocks = size / 8;
        int n;

        if (size == 0)
                return;

        DECLARE_ALIGNED(uint64_t ks_sse[16], 64);

        convert_ks_for_sse(ks_sse, ks);

        uint64_t iv = *p_iv;

        for (n = 0; n < nblocks; n++) {
                uint64_t in_block = in[n];

                out[n] = des_enc_dec_1_sse(in_block, ks_sse, 0 /* decrypt */) ^ iv;
                iv = in_block;
        }

#ifdef SAFE_DATA
        clear_mem(ks_sse, sizeof(ks_sse));
#endif
}

IMB_DLL_LOCAL
void
des3_enc_cbc_sse(const void *input, void *output, const int size, const uint64_t *ks1,
                 const uint64_t *ks2, const uint64_t *ks3, const uint64_t *p_iv)
{
#ifdef SAFE_PARAM
        if ((input == NULL) || (output == NULL) || (ks1 == NULL) || (ks2 == NULL) ||
            (ks3 == NULL) || (p_iv == NULL) || (size < 0))
                return;
#else
        IMB_ASSERT(size >= 0);
        IMB_ASSERT(input != NULL);
        IMB_ASSERT(output != NULL);
        IMB_ASSERT(ks1 != NULL);
        IMB_ASSERT(ks2 != NULL);
        IMB_ASSERT(ks3 != NULL);
        IMB_ASSERT(p_iv != NULL);
#endif
        const uint64_t *in = input;
        uint64_t *out = output;
        const int nblocks = size / 8;
        int n;

        if (size == 0)
                return;

        DECLARE_ALIGNED(uint64_t ks1_sse[16], 64);
        DECLARE_ALIGNED(uint64_t ks2_sse[16], 64);
        DECLARE_ALIGNED(uint64_t ks3_sse[16], 64);

        convert_ks_for_sse(ks1_sse, ks1);
        convert_ks_for_sse(ks2_sse, ks2);
        convert_ks_for_sse(ks3_sse, ks3);

        uint64_t iv = *p_iv;

        for (n = 0; n < nblocks; n++) {
                uint64_t t = in[n] ^ iv;

                t = des_enc_dec_1_sse(t, ks1_sse, 1 /* encrypt */);
                t = des_enc_dec_1_sse(t, ks2_sse, 0 /* decrypt */);
                t = des_enc_dec_1_sse(t, ks3_sse, 1 /* encrypt */);
                out[n] = iv = t;
        }

#ifdef SAFE_DATA
        clear_mem(ks1_sse, sizeof(ks1_sse));
        clear_mem(ks2_sse, sizeof(ks2_sse));
        clear_mem(ks3_sse, sizeof(ks3_sse));
#endif
}

IMB_DLL_LOCAL
void
des3_dec_cbc_sse(const void *input, void *output, const int size, const uint64_t *ks1,
                 const uint64_t *ks2, const uint64_t *ks3, const uint64_t *p_iv)
{
#ifdef SAFE_PARAM
        if ((input == NULL) || (output == NULL) || (ks1 == NULL) || (ks2 == NULL) ||
            (ks3 == NULL) || (p_iv == NULL) || (size < 0))
                return;
#else
        IMB_ASSERT(size >= 0);
        IMB_ASSERT(input != NULL);
        IMB_ASSERT(output != NULL);
        IMB_ASSERT(ks1 != NULL);
        IMB_ASSERT(ks2 != NULL);
        IMB_ASSERT(ks3 != NULL);
        IMB_ASSERT(p_iv != NULL);
#endif
        const uint64_t *in = input;
        uint64_t *out = output;
        const int nblocks = size / 8;
        int n;

        if (size == 0)
                return;

        DECLARE_ALIGNED(uint64_t ks1_sse[16], 64);
        DECLARE_ALIGNED(uint64_t ks2_sse[16], 64);
        DECLARE_ALIGNED(uint64_t ks3_sse[16], 64);

        convert_ks_for_sse(ks1_sse, ks1);
        convert_ks_for_sse(ks2_sse, ks2);
        convert_ks_for_sse(ks3_sse, ks3);

        uint64_t iv = *p_iv;

        for (n = 0; n < nblocks; n++) {
                uint64_t t;
                const uint64_t next_iv = in[n];

                t = des_enc_dec_1_sse(next_iv, ks3_sse, 0 /* decrypt */);
                t = des_enc_dec_1_sse(t, ks2_sse, 1 /* encrypt */);
                t = des_enc_dec_1_sse(t, ks1_sse, 0 /* decrypt */);
                out[n] = t ^ iv;

                iv = next_iv;
        }

#ifdef SAFE_DATA
        clear_mem(ks1_sse, sizeof(ks1_sse));
        clear_mem(ks2_sse, sizeof(ks2_sse));
        clear_mem(ks3_sse, sizeof(ks3_sse));
#endif
}

__forceinline void
cfb_one_sse(const void *input, void *output, const int size, const uint64_t *ks,
            const uint64_t *ks_sse, const uint64_t *p_iv)
{
#ifdef SAFE_PARAM
        if ((input == NULL) || (output == NULL) || (ks == NULL) || (p_iv == NULL) || (size < 0))
                return;
#else
        IMB_ASSERT(size <= 8 && size >= 0);
        IMB_ASSERT(input != NULL);
        IMB_ASSERT(output != NULL);
        IMB_ASSERT(ks != NULL);
        IMB_ASSERT(p_iv != NULL);
#endif
        uint8_t *out = (uint8_t *) output;
        const uint8_t *in = (const uint8_t *) input;
        DECLARE_ALIGNED(uint64_t ks_exp[16], 64);
        uint64_t t;

        if (ks_sse == NULL) {
                convert_ks_for_sse(ks_exp, ks);
                ks_sse = ks_exp;
        }

        t = des_enc_dec_1_sse(*p_iv, ks_sse, 1 /* encrypt */);

        /* XOR and copy in one go */
        if (size & 1) {
                *out++ = *in++ ^ ((uint8_t) t);
                t >>= 8;
        }

        if (size & 2) {
                uint16_t *out2 = (uint16_t *) out;
                const uint16_t *in2 = (const uint16_t *) in;

                *out2 = *in2 ^ ((uint16_t) t);
                t >>= 16;
                out += 2;
                in += 2;
        }

        if (size & 4) {
                uint32_t *out4 = (uint32_t *) out;
                const uint32_t *in4 = (const uint32_t *) in;

                *out4 = *in4 ^ ((uint32_t) t);
        }

#ifdef SAFE_DATA
        clear_var(&t, sizeof(t));
        if (ks_sse == ks_exp)
                clear_mem(ks_exp, sizeof(ks_exp));
#endif
}

IMB_DLL_LOCAL
void
docsis_des_enc_sse(const void *input, void *output, const int size, const uint64_t *ks,
                   const uint64_t *p_iv)
{
#ifdef SAFE_PARAM
        if ((input == NULL) || (output == NULL) || (ks == NULL) || (p_iv == NULL) || (size < 0))
                return;
#else
        IMB_ASSERT(size >= 0);
        IMB_ASSERT(input != NULL);
        IMB_ASSERT(output != NULL);
        IMB_ASSERT(ks != NULL);
        IMB_ASSERT(p_iv != NULL);
#endif
        const uint64_t *in = input;
        uint64_t *out = output;
        const int nblocks = size / IMB_DES_BLOCK_SIZE;
        const int partial = size & 7;
        int n;

        if (size == 0)
                return;

        DECLARE_ALIGNED(uint64_t ks_sse[16], 64);

        convert_ks_for_sse(ks_sse, ks);

        uint64_t iv = *p_iv;

        for (n = 0; n < nblocks; n++)
                out[n] = iv = des_enc_dec_1_sse(in[n] ^ iv, ks_sse, 1 /* encrypt */);

        if (partial) {
                if (nblocks)
                        cfb_one_sse(&in[nblocks], &out[nblocks], partial, ks, ks_sse,
                                    &out[nblocks - 1]);
                else
                        cfb_one_sse(input, output, partial, ks, ks_sse, p_iv);
        }

#ifdef SAFE_DATA
        clear_mem(ks_sse, sizeof(ks_sse));
#endif
}

IMB_DLL_LOCAL
void
docsis_des_dec_sse(const void *input, void *output, const int size, const uint64_t *ks,
                   const uint64_t *p_iv)
{
#ifdef SAFE_PARAM
        if ((input == NULL) || (output == NULL) || (ks == NULL) || (p_iv == NULL) || (size < 0))
                return;
#else
        IMB_ASSERT(size >= 0);
        IMB_ASSERT(input != NULL);
        IMB_ASSERT(output != NULL);
        IMB_ASSERT(ks != NULL);
        IMB_ASSERT(p_iv != NULL);
#endif
        const uint64_t *in = input;
        uint64_t *out = output;
        const int nblocks = size / IMB_DES_BLOCK_SIZE;
        const int partial = size & 7;
        int n;

        if (size == 0)
                return;

        DECLARE_ALIGNED(uint64_t ks_sse[16], 64);

        convert_ks_for_sse(ks_sse, ks);

        if (partial) {
                if (!nblocks) {
                        /* first block is the partial one */
                        cfb_one_sse(input, output, partial, ks, ks_sse, p_iv);
                        return;
                }
                /* last block is partial */
                cfb_one_sse(&in[nblocks], &out[nblocks], partial, ks, ks_sse, &in[nblocks - 1]);
        }

        uint64_t iv = *p_iv;

        for (n = 0; n < nblocks; n++) {
                uint64_t in_block = in[n];

                out[n] = des_enc_dec_1_sse(in_block, ks_sse, 0 /* decrypt */) ^ iv;
                iv = in_block;
        }

#ifdef SAFE_DATA
        clear_mem(ks_sse, sizeof(ks_sse));
#endif
}

IMB_DLL_EXPORT
void
des_cfb_one(void *output, const void *input, const uint64_t *iv, const uint64_t *ks, const int size)
{
        cfb_one_sse(input, output, size, ks, NULL, iv);
}
