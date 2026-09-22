/*******************************************************************************
  Copyright (c) 2012-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <stdio.h>
#include "intel-ipsec-mb.h"
#include "include/clear_regs_mem.h"
#include "include/error.h"
#include "include/arch_sse_type1.h"
#include "include/arch_avx2_type1.h"

static const uint32_t in[4 * 3] = { 0x01010101, 0x01010101, 0x01010101, 0x01010101,
                                    0x02020202, 0x02020202, 0x02020202, 0x02020202,
                                    0x03030303, 0x03030303, 0x03030303, 0x03030303 };

void
aes_xcbc_expand_key_sse(const void *key, void *k1_exp, void *k2, void *k3)
{
#ifdef SAFE_PARAM
        imb_set_errno(NULL, 0);
        if (k1_exp == NULL || k2 == NULL || k3 == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
#endif
        DECLARE_ALIGNED(uint32_t keys_exp_enc[11 * 4], 16);

        aes_keyexp_128_enc_sse(key, keys_exp_enc);

        aes128_ecbenc_x3_sse(in, keys_exp_enc, k1_exp, k2, k3);

        aes_keyexp_128_enc_sse(k1_exp, k1_exp);

#ifdef SAFE_DATA
        clear_mem(&keys_exp_enc, sizeof(keys_exp_enc));
#endif
}

__forceinline void
aes_xcbc_expand_key_avx_common(const void *key, void *k1_exp, void *k2, void *k3)
{
#ifdef SAFE_PARAM
        imb_set_errno(NULL, 0);
        if (k1_exp == NULL || k2 == NULL || k3 == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
#endif
        DECLARE_ALIGNED(uint32_t keys_exp_enc[11 * 4], 16);

        aes_keyexp_128_enc_avx(key, keys_exp_enc);

        aes128_ecbenc_x3_avx(in, keys_exp_enc, k1_exp, k2, k3);

        aes_keyexp_128_enc_avx(k1_exp, k1_exp);

#ifdef SAFE_DATA
        clear_mem(&keys_exp_enc, sizeof(keys_exp_enc));
#endif
}

void
aes_xcbc_expand_key_avx(const void *key, void *k1_exp, void *k2, void *k3)
{
        aes_xcbc_expand_key_avx_common(key, k1_exp, k2, k3);
}

void
aes_xcbc_expand_key_avx2(const void *key, void *k1_exp, void *k2, void *k3)
{
        aes_xcbc_expand_key_avx_common(key, k1_exp, k2, k3);
}

void
aes_xcbc_expand_key_avx512(const void *key, void *k1_exp, void *k2, void *k3)
{
        aes_xcbc_expand_key_avx_common(key, k1_exp, k2, k3);
}
