/*******************************************************************************
  Copyright (c) 2024-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <stdint.h>
#include <string.h>

#include "intel-ipsec-mb.h"
#include "mb_mgr.h" /* self_test_failed() */
#include "arch_sse_type1.h"
#include "gcm.h"
#include "error.h"
#include "sha_generic.h"

/**
 * @brief Pre-processes SM4-GCM key data
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param state pointer to IMB_MGR
 * @param key pointer to key data
 * @param key_data GCM expanded key data
 *
 */
void
imb_sm4_gcm_pre(IMB_MGR *state, const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }

        if (key == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        if (self_test_failed(state)) {
                imb_set_errno(state, IMB_ERR_SELFTEST);
                return;
        }

        DECLARE_ALIGNED(uint32_t dust[IMB_SM4_KEY_SCHEDULE_ROUNDS], 16);
        DECLARE_ALIGNED(uint8_t hash_key[16], 16);
        DECLARE_ALIGNED(uint8_t all_zeros[16], 16) = { 0 };

        IMB_SM4_KEYEXP(state, key, (uint32_t *) key_data->expanded_keys, dust);
        sm4_ecb_sse(all_zeros, hash_key, 16, (uint32_t *) key_data->expanded_keys);
        IMB_GHASH_PRE(state, hash_key, key_data);
#ifdef SAFE_DATA
        imb_clear_mem(hash_key, 16);
        imb_clear_mem(dust, IMB_SM4_KEY_SCHEDULE_ROUNDS * 4);
#endif
}
