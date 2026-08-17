/*******************************************************************************
  Copyright (c) 2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "intel-ipsec-mb.h"

#ifndef SM4_GCM_H
#define SM4_GCM_H

__forceinline void
sm4_gcm(IMB_MGR *state, const struct gcm_key_data *key_data, void *dst, const void *src,
        const uint64_t len, const void *iv, const void *aad, const uint64_t aad_len, void *tag,
        const uint64_t tag_len, IMB_CIPHER_DIRECTION dir)

{
        DECLARE_ALIGNED(uint8_t counter_block_0[16], 16) = { 0 };
        memcpy(counter_block_0, iv, 12);
        counter_block_0[15] = 1;
        uint8_t initial_tag[16] = { 0 };
        uint8_t enc_counter_block_0[16];

        /* Encrypt counter block 0 */
        SM4_ECB(counter_block_0, enc_counter_block_0, 16,
                (const uint32_t *) key_data->expanded_keys);

        /* Increment block counter value for the encryption part */
        counter_block_0[15]++;

        /* Authenticate AAD */
        IMB_GHASH(state, key_data, aad, aad_len, initial_tag, 16);

        if (dir == IMB_DIR_ENCRYPT) {
                /* SM4-CTR on plaintext */
                SM4_CTR(src, dst, len, (const uint32_t *) key_data->expanded_keys, counter_block_0,
                        16);

                /* Authenticate ciphertext */
                IMB_GHASH(state, key_data, dst, len, initial_tag, 16);
        } else {
                /* Authenticate ciphertext */
                IMB_GHASH(state, key_data, src, len, initial_tag, 16);

                /* SM4-CTR on ciphertext */
                SM4_CTR(src, dst, len, (const uint32_t *) key_data->expanded_keys, counter_block_0,
                        16);
        }

        /* XOR with len(AAD) || len(C) and GHASH (XOR done internally) */
        uint64_t lens[2];
        lens[0] = BSWAP64(aad_len << 3);
        lens[1] = BSWAP64(len << 3);

        IMB_GHASH(state, key_data, lens, 16, initial_tag, 16);

        /* XOR with encrypted counter block 0 */
        uint8_t *tag8 = (uint8_t *) tag;

        for (unsigned i = 0; i < tag_len; i++)
                tag8[i] = initial_tag[i] ^ enc_counter_block_0[i];

#ifdef SAFE_DATA
        imb_clear_mem(enc_counter_block_0, 16);
#endif
}

#endif /* SM4_GCM_H */
