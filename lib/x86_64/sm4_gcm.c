/*******************************************************************************
  Copyright (c) 2024, Intel Corporation

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
#include <string.h>

#include "intel-ipsec-mb.h"
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

        DECLARE_ALIGNED(uint32_t dust[IMB_SM4_KEY_SCHEDULE_ROUNDS], 16);
        DECLARE_ALIGNED(uint8_t hash_key[16], 16);
        DECLARE_ALIGNED(uint8_t all_zeros[16], 16) = { 0 };

        IMB_SM4_KEYEXP(state, key, (uint32_t *) key_data->expanded_keys, dust);
        sm4_ecb_sse(all_zeros, hash_key, 16, (uint32_t *) key_data->expanded_keys);
        IMB_GHASH_PRE(state, hash_key, key_data);
}

void
imb_sm4_gcm_enc(IMB_MGR *state, const struct gcm_key_data *key_data, void *dst, const void *src,
                const uint64_t len, const void *iv, const void *aad, const uint64_t aad_len,
                void *tag, const uint64_t tag_len)
{
        DECLARE_ALIGNED(uint8_t counter_block_0[16], 16) = { 0 };
        memcpy(counter_block_0, iv, 12);
        counter_block_0[15] = 1;
        uint8_t initial_tag[16] = { 0 };
        uint8_t enc_counter_block_0[16];

        /* Encrypt counter block 0 */
        if (state->used_arch == IMB_ARCH_AVX2 && state->used_arch_type == 4)
                sm4_ecb_ni_avx2(counter_block_0, enc_counter_block_0, 16,
                                (const uint32_t *) key_data->expanded_keys);
        else
                sm4_ecb_sse(counter_block_0, enc_counter_block_0, 16,
                            (const uint32_t *) key_data->expanded_keys);

        /* Increment block counter value for the encryption part */
        counter_block_0[15]++;

        /* Authenticate AAD */
        IMB_GHASH(state, key_data, aad, aad_len, initial_tag, 16);

        /* SM4-CTR on plaintext */
        if (state->used_arch == IMB_ARCH_AVX2 && state->used_arch_type == 4)
                sm4_cntr_ni_avx2(src, dst, len, (const uint32_t *) key_data->expanded_keys,
                                 counter_block_0, 16);
        else
                sm4_cntr_sse(src, dst, len, (const uint32_t *) key_data->expanded_keys,
                             counter_block_0, 16);

        /* Authenticate ciphertext */
        IMB_GHASH(state, key_data, dst, len, initial_tag, 16);

        /* XOR with len(AAD) || len(C) and GHASH (XOR done internally) */
        uint64_t lens[2];
        lens[0] = bswap8(aad_len << 3);
        lens[1] = bswap8(len << 3);

        IMB_GHASH(state, key_data, lens, 16, initial_tag, 16);

        /* XOR with encrypted counter block 0 */
        uint8_t *tag8 = (uint8_t *) tag;

        for (unsigned i = 0; i < tag_len; i++)
                tag8[i] = initial_tag[i] ^ enc_counter_block_0[i];
}

void
imb_sm4_gcm_dec(IMB_MGR *state, const struct gcm_key_data *key_data, void *dst, const void *src,
                const uint64_t len, const void *iv, const void *aad, const uint64_t aad_len,
                void *tag, const uint64_t tag_len)
{
        DECLARE_ALIGNED(uint8_t counter_block_0[16], 16) = { 0 };
        memcpy(counter_block_0, iv, 12);
        counter_block_0[15] = 1;
        uint8_t initial_tag[16] = { 0 };
        uint8_t enc_counter_block_0[16];

        /* Encrypt counter block 0 */
        if (state->used_arch == IMB_ARCH_AVX2 && state->used_arch_type == 4)
                sm4_ecb_ni_avx2(counter_block_0, enc_counter_block_0, 16,
                                (const uint32_t *) key_data->expanded_keys);
        else
                sm4_ecb_sse(counter_block_0, enc_counter_block_0, 16,
                            (const uint32_t *) key_data->expanded_keys);

        /* Increment block counter value for the encryption part */
        counter_block_0[15]++;

        /* Authenticate AAD */
        IMB_GHASH(state, key_data, aad, aad_len, initial_tag, 16);

        /* Authenticate ciphertext */
        IMB_GHASH(state, key_data, src, len, initial_tag, 16);

        /* SM4-CTR on ciphertext */
        if (state->used_arch == IMB_ARCH_AVX2 && state->used_arch_type == 4)
                sm4_cntr_ni_avx2(src, dst, len, (const uint32_t *) key_data->expanded_keys,
                                 counter_block_0, 16);
        else
                sm4_cntr_sse(src, dst, len, (const uint32_t *) key_data->expanded_keys,
                             counter_block_0, 16);

        /* XOR with len(AAD) || len(C) and GHASH (XOR done internally) */
        uint64_t lens[2];
        lens[0] = bswap8(aad_len << 3);
        lens[1] = bswap8(len << 3);

        IMB_GHASH(state, key_data, lens, 16, initial_tag, 16);

        /* XOR with encrypted counter block 0 */
        uint8_t *tag8 = (uint8_t *) tag;

        for (unsigned i = 0; i < tag_len; i++)
                tag8[i] = initial_tag[i] ^ enc_counter_block_0[i];
}
