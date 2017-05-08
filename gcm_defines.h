/*
 * Copyright (c) 2012-2017, Intel Corporation
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef GCM_DEFINES_H
#define GCM_DEFINES_H

#include <stdint.h>

#include <aux_funcs.h>
#include <os.h>

#ifdef __cplusplus
extern "C" {
#endif

        /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */
#define MAX_TAG_LEN (16)
        //
        // IV data is limited to 16 bytes. The last DWORD (4 bytes) must be 0x1
        //
#define GCM_IV_LEN (16)
#define GCM_IV_DATA_LEN (12)
#define GCM_IV_END_MARK {0x00, 0x00, 0x00, 0x01}
#define GCM_IV_END_START (12)

#define LONGEST_TESTED_AAD_LENGTH (2* 1024)

        // Key lengths of 128 and 256 supported
#define GCM_128_KEY_LEN (16)
#define GCM_192_KEY_LEN (24)
#define GCM_256_KEY_LEN (32)

#define GCM_BLOCK_LEN  16
#define GCM_ENC_KEY_LEN  16
#define GCM_KEY_SETS (15) /*exp key + 14 exp round keys*/

/**
 * @brief holds intermediate key data needed to improve performance
 *
 * gcm_data hold internal key information used by gcm128 and gcm256.
 */
#ifdef __WIN32
__declspec(align(16))
#endif /* WIN32 */
struct gcm_data {
        uint8_t expanded_keys[GCM_ENC_KEY_LEN * GCM_KEY_SETS];
        uint8_t shifted_hkey_1[GCM_ENC_KEY_LEN];  // store HashKey <<1 mod poly here
        uint8_t shifted_hkey_2[GCM_ENC_KEY_LEN];  // store HashKey^2 <<1 mod poly here
        uint8_t shifted_hkey_3[GCM_ENC_KEY_LEN];  // store HashKey^3 <<1 mod poly here
        uint8_t shifted_hkey_4[GCM_ENC_KEY_LEN];  // store HashKey^4 <<1 mod poly here
        uint8_t shifted_hkey_5[GCM_ENC_KEY_LEN];  // store HashKey^5 <<1 mod poly here
        uint8_t shifted_hkey_6[GCM_ENC_KEY_LEN];  // store HashKey^6 <<1 mod poly here
        uint8_t shifted_hkey_7[GCM_ENC_KEY_LEN];  // store HashKey^7 <<1 mod poly here
        uint8_t shifted_hkey_8[GCM_ENC_KEY_LEN];  // store HashKey^8 <<1 mod poly here
        uint8_t shifted_hkey_1_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey <<1 mod poly here (for Karatsuba purposes)
        uint8_t shifted_hkey_2_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^2 <<1 mod poly here (for Karatsuba purposes)
        uint8_t shifted_hkey_3_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^3 <<1 mod poly here (for Karatsuba purposes)
        uint8_t shifted_hkey_4_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^4 <<1 mod poly here (for Karatsuba purposes)
        uint8_t shifted_hkey_5_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^5 <<1 mod poly here (for Karatsuba purposes)
        uint8_t shifted_hkey_6_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^6 <<1 mod poly here (for Karatsuba purposes)
        uint8_t shifted_hkey_7_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^7 <<1 mod poly here (for Karatsuba purposes)
        uint8_t shifted_hkey_8_k[GCM_ENC_KEY_LEN];  // store XOR of High 64 bits and Low 64 bits of  HashKey^8 <<1 mod poly here (for Karatsuba purposes)
        // init, update and finalize context data
        uint8_t  aad_hash[GCM_BLOCK_LEN];
        uint64_t aad_length;
        uint64_t in_length;
        uint8_t  partial_block_enc_key[GCM_BLOCK_LEN];
        uint8_t  orig_IV[GCM_BLOCK_LEN];
        uint8_t  current_counter[GCM_BLOCK_LEN];
        uint64_t  partial_block_length;
}
#ifdef LINUX
        __attribute__ ((aligned (16)));
#else
        ;
#endif

/**
 * @brief GCM-AES Encryption using 128 bit keys
 *
 * @param my_ctx_data GCM context data
 * @param out Ciphertext output. Encrypt in-place is allowed.
 * @param in Plaintext input.
 * @param len Length of data in Bytes for encryption.
 * @param iv Pre-counter block j0: 4 byte salt (from Security Association)
 *           concatenated with 8 byte Initialization Vector (from IPSec ESP
 *           Payload) concatenated with 0x00000001. 16-byte pointer.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void aesni_gcm128_enc_sse(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm128_enc_avx_gen2(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm128_enc_avx_gen4(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief GCM-AES Decryption using 128 bit keys
 *
 * @param my_ctx_data GCM context data
 * @param out Plaintext output. Decrypt in-place is allowed.
 * @param in Ciphertext input.
 * @param len Length of data in Bytes for decryption.
 * @param iv Pre-counter block j0: 4 byte salt (from Security Association)
 *           concatenated with 8 byte Initialization Vector (from IPSec ESP
 *           Payload) concatenated with 0x00000001. 16-byte pointer.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void aesni_gcm128_dec_sse(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm128_dec_avx_gen2(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm128_dec_avx_gen4(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief Start a AES-128-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param iv Pre-counter block j0: 4 byte salt (from Security Association)
 *           concatenated with 8 byte Initialization Vector (from IPSec ESP
 *           Payload) concatenated with 0x00000001. 16-byte pointer.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 *
 */
void
aesni_gcm128_init_sse(struct gcm_data *my_ctx_data,
                      uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
void
aesni_gcm128_init_avx_gen2(struct gcm_data *my_ctx_data,
                           uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
void
aesni_gcm128_init_avx_gen4(struct gcm_data *my_ctx_data,
                           uint8_t *iv, uint8_t const *aad, uint64_t aad_len);

/**
 * @brief encrypt a block of a AES-128-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param out Ciphertext output. Encrypt in-place is allowed.
 * @param in Plaintext input.
 * @param len Length of data in Bytes for decryption.
 */
void
aesni_gcm128_enc_update_sse(struct gcm_data *my_ctx_data, uint8_t *out,
                            const uint8_t *in, uint64_t len);
void
aesni_gcm128_enc_update_avx_gen2(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);
void
aesni_gcm128_enc_update_avx_gen4(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);

/**
 * @brief decrypt a block of a AES-128-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param out Plaintext output. Decrypt in-place is allowed.
 * @param in Ciphertext input.
 * @param len Length of data in Bytes for decryption.
 */
void
aesni_gcm128_dec_update_sse(struct gcm_data *my_ctx_data, uint8_t *out,
                            const uint8_t *in, uint64_t len);
void
aesni_gcm128_dec_update_avx_gen2(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);
void
aesni_gcm128_dec_update_avx_gen4(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);

/**
 * @brief End encryption of a AES-128-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void
aesni_gcm128_enc_finalize_sse(struct gcm_data *my_ctx_data,
                              uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm128_enc_finalize_avx_gen2(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm128_enc_finalize_avx_gen4(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief End decryption of a AES-128-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void
aesni_gcm128_dec_finalize_sse(struct gcm_data *my_ctx_data,
                              uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm128_dec_finalize_avx_gen2(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm128_dec_finalize_avx_gen4(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);
/**
 * @brief Precomputation of HashKey constants
 *
 * Precomputation of HashKey<<1 mod poly constants (shifted_hkey_X and
 * shifted_hkey_X_k).
 *
 * @param gdata GCM context data
 */
void aesni_gcm128_precomp_sse(struct gcm_data *gdata);
void aesni_gcm128_precomp_avx_gen2(struct gcm_data *gdata);
void aesni_gcm128_precomp_avx_gen4(struct gcm_data *gdata);
void aesni_gcm192_precomp_sse(struct gcm_data *gdata);
void aesni_gcm192_precomp_avx_gen2(struct gcm_data *gdata);
void aesni_gcm192_precomp_avx_gen4(struct gcm_data *gdata);
void aesni_gcm256_precomp_sse(struct gcm_data *gdata);
void aesni_gcm256_precomp_avx_gen2(struct gcm_data *gdata);
void aesni_gcm256_precomp_avx_gen4(struct gcm_data *gdata);

void aesni_gcm128_precomp_sse(struct gcm_data *gdata);
void aesni_gcm128_precomp_avx_gen2(struct gcm_data *gdata);
void aesni_gcm128_precomp_avx_gen4(struct gcm_data *gdata);
void aesni_gcm192_precomp_sse(struct gcm_data *gdata);
void aesni_gcm192_precomp_avx_gen2(struct gcm_data *gdata);
void aesni_gcm192_precomp_avx_gen4(struct gcm_data *gdata);
void aesni_gcm256_precomp_sse(struct gcm_data *gdata);
void aesni_gcm256_precomp_avx_gen2(struct gcm_data *gdata);
void aesni_gcm256_precomp_avx_gen4(struct gcm_data *gdata);

/**
 * @brief pre-processes GCM128 key data (SSE version)
 *
 * Prefills the gcm data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param key
 * @param gdata GCM context data
 *
 */
__forceinline
void aesni_gcm128_pre_sse(const void *key, struct gcm_data *gdata)
{
        //////
        // Prefill the key values for each round of encrypting/decrypting
        // Prefill the Sub Hash key values for encoding the tag
        //////
        aes_keyexp_128_enc_sse(key, gdata->expanded_keys);
        aesni_gcm128_precomp_sse(gdata);
}

/**
 * @brief pre-processes GCM128 key data (AVX version)
 *
 * Prefills the gcm data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param key key data
 * @param gdata GCM context data
 */
__forceinline
void aesni_gcm128_pre_avx_gen2(const void *key, struct gcm_data *gdata)
{
        //////
        // Prefill the key values for each round of encrypting/decrypting
        // Prefill the Sub Hash key values for encoding the tag
        //////
        aes_keyexp_128_enc_avx(key, gdata->expanded_keys);
        aesni_gcm128_precomp_avx_gen2(gdata);
}

/**
 * @brief pre-processes GCM128 key data (AVX version)
 *
 * Prefills the gcm data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param key key data
 * @param gdata GCM context data
 */
__forceinline
void aesni_gcm128_pre_avx_gen4(const void *key, struct gcm_data *gdata)
{
        //////
        // Prefill the key values for each round of encrypting/decrypting
        // Prefill the Sub Hash key values for encoding the tag
        //////
        aes_keyexp_128_enc_avx2(key, gdata->expanded_keys);
        aesni_gcm128_precomp_avx_gen4(gdata);
}

/**
 * @brief pre-processes GCM192 key data (SSE version)
 *
 * Prefills the gcm data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param key
 * @param gdata GCM context data
 *
 */
__forceinline
void aesni_gcm192_pre_sse(const void *key, struct gcm_data *gdata)
{
        //////
        // Prefill the key values for each round of encrypting/decrypting
        // Prefill the Sub Hash key values for encoding the tag
        //////
        aes_keyexp_192_enc_sse(key, gdata->expanded_keys);
        aesni_gcm192_precomp_sse(gdata);
}

/**
 * @brief pre-processes GCM192 key data (AVX version)
 *
 * Prefills the gcm data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param key key data
 * @param gdata GCM context data
 */
__forceinline
void aesni_gcm192_pre_avx_gen2(const void *key, struct gcm_data *gdata)
{
        //////
        // Prefill the key values for each round of encrypting/decrypting
        // Prefill the Sub Hash key values for encoding the tag
        //////
        aes_keyexp_192_enc_avx(key, gdata->expanded_keys);
        aesni_gcm192_precomp_avx_gen2(gdata);
}

/**
 * @brief pre-processes GCM192 key data (AVX version)
 *
 * Prefills the gcm data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param key key data
 * @param gdata GCM context data
 */
__forceinline
void aesni_gcm192_pre_avx_gen4(const void *key, struct gcm_data *gdata)
{
        //////
        // Prefill the key values for each round of encrypting/decrypting
        // Prefill the Sub Hash key values for encoding the tag
        //////
        aes_keyexp_192_enc_avx2(key, gdata->expanded_keys);
        aesni_gcm192_precomp_avx_gen4(gdata);
}

/**
 * @brief GCM-AES Encryption using 192 bit keys
 *
 * @param my_ctx_data GCM context data
 * @param out Ciphertext output. Encrypt in-place is allowed.
 * @param in Plaintext input.
 * @param len Length of data in Bytes for encryption.
 * @param iv Pre-counter block j0: 4 byte salt (from Security Association)
 *           concatenated with 8 byte Initialization Vector (from IPSec ESP
 *           Payload) concatenated with 0x00000001. 16-byte pointer.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void
aesni_gcm192_enc_sse(struct gcm_data *my_ctx_data,
                     uint8_t *out, uint8_t const *in, uint64_t len,
                     uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                     uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm192_enc_avx_gen2(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm192_enc_avx_gen4(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief GCM-AES Decryption using 192 bit keys
 *
 * @param my_ctx_data GCM context data
 * @param out Plaintext output. Decrypt in-place is allowed.
 * @param in Ciphertext input.
 * @param len Length of data in Bytes for decryption.
 * @param iv Pre-counter block j0: 4 byte salt (from Security Association)
 *           concatenated with 8 byte Initialization Vector (from IPSec ESP
 *           Payload) concatenated with 0x00000001. 16-byte pointer.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void
aesni_gcm192_dec_sse(struct gcm_data *my_ctx_data,
                     uint8_t *out, uint8_t const *in, uint64_t len,
                     uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                     uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm192_dec_avx_gen2(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm192_dec_avx_gen4(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);
/**
 * @brief Start a AES-192-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param iv Pre-counter block j0: 4 byte salt (from Security Association)
 *           concatenated with 8 byte Initialization Vector (from IPSec ESP
 *           Payload) concatenated with 0x00000001. 16-byte pointer.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 *
 */
void
aesni_gcm192_init_sse(struct gcm_data *my_ctx_data,
                      uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
void
aesni_gcm192_init_avx_gen2(struct gcm_data *my_ctx_data,
                           uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
void
aesni_gcm192_init_avx_gen4(struct gcm_data *my_ctx_data,
                           uint8_t *iv, uint8_t const *aad, uint64_t aad_len);

/**
 * @brief encrypt a block of a AES-192-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param out Ciphertext output. Encrypt in-place is allowed.
 * @param in Plaintext input.
 * @param len Length of data in Bytes for decryption.
 */
void
aesni_gcm192_enc_update_sse(struct gcm_data *my_ctx_data, uint8_t *out,
                            const uint8_t *in, uint64_t len);
void
aesni_gcm192_enc_update_avx_gen2(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);
void
aesni_gcm192_enc_update_avx_gen4(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);

/**
 * @brief decrypt a block of a AES-192-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param out Plaintext output. Decrypt in-place is allowed.
 * @param in Ciphertext input.
 * @param len Length of data in Bytes for decryption.
 */
void
aesni_gcm192_dec_update_sse(struct gcm_data *my_ctx_data, uint8_t *out,
                            const uint8_t *in, uint64_t len);
void
aesni_gcm192_dec_update_avx_gen2(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);
void
aesni_gcm192_dec_update_avx_gen4(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);

/**
 * @brief End encryption of a AES-192-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void
aesni_gcm192_enc_finalize_sse(struct gcm_data *my_ctx_data,
                              uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm192_enc_finalize_avx_gen2(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm192_enc_finalize_avx_gen4(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief End decryption of a AES-192-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void
aesni_gcm192_dec_finalize_sse(struct gcm_data *my_ctx_data,
                              uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm192_dec_finalize_avx_gen2(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm192_dec_finalize_avx_gen4(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief GCM-AES Encryption using 256 bit keys
 *
 * @param my_ctx_data GCM context data
 * @param out Ciphertext output. Encrypt in-place is allowed.
 * @param in Plaintext input.
 * @param len Length of data in Bytes for encryption.
 * @param iv Pre-counter block j0: 4 byte salt (from Security Association)
 *           concatenated with 8 byte Initialization Vector (from IPSec ESP
 *           Payload) concatenated with 0x00000001. 16-byte pointer.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void
aesni_gcm256_enc_sse(struct gcm_data *my_ctx_data,
                     uint8_t *out, uint8_t const *in, uint64_t len,
                     uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                     uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm256_enc_avx_gen2(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm256_enc_avx_gen4(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief GCM-AES Decryption using 256 bit keys
 *
 * @param my_ctx_data GCM context data
 * @param out Plaintext output. Decrypt in-place is allowed.
 * @param in Ciphertext input.
 * @param len Length of data in Bytes for decryption.
 * @param iv Pre-counter block j0: 4 byte salt (from Security Association)
 *           concatenated with 8 byte Initialization Vector (from IPSec ESP
 *           Payload) concatenated with 0x00000001. 16-byte pointer.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void
aesni_gcm256_dec_sse(struct gcm_data *my_ctx_data,
                     uint8_t *out, uint8_t const *in, uint64_t len,
                     uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                     uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm256_dec_avx_gen2(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

void
aesni_gcm256_dec_avx_gen4(struct gcm_data *my_ctx_data,
                          uint8_t *out, uint8_t const *in, uint64_t len,
                          uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                          uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief Start a AES-256-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param iv Pre-counter block j0: 4 byte salt (from Security Association)
 *           concatenated with 8 byte Initialization Vector (from IPSec ESP
 *           Payload) concatenated with 0x00000001. 16-byte pointer.
 * @param aad Additional Authentication Data (AAD).
 * @param aad_len Length of AAD.
 *
 */
void
aesni_gcm256_init_sse(struct gcm_data *my_ctx_data,
                      uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
void
aesni_gcm256_init_avx_gen2(struct gcm_data *my_ctx_data,
                           uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
void
aesni_gcm256_init_avx_gen4(struct gcm_data *my_ctx_data,
                           uint8_t *iv, uint8_t const *aad, uint64_t aad_len);

/**
 * @brief encrypt a block of a AES-256-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param out Ciphertext output. Encrypt in-place is allowed.
 * @param in Plaintext input.
 * @param len Length of data in Bytes for decryption.
 */
void
aesni_gcm256_enc_update_sse(struct gcm_data *my_ctx_data, uint8_t *out,
                            const uint8_t *in, uint64_t len);
void
aesni_gcm256_enc_update_avx_gen2(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);
void
aesni_gcm256_enc_update_avx_gen4(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);

/**
 * @brief decrypt a block of a AES-256-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param out Plaintext output. Decrypt in-place is allowed.
 * @param in Ciphertext input.
 * @param len Length of data in Bytes for decryption.
 */
void
aesni_gcm256_dec_update_sse(struct gcm_data *my_ctx_data, uint8_t *out,
                            const uint8_t *in, uint64_t len);
void
aesni_gcm256_dec_update_avx_gen2(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);
void
aesni_gcm256_dec_update_avx_gen4(struct gcm_data *my_ctx_data, uint8_t *out,
                                 const uint8_t *in, uint64_t len);

/**
 * @brief End encryption of a AES-256-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void
aesni_gcm256_enc_finalize_sse(struct gcm_data *my_ctx_data,
                              uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm256_enc_finalize_avx_gen2(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm256_enc_finalize_avx_gen4(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief End decryption of a AES-256-GCM Encryption message
 *
 * @param my_ctx_data GCM context data
 * @param auth_tag Authenticated Tag output.
 * @param auth_tag_len Authenticated Tag Length in bytes (must be
 *                     a multiple of 4 bytes). Valid values are
 *                     16 (most likely), 12 or 8.
 */
void
aesni_gcm256_dec_finalize_sse(struct gcm_data *my_ctx_data,
                              uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm256_dec_finalize_avx_gen2(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);
void
aesni_gcm256_dec_finalize_avx_gen4(struct gcm_data *my_ctx_data,
                                   uint8_t *auth_tag, uint64_t auth_tag_len);

/**
 * @brief pre-processes GCM256 key data (SSE version)
 *
 * Prefills the gcm data with key values for each round and
 * the initial sub hash key for tag encoding
 */
__forceinline
void aesni_gcm256_pre_sse(const void *key, struct gcm_data *gdata)
{
        struct gcm_data tmp;
        //////
        // Prefill the key values for each round of encrypting/decrypting
        // Prefill the Sub Hash key values for encoding the tag
        //////
        aes_keyexp_256_sse(key, gdata->expanded_keys, tmp.expanded_keys);
        aesni_gcm256_precomp_sse(gdata);
}

/**
 * @brief pre-processes GCM256 key data (AVX version)
 *
 * Prefills the gcm data with key values for each round and
 * the initial sub hash key for tag encoding
 */
__forceinline
void aesni_gcm256_pre_avx_gen2(const void *key, struct gcm_data *gdata)
{
        //////
        // Prefill the key values for each round of encrypting/decrypting
        // Prefill the Sub Hash key values for encoding the tag
        //////
        aes_keyexp_256_enc_avx(key, gdata->expanded_keys);
        aesni_gcm256_precomp_avx_gen2(gdata);
}

/**
 * @brief pre-processes GCM256 key data (AVX2 version)
 *
 * Prefills the gcm data with key values for each round and
 * the initial sub hash key for tag encoding
 */
__forceinline
void aesni_gcm256_pre_avx_gen4(const void *key, struct gcm_data *gdata)
{
        //////
        // Prefill the key values for each round of encrypting/decrypting
        // Prefill the Sub Hash key values for encoding the tag
        //////
        aes_keyexp_256_enc_avx2(key, gdata->expanded_keys);
        aesni_gcm256_precomp_avx_gen4(gdata);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* ifndef GCM_DEFINES_H */
