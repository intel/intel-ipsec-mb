/*
 * Copyright (c) 2012-2016, Intel Corporation
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

typedef unsigned char u8;
#ifdef LINUX
typedef unsigned long int u64;
#else
typedef unsigned __int64 u64;
#endif

typedef struct gcm_data {
        u8 expanded_keys[16*11];
        u8 shifted_hkey_1[16];  // store HashKey <<1 mod poly here
        u8 shifted_hkey_2[16];  // store HashKey^2 <<1 mod poly here
        u8 shifted_hkey_3[16];  // store HashKey^3 <<1 mod poly here
        u8 shifted_hkey_4[16];  // store HashKey^4 <<1 mod poly here
        u8 shifted_hkey_5[16];  // store HashKey^5 <<1 mod poly here
        u8 shifted_hkey_6[16];  // store HashKey^6 <<1 mod poly here
        u8 shifted_hkey_7[16];  // store HashKey^7 <<1 mod poly here
        u8 shifted_hkey_8[16];  // store HashKey^8 <<1 mod poly here
        u8 shifted_hkey_1_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey <<1 mod poly here (for Karatsuba purposes)
        u8 shifted_hkey_2_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^2 <<1 mod poly here (for Karatsuba purposes)
        u8 shifted_hkey_3_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^3 <<1 mod poly here (for Karatsuba purposes)
        u8 shifted_hkey_4_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^4 <<1 mod poly here (for Karatsuba purposes)
        u8 shifted_hkey_5_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^5 <<1 mod poly here (for Karatsuba purposes)
        u8 shifted_hkey_6_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^6 <<1 mod poly here (for Karatsuba purposes)
        u8 shifted_hkey_7_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^7 <<1 mod poly here (for Karatsuba purposes)
        u8 shifted_hkey_8_k[16];  // store XOR of High 64 bits and Low 64 bits of  HashKey^8 <<1 mod poly here (for Karatsuba purposes)
} gcm_data;

void 
aesni_gcm_enc_sse(gcm_data *my_ctx_data, /* aligned to 16 Bytes */
                  u8 *out, /* Ciphertext output. Encrypt in-place is allowed.  */
                  const u8 *in, /* Plaintext input */
                  u64 plaintext_len, /* Length of data in Bytes for encryption. */
                  u8 *iv, /* Pre-counter block j0: 4 byte salt (from Security Association)
                             concatenated with 8 byte Initialisation Vector
                             (from IPSec ESP Payload) concatenated with 0x00000001.
                             16-byte aligned pointer. */
                  const u8 *aad, /* Additional Authentication Data (AAD)*/
                  u64 aad_len, /* Length of AAD in bytes. With RFC4106 this is going to be 8 or 12 Bytes */
                  u8 *auth_tag, /* Authenticated Tag output. */
                  u64 auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */
                  
void
aesni_gcm_enc_avx_gen4(gcm_data *my_ctx_data, /* aligned to 16 Bytes */
                       u8 *out, /* Ciphertext output. Encrypt in-place is allowed.  */
                       const u8 *in, /* Plaintext input */
                       u64 plaintext_len, /* Length of data in Bytes for encryption. */
                       u8 *iv, /* Pre-counter block j0: 4 byte salt 
                                       (from Security Association) concatenated with 8 byte
                                       Initialisation Vector (from IPSec ESP Payload)
                                       concatenated with 0x00000001. 16-byte aligned pointer. */
                       const u8 *aad, /* Additional Authentication Data (AAD)*/
                       u64 aad_len, /* Length of AAD in bytes. With RFC4106 this is going to be 8 or 12 Bytes */
                       u8 *auth_tag, /* Authenticated Tag output. */
                       u64 auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */

void
aesni_gcm_enc_avx_gen2(gcm_data *my_ctx_data, /* aligned to 16 Bytes */
                       u8 *out, /* Ciphertext output. Encrypt in-place is allowed.  */
                       const u8 *in, /* Plaintext input */
                       u64 plaintext_len, /* Length of data in Bytes for encryption. */
                       u8 *iv, /* Pre-counter block j0: 4 byte salt (from Security Association)
                                  concatenated with 8 byte Initialisation Vector 
                                  (from IPSec ESP Payload) concatenated with 0x00000001.
                                  16-byte aligned pointer. */
                       const u8 *aad, /* Additional Authentication Data (AAD)*/
                       u64 aad_len, /* Length of AAD in bytes. With RFC4106 this is going to be 8 or 12 Bytes */
                       u8 *auth_tag, /* Authenticated Tag output. */
                       u64 auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */

void
aesni_gcm_dec_sse(gcm_data *my_ctx_data, /* aligned to 16 Bytes */
                  u8 *out, /* Plaintext output. Decrypt in-place is allowed.  */
                  const u8 *in, /* Ciphertext input */
                  u64 plaintext_len, /* Length of data in Bytes for encryption. */
                  u8 *iv, /* Pre-counter block j0: 4 byte salt (from Security Association)
                             concatenated with 8 byte Initialisation Vector
                             (from IPSec ESP Payload) concatenated with 0x00000001.
                             16-byte aligned pointer. */
                  const u8 *aad, /* Additional Authentication Data (AAD)*/
                  u64 aad_len, /* Length of AAD in bytes. With RFC4106 this is going to be 8 or 12 Bytes */
                  u8 *auth_tag, /* Authenticated Tag output. */
                  u64 auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */

void
aesni_gcm_dec_avx_gen4(gcm_data *my_ctx_data, /* aligned to 16 Bytes */
                       u8 *out, /* Plaintext output. Decrypt in-place is allowed.  */
                       const u8 *in, /* Ciphertext input */
                       u64 plaintext_len, /* Length of data in Bytes for encryption. */
                       u8 *iv, /* Pre-counter block j0: 4 byte salt (from Security Association)
                                  concatenated with 8 byte Initialisation Vector
                                  (from IPSec ESP Payload) concatenated with 0x00000001.
                                  16-byte aligned pointer. */
                       const u8 *aad, /* Additional Authentication Data (AAD)*/
                       u64 aad_len, /* Length of AAD in bytes. With RFC4106 this is going to be 8 or 12 Bytes */
                       u8 *auth_tag, /* Authenticated Tag output. */
                       u64 auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */

void
aesni_gcm_dec_avx_gen2(gcm_data *my_ctx_data, /* aligned to 16 Bytes */
                       u8 *out, /* Plaintext output. Decrypt in-place is allowed.  */
                       const u8 *in, /* Ciphertext input */
                       u64 plaintext_len, /* Length of data in Bytes for encryption. */
                       u8 *iv, /* Pre-counter block j0: 4 byte salt
                                  (from Security Association) concatenated with
                                  8 byte Initialisation Vector (from IPSec ESP Payload)
                                  concatenated with 0x00000001. 16-byte aligned pointer. */
                       const u8 *aad, /* Additional Authentication Data (AAD)*/
                       u64 aad_len, /* Length of AAD in bytes. With RFC4106 this is going to be 8 or 12 Bytes */
                       u8 *auth_tag, /* Authenticated Tag output. */
                       u64 auth_tag_len); /* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */

void
aesni_gcm_precomp_sse(gcm_data *my_ctx_data, 
                      u8 *hash_subkey); /* H, the Hash sub key input. Data starts on a 16-byte boundary. */

void
aesni_gcm_precomp_avx_gen4(gcm_data *my_ctx_data, 
                           u8	*hash_subkey); /* H, the Hash sub key input. Data starts on a 16-byte boundary. */

void
aesni_gcm_precomp_avx_gen2(gcm_data *my_ctx_data, 
                           u8 *hash_subkey); /* H, the Hash sub key input. Data starts on a 16-byte boundary. */
