/*******************************************************************************
  Copyright (c) 2012-2017, Intel Corporation

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

#ifndef IMB_JOB_AES_HMAC_H
#define IMB_JOB_AES_HMAC_H

#include "types.h"

typedef enum {
        STS_BEING_PROCESSED = 0,
        STS_COMPLETED_AES =   1,
        STS_COMPLETED_HMAC =  2,
        STS_COMPLETED =       3, /* COMPLETED_AES | COMPLETED_HMAC */
        STS_INVALID_ARGS =    4,
        STS_INTERNAL_ERROR,
        STS_ERROR
} JOB_STS;

typedef enum {
        CBC = 1,
        CNTR,
        NULL_CIPHER,
        DOCSIS_SEC_BPI,
#ifndef NO_GCM
        GCM,
#endif /* !NO_GCM */
        CUSTOM_CIPHER,
        DES,
        DOCSIS_DES,
        CCM,
        DES3
} JOB_CIPHER_MODE;

typedef enum {
        ENCRYPT = 1,
        DECRYPT
} JOB_CIPHER_DIRECTION;

typedef enum {
        SHA1 = 1,
        SHA_224,
        SHA_256,
        SHA_384,
        SHA_512,
        AES_XCBC,
        MD5,
        NULL_HASH,
#ifndef NO_GCM
        AES_GMAC,
#endif /* !NO_GCM */
        CUSTOM_HASH,
        AES_CCM,
} JOB_HASH_ALG;

typedef enum {
        CIPHER_HASH = 1,
        HASH_CIPHER
} JOB_CHAIN_ORDER;

typedef enum {
        AES_128_BYTES = 16,
        AES_192_BYTES = 24,
        AES_256_BYTES = 32
} AES_KEY_SIZE_BYTES;

typedef struct JOB_AES_HMAC {
        /*
         * For AES, aes_enc_key_expanded and aes_dec_key_expanded are
         * expected to point to expanded keys structure.
         * - AES-CTR and AES-CCM, only aes_enc_key_expanded is used
         * - DOCSIS (AES-CBC + AES-CFB), both pointers are used
         *   aes_enc_key_expanded has to be set always for the partial block
         *
         * For DES, aes_enc_key_expanded and aes_dec_key_expanded are
         * expected to point to DES key schedule.
         * - same key schedule used for enc and dec operations
         *
         * For 3DES, aes_enc_key_expanded and aes_dec_key_expanded are
         * expected to point to an array of 3 pointers for
         * the corresponding 3 key schedules.
         * - same key schedule used for enc and dec operations
         */
        const void *aes_enc_key_expanded;  /* 16-byte aligned pointer. */
        const void *aes_dec_key_expanded;
        UINT64 aes_key_len_in_bytes; /* Only 16, 24, and  32 byte (128, 192 and
                                      * 256-bit) keys supported at this time. */
        const UINT8 *src; /* Input. May be cipher text or plaintext.
                           * In-place ciphering allowed. */
        UINT8 *dst; /*Output. May be cipher text or plaintext.
                     * In-place ciphering allowed, i.e. dst = src. */
        UINT64 cipher_start_src_offset_in_bytes;
        UINT64 msg_len_to_cipher_in_bytes; /* Max len = 65472 bytes.
                                            * IPSec case, the maximum cipher
                                            * length would be:
                                            * 65535 -
                                            * 20 (outer IP header) -
                                            * 24 (ESP header + IV) -
                                            * 12 (supported ICV length) */
        UINT64 hash_start_src_offset_in_bytes;
        UINT64 msg_len_to_hash_in_bytes; /* Max len = 65496 bytes.
                                          * (Max cipher len +
                                          * 24 bytes ESP header) */
        const UINT8 *iv; /* AES IV. */
        UINT64 iv_len_in_bytes; /* AES IV length in bytes. */
        UINT8 *auth_tag_output; /* HMAC Tag output. This may point to a location
                                 * in the src buffer (for in place)*/
        UINT64 auth_tag_output_len_in_bytes; /* HMAC Tag output length in bytes.
                                              * (May be a truncated value)*/

        /* Start algorithm-specific fields */
        union {
                struct _HMAC_specific_fields {
                        /* Hashed result of HMAC key xor'd with ipad (0x36). */
                        const UINT8 *_hashed_auth_key_xor_ipad;
                        /* Hashed result of HMAC key xor'd with opad (0x5c). */
                        const UINT8 *_hashed_auth_key_xor_opad;
                } HMAC;
                struct _AES_XCBC_specific_fields {
                        /* 16-byte aligned pointers */
                        const UINT32 *_k1_expanded;
                        const UINT8 *_k2;
                        const UINT8 *_k3;
                } XCBC;
                struct _AES_CCM_specific_fields {
                        /* Additional Authentication Data (AAD) */
                        const void *aad;
                        UINT64 aad_len_in_bytes; /* Length of AAD */
                } CCM;
#ifndef NO_GCM
                struct _AES_GCM_specific_fields {
                        /* Additional Authentication Data (AAD) */
                        const void *aad;
                        UINT64 aad_len_in_bytes;    /* Length of AAD */
                } GCM;
#endif /* !NO_GCM */
        } u;

        JOB_STS status;
        JOB_CIPHER_MODE cipher_mode; /* CBC, CNTR, DES, GCM etc. */
        JOB_CIPHER_DIRECTION cipher_direction; /* Encrypt/decrypt */
        /* Ignored as the direction is implied by the chain _order field. */
        JOB_HASH_ALG hash_alg; /* SHA-1 or others... */
        JOB_CHAIN_ORDER chain_order; /* CIPHER_HASH or HASH_CIPHER */

        void *user_data;
        void *user_data2;

        /*
         * stateless custom cipher and hash
         *   Return:
         *     success: 0
         *     fail:    other
         */
        int (*cipher_func)(struct JOB_AES_HMAC *);
        int (*hash_func)(struct JOB_AES_HMAC *);
} JOB_AES_HMAC;

#define hashed_auth_key_xor_ipad u.HMAC._hashed_auth_key_xor_ipad
#define hashed_auth_key_xor_opad u.HMAC._hashed_auth_key_xor_opad
#define _k1_expanded             u.XCBC._k1_expanded
#define _k2                      u.XCBC._k2
#define _k3                      u.XCBC._k3

#endif /* IMB_JOB_AES_HMAC_H */
