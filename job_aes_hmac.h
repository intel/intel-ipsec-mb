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

#ifndef _JOB_AES_HMAC_H_
#define _JOB_AES_HMAC_H_

#include "types.h"
#include "asm_types.h"
#include "gcm_defines.h"

typedef enum JOB_STS {
        STS_BEING_PROCESSED = 0,
        STS_COMPLETED_AES =   1,
        STS_COMPLETED_HMAC =  2,
        STS_COMPLETED =       3, // COMPLETED_AES | COMPLETED_HMAC
        STS_INVALID_ARGS =    4,
        STS_INTERNAL_ERROR =  8,
        STS_AUTH_FAILED    =  16,
} JOB_STS;

typedef enum JOB_CIPHER_MODE {
        CBC = 1,
        CNTR,
        NULL_CIPHER,
        DOCSIS_SEC_BPI,
        GCM,

        CIPHER_MODE_NUMOF
} JOB_CIPHER_MODE;

typedef enum JOB_CIPHER_DIRECTION {
        ENCRYPT = 1,
        DECRYPT
} JOB_CIPHER_DIRECTION;

typedef enum JOB_HASH_ALG {
        SHA1 = 1,
        SHA_224,
        SHA_256,
        SHA_384,
        SHA_512,
        AES_XCBC,
        MD5,
        NULL_HASH,
        GCM_AES,

        HASH_ALG_NUMOF
} JOB_HASH_ALG;

typedef enum JOB_CHAIN_ORDER {
        CIPHER_HASH = 1,
        HASH_CIPHER
} JOB_CHAIN_ORDER;

typedef enum AES_KEY_SIZE_BYTES {
        AES_128_BYTES = 16,
        AES_192_BYTES = 24,
        AES_256_BYTES = 32
} AES_KEY_SIZE_BYTES;

/*
 * Extended
 */
enum JOB_TASK {
        JOB_TASK_INVALID = 0,

        JOB_TASK_AES128_CBC,
        JOB_TASK_AES192_CBC,
        JOB_TASK_AES256_CBC,
        JOB_TASK_AES128_CTR,
        JOB_TASK_AES192_CTR,
        JOB_TASK_AES256_CTR,
        JOB_TASK_AES128_GCM,
        JOB_TASK_AES192_GCM,
        JOB_TASK_AES256_GCM,
        JOB_TASK_DOCSIS,
        JOB_TASK_NULL_CIPHER,
        JOB_TASK_SHA1,
        JOB_TASK_SHA224,
        JOB_TASK_SHA256,
        JOB_TASK_SHA384,
        JOB_TASK_SHA512,
        JOB_TASK_MD5,
        JOB_TASK_XCBC,
        JOB_TASK_NULL_HASH,

        JOB_TASK_NUMOF,
};

__win_aligned(32)
struct JOB_AES_HMAC {
        const void *aes_enc_key_expanded;
        const void *aes_dec_key_expanded;

        UINT64 aes_key_len_in_bytes; /* Only 16, 24, and  32 byte (128, 192 and 256-bit) keys supported at this time. */
        const void *src; /* Input. May be cipher text or plaintext. In-place ciphering allowed. */
        void *dst; /*Output. May be cipher text or plaintext. In-place ciphering allowed, i.e. dst = src. */
        UINT64 cipher_start_src_offset_in_bytes;
        UINT64 msg_len_to_cipher_in_bytes; /* Max len = 65472 bytes. (IPSec case, the maximum cipher
                                            * length would be 65535 - 20 (outer IP header) - 24 (ESP
                                            * header + IV) - 12 (ICV length we agreed to support)) */
        UINT64 hash_start_src_offset_in_bytes;
        UINT64 msg_len_to_hash_in_bytes; /* Max len = 65496 bytes. (Max cipher len + 24 bytes ESP header) */
        const void *iv; /* AES IV. */
        UINT64 iv_len_in_bytes; /* AES IV Len in bytes. */
        void *auth_tag_output; /* HMAC Tag output. This may point to a location in the src buffer (for in place)*/
        UINT64 auth_tag_output_len_in_bytes; /* HMAC Tag output length in bytes. (May be a truncated value)*/

        /* Start algorithm-specific fields */
        union {
                struct _HMAC_specific_fields{
                        const void *_hashed_auth_key_xor_ipad; /* Hashed result of HMAC key xor'd with ipad (0x36). */
                        const void *_hashed_auth_key_xor_opad; /* Hashed result of HMAC key xor'd with opad (0x5c). */
                } HMAC;
                struct _AES_XCBC_specific_fields{
                        const void *_k1_expanded;   /* 16-byte aligned pointer. */
                        const void *_k2;            /* 16-byte aligned pointer. */
                        const void *_k3;            /* 16-byte aligned pointer. */
                } XCBC;
        } u;

        JOB_STS status;
        JOB_CIPHER_MODE cipher_mode; // CBC or CNTR
        JOB_CIPHER_DIRECTION cipher_direction; // Encrypt/decrypt
        JOB_HASH_ALG hash_alg; // SHA-1 or others...
        JOB_CHAIN_ORDER chain_order; // unused
        int current_stage;              /* New job scheduler: current stage (1 or 0) */

        void *user_data;
        void *user_data2;

        /*
         * extended by New job scheduler
         */
        const void *aad;                /* AAD for GCM */
        UINT64 aad_len_in_bytes;        /* AAD length in bytes */

        /* private use (not access) */
        enum JOB_TASK stage_task[2];    /* task */
        UINT8 decode_tag[32];		/* verifying used */
        void *encode_tag_p;             /* decoded TAG */
        unsigned enable_tag_cmp :1;     /* compaire TAG */
        unsigned enable_esn :1;         /* enable ESN */
        UINT32 esn_high;                /* IPsec v3 ESN (big endia) */

        DECLARE_ALIGNED(struct gcm_context_data gcm_context, 16);  /* for oneshot GCM */
        DECLARE_ALIGNED(UINT128 ext_data[2], 16);/* CTR block and AAD used */
} __linux_aligned(32);

typedef struct JOB_AES_HMAC JOB_AES_HMAC;

#define hashed_auth_key_xor_ipad u.HMAC._hashed_auth_key_xor_ipad
#define hashed_auth_key_xor_opad u.HMAC._hashed_auth_key_xor_opad
#define _k1_expanded             u.XCBC._k1_expanded
#define _k2                      u.XCBC._k2
#define _k3                      u.XCBC._k3

#endif /* !_JOB_AES_HMAC_H_ */
