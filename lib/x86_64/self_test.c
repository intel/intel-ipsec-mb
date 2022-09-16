/*******************************************************************************
  Copyright (c) 2022, Intel Corporation

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


#include <string.h>
#include <stdint.h>

#include "intel-ipsec-mb.h"
#include "arch_x86_64.h"

static int process_job(IMB_MGR *p_mgr)
{
        IMB_JOB *job = IMB_SUBMIT_JOB(p_mgr);

        if (!job) {
                const int err = imb_get_errno(p_mgr);

                /* check for error */
                if (err != 0)
                        return 0;

                /* flush to get the job processed */
                job = IMB_FLUSH_JOB(p_mgr);
                
                /* if flush returns nothing then it's an error */
                if (!job)
                        return 0;
        }

        /* if returned job is not complete then it's an error */
        if (job->status != IMB_STATUS_COMPLETED)
                return 0;

        return 1;
}

/*
 * =============================================================================
 * CIPHER SELF-TEST
 * =============================================================================
 */

struct self_test_cipher_vector {
        IMB_CIPHER_MODE cipher_mode;
	const uint8_t *cipher_key;
        size_t cipher_key_size;    /* key size in bytes */
	const uint8_t *cipher_iv;  /* initialization vector */
        size_t cipher_iv_size;
	const uint8_t *plain_text;
        size_t plain_text_size;
	const uint8_t *cipher_text;
};

/*
 *  AES-CBC Test vectors from
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

static const uint8_t aes_cbc_128_key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const uint8_t aes_cbc_128_iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t aes_cbc_128_plain_text[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const uint8_t aes_cbc_128_cipher_text[] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
        0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
        0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
        0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};

static const uint8_t aes_cbc_192_key[] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
};
static const uint8_t aes_cbc_192_iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t aes_cbc_192_plain_text[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
static const uint8_t aes_cbc_192_cipher_text[] = {
        0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
        0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
        0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
        0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
        0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0,
        0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
        0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81,
        0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd
};

static const uint8_t aes_cbc_256_key[] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
static const uint8_t aes_cbc_256_iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t aes_cbc_256_plain_text[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
static const uint8_t aes_cbc_256_cipher_text[] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
        0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
        0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
        0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
        0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
        0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
        0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
        0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
};

/*
 * Test Vector from
 * https://tools.ietf.org/html/rfc3686
 */

static const uint8_t aes_ctr_128_key[] = {
        0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC,
        0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E,
};
static const uint8_t aes_ctr_128_iv[] = {
        0x00, 0x00, 0x00, 0x30,	/* nonce */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t aes_ctr_128_plain_text[] = {
        0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
        0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67,
};
static const uint8_t aes_ctr_128_cipher_text[] = {
        0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79,
        0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8,
};

static const uint8_t aes_ctr_192_key[] = {
        0x16, 0xAF, 0x5B, 0x14, 0x5F, 0xC9, 0xF5, 0x79,
        0xC1, 0x75, 0xF9, 0x3E, 0x3B, 0xFB, 0x0E, 0xED,
        0x86, 0x3D, 0x06, 0xCC, 0xFD, 0xB7, 0x85, 0x15,
};
static const uint8_t aes_ctr_192_iv[] = {
        0x00, 0x00, 0x00, 0x48,	/* nonce */
        0x36, 0x73, 0x3C, 0x14, 0x7D, 0x6D, 0x93, 0xCB,
};
static const uint8_t aes_ctr_192_plain_text[] = {
        0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
        0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67,
};
static const uint8_t aes_ctr_192_cipher_text[] = {
        0x4B, 0x55, 0x38, 0x4F, 0xE2, 0x59, 0xC9, 0xC8,
        0x4E, 0x79, 0x35, 0xA0, 0x03, 0xCB, 0xE9, 0x28,
};

static const uint8_t aes_ctr_256_key[] = {
        0x77, 0x6B, 0xEF, 0xF2, 0x85, 0x1D, 0xB0, 0x6F,
        0x4C, 0x8A, 0x05, 0x42, 0xC8, 0x69, 0x6F, 0x6C,
        0x6A, 0x81, 0xAF, 0x1E, 0xEC, 0x96, 0xB4, 0xD3,
        0x7F, 0xC1, 0xD6, 0x89, 0xE6, 0xC1, 0xC1, 0x04,
};
static const uint8_t aes_ctr_256_iv[] = {
        0x00, 0x00, 0x00, 0x60,	/* nonce */
        0xDB, 0x56, 0x72, 0xC9, 0x7A, 0xA8, 0xF0, 0xB2,
};
static const uint8_t aes_ctr_256_plain_text[] = {
        0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
        0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67,
};
static const uint8_t aes_ctr_256_cipher_text[] = {
        0x14, 0x5A, 0xD0, 0x1D, 0xBF, 0x82, 0x4E, 0xC7,
        0x56, 0x08, 0x63, 0xDC, 0x71, 0xE3, 0xE0, 0xC0,
};


#define ADD_CIPHER_VECTOR(_cmode,_key,_iv,_plain,_cipher) \
        {_cmode, _key, sizeof(_key), _iv, sizeof(_iv), \
                        _plain, sizeof(_plain), _cipher}

struct self_test_cipher_vector cipher_vectors[] = {
        ADD_CIPHER_VECTOR(IMB_CIPHER_CBC, aes_cbc_128_key, aes_cbc_128_iv,
                          aes_cbc_128_plain_text, aes_cbc_128_cipher_text),
        ADD_CIPHER_VECTOR(IMB_CIPHER_CBC, aes_cbc_192_key, aes_cbc_192_iv,
                          aes_cbc_192_plain_text, aes_cbc_192_cipher_text),
        ADD_CIPHER_VECTOR(IMB_CIPHER_CBC, aes_cbc_256_key, aes_cbc_256_iv,
                          aes_cbc_256_plain_text, aes_cbc_256_cipher_text),
        ADD_CIPHER_VECTOR(IMB_CIPHER_CNTR, aes_ctr_128_key, aes_ctr_128_iv,
                          aes_ctr_128_plain_text, aes_ctr_128_cipher_text),
        ADD_CIPHER_VECTOR(IMB_CIPHER_CNTR, aes_ctr_192_key, aes_ctr_192_iv,
                          aes_ctr_192_plain_text, aes_ctr_192_cipher_text),
        ADD_CIPHER_VECTOR(IMB_CIPHER_CNTR, aes_ctr_256_key, aes_ctr_256_iv,
                          aes_ctr_256_plain_text, aes_ctr_256_cipher_text),
};

static int self_test_ciphers(IMB_MGR *p_mgr)
{
        uint8_t scratch[256];
        DECLARE_ALIGNED(uint32_t expkey_enc[4*15], 16);
        DECLARE_ALIGNED(uint32_t expkey_dec[4*15], 16);
        unsigned i;

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (i = 0; i < IMB_DIM(cipher_vectors); i++) {
                struct self_test_cipher_vector *v = &cipher_vectors[i];

                IMB_ASSERT(v->plain_text_size <= sizeof(scratch));

                /* message too long */
                if (v->plain_text_size > sizeof(scratch))
                        return 0;

                switch (v->cipher_key_size) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(p_mgr, v->cipher_key,
                                           expkey_enc, expkey_dec);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES_KEYEXP_192(p_mgr, v->cipher_key,
                                           expkey_enc, expkey_dec);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(p_mgr, v->cipher_key,
                                           expkey_enc, expkey_dec);
                        break;
                default:
                        /* invalid key size */
                        return 0;
                }

                /* test encrypt direction */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                job->hash_alg = IMB_AUTH_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->src = v->plain_text;
                job->dst = scratch;
                job->cipher_mode = v->cipher_mode;
                job->enc_keys = expkey_enc;
                if (v->cipher_mode != IMB_CIPHER_CNTR)
                        job->dec_keys = expkey_dec;
                job->key_len_in_bytes = v->cipher_key_size;
                job->iv = v->cipher_iv;
                job->iv_len_in_bytes = v->cipher_iv_size;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = v->plain_text_size;

                memset(scratch, 0, sizeof(scratch));

                /* submit job and get it processed */
                if (!process_job(p_mgr))
                        return 0;

                /* check for cipher text mismatch */
                if (memcmp(scratch, v->cipher_text, v->plain_text_size))
                        return 0;

                /* test decrypt direction */
                job = IMB_GET_NEXT_JOB(p_mgr);

                job->hash_alg = IMB_AUTH_NULL;
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = v->cipher_text;
                job->dst = scratch;
                job->cipher_mode = v->cipher_mode;
                job->dec_keys = expkey_dec;
                if (v->cipher_mode == IMB_CIPHER_CNTR)
                        job->enc_keys = expkey_enc;
                job->key_len_in_bytes = v->cipher_key_size;
                job->iv = v->cipher_iv;
                job->iv_len_in_bytes = v->cipher_iv_size;
                job->cipher_start_src_offset_in_bytes = 0;
                job->msg_len_to_cipher_in_bytes = v->plain_text_size;

                memset(scratch, 0, sizeof(scratch));

                /* submit job and get it processed */
                if (!process_job(p_mgr))
                        return 0;

                /* check for plain text mismatch */
                if (memcmp(scratch, v->plain_text, v->plain_text_size))
                        return 0;
                
        } /* for(cipher_vectors) */

        return 1;
}

/*
 * =============================================================================
 * HASH SELF-TEST
 * =============================================================================
 */

struct self_test_hash_vector {
        IMB_HASH_ALG hash_mode;
	const uint8_t *hash_key; /* cmac, hmac, gmac */
        size_t hash_key_size;    /* key size in bytes */
	const uint8_t *message;
        size_t message_size;
	const uint8_t *tag;
        size_t tag_size;
	const uint8_t *hash_iv; /* gmac */
        size_t hash_iv_size;
};

/*
 * Test vectors come from this NIST document:
 *
 * https://csrc.nist.gov/csrc/media/projects/
 *     cryptographic-standards-and-guidelines/documents/examples/sha_all.pdf
 */

const uint8_t sha_message[] = {
        0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65,
        0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67,
        0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
        0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b,
        0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d,
        0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f,
        0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71
};

const uint8_t sha1_digest[] = {
        0x84, 0x98, 0x3e, 0x44,
        0x1c, 0x3b, 0xd2, 0x6e,
        0xba, 0xae, 0x4a, 0xa1,
        0xf9, 0x51, 0x29, 0xe5,
        0xe5, 0x46, 0x70, 0xf1
};

const uint8_t sha224_digest[] = {
        0x75, 0x38, 0x8b, 0x16,
        0x51, 0x27, 0x76, 0xcc,
        0x5d, 0xba, 0x5d, 0xa1,
        0xfd, 0x89, 0x01, 0x50,
        0xb0, 0xc6, 0x45, 0x5c,
        0xb4, 0xf5, 0x8b, 0x19,
        0x52, 0x52, 0x25, 0x25
};

const uint8_t sha256_digest[] = {
        0x24, 0x8d, 0x6a, 0x61,
        0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93,
        0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59,
        0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4,
        0x19, 0xdb, 0x06, 0xc1
};

const uint8_t sha384_digest[] = {
        0x33, 0x91, 0xfd, 0xdd, 0xfc, 0x8d, 0xc7, 0x39,
        0x37, 0x07, 0xa6, 0x5b, 0x1b, 0x47, 0x09, 0x39,
        0x7c, 0xf8, 0xb1, 0xd1, 0x62, 0xaf, 0x05, 0xab,
        0xfe, 0x8f, 0x45, 0x0d, 0xe5, 0xf3, 0x6b, 0xc6,
        0xb0, 0x45, 0x5a, 0x85, 0x20, 0xbc, 0x4e, 0x6f,
        0x5f, 0xe9, 0x5b, 0x1f, 0xe3, 0xc8, 0x45, 0x2b
};

const uint8_t sha512_digest[] = {
        0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a,
        0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
        0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8,
        0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
        0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9,
        0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
        0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03,
        0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45
};

#define ADD_SHA_VECTOR(_hmode,_msg,_digest)     \
        {_hmode, NULL, 0, _msg, sizeof(_msg),                   \
                        _digest, sizeof(_digest), NULL, 0}

/*
 * Test vector from https://csrc.nist.gov/csrc/media/publications/fips/198/
 * archive/2002-03-06/documents/fips-198a.pdf
 */

static const uint8_t hmac_sha1_key[] = {
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        0xa0
};

static const uint8_t hmac_sha1_message[] = {
        0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x23,
        0x34
};

static const uint8_t hmac_sha1_digest[] = {
        0x9e, 0xa8, 0x86, 0xef, 0xe2, 0x68, 0xdb, 0xec,
        0xce, 0x42, 0x0c, 0x75
};

/*
 * Test vector from https://csrc.nist.gov/csrc/media/projects/
 * cryptographic-standards-and-guidelines/documents/examples/hmac_sha224.pdf
 */
static const uint8_t hmac_sha224_key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};
static const uint8_t hmac_sha224_message[] = {
        0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d,
        0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66,
        0x6f, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x6c, 0x65,
        0x6e, 0x3d, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x6c,
        0x65, 0x6e
};
static const uint8_t hmac_sha224_digest[] = {
        0xc7, 0x40, 0x5e, 0x3a, 0xe0, 0x58, 0xe8, 0xcd,
        0x30, 0xb0, 0x8b, 0x41, 0x40, 0x24, 0x85, 0x81,
        0xed, 0x17, 0x4c, 0xb3, 0x4e, 0x12, 0x24, 0xbc,
        0xc1, 0xef, 0xc8, 0x1b
};

/*
 * Test vector from https://csrc.nist.gov/csrc/media/projects/
 * cryptographic-standards-and-guidelines/documents/examples/hmac_sha256.pdf
 */
static const uint8_t hmac_sha256_key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};
static const uint8_t hmac_sha256_message[] = {
        0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d,
        0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66,
        0x6f, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x6c, 0x65,
        0x6e, 0x3d, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x6c,
        0x65, 0x6e
};
static const uint8_t hmac_sha256_digest[] = {
        0x8b, 0xb9, 0xa1, 0xdb, 0x98, 0x06, 0xf2, 0x0d,
        0xf7, 0xf7, 0x7b, 0x82, 0x13, 0x8c, 0x79, 0x14,
        0xd1, 0x74, 0xd5, 0x9e, 0x13, 0xdc, 0x4d, 0x01,
        0x69, 0xc9, 0x05, 0x7b, 0x13, 0x3e, 0x1d, 0x62,
};

/*
 * Test vector from https://csrc.nist.gov/csrc/media/projects/
 * cryptographic-standards-and-guidelines/documents/examples/hmac_sha384.pdf
 */
static const uint8_t hmac_sha384_key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
};
static const uint8_t hmac_sha384_message[] = {
        0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d,
        0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66,
        0x6f, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x6c, 0x65,
        0x6e, 0x3d, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x6c,
        0x65, 0x6e
};
static const uint8_t hmac_sha384_digest[] = {
        0x63, 0xc5, 0xda, 0xa5, 0xe6, 0x51, 0x84, 0x7c,
        0xa8, 0x97, 0xc9, 0x58, 0x14, 0xab, 0x83, 0x0b,
        0xed, 0xed, 0xc7, 0xd2, 0x5e, 0x83, 0xee, 0xf9
};

/*
 * Test vector from https://csrc.nist.gov/csrc/media/projects/
 * cryptographic-standards-and-guidelines/documents/examples/hmac_sha512.pdf
 */
static const uint8_t hmac_sha512_key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
};
static const uint8_t hmac_sha512_message[] = {
        0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d,
        0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66,
        0x6f, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x6c, 0x65,
        0x6e, 0x3d, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x6c,
        0x65, 0x6e
};
static const uint8_t hmac_sha512_digest[] = {
        0xfc, 0x25, 0xe2, 0x40, 0x65, 0x8c, 0xa7, 0x85,
        0xb7, 0xa8, 0x11, 0xa8, 0xd3, 0xf7, 0xb4, 0xca,
        0x48, 0xcf, 0xa2, 0x6a, 0x8a, 0x36, 0x6b, 0xf2,
        0xcd, 0x1f, 0x83, 0x6b, 0x05, 0xfc, 0xb0, 0x24
};

#define ADD_HMAC_SHA_VECTOR(_hmode,_key,_msg,_digest)  \
        {_hmode, _key, sizeof(_key), _msg, sizeof(_msg),        \
                        _digest, sizeof(_digest), NULL, 0}

/*
 * 3GPP 33.401 C.2.1 Test Case 2
 */
static const uint8_t aes_cmac_128_key[] = {
        0xd3, 0xc5, 0xd5, 0x92, 0x32, 0x7f, 0xb1, 0x1c,
        0x40, 0x35, 0xc6, 0x68, 0x0a, 0xf8, 0xc6, 0xd1
};

static const uint8_t aes_cmac_128_tag[] = {
        0xb9, 0x37, 0x87, 0xe6
};

static const uint8_t aes_cmac_128_message[] = {
        0x39, 0x8a, 0x59, 0xb4, 0xd4, 0x00, 0x00, 0x00,
        0x48, 0x45, 0x83, 0xd5, 0xaf, 0xe0, 0x82, 0xae
};

static const uint8_t aes_cmac_256_key[] = {
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
        0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
        0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
};
static const uint8_t aes_cmac_256_message[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57
};
static const uint8_t aes_cmac_256_tag[] = {
        0x15, 0x67, 0x27, 0xDC, 0x08, 0x78, 0x94, 0x4A,
        0x02, 0x3C, 0x1F, 0xE0, 0x3B, 0xAD, 0x6D, 0x93
};

#define ADD_CMAC_VECTOR(_hmode,_key,_msg,_digest)               \
        {_hmode, _key, sizeof(_key), _msg, sizeof(_msg),        \
                        _digest, sizeof(_digest), NULL, 0}

/*
 * GMAC vectors
 */
static const uint8_t aes_gmac_128_key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static const uint8_t aes_gmac_128_iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
};
static const uint8_t aes_gmac_128_message[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};
static const uint8_t aes_gmac_128_tag[] =  {
        0xC5, 0x3A, 0xF9, 0xE8
};

static const uint8_t aes_gmac_192_key[] = {
        0xaa, 0x74, 0x0a, 0xbf, 0xad, 0xcd, 0xa7, 0x79,
        0x22, 0x0d, 0x3b, 0x40, 0x6c, 0x5d, 0x7e, 0xc0,
        0x9a, 0x77, 0xfe, 0x9d, 0x94, 0x10, 0x45, 0x39,
};
static const uint8_t aes_gmac_192_iv[] = {
        0xab, 0x22, 0x65, 0xb4, 0xc1, 0x68, 0x95, 0x55,
        0x61, 0xf0, 0x43, 0x15
};
static const uint8_t aes_gmac_192_message[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
};
static const uint8_t aes_gmac_192_tag[] =  {
        0xCF, 0x82, 0x80, 0x64, 0x02, 0x46, 0xF4, 0xFB,
        0x33, 0xAE, 0x1D, 0x90, 0xEA, 0x48, 0x83, 0xDB
};

static const uint8_t aes_gmac_256_key[] = {
        0xb5, 0x48, 0xe4, 0x93, 0x4f, 0x5c, 0x64, 0xd3,
        0xc0, 0xf0, 0xb7, 0x8f, 0x7b, 0x4d, 0x88, 0x24,
        0xaa, 0xc4, 0x6b, 0x3c, 0x8d, 0x2c, 0xc3, 0x5e,
        0xe4, 0xbf, 0xb2, 0x54, 0xe4, 0xfc, 0xba, 0xf7,
};
static const uint8_t aes_gmac_256_iv[] = {
        0x2e, 0xed, 0xe1, 0xdc, 0x64, 0x47, 0xc7, 0xaf,
        0xc4, 0x41, 0x53, 0x58,
};
static const uint8_t aes_gmac_256_message[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x01
};
static const uint8_t aes_gmac_256_tag[] =  {
        0x77, 0x46, 0x0D, 0x6F, 0xB1, 0x87, 0xDB, 0xA9,
        0x46, 0xAD, 0xCD, 0xFB, 0xB7, 0xF9, 0x13, 0xA1
};

#define ADD_GMAC_VECTOR(_hmode,_key,_iv,_msg,_tag)              \
        {_hmode, _key, sizeof(_key), _msg, sizeof(_msg),        \
                        _tag, sizeof(_tag), \
                        _iv, sizeof(_iv)}

struct self_test_hash_vector hash_vectors[] = {
        ADD_SHA_VECTOR(IMB_AUTH_SHA_1, sha_message, sha1_digest),
        ADD_SHA_VECTOR(IMB_AUTH_SHA_224, sha_message, sha224_digest),
        ADD_SHA_VECTOR(IMB_AUTH_SHA_256, sha_message, sha256_digest),
        ADD_SHA_VECTOR(IMB_AUTH_SHA_384, sha_message, sha384_digest),
        ADD_SHA_VECTOR(IMB_AUTH_SHA_512, sha_message, sha512_digest),
        ADD_HMAC_SHA_VECTOR(IMB_AUTH_HMAC_SHA_1, hmac_sha1_key,
                            hmac_sha1_message, hmac_sha1_digest),
        ADD_HMAC_SHA_VECTOR(IMB_AUTH_HMAC_SHA_224, hmac_sha224_key,
                            hmac_sha224_message, hmac_sha224_digest),
        ADD_HMAC_SHA_VECTOR(IMB_AUTH_HMAC_SHA_256, hmac_sha256_key,
                            hmac_sha256_message, hmac_sha256_digest),
        ADD_HMAC_SHA_VECTOR(IMB_AUTH_HMAC_SHA_384, hmac_sha384_key,
                            hmac_sha384_message, hmac_sha384_digest),
        ADD_HMAC_SHA_VECTOR(IMB_AUTH_HMAC_SHA_512, hmac_sha512_key,
                            hmac_sha512_message, hmac_sha512_digest),
        ADD_CMAC_VECTOR(IMB_AUTH_AES_CMAC, aes_cmac_128_key,
                        aes_cmac_128_message, aes_cmac_128_tag),
        ADD_CMAC_VECTOR(IMB_AUTH_AES_CMAC_256, aes_cmac_256_key,
                        aes_cmac_256_message, aes_cmac_256_tag),
        ADD_GMAC_VECTOR(IMB_AUTH_AES_GMAC_128, aes_gmac_128_key,
                        aes_gmac_128_iv, aes_gmac_128_message,
                        aes_gmac_128_tag),
        ADD_GMAC_VECTOR(IMB_AUTH_AES_GMAC_192, aes_gmac_192_key,
                        aes_gmac_192_iv, aes_gmac_192_message,
                        aes_gmac_192_tag),
        ADD_GMAC_VECTOR(IMB_AUTH_AES_GMAC_256, aes_gmac_256_key,
                        aes_gmac_256_iv, aes_gmac_256_message,
                        aes_gmac_256_tag),
};

static int self_test_hash(IMB_MGR *p_mgr)
{
        /* hmac */
        DECLARE_ALIGNED(uint8_t hmac_ipad[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t hmac_opad[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        /* cmac */
        DECLARE_ALIGNED(uint32_t expkey[4*15], 16);
        DECLARE_ALIGNED(uint32_t dust[4*15], 16);
        uint32_t skey1[4], skey2[4];
        /* gmac */
        struct gcm_key_data gmac_key;
        /* all */
        uint8_t scratch[IMB_SHA_512_BLOCK_SIZE];
        unsigned i;

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (i = 0; i < IMB_DIM(hash_vectors); i++) {
                struct self_test_hash_vector *v = &hash_vectors[i];

                IMB_ASSERT(v->tag_size <= sizeof(scratch));

                /* tag too long */
                if (v->tag_size > sizeof(scratch))
                        return 0;

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                job->hash_alg = v->hash_mode;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = v->message;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = v->message_size;
                job->auth_tag_output = scratch;
                job->auth_tag_output_len_in_bytes = v->tag_size;

                if (v->hash_mode == IMB_AUTH_HMAC_SHA_1) {
                        /* compute IPAD and OPAD */
                        unsigned j;

                        IMB_ASSERT(sizeof(scratch) >= IMB_SHA1_BLOCK_SIZE);

                        memset(scratch, 0x36, IMB_SHA1_BLOCK_SIZE);
                        for (j = 0; j < v->hash_key_size; j++)
                                scratch[j] ^= v->hash_key[j];
                        IMB_SHA1_ONE_BLOCK(p_mgr, scratch, hmac_ipad);

                        memset(scratch, 0x5c, IMB_SHA1_BLOCK_SIZE);
                        for (j = 0; j < v->hash_key_size; j++)
                                scratch[j] ^= v->hash_key[j];
                        IMB_SHA1_ONE_BLOCK(p_mgr, scratch, hmac_opad);

                        job->u.HMAC._hashed_auth_key_xor_ipad = hmac_ipad;
                        job->u.HMAC._hashed_auth_key_xor_opad = hmac_opad;
                }

                if (v->hash_mode == IMB_AUTH_HMAC_SHA_224 ||
                    v->hash_mode == IMB_AUTH_HMAC_SHA_256) {
                        /* compute IPAD and OPAD */
                        unsigned j;

                        IMB_ASSERT(sizeof(scratch) >= IMB_SHA_256_BLOCK_SIZE);

                        memset(scratch, 0x36, IMB_SHA_256_BLOCK_SIZE);
                        for (j = 0; j < v->hash_key_size; j++)
                                scratch[j] ^= v->hash_key[j];
                        if (v->hash_mode == IMB_AUTH_HMAC_SHA_224)
                                IMB_SHA224_ONE_BLOCK(p_mgr, scratch, hmac_ipad);
                        else
                                IMB_SHA256_ONE_BLOCK(p_mgr, scratch, hmac_ipad);

                        memset(scratch, 0x5c, IMB_SHA_256_BLOCK_SIZE);
                        for (j = 0; j < v->hash_key_size; j++)
                                scratch[j] ^= v->hash_key[j];
                        if (v->hash_mode == IMB_AUTH_HMAC_SHA_224)
                                IMB_SHA224_ONE_BLOCK(p_mgr, scratch, hmac_opad);
                        else
                                IMB_SHA256_ONE_BLOCK(p_mgr, scratch, hmac_opad);

                        job->u.HMAC._hashed_auth_key_xor_ipad = hmac_ipad;
                        job->u.HMAC._hashed_auth_key_xor_opad = hmac_opad;
                }

                if (v->hash_mode == IMB_AUTH_HMAC_SHA_384 ||
                    v->hash_mode == IMB_AUTH_HMAC_SHA_512) {
                        /* compute IPAD and OPAD */
                        unsigned j;

                        IMB_ASSERT(sizeof(scratch) >= IMB_SHA_512_BLOCK_SIZE);

                        memset(scratch, 0x36, IMB_SHA_512_BLOCK_SIZE);
                        for (j = 0; j < v->hash_key_size; j++)
                                scratch[j] ^= v->hash_key[j];
                        if (v->hash_mode == IMB_AUTH_HMAC_SHA_384)
                                IMB_SHA384_ONE_BLOCK(p_mgr, scratch, hmac_ipad);
                        else
                                IMB_SHA512_ONE_BLOCK(p_mgr, scratch, hmac_ipad);

                        memset(scratch, 0x5c, IMB_SHA_512_BLOCK_SIZE);
                        for (j = 0; j < v->hash_key_size; j++)
                                scratch[j] ^= v->hash_key[j];
                        if (v->hash_mode == IMB_AUTH_HMAC_SHA_384)
                                IMB_SHA384_ONE_BLOCK(p_mgr, scratch, hmac_opad);
                        else
                                IMB_SHA512_ONE_BLOCK(p_mgr, scratch, hmac_opad);

                        job->u.HMAC._hashed_auth_key_xor_ipad = hmac_ipad;
                        job->u.HMAC._hashed_auth_key_xor_opad = hmac_opad;
                }

                if (v->hash_mode == IMB_AUTH_AES_CMAC) {
                        IMB_AES_KEYEXP_128(p_mgr, v->hash_key, expkey, dust);
                        IMB_AES_CMAC_SUBKEY_GEN_128(p_mgr, expkey, skey1, skey2);
                        job->u.CMAC._key_expanded = expkey;
                        job->u.CMAC._skey1 = skey1;
                        job->u.CMAC._skey2 = skey2;
                }

                if (v->hash_mode == IMB_AUTH_AES_CMAC_256) {
                        IMB_AES_KEYEXP_256(p_mgr, v->hash_key, expkey, dust);
                        IMB_AES_CMAC_SUBKEY_GEN_256(p_mgr, expkey, skey1, skey2);
                        job->u.CMAC._key_expanded = expkey;
                        job->u.CMAC._skey1 = skey1;
                        job->u.CMAC._skey2 = skey2;
                }

                if (v->hash_mode == IMB_AUTH_AES_GMAC_128) {
                        IMB_AES128_GCM_PRE(p_mgr, v->hash_key, &gmac_key);
                        job->u.GMAC._key = &gmac_key;
                        job->u.GMAC._iv = v->hash_iv;
                        job->u.GMAC.iv_len_in_bytes = v->hash_iv_size;
                }
                
                if (v->hash_mode == IMB_AUTH_AES_GMAC_192) {
                        IMB_AES192_GCM_PRE(p_mgr, v->hash_key, &gmac_key);
                        job->u.GMAC._key = &gmac_key;
                        job->u.GMAC._iv = v->hash_iv;
                        job->u.GMAC.iv_len_in_bytes = v->hash_iv_size;
                }

                if (v->hash_mode == IMB_AUTH_AES_GMAC_256) {
                        IMB_AES256_GCM_PRE(p_mgr, v->hash_key, &gmac_key);
                        job->u.GMAC._key = &gmac_key;
                        job->u.GMAC._iv = v->hash_iv;
                        job->u.GMAC.iv_len_in_bytes = v->hash_iv_size;
                }

                /* clear space where computed TAG is put into */
                memset(scratch, 0, sizeof(scratch));

                /* submit job and get it processed */
                if (!process_job(p_mgr))
                        return 0;

                /* check for TAG mismatch */
                if (memcmp(scratch, v->tag, v->tag_size))
                        return 0;

                /* exercise direct API test if available */
                memset(scratch, 0, sizeof(scratch));

                if (v->hash_mode == IMB_AUTH_SHA_1) {
                        memset(scratch, 0, sizeof(scratch));
                        IMB_SHA1(p_mgr, v->message, v->message_size, scratch);
                        if (memcmp(scratch, v->tag, v->tag_size))
                                return 0;
                }
                if (v->hash_mode == IMB_AUTH_SHA_224) {
                        memset(scratch, 0, sizeof(scratch));
                        IMB_SHA224(p_mgr, v->message, v->message_size, scratch);
                        if (memcmp(scratch, v->tag, v->tag_size))
                                return 0;
                }
                if (v->hash_mode == IMB_AUTH_SHA_256) {
                        memset(scratch, 0, sizeof(scratch));
                        IMB_SHA256(p_mgr, v->message, v->message_size, scratch);
                        if (memcmp(scratch, v->tag, v->tag_size))
                                return 0;
                }
                if (v->hash_mode == IMB_AUTH_SHA_384) {
                        memset(scratch, 0, sizeof(scratch));
                        IMB_SHA384(p_mgr, v->message, v->message_size, scratch);
                        if (memcmp(scratch, v->tag, v->tag_size))
                                return 0;
                }
                if (v->hash_mode == IMB_AUTH_SHA_512) {
                        memset(scratch, 0, sizeof(scratch));
                        IMB_SHA512(p_mgr, v->message, v->message_size, scratch);
                        if (memcmp(scratch, v->tag, v->tag_size))
                                return 0;
                }
                if (v->hash_mode == IMB_AUTH_AES_GMAC_128) {
                        struct gcm_context_data ctx;

                        memset(scratch, 0, sizeof(scratch));
                        IMB_AES128_GCM_PRE(p_mgr, v->hash_key, &gmac_key);
                        IMB_AES128_GMAC_INIT(p_mgr, &gmac_key, &ctx, v->hash_iv,
                                             v->hash_iv_size);
                        IMB_AES128_GMAC_UPDATE(p_mgr, &gmac_key, &ctx,
                                               v->message, v->message_size);
                        IMB_AES128_GMAC_FINALIZE(p_mgr, &gmac_key, &ctx,
                                                 scratch, v->tag_size);
                        if (memcmp(scratch, v->tag, v->tag_size))
                                return 0;
                }
                if (v->hash_mode == IMB_AUTH_AES_GMAC_192) {
                        struct gcm_context_data ctx;

                        memset(scratch, 0, sizeof(scratch));
                        IMB_AES192_GCM_PRE(p_mgr, v->hash_key, &gmac_key);
                        IMB_AES192_GMAC_INIT(p_mgr, &gmac_key, &ctx, v->hash_iv,
                                             v->hash_iv_size);
                        IMB_AES192_GMAC_UPDATE(p_mgr, &gmac_key, &ctx,
                                               v->message, v->message_size);
                        IMB_AES192_GMAC_FINALIZE(p_mgr, &gmac_key, &ctx,
                                                 scratch, v->tag_size);
                        if (memcmp(scratch, v->tag, v->tag_size))
                                return 0;
                }
                if (v->hash_mode == IMB_AUTH_AES_GMAC_256) {
                        struct gcm_context_data ctx;

                        memset(scratch, 0, sizeof(scratch));
                        IMB_AES256_GCM_PRE(p_mgr, v->hash_key, &gmac_key);
                        IMB_AES256_GMAC_INIT(p_mgr, &gmac_key, &ctx, v->hash_iv,
                                             v->hash_iv_size);
                        IMB_AES256_GMAC_UPDATE(p_mgr, &gmac_key, &ctx,
                                               v->message, v->message_size);
                        IMB_AES256_GMAC_FINALIZE(p_mgr, &gmac_key, &ctx,
                                                 scratch, v->tag_size);
                        if (memcmp(scratch, v->tag, v->tag_size))
                                return 0;
                }

        } /* for(hash_vectors) */

        return 1;
}

/*
 * =============================================================================
 * AEAD SELF-TEST
 * =============================================================================
 */

struct self_test_gcm_vector {
        IMB_HASH_ALG hash_mode;
        IMB_CIPHER_MODE cipher_mode;
	const uint8_t *cipher_key;
        size_t cipher_key_size;
	const uint8_t *cipher_iv;
        size_t cipher_iv_size;
	const uint8_t *aad;
        size_t aad_size;
	const uint8_t *plain_text;
        size_t plain_text_size;
	const uint8_t *cipher_text;
	const uint8_t *tag;
        size_t tag_size;
};

/*
 * http://csrc.nist.gov/groups/STM/cavp/gcmtestvectors.zip
 *    gcmEncryptExtIV128.rsp
 */
static const uint8_t aes_gcm_128_key[] = {
        0xc9, 0x39, 0xcc, 0x13, 0x39, 0x7c, 0x1d, 0x37,
        0xde, 0x6a, 0xe0, 0xe1, 0xcb, 0x7c, 0x42, 0x3c
};
static const uint8_t aes_gcm_128_iv[] = {
        0xb3, 0xd8, 0xcc, 0x01, 0x7c, 0xbb, 0x89, 0xb3,
        0x9e, 0x0f, 0x67, 0xe2
};
static const uint8_t aes_gcm_128_plain_text[] = {
        0xc3, 0xb3, 0xc4, 0x1f, 0x11, 0x3a, 0x31, 0xb7,
        0x3d, 0x9a, 0x5c, 0xd4, 0x32, 0x10, 0x30, 0x69
};
static const uint8_t aes_gcm_128_aad[] = {
        0x24, 0x82, 0x56, 0x02, 0xbd, 0x12, 0xa9, 0x84,
        0xe0, 0x09, 0x2d, 0x3e, 0x44, 0x8e, 0xda, 0x5f
};
static const uint8_t aes_gcm_128_cipher_text[] = {
        0x93, 0xfe, 0x7d, 0x9e, 0x9b, 0xfd, 0x10, 0x34,
        0x8a, 0x56, 0x06, 0xe5, 0xca, 0xfa, 0x73, 0x54
};
static const uint8_t aes_gcm_128_tag[] = {
        0x00, 0x32, 0xa1, 0xdc, 0x85, 0xf1, 0xc9, 0x78,
        0x69, 0x25, 0xa2, 0xe7, 0x1d, 0x82, 0x72, 0xdd
};

/*
 * https://tools.ietf.org/html/draft-mcgrew-gcm-test-01 case #7
 */
static const uint8_t aes_gcm_192_key[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
};
static const uint8_t aes_gcm_192_plain_text[] =  {
        0x45, 0x00, 0x00, 0x28, 0xa4, 0xad, 0x40, 0x00,
        0x40, 0x06, 0x78, 0x80, 0x0a, 0x01, 0x03, 0x8f,
        0x0a, 0x01, 0x06, 0x12, 0x80, 0x23, 0x06, 0xb8,
        0xcb, 0x71, 0x26, 0x02, 0xdd, 0x6b, 0xb0, 0x3e,
        0x50, 0x10, 0x16, 0xd0, 0x75, 0x68, 0x00, 0x01,
};
static const uint8_t aes_gcm_192_aad[] = {
        0x00, 0x00, 0xa5, 0xf8, 0x00, 0x00, 0x00, 0x0a,
};
static const uint8_t aes_gcm_192_iv[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
};
static const uint8_t aes_gcm_192_cipher_text[] = {
        0xa5, 0xb1, 0xf8, 0x06, 0x60, 0x29, 0xae, 0xa4,
        0x0e, 0x59, 0x8b, 0x81, 0x22, 0xde, 0x02, 0x42,
        0x09, 0x38, 0xb3, 0xab, 0x33, 0xf8, 0x28, 0xe6,
        0x87, 0xb8, 0x85, 0x8b, 0x5b, 0xfb, 0xdb, 0xd0,
        0x31, 0x5b, 0x27, 0x45, 0x21, 0x44, 0xcc, 0x77,
};
static const uint8_t aes_gcm_192_tag[] = {
        0x95, 0x45, 0x7b, 0x96, 0x52, 0x03, 0x7f, 0x53,
        0x18, 0x02, 0x7b, 0x5b, 0x4c, 0xd7, 0xa6, 0x36,
};

/*
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/
 *    documents/proposedmodes/gcm/gcm-revised-spec.pdf
 */
static const uint8_t aes_gcm_256_key[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static const uint8_t aes_gcm_256_plain_text[] =  {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
};
static const uint8_t aes_gcm_256_aad[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
};
static const uint8_t aes_gcm_256_iv[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
};
static const uint8_t aes_gcm_256_cipher_text[] = {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62
};
static const uint8_t aes_gcm_256_tag[] = {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
};

#define ADD_GCM_VECTOR(_key,_iv,_aad,_plain,_cipher,_tag)       \
        {IMB_AUTH_AES_GMAC, IMB_CIPHER_GCM, _key, sizeof(_key), \
                        _iv, sizeof(_iv), _aad, sizeof(_aad),   \
                        _plain, sizeof(_plain), _cipher,        \
                        _tag, sizeof(_tag)}

struct self_test_gcm_vector aead_gcm_vectors[] = {
        ADD_GCM_VECTOR(aes_gcm_128_key, aes_gcm_128_iv, aes_gcm_128_aad,
                       aes_gcm_128_plain_text, aes_gcm_128_cipher_text,
                       aes_gcm_128_tag),
        ADD_GCM_VECTOR(aes_gcm_192_key, aes_gcm_192_iv, aes_gcm_192_aad,
                       aes_gcm_192_plain_text, aes_gcm_192_cipher_text,
                       aes_gcm_192_tag),
        ADD_GCM_VECTOR(aes_gcm_256_key, aes_gcm_256_iv, aes_gcm_256_aad,
                       aes_gcm_256_plain_text, aes_gcm_256_cipher_text,
                       aes_gcm_256_tag)
};


static int self_test_aead_gcm(IMB_MGR *p_mgr)
{
        struct gcm_key_data gcm_key;
        struct gcm_context_data ctx;
        uint8_t text[128], tag[16];
        unsigned i;

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (i = 0; i < IMB_DIM(aead_gcm_vectors); i++) {
                struct self_test_gcm_vector *v = &aead_gcm_vectors[i];

                IMB_ASSERT(v->tag_size <= sizeof(tag));
                IMB_ASSERT(v->plain_text_size <= sizeof(text));

                /* tag too long */
                if (v->tag_size > sizeof(tag))
                        return 0;

                /* message too long */
                if (v->plain_text_size > sizeof(text))
                        return 0;

                switch (v->cipher_key_size) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_PRE(p_mgr, v->cipher_key,
                                           &gcm_key);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_PRE(p_mgr, v->cipher_key,
                                           &gcm_key);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES256_GCM_PRE(p_mgr, v->cipher_key,
                                           &gcm_key);
                        break;
                default:
                        return 0;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                /* encrypt test */
                job->cipher_mode = v->cipher_mode;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->key_len_in_bytes = v->cipher_key_size;
                job->src = v->plain_text;
                job->dst = text;
                job->msg_len_to_cipher_in_bytes = v->plain_text_size;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = v->cipher_iv;
                job->iv_len_in_bytes = v->cipher_iv_size;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tag_size;
                job->hash_alg = v->hash_mode;
                job->enc_keys = &gcm_key;
                job->dec_keys = &gcm_key;
                job->u.GCM.aad = v->aad;
                job->u.GCM.aad_len_in_bytes = v->aad_size;

                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                /* submit job and get it processed */
                if (!process_job(p_mgr))
                        return 0;

                /* check for TAG mismatch */
                if (memcmp(tag, v->tag, v->tag_size))
                        return 0;

                /* check for text mismatch */
                if (memcmp(text, v->cipher_text, v->plain_text_size))
                        return 0;

                /* decrypt test */
                job = IMB_GET_NEXT_JOB(p_mgr);

                job->cipher_mode = v->cipher_mode;
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->key_len_in_bytes = v->cipher_key_size;
                job->src = v->cipher_text;
                job->dst = text;
                job->msg_len_to_cipher_in_bytes = v->plain_text_size;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = v->cipher_iv;
                job->iv_len_in_bytes = v->cipher_iv_size;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tag_size;
                job->hash_alg = v->hash_mode;
                job->enc_keys = &gcm_key;
                job->dec_keys = &gcm_key;
                job->u.GCM.aad = v->aad;
                job->u.GCM.aad_len_in_bytes = v->aad_size;

                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                /* submit job and get it processed */
                if (!process_job(p_mgr))
                        return 0;

                /* check for TAG mismatch */
                if (memcmp(tag, v->tag, v->tag_size))
                        return 0;

                /* check for text mismatch */
                if (memcmp(text, v->plain_text, v->plain_text_size))
                        return 0;

                /* test direct API */

                /* encrypt direction */
                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                switch (v->cipher_key_size) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   v->cipher_iv,
                                                   v->cipher_iv_size,
                                                   v->aad, v->aad_size);
                        IMB_AES128_GCM_ENC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  v->plain_text,
                                                  v->plain_text_size);
                        IMB_AES128_GCM_ENC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tag_size);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   v->cipher_iv,
                                                   v->cipher_iv_size,
                                                   v->aad, v->aad_size);
                        IMB_AES192_GCM_ENC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  v->plain_text,
                                                  v->plain_text_size);
                        IMB_AES192_GCM_ENC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tag_size);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES256_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   v->cipher_iv,
                                                   v->cipher_iv_size,
                                                   v->aad, v->aad_size);
                        IMB_AES256_GCM_ENC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  v->plain_text,
                                                  v->plain_text_size);
                        IMB_AES256_GCM_ENC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tag_size);
                        break;
                default:
                        return 0;
                }
                /* check for TAG mismatch */
                if (memcmp(tag, v->tag, v->tag_size))
                        return 0;

                /* check for text mismatch */
                if (memcmp(text, v->cipher_text, v->plain_text_size))
                        return 0;

                /* decrypt direction */
                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));
                switch (v->cipher_key_size) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   v->cipher_iv,
                                                   v->cipher_iv_size,
                                                   v->aad, v->aad_size);
                        IMB_AES128_GCM_DEC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  v->cipher_text,
                                                  v->plain_text_size);
                        IMB_AES128_GCM_DEC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tag_size);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   v->cipher_iv,
                                                   v->cipher_iv_size,
                                                   v->aad, v->aad_size);
                        IMB_AES192_GCM_DEC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  v->cipher_text,
                                                  v->plain_text_size);
                        IMB_AES192_GCM_DEC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tag_size);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES256_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   v->cipher_iv,
                                                   v->cipher_iv_size,
                                                   v->aad, v->aad_size);
                        IMB_AES256_GCM_DEC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  v->cipher_text,
                                                  v->plain_text_size);
                        IMB_AES256_GCM_DEC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tag_size);
                        break;
                default:
                        return 0;
                }
                /* check for TAG mismatch */
                if (memcmp(tag, v->tag, v->tag_size))
                        return 0;

                /* check for text mismatch */
                if (memcmp(text, v->plain_text, v->plain_text_size))
                        return 0;

        }  /* for(gcm_vectors) */

        return 1;
}

struct self_test_aead_ccm_vector {
        IMB_HASH_ALG hash_mode;
        IMB_CIPHER_MODE cipher_mode;
	const uint8_t *cipher_key;
        size_t cipher_key_size;
	const uint8_t *cipher_nonce;
        size_t cipher_nonce_size;
	const uint8_t *aad;
        size_t aad_size;
	const uint8_t *plain_text;
        size_t plain_text_size;
	const uint8_t *cipher_text;
	const uint8_t *tag;
        size_t tag_size;
};

/*
 * Test vectors from https://tools.ietf.org/html/rfc3610
 */
static const uint8_t aes_ccm_128_key[] = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF
};
static const uint8_t aes_ccm_128_nonce[] = {
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0,
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5
};
static const uint8_t aes_ccm_128_plain_text[] = {
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
};
static const uint8_t aes_ccm_128_aad[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};
static const uint8_t aes_ccm_128_cipher_text[] = {
        0x58, 0x8C, 0x97, 0x9A, 0x61, 0xC6, 0x63, 0xD2,
        0xF0, 0x66, 0xD0, 0xC2, 0xC0, 0xF9, 0x89, 0x80,
        0x6D, 0x5F, 0x6B, 0x61, 0xDA, 0xC3, 0x84,
};
static const uint8_t aes_ccm_128_tag[] = {
        0x17, 0xE8, 0xD1, 0x2C, 0xFD, 0xF9, 0x26, 0xE0
};

static const uint8_t aes_ccm_256_key[] = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF
};
static const uint8_t aes_ccm_256_nonce[] = {
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xA0,
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5
};
static const uint8_t aes_ccm_256_plain_text[] = {
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
};
static const uint8_t aes_ccm_256_aad[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};
static const uint8_t aes_ccm_256_cipher_text[] = {
        0x21, 0x61, 0x63, 0xDE, 0xCF, 0x74, 0xE0, 0x0C,
        0xAB, 0x04, 0x56, 0xFF, 0x45, 0xCD, 0xA7, 0x17,
        0x1F, 0xA5, 0x96, 0xD7, 0x0F, 0x76, 0x91
};
static const uint8_t aes_ccm_256_tag[] = {
        0xCA, 0x8A, 0xFA, 0xA2, 0x3F, 0x22, 0x3E, 0x64
};

#define ADD_CCM_VECTOR(_key,_nonce,_aad,_plain,_cipher,_tag)   \
        {IMB_AUTH_AES_CCM, IMB_CIPHER_CCM, _key, sizeof(_key), \
                        _nonce, sizeof(_nonce), _aad, sizeof(_aad),   \
                        _plain, sizeof(_plain), _cipher, \
                        _tag, sizeof(_tag)}

struct self_test_aead_ccm_vector aead_ccm_vectors[] = {
        ADD_CCM_VECTOR(aes_ccm_128_key, aes_ccm_128_nonce, aes_ccm_128_aad,
                       aes_ccm_128_plain_text, aes_ccm_128_cipher_text,
                       aes_ccm_128_tag),
        ADD_CCM_VECTOR(aes_ccm_256_key, aes_ccm_256_nonce, aes_ccm_256_aad,
                       aes_ccm_256_plain_text, aes_ccm_256_cipher_text,
                       aes_ccm_256_tag)
};

static int self_test_aead_ccm(IMB_MGR *p_mgr)
{
        DECLARE_ALIGNED(uint32_t expkey[4*15], 16);
        DECLARE_ALIGNED(uint32_t dust[4*15], 16);
        uint8_t text[128], tag[16];
        unsigned i;

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (i = 0; i < IMB_DIM(aead_ccm_vectors); i++) {
                struct self_test_aead_ccm_vector *v = &aead_ccm_vectors[i];

                IMB_ASSERT(v->tag_size <= sizeof(tag));
                IMB_ASSERT(v->plain_text_size <= sizeof(text));

                /* tag too long */
                if (v->tag_size > sizeof(tag))
                        return 0;

                /* message too long */
                if (v->plain_text_size > sizeof(text))
                        return 0;

                switch (v->cipher_key_size) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(p_mgr, v->cipher_key, expkey,
                                           dust);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(p_mgr, v->cipher_key, expkey,
                                           dust);
                        break;
                default:
                        return 0;
                }

                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                /* encrypt test */
                job->cipher_mode = v->cipher_mode;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->key_len_in_bytes = v->cipher_key_size;
                job->src = v->plain_text;
                job->dst = text;
                job->msg_len_to_cipher_in_bytes = v->plain_text_size;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->msg_len_to_hash_in_bytes = v->plain_text_size;
                job->hash_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = v->cipher_nonce;
                job->iv_len_in_bytes = v->cipher_nonce_size;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tag_size;
                job->hash_alg = v->hash_mode;
                job->enc_keys = expkey;
                job->dec_keys = expkey;
                job->u.CCM.aad_len_in_bytes = v->aad_size;
                job->u.CCM.aad = v->aad;

                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                /* submit job and get it processed */
                if (!process_job(p_mgr))
                        return 0;

                /* check for TAG mismatch */
                if (memcmp(tag, v->tag, v->tag_size))
                        return 0;

                /* check for text mismatch */
                if (memcmp(text, v->cipher_text, v->plain_text_size))
                        return 0;

                /* decrypt test */
                job = IMB_GET_NEXT_JOB(p_mgr);

                job->cipher_mode = v->cipher_mode;
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->key_len_in_bytes = v->cipher_key_size;
                job->src = v->cipher_text;
                job->dst = text;
                job->msg_len_to_cipher_in_bytes = v->plain_text_size;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->msg_len_to_hash_in_bytes = v->plain_text_size;
                job->hash_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = v->cipher_nonce;
                job->iv_len_in_bytes = v->cipher_nonce_size;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tag_size;
                job->hash_alg = v->hash_mode;
                job->enc_keys = expkey;
                job->dec_keys = expkey;
                job->u.CCM.aad_len_in_bytes = v->aad_size;
                job->u.CCM.aad = v->aad;

                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                /* submit job and get it processed */
                if (!process_job(p_mgr))
                        return 0;

                /* check for TAG mismatch */
                if (memcmp(tag, v->tag, v->tag_size))
                        return 0;

                /* check for text mismatch */
                if (memcmp(text, v->plain_text, v->plain_text_size))
                        return 0;
        }  /* for(ccm_vectors) */

        return 1;
}

static int self_test_aead(IMB_MGR *p_mgr)
{
        if (!self_test_aead_gcm(p_mgr))
                return 0;
        if (!self_test_aead_ccm(p_mgr))
                return 0;
        return 1;
}

/*
 * =============================================================================
 * SELF-TEST INTERNAL API
 * =============================================================================
 */

IMB_DLL_LOCAL int self_test(IMB_MGR *p_mgr)
{
        int ret = 1;

        p_mgr->features |= IMB_FEATURE_SELF_TEST;
        p_mgr->features &= ~IMB_FEATURE_SELF_TEST_PASS;

        if (!self_test_ciphers(p_mgr))
                ret = 0;

        if (!self_test_hash(p_mgr))
                ret = 0;

        if (!self_test_aead(p_mgr))
                ret = 0;

        if (ret)
                p_mgr->features |= IMB_FEATURE_SELF_TEST_PASS;

#ifdef NO_SELF_TEST_DEV
        p_mgr->features &= ~(IMB_FEATURE_SELF_TEST |
                             IMB_FEATURE_SELF_TEST_PASS);
        ret = 1;
#endif

        return ret;
}
