/*******************************************************************************
  Copyright (c) 2012-2022, Intel Corporation

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

static int process_job(IMB_MGR *p_mgr, IMB_JOB **p_job)
{
        IMB_JOB *job = IMB_SUBMIT_JOB(p_mgr);

        if (!job) {
                const int err = imb_get_errno(p_mgr);
                
                /* check for error */
                if (err != 0)
                        return 0;
                
                /* if no error then flush to get one */
                job = IMB_FLUSH_JOB(p_mgr);
                /* if flush returns nothing then it's an error */
                if (!job)
                        return 0;
        }

        /* if returned job is not complete then it's an error */
        if (job->status != IMB_STATUS_COMPLETED)
                return 0;

        *p_job = job;
        return 1;
}

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
                if (!process_job(p_mgr, &job))
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
                if (!process_job(p_mgr, &job))
                        return 0;

                /* check for plain text mismatch */
                if (memcmp(scratch, v->plain_text, v->plain_text_size))
                        return 0;
                
        } /* for(cipher_vectors) */

        return 1;
}

IMB_DLL_LOCAL int self_test(IMB_MGR *p_mgr)
{
        if (!self_test_ciphers(p_mgr))
                return 0;

        return 1;
}
