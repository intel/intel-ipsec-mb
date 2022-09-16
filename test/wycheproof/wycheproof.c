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
#include <stdlib.h>
#include <stdio.h>

#include <intel-ipsec-mb.h>

#include "mac_test.h"
#include "aead_test.h"

static unsigned run_vectors = 0;
static unsigned skip_vectors = 0;

static unsigned total_run_vectors = 0;
static unsigned total_skip_vectors = 0;

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

static void
prep_iopad(const size_t scratch_size, void *scratch,
           const size_t key_size, const void *key,
           const int pattern)
{
        uint8_t *cb = (uint8_t *) scratch;
        const uint8_t *kp = (const uint8_t *) key;
        const size_t max_j =
                (key_size > scratch_size) ? scratch_size : key_size;
        size_t j;

        memset(scratch, pattern, scratch_size);
        for (j = 0; j < max_j; j++)
                cb[j] ^= kp[j];
}

#define PUTS_ONCE(_s) { \
        static int _ran_already = 0;            \
                                                \
        if (!_ran_already) {                    \
                _ran_already = 1;               \
                printf("\t@note %s\n", _s);       \
        }                                       \
        }

/*
 * =============================================================================
 * MAC TESTS
 * =============================================================================
 */
static void print_mac_test(const struct mac_test *v)
{
        if (v->iv != NULL) {
                printf("MAC vector details:\n"
                       "    tcId = %u\n"
                       "    keySize = %u [bits]\n"
                       "    tagSize = %u [bits]\n"
                       "    msgSize = %u [bits]\n"
                       "    ivSize = %u [bits]\n"
                       "    resultValid = %d\n",
                       (unsigned)v->tcId, (unsigned)v->keySize,
                       (unsigned)v->tagSize, (unsigned)v->msgSize,
                       (unsigned)v->ivSize, (int)v->resultValid);
        } else {
                printf("MAC vector details:\n"
                       "    tcId = %u\n"
                       "    keySize = %u [bits]\n"
                       "    tagSize = %u [bits]\n"
                       "    msgSize = %u [bits]\n"
                       "    resultValid = %d\n",
                       (unsigned)v->tcId, (unsigned)v->keySize,
                       (unsigned)v->tagSize, (unsigned)v->msgSize,
                       (int)v->resultValid);
        }
}

static int err_code = 0;

static int
mac_submit_and_check(IMB_MGR *p_mgr,
                     const struct mac_test *v,
                     const void *res_tag,
                     const int job_api)
{
        if (job_api) {
                /* submit job and get it processed */
                if (!process_job(p_mgr)) {
                        if (v->resultValid) {
                                print_mac_test(v);
                                printf("JOB-API submit/flush error!\n");
                                printf("ERROR: %s\n",
                                       imb_get_strerror(imb_get_errno(p_mgr)));
                                return 0;
                        } else {
                                /* error was expected */
                                return 1;
                        }
                }
        } else {
                if (err_code != 0) {
                        if (v->resultValid) {
                                print_mac_test(v);
                                printf("DIRECT-API error!\n");
                                printf("ERROR: %s\n",
                                       imb_get_strerror(err_code));
                                return 0;
                        } else {
                                /* error was expected */
                                err_code = 0;
                                return 1;
                        }
                }
        }

        const int tag_mismatch = memcmp(res_tag, v->tag, v->tagSize / 8);

        /* was mismatch expected? */
        if (v->resultValid == 0 && tag_mismatch)
                return 1;

        /* check for TAG mismatch */
        if (tag_mismatch) {
                printf("%s: TAG mismatch!\n",
                       job_api ? "JOB-API" : "DIRECT-API");
                print_mac_test(v);
                return 0;
        }

        return 1;
}

static void errno_update(IMB_MGR *p_mgr)
{
        const int new_code = imb_get_errno(p_mgr);

        if (err_code == 0 && new_code != 0)
                err_code = new_code;
}

static void errno_reset(void)
{
        errno = 0;
}

extern const struct mac_test aes_cmac_test_json[];

static int test_cmac(IMB_MGR *p_mgr)
{
        const struct mac_test *v = aes_cmac_test_json;
        DECLARE_ALIGNED(uint32_t expkey[4*15], 16);
        DECLARE_ALIGNED(uint32_t dust[4*15], 16);
        uint32_t skey1[4], skey2[4];
        uint8_t scratch[IMB_SHA_512_BLOCK_SIZE];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for ( ; v->msg != NULL; v++, run_vectors++) {
                IMB_ASSERT((v->tagSize / 8) <= sizeof(scratch));

                /* tag too long */
                if (v->tagSize > (sizeof(scratch) * 8)) {
                        print_mac_test(v);
                        return 0;
                }

                if ((v->keySize / 8) == IMB_KEY_192_BYTES) {
                        /* unsupported - skip it*/
                        PUTS_ONCE("AES-CMAC-192 not supported");
                        skip_vectors++;
                        run_vectors--;
                        continue;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                job->cipher_mode = IMB_CIPHER_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = (const void *) v->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->auth_tag_output = scratch;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;

                if ((v->keySize / 8) == IMB_KEY_128_BYTES) {
                        job->hash_alg = IMB_AUTH_AES_CMAC;
                        IMB_AES_KEYEXP_128(p_mgr, v->key, expkey, dust);
                        IMB_AES_CMAC_SUBKEY_GEN_128(p_mgr, expkey, skey1,
                                                    skey2);
                        job->u.CMAC._key_expanded = expkey;
                        job->u.CMAC._skey1 = skey1;
                        job->u.CMAC._skey2 = skey2;
                } else if ((v->keySize / 8) == IMB_KEY_256_BYTES) {
                        job->hash_alg = IMB_AUTH_AES_CMAC_256;
                        IMB_AES_KEYEXP_256(p_mgr, v->key, expkey, dust);
                        IMB_AES_CMAC_SUBKEY_GEN_256(p_mgr, expkey, skey1,
                                                    skey2);
                        job->u.CMAC._key_expanded = expkey;
                        job->u.CMAC._skey1 = skey1;
                        job->u.CMAC._skey2 = skey2;
                }

                /* clear space where computed TAG is put into */
                memset(scratch, 0, sizeof(scratch));

                if (!mac_submit_and_check(p_mgr, v, scratch, 1))
                        return 0;
        }

        return 1;
}

extern const struct mac_test gmac_test_json[];

static int test_gmac(IMB_MGR *p_mgr)
{
        const struct mac_test *v = gmac_test_json;
        struct gcm_key_data gmac_key;
        uint8_t scratch[IMB_SHA_512_BLOCK_SIZE];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for ( ; v->msg != NULL; v++, run_vectors++) {
                IMB_ASSERT((v->tagSize / 8) <= sizeof(scratch));

                /* tag too long */
                if (v->tagSize > (sizeof(scratch) * 8)) {
                        print_mac_test(v);
                        return 0;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                job->cipher_mode = IMB_CIPHER_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = (const void *) v->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->auth_tag_output = scratch;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;

                if ((v->keySize / 8) == IMB_KEY_128_BYTES) {
                        job->hash_alg = IMB_AUTH_AES_GMAC_128;
                        IMB_AES128_GCM_PRE(p_mgr, v->key, &gmac_key);
                        job->u.GMAC._key = &gmac_key;
                        job->u.GMAC._iv = (const void *) v->iv;
                        job->u.GMAC.iv_len_in_bytes = v->ivSize / 8;
                } else if ((v->keySize / 8) == IMB_KEY_192_BYTES) {
                        job->hash_alg = IMB_AUTH_AES_GMAC_192;
                        IMB_AES192_GCM_PRE(p_mgr, v->key, &gmac_key);
                        job->u.GMAC._key = &gmac_key;
                        job->u.GMAC._iv = (const void *) v->iv;
                        job->u.GMAC.iv_len_in_bytes = v->ivSize / 8;
                } else if ((v->keySize / 8) == IMB_KEY_256_BYTES) {
                        job->hash_alg = IMB_AUTH_AES_GMAC_256;
                        IMB_AES256_GCM_PRE(p_mgr, v->key, &gmac_key);
                        job->u.GMAC._key = &gmac_key;
                        job->u.GMAC._iv = (const void *) v->iv;
                        job->u.GMAC.iv_len_in_bytes = v->ivSize / 8;
                }
                /* clear space where computed TAG is put into */
                memset(scratch, 0, sizeof(scratch));

                if (!mac_submit_and_check(p_mgr, v, scratch, 1))
                        return 0;

                /* exercise direct API test if available */
                memset(scratch, 0, sizeof(scratch));
                errno_reset();

                if ((v->keySize / 8) == IMB_KEY_128_BYTES) {
                        struct gcm_context_data ctx;

                        IMB_AES128_GCM_PRE(p_mgr, v->key, &gmac_key);
                        errno_update(p_mgr);
                        IMB_AES128_GMAC_INIT(p_mgr, &gmac_key, &ctx,
                                             (const void *) v->iv,
                                             v->ivSize / 8);
                        errno_update(p_mgr);
                        IMB_AES128_GMAC_UPDATE(p_mgr, &gmac_key, &ctx,
                                               (const void *) v->msg,
                                               v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_AES128_GMAC_FINALIZE(p_mgr, &gmac_key, &ctx,
                                                 scratch, v->tagSize / 8);
                        errno_update(p_mgr);
                }
                if ((v->keySize / 8) == IMB_KEY_192_BYTES) {
                        struct gcm_context_data ctx;

                        IMB_AES192_GCM_PRE(p_mgr, v->key, &gmac_key);
                        errno_update(p_mgr);
                        IMB_AES192_GMAC_INIT(p_mgr, &gmac_key, &ctx,
                                             (const void *) v->iv,
                                             v->ivSize / 8);
                        errno_update(p_mgr);
                        IMB_AES192_GMAC_UPDATE(p_mgr, &gmac_key, &ctx,
                                               (const void *) v->msg,
                                               v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_AES192_GMAC_FINALIZE(p_mgr, &gmac_key, &ctx,
                                                 scratch, v->tagSize / 8);
                        errno_update(p_mgr);
                }
                if ((v->keySize / 8) == IMB_KEY_256_BYTES) {
                        struct gcm_context_data ctx;

                        IMB_AES256_GCM_PRE(p_mgr, v->key, &gmac_key);
                        errno_update(p_mgr);
                        IMB_AES256_GMAC_INIT(p_mgr, &gmac_key, &ctx,
                                             (const void *) v->iv,
                                             v->ivSize / 8);
                        errno_update(p_mgr);
                        IMB_AES256_GMAC_UPDATE(p_mgr, &gmac_key, &ctx,
                                               (const void *) v->msg,
                                               v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_AES256_GMAC_FINALIZE(p_mgr, &gmac_key, &ctx,
                                                 scratch, v->tagSize / 8);
                        errno_update(p_mgr);
                }

                if (!mac_submit_and_check(p_mgr, v, scratch, 0))
                        return 0;
        }

        return 1;
}

extern const struct mac_test hmac_sha1_test_json[];

static int test_hmac_sha1(IMB_MGR *p_mgr)
{
        const struct mac_test *v = hmac_sha1_test_json;
        DECLARE_ALIGNED(uint8_t hmac_ipad[IMB_SHA1_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t hmac_opad[IMB_SHA1_DIGEST_SIZE_IN_BYTES], 16);
        uint8_t scratch[IMB_SHA1_BLOCK_SIZE];
        uint8_t key[IMB_SHA1_DIGEST_SIZE_IN_BYTES];
        uint8_t tag[IMB_SHA1_DIGEST_SIZE_IN_BYTES];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for ( ; v->msg != NULL; v++, run_vectors++) {
                const void *key_ptr = NULL;
                size_t key_size = 0;

                IMB_ASSERT((v->tagSize / 8) <= sizeof(tag));

                /* tag too long */
                if (v->tagSize > (sizeof(tag) * 8)) {
                        print_mac_test(v);
                        return 0;
                }

                if (v->msgSize == 0) {
                        /* @todo skip */
                        PUTS_ONCE("HMAC-SHA1 msgSize=0 not supported");
                        run_vectors--;
                        skip_vectors++;
                        continue;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                job->hash_alg = IMB_AUTH_HMAC_SHA_1;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = (const void *) v->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->auth_tag_output = tag;

                /* @note smaller tags sizes can be rejected */
                if ((v->tagSize / 8) > 0 &&
                    (v->tagSize / 8) <= IMB_SHA1_DIGEST_SIZE_IN_BYTES)
                        job->auth_tag_output_len_in_bytes =
                                IMB_SHA1_DIGEST_SIZE_IN_BYTES;
                else
                        job->auth_tag_output_len_in_bytes = v->tagSize / 8;

                /* prepare key */
                if ((v->keySize / 8) <= IMB_SHA1_BLOCK_SIZE) {
                        key_ptr = v->key;
                        key_size = v->keySize / 8;
                } else {
                        IMB_SHA1(p_mgr, v->key, v->keySize / 8, key);
                        key_ptr = key;
                        key_size = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
                }

                /* compute IPAD and OPAD */
                prep_iopad(sizeof(scratch), scratch, key_size, key_ptr, 0x36);
                IMB_SHA1_ONE_BLOCK(p_mgr, scratch, hmac_ipad);

                prep_iopad(sizeof(scratch), scratch, key_size, key_ptr, 0x5c);
                IMB_SHA1_ONE_BLOCK(p_mgr, scratch, hmac_opad);

                job->u.HMAC._hashed_auth_key_xor_ipad = hmac_ipad;
                job->u.HMAC._hashed_auth_key_xor_opad = hmac_opad;

                /* clear space where computed TAG is put into */
                memset(tag, 0, sizeof(tag));

                if (!mac_submit_and_check(p_mgr, v, tag, 1))
                        return 0;
        }

        return 1;
}

extern const struct mac_test hmac_sha224_test_json[];

static int test_hmac_sha224(IMB_MGR *p_mgr)
{
        const struct mac_test *v = hmac_sha224_test_json;
        DECLARE_ALIGNED(uint8_t hmac_ipad[IMB_SHA256_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t hmac_opad[IMB_SHA256_DIGEST_SIZE_IN_BYTES], 16);
        uint8_t scratch[IMB_SHA_256_BLOCK_SIZE];
        uint8_t key[IMB_SHA256_DIGEST_SIZE_IN_BYTES];
        uint8_t tag[IMB_SHA256_DIGEST_SIZE_IN_BYTES];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for ( ; v->msg != NULL; v++, run_vectors++) {
                const void *key_ptr = NULL;
                size_t key_size = 0;

                IMB_ASSERT((v->tagSize / 8) <= sizeof(tag));

                /* tag too long */
                if (v->tagSize > (sizeof(tag) * 8)) {
                        print_mac_test(v);
                        return 0;
                }

                if (v->msgSize == 0) {
                        /* @todo skip */
                        PUTS_ONCE("HMAC-SHA224 msgSize=0 not supported");
                        run_vectors--;
                        skip_vectors++;
                        continue;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                job->hash_alg = IMB_AUTH_HMAC_SHA_224;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = (const void *) v->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;

                /* prepare key */
                if ((v->keySize / 8) <= IMB_SHA_256_BLOCK_SIZE) {
                        key_ptr = v->key;
                        key_size = v->keySize / 8;
                } else {
                        IMB_SHA224(p_mgr, v->key, v->keySize / 8, key);
                        key_ptr = key;
                        key_size = IMB_SHA224_DIGEST_SIZE_IN_BYTES;
                }
                /* compute IPAD and OPAD */
                prep_iopad(sizeof(scratch), scratch, key_size, key_ptr, 0x36);
                IMB_SHA224_ONE_BLOCK(p_mgr, scratch, hmac_ipad);

                prep_iopad(sizeof(scratch), scratch, key_size, key_ptr, 0x5c);
                IMB_SHA224_ONE_BLOCK(p_mgr, scratch, hmac_opad);

                job->u.HMAC._hashed_auth_key_xor_ipad = hmac_ipad;
                job->u.HMAC._hashed_auth_key_xor_opad = hmac_opad;

                /* clear space where computed TAG is put into */
                memset(tag, 0, sizeof(tag));

                if (!mac_submit_and_check(p_mgr, v, tag, 1))
                        return 0;
        }

        return 1;
}

extern const struct mac_test hmac_sha256_test_json[];

static int test_hmac_sha256(IMB_MGR *p_mgr)
{
        const struct mac_test *v = hmac_sha256_test_json;
        DECLARE_ALIGNED(uint8_t hmac_ipad[IMB_SHA256_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t hmac_opad[IMB_SHA256_DIGEST_SIZE_IN_BYTES], 16);
        uint8_t scratch[IMB_SHA_256_BLOCK_SIZE];
        uint8_t key[IMB_SHA256_DIGEST_SIZE_IN_BYTES];
        uint8_t tag[IMB_SHA256_DIGEST_SIZE_IN_BYTES];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for ( ; v->msg != NULL; v++, run_vectors++) {
                const void *key_ptr = NULL;
                size_t key_size = 0;

                IMB_ASSERT((v->tagSize / 8) <= sizeof(tag));

                /* tag too long */
                if (v->tagSize > (sizeof(tag) * 8)) {
                        print_mac_test(v);
                        return 0;
                }

                if (v->msgSize == 0) {
                        /* @todo skip */
                        PUTS_ONCE("HMAC-SHA256 msgSize=0 not supported");
                        run_vectors--;
                        skip_vectors++;
                        continue;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                job->hash_alg = IMB_AUTH_HMAC_SHA_256;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = (const void *) v->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;

                /* prepare key */
                if ((v->keySize / 8) <= IMB_SHA_256_BLOCK_SIZE) {
                        key_ptr = v->key;
                        key_size = v->keySize / 8;
                } else {
                        IMB_SHA256(p_mgr, v->key, v->keySize / 8, key);
                        key_ptr = key;
                        key_size = IMB_SHA256_DIGEST_SIZE_IN_BYTES;
                }

                /* compute IPAD and OPAD */
                prep_iopad(sizeof(scratch), scratch, key_size, key_ptr, 0x36);
                IMB_SHA256_ONE_BLOCK(p_mgr, scratch, hmac_ipad);

                prep_iopad(sizeof(scratch), scratch, key_size, key_ptr, 0x5c);
                IMB_SHA256_ONE_BLOCK(p_mgr, scratch, hmac_opad);

                job->u.HMAC._hashed_auth_key_xor_ipad = hmac_ipad;
                job->u.HMAC._hashed_auth_key_xor_opad = hmac_opad;

                /* clear space where computed TAG is put into */
                memset(tag, 0, sizeof(tag));

                if (!mac_submit_and_check(p_mgr, v, tag, 1))
                        return 0;
        }

        return 1;
}

extern const struct mac_test hmac_sha384_test_json[];

static int test_hmac_sha384(IMB_MGR *p_mgr)
{
        const struct mac_test *v = hmac_sha384_test_json;
        DECLARE_ALIGNED(uint8_t hmac_ipad[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t hmac_opad[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        uint8_t scratch[IMB_SHA_512_BLOCK_SIZE];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for ( ; v->msg != NULL; v++, run_vectors++) {
                IMB_ASSERT((v->tagSize / 8) <= sizeof(scratch));

                /* tag too long */
                if (v->tagSize > (sizeof(scratch) * 8)) {
                        print_mac_test(v);
                        return 0;
                }

                if (v->msgSize == 0) {
                        /* @todo skip */
                        PUTS_ONCE("HMAC-SHA384 msgSize=0 not supported");
                        run_vectors--;
                        skip_vectors++;
                        continue;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                job->hash_alg = IMB_AUTH_HMAC_SHA_384;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = (const void *) v->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->auth_tag_output = scratch;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;

                /* compute IPAD and OPAD */
                prep_iopad(sizeof(scratch), scratch,
                           v->keySize / 8, v->key, 0x36);
                IMB_SHA384_ONE_BLOCK(p_mgr, scratch, hmac_ipad);

                prep_iopad(sizeof(scratch), scratch,
                           v->keySize / 8, v->key, 0x5c);
                IMB_SHA384_ONE_BLOCK(p_mgr, scratch, hmac_opad);

                job->u.HMAC._hashed_auth_key_xor_ipad = hmac_ipad;
                job->u.HMAC._hashed_auth_key_xor_opad = hmac_opad;

                /* clear space where computed TAG is put into */
                memset(scratch, 0, sizeof(scratch));

                if (!mac_submit_and_check(p_mgr, v, scratch, 1))
                        return 0;
        }

        return 1;
}

extern const struct mac_test hmac_sha512_test_json[];

static int test_hmac_sha512(IMB_MGR *p_mgr)
{
        const struct mac_test *v = hmac_sha512_test_json;
        DECLARE_ALIGNED(uint8_t hmac_ipad[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        DECLARE_ALIGNED(uint8_t hmac_opad[IMB_SHA512_DIGEST_SIZE_IN_BYTES], 16);
        uint8_t scratch[IMB_SHA_512_BLOCK_SIZE];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for ( ; v->msg != NULL; v++, run_vectors++) {
                IMB_ASSERT((v->tagSize / 8) <= sizeof(scratch));

                /* tag too long */
                if (v->tagSize > (sizeof(scratch) * 8)) {
                        print_mac_test(v);
                        return 0;
                }

                if (v->msgSize == 0) {
                        /* @todo skip */
                        PUTS_ONCE("HMAC-SHA512 msgSize=0 not supported");
                        run_vectors--;
                        skip_vectors++;
                        continue;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                job->hash_alg = IMB_AUTH_HMAC_SHA_512;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = (const void *) v->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->auth_tag_output = scratch;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;

                /* compute IPAD and OPAD */
                prep_iopad(sizeof(scratch), scratch,
                           v->keySize / 8, v->key, 0x36);
                IMB_SHA512_ONE_BLOCK(p_mgr, scratch, hmac_ipad);

                prep_iopad(sizeof(scratch), scratch,
                           v->keySize / 8, v->key, 0x5c);
                IMB_SHA512_ONE_BLOCK(p_mgr, scratch, hmac_opad);

                job->u.HMAC._hashed_auth_key_xor_ipad = hmac_ipad;
                job->u.HMAC._hashed_auth_key_xor_opad = hmac_opad;

                /* clear space where computed TAG is put into */
                memset(scratch, 0, sizeof(scratch));

                if (!mac_submit_and_check(p_mgr, v, scratch, 1))
                        return 0;
        }

        return 1;
}

/*
 * =============================================================================
 * AEAD TESTS
 * =============================================================================
 */

static void print_aead_test(const struct aead_test *v)
{
        printf("AEAD vector details:\n"
               "    tcId = %u\n"
               "    ivSize = %u [bits]\n"
               "    keySize = %u [bits]\n"
               "    tagSize = %u [bits]\n"
               "    aadSize = %u [bits]\n"
               "    msgSize = %u [bits]\n"
               "    resultValid = %d\n",
               (unsigned)v->tcId, (unsigned)v->ivSize,
               (unsigned)v->keySize, (unsigned)v->tagSize,
               (unsigned)v->aadSize, (unsigned)v->msgSize,
               (int)v->resultValid);
}

static int
aead_submit_and_check(IMB_MGR *p_mgr,
                      const struct aead_test *v,
                      const void *res_tag,
                      const void *res_text,
                      const int job_api,
                      const int is_encrypt)
{
        if (job_api) {
                /* submit job and get it processed */
                if (!process_job(p_mgr)) {
                        if (v->resultValid) {
                                print_aead_test(v);
                                printf("JOB-API submit/flush error!\n");
                                return 0;
                        } else {
                                /* error was expected */
                                return 1;
                        }
                }
        } else {
                if (err_code != 0) {
                        if (v->resultValid) {
                                print_aead_test(v);
                                printf("DIRECT-API error!\n");
                                printf("ERROR: %s\n",
                                       imb_get_strerror(err_code));
                                return 0;
                        } else {
                                /* error was expected */
                                err_code = 0;
                                return 1;
                        }
                }
        }

        const int tag_mismatch = memcmp(res_tag, v->tag, v->tagSize / 8);
        const int text_mismatch = is_encrypt ?
                memcmp(res_text, v->ct, v->msgSize / 8) :
                memcmp(res_text, v->msg, v->msgSize / 8);

        if (v->resultValid == 0 && (tag_mismatch || text_mismatch))
                return 1;

        /* check for TAG mismatch */
        if (tag_mismatch) {
                printf("%s %s: TAG mismatch!\n",
                       job_api ? "JOB-API" : "DIRECT-API",
                       is_encrypt ? "encrypt" : "decrypt");
                print_aead_test(v);
                return 0;
        }

        /* check for text mismatch */
        if (text_mismatch) {
                printf("%s %s mismatch!\n",
                       job_api ? "JOB-API" : "DIRECT-API",
                       is_encrypt ? "encrypt: cipher-text" :
                       "decrypt: plain-text");
                print_aead_test(v);
                return 0;
        }

        return 1;
}

extern const struct aead_test aes_gcm_test_json[];

static int test_aead_gcm(IMB_MGR *p_mgr)
{
        const struct aead_test *v = NULL;
        struct gcm_key_data gcm_key;
        struct gcm_context_data ctx;
        uint8_t text[512], tag[16];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (v = aes_gcm_test_json; v->msg != NULL; v++, run_vectors++) {
                IMB_ASSERT(v->tagSize <= (sizeof(tag) * 8));
                IMB_ASSERT(v->msgSize <= (sizeof(text) * 8));

                /* tag too long */
                if (v->tagSize > (sizeof(tag) * 8)) {
                        print_aead_test(v);
                        return 0;
                }
                /* message too long */
                if (v->msgSize > (sizeof(text) * 8)) {
                        print_aead_test(v);
                        return 0;
                }

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_PRE(p_mgr, v->key, &gcm_key);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_PRE(p_mgr, v->key, &gcm_key);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES256_GCM_PRE(p_mgr, v->key, &gcm_key);
                        break;
                default:
                        printf("Invalid key size: %u bytes!\n",
                               (unsigned)v->keySize / 8);
                        print_aead_test(v);
                        return 0;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                /* encrypt test */
                job->cipher_mode = IMB_CIPHER_GCM;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->key_len_in_bytes = v->keySize / 8;
                job->src = (const void *) v->msg;
                job->dst = text;
                job->msg_len_to_cipher_in_bytes = v->msgSize / 8;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = (const void *) v->iv;
                job->iv_len_in_bytes = v->ivSize / 8;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;
                job->hash_alg = IMB_AUTH_AES_GMAC;
                job->enc_keys = &gcm_key;
                job->dec_keys = &gcm_key;
                job->u.GCM.aad = v->aad;
                job->u.GCM.aad_len_in_bytes = v->aadSize / 8;

                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                /* submit job and check */
                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 1))
                        return 0;

                /* decrypt test */
                job = IMB_GET_NEXT_JOB(p_mgr);

                job->cipher_mode = IMB_CIPHER_GCM;
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->key_len_in_bytes = v->keySize / 8;
                job->src = (const void *) v->ct;
                job->dst = text;
                job->msg_len_to_cipher_in_bytes = v->msgSize / 8;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = (const void *) v->iv;
                job->iv_len_in_bytes = v->ivSize / 8;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;
                job->hash_alg = IMB_AUTH_AES_GMAC;
                job->enc_keys = &gcm_key;
                job->dec_keys = &gcm_key;
                job->u.GCM.aad = v->aad;
                job->u.GCM.aad_len_in_bytes = v->aadSize / 8;

                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                /* submit job and check */
                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 0))
                        return 0;

                /* test direct API */

                /* encrypt direction */
                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));
                errno_reset();

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   (const void *) v->iv,
                                                   v->ivSize / 8,
                                                   (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        IMB_AES128_GCM_ENC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  (const void *) v->msg,
                                                  v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_AES128_GCM_ENC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tagSize / 8);
                        errno_update(p_mgr);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   (const void *) v->iv,
                                                   v->ivSize / 8,
                                                   (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        IMB_AES192_GCM_ENC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  (const void *) v->msg,
                                                  v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_AES192_GCM_ENC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tagSize / 8);
                        errno_update(p_mgr);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES256_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   (const void *) v->iv,
                                                   v->ivSize / 8,
                                                   (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        IMB_AES256_GCM_ENC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  (const void *) v->msg,
                                                  v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_AES256_GCM_ENC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tagSize / 8);
                        errno_update(p_mgr);
                        break;
                default:
                        printf("Invalid key size: %u bytes!\n",
                               (unsigned)v->keySize / 8);
                        print_aead_test(v);
                        return 0;
                }
                /* submit job and check */
                if (!aead_submit_and_check(p_mgr, v, tag, text, 0, 1))
                        return 0;

                /* decrypt direction */
                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));
                errno_reset();
                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   (const void *) v->iv,
                                                   v->ivSize / 8,
                                                   (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        IMB_AES128_GCM_DEC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  (const void *) v->ct,
                                                  v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_AES128_GCM_DEC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tagSize / 8);
                        errno_update(p_mgr);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   (const void *) v->iv,
                                                   v->ivSize / 8,
                                                   (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        IMB_AES192_GCM_DEC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  (const void *) v->ct,
                                                  v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_AES192_GCM_DEC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tagSize / 8);
                        errno_update(p_mgr);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES256_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx,
                                                   (const void *) v->iv,
                                                   v->ivSize / 8,
                                                   (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        IMB_AES256_GCM_DEC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                  (const void *) v->ct,
                                                  v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_AES256_GCM_DEC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                    v->tagSize / 8);
                        errno_update(p_mgr);
                        break;
                default:
                        printf("Invalid key size: %u bytes!\n",
                               (unsigned)v->keySize / 8);
                        print_aead_test(v);
                        return 0;
                }
                /* submit job and check */
                if (!aead_submit_and_check(p_mgr, v, tag, text, 0, 0))
                        return 0;
        }

        return 1;
}

extern const struct aead_test chacha20_poly1305_test_json[];

static int test_aead_chacha20_poly1305(IMB_MGR *p_mgr)
{
        const struct aead_test *v = NULL;
        struct chacha20_poly1305_context_data ctx;
        uint8_t text[512], tag[16];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (v = chacha20_poly1305_test_json; v->msg != NULL;
             v++, run_vectors++) {
                IMB_ASSERT(v->tagSize <= (sizeof(tag) * 8));
                IMB_ASSERT(v->msgSize <= (sizeof(text) * 8));

                /* tag too long */
                if (v->tagSize > (sizeof(tag) * 8)) {
                        print_aead_test(v);
                        return 0;
                }
                /* message too long */
                if (v->msgSize > (sizeof(text) * 8)) {
                        print_aead_test(v);
                        return 0;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                /* encrypt test */
                job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->key_len_in_bytes = v->keySize / 8;
                job->src = (const void *) v->msg;
                job->dst = text;
                job->msg_len_to_cipher_in_bytes = v->msgSize / 8;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = (const void *) v->iv;
                job->iv_len_in_bytes = v->ivSize / 8;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;
                job->hash_alg = IMB_AUTH_CHACHA20_POLY1305;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->hash_start_src_offset_in_bytes = 0;
                job->enc_keys = (const void *) v->key;
                job->dec_keys = (const void *) v->key;
                job->u.CHACHA20_POLY1305.aad = (const void *) v->aad;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = v->aadSize / 8;

                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                /* submit job and check */
                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 1))
                        return 0;

                /* decrypt test */
                job = IMB_GET_NEXT_JOB(p_mgr);

                job->cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->key_len_in_bytes = v->keySize / 8;
                job->src = (const void *) v->ct;
                job->dst = text;
                job->msg_len_to_cipher_in_bytes = v->msgSize / 8;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = (const void *) v->iv;
                job->iv_len_in_bytes = v->ivSize / 8;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;
                job->hash_alg = IMB_AUTH_CHACHA20_POLY1305;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->hash_start_src_offset_in_bytes = 0;
                job->enc_keys = (const void *) v->key;
                job->dec_keys = (const void *) v->key;
                job->u.CHACHA20_POLY1305.aad = (const void *) v->aad;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = v->aadSize / 8;

                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                /* submit job and check */
                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 0))
                        return 0;

                /* test direct API */

                /* encrypt direction */
                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));
                errno_reset();

                IMB_CHACHA20_POLY1305_INIT(p_mgr, (const void *) v->key, &ctx,
                                           (const void *) v->iv,
                                           (const void *) v->aad,
                                           v->aadSize / 8);
                errno_update(p_mgr);
                IMB_CHACHA20_POLY1305_ENC_UPDATE(p_mgr, (const void *) v->key,
                                                 &ctx, text,
                                                 (const void *) v->msg,
                                                 v->msgSize / 8);
                errno_update(p_mgr);
                IMB_CHACHA20_POLY1305_ENC_FINALIZE(p_mgr, &ctx, tag,
                                                   v->tagSize / 8);
                errno_update(p_mgr);

                /* submit job and check */
                if (!aead_submit_and_check(p_mgr, v, tag, text, 0, 1))
                        return 0;

                /* decrypt direction */
                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));
                errno_reset();

                IMB_CHACHA20_POLY1305_INIT(p_mgr, (const void *) v->key, &ctx,
                                           (const void *) v->iv,
                                           (const void *) v->aad,
                                           v->aadSize / 8);
                errno_update(p_mgr);
                IMB_CHACHA20_POLY1305_DEC_UPDATE(p_mgr, (const void *) v->key,
                                                 &ctx, text,
                                                 (const void *) v->ct,
                                                 v->msgSize / 8);
                errno_update(p_mgr);
                IMB_CHACHA20_POLY1305_DEC_FINALIZE(p_mgr, &ctx, tag,
                                                   v->tagSize / 8);
                errno_update(p_mgr);

                /* submit job and check */
                if (!aead_submit_and_check(p_mgr, v, tag, text, 0, 0))
                        return 0;
        }

        return 1;
}

extern const struct aead_test aes_ccm_test_json[];

static int test_aead_ccm(IMB_MGR *p_mgr)
{
        const struct aead_test *v = NULL;
        DECLARE_ALIGNED(uint32_t expkey[4*15], 16);
        DECLARE_ALIGNED(uint32_t dust[4*15], 16);
        uint8_t text[512], tag[16];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (v = aes_ccm_test_json; v->msg != NULL; v++, run_vectors++) {
                IMB_ASSERT(v->tagSize <= (sizeof(tag) * 8));
                IMB_ASSERT(v->msgSize <= (sizeof(text) * 8));

                /* tag too long */
                if (v->tagSize > (sizeof(tag) * 8)) {
                        print_aead_test(v);
                        return 0;
                }
                /* message too long */
                if (v->msgSize > (sizeof(text) * 8)) {
                        print_aead_test(v);
                        return 0;
                }

                if ((v->aadSize / 8) > 46) {
                        /* unsupported AAD sizes - skip it */
                        PUTS_ONCE("AES-CCM AAD > 46 bytes not supported");
                        run_vectors--;
                        skip_vectors++;
                        continue;
                }

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(p_mgr, v->key, expkey, dust);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(p_mgr, v->key, expkey, dust);
                        break;
                case IMB_KEY_192_BYTES:
                        /* unsupported key size - skip it */
                        PUTS_ONCE("AES-CCM-192 not supported");
                        run_vectors--;
                        skip_vectors++;
                        continue;
                default:
                        printf("Invalid key size: %u bytes!\n",
                               (unsigned)v->keySize / 8);
                        print_aead_test(v);
                        return 0;
                }

                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                /* encrypt test */
                job->cipher_mode = IMB_CIPHER_CCM;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->key_len_in_bytes = v->keySize / 8;
                job->src = (const void *) v->msg;
                job->dst = text;
                job->msg_len_to_cipher_in_bytes = v->msgSize / 8;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->hash_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = (const void *) v->iv;
                job->iv_len_in_bytes = v->ivSize / 8;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;
                job->hash_alg = IMB_AUTH_AES_CCM;
                job->enc_keys = expkey;
                job->dec_keys = expkey;
                job->u.CCM.aad_len_in_bytes = v->aadSize / 8;
                job->u.CCM.aad = v->aad;

                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                /* submit job and check */
                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 1))
                        return 0;

                /* decrypt test */
                job = IMB_GET_NEXT_JOB(p_mgr);

                job->cipher_mode = IMB_CIPHER_CCM;
                job->cipher_direction = IMB_DIR_DECRYPT;
                job->chain_order = IMB_ORDER_CIPHER_HASH;
                job->key_len_in_bytes = v->keySize / 8;
                job->src = (const void *) v->ct;
                job->dst = text;
                job->msg_len_to_cipher_in_bytes = v->msgSize / 8;
                job->cipher_start_src_offset_in_bytes = UINT64_C(0);
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->hash_start_src_offset_in_bytes = UINT64_C(0);
                job->iv = (const void *) v->iv;
                job->iv_len_in_bytes = v->ivSize / 8;
                job->auth_tag_output = tag;
                job->auth_tag_output_len_in_bytes = v->tagSize / 8;
                job->hash_alg = IMB_AUTH_AES_CCM;
                job->enc_keys = expkey;
                job->dec_keys = expkey;
                job->u.CCM.aad_len_in_bytes = v->aadSize / 8;
                job->u.CCM.aad = v->aad;

                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));

                /* submit job and check */
                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 0))
                        return 0;
        }  /* for(ccm_vectors) */

        return 1;
}

static int test_all(IMB_MGR *p_mgr)
{
        const struct {
                int (*fn)(IMB_MGR *);
                const char *name;
        } test_tab[] = {
                { test_aead_gcm, "AEAD AES-GCM" },
                { test_aead_ccm, "AEAD AES-CCM" },
                { test_aead_chacha20_poly1305, "AEAD CHACHA20-POLY1305" },
                { test_cmac, "AES-CMAC" },
                { test_gmac, "GMAC" },
                { test_hmac_sha1, "HMAC-SHA1" },
                { test_hmac_sha224, "HMAC-SHA224" },
                { test_hmac_sha256, "HMAC-SHA256" },
                { test_hmac_sha384, "HMAC-SHA384" },
                { test_hmac_sha512, "HMAC-SHA512" }
        };
        unsigned i;
        int ret = 1;

        for (i = 0; i < IMB_DIM(test_tab); i++) {
                run_vectors = 0;
                skip_vectors = 0;
                if (test_tab[i].fn(p_mgr) == 0) {
                        printf("Testing %s: FAILED\n", test_tab[i].name);
                        ret = 0;
                } else {
                        printf("Testing %s: PASSED (run: %u, skipped: %u)\n",
                               test_tab[i].name, run_vectors, skip_vectors);
                }
                total_run_vectors += run_vectors;
                total_skip_vectors += skip_vectors;
        }
        return ret;
}


/*
 * =============================================================================
 * MAIN
 * =============================================================================
 */

static void
usage(const char *name)
{
	printf("Usage: %s [args], where args are zero or more\n"
               "--aesni-emu test AESNI emulation interface\n"
               "--avx512    test AVX512 interface\n"
               "--avx2      test AVX2 interface\n"
               "--avx       test AVX interface\n"
               "--sse       test SSE interface\n"
               "--shani-off don't use SHA extensions "
               "(auto-detect by default)\n"
               "--gfni-off  don't use GFNI extensions "
               "(auto-detect by default)\n", name);
}

int main(int argc, const char **argv)
{
        IMB_ARCH arch_to_run = IMB_ARCH_NUM;
        uint64_t flags = 0;
        const uint64_t feat_flags = imb_get_feature_flags();
        IMB_MGR *p_mgr = NULL;
        int i;

        if (imb_get_version() < IMB_VERSION(0, 50, 0)) {
                printf("Library version detection unsupported!\n");
        } else {
                printf("Tool version: %s\n", IMB_VERSION_STR);
                printf("Library version: %s\n", imb_get_version_str());
        }

	for (i = 1; i < argc; i++) {
		if ((strcmp(argv[i], "-h") == 0) ||
                    (strcmp(argv[i], "--help") == 0)) {
			usage(argv[0]);
			return EXIT_SUCCESS;
                } else if (strcmp(argv[i], "--aesni-emu") == 0) {
                        flags |= IMB_FLAG_AESNI_OFF;
                        arch_to_run = IMB_ARCH_NOAESNI;
                } else if (strcmp(argv[i], "--sse") == 0) {
                        arch_to_run = IMB_ARCH_SSE;
                } else if (strcmp(argv[i], "--avx") == 0) {
                        arch_to_run = IMB_ARCH_AVX;
                } else if (strcmp(argv[i], "--avx2") == 0) {
                        arch_to_run = IMB_ARCH_AVX2;
                } else if (strcmp(argv[i], "--avx512") == 0) {
                        arch_to_run = IMB_ARCH_AVX512;
                } else if (strcmp(argv[i], "--shani-off") == 0) {
                        flags |= IMB_FLAG_SHANI_OFF;
                } else if (strcmp(argv[i], "--gfni-off") == 0) {
                        flags |= IMB_FLAG_GFNI_OFF;
                }
        }

        p_mgr = alloc_mb_mgr(flags);
        if (p_mgr == NULL) {
                printf("Error allocating MB_MGR structure: %s\n",
                       imb_get_strerror(imb_get_errno(p_mgr)));
                return EXIT_FAILURE;
        }

        switch (arch_to_run) {
        case IMB_ARCH_NOAESNI:
                if (((feat_flags & IMB_FEATURE_AESNI_EMU) == 0) &&
                    (imb_get_errno(p_mgr) == IMB_ERR_NO_AESNI_EMU)) {
                        printf("AESNI Emulation is not enabled!\n");
                        free_mb_mgr(p_mgr);
                        return EXIT_FAILURE;
                }
                init_mb_mgr_sse(p_mgr);
                break;
        case IMB_ARCH_SSE:
                init_mb_mgr_sse(p_mgr);
                break;
        case IMB_ARCH_AVX:
                init_mb_mgr_avx(p_mgr);
                break;
        case IMB_ARCH_AVX2:
                init_mb_mgr_avx2(p_mgr);
                break;
        case IMB_ARCH_AVX512:
                init_mb_mgr_avx512(p_mgr);
                break;
        default:
                /* auto-detect */
                init_mb_mgr_auto(p_mgr, &arch_to_run);
                break;
        }

        if (p_mgr->features & IMB_FEATURE_SELF_TEST)
                printf("SELF-TEST: %s\n",
                       (p_mgr->features & IMB_FEATURE_SELF_TEST_PASS) ?
                       "PASS" : "FAIL");
        else
                printf("SELF-TEST: N/A (requires library >= v1.3)\n");

        if (imb_get_errno(p_mgr) != 0) {
                printf("Error initializing MB_MGR structure! %s\n",
                       imb_get_strerror(imb_get_errno(p_mgr)));
                free_mb_mgr(p_mgr);
                return EXIT_FAILURE;
        }

        if (!test_all(p_mgr)) {
                printf("Wycheproof test complete: FAILED\n");
                free_mb_mgr(p_mgr);
                return EXIT_FAILURE;
        }

        printf("Test complete: PASSED (run: %u, skipped: %u)\n",
               total_run_vectors, total_skip_vectors);

        free_mb_mgr(p_mgr);
        return EXIT_SUCCESS;
}
