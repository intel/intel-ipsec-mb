/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/*
 * Project Wycheproof test vectors (https://github.com/google/wycheproof).
 *
 * Unlike the other KAT modules, these vector sets deliberately contain
 * negative ("invalid") test cases that probe for known weaknesses and for
 * malformed parameter handling. A vector marked "invalid" passes when the
 * library either rejects the operation or produces a result that differs from
 * the recorded one.
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <intel-ipsec-mb.h>

#include "utils.h"
#include "mac_test.h"
#include "aead_test.h"
#include "wycheproof_test.h"

/* buffers large enough for the biggest message/tag in the vector sets */
#define MAX_TEXT_SIZE 1024
#define MAX_TAG_SIZE  16

/* maximum AAD size supported by the AES-CCM implementation */
#define CCM_MAX_AAD_SIZE 46

/* direct API error code, sticky until reset by errno_reset() */
static int err_code;

/* reasons why vectors of the suite being run were not tested */
static struct {
        const char *note;
        unsigned count;
} skip_notes[8];

static unsigned num_skip_notes;

/**
 * @brief Record that a vector was skipped for the given reason
 *
 * @param [in] note reason the vector could not be tested
 */
static void
skip_note_add(const char *note)
{
        for (unsigned i = 0; i < num_skip_notes; i++) {
                if (strcmp(skip_notes[i].note, note) == 0) {
                        skip_notes[i].count++;
                        return;
                }
        }

        if (num_skip_notes < IMB_DIM(skip_notes)) {
                skip_notes[num_skip_notes].note = note;
                skip_notes[num_skip_notes].count = 1;
                num_skip_notes++;
        }
}

/**
 * @brief Print the skip reasons collected while running a suite
 */
static void
skip_notes_print(void)
{
        for (unsigned i = 0; i < num_skip_notes; i++)
                printf("\t%u vector(s) skipped: %s\n", skip_notes[i].count, skip_notes[i].note);
}

/**
 * @brief Print progress for the vector being tested
 *
 * @param [in] tc_id test case identifier of the vector
 */
static void
vector_progress(const size_t tc_id)
{
        if (quiet_mode)
                return;
#ifdef DEBUG
        printf("Wycheproof vector %zu\n", tc_id);
#else
        (void) tc_id;
        printf(".");
#endif
}

static int
process_job(IMB_MGR *p_mgr)
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
errno_update(IMB_MGR *p_mgr)
{
        const int new_code = imb_get_errno(p_mgr);

        if (err_code == 0 && new_code != 0)
                err_code = new_code;
}

static void
errno_reset(void)
{
        err_code = 0;
        errno = 0;
}

/*
 * =============================================================================
 * MAC TESTS
 * =============================================================================
 */
static void
print_mac_test(const struct mac_test *v)
{
        if (v->iv != NULL) {
                printf("MAC vector details:\n"
                       "    tcId = %u\n"
                       "    keySize = %u [bits]\n"
                       "    tagSize = %u [bits]\n"
                       "    msgSize = %u [bits]\n"
                       "    ivSize = %u [bits]\n"
                       "    resultValid = %d\n",
                       (unsigned) v->tcId, (unsigned) v->keySize, (unsigned) v->tagSize,
                       (unsigned) v->msgSize, (unsigned) v->ivSize, (int) v->resultValid);
        } else {
                printf("MAC vector details:\n"
                       "    tcId = %u\n"
                       "    keySize = %u [bits]\n"
                       "    tagSize = %u [bits]\n"
                       "    msgSize = %u [bits]\n"
                       "    resultValid = %d\n",
                       (unsigned) v->tcId, (unsigned) v->keySize, (unsigned) v->tagSize,
                       (unsigned) v->msgSize, (int) v->resultValid);
        }
}

static int
mac_submit_and_check(IMB_MGR *p_mgr, const struct mac_test *v, const void *res_tag,
                     const int job_api)
{
        if (job_api) {
                /* submit job and get it processed */
                if (!process_job(p_mgr)) {
                        if (v->resultValid) {
                                print_mac_test(v);
                                printf("JOB-API submit/flush error!\n");
                                printf("ERROR: %s\n", imb_get_strerror(imb_get_errno(p_mgr)));
                                return 0;
                        }
                        /* error was expected */
                        return 1;
                }
        } else {
                if (err_code != 0) {
                        if (v->resultValid) {
                                print_mac_test(v);
                                printf("DIRECT-API error!\n");
                                printf("ERROR: %s\n", imb_get_strerror(err_code));
                                return 0;
                        }
                        /* error was expected */
                        err_code = 0;
                        return 1;
                }
        }

        const int tag_mismatch = memcmp(res_tag, v->tag, v->tagSize / 8);

        /* was mismatch expected? */
        if (v->resultValid == 0 && tag_mismatch)
                return 1;

        /* check for TAG mismatch */
        if (tag_mismatch) {
                printf("%s: TAG mismatch!\n", job_api ? "JOB-API" : "DIRECT-API");
                print_mac_test(v);
                return 0;
        }

        return 1;
}

/**
 * @brief Handle a MAC vector using a key size the library does not implement.
 *
 * Such vectors only ever appear as negative test cases: the expectation is
 * that the parameter set is rejected.
 *
 * @return Test result
 * @retval 1 vector accounted for as expected rejection
 * @retval 0 vector is valid and cannot be tested (caller should skip it)
 */
static int
mac_unsupported_key_size(const struct mac_test *v)
{
        if (v->resultValid) {
                /* valid vector with an unsupported key size - nothing to test */
                return 0;
        }
        return 1;
}

static void
test_cmac(IMB_MGR *p_mgr, const struct mac_test *vectors, struct test_suite_context *ts)
{
        const struct mac_test *v;
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        uint32_t skey1[4], skey2[4];
        uint8_t scratch[IMB_SHA_512_BLOCK_SIZE];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (v = vectors; v->msg != NULL; v++) {
                vector_progress(v->tcId);

                /* tag too long */
                if (v->tagSize > (sizeof(scratch) * 8)) {
                        print_mac_test(v);
                        test_suite_update(ts, 0, 1);
                        continue;
                }

                if ((v->keySize / 8) == IMB_KEY_192_BYTES) {
                        skip_note_add("AES-CMAC-192 not supported");
                        continue;
                }

                if ((v->keySize / 8) != IMB_KEY_128_BYTES &&
                    (v->keySize / 8) != IMB_KEY_256_BYTES) {
                        if (mac_unsupported_key_size(v)) {
                                /* the key size is rejected, as expected */
                                test_suite_update(ts, 1, 0);
                                continue;
                        }
                        skip_note_add("AES-CMAC key size not supported");
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
                        IMB_AES_CMAC_SUBKEY_GEN_128(p_mgr, expkey, skey1, skey2);
                } else {
                        job->hash_alg = IMB_AUTH_AES_CMAC_256;
                        IMB_AES_KEYEXP_256(p_mgr, v->key, expkey, dust);
                        IMB_AES_CMAC_SUBKEY_GEN_256(p_mgr, expkey, skey1, skey2);
                }
                job->u.CMAC._key_expanded = expkey;
                job->u.CMAC._skey1 = skey1;
                job->u.CMAC._skey2 = skey2;

                /* clear space where computed TAG is put into */
                memset(scratch, 0, sizeof(scratch));

                if (!mac_submit_and_check(p_mgr, v, scratch, 1))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);
        }
}

static void
test_gmac(IMB_MGR *p_mgr, const struct mac_test *vectors, struct test_suite_context *ts)
{
        const struct mac_test *v;
        struct gcm_key_data gmac_key;
        uint8_t scratch[IMB_SHA_512_BLOCK_SIZE];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (v = vectors; v->msg != NULL; v++) {
                vector_progress(v->tcId);

                /* tag too long */
                if (v->tagSize > (sizeof(scratch) * 8)) {
                        print_mac_test(v);
                        test_suite_update(ts, 0, 1);
                        continue;
                }

                if ((v->keySize / 8) != IMB_KEY_128_BYTES &&
                    (v->keySize / 8) != IMB_KEY_192_BYTES &&
                    (v->keySize / 8) != IMB_KEY_256_BYTES) {
                        if (mac_unsupported_key_size(v)) {
                                /* the key size is rejected, as expected */
                                test_suite_update(ts, 1, 0);
                                continue;
                        }
                        skip_note_add("AES-GMAC key size not supported");
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
                        job->hash_alg = IMB_AUTH_AES_GMAC_128;
                        IMB_AES128_GCM_PRE(p_mgr, v->key, &gmac_key);
                } else if ((v->keySize / 8) == IMB_KEY_192_BYTES) {
                        job->hash_alg = IMB_AUTH_AES_GMAC_192;
                        IMB_AES192_GCM_PRE(p_mgr, v->key, &gmac_key);
                } else {
                        job->hash_alg = IMB_AUTH_AES_GMAC_256;
                        IMB_AES256_GCM_PRE(p_mgr, v->key, &gmac_key);
                }
                job->u.GMAC._key = &gmac_key;
                job->u.GMAC._iv = (const void *) v->iv;
                job->u.GMAC.iv_len_in_bytes = v->ivSize / 8;

                /* clear space where computed TAG is put into */
                memset(scratch, 0, sizeof(scratch));

                if (!mac_submit_and_check(p_mgr, v, scratch, 1))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);

                /* exercise direct API test if available */
                memset(scratch, 0, sizeof(scratch));
                errno_reset();

                if ((v->keySize / 8) == IMB_KEY_128_BYTES) {
                        struct gcm_context_data ctx;

                        memset(&ctx, 0, sizeof(ctx));
                        IMB_AES128_GCM_PRE(p_mgr, v->key, &gmac_key);
                        errno_update(p_mgr);
                        IMB_AES128_GMAC_INIT(p_mgr, &gmac_key, &ctx, (const void *) v->iv,
                                             v->ivSize / 8);
                        errno_update(p_mgr);
                        /* context is only usable when init succeeded */
                        if (err_code == 0) {
                                IMB_AES128_GMAC_UPDATE(p_mgr, &gmac_key, &ctx,
                                                       (const void *) v->msg, v->msgSize / 8);
                                errno_update(p_mgr);
                                IMB_AES128_GMAC_FINALIZE(p_mgr, &gmac_key, &ctx, scratch,
                                                         v->tagSize / 8);
                                errno_update(p_mgr);
                        }
                } else if ((v->keySize / 8) == IMB_KEY_192_BYTES) {
                        struct gcm_context_data ctx;

                        memset(&ctx, 0, sizeof(ctx));
                        IMB_AES192_GCM_PRE(p_mgr, v->key, &gmac_key);
                        errno_update(p_mgr);
                        IMB_AES192_GMAC_INIT(p_mgr, &gmac_key, &ctx, (const void *) v->iv,
                                             v->ivSize / 8);
                        errno_update(p_mgr);
                        if (err_code == 0) {
                                IMB_AES192_GMAC_UPDATE(p_mgr, &gmac_key, &ctx,
                                                       (const void *) v->msg, v->msgSize / 8);
                                errno_update(p_mgr);
                                IMB_AES192_GMAC_FINALIZE(p_mgr, &gmac_key, &ctx, scratch,
                                                         v->tagSize / 8);
                                errno_update(p_mgr);
                        }
                } else {
                        struct gcm_context_data ctx;

                        memset(&ctx, 0, sizeof(ctx));
                        IMB_AES256_GCM_PRE(p_mgr, v->key, &gmac_key);
                        errno_update(p_mgr);
                        IMB_AES256_GMAC_INIT(p_mgr, &gmac_key, &ctx, (const void *) v->iv,
                                             v->ivSize / 8);
                        errno_update(p_mgr);
                        if (err_code == 0) {
                                IMB_AES256_GMAC_UPDATE(p_mgr, &gmac_key, &ctx,
                                                       (const void *) v->msg, v->msgSize / 8);
                                errno_update(p_mgr);
                                IMB_AES256_GMAC_FINALIZE(p_mgr, &gmac_key, &ctx, scratch,
                                                         v->tagSize / 8);
                                errno_update(p_mgr);
                        }
                }

                if (!mac_submit_and_check(p_mgr, v, scratch, 0))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);
        }
}

/**
 * @brief Run a set of HMAC vectors through the JOB API.
 *
 * @param [in] p_mgr        initialised IMB_MGR
 * @param [in] vectors      sentinel terminated vector array
 * @param [in] hash_alg     HMAC algorithm to test
 * @param [in] digest_size  full digest size of @a hash_alg in bytes
 * @param [in] full_tag     when set, the full digest size is requested from
 *                          the library instead of the (possibly truncated)
 *                          vector tag size
 * @param [in] zero_msg_note note printed when zero length messages are skipped
 *
 * @return Test result
 * @retval 1 all vectors behaved as expected
 * @retval 0 at least one vector failed
 */
static void
test_hmac(IMB_MGR *p_mgr, const struct mac_test *vectors, struct test_suite_context *ts,
          const IMB_HASH_ALG hash_alg, const size_t digest_size, const int full_tag,
          const char *zero_msg_note)
{
        const struct mac_test *v;
        /* imb_hmac_ipad_opad() writes up to one hash block, SHA3 being the largest */
        DECLARE_ALIGNED(uint8_t hmac_ipad[IMB_SHA3_MAX_BLOCK_SIZE], 16);
        DECLARE_ALIGNED(uint8_t hmac_opad[IMB_SHA3_MAX_BLOCK_SIZE], 16);
        uint8_t tag[IMB_SHA_512_BLOCK_SIZE];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (v = vectors; v->msg != NULL; v++) {
                vector_progress(v->tcId);

                /* tag too long */
                if (v->tagSize > (sizeof(tag) * 8)) {
                        print_mac_test(v);
                        test_suite_update(ts, 0, 1);
                        continue;
                }

                if (v->msgSize == 0) {
                        skip_note_add(zero_msg_note);
                        continue;
                }

                /* test JOB API */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

                job->hash_alg = hash_alg;
                job->cipher_mode = IMB_CIPHER_NULL;
                job->cipher_direction = IMB_DIR_ENCRYPT;
                job->chain_order = IMB_ORDER_HASH_CIPHER;
                job->src = (const void *) v->msg;
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = v->msgSize / 8;
                job->auth_tag_output = tag;

                /* @note smaller tag sizes can be rejected */
                if (full_tag && (v->tagSize / 8) > 0 && (v->tagSize / 8) <= digest_size)
                        job->auth_tag_output_len_in_bytes = digest_size;
                else
                        job->auth_tag_output_len_in_bytes = v->tagSize / 8;

                imb_hmac_ipad_opad(p_mgr, hash_alg, v->key, v->keySize / 8, hmac_ipad, hmac_opad);

                job->u.HMAC._hashed_auth_key_xor_ipad = hmac_ipad;
                job->u.HMAC._hashed_auth_key_xor_opad = hmac_opad;

                /* clear space where computed TAG is put into */
                memset(tag, 0, sizeof(tag));

                if (!mac_submit_and_check(p_mgr, v, tag, 1))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);
        }
}

/*
 * =============================================================================
 * AEAD TESTS
 * =============================================================================
 */

static void
print_aead_test(const struct aead_test *v)
{
        printf("AEAD vector details:\n"
               "    tcId = %u\n"
               "    ivSize = %u [bits]\n"
               "    keySize = %u [bits]\n"
               "    tagSize = %u [bits]\n"
               "    aadSize = %u [bits]\n"
               "    msgSize = %u [bits]\n"
               "    resultValid = %d\n",
               (unsigned) v->tcId, (unsigned) v->ivSize, (unsigned) v->keySize,
               (unsigned) v->tagSize, (unsigned) v->aadSize, (unsigned) v->msgSize,
               (int) v->resultValid);
}

static int
aead_submit_and_check(IMB_MGR *p_mgr, const struct aead_test *v, const void *res_tag,
                      const void *res_text, const int job_api, const int is_encrypt)
{
        if (job_api) {
                /* submit job and get it processed */
                if (!process_job(p_mgr)) {
                        if (v->resultValid) {
                                print_aead_test(v);
                                printf("JOB-API submit/flush error!\n");
                                return 0;
                        }
                        /* error was expected */
                        return 1;
                }
        } else {
                if (err_code != 0) {
                        if (v->resultValid) {
                                print_aead_test(v);
                                printf("DIRECT-API error!\n");
                                printf("ERROR: %s\n", imb_get_strerror(err_code));
                                return 0;
                        }
                        /* error was expected */
                        err_code = 0;
                        return 1;
                }
        }

        const int tag_mismatch = memcmp(res_tag, v->tag, v->tagSize / 8);
        const int text_mismatch = is_encrypt ? memcmp(res_text, v->ct, v->msgSize / 8)
                                             : memcmp(res_text, v->msg, v->msgSize / 8);

        if (v->resultValid == 0 && (tag_mismatch || text_mismatch))
                return 1;

        /* check for TAG mismatch */
        if (tag_mismatch) {
                printf("%s %s: TAG mismatch!\n", job_api ? "JOB-API" : "DIRECT-API",
                       is_encrypt ? "encrypt" : "decrypt");
                print_aead_test(v);
                return 0;
        }

        /* check for text mismatch */
        if (text_mismatch) {
                printf("%s %s mismatch!\n", job_api ? "JOB-API" : "DIRECT-API",
                       is_encrypt ? "encrypt: cipher-text" : "decrypt: plain-text");
                print_aead_test(v);
                return 0;
        }

        return 1;
}

/**
 * @brief Check AEAD vector buffer requirements against the local scratch space.
 *
 * @return Test result
 * @retval 1 vector fits into the scratch buffers
 * @retval 0 vector is too big
 */
static int
aead_size_check(const struct aead_test *v)
{
        if (v->tagSize > (MAX_TAG_SIZE * 8) || v->msgSize > (MAX_TEXT_SIZE * 8)) {
                print_aead_test(v);
                return 0;
        }
        return 1;
}

static void
test_aead_gcm(IMB_MGR *p_mgr, const struct aead_test *vectors, struct test_suite_context *ts)
{
        const struct aead_test *v;
        struct gcm_key_data gcm_key;
        struct gcm_context_data ctx;
        uint8_t text[MAX_TEXT_SIZE], tag[MAX_TAG_SIZE];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (v = vectors; v->msg != NULL; v++) {
                vector_progress(v->tcId);

                if (!aead_size_check(v)) {
                        test_suite_update(ts, 0, 1);
                        continue;
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
                        printf("Invalid key size: %u bytes!\n", (unsigned) v->keySize / 8);
                        print_aead_test(v);
                        test_suite_update(ts, 0, 1);
                        continue;
                }

                /* test JOB API - encrypt */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

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

                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 1))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);

                /* test JOB API - decrypt */
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

                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 0))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);

                /* test direct API - encrypt */
                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));
                memset(&ctx, 0, sizeof(ctx));
                errno_reset();

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx, (const void *) v->iv,
                                                   v->ivSize / 8, (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        /* context is only usable when init succeeded */
                        if (err_code == 0) {
                                IMB_AES128_GCM_ENC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                          (const void *) v->msg, v->msgSize / 8);
                                errno_update(p_mgr);
                                IMB_AES128_GCM_ENC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                            v->tagSize / 8);
                                errno_update(p_mgr);
                        }
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx, (const void *) v->iv,
                                                   v->ivSize / 8, (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        if (err_code == 0) {
                                IMB_AES192_GCM_ENC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                          (const void *) v->msg, v->msgSize / 8);
                                errno_update(p_mgr);
                                IMB_AES192_GCM_ENC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                            v->tagSize / 8);
                                errno_update(p_mgr);
                        }
                        break;
                default:
                        IMB_AES256_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx, (const void *) v->iv,
                                                   v->ivSize / 8, (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        if (err_code == 0) {
                                IMB_AES256_GCM_ENC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                          (const void *) v->msg, v->msgSize / 8);
                                errno_update(p_mgr);
                                IMB_AES256_GCM_ENC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                            v->tagSize / 8);
                                errno_update(p_mgr);
                        }
                        break;
                }

                if (!aead_submit_and_check(p_mgr, v, tag, text, 0, 1))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);

                /* test direct API - decrypt */
                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));
                memset(&ctx, 0, sizeof(ctx));
                errno_reset();

                switch (v->keySize / 8) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx, (const void *) v->iv,
                                                   v->ivSize / 8, (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        if (err_code == 0) {
                                IMB_AES128_GCM_DEC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                          (const void *) v->ct, v->msgSize / 8);
                                errno_update(p_mgr);
                                IMB_AES128_GCM_DEC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                            v->tagSize / 8);
                                errno_update(p_mgr);
                        }
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx, (const void *) v->iv,
                                                   v->ivSize / 8, (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        if (err_code == 0) {
                                IMB_AES192_GCM_DEC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                          (const void *) v->ct, v->msgSize / 8);
                                errno_update(p_mgr);
                                IMB_AES192_GCM_DEC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                            v->tagSize / 8);
                                errno_update(p_mgr);
                        }
                        break;
                default:
                        IMB_AES256_GCM_INIT_VAR_IV(p_mgr, &gcm_key, &ctx, (const void *) v->iv,
                                                   v->ivSize / 8, (const void *) v->aad,
                                                   v->aadSize / 8);
                        errno_update(p_mgr);
                        if (err_code == 0) {
                                IMB_AES256_GCM_DEC_UPDATE(p_mgr, &gcm_key, &ctx, text,
                                                          (const void *) v->ct, v->msgSize / 8);
                                errno_update(p_mgr);
                                IMB_AES256_GCM_DEC_FINALIZE(p_mgr, &gcm_key, &ctx, tag,
                                                            v->tagSize / 8);
                                errno_update(p_mgr);
                        }
                        break;
                }

                if (!aead_submit_and_check(p_mgr, v, tag, text, 0, 0))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);
        }
}

static void
test_aead_chacha20_poly1305(IMB_MGR *p_mgr, const struct aead_test *vectors,
                            struct test_suite_context *ts)
{
        const struct aead_test *v;
        struct chacha20_poly1305_context_data ctx;
        uint8_t text[MAX_TEXT_SIZE], tag[MAX_TAG_SIZE];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (v = vectors; v->msg != NULL; v++) {
                vector_progress(v->tcId);

                if (!aead_size_check(v)) {
                        test_suite_update(ts, 0, 1);
                        continue;
                }

                /* test JOB API - encrypt */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

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

                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 1))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);

                /* test JOB API - decrypt */
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

                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 0))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);

                /*
                 * The direct API takes a fixed size 12 byte nonce and offers no
                 * IV length argument, so it cannot detect and reject vectors
                 * carrying a different nonce size.
                 */
                if (v->ivSize != (IMB_CHACHA20_POLY1305_IV_SIZE * 8)) {
                        skip_note_add("API requires 12 byte nonce (no nonce length argument)");
                        continue;
                }

                /* test direct API - encrypt */
                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));
                memset(&ctx, 0, sizeof(ctx));
                errno_reset();

                IMB_CHACHA20_POLY1305_INIT(p_mgr, (const void *) v->key, &ctx, (const void *) v->iv,
                                           (const void *) v->aad, v->aadSize / 8);
                errno_update(p_mgr);
                /* context is only usable when init succeeded */
                if (err_code == 0) {
                        IMB_CHACHA20_POLY1305_ENC_UPDATE(p_mgr, (const void *) v->key, &ctx, text,
                                                         (const void *) v->msg, v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_CHACHA20_POLY1305_ENC_FINALIZE(p_mgr, &ctx, tag, v->tagSize / 8);
                        errno_update(p_mgr);
                }

                if (!aead_submit_and_check(p_mgr, v, tag, text, 0, 1))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);

                /* test direct API - decrypt */
                memset(text, 0, sizeof(text));
                memset(tag, 0, sizeof(tag));
                memset(&ctx, 0, sizeof(ctx));
                errno_reset();

                IMB_CHACHA20_POLY1305_INIT(p_mgr, (const void *) v->key, &ctx, (const void *) v->iv,
                                           (const void *) v->aad, v->aadSize / 8);
                errno_update(p_mgr);
                if (err_code == 0) {
                        IMB_CHACHA20_POLY1305_DEC_UPDATE(p_mgr, (const void *) v->key, &ctx, text,
                                                         (const void *) v->ct, v->msgSize / 8);
                        errno_update(p_mgr);
                        IMB_CHACHA20_POLY1305_DEC_FINALIZE(p_mgr, &ctx, tag, v->tagSize / 8);
                        errno_update(p_mgr);
                }

                if (!aead_submit_and_check(p_mgr, v, tag, text, 0, 0))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);
        }
}

static void
test_aead_ccm(IMB_MGR *p_mgr, const struct aead_test *vectors, struct test_suite_context *ts)
{
        const struct aead_test *v;
        DECLARE_ALIGNED(uint32_t expkey[4 * 15], 16);
        DECLARE_ALIGNED(uint32_t dust[4 * 15], 16);
        uint8_t text[MAX_TEXT_SIZE], tag[MAX_TAG_SIZE];

        while (IMB_FLUSH_JOB(p_mgr) != NULL)
                ;

        for (v = vectors; v->msg != NULL; v++) {
                vector_progress(v->tcId);

                if (!aead_size_check(v)) {
                        test_suite_update(ts, 0, 1);
                        continue;
                }

                if ((v->aadSize / 8) > CCM_MAX_AAD_SIZE) {
                        skip_note_add("AES-CCM AAD > 46 bytes not supported");
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
                        skip_note_add("AES-CCM-192 not supported");
                        continue;
                default:
                        printf("Invalid key size: %u bytes!\n", (unsigned) v->keySize / 8);
                        print_aead_test(v);
                        test_suite_update(ts, 0, 1);
                        continue;
                }

                /* test JOB API - encrypt */
                IMB_JOB *job = IMB_GET_NEXT_JOB(p_mgr);

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

                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 1))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);

                /* test JOB API - decrypt */
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

                if (!aead_submit_and_check(p_mgr, v, tag, text, 1, 0))
                        test_suite_update(ts, 0, 1);
                else
                        test_suite_update(ts, 1, 0);
        }
}

/*
 * =============================================================================
 * TEST DRIVER
 * =============================================================================
 */

enum vector_kind { VECTOR_KIND_MAC, VECTOR_KIND_AEAD };

struct wycheproof_suite {
        const char *name;
        const char *file_name;
        enum vector_kind kind;
        void (*mac_fn)(IMB_MGR *, const struct mac_test *, struct test_suite_context *);
        void (*aead_fn)(IMB_MGR *, const struct aead_test *, struct test_suite_context *);
};

static void
test_hmac_sha1(IMB_MGR *p_mgr, const struct mac_test *v, struct test_suite_context *ts)
{
        test_hmac(p_mgr, v, ts, IMB_AUTH_HMAC_SHA_1, IMB_SHA1_DIGEST_SIZE_IN_BYTES, 1,
                  "HMAC-SHA1 msgSize=0 not supported");
}

static void
test_hmac_sha224(IMB_MGR *p_mgr, const struct mac_test *v, struct test_suite_context *ts)
{
        test_hmac(p_mgr, v, ts, IMB_AUTH_HMAC_SHA_224, IMB_SHA224_DIGEST_SIZE_IN_BYTES, 0,
                  "HMAC-SHA224 msgSize=0 not supported");
}

static void
test_hmac_sha256(IMB_MGR *p_mgr, const struct mac_test *v, struct test_suite_context *ts)
{
        test_hmac(p_mgr, v, ts, IMB_AUTH_HMAC_SHA_256, IMB_SHA256_DIGEST_SIZE_IN_BYTES, 0,
                  "HMAC-SHA256 msgSize=0 not supported");
}

static void
test_hmac_sha384(IMB_MGR *p_mgr, const struct mac_test *v, struct test_suite_context *ts)
{
        test_hmac(p_mgr, v, ts, IMB_AUTH_HMAC_SHA_384, IMB_SHA384_DIGEST_SIZE_IN_BYTES, 0,
                  "HMAC-SHA384 msgSize=0 not supported");
}

static void
test_hmac_sha512(IMB_MGR *p_mgr, const struct mac_test *v, struct test_suite_context *ts)
{
        test_hmac(p_mgr, v, ts, IMB_AUTH_HMAC_SHA_512, IMB_SHA512_DIGEST_SIZE_IN_BYTES, 0,
                  "HMAC-SHA512 msgSize=0 not supported");
}

static int
run_suite(IMB_MGR *mb_mgr, const struct wycheproof_suite *s)
{
        struct test_json_alloc_ctx *jctx = NULL;
        struct mac_test *mac_vectors = NULL;
        struct aead_test *aead_vectors = NULL;
        struct test_suite_context ts;

        test_suite_start(&ts, s->name);

        err_code = 0;
        num_skip_notes = 0;

        if (!quiet_mode)
                printf("%s test vectors:\n", s->name);

        if (s->kind == VECTOR_KIND_MAC) {
                if (load_mac_vectors(kat_vector_dir, s->file_name, &mac_vectors, &jctx) < 0) {
                        test_suite_update(&ts, 0, 1);
                        return test_suite_end(&ts);
                }
                s->mac_fn(mb_mgr, mac_vectors, &ts);
        } else {
                if (load_aead_vectors(kat_vector_dir, s->file_name, &aead_vectors, &jctx) < 0) {
                        test_suite_update(&ts, 0, 1);
                        return test_suite_end(&ts);
                }
                s->aead_fn(mb_mgr, aead_vectors, &ts);
        }

        if (!quiet_mode) {
                printf("\n");
                skip_notes_print();
        }

        json_free_test_ctx(jctx);

        return test_suite_end(&ts);
}

int
wycheproof_gcm_test(IMB_MGR *mb_mgr)
{
        static const struct wycheproof_suite s = { "AES-GCM Wycheproof", "wycheproof_gcm_test.json",
                                                   VECTOR_KIND_AEAD, NULL, test_aead_gcm };

        return run_suite(mb_mgr, &s);
}

int
wycheproof_ccm_test(IMB_MGR *mb_mgr)
{
        static const struct wycheproof_suite s = { "AES-CCM Wycheproof", "wycheproof_ccm_test.json",
                                                   VECTOR_KIND_AEAD, NULL, test_aead_ccm };

        return run_suite(mb_mgr, &s);
}

int
wycheproof_chacha20_poly1305_test(IMB_MGR *mb_mgr)
{
        static const struct wycheproof_suite s = { "CHACHA20-POLY1305 Wycheproof",
                                                   "wycheproof_chacha20_poly1305_test.json",
                                                   VECTOR_KIND_AEAD, NULL,
                                                   test_aead_chacha20_poly1305 };

        return run_suite(mb_mgr, &s);
}

int
wycheproof_cmac_test(IMB_MGR *mb_mgr)
{
        static const struct wycheproof_suite s = { "AES-CMAC Wycheproof",
                                                   "wycheproof_cmac_test.json", VECTOR_KIND_MAC,
                                                   test_cmac, NULL };

        return run_suite(mb_mgr, &s);
}

int
wycheproof_gmac_test(IMB_MGR *mb_mgr)
{
        static const struct wycheproof_suite s = { "AES-GMAC Wycheproof",
                                                   "wycheproof_gmac_test.json", VECTOR_KIND_MAC,
                                                   test_gmac, NULL };

        return run_suite(mb_mgr, &s);
}

int
wycheproof_hmac_sha1_test(IMB_MGR *mb_mgr)
{
        static const struct wycheproof_suite s = { "HMAC-SHA1 Wycheproof",
                                                   "wycheproof_hmac_sha1_test.json",
                                                   VECTOR_KIND_MAC, test_hmac_sha1, NULL };

        return run_suite(mb_mgr, &s);
}

int
wycheproof_hmac_sha224_test(IMB_MGR *mb_mgr)
{
        static const struct wycheproof_suite s = { "HMAC-SHA224 Wycheproof",
                                                   "wycheproof_hmac_sha224_test.json",
                                                   VECTOR_KIND_MAC, test_hmac_sha224, NULL };

        return run_suite(mb_mgr, &s);
}

int
wycheproof_hmac_sha256_test(IMB_MGR *mb_mgr)
{
        static const struct wycheproof_suite s = { "HMAC-SHA256 Wycheproof",
                                                   "wycheproof_hmac_sha256_test.json",
                                                   VECTOR_KIND_MAC, test_hmac_sha256, NULL };

        return run_suite(mb_mgr, &s);
}

int
wycheproof_hmac_sha384_test(IMB_MGR *mb_mgr)
{
        static const struct wycheproof_suite s = { "HMAC-SHA384 Wycheproof",
                                                   "wycheproof_hmac_sha384_test.json",
                                                   VECTOR_KIND_MAC, test_hmac_sha384, NULL };

        return run_suite(mb_mgr, &s);
}

int
wycheproof_hmac_sha512_test(IMB_MGR *mb_mgr)
{
        static const struct wycheproof_suite s = { "HMAC-SHA512 Wycheproof",
                                                   "wycheproof_hmac_sha512_test.json",
                                                   VECTOR_KIND_MAC, test_hmac_sha512, NULL };

        return run_suite(mb_mgr, &s);
}
