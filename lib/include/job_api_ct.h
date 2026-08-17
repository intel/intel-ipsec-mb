/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef JOB_API_CT_H
#define JOB_API_CT_H

#include "intel-ipsec-mb.h"
#include "include/imb_ct.h"

#define SECRET_MARK   1
#define SECRET_UNMARK 0

/*
 * Constant-time (CT) validation hooks for the JOB API.
 *
 * Classification used:
 *
 *   secret : cipher key schedule (enc_keys / dec_keys), AEAD hash sub-keys,
 *            HMAC ipad/opad key state, the plain text of an encrypt operation
 *            and the message of a keyed MAC-only job
 *   public : IV / nonce, AAD, all lengths and offsets, and - after completion -
 *            the cipher text and the authentication tag
 *
 * These helpers mark the secret inputs of a job before it is handed to the
 * processing routines, and release the intentionally-public outputs
 * once the job has completed.
 *
 * Secrets are marked on submission and released when the job is returned to
 * the application, so the poisoned window is exactly the job.
 *
 * Scope: this first phase covers the JOB API only and within the API it covers the
 * AEAD algorithms (i.e. AES-GCM, AES-CCM, SM4-GCM or ChaCha20-Poly1305), the keyed
 * authentication algorithms (i.e. HMAC, AES-GMAC, GHASH, AES-CMAC, AES-XCBC,
 * Poly1305 or SNOW3G-UIA2) plus the cipher modes (i.e. AES-CBC, AES-CTR, AES-ECB,
 * AES-CFB, DOCSIS-SEC BPI, DES/3DES, SM4, ZUC, SNOW3G, SNOW5G or KASUMI).
 * The unkeyed digests and the CRCs have no key to mark.
 * Modes not listed in the switches below deliberately fall through without key
 * marking; their key schedules have algorithm-specific layouts that need to be
 * added individually.
 */
#ifdef IMB_CONSTANT_TIME_VALIDATION

/**
 * @brief Returns the size in bytes of an expanded AES key schedule
 *
 * @param key_len_in_bytes raw AES key length (16, 24 or 32 bytes)
 *
 * @return expanded key schedule size in bytes, 0 if key length not recognized
 */
static inline uint64_t
imb_ct_aes_exp_key_size(const uint64_t key_len_in_bytes)
{
        switch (key_len_in_bytes) {
        case IMB_KEY_128_BYTES:
                return 11 * 16; /* 11 AES rounds */
        case IMB_KEY_192_BYTES:
                return 13 * 16; /* 13 AES rounds */
        case IMB_KEY_256_BYTES:
                return 15 * 16; /* 15 AES rounds */
        default:
                return 0;
        }
}

/**
 * @brief Tells whether a job carries its message data as an SGL descriptor list
 *
 * The SGL cipher modes come in two flavours.  In the context based flavour
 * (sgl_state INIT / UPDATE / COMPLETE) the message is passed through the plain
 * src / dst pointers, one segment per job.  Only in the IMB_SGL_ALL flavour do
 * the src / dst unions instead hold a pointer to an array of IMB_SGL_IOV
 * descriptors and the number of segments, in which case the message data has
 * to be walked segment by segment.
 *
 * @param job pointer to job
 *
 * @return SGL descriptor use status
 * @retval 1 job uses an SGL descriptor list
 * @retval 0 job doesn't use SGL descriptor
 */
static inline int
imb_ct_job_is_sgl(const IMB_JOB *job)
{
        if (job == NULL)
                return 0;

        if (job->cipher_mode == IMB_CIPHER_GCM_SGL ||
            job->cipher_mode == IMB_CIPHER_CHACHA20_POLY1305_SGL)
                return (job->sgl_state == IMB_SGL_ALL);

        return 0;
}

/**
 * @brief Returns the size in bytes of the HMAC ipad/opad key state
 *
 * For the SHA-1 and SHA-2 family the application passes the intermediate hash
 * state produced from the padded key, so the size is that of the algorithm
 * state and not of the truncated digest: SHA-224 shares the SHA-256 state and
 * SHA-384 shares the SHA-512 state.  The SHA-3 variants have no intermediate
 * state, the padded key block itself is passed, so there the size is the block
 * size.
 *
 * @param hash_alg hash algorithm of the job
 *
 * @return ipad/opad buffer size in bytes, 0 if the algorithm is not HMAC
 */
static inline uint64_t
imb_ct_hmac_state_size(const IMB_HASH_ALG hash_alg)
{
        switch (hash_alg) {
        case IMB_AUTH_MD5:
                return IMB_MD5_DIGEST_SIZE_IN_BYTES;
        case IMB_AUTH_HMAC_SHA_1:
                return IMB_SHA1_DIGEST_SIZE_IN_BYTES;
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
                return IMB_SHA256_DIGEST_SIZE_IN_BYTES;
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
                return IMB_SHA512_DIGEST_SIZE_IN_BYTES;
        case IMB_AUTH_HMAC_SM3:
                return IMB_SM3_DIGEST_SIZE;
        case IMB_AUTH_HMAC_SHA3_224:
                return IMB_SHA3_224_BLOCK_SIZE;
        case IMB_AUTH_HMAC_SHA3_256:
                return IMB_SHA3_256_BLOCK_SIZE;
        case IMB_AUTH_HMAC_SHA3_384:
                return IMB_SHA3_384_BLOCK_SIZE;
        case IMB_AUTH_HMAC_SHA3_512:
                return IMB_SHA3_512_BLOCK_SIZE;
        default:
                return 0;
        }
}

/**
 * @brief Applies the requested marking to every piece of key material
 *
 * The same set of regions has to be marked secret on submission and released
 * on completion, so the walk is written once: the regions are collected first
 * and the direction of the marking is applied to all of them at the end.
 *
 * @param job    pointer to job
 * @param secret non-zero to mark the key material secret, 0 to release it
 */
static inline void
imb_ct_job_mark_keys(const IMB_JOB *job, const int secret)
{
        if (job == NULL)
                return;

        /* cipher key schedule */
        switch (job->cipher_mode) {
        case IMB_CIPHER_GCM:
        case IMB_CIPHER_GCM_SGL:
        case IMB_CIPHER_SM4_GCM:
                /*
                 * AES-GCM and SM4-GCM both expand into struct gcm_key_data,
                 * which holds the round keys and the pre-computed GHASH
                 * sub-key powers.  Fixed size, so no per-architecture logic.
                 */
                imb_ct_secret(job->enc_keys, sizeof(struct gcm_key_data), secret);
                break;
        case IMB_CIPHER_CHACHA20_POLY1305:
        case IMB_CIPHER_CHACHA20_POLY1305_SGL:
        case IMB_CIPHER_CHACHA20:
                /* ChaCha20 uses the raw 256-bit key, there is no expansion */
                imb_ct_secret(job->enc_keys, job->key_len_in_bytes, secret);
                break;
        case IMB_CIPHER_CCM:
        case IMB_CIPHER_CNTR:
        case IMB_CIPHER_ECB:
        case IMB_CIPHER_CFB:
                /* CTR/ECB/CCM/CFB only ever use the encrypt key schedule */
                imb_ct_secret(job->enc_keys, imb_ct_aes_exp_key_size(job->key_len_in_bytes),
                              secret);
                break;
        case IMB_CIPHER_PON_AES_CNTR:
                if (job->msg_len_to_cipher_in_bytes > 0) {
                        /* In no encryption mode message length is 0 */
                        imb_ct_secret(job->enc_keys, imb_ct_aes_exp_key_size(job->key_len_in_bytes),
                                      secret);
                }
                break;
        case IMB_CIPHER_CBC:
        case IMB_CIPHER_DOCSIS_SEC_BPI:
        case IMB_CIPHER_AES_NEA5:
        case IMB_CIPHER_AES_NCA5:
                imb_ct_secret(job->enc_keys, imb_ct_aes_exp_key_size(job->key_len_in_bytes),
                              secret);
                imb_ct_secret(job->dec_keys, imb_ct_aes_exp_key_size(job->key_len_in_bytes),
                              secret);
                break;
        case IMB_CIPHER_SNOW3G_UEA2:
                imb_ct_secret(job->enc_keys, sizeof(snow3g_key_schedule_t), secret);
                break;
        case IMB_CIPHER_SNOW5G_NEA4:
        case IMB_CIPHER_SNOW5G_NCA4:
        case IMB_CIPHER_ZUC_EEA3:
        case IMB_CIPHER_ZUC_NEA6:
        case IMB_CIPHER_ZUC_NCA6:
                imb_ct_secret(job->enc_keys, job->key_len_in_bytes, secret);
                break;
        case IMB_CIPHER_KASUMI_UEA1:
                imb_ct_secret(job->enc_keys, IMB_KASUMI_KEY_SIZE, secret);
                break;
        case IMB_CIPHER_DES:
        case IMB_CIPHER_DOCSIS_DES:
                imb_ct_secret(job->enc_keys, IMB_DES_KEY_SCHED_SIZE, secret);
                imb_ct_secret(job->dec_keys, IMB_DES_KEY_SCHED_SIZE, secret);
                break;
        case IMB_CIPHER_DES3:
                if (job->enc_keys != NULL) {
                        const void *const *ks = (const void *const *) job->enc_keys;

                        imb_ct_secret(ks[0], IMB_DES_KEY_SCHED_SIZE, secret);
                        imb_ct_secret(ks[1], IMB_DES_KEY_SCHED_SIZE, secret);
                        imb_ct_secret(ks[2], IMB_DES_KEY_SCHED_SIZE, secret);
                }
                if (job->dec_keys != NULL) {
                        const void *const *ks = (const void *const *) job->dec_keys;

                        imb_ct_secret(ks[0], IMB_DES_KEY_SCHED_SIZE, secret);
                        imb_ct_secret(ks[1], IMB_DES_KEY_SCHED_SIZE, secret);
                        imb_ct_secret(ks[2], IMB_DES_KEY_SCHED_SIZE, secret);
                }
                break;
        case IMB_CIPHER_SM4_ECB:
        case IMB_CIPHER_SM4_CBC:
        case IMB_CIPHER_SM4_CTR:
                imb_ct_secret(job->enc_keys, IMB_SM4_KEY_SCHEDULE_ROUNDS * sizeof(uint32_t),
                              secret);
                imb_ct_secret(job->dec_keys, IMB_SM4_KEY_SCHEDULE_ROUNDS * sizeof(uint32_t),
                              secret);
                break;
        default:
                /* key schedule layout not yet described - see note above */
                break;
        }

        /* authentication key material */
        switch (job->hash_alg) {
        case IMB_AUTH_AES_GMAC_128:
        case IMB_AUTH_AES_GMAC_192:
        case IMB_AUTH_AES_GMAC_256:
                imb_ct_secret(job->u.GMAC._key, sizeof(struct gcm_key_data), secret);
                break;
        case IMB_AUTH_MD5:
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
        case IMB_AUTH_HMAC_SM3:
        case IMB_AUTH_HMAC_SHA3_224:
        case IMB_AUTH_HMAC_SHA3_256:
        case IMB_AUTH_HMAC_SHA3_384:
        case IMB_AUTH_HMAC_SHA3_512: {
                const uint64_t sz = imb_ct_hmac_state_size(job->hash_alg);

                imb_ct_secret(job->u.HMAC._hashed_auth_key_xor_ipad, sz, secret);
                imb_ct_secret(job->u.HMAC._hashed_auth_key_xor_opad, sz, secret);
                break;
        }
        case IMB_AUTH_GHASH:
                imb_ct_secret(job->u.GHASH._key, sizeof(struct gcm_key_data), secret);
                break;
        case IMB_AUTH_POLY1305:
                /* Poly1305 one-time key: 16-byte r followed by 16-byte s */
                imb_ct_secret(job->u.POLY1305._key, 32, secret);
                break;
        case IMB_AUTH_AES_XCBC:
                imb_ct_secret(job->u.XCBC._k1_expanded, imb_ct_aes_exp_key_size(IMB_KEY_128_BYTES),
                              secret);
                imb_ct_secret(job->u.XCBC._k2, 16, secret);
                imb_ct_secret(job->u.XCBC._k3, 16, secret);
                break;
        case IMB_AUTH_AES_CMAC:
                imb_ct_secret(job->u.CMAC._key_expanded, imb_ct_aes_exp_key_size(IMB_KEY_128_BYTES),
                              secret);
                imb_ct_secret(job->u.CMAC._skey1, IMB_KEY_128_BYTES, secret);
                imb_ct_secret(job->u.CMAC._skey2, IMB_KEY_128_BYTES, secret);
                break;
        case IMB_AUTH_AES_CMAC_256:
                imb_ct_secret(job->u.CMAC._key_expanded, imb_ct_aes_exp_key_size(IMB_KEY_256_BYTES),
                              secret);
                imb_ct_secret(job->u.CMAC._skey1, IMB_KEY_256_BYTES, secret);
                imb_ct_secret(job->u.CMAC._skey2, IMB_KEY_256_BYTES, secret);
                break;
        case IMB_AUTH_KASUMI_UIA1:
                imb_ct_secret(job->u.KASUMI_UIA1._key, IMB_KASUMI_KEY_SIZE, secret);
                break;
        case IMB_AUTH_SNOW3G_UIA2:
                imb_ct_secret(job->u.SNOW3G_UIA2._key, sizeof(snow3g_key_schedule_t), secret);
                break;
        case IMB_AUTH_ZUC_EIA3:
                imb_ct_secret(job->u.ZUC_EIA3._key, IMB_ZUC_KEY_LEN_IN_BYTES, secret);
                break;
        case IMB_AUTH_AES_NIA5:
        case IMB_AUTH_AES_NCA5:
                imb_ct_secret(job->u.NIA._key, imb_ct_aes_exp_key_size(IMB_KEY_256_BYTES), secret);
                break;
        case IMB_AUTH_SNOW5G_NIA4:
        case IMB_AUTH_SNOW5G_NCA4:
        case IMB_AUTH_ZUC_NIA6:
        case IMB_AUTH_ZUC_NCA6:
                imb_ct_secret(job->u.NIA._key, 32, secret);
                break;
        default:
                break;
        }
}

/**
 * @brief Applies the requested marking to the message data referenced by a job
 *
 * Only the plain text side is handled here. On encrypt that is the source
 * buffer; on decrypt the source holds cipher text, which is already public, and
 * the recovered plain text lands in the destination buffer instead.
 *
 * As with the key material this is symmetric: the source buffer belongs to the
 * application and is routinely reused across calls, so it has to be marked
 * as non-secret when the job completes.
 *
 * @param job    pointer to job
 * @param secret non-zero to mark the message data secret, 0 to release it
 */
static inline void
imb_ct_job_mark_src(const IMB_JOB *job, const int secret)
{
        if (job == NULL)
                return;

        if (job->cipher_direction != IMB_DIR_ENCRYPT || job->cipher_mode == IMB_CIPHER_NULL)
                return;

        if (imb_ct_job_is_sgl(job)) {
                /*
                 * SGL job: src is an array of descriptors, dst is a segment
                 * count.  Only the payload of each segment is secret - the
                 * descriptors themselves (pointers and lengths) are public.
                 */
                const struct IMB_SGL_IOV *segs = job->sgl_io_segs;

                if (segs == NULL)
                        return;

                for (uint64_t i = 0; i < job->num_sgl_io_segs; i++)
                        imb_ct_secret(segs[i].in, segs[i].len, secret);
        } else {
                const void *p = job->src + job->cipher_start_src_offset_in_bytes;

                imb_ct_secret(p, job->msg_len_to_cipher_in_bytes, secret);
        }
}

/**
 * @brief Tells whether the message authenticated by a job is to be treated as
 *        secret
 *
 * Unlike the cipher case, the authenticated message is not secret by default.
 * It is only marked for the keyed MAC algorithms, where the message is user
 * plane data that the MAC is protecting.  Three families are deliberately left
 * out:
 *
 *   - the unkeyed digests (SHA-1, SHA-2, SHA-3, SHAKE, SM3) and the CRCs, which
 *     carry no key and are used over data that is already public,
 *   - the AEAD algorithms, where the authenticated range is the AAD followed by
 *     the cipher text and both are public by construction,
 *   - GMAC and GHASH, which authenticate additional data rather than a payload.
 *
 * @param hash_alg hash algorithm of the job
 *
 * @return message secrecy status
 * @retval 1 the authenticated message is secret
 * @retval 0 the authenticated message is public
 */
static inline int
imb_ct_hash_msg_is_secret(const IMB_HASH_ALG hash_alg)
{
        switch (hash_alg) {
        case IMB_AUTH_MD5:
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
        case IMB_AUTH_HMAC_SM3:
        case IMB_AUTH_HMAC_SHA3_224:
        case IMB_AUTH_HMAC_SHA3_256:
        case IMB_AUTH_HMAC_SHA3_384:
        case IMB_AUTH_HMAC_SHA3_512:
        case IMB_AUTH_AES_XCBC:
        case IMB_AUTH_AES_CMAC:
        case IMB_AUTH_AES_CMAC_256:
        case IMB_AUTH_POLY1305:
        case IMB_AUTH_KASUMI_UIA1:
        case IMB_AUTH_SNOW3G_UIA2:
        case IMB_AUTH_ZUC_EIA3:
        case IMB_AUTH_AES_NIA5:
        case IMB_AUTH_AES_NCA5:
        case IMB_AUTH_SNOW5G_NIA4:
        case IMB_AUTH_SNOW5G_NCA4:
        case IMB_AUTH_ZUC_NIA6:
        case IMB_AUTH_ZUC_NCA6:
                return 1;
        default:
                return 0;
        }
}

/**
 * @brief Applies the requested marking to the message authenticated by a job
 *
 * This is the authentication counterpart of imb_ct_job_mark_src() and it is
 * symmetric in the same way: the buffer belongs to the application, so what is
 * marked on submission has to be released on completion.
 *
 * Only jobs that authenticate without ciphering are considered.  When a cipher
 * is chained with a MAC the authenticated range covers cipher text - on encrypt
 * because the MAC is computed after the cipher, on decrypt because the MAC is
 * verified before it - and cipher text is public.  The plain text of such a job
 * is already handled by imb_ct_job_mark_src().
 *
 * @param job    pointer to job
 * @param secret non-zero to mark the message secret, 0 to release it
 */
static inline void
imb_ct_job_mark_hash_src(const IMB_JOB *job, const int secret)
{
        if (job == NULL)
                return;

        if (job->cipher_mode != IMB_CIPHER_NULL)
                return;

        if (!imb_ct_hash_msg_is_secret(job->hash_alg))
                return;

        imb_ct_secret(job->src + job->hash_start_src_offset_in_bytes, job->msg_len_to_hash_in_bytes,
                      secret);
}

/**
 * @brief Marks the secret inputs of a job as undefined for valgrind memcheck
 *
 * Called on job submission, before the job is passed to the processing
 * routines.
 *
 * @param job pointer to job being submitted
 */
static inline void
imb_ct_job_classify(const IMB_JOB *job)
{
        if (job == NULL)
                return;

        imb_ct_job_mark_keys(job, SECRET_MARK);
        imb_ct_job_mark_src(job, SECRET_MARK);
        imb_ct_job_mark_hash_src(job, SECRET_MARK);
}

/**
 * @brief Releases the public outputs of a completed job
 *
 * Called on every path that returns a completed job to the application.
 *
 * The key material is released here as well, so that the window in which a
 * secret is poisoned is exactly the job that uses it. This matters because
 * the key schedule and the source buffer are owned by the application.
 *
 * @param job pointer to completed job
 */
static inline void
imb_ct_job_declassify(const IMB_JOB *job)
{
        /*
         * Jobs rejected by the argument checks never get classified and
         * their fields cannot be trusted (bad pointers or lengths).
         */
        if (job == NULL || job->status >= IMB_STATUS_INVALID_ARGS)
                return;

        imb_ct_job_mark_keys(job, SECRET_UNMARK);
        imb_ct_job_mark_src(job, SECRET_UNMARK);
        imb_ct_job_mark_hash_src(job, SECRET_UNMARK);

        /*
         * Destination buffer or tag output are never set as secret but
         * they become undefined because they are written to during computation
         * with poisoned key and source buffer.
         * They need to marked as public to avoid any potential false positives
         * at application level, i.e. memory compare operation.
         */
        if (imb_ct_job_is_sgl(job)) {
                const struct IMB_SGL_IOV *segs = job->sgl_io_segs;

                if (segs != NULL) {
                        for (uint64_t i = 0; i < job->num_sgl_io_segs; i++)
                                imb_ct_secret(segs[i].out, segs[i].len, SECRET_UNMARK);
                }
        } else {
                imb_ct_secret(job->dst, job->msg_len_to_cipher_in_bytes, SECRET_UNMARK);
        }

        imb_ct_secret(job->auth_tag_output, job->auth_tag_output_len_in_bytes, SECRET_UNMARK);
}

#else /* IMB_CONSTANT_TIME_VALIDATION */

static inline void
imb_ct_job_classify(const IMB_JOB *job)
{
        (void) job;
}

static inline void
imb_ct_job_declassify(const IMB_JOB *job)
{
        (void) job;
}

#endif /* IMB_CONSTANT_TIME_VALIDATION */

#endif /* JOB_API_CT_H */
