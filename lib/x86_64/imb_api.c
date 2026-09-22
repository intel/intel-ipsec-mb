/*******************************************************************************
  Copyright (c) 2024-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <stdint.h>
#include <stddef.h>
#include "intel-ipsec-mb.h"
#include "mb_mgr.h"
#include "error.h"

IMB_DLL_EXPORT int
imb_get_features(IMB_MGR *mb_mgr, uint64_t *p_features)
{
        if (mb_mgr == NULL || p_features == NULL)
                return EINVAL;

        *p_features = mb_mgr->features;
        return 0;
}

IMB_DLL_EXPORT int
imb_get_flags(IMB_MGR *mb_mgr, uint64_t *p_flags)
{
        if (mb_mgr == NULL || p_flags == NULL)
                return EINVAL;

        *p_flags = mb_mgr->flags;
        return 0;
}

IMB_DLL_EXPORT IMB_JOB *
imb_submit_job(IMB_MGR *state)
{
        return CALL_SUBMIT_JOB(state);
}

IMB_DLL_EXPORT IMB_JOB *
imb_submit_job_nocheck(IMB_MGR *state)
{
        return CALL_SUBMIT_JOB_NOCHECK(state);
}

IMB_DLL_EXPORT IMB_JOB *
imb_flush_job(IMB_MGR *state)
{
        return CALL_FLUSH_JOB(state);
}

IMB_DLL_EXPORT uint32_t
imb_queue_size(IMB_MGR *state)
{
        return CALL_QUEUE_SIZE(state);
}

IMB_DLL_EXPORT IMB_JOB *
imb_get_completed_job(IMB_MGR *state)
{
        return CALL_GET_COMPLETED_JOB(state);
}

IMB_DLL_EXPORT IMB_JOB *
imb_get_next_job(IMB_MGR *state)
{
        return CALL_GET_NEXT_JOB(state);
}

IMB_DLL_EXPORT uint32_t
imb_get_next_burst(IMB_MGR *state, const uint32_t n_jobs, struct IMB_JOB **p_jobs)
{
        return CALL_GET_NEXT_BURST(state, n_jobs, p_jobs);
}

IMB_DLL_EXPORT uint32_t
imb_submit_burst(IMB_MGR *state, const uint32_t n_jobs, struct IMB_JOB **p_jobs)
{
        return CALL_SUBMIT_BURST(state, n_jobs, p_jobs);
}

IMB_DLL_EXPORT uint32_t
imb_submit_burst_nocheck(IMB_MGR *state, const uint32_t n_jobs, struct IMB_JOB **p_jobs)
{
        return CALL_SUBMIT_BURST_NOCHECK(state, n_jobs, p_jobs);
}

IMB_DLL_EXPORT uint32_t
imb_flush_burst(IMB_MGR *state, const uint32_t n_jobs, struct IMB_JOB **p_jobs)
{
        return CALL_FLUSH_BURST(state, n_jobs, p_jobs);
}

IMB_DLL_EXPORT uint32_t
imb_submit_cipher_burst(IMB_MGR *state, struct IMB_JOB *p_jobs, const uint32_t n_jobs,
                        const IMB_CIPHER_MODE cipher, const IMB_CIPHER_DIRECTION dir,
                        const IMB_KEY_SIZE_BYTES key_size)
{
        return CALL_SUBMIT_CIPHER_BURST(state, p_jobs, n_jobs, cipher, dir, key_size);
}

IMB_DLL_EXPORT uint32_t
imb_submit_cipher_burst_nocheck(IMB_MGR *state, struct IMB_JOB *p_jobs, const uint32_t n_jobs,
                                const IMB_CIPHER_MODE cipher, const IMB_CIPHER_DIRECTION dir,
                                const IMB_KEY_SIZE_BYTES key_size)
{
        return CALL_SUBMIT_CIPHER_BURST_NOCHECK(state, p_jobs, n_jobs, cipher, dir, key_size);
}

IMB_DLL_EXPORT uint32_t
imb_submit_hash_burst(IMB_MGR *state, struct IMB_JOB *p_jobs, const uint32_t n_jobs,
                      const IMB_HASH_ALG hash)
{
        return CALL_SUBMIT_HASH_BURST(state, p_jobs, n_jobs, hash);
}

IMB_DLL_EXPORT uint32_t
imb_submit_hash_burst_nocheck(IMB_MGR *state, struct IMB_JOB *p_jobs, const uint32_t n_jobs,
                              const IMB_HASH_ALG hash)
{
        return CALL_SUBMIT_HASH_BURST_NOCHECK(state, p_jobs, n_jobs, hash);
}

IMB_DLL_EXPORT uint32_t
imb_submit_aead_burst(IMB_MGR *state, struct IMB_JOB *p_jobs, const uint32_t n_jobs,
                      const IMB_CIPHER_MODE cipher, const IMB_CIPHER_DIRECTION dir,
                      const IMB_KEY_SIZE_BYTES key_size)
{
        return CALL_SUBMIT_AEAD_BURST(state, p_jobs, n_jobs, cipher, dir, key_size);
}

IMB_DLL_EXPORT uint32_t
imb_submit_aead_burst_nocheck(IMB_MGR *state, struct IMB_JOB *p_jobs, const uint32_t n_jobs,
                              const IMB_CIPHER_MODE cipher, const IMB_CIPHER_DIRECTION dir,
                              const IMB_KEY_SIZE_BYTES key_size)
{
        return CALL_SUBMIT_AEAD_BURST_NOCHECK(state, p_jobs, n_jobs, cipher, dir, key_size);
}

IMB_DLL_EXPORT void
imb_aes_keyexp_128(const void *key, void *enc_exp_key, void *dec_exp_key, IMB_MGR *state)
{
        CALL_AES_KEYEXP_128(state, key, enc_exp_key, dec_exp_key);
}

IMB_DLL_EXPORT void
imb_aes_keyexp_192(const void *key, void *enc_exp_key, void *dec_exp_key, IMB_MGR *state)
{
        CALL_AES_KEYEXP_192(state, key, enc_exp_key, dec_exp_key);
}

IMB_DLL_EXPORT void
imb_aes_keyexp_256(const void *key, void *enc_exp_key, void *dec_exp_key, IMB_MGR *state)
{
        CALL_AES_KEYEXP_256(state, key, enc_exp_key, dec_exp_key);
}

IMB_DLL_EXPORT void
imb_aes_cmac_subkey_gen_128(const void *enc_exp_key, void *key1, void *key2, IMB_MGR *state)
{
        CALL_AES_CMAC_SUBKEY_GEN_128(state, enc_exp_key, key1, key2);
}

IMB_DLL_EXPORT void
imb_aes_cmac_subkey_gen_256(const void *enc_exp_key, void *key1, void *key2, IMB_MGR *state)
{
        CALL_AES_CMAC_SUBKEY_GEN_256(state, enc_exp_key, key1, key2);
}

IMB_DLL_EXPORT void
imb_aes_xcbc_keyexp(const void *key, void *exp_key1, void *exp_key2, void *exp_key3, IMB_MGR *state)
{
        CALL_AES_XCBC_KEYEXP(state, key, exp_key1, exp_key2, exp_key3);
}

IMB_DLL_EXPORT void
imb_des_keysched(uint64_t *ks, const void *key, IMB_MGR *state)
{
        CALL_DES_KEYSCHED(state, ks, key);
}

IMB_DLL_EXPORT void
imb_sha1_one_block(const void *src, void *digest, IMB_MGR *state)
{
        CALL_SHA1_ONE_BLOCK(state, src, digest);
}

IMB_DLL_EXPORT void
imb_sha224_one_block(const void *src, void *digest, IMB_MGR *state)
{
        CALL_SHA224_ONE_BLOCK(state, src, digest);
}

IMB_DLL_EXPORT void
imb_sha256_one_block(const void *src, void *digest, IMB_MGR *state)
{
        CALL_SHA256_ONE_BLOCK(state, src, digest);
}

IMB_DLL_EXPORT void
imb_sha384_one_block(const void *src, void *digest, IMB_MGR *state)
{
        CALL_SHA384_ONE_BLOCK(state, src, digest);
}

IMB_DLL_EXPORT void
imb_sha512_one_block(const void *src, void *digest, IMB_MGR *state)
{
        CALL_SHA512_ONE_BLOCK(state, src, digest);
}

IMB_DLL_EXPORT void
imb_md5_one_block(const void *src, void *digest, IMB_MGR *state)
{
        CALL_MD5_ONE_BLOCK(state, src, digest);
}

IMB_DLL_EXPORT void
imb_sha1(const void *src, const uint64_t length, void *digest, IMB_MGR *state)
{
        CALL_SHA1(state, src, length, digest);
}

IMB_DLL_EXPORT void
imb_sha224(const void *src, const uint64_t length, void *digest, IMB_MGR *state)
{
        CALL_SHA224(state, src, length, digest);
}

IMB_DLL_EXPORT void
imb_sha256(const void *src, const uint64_t length, void *digest, IMB_MGR *state)
{
        CALL_SHA256(state, src, length, digest);
}

IMB_DLL_EXPORT void
imb_sha384(const void *src, const uint64_t length, void *digest, IMB_MGR *state)
{
        CALL_SHA384(state, src, length, digest);
}

IMB_DLL_EXPORT void
imb_sha512(const void *src, const uint64_t length, void *digest, IMB_MGR *state)
{
        CALL_SHA512(state, src, length, digest);
}

IMB_DLL_EXPORT int
imb_aes128_cfb_one(void *dst, const void *src, const void *iv, const void *enc_exp_key,
                   uint64_t len, IMB_MGR *state)
{
#ifdef SAFE_PARAM
        if (state == NULL)
                return IMB_ERR_NULL_MBMGR;
        if (dst == NULL)
                return IMB_ERR_NULL_DST;
        if (src == NULL)
                return IMB_ERR_NULL_SRC;
        if (iv == NULL)
                return IMB_ERR_NULL_IV;
        if (enc_exp_key == NULL)
                return IMB_ERR_NULL_EXP_KEY;
        if (len > IMB_AES_BLOCK_SIZE)
                return IMB_ERR_CIPH_LEN;
#endif
        CALL_AES128_CFB_ONE(state, dst, src, iv, enc_exp_key, len);
        return 0;
}

IMB_DLL_EXPORT int
imb_aes256_cfb_one(void *dst, const void *src, const void *iv, const void *enc_exp_key,
                   uint64_t len, IMB_MGR *state)
{
#ifdef SAFE_PARAM
        if (state == NULL)
                return IMB_ERR_NULL_MBMGR;
        if (dst == NULL)
                return IMB_ERR_NULL_DST;
        if (src == NULL)
                return IMB_ERR_NULL_SRC;
        if (iv == NULL)
                return IMB_ERR_NULL_IV;
        if (enc_exp_key == NULL)
                return IMB_ERR_NULL_EXP_KEY;
        if (len > IMB_AES_BLOCK_SIZE)
                return IMB_ERR_CIPH_LEN;
#endif
        CALL_AES256_CFB_ONE(state, dst, src, iv, enc_exp_key, len);
        return 0;
}

IMB_DLL_EXPORT void
imb_aes128_gcm_enc(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES128_GCM_ENC(state, key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                            auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes192_gcm_enc(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES192_GCM_ENC(state, key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                            auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes256_gcm_enc(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES256_GCM_ENC(state, key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                            auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes128_gcm_dec(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES128_GCM_DEC(state, key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                            auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes192_gcm_dec(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES192_GCM_DEC(state, key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                            auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes256_gcm_dec(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                   void *out, const void *in, uint64_t len, const void *iv, const void *aad,
                   uint64_t aad_len, void *auth_tag, uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES256_GCM_DEC(state, key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                            auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes128_gcm_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                    const void *iv, const void *aad, uint64_t aad_len, IMB_MGR *state)
{
        CALL_AES128_GCM_INIT(state, key_data, context_data, iv, aad, aad_len);
}

IMB_DLL_EXPORT void
imb_aes192_gcm_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                    const void *iv, const void *aad, uint64_t aad_len, IMB_MGR *state)
{
        CALL_AES192_GCM_INIT(state, key_data, context_data, iv, aad, aad_len);
}

IMB_DLL_EXPORT void
imb_aes256_gcm_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                    const void *iv, const void *aad, uint64_t aad_len, IMB_MGR *state)
{
        CALL_AES256_GCM_INIT(state, key_data, context_data, iv, aad, aad_len);
}

IMB_DLL_EXPORT void
imb_aes128_gcm_enc_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state)
{
        CALL_AES128_GCM_ENC_UPDATE(state, key_data, context_data, out, in, len);
}

IMB_DLL_EXPORT void
imb_aes192_gcm_enc_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state)
{
        CALL_AES192_GCM_ENC_UPDATE(state, key_data, context_data, out, in, len);
}

IMB_DLL_EXPORT void
imb_aes256_gcm_enc_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state)
{
        CALL_AES256_GCM_ENC_UPDATE(state, key_data, context_data, out, in, len);
}

IMB_DLL_EXPORT void
imb_aes128_gcm_dec_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state)
{
        CALL_AES128_GCM_DEC_UPDATE(state, key_data, context_data, out, in, len);
}

IMB_DLL_EXPORT void
imb_aes192_gcm_dec_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state)
{
        CALL_AES192_GCM_DEC_UPDATE(state, key_data, context_data, out, in, len);
}

IMB_DLL_EXPORT void
imb_aes256_gcm_dec_update(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, void *out, const void *in,
                          const uint64_t len, IMB_MGR *state)
{
        CALL_AES256_GCM_DEC_UPDATE(state, key_data, context_data, out, in, len);
}

IMB_DLL_EXPORT void
imb_aes128_gcm_enc_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES128_GCM_ENC_FINALIZE(state, key_data, context_data, auth_tag, auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes192_gcm_enc_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES192_GCM_ENC_FINALIZE(state, key_data, context_data, auth_tag, auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes256_gcm_enc_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES256_GCM_ENC_FINALIZE(state, key_data, context_data, auth_tag, auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes128_gcm_dec_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES128_GCM_DEC_FINALIZE(state, key_data, context_data, auth_tag, auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes192_gcm_dec_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES192_GCM_DEC_FINALIZE(state, key_data, context_data, auth_tag, auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes256_gcm_dec_finalize(const struct gcm_key_data *key_data,
                            struct gcm_context_data *context_data, void *auth_tag,
                            const uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES256_GCM_DEC_FINALIZE(state, key_data, context_data, auth_tag, auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes128_gcm_precomp(struct gcm_key_data *key_data, IMB_MGR *state)
{
        CALL_AES128_GCM_PRECOMP(state, key_data);
}

IMB_DLL_EXPORT void
imb_aes192_gcm_precomp(struct gcm_key_data *key_data, IMB_MGR *state)
{
        CALL_AES192_GCM_PRECOMP(state, key_data);
}

IMB_DLL_EXPORT void
imb_aes256_gcm_precomp(struct gcm_key_data *key_data, IMB_MGR *state)
{
        CALL_AES256_GCM_PRECOMP(state, key_data);
}

IMB_DLL_EXPORT void
imb_aes128_gcm_pre(const void *key, struct gcm_key_data *key_data, IMB_MGR *state)
{
        CALL_AES128_GCM_PRE(state, key, key_data);
}

IMB_DLL_EXPORT void
imb_aes192_gcm_pre(const void *key, struct gcm_key_data *key_data, IMB_MGR *state)
{
        CALL_AES192_GCM_PRE(state, key, key_data);
}

IMB_DLL_EXPORT void
imb_aes256_gcm_pre(const void *key, struct gcm_key_data *key_data, IMB_MGR *state)
{
        CALL_AES256_GCM_PRE(state, key, key_data);
}

IMB_DLL_EXPORT void
imb_aes128_gcm_init_var_iv(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data, const void *iv,
                           const uint64_t iv_len, const void *aad, const uint64_t aad_len,
                           IMB_MGR *state)
{
        CALL_AES128_GCM_INIT_VAR_IV(state, key_data, context_data, iv, iv_len, aad, aad_len);
}

IMB_DLL_EXPORT void
imb_aes192_gcm_init_var_iv(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data, const void *iv,
                           const uint64_t iv_len, const void *aad, const uint64_t aad_len,
                           IMB_MGR *state)
{
        CALL_AES192_GCM_INIT_VAR_IV(state, key_data, context_data, iv, iv_len, aad, aad_len);
}

IMB_DLL_EXPORT void
imb_aes256_gcm_init_var_iv(const struct gcm_key_data *key_data,
                           struct gcm_context_data *context_data, const void *iv,
                           const uint64_t iv_len, const void *aad, const uint64_t aad_len,
                           IMB_MGR *state)
{
        CALL_AES256_GCM_INIT_VAR_IV(state, key_data, context_data, iv, iv_len, aad, aad_len);
}

IMB_DLL_EXPORT void
imb_aes128_gmac_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                     const void *iv, const uint64_t iv_len, IMB_MGR *state)
{
        CALL_AES128_GMAC_INIT(state, key_data, context_data, iv, iv_len);
}

IMB_DLL_EXPORT void
imb_aes192_gmac_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                     const void *iv, const uint64_t iv_len, IMB_MGR *state)
{
        CALL_AES192_GMAC_INIT(state, key_data, context_data, iv, iv_len);
}

IMB_DLL_EXPORT void
imb_aes256_gmac_init(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                     const void *iv, const uint64_t iv_len, IMB_MGR *state)
{
        CALL_AES256_GMAC_INIT(state, key_data, context_data, iv, iv_len);
}

IMB_DLL_EXPORT void
imb_aes128_gmac_update(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                       const void *in, const uint64_t len, IMB_MGR *state)
{
        CALL_AES128_GMAC_UPDATE(state, key_data, context_data, in, len);
}

IMB_DLL_EXPORT void
imb_aes192_gmac_update(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                       const void *in, const uint64_t len, IMB_MGR *state)
{
        CALL_AES192_GMAC_UPDATE(state, key_data, context_data, in, len);
}

IMB_DLL_EXPORT void
imb_aes256_gmac_update(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                       const void *in, const uint64_t len, IMB_MGR *state)
{
        CALL_AES256_GMAC_UPDATE(state, key_data, context_data, in, len);
}

IMB_DLL_EXPORT void
imb_aes128_gmac_finalize(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                         void *auth_tag, const uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES128_GMAC_FINALIZE(state, key_data, context_data, auth_tag, auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes192_gmac_finalize(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                         void *auth_tag, const uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES192_GMAC_FINALIZE(state, key_data, context_data, auth_tag, auth_tag_len);
}

IMB_DLL_EXPORT void
imb_aes256_gmac_finalize(const struct gcm_key_data *key_data, struct gcm_context_data *context_data,
                         void *auth_tag, const uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_AES256_GMAC_FINALIZE(state, key_data, context_data, auth_tag, auth_tag_len);
}

IMB_DLL_EXPORT void
imb_ghash_pre(const void *key, struct gcm_key_data *key_data, IMB_MGR *state)
{
        CALL_GHASH_PRE(state, key, key_data);
}

IMB_DLL_EXPORT void
imb_ghash(const struct gcm_key_data *key_data, const void *src, const uint64_t len, void *auth_tag,
          const uint64_t auth_tag_len, IMB_MGR *state)
{
        CALL_GHASH(state, key_data, src, len, auth_tag, auth_tag_len);
}

IMB_DLL_EXPORT int
imb_kasumi_init_f8_key_sched(const void *key, kasumi_key_sched_t *exp_key, IMB_MGR *state)
{
        return CALL_KASUMI_INIT_F8_KEY_SCHED(state, key, exp_key);
}

IMB_DLL_EXPORT int
imb_kasumi_init_f9_key_sched(const void *key, kasumi_key_sched_t *exp_key, IMB_MGR *state)
{
        return CALL_KASUMI_INIT_F9_KEY_SCHED(state, key, exp_key);
}

IMB_DLL_EXPORT size_t
imb_kasumi_key_sched_size(IMB_MGR *state)
{
        return CALL_KASUMI_KEY_SCHED_SIZE(state);
}

IMB_DLL_EXPORT int
imb_snow3g_init_key_sched(const void *key, snow3g_key_schedule_t *exp_key, IMB_MGR *state)
{
        return CALL_SNOW3G_INIT_KEY_SCHED(state, key, exp_key);
}

IMB_DLL_EXPORT size_t
imb_snow3g_key_sched_size(IMB_MGR *state)
{
        return CALL_SNOW3G_KEY_SCHED_SIZE(state);
}

IMB_DLL_EXPORT uint32_t
imb_hec_32(const uint8_t *src, IMB_MGR *state)
{
        return CALL_HEC_32(state, src);
}

IMB_DLL_EXPORT uint64_t
imb_hec_64(const uint8_t *src, IMB_MGR *state)
{
        return CALL_HEC_64(state, src);
}

IMB_DLL_EXPORT void
imb_sm4_keyexp(const void *key, void *exp_enc_key, void *exp_dec_key, IMB_MGR *state)
{
        CALL_SM4_KEYEXP(state, key, exp_enc_key, exp_dec_key);
}

IMB_DLL_EXPORT void
imb_chacha20_poly1305_init(const void *key, struct chacha20_poly1305_context_data *ctx,
                           const void *iv, const void *aad, const uint64_t aadl, IMB_MGR *state)
{
        CALL_CHACHA20_POLY1305_INIT(state, key, ctx, iv, aad, aadl);
}

IMB_DLL_EXPORT void
imb_chacha20_poly1305_enc_update(const void *key, struct chacha20_poly1305_context_data *ctx,
                                 void *dst, const void *src, const uint64_t len, IMB_MGR *state)
{
        CALL_CHACHA20_POLY1305_ENC_UPDATE(state, key, ctx, dst, src, len);
}

IMB_DLL_EXPORT void
imb_chacha20_poly1305_dec_update(const void *key, struct chacha20_poly1305_context_data *ctx,
                                 void *dst, const void *src, const uint64_t len, IMB_MGR *state)
{
        CALL_CHACHA20_POLY1305_DEC_UPDATE(state, key, ctx, dst, src, len);
}

IMB_DLL_EXPORT void
imb_chacha20_poly1305_enc_finalize(struct chacha20_poly1305_context_data *ctx, void *tag,
                                   const uint64_t tagl, IMB_MGR *state)
{
        CALL_CHACHA20_POLY1305_ENC_FINALIZE(state, ctx, tag, tagl);
}

IMB_DLL_EXPORT void
imb_chacha20_poly1305_dec_finalize(struct chacha20_poly1305_context_data *ctx, void *tag,
                                   const uint64_t tagl, IMB_MGR *state)
{
        CALL_CHACHA20_POLY1305_DEC_FINALIZE(state, ctx, tag, tagl);
}
