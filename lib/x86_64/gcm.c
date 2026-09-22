/*******************************************************************************
  Copyright (c) 2018-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <stdint.h>
#include "intel-ipsec-mb.h"
#include "gcm.h"
#include "error.h"

/**
 * @brief Pre-processes GCM key data
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @param key pointer to key data
 * @param key_data GCM expanded key data
 *
 */

void
aes_gcm_pre_128_sse(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_128_enc_sse(key, key_data->expanded_keys);
        aes_gcm_precomp_128_sse(key_data);
}

void
aes_gcm_pre_128_avx_gen4(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_128_enc_avx2(key, key_data->expanded_keys);
        aes_gcm_precomp_128_avx_gen4(key_data);
}

void
aes_gcm_pre_128_vaes_avx512(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_128_enc_avx2(key, key_data->expanded_keys);
        aes_gcm_precomp_128_vaes_avx512(key_data);
}

void
aes_gcm_pre_128_vaes_avx2(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_128_enc_avx2(key, key_data->expanded_keys);
        aes_gcm_precomp_128_vaes_avx2(key_data);
}

void
aes_gcm_pre_192_sse(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_192_enc_sse(key, key_data->expanded_keys);
        aes_gcm_precomp_192_sse(key_data);
}

void
aes_gcm_pre_192_avx_gen4(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_192_enc_avx2(key, key_data->expanded_keys);
        aes_gcm_precomp_192_avx_gen4(key_data);
}

void
aes_gcm_pre_192_vaes_avx512(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_192_enc_avx2(key, key_data->expanded_keys);
        aes_gcm_precomp_192_vaes_avx512(key_data);
}

void
aes_gcm_pre_192_vaes_avx2(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_192_enc_avx2(key, key_data->expanded_keys);
        aes_gcm_precomp_192_vaes_avx2(key_data);
}

void
aes_gcm_pre_256_sse(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_256_enc_sse(key, key_data->expanded_keys);
        aes_gcm_precomp_256_sse(key_data);
}

void
aes_gcm_pre_256_avx_gen4(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_256_enc_avx2(key, key_data->expanded_keys);
        aes_gcm_precomp_256_avx_gen4(key_data);
}

void
aes_gcm_pre_256_vaes_avx512(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_256_enc_avx2(key, key_data->expanded_keys);
        aes_gcm_precomp_256_vaes_avx512(key_data);
}

void
aes_gcm_pre_256_vaes_avx2(const void *key, struct gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        /* reset error status */
        imb_set_errno(NULL, 0);

        if (key == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_KEY);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_EXP_KEY);
                return;
        }
#endif
        aes_keyexp_256_enc_avx2(key, key_data->expanded_keys);
        aes_gcm_precomp_256_vaes_avx2(key_data);
}

void
imb_aes_gmac_init_128_sse(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, const uint8_t *iv,
                          const uint64_t iv_len)
{
        aes_gcm_init_var_iv_128_sse(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_init_192_sse(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, const uint8_t *iv,
                          const uint64_t iv_len)
{
        aes_gcm_init_var_iv_192_sse(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_init_256_sse(const struct gcm_key_data *key_data,
                          struct gcm_context_data *context_data, const uint8_t *iv,
                          const uint64_t iv_len)
{
        aes_gcm_init_var_iv_256_sse(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_finalize_128_sse(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data, uint8_t *auth_tag,
                              const uint64_t auth_tag_len)
{
        aes_gcm_enc_128_finalize_sse(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_finalize_192_sse(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data, uint8_t *auth_tag,
                              const uint64_t auth_tag_len)
{
        aes_gcm_enc_192_finalize_sse(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_finalize_256_sse(const struct gcm_key_data *key_data,
                              struct gcm_context_data *context_data, uint8_t *auth_tag,
                              const uint64_t auth_tag_len)
{
        aes_gcm_enc_256_finalize_sse(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_init_128_avx_gen4(const struct gcm_key_data *key_data,
                               struct gcm_context_data *context_data, const uint8_t *iv,
                               const uint64_t iv_len)
{
        aes_gcm_init_var_iv_128_avx_gen4(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_init_192_avx_gen4(const struct gcm_key_data *key_data,
                               struct gcm_context_data *context_data, const uint8_t *iv,
                               const uint64_t iv_len)
{
        aes_gcm_init_var_iv_192_avx_gen4(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_init_256_avx_gen4(const struct gcm_key_data *key_data,
                               struct gcm_context_data *context_data, const uint8_t *iv,
                               const uint64_t iv_len)
{
        aes_gcm_init_var_iv_256_avx_gen4(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_finalize_128_avx_gen4(const struct gcm_key_data *key_data,
                                   struct gcm_context_data *context_data, uint8_t *auth_tag,
                                   const uint64_t auth_tag_len)
{
        aes_gcm_enc_128_finalize_avx_gen4(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_finalize_192_avx_gen4(const struct gcm_key_data *key_data,
                                   struct gcm_context_data *context_data, uint8_t *auth_tag,
                                   const uint64_t auth_tag_len)
{
        aes_gcm_enc_192_finalize_avx_gen4(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_finalize_256_avx_gen4(const struct gcm_key_data *key_data,
                                   struct gcm_context_data *context_data, uint8_t *auth_tag,
                                   const uint64_t auth_tag_len)
{
        aes_gcm_enc_256_finalize_avx_gen4(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_init_128_vaes_avx512(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data, const uint8_t *iv,
                                  const uint64_t iv_len)
{
        aes_gcm_init_var_iv_128_vaes_avx512(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_init_192_vaes_avx512(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data, const uint8_t *iv,
                                  const uint64_t iv_len)
{
        aes_gcm_init_var_iv_192_vaes_avx512(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_init_256_vaes_avx512(const struct gcm_key_data *key_data,
                                  struct gcm_context_data *context_data, const uint8_t *iv,
                                  const uint64_t iv_len)
{
        aes_gcm_init_var_iv_256_vaes_avx512(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_finalize_128_vaes_avx512(const struct gcm_key_data *key_data,
                                      struct gcm_context_data *context_data, uint8_t *auth_tag,
                                      const uint64_t auth_tag_len)
{
        aes_gcm_enc_128_finalize_vaes_avx512(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_finalize_192_vaes_avx512(const struct gcm_key_data *key_data,
                                      struct gcm_context_data *context_data, uint8_t *auth_tag,
                                      const uint64_t auth_tag_len)
{
        aes_gcm_enc_192_finalize_vaes_avx512(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_finalize_256_vaes_avx512(const struct gcm_key_data *key_data,
                                      struct gcm_context_data *context_data, uint8_t *auth_tag,
                                      const uint64_t auth_tag_len)
{
        aes_gcm_enc_256_finalize_vaes_avx512(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_init_128_vaes_avx2(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data, const uint8_t *iv,
                                const uint64_t iv_len)
{
        aes_gcm_init_var_iv_128_vaes_avx2(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_init_192_vaes_avx2(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data, const uint8_t *iv,
                                const uint64_t iv_len)
{
        aes_gcm_init_var_iv_192_vaes_avx2(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_init_256_vaes_avx2(const struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data, const uint8_t *iv,
                                const uint64_t iv_len)
{
        aes_gcm_init_var_iv_256_vaes_avx2(key_data, context_data, iv, iv_len, NULL, 0);
}

void
imb_aes_gmac_finalize_128_vaes_avx2(const struct gcm_key_data *key_data,
                                    struct gcm_context_data *context_data, uint8_t *auth_tag,
                                    const uint64_t auth_tag_len)
{
        aes_gcm_enc_128_finalize_vaes_avx2(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_finalize_192_vaes_avx2(const struct gcm_key_data *key_data,
                                    struct gcm_context_data *context_data, uint8_t *auth_tag,
                                    const uint64_t auth_tag_len)
{
        aes_gcm_enc_192_finalize_vaes_avx2(key_data, context_data, auth_tag, auth_tag_len);
}

void
imb_aes_gmac_finalize_256_vaes_avx2(const struct gcm_key_data *key_data,
                                    struct gcm_context_data *context_data, uint8_t *auth_tag,
                                    const uint64_t auth_tag_len)
{
        aes_gcm_enc_256_finalize_vaes_avx2(key_data, context_data, auth_tag, auth_tag_len);
}
