/**********************************************************************
  Copyright(c) 2026, Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>

#ifdef _WIN32
#define strdup     _strdup
#define strcasecmp _stricmp
#endif

#include <intel-ipsec-mb.h>

#include "algo_maps.h"
#include "job_utils.h"
#include "misc.h"

/* cipher and authentication IV sizes */
uint32_t cipher_iv_size = 0;
uint32_t auth_iv_size = 0;
uint8_t auth_tag_size = 0;

/* source buffer offset applied to cipher and hash operations */
uint64_t offset = 4;

/* 0 => not possible, 1 => possible */
int is_avx_sse_check_possible = 0;

void
avx_sse_check(const char *ctx_str, const IMB_HASH_ALG hash_alg, const IMB_CIPHER_MODE cipher_mode)
{
        if (!is_avx_sse_check_possible)
                return;

        const uint32_t avx_sse_flag = avx_sse_transition_check();

        if (!avx_sse_flag)
                return;

        const char *hash_str = misc_hash_alg_to_str(hash_alg);
        const char *cipher_str = misc_cipher_mode_to_str(cipher_mode);

        if (avx_sse_flag & MISC_AVX_SSE_ZMM0_15_ISSUE)
                printf("ERROR: AVX-SSE transition after %s in ZMM0-ZMM15: "
                       "HASH=%s, CIPHER=%s\n",
                       ctx_str, hash_str, cipher_str);
        else if (avx_sse_flag & MISC_AVX_SSE_YMM0_15_ISSUE)
                printf("ERROR: AVX-SSE transition after %s in YMM0-YMM15: "
                       "HASH=%s, CIPHER=%s\n",
                       ctx_str, hash_str, cipher_str);
}

void
print_algo_info(const struct params_s *params)
{
        const struct custom_job_params *job_params;
        size_t i;

        for (i = 0; i < num_aead_algo_str_map; i++) {
                job_params = &aead_algo_str_map[i].values.job_params;
                if (job_params->cipher_mode == params->cipher_mode &&
                    job_params->hash_alg == params->hash_alg &&
                    job_params->key_size == params->key_size) {
                        printf("AEAD algo = %s ", aead_algo_str_map[i].name);
                        return;
                }
        }

        for (i = 0; i < num_cipher_algo_str_map; i++) {
                job_params = &cipher_algo_str_map[i].values.job_params;
                if (job_params->cipher_mode == params->cipher_mode &&
                    job_params->key_size == params->key_size) {
                        printf("Cipher algo = %s ", cipher_algo_str_map[i].name);
                        break;
                }
        }
        for (i = 0; i < num_hash_algo_str_map; i++) {
                job_params = &hash_algo_str_map[i].values.job_params;
                if (job_params->hash_alg == params->hash_alg) {
                        printf("Hash algo = %s ", hash_algo_str_map[i].name);
                        break;
                }
        }
}

int
fill_keys(IMB_MGR *mb_mgr, struct cipher_auth_keys *keys, const uint8_t *ciph_key,
          const uint8_t *auth_key, const struct params_s *params,
          const struct key_fill_pattern *pattern)
{
        uint32_t *dust = keys->dust;
        uint32_t *k1_expanded = keys->k1_expanded;
        uint8_t *k2 = keys->k2;
        uint8_t *k3 = keys->k3;
        uint8_t *ck = keys->ck;
        uint8_t *nia4_key = keys->nia4_key;
        uint32_t *enc_keys = keys->enc_keys;
        uint32_t *dec_keys = keys->dec_keys;
        uint8_t *ipad = keys->ipad;
        uint8_t *opad = keys->opad;
        struct gcm_key_data *gdata_key = &keys->gdata_key;

        /* Set all expanded keys to the requested patterns if provided */
        if (pattern != NULL) {
                const int pattern_auth_key = pattern->auth_key;
                const int pattern_cipher_key = pattern->cipher_key;

                switch (params->hash_alg) {
                case IMB_AUTH_AES_XCBC:
                        nosimd_memset(k1_expanded, pattern_auth_key, sizeof(keys->k1_expanded));
                        nosimd_memset(k2, pattern_auth_key, sizeof(keys->k2));
                        nosimd_memset(k3, pattern_auth_key, sizeof(keys->k3));
                        break;
                case IMB_AUTH_AES_CMAC:
                case IMB_AUTH_AES_CMAC_256:
                        nosimd_memset(k1_expanded, pattern_auth_key, sizeof(keys->k1_expanded));
                        nosimd_memset(k2, pattern_auth_key, sizeof(keys->k2));
                        nosimd_memset(k3, pattern_auth_key, sizeof(keys->k3));
                        break;
                case IMB_AUTH_POLY1305:
                case IMB_AUTH_AES_NIA5:
                        nosimd_memset(k1_expanded, pattern_auth_key, sizeof(keys->k1_expanded));
                        break;
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
                case IMB_AUTH_MD5:
                        nosimd_memset(ipad, pattern_auth_key, sizeof(keys->ipad));
                        nosimd_memset(opad, pattern_auth_key, sizeof(keys->opad));
                        break;
                case IMB_AUTH_ZUC_EIA3:
                case IMB_AUTH_ZUC_NIA6:
                case IMB_AUTH_SNOW3G_UIA2:
                case IMB_AUTH_KASUMI_UIA1:
                        /* k2 is the buffer these algorithms take the key from */
                        nosimd_memset(k2, pattern_auth_key, sizeof(keys->k2));
                        break;
                case IMB_AUTH_SNOW5G_NIA4:
                        /* nia4_key is the buffer this algorithm takes the key from */
                        nosimd_memset(nia4_key, pattern_auth_key, sizeof(keys->nia4_key));
                        break;
                case IMB_AUTH_AES_NCA5:
                case IMB_AUTH_ZUC_NCA6:
                case IMB_AUTH_SNOW5G_NCA4:
                case IMB_AUTH_AES_CCM:
                case IMB_AUTH_SM4_GCM:
                case IMB_AUTH_AES_GMAC:
                case IMB_AUTH_NULL:
                case IMB_AUTH_SHA_1:
                case IMB_AUTH_SHA_224:
                case IMB_AUTH_SHA_256:
                case IMB_AUTH_SHA_384:
                case IMB_AUTH_SHA_512:
                case IMB_AUTH_PON_CRC_BIP:
                case IMB_AUTH_DOCSIS_CRC32:
                case IMB_AUTH_CHACHA20_POLY1305:
                case IMB_AUTH_CHACHA20_POLY1305_SGL:
                case IMB_AUTH_GCM_SGL:
                case IMB_AUTH_CRC32_ETHERNET_FCS:
                case IMB_AUTH_CRC32_SCTP:
                case IMB_AUTH_CRC32_WIMAX_OFDMA_DATA:
                case IMB_AUTH_CRC24_LTE_A:
                case IMB_AUTH_CRC24_LTE_B:
                case IMB_AUTH_CRC16_X25:
                case IMB_AUTH_CRC16_FP_DATA:
                case IMB_AUTH_CRC11_FP_HEADER:
                case IMB_AUTH_CRC10_IUUP_DATA:
                case IMB_AUTH_CRC8_WIMAX_OFDMA_HCS:
                case IMB_AUTH_CRC7_FP_HEADER:
                case IMB_AUTH_CRC6_IUUP_HEADER:
                case IMB_AUTH_SM3:
                case IMB_AUTH_SHA3_224:
                case IMB_AUTH_SHA3_256:
                case IMB_AUTH_SHA3_384:
                case IMB_AUTH_SHA3_512:
                case IMB_AUTH_SHAKE128:
                case IMB_AUTH_SHAKE256:
                        /* No operation needed */
                        break;
                case IMB_AUTH_AES_GMAC_128:
                case IMB_AUTH_AES_GMAC_192:
                case IMB_AUTH_AES_GMAC_256:
                case IMB_AUTH_GHASH:
                        nosimd_memset(gdata_key, pattern_auth_key, sizeof(keys->gdata_key));
                        break;
                default:
                        fprintf(stderr, "Unsupported hash algorithm %u, line %d\n",
                                (unsigned) params->hash_alg, __LINE__);
                        return -1;
                }

                switch (params->cipher_mode) {
                case IMB_CIPHER_GCM:
                case IMB_CIPHER_SM4_GCM:
                        nosimd_memset(gdata_key, pattern_cipher_key, sizeof(keys->gdata_key));
                        break;
                case IMB_CIPHER_PON_AES_CNTR:
                case IMB_CIPHER_CBC:
                case IMB_CIPHER_SM4_CBC:
                case IMB_CIPHER_SM4_CNTR:
                case IMB_CIPHER_CCM:
                case IMB_CIPHER_CNTR:
                case IMB_CIPHER_AES_NEA5:
                case IMB_CIPHER_DOCSIS_SEC_BPI:
                case IMB_CIPHER_SM4_ECB:
                case IMB_CIPHER_ECB:
                case IMB_CIPHER_CFB:
                        nosimd_memset(enc_keys, pattern_cipher_key, sizeof(keys->enc_keys));
                        nosimd_memset(dec_keys, pattern_cipher_key, sizeof(keys->dec_keys));
                        break;
                case IMB_CIPHER_DES:
                case IMB_CIPHER_DES3:
                case IMB_CIPHER_DOCSIS_DES:
                case IMB_CIPHER_AES_NCA5:
                case IMB_CIPHER_ZUC_NCA6:
                case IMB_CIPHER_SNOW5G_NCA4:
                        nosimd_memset(enc_keys, pattern_cipher_key, sizeof(keys->enc_keys));
                        break;
                case IMB_CIPHER_SNOW3G_UEA2:
                case IMB_CIPHER_KASUMI_UEA1:
                        nosimd_memset(ck, pattern_cipher_key, 16);
                        break;
                case IMB_CIPHER_ZUC_NEA6:
                case IMB_CIPHER_ZUC_EEA3:
                case IMB_CIPHER_CHACHA20:
                case IMB_CIPHER_CHACHA20_POLY1305:
                case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                case IMB_CIPHER_SNOW5G_NEA4:
                        nosimd_memset(ck, pattern_cipher_key, 32);
                        break;
                case IMB_CIPHER_NULL:
                        /* No operation needed */
                        break;
                default:
                        fprintf(stderr, "Unsupported cipher mode\n");
                        return -1;
                }

                return 0;
        }

        switch (params->hash_alg) {
        case IMB_AUTH_AES_XCBC:
                IMB_AES_XCBC_KEYEXP(mb_mgr, auth_key, k1_expanded, k2, k3);
                break;
        case IMB_AUTH_AES_CMAC:
                IMB_AES_KEYEXP_128(mb_mgr, auth_key, k1_expanded, dust);
                IMB_AES_CMAC_SUBKEY_GEN_128(mb_mgr, k1_expanded, k2, k3);
                break;
        case IMB_AUTH_AES_CMAC_256:
                IMB_AES_KEYEXP_256(mb_mgr, auth_key, k1_expanded, dust);
                IMB_AES_CMAC_SUBKEY_GEN_256(mb_mgr, k1_expanded, k2, k3);
                break;
        case IMB_AUTH_AES_NIA5:
                IMB_AES_KEYEXP_256(mb_mgr, auth_key, k1_expanded, dust);
                break;
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
        case IMB_AUTH_MD5:
                imb_hmac_ipad_opad(mb_mgr, params->hash_alg, auth_key, MAX_KEY_SIZE, ipad, opad);
                break;
        case IMB_AUTH_ZUC_EIA3:
        case IMB_AUTH_ZUC_NIA6:
        case IMB_AUTH_SNOW3G_UIA2:
        case IMB_AUTH_KASUMI_UIA1:
                nosimd_memcpy(k2, auth_key, sizeof(keys->k2));
                break;
        case IMB_AUTH_SNOW5G_NIA4:
                /* Copying data in 16 byte chunks to keep the stack clean */
                nosimd_memcpy(nia4_key, auth_key, 16);
                nosimd_memcpy(nia4_key + 16, auth_key + 16, 16);
                break;
        case IMB_AUTH_AES_GMAC_128:
                IMB_AES128_GCM_PRE(mb_mgr, auth_key, gdata_key);
                break;
        case IMB_AUTH_AES_GMAC_192:
                IMB_AES192_GCM_PRE(mb_mgr, auth_key, gdata_key);
                break;
        case IMB_AUTH_AES_GMAC_256:
                IMB_AES256_GCM_PRE(mb_mgr, auth_key, gdata_key);
                break;
        case IMB_AUTH_GHASH:
                IMB_GHASH_PRE(mb_mgr, auth_key, gdata_key);
                break;
        case IMB_AUTH_AES_CCM:
        case IMB_AUTH_SM4_GCM:
        case IMB_AUTH_AES_GMAC:
        case IMB_AUTH_NULL:
        case IMB_AUTH_SHA_1:
        case IMB_AUTH_SHA_224:
        case IMB_AUTH_SHA_256:
        case IMB_AUTH_SHA_384:
        case IMB_AUTH_SHA_512:
        case IMB_AUTH_PON_CRC_BIP:
        case IMB_AUTH_DOCSIS_CRC32:
        case IMB_AUTH_CHACHA20_POLY1305:
        case IMB_AUTH_CHACHA20_POLY1305_SGL:
        case IMB_AUTH_GCM_SGL:
        case IMB_AUTH_CRC32_ETHERNET_FCS:
        case IMB_AUTH_CRC32_SCTP:
        case IMB_AUTH_CRC32_WIMAX_OFDMA_DATA:
        case IMB_AUTH_CRC24_LTE_A:
        case IMB_AUTH_CRC24_LTE_B:
        case IMB_AUTH_CRC16_X25:
        case IMB_AUTH_CRC16_FP_DATA:
        case IMB_AUTH_CRC11_FP_HEADER:
        case IMB_AUTH_CRC10_IUUP_DATA:
        case IMB_AUTH_CRC8_WIMAX_OFDMA_HCS:
        case IMB_AUTH_CRC7_FP_HEADER:
        case IMB_AUTH_CRC6_IUUP_HEADER:
        case IMB_AUTH_SM3:
        case IMB_AUTH_SHA3_224:
        case IMB_AUTH_SHA3_256:
        case IMB_AUTH_SHA3_384:
        case IMB_AUTH_SHA3_512:
        case IMB_AUTH_SHAKE128:
        case IMB_AUTH_SHAKE256:
        case IMB_AUTH_AES_NCA5:
        case IMB_AUTH_ZUC_NCA6:
        case IMB_AUTH_SNOW5G_NCA4:
                /* No operation needed */
                break;
        case IMB_AUTH_POLY1305:
                nosimd_memcpy(k1_expanded, auth_key, 32);
                break;
        default:
                fprintf(stderr, "Unsupported hash algorithm %u, line %d\n",
                        (unsigned) params->hash_alg, __LINE__);
                return -1;
        }

        switch (params->cipher_mode) {
        case IMB_CIPHER_GCM:
                switch (params->key_size) {
                case IMB_KEY_128_BYTES:
                        IMB_AES128_GCM_PRE(mb_mgr, ciph_key, gdata_key);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES192_GCM_PRE(mb_mgr, ciph_key, gdata_key);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES256_GCM_PRE(mb_mgr, ciph_key, gdata_key);
                        break;
                default:
                        fprintf(stderr, "Wrong key size\n");
                        return -1;
                }
                break;
        case IMB_CIPHER_PON_AES_CNTR:
                switch (params->key_size) {
                case 16:
                        IMB_AES_KEYEXP_128(mb_mgr, ciph_key, enc_keys, dec_keys);
                        break;
                case 0:
                        break;
                default:
                        fprintf(stderr, "Wrong key size\n");
                        return -1;
                }
                break;
        case IMB_CIPHER_CBC:
        case IMB_CIPHER_CCM:
        case IMB_CIPHER_CNTR:
        case IMB_CIPHER_AES_NEA5:
        case IMB_CIPHER_DOCSIS_SEC_BPI:
        case IMB_CIPHER_ECB:
        case IMB_CIPHER_CFB:
                switch (params->key_size) {
                case IMB_KEY_128_BYTES:
                        IMB_AES_KEYEXP_128(mb_mgr, ciph_key, enc_keys, dec_keys);
                        break;
                case IMB_KEY_192_BYTES:
                        IMB_AES_KEYEXP_192(mb_mgr, ciph_key, enc_keys, dec_keys);
                        break;
                case IMB_KEY_256_BYTES:
                        IMB_AES_KEYEXP_256(mb_mgr, ciph_key, enc_keys, dec_keys);
                        break;
                default:
                        fprintf(stderr, "Wrong key size\n");
                        return -1;
                }
                break;
        case IMB_CIPHER_SM4_ECB:
        case IMB_CIPHER_SM4_CBC:
        case IMB_CIPHER_SM4_CNTR:
                IMB_SM4_KEYEXP(mb_mgr, ciph_key, enc_keys, dec_keys);
                break;
        case IMB_CIPHER_SM4_GCM:
                imb_sm4_gcm_pre(mb_mgr, ciph_key, gdata_key);
                break;
        case IMB_CIPHER_DES:
        case IMB_CIPHER_DES3:
        case IMB_CIPHER_DOCSIS_DES:
                des_key_schedule((uint64_t *) enc_keys, ciph_key);
                break;
        case IMB_CIPHER_SNOW3G_UEA2:
        case IMB_CIPHER_KASUMI_UEA1:
                nosimd_memcpy(ck, ciph_key, 16);
                break;
        case IMB_CIPHER_ZUC_NCA6:
        case IMB_CIPHER_SNOW5G_NCA4:
                /* enc_keys is the buffer these algorithms take the key from */
                nosimd_memcpy(enc_keys, ciph_key, 16);
                nosimd_memcpy((uint8_t *) enc_keys + 16, ciph_key + 16, 16);
                break;
        case IMB_CIPHER_ZUC_EEA3:
        case IMB_CIPHER_ZUC_NEA6:
        case IMB_CIPHER_CHACHA20:
        case IMB_CIPHER_CHACHA20_POLY1305:
        case IMB_CIPHER_CHACHA20_POLY1305_SGL:
        case IMB_CIPHER_SNOW5G_NEA4:
                /* Use of:
                 *     nosimd_memcpy(ck, ciph_key, 32);
                 * leaves sensitive data on the stack.
                 * Copying data in 16 byte chunks instead.
                 */
                nosimd_memcpy(ck, ciph_key, 16);
                nosimd_memcpy(ck + 16, ciph_key + 16, 16);
                break;
        case IMB_CIPHER_AES_NCA5:
                IMB_AES_KEYEXP_256(mb_mgr, ciph_key, enc_keys, dec_keys);
                break;
        case IMB_CIPHER_NULL:
                /* No operation needed */
                break;
        default:
                fprintf(stderr, "Unsupported cipher mode\n");
                return -1;
        }

        return 0;
}

int
fill_job(IMB_JOB *job, const struct params_s *params, uint8_t *buf, uint8_t *digest,
         const uint8_t *aad, const uint32_t buf_size, const uint8_t tag_size,
         IMB_CIPHER_DIRECTION cipher_dir, struct cipher_auth_keys *keys, uint8_t *cipher_iv,
         uint8_t *auth_iv, const unsigned index)
{
        static const void *ks_ptr[3];
        uint32_t *k1_expanded = keys->k1_expanded;
        uint8_t *k2 = keys->k2;
        uint8_t *k3 = keys->k3;
        uint8_t *ck = keys->ck;
        uint8_t *nia4_key = keys->nia4_key;
        uint32_t *enc_keys = keys->enc_keys;
        uint32_t *dec_keys = keys->dec_keys;
        uint8_t *ipad = keys->ipad;
        uint8_t *opad = keys->opad;
        struct gcm_key_data *gdata_key = &keys->gdata_key;
        uint64_t cipher_offset_in_bytes = offset;

        job->msg_len_to_cipher_in_bytes = buf_size;

        job->msg_len_to_hash_in_bytes = buf_size;
        job->iv = cipher_iv;
        job->user_data = (void *) ((uintptr_t) index);

        if (params->cipher_mode == IMB_CIPHER_PON_AES_CNTR) {
                /* Subtract XGEM header */
                job->msg_len_to_cipher_in_bytes -= 8;
                cipher_offset_in_bytes += 8;
                /* If no crypto needed, set msg_len_to_cipher to 0 */
                if (params->key_size == 0)
                        job->msg_len_to_cipher_in_bytes = 0;
        }

        if (params->hash_alg == IMB_AUTH_DOCSIS_CRC32 &&
            params->cipher_mode == IMB_CIPHER_DOCSIS_SEC_BPI) {
                if (buf_size >= (IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE + IMB_DOCSIS_CRC32_TAG_SIZE)) {
                        const uint64_t cipher_adjust = /* SA + DA only */
                                IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE - 2;

                        cipher_offset_in_bytes += cipher_adjust;
                        job->msg_len_to_cipher_in_bytes -= cipher_adjust;
                        job->msg_len_to_hash_in_bytes -= IMB_DOCSIS_CRC32_TAG_SIZE;
                } else if (buf_size > IMB_DOCSIS_CRC32_TAG_SIZE) {
                        job->msg_len_to_cipher_in_bytes = 0;
                        job->msg_len_to_hash_in_bytes -= IMB_DOCSIS_CRC32_TAG_SIZE;
                } else {
                        job->msg_len_to_cipher_in_bytes = 0;
                        job->msg_len_to_hash_in_bytes = 0;
                }
        }

        /* In-place operation */
        /* "offset" will be applied to src inside the library code */
        job->src = buf - offset;
        job->dst = buf - offset + cipher_offset_in_bytes;
        job->auth_tag_output = digest;
        job->hash_start_src_offset_in_bytes = offset;

        job->hash_alg = params->hash_alg;
        switch (params->hash_alg) {
        case IMB_AUTH_AES_XCBC:
                job->u.XCBC._k1_expanded = k1_expanded;
                job->u.XCBC._k2 = k2;
                job->u.XCBC._k3 = k3;
                break;
        case IMB_AUTH_AES_CMAC:
                job->u.CMAC._key_expanded = k1_expanded;
                job->u.CMAC._skey1 = k2;
                job->u.CMAC._skey2 = k3;
                break;
        case IMB_AUTH_AES_CMAC_256:
                job->u.CMAC._key_expanded = k1_expanded;
                job->u.CMAC._skey1 = k2;
                job->u.CMAC._skey2 = k3;
                break;
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
        case IMB_AUTH_MD5:
                /* HMAC hash alg is SHA1 or MD5 */
                job->u.HMAC._hashed_auth_key_xor_ipad = (uint8_t *) ipad;
                job->u.HMAC._hashed_auth_key_xor_opad = (uint8_t *) opad;
                break;
        case IMB_AUTH_ZUC_EIA3:
                job->u.ZUC_EIA3._key = k2;
                job->u.ZUC_EIA3._iv = auth_iv;

                break;
        case IMB_AUTH_ZUC_NIA6:
                job->u.NIA._key = k2;
                job->u.NIA._iv = auth_iv;
                break;
        case IMB_AUTH_SNOW3G_UIA2:
                job->u.SNOW3G_UIA2._key = k2;
                job->u.SNOW3G_UIA2._iv = auth_iv;

                break;
        case IMB_AUTH_KASUMI_UIA1:
                job->u.KASUMI_UIA1._key = k2;
                break;
        case IMB_AUTH_AES_GMAC_128:
        case IMB_AUTH_AES_GMAC_192:
        case IMB_AUTH_AES_GMAC_256:
                job->u.GMAC._key = gdata_key;
                job->u.GMAC._iv = auth_iv;
                job->u.GMAC.iv_len_in_bytes = (auth_iv_size != 0) ? auth_iv_size : 12;
                break;
        case IMB_AUTH_GHASH:
                job->u.GHASH._key = gdata_key;
                job->u.GHASH._init_tag = auth_iv;
                break;
        case IMB_AUTH_PON_CRC_BIP:
        case IMB_AUTH_NULL:
        case IMB_AUTH_AES_GMAC:
        case IMB_AUTH_AES_CCM:
        case IMB_AUTH_SM4_GCM:
        case IMB_AUTH_SHA_1:
        case IMB_AUTH_SHA_224:
        case IMB_AUTH_SHA_256:
        case IMB_AUTH_SHA_384:
        case IMB_AUTH_SHA_512:
        case IMB_AUTH_GCM_SGL:
        case IMB_AUTH_CRC32_ETHERNET_FCS:
        case IMB_AUTH_CRC32_SCTP:
        case IMB_AUTH_CRC32_WIMAX_OFDMA_DATA:
        case IMB_AUTH_CRC24_LTE_A:
        case IMB_AUTH_CRC24_LTE_B:
        case IMB_AUTH_CRC16_X25:
        case IMB_AUTH_CRC16_FP_DATA:
        case IMB_AUTH_CRC11_FP_HEADER:
        case IMB_AUTH_CRC10_IUUP_DATA:
        case IMB_AUTH_CRC8_WIMAX_OFDMA_HCS:
        case IMB_AUTH_CRC7_FP_HEADER:
        case IMB_AUTH_CRC6_IUUP_HEADER:
        case IMB_AUTH_SM3:
        case IMB_AUTH_SHA3_224:
        case IMB_AUTH_SHA3_256:
        case IMB_AUTH_SHA3_384:
        case IMB_AUTH_SHA3_512:
        case IMB_AUTH_SHAKE128:
        case IMB_AUTH_SHAKE256:
                /* No operation needed */
                break;
        case IMB_AUTH_DOCSIS_CRC32:
        case IMB_AUTH_AES_NCA5:
        case IMB_AUTH_ZUC_NCA6:
        case IMB_AUTH_SNOW5G_NCA4:
                /* No operation needed */
                break;
        case IMB_AUTH_POLY1305:
                job->u.POLY1305._key = k1_expanded;
                break;
        case IMB_AUTH_CHACHA20_POLY1305:
        case IMB_AUTH_CHACHA20_POLY1305_SGL:
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = params->aad_size;
                job->u.CHACHA20_POLY1305.aad = aad;
                break;
        case IMB_AUTH_AES_NIA5:
                job->u.NIA._key = k1_expanded;
                job->u.NIA._iv = auth_iv;
                break;
        case IMB_AUTH_SNOW5G_NIA4:
                job->u.NIA._key = nia4_key;
                job->u.NIA._iv = auth_iv;
                break;
        default:
                printf("Unsupported hash algorithm %u, line %d\n", (unsigned) params->hash_alg,
                       __LINE__);
                return -1;
        }

        job->auth_tag_output_len_in_bytes = (uint64_t) tag_size;

        job->cipher_direction = cipher_dir;

        if (params->cipher_mode == IMB_CIPHER_NULL) {
                job->chain_order = IMB_ORDER_HASH_CIPHER;
        } else if (params->cipher_mode == IMB_CIPHER_CCM ||
                   (params->cipher_mode == IMB_CIPHER_DOCSIS_SEC_BPI &&
                    params->hash_alg == IMB_AUTH_DOCSIS_CRC32)) {
                if (job->cipher_direction == IMB_DIR_ENCRYPT)
                        job->chain_order = IMB_ORDER_HASH_CIPHER;
                else
                        job->chain_order = IMB_ORDER_CIPHER_HASH;
        } else {
                if (job->cipher_direction == IMB_DIR_ENCRYPT)
                        job->chain_order = IMB_ORDER_CIPHER_HASH;
                else
                        job->chain_order = IMB_ORDER_HASH_CIPHER;
        }

        /* Translating enum to the API's one */
        job->cipher_mode = params->cipher_mode;
        job->key_len_in_bytes = params->key_size;

        job->cipher_start_src_offset_in_bytes = cipher_offset_in_bytes;

        switch (job->cipher_mode) {
        case IMB_CIPHER_SM4_CBC:
        case IMB_CIPHER_CBC:
        case IMB_CIPHER_DOCSIS_SEC_BPI:
                job->enc_keys = enc_keys;
                job->dec_keys = dec_keys;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_AES_NCA5:
        case IMB_CIPHER_ZUC_NCA6:
        case IMB_CIPHER_SNOW5G_NCA4:
                job->u.NCA.aad_len_in_bytes = params->aad_size;
                job->u.NCA.aad = aad;
                /* Fall-through */
        case IMB_CIPHER_PON_AES_CNTR:
        case IMB_CIPHER_SM4_CNTR:
        case IMB_CIPHER_CNTR:
        case IMB_CIPHER_AES_NEA5:
        case IMB_CIPHER_CFB:
                job->enc_keys = enc_keys;
                job->dec_keys = enc_keys;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_GCM:
        case IMB_CIPHER_SM4_GCM:
                job->enc_keys = gdata_key;
                job->dec_keys = gdata_key;
                job->u.GCM.aad_len_in_bytes = params->aad_size;
                job->u.GCM.aad = aad;
                job->iv_len_in_bytes = 12;
                break;
        case IMB_CIPHER_CCM:
                job->msg_len_to_cipher_in_bytes = buf_size;
                job->msg_len_to_hash_in_bytes = buf_size;
                job->u.CCM.aad_len_in_bytes = params->aad_size;
                job->u.CCM.aad = aad;
                job->enc_keys = enc_keys;
                job->dec_keys = enc_keys;
                job->iv_len_in_bytes = 13;
                break;
        case IMB_CIPHER_DES:
        case IMB_CIPHER_DOCSIS_DES:
                job->enc_keys = enc_keys;
                job->dec_keys = enc_keys;
                job->iv_len_in_bytes = 8;
                break;
        case IMB_CIPHER_DES3:
                ks_ptr[0] = ks_ptr[1] = ks_ptr[2] = enc_keys;
                job->enc_keys = ks_ptr;
                job->dec_keys = ks_ptr;
                job->iv_len_in_bytes = 8;
                break;
        case IMB_CIPHER_ECB:
        case IMB_CIPHER_SM4_ECB:
                job->enc_keys = enc_keys;
                job->dec_keys = dec_keys;
                job->iv_len_in_bytes = 0;
                break;
        case IMB_CIPHER_ZUC_EEA3:
                job->enc_keys = ck;
                job->dec_keys = ck;
                if (job->key_len_in_bytes == 16)
                        job->iv_len_in_bytes = 16;
                else /* 32 */
                        job->iv_len_in_bytes = 25;
                break;
        case IMB_CIPHER_SNOW3G_UEA2:
                job->enc_keys = ck;
                job->dec_keys = ck;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_KASUMI_UEA1:
                job->enc_keys = ck;
                job->dec_keys = ck;
                job->iv_len_in_bytes = 8;
                break;
        case IMB_CIPHER_CHACHA20:
        case IMB_CIPHER_CHACHA20_POLY1305:
        case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                job->enc_keys = ck;
                job->dec_keys = ck;
                job->iv_len_in_bytes = 12;
                break;
        case IMB_CIPHER_SNOW5G_NEA4:
        case IMB_CIPHER_ZUC_NEA6:
                job->enc_keys = ck;
                job->dec_keys = ck;
                job->iv_len_in_bytes = 16;
                break;
        case IMB_CIPHER_NULL:
                /* No operation needed */
                break;
        default:
                printf("Unsupported cipher mode\n");
                return -1;
        }

        /*
         * If cipher IV size is set from command line,
         * overwrite the value here.
         */
        if (cipher_iv_size != 0)
                job->iv_len_in_bytes = cipher_iv_size;

        return 0;
}

/*
 * Checks if the cipher mode and hash algorithm combination is supported
 * by the test applications.
 * Returns 1 if the combination is valid, 0 otherwise.
 */
int
is_valid_combination(const IMB_CIPHER_MODE c_mode, const IMB_HASH_ALG hash_alg)
{
        /* Skip not supported combinations */
        if ((c_mode == IMB_CIPHER_GCM && hash_alg != IMB_AUTH_AES_GMAC) ||
            (c_mode != IMB_CIPHER_GCM && hash_alg == IMB_AUTH_AES_GMAC))
                return 0;
        if ((c_mode == IMB_CIPHER_CCM && hash_alg != IMB_AUTH_AES_CCM) ||
            (c_mode != IMB_CIPHER_CCM && hash_alg == IMB_AUTH_AES_CCM))
                return 0;
        if ((c_mode == IMB_CIPHER_SM4_GCM && hash_alg != IMB_AUTH_SM4_GCM) ||
            (c_mode != IMB_CIPHER_SM4_GCM && hash_alg == IMB_AUTH_SM4_GCM))
                return 0;
        if ((c_mode == IMB_CIPHER_PON_AES_CNTR && hash_alg != IMB_AUTH_PON_CRC_BIP) ||
            (c_mode != IMB_CIPHER_PON_AES_CNTR && hash_alg == IMB_AUTH_PON_CRC_BIP))
                return 0;
        if (c_mode == IMB_CIPHER_DOCSIS_SEC_BPI &&
            (hash_alg != IMB_AUTH_NULL && hash_alg != IMB_AUTH_DOCSIS_CRC32))
                return 0;
        if (c_mode != IMB_CIPHER_DOCSIS_SEC_BPI && hash_alg == IMB_AUTH_DOCSIS_CRC32)
                return 0;
        if ((c_mode == IMB_CIPHER_CHACHA20_POLY1305 && hash_alg != IMB_AUTH_CHACHA20_POLY1305) ||
            (c_mode != IMB_CIPHER_CHACHA20_POLY1305 && hash_alg == IMB_AUTH_CHACHA20_POLY1305))
                return 0;

        if ((c_mode == IMB_CIPHER_AES_NCA5 && hash_alg != IMB_AUTH_AES_NCA5) ||
            (c_mode != IMB_CIPHER_AES_NCA5 && hash_alg == IMB_AUTH_AES_NCA5))
                return 0;

        if ((c_mode == IMB_CIPHER_ZUC_NCA6 && hash_alg != IMB_AUTH_ZUC_NCA6) ||
            (c_mode != IMB_CIPHER_ZUC_NCA6 && hash_alg == IMB_AUTH_ZUC_NCA6))
                return 0;
        if ((c_mode == IMB_CIPHER_SNOW5G_NCA4 && hash_alg != IMB_AUTH_SNOW5G_NCA4) ||
            (c_mode != IMB_CIPHER_SNOW5G_NCA4 && hash_alg == IMB_AUTH_SNOW5G_NCA4))
                return 0;
        /* This test app does not support SGL yet */
        if ((c_mode == IMB_CIPHER_CHACHA20_POLY1305_SGL) ||
            (hash_alg == IMB_AUTH_CHACHA20_POLY1305_SGL))
                return 0;

        if ((c_mode == IMB_CIPHER_GCM_SGL) || (hash_alg == IMB_AUTH_GCM_SGL))
                return 0;

        return 1;
}

/*
 * Checks if the buffer size can be used with the selected algorithms.
 * Returns 1 if the size is valid, 0 otherwise.
 */
int
is_valid_job_size(const struct params_s *params, const uint32_t buf_size)
{
        /*
         * CBC, CFB and ECB operation modes do not support lengths
         * which are non-multiple of block size
         */
        if (params->cipher_mode == IMB_CIPHER_CBC || params->cipher_mode == IMB_CIPHER_CFB ||
            params->cipher_mode == IMB_CIPHER_ECB)
                if ((buf_size % IMB_AES_BLOCK_SIZE) != 0)
                        return 0;

        if (params->cipher_mode == IMB_CIPHER_SM4_ECB || params->cipher_mode == IMB_CIPHER_SM4_CBC)
                if ((buf_size % IMB_SM4_BLOCK_SIZE) != 0)
                        return 0;

        if (params->cipher_mode == IMB_CIPHER_DES || params->cipher_mode == IMB_CIPHER_DES3)
                if ((buf_size % IMB_DES_BLOCK_SIZE) != 0)
                        return 0;

        /*
         * KASUMI-UIA1 needs to be at least 9 bytes
         * (IV + direction bit + '1' + 0s to align to
         * byte boundary)
         */
        if (params->hash_alg == IMB_AUTH_KASUMI_UIA1)
                if (buf_size < (IMB_KASUMI_BLOCK_SIZE + 1))
                        return 0;

        return 1;
}

/*
 * Returns a random message size, valid for the selected algorithms,
 * to be used by IMIX (mixed size) tests.
 */
uint32_t
generate_imix_job_size(const struct params_s *params, const uint32_t max_size)
{
        uint32_t random_num = (uint32_t) rand() % max_size;

        /* If random number is 0, change the size to 16 */
        if (random_num == 0)
                random_num = 16;

        /*
         * CBC, CFB and ECB operation modes do not support lengths
         * which are non-multiple of block size
         */
        if (params->cipher_mode == IMB_CIPHER_CBC || params->cipher_mode == IMB_CIPHER_CFB ||
            params->cipher_mode == IMB_CIPHER_ECB) {
                random_num += (IMB_AES_BLOCK_SIZE - 1);
                random_num &= (~(IMB_AES_BLOCK_SIZE - 1));
        }

        if (params->cipher_mode == IMB_CIPHER_DES || params->cipher_mode == IMB_CIPHER_DES3) {
                random_num += (IMB_DES_BLOCK_SIZE - 1);
                random_num &= (~(IMB_DES_BLOCK_SIZE - 1));
        }

        if (params->cipher_mode == IMB_CIPHER_SM4_ECB ||
            params->cipher_mode == IMB_CIPHER_SM4_CBC) {
                random_num += (IMB_SM4_BLOCK_SIZE - 1);
                random_num &= (~(IMB_SM4_BLOCK_SIZE - 1));
        }

        /*
         * KASUMI-UIA1 needs to be at least 9 bytes
         * (IV + direction bit + '1' + 0s to align to
         * byte boundary)
         */
        if (params->hash_alg == IMB_AUTH_KASUMI_UIA1)
                if (random_num < (IMB_KASUMI_BLOCK_SIZE + 1))
                        random_num = 16;

        return random_num;
}

int
get_next_num_arg(const char *const *argv, const int index, const int argc, void *dst,
                 const size_t dst_size)
{
        char *endptr = NULL;
        uint64_t val, max_val;

        if (dst == NULL || argv == NULL || index < 0 || argc < 0) {
                fprintf(stderr, "%s() internal error!\n", __func__);
                exit(EXIT_FAILURE);
        }

        if (index >= (argc - 1)) {
                fprintf(stderr, "'%s' requires an argument!\n", argv[index]);
                exit(EXIT_FAILURE);
        }

        const char *arg = argv[index + 1];

        /* strtoull() accepts negative numbers and wraps them around */
        for (const char *p = arg; *p != '\0'; p++) {
                if (isspace((unsigned char) *p))
                        continue;
                if (*p == '-') {
                        fprintf(stderr, "Negative value '%s' not allowed for '%s'!\n", arg,
                                argv[index]);
                        exit(EXIT_FAILURE);
                }
                break;
        }

        errno = 0;
#ifdef _WIN32
        val = _strtoui64(arg, &endptr, 0);
#else
        val = strtoull(arg, &endptr, 0);
#endif
        if (endptr == arg || (endptr != NULL && *endptr != '\0')) {
                fprintf(stderr, "Error converting '%s' as value for '%s'!\n", arg, argv[index]);
                exit(EXIT_FAILURE);
        }

        if (errno == ERANGE) {
                fprintf(stderr, "Value '%s' for '%s' is out of range!\n", arg, argv[index]);
                exit(EXIT_FAILURE);
        }

        switch (dst_size) {
        case (sizeof(uint8_t)):
                max_val = UINT8_MAX;
                break;
        case (sizeof(uint16_t)):
                max_val = UINT16_MAX;
                break;
        case (sizeof(uint32_t)):
                max_val = UINT32_MAX;
                break;
        case (sizeof(uint64_t)):
                max_val = UINT64_MAX;
                break;
        default:
                fprintf(stderr, "%s() invalid dst_size %u!\n", __func__, (unsigned) dst_size);
                exit(EXIT_FAILURE);
                break;
        }

        if (val > max_val) {
                fprintf(stderr, "Value '%s' for '%s' exceeds maximum of %" PRIu64 "!\n", arg,
                        argv[index], max_val);
                exit(EXIT_FAILURE);
        }

        switch (dst_size) {
        case (sizeof(uint8_t)):
                *((uint8_t *) dst) = (uint8_t) val;
                break;
        case (sizeof(uint16_t)):
                *((uint16_t *) dst) = (uint16_t) val;
                break;
        case (sizeof(uint32_t)):
                *((uint32_t *) dst) = (uint32_t) val;
                break;
        case (sizeof(uint64_t)):
                *((uint64_t *) dst) = val;
                break;
        default:
                fprintf(stderr, "%s() invalid dst_size %u!\n", __func__, (unsigned) dst_size);
                exit(EXIT_FAILURE);
                break;
        }

        return index + 1;
}

/*
 * Check string argument is supported and if it is, return values associated
 * with it.
 */
const union params *
check_string_arg(const char *param, const char *arg, const struct str_value_mapping *map,
                 const size_t num_avail_opts)
{
        unsigned int i;

        if (arg == NULL) {
                fprintf(stderr, "%s requires an argument\n", param);
                goto exit;
        }

        for (i = 0; i < num_avail_opts; i++)
                if (strcasecmp(arg, map[i].name) == 0)
                        return &(map[i].values);

        /* Argument is not listed in the available options */
        fprintf(stderr, "Invalid argument for %s\n", param);
exit:
        fprintf(stderr, "Accepted arguments: ");
        for (i = 0; i < num_avail_opts; i++)
                fprintf(stderr, "%s ", map[i].name);
        fprintf(stderr, "\n");

        return NULL;
}

int
parse_range(const char *const *argv, const int index, const int argc,
            uint32_t range_values[NUM_RANGE])
{
        char *token;
        unsigned int i;

        if (range_values == NULL || argv == NULL || index < 0 || argc < 0) {
                fprintf(stderr, "%s() internal error!\n", __func__);
                exit(EXIT_FAILURE);
        }

        if (index >= (argc - 1)) {
                fprintf(stderr, "'%s' requires an argument!\n", argv[index]);
                exit(EXIT_FAILURE);
        }

        char *copy_arg = strdup(argv[index + 1]);

        if (copy_arg == NULL) {
                fprintf(stderr, "%s() internal error!\n", __func__);
                exit(EXIT_FAILURE);
        }

        token = strtok(copy_arg, ":");

        /* Try parsing range (minimum, step and maximum values) */
        for (i = 0; i < NUM_RANGE; i++) {
                char *endptr = NULL;
                unsigned long number;

                if (token == NULL)
                        goto no_range;

                /* strtoul() accepts negative numbers and wraps them around */
                if (strchr(token, '-') != NULL)
                        goto no_range;

                errno = 0;
                number = strtoul(token, &endptr, 10);

                /* the complete token has to be a valid 32-bit number */
                if (errno != 0 || endptr == token || *endptr != '\0' || number > UINT32_MAX)
                        goto no_range;

                range_values[i] = (uint32_t) number;
                token = strtok(NULL, ":");
        }

        if (token != NULL)
                goto no_range;

#ifndef PIN_BASED_CEC
        if (range_values[RANGE_MAX] < range_values[RANGE_MIN]) {
                fprintf(stderr, "Maximum value of range cannot be lower "
                                "than minimum value\n");
                exit(EXIT_FAILURE);
        }

        if (range_values[RANGE_STEP] == 0) {
                fprintf(stderr, "Step value in range cannot be 0\n");
                exit(EXIT_FAILURE);
        }
#endif
        goto end_range;
no_range:
        /* Try parsing as single value */
        get_next_num_arg(argv, index, argc, &range_values[RANGE_MIN],
                         sizeof(range_values[RANGE_MIN]));

        range_values[RANGE_MAX] = range_values[RANGE_MIN];

end_range:
        free(copy_arg);
        return (index + 1);
}
