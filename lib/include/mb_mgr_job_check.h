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

#ifndef MB_MGR_JOB_CHECK_H
#define MB_MGR_JOB_CHECK_H

#include "intel-ipsec-mb.h"
#include "include/error.h"

/* GCM NIST standard: len(M) < 2^39 - 256 */
#define GCM_MAX_LEN  UINT64_C(((1ULL << 39) - 256) - 1)
#define SNOW3G_MAX_BITLEN (UINT32_MAX)
#define MB_MAX_LEN16 ((1 << 16) - 2)

__forceinline int
is_job_invalid(IMB_MGR *state, const IMB_JOB *job,
               const IMB_CIPHER_MODE cipher_mode, const IMB_HASH_ALG hash_alg,
               const IMB_CIPHER_DIRECTION cipher_direction,
               const IMB_KEY_SIZE_BYTES key_len_in_bytes)
{
        const uint64_t auth_tag_len_fips[] = {
                0,  /* INVALID selection */
                20, /* IMB_AUTH_HMAC_SHA_1 */
                28, /* IMB_AUTH_HMAC_SHA_224 */
                32, /* IMB_AUTH_HMAC_SHA_256 */
                48, /* IMB_AUTH_HMAC_SHA_384 */
                64, /* IMB_AUTH_HMAC_SHA_512 */
                12, /* IMB_AUTH_AES_XCBC */
                16, /* IMB_AUTH_MD5 */
                0,  /* IMB_AUTH_NULL */
                16, /* IMB_AUTH_AES_GMAC */
                0,  /* IMB_AUTH_CUSTOM */
                0,  /* IMB_AUTH_AES_CCM */
                16, /* IMB_AUTH_AES_CMAC */
                20, /* IMB_AUTH_SHA_1 */
                28, /* IMB_AUTH_SHA_224 */
                32, /* IMB_AUTH_SHA_256 */
                48, /* IMB_AUTH_SHA_384 */
                64, /* IMB_AUTH_SHA_512 */
                4,  /* IMB_AUTH_AES_CMAC 3GPP */
                8,  /* IMB_AUTH_PON_CRC_BIP */
                4,  /* IMB_AUTH_ZUC_EIA3_BITLEN */
                4,  /* IMB_AUTH_DOCSIS_CRC32 */
                4,  /* IMB_AUTH_SNOW3G_UIA2_BITLEN */
                4,  /* IMB_AUTH_KASUMI_UIA1 */
                16, /* IMB_AUTH_AES_GMAC_128 */
                16, /* IMB_AUTH_AES_GMAC_192 */
                16, /* IMB_AUTH_AES_GMAC_256 */
                16, /* IMB_AUTH_AES_CMAC_256 */
                16, /* IMB_AUTH_POLY1305 */
                16, /* IMB_AUTH_CHACHA_POLY1305 */
                16, /* IMB_AUTH_CHACHA_POLY1305_SGL */
                4,  /* IMB_AUTH_ZUC256_EIA3_BITLEN */
                16, /* IMB_AUTH_SNOW_V_AEAD */
                16, /* IMB_AUTH_AES_GCM_SGL */
                4,  /* IMB_AUTH_CRC32_ETHERNET_FCS */
                4,  /* IMB_AUTH_CRC32_SCTP */
                4,  /* IMB_AUTH_CRC32_WIMAX_OFDMA_DATA */
                4,  /* IMB_AUTH_CRC24_LTE_A */
                4,  /* IMB_AUTH_CRC24_LTE_B */
                4,  /* IMB_AUTH_CRC16_X25 */
                4,  /* IMB_AUTH_CRC16_FP_DATA */
                4,  /* IMB_AUTH_CRC11_FP_HEADER */
                4,  /* IMB_AUTH_CRC10_IUUP_DATA */
                4,  /* IMB_AUTH_CRC8_WIMAX_OFDMA_HCS */
                4,  /* IMB_AUTH_CRC7_FP_HEADER */
                4,  /* IMB_AUTH_CRC6_IUUP_HEADER */
                16, /* IMB_AUTH_GHASH */
        };
        const uint64_t auth_tag_len_ipsec[] = {
                0,  /* INVALID selection */
                12, /* IMB_AUTH_HMAC_SHA_1 */
                14, /* IMB_AUTH_HMAC_SHA_224 */
                16, /* IMB_AUTH_HMAC_SHA_256 */
                24, /* IMB_AUTH_HMAC_SHA_384 */
                32, /* IMB_AUTH_HMAC_SHA_512 */
                12, /* IMB_AUTH_AES_XCBC */
                12, /* IMB_AUTH_MD5 */
                0,  /* IMB_AUTH_NULL */
                16, /* IMB_AUTH_AES_GMAC */
                0,  /* IMB_AUTH_CUSTOM */
                0,  /* IMB_AUTH_AES_CCM */
                16, /* IMB_AUTH_AES_CMAC */
                20, /* IMB_AUTH_SHA_1 */
                28, /* IMB_AUTH_SHA_224 */
                32, /* IMB_AUTH_SHA_256 */
                48, /* IMB_AUTH_SHA_384 */
                64, /* IMB_AUTH_SHA_512 */
                4,  /* IMB_AUTH_AES_CMAC 3GPP */
                8,  /* IMB_AUTH_PON_CRC_BIP */
                4,  /* IMB_AUTH_ZUC_EIA3_BITLEN */
                4,  /* IMB_AUTH_DOCSIS_CRC32 */
                4,  /* IMB_AUTH_SNOW3G_UIA2_BITLEN */
                4,  /* IMB_AUTH_KASUMI_UIA1 */
                16, /* IMB_AUTH_AES_GMAC_128 */
                16, /* IMB_AUTH_AES_GMAC_192 */
                16, /* IMB_AUTH_AES_GMAC_256 */
                16, /* IMB_AUTH_AES_CMAC_256 */
                16, /* IMB_AUTH_POLY1305 */
                16, /* IMB_AUTH_CHACHA_POLY1305 */
                16, /* IMB_AUTH_CHACHA_POLY1305_SGL */
                4,  /* IMB_AUTH_ZUC256_EIA3_BITLEN */
                16, /* IMB_AUTH_SNOW_V_AEAD */
                16, /* IMB_AUTH_AES_GCM_SGL */
                4,  /* IMB_AUTH_CRC32_ETHERNET_FCS */
                4,  /* IMB_AUTH_CRC32_SCTP */
                4,  /* IMB_AUTH_CRC32_WIMAX_OFDMA_DATA */
                4,  /* IMB_AUTH_CRC24_LTE_A */
                4,  /* IMB_AUTH_CRC24_LTE_B */
                4,  /* IMB_AUTH_CRC16_X25 */
                4,  /* IMB_AUTH_CRC16_FP_DATA */
                4,  /* IMB_AUTH_CRC11_FP_HEADER */
                4,  /* IMB_AUTH_CRC10_IUUP_DATA */
                4,  /* IMB_AUTH_CRC8_WIMAX_OFDMA_HCS */
                4,  /* IMB_AUTH_CRC7_FP_HEADER */
                4,  /* IMB_AUTH_CRC6_IUUP_HEADER */
                16, /* IMB_AUTH_GHASH */
        };

        /* Maximum length of buffer in PON is 2^14 + 8, since maximum
         * PLI value is 2^14 - 1 + 1 extra byte of padding + 8 bytes
         * of XGEM header */
        const uint64_t max_pon_len = (1 << 14) + 8;

        if (cipher_direction != IMB_DIR_DECRYPT &&
            cipher_direction != IMB_DIR_ENCRYPT &&
            cipher_mode != IMB_CIPHER_NULL) {
                imb_set_errno(state, IMB_ERR_JOB_CIPH_DIR);
                return 1;
        }
        switch (cipher_mode) {
        case IMB_CIPHER_CBC:
        case IMB_CIPHER_CBCS_1_9:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_ENCRYPT &&
                    job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_DECRYPT &&
                    job->dec_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(16) &&
                    key_len_in_bytes != UINT64_C(24) &&
                    key_len_in_bytes != UINT64_C(32)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes & UINT64_C(15)) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (cipher_mode == IMB_CIPHER_CBCS_1_9) {
                        if (job->msg_len_to_cipher_in_bytes >
                            ((1ULL << (60)) - 1)) {
                                imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                                return 1;
                        }
                        if (job->cipher_fields.CBCS.next_iv == NULL) {
                                imb_set_errno(state,
                                              IMB_ERR_JOB_NULL_NEXT_IV);
                                return 1;
                        }
                } else if (cipher_direction == IMB_DIR_ENCRYPT &&
                           job->msg_len_to_cipher_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                break;
        case IMB_CIPHER_ECB:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_ENCRYPT &&
                    job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_DECRYPT &&
                    job->dec_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(16) &&
                    key_len_in_bytes != UINT64_C(24) &&
                    key_len_in_bytes != UINT64_C(32)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0 ||
                    job->msg_len_to_cipher_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes & UINT64_C(15)) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(0)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                break;
        case IMB_CIPHER_CNTR:
        case IMB_CIPHER_CNTR_BITLEN:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(16) &&
                    key_len_in_bytes != UINT64_C(24) &&
                    key_len_in_bytes != UINT64_C(32)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if ((cipher_mode == IMB_CIPHER_CNTR &&
                     job->iv_len_in_bytes != UINT64_C(16) &&
                     job->iv_len_in_bytes != UINT64_C(12)) ||
                     (cipher_mode == IMB_CIPHER_CNTR_BITLEN &&
                      job->iv_len_in_bytes != UINT64_C(16))) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                /*
                 * msg_len_to_cipher_in_bits is used with CNTR_BITLEN, but it is
                 * effectively the same field as msg_len_to_cipher_in_bytes,
                 * since it is part of the same union
                 */
                if (job->msg_len_to_cipher_in_bytes == 0) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                break;
        case IMB_CIPHER_NULL:
                /*
                 * No checks required for this mode
                 * @note NULL cipher doesn't perform memory copy operation
                 *       from source to destination
                 */
                break;
        case IMB_CIPHER_DOCSIS_SEC_BPI:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->enc_keys == NULL) {
                        /* it has to be set regardless of direction (AES-CFB) */
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_DECRYPT &&
                    job->dec_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if ((key_len_in_bytes != UINT64_C(16)) &&
                    (key_len_in_bytes != UINT64_C(32))) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                break;
        case IMB_CIPHER_GCM:
        case IMB_CIPHER_GCM_SGL:
                if (job->msg_len_to_cipher_in_bytes > GCM_MAX_LEN) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes != 0 && job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes != 0 && job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                /* Same key structure used for encrypt and decrypt */
                if (cipher_direction == IMB_DIR_ENCRYPT &&
                    job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_DECRYPT &&
                    job->dec_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(16) &&
                    key_len_in_bytes != UINT64_C(24) &&
                    key_len_in_bytes != UINT64_C(32)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes == 0) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                if (cipher_mode == IMB_CIPHER_GCM &&
                    hash_alg != IMB_AUTH_AES_GMAC) {
                        imb_set_errno(state, IMB_ERR_HASH_ALGO);
                        return 1;
                }
                if (cipher_mode == IMB_CIPHER_GCM_SGL &&
                    hash_alg != IMB_AUTH_GCM_SGL) {
                        imb_set_errno(state, IMB_ERR_HASH_ALGO);
                        return 1;
                }
                break;
        case IMB_CIPHER_CUSTOM:
                /* no checks here */
                if (job->cipher_func == NULL) {
                        imb_set_errno(state, EFAULT);
                        return 1;
                }
                break;
        case IMB_CIPHER_DES:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_ENCRYPT &&
                    job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_DECRYPT &&
                    job->dec_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(8)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0 ||
                    job->msg_len_to_cipher_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes & UINT64_C(7)) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(8)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                break;
        case IMB_CIPHER_DOCSIS_DES:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_ENCRYPT &&
                    job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_DECRYPT &&
                    job->dec_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(8)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0 ||
                    job->msg_len_to_cipher_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(8)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                break;
        case IMB_CIPHER_CCM:
                if (job->msg_len_to_cipher_in_bytes != 0) {
                        if (job->src == NULL) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                                return 1;
                        }
                        if (job->dst == NULL) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                                return 1;
                        }
                }
                if (job->msg_len_to_cipher_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->enc_keys == NULL) {
                        /* AES-CTR and CBC-MAC use only encryption keys */
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                /* currently only AES-CCM-128 and AES-CCM-256 supported */
                if (key_len_in_bytes != UINT64_C(16) &&
                    key_len_in_bytes != UINT64_C(32)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                /*
                 * From RFC3610:
                 *     Nonce length = 15 - L
                 *     Valid L values are: 2 to 8
                 * Then valid nonce lengths 13 to 7 (inclusive).
                 */
                if (job->iv_len_in_bytes > UINT64_C(13) ||
                    job->iv_len_in_bytes < UINT64_C(7)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                if (hash_alg != IMB_AUTH_AES_CCM) {
                        imb_set_errno(state, IMB_ERR_HASH_ALGO);
                        return 1;
                }
                break;
        case IMB_CIPHER_DES3:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(24)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0 ||
                    job->msg_len_to_cipher_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes & UINT64_C(7)) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(8)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                if (cipher_direction == IMB_DIR_ENCRYPT) {
                        const void * const *ks_ptr =
                                (const void * const *)job->enc_keys;

                        if (ks_ptr == NULL) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                                return 1;
                        }
                        if (ks_ptr[0] == NULL || ks_ptr[1] == NULL ||
                            ks_ptr[2] == NULL) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                                return 1;
                        }
                } else {
                        const void * const *ks_ptr =
                                (const void * const *)job->dec_keys;

                        if (ks_ptr == NULL) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                                return 1;
                        }
                        if (ks_ptr[0] == NULL || ks_ptr[1] == NULL ||
                            ks_ptr[2] == NULL) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                                return 1;
                        }
                }
                break;
        case IMB_CIPHER_PON_AES_CNTR:
                /*
                 * CRC and cipher are done together. A few assumptions:
                 * - CRC and cipher start offsets are the same
                 * - last 4 bytes (32 bits) of the buffer is CRC
                 * - updated CRC value is put into the source buffer
                 *   (encryption only)
                 * - CRC length is msg_len_to_cipher_in_bytes - 4 bytes
                 * - msg_len_to_cipher_in_bytes is aligned to 4 bytes
                 * - If msg_len_to_cipher_in_bytes is 0, IV and key pointers
                 *   are not required, as encryption is not done
                 */
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }

                /* source and destination buffer pointers cannot be the same,
                 * as there are always 8 bytes that are not ciphered */
                if ((job->src + job->cipher_start_src_offset_in_bytes)
                    != job->dst) {
                        imb_set_errno(state, EINVAL);
                        return 1;
                }
                if (hash_alg != IMB_AUTH_PON_CRC_BIP) {
                        imb_set_errno(state, IMB_ERR_HASH_ALGO);
                        return 1;
                }
                /*
                 * If message length to cipher != 0, AES-CTR is performed and
                 * key and IV require to be set properly
                 */
                if (job->msg_len_to_cipher_in_bytes != UINT64_C(0)) {

                        /* message size needs to be aligned to 4 bytes */
                        if ((job->msg_len_to_cipher_in_bytes & 3) != 0) {
                                imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                                return 1;
                        }

                        /* Subtract 8 bytes to maximum length since
                         * XGEM header is not ciphered */
                        if ((job->msg_len_to_cipher_in_bytes >
                             (max_pon_len - 8))) {
                                imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                                return 1;
                        }

                        if (key_len_in_bytes != UINT64_C(16)) {
                                imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                                return 1;
                        }
                        if (job->iv_len_in_bytes != UINT64_C(16)) {
                                imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                                return 1;
                        }
                        if (job->iv == NULL) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                                return 1;
                        }
                        if (job->enc_keys == NULL) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                                return 1;
                        }
                }
                if (job->msg_len_to_cipher_in_bytes >= 4) {
                        const uint64_t xgem_hdr = *(const uint64_t *)
                                (job->src +
                                 job->hash_start_src_offset_in_bytes);

                        /* PLI is 14 MS bits of XGEM header */
                        const uint16_t pli = BSWAP64(xgem_hdr) >> 50;

                        /* CRC only if PLI is more than 4 bytes */
                        if (pli > 4) {
                                const uint16_t crc_len = pli - 4;

                                if (crc_len >
                                    job->msg_len_to_cipher_in_bytes - 4) {
                                        imb_set_errno(state,
                                                      IMB_ERR_JOB_PON_PLI);
                                        return 1;
                                }
                        }
                }
                break;
        case IMB_CIPHER_ZUC_EEA3:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(16) &&
                    key_len_in_bytes != UINT64_C(32)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes == 0 ||
                    job->msg_len_to_cipher_in_bytes > ZUC_MAX_BYTELEN) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (key_len_in_bytes == UINT64_C(16)) {
                        if (job->iv_len_in_bytes != UINT64_C(16)) {
                                imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                                return 1;
                        }
                } else {
                        if (job->iv_len_in_bytes != UINT64_C(23) &&
                            job->iv_len_in_bytes != UINT64_C(25)) {
                                imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                                return 1;
                        }
                }
                break;
        case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bits == 0 ||
                    job->msg_len_to_cipher_in_bits > SNOW3G_MAX_BITLEN) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                break;
        case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bits == 0 ||
                    job->msg_len_to_cipher_in_bits > KASUMI_MAX_LEN) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(8)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                break;
        case IMB_CIPHER_CHACHA20:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(32)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                /* Per RFC 7539, max cipher size is (2^32 - 1) x 64 */
                if (job->msg_len_to_cipher_in_bytes == 0 ||
                    job->msg_len_to_cipher_in_bytes > ((1ULL << 38) - 64)) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(12)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                break;
        case IMB_CIPHER_CHACHA20_POLY1305:
        case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                if (job->msg_len_to_cipher_in_bytes != 0 && job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes != 0 && job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(32)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                /* Per RFC 7539, max cipher size is (2^32 - 1) x 64 */
                if (job->msg_len_to_cipher_in_bytes > ((1ULL << 38) - 64)) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(12)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                break;
        case IMB_CIPHER_SNOW_V_AEAD:
        case IMB_CIPHER_SNOW_V:
                if (job->msg_len_to_cipher_in_bytes != 0 && job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes != 0 && job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (job->iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->enc_keys == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (key_len_in_bytes != UINT64_C(32)) {
                        imb_set_errno(state, IMB_ERR_JOB_KEY_LEN);
                        return 1;
                }
                if (job->iv_len_in_bytes != UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                if (cipher_mode == IMB_CIPHER_SNOW_V_AEAD &&
                    hash_alg != IMB_AUTH_SNOW_V_AEAD) {
                        imb_set_errno(state, IMB_ERR_HASH_ALGO);
                        return 1;
                }
                break;
        default:
                imb_set_errno(state, IMB_ERR_CIPH_MODE);
                return 1;
        }

        switch (hash_alg) {
        case IMB_AUTH_HMAC_SHA_1:
        case IMB_AUTH_MD5:
        case IMB_AUTH_HMAC_SHA_224:
        case IMB_AUTH_HMAC_SHA_256:
        case IMB_AUTH_HMAC_SHA_384:
        case IMB_AUTH_HMAC_SHA_512:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg] &&
                    job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_fips[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes == 0 ||
                    job->msg_len_to_hash_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->u.HMAC._hashed_auth_key_xor_ipad == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_HMAC_IPAD);
                        return 1;
                }
                if (job->u.HMAC._hashed_auth_key_xor_opad == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_HMAC_OPAD);
                        return 1;
                }
                break;
        case IMB_AUTH_AES_XCBC:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg] &&
                    job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_fips[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                if (job->u.XCBC._k1_expanded == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_XCBC_K1_EXP);
                        return 1;
                }
                if (job->u.XCBC._k2 == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_XCBC_K2);
                        return 1;
                }
                if (job->u.XCBC._k3 == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_XCBC_K3);
                        return 1;
                }
                break;
        case IMB_AUTH_NULL:
                break;
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
                if (job->src == NULL && job->msg_len_to_hash_in_bytes != 0) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                break;
        case IMB_AUTH_AES_GMAC:
                if (job->auth_tag_output_len_in_bytes < UINT64_C(1) ||
                    job->auth_tag_output_len_in_bytes > UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if ((job->u.GCM.aad_len_in_bytes > 0) &&
                    (job->u.GCM.aad == NULL)) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AAD);
                        return 1;
                }
                if (cipher_mode != IMB_CIPHER_GCM) {
                        imb_set_errno(state, IMB_ERR_CIPH_MODE);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                /*
                 * msg_len_to_hash_in_bytes not checked against zero.
                 * It is not used for AES-GCM & GMAC - see
                 * SUBMIT_JOB_AES_GCM_ENC and SUBMIT_JOB_AES_GCM_DEC functions.
                 */
                break;
        case IMB_AUTH_GCM_SGL:
                if (cipher_mode != IMB_CIPHER_GCM_SGL) {
                        imb_set_errno(state, IMB_ERR_CIPH_MODE);
                        return 1;
                }
                if (job->u.GCM.ctx == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SGL_CTX);
                        return 1;
                }
                if (job->sgl_state == IMB_SGL_COMPLETE) {
                        if (job->auth_tag_output_len_in_bytes < UINT64_C(1) ||
                            job->auth_tag_output_len_in_bytes > UINT64_C(16)) {
                                imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                                return 1;
                        }
                        if (job->auth_tag_output == NULL) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                                return 1;
                        }
                }
                if (job->sgl_state == IMB_SGL_INIT) {
                        if ((job->u.GCM.aad_len_in_bytes > 0) &&
                            (job->u.GCM.aad == NULL)) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_AAD);
                                return 1;
                        }
                }
                break;
        case IMB_AUTH_AES_GMAC_128:
        case IMB_AUTH_AES_GMAC_192:
        case IMB_AUTH_AES_GMAC_256:
                if (job->auth_tag_output_len_in_bytes < UINT64_C(1) ||
                    job->auth_tag_output_len_in_bytes > UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                /* This GMAC mode is to be used as stand-alone,
                 * not combined with GCM */
                if (cipher_mode == IMB_CIPHER_GCM) {
                        imb_set_errno(state, IMB_ERR_CIPH_MODE);
                        return 1;
                }
                if (job->u.GMAC._key == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH_KEY);
                        return 1;
                }
                if (job->u.GMAC._iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->u.GMAC.iv_len_in_bytes == 0) {
                        imb_set_errno(state, IMB_ERR_JOB_IV_LEN);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes != 0 && job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                break;
        case IMB_AUTH_GHASH:
                if (job->auth_tag_output_len_in_bytes < UINT64_C(1) ||
                    job->auth_tag_output_len_in_bytes > UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->u.GHASH._key == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH_KEY);
                        return 1;
                }
                if (job->u.GHASH._init_tag == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_GHASH_INIT_TAG);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes != 0 && job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                break;
        case IMB_AUTH_CUSTOM:
                if (job->hash_func == NULL) {
                        imb_set_errno(state, EFAULT);
                        return 1;
                }
                break;
        case IMB_AUTH_AES_CCM:
                if (job->msg_len_to_hash_in_bytes != 0 && job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->u.CCM.aad_len_in_bytes > 46) {
                        /* 3 x AES_BLOCK - 2 bytes for AAD len */
                        imb_set_errno(state, IMB_ERR_JOB_AAD_LEN);
                        return 1;
                }
                if ((job->u.CCM.aad_len_in_bytes > 0) &&
                    (job->u.CCM.aad == NULL)) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AAD);
                        return 1;
                }
                /* M can be any even number from 4 to 16 */
                if (job->auth_tag_output_len_in_bytes < UINT64_C(4) ||
                    job->auth_tag_output_len_in_bytes > UINT64_C(16) ||
                    ((job->auth_tag_output_len_in_bytes & 1) != 0)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                                return 1;
                }
                if (cipher_mode != IMB_CIPHER_CCM) {
                        imb_set_errno(state, IMB_ERR_CIPH_MODE);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                /*
                 * AES-CCM allows for only one message for
                 * cipher and authentication.
                 * AAD can be used to extend authentication over
                 * clear text fields.
                 */
                if (job->msg_len_to_cipher_in_bytes !=
                    job->msg_len_to_hash_in_bytes) {
                        imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                        return 1;
                }
                if (job->cipher_start_src_offset_in_bytes !=
                    job->hash_start_src_offset_in_bytes) {
                        imb_set_errno(state, IMB_ERR_JOB_SRC_OFFSET);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                break;
        case IMB_AUTH_AES_CMAC:
        case IMB_AUTH_AES_CMAC_BITLEN:
        case IMB_AUTH_AES_CMAC_256:
                /*
                 * WARNING: When using IMB_AUTH_AES_CMAC_BITLEN, length of
                 * message is passed in bits, using job->msg_len_to_hash_in_bits
                 * (unlike "normal" IMB_AUTH_AES_CMAC, where is passed in bytes,
                 * using job->msg_len_to_hash_in_bytes).
                 */
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if ((job->u.CMAC._key_expanded == NULL) ||
                    (job->u.CMAC._skey1 == NULL) ||
                    (job->u.CMAC._skey2 == NULL)) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                /* T is 128 bits but 96 bits is also allowed due to
                 * IPsec use case (RFC 4494) and 32 bits for CMAC 3GPP.
                 * ACVP validation requires tag size of 8 bits.
                 */
                if (job->auth_tag_output_len_in_bytes < UINT64_C(1) ||
                    job->auth_tag_output_len_in_bytes > UINT64_C(16)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                break;
        case IMB_AUTH_SHA_1:
        case IMB_AUTH_SHA_224:
        case IMB_AUTH_SHA_256:
        case IMB_AUTH_SHA_384:
        case IMB_AUTH_SHA_512:
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                break;
        case IMB_AUTH_PON_CRC_BIP:
                /*
                 * Authentication tag in PON is BIP 32-bit value only
                 * CRC is done together with cipher,
                 * its initial value is read from the source buffer and
                 * updated value put into the destination buffer.
                 * - msg_len_to_hash_in_bytes is aligned to 4 bytes
                 */
                if (((job->msg_len_to_hash_in_bytes & UINT64_C(3)) != 0) ||
                    (job->msg_len_to_hash_in_bytes < UINT64_C(8)) ||
                    (job->msg_len_to_hash_in_bytes > max_pon_len)) {
                        /*
                         * Length aligned to 4 bytes (and at least 8 bytes,
                         * including 8-byte XGEM header and no more
                         * than max length)
                         */
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        /* 64-bits:
                         * - BIP 32-bits
                         * - CRC 32-bits
                         */
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (cipher_mode != IMB_CIPHER_PON_AES_CNTR) {
                        imb_set_errno(state, IMB_ERR_CIPH_MODE);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                break;
        case IMB_AUTH_ZUC_EIA3_BITLEN:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if ((job->msg_len_to_hash_in_bits < ZUC_MIN_BITLEN) ||
                    (job->msg_len_to_hash_in_bits > ZUC_MAX_BITLEN)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                if (job->u.ZUC_EIA3._key == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (job->u.ZUC_EIA3._iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                break;
        case IMB_AUTH_ZUC256_EIA3_BITLEN:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if ((job->msg_len_to_hash_in_bits < ZUC_MIN_BITLEN) ||
                    (job->msg_len_to_hash_in_bits > ZUC_MAX_BITLEN)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                if (job->u.ZUC_EIA3._key == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (job->u.ZUC_EIA3._iv == NULL) {
                        /* If 25-byte IV is NULL, check 23-byte IV */
                        if (job->u.ZUC_EIA3._iv23 == NULL) {
                                imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                                return 1;
                        }
                }
                if ((job->auth_tag_output_len_in_bytes != 4) &&
                    (job->auth_tag_output_len_in_bytes != 8) &&
                    (job->auth_tag_output_len_in_bytes != 16)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                break;
        case IMB_AUTH_DOCSIS_CRC32:
                /**
                 * Use only in combination with DOCSIS_SEC_BPI.
                 * Assumptions about Ethernet PDU carried over DOCSIS:
                 * - cipher_start_src_offset_in_bytes <=
                 *       (hash_start_src_offset_in_bytes + 12)
                 * - msg_len_to_cipher_in_bytes <=
                 *       (msg_len_to_hash_in_bytes - 12 + 4)
                 * - @note: in-place operation allowed only
                 * - authentication tag size is 4 bytes
                 * - @note: in encrypt direction, computed CRC value is put into
                 *   the source buffer
                 * - encrypt chain order: hash, cipher
                 * - decrypt chain order: cipher, hash
                 */
                if (cipher_mode != IMB_CIPHER_DOCSIS_SEC_BPI) {
                        imb_set_errno(state, IMB_ERR_CIPH_MODE);
                        return 1;
                }
                if (job->msg_len_to_cipher_in_bytes &&
                    job->msg_len_to_hash_in_bytes) {
                        const uint64_t ciph_adjust =
                                IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE -
                                2 - /* ETH TYPE */
                                IMB_DOCSIS_CRC32_TAG_SIZE;

                        if ((job->msg_len_to_cipher_in_bytes + ciph_adjust) >
                            job->msg_len_to_hash_in_bytes) {
                                imb_set_errno(state, IMB_ERR_JOB_CIPH_LEN);
                                return 1;
                        }
                        if (job->cipher_start_src_offset_in_bytes <
                            (job->hash_start_src_offset_in_bytes + 12)) {
                                imb_set_errno(state, IMB_ERR_JOB_SRC_OFFSET);
                                return 1;
                        }
                }
                if (job->msg_len_to_hash_in_bytes > MB_MAX_LEN16) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        /* Ethernet FCS CRC is 32-bits */
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if ((cipher_direction == IMB_DIR_ENCRYPT &&
                     job->chain_order != IMB_ORDER_HASH_CIPHER) ||
                    (cipher_direction == IMB_DIR_DECRYPT &&
                     job->chain_order != IMB_ORDER_CIPHER_HASH)) {
                        imb_set_errno(state, IMB_ERR_JOB_CHAIN_ORDER);
                        return 1;
                }
                break;
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if ((job->msg_len_to_hash_in_bits == 0) ||
                    (job->msg_len_to_hash_in_bits > SNOW3G_MAX_BITLEN)) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                if (job->u.SNOW3G_UIA2._key == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (job->u.SNOW3G_UIA2._iv == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_IV);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                break;
        case IMB_AUTH_KASUMI_UIA1:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                /*
                 * KASUMI-UIA1 needs to be at least 8 bytes
                 * (IV + direction bit + '1' + 0s to align to byte boundary)
                 */
                if ((job->msg_len_to_hash_in_bytes <
                     (IMB_KASUMI_BLOCK_SIZE + 1)) ||
                    (job->msg_len_to_hash_in_bytes >
                     (KASUMI_MAX_LEN / BYTESIZE))) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_LEN);
                        return 1;
                }
                if (job->u.KASUMI_UIA1._key == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_KEY);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                break;
        case IMB_AUTH_POLY1305:
                if (job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->u.POLY1305._key == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH_KEY);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                break;
        case IMB_AUTH_CHACHA20_POLY1305:
                if (job->msg_len_to_hash_in_bytes != 0 && job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes != 0 && job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (cipher_mode != IMB_CIPHER_CHACHA20_POLY1305) {
                        imb_set_errno(state, IMB_ERR_CIPH_MODE);
                        return 1;
                }
                if (job->u.CHACHA20_POLY1305.aad == NULL &&
                    job->u.CHACHA20_POLY1305.aad_len_in_bytes > 0) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AAD);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                break;
        case IMB_AUTH_CHACHA20_POLY1305_SGL:
                if (job->msg_len_to_hash_in_bytes != 0 && job->src == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SRC);
                        return 1;
                }
                if (job->msg_len_to_hash_in_bytes != 0 && job->dst == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_DST);
                        return 1;
                }
                if (cipher_mode != IMB_CIPHER_CHACHA20_POLY1305_SGL) {
                        imb_set_errno(state, IMB_ERR_CIPH_MODE);
                        return 1;
                }
                if (job->u.CHACHA20_POLY1305.aad == NULL &&
                    job->u.CHACHA20_POLY1305.aad_len_in_bytes > 0) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AAD);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (job->u.CHACHA20_POLY1305.ctx == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_SGL_CTX);
                        return 1;
                }
                break;
        case IMB_AUTH_SNOW_V_AEAD:
                if ((job->u.SNOW_V_AEAD.aad_len_in_bytes > 0) &&
                    (job->u.SNOW_V_AEAD.aad == NULL)) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AAD);
                        return 1;
                }
                if (job->auth_tag_output == NULL) {
                        imb_set_errno(state, IMB_ERR_JOB_NULL_AUTH);
                        return 1;
                }
                if (job->auth_tag_output_len_in_bytes !=
                    auth_tag_len_ipsec[hash_alg]) {
                        imb_set_errno(state, IMB_ERR_JOB_AUTH_TAG_LEN);
                        return 1;
                }
                if (cipher_mode != IMB_CIPHER_SNOW_V_AEAD) {
                        imb_set_errno(state, IMB_ERR_CIPH_MODE);
                        return 1;
                }
                break;
        default:
                imb_set_errno(state, IMB_ERR_HASH_ALGO);
                return 1;
        }
        return 0;
}

#endif /* MB_MGR_JOB_CHECK_H */
