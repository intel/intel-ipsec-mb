/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

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

/* Standard Includes */
#include <stdio.h>
#include <string.h>

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>

/* Intel IPsec library include */
#include <intel-ipsec-mb.h>

/* Local Includes */
#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_gcm.h"
#include "prov_ciphers.h"

#define PROV_GCM_TLS_TOTAL_IV_LEN             (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN)
#define PROV_GCM_TLS_PAYLOADLENGTH_MSB_OFFSET 2
#define PROV_GCM_TLS_PAYLOADLENGTH_LSB_OFFSET 1
#define PROV_BYTE_SHIFT                       8

#define AES_GCM_BLOCK_SIZE 1

#define TLS_VIRT_HDR_SIZE 13

#define AES_KEY_SIZE_128 16
#define AES_KEY_SIZE_192 24
#define AES_KEY_SIZE_256 32

/* The length of valid GCM Tag must be between 0 and 16 Bytes */
#define PROV_GCM_TAG_MIN_LEN 0
#define PROV_GCM_TAG_MAX_LEN 16

#define GET_TLS_HDR(qctx) ((qctx)->tls_aad)

#define GET_TLS_VERSION(hdr) (((hdr)[9]) << PROV_BYTE_SHIFT | (hdr)[10])

#define GET_TLS_PAYLOAD_LEN(hdr)                                                                   \
        (((((hdr)[11]) << PROV_BYTE_SHIFT) & 0xff00) | ((hdr)[12] & 0x00ff))

#define SET_TLS_PAYLOAD_LEN(hdr, len)                                                              \
        do {                                                                                       \
                hdr[11] = (len & 0xff00) >> PROV_BYTE_SHIFT;                                       \
                hdr[12] = len & 0xff;                                                              \
        } while (0)

int
vaesgcm_init_key(void *ctx, const unsigned char *inkey);
int
vaesgcm_init_gcm(void *ctx);

static int
prov_check_gcm_nid(int nid)
{
        if (nid == NID_aes_128_gcm || nid == NID_aes_192_gcm || nid == NID_aes_256_gcm)
                return 1;
        else
                return 0;
}

int
vaesgcm_ciphers_init(void *ctx, const unsigned char *inkey, const unsigned char *iv, int enc)
{
        PROV_GCM_CTX *qctx = (PROV_GCM_CTX *) ctx;
        int retval = 1;

        if (ctx == NULL) {
                return 0;
        }
        qctx->enc = enc;
        if (qctx == NULL) {
                return 0;
        }

        /* If a key is set and a tag has already been calculated
         * this cipher ctx is being reused, so zero the gcm ctx and tag state variables */
        if (qctx->ckey_set && qctx->tag_calculated) {
                memset(&(qctx->gcm_ctx), 0, sizeof(qctx->gcm_ctx));
                qctx->tag_set = 0;
                qctx->tag_calculated = 0;
        }

        /* Allocate gcm auth tag */
        if (!qctx->tag) {
                qctx->tag = OPENSSL_zalloc(EVP_GCM_TLS_TAG_LEN);

                if (qctx->tag) {
                        qctx->tag_len = EVP_GCM_TLS_TAG_LEN;
                        qctx->tag_set = 0;
                } else {
                        qctx->tag_len = 0;
                        return 0;
                }
        }

        qctx->tag_set = 0;

        /* Allocate gcm calculated_tag */
        if (!qctx->calculated_tag) {
                qctx->calculated_tag = OPENSSL_zalloc(EVP_GCM_TLS_TAG_LEN);

                if (qctx->calculated_tag) {
                        qctx->tag_calculated = 0;
                } else {
                        qctx->tag_len = 0;
                        return 0;
                }
        }

        /* If we have an IV passed in, and the iv_len has not yet been set
         *  default to PROV_GCM_TLS_TOTAL_IV_LEN (if IV size isn't 12 bytes,
         *  it would have been set via ctrl function before we got here) */
        if (qctx->iv_len <= 0) {
                qctx->iv_len = PROV_GCM_TLS_TOTAL_IV_LEN;
        }

        /* If we have an IV passed in and have yet to allocate memory for the IV */
        qctx->iv = OPENSSL_realloc(qctx->iv, qctx->iv_len);
        qctx->next_iv = OPENSSL_realloc(qctx->next_iv, qctx->iv_len);
        qctx->iv_set = 0;

        /* IV passed in */
        if (iv != NULL) {
                if (qctx->iv) {
                        memcpy(qctx->iv, iv, qctx->iv_len);
                        memcpy(qctx->next_iv, iv, qctx->iv_len);
                        qctx->iv_set = 1;
                }
                qctx->iv_gen = 0;
        }

        qctx->tls_aad_len = -1;

        /* If we got a key passed in, initialize the key schedule */
        if (inkey)
                retval = vaesgcm_init_key(ctx, inkey);

        /* If both the cipher key and the IV have been set,
         * then init the gcm context */
        if (qctx->ckey_set && qctx->iv_set)
                retval = vaesgcm_init_gcm(ctx);

        return retval;
}

static inline void
aes_gcm_increment_counter(unsigned char *ifc)
{
        int inv_field_size = 8;
        unsigned char byte;

        /* Loop over ifc starting with the least significant byte
         * and work towards the most significant byte of ifc*/
        do {
                --inv_field_size;
                byte = ifc[inv_field_size];

                /* Increment by one and copy back to invocation field */
                ++byte;
                ifc[inv_field_size] = byte;

                if (byte)
                        return;
        } while (inv_field_size);
}

int
vaesgcm_ciphers_ctrl(void *ctx, int type, int arg, void *ptr)
{
        PROV_GCM_CTX *qctx = (PROV_GCM_CTX *) ctx;
        int ret_val = 0;
        int enc = 0;

        if (ctx == NULL) {
                return -1;
        }

        if (qctx == NULL) {
                return -1;
        }
        enc = qctx->enc;
        switch (type) {
        case EVP_CTRL_INIT: {

                memset(qctx, 0, sizeof(vaesgcm_ctx));

                qctx->tls_aad_len = -1;
                qctx->iv_gen = -1;

                ret_val = 1;
                break;
        }

        case EVP_CTRL_GCM_SET_IVLEN: {

                if (arg <= 0) {
                        ret_val = 0;
                        break;
                }

                qctx->iv_len = arg;
                qctx->iv_set = 0;

                ret_val = 1;
                break;
        }

        case EVP_CTRL_GCM_SET_TAG: {

                if (enc || arg <= PROV_GCM_TAG_MIN_LEN || arg > PROV_GCM_TAG_MAX_LEN) {
                        ret_val = 0;
                        break;
                }

                if (qctx->tag) {
                        OPENSSL_free(qctx->tag);
                        qctx->tag = NULL;
                }

                qctx->tag = OPENSSL_zalloc(arg);
                if (qctx->tag) {
                        memcpy(qctx->tag, ptr, arg);
                        qctx->tag_len = arg;
                        qctx->tag_set = 1;
                        ret_val = 1;
                } else {
                        ret_val = 0;
                }
                break;
        }

        case EVP_CTRL_GCM_GET_TAG: {
                if (!enc || arg <= PROV_GCM_TAG_MIN_LEN || arg > PROV_GCM_TAG_MAX_LEN ||
                    qctx->tag_len <= 0) {
                        ret_val = 0;
                        break;
                }

                if (!qctx->tag_set || (ptr == NULL)) {
                        ret_val = 0;
                        break;
                } else
                        memcpy(ptr, qctx->tag, arg);

                qctx->iv_set = 0;
                qctx->tag_calculated = 0;
                qctx->tag_set = 0;

                ret_val = 1;
                break;
        }

        case EVP_CTRL_GCM_SET_IV_FIXED: {

                if (ptr == NULL || qctx->next_iv == NULL) {
                        ret_val = 0;
                        break;
                }
                /* Special case: -1 length restores whole IV */
                if (arg == -1) {
                        memcpy(qctx->next_iv, ptr, qctx->iv_len);
                        qctx->iv_gen = 1;
                        ret_val = 1;
                        break;
                }

                /* Fixed field must be at least 4 bytes (EVP_GCM_TLS_FIXED_IV_LEN)
                 * and invocation field at least 8 (EVP_GCM_TLS_EXPLICIT_IV_LEN)
                 */
                if ((arg < EVP_GCM_TLS_FIXED_IV_LEN) ||
                    (qctx->iv_len - arg) < EVP_GCM_TLS_EXPLICIT_IV_LEN) {
                        ret_val = 0;
                        break;
                }

                if (arg != EVP_GCM_TLS_FIXED_IV_LEN) {
                        ret_val = 0;
                        break;
                }

                int iv_len = EVP_GCM_TLS_FIXED_IV_LEN;

                if (!qctx->iv) {
                        qctx->iv = OPENSSL_zalloc(iv_len);

                        if (qctx->iv == NULL) {
                                qctx->iv_len = 0;
                                qctx->iv_gen = 0;
                                ret_val = 0;
                                break;
                        } else
                                qctx->iv_len = iv_len;
                }

                if (!qctx->next_iv) {
                        qctx->next_iv = OPENSSL_zalloc(iv_len);

                        if (qctx->next_iv == NULL) {
                                qctx->iv_len = 0;
                                qctx->iv_gen = 0;
                                ret_val = 0;
                                break;
                        } else
                                qctx->iv_len = iv_len;
                }

                if (arg) {
                        memcpy(qctx->next_iv, ptr, arg);
                }

                /* Generate the explicit part of the IV for encryption */
                if (enc && RAND_bytes(qctx->next_iv + arg, qctx->iv_len - arg) <= 0) {
                        ret_val = 0;
                        break;
                }

                qctx->iv_gen = 1;
                ret_val = 1;
                break;
        }

        case EVP_CTRL_GCM_IV_GEN: {

                /* Called in TLS case before encryption */
                if (NULL == qctx->iv || NULL == qctx->next_iv || NULL == ptr) {
                        ret_val = 0;
                        break;
                }

                if (0 == qctx->iv_gen) {
                        ret_val = 0;
                        break;
                }

                /* Set the IV that will be used in the current operation */
                memcpy(qctx->iv, qctx->next_iv, qctx->iv_len);
                if (arg <= 0 || arg > qctx->iv_len) {
                        arg = qctx->iv_len;
                }

                /* Copy the explicit IV in the output buffer */
                memcpy(ptr, qctx->next_iv + qctx->iv_len - arg, arg);

                /* Increment invocation field counter (last 8 bytes of IV) */
                aes_gcm_increment_counter(qctx->next_iv + qctx->iv_len - 8);

                qctx->iv_set = 1;
                ret_val = 1;
                break;
        }

        case EVP_CTRL_GCM_SET_IV_INV: {
                /* Called in TLS case before decryption */
                if (0 == qctx->iv_gen || enc) {
                        ret_val = 0;
                        break;
                }

                if (NULL == qctx->iv || NULL == qctx->next_iv || NULL == ptr) {
                        ret_val = 0;
                        break;
                }

                /* Retrieve the explicit IV from the message buffer */
                memcpy(qctx->next_iv + qctx->iv_len - arg, ptr, arg);
                /* Set the IV that will be used in the current operation */
                memcpy(qctx->iv, qctx->next_iv, qctx->iv_len);

                qctx->iv_set = 1;
                ret_val = 1;
                break;
        }

        case EVP_CTRL_AEAD_TLS1_AAD: {

                if (arg != EVP_AEAD_TLS1_AAD_LEN) {
                        ret_val = 0;
                        break;
                }

                /* Check to see if tls_aad already allocated with correct size,
                 * if so, reuse and save ourselves a free and malloc */
                if ((qctx->tls_aad_len == EVP_AEAD_TLS1_AAD_LEN) && qctx->tls_aad)
                        memcpy(qctx->tls_aad, ptr, qctx->tls_aad_len);
                else {
                        if (qctx->tls_aad) {
                                OPENSSL_free(qctx->tls_aad);
                                qctx->tls_aad_len = -1;
                                qctx->tls_aad_set = 0;
                        }

                        qctx->tls_aad_len = EVP_AEAD_TLS1_AAD_LEN;

                        qctx->tls_aad = OPENSSL_malloc(qctx->tls_aad_len);
                        if (qctx->tls_aad) {
                                /* Copy the header from payload into the buffer */
                                memcpy(qctx->tls_aad, ptr, qctx->tls_aad_len);
                        } else {
                                ret_val = 0;
                                break;
                        }
                }

                /* Extract the length of the payload from the TLS header */
                unsigned int plen = qctx->tls_aad[arg - PROV_GCM_TLS_PAYLOADLENGTH_MSB_OFFSET]
                                            << PROV_BYTE_SHIFT |
                                    qctx->tls_aad[arg - PROV_GCM_TLS_PAYLOADLENGTH_LSB_OFFSET];

                /* The payload contains the explicit IV -> correct the length */
                plen -= EVP_GCM_TLS_EXPLICIT_IV_LEN;

                /* If decrypting correct for tag too */
                if (!enc) {
                        plen -= EVP_GCM_TLS_TAG_LEN;
                }

                /* Fix the length like in the SW version of GCM */
                qctx->tls_aad[EVP_AEAD_TLS1_AAD_LEN - PROV_GCM_TLS_PAYLOADLENGTH_MSB_OFFSET] =
                        plen >> PROV_BYTE_SHIFT;
                qctx->tls_aad[EVP_AEAD_TLS1_AAD_LEN - PROV_GCM_TLS_PAYLOADLENGTH_LSB_OFFSET] =
                        plen; // & 0xff;
                qctx->tls_aad_set = 1;

                /* Extra padding: tag appended to record */
                ret_val = EVP_GCM_TLS_TAG_LEN;
                break;
        }

        case EVP_CTRL_GET_IVLEN: {
                *(int *) ptr = qctx->iv_len;
                ret_val = 1;
                break;
        }

        default: {
                ret_val = -1;
                break;
        }
        }

        return ret_val;
}

int
vaesgcm_ciphers_cleanup(void *ctx)
{
        PROV_GCM_CTX *qctx = (PROV_GCM_CTX *) ctx;
        if (qctx) {
                OPENSSL_cleanse(&qctx->key_data, sizeof(qctx->key_data));

                if (qctx->iv) {
                        OPENSSL_clear_free(qctx->iv, qctx->iv_len);
                        qctx->iv = NULL;
                        qctx->iv_set = 0;
                }

                if (qctx->next_iv) {
                        OPENSSL_clear_free(qctx->next_iv, qctx->iv_len);
                        qctx->next_iv = NULL;
                        qctx->iv_len = 0;
                }

                if (qctx->tls_aad) {
                        OPENSSL_clear_free(qctx->tls_aad, EVP_AEAD_TLS1_AAD_LEN);
                        qctx->tls_aad = NULL;
                        qctx->tls_aad_len = -1;
                        qctx->tls_aad_set = 0;
                }

                if (qctx->calculated_tag) {
                        OPENSSL_clear_free(qctx->calculated_tag, qctx->tag_len);
                        qctx->calculated_tag = NULL;
                        qctx->tag_calculated = 0;
                }

                if (qctx->tag) {
                        OPENSSL_clear_free(qctx->tag, qctx->tag_len);
                        qctx->tag = NULL;
                        qctx->tag_len = 0;
                        qctx->tag_set = 0;
                }
        }
        return 1;
}

int
PROV_AES_CIPHER_CTX_encrypting(PROV_GCM_CTX *qctx)
{
        return qctx->enc;
}

int
aes_gcm_tls_cipher(void *ctx, unsigned char *out, size_t *padlen, const unsigned char *in,
                   size_t len, int enc)
{
        PROV_GCM_CTX *qctx = (PROV_GCM_CTX *) ctx;
        unsigned int message_len = 0;
        int nid = 0;
        void *tag = NULL;
        unsigned int tag_offset = len - EVP_GCM_TLS_TAG_LEN;
        unsigned char *orig_payload_loc = (unsigned char *) in;
        struct gcm_key_data *key_data_ptr = NULL;
        struct gcm_context_data *gcm_ctx_ptr = NULL;

        if (NULL == in || out != in || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN)) {
                return -1;
        }

        if (vaesgcm_ciphers_ctrl(ctx, enc ? EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
                                 EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0) {
                return -1;
        }
        nid = prov_aes_gcm_ctx_get_nid((PROV_AES_GCM_CTX *) ctx);
        key_data_ptr = &(qctx->key_data);

        if (0 == vaesgcm_init_gcm(ctx)) {
                return -1;
        }

        /* Include the explicit part of the IV at the beginning of the output  */
        in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
        out += EVP_GCM_TLS_EXPLICIT_IV_LEN;

        /* This is the length of the message that must be encrypted */
        message_len = len - (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN);

        gcm_ctx_ptr = &(qctx->gcm_ctx);

        tag = orig_payload_loc + tag_offset;

        if (enc) {
                /* Encrypt the payload */
                prov_imb_aes_gcm_enc_update(nid, key_data_ptr, gcm_ctx_ptr, out, in, message_len);

                /* Finalize to get the GCM Tag */
                prov_imb_aes_gcm_enc_finalize(nid, key_data_ptr, gcm_ctx_ptr, tag,
                                              EVP_GCM_TLS_TAG_LEN);

                qctx->tag_set = 1;
        } else {
                prov_imb_aes_gcm_dec_update(nid, key_data_ptr, gcm_ctx_ptr, out, in, message_len);

                uint8_t tempTag[EVP_GCM_TLS_TAG_LEN];
                memset(tempTag, 0, EVP_GCM_TLS_TAG_LEN);

                prov_imb_aes_gcm_enc_finalize(nid, key_data_ptr, gcm_ctx_ptr, tempTag,
                                              EVP_GCM_TLS_TAG_LEN);

                if (memcmp(tag, tempTag, EVP_GCM_TLS_TAG_LEN) != 0) {
                        return -1;
                }
        }

        if (enc)
                *padlen = len;
        else
                *padlen = message_len;
        return 1;
}

int
vaesgcm_ciphers_do_cipher(void *ctx, unsigned char *out, size_t *padlen, const unsigned char *in,
                          size_t len)
{
        PROV_GCM_CTX *qctx = (PROV_GCM_CTX *) ctx;
        int enc = 0;
        int nid = 0;
        struct gcm_key_data *key_data_ptr = NULL;
        struct gcm_context_data *gcm_ctx_ptr = NULL;

        if (ctx == NULL) {
                return -1;
        }
        if (qctx == NULL) {
                return -1;
        }
        enc = PROV_AES_CIPHER_CTX_encrypting(qctx);
        nid = prov_aes_gcm_ctx_get_nid((PROV_AES_GCM_CTX *) qctx);

        key_data_ptr = &(qctx->key_data);
        if (!prov_check_gcm_nid(nid)) {
                return -1;
        }

        /* Distinguish between a regular crypto update and the TLS case
         * qctx->tls_aad_len only set when EVP_CTRL_AEAD_TLS1_AAD control is sent */
        if (qctx->tls_aad_len >= 0)
                return aes_gcm_tls_cipher(ctx, out, padlen, in, len, enc);

        gcm_ctx_ptr = &(qctx->gcm_ctx);

        /* If we have a case where out == NULL, and in != NULL,
         * then its aad being passed */
        if ((out == NULL) && (in != NULL)) {
                prov_imb_aes_gcm_init_var_iv(nid, key_data_ptr, gcm_ctx_ptr, qctx->iv, qctx->iv_len,
                                             in, len);

                *padlen = len;
                return 1;
        }

        /* Handle the case where EVP_EncryptFinal_ex is called with a NULL input buffer.
         * Note: Null CT/PT provided to EVP_Encrypt|DecryptUpdate shares the same function
         * signature as if EVP_Encrypt|DecryptFinal_ex() was called */
        if (in == NULL && out != NULL) {

                if (enc) {
                        if (qctx->tag == NULL || qctx->tag_len <= 0) {
                                return -1;
                        }

                        /* if we haven't already calculated and the set the tag,
                         * then do so */
                        if (qctx->tag_set < 1) {
                                prov_imb_aes_gcm_enc_finalize(nid, key_data_ptr, gcm_ctx_ptr,
                                                              qctx->tag, qctx->tag_len);
                        }
                        qctx->tag_set = 1;
                        memcpy(qctx->buf, qctx->tag, qctx->tag_len);

                } else { /* Decrypt Flow */

                        if (qctx->tag_len < 0 || qctx->calculated_tag == NULL) {
                                return -1;
                        }

                        if (qctx->tag_calculated < 1) {
                                prov_imb_aes_gcm_dec_finalize(nid, key_data_ptr, gcm_ctx_ptr, out,
                                                              qctx->tag_len);

                                /* Stash the calculated tag from the decryption,
                                 * so it can get compared to expected value below */
                                memcpy(qctx->calculated_tag, out, qctx->tag_len);
                                qctx->tag_calculated = 1;
                        }
                        if (qctx->tag_set) {
                                if (memcmp(qctx->calculated_tag, qctx->tag, qctx->tag_len) == 0) {
                                        return 0;
                                } else {
                                        return -1;
                                }
                        }
                }
        } else {
                if (enc)
                        prov_imb_aes_gcm_enc_update(nid, key_data_ptr, gcm_ctx_ptr, out, in, len);
                else
                        prov_imb_aes_gcm_dec_update(nid, key_data_ptr, gcm_ctx_ptr, out, in, len);
        }
        *padlen = len;
        return 1;
}

int
vaesgcm_init_key(void *ctx, const unsigned char *inkey)
{
        PROV_GCM_CTX *qctx = (PROV_GCM_CTX *) ctx;
        struct gcm_key_data *key_data_ptr = NULL;
        int nid = 0;
        const void *key = NULL;

        if (ctx == NULL || inkey == NULL) {
                return 0;
        }

        if (qctx == NULL) {
                return 0;
        }
        nid = prov_aes_gcm_ctx_get_nid((PROV_AES_GCM_CTX *) ctx);
        if (!prov_check_gcm_nid(nid)) {
                return -1;
        }
        key = (const void *) (inkey);
        key_data_ptr = &(qctx->key_data);

        prov_imb_aes_gcm_precomp(nid, key, key_data_ptr);

        qctx->ckey_set = 1;
        return 1;
}

int
vaesgcm_init_gcm(void *ctx)
{
        PROV_GCM_CTX *qctx = (PROV_GCM_CTX *) ctx;
        int nid = 0;
        int aad_len = 0;
        struct gcm_key_data *key_data_ptr = NULL;
        struct gcm_context_data *gcm_ctx_ptr = NULL;
        const unsigned char *aad_ptr = NULL;

        if (ctx == NULL) {
                return 0;
        }

        if (qctx == NULL) {
                return 0;
        }
        nid = prov_aes_gcm_ctx_get_nid((PROV_AES_GCM_CTX *) ctx);
        if (!prov_check_gcm_nid(nid)) {
                return 0;
        }

        /* if both the cipher key and the IV have been set, then init */
        if (qctx->ckey_set && (qctx->iv_set || qctx->iv_gen)) {
                key_data_ptr = &(qctx->key_data);
                gcm_ctx_ptr = &(qctx->gcm_ctx);
                aad_ptr = qctx->tls_aad;
                aad_len = qctx->tls_aad_len;
                if (qctx->tls_aad_len < 0)
                        aad_len = 0;

                prov_imb_aes_gcm_init_var_iv(nid, key_data_ptr, gcm_ctx_ptr, qctx->iv, qctx->iv_len,
                                             aad_ptr, aad_len);

                return 1;
        } else {
                return 0;
        }
}