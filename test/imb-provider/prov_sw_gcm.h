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

#ifndef PROV_SW_GCM_H
#define PROV_SW_GCM_H

#include <openssl/evp.h>
#include <openssl/modes.h>
#include <intel-ipsec-mb.h>

#define VAESGCM_COMMON_CIPHER_FLAG EVP_CIPH_FLAG_DEFAULT_ASN1

#define VAESGCM_FLAGS (VAESGCM_COMMON_CIPHER_FLAG | EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV)

#define VAESGCM_FLAG                                                                               \
        (VAESGCM_FLAGS | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER |                 \
         EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY)

#define vaesgcm_data(ctx) ((vaesgcm_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx))

typedef struct vaesgcm_ctx_t {
        struct gcm_key_data key_data;
        struct gcm_context_data gcm_ctx;

        int init_flags;

        unsigned int ckey_set;

        unsigned char *tls_aad;
        int tls_aad_len;
        unsigned int tls_aad_set;

        unsigned char *tag;
        unsigned char *calculated_tag;
        int tag_len;
        unsigned int tag_set;
        unsigned int tag_calculated;

        unsigned char *iv;
        unsigned char *next_iv;
        int iv_len;
        unsigned int iv_set;
        int iv_gen;
} __attribute__((aligned(64))) vaesgcm_ctx;

int
vaesgcm_ciphers_init(void *ctx, const unsigned char *inkey, const unsigned char *iv, int enc);

int
vaesgcm_ciphers_ctrl(void *ctx, int type, int arg, void *ptr);

int
vaesgcm_ciphers_do_cipher(void *ctx, unsigned char *out, size_t *padlen, const unsigned char *in,
                          size_t len);
int
vaesgcm_ciphers_cleanup(void *ctx);

int
init_ipsec_mb_mgr(void);
void
free_ipsec_mb_mgr(void);

void
prov_imb_aes_gcm_precomp(int nid, const void *key, struct gcm_key_data *key_data_ptr);

void
prov_imb_aes_gcm_init_var_iv(int nid, struct gcm_key_data *key_data_ptr,
                             struct gcm_context_data *context_data, const uint8_t *iv,
                             const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len);

void
prov_imb_aes_gcm_enc_update(int nid, struct gcm_key_data *key_data_ptr,
                            struct gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                            uint64_t len);

void
prov_imb_aes_gcm_dec_update(int nid, struct gcm_key_data *key_data_ptr,
                            struct gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                            uint64_t len);

void
prov_imb_aes_gcm_enc_finalize(int nid, const struct gcm_key_data *key_data_ptr,
                              struct gcm_context_data *context_data, uint8_t *auth_tag,
                              uint64_t auth_tag_len);

void
prov_imb_aes_gcm_dec_finalize(int nid, const struct gcm_key_data *key_data_ptr,
                              struct gcm_context_data *context_data, uint8_t *auth_tag,
                              uint64_t auth_tag_len);

#endif /* PROV_SW_GCM_H */
