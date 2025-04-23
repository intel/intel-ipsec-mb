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

#include <stddef.h>
#include <stdarg.h>
#include "openssl/ossl_typ.h"
#include "openssl/evp.h"

#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_gcm.h"

int prov_digest_nids[] = {};
int prov_cipher_nids[] = {};
const int num_digest_nids = sizeof(prov_digest_nids) / sizeof(prov_digest_nids[0]);
int prov_evp_nids[] = {};
const int num_evp_nids = sizeof(prov_evp_nids) / sizeof(prov_evp_nids[0]);
typedef struct _digest_data {
        const int m_type;
        EVP_MD *md;
        const int pkey_type;

} digest_data;
static digest_data digest_info[] = {};

typedef struct _chained_info {
        const int nid;
        EVP_CIPHER *cipher;
        const int keylen;
} chained_info;

static chained_info info[] = {
        { NID_aes_128_gcm, NULL, AES_KEY_SIZE_128 },
        { NID_aes_192_gcm, NULL, AES_KEY_SIZE_192 },
        { NID_aes_256_gcm, NULL, AES_KEY_SIZE_256 },
};

static const unsigned int num_cc = sizeof(info) / sizeof(chained_info);

void
prov_free_digest_meth(void)
{
        int i;

        for (i = 0; i < num_digest_nids; i++) {
                if (digest_info[i].md != NULL) {
                        switch (digest_info[i].m_type) {
                        }
                        digest_info[i].md = NULL;
                }
        }
}

static inline const EVP_CIPHER *
prov_gcm_cipher_sw_impl(int nid)
{
        switch (nid) {
        case NID_aes_128_gcm:
                return EVP_aes_128_gcm();
        case NID_aes_192_gcm:
                return EVP_aes_192_gcm();
        case NID_aes_256_gcm:
                return EVP_aes_256_gcm();
        default:
                fprintf(stderr, "Invalid nid %d\n", nid);
                return NULL;
        }
}

const EVP_CIPHER *
prov_create_gcm_cipher_meth(int nid, int keylen)
{
        EVP_CIPHER *c = NULL;
        int res = 1;

        if ((c = EVP_CIPHER_meth_new(nid, AES_GCM_BLOCK_SIZE, keylen)) == NULL) {
                fprintf(stderr, "Failed to allocate cipher methods for nid %d\n", nid);
                return NULL;
        }

        res &= EVP_CIPHER_meth_set_iv_length(c, IMB_GCM_IV_DATA_LEN);
        res &= EVP_CIPHER_meth_set_flags(c, VAESGCM_FLAG);
        res &= EVP_CIPHER_meth_set_impl_ctx_size(c, sizeof(vaesgcm_ctx));
        res &= EVP_CIPHER_meth_set_set_asn1_params(c, NULL);
        res &= EVP_CIPHER_meth_set_get_asn1_params(c, NULL);
        if (0 == res) {
                fprintf(stderr, "Failed to set cipher methods for nid %d\n", nid);
                EVP_CIPHER_meth_free(c);
                return NULL;
        }
        return c;
}

void
prov_create_ciphers(void)
{
        int i;

        for (i = 0; i < num_cc; i++) {
                if (info[i].cipher == NULL) {
                        switch (info[i].nid) {
                        case NID_aes_128_gcm:
                        case NID_aes_192_gcm:
                        case NID_aes_256_gcm:
                                info[i].cipher = (EVP_CIPHER *) prov_create_gcm_cipher_meth(
                                        info[i].nid, info[i].keylen);
                                break;
                        default:
                                /* Do nothing */
                                break;
                        }
                }
        }
}

void
prov_free_ciphers(void)
{
        int i;

        for (i = 0; i < num_cc; i++) {
                if (info[i].cipher != NULL) {
                        switch (info[i].nid) {
                        case NID_aes_128_gcm:
                        case NID_aes_192_gcm:
                        case NID_aes_256_gcm:
                                EVP_CIPHER_meth_free(info[i].cipher);
                        }
                        info[i].cipher = NULL;
                }
        }
}