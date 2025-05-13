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

/* Local Includes */
#include "prov_sw_gcm.h"

IMB_MGR *ipsec_mgr = NULL;

void
prov_imb_aes_gcm_precomp(int nid, const void *key, struct gcm_key_data *key_data_ptr)
{
        switch (nid) {
        case NID_aes_128_gcm:
                IMB_AES128_GCM_PRE(ipsec_mgr, key, key_data_ptr);
                break;

        case NID_aes_192_gcm:
                IMB_AES192_GCM_PRE(ipsec_mgr, key, key_data_ptr);
                break;

        case NID_aes_256_gcm:
                IMB_AES256_GCM_PRE(ipsec_mgr, key, key_data_ptr);
                break;
        }
}

void
prov_imb_aes_gcm_init_var_iv(int nid, struct gcm_key_data *key_data_ptr,
                             struct gcm_context_data *gcm_ctx_ptr, const uint8_t *iv,
                             const uint64_t iv_len, const uint8_t *aad, const uint64_t aad_len)
{

        switch (nid) {
        case NID_aes_128_gcm:
                IMB_AES128_GCM_INIT_VAR_IV(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, iv, iv_len, aad,
                                           aad_len);
                break;

        case NID_aes_192_gcm:
                IMB_AES192_GCM_INIT_VAR_IV(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, iv, iv_len, aad,
                                           aad_len);
                break;

        case NID_aes_256_gcm:
                IMB_AES256_GCM_INIT_VAR_IV(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, iv, iv_len, aad,
                                           aad_len);
                break;
        }
}

void
prov_imb_aes_gcm_enc_update(int nid, struct gcm_key_data *key_data_ptr,
                            struct gcm_context_data *gcm_ctx_ptr, uint8_t *out, const uint8_t *in,
                            uint64_t len)
{

        switch (nid) {
        case NID_aes_128_gcm:
                IMB_AES128_GCM_ENC_UPDATE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, out, in, len);
                break;

        case NID_aes_192_gcm:
                IMB_AES192_GCM_ENC_UPDATE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, out, in, len);
                break;

        case NID_aes_256_gcm:
                IMB_AES256_GCM_ENC_UPDATE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, out, in, len);
                break;
        }
}

void
prov_imb_aes_gcm_dec_update(int nid, struct gcm_key_data *key_data_ptr,
                            struct gcm_context_data *gcm_ctx_ptr, uint8_t *out, const uint8_t *in,
                            uint64_t len)
{
        switch (nid) {
        case NID_aes_128_gcm:
                IMB_AES128_GCM_DEC_UPDATE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, out, in, len);
                break;

        case NID_aes_192_gcm:
                IMB_AES192_GCM_DEC_UPDATE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, out, in, len);
                break;

        case NID_aes_256_gcm:
                IMB_AES256_GCM_DEC_UPDATE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, out, in, len);
                break;
        }
}

void
prov_imb_aes_gcm_enc_finalize(int nid, const struct gcm_key_data *key_data_ptr,
                              struct gcm_context_data *gcm_ctx_ptr, uint8_t *auth_tag,
                              uint64_t auth_tag_len)
{

        switch (nid) {
        case NID_aes_128_gcm:
                IMB_AES128_GCM_ENC_FINALIZE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, auth_tag,
                                            auth_tag_len);
                break;

        case NID_aes_192_gcm:
                IMB_AES192_GCM_ENC_FINALIZE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, auth_tag,
                                            auth_tag_len);
                break;

        case NID_aes_256_gcm:
                IMB_AES256_GCM_ENC_FINALIZE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, auth_tag,
                                            auth_tag_len);
                break;
        }
}

void
prov_imb_aes_gcm_dec_finalize(int nid, const struct gcm_key_data *key_data_ptr,
                              struct gcm_context_data *gcm_ctx_ptr, uint8_t *auth_tag,
                              uint64_t auth_tag_len)

{

        switch (nid) {
        case NID_aes_128_gcm:
                IMB_AES128_GCM_DEC_FINALIZE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, auth_tag,
                                            auth_tag_len);
                break;

        case NID_aes_192_gcm:
                IMB_AES192_GCM_DEC_FINALIZE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, auth_tag,
                                            auth_tag_len);
                break;

        case NID_aes_256_gcm:
                IMB_AES256_GCM_DEC_FINALIZE(ipsec_mgr, key_data_ptr, gcm_ctx_ptr, auth_tag,
                                            auth_tag_len);
                break;
        }
}

int
init_ipsec_mb_mgr()
{
        if (ipsec_mgr == NULL) {
                ipsec_mgr = alloc_mb_mgr(0);

                if (ipsec_mgr == NULL) {
                        return 0;
                } else {
                        /* Initialize the manager to dispatch IPsec APIs */
                        init_mb_mgr_auto(ipsec_mgr, NULL);
                        return 1;
                }
        }
        return 0;
}

void
free_ipsec_mb_mgr()
{
        if (ipsec_mgr) {
                free_mb_mgr(ipsec_mgr);
                ipsec_mgr = NULL;
        }
}
