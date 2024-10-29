/*******************************************************************************
  Copyright (c) 2023-2024, Intel Corporation

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

#include "intel-ipsec-mb.h"
#include "include/error.h"

IMB_DLL_EXPORT void
imb_quic_aes_gcm(IMB_MGR *state, const struct gcm_key_data *key_data,
                 const IMB_KEY_SIZE_BYTES key_size, const IMB_CIPHER_DIRECTION cipher_dir,
                 void *dst_ptr_array[], const void *const src_ptr_array[],
                 const uint64_t len_array[], const void *const iv_ptr_array[],
                 const void *const aad_ptr_array[], const uint64_t aad_len, void *tag_ptr_array[],
                 const uint64_t tag_len, const uint64_t num_packets)
{
        /**
         * @note 12 byte IV is assumed
         * @note it can be out of place operation
         * but AAD needs to be copied by the caller
         */
        struct gcm_context_data ctx;
        uint64_t n;

#ifdef SAFE_PARAM
        if (state == NULL) {
                imb_set_errno(NULL, IMB_ERR_NULL_MBMGR);
                return;
        }
        if (key_data == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_EXP_KEY);
                return;
        }
        if (dst_ptr_array == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_DST);
                return;
        }
        if (src_ptr_array == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_SRC);
                return;
        }
        if (iv_ptr_array == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_IV);
                return;
        }
        if (aad_ptr_array == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_AAD);
                return;
        }
        if (tag_ptr_array == NULL) {
                imb_set_errno(state, IMB_ERR_NULL_AUTH);
                return;
        }
        for (n = 0; n < num_packets; n++) {
                if (dst_ptr_array[n] == NULL && len_array[n] != 0) {
                        imb_set_errno(state, IMB_ERR_NULL_DST);
                        return;
                }
                if (src_ptr_array[n] == NULL && len_array[n] != 0) {
                        imb_set_errno(state, IMB_ERR_NULL_SRC);
                        return;
                }
                if (iv_ptr_array[n] == NULL) {
                        imb_set_errno(state, IMB_ERR_NULL_IV);
                        return;
                }
                if (aad_ptr_array[n] == NULL && aad_len != 0) {
                        imb_set_errno(state, IMB_ERR_NULL_AAD);
                        return;
                }
                if (tag_ptr_array[n] == NULL) {
                        imb_set_errno(state, IMB_ERR_NULL_AUTH);
                        return;
                }
        }
        switch (key_size) {
        case IMB_KEY_128_BYTES:
        case IMB_KEY_256_BYTES:
                break;
        case IMB_KEY_192_BYTES:
                /* AES-192 is not supported by QUIC */
        default:
                imb_set_errno(state, IMB_ERR_KEY_LEN);
                return;
        }
        switch (cipher_dir) {
        case IMB_DIR_ENCRYPT:
        case IMB_DIR_DECRYPT:
                break;
        default:
                imb_set_errno(state, IMB_ERR_JOB_CIPH_DIR);
                return;
        }
#endif /* SAFE_PARAM */

        if (cipher_dir == IMB_DIR_ENCRYPT) {
                if (key_size == IMB_KEY_128_BYTES) {
                        for (n = 0; n < num_packets; n++) {
                                IMB_AES128_GCM_ENC(state, key_data, &ctx, dst_ptr_array[n],
                                                   src_ptr_array[n], len_array[n], iv_ptr_array[n],
                                                   aad_ptr_array[n], aad_len, tag_ptr_array[n],
                                                   tag_len);
                        }
                } else /* assume 256-bits key */ {
                        for (n = 0; n < num_packets; n++) {
                                IMB_AES256_GCM_ENC(state, key_data, &ctx, dst_ptr_array[n],
                                                   src_ptr_array[n], len_array[n], iv_ptr_array[n],
                                                   aad_ptr_array[n], aad_len, tag_ptr_array[n],
                                                   tag_len);
                        }
                }
        } else /* decrypt direction */ {
                if (key_size == IMB_KEY_128_BYTES) {
                        for (n = 0; n < num_packets; n++) {
                                IMB_AES128_GCM_DEC(state, key_data, &ctx, dst_ptr_array[n],
                                                   src_ptr_array[n], len_array[n], iv_ptr_array[n],
                                                   aad_ptr_array[n], aad_len, tag_ptr_array[n],
                                                   tag_len);
                        }
                } else /* assume 256-bits key */ {
                        for (n = 0; n < num_packets; n++) {
                                IMB_AES256_GCM_DEC(state, key_data, &ctx, dst_ptr_array[n],
                                                   src_ptr_array[n], len_array[n], iv_ptr_array[n],
                                                   aad_ptr_array[n], aad_len, tag_ptr_array[n],
                                                   tag_len);
                        }
                }
        }
}
