/*******************************************************************************
  Copyright (c) 2023, Intel Corporation

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
imb_quic_hp_aes_ecb(IMB_MGR *state,
                    const void *exp_key_data,
                    void *dst_ptr_array[],
                    const void * const src_ptr_array[],
                    const uint64_t num_packets,
                    const IMB_KEY_SIZE_BYTES key_size)
{
#ifdef SAFE_PARAM
        uint64_t i;

        if (exp_key_data == NULL) {
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
        for (i = 0; i < num_packets; i++) {
                if (dst_ptr_array[i] == NULL) {
                        imb_set_errno(state, IMB_ERR_NULL_DST);
                        return;
                }
                if (src_ptr_array[i] == NULL) {
                        imb_set_errno(state, IMB_ERR_NULL_SRC);
                        return;
                }
        }

        switch (key_size) {
        case IMB_KEY_128_BYTES:
        case IMB_KEY_192_BYTES:
        case IMB_KEY_256_BYTES:
                break;
        default:
                imb_set_errno(state, IMB_ERR_KEY_LEN);
                return;
        }
#endif /* SAFE_PARAM */

        imb_set_errno(state, 0);

        switch (key_size) {
        case IMB_KEY_128_BYTES:
                state->aes_ecb_128_quic(src_ptr_array, exp_key_data,
                                        dst_ptr_array, num_packets);
                break;
        case IMB_KEY_192_BYTES:
                state->aes_ecb_192_quic(src_ptr_array, exp_key_data,
                                        dst_ptr_array, num_packets);
                break;
        case IMB_KEY_256_BYTES:
        default:
                state->aes_ecb_256_quic(src_ptr_array, exp_key_data,
                                        dst_ptr_array, num_packets);
                break;
        };
}
