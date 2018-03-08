/*******************************************************************************
  Copyright (c) 2012-2018, Intel Corporation

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

/* interface to asm routines */

#ifndef IMB_ASM_H
#define IMB_ASM_H

#include "intel-ipsec-mb.h"

/* Define interface to base asm code */

/* AES-CBC */
void aes_cbc_enc_128_x8(AES_ARGS_x8 *args, uint64_t len_in_bytes);
void aes_cbc_enc_192_x8(AES_ARGS_x8 *args, uint64_t len_in_bytes);
void aes_cbc_enc_256_x8(AES_ARGS_x8 *args, uint64_t len_in_bytes);

void aes_cbc_dec_128_avx(const void *in, const uint8_t *IV, const void *keys,
                         void *out, uint64_t len_bytes);
void aes_cbc_dec_192_avx(const void *in, const uint8_t *IV, const void *keys,
                         void *out, uint64_t len_bytes);
void aes_cbc_dec_256_avx(const void *in, const uint8_t *IV, const void *keys,
                         void *out, uint64_t len_bytes);

void aes_cbc_dec_128_sse(const void *in, const uint8_t *IV, const void *keys,
                         void *out, uint64_t len_bytes);
void aes_cbc_dec_192_sse(const void *in, const uint8_t *IV, const void *keys,
                         void *out, uint64_t len_bytes);
void aes_cbc_dec_256_sse(const void *in, const uint8_t *IV, const void *keys,
                         void *out, uint64_t len_bytes);

/* AES-CTR */
void aes_cntr_256_sse(const void *in, const void *IV, const void *keys,
                      void *out, uint64_t len_bytes, uint64_t IV_len);
void aes_cntr_192_sse(const void *in, const void *IV, const void *keys,
                      void *out, uint64_t len_bytes, uint64_t IV_len);
void aes_cntr_128_sse(const void *in, const void *IV, const void *keys,
                      void *out, uint64_t len_bytes, uint64_t IV_len);

void aes_cntr_256_avx(const void *in, const void *IV, const void *keys,
                      void *out, uint64_t len_bytes, uint64_t IV_len);
void aes_cntr_192_avx(const void *in, const void *IV, const void *keys,
                      void *out, uint64_t len_bytes, uint64_t IV_len);
void aes_cntr_128_avx(const void *in, const void *IV, const void *keys,
                      void *out, uint64_t len_bytes, uint64_t IV_len);

/* AES128-CFB */
void aes_cfb_128_one_sse(void *out, const void *in, const void *iv,
                         const void *keys, uint64_t len);
void aes_cfb_128_one_avx(void *out, const void *in, const void *iv,
                         const void *keys, uint64_t len);
#define aes_cfb_128_one_avx2   aes_cfb_128_one_avx
#define aes_cfb_128_one_avx512 aes_cfb_128_one_avx2

/* AES128-ECBENC */
void aes128_ecbenc_x3_sse(const void *in, void *keys,
                          void *out1, void *out2, void *out3);
void aes128_ecbenc_x3_avx(const void *in, void *keys,
                          void *out1, void *out2, void *out3);

#endif /* IMB_ASM_H */


