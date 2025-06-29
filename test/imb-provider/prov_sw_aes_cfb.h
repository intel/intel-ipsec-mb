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

#ifndef PROV_SW_AES_CFB_H
#define PROV_SW_AES_CFB_H

#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <intel-ipsec-mb.h>
#include "prov_sw_freelist.h"
#include "prov_sw_request.h"
#include "prov_aes_cfb.h"

#define AES_CFB_IV_LEN        16
#define PROV_ENC_DEC_KEY_SIZE (4 * 15)
#define AES_CFB_BLOCK_SIZE    1
#define MAX_CFB_JOBS          32

#define PROV_CFB_FLAGS                                                                             \
        (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CFB_MODE | EVP_CIPH_FLAG_PIPELINE |                 \
         EVP_CIPH_CUSTOM_COPY)

int
aes_cfb_async_init(ALG_CTX *ctx, const unsigned char *inkey, size_t keylen, const unsigned char *iv,
                   size_t ivlen, int enc);
int
aes_cfb_async_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize,
                        const unsigned char *in, size_t len);
void
aes_cfb_async_cleanup(ALG_CTX *ctx);

#endif