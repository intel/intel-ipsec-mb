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

#ifndef PROV_SW_CCM_H
#define PROV_SW_CCM_H

#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <intel-ipsec-mb.h>
#include "prov_sw_freelist.h"
#include "prov_sw_request.h"

#define AES_CCM_IV_LEN            12
#define PROV_AES_CCM_OP_VALUE     15
#define PROV_CCM_IV_WRITE_BUFFER  1
#define PROV_CCM_AAD_WRITE_BUFFER 18

#define TLS_VIRT_HDR_SIZE 13
#define PROV_BYTE_SHIFT   8

#define PROV_CCM_TLS_TOTAL_IV_LEN             (EVP_CCM_TLS_FIXED_IV_LEN + EVP_CCM_TLS_EXPLICIT_IV_LEN)
#define PROV_CCM_TLS_PAYLOADLENGTH_MSB_OFFSET 2
#define PROV_CCM_TLS_PAYLOADLENGTH_LSB_OFFSET 1

/* The length of valid CCM Tag must be between 0 and 16 Bytes */
#define PROV_CCM_TAG_MIN_LEN 0
#define PROV_CCM_TAG_MAX_LEN 16
#define PROV_CCM_IV_MAX_LEN  16

#define PROV_SW_CCM_FLAGS (EVP_CIPH_CCM_MODE | EVP_CIPH_CUSTOM_IV)

int
prov_sw_ccm_init(ALG_CTX *ctx, const unsigned char *key, size_t keylen, const unsigned char *iv,
                 const size_t ivlen, const int enc);
int
prov_sw_ccm_do_cipher(ALG_CTX *ctx, unsigned char *out, size_t *outl, const size_t outsize,
                      const unsigned char *in, const size_t len);
int
prov_sw_ccm_cleanup(ALG_CTX *ctx);

int
prov_aes_ccm_ctrl(ALG_CTX *ctx, const int type, int arg, const void *ptr);

#endif /* PROV_SW_CCM_H */