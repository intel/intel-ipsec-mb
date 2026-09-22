/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
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