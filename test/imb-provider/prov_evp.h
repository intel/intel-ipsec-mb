/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_EVP_H
#define PROV_EVP_H

#include <openssl/ossl_typ.h>
#include "e_prov.h"

#define AES_KEY_SIZE_128   16
#define AES_KEY_SIZE_192   24
#define AES_KEY_SIZE_256   32
#define AES_GCM_BLOCK_SIZE 1
#define AES_CCM_BLOCK_SIZE 1

void
prov_create_ciphers(void);
void
prov_free_ciphers(void);

const EVP_CIPHER *
prov_create_gcm_cipher_meth(int nid, int keylen);
const EVP_CIPHER *
prov_create_ccm_cipher_meth(int nid, int keylen);

#endif