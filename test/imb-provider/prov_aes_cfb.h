/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef PROV_AES_CFB_H
#define PROV_AES_CFB_H

#ifdef ENABLE_PROV_SW_AES_CFB
/* Standard Includes */
#include <string.h>

/* OpenSSL Includes */
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/modes.h>
#include <openssl/types.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include <openssl/core_names.h>
#include <openssl/aes.h>

/* Intel IPsec library include */
#include <intel-ipsec-mb.h>

/* Local Includes */
#include "prov_provider.h"
#include "e_prov.h"

#endif /* ENABLE_PROV_SW_AES_CFB */
#endif /* PROV_AES_CFB_H */