/*******************************************************************************
  Copyright (c) 2020-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

/* Use XSI-compliant portable version of strerror_r() */
#undef _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "intel-ipsec-mb.h"
#include "error.h"

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

IMB_DLL_LOCAL volatile int imb_errno;
IMB_DLL_LOCAL const int imb_errno_types[] = { IMB_ERR_NULL_MBMGR,
                                              IMB_ERR_JOB_NULL_SRC,
                                              IMB_ERR_JOB_NULL_DST,
                                              IMB_ERR_JOB_NULL_KEY,
                                              IMB_ERR_JOB_NULL_IV,
                                              IMB_ERR_JOB_NULL_AUTH,
                                              IMB_ERR_JOB_NULL_AAD,
                                              IMB_ERR_JOB_CIPH_LEN,
                                              IMB_ERR_JOB_AUTH_LEN,
                                              IMB_ERR_JOB_IV_LEN,
                                              IMB_ERR_JOB_KEY_LEN,
                                              IMB_ERR_JOB_AUTH_TAG_LEN,
                                              IMB_ERR_JOB_AAD_LEN,
                                              IMB_ERR_JOB_SRC_OFFSET,
                                              IMB_ERR_JOB_CHAIN_ORDER,
                                              IMB_ERR_CIPH_MODE,
                                              IMB_ERR_HASH_ALGO,
                                              IMB_ERR_JOB_NULL_AUTH_KEY,
                                              IMB_ERR_JOB_NULL_SGL_CTX,
                                              IMB_ERR_JOB_NULL_NEXT_IV,
                                              IMB_ERR_JOB_PON_PLI,
                                              IMB_ERR_NULL_SRC,
                                              IMB_ERR_NULL_DST,
                                              IMB_ERR_NULL_KEY,
                                              IMB_ERR_NULL_EXP_KEY,
                                              IMB_ERR_NULL_IV,
                                              IMB_ERR_NULL_AUTH,
                                              IMB_ERR_NULL_AAD,
                                              IMB_ERR_CIPH_LEN,
                                              IMB_ERR_AUTH_LEN,
                                              IMB_ERR_IV_LEN,
                                              IMB_ERR_KEY_LEN,
                                              IMB_ERR_AUTH_TAG_LEN,
                                              IMB_ERR_AAD_LEN,
                                              IMB_ERR_SRC_OFFSET,
                                              IMB_ERR_NULL_AUTH_KEY,
                                              IMB_ERR_NULL_CTX,
                                              IMB_ERR_JOB_NULL_HMAC_OPAD,
                                              IMB_ERR_JOB_NULL_HMAC_IPAD,
                                              IMB_ERR_JOB_NULL_XCBC_K1_EXP,
                                              IMB_ERR_JOB_NULL_XCBC_K2,
                                              IMB_ERR_JOB_NULL_XCBC_K3,
                                              IMB_ERR_JOB_CIPH_DIR,
                                              IMB_ERR_JOB_NULL_GHASH_INIT_TAG,
                                              IMB_ERR_MISSING_CPUFLAGS_INIT_MGR,
                                              IMB_ERR_NULL_JOB,
                                              IMB_ERR_QUEUE_SPACE,
                                              IMB_ERR_NULL_BURST,
                                              IMB_ERR_BURST_SIZE,
                                              IMB_ERR_BURST_OOO,
                                              IMB_ERR_SELFTEST,
                                              IMB_ERR_BURST_SUITE_ID,
                                              IMB_ERR_JOB_SGL_STATE,
                                              IMB_ERR_PQC_KEYOP,
                                              IMB_ERR_PQC_SIGNOP,
                                              IMB_ERR_PQC_NO_KEY,
                                              IMB_ERR_PQC_ALG,
                                              IMB_ERR_PQC_INIT,
                                              IMB_ERR_PQC_KEMOP,
                                              IMB_ERR_PQC_VERIFY_FAILED,
                                              IMB_ERR_PQC_BUFFER_SIZE,
                                              IMB_ERR_PQC_PARAMS,
                                              IMB_ERR_PQC_CTX_LEN,
                                              IMB_ERR_PQC_MSG_LEN };

int
imb_get_errno(IMB_MGR *mb_mgr)
{
        /* check for imb_errno_types[] mismatch vs enum IMB_ERR */
        IMB_ASSERT((IMB_DIM(imb_errno_types) + 1) == (IMB_ERR_MAX - IMB_ERR_MIN));

        /* try get IMB_MGR error status first */
        if (mb_mgr != NULL && mb_mgr->imb_errno)
                return mb_mgr->imb_errno;

        /* otherwise return global error status */
        return imb_errno;
}

const char *
imb_get_strerror(int errnum)
{
        if (errnum >= IMB_ERR_MAX)
                return "Unknown error";

        switch (errnum) {
        case 0:
                return "No error";
        case IMB_ERR_NULL_MBMGR:
                return "Null IMB_MGR pointer";
        case IMB_ERR_JOB_NULL_SRC:
                return "Null source pointer";
        case IMB_ERR_JOB_NULL_DST:
                return "Null destination pointer";
        case IMB_ERR_JOB_NULL_KEY:
                return "Null key pointer";
        case IMB_ERR_JOB_NULL_IV:
                return "Null Initialization Vector (IV) pointer";
        case IMB_ERR_JOB_NULL_AUTH:
                return "Null authentication tag output pointer";
        case IMB_ERR_JOB_NULL_AAD:
                return "Null Additional Authenticated Data (AAD) pointer";
        case IMB_ERR_JOB_CIPH_LEN:
                return "Invalid cipher message length";
        case IMB_ERR_JOB_AUTH_LEN:
                return "Invalid authentication message length";
        case IMB_ERR_JOB_IV_LEN:
                return "Invalid Initialization Vector (IV) length";
        case IMB_ERR_JOB_KEY_LEN:
                return "Invalid key length";
        case IMB_ERR_JOB_AUTH_TAG_LEN:
                return "Invalid authentication tag length";
        case IMB_ERR_JOB_AAD_LEN:
                return "Invalid Additional Authenticated Data (AAD) length";
        case IMB_ERR_JOB_SRC_OFFSET:
                return "Invalid source offset";
        case IMB_ERR_JOB_CHAIN_ORDER:
                return "Invalid chain order";
        case IMB_ERR_CIPH_MODE:
                return "Invalid cipher mode";
        case IMB_ERR_HASH_ALGO:
                return "Invalid hash algorithm";
        case IMB_ERR_JOB_NULL_AUTH_KEY:
                return "Null pointer to authentication key";
        case IMB_ERR_JOB_NULL_SGL_CTX:
                return "Null pointer to SGL context";
        case IMB_ERR_JOB_NULL_NEXT_IV:
                return "Null pointer to next IV";
        case IMB_ERR_JOB_PON_PLI:
                return "Invalid PON PLI (CRC length vs cipher length)";
        case IMB_ERR_JOB_NULL_HMAC_OPAD:
                return "Null pointer to HMAC OPAD";
        case IMB_ERR_JOB_NULL_HMAC_IPAD:
                return "Null pointer to HMAC IPAD";
        case IMB_ERR_JOB_NULL_XCBC_K1_EXP:
                return "Null pointer to XCBC K1 expanded";
        case IMB_ERR_JOB_NULL_XCBC_K2:
                return "Null pointer to XCBC K2";
        case IMB_ERR_JOB_NULL_XCBC_K3:
                return "Null pointer to XCBC K3";
        case IMB_ERR_JOB_NULL_GHASH_INIT_TAG:
                return "Null pointer to GHASH initial tag value";
        case IMB_ERR_NULL_SRC:
                return "Null source pointer (direct API)";
        case IMB_ERR_NULL_DST:
                return "Null destination pointer (direct API)";
        case IMB_ERR_NULL_KEY:
                return "Null key pointer (direct API)";
        case IMB_ERR_NULL_EXP_KEY:
                return "Null expanded key pointer (direct API)";
        case IMB_ERR_NULL_IV:
                return "Null Initialization Vector (IV) pointer (direct API)";
        case IMB_ERR_NULL_AUTH:
                return "Null authentication tag output pointer (direct API)";
        case IMB_ERR_NULL_AAD:
                return "Null Additional Authenticated Data (AAD) "
                       "pointer (direct API)";
        case IMB_ERR_CIPH_LEN:
                return "Invalid cipher message length (direct API)";
        case IMB_ERR_AUTH_LEN:
                return "Invalid authentication message length (direct API)";
        case IMB_ERR_IV_LEN:
                return "Invalid Initialization Vector (IV) length (direct API)";
        case IMB_ERR_KEY_LEN:
                return "Invalid key length (direct API)";
        case IMB_ERR_AUTH_TAG_LEN:
                return "Invalid authentication tag length (direct API)";
        case IMB_ERR_AAD_LEN:
                return "Invalid Additional Authenticated Data (AAD) "
                       "length (direct API)";
        case IMB_ERR_SRC_OFFSET:
                return "Invalid source offset (direct API)";
        case IMB_ERR_NULL_AUTH_KEY:
                return "Null pointer to authentication key (direct API)";
        case IMB_ERR_NULL_CTX:
                return "Null pointer to context (direct API)";
        case IMB_ERR_JOB_CIPH_DIR:
                return "Invalid cipher direction";
        case IMB_ERR_MISSING_CPUFLAGS_INIT_MGR:
                return "Failed to initialize IMB_MGR due to missing "
                       "required CPU flags";
        case IMB_ERR_NULL_JOB:
                return "NULL job pointer";
        case IMB_ERR_QUEUE_SPACE:
                return "Not enough space in job queue";
        case IMB_ERR_NULL_BURST:
                return "NULL pointer to burst job array";
        case IMB_ERR_BURST_SIZE:
                return "Invalid burst size";
        case IMB_ERR_BURST_OOO:
                return "Burst jobs out of order";
        case IMB_ERR_SELFTEST:
                return "Self-test failed";
        case IMB_ERR_BURST_SUITE_ID:
                return "Invalid cipher suite ID (async burst API)";
        case IMB_ERR_JOB_SGL_STATE:
                return "Invalid SGL state";
        case IMB_ERR_PQC_KEYOP:
                return "PQC key generation or key parse failure";
        case IMB_ERR_PQC_SIGNOP:
                return "PQC sign operation failure, or verify operation could not be performed";
        case IMB_ERR_PQC_NO_KEY:
                return "PQC operation attempted with no key bound to the context";
        case IMB_ERR_PQC_ALG:
                return "Invalid PQC algorithm/parameter set selector";
        case IMB_ERR_PQC_INIT:
                return "PQC context allocation or initialization failure";
        case IMB_ERR_PQC_KEMOP:
                return "PQC key-encapsulation encap/decap operation failure";
        case IMB_ERR_PQC_VERIFY_FAILED:
                return "PQC signature verification failed (invalid signature)";
        case IMB_ERR_PQC_BUFFER_SIZE:
                return "PQC buffer length invalid for the operation requested";
        case IMB_ERR_PQC_PARAMS:
                return "PQC optional-params struct size field mismatch or "
                       "reserved field is not zero";
        case IMB_ERR_PQC_CTX_LEN:
                return "PQC context string length out of range";
        case IMB_ERR_PQC_MSG_LEN:
                return "PQC message length invalid for the operation requested";
        default:
                return strerror(errnum);
        }
}
