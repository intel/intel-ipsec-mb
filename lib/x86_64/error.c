/*******************************************************************************
  Copyright (c) 2020-2022, Intel Corporation

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

IMB_DLL_LOCAL int imb_errno;
IMB_DLL_LOCAL const int imb_errno_types[] = {
        IMB_ERR_NULL_MBMGR,
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
        IMB_ERR_NO_AESNI_EMU,
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
        IMB_ERR_SELFTEST
};

#ifdef DEBUG
static_assert((IMB_DIM(imb_errno_types) + 1) == (IMB_ERR_MAX - IMB_ERR_MIN),
              "imb_errno_types[] mismatch vs enum IMB_ERR");
#endif

int imb_get_errno(IMB_MGR *mb_mgr)
{
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

        switch (errnum){
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
        case IMB_ERR_NO_AESNI_EMU:
                return "No AESNI emulation support";
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
        default:
                return strerror(errnum);
        }
}
