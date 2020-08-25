/*******************************************************************************
  Copyright (c) 2020, Intel Corporation

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

#ifndef LINUX
#pragma warning(disable : 4996)
#endif

int imb_get_errno(IMB_MGR *mb_mgr)
{
        /* try get IMB_MGR error status first */
        if (mb_mgr != NULL)
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
        default:
                return strerror(errnum);
        }
}
