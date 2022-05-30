/*******************************************************************************
  Copyright (c) 2022, Intel Corporation

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

#include <string.h>

#include "intel-ipsec-mb.h"
#include "include/ipsec_ooo_mgr.h"
#include "include/ooo_mgr_reset.h"

IMB_DLL_LOCAL
void ooo_mgr_aes_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_AES_OOO *p_mgr = (MB_MGR_AES_OOO *) p_ooo_mgr;

        memset(p_mgr, 0, sizeof(*p_mgr));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));
        if (num_lanes == 4)
                p_mgr->unused_lanes = 0xF3210;
        else if (num_lanes == 8)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == 12) {
                /* CBCS only */
                p_mgr->unused_lanes = 0xBA9876543210;
                memset(&p_mgr->lens64[12], 0xFF,
                       sizeof(p_mgr->lens64) - sizeof(p_mgr->lens64[0] * 12));
        } else if (num_lanes == 16)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_docsis_aes_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_DOCSIS_AES_OOO *p_mgr = (MB_MGR_DOCSIS_AES_OOO *) p_ooo_mgr;

        memset(p_mgr, 0, sizeof(*p_mgr));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));
        if (num_lanes == 4)
                p_mgr->unused_lanes = 0xF3210;
        else if (num_lanes == 8)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == 16)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_cmac_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_CMAC_OOO *p_mgr = (MB_MGR_CMAC_OOO *) p_ooo_mgr;

        memset(p_mgr, 0, sizeof(*p_mgr));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));
        if (num_lanes == 4)
                p_mgr->unused_lanes = 0xF3210;
        else if (num_lanes == 8)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == 16)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_ccm_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_CCM_OOO *p_mgr = (MB_MGR_CCM_OOO *) p_ooo_mgr;

        memset(p_mgr, 0, sizeof(*p_mgr));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));
        if (num_lanes == 4)
                p_mgr->unused_lanes = 0xF3210;
        else if (num_lanes == 8)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == 16)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_aes_xcbc_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_AES_XCBC_OOO *p_mgr = (MB_MGR_AES_XCBC_OOO *) p_ooo_mgr;
        unsigned i;
        
        memset(p_mgr, 0, sizeof(*p_mgr));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        for (i = 0; i < num_lanes; i++)
                p_mgr->ldata[i].final_block[16] = 0x80;

        if (num_lanes == 4)
                p_mgr->unused_lanes = 0xFF03020100;
        else if (num_lanes == 8)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == 16)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_hmac_sha1_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_HMAC_SHA_1_OOO *p_mgr = (MB_MGR_HMAC_SHA_1_OOO *) p_ooo_mgr;
        unsigned i;
        
        memset(p_mgr, 0, sizeof(*p_mgr));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        for (i = 0; i < num_lanes; i++) {
                p_mgr->ldata[i].extra_block[64] = 0x80;

                /* 5 dwords of digest, add padding */
                p_mgr->ldata[i].outer_block[5 * 4] = 0x80;
                p_mgr->ldata[i].outer_block[64 - 2] = 0x02;
                p_mgr->ldata[i].outer_block[64 - 1] = 0xa0;
        }

        IMB_ASSERT(AVX_NUM_SHA1_LANES == SSE_NUM_SHA1_LANES);

        if (num_lanes == 2)
                p_mgr->unused_lanes = 0xFF0100; /* SHANI */
        else if (num_lanes == AVX_NUM_SHA1_LANES)
                p_mgr->unused_lanes = 0xFF03020100;
        else if (num_lanes == AVX2_NUM_SHA1_LANES)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == AVX512_NUM_SHA1_LANES)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_hmac_sha224_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_HMAC_SHA_256_OOO *p_mgr = (MB_MGR_HMAC_SHA_256_OOO *) p_ooo_mgr;
        unsigned i;
        
        memset(p_mgr, 0, sizeof(*p_mgr));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        for (i = 0; i < num_lanes; i++) {
                p_mgr->ldata[i].extra_block[64] = 0x80;

                /* 7 dwords of digest, add padding */
                p_mgr->ldata[i].outer_block[7 * 4] = 0x80;
                p_mgr->ldata[i].outer_block[64 - 2] = 0x02;
                p_mgr->ldata[i].outer_block[64 - 1] = 0xe0;
        }

        IMB_ASSERT(AVX_NUM_SHA256_LANES == SSE_NUM_SHA256_LANES);

        if (num_lanes == 2)
                p_mgr->unused_lanes = 0xFF0100; /* SHANI */
        else if (num_lanes == AVX_NUM_SHA256_LANES)
                p_mgr->unused_lanes = 0xFF03020100;
        else if (num_lanes == AVX2_NUM_SHA256_LANES)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == AVX512_NUM_SHA256_LANES)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_hmac_sha256_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_HMAC_SHA_256_OOO *p_mgr = (MB_MGR_HMAC_SHA_256_OOO *) p_ooo_mgr;
        unsigned i;
        
        memset(p_mgr, 0, sizeof(*p_mgr));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        for (i = 0; i < num_lanes; i++) {
                p_mgr->ldata[i].extra_block[64] = 0x80;

                /* 8 dwords of digest, add padding */
                p_mgr->ldata[i].outer_block[8 * 4] = 0x80;
                p_mgr->ldata[i].outer_block[64 - 2] = 0x03;
                p_mgr->ldata[i].outer_block[64 - 1] = 0x00;
        }

        IMB_ASSERT(AVX_NUM_SHA256_LANES == SSE_NUM_SHA256_LANES);

        if (num_lanes == 2)
                p_mgr->unused_lanes = 0xFF0100; /* SHANI */
        else if (num_lanes == AVX_NUM_SHA256_LANES)
                p_mgr->unused_lanes = 0xFF03020100;
        else if (num_lanes == AVX2_NUM_SHA256_LANES)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == AVX512_NUM_SHA256_LANES)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}
