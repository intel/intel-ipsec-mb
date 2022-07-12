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
#include <stddef.h> /* offsetof() */

IMB_DLL_LOCAL
void ooo_mgr_aes_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_AES_OOO *p_mgr = (MB_MGR_AES_OOO *) p_ooo_mgr;

        memset(p_mgr, 0, offsetof(MB_MGR_AES_OOO,road_block));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));
        if (num_lanes == 4)
                p_mgr->unused_lanes = 0xF3210;
        else if (num_lanes == 8)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == 12) {
                /* CBCS only */
                const size_t set_0xff_size =
                        sizeof(p_mgr->lens64) - (12 * sizeof(p_mgr->lens64[0]));

                p_mgr->unused_lanes = 0xBA9876543210;
                memset(&p_mgr->lens64[12], 0xFF, set_0xff_size);
        } else if (num_lanes == 16)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_docsis_aes_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_DOCSIS_AES_OOO *p_mgr = (MB_MGR_DOCSIS_AES_OOO *) p_ooo_mgr;

        memset(p_mgr, 0, offsetof(MB_MGR_DOCSIS_AES_OOO,road_block));
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

        memset(p_mgr, 0, offsetof(MB_MGR_CMAC_OOO,road_block));
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

        memset(p_mgr, 0, offsetof(MB_MGR_CCM_OOO,road_block));
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
        
        memset(p_mgr, 0, offsetof(MB_MGR_AES_XCBC_OOO,road_block));
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
        
        memset(p_mgr, 0, offsetof(MB_MGR_HMAC_SHA_1_OOO,road_block));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        for (i = 0; i < num_lanes; i++) {
                p_mgr->ldata[i].extra_block[IMB_SHA1_BLOCK_SIZE] = 0x80;

                p_mgr->ldata[i].outer_block[IMB_SHA1_DIGEST_SIZE_IN_BYTES] =
                        0x80;
                p_mgr->ldata[i].outer_block[IMB_SHA1_BLOCK_SIZE - 2] = 0x02;
                p_mgr->ldata[i].outer_block[IMB_SHA1_BLOCK_SIZE - 1] = 0xa0;
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
        
        memset(p_mgr, 0, offsetof(MB_MGR_HMAC_SHA_256_OOO,road_block));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        for (i = 0; i < num_lanes; i++) {
                p_mgr->ldata[i].extra_block[IMB_SHA_256_BLOCK_SIZE] = 0x80;

                p_mgr->ldata[i].outer_block[IMB_SHA224_DIGEST_SIZE_IN_BYTES] =
                        0x80;
                p_mgr->ldata[i].outer_block[IMB_SHA_256_BLOCK_SIZE - 2] = 0x02;
                p_mgr->ldata[i].outer_block[IMB_SHA_256_BLOCK_SIZE - 1] = 0xe0;
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
        
        memset(p_mgr, 0, offsetof(MB_MGR_HMAC_SHA_256_OOO,road_block));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        for (i = 0; i < num_lanes; i++) {
                p_mgr->ldata[i].extra_block[IMB_SHA_256_BLOCK_SIZE] = 0x80;

                p_mgr->ldata[i].outer_block[IMB_SHA256_DIGEST_SIZE_IN_BYTES] =
                        0x80;
                p_mgr->ldata[i].outer_block[IMB_SHA_256_BLOCK_SIZE - 2] = 0x03;
                p_mgr->ldata[i].outer_block[IMB_SHA_256_BLOCK_SIZE - 1] = 0x00;
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
void ooo_mgr_hmac_sha384_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_HMAC_SHA_512_OOO *p_mgr = (MB_MGR_HMAC_SHA_512_OOO *) p_ooo_mgr;
        unsigned i;
        
        memset(p_mgr, 0, offsetof(MB_MGR_HMAC_SHA_512_OOO,road_block));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        for (i = 0; i < num_lanes; i++) {
                p_mgr->ldata[i].extra_block[IMB_SHA_384_BLOCK_SIZE] = 0x80;

                p_mgr->ldata[i].outer_block[IMB_SHA384_DIGEST_SIZE_IN_BYTES] =
                        0x80;
                /*
                 * hmac outer block length always of fixed size, it is OKey
                 * length, a whole message block length, 1024 bits, with padding
                 * plus the length of the inner digest, which is 384 bits
                 * 1408 bits == 0x0580. The input message block needs to be
                 * converted to big endian within the sha implementation
                 * before use.
                 */
                p_mgr->ldata[i].outer_block[IMB_SHA_384_BLOCK_SIZE - 2] = 0x05;
                p_mgr->ldata[i].outer_block[IMB_SHA_384_BLOCK_SIZE - 1] = 0x80;
        }

        IMB_ASSERT(AVX_NUM_SHA512_LANES == SSE_NUM_SHA512_LANES);

        if (num_lanes == AVX_NUM_SHA512_LANES)
                p_mgr->unused_lanes = 0xFF0100;
        else if (num_lanes == AVX2_NUM_SHA512_LANES)
                p_mgr->unused_lanes = 0xFF03020100;
        else if (num_lanes == AVX512_NUM_SHA512_LANES)
                p_mgr->unused_lanes = 0xF76543210;
}

IMB_DLL_LOCAL
void ooo_mgr_hmac_sha512_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_HMAC_SHA_512_OOO *p_mgr = (MB_MGR_HMAC_SHA_512_OOO *) p_ooo_mgr;
        unsigned i;
        
        memset(p_mgr, 0, offsetof(MB_MGR_HMAC_SHA_512_OOO,road_block));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        for (i = 0; i < num_lanes; i++) {
                p_mgr->ldata[i].extra_block[IMB_SHA_512_BLOCK_SIZE] = 0x80;

                p_mgr->ldata[i].outer_block[IMB_SHA512_DIGEST_SIZE_IN_BYTES] =
                        0x80;
                 /*
                 * hmac outer block length always of fixed size, it is OKey
                 * length, a whole message block length, 1024 bits, with padding
                 * plus the length of the inner digest, which is 512 bits
                 * 1536 bits == 0x600. The input message block needs to be
                 * converted to big endian within the sha implementation
                 * before use.
                 */
                p_mgr->ldata[i].outer_block[IMB_SHA_512_BLOCK_SIZE - 2] = 0x06;
                p_mgr->ldata[i].outer_block[IMB_SHA_512_BLOCK_SIZE - 1] = 0x00;
        }

        IMB_ASSERT(AVX_NUM_SHA512_LANES == SSE_NUM_SHA512_LANES);

        if (num_lanes == AVX_NUM_SHA512_LANES)
                p_mgr->unused_lanes = 0xFF0100;
        else if (num_lanes == AVX2_NUM_SHA512_LANES)
                p_mgr->unused_lanes = 0xFF03020100;
        else if (num_lanes == AVX512_NUM_SHA512_LANES)
                p_mgr->unused_lanes = 0xF76543210;
}

IMB_DLL_LOCAL
void ooo_mgr_hmac_md5_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_HMAC_MD5_OOO *p_mgr = (MB_MGR_HMAC_MD5_OOO *) p_ooo_mgr;
        unsigned i;
        
        memset(p_mgr, 0, offsetof(MB_MGR_HMAC_MD5_OOO,road_block));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        for (i = 0; i < num_lanes; i++) {
                p_mgr->ldata[i].extra_block[64] = 0x80;

                p_mgr->ldata[i].outer_block[4 * 4] = 0x80;
                p_mgr->ldata[i].outer_block[64 - 7] = 0x02;
                p_mgr->ldata[i].outer_block[64 - 8] = 0x80;
        }

        IMB_ASSERT(AVX_NUM_MD5_LANES == SSE_NUM_MD5_LANES);

        if (num_lanes == AVX_NUM_MD5_LANES)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == AVX2_NUM_MD5_LANES)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_zuc_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_ZUC_OOO *p_mgr = (MB_MGR_ZUC_OOO *) p_ooo_mgr;
        
        memset(p_mgr, 0, offsetof(MB_MGR_ZUC_OOO,road_block));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        if (num_lanes == 4) {
                p_mgr->unused_lanes = 0xFF03020100;
                p_mgr->unused_lane_bitmask = 0x0f;
        } else if (num_lanes == 8) {
                p_mgr->unused_lanes = 0xF76543210;
                p_mgr->unused_lane_bitmask = 0xff;
        } else if (num_lanes == 16) {
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
                p_mgr->unused_lane_bitmask = 0xffff;
        }
}

IMB_DLL_LOCAL
void ooo_mgr_sha1_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_SHA_1_OOO *p_mgr = (MB_MGR_SHA_1_OOO *) p_ooo_mgr;
        
        memset(p_mgr, 0, offsetof(MB_MGR_SHA_1_OOO,road_block));

        if (num_lanes == 2)
                p_mgr->unused_lanes = 0xF10; /* SHANI */
        else if (num_lanes == AVX_NUM_SHA1_LANES)
                p_mgr->unused_lanes = 0xF3210;
        else if (num_lanes == AVX2_NUM_SHA1_LANES)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == AVX512_NUM_SHA1_LANES)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_sha256_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_SHA_256_OOO *p_mgr = (MB_MGR_SHA_256_OOO *) p_ooo_mgr;

        memset(p_mgr, 0, offsetof(MB_MGR_SHA_256_OOO,road_block));

        if (num_lanes == 2)
                p_mgr->unused_lanes = 0xF10; /* SHANI */
        if (num_lanes == AVX_NUM_SHA256_LANES)
                p_mgr->unused_lanes = 0xF3210;
        else if (num_lanes == AVX2_NUM_SHA256_LANES)
                p_mgr->unused_lanes = 0xF76543210;
        else if (num_lanes == AVX512_NUM_SHA256_LANES)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_sha512_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_SHA_512_OOO *p_mgr = (MB_MGR_SHA_512_OOO *) p_ooo_mgr;

        memset(p_mgr, 0, offsetof(MB_MGR_SHA_512_OOO,road_block));

        if (num_lanes == AVX_NUM_SHA512_LANES)
                p_mgr->unused_lanes = 0xF10;
        else if (num_lanes == AVX2_NUM_SHA512_LANES)
                p_mgr->unused_lanes = 0xF3210;
        else if (num_lanes == AVX512_NUM_SHA512_LANES)
                p_mgr->unused_lanes = 0xF76543210;
}

IMB_DLL_LOCAL
void ooo_mgr_des_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_DES_OOO *p_mgr = (MB_MGR_DES_OOO *) p_ooo_mgr;
        
        memset(p_mgr, 0, offsetof(MB_MGR_DES_OOO,road_block));

        if (num_lanes == 16)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}

IMB_DLL_LOCAL
void ooo_mgr_snow3g_reset(void *p_ooo_mgr, const unsigned num_lanes)
{
        MB_MGR_SNOW3G_OOO *p_mgr = (MB_MGR_SNOW3G_OOO *) p_ooo_mgr;

        memset(p_mgr, 0, offsetof(MB_MGR_SNOW3G_OOO,road_block));
        memset(p_mgr->lens, 0xff, sizeof(p_mgr->lens));

        if (num_lanes == 4) {
                /*
                 * lens[0:3]   indicate outstanding bytes after
                 *             rounding up length to dwords
                 *             - initialize to 0
                 * lens[4]     common min length for all lanes in dwords
                 *             - initialize to 0
                 * lens[8:11]  keep lengths rounded up to dwords
                 *             - initialize to UINT32_MAX not to interfere
                 *               when searching for minimum length
                 * lens[5:7]   unused
                 * lens[12:15] unused
                 */
                p_mgr->lens[8] = 0xffffffff;
                p_mgr->lens[9] = 0xffffffff;
                p_mgr->lens[10] = 0xffffffff;
                p_mgr->lens[11] = 0xffffffff;
                p_mgr->unused_lanes = 0x3210;
        } else if (num_lanes == 16)
                p_mgr->unused_lanes = 0xFEDCBA9876543210;
}
