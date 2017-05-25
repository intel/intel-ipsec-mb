/*
 * Copyright (c) 2012-2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef DEBUG
#include <assert.h>
#else
#define assert(x)
#endif

#include "mb_mgr.h"
#include "save_xmms.h"
#include "asm.h"

void
_init_mb_mgr_avx(MB_MGR *state)
{
        unsigned int j;
        UINT8 *p;

        // Init AES out-of-order fields
        state->states[JOB_STATE_AES128].aes128_ooo.lens[0] = 0;
        state->states[JOB_STATE_AES128].aes128_ooo.lens[1] = 0;
        state->states[JOB_STATE_AES128].aes128_ooo.lens[2] = 0;
        state->states[JOB_STATE_AES128].aes128_ooo.lens[3] = 0;
        state->states[JOB_STATE_AES128].aes128_ooo.lens[4] = 0;
        state->states[JOB_STATE_AES128].aes128_ooo.lens[5] = 0;
        state->states[JOB_STATE_AES128].aes128_ooo.lens[6] = 0;
        state->states[JOB_STATE_AES128].aes128_ooo.lens[7] = 0;
        state->states[JOB_STATE_AES128].aes128_ooo.unused_lanes = 0xF76543210;
        state->states[JOB_STATE_AES128].aes128_ooo.job_in_lane[0] = NULL;
        state->states[JOB_STATE_AES128].aes128_ooo.job_in_lane[1] = NULL;
        state->states[JOB_STATE_AES128].aes128_ooo.job_in_lane[2] = NULL;
        state->states[JOB_STATE_AES128].aes128_ooo.job_in_lane[3] = NULL;
        state->states[JOB_STATE_AES128].aes128_ooo.job_in_lane[4] = NULL;
        state->states[JOB_STATE_AES128].aes128_ooo.job_in_lane[5] = NULL;
        state->states[JOB_STATE_AES128].aes128_ooo.job_in_lane[6] = NULL;
        state->states[JOB_STATE_AES128].aes128_ooo.job_in_lane[7] = NULL;

        state->states[JOB_STATE_AES192].aes192_ooo.lens[0] = 0;
        state->states[JOB_STATE_AES192].aes192_ooo.lens[1] = 0;
        state->states[JOB_STATE_AES192].aes192_ooo.lens[2] = 0;
        state->states[JOB_STATE_AES192].aes192_ooo.lens[3] = 0;
        state->states[JOB_STATE_AES192].aes192_ooo.lens[4] = 0;
        state->states[JOB_STATE_AES192].aes192_ooo.lens[5] = 0;
        state->states[JOB_STATE_AES192].aes192_ooo.lens[6] = 0;
        state->states[JOB_STATE_AES192].aes192_ooo.lens[7] = 0;
        state->states[JOB_STATE_AES192].aes192_ooo.unused_lanes = 0xF76543210;
        state->states[JOB_STATE_AES192].aes192_ooo.job_in_lane[0] = NULL;
        state->states[JOB_STATE_AES192].aes192_ooo.job_in_lane[1] = NULL;
        state->states[JOB_STATE_AES192].aes192_ooo.job_in_lane[2] = NULL;
        state->states[JOB_STATE_AES192].aes192_ooo.job_in_lane[3] = NULL;
        state->states[JOB_STATE_AES192].aes192_ooo.job_in_lane[4] = NULL;
        state->states[JOB_STATE_AES192].aes192_ooo.job_in_lane[5] = NULL;
        state->states[JOB_STATE_AES192].aes192_ooo.job_in_lane[6] = NULL;
        state->states[JOB_STATE_AES192].aes192_ooo.job_in_lane[7] = NULL;

        state->states[JOB_STATE_AES256].aes256_ooo.lens[0] = 0;
        state->states[JOB_STATE_AES256].aes256_ooo.lens[1] = 0;
        state->states[JOB_STATE_AES256].aes256_ooo.lens[2] = 0;
        state->states[JOB_STATE_AES256].aes256_ooo.lens[3] = 0;
        state->states[JOB_STATE_AES256].aes256_ooo.lens[4] = 0;
        state->states[JOB_STATE_AES256].aes256_ooo.lens[5] = 0;
        state->states[JOB_STATE_AES256].aes256_ooo.lens[6] = 0;
        state->states[JOB_STATE_AES256].aes256_ooo.lens[7] = 0;
        state->states[JOB_STATE_AES256].aes256_ooo.unused_lanes = 0xF76543210;
        state->states[JOB_STATE_AES256].aes256_ooo.job_in_lane[0] = NULL;
        state->states[JOB_STATE_AES256].aes256_ooo.job_in_lane[1] = NULL;
        state->states[JOB_STATE_AES256].aes256_ooo.job_in_lane[2] = NULL;
        state->states[JOB_STATE_AES256].aes256_ooo.job_in_lane[3] = NULL;
        state->states[JOB_STATE_AES256].aes256_ooo.job_in_lane[4] = NULL;
        state->states[JOB_STATE_AES256].aes256_ooo.job_in_lane[5] = NULL;
        state->states[JOB_STATE_AES256].aes256_ooo.job_in_lane[6] = NULL;
        state->states[JOB_STATE_AES256].aes256_ooo.job_in_lane[7] = NULL;

        /* DOCSIS SEC BPI uses same settings as AES128 CBC */
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.lens[0] = 0;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.lens[1] = 0;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.lens[2] = 0;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.lens[3] = 0;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.lens[4] = 0;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.lens[5] = 0;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.lens[6] = 0;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.lens[7] = 0;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.unused_lanes = 0xF76543210;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.job_in_lane[0] = NULL;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.job_in_lane[1] = NULL;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.job_in_lane[2] = NULL;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.job_in_lane[3] = NULL;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.job_in_lane[4] = NULL;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.job_in_lane[5] = NULL;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.job_in_lane[6] = NULL;
        state->states[JOB_STATE_DOCSIS].docsis_sec_ooo.job_in_lane[7] = NULL;

        // Init HMAC/SHA1 out-of-order fields
        state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.lens[0] = 0;
        state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.lens[1] = 0;
        state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.lens[2] = 0;
        state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.lens[3] = 0;
        state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.lens[4] = 0xFFFF;
        state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.lens[5] = 0xFFFF;
        state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.lens[6] = 0xFFFF;
        state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.lens[7] = 0xFFFF;
        state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.unused_lanes = 0xFF03020100;
        for (j=0; j<AVX_NUM_SHA1_LANES; j++) {
                state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.ldata[j].job_in_lane = NULL;
                state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64+7);
                p = state->states[JOB_STATE_SHA1].hmac_sha_1_ooo.ldata[j].outer_block;
                memset(p + 5*4 + 1,
                       0x00,
                       64 - 5*4 - 1 - 2);
                p[5*4] = 0x80;
                p[64-2] = 0x02;
                p[64-1] = 0xA0;
        }

        // Init HMAC/SHA224 out-of-order fields
        state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.lens[0] = 0;
        state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.lens[1] = 0;
        state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.lens[2] = 0;
        state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.lens[3] = 0;
        state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.lens[4] = 0xFFFF;
        state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.lens[5] = 0xFFFF;
        state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.lens[6] = 0xFFFF;
        state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.lens[7] = 0xFFFF;
        state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.unused_lanes = 0xFF03020100;
        for (j=0; j<AVX_NUM_SHA256_LANES; j++) {
                state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.ldata[j].job_in_lane = NULL;
                state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64+7);
                p = state->states[JOB_STATE_SHA224].hmac_sha_224_ooo.ldata[j].outer_block;
                memset(p + 8*4 + 1,
                       0x00,
                       64 - 8*4 - 1 - 2);
                p[7*4] = 0x80;  // digest 7 words long
                p[64-2] = 0x02; // length in little endian = 0x02E0
                p[64-1] = 0xE0;
        }

        // Init HMAC/SHA256 out-of-order fields
        state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.lens[0] = 0;
        state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.lens[1] = 0;
        state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.lens[2] = 0;
        state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.lens[3] = 0;
        state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.lens[4] = 0xFFFF;
        state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.lens[5] = 0xFFFF;
        state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.lens[6] = 0xFFFF;
        state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.lens[7] = 0xFFFF;
        state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.unused_lanes = 0xFF03020100;
        for (j=0; j<AVX_NUM_SHA256_LANES; j++) {
                state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.ldata[j].job_in_lane = NULL;
                state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64+7);
                p = state->states[JOB_STATE_SHA256].hmac_sha_256_ooo.ldata[j].outer_block;
                memset(p + 8*4 + 1,
                       0x00,
                       64 - 8*4 - 1 - 2);
                p[8*4] = 0x80;  // 8 digest words
                p[64-2] = 0x03; // length
                p[64-1] = 0x00;
        }

        // Init HMAC/SHA384 out-of-order fields
        state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.lens[0] = 0;
        state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.lens[1] = 0;
        state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.lens[2] = 0xFFFF;
        state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.lens[3] = 0xFFFF;
        state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.lens[4] = 0xFFFF;
        state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.lens[5] = 0xFFFF;
        state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.lens[6] = 0xFFFF;
        state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.lens[7] = 0xFFFF;
        state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.unused_lanes = 0xFF0100;
        for (j=0; j< AVX_NUM_SHA512_LANES; j++) {
                state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.ldata[j].job_in_lane = NULL;
                state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.ldata[j].extra_block[SHA_384_BLOCK_SIZE] = 0x80;
                memset(state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.ldata[j].extra_block + (SHA_384_BLOCK_SIZE + 1),
                       0x00,
                       (SHA_384_BLOCK_SIZE+7));
                p = state->states[JOB_STATE_SHA384].hmac_sha_384_ooo.ldata[j].outer_block;
                memset(p + SHA384_DIGEST_SIZE_IN_BYTES  + 1,
                       0x00,
                       SHA_384_BLOCK_SIZE - SHA384_DIGEST_SIZE_IN_BYTES  - 1 - 2); // special end point because this length is constant
                // mark the end
                p[SHA384_DIGEST_SIZE_IN_BYTES] = 0x80;
                // hmac outer block length always of fixed size, it is OKey length, a whole message block length, 1024 bits,, with padding
                // plus the length of the inner digest, which is 384 bits
                // 1408 bits == 0x0580. The input message block needs to be converted to big endian within the sha implementation before use.
                p[SHA_384_BLOCK_SIZE - 2] = 0x05;
                p[SHA_384_BLOCK_SIZE - 1] = 0x80;
        }

        // Init HMAC/SHA512 out-of-order fields
        state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.lens[0] = 0;
        state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.lens[1] = 0;
        state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.lens[2] = 0xFFFF;
        state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.lens[3] = 0xFFFF;
        state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.lens[4] = 0xFFFF;
        state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.lens[5] = 0xFFFF;
        state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.lens[6] = 0xFFFF;
        state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.lens[7] = 0xFFFF;
        state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.unused_lanes = 0xFF0100;
        for (j=0; j< AVX_NUM_SHA512_LANES; j++) {
                state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.ldata[j].job_in_lane = NULL;
                state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.ldata[j].extra_block[SHA_512_BLOCK_SIZE] = 0x80;
                memset(state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.ldata[j].extra_block + (SHA_512_BLOCK_SIZE + 1),
                       0x00,
                       (SHA_512_BLOCK_SIZE+7));
                p = state->states[JOB_STATE_SHA512].hmac_sha_512_ooo.ldata[j].outer_block;
                memset(p + SHA512_DIGEST_SIZE_IN_BYTES  + 1,
                       0x00,
                       SHA_512_BLOCK_SIZE - SHA512_DIGEST_SIZE_IN_BYTES  - 1 - 2); // special end point because this length is constant
                // mark the end
                p[SHA512_DIGEST_SIZE_IN_BYTES] = 0x80;
                // hmac outer block length always of fixed size, it is OKey length, a whole message block length, 1024 bits,, with padding
                // plus the length of the inner digest, which is 512 bits
                // 1536 bits == 0x600. The input message block needs to be converted to big endian within the sha implementation before use.
                p[SHA_512_BLOCK_SIZE - 2] = 0x06;
                p[SHA_512_BLOCK_SIZE - 1] = 0x00;
        }

        // Init HMAC/MD5 out-of-order fields
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[0] = 0;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[1] = 0;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[2] = 0;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[3] = 0;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[4] = 0;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[5] = 0;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[6] = 0;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[7] = 0;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[8] = 0xFFFF;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[9] = 0xFFFF;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[10] = 0xFFFF;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[11] = 0xFFFF;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[12] = 0xFFFF;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[13] = 0xFFFF;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[14] = 0xFFFF;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.lens[15] = 0xFFFF;
        state->states[JOB_STATE_MD5].hmac_md5_ooo.unused_lanes = 0xF76543210;
        for (j=0; j<AVX_NUM_MD5_LANES; j++) {
                state->states[JOB_STATE_MD5].hmac_md5_ooo.ldata[j].job_in_lane = NULL;
                state->states[JOB_STATE_MD5].hmac_md5_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->states[JOB_STATE_MD5].hmac_md5_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64+7);
                p = state->states[JOB_STATE_MD5].hmac_md5_ooo.ldata[j].outer_block;
                memset(p + 5*4 + 1,
                       0x00,
                       64 - 5*4 - 1 - 2);
                p[4*4] = 0x80;
                p[64-7] = 0x02;
                p[64-8] = 0x80;
        }

        // Init AES/XCBC OOO fields
        state->states[JOB_STATE_XCBC].aes_xcbc_ooo.lens[0] = 0;
        state->states[JOB_STATE_XCBC].aes_xcbc_ooo.lens[1] = 0;
        state->states[JOB_STATE_XCBC].aes_xcbc_ooo.lens[2] = 0;
        state->states[JOB_STATE_XCBC].aes_xcbc_ooo.lens[3] = 0;
        state->states[JOB_STATE_XCBC].aes_xcbc_ooo.lens[4] = 0;
        state->states[JOB_STATE_XCBC].aes_xcbc_ooo.lens[5] = 0;
        state->states[JOB_STATE_XCBC].aes_xcbc_ooo.lens[6] = 0;
        state->states[JOB_STATE_XCBC].aes_xcbc_ooo.lens[7] = 0;
        state->states[JOB_STATE_XCBC].aes_xcbc_ooo.unused_lanes = 0xF76543210;
        for (j=0; j<8; j++) {
                state->states[JOB_STATE_XCBC].aes_xcbc_ooo.ldata[j].job_in_lane = NULL;
                state->states[JOB_STATE_XCBC].aes_xcbc_ooo.ldata[j].final_block[16] = 0x80;
                memset(state->states[JOB_STATE_XCBC].aes_xcbc_ooo.ldata[j].final_block + 17, 0x00, 15);
        }

        // Init "in order" components
        state->handler = NULL;
        state->next  = 0;
        state->depth = 0;
}
