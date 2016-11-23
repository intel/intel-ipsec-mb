/*
 * Copyright (c) 2012-2016, Intel Corporation
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
#include <assert.h>
#ifdef __WIN32
#include<intrin.h>
#endif

#include "mb_mgr.h"
#include "save_xmms.h"
#include "asm.h"

JOB_AES_HMAC* submit_job_aes128_enc_sse(MB_MGR_AES_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_aes128_enc_sse(MB_MGR_AES_OOO *state);

JOB_AES_HMAC* submit_job_aes192_enc_sse(MB_MGR_AES_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_aes192_enc_sse(MB_MGR_AES_OOO *state);

JOB_AES_HMAC* submit_job_aes256_enc_sse(MB_MGR_AES_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_aes256_enc_sse(MB_MGR_AES_OOO *state);

JOB_AES_HMAC* submit_job_hmac_sse(MB_MGR_HMAC_SHA_1_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_hmac_sse(MB_MGR_HMAC_SHA_1_OOO *state);

JOB_AES_HMAC* submit_job_hmac_ni_sse(MB_MGR_HMAC_SHA_1_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_hmac_ni_sse(MB_MGR_HMAC_SHA_1_OOO *state);

JOB_AES_HMAC* submit_job_hmac_sha_224_sse(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_hmac_sha_224_sse(MB_MGR_HMAC_SHA_256_OOO *state);

JOB_AES_HMAC* submit_job_hmac_sha_224_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_hmac_sha_224_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state);

JOB_AES_HMAC* submit_job_hmac_sha_256_sse(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_hmac_sha_256_sse(MB_MGR_HMAC_SHA_256_OOO *state);

JOB_AES_HMAC* submit_job_hmac_sha_256_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_hmac_sha_256_ni_sse(MB_MGR_HMAC_SHA_256_OOO *state);

JOB_AES_HMAC* submit_job_hmac_sha_384_sse(MB_MGR_HMAC_SHA_512_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_hmac_sha_384_sse(MB_MGR_HMAC_SHA_512_OOO *state);

JOB_AES_HMAC* submit_job_hmac_sha_512_sse(MB_MGR_HMAC_SHA_512_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_hmac_sha_512_sse(MB_MGR_HMAC_SHA_512_OOO *state);

JOB_AES_HMAC* submit_job_hmac_md5_sse(MB_MGR_HMAC_MD5_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_hmac_md5_sse(MB_MGR_HMAC_MD5_OOO *state);


JOB_AES_HMAC* submit_job_aes_xcbc_sse(MB_MGR_AES_XCBC_OOO *state, JOB_AES_HMAC* job);
JOB_AES_HMAC* flush_job_aes_xcbc_sse(MB_MGR_AES_XCBC_OOO *state);

#define SAVE_XMMS save_xmms
#define RESTORE_XMMS restore_xmms
#define SUBMIT_JOB_AES128_ENC submit_job_aes128_enc_sse
#define SUBMIT_JOB_AES128_DEC submit_job_aes128_dec_sse
#define FLUSH_JOB_AES128_ENC  flush_job_aes128_enc_sse
#define SUBMIT_JOB_AES192_ENC submit_job_aes192_enc_sse
#define SUBMIT_JOB_AES192_DEC submit_job_aes192_dec_sse
#define FLUSH_JOB_AES192_ENC  flush_job_aes192_enc_sse
#define SUBMIT_JOB_AES256_ENC submit_job_aes256_enc_sse
#define SUBMIT_JOB_AES256_DEC submit_job_aes256_dec_sse
#define FLUSH_JOB_AES256_ENC  flush_job_aes256_enc_sse
#define SUBMIT_JOB_HMAC       submit_job_hmac_sse
#define FLUSH_JOB_HMAC        flush_job_hmac_sse
#define SUBMIT_JOB_HMAC_NI    submit_job_hmac_ni_sse
#define FLUSH_JOB_HMAC_NI     flush_job_hmac_ni_sse
#define SUBMIT_JOB_HMAC_SHA_224       submit_job_hmac_sha_224_sse
#define FLUSH_JOB_HMAC_SHA_224        flush_job_hmac_sha_224_sse
#define SUBMIT_JOB_HMAC_SHA_224_NI    submit_job_hmac_sha_224_ni_sse
#define FLUSH_JOB_HMAC_SHA_224_NI     flush_job_hmac_sha_224_ni_sse
#define SUBMIT_JOB_HMAC_SHA_256       submit_job_hmac_sha_256_sse
#define FLUSH_JOB_HMAC_SHA_256        flush_job_hmac_sha_256_sse
#define SUBMIT_JOB_HMAC_SHA_256_NI    submit_job_hmac_sha_256_ni_sse
#define FLUSH_JOB_HMAC_SHA_256_NI     flush_job_hmac_sha_256_ni_sse
#define SUBMIT_JOB_HMAC_SHA_384       submit_job_hmac_sha_384_sse
#define FLUSH_JOB_HMAC_SHA_384        flush_job_hmac_sha_384_sse
#define SUBMIT_JOB_HMAC_SHA_512       submit_job_hmac_sha_512_sse
#define FLUSH_JOB_HMAC_SHA_512        flush_job_hmac_sha_512_sse
#define SUBMIT_JOB_HMAC_MD5   submit_job_hmac_md5_sse
#define FLUSH_JOB_HMAC_MD5    flush_job_hmac_md5_sse
#define SUBMIT_JOB_AES_XCBC   submit_job_aes_xcbc_sse
#define FLUSH_JOB_AES_XCBC    flush_job_aes_xcbc_sse

#define SUBMIT_JOB_AES128_CNTR submit_job_aes128_cntr_sse
#define SUBMIT_JOB_AES192_CNTR submit_job_aes192_cntr_sse
#define SUBMIT_JOB_AES256_CNTR submit_job_aes256_cntr_sse

#define AES_CBC_DEC_128       aes_cbc_dec_128_sse
#define AES_CBC_DEC_192       aes_cbc_dec_192_sse
#define AES_CBC_DEC_256       aes_cbc_dec_256_sse

#define AES_CNTR_128       aes_cntr_128_sse
#define AES_CNTR_192       aes_cntr_192_sse
#define AES_CNTR_256       aes_cntr_256_sse

////////////////////////////////////////////////////////////////////////

#define SUBMIT_JOB   submit_job_sse
#define FLUSH_JOB    flush_job_sse

#define SUBMIT_JOB_AES128_DEC submit_job_aes128_dec_sse
#define SUBMIT_JOB_AES192_DEC submit_job_aes192_dec_sse
#define SUBMIT_JOB_AES256_DEC submit_job_aes256_dec_sse
#define QUEUE_SIZE queue_size_sse

////////////////////////////////////////////////////////////////////////

#define SUBMIT_JOB_AES_ENC SUBMIT_JOB_AES_ENC_SSE
#define FLUSH_JOB_AES_ENC  FLUSH_JOB_AES_ENC_SSE
#define SUBMIT_JOB_AES_DEC SUBMIT_JOB_AES_DEC_SSE
#define SUBMIT_JOB_HASH    SUBMIT_JOB_HASH_SSE
#define FLUSH_JOB_HASH     FLUSH_JOB_HASH_SSE

////////////////////////////////////////////////////////////////////////

/* Variable to decide between SIMD or SHAxNI OOO scheduler selection. */
enum SHA_EXTENSION_USAGE sse_sha_ext_usage = SHA_EXT_DETECT;

/* Used to decide if SHA1/SHA256 SIMD or SHA1NI OOO scheduler should be called. */
#define HASH_USE_SHAEXT sse_sha_ext_usage

////////////////////////////////////////////////////////////////////////

struct cpuid_regs {
        UINT32 eax;
        UINT32 ebx;
        UINT32 ecx;
        UINT32 edx;
};

/*
 * A C wrapper for CPUID opcode
 *
 * Parameters:
 *    [in] leaf    - CPUID leaf number (EAX)
 *    [in] subleaf - CPUID sub-leaf number (ECX)
 *    [out] out    - registers structure to store results of CPUID into
 */
static void
__cpuid(const unsigned leaf, const unsigned subleaf,
        struct cpuid_regs *out)
{
#ifdef __WIN32
        /* Windows */
        int regs[4];

        __cpuidex(regs, leaf, subleaf);
        out->eax = regs[0];
        out->ebx = regs[1];
        out->ecx = regs[2];
        out->edx = regs[3];
#else
        /* Linux */
#ifdef __x86_64__
        asm volatile("mov %4, %%eax\n\t"
                     "mov %5, %%ecx\n\t"
                     "cpuid\n\t"
                     "mov %%eax, %0\n\t"
                     "mov %%ebx, %1\n\t"
                     "mov %%ecx, %2\n\t"
                     "mov %%edx, %3\n\t"
                     : "=g" (out->eax), "=g" (out->ebx), "=g" (out->ecx),
                       "=g" (out->edx)
                     : "g" (leaf), "g" (subleaf)
                     : "%eax", "%ebx", "%ecx", "%edx");
#else
        asm volatile("push %%ebx\n\t"
                     "mov %4, %%eax\n\t"
                     "mov %5, %%ecx\n\t"
                     "cpuid\n\t"
                     "mov %%eax, %0\n\t"
                     "mov %%ebx, %1\n\t"
                     "mov %%ecx, %2\n\t"
                     "mov %%edx, %3\n\t"
                     "pop %%ebx\n\t"
                     : "=g" (out->eax), "=g" (out->ebx), "=g" (out->ecx),
                       "=g" (out->edx)
                     : "g" (leaf), "g" (subleaf)
                     : "%eax", "%ecx", "%edx");
#endif
#endif /* Linux */
}

/*
 * Uses CPUID instruction to detected presence of SHA extensions.
 *
 * Return value:
 *     0 - SHA extensions not present
 *     1 - SHA extensions present
 */
static int
sha_extensions_supported(void)
{
        struct cpuid_regs r;

        /* Check highest leaf number. If less then 7 then SHA not supported. */
        __cpuid(0x0, 0x0, &r);
        if (r.eax < 0x7)
                return 0;
        
        /* Check presence of SHA extensions in the extended feature flags */
        __cpuid(0x7, 0x0, &r);
        if (r.ebx & (1 << 29))
                return 1;

        return 0;
}

void 
init_mb_mgr_sse(MB_MGR *state)
{
        unsigned int j;
        UINT8 *p;

#ifdef HASH_USE_SHAEXT
        switch (HASH_USE_SHAEXT) {
        case SHA_EXT_PRESENT:
                break;
        case SHA_EXT_NOT_PRESENT:
                break;
        case SHA_EXT_DETECT:
        default:
                if (sha_extensions_supported())
                        HASH_USE_SHAEXT = SHA_EXT_PRESENT;
                else
                        HASH_USE_SHAEXT = SHA_EXT_NOT_PRESENT;
                break;
        }
#endif /* HASH_USE_SHAEXT */

        // Init AES out-of-order fields
        state->aes128_ooo.lens[0] = 0;
        state->aes128_ooo.lens[1] = 0;
        state->aes128_ooo.lens[2] = 0;
        state->aes128_ooo.lens[3] = 0;
        state->aes128_ooo.lens[4] = 0xFFFF;
        state->aes128_ooo.lens[5] = 0xFFFF;
        state->aes128_ooo.lens[6] = 0xFFFF;
        state->aes128_ooo.lens[7] = 0xFFFF;
        state->aes128_ooo.unused_lanes = 0xFF03020100;
        state->aes128_ooo.job_in_lane[0] = NULL;
        state->aes128_ooo.job_in_lane[1] = NULL;
        state->aes128_ooo.job_in_lane[2] = NULL;
        state->aes128_ooo.job_in_lane[3] = NULL;

        state->aes192_ooo.lens[0] = 0;
        state->aes192_ooo.lens[1] = 0;
        state->aes192_ooo.lens[2] = 0;
        state->aes192_ooo.lens[3] = 0;
        state->aes192_ooo.lens[4] = 0xFFFF;
        state->aes192_ooo.lens[5] = 0xFFFF;
        state->aes192_ooo.lens[6] = 0xFFFF;
        state->aes192_ooo.lens[7] = 0xFFFF;
        state->aes192_ooo.unused_lanes = 0xFF03020100;
        state->aes192_ooo.job_in_lane[0] = NULL;
        state->aes192_ooo.job_in_lane[1] = NULL;
        state->aes192_ooo.job_in_lane[2] = NULL;
        state->aes192_ooo.job_in_lane[3] = NULL;

        state->aes256_ooo.lens[0] = 0;
        state->aes256_ooo.lens[1] = 0;
        state->aes256_ooo.lens[2] = 0;
        state->aes256_ooo.lens[3] = 0;
        state->aes256_ooo.lens[4] = 0xFFFF;
        state->aes256_ooo.lens[5] = 0xFFFF;
        state->aes256_ooo.lens[6] = 0xFFFF;
        state->aes256_ooo.lens[7] = 0xFFFF;
        state->aes256_ooo.unused_lanes = 0xFF03020100;
        state->aes256_ooo.job_in_lane[0] = NULL;
        state->aes256_ooo.job_in_lane[1] = NULL;
        state->aes256_ooo.job_in_lane[2] = NULL;
        state->aes256_ooo.job_in_lane[3] = NULL;

        // Init HMAC/SHA1 out-of-order fields
        state->hmac_sha_1_ooo.lens[0] = 0;
        state->hmac_sha_1_ooo.lens[1] = 0;
        state->hmac_sha_1_ooo.lens[2] = 0;
        state->hmac_sha_1_ooo.lens[3] = 0;
        state->hmac_sha_1_ooo.lens[4] = 0xFFFF;
        state->hmac_sha_1_ooo.lens[5] = 0xFFFF;
        state->hmac_sha_1_ooo.lens[6] = 0xFFFF;
        state->hmac_sha_1_ooo.lens[7] = 0xFFFF;
        state->hmac_sha_1_ooo.unused_lanes = 0xFF03020100;
        for (j=0; j<SSE_NUM_SHA1_LANES; j++) {
                state->hmac_sha_1_ooo.ldata[j].job_in_lane = NULL;
                state->hmac_sha_1_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->hmac_sha_1_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64+7);
                p = state->hmac_sha_1_ooo.ldata[j].outer_block;
                memset(p + 5*4 + 1,
                       0x00,
                       64 - 5*4 - 1 - 2);
                p[5*4] = 0x80;
                p[64-2] = 0x02;
                p[64-1] = 0xA0;
        }

#ifdef HASH_USE_SHAEXT
        if (HASH_USE_SHAEXT == SHA_EXT_PRESENT) {
                // Init HMAC/SHA1 NI out-of-order fields
                state->hmac_sha_1_ooo.lens[0] = 0;
                state->hmac_sha_1_ooo.lens[1] = 0;
                state->hmac_sha_1_ooo.lens[2] = 0xFFFF;
                state->hmac_sha_1_ooo.lens[3] = 0xFFFF;
                state->hmac_sha_1_ooo.lens[4] = 0xFFFF;
                state->hmac_sha_1_ooo.lens[5] = 0xFFFF;
                state->hmac_sha_1_ooo.lens[6] = 0xFFFF;
                state->hmac_sha_1_ooo.lens[7] = 0xFFFF;
                state->hmac_sha_1_ooo.unused_lanes = 0xFF0100;
        }
#endif /* HASH_USE_SHAEXT */
    
        // Init HMAC/SHA224 out-of-order fields
        state->hmac_sha_224_ooo.lens[0] = 0;
        state->hmac_sha_224_ooo.lens[1] = 0;
        state->hmac_sha_224_ooo.lens[2] = 0;
        state->hmac_sha_224_ooo.lens[3] = 0;
        state->hmac_sha_224_ooo.lens[4] = 0xFFFF;
        state->hmac_sha_224_ooo.lens[5] = 0xFFFF;
        state->hmac_sha_224_ooo.lens[6] = 0xFFFF;
        state->hmac_sha_224_ooo.lens[7] = 0xFFFF;
        state->hmac_sha_224_ooo.unused_lanes = 0xFF03020100;
        for (j=0; j<SSE_NUM_SHA256_LANES; j++) {
                state->hmac_sha_224_ooo.ldata[j].job_in_lane = NULL;
                state->hmac_sha_224_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->hmac_sha_224_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64+7);
                p = state->hmac_sha_224_ooo.ldata[j].outer_block;
                memset(p + 8*4 + 1,
                       0x00,
                       64 - 8*4 - 1 - 2);
                p[7*4] = 0x80;  // digest 7 words long
                p[64-2] = 0x02; // length in little endian = 0x02E0
                p[64-1] = 0xE0;
        }
#ifdef HASH_USE_SHAEXT
        if (HASH_USE_SHAEXT == SHA_EXT_PRESENT) {
                // Init HMAC/SHA224 NI out-of-order fields
                state->hmac_sha_224_ooo.lens[0] = 0;
                state->hmac_sha_224_ooo.lens[1] = 0;
                state->hmac_sha_224_ooo.lens[2] = 0xFFFF;
                state->hmac_sha_224_ooo.lens[3] = 0xFFFF;
                state->hmac_sha_224_ooo.lens[4] = 0xFFFF;
                state->hmac_sha_224_ooo.lens[5] = 0xFFFF;
                state->hmac_sha_224_ooo.lens[6] = 0xFFFF;
                state->hmac_sha_224_ooo.lens[7] = 0xFFFF;
                state->hmac_sha_224_ooo.unused_lanes = 0xFF0100;
        }
#endif /* HASH_USE_SHAEXT */

        // Init HMAC/SHA_256 out-of-order fields
        state->hmac_sha_256_ooo.lens[0] = 0;
        state->hmac_sha_256_ooo.lens[1] = 0;
        state->hmac_sha_256_ooo.lens[2] = 0;
        state->hmac_sha_256_ooo.lens[3] = 0;
        state->hmac_sha_256_ooo.lens[4] = 0xFFFF;
        state->hmac_sha_256_ooo.lens[5] = 0xFFFF;
        state->hmac_sha_256_ooo.lens[6] = 0xFFFF;
        state->hmac_sha_256_ooo.lens[7] = 0xFFFF;
        state->hmac_sha_256_ooo.unused_lanes = 0xFF03020100;
        for (j=0; j<SSE_NUM_SHA256_LANES; j++) {
                state->hmac_sha_256_ooo.ldata[j].job_in_lane = NULL;
                state->hmac_sha_256_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->hmac_sha_256_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64+7);
                p = state->hmac_sha_256_ooo.ldata[j].outer_block;
                memset(p + 8*4 + 1,
                       0x00,
                       64 - 8*4 - 1 - 2); // digest is 8*4 bytes long
                p[8*4] = 0x80;
                p[64-2] = 0x03; // length of (opad (64*8) bits + 256 bits) in hex is 0x300
                p[64-1] = 0x00;
        }
#ifdef HASH_USE_SHAEXT
        if (HASH_USE_SHAEXT == SHA_EXT_PRESENT) {
                // Init HMAC/SHA256 NI out-of-order fields
                state->hmac_sha_256_ooo.lens[0] = 0;
                state->hmac_sha_256_ooo.lens[1] = 0;
                state->hmac_sha_256_ooo.lens[2] = 0xFFFF;
                state->hmac_sha_256_ooo.lens[3] = 0xFFFF;
                state->hmac_sha_256_ooo.lens[4] = 0xFFFF;
                state->hmac_sha_256_ooo.lens[5] = 0xFFFF;
                state->hmac_sha_256_ooo.lens[6] = 0xFFFF;
                state->hmac_sha_256_ooo.lens[7] = 0xFFFF;
                state->hmac_sha_256_ooo.unused_lanes = 0xFF0100;
        }
#endif /* HASH_USE_SHAEXT */
    
        // Init HMAC/SHA384 out-of-order fields
        state->hmac_sha_384_ooo.lens[0] = 0;
        state->hmac_sha_384_ooo.lens[1] = 0;
        state->hmac_sha_384_ooo.lens[2] = 0xFFFF;
        state->hmac_sha_384_ooo.lens[3] = 0xFFFF;
        state->hmac_sha_384_ooo.lens[4] = 0xFFFF;
        state->hmac_sha_384_ooo.lens[5] = 0xFFFF;
        state->hmac_sha_384_ooo.lens[6] = 0xFFFF;
        state->hmac_sha_384_ooo.lens[7] = 0xFFFF;
        state->hmac_sha_384_ooo.unused_lanes = 0xFF0100;
        for (j=0; j< SSE_NUM_SHA512_LANES; j++) {
                state->hmac_sha_384_ooo.ldata[j].job_in_lane = NULL;
                state->hmac_sha_384_ooo.ldata[j].extra_block[SHA_384_BLOCK_SIZE] = 0x80;
                memset(state->hmac_sha_384_ooo.ldata[j].extra_block + (SHA_384_BLOCK_SIZE + 1),
                       0x00,
                       (SHA_384_BLOCK_SIZE+7));
                p = state->hmac_sha_384_ooo.ldata[j].outer_block;
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
        state->hmac_sha_512_ooo.lens[0] = 0;
        state->hmac_sha_512_ooo.lens[1] = 0;
        state->hmac_sha_512_ooo.lens[2] = 0xFFFF;
        state->hmac_sha_512_ooo.lens[3] = 0xFFFF;
        state->hmac_sha_512_ooo.lens[4] = 0xFFFF;
        state->hmac_sha_512_ooo.lens[5] = 0xFFFF;
        state->hmac_sha_512_ooo.lens[6] = 0xFFFF;
        state->hmac_sha_512_ooo.lens[7] = 0xFFFF;
        state->hmac_sha_512_ooo.unused_lanes = 0xFF0100;
        for (j=0; j< SSE_NUM_SHA512_LANES; j++) {
                state->hmac_sha_512_ooo.ldata[j].job_in_lane = NULL;
                state->hmac_sha_512_ooo.ldata[j].extra_block[SHA_512_BLOCK_SIZE] = 0x80;
                memset(state->hmac_sha_512_ooo.ldata[j].extra_block + (SHA_512_BLOCK_SIZE + 1),
                       0x00,
                       (SHA_512_BLOCK_SIZE+7));
                p = state->hmac_sha_512_ooo.ldata[j].outer_block;
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
        state->hmac_md5_ooo.lens[0] = 0;
        state->hmac_md5_ooo.lens[1] = 0;
        state->hmac_md5_ooo.lens[2] = 0;
        state->hmac_md5_ooo.lens[3] = 0;
        state->hmac_md5_ooo.lens[4] = 0;
        state->hmac_md5_ooo.lens[5] = 0;
        state->hmac_md5_ooo.lens[6] = 0;
        state->hmac_md5_ooo.lens[7] = 0;
        state->hmac_md5_ooo.lens[8] = 0xFFFF;
        state->hmac_md5_ooo.lens[9] = 0xFFFF;
        state->hmac_md5_ooo.lens[10] = 0xFFFF;
        state->hmac_md5_ooo.lens[11] = 0xFFFF;
        state->hmac_md5_ooo.lens[12] = 0xFFFF;
        state->hmac_md5_ooo.lens[13] = 0xFFFF;
        state->hmac_md5_ooo.lens[14] = 0xFFFF;
        state->hmac_md5_ooo.lens[15] = 0xFFFF;
        state->hmac_md5_ooo.unused_lanes = 0xF76543210;
        for (j=0; j<SSE_NUM_MD5_LANES; j++) {
                state->hmac_md5_ooo.ldata[j].job_in_lane = NULL;
                state->hmac_md5_ooo.ldata[j].extra_block[64] = 0x80;
                memset(state->hmac_md5_ooo.ldata[j].extra_block + 65,
                       0x00,
                       64+7);
                p = state->hmac_md5_ooo.ldata[j].outer_block;
                memset(p + 5*4 + 1,
                       0x00,
                       64 - 5*4 - 1 - 2);
                p[4*4] = 0x80;
                p[64-7] = 0x02;
                p[64-8] = 0x80;
        }

        // Init AES/XCBC OOO fields
        state->aes_xcbc_ooo.lens[0] = 0;
        state->aes_xcbc_ooo.lens[1] = 0;
        state->aes_xcbc_ooo.lens[2] = 0;
        state->aes_xcbc_ooo.lens[3] = 0;
        state->aes_xcbc_ooo.lens[4] = 0xFFFF;
        state->aes_xcbc_ooo.lens[5] = 0xFFFF;
        state->aes_xcbc_ooo.lens[6] = 0xFFFF;
        state->aes_xcbc_ooo.lens[7] = 0xFFFF;
        state->aes_xcbc_ooo.unused_lanes = 0xFF03020100;
        for (j=0; j<4; j++) {
                state->aes_xcbc_ooo.ldata[j].job_in_lane = NULL;
                state->aes_xcbc_ooo.ldata[j].final_block[16] = 0x80;
                memset(state->aes_xcbc_ooo.ldata[j].final_block + 17, 0x00, 15);
        }

        // Init "in order" components
        state->next_job = 0;
        state->earliest_job = -1;
}

#include "mb_mgr_code.h"
