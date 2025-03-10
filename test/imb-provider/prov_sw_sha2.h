/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

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

/* Standard Includes */
#include <stdio.h>
#include <string.h>

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>
#include <openssl/modes.h>
#include <openssl/sha.h>

/* Intel IPsec library include */
#include <intel-ipsec-mb.h>

/* Internal flags that can be queried */
#define PROV_DIGEST_FLAG_XOF          0x0001
#define PROV_DIGEST_FLAG_ALGID_ABSENT 0x0002

#define SHA2_FLAGS PROV_DIGEST_FLAG_ALGID_ABSENT

#define PROV_SHA224_DIGEST_LENGTH 28
#define PROV_SHA256_DIGEST_LENGTH 32
#define PROV_SHA384_DIGEST_LENGTH 48
#define PROV_SHA512_DIGEST_LENGTH 64

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
typedef __int64 i64;
typedef unsigned __int64 u64;
#define U64(C) C##UI64
#elif defined(__arch64__)
typedef long i64;
typedef unsigned long u64;
#define U64(C) C##UL
#else
typedef long long i64;
typedef unsigned long long u64;
#define U64(C) C##ULL
#endif

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide.                    !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#define PROV_SHA_LONG unsigned long long int

#define PROV_SHA_LBLOCK 16

#define PROV_SHA_MAX_SIZE 99999999

/* SHA-256 treats input data as a contiguous array of 32 bit wide
 * big-endian values.
 */
#define PROV_SHA256_CBLOCK (PROV_SHA_LBLOCK * 4) // original value is *4

/* SHA-512 treats input data as a contiguous array of 64 bit wide
 * big-endian values.
 */
#define PROV_SHA512_CBLOCK (PROV_SHA_LBLOCK * 8)

typedef struct prov_sha2_st {
        PROV_SHA_LONG h[8];
        PROV_SHA_LONG Nl, Nh;
        size_t block_size;
        size_t md_size;    /* output length, variable in XOF */
        size_t data_bufsz; /* used bytes in below buffer */
        union {
                /*used for 224 & 256 block sizes */
                unsigned char small_data[PROV_SHA_MAX_SIZE];

                /*used for 384 & 512 block sizes */
                unsigned char large_data[PROV_SHA_MAX_SIZE];
        } u;
        unsigned int num;
        unsigned int md_len;
        int md_type;
        unsigned char *name1;
        unsigned char *data22;
        unsigned char digest_data1[EVP_MAX_MD_SIZE];

        EVP_MD *sw_md;
        EVP_MD_CTX *sw_md_ctx;
} PROV_SHA2_CTX;

int
mb_prov_SHA2_init(PROV_SHA2_CTX *ctx);
int
mb_prov_SHA2_update(PROV_SHA2_CTX *ctx, const void *actual_data, size_t len);
int
mb_prov_SHA2_final(PROV_SHA2_CTX *ctx, unsigned char *md);
int
mb_prov_sha2_cleanup(PROV_SHA2_CTX *ctx);
int
prov_sha2_ctx_get_nid(PROV_SHA2_CTX *ctx);