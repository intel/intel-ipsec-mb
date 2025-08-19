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

#ifndef PROV_SW_REQUEST_H
#define PROV_SW_REQUEST_H

#include <stdio.h>
#include <stdint.h>
#include <openssl/ec.h>
#include <openssl/modes.h>

#include <openssl/async.h>
#include <openssl/modes.h>
#include <openssl/core_dispatch.h>
#include <intel-ipsec-mb.h>

#define GENERIC_BLOCK_SIZE 16
typedef struct prov_evp_aes_cbc_cipher_st PROV_EVP_CIPHER;

typedef struct {
        EVP_MD *md;
        EVP_MD *alloc_md;
        ENGINE *engine;
} PROV_DIGEST;

typedef struct _alg_context {

        EVP_MAC_CTX *mac_ctx;
        void *provctx;
        OSSL_LIB_CTX *libctx;
        PROV_DIGEST digest;
        size_t tls_data_size;
        size_t md_size;
        size_t digest_len;
        unsigned char *key;
        size_t keylen;

        size_t block_size;
        IMB_HASH_ALG hash_alg;
        unsigned char msg_hash[64];

        int nid;
        block128_f block;
        union {
                cbc128_f cbc;
                ctr128_f ctr;
                ecb128_f ecb;
        } stream;

        unsigned int mode;
        size_t ivlen;
        size_t blocksize;
        size_t bufsz; /* Number of bytes in buf */
        unsigned int num;
        unsigned int use_bits : 1;
        unsigned int enc : 1;
        unsigned int variable_keylength : 1;
        unsigned int key_set : 1;
        unsigned int pad : 1;
        unsigned int inverse_cipher : 1;
        unsigned int iv_set : 1;

        size_t tlsmacsize;
        unsigned int tlsversion;
        unsigned char *tlsmac;

        /* The original value of the iv */
        unsigned char oiv[GENERIC_BLOCK_SIZE];

        unsigned char next_iv[GENERIC_BLOCK_SIZE];
        /* Buffer of partial blocks processed via update calls */
        unsigned char buf[GENERIC_BLOCK_SIZE];
        unsigned char iv[GENERIC_BLOCK_SIZE];
        const void *ks; /* Pointer to algorithm specific key data */
        IMB_JOB *imb_job;
        unsigned char *enc_keys;
        unsigned char *dec_keys;
        uint8_t auths[64];
        unsigned char *aad;
        int aad_len;

        int tls_aad_len;
        int tag_len;
        int iv_len;
        size_t tls_aad_pad_sz;
        size_t L, M;
        int tag_set;
        PROV_EVP_CIPHER *cipher;

        unsigned char *tag;
        int tag_calculated;
        unsigned char *out;
        unsigned char chacha20_key[32]; /* ChaCha20 key (32 bytes) */
        unsigned char chacha20_iv[12];  /* ChaCha20 IV (12 bytes) */
} ALG_CTX;

typedef struct _op_data {
        struct _op_data *next;
        struct _op_data *prev;
        ALG_CTX *state;
        unsigned char *out;
        const unsigned char *in;
        const unsigned char *data;
        unsigned char *hash;
        IMB_JOB *imb_job;
        size_t len;
        ASYNC_JOB *job;
        int *sts;
        uint8_t auths[64];
        unsigned char enc_keys[16 * 15];
        unsigned char dec_keys[16 * 15];
        const uint8_t *iv;
        int key_len;
        int iv_len;
        int flush;
        struct timespec timestamp;
} op_data;

#endif /* PROV_SW_REQUEST_H */