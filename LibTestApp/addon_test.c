/*
 * Copyright (c) 2017, Intel Corporation
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

#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mb_mgr.h>

#include "addon_test.h"


#if defined(DEBUG)
# define TRACE(fmt, ...)	fprintf(stderr, "%s:%d "fmt, __func__, __LINE__, __VA_ARGS__)
#else
# define TRACE(fmt, ...)
#endif

struct cipher_attr_s {
        const char *name;
        JOB_CIPHER_MODE mode;
        unsigned key_len;
        unsigned iv_len;
};

struct auth_attr_s {
        const char *name;
        JOB_HASH_ALG hash;
        unsigned tag_len;
};

struct test_vec_s {
        uint8_t iv[16];
        uint8_t txt[64];
        uint8_t tag[32];
        uint8_t verify[32];
                
        uint8_t enc_key[16*16];
        uint8_t dec_key[16*16];
        uint8_t ipad[256];
        uint8_t opad[256];
        const struct cipher_attr_s *cipher;
        const struct auth_attr_s *auth;
        
        STAILQ_ENTRY(test_vec_s) entry;
        unsigned seq;
};

/*
 * addon cipher function
 */
static int
cipher_addon(struct JOB_AES_HMAC *job)
{
        struct test_vec_s *node = job->user_data;
        int ret;
        
        TRACE("Seq:%u Cipher Addon cipher:%s auth:%s\n",
              node->seq, node->cipher->name, node->auth->name);

        if (job->cipher_direction == ENCRYPT) {
                memset(job->dst, 1, job->msg_len_to_cipher_in_bytes);
        } else {
                memset(job->dst, 2, job->msg_len_to_cipher_in_bytes);
        }
        return 0;	/* success */
}

/*
 * addon hash function
 */
static int
hash_addon(struct JOB_AES_HMAC *job)
{
        struct test_vec_s *node = job->user_data;
        
        TRACE("Seq:%u Auth Addon cipher:%s auth:%s\n",
              node->seq, node->cipher->name, node->auth->name);

        memset(job->auth_tag_output, 3, job->auth_tag_output_len_in_bytes);
        return 0;	/* success */
}

/*
 * test cipher functions
 */
static const struct auth_attr_s AUTH_ATTR[] = {
        {
                .name = "SHA1",
                .hash = SHA1,
                .tag_len = 12,
        },
        {
                .name = "SHA224",
                .hash = SHA_224,
                .tag_len = 14,
        },
        {
                .name = "SHA256",
                .hash = SHA_256,
                .tag_len = 16,
        },
        {
                .name = "SHA384",
                .hash = SHA_384,
                .tag_len = 24,
        },
        {
                .name = "SHA512",
                .hash = SHA_512,
                .tag_len = 32,
        },
        {
                .name = "MD5",
                .hash = MD5,
                .tag_len = 12,
        },
        {
                .name = "HASH_ADDON",
                .hash = HASH_ADDON,
                .tag_len = 16,
        },
};

/*
 * test hash functions
 */
static const struct cipher_attr_s  CIPHER_ATTR[] = {
        {
                .name = "CBC128",
                .mode = CBC,
                .key_len = 16,
                .iv_len = 16,
        },
        {
                .name = "CBC192",
                .mode = CBC,
                .key_len = 24,
                .iv_len = 16,
        },
        {
                .name = "CBC256",
                .mode = CBC,
                .key_len = 32,
                .iv_len = 16,
        },
        
        {
                .name = "CIPHER_ADDON",
                .mode = CIPHER_ADDON,
                .key_len = 32,
                .iv_len = 12,
        },

        {
                .name = "CTR128",
                .mode = CNTR,
                .key_len = 16,
                .iv_len = 8,
        },
        {
                .name = "CTR192",
                .mode = CNTR,
                .key_len = 24,
                .iv_len = 8,
        },
        {
                .name = "CTR256",
                .mode = CNTR,
                .key_len = 32,
                .iv_len = 8,
        },
};

#define ARRAYOF(_a)	(sizeof(_a) / sizeof(_a[0]))

static inline int
job_check(const struct JOB_AES_HMAC *job)
{
        struct test_vec_s *done = job->user_data;

        TRACE("done Seq:%u Cipher:%s Auth:%s\n",
              done->seq, done->cipher->name, done->auth->name);

        if (job->status != STS_COMPLETED) {
                TRACE("failed job status:%d\n", job->status);
                return -1;
        }
        if (job->cipher_mode == CIPHER_ADDON) {
                if (job->cipher_direction == ENCRYPT) {
                        for (unsigned i = 0; i < job->msg_len_to_cipher_in_bytes; i++) {
                                if (job->dst[i] != 1) {
                                        TRACE("NG add-on encryption %u\n", i);
                                        return -1;
                                }
                        }
                        TRACE("Addon encryption passes Seq:%u\n", done->seq);
                } else {
                        for (unsigned i = 0; i < job->msg_len_to_cipher_in_bytes; i++) {
                                if (job->dst[i] != 2) {
                                        TRACE("NG add-on decryption %u\n", i);
                                        return -1;
                                }
                        }
                        TRACE("Addon decryption passes Seq:%u\n", done->seq);
                }
        }

        if (job->hash_alg == HASH_ADDON) {
                for (unsigned i = 0; i < job->auth_tag_output_len_in_bytes; i++) {
                        if (job->auth_tag_output[i] != 3) {
                                TRACE("NG add-on hashing %u\n", i);
                                return -1;
                        }
                }
                TRACE("Addon hashing passes Seq:%u\n", done->seq);
        }
        return 0;
}


void
addon_test(struct MB_MGR *mgr)
{
        STAILQ_HEAD(test_vec_head, test_vec_s) head = STAILQ_HEAD_INITIALIZER(head);
        struct test_vec_s *node, *done;
        struct JOB_AES_HMAC *job;
        unsigned seq = 0;
        int result = 0;

        /* encryption */
        for (unsigned i = 0; i < ARRAYOF(CIPHER_ATTR); i++) {
                for (unsigned j = 0; j < ARRAYOF(AUTH_ATTR); j++) {
                        while ((job = IMB_GET_NEXT_JOB(mgr)) == NULL) {
                                job = IMB_FLUSH_JOB(mgr);
                                result |= job_check(job);
                                done = job->user_data;
                                STAILQ_INSERT_TAIL(&head, done, entry);
                        }
                        node = malloc(sizeof(*node));
                        node->seq = seq++;

                        node->cipher = &CIPHER_ATTR[i];
                        node->auth = &AUTH_ATTR[j];


                        job->cipher_func = cipher_addon;
                        job->hash_func = hash_addon;

                        job->aes_enc_key_expanded = node->enc_key;
                        job->aes_dec_key_expanded = node->dec_key;
                        job->aes_key_len_in_bytes = node->cipher->key_len;
                        job->src = node->txt;
                        job->dst = node->txt;
                        job->cipher_start_src_offset_in_bytes = 16;
                        job->msg_len_to_cipher_in_bytes = sizeof(node->txt);
                        job->hash_start_src_offset_in_bytes = 0;
                        job->msg_len_to_hash_in_bytes = sizeof(node->txt) + sizeof(node->iv);
                        job->iv = node->iv;
                        job->iv_len_in_bytes = node->cipher->iv_len;
                        job->auth_tag_output = node->tag;
                        job->auth_tag_output_len_in_bytes = node->auth->tag_len;
                                
                        job->u.HMAC._hashed_auth_key_xor_ipad = node->ipad;
                        job->u.HMAC._hashed_auth_key_xor_opad = node->opad;
                        job->cipher_mode = node->cipher->mode;
                        job->cipher_direction = ENCRYPT;
                        job->chain_order = CIPHER_HASH;
                        job->hash_alg = node->auth->hash;
                        job->user_data = node;

                        job = IMB_SUBMIT_JOB_NOCHECK(mgr);
                        while (job) {
                                result |= job_check(job);
                                done = job->user_data;
                                STAILQ_INSERT_TAIL(&head, done, entry);
                                
                                job = IMB_GET_COMPLETED_JOB(mgr);
                        }
                }
        }
        while ((job = IMB_FLUSH_JOB(mgr)) != NULL) {
                result |= job_check(job);
                done = job->user_data;
                STAILQ_INSERT_TAIL(&head, done, entry);
        }

        /* decryption */
        while ((node = STAILQ_FIRST(&head)) != NULL) {
                STAILQ_REMOVE_HEAD(&head, entry);
                
                while ((job = IMB_GET_NEXT_JOB(mgr)) == NULL) {
                        job = IMB_FLUSH_JOB(mgr);
                        result |= job_check(job);
                        done = job->user_data;
                        free(done);
                }

                job->cipher_func = cipher_addon;
                job->hash_func = hash_addon;

                job->aes_enc_key_expanded = node->enc_key;
                job->aes_dec_key_expanded = node->dec_key;
                job->aes_key_len_in_bytes = node->cipher->key_len;
                job->src = node->txt;
                job->dst = node->txt;
                job->cipher_start_src_offset_in_bytes = 16;
                job->msg_len_to_cipher_in_bytes = sizeof(node->txt);
                job->hash_start_src_offset_in_bytes = 0;
                job->msg_len_to_hash_in_bytes = sizeof(node->txt) + sizeof(node->iv);
                job->iv = node->iv;
                job->iv_len_in_bytes = node->cipher->iv_len;
                job->auth_tag_output = node->tag;
                job->auth_tag_output_len_in_bytes = node->auth->tag_len;
                                
                job->u.HMAC._hashed_auth_key_xor_ipad = node->ipad;
                job->u.HMAC._hashed_auth_key_xor_opad = node->opad;
                job->cipher_mode = node->cipher->mode;
                job->cipher_direction = DECRYPT;
                job->chain_order = HASH_CIPHER;
                job->hash_alg = node->auth->hash;
                job->user_data = node;

                job = IMB_SUBMIT_JOB_NOCHECK(mgr);
                while (job) {
                        result |= job_check(job);
                        done = job->user_data;
                        free(done);
                                
                        job = IMB_GET_COMPLETED_JOB(mgr);
                }
        }

        while ((job = IMB_FLUSH_JOB(mgr)) != NULL) {
                result |= job_check(job);
                done = job->user_data;
                free(done);
         }

        if (result)
                fprintf(stdout, "failed addon test\n");
        else
                fprintf(stdout, "Addon test passes\n");
}
