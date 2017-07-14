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

#ifndef NO_ADDON

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


static int
cipher_encrypt(struct JOB_AES_HMAC *job)
{
        (void) job;
        return 0;	/* SUCCESS */
}

static int
cipher_decrypt(struct JOB_AES_HMAC *job)
{
        (void) job;
        return 0;	/* SUCCESS */
}

static struct JOB_AES_HMAC *
cipher_addon(struct MB_MGR *state __attribute__((unused)),
             struct JOB_AES_HMAC *job)
{
        struct test_vec_s *node = job->user_data;
        
        fprintf(stderr, "Seq:%u Cipher Addon cipher:%s auth:%s\n",
                node->seq, node->cipher->name, node->auth->name);

        if (job->status & STS_COMPLETED_AES) {
                fprintf(stderr, "%s already ciphered\n", __func__);
        } else {
                int ret;

                if (job->cipher_direction == ENCRYPT)
                        ret = cipher_encrypt(job);
                else
                        ret = cipher_decrypt(job);

                if (ret)
                        job->status = STS_INTERNAL_ERROR;
                else
                        job->status |= STS_COMPLETED_AES;
        }
        return job;
}

static struct JOB_AES_HMAC *
hash_addon(struct MB_MGR *state __attribute__((unused)),
           struct JOB_AES_HMAC *job)
{
        struct test_vec_s *node = job->user_data;
        
        fprintf(stderr, "Seq:%u Auth Addon cipher:%s auth:%s\n",
                node->seq, node->cipher->name, node->auth->name);

        if (job->status & STS_COMPLETED_HMAC) {
                fprintf(stderr, "%s already hashed\n", __func__);
        } else {
                job->status |= STS_COMPLETED_HMAC;
        }

        return job;
}


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


void
addon_test(struct MB_MGR *mgr)
{
        STAILQ_HEAD(test_vec_head, test_vec_s) head = STAILQ_HEAD_INITIALIZER(head);
        struct test_vec_s *node, *done;
        struct JOB_AES_HMAC *job;
        unsigned seq = 0;
        
        for (unsigned i = 0; i < ARRAYOF(CIPHER_ATTR); i++) {
                for (unsigned j = 0; j < ARRAYOF(AUTH_ATTR); j++) {
                        while ((job = IMB_GET_NEXT_JOB(mgr)) == NULL) {
                                job = IMB_FLUSH_JOB(mgr);
                                if (job->status != STS_COMPLETED)
                                        fprintf(stderr, "failed job status:%d\n",
                                                job->status);
                                done = job->user_data;
                                fprintf(stderr, "done Seq:%u Cipher:%s Auth:%s\n",
                                        done->seq, done->cipher->name, done->auth->name);
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
                                if (job->status != STS_COMPLETED)
                                        fprintf(stderr, "failed job status:%d\n",
                                                job->status);
                                done = job->user_data;
                                fprintf(stderr, "done Seq:%u Cipher:%s Auth:%s\n",
                                        done->seq, done->cipher->name, done->auth->name);
                                STAILQ_INSERT_TAIL(&head, done, entry);
                                
                                job = IMB_GET_COMPLETED_JOB(mgr);
                        }
                }
        }
        while ((job = IMB_FLUSH_JOB(mgr)) != NULL) {
                if (job->status != STS_COMPLETED)
                        fprintf(stderr, "failed job status:%d\n",
                                job->status);
                done = job->user_data;
                fprintf(stderr, "done Seq:%u Cipher:%s Auth:%s\n",
                        done->seq, done->cipher->name, done->auth->name);
                STAILQ_INSERT_TAIL(&head, done, entry);
         }


        fprintf(stderr, "XXX decrypting\n");

        while ((node = STAILQ_FIRST(&head)) != NULL) {
                STAILQ_REMOVE_HEAD(&head, entry);
                
                while ((job = IMB_GET_NEXT_JOB(mgr)) == NULL) {
                        job = IMB_FLUSH_JOB(mgr);
                        if (job->status != STS_COMPLETED)
                                fprintf(stderr, "failed job status:%d\n",
                                                job->status);
                        done = job->user_data;
                        fprintf(stderr, "done Seq:%u Cipher:%s Auth:%s\n",
                                done->seq, done->cipher->name, done->auth->name);
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
                        if (job->status != STS_COMPLETED)
                                fprintf(stderr, "failed job status:%d\n",
                                        job->status);
                        done = job->user_data;
                        fprintf(stderr, "done Seq:%u Cipher:%s Auth:%s\n",
                                done->seq, done->cipher->name, done->auth->name);
                        free(done);
                                
                        job = IMB_GET_COMPLETED_JOB(mgr);
                }

        }

        while ((job = IMB_FLUSH_JOB(mgr)) != NULL) {
                if (job->status != STS_COMPLETED)
                        fprintf(stderr, "failed job status:%d\n",
                                job->status);
                done = job->user_data;
                fprintf(stderr, "done Seq:%u Cipher:%s Auth:%s\n",
                        done->seq, done->cipher->name, done->auth->name);
                free(done);
         }
}


#if 0
static const struct cipher_attr_s *
get_cipher_attr(void)
{
        int n = random();

        n %= (sizeof(CIPHER_ATTR) / sizeof(CIPHER_ATTR[0]));
        //        fprintf(stderr, "cipher:%s\n", CIPHER_ATTR[n].name);
        return &CIPHER_ATTR[n];
}

static const struct auth_attr_s *
get_auth_attr(void)
{
        int n = random();

        n %= (sizeof(AUTH_ATTR) / sizeof(AUTH_ATTR[0]));
        //        fprintf(stderr, "auth:%s\n", AUTH_ATTR[n].name);
        return &AUTH_ATTR[n];
}

void
addon_test(struct MB_MGR *state)
{
        struct packet_s {
                char iv[16];
                char data[16];
                char tag[32];
        };
        struct packet_s *pkt = NULL;
        unsigned cipher_key_len[] = {
                16, 24, 32,
        };
        JOB_HASH_ALG hash_alg[] = {
                SHA1, SHA_224, SHA_256, SHA_384, SHA_512, MD5,
        };
        char any_key[512];
        DECLARE_ALIGNED(uint32_t enc_keys[15*4], 16);
        DECLARE_ALIGNED(uint32_t dec_keys[15*4], 16);
        DECLARE_ALIGNED(uint8_t ipad_hash[5*4], 16);
        DECLARE_ALIGNED(uint8_t opad_hash[5*4], 16);
        unsigned tag_len[] = {
                12, 14, 16, 24, 32, 12,
        };
        JOB_CIPHER_DIRECTION cipher_dir[] = {
                ENCRYPT, DECRYPT,
        };
        JOB_CHAIN_ORDER chain_order[] = {
                CIPHER_HASH, HASH_CIPHER,
        };

        if ((pkt = calloc(1000, sizeof(*pkt))) != NULL) {
                const struct auth_attr_s *auth_attr;
                const struct cipher_attr_s *cipher_attr;
                struct JOB_AES_HMAC *job;
                unsigned loops = 10000;

                while (loops--) {
                        struct packet_s *p = pkt;

                        for (unsigned i = 0; i < 1000; i++) {

                                cipher_attr = get_cipher_attr();
                                auth_attr = get_auth_attr();

                                while ((job = IMB_GET_NEXT_JOB(state)) == NULL) {
                                        job = IMB_FLUSH_JOB(state);
                                        if (job->status != STS_COMPLETED)
                                                fprintf(stderr, "failed job status:%d\n",
                                                        job->status);
                                }

                                job->cipher_func = cipher_addon;
                                job->hash_func = hash_addon;

                                job->aes_enc_key_expanded = enc_keys;
                                job->aes_dec_key_expanded = dec_keys;
                                job->aes_key_len_in_bytes = cipher_attr->key_len;
                                job->src = (const UINT8 *) p;
                                job->dst = p->data;
                                job->cipher_start_src_offset_in_bytes = 16;
                                job->msg_len_to_cipher_in_bytes = 16;
                                job->hash_start_src_offset_in_bytes = 0;
                                job->msg_len_to_hash_in_bytes = 32;
                                job->iv = p->iv;
                                job->iv_len_in_bytes = cipher_attr->iv_len;
                                job->auth_tag_output = p->tag;
                                job->auth_tag_output_len_in_bytes = auth_attr->tag_len;
                                
                                job->u.HMAC._hashed_auth_key_xor_ipad = (const UINT8 *) ipad_hash;
                                job->u.HMAC._hashed_auth_key_xor_opad = (const UINT8 *) opad_hash;
                                job->cipher_mode = cipher_attr->mode;
                                job->cipher_direction = cipher_attr->dir;
                                job->chain_order = cipher_attr->chain_order;
                                job->hash_alg = auth_attr->hash;

                                job = IMB_SUBMIT_JOB_NOCHECK(state);
                                while (job) {
                                        if (job->status != STS_COMPLETED)
                                                fprintf(stderr, "failed job status:%d\n",
                                                        job->status);
                                        job = IMB_GET_COMPLETED_JOB(state);
                                }
                                p++;
                        }
                }

                while ((job = IMB_FLUSH_JOB(state)) != NULL) {
                        if (job->status != STS_COMPLETED)
                                fprintf(stderr, "failed job status:%d\n",
                                        job->status);
                }
                free(pkt);
        }
}
#endif
#endif /* !NO_ADDON */
