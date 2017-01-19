


#include <sys/queue.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "handler.h"

struct esp_hd_s {
        uint32_t spi;
        uint32_t seq;
} __attribute__((packed));


struct esp_frame_s {
        uint8_t verify[16];

        SLIST_ENTRY(esp_frame_s) node;

        union {
                struct {
                        struct esp_hd_s hd;
                        uint8_t iv[8];
                        uint8_t payload[0];
                } ctr;
                struct {
                        struct esp_hd_s hd;
                        uint8_t iv[16];
                        uint8_t payload[0];
                } cbc;
        };
};

SLIST_HEAD(esp_list_s, esp_frame_s);


/****************************************************************************
 *
 ****************************************************************************/
static void
hmac_sha256_key_expand(const struct handler_s *handler,
                       const void *key,
                       uint8_t *ipad,
                       uint8_t *opad)
{
        uint8_t ipad_buf[SHA_256_BLOCK_SIZE] __attribute__((aligned(16)));
        uint8_t opad_buf[SHA_256_BLOCK_SIZE] __attribute__((aligned(16)));

        memset(ipad_buf, 0x36, sizeof(ipad_buf));
        memset(opad_buf, 0x5c, sizeof(opad_buf));


        for (unsigned i = 0; i < SHA_256_BLOCK_SIZE; i++) {

                ipad_buf[i] ^= ((const uint8_t *) key)[i];
                opad_buf[i] ^= ((const uint8_t *) key)[i];
        }
        handler->sha256(ipad_buf, ipad);
        handler->sha256(opad_buf, opad);
}

static uint64_t
bench_cbc(const struct handler_s *handler,
          struct esp_list_s *head,
          unsigned payload_len)
{
        struct MB_MGR mb_mgr;
        union expkey_u enc_key __attribute__((aligned(16)));
        union expkey_u dec_key __attribute__((aligned(16)));
        union expkey_u auth_key __attribute__((aligned(16)));
        JOB_CIPHER_DIRECTION dir;
        uint64_t start_tsc, end_tsc;
        struct JOB_AES_HMAC *job;
        unsigned enc_cnt = 0, dec_cnt = 0;
        handler->init_mb_mgr(&mb_mgr);
        handler->keyexp_256("12345678901234567890123456789012",
                            enc_key.enckey, dec_key.enckey);
        hmac_sha256_key_expand(handler,
                               "12345678901234567890123456789012"
                               "12345678901234567890123456789012",
                               auth_key.ipad,
                               auth_key.opad);
        start_tsc = rdtsc();
        for (dir = ENCRYPT; dir <= DECRYPT; dir++) {
                JOB_CHAIN_ORDER order;
                struct esp_frame_s *next = SLIST_FIRST(head);

                if (dir == ENCRYPT) {
                        order = CIPHER_HASH;
                } else {
                        order = HASH_CIPHER;
                }

                while (next) {
                        struct esp_frame_s *frame = next;

                        next = SLIST_NEXT(frame ,node);
                        if (next)
                                prefetch0(next);
                retry:
                        job = handler->get_next_job(&mb_mgr);
                        if (job) {
                                job->user_data  = frame->verify;
                                job->user_data2 = &frame->cbc.payload[payload_len];

                                job->cipher_direction = dir;
                                job->chain_order = order;
                                job->dst = frame->cbc.payload;
                                job->src = (const UINT8 *) &frame->cbc.hd;

                                job->cipher_mode = CBC;
                                job->aes_enc_key_expanded = enc_key.enckey;
                                job->aes_dec_key_expanded = dec_key.enckey;
                                job->aes_key_len_in_bytes = 256;
                                job->iv = frame->cbc.iv;
                                job->iv_len_in_bytes = 16;
                                job->cipher_start_src_offset_in_bytes = 16 + 8;
                                job->msg_len_to_cipher_in_bytes = payload_len;

                                job->hash_alg = SHA_256;
                                job->hashed_auth_key_xor_ipad = auth_key.ipad;
                                job->hashed_auth_key_xor_opad = auth_key.opad;
                                job->hash_start_src_offset_in_bytes = 0;
                                job->msg_len_to_hash_in_bytes = payload_len + 16;
                                job->auth_tag_output_len_in_bytes = 16;
                                if (dir == ENCRYPT)
                                        job->auth_tag_output = &frame->cbc.payload[payload_len];
                                else
                                        job->auth_tag_output = frame->verify;
                        } else {
                                while ((job = handler->flush_job(&mb_mgr)) != NULL) {
                                        if (job->status != STS_COMPLETED) {
                                                fprintf(stderr, "error line:%d\n", __LINE__);
                                                goto error;
                                        } else {
                                                if (job->cipher_direction == DECRYPT) {
                                                        if (memcmp(job->user_data,
                                                                   job->user_data2,
                                                                   16)) {
                                                                fprintf(stderr, "mismatched\n");
                                                        } else {
                                                                dec_cnt++;
                                                        }
                                                } else {
                                                        enc_cnt++;
                                                }
                                        }
                                }
                                goto retry;
                        }

                        job = handler->submit_job(&mb_mgr);
                        while (job) {
                                if (job->status != STS_COMPLETED) {
                                        fprintf(stderr, "error line:%d\n", __LINE__);
                                        goto error;
                                } else {
                                        if (job->cipher_direction == DECRYPT) {
                                                if (memcmp(job->user_data,
                                                           job->user_data2,
                                                           16)) {
                                                        fprintf(stderr, "mismatched\n");
                                                } else {
                                                        dec_cnt++;
                                                }
                                        } else {
                                                enc_cnt++;
                                        }
                                }
                                job = handler->get_completed_job(&mb_mgr);
                        }
                }
        }

        while ((job = handler->flush_job(&mb_mgr)) != NULL) {
                if (job->status != STS_COMPLETED) {
                        fprintf(stderr, "error line:%d\n", __LINE__);
                        goto error;
                } else {
                        if (job->cipher_direction == DECRYPT) {
                                if (memcmp(job->user_data,
                                           job->user_data2,
                                           16)) {
                                        fprintf(stderr, "mismatched\n");
                                } else {
                                        dec_cnt++;
                                }
                        } else {
                                enc_cnt++;
                        }
                }
        }
        if (enc_cnt != dec_cnt) {
                fprintf(stderr, "mismatched enc:%u dec:%u\n", enc_cnt, dec_cnt);
        }
        end_tsc = rdtsc();
        return end_tsc - start_tsc;
 error:
        fprintf(stderr, "error\n");
        return 0;
}

struct ctr_block_s {
        uint8_t nonce[4];
        uint8_t iv[8];
        union {
                uint8_t ctr[8];
                uint32_t ctr32;	/* _be */
        };
} __attribute__((packed));


static uint64_t
bench_ctr(const struct handler_s *handler,
          struct esp_list_s *head,
          unsigned payload_len)
{
        struct MB_MGR mb_mgr;
        union expkey_u cipher_key __attribute__((aligned(16)));
        union expkey_u auth_key __attribute__((aligned(16)));
        JOB_CIPHER_DIRECTION dir;
        uint64_t start_tsc, end_tsc;
        uint8_t nonce[4] = "1234";
        struct JOB_AES_HMAC *job;
        unsigned enc_cnt = 0, dec_cnt = 0;
        handler->init_mb_mgr(&mb_mgr);
        handler->keyexp_enc_256("12345678901234567890123456789012",
                                cipher_key.enckey);
        hmac_sha256_key_expand(handler,
                               "12345678901234567890123456789012"
                               "12345678901234567890123456789012",
                               auth_key.ipad,
                               auth_key.opad);
        start_tsc = rdtsc();
        for (dir = ENCRYPT; dir <= DECRYPT; dir++) {
                JOB_CHAIN_ORDER order;
                struct esp_frame_s *next = SLIST_FIRST(head);

                if (dir == ENCRYPT) {
                        order = CIPHER_HASH;
                } else {
                        order = HASH_CIPHER;
                }

                while (next) {
                        struct esp_frame_s *frame = next;
                        struct ctr_block_s ctr_block __attribute__((aligned(16)));

                        next = SLIST_NEXT(frame ,node);
                        if (next)
                                prefetch0(next);

                        memcpy(ctr_block.nonce, nonce, 4);
                        memcpy(ctr_block.iv, frame->ctr.iv, 8);
                        ctr_block.ctr32 = bswap32(1);

                retry:
                        job = handler->get_next_job(&mb_mgr);
                        if (job) {
                                job->user_data  = frame->verify;
                                job->user_data2 = &frame->ctr.payload[payload_len];

                                job->cipher_direction = dir;
                                job->chain_order = order;
                                job->dst = frame->ctr.payload;
                                job->src = (const UINT8 *) &frame->ctr.hd;

                                job->cipher_mode = CNTR;
                                job->aes_enc_key_expanded = cipher_key.enckey;
                                job->aes_dec_key_expanded = cipher_key.enckey;
                                job->aes_key_len_in_bytes = 256;
                                job->iv = (const UINT8 *) ctr_block.nonce;
                                job->iv_len_in_bytes = sizeof(ctr_block);
                                job->cipher_start_src_offset_in_bytes = 16;
                                job->msg_len_to_cipher_in_bytes = payload_len;

                                job->hash_alg = SHA_256;
                                job->hashed_auth_key_xor_ipad = auth_key.ipad;
                                job->hashed_auth_key_xor_opad = auth_key.opad;
                                job->hash_start_src_offset_in_bytes = 0;
                                job->msg_len_to_hash_in_bytes = payload_len + 16;
                                job->auth_tag_output_len_in_bytes = 16;
                                if (dir == ENCRYPT)
                                        job->auth_tag_output = &frame->ctr.payload[payload_len];
                                else
                                        job->auth_tag_output = frame->verify;
                        } else {
                                while ((job = handler->flush_job(&mb_mgr)) != NULL) {
                                        if (job->status != STS_COMPLETED) {
                                                fprintf(stderr, "error line:%d\n", __LINE__);
                                                goto error;
                                        } else {
                                                if (job->cipher_direction == DECRYPT) {
                                                        if (memcmp(job->user_data,
                                                                   job->user_data2,
                                                                   16)) {
                                                                fprintf(stderr, "mismatched\n");                                                        } else {
                                                                dec_cnt++;
                                                        }
                                                } else {
                                                        enc_cnt++;
                                                }
                                        }
                                }
                                goto retry;
                        }

                        job = handler->submit_job(&mb_mgr);
                        while (job) {
                                if (job->status != STS_COMPLETED) {
                                        fprintf(stderr, "error line:%d\n", __LINE__);
                                        goto error;
                                } else {
                                        if (job->cipher_direction == DECRYPT) {
                                                if (memcmp(job->user_data,
                                                           job->user_data2,
                                                           16)) {
                                                        fprintf(stderr, "mismatched\n");
                                                } else {
                                                        dec_cnt++;
                                                }
                                        } else {
                                                enc_cnt++;
                                        }
                                }
                                job = handler->get_completed_job(&mb_mgr);
                        }
                }
        }

        while ((job = handler->flush_job(&mb_mgr)) != NULL) {
                if (job->status != STS_COMPLETED) {
                        fprintf(stderr, "error line:%d\n", __LINE__);
                        goto error;
                } else {
                        if (job->cipher_direction == DECRYPT) {
                                if (memcmp(job->user_data,
                                           job->user_data2,
                                           16)) {
                                        fprintf(stderr, "mismatched\n");
                                } else {
                                        dec_cnt++;
                                }
                        } else {
                                enc_cnt++;
                        }
                }
        }
        if (enc_cnt != dec_cnt) {
                fprintf(stderr, "mismatched enc:%u dec:%u\n", enc_cnt, dec_cnt);
        }
        end_tsc = rdtsc();
        return end_tsc - start_tsc;
 error:
        fprintf(stderr, "error\n");
        return 0;
}

static uint64_t
bench_gcm(const struct handler_s *handler,
          struct esp_list_s *head,
          unsigned payload_len)
{
        JOB_CIPHER_DIRECTION dir;
        uint64_t start_tsc, end_tsc;
        uint8_t nonce[8] = "12345678";
        struct gcm_data gdata __attribute__((aligned(16)));
        unsigned ng = 0, ok = 0;

        handler->keyexp_enc_256("12345678901234567890123456789012",
                                gdata.expanded_keys);

        start_tsc = rdtsc();
        for (dir = ENCRYPT; dir <= DECRYPT; dir++) {
                struct esp_frame_s *next = SLIST_FIRST(head);

                while (next) {
                        struct esp_frame_s *frame = next;
                        struct ctr_block_s ctr_block __attribute__((aligned(16)));
                        uint8_t aad[8] __attribute__((aligned(16)));

                        next = SLIST_NEXT(frame ,node);
                        if (next)
                                prefetch0(next);

                        memcpy(aad, &frame->ctr.hd, 8);
                        memcpy(ctr_block.nonce, nonce, 4);
                        memcpy(ctr_block.iv, frame->ctr.iv, 8);
                        ctr_block.ctr32 = bswap32(1);

                        if (dir == ENCRYPT) {
                                handler->gcm_enc_256(&gdata,
                                                     frame->ctr.payload,
                                                     frame->ctr.payload, payload_len,
                                                     (uint8_t *) &ctr_block,
                                                     aad, 8,
                                                     &frame->ctr.payload[payload_len], 16);
                        } else {
                                handler->gcm_dec_256(&gdata,
                                                     frame->ctr.payload,
                                                     frame->ctr.payload, payload_len,
                                                     (uint8_t *) &ctr_block,
                                                     aad, 8,
                                                     frame->verify, 16);

                                if (memcmp(frame->verify, &frame->ctr.payload[payload_len], 16)) {
                                        ng++;

                                        hexdump(stderr, "enc",
                                                &frame->ctr.payload[payload_len], 16);
                                        hexdump(stderr, "dec", frame->verify, 16);
                                        break;
                                } else {
                                        ok++;
                                }
                        }
                }
        }
        end_tsc = rdtsc();
        if (ng)
                fprintf(stderr, "Ok:%u Ng:%u\n", ok, ng);
        return end_tsc - start_tsc;
}

static int
init(struct esp_list_s *head,
     unsigned num,
     unsigned size)
{
        uint32_t seq;
        uint64_t seq64 = random();

        SLIST_INIT(head);

        for (seq = 0; seq < num; seq++) {
                struct esp_frame_s *frame;

                if ((frame = aligned_alloc(4096, size)) == NULL)
                        return -1;
                frame->ctr.hd.seq = bswap32(seq + 1);
                memcpy(frame->ctr.iv, &seq64, 8);
                seq64++;
                SLIST_INSERT_HEAD(head, frame, node);
        }
        return 0;
}

int
benchmark(enum capability_e cap)
{
        struct esp_list_s head;
        uint64_t tsc;
        unsigned len;
        unsigned size = 1024 * 8;
        unsigned num = 1024 * 8;
        const struct handler_s *handler = get_handler(cap);

        if (init(&head, num, size)) {
                fprintf(stderr, "failed to initialize\n");
                return -1;
        }

        for (len = 64; len < size; len <<= 1) {
                tsc = bench_ctr(handler, &head, len);
                if (!tsc)
                        break;
                fprintf(stderr,
                        "CTR len:%u %"PRIu64" cycles/packet %.2f cycles/Byte \n",
                        len, tsc / (num * 2), (double) tsc / (double) (len * num * 2.0));
        }

        for (len = 64; len < size; len <<= 1) {
                tsc = bench_cbc(handler, &head, len);
                if (!tsc)
                        break;
                fprintf(stderr,
                        "CBC len:%u %"PRIu64" cycles/packet %.2f cycles/Byte \n",
                        len, tsc / (num * 2), (double) tsc / (double) (len * num * 2.0));
        }

        for (len = 64; len < size; len <<= 1) {
                tsc = bench_gcm(handler, &head, len);
                if (!tsc)
                        break;
                fprintf(stderr,
                        "GCM len:%u %"PRIu64" cycles/packet %.2f cycles/Byte \n",
                        len, tsc / (num * 2), (double) tsc / (double) (len * num * 2.0));
        }

        {
                struct esp_frame_s *next;

                next = SLIST_FIRST(&head);
                while (next) {
                        struct esp_frame_s *frame = next;

                        next = SLIST_NEXT(frame, node);
                        free(frame);
                }
        }
        return 0;
}
