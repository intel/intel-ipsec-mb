
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>

#include "aux_funcs.h"
#include "handler.h"

struct test_data_s {
        uint32_t round_key[15*4];	/* aligned 16 */
        uint8_t pad_1;
        uint8_t raw_key[32];		/* not aligned 16 */
        uint8_t in[16];			/* not aligned 16 */
        uint8_t out_1[16];		/* not aligned 16 */
        uint8_t out_2[16];		/* not aligned 16 */
        uint8_t pad_2;
} __attribute__((packed));



static inline int
aes_ecb(const void *in,
        const void *key,
        unsigned key_len,
        void *out)
{
        AES_KEY enc_key;

        if (AES_set_encrypt_key(key, key_len << 3, &enc_key))
                return -1;
        AES_encrypt(in, out, &enc_key);
        return 0;
}

static inline int
aes_ecb_128(const void *in,
            const void *key,
            void *out)
{
        return aes_ecb(in, key, 16, out);
}

static inline int
aes_ecb_192(const void *in,
            const void *key,
            void *out)
{
        return aes_ecb(in, key, 24, out);
}

static inline int
aes_ecb_256(const void *in,
            const void *key,
            void *out)
{
        return aes_ecb(in, key, 32, out);
}

static void
random_set(void *dst,
           unsigned len)
{
        uint8_t *p = dst;

        while (len) {
                uint32_t v = random();
                unsigned t = len > 4 ? 4 : len;

                memcpy(p, &v, t);
                len -= t;
                p += t;

        }
}

int
ecb_test(enum capability_e cap)
{
        const struct handler_s *handler = get_handler(cap);
        struct test_data_s data __attribute__((aligned(16)));

        random_set(data.raw_key, sizeof(data.raw_key));
        random_set(data.in, sizeof(data.in));

        if (!handler)
                return -1;

        aes_ecb_128(data.in, data.raw_key, data.out_1);
        handler->keyexp_enc_128(data.raw_key, data.round_key);
        handler->ecbenc_128(data.in, data.round_key, data.out_2);
        if (memcmp(data.out_1, data.out_2, sizeof(data.out_1))) {
                FPRINTF(stderr, "key_len:128 mismatched\n");
                return -1;
        }

        aes_ecb_192(data.in, data.raw_key, data.out_1);
        handler->keyexp_enc_192(data.raw_key, data.round_key);
        handler->ecbenc_192(data.in, data.round_key, data.out_2);
        if (memcmp(data.out_1, data.out_2, sizeof(data.out_1))) {
                FPRINTF(stderr, "key_len:192 mismatched\n");
                return -1;
        }

        aes_ecb_256(data.in, data.raw_key, data.out_1);
        handler->keyexp_enc_256(data.raw_key, data.round_key);
        handler->ecbenc_256(data.in, data.round_key, data.out_2);
        if (memcmp(data.out_1, data.out_2, sizeof(data.out_1))) {
                FPRINTF(stderr, "key_len:256 mismatched\n");
                return -1;
        }

        return 0;
}
