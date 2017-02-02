#ifndef _HANDLER_H_
#define _HANDLER_H_

#include <stdint.h>
#include <stdio.h>

#include <aux_funcs.h>
#include <mb_mgr.h>
#include <gcm_defines.h>

enum capability_e {
        SSE = 0,
        AVX,
        AVX2,
        AVX512,

        NB_CAPS,
};

static const char *CapName[] = {
        "SSE",
        "AVX",
        "AVX2",
        "AVX512",
};

typedef void (*xcbc_expand_key_t)(const void *, void *k1, void *k2, void *k3);
typedef void (*keyexp_t)(const void *raw, void *enc, void *dec);
typedef void (*keyexp_enc_t)(const void *raw, void *enc);
typedef void (*gcm_precomp_t)(struct gcm_data *, u8 *);
typedef void (*gcm_comp_t)(gcm_data *, u8 *out, const u8 *in, u64 len, u8 *iv,
                           const u8 *aad, u64 aad_len, u8 *tag, u64 tag_len);
typedef void (*hash_one_block_t)(const void *in, void *out);
typedef void (*ecbenc_t)(const void *in, const void *enc_exp_keys, void *out);

struct handler_s {
        init_mb_mgr_t init_mb_mgr;
        get_next_job_t get_next_job;
        submit_job_t submit_job;
        get_completed_job_t get_completed_job;
        flush_job_t flush_job;

        ecbenc_t ecbenc_128;
        ecbenc_t ecbenc_192;
        ecbenc_t ecbenc_256;

        gcm_precomp_t gcm_precomp_128;
        gcm_comp_t gcm_enc_128;
        gcm_comp_t gcm_dec_128;
        gcm_precomp_t gcm_precomp_192;
        gcm_comp_t gcm_enc_192;
        gcm_comp_t gcm_dec_192;
        gcm_precomp_t gcm_precomp_256;
        gcm_comp_t gcm_enc_256;
        gcm_comp_t gcm_dec_256;

        keyexp_t keyexp_128;
        keyexp_t keyexp_192;
        keyexp_t keyexp_256;

        hash_one_block_t sha1;
        hash_one_block_t sha256;
        hash_one_block_t sha384;
        hash_one_block_t sha512;
        xcbc_expand_key_t keyexp_xcbc;

        keyexp_enc_t keyexp_enc_128;
        keyexp_enc_t keyexp_enc_192;
        keyexp_enc_t keyexp_enc_256;
};

static const struct handler_s Handlers[] = {
        [SSE] = {
                .sha1              = sha1_one_block_sse,
                .sha256            = sha256_one_block_sse,
                .sha384            = sha384_one_block_sse,
                .sha512            = sha512_one_block_sse,
                .keyexp_xcbc       = aes_xcbc_expand_key_sse,
                .keyexp_128        = aes_keyexp_128_sse,
                .keyexp_192        = aes_keyexp_192_sse,
                .keyexp_256        = aes_keyexp_256_sse,
                .keyexp_enc_128    = aes_keyexp_128_enc_sse,
                .keyexp_enc_192    = aes_keyexp_192_enc_sse,
                .keyexp_enc_256    = aes_keyexp_256_enc_sse,
                .ecbenc_128        = aes_ecbenc_128_sse,
                .ecbenc_192        = aes_ecbenc_192_sse,
                .ecbenc_256        = aes_ecbenc_256_sse,
                .gcm_precomp_128   = aesni_gcm_precomp_sse,
                .gcm_enc_128       = aesni_gcm_enc_sse,
                .gcm_dec_128       = aesni_gcm_dec_sse,
                .gcm_precomp_192   = aesni_gcm192_precomp_sse,
                .gcm_enc_192       = aesni_gcm192_enc_sse,
                .gcm_dec_192       = aesni_gcm192_dec_sse,
                .gcm_precomp_256   = aesni_gcm256_precomp_sse,
                .gcm_enc_256       = aesni_gcm256_enc_sse,
                .gcm_dec_256       = aesni_gcm256_dec_sse,
                .init_mb_mgr       = init_mb_mgr_sse,
                .get_next_job      = get_next_job_sse,
                .submit_job        = submit_job_sse,
                .get_completed_job = get_completed_job_sse,
                .flush_job         = flush_job_sse,
        },
        [AVX] = {
                .sha1              = sha1_one_block_avx,
                .sha256            = sha256_one_block_avx,
                .sha384            = sha384_one_block_avx,
                .sha512            = sha512_one_block_avx,
                .keyexp_xcbc       = aes_xcbc_expand_key_avx,
                .keyexp_128        = aes_keyexp_128_avx,
                .keyexp_192        = aes_keyexp_192_avx,
                .keyexp_256        = aes_keyexp_256_avx,
                .keyexp_enc_128    = aes_keyexp_128_enc_avx,
                .keyexp_enc_192    = aes_keyexp_192_enc_avx,
                .keyexp_enc_256    = aes_keyexp_256_enc_avx,
                .ecbenc_128         = aes_ecbenc_128_avx,
                .ecbenc_192         = aes_ecbenc_192_avx,
                .ecbenc_256         = aes_ecbenc_256_avx,
                .gcm_precomp_128   = aesni_gcm_precomp_avx_gen2,
                .gcm_enc_128       = aesni_gcm_enc_avx_gen2,
                .gcm_dec_128       = aesni_gcm_dec_avx_gen2,
                .gcm_precomp_192   = aesni_gcm192_precomp_avx_gen2,
                .gcm_enc_192       = aesni_gcm192_enc_avx_gen2,
                .gcm_dec_192       = aesni_gcm192_dec_avx_gen2,
                .gcm_precomp_256   = aesni_gcm256_precomp_avx_gen2,
                .gcm_enc_256       = aesni_gcm256_enc_avx_gen2,
                .gcm_dec_256       = aesni_gcm256_dec_avx_gen2,
                .init_mb_mgr       = init_mb_mgr_avx,
                .get_next_job      = get_next_job_avx,
                .submit_job        = submit_job_avx,
                .get_completed_job = get_completed_job_avx,
                .flush_job         = flush_job_avx,

        },
        [AVX2] = {
                .sha1              = sha1_one_block_avx2,
                .sha256            = sha256_one_block_avx2,
                .sha384            = sha384_one_block_avx2,
                .sha512            = sha512_one_block_avx2,
                .keyexp_xcbc       = aes_xcbc_expand_key_avx2,
                .keyexp_128        = aes_keyexp_128_avx2,
                .keyexp_192        = aes_keyexp_192_avx2,
                .keyexp_256        = aes_keyexp_256_avx2,
                .keyexp_enc_128    = aes_keyexp_128_enc_avx2,
                .keyexp_enc_192    = aes_keyexp_192_enc_avx2,
                .keyexp_enc_256    = aes_keyexp_256_enc_avx2,
                .ecbenc_128         = aes_ecbenc_128_avx2,
                .ecbenc_192         = aes_ecbenc_192_avx2,
                .ecbenc_256         = aes_ecbenc_256_avx2,
                .gcm_precomp_128   = aesni_gcm_precomp_avx_gen4,
                .gcm_enc_128       = aesni_gcm_enc_avx_gen4,
                .gcm_dec_128       = aesni_gcm_dec_avx_gen4,
                .gcm_precomp_192   = aesni_gcm192_precomp_avx_gen4,
                .gcm_enc_192       = aesni_gcm192_enc_avx_gen4,
                .gcm_dec_192       = aesni_gcm192_dec_avx_gen4,
                .gcm_precomp_256   = aesni_gcm256_precomp_avx_gen4,
                .gcm_enc_256       = aesni_gcm256_enc_avx_gen4,
                .gcm_dec_256       = aesni_gcm256_dec_avx_gen4,
                .init_mb_mgr       = init_mb_mgr_avx2,
                .get_next_job      = get_next_job_avx2,
                .submit_job        = submit_job_avx2,
                .get_completed_job = get_completed_job_avx2,
                .flush_job         = flush_job_avx2,
        },
        [AVX512] = {
                .sha1              = sha1_one_block_avx512,
                .sha256            = sha256_one_block_avx512,
                .sha384            = sha384_one_block_avx512,
                .sha512            = sha512_one_block_avx512,
                .keyexp_xcbc       = aes_xcbc_expand_key_avx512,
                .keyexp_128        = aes_keyexp_128_avx512,
                .keyexp_192        = aes_keyexp_192_avx512,
                .keyexp_256        = aes_keyexp_256_avx512,
                .keyexp_enc_128    = aes_keyexp_128_enc_avx512,
                .keyexp_enc_192    = aes_keyexp_192_enc_avx512,
                .keyexp_enc_256    = aes_keyexp_256_enc_avx512,
                .ecbenc_128         = aes_ecbenc_128_avx512,
                .ecbenc_192         = aes_ecbenc_192_avx512,
                .ecbenc_256         = aes_ecbenc_256_avx512,
                .gcm_precomp_128   = aesni_gcm_precomp_avx_gen4,
                .gcm_enc_128       = aesni_gcm_enc_avx_gen4,
                .gcm_dec_128       = aesni_gcm_dec_avx_gen4,
                .gcm_precomp_192   = aesni_gcm192_precomp_avx_gen4,
                .gcm_enc_192       = aesni_gcm192_enc_avx_gen4,
                .gcm_dec_192       = aesni_gcm192_dec_avx_gen4,
                .gcm_precomp_256   = aesni_gcm256_precomp_avx_gen4,
                .gcm_enc_256       = aesni_gcm256_enc_avx_gen4,
                .gcm_dec_256       = aesni_gcm256_dec_avx_gen4,
                .init_mb_mgr       = init_mb_mgr_avx512,
                .get_next_job      = get_next_job_avx512,
                .submit_job        = submit_job_avx512,
                .get_completed_job = get_completed_job_avx512,
                .flush_job         = flush_job_avx512,
        },
};

static inline const struct handler_s *
get_handler(enum capability_e cap)
{
        return &Handlers[cap];
}

static inline const char *
get_cap_name(enum capability_e cap)
{
        return CapName[cap];
}

#ifndef ARRAYOF
# define ARRAYOF(_a)	(sizeof(_a)/sizeof(_a[0]))
#endif

enum result_e {
        OK = 0,
        FAIL,
        SKIP,

        NB_RESULTS,
};

union expkey_u {
        struct {	/* CTR */
                uint32_t enckey[4*15];
        } __attribute__((packed));

        struct {	/* hmac */
                uint8_t ipad[64];
                uint8_t opad[64];
        } __attribute__((packed));

        struct {	/* xcbc */
                uint32_t k1[4*11];
                uint8_t k2[16];
                uint8_t k3[16];
        } __attribute__((packed));
};


extern int Verbose;

#define FPRINTF(_f, ...)                                \
do {                                                    \
        if (Verbose)                                    \
                fprintf((_f), ##__VA_ARGS__);           \
} while (0)

static inline void
hexdump(FILE *fp,
        const char *msg,
        const void *p,
        size_t len)
{
        unsigned int i, out, ofs;
        const unsigned char *data = p;

        if (!Verbose)
                return;

        fprintf(fp, "%s\n", msg);

        ofs = 0;
        while (ofs < len) {
                char line[120];

                out = snprintf(line, sizeof(line), "%08x:", ofs);
                for (i = 0; ((ofs + i) < len) && (i < 16); i++)
                        out += snprintf(line + out, sizeof(line) - out,
                                        " %02x", (data[ofs + i] & 0xff));
                for(; i <= 16; i++)
                        out += snprintf(line + out, sizeof(line) - out, " | ");
                for(i = 0; (ofs < len) && (i < 16); i++, ofs++) {
                        unsigned char c = data[ofs];
                        if ( (c < ' ') || (c > '~'))
                                c = '.';
                        out += snprintf(line + out, sizeof(line) - out, "%c", c);
                }
                fprintf(fp, "%s\n", line);
        }
}

static inline uint32_t
bswap32(uint32_t _x)
{
        register uint32_t x = _x;

        asm volatile ("bswap %[x]" : [x] "+r" (x));
        return x;
}

static inline uint64_t
rdtsc(void)
{
        union {
                uint64_t tsc_64;
                struct {
                        uint32_t lo_32;
                        uint32_t hi_32;
                };
        } tsc;

        asm volatile("rdtsc" :
                     "=a" (tsc.lo_32),
                     "=d" (tsc.hi_32));
        return tsc.tsc_64;
}

static inline void
prefetch0(const volatile void *p)
{
        asm volatile ("prefetcht0 %[p]" : : [p] "m" (*(const volatile char *) p));
}

/*
 * prototypes
 */
extern int ctr_test(enum capability_e cap);
extern int gcm_test(enum capability_e cap);
extern int hmac_test(enum capability_e cap);
extern int ecb_test(enum capability_e cap);
extern int benchmark(enum capability_e cap);

#endif	/* !_HANDLER_H_ */
