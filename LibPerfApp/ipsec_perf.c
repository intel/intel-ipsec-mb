/**********************************************************************
  Copyright(c) 2017-2018, Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#include <intrin.h>
#define __forceinline static __forceinline
#else
#include <x86intrin.h>
#define __forceinline static inline __attribute__((always_inline))
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#endif

#include "mb_mgr.h"
#include "gcm_defines.h"

#define BUFSIZE (512 * 1024 * 1024)
#define JOB_SIZE (2 * 1024)
#define JOB_SIZE_STEP 16
#define REGION_SIZE (JOB_SIZE + 3003)
#define NUM_OFFSETS (BUFSIZE / REGION_SIZE)
#define NUM_RUNS 16
#define KEYS_PER_JOB 15
#define ITER_SCALE 200000
#define BITS(x) (sizeof(x) * 8)

#define NUM_ARCHS 4 /* SSE, AVX, AVX2, AVX512 */
#define NUM_TYPES 6 /* AES_HMAC, AES_DOCSIS, AES_GCM, AES_CCM, DES, 3DES */
#define MAX_NUM_THREADS 16 /* Maximum number of threads that can be created */

#define CIPHER_MODES_AES 4	/* CBC, CNTR, CNTR+8, NULL_CIPHER */
#define CIPHER_MODES_DOCSIS 4	/* AES DOCSIS, AES DOCSIS+8, DES DOCSIS,
                                   DES DOCSIS+8 */
#define CIPHER_MODES_DES 1	/* DES */
#define CIPHER_MODES_GCM 1	/* GCM */
#define CIPHER_MODES_CCM 1	/* CCM */
#define CIPHER_MODES_3DES 1	/* 3DES */
#define DIRECTIONS 2		/* ENC, DEC */
#define HASH_ALGS_AES 9		/* SHA1, SHA256, SHA224, SHA384, SHA512, XCBC,
                                   MD5, NULL_HASH, CMAC */
#define HASH_ALGS_DOCSIS 1	/* NULL_HASH */
#define HASH_ALGS_GCM 1		/* GCM */
#define HASH_ALGS_CCM 1		/* CCM */
#define HASH_ALGS_DES 1		/* NULL_HASH for DES */
#define HASH_ALGS_3DES 1	/* NULL_HASH for 3DES */
#define KEY_SIZES_AES 3		/* 16, 24, 32 */
#define KEY_SIZES_DOCSIS 1	/* 16 or 8 */
#define KEY_SIZES_GCM 3		/* 16, 24, 32 */
#define KEY_SIZES_CCM 1		/* 16 */
#define KEY_SIZES_DES 1		/* 8 */
#define KEY_SIZES_3DES 1	/* 8 x 3 */

/* Those defines tell how many different test cases are to be performed.
 * Have to be multiplied by number of chosen architectures.
 */
#define VARIANTS_PER_ARCH_AES (CIPHER_MODES_AES * DIRECTIONS *  \
                               HASH_ALGS_AES * KEY_SIZES_AES)
#define VARIANTS_PER_ARCH_DOCSIS (CIPHER_MODES_DOCSIS * DIRECTIONS *  \
                                  HASH_ALGS_DOCSIS * KEY_SIZES_DOCSIS)
#define VARIANTS_PER_ARCH_GCM (CIPHER_MODES_GCM * DIRECTIONS *  \
                               HASH_ALGS_GCM * KEY_SIZES_GCM)
#define VARIANTS_PER_ARCH_CCM (CIPHER_MODES_CCM * DIRECTIONS *  \
                               HASH_ALGS_CCM * KEY_SIZES_CCM)
#define VARIANTS_PER_ARCH_DES (CIPHER_MODES_DES * DIRECTIONS *  \
                               HASH_ALGS_DES * KEY_SIZES_DES)
#define VARIANTS_PER_ARCH_3DES (CIPHER_MODES_3DES * DIRECTIONS *  \
                                HASH_ALGS_3DES * KEY_SIZES_3DES)

/* Typedefs used for GCM callbacks */
typedef void (*aesni_gcm_t)(const struct gcm_key_data *,
                            struct gcm_context_data *,
                            uint8_t *, const uint8_t *, uint64_t,
                            const uint8_t *, const uint8_t *, uint64_t,
                            uint8_t *, uint64_t);
typedef void (*aesni_gcm_pre_t)(const void *, struct gcm_key_data *);

/* AES_HMAC, DOCSIS callbacks */
struct funcs_s {
        init_mb_mgr_t       init_mb_mgr;
        get_next_job_t      get_next_job;
        submit_job_t        submit_job;
        get_completed_job_t get_completed_job;
        flush_job_t         flush_job;
};

/* GCM callbacks */
struct funcs_gcm_s {
        aesni_gcm_pre_t	aesni_gcm_pre;
        aesni_gcm_t	aesni_gcm_enc;
        aesni_gcm_t	aesni_gcm_dec;
};

enum arch_type_e {
        ARCH_SSE = 0,
        ARCH_AVX,
        ARCH_AVX2,
        ARCH_AVX512
};

enum test_type_e {
        TTYPE_AES_HMAC,
        TTYPE_AES_DOCSIS,
        TTYPE_AES_GCM,
        TTYPE_AES_CCM,
        TTYPE_AES_DES,
        TTYPE_AES_3DES
};

/* This enum will be mostly translated to JOB_CIPHER_MODE */
enum test_cipher_mode_e {
        TEST_CBC = 1,
        TEST_CNTR,
        TEST_CNTR8, /* CNTR with increased buffer by 8 */
        TEST_NULL_CIPHER,
        TEST_AESDOCSIS,
        TEST_AESDOCSIS8, /* AES DOCSIS with increased buffer size by 8 */
        TEST_DESDOCSIS,
        TEST_DESDOCSIS4, /* DES DOCSIS with increased buffer size by 4 */
        TEST_GCM, /* Additional field used by GCM, not translated */
        TEST_CCM,
        TEST_DES,
        TEST_3DES,
};

/* This enum will be mostly translated to JOB_HASH_ALG */
enum test_hash_alg_e {
        TEST_SHA1 = 1,
        TEST_SHA_224,
        TEST_SHA_256,
        TEST_SHA_384,
        TEST_SHA_512,
        TEST_XCBC,
        TEST_MD5,
        TEST_HASH_CMAC, /* added here to be included in AES tests */
        TEST_NULL_HASH,
        TEST_HASH_GCM, /* Additional field used by GCM, not translated */
        TEST_CUSTOM_HASH, /* unused */
        TEST_HASH_CCM
};

/* Struct storing cipher parameters */
struct params_s {
        JOB_CIPHER_DIRECTION	cipher_dir;
        enum test_type_e	test_type; /* AES, DOCSIS, GCM */
        enum test_cipher_mode_e	cipher_mode;
        enum test_hash_alg_e	hash_alg;
        uint32_t		aes_key_size;
        uint32_t		size_aes;
        uint32_t		num_sizes;
        uint32_t		num_variants;
};

/* This struct stores all information about performed test case */
struct variant_s {
        uint32_t arch;
        struct params_s params;
        uint64_t *avg_times;
};

/* Struct storing information to be passed to threads */
struct thread_info {
        int print_info;
        int core;
} t_info[MAX_NUM_THREADS];

enum cache_type_e {
        WARM = 0,
        COLD = 1
};

#ifdef DEBUG
#define FUNCS(A) {                              \
                init_mb_mgr_##A,                \
                        get_next_job_##A,       \
                        submit_job_##A,         \
                        get_completed_job_##A,  \
                        flush_job_##A           \
                        }
#else
#define FUNCS(A) {                              \
                init_mb_mgr_##A,                \
                        get_next_job_##A,       \
                        submit_job_nocheck_##A, \
                        get_completed_job_##A,  \
                        flush_job_##A           \
                        }
#endif

#define FUNCS_GCM(A)                                                    \
        {aes_gcm_pre_128_##A, aes_gcm_enc_128_##A, aes_gcm_dec_128_##A}, \
        {aes_gcm_pre_192_##A, aes_gcm_enc_192_##A, aes_gcm_dec_192_##A}, \
        {aes_gcm_pre_256_##A, aes_gcm_enc_256_##A, aes_gcm_dec_256_##A}


/* Function pointers used by TTYPE_AES_HMAC, TTYPE_AES_DOCSIS */
struct funcs_s func_sets[NUM_ARCHS] = {
        FUNCS(sse),
        FUNCS(avx),
        FUNCS(avx2),
        FUNCS(avx512)
};

/* Function pointers used by TTYPE_AES_GCM */
struct funcs_gcm_s func_sets_gcm[NUM_ARCHS - 1][3] = {
        {FUNCS_GCM(sse)},
        {FUNCS_GCM(avx_gen2)}, /* AVX */
        {FUNCS_GCM(avx_gen4)} /* AVX2 */
};

enum cache_type_e cache_type = WARM;
/* As enum: SHA1, SHA224, SHA256, SHA384, SHA512,
   XCBC, MD5, NULL, GMAC, CUSTOM, CCM, CMAC */
const uint32_t auth_tag_length_bytes[12] = {
        12, 14, 16, 24, 32, 12, 12, 0, 8, 0, 16, 16
};
uint8_t *buf = NULL;
uint32_t index_limit;
uint128_t *keys = NULL;
uint64_t *offset_ptr = NULL;
uint32_t key_idxs[NUM_OFFSETS];
uint32_t offsets[NUM_OFFSETS];
int sha_size_incr = 24;

uint8_t archs[NUM_ARCHS] = {1, 1, 1, 1}; /* uses all function sets */
/* AES, DOCSIS, GCM, CCM, DES, 3DES */
uint8_t test_types[NUM_TYPES] = {1, 1, 1, 1, 1, 1};

int use_gcm_job_api = 0;
uint64_t core_mask = 0; /* bitmap of selected cores */

/* Those inline functions run different types of ipsec_mb library functions.
 * They run different functions depending on the chosen architecture
 */
__forceinline void init_mb_mgr(MB_MGR *mgr, uint32_t arch)
{
        func_sets[arch].init_mb_mgr(mgr);
}

__forceinline JOB_AES_HMAC *get_next_job(MB_MGR *mgr, const uint32_t arch)
{
        return func_sets[arch].get_next_job(mgr);
}

__forceinline JOB_AES_HMAC *submit_job(MB_MGR *mgr, const uint32_t arch)
{
        return func_sets[arch].submit_job(mgr);
}

__forceinline JOB_AES_HMAC *get_completed_job(MB_MGR *mgr, const uint32_t arch)
{
        return func_sets[arch].get_completed_job(mgr);
}

__forceinline JOB_AES_HMAC *flush_job(MB_MGR *mgr, const uint32_t arch)
{
        return func_sets[arch].flush_job(mgr);
}

/* GCM functions take also key size argument (128, 192, 256bit) */
__forceinline void aesni_gcm_pre(const uint32_t arch, const uint8_t key_sz,
                                 uint8_t *key, struct gcm_key_data *gdata)
{
        func_sets_gcm[arch][key_sz].aesni_gcm_pre(key, gdata);
}

__forceinline void aesni_gcm_enc(const uint32_t arch, const uint8_t key_sz,
                                 const struct gcm_key_data *gdata,
                                 struct gcm_context_data *ctx,
                                 uint8_t *out, uint8_t const *in,
                                 uint64_t len, uint8_t *iv,
                                 uint8_t const *aad, uint64_t aad_len,
                                 uint8_t *auth_tag, uint64_t auth_tag_len)
{
        func_sets_gcm[arch][key_sz].aesni_gcm_enc(gdata, ctx, out, in, len, iv,
                                                  aad, aad_len,
                                                  auth_tag, auth_tag_len);

}

__forceinline void aesni_gcm_dec(const uint32_t arch, const uint8_t key_sz,
                                 const struct gcm_key_data *gdata,
                                 struct gcm_context_data *ctx,
                                 uint8_t *out, uint8_t const *in,
                                 uint64_t len, uint8_t *iv,
                                 uint8_t const *aad, uint64_t aad_len,
                                 uint8_t *auth_tag, uint64_t auth_tag_len)
{
        func_sets_gcm[arch][key_sz].aesni_gcm_dec(gdata, ctx, out, in, len, iv,
                                                  aad, aad_len,
                                                  auth_tag, auth_tag_len);

}

/* Get number of bits set in value */
static int bitcount(const uint64_t val)
{
        unsigned i;
        int bits = 0;

        for (i = 0; i < BITS(val); i++)
                if (val & (1ULL << i))
                        bits++;

        return bits;
}

/* Get the next core in core mask
   Set last_core to negative to start from beginnig of core_mask */
static int next_core(const uint64_t core_mask,
                     const int last_core)
{
        int core = 0;

        if (last_core >= 0)
                core = last_core;

        while (((core_mask >> core) & 1) == 0) {
                core++;

                if (core >= (int)BITS(core_mask))
                        return -1;
        }

        return core;
}

/* Set CPU affinity for current thread */
static int set_affinity(const int cpu)
{
        int ret = 0;
#ifndef _WIN32
        cpu_set_t cpuset;
        int num_cpus = 0;

        /* Get number of cpus in the system */
        num_cpus = sysconf(_SC_NPROCESSORS_CONF);
        if (num_cpus == 0) {
                fprintf(stderr, "Zero processors in the system!");
                return 1;
        }

        /* Check if selected core is valid */
        if (cpu < 0 || cpu >= num_cpus) {
                fprintf(stderr, "Invalid CPU selected! "
                        "Max valid CPU is %u\n", num_cpus - 1);
                return 1;
        }

        CPU_ZERO(&cpuset);
        CPU_SET(cpu, &cpuset);

        /* Set affinity of current process to cpu */
        ret = sched_setaffinity(0, sizeof(cpuset), &cpuset);
#endif /* _WIN32 */

        return ret;
}

/* Freeing allocated memory */
static void free_mem(void)
{
        if (offset_ptr != NULL)
                free(offset_ptr);
        if (buf != NULL)
                free(buf);
}

/* Input buffer initialization */
static void init_buf(enum cache_type_e ctype)
{
        uint32_t tmp_off;
        uint64_t offset;
        int i;

        buf = (uint8_t *) malloc(BUFSIZE + REGION_SIZE);
        if (!buf) {
                fprintf(stderr, "Could not malloc buf\n");
                exit(EXIT_FAILURE);
        }

        offset_ptr = (uint64_t *)
                malloc(NUM_OFFSETS * KEYS_PER_JOB * sizeof(uint128_t) + 0x0F);
        if (!offset_ptr) {
                fprintf(stderr, "Could not malloc keys\n");
                free_mem();
                exit(EXIT_FAILURE);
        }

        offset = (uint64_t) offset_ptr;
        keys = (uint128_t *) ((offset + 0x0F) & ~0x0F); /* align to 16 bytes */

        if (ctype == COLD) {
                for (i = 0; i < NUM_OFFSETS; i++) {
                        offsets[i] = i * REGION_SIZE + (rand() & 0x3F0);
                        key_idxs[i] = i * KEYS_PER_JOB;
                }
                for (i = NUM_OFFSETS - 1; i >= 0; i--) {
                        offset = rand();
                        offset *= i;
                        offset /= RAND_MAX;
                        tmp_off = offsets[offset];
                        offsets[offset] = offsets[i];
                        offsets[i] = tmp_off;
                        tmp_off = key_idxs[offset];
                        key_idxs[offset] = key_idxs[i];
                        key_idxs[i] = tmp_off;
                }
                index_limit = NUM_OFFSETS;
        } else {/* WARM */
                for (i = 0; i < NUM_OFFSETS; i += 2) {
                        offsets[i]   = (2 * i + 0) * REGION_SIZE +
                                (rand() & 0x3F0);
                        offsets[i + 1] = (2 * i + 1) * REGION_SIZE +
                                (rand() & 0x3F0);
                        key_idxs[i]  = (2 * i + 0) * KEYS_PER_JOB;
                }
                index_limit = 8;
        }
}

/* This function translates enum test_ciper_mode_e to be used by ipsec_mb
 * library
 */
static JOB_CIPHER_MODE translate_cipher_mode(enum test_cipher_mode_e test_mode)
{
        JOB_CIPHER_MODE c_mode = NULL_CIPHER;

        switch (test_mode) {
        case TEST_CBC:
                c_mode = CBC;
                break;
        case TEST_CNTR:
        case TEST_CNTR8:
                c_mode = CNTR;
                break;
        case TEST_NULL_CIPHER:
                c_mode = NULL_CIPHER;
                break;
        case TEST_AESDOCSIS:
        case TEST_AESDOCSIS8:
                c_mode = DOCSIS_SEC_BPI;
                break;
        case TEST_DESDOCSIS:
        case TEST_DESDOCSIS4:
                c_mode = DOCSIS_DES;
                break;
        case TEST_GCM:
                c_mode = GCM;
                break;
        case TEST_CCM:
                c_mode = CCM;
                break;
        case TEST_DES:
                c_mode = DES;
                break;
        case TEST_3DES:
                c_mode = DES3;
                break;
        default:
                break;
        }
        return c_mode;
}

/* Performs test using AES_HMAC or DOCSIS */
static uint64_t
do_test(const uint32_t arch, MB_MGR *mb_mgr, struct params_s *params,
        const uint32_t num_iter)
{
        JOB_AES_HMAC *job;
        JOB_AES_HMAC job_template;
        uint32_t i;
        static uint32_t index = 0;
        static DECLARE_ALIGNED(uint128_t iv, 16);
        static uint32_t ipad[5], opad[5], digest[3];
        static DECLARE_ALIGNED(uint32_t k1_expanded[11 * 4], 16);
        static DECLARE_ALIGNED(uint8_t	k2[16], 16);
        static DECLARE_ALIGNED(uint8_t	k3[16], 16);
        static DECLARE_ALIGNED(struct gcm_key_data gdata_key, 16);
        uint32_t size_aes;
        uint64_t time = 0;
        uint32_t aux;

        if ((params->cipher_mode == TEST_AESDOCSIS8) ||
            (params->cipher_mode == TEST_CNTR8))
                size_aes = params->size_aes + 8;
        else if (params->cipher_mode == TEST_DESDOCSIS4)
                size_aes = params->size_aes + 4;
        else
                size_aes = params->size_aes;

        job_template.msg_len_to_cipher_in_bytes = size_aes;
        job_template.msg_len_to_hash_in_bytes = size_aes + sha_size_incr;
        job_template.hash_start_src_offset_in_bytes = 0;
        job_template.cipher_start_src_offset_in_bytes = sha_size_incr;
        job_template.iv = (uint8_t *) &iv;
        job_template.iv_len_in_bytes = 16;

        job_template.auth_tag_output = (uint8_t *) digest;

        switch (params->hash_alg) {
        case TEST_XCBC:
                job_template._k1_expanded = k1_expanded;
                job_template._k2 = k2;
                job_template._k3 = k3;
                job_template.hash_alg = AES_XCBC;
                break;
        case TEST_HASH_CCM:
                job_template.hash_alg = AES_CCM;
                break;
        case TEST_HASH_GCM:
                job_template.hash_alg = AES_GMAC;
                break;
        case TEST_NULL_HASH:
                job_template.hash_alg = NULL_HASH;
                break;
        case TEST_HASH_CMAC:
                job_template.u.CMAC._key_expanded = k1_expanded;
                job_template.u.CMAC._skey1 = k2;
                job_template.u.CMAC._skey2 = k3;
                job_template.hash_alg = AES_CMAC;
                break;
        default:
                /* HMAC hash alg is SHA1 or MD5 */
                job_template.hashed_auth_key_xor_ipad = (uint8_t *) ipad;
                job_template.hashed_auth_key_xor_opad = (uint8_t *) opad;
                job_template.hash_alg = (JOB_HASH_ALG) params->hash_alg;
                break;
        }
        job_template.auth_tag_output_len_in_bytes =
                (uint64_t) auth_tag_length_bytes[job_template.hash_alg - 1];

        job_template.cipher_direction = params->cipher_dir;

        if (params->cipher_mode == TEST_NULL_CIPHER) {
                job_template.chain_order = HASH_CIPHER;
        } else {
                if (job_template.cipher_direction == ENCRYPT)
                        job_template.chain_order = CIPHER_HASH;
                else
                        job_template.chain_order = HASH_CIPHER;
        }

        /* Translating enum to the API's one */
        job_template.cipher_mode = translate_cipher_mode(params->cipher_mode);
        job_template.aes_key_len_in_bytes = params->aes_key_size;
        if (job_template.cipher_mode == GCM) {
                uint8_t key[32];

                aesni_gcm_pre(arch, (params->aes_key_size / 8) - 2,
                              key, &gdata_key);
                job_template.aes_enc_key_expanded = &gdata_key;
                job_template.aes_dec_key_expanded = &gdata_key;
                job_template.u.GCM.aad_len_in_bytes = 12;
                job_template.iv_len_in_bytes = 12;
        } else if (job_template.cipher_mode == CCM) {
                job_template.msg_len_to_cipher_in_bytes = size_aes;
                job_template.msg_len_to_hash_in_bytes = size_aes;
                job_template.hash_start_src_offset_in_bytes = 0;
                job_template.cipher_start_src_offset_in_bytes = 0;
                job_template.u.CCM.aad_len_in_bytes = 8;
                job_template.iv_len_in_bytes = 13;
        } else if (job_template.cipher_mode == DES ||
                   job_template.cipher_mode == DES3 ||
                   job_template.cipher_mode == DOCSIS_DES) {
                job_template.aes_key_len_in_bytes = 8;
                job_template.iv_len_in_bytes = 8;
        }

        time = __rdtscp(&aux);
        for (i = 0; i < num_iter; i++) {
                job = get_next_job(mb_mgr, arch);
                *job = job_template;

                job->src = buf + offsets[index];
                job->dst = buf + offsets[index] + sha_size_incr;
                if (job->cipher_mode == GCM) {
                        job->u.GCM.aad = job->src;
                } else if (job->cipher_mode == CCM) {
                        job->u.CCM.aad = job->src;
                        job->aes_enc_key_expanded = job->aes_dec_key_expanded =
                                (uint32_t *) &keys[key_idxs[index]];
                } else if (job->cipher_mode == DES3) {
                        static const void *ks_ptr[3];

                        ks_ptr[0] = ks_ptr[1] = ks_ptr[2] =
                                &keys[key_idxs[index]];
                        job->aes_enc_key_expanded =
                                job->aes_dec_key_expanded = ks_ptr;
                } else {
                        job->aes_enc_key_expanded = job->aes_dec_key_expanded =
                                (uint32_t *) &keys[key_idxs[index]];
                }

                index += 2;
                if (index >= index_limit)
                        index = 0;

                job = submit_job(mb_mgr, arch);
                while (job) {
#ifdef DEBUG
                        if (job->status != STS_COMPLETED)
                                fprintf(stderr, "failed job, status:%d\n",
                                        job->status);
#endif
                        job = get_completed_job(mb_mgr, arch);
                }
        }

        while ((job = flush_job(mb_mgr, arch))) {
#ifdef DEBUG
                if (job->status != STS_COMPLETED)
                        fprintf(stderr, "failed job, status:%d\n", job->status);
#endif
        }

        time = __rdtscp(&aux) - time;
        return time / num_iter;
}

/* Performs test using GCM */
static uint64_t
do_test_gcm(const uint32_t arch, struct params_s *params,
            const uint32_t num_iter)
{
        struct gcm_key_data gdata_key;
        struct gcm_context_data gdata_ctx;
        uint8_t *key;
        static uint32_t index = 0;
        uint8_t key_sz = params->aes_key_size / 8 - 2;
        uint32_t size_aes = params->size_aes;
        uint32_t i;
        uint8_t aad[12];
        uint8_t auth_tag[12];
        DECLARE_ALIGNED(uint8_t iv[16], 16);
        uint64_t time = 0;
        uint32_t aux;

        key = (uint8_t *) malloc(sizeof(uint8_t) * params->aes_key_size);
        if (!key) {
                fprintf(stderr, "Could not malloc key\n");
                free_mem();
                exit(EXIT_FAILURE);
        }

        aesni_gcm_pre(arch, key_sz, key, &gdata_key);
        if (params->cipher_dir == ENCRYPT) {
                time = __rdtscp(&aux);
                for (i = 0; i < num_iter; i++) {
                        aesni_gcm_enc(arch, key_sz, &gdata_key, &gdata_ctx,
                                      buf + offsets[index] + sha_size_incr,
                                      buf + offsets[index] + sha_size_incr,
                                      size_aes, iv, aad, sizeof(aad),
                                      auth_tag, sizeof(auth_tag));
                        index += 2;
                        if (index >= index_limit)
                                index = 0;
                }
                time = __rdtscp(&aux) - time;
        } else { /*DECRYPT*/
                time = __rdtscp(&aux);
                for (i = 0; i < num_iter; i++) {
                        aesni_gcm_dec(arch, key_sz, &gdata_key, &gdata_ctx,
                                      buf + offsets[index] + sha_size_incr,
                                      buf + offsets[index] + sha_size_incr,
                                      size_aes, iv, aad, sizeof(aad),
                                      auth_tag, sizeof(auth_tag));
                        index += 2;
                        if (index >= index_limit)
                                index = 0;
                }
                time = __rdtscp(&aux) - time;
        }

        free(key);
        return time / num_iter;
}


/* Method used by qsort to compare 2 values */
static int compare_uint64_t(const void *a, const void *b)
{
        return (int)(int64_t)(*(const uint64_t *)a - *(const uint64_t *)b);
}

/* Computes mean of set of times after dropping bottom and top quarters */
static uint64_t mean_median(uint64_t *array, uint32_t size)
{
        uint32_t quarter = size / 4;
        uint32_t i;
        uint64_t sum;

        /* these are single threaded runs, so we skip
         * the hardware thread related skew clipping
         * thus skipping "ignore first and last eighth"
         */

        /* ignore lowest and highest quarter */
        qsort(array, size, sizeof(uint64_t), compare_uint64_t);

        /* dropping the bottom and top quarters
         * after sorting to remove noise/variations
         */
        array += quarter;
        size -= quarter * 2;


        if ((size == 0) || (size & 0x80000000)) {
                fprintf(stderr, "not enough data points\n");
                free_mem();
                exit(EXIT_FAILURE);
        }
        sum = 0;
        for (i = 0; i < size; i++)
                sum += array[i];

        sum = (sum + size / 2) / size;
        return sum;
}

/* Runs test for each buffer size and stores averaged execution time */
static void
process_variant(MB_MGR *mgr, const uint32_t arch, struct params_s *params,
                struct variant_s *variant_ptr, const uint32_t run)
{
        const uint32_t sizes = params->num_sizes;
        uint64_t *times = &variant_ptr->avg_times[run];
        uint32_t sz;

        for (sz = 0; sz < sizes; sz++) {
                const uint32_t size_aes = (sz + 1) * JOB_SIZE_STEP;
                const uint32_t num_iter = ITER_SCALE / size_aes;

                params->size_aes = size_aes;
                if (params->test_type == TTYPE_AES_GCM && (!use_gcm_job_api))
                        *times = do_test_gcm(arch, params, 2 * num_iter);
                else
                        *times = do_test(arch, mgr, params, num_iter);
                times += NUM_RUNS;
        }

        variant_ptr->params = *params;
        variant_ptr->arch = arch;
}

/* Sets cipher mode, hash algorithm */
static void
do_variants(MB_MGR *mgr, const uint32_t arch, struct params_s *params,
            const uint32_t run, struct variant_s **variant_ptr,
            uint32_t *variant)
{
        uint32_t hash_alg;
        uint32_t h_start = TEST_SHA1;
        uint32_t h_end = TEST_NULL_HASH;
        uint32_t c_mode;
        uint32_t c_start = TEST_CBC;
        uint32_t c_end = TEST_NULL_CIPHER;

        switch (params->test_type) {
        case TTYPE_AES_DOCSIS:
                h_start = TEST_NULL_HASH;
                c_start = TEST_AESDOCSIS;
                c_end = TEST_DESDOCSIS4;
                break;
        case TTYPE_AES_GCM:
                h_start = TEST_HASH_GCM;
                h_end = TEST_HASH_GCM;
                c_start = TEST_GCM;
                c_end = TEST_GCM;
                break;
        case TTYPE_AES_CCM:
                h_start = TEST_HASH_CCM;
                h_end = TEST_HASH_CCM;
                c_start = TEST_CCM;
                c_end = TEST_CCM;
                break;
        case TTYPE_AES_DES:
                h_start = TEST_NULL_HASH;
                h_end = TEST_NULL_HASH;
                c_start = TEST_DES;
                c_end = TEST_DES;
                break;
        case TTYPE_AES_3DES:
                h_start = TEST_NULL_HASH;
                h_end = TEST_NULL_HASH;
                c_start = TEST_3DES;
                c_end = TEST_3DES;
                break;
        default:
                break;
        }

        for (c_mode = c_start; c_mode <= c_end; c_mode++) {
                params->cipher_mode = (enum test_cipher_mode_e) c_mode;
                for (hash_alg = h_start; hash_alg <= h_end; hash_alg++) {
                        params->hash_alg = (enum test_hash_alg_e) hash_alg;
                        process_variant(mgr, arch, params, *variant_ptr, run);
                        (*variant)++;
                        (*variant_ptr)++;
                }
        }
}

/* Sets cipher direction and key size  */
static void
run_dir_test(MB_MGR *mgr, const uint32_t arch, struct params_s *params,
             const uint32_t run, struct variant_s **variant_ptr,
             uint32_t *variant)
{
        uint32_t dir;
        uint32_t k; /* Key size */
        uint32_t limit = AES_256_BYTES; /* Key size value limit */

        if (params->test_type == TTYPE_AES_DOCSIS ||
            params->test_type == TTYPE_AES_DES ||
            params->test_type == TTYPE_AES_3DES ||
            params->test_type == TTYPE_AES_CCM)
                limit = AES_128_BYTES;

        init_mb_mgr(mgr, arch);

        for (dir = ENCRYPT; dir <= DECRYPT; dir++) {
                params->cipher_dir = (JOB_CIPHER_DIRECTION) dir;
                for (k = AES_128_BYTES; k <= limit; k += 8) {
                        params->aes_key_size = k;
                        do_variants(mgr, arch, params, run, variant_ptr,
                                    variant);
                }
        }
}

/* Generates output containing averaged times for each test variant */
static void print_times(struct variant_s *variant_list, struct params_s *params,
                        const uint32_t total_variants)
{
        const uint32_t sizes = params->num_sizes;
        uint32_t col;
        uint32_t sz;

        /* Temporary variables */
        struct params_s par;
        uint8_t	c_mode;
        uint8_t c_dir;
        uint8_t h_alg;
        const char *func_names[4] = {
                "SSE", "AVX", "AVX2", "AVX512"
        };
        const char *c_mode_names[12] = {
                "CBC", "CNTR", "CNTR+8", "NULL_CIPHER", "DOCAES", "DOCAES+8",
                "DOCDES", "DOCDES+4", "GCM", "CCM", "DES", "3DES"
        };
        const char *c_dir_names[2] = {
                "ENCRYPT", "DECRYPT"
        };
        const char *h_alg_names[12] = {
                "SHA1", "SHA_224", "SHA_256", "SHA_384", "SHA_512", "XCBC",
                "MD5", "CMAC", "NULL_HASH", "GCM", "CUSTOM", "CCM"
        };
        printf("ARCH");
        for (col = 0; col < total_variants; col++)
                printf("\t%s", func_names[variant_list[col].arch]);
        printf("\n");
        printf("CIPHER");
        for (col = 0; col < total_variants; col++) {
                par = variant_list[col].params;
                c_mode = par.cipher_mode - CBC;
                printf("\t%s", c_mode_names[c_mode]);
        }
        printf("\n");
        printf("DIR");
        for (col = 0; col < total_variants; col++) {
                par = variant_list[col].params;
                c_dir = par.cipher_dir - ENCRYPT;
                printf("\t%s", c_dir_names[c_dir]);
        }
        printf("\n");
        printf("HASH_ALG");
        for (col = 0; col < total_variants; col++) {
                par = variant_list[col].params;
                h_alg = par.hash_alg - SHA1;
                printf("\t%s", h_alg_names[h_alg]);
        }
        printf("\n");
        printf("KEY_SIZE");
        for (col = 0; col < total_variants; col++) {
                par = variant_list[col].params;
                printf("\tAES-%u", par.aes_key_size * 8);
        }
        printf("\n");
        for (sz = 0; sz < sizes; sz++) {
                printf("%d", (sz + 1) * JOB_SIZE_STEP);
                for (col = 0; col < total_variants; col++) {
                        uint64_t *time_ptr =
                                &variant_list[col].avg_times[sz * NUM_RUNS];
                        const unsigned long long val =
                                mean_median(time_ptr, NUM_RUNS);

                        printf("\t%llu", val);
                }
                printf("\n");
        }
}

/* Prepares data structure for test variants storage, sets test configuration */
#ifdef _WIN32
static void
#else
static void *
#endif
run_tests(void *arg)
{
        uint32_t i;
        struct thread_info *info = (struct thread_info *)arg;
        MB_MGR mb_mgr;
        struct params_s params;
        uint32_t num_variants[NUM_TYPES] = {0, 0, 0};
        uint32_t type, at_size, run, arch;
        uint32_t variants_per_arch, max_arch;
        uint32_t variant;
        uint32_t total_variants = 0;
        struct variant_s *variant_ptr;
        struct variant_s *variant_list;

        params.num_sizes = JOB_SIZE / JOB_SIZE_STEP;

        /* if cores selected then set affinity */
        if (core_mask)
                if (set_affinity(info->core) != 0) {
                        fprintf(stderr, "Failed to set cpu "
                                "affinity on core %d\n", info->core);
                        free_mem();
                        exit(EXIT_FAILURE);
                }

        for (type = TTYPE_AES_HMAC; type < NUM_TYPES; type++) {
                if (test_types[type] == 0)
                        continue;


                switch (type) {
                default:
                case TTYPE_AES_HMAC:
                        variants_per_arch = VARIANTS_PER_ARCH_AES;
                        max_arch = NUM_ARCHS;
                        break;
                case TTYPE_AES_DOCSIS:
                        variants_per_arch = VARIANTS_PER_ARCH_DOCSIS;
                        max_arch = NUM_ARCHS;
                        break;
                case TTYPE_AES_GCM:
                        variants_per_arch = VARIANTS_PER_ARCH_GCM;
                        max_arch = NUM_ARCHS - 1; /* No AVX512 for GCM */
                        break;
                case TTYPE_AES_CCM:
                        variants_per_arch = VARIANTS_PER_ARCH_CCM;
                        max_arch = NUM_ARCHS;
                        break;
                case TTYPE_AES_DES:
                        variants_per_arch = VARIANTS_PER_ARCH_DES;
                        max_arch = NUM_ARCHS;
                        break;
                case TTYPE_AES_3DES:
                        variants_per_arch = VARIANTS_PER_ARCH_3DES;
                        max_arch = NUM_ARCHS;
                        break;
                }

                /* Calculating number of all variants */
                for (arch = 0; arch < max_arch; arch++) {
                        if (archs[arch] == 0)
                                continue;
                        num_variants[type] += variants_per_arch;
                }
                total_variants += num_variants[type];
        }

        variant_list = (struct variant_s *)
                malloc(total_variants * sizeof(struct variant_s));
        if (!variant_list) {
                fprintf(stderr, "Cannot allocate memory\n");
                free_mem();
                exit(EXIT_FAILURE);
        }

        at_size = NUM_RUNS * params.num_sizes * sizeof(uint64_t);
        for (variant = 0, variant_ptr = variant_list;
             variant < total_variants;
             variant++, variant_ptr++) {
                variant_ptr->avg_times = (uint64_t *) malloc(at_size);
                if (!variant_ptr->avg_times) {
                        fprintf(stderr, "Cannot allocate memory\n");
                        free_mem();
                        exit(EXIT_FAILURE);
                }
        }
        for (run = 0; run < NUM_RUNS; run++) {
                fprintf(stderr, "Starting run %d of %d\n", run+1, NUM_RUNS);

                variant = 0;
                variant_ptr = variant_list;

                for (type = TTYPE_AES_HMAC; type < NUM_TYPES; type++) {
                        if (test_types[type] == 0)
                                continue;

                        if (type == TTYPE_AES_GCM)
                                /* No AVX512 for GCM */
                                max_arch = NUM_ARCHS - 1;
                        else
                                max_arch = NUM_ARCHS;

                        params.num_variants = num_variants[type];
                        params.test_type = type;
                        /* Performing tests for each selected architecture */
                        for (arch = 0; arch < max_arch; arch++) {
                                if (archs[arch] == 0)
                                        continue;
                                run_dir_test(&mb_mgr, arch, &params, run,
                                             &variant_ptr, &variant);
                        }
                } /* end for type */
        } /* end for run */
        if (info->print_info == 1)
                print_times(variant_list, &params, total_variants);

        if (variant_list != NULL) {
                /* Freeing variants list */
                for (i = 0; i < total_variants; i++)
                        free(variant_list[i].avg_times);
                free(variant_list);
        }
#ifndef _WIN32
        return NULL;
#endif
}

static void usage(void)
{
        fprintf(stderr, "Usage: ipsec_perf [args], "
                "where args are zero or more\n"
                "-h: print this message\n"
                "-c: Use cold cache, it uses warm as default\n"
                "-w: Use warm cache\n"
                "--no-avx512: Don't do AVX512\n"
                "--no-avx2: Don't do AVX2\n"
                "--no-avx: Don't do AVX\n"
                "--no-sse: Don't do SSE\n"
                "-o val: Use <val> for the SHA size increment, default is 24\n"
                "--shani-on: use SHA extensions, default: auto-detect\n"
                "--shani-off: don't use SHA extensions\n"
                "--no-gcm: do not run GCM perf tests\n"
                "--no-aes: do not run standard AES + HMAC perf tests\n"
                "--no-docsis: do not run DOCSIS cipher perf tests\n"
                "--no-ccm: do not run CCM cipher perf tests\n"
                "--no-des: do not run DES cipher perf tests\n"
                "--no-3des: do not run 3DES cipher perf tests\n"
                "--gcm-job-api: use JOB API for GCM perf tests"
                " (raw GCM API is default)\n"
                "--threads num: <num> for the number of threads to run"
                " Max: %d\n"
                "--cores mask: <mask> CPU's to run threads.\n",
                MAX_NUM_THREADS + 1);
}

int main(int argc, char *argv[])
{
        MB_MGR lmgr;
        int i, num_t = 0, core = 0;
        struct thread_info *thread_info_p = t_info;

#ifdef _WIN32
        HANDLE threads[MAX_NUM_THREADS];
#else
        pthread_t tids[MAX_NUM_THREADS];
#endif

        for (i = 1; i < argc; i++)
                if (strcmp(argv[i], "-h") == 0) {
                        usage();
                        return EXIT_SUCCESS;
                } else if (strcmp(argv[i], "-c") == 0) {
                        cache_type = COLD;
                        fprintf(stderr, "Cold cache, ");
                } else if (strcmp(argv[i], "-w") == 0) {
                        cache_type = WARM;
                        fprintf(stderr, "Warm cache, ");
                } else if (strcmp(argv[i], "--no-avx512") == 0) {
                        archs[ARCH_AVX512] = 0;
                } else if (strcmp(argv[i], "--no-avx2") == 0) {
                        archs[ARCH_AVX2] = 0;
                } else if (strcmp(argv[i], "--no-avx") == 0) {
                        archs[ARCH_AVX] = 0;
                } else if (strcmp(argv[i], "--no-sse") == 0) {
                        archs[ARCH_SSE] = 0;
                } else if (strcmp(argv[i], "--shani-on") == 0) {
                        sse_sha_ext_usage = SHA_EXT_PRESENT;
                } else if (strcmp(argv[i], "--shani-off") == 0) {
                        sse_sha_ext_usage = SHA_EXT_NOT_PRESENT;
                } else if (strcmp(argv[i], "--no-gcm") == 0) {
                        test_types[TTYPE_AES_GCM] = 0;
                } else if (strcmp(argv[i], "--no-aes") == 0) {
                        test_types[TTYPE_AES_HMAC] = 0;
                } else if (strcmp(argv[i], "--no-docsis") == 0) {
                        test_types[TTYPE_AES_DOCSIS] = 0;
                } else if (strcmp(argv[i], "--no-ccm") == 0) {
                        test_types[TTYPE_AES_CCM] = 0;
                } else if (strcmp(argv[i], "--no-des") == 0) {
                        test_types[TTYPE_AES_DES] = 0;
                } else if (strcmp(argv[i], "--no-3des") == 0) {
                        test_types[TTYPE_AES_3DES] = 0;
                } else if (strcmp(argv[i], "--gcm-job-api") == 0) {
                        use_gcm_job_api = 1;
                } else if ((strcmp(argv[i], "-o") == 0) && (i < argc - 1)) {
                        i++;
                        sha_size_incr = atoi(argv[i]);
                } else if (strcmp(argv[i], "--threads") == 0) {
                        num_t = atoi(argv[++i]);
                        if (num_t > (MAX_NUM_THREADS + 1)) {
                                fprintf(stderr, "Invalid number of threads!\n");
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--cores") == 0) {
                        errno = 0;
                        core_mask = strtoull(argv[++i], NULL, 0);
                        if (errno != 0) {
                                fprintf(stderr, "Error converting cpu mask!\n");
                                return EXIT_FAILURE;
                        }
                } else {
                        usage();
                        return EXIT_FAILURE;
                }

        /* Check num cores >= number of threads */
        if ((core_mask != 0 && num_t != 0) && (num_t > bitcount(core_mask))) {
                fprintf(stderr, "Insufficient number of cores in "
                        "core mask (0x%lx) to run %d threads!\n",
                        (unsigned long) core_mask, num_t);
                return EXIT_FAILURE;
        }

        fprintf(stderr, "SHA size incr = %d\n", sha_size_incr);
        init_mb_mgr_sse(&lmgr);
        if (archs[ARCH_SSE]) {
                fprintf(stderr, "%s SHA extensions (shani) for SSE arch\n",
                        (sse_sha_ext_usage == SHA_EXT_PRESENT) ?
                        "Using" : "Not using");
        }

        memset(t_info, 0, sizeof(t_info));
        init_buf(cache_type);
        if (num_t > 1)
                for (i = 0; i < num_t - 1; i++, thread_info_p++) {
                        /* Set core if selected */
                        if (core_mask) {
                                core = next_core(core_mask, core);
                                thread_info_p->core = core++;
                        }
#ifdef _WIN32
                        threads[i] = (HANDLE)
                                _beginthread(&run_tests, 0,
                                             (void *)thread_info_p);
#else
                        pthread_attr_t attr;

                        pthread_attr_init(&attr);
                        pthread_create(&tids[i], &attr, run_tests,
                                       (void *)thread_info_p);
#endif
                }

        thread_info_p->print_info = 1;
        if (core_mask) {
                core = next_core(core_mask, core);
                thread_info_p->core = core;
        }

        run_tests((void *)thread_info_p);
        if (num_t > 1) {
#ifdef _WIN32
                WaitForMultipleObjects(num_t, threads, FALSE, INFINITE);
#endif
                for (i = 0; i < num_t - 1; i++) {
                        fprintf(stderr, "Waiting on thread %d to finish...\n",
                                i+2);
#ifdef _WIN32
                        CloseHandle(threads[i]);
#else
                        pthread_join(tids[i], NULL);
#endif
                }
        }
        free_mem();

        return EXIT_SUCCESS;
}
