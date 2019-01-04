/**********************************************************************
  Copyright(c) 2017-2019, Intel Corporation All rights reserved.

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
#include <malloc.h> /* memalign() or _aligned_malloc()/aligned_free() */

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

#include <intel-ipsec-mb.h>

#include "msr.h"

#define BUFSIZE (512 * 1024 * 1024)
#define JOB_SIZE_MAX (2 * 1024)
#define JOB_SIZE_STEP 16
#define REGION_SIZE (JOB_SIZE_MAX + 2048)
#define NUM_OFFSETS (BUFSIZE / REGION_SIZE)
#define NUM_RUNS 16
#define KEYS_PER_JOB 15

#define ITER_SCALE_SMOKE 2048
#define ITER_SCALE_SHORT 200000
#define ITER_SCALE_LONG  2000000

#define BITS(x) (sizeof(x) * 8)
#define DIM(x) (sizeof(x)/sizeof(x[0]))

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

#define IA32_MSR_FIXED_CTR_CTRL      0x38D
#define IA32_MSR_PERF_GLOBAL_CTR     0x38F
#define IA32_MSR_CPU_UNHALTED_THREAD 0x30A

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

enum arch_type_e {
        ARCH_SSE = 0,
        ARCH_AVX,
        ARCH_AVX2,
        ARCH_AVX512,
        NUM_ARCHS
};

const char *arch_strings[NUM_ARCHS] = {
        "SSE",
        "AVX",
        "AVX2",
        "AVX512"
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
        uint32_t                core;
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
        MB_MGR *p_mgr;
} t_info[MAX_NUM_THREADS];

enum cache_type_e {
        WARM = 0,
        COLD = 1
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
uint32_t sha_size_incr = 24;

uint32_t job_size_start = 0;
uint32_t job_iter = 0;

uint8_t archs[NUM_ARCHS] = {1, 1, 1, 1}; /* uses all function sets */
/* AES, DOCSIS, GCM, CCM, DES, 3DES */
uint8_t test_types[NUM_TYPES] = {1, 1, 1, 1, 1, 1};

int use_gcm_job_api = 0;
int use_unhalted_cycles = 0; /* read unhalted cycles instead of tsc */
uint64_t rd_cycles_cost = 0; /* cost of reading unhalted cycles */
uint64_t core_mask = 0; /* bitmap of selected cores */

uint64_t flags = 0; /* flags passed to alloc_mb_mgr() */

uint32_t iter_scale = ITER_SCALE_LONG;

/* Read unhalted cycles */
__forceinline uint64_t read_cycles(uint32_t core)
{
        uint64_t val = 0;

        if (msr_read(core, IA32_MSR_CPU_UNHALTED_THREAD,
                     &val) != MACHINE_RETVAL_OK) {
                fprintf(stderr, "Error reading cycles "
                        "counter on core %u!\n", core);
                exit(EXIT_FAILURE);
        }

        return val;
}

/* Method used by qsort to compare 2 values */
static int compare_uint64_t(const void *a, const void *b)
{
        return (int)(int64_t)(*(const uint64_t *)a - *(const uint64_t *)b);
}

/* Get number of bits set in value */
static unsigned bitcount(const uint64_t val)
{
        unsigned i, bits = 0;

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
        int num_cpus = 0;

        /* Get number of cpus in the system */
#ifdef _WIN32
        GROUP_AFFINITY NewGroupAffinity;

        memset(&NewGroupAffinity, 0, sizeof(GROUP_AFFINITY));
        num_cpus = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
#else
        num_cpus = sysconf(_SC_NPROCESSORS_CONF);
#endif
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

#ifdef _WIN32
        NewGroupAffinity.Mask = 1ULL << cpu;
        ret = !SetThreadGroupAffinity(GetCurrentThread(),
                                      &NewGroupAffinity, NULL);
#else
        cpu_set_t cpuset;

        CPU_ZERO(&cpuset);
        CPU_SET(cpu, &cpuset);

        /* Set affinity of current process to cpu */
        ret = sched_setaffinity(0, sizeof(cpuset), &cpuset);
#endif /* _WIN32 */

        return ret;
}

/* Start counting unhalted cycles */
static int start_cycles_ctr(uint32_t core)
{
        int ret;

        if (core >= BITS(core_mask))
                return 1;

        /* Disable cycles counter */
        ret = msr_write(core, IA32_MSR_PERF_GLOBAL_CTR, 0);
        if (ret != MACHINE_RETVAL_OK)
                return ret;

        /* Zero cycles counter */
        ret = msr_write(core, IA32_MSR_CPU_UNHALTED_THREAD, 0);
        if (ret != MACHINE_RETVAL_OK)
                return ret;

        /* Enable OS and user tracking in FixedCtr1 */
        ret = msr_write(core, IA32_MSR_FIXED_CTR_CTRL, 0x30);
        if (ret != MACHINE_RETVAL_OK)
                return ret;

        /* Enable cycles counter */
        return  msr_write(core, IA32_MSR_PERF_GLOBAL_CTR, (1ULL << 33));
}

/* Init MSR module */
static int init_msr_mod(void)
{
        unsigned max_core_count = 0;
#ifdef _WIN32
        max_core_count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
#else
        max_core_count = sysconf(_SC_NPROCESSORS_CONF);
#endif
        if (max_core_count == 0) {
                fprintf(stderr, "Zero processors in the system!");
                return MACHINE_RETVAL_ERROR;
        }

        return machine_init(max_core_count);
}

/* Set the cost of reading unhalted cycles using RDMSR */
static int set_unhalted_cycle_cost(const int core, uint64_t *value)
{
        uint64_t time1, time2;

        if (value == NULL || core < 0)
                return 1;

        time1 = read_cycles(core);
        time2 = read_cycles(core);

        /* Calculate delta */
        *value = (time2 - time1);

        return 0;
}

/* Calculate the general cost of reading unhalted cycles (median) */
static int set_avg_unhalted_cycle_cost(const int core, uint64_t *value)
{
        unsigned i;
        uint64_t cycles[10];

        if (value == NULL || core_mask == 0 || core < 0)
                return 1;

        /* Fill cycles table with read cost values */
        for (i = 0; i < DIM(cycles); i++)
                if (set_unhalted_cycle_cost(core, &cycles[i]) != 0)
                        return 1;

        /* sort array */
        qsort(cycles, DIM(cycles), sizeof(uint64_t), compare_uint64_t);

        /* set median cost */
        *value = cycles[DIM(cycles)/2];

        return 0;
}

/* Freeing allocated memory */
static void free_mem(void)
{
#ifdef LINUX
        if (offset_ptr != NULL)
                free(offset_ptr);

        if (buf != NULL)
                free(buf);
#else
        if (offset_ptr != NULL)
                _aligned_free(offset_ptr);

        if (buf != NULL)
                _aligned_free(buf);
#endif
}

/* Input buffer initialization */
static void init_buf(enum cache_type_e ctype)
{
        const size_t bufs_size = BUFSIZE + REGION_SIZE;
        const size_t keys_size = NUM_OFFSETS * KEYS_PER_JOB * sizeof(uint128_t);
        const size_t alignment = 64;
        uint32_t tmp_off;
        int i;

#ifdef LINUX
        buf = (uint8_t *) memalign(alignment, bufs_size);
#else
        buf = (uint8_t *) _aligned_malloc(bufs_size, alignment);
#endif
        if (!buf) {
                fprintf(stderr, "Could not malloc buf\n");
                exit(EXIT_FAILURE);
        }

#ifdef LINUX
        offset_ptr = (uint64_t *) memalign(alignment, keys_size);
#else
        offset_ptr = (uint64_t *) _aligned_malloc(keys_size, alignment);
#endif
        if (!offset_ptr) {
                fprintf(stderr, "Could not malloc keys\n");
                free_mem();
                exit(EXIT_FAILURE);
        }

        keys = (uint128_t *) offset_ptr;

        if (ctype == COLD) {
                for (i = 0; i < NUM_OFFSETS; i++) {
                        offsets[i] = i * REGION_SIZE + (rand() & 0x3C0);
                        key_idxs[i] = i * KEYS_PER_JOB;
                }
                for (i = NUM_OFFSETS - 1; i >= 0; i--) {
                        const uint64_t offset = (rand() * i) / RAND_MAX;

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
                                (rand() & 0x3C0);
                        offsets[i + 1] = (2 * i + 1) * REGION_SIZE +
                                (rand() & 0x3C0);
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
do_test(MB_MGR *mb_mgr, struct params_s *params,
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
        static DECLARE_ALIGNED(struct gcm_key_data gdata_key, 512);
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
                job_template.u.XCBC._k1_expanded = k1_expanded;
                job_template.u.XCBC._k2 = k2;
                job_template.u.XCBC._k3 = k3;
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
                job_template.u.HMAC._hashed_auth_key_xor_ipad =
                        (uint8_t *) ipad;
                job_template.u.HMAC._hashed_auth_key_xor_opad =
                        (uint8_t *) opad;
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

                switch (params->aes_key_size) {
                case AES_128_BYTES:
                        IMB_AES128_GCM_PRE(mb_mgr, key, &gdata_key);
                        break;
                case AES_192_BYTES:
                        IMB_AES192_GCM_PRE(mb_mgr, key, &gdata_key);
                        break;
                case AES_256_BYTES:
                default:
                        IMB_AES256_GCM_PRE(mb_mgr, key, &gdata_key);
                        break;
                }
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
                   job_template.cipher_mode == DOCSIS_DES) {
                job_template.aes_key_len_in_bytes = 8;
                job_template.iv_len_in_bytes = 8;
        } else if (job_template.cipher_mode == DES3) {
                job_template.aes_key_len_in_bytes = 24;
                job_template.iv_len_in_bytes = 8;
        }

#ifndef _WIN32
        if (use_unhalted_cycles)
                time = read_cycles(params->core);
        else
#endif
                time = __rdtscp(&aux);

        for (i = 0; i < num_iter; i++) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
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

#ifdef DEBUG
                job = IMB_SUBMIT_JOB(mb_mgr);
#else
                job = IMB_SUBMIT_JOB_NOCHECK(mb_mgr);
#endif
                while (job) {
#ifdef DEBUG
                        if (job->status != STS_COMPLETED)
                                fprintf(stderr, "failed job, status:%d\n",
                                        job->status);
#endif
                        job = IMB_GET_COMPLETED_JOB(mb_mgr);
                }
        }

        while ((job = IMB_FLUSH_JOB(mb_mgr))) {
#ifdef DEBUG
                if (job->status != STS_COMPLETED)
                        fprintf(stderr, "failed job, status:%d\n", job->status);
#endif
        }

#ifndef _WIN32
        if (use_unhalted_cycles)
                time = (read_cycles(params->core) - rd_cycles_cost) - time;
        else
#endif
                time = __rdtscp(&aux) - time;

        return time / num_iter;
}

/* Performs test using GCM */
static uint64_t
do_test_gcm(struct params_s *params,
            const uint32_t num_iter, MB_MGR *mb_mgr)
{
        static DECLARE_ALIGNED(struct gcm_key_data gdata_key, 512);
        static DECLARE_ALIGNED(struct gcm_context_data gdata_ctx, 64);
        uint8_t *key;
        static uint32_t index = 0;
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

        switch (params->aes_key_size) {
        case AES_128_BYTES:
                IMB_AES128_GCM_PRE(mb_mgr, key, &gdata_key);
                break;
        case AES_192_BYTES:
                IMB_AES192_GCM_PRE(mb_mgr, key, &gdata_key);
                break;
        case AES_256_BYTES:
        default:
                IMB_AES256_GCM_PRE(mb_mgr, key, &gdata_key);
                break;
        }

        if (params->cipher_dir == ENCRYPT) {
#ifndef _WIN32
                if (use_unhalted_cycles)
                        time = read_cycles(params->core);
                else
#endif
                        time = __rdtscp(&aux);

                if (params->aes_key_size == AES_128_BYTES) {
                        for (i = 0; i < num_iter; i++) {
                                IMB_AES128_GCM_ENC(mb_mgr, &gdata_key,
                                                   &gdata_ctx,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   size_aes, iv,
                                                   aad, sizeof(aad),
                                                   auth_tag, sizeof(auth_tag));
                                index += 2;
                                if (index >= index_limit)
                                        index = 0;
                        }
                } else if (params->aes_key_size == AES_192_BYTES) {
                        for (i = 0; i < num_iter; i++) {
                                IMB_AES192_GCM_ENC(mb_mgr, &gdata_key,
                                                   &gdata_ctx,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   size_aes, iv,
                                                   aad, sizeof(aad),
                                                   auth_tag, sizeof(auth_tag));
                                index += 2;
                                if (index >= index_limit)
                                        index = 0;
                        }
                } else { /* 256 */
                        for (i = 0; i < num_iter; i++) {
                                IMB_AES256_GCM_ENC(mb_mgr, &gdata_key,
                                                   &gdata_ctx,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   size_aes, iv,
                                                   aad, sizeof(aad),
                                                   auth_tag, sizeof(auth_tag));
                                index += 2;
                                if (index >= index_limit)
                                        index = 0;
                        }
                }
#ifndef _WIN32
                if (use_unhalted_cycles)
                        time = (read_cycles(params->core) -
                                rd_cycles_cost) - time;
                else
#endif
                        time = __rdtscp(&aux) - time;
        } else { /*DECRYPT*/
#ifndef _WIN32
                if (use_unhalted_cycles)
                        time = read_cycles(params->core);
                else
#endif
                        time = __rdtscp(&aux);

                if (params->aes_key_size == AES_128_BYTES) {
                        for (i = 0; i < num_iter; i++) {
                                IMB_AES128_GCM_DEC(mb_mgr, &gdata_key,
                                                   &gdata_ctx,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   size_aes, iv,
                                                   aad, sizeof(aad),
                                                   auth_tag, sizeof(auth_tag));
                                index += 2;
                                if (index >= index_limit)
                                        index = 0;
                        }
                } else if (params->aes_key_size == AES_192_BYTES) {
                        for (i = 0; i < num_iter; i++) {
                                IMB_AES192_GCM_DEC(mb_mgr, &gdata_key,
                                                   &gdata_ctx,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   size_aes, iv,
                                                   aad, sizeof(aad),
                                                   auth_tag, sizeof(auth_tag));
                                index += 2;
                                if (index >= index_limit)
                                        index = 0;
                        }
                } else { /* 256 */
                        for (i = 0; i < num_iter; i++) {
                                IMB_AES256_GCM_DEC(mb_mgr, &gdata_key,
                                                   &gdata_ctx,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   buf + offsets[index]
                                                   + sha_size_incr,
                                                   size_aes, iv,
                                                   aad, sizeof(aad),
                                                   auth_tag, sizeof(auth_tag));
                                index += 2;
                                if (index >= index_limit)
                                        index = 0;
                        }
                }
#ifndef _WIN32
                if (use_unhalted_cycles)
                        time = (read_cycles(params->core) -
                                rd_cycles_cost) - time;
                else
#endif
                        time = __rdtscp(&aux) - time;
        }

        free(key);
        return time / num_iter;
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
                const uint32_t size_aes = job_size_start + (sz * JOB_SIZE_STEP);
                const uint32_t num_iter =
                        (iter_scale >= size_aes) ? (iter_scale / size_aes) : 1;

                params->size_aes = size_aes;
                if (params->test_type == TTYPE_AES_GCM && (!use_gcm_job_api)) {
                        if (job_iter == 0)
                                *times = do_test_gcm(params, 2 * num_iter, mgr);
                        else
                                *times = do_test_gcm(params, job_iter, mgr);
                } else {
                        if (job_iter == 0)
                                *times = do_test(mgr, params, num_iter);
                        else
                                *times = do_test(mgr, params, job_iter);
                }
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

        switch (arch) {
        case 0:
                init_mb_mgr_sse(mgr);
                break;
        case 1:
                init_mb_mgr_avx(mgr);
                break;
        case 2:
                init_mb_mgr_avx2(mgr);
                break;
        default:
        case 3:
                init_mb_mgr_avx512(mgr);
                break;
        }

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
                printf("%d", job_size_start + (sz * JOB_SIZE_STEP));
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
        MB_MGR *p_mgr = NULL;
        struct params_s params;
        uint32_t num_variants[NUM_TYPES] = {0, 0, 0};
        uint32_t type, at_size, run, arch;
        uint32_t variants_per_arch, max_arch;
        uint32_t variant;
        uint32_t total_variants = 0;
        struct variant_s *variant_ptr = NULL;
        struct variant_s *variant_list = NULL;

        p_mgr = info->p_mgr;
        if (job_size_start == 0) {
                /* Unmodified through command line parameters. Use defaults. */
                params.num_sizes = JOB_SIZE_MAX / JOB_SIZE_STEP;
                job_size_start = JOB_SIZE_STEP;
        } else {
                /* Test only selected size */
                params.num_sizes = 1;
        }

        params.core = (uint32_t)info->core;

        /* if cores selected then set affinity */
        if (core_mask)
                if (set_affinity(info->core) != 0) {
                        fprintf(stderr, "Failed to set cpu "
                                "affinity on core %d\n", info->core);
                        goto exit_failure;
                }

        /* If unhalted cycles selected and this is
           the primary thread then start counter */
        if (use_unhalted_cycles && info->print_info) {
                int ret;

                ret = start_cycles_ctr(params.core);
                if (ret != 0) {
                        fprintf(stderr, "Failed to start cycles "
                                "counter on core %u\n", params.core);
                        goto exit_failure;
                }
                /* Get average cost of reading counter */
                ret = set_avg_unhalted_cycle_cost(params.core, &rd_cycles_cost);
                if (ret != 0 || rd_cycles_cost == 0) {
                        fprintf(stderr, "Error calculating unhalted "
                                "cycles read overhead!\n");
                        goto exit_failure;
                } else
                        fprintf(stderr, "Started counting unhalted cycles on "
                                "core %d\nUnhalted cycles read cost = %lu "
                                "cycles\n", params.core,
                                (unsigned long)rd_cycles_cost);
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
                        max_arch = NUM_ARCHS;
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
        if (variant_list == NULL) {
                fprintf(stderr, "Cannot allocate memory\n");
                goto exit_failure;
        }

        at_size = NUM_RUNS * params.num_sizes * sizeof(uint64_t);
        for (variant = 0, variant_ptr = variant_list;
             variant < total_variants;
             variant++, variant_ptr++) {
                variant_ptr->avg_times = (uint64_t *) malloc(at_size);
                if (!variant_ptr->avg_times) {
                        fprintf(stderr, "Cannot allocate memory\n");
                        goto exit_failure;
                }
        }
        for (run = 0; run < NUM_RUNS; run++) {
                fprintf(stderr, "Starting run %d of %d\n", run+1, NUM_RUNS);

                variant = 0;
                variant_ptr = variant_list;

                if (iter_scale == ITER_SCALE_SMOKE && run != 0)
                        continue;

                for (type = TTYPE_AES_HMAC; type < NUM_TYPES; type++) {
                        if (test_types[type] == 0)
                                continue;

                        max_arch = NUM_ARCHS;

                        params.num_variants = num_variants[type];
                        params.test_type = type;
                        /* Performing tests for each selected architecture */
                        for (arch = 0; arch < max_arch; arch++) {
                                if (archs[arch] == 0)
                                        continue;
                                run_dir_test(p_mgr, arch, &params, run,
                                             &variant_ptr, &variant);
                        }
                } /* end for type */
        } /* end for run */
        if (info->print_info == 1 && iter_scale != ITER_SCALE_SMOKE)
                print_times(variant_list, &params, total_variants);

        if (variant_list != NULL) {
                /* Freeing variants list */
                for (i = 0; i < total_variants; i++)
                        free(variant_list[i].avg_times);
                free(variant_list);
        }
        free_mb_mgr(p_mgr);
#ifndef _WIN32
        return NULL;

#else
        return;
#endif
exit_failure:
        if (variant_list != NULL)
                free(variant_list);
        free_mem();
        free_mb_mgr(p_mgr);
        exit(EXIT_FAILURE);
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
                "--cores mask: <mask> CPU's to run threads\n"
                "--unhalted-cycles: measure using unhalted cycles (requires root).\n"
                "                   Note: RDTSC is used by default.\n"
                "--quick: reduces number of test iterations by x10\n"
                "         (less precise but quicker)\n"
                "--smoke: very quick, unprecise and without print out\n"
                "         (for validation only)\n"
                "--job-size: size of the cipher & MAC job in bytes\n"
                "            (-o still applies for MAC)\n"
                "--job-iter: number of tests iterations for each job size\n",
                MAX_NUM_THREADS + 1);
}

static int
get_next_num_arg(const char * const *argv, const int index, const int argc,
                 void *dst, const size_t dst_size)
{
        char *endptr = NULL;
        uint64_t val;

        if (dst == NULL || argv == NULL || index < 0 || argc < 0) {
                fprintf(stderr, "%s() internal error!\n", __func__);
                exit(EXIT_FAILURE);
        }

        if (index >= (argc - 1)) {
                fprintf(stderr, "'%s' requires an argument!\n", argv[index]);
                exit(EXIT_FAILURE);
        }

#ifdef _WIN32
        val = _strtoui64(argv[index + 1], &endptr, 0);
#else
        val = strtoull(argv[index + 1], &endptr, 0);
#endif
        if (endptr == argv[index + 1] || (endptr != NULL && *endptr != '\0')) {
                fprintf(stderr, "Error converting '%s' as value for '%s'!\n",
                        argv[index + 1], argv[index]);
                exit(EXIT_FAILURE);
        }

        switch (dst_size) {
        case (sizeof(uint8_t)):
                *((uint8_t *)dst) = (uint8_t) val;
                break;
        case (sizeof(uint16_t)):
                *((uint16_t *)dst) = (uint16_t) val;
                break;
        case (sizeof(uint32_t)):
                *((uint32_t *)dst) = (uint32_t) val;
                break;
        case (sizeof(uint64_t)):
                *((uint64_t *)dst) = val;
                break;
        default:
                fprintf(stderr, "%s() invalid dst_size %u!\n",
                        __func__, (unsigned) dst_size);
                exit(EXIT_FAILURE);
                break;
        }

        return index + 1;
}

static int
detect_arch(unsigned int arch_support[NUM_ARCHS])
{
        const uint64_t detect_sse =
                IMB_FEATURE_SSE4_2 | IMB_FEATURE_CMOV | IMB_FEATURE_AESNI;
        const uint64_t detect_avx =
                IMB_FEATURE_AVX | IMB_FEATURE_CMOV | IMB_FEATURE_AESNI;
        const uint64_t detect_avx2 = IMB_FEATURE_AVX2 | detect_avx;
        const uint64_t detect_avx512 = IMB_FEATURE_AVX512_SKX | detect_avx2;
        MB_MGR *p_mgr = NULL;
        enum arch_type_e arch_id;

        if (arch_support == NULL) {
                fprintf(stderr, "Array not passed correctly\n");
                return -1;
        }

        for (arch_id = ARCH_SSE; arch_id < NUM_ARCHS; arch_id++)
                arch_support[arch_id] = 1;

        p_mgr = alloc_mb_mgr(0);
        if (p_mgr == NULL) {
                fprintf(stderr, "Architecture detect error!\n");
                return -1;
        }

        if ((p_mgr->features & detect_avx512) != detect_avx512)
                arch_support[ARCH_AVX512] = 0;

        if ((p_mgr->features & detect_avx2) != detect_avx2)
                arch_support[ARCH_AVX2] = 0;

        if ((p_mgr->features & detect_avx) != detect_avx)
                arch_support[ARCH_AVX] = 0;

        if ((p_mgr->features & detect_sse) != detect_sse)
                arch_support[ARCH_SSE] = 0;

        free_mb_mgr(p_mgr);

        return 0;
}

int main(int argc, char *argv[])
{
        uint32_t num_t = 0;
        int i, core = 0;
        struct thread_info *thread_info_p = t_info;
        unsigned int arch_id;
        unsigned int arch_support[NUM_ARCHS];

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
                        flags &= (~IMB_FLAG_SHANI_OFF);
                } else if (strcmp(argv[i], "--shani-off") == 0) {
                        flags |= IMB_FLAG_SHANI_OFF;
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
                } else if (strcmp(argv[i], "--quick") == 0) {
                        iter_scale = ITER_SCALE_SHORT;
                } else if (strcmp(argv[i], "--smoke") == 0) {
                        iter_scale = ITER_SCALE_SMOKE;
                } else if (strcmp(argv[i], "-o") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &sha_size_incr,
                                             sizeof(sha_size_incr));
                } else if (strcmp(argv[i], "--job-size") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &job_size_start,
                                             sizeof(job_size_start));
                        if (job_size_start > JOB_SIZE_MAX) {
                                fprintf(stderr,
                                        "Invalid job size %u (max %u)!\n",
                                        (unsigned) job_size_start,
                                        JOB_SIZE_MAX);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--job-iter") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &job_iter, sizeof(job_iter));
                } else if (strcmp(argv[i], "--threads") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &num_t, sizeof(num_t));
                        if (num_t > (MAX_NUM_THREADS + 1)) {
                                fprintf(stderr, "Invalid number of threads!\n");
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--cores") == 0) {
                        i = get_next_num_arg((const char * const *)argv, i,
                                             argc, &core_mask,
                                             sizeof(core_mask));
                } else if (strcmp(argv[i], "--unhalted-cycles") == 0) {
                        use_unhalted_cycles = 1;
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

        /* if cycles selected then init MSR module */
        if (use_unhalted_cycles) {
                if (core_mask == 0) {
                        fprintf(stderr, "Must specify core mask "
                                "when reading unhalted cycles!\n");
                        return EXIT_FAILURE;
                }

                if (init_msr_mod() != 0) {
                        fprintf(stderr, "Error initializing MSR module!\n");
                        return EXIT_FAILURE;
                }
        }

        if (detect_arch(arch_support) < 0)
                return EXIT_FAILURE;

        /* disable tests depending on instruction sets supported */
        for (arch_id = 0; arch_id < NUM_ARCHS; arch_id++) {
                if (archs[arch_id] == 1 && arch_support[arch_id] == 0) {
                        archs[arch_id] = 0;
                        fprintf(stderr,
                                "%s not supported. Disabling %s tests\n",
                                arch_strings[arch_id], arch_strings[arch_id]);
                }
        }

        fprintf(stderr, "SHA size incr = %d\n", sha_size_incr);
        if (archs[ARCH_SSE]) {
                MB_MGR *p_mgr = alloc_mb_mgr(flags);

                if (p_mgr == NULL) {
                        fprintf(stderr, "Error allocating MB_MGR structure!\n");
                        return EXIT_FAILURE;
                }
                init_mb_mgr_sse(p_mgr);
                fprintf(stderr, "%s SHA extensions (shani) for SSE arch\n",
                        (p_mgr->features & IMB_FEATURE_SHANI) ?
                        "Using" : "Not using");
                free_mb_mgr(p_mgr);
        }

        memset(t_info, 0, sizeof(t_info));

        srand(ITER_SCALE_LONG + ITER_SCALE_SHORT + ITER_SCALE_SMOKE);
        init_buf(cache_type);

        if (num_t > 1) {
                uint32_t n;

                for (n = 0; n < (num_t - 1); n++, thread_info_p++) {
                        /* Set core if selected */
                        if (core_mask) {
                                core = next_core(core_mask, core);
                                thread_info_p->core = core++;
                        }

                        /* Allocate MB manager for each thread */
                        thread_info_p->p_mgr = alloc_mb_mgr(flags);
                        if (thread_info_p->p_mgr == NULL) {
                                fprintf(stderr, "Failed to allocate MB_MGR "
                                        "structure for thread %u!\n",
                                        (unsigned)(n + 1));
                                free_mem();
                                exit(EXIT_FAILURE);
                        }
#ifdef _WIN32
                        threads[n] = (HANDLE)
                                _beginthread(&run_tests, 0,
                                             (void *)thread_info_p);
#else
                        pthread_attr_t attr;

                        pthread_attr_init(&attr);
                        pthread_create(&tids[n], &attr, run_tests,
                                       (void *)thread_info_p);
#endif
                }
        }

        thread_info_p->print_info = 1;
        thread_info_p->p_mgr = alloc_mb_mgr(flags);
        if (thread_info_p->p_mgr == NULL) {
                fprintf(stderr, "Failed to allocate MB_MGR "
                        "structure for main thread!\n");
                free_mem();
                exit(EXIT_FAILURE);
        }
        if (core_mask) {
                core = next_core(core_mask, core);
                thread_info_p->core = core;
        }

        run_tests((void *)thread_info_p);
        if (num_t > 1) {
                uint32_t n;

#ifdef _WIN32
                WaitForMultipleObjects(num_t, threads, FALSE, INFINITE);
#endif
                for (n = 0; n < (num_t - 1); n++) {
                        fprintf(stderr, "Waiting on thread %u to finish...\n",
                                (unsigned)(n + 2));
#ifdef _WIN32
                        CloseHandle(threads[n]);
#else
                        pthread_join(tids[n], NULL);
#endif
                }
        }

        if (use_unhalted_cycles)
                machine_fini();

        free_mem();

        return EXIT_SUCCESS;
}
