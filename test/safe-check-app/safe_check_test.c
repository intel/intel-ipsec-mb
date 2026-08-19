/**********************************************************************
  Copyright(c) 2026, Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

/**
 * @brief Sensitive data (safe check) test application
 *
 * Scans all supported algorithms, key sizes, message sizes and cipher
 * directions looking for sensitive data (keys, plaintext) left behind in
 * general purpose registers, SIMD registers, stack, IMB_MGR and out-of-order
 * managers after key expansion and job processing.
 *
 * The application does not verify any cryptographic results.
 * Use the imb-xvalid application for cross architecture result validation.
 *
 * Requires the library to be compiled with SAFE_DATA option (default).
 */

#include <stdio.h>
#include <stdlib.h> /* posix_memalign() and free() */
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#ifndef LINUX
#include <malloc.h> /* _aligned_malloc() and aligned_free() */
#endif
#include "misc.h"
#include "utils.h"
#ifdef PIN_BASED_CEC
#include <pin_based_cec.h>
#endif

#ifdef _WIN32
#include <intrin.h>
#define strdup     _strdup
#define BSWAP64    _byteswap_uint64
#define __func__   __FUNCTION__
#define strcasecmp _stricmp
#else
#include <x86intrin.h>
#define BSWAP64 __builtin_bswap64
#endif

#include <intel-ipsec-mb.h>
#include "include/mb_mgr.h"

#include "algo_maps.h"
#include "job_params.h"
#include "job_utils.h"

/* maximum size of a test buffer */
#define JOB_SIZE_TOP (16 * 1024)
/* min size of a buffer when testing range of buffers */
#define DEFAULT_JOB_SIZE_MIN 16
/* max size of a buffer when testing range of buffers */
#define DEFAULT_JOB_SIZE_MAX (2 * 1024)
/* number of bytes to increase buffer size when testing range of buffers */
#define DEFAULT_JOB_SIZE_STEP 16

#define MAX_GCM_AAD_SIZE 1024
#define MAX_CCM_AAD_SIZE 46
#define MAX_AAD_SIZE     1024
#define NUM_TAG_SIZES    7

#define MAX_IV_SIZE 16

/* Maximum number of jobs submitted in one go */
#define MAX_NUM_JOBS 17

/*
 * Number of IMIX iterations per job number.
 * It has to be greater than the maximum number of jobs submitted in one go,
 * so that all multi-buffer job submit and flush scenarios get covered.
 * It is lower than the cross validation application uses, as every
 * iteration performs a full register, stack and memory scan.
 */
#define IMIX_ITER (2 * MAX_NUM_JOBS)

/* MAX_KEY_SIZE and MAX_DIGEST_SIZE come from job_params.h */

#define SEED        0xdeadcafe
#define STACK_DEPTH 8192

/* Max safe check retries to eliminate false positives */
#define MAX_SAFE_RETRIES     100
#define DEFAULT_SAFE_RETRIES 2

/* Sensitive data search pattern definitions */
#define FOUND_CIPHER_KEY 1
#define FOUND_AUTH_KEY   2
#define FOUND_TEXT       3

static int pattern_auth_key;
static int pattern_cipher_key;
static int pattern_plain_text;

/* Struct storing all necessary data for crypto operations */
struct data {
        uint8_t test_buf[MAX_NUM_JOBS][JOB_SIZE_TOP];
        uint8_t src_dst_buf[MAX_NUM_JOBS][JOB_SIZE_TOP];
        uint8_t aad[MAX_AAD_SIZE];
        uint8_t in_digest[MAX_NUM_JOBS][MAX_DIGEST_SIZE];
        uint8_t out_digest[MAX_NUM_JOBS][MAX_DIGEST_SIZE];
        uint8_t cipher_iv[MAX_IV_SIZE];
        uint8_t auth_iv[MAX_IV_SIZE];
        uint8_t ciph_key[MAX_KEY_SIZE];
        uint8_t auth_key[MAX_KEY_SIZE];
        struct cipher_auth_keys keys;
        uint8_t tag_size;
};

uint8_t custom_test = 0;
uint8_t verbose = 0;
uint32_t safe_retries = DEFAULT_SAFE_RETRIES;

uint32_t job_sizes[NUM_RANGE] = { DEFAULT_JOB_SIZE_MIN, DEFAULT_JOB_SIZE_STEP,
                                  DEFAULT_JOB_SIZE_MAX };

struct custom_job_params custom_job_params = { .cipher_mode = IMB_CIPHER_NULL,
                                               .hash_alg = IMB_AUTH_NULL,
                                               .key_size = 0 };

/* Architectures to test, indexed with IMB_ARCH, IMB_ARCH_NONE is never tested */
uint8_t archs[IMB_ARCH_NUM] = { 0, 1, 1, 1, 1 };

/* Cipher directions to test, indexed with IMB_CIPHER_DIRECTION */
uint8_t cipher_dirs[IMB_DIR_DECRYPT + 1] = { 0, 1, 1 };

/* Number of jobs submitted in one go (0 => test all values from num_jobs_tab) */
uint32_t max_num_jobs = 0;

/* Number of jobs submitted in one go to be exercised */
static const unsigned num_jobs_tab[] = { 1, 3, 4, 5, 7, 8, 9, 15, 16, 17 };

/* 1 => additionally run tests with mixed job sizes in one go */
unsigned int imix_enabled = 0;

uint64_t flags = 0; /* flags passed to alloc_mb_mgr() */

int burst_api = 0;

static void
clear_data(struct data *data)
{
        unsigned i;

        for (i = 0; i < MAX_NUM_JOBS; i++) {
                imb_clear_mem(data->test_buf[i], JOB_SIZE_TOP);
                imb_clear_mem(data->src_dst_buf[i], JOB_SIZE_TOP);
                imb_clear_mem(data->in_digest[i], MAX_DIGEST_SIZE);
                imb_clear_mem(data->out_digest[i], MAX_DIGEST_SIZE);
        }

        imb_clear_mem(data->aad, MAX_AAD_SIZE);
        imb_clear_mem(data->cipher_iv, MAX_IV_SIZE);
        imb_clear_mem(data->auth_iv, MAX_IV_SIZE);
        imb_clear_mem(data->ciph_key, MAX_KEY_SIZE);
        imb_clear_mem(data->auth_key, MAX_KEY_SIZE);
        imb_clear_mem(&data->keys, sizeof(struct cipher_auth_keys));
}

/**
 * Generate fill patterns
 * - make sure each patterns are different
 * - do not return zero pattern
 * - make sure it takes as long as possible before pattern is reused again
 */
static int
get_pattern_seed(void)
{
        static int pattern_seed = 0;

        if (pattern_seed == 0)
                pattern_seed = (pattern_seed + 1) & 255;

        const int ret_seed = pattern_seed;

        pattern_seed = (pattern_seed + 1) & 255;
        return ret_seed;
}

static void
generate_one_pattern(const int idx)
{
        switch (idx) {
        case 0:
                pattern_auth_key = get_pattern_seed();
                break;
        case 1:
                pattern_cipher_key = get_pattern_seed();
                break;
        default:
                pattern_plain_text = get_pattern_seed();
                break;
        }
}

static void
generate_patterns(void)
{
        const int var_tab[][3] = { { 0, 1, 2 }, { 1, 0, 2 }, { 2, 1, 0 },
                                   { 0, 2, 1 }, { 1, 2, 0 }, { 2, 0, 1 } };
        static int var_idx = 0;

        /* change order of generating patterns */
        generate_one_pattern(var_tab[var_idx][0]);
        generate_one_pattern(var_tab[var_idx][1]);
        generate_one_pattern(var_tab[var_idx][2]);
        var_idx = (var_idx + 1) % IMB_DIM(var_tab);

        nosimd_memset(&pattern8_auth_key, pattern_auth_key, sizeof(pattern8_auth_key));
        nosimd_memset(&pattern8_cipher_key, pattern_cipher_key, sizeof(pattern8_cipher_key));
        nosimd_memset(&pattern8_plain_text, pattern_plain_text, sizeof(pattern8_plain_text));
}

static void
print_patterns(void)
{
        printf(">>> Patterns: AUTH_KEY = 0x%02x, CIPHER_KEY = 0x%02x, "
               "PLAIN_TEXT = 0x%02x\n",
               pattern_auth_key, pattern_cipher_key, pattern_plain_text);
}

/**
 * @brief Searches across a block of memory if a pattern is present
 *        (indicating there is some left over sensitive data)
 *
 * @return search status
 * @retval 0 nothing found
 * @retval FOUND_CIPHER_KEY fragment of CIPHER_KEY found
 * @retval FOUND_AUTH_KEY fragment of AUTH_KEY found
 * @retval FOUND_TEXT fragment of TEXT found
 */
static int
search_patterns(const void *ptr, const size_t mem_size, size_t *offset)
{
        const uint8_t *ptr8 = (const uint8_t *) ptr;
        const size_t limit = mem_size - sizeof(uint64_t);

        for (size_t i = *offset; i <= limit; i++) {
                const uint64_t string = *((const uint64_t *) &ptr8[i]);

                if (string == pattern8_cipher_key) {
                        *offset = i;
                        return FOUND_CIPHER_KEY;
                }

                if (string == pattern8_auth_key) {
                        *offset = i;
                        return FOUND_AUTH_KEY;
                }

                if (string == pattern8_plain_text) {
                        *offset = i;
                        return FOUND_TEXT;
                }
        }

        return 0;
}

/**
 * @brief Tests memory pattern search function for specific buffer size
 *
 * @param [in] cb_size size of the test buffer
 * @param [in] pattern byte pattern to be used in the test
 *
 * @return Test status
 * @retval 0 OK
 * @retval -1 Test case 1 failed
 * @retval -2 Test case 2 failed
 * @retval -3 Test case 3 failed
 * @retval -100 Buffer allocation error
 */
static int
mem_search_avx2_test_case(const size_t cb_size, const int pattern)
{
        uint8_t *cb = malloc(cb_size);
        int ret = 0;

        if (cb == NULL)
                return -100;

        size_t i = 0;

        /* test 1: pattern shrinks from start to the end */
        for (i = 0; i < cb_size; i++) {
                const size_t current_sz = cb_size - i;
                uint8_t *p = &cb[i];

                if (i != 0)
                        nosimd_memset(cb, 0, i);
                nosimd_memset(p, pattern, current_sz);

                const uint64_t r1 = mem_search_avx2(cb, cb_size);

                if (current_sz >= sizeof(uint64_t) && r1 == 0ULL) {
                        ret = -1;
                        break;
                }

                const uint64_t r2 = mem_search_avx2(p, current_sz);

                if (current_sz >= sizeof(uint64_t) && r2 == 0ULL) {
                        ret = -1;
                        break;
                }
        }

        /* test 2: pattern grows from end to start */
        for (i = 0; (ret == 0) && (i < cb_size); i++) {
                const size_t current_sz = cb_size - i;
                uint8_t *p = &cb[current_sz];

                nosimd_memset(cb, 0, current_sz);
                if (i != 0)
                        nosimd_memset(p, pattern, i);

                const uint64_t r1 = mem_search_avx2(cb, cb_size);

                if (i >= sizeof(uint64_t) && r1 == 0ULL) {
                        ret = -2;
                        break;
                }

                const uint64_t r2 = mem_search_avx2(p, i);

                if (i >= sizeof(uint64_t) && r2 == 0ULL) {
                        ret = -2;
                        break;
                }
        }

        /* test 3: moving and growing pattern */
        for (i = 0; (ret == 0) && (i < cb_size); i++) {
                const size_t current_sz = cb_size - i;
                uint8_t *p = &cb[i];

                for (size_t j = 1; (ret == 0) && (j < current_sz); j++) {
                        if ((i + j) > cb_size)
                                break;

                        nosimd_memset(cb, 0, cb_size);
                        nosimd_memset(p, pattern, j);

                        const uint64_t r1 = mem_search_avx2(cb, cb_size);

                        if (j >= sizeof(uint64_t) && r1 == 0ULL) {
                                ret = -3;
                                break;
                        }

                        const uint64_t r2 = mem_search_avx2(p, current_sz);

                        if (j >= sizeof(uint64_t) && r2 == 0ULL) {
                                ret = -3;
                                break;
                        }
                }
        }

        free(cb);
        return ret;
}

/*
 * @brief Tests memory pattern search function for range of memory buffer sizes
 *
 * @return Test status
 * @retval 0 OK
 * @retval -1 Test case 1 failed
 * @retval -2 Test case 2 failed
 * @retval -3 Test case 3 failed
 * @retval -4 Negative test case 4 failed
 * @retval -100 Buffer allocation error
 */
static int
mem_search_avx2_test(void)
{
        const int pattern_tab[3] = { pattern_cipher_key, pattern_auth_key, pattern_plain_text };
        int ret = 0;

        /* positive tests */
        for (size_t i = 8; (ret == 0) && (i <= 128); i++)
                for (size_t n = 0; (ret == 0) && (n < IMB_DIM(pattern_tab)); n++)
                        ret = mem_search_avx2_test_case(i, pattern_tab[n]);

        /* negative test */
        if (ret == 0) {
                int negative_pattern = 0;

                for (negative_pattern = 1; negative_pattern < 256; negative_pattern++) {
                        size_t n = 0;

                        for (n = 0; n < IMB_DIM(pattern_tab); n++)
                                if (negative_pattern == pattern_tab[n])
                                        break;

                        /* there was no match against existing patterns */
                        if (n >= IMB_DIM(pattern_tab))
                                break;
                }

                if (mem_search_avx2_test_case(128, negative_pattern) == 0)
                        ret = -4;
        }

        return ret;
}

/**
 * @brief Searches across a block of memory if a pattern is present
 *        (indicating there is some left over sensitive data)
 *
 * @return search status
 * @retval 0 nothing found
 * @retval FOUND_CIPHER_KEY fragment of CIPHER_KEY found
 * @retval FOUND_AUTH_KEY fragment of AUTH_KEY found
 * @retval FOUND_TEXT fragment of TEXT found
 */
static int
search_patterns_ex(const void *ptr, const size_t mem_size, size_t *offset)
{
        static uint32_t avx2_check = UINT32_MAX;

        if (mem_size < sizeof(uint64_t) || offset == NULL)
                return 0;

        if (ptr == NULL)
                return 0;

        *offset = 0;

        if (avx2_check == UINT32_MAX) {
                /*
                 * Use the library CPU feature detection to make sure AVX2 code
                 * can be executed. Checking the CPUID AVX2 bit alone is not
                 * enough - the OS also has to enable XSAVE and the YMM state.
                 */
                const uint64_t features = imb_get_cpu_features();

                avx2_check = ((features & IMB_CPUFLAGS_AVX2) == IMB_CPUFLAGS_AVX2) ? 1 : 0;

                /* run test of mem_search_avx2() function */
                if (avx2_check && (mem_search_avx2_test() != 0)) {
                        printf("ERROR: test_mem_search_avx2() test failed!\n");
                        avx2_check = 0;
                }
        }

        if (avx2_check)
                if (mem_search_avx2(ptr, mem_size) == 0ULL)
                        return 0;

        /*
         * If AVX2 fast search reports a problem then run the slow check
         * - also run slow check if AVX2 not available
         */
        return search_patterns(ptr, mem_size, offset);
}

struct safe_check_ctx {
        int key_exp_phase;

        IMB_ARCH arch;
        IMB_CIPHER_DIRECTION cipher_dir;
        unsigned num_jobs;
        const char *dir_name;
        unsigned job_size;
        unsigned imix;

        int gps_check;
        size_t gps_offset;

        int simd_check;
        size_t simd_offset;
        size_t simd_reg_size;
        const char *simd_reg_name;

        int rsp_check;
        size_t rsp_offset;
        void *rsp_ptr;
        uint8_t rsp_buf[64];

        int mgr_check;
        size_t mgr_offset;
        void *mgr_ptr;

        int ooo_check;
        size_t ooo_offset;
        void *ooo_ptr;
        const char *ooo_name;
        size_t ooo_size;
};

static void
print_match_gp(const void *ptr, const size_t offset)
{
        const char *reg_str[] = { "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8",
                                  "r9",  "r10", "r11", "r12", "r13", "r14", "r15" };
        const uint8_t *ptr8 = (const uint8_t *) ptr;
        const size_t len_to_print = 8;
        const size_t reg_idx = offset / 8;
        const char *reg_name = (reg_idx < DIM(reg_str)) ? reg_str[reg_idx] : "<unknown>";

        hexdump_ex(stderr, reg_name, &ptr8[offset & ~7], len_to_print, NULL);
}

static void
print_match_xyzmm(const void *ptr, const size_t offset, const size_t simd_size,
                  const char *simd_name)
{
        const uint8_t *ptr8 = (const uint8_t *) ptr;
        const size_t len_to_print = simd_size;
        const size_t reg_idx = offset / simd_size;
        char reg_name[8];

        nosimd_memset(reg_name, 0, sizeof(reg_name));
        snprintf(reg_name, sizeof(reg_name) - 1, "%s%zu", simd_name, reg_idx);
        hexdump_ex(stderr, reg_name, &ptr8[reg_idx * simd_size], len_to_print, NULL);
}

static void
print_match_memory(const void *ptr, const size_t mem_size, const size_t offset,
                   const char *mem_name)
{
        const uint8_t *ptr8 = (const uint8_t *) ptr;
        static uint8_t tb[64];
        const size_t len_to_print =
                (sizeof(tb) > (mem_size - offset)) ? (mem_size - offset) : sizeof(tb);

        nosimd_memcpy(tb, &ptr8[offset], len_to_print);
        hexdump_ex(stderr, mem_name, tb, len_to_print, &ptr8[offset]);
}

static void
print_match_stack(const struct safe_check_ctx *ctx)
{
        const uint8_t *rsp8 = (const uint8_t *) ctx->rsp_ptr;
        /* the scanned block starts STACK_DEPTH bytes below RSP */
        const uint8_t *ptr8 = rsp8 - STACK_DEPTH;
        const size_t len_to_print = 64;

        fprintf(stderr, "RSP = %p, offset = %zu, effective address = %p\n", rsp8, ctx->rsp_offset,
                &ptr8[ctx->rsp_offset]);

        hexdump_ex(stderr, "STACK", ctx->rsp_buf, len_to_print, &ptr8[ctx->rsp_offset]);
}

static void
print_match_type(const int check, const char *err_str)
{
        if (check == FOUND_CIPHER_KEY)
                fprintf(stderr, "Part of CIPHER_KEY found when %s\n", err_str);
        else if (check == FOUND_AUTH_KEY)
                fprintf(stderr, "Part of AUTH_KEY found when %s\n", err_str);
        else if (check == FOUND_TEXT)
                fprintf(stderr, "Part of plain/cipher text found when %s\n", err_str);
}

static void
print_match(const struct safe_check_ctx *ctx, const char *err_str)
{
        if (ctx->gps_check) {
                print_match_type(ctx->gps_check, err_str);
                print_match_gp(gps, ctx->gps_offset);
                return;
        }

        if (ctx->simd_check) {
                print_match_type(ctx->simd_check, err_str);
                print_match_xyzmm(simd_regs, ctx->simd_offset, ctx->simd_reg_size,
                                  ctx->simd_reg_name);
                return;
        }

        if (ctx->rsp_check) {
                print_match_type(ctx->rsp_check, err_str);
                print_match_stack(ctx);
                return;
        }

        if (ctx->mgr_check) {
                print_match_type(ctx->mgr_check, err_str);
                print_match_memory(ctx->mgr_ptr, imb_get_mb_mgr_size(), ctx->mgr_offset, "IMB_MGR");
                return;
        }

        if (ctx->ooo_check) {
                print_match_type(ctx->ooo_check, err_str);
                print_match_memory(ctx->ooo_ptr, ctx->ooo_size, ctx->ooo_offset, ctx->ooo_name);
                return;
        }
}

static int
compare_match(const struct safe_check_ctx *a, const struct safe_check_ctx *b)
{
        if (a->key_exp_phase != b->key_exp_phase)
                return 1;
        if (a->arch != b->arch)
                return 1;
        if (a->cipher_dir != b->cipher_dir)
                return 1;
        if (a->num_jobs != b->num_jobs)
                return 1;
        if ((a->dir_name == NULL) != (b->dir_name == NULL))
                return 1;
        if (a->dir_name != NULL && strcmp(a->dir_name, b->dir_name) != 0)
                return 1;

        if (a->gps_check != b->gps_check)
                return 1;
        if (a->gps_offset != b->gps_offset)
                return 1;

        if (a->simd_check != b->simd_check)
                return 1;
        if (a->simd_offset != b->simd_offset)
                return 1;

        if (a->rsp_check != b->rsp_check)
                return 1;
        if (a->rsp_offset != b->rsp_offset)
                return 1;

        if (a->mgr_check != b->mgr_check)
                return 1;
        if (a->mgr_offset != b->mgr_offset)
                return 1;

        if (a->ooo_check != b->ooo_check)
                return 1;
        if (a->ooo_offset != b->ooo_offset)
                return 1;
        if (a->ooo_ptr != b->ooo_ptr)
                return 1;

        return 0;
}

/*
 * @brief Checks for sensitive information in registers, stack and MB_MGR
 *        (in this order, to try to minimize pollution of the data left out
 *        after the job completion, due to these actual checks).
 *
 * @return check status
 * @retval 0 all OK
 * @retval -1 sensitive data found
 * @retval -2 wrong input arguments
 */
static int
perform_safe_checks(IMB_MGR *mgr, const IMB_ARCH arch, struct safe_check_ctx *ctx, const char *dir)
{
        static const struct {
                size_t simd_set_size;
                void (*simd_dump_fn)(void);
        } simd_ctx[] = {
                { 0, NULL },                     /* none */
                { XMM_MEM_SIZE, dump_xmms_sse }, /* sse */
                { YMM_MEM_SIZE, dump_ymms },     /* avx2 */
                { ZMM_MEM_SIZE, dump_zmms },     /* avx512 */
                { ZMM_MEM_SIZE, dump_zmms }      /* avx10 */
        };

        dump_gps();

        if (ctx == NULL)
                return -2;

        if (arch == IMB_ARCH_NONE || arch >= IMB_ARCH_NUM) {
                fprintf(stderr, "Invalid architecture!\n");
                return -2;
        }

        uint8_t *rsp_ptr = rdrsp();

        simd_ctx[arch].simd_dump_fn();

        nosimd_memset(ctx, 0, sizeof(*ctx));

        ctx->rsp_ptr = rsp_ptr;
        ctx->arch = arch;
        ctx->dir_name = dir;

        if (arch == IMB_ARCH_AVX2) {
                ctx->simd_reg_size = 32;
                ctx->simd_reg_name = "ymm";
        } else if (arch == IMB_ARCH_AVX512 || arch == IMB_ARCH_AVX10) {
                ctx->simd_reg_size = 64;
                ctx->simd_reg_name = "zmm";
        } else {
                ctx->simd_reg_size = 16;
                ctx->simd_reg_name = "xmm";
        }

        ctx->rsp_check = search_patterns_ex((rsp_ptr - STACK_DEPTH), STACK_DEPTH, &ctx->rsp_offset);
        if (ctx->rsp_check != 0) {
                const uint8_t *sp = (const uint8_t *) (rsp_ptr - STACK_DEPTH);

                nosimd_memcpy(ctx->rsp_buf, &sp[ctx->rsp_offset], sizeof(ctx->rsp_buf));
                return -1;
        }

        ctx->gps_check = search_patterns_ex(gps, GP_MEM_SIZE, &ctx->gps_offset);
        if (ctx->gps_check != 0)
                return -1;

        ctx->simd_check =
                search_patterns_ex(simd_regs, simd_ctx[arch].simd_set_size, &ctx->simd_offset);
        if (ctx->simd_check != 0)
                return -1;

        /*
         * Search IMB_MGR and OOO managers one after another.
         * Start with index -1 to get information about IMB_MGR itself.
         */
        for (int i = -1;; i++) {
                void *ooo_mgr_p = NULL;
                size_t ooo_mgr_size = 0;
                const char *ooo_mgr_name = NULL;

                if (imb_get_ooo_mgr(mgr, i, &ooo_mgr_p, &ooo_mgr_size, &ooo_mgr_name) == EINVAL) {
                        /* Invalid OOO manager index reached and i = number of OOO managers */
                        break;
                }

                /* Skip NULL or zero-size OOO managers */
                if (ooo_mgr_p == NULL || ooo_mgr_size == 0)
                        continue;

                ctx->ooo_check = search_patterns_ex(ooo_mgr_p, ooo_mgr_size, &ctx->ooo_offset);
                if (ctx->ooo_check != 0) {
                        ctx->ooo_ptr = ooo_mgr_p;
                        ctx->ooo_name = ooo_mgr_name;
                        ctx->ooo_size = ooo_mgr_size;
                        return -1;
                }
        }

        return 0;
}

/*
 * @brief Checks job completion status and job order
 *
 * @return Operation status
 * @retval 0 job completed
 * @retval -1 job error
 */
static int
post_job(IMB_MGR *mgr, const IMB_JOB *job, unsigned *num_processed_jobs)
{
        const unsigned idx = (unsigned) ((uintptr_t) job->user_data);

        if (job->status != IMB_STATUS_COMPLETED) {
                const int errc = imb_get_errno(mgr);

                fprintf(stderr,
                        "failed job, status:%d, "
                        "error code:%d '%s'\n",
                        job->status, errc, imb_get_strerror(errc));
                return -1;
        }

        if (idx != *num_processed_jobs) {
                fprintf(stderr,
                        "job returned out of order, "
                        "received %u, expected %u\n",
                        idx, *num_processed_jobs);
                return -1;
        }

        (*num_processed_jobs)++;

        return 0;
}

/* Sets up job context and fills the message buffer with the plain text pattern */
static void
set_job_ctx(struct job_ctx *ctx, const struct params_s *params, const uint32_t buf_size,
            uint8_t *in_digest, uint8_t *out_digest, const uint8_t tag_size, uint8_t *test_buf,
            uint8_t *src_dst_buf)
{
        ctx->in_digest = in_digest;
        ctx->out_digest = out_digest;
        ctx->tag_size_to_check = tag_size;
        ctx->test_buf = test_buf;
        ctx->src_dst_buf = src_dst_buf;
        ctx->buf_size = buf_size;

        /* PON only fields, left at zero for all other algorithms */
        ctx->pli = 0;
        ctx->xgem_hdr = 0;

        if (params->hash_alg == IMB_AUTH_PON_CRC_BIP) {
                /* Buf size is XGEM payload, including CRC,
                 * allocate space for XGEM header and padding */
                ctx->pli = (uint16_t) ctx->buf_size;
                ctx->buf_size += 8;
                if (ctx->buf_size < 16)
                        ctx->buf_size = 16;
                if (ctx->buf_size % 4)
                        ctx->buf_size = (ctx->buf_size + 3) & 0xfffffffc;
                if (ctx->buf_size > JOB_SIZE_TOP) {
                        fprintf(stderr, "Invalid PON buffer size %u (max %d)\n", ctx->buf_size,
                                JOB_SIZE_TOP);
                        exit(EXIT_FAILURE);
                }
                /*
                 * Only first 4 bytes are checked, corresponding to BIP
                 */
                ctx->tag_size_to_check = 4;
        }

        if (params->hash_alg == IMB_AUTH_DOCSIS_CRC32) {
                if (ctx->buf_size >=
                    (IMB_DOCSIS_CRC32_MIN_ETH_PDU_SIZE + IMB_DOCSIS_CRC32_TAG_SIZE))
                        ctx->tag_size_to_check = IMB_DOCSIS_CRC32_TAG_SIZE;
                else
                        ctx->tag_size_to_check = 0;
        }

        /* Fill the message with the sensitive data pattern */
        nosimd_memset(ctx->test_buf, pattern_plain_text, ctx->buf_size);

        /* For PON, construct the XGEM header, setting valid PLI */
        if (params->hash_alg == IMB_AUTH_PON_CRC_BIP) {
                /* create XGEM header template */
                const uint16_t shifted_pli = (ctx->pli << 2) & 0xffff;
                uint64_t *p_src = (uint64_t *) ctx->test_buf;

                ctx->xgem_hdr = ((shifted_pli >> 8) & 0xff) | ((shifted_pli & 0xff) << 8);
                p_src[0] = ctx->xgem_hdr;
        }

        /* Randomize memory for output digest */
        generate_random_buf(ctx->out_digest, ctx->tag_size_to_check);
}

/*
 * @brief Submits number of jobs and waits for their completion
 *
 * @return Operation status
 * @retval 0 all OK
 * @retval -1 job error
 */
static int
process_jobs(IMB_MGR *mb_mgr, const IMB_JOB *job_tab, const unsigned num_jobs,
             const struct params_s *params, const char *avx_sse_text_submit,
             const char *avx_sse_text_flush)
{
        unsigned num_processed_jobs = 0;
        unsigned i;

        if (burst_api) {
                IMB_JOB *burst_jobs[IMB_MAX_BURST_SIZE];

                /* num_jobs will always be lower than IMB_MAX_BURST_SIZE */
                unsigned num_rx_jobs = IMB_GET_NEXT_BURST(mb_mgr, num_jobs, burst_jobs);

                if (num_rx_jobs != num_jobs) {
                        fprintf(stderr,
                                "Number of jobs received %u is different than requested %u\n",
                                num_rx_jobs, num_jobs);
                        return -1;
                }

                for (i = 0; i < num_jobs; i++)
                        *burst_jobs[i] = job_tab[i];

                num_rx_jobs = IMB_SUBMIT_BURST(mb_mgr, num_jobs, burst_jobs);

                avx_sse_check(avx_sse_text_submit, (unsigned) params->hash_alg,
                              (unsigned) params->cipher_mode);

                if (num_rx_jobs < num_jobs) {
                        num_rx_jobs += IMB_FLUSH_BURST(mb_mgr, (num_jobs - num_rx_jobs),
                                                       &burst_jobs[num_rx_jobs]);
                        avx_sse_check(avx_sse_text_flush, (unsigned) params->hash_alg,
                                      (unsigned) params->cipher_mode);
                }

                if (num_rx_jobs != num_jobs) {
                        fprintf(stderr,
                                "Number of processed jobs %u is different than submitted %u\n",
                                num_rx_jobs, num_jobs);
                        return -1;
                }

                for (i = 0; i < num_rx_jobs; i++)
                        if (post_job(mb_mgr, burst_jobs[i], &num_processed_jobs) < 0)
                                return -1;

                return 0;
        }

        for (i = 0; i < num_jobs; i++) {
                IMB_JOB *job = IMB_GET_NEXT_JOB(mb_mgr);

                *job = job_tab[i];

                job = IMB_SUBMIT_JOB(mb_mgr);

                avx_sse_check(avx_sse_text_submit, (unsigned) params->hash_alg,
                              (unsigned) params->cipher_mode);

                if (job != NULL)
                        if (post_job(mb_mgr, job, &num_processed_jobs) < 0)
                                return -1;
        }

        /* Flush the rest of the jobs, if there are outstanding jobs */
        while (num_processed_jobs != num_jobs) {
                IMB_JOB *job = IMB_FLUSH_JOB(mb_mgr);

                avx_sse_check(avx_sse_text_flush, (unsigned) params->hash_alg,
                              (unsigned) params->cipher_mode);

                while (job != NULL) {
                        if (post_job(mb_mgr, job, &num_processed_jobs) < 0)
                                return -1;

                        /* Get more completed jobs */
                        job = IMB_GET_COMPLETED_JOB(mb_mgr);
                }
        }

        return 0;
}

static void
print_fail_context(IMB_MGR *mb_mgr, const IMB_ARCH arch, const struct params_s *params,
                   const struct data *data, const struct safe_check_ctx *safe_ctx)
{
        uint64_t features = 0;

        printf("Failures in\n");
        print_algo_info(params);

        printf("\nTested ");
        (void) imb_get_features(mb_mgr, &features);
        print_tested_arch(features, arch);

        printf("Cipher direction = %s\n",
               (safe_ctx != NULL && safe_ctx->cipher_dir == IMB_DIR_DECRYPT) ? "DECRYPT"
                                                                             : "ENCRYPT");
        if (safe_ctx != NULL) {
                printf("Number of jobs = %u\n", safe_ctx->num_jobs);
                if (!safe_ctx->key_exp_phase) {
                        if (safe_ctx->imix)
                                printf("Buffer size = IMIX (randomized per job)\n");
                        else
                                printf("Buffer size = %u\n", safe_ctx->job_size);
                }
        }
        printf("Key size = %u\n", params->key_size);
        printf("Tag size = %u\n", data->tag_size);
        printf("AAD size = %u\n", params->aad_size);
}

/*
 * @brief Runs number of jobs of a given algorithm and cipher direction and
 *        checks for sensitive data left in registers, stack and memory
 *
 * @return Operation status
 * @retval 0 no sensitive data found
 * @retval -1 operation error (unsupported algorithm, job error, etc.)
 * @retval -2 sensitive data found
 */
static int
do_test(IMB_MGR *mb_mgr, const IMB_ARCH arch, const struct params_s *params, struct data *data,
        const IMB_CIPHER_DIRECTION cipher_dir, const unsigned imix, const unsigned num_jobs,
        struct safe_check_ctx *p_safe_check)
{
        struct job_ctx job_ctx_tab[MAX_NUM_JOBS];
        IMB_JOB job_tab[MAX_NUM_JOBS];
        unsigned i;
        int ret = -1;
        struct cipher_auth_keys *keys = &data->keys;
        const int is_enc = (cipher_dir == IMB_DIR_ENCRYPT);
        const char *dir_str = is_enc ? "encrypting" : "decrypting";

        if (num_jobs == 0 || num_jobs > MAX_NUM_JOBS)
                return -1;

        /*
         * Set keys and plain text to known patterns, so that they can be
         * searched for later on in the registers, stack and MB_MGR structure.
         */
        generate_random_buf(data->cipher_iv, MAX_IV_SIZE);
        generate_random_buf(data->auth_iv, MAX_IV_SIZE);
        generate_random_buf(data->aad, MAX_AAD_SIZE);
        nosimd_memset(data->ciph_key, pattern_cipher_key, MAX_KEY_SIZE);
        nosimd_memset(data->auth_key, pattern_auth_key, MAX_KEY_SIZE);

        for (i = 0; i < num_jobs; i++) {
                /* Job sizes are randomized per job in the IMIX mode */
                const uint32_t buf_size =
                        imix ? generate_imix_job_size(params, DEFAULT_JOB_SIZE_MAX)
                             : params->buf_size;

                set_job_ctx(&job_ctx_tab[i], params, buf_size, data->in_digest[i],
                            data->out_digest[i], data->tag_size, data->test_buf[i],
                            data->src_dst_buf[i]);
        }

        p_safe_check->cipher_dir = cipher_dir;
        p_safe_check->num_jobs = num_jobs;

        /*
         * First use actual key expansion functions and check registers,
         * stack and memory for left over information.
         * Then set a pattern in the expanded key memory to search for later on.
         */
        if (fill_keys(mb_mgr, keys, data->ciph_key, data->auth_key, params, NULL) < 0)
                goto exit;

        if (perform_safe_checks(mb_mgr, arch, p_safe_check,
                                is_enc ? "expanding encryption keys"
                                       : "expanding decryption keys") < 0) {
                p_safe_check->key_exp_phase = 1;
                p_safe_check->cipher_dir = cipher_dir;
                p_safe_check->num_jobs = num_jobs;
                p_safe_check->imix = imix;
                ret = -2;
                goto exit;
        }

        /* Fill the expanded keys with the patterns to search for */
        const struct key_fill_pattern key_pattern = { .cipher_key = (uint8_t) pattern_cipher_key,
                                                      .auth_key = (uint8_t) pattern_auth_key };

        if (fill_keys(mb_mgr, keys, data->ciph_key, data->auth_key, params, &key_pattern) < 0)
                goto exit;

#ifdef PIN_BASED_CEC
        PinBasedCEC_MarkSecret((uintptr_t) keys->enc_keys, sizeof(keys->enc_keys));
        PinBasedCEC_MarkSecret((uintptr_t) keys->dec_keys, sizeof(keys->dec_keys));
        PinBasedCEC_MarkSecret((uintptr_t) &keys->gdata_key, sizeof(keys->gdata_key));
        PinBasedCEC_MarkSecret((uintptr_t) keys->k1_expanded, sizeof(keys->k1_expanded));
        PinBasedCEC_MarkSecret((uintptr_t) keys->k2, sizeof(keys->k2));
        PinBasedCEC_MarkSecret((uintptr_t) keys->k3, sizeof(keys->k3));
        PinBasedCEC_MarkSecret((uintptr_t) keys->ck, sizeof(keys->ck));
        PinBasedCEC_MarkSecret((uintptr_t) keys->nia4_key, sizeof(keys->nia4_key));
#endif

        /*
         * Build and process encrypt jobs.
         * In case of the decrypt direction, this pass produces the cipher text
         * to be used as an input for the decrypt jobs. This way the plain text
         * pattern is not fed into the library as the message to decrypt.
         */
        for (i = 0; i < num_jobs; i++) {
                IMB_JOB *job = &job_tab[i];

                nosimd_memcpy(job_ctx_tab[i].src_dst_buf, job_ctx_tab[i].test_buf,
                              job_ctx_tab[i].buf_size);

                if (fill_job(job, params, job_ctx_tab[i].src_dst_buf, job_ctx_tab[i].in_digest,
                             data->aad, job_ctx_tab[i].buf_size, data->tag_size, IMB_DIR_ENCRYPT,
                             keys, data->cipher_iv, data->auth_iv, i) < 0)
                        goto exit;

                /* Randomize memory for the input digest */
                generate_random_buf(job_ctx_tab[i].in_digest, data->tag_size);

                if (burst_api)
                        imb_set_session(mb_mgr, job);
        }

        if (process_jobs(mb_mgr, job_tab, num_jobs, params, "enc-submit", "enc-flush") != 0)
                goto exit;

        if (!is_enc) {
                /* Build and process decrypt jobs on top of the cipher text */
                for (i = 0; i < num_jobs; i++) {
                        IMB_JOB *job = &job_tab[i];

                        if (fill_job(job, params, job_ctx_tab[i].src_dst_buf,
                                     job_ctx_tab[i].out_digest, data->aad, job_ctx_tab[i].buf_size,
                                     data->tag_size, IMB_DIR_DECRYPT, keys, data->cipher_iv,
                                     data->auth_iv, i) < 0)
                                goto exit;

                        /* Randomize memory for the output digest */
                        generate_random_buf(job_ctx_tab[i].out_digest, data->tag_size);

                        if (burst_api)
                                imb_set_session(mb_mgr, job);
                }

                if (process_jobs(mb_mgr, job_tab, num_jobs, params, "dec-submit", "dec-flush") != 0)
                        goto exit;
        }

#ifdef PIN_BASED_CEC
        PinBasedCEC_ClearSecrets();
#endif

        /*
         * Check that the registers, stack and MB_MGR do not contain any
         * sensitive information after the jobs are returned
         */
        if (perform_safe_checks(mb_mgr, arch, p_safe_check, dir_str) < 0) {
                p_safe_check->cipher_dir = cipher_dir;
                p_safe_check->num_jobs = num_jobs;
                p_safe_check->job_size = job_ctx_tab[0].buf_size;
                p_safe_check->imix = imix;
                ret = -2;
                goto exit;
        }

        ret = 0;

exit:
        /* clear data */
        clear_data(data);

        if (ret == -1)
                print_fail_context(mb_mgr, arch, params, data, NULL);

        return ret;
}

/*
 * Runs safe check for a single buffer size (or mixed job sizes when \a imix
 * is set), for all tag sizes, AAD sizes and cipher directions
 */
static void
test_single(IMB_MGR *mb_mgr, const IMB_ARCH arch, struct params_s *params,
            struct data *variant_data, const uint32_t buf_size, const unsigned imix)
{
        unsigned int i;
        unsigned int num_tag_sizes = 0;
        uint8_t tag_sizes[NUM_TAG_SIZES];
        const uint32_t min_aad_sz = 0;
        uint32_t max_aad_sz, aad_sz;
        static const IMB_CIPHER_DIRECTION dir_tab[] = { IMB_DIR_ENCRYPT, IMB_DIR_DECRYPT };
        /* IMIX tests submit more than one job of a randomized size */
        const unsigned min_num_jobs = imix ? 2 : 1;

        if (params->hash_alg >= IMB_AUTH_NUM) {
                fprintf(stderr, "Invalid hash alg\n");
                printf("FAIL\n");
                exit(EXIT_FAILURE);
        }

        /* IMIX tests focus on mixed job sizes and are run with no AAD */
        if (imix)
                max_aad_sz = 0;
        else if (params->cipher_mode == IMB_CIPHER_GCM)
                max_aad_sz = MAX_GCM_AAD_SIZE;
        else if (params->cipher_mode == IMB_CIPHER_CCM)
                max_aad_sz = MAX_CCM_AAD_SIZE;
        else
                max_aad_sz = 0;

        /* If tag size is defined by user, only test this size */
        if (auth_tag_size != 0) {
                tag_sizes[0] = auth_tag_size;
                num_tag_sizes = 1;
        } else {
                /* If CCM, test all tag sizes supported (4,6,8,10,12,14,16) */
                if (params->hash_alg == IMB_AUTH_AES_CCM) {
                        for (i = 4; i <= 16; i += 2)
                                tag_sizes[num_tag_sizes++] = (uint8_t) i;
                } else {
                        tag_sizes[0] = auth_tag_len_bytes[params->hash_alg - 1];
                        num_tag_sizes = 1;
                }
        }

        for (i = 0; i < num_tag_sizes; i++) {
                variant_data->tag_size = tag_sizes[i];

                for (aad_sz = min_aad_sz; aad_sz <= max_aad_sz; aad_sz++) {
                        params->aad_size = aad_sz;
                        params->buf_size = buf_size;

                        /* Job sizes are randomized per job in the IMIX mode */
                        if (!imix && !is_valid_job_size(params, buf_size))
                                continue;

                        for (unsigned d = 0; d < IMB_DIM(dir_tab); d++) {
                                const IMB_CIPHER_DIRECTION dir = dir_tab[d];

                                /* Skip cipher direction not selected by the user */
                                if (cipher_dirs[dir] == 0)
                                        continue;

                                for (unsigned n = 0; n < DIM(num_jobs_tab); n++) {
                                        const unsigned num_jobs = num_jobs_tab[n];
                                        struct safe_check_ctx safe_ctx1 = { 0 };

                                        /* Skip job numbers not selected by the user */
                                        if (max_num_jobs != 0 && num_jobs != max_num_jobs)
                                                continue;

                                        if (num_jobs < min_num_jobs)
                                                continue;

                                        const int result1 =
                                                do_test(mb_mgr, arch, params, variant_data, dir,
                                                        imix, num_jobs, &safe_ctx1);

                                        if (result1 == -1) {
                                                printf("FAIL\n");
                                                exit(EXIT_FAILURE);
                                        }

                                        if (result1 != -2)
                                                continue;

                                        /*
                                         * Potential match found.
                                         * Change the patterns and retry to
                                         * eliminate false positives.
                                         */
                                        for (uint32_t retry = 0; retry < safe_retries; retry++) {
                                                struct safe_check_ctx safe_ctx2 = { 0 };

                                                generate_patterns();

                                                const int result2 =
                                                        do_test(mb_mgr, arch, params, variant_data,
                                                                dir, imix, num_jobs, &safe_ctx2);

                                                if (result2 == -1) {
                                                        printf("FAIL\n");
                                                        exit(EXIT_FAILURE);
                                                }

                                                if (result2 != -2 ||
                                                    compare_match(&safe_ctx1, &safe_ctx2) != 0)
                                                        break;

                                                if (retry == (safe_retries - 1)) {
                                                        printf("FAIL\n");
                                                        print_patterns();
                                                        print_fail_context(mb_mgr, arch, params,
                                                                           variant_data,
                                                                           &safe_ctx2);
                                                        print_match(&safe_ctx2, safe_ctx2.dir_name);
                                                        exit(EXIT_FAILURE);
                                                }
                                        }
                                }
                        }
                }
        }
}

/* Runs safe check for each buffer size */
static void
process_variant(IMB_MGR *mb_mgr, const IMB_ARCH arch, struct params_s *params,
                struct data *variant_data)
{
#ifdef PIN_BASED_CEC
        const uint32_t sizes = job_sizes[RANGE_MAX];
#else
        const uint32_t sizes = params->num_sizes;
#endif
        uint32_t sz;

        if (verbose) {
                printf("[INFO] ");
                print_algo_info(params);
                printf("\n");
        }

        /* Reset the variant data */
        clear_data(variant_data);

        for (sz = 0; sz < sizes; sz++) {
#ifdef PIN_BASED_CEC
                const uint32_t buf_size = job_sizes[RANGE_MIN];
#else
                const uint32_t buf_size = job_sizes[RANGE_MIN] + (sz * job_sizes[RANGE_STEP]);
#endif

                test_single(mb_mgr, arch, params, variant_data, buf_size, 0);
        }

        /*
         * Perform IMIX tests, where job sizes are randomized per job.
         * Each iteration exercises a new set of job sizes.
         */
        if (imix_enabled)
                for (uint32_t it = 0; it < IMIX_ITER; it++)
                        test_single(mb_mgr, arch, params, variant_data, 0, 1);
}

/* Runs safe check for all algorithms and key sizes on a given architecture */
static void
run_test(const IMB_ARCH arch, struct params_s *params, struct data *variant_data)
{
        IMB_MGR *mb_mgr = alloc_mb_mgr(flags);

        if (mb_mgr == NULL) {
                fprintf(stderr, "MB MGR could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        switch (arch) {
        case IMB_ARCH_SSE:
                init_mb_mgr_sse(mb_mgr);
                break;
        case IMB_ARCH_AVX2:
                init_mb_mgr_avx2(mb_mgr);
                break;
        case IMB_ARCH_AVX512:
                init_mb_mgr_avx512(mb_mgr);
                break;
        case IMB_ARCH_AVX10:
                init_mb_mgr_avx10(mb_mgr);
                break;
        default:
                fprintf(stderr, "Invalid architecture\n");
                free_mb_mgr(mb_mgr);
                exit(EXIT_FAILURE);
        }

        uint64_t features = 0;

        if (imb_get_features(mb_mgr, &features) != 0) {
                fprintf(stderr, "MB MGR get features failure\n");
                free_mb_mgr(mb_mgr);
                exit(EXIT_FAILURE);
        }

        if (features & IMB_FEATURE_SELF_TEST)
                if (!(features & IMB_FEATURE_SELF_TEST_PASS))
                        fprintf(stderr, "SELF-TEST: FAIL\n");

        if (imb_get_errno(mb_mgr) != 0) {
                fprintf(stderr, "Error initializing MB_MGR structure! %s\n",
                        imb_get_strerror(imb_get_errno(mb_mgr)));
                free_mb_mgr(mb_mgr);
                exit(EXIT_FAILURE);
        }

        printf("Testing ");
        print_tested_arch(features, arch);

        if (custom_test) {
                params->key_size = custom_job_params.key_size;
                params->cipher_mode = custom_job_params.cipher_mode;
                params->hash_alg = custom_job_params.hash_alg;
                process_variant(mb_mgr, arch, params, variant_data);
                goto exit;
        }

        IMB_CIPHER_MODE c_mode;

        for (c_mode = IMB_CIPHER_CBC; c_mode < IMB_CIPHER_NUM; c_mode++) {
                IMB_HASH_ALG hash_alg;

                /* Skip IMB_CIPHER_CUSTOM */
                if (c_mode == IMB_CIPHER_CUSTOM)
                        continue;

                params->cipher_mode = c_mode;

                for (hash_alg = IMB_AUTH_HMAC_SHA_1; hash_alg < IMB_AUTH_NUM; hash_alg++) {
                        /* Skip IMB_AUTH_CUSTOM */
                        if (hash_alg == IMB_AUTH_CUSTOM)
                                continue;

                        /* Skip not supported combinations */
                        if (!is_valid_combination(c_mode, hash_alg))
                                continue;

                        params->hash_alg = hash_alg;

                        const uint8_t min_sz = key_sizes[c_mode - 1][0];
                        const uint8_t max_sz = key_sizes[c_mode - 1][1];
                        const uint8_t step_sz = key_sizes[c_mode - 1][2];
                        uint8_t key_sz;

                        for (key_sz = min_sz; key_sz <= max_sz; key_sz += step_sz) {
                                params->key_size = key_sz;
                                process_variant(mb_mgr, arch, params, variant_data);
                        }
                }
        }

exit:
        free_mb_mgr(mb_mgr);
}

/* Prepares data structure for test variants storage and runs the tests */
static void
run_tests(void)
{
        struct params_s params;
        struct data *variant_data = NULL;
        IMB_ARCH arch;
#ifdef PIN_BASED_CEC
        const uint32_t pkt_size = job_sizes[RANGE_MIN];
        const uint32_t num_iter = job_sizes[RANGE_MAX];

        params.num_sizes = 1;
#else
        const uint32_t min_size = job_sizes[RANGE_MIN];
        const uint32_t max_size = job_sizes[RANGE_MAX];
        const uint32_t step_size = job_sizes[RANGE_STEP];

        params.num_sizes = ((max_size - min_size) / step_size) + 1;
#endif

        variant_data = malloc(sizeof(struct data));

        if (variant_data == NULL) {
                fprintf(stderr, "Test data could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        if (verbose) {
#ifdef PIN_BASED_CEC
                printf("Testing buffer size = %u bytes, %u times\n", pkt_size, num_iter);
#else
                if (min_size == max_size)
                        printf("Testing buffer size = %u bytes\n", min_size);
                else
                        printf("Testing buffer sizes from %u to %u "
                               "in steps of %u bytes\n",
                               min_size, max_size, step_size);
#endif
        }

        /* Performing tests for each selected architecture */
        for (arch = IMB_ARCH_SSE; arch < IMB_ARCH_NUM; arch++) {
                if (archs[arch] == 0)
                        continue;
                run_test(arch, &params, variant_data);
        }

        free(variant_data);
}

static void
usage(const char *app_name)
{
        fprintf(stderr,
                "Usage: %s [args], "
                "where args are zero or more\n"
                "-h: print this message\n"
                "-v: verbose, prints extra information\n"
                "--arch: architecture to test (SSE/AVX2/AVX512/AVX10), "
                "default: test all architectures\n"
                "--cipher-dir: cipher direction to test (ENCRYPT/DECRYPT), "
                "default: test both directions\n"
                "--cipher-algo: select cipher algorithm to run on the custom "
                "test\n"
                "--hash-algo: select hash algorithm to run on the custom test\n"
                "--aead-algo: select AEAD algorithm to run on the custom test\n"
                "--no-avx10: don't do AVX10\n"
                "--no-avx512: don't do AVX512\n"
                "--no-avx2: don't do AVX2\n"
                "--no-sse: don't do SSE\n"
                "--shani-on: use SHA extensions, default: auto-detect\n"
                "--shani-off: don't use SHA extensions\n"
                "--gfni-on: use Galois Field extensions, default: auto-detect\n"
                "--gfni-off: don't use Galois Field extensions\n"
                "--cipher-iv-size: size of cipher IV\n"
                "--auth-iv-size: size of authentication IV\n"
                "--tag-size: size of authentication tag\n"
                "--job-size: size of the cipher & MAC job in bytes. "
#ifndef PIN_BASED_CEC
                "It can be:\n"
                "            - single value: test single size\n"
                "            - range: test multiple sizes with following format"
                " min:step:max (e.g. 16:16:256)\n"
#else
                "            - size:1:num_iterations format\n"
                "              e.g. 64:1:128 => repeat 128 times operation on a 64 byte buffer\n"
#endif
                "--num-jobs: number of jobs to submit in one go "
                "(default: test 1, 3, 4, 5, 7, 8, 9, 15, 16 and 17 jobs; maximum = %d)\n"
                "--imix: additionally scan jobs of mixed (randomized) sizes submitted in one go, "
                "%d iterations per algorithm\n"
                "--safe-retries: number of retries with new patterns to confirm "
                "a match (default %d, maximum %d)\n"
                "--avx-sse: if XGETBV is available then check for potential "
                "AVX-SSE transition problems\n"
                "--burst-api: use burst API instead of single job API\n"
                "--offset: offset in bytes where the plaintext will be placed from the start of "
                "the allocated buffer (default 4 bytes)\n",
                app_name, MAX_NUM_JOBS, IMIX_ITER, DEFAULT_SAFE_RETRIES, MAX_SAFE_RETRIES);
}

int
main(int argc, char *argv[])
{
        int i;
        unsigned int arch_id;
        uint8_t arch_support[IMB_ARCH_NUM];
        const union params *values;
        unsigned int cipher_algo_set = 0;
        unsigned int hash_algo_set = 0;
        unsigned int aead_algo_set = 0;

        for (i = 1; i < argc; i++)
                if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                        usage(argv[0]);
                        return EXIT_SUCCESS;
                } else if (strcmp(argv[i], "-v") == 0) {
                        verbose = 1;
                } else if (update_flags_and_archs(argv[i], archs, &flags)) {
                        /* architecture and feature flags updated */
                } else if (strcmp(argv[i], "--arch") == 0) {
                        /* Use index 1 to skip arch_str_map.name = "NONE" */
                        values = check_string_arg(argv[i], argv[i + 1], arch_str_map + 1,
                                                  num_arch_str_map - 1);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        /*
                         * Disable all the other architectures
                         * and enable only the specified
                         */
                        nosimd_memset(archs, 0, sizeof(archs));
                        archs[values->arch_type] = 1;
                        i++;
                } else if (strcmp(argv[i], "--cipher-dir") == 0) {
                        values = check_string_arg(argv[i], argv[i + 1], cipher_dir_str_map,
                                                  num_cipher_dir_str_map);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        /* Disable the other cipher direction */
                        nosimd_memset(cipher_dirs, 0, sizeof(cipher_dirs));
                        cipher_dirs[values->cipher_dir] = 1;
                        i++;
                } else if (strcmp(argv[i], "--cipher-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i + 1], cipher_algo_str_map,
                                                  num_cipher_algo_str_map);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.cipher_mode = values->job_params.cipher_mode;
                        custom_job_params.key_size = values->job_params.key_size;
                        custom_test = 1;
                        cipher_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--hash-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i + 1], hash_algo_str_map,
                                                  num_hash_algo_str_map);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.hash_alg = values->job_params.hash_alg;
                        custom_test = 1;
                        hash_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--aead-algo") == 0) {
                        values = check_string_arg(argv[i], argv[i + 1], aead_algo_str_map,
                                                  num_aead_algo_str_map);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        custom_job_params.cipher_mode = values->job_params.cipher_mode;
                        custom_job_params.key_size = values->job_params.key_size;
                        custom_job_params.hash_alg = values->job_params.hash_alg;
                        custom_test = 1;
                        aead_algo_set = 1;
                        i++;
                } else if (strcmp(argv[i], "--job-size") == 0) {
                        /* Try parsing the argument as a range first */
                        i = parse_range((const char *const *) argv, i, argc, job_sizes);
                        if (job_sizes[RANGE_MAX] > JOB_SIZE_TOP) {
                                fprintf(stderr, "Invalid job size %u (max %d)\n",
                                        (unsigned) job_sizes[RANGE_MAX], JOB_SIZE_TOP);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--cipher-iv-size") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &cipher_iv_size,
                                             sizeof(cipher_iv_size));
                        if (cipher_iv_size > MAX_IV_SIZE) {
                                fprintf(stderr,
                                        "IV size cannot be "
                                        "higher than %d\n",
                                        MAX_IV_SIZE);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--auth-iv-size") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &auth_iv_size,
                                             sizeof(auth_iv_size));
                        if (auth_iv_size > MAX_IV_SIZE) {
                                fprintf(stderr,
                                        "IV size cannot be "
                                        "higher than %d\n",
                                        MAX_IV_SIZE);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--tag-size") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &auth_tag_size,
                                             sizeof(auth_tag_size));
                        if (auth_tag_size > MAX_DIGEST_SIZE) {
                                fprintf(stderr,
                                        "Tag size cannot be "
                                        "higher than %d\n",
                                        MAX_DIGEST_SIZE);
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--num-jobs") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &max_num_jobs,
                                             sizeof(max_num_jobs));
                        if (max_num_jobs == 0 || max_num_jobs > MAX_NUM_JOBS) {
                                fprintf(stderr, "Number of jobs must be in 1..%d range\n",
                                        MAX_NUM_JOBS);
                                return EXIT_FAILURE;
                        }
                        unsigned n;

                        for (n = 0; n < DIM(num_jobs_tab); n++)
                                if (num_jobs_tab[n] == max_num_jobs)
                                        break;

                        if (n >= DIM(num_jobs_tab)) {
                                fprintf(stderr,
                                        "Number of jobs %u is not one of the "
                                        "supported values: ",
                                        max_num_jobs);
                                for (n = 0; n < DIM(num_jobs_tab); n++)
                                        fprintf(stderr, "%u ", num_jobs_tab[n]);
                                fprintf(stderr, "\n");
                                return EXIT_FAILURE;
                        }
                } else if (strcmp(argv[i], "--imix") == 0) {
                        imix_enabled = 1;
                } else if (strcmp(argv[i], "--safe-retries") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &safe_retries,
                                             sizeof(safe_retries));
                        if (safe_retries > MAX_SAFE_RETRIES) {
                                fprintf(stderr,
                                        "Number of retries cannot be "
                                        "higher than %d\n",
                                        MAX_SAFE_RETRIES);
                                return EXIT_FAILURE;
                        }
                        if (safe_retries == 0)
                                safe_retries = 1;
                } else if (strcmp(argv[i], "--avx-sse") == 0) {
                        is_avx_sse_check_possible = avx_sse_detectability();
                        if (!is_avx_sse_check_possible)
                                fprintf(stderr, "XGETBV not available\n");
                } else if (strcmp(argv[i], "--burst-api") == 0) {
                        burst_api = 1;
                } else if (strcmp(argv[i], "--offset") == 0) {
                        i = get_next_num_arg((const char *const *) argv, i, argc, &offset,
                                             sizeof(offset));
                } else {
                        usage(argv[0]);
                        return EXIT_FAILURE;
                }

        if (imix_enabled && max_num_jobs == 1) {
                fprintf(stderr, "IMIX tests require more than one job submitted in one go\n");
                return EXIT_FAILURE;
        }

        if (custom_test) {
                if (aead_algo_set && (cipher_algo_set || hash_algo_set)) {
                        fprintf(stderr, "AEAD algorithm cannot be used "
                                        "combined with another cipher/hash "
                                        "algorithm\n");
                        return EXIT_FAILURE;
                }
        }

        if (job_sizes[RANGE_MIN] == 0 && !aead_algo_set) {
                fprintf(stderr, "Buffer size cannot be 0 unless only "
                                "an AEAD algorithm is tested\n");
                return EXIT_FAILURE;
        }

        /* detect available architectures and features */
        if (detect_arch(arch_support, flags) < 0)
                return EXIT_FAILURE;

        /* disable tests depending on instruction sets supported */
        for (arch_id = IMB_ARCH_SSE; arch_id < IMB_ARCH_NUM; arch_id++) {
                if (arch_support[arch_id] == 0) {
                        archs[arch_id] = 0;
                        fprintf(stderr, "%s not supported. Disabling %s tests\n",
                                arch_str_map[arch_id].name, arch_str_map[arch_id].name);
                }
        }

        IMB_MGR *p_mgr = alloc_mb_mgr(flags);

        if (p_mgr == NULL) {
                fprintf(stderr, "Error allocating MB_MGR structure!\n");
                return EXIT_FAILURE;
        }

        uint64_t features = 0;
        const int ret = imb_get_features(p_mgr, &features);

        if (ret != 0) {
                printf("Error retrieving MB_MGR features! %s\n", imb_get_strerror(ret));
                free_mb_mgr(p_mgr);
                return EXIT_FAILURE;
        }

        if ((features & IMB_FEATURE_SAFE_DATA) == 0) {
                fprintf(stderr, "Library needs to be compiled with SAFE_DATA "
                                "to run the safe check tests\n");
                free_mb_mgr(p_mgr);
                return EXIT_FAILURE;
        }
        free_mb_mgr(p_mgr);

        srand(SEED);

        generate_patterns();

        run_tests();

        fprintf(stdout, "All tests passed\n");

        return EXIT_SUCCESS;
}
