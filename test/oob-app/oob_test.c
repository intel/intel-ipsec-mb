/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

/**
 * @brief Out-of-bounds memory access regression test
 *
 * Verifies that submitting cipher, hash and AEAD jobs through checked and
 * NOCHECK single-job, type-specific burst and generic burst submit paths
 * does not read or write past the declared message boundaries. The same is
 * verified for the direct PQC (ML-DSA and ML-KEM) APIs.
 *
 * Technique: each data buffer (src, dst, AAD, tag, IV) is placed immediately
 * adjacent to a guard page (PROT_NONE / PAGE_NOACCESS).
 *
 *   OVERRUN test:  [ data ][ GUARD ]  data ends at the guard boundary
 *   UNDERRUN test: [ GUARD ][ data ]  data starts at the guard boundary
 *
 * Any read or write that extends beyond the declared message length triggers a
 * hardware page fault (SIGSEGV / EXCEPTION_ACCESS_VIOLATION), which is caught
 * and reported as a test failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>
#include <assert.h>

#include "guard_mem.h"
#include <intel-ipsec-mb.h>
#include "utils.h"

/* ========================================================================== */
/* SIGSEGV / Access Violation handler                                         */
/* ========================================================================== */

#ifdef _WIN32
static jmp_buf test_jmp_env;

static LONG WINAPI
test_exception_handler(EXCEPTION_POINTERS *ep)
{
        if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
                longjmp(test_jmp_env, 1);
        }
        return EXCEPTION_CONTINUE_SEARCH;
}

#define TEST_SETJMP() setjmp(test_jmp_env)
#else
static sigjmp_buf test_jmp_env;

static void
test_sigsegv_handler(int signum) __attribute__((noreturn));

/**
 * @brief SIGSEGV signal handler - longjmps back to the test checkpoint.
 *
 * SA_NODEFER prevents the kernel from blocking SIGSEGV on handler entry,
 * so no manual sigprocmask unblock or handler re-install is needed.
 *
 * @param [in] signum signal number (unused)
 */
static void
test_sigsegv_handler(int signum)
{
        (void) signum;
        siglongjmp(test_jmp_env, 1);
}

#define TEST_SETJMP() sigsetjmp(test_jmp_env, 0)
#endif

/* ========================================================================== */
/* Constants and shared buffers                                               */
/* ========================================================================== */

#define IV_SIZE_MAX          16   /**< max IV size across all algorithms */
#define TAG_SIZE_MAX         64   /**< max auth tag size (SHA-512 = 64 bytes) */
#define MAX_TEST_LEN_DEFAULT 2048 /**< default maximum message length to test */
#define MAX_FAIL_PRINT       5    /**< max SEGFAULT messages per test vector */
#define MAX_VEC_FAIL         5    /**< max failures per vector before skipping */

/** Configurable maximum test length (set via --max-len CLI option) */
static unsigned max_test_len = MAX_TEST_LEN_DEFAULT;

/**
 * Per-vector failure output limiter. Set to MAX_FAIL_PRINT before each vector
 * loop; test functions decrement and stop printing once it reaches zero.
 */
static int fail_print_remaining = 0;

/**
 * Large aligned buffer for key-related pointers (enc_keys, dec_keys,
 * HMAC ipad/opad, XCBC/CMAC keys, GCM key data, etc.).
 * Must be large enough for struct gcm_key_data and 64-byte aligned.
 */
#ifdef _MSC_VER
__declspec(align(64)) static uint8_t key_store[8192];
#else
static uint8_t key_store[8192] __attribute__((aligned(64)));
#endif

/** 3DES key schedule pointers (3 x key schedule) */
static const void *ks_ptrs[3];

/* ========================================================================== */
/* OOB test direction and buffer helpers                                      */
/* ========================================================================== */

/** Out-of-bounds test direction */
enum oob_type {
        OOB_OVERRUN = 0,  /**< guard page after data (overrun detection) */
        OOB_UNDERRUN = 1, /**< guard page before data (underrun detection) */
        OOB_NUM = 2,
};

static const char *oob_type_name[] = { "overrun", "underrun" };

/**
 * @brief Get a data pointer for OOB testing from a guard_mem allocation.
 *
 * For overrun: returns a pointer such that ptr + len = guard page boundary.
 * For underrun: returns a pointer at the start of usable (right after guard).
 *
 * @param [in] gm   guard memory allocation
 * @param [in] len  data length in bytes
 * @param [in] oob  OOB test direction
 *
 * @return pointer to the data buffer
 */
static uint8_t *
oob_buf(const struct guard_mem *gm, const size_t len, const enum oob_type oob)
{
        assert(len <= gm->size);

        if (oob == OOB_OVERRUN)
                return (uint8_t *) gm->usable + gm->size - len;
        else
                return (uint8_t *) gm->usable;
}

/**
 * @brief Collection of guard memory allocations for OOB testing.
 *
 * Each buffer has guard pages on both sides: [Guard][RW][Guard].
 * Data is positioned at the end (overrun) or start (underrun) of the RW region.
 */
struct oob_mem {
        struct guard_mem src; /**< src buffer */
        struct guard_mem dst; /**< dst buffer */
        struct guard_mem aad; /**< AAD buffer */
        struct guard_mem tag; /**< auth tag buffer */
        struct guard_mem iv;  /**< IV buffer */
};

/**
 * @brief Allocate all guard memory regions for OOB testing.
 *
 * @param [in/out] mem      OOB memory structure to initialize
 * @param [in]     buf_size usable size for each allocation
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 failure
 */
static int
oob_mem_alloc(struct oob_mem *mem, const size_t buf_size)
{
        memset(mem, 0, sizeof(*mem));

        if (guard_mem_alloc(&mem->src, buf_size) != 0 ||
            guard_mem_alloc(&mem->dst, buf_size) != 0 ||
            guard_mem_alloc(&mem->aad, buf_size) != 0 ||
            guard_mem_alloc(&mem->tag, buf_size) != 0 || guard_mem_alloc(&mem->iv, buf_size) != 0)
                return -1;

        return 0;
}

/**
 * @brief Free all guard memory regions.
 *
 * @param [in] mem OOB memory structure to free
 */
static void
oob_mem_free(struct oob_mem *mem)
{
        guard_mem_free(&mem->src);
        guard_mem_free(&mem->dst);
        guard_mem_free(&mem->aad);
        guard_mem_free(&mem->tag);
        guard_mem_free(&mem->iv);
}

/* ========================================================================== */
/* Architecture init helper                                                   */
/* ========================================================================== */

/**
 * @brief Initialize \a mgr for a specific architecture.
 *
 * @param [in,out] mgr  multi-buffer manager to initialize
 * @param [in]     arch target architecture
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 unsupported architecture
 */
static int
init_mgr_for_arch(IMB_MGR *mgr, const IMB_ARCH arch)
{
        switch (arch) {
        case IMB_ARCH_SSE:
                init_mb_mgr_sse(mgr);
                break;
        case IMB_ARCH_AVX2:
                init_mb_mgr_avx2(mgr);
                break;
        case IMB_ARCH_AVX512:
                init_mb_mgr_avx512(mgr);
                break;
        case IMB_ARCH_AVX10:
                init_mb_mgr_avx10(mgr);
                break;
        default:
                return -1;
        }

        const int ret = imb_get_errno(mgr);

        if (ret != 0) {
                printf("oob-app: %s\n", imb_get_strerror(ret));
                return -1;
        }

        return 0;
}

/* ========================================================================== */
/* Cipher test vectors and functions                                          */
/* ========================================================================== */

/** Cipher test vector descriptor */
struct cipher_test_vec {
        const char *name;         /**< test name for display */
        IMB_CIPHER_MODE cipher;   /**< cipher mode to test */
        IMB_CIPHER_DIRECTION dir; /**< encrypt or decrypt */
        unsigned key_len;         /**< key length in bytes */
        unsigned iv_len;          /**< IV length in bytes */
        unsigned msg_len;         /**< message length (set by runner) */
        unsigned min_len;         /**< minimum test length in bytes */
        unsigned step;            /**< length increment step */
};

/** Table of cipher algorithms to test */
static const struct cipher_test_vec cipher_tests[] = {
        /* AES-CBC (block size 16) */
        { "AES-128-CBC-DEC", IMB_CIPHER_CBC, IMB_DIR_DECRYPT, 16, 16, 16, 16, 16 },
        { "AES-192-CBC-DEC", IMB_CIPHER_CBC, IMB_DIR_DECRYPT, 24, 16, 16, 16, 16 },
        { "AES-256-CBC-DEC", IMB_CIPHER_CBC, IMB_DIR_DECRYPT, 32, 16, 16, 16, 16 },
        { "AES-128-CBC-ENC", IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, 16, 16, 16, 16, 16 },
        { "AES-192-CBC-ENC", IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, 24, 16, 16, 16, 16 },
        { "AES-256-CBC-ENC", IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, 32, 16, 16, 16, 16 },
        /* AES-CTR (stream) */
        { "AES-128-CTR-ENC", IMB_CIPHER_CNTR, IMB_DIR_ENCRYPT, 16, 16, 1, 1, 1 },
        { "AES-192-CTR-ENC", IMB_CIPHER_CNTR, IMB_DIR_ENCRYPT, 24, 16, 1, 1, 1 },
        { "AES-256-CTR-ENC", IMB_CIPHER_CNTR, IMB_DIR_ENCRYPT, 32, 16, 1, 1, 1 },
        { "AES-128-CTR-DEC", IMB_CIPHER_CNTR, IMB_DIR_DECRYPT, 16, 16, 1, 1, 1 },
        { "AES-192-CTR-DEC", IMB_CIPHER_CNTR, IMB_DIR_DECRYPT, 24, 16, 1, 1, 1 },
        { "AES-256-CTR-DEC", IMB_CIPHER_CNTR, IMB_DIR_DECRYPT, 32, 16, 1, 1, 1 },
        /* AES-ECB (block size 16) */
        { "AES-128-ECB-ENC", IMB_CIPHER_ECB, IMB_DIR_ENCRYPT, 16, 0, 16, 16, 16 },
        { "AES-128-ECB-DEC", IMB_CIPHER_ECB, IMB_DIR_DECRYPT, 16, 0, 16, 16, 16 },
        { "AES-192-ECB-ENC", IMB_CIPHER_ECB, IMB_DIR_ENCRYPT, 24, 0, 16, 16, 16 },
        { "AES-192-ECB-DEC", IMB_CIPHER_ECB, IMB_DIR_DECRYPT, 24, 0, 16, 16, 16 },
        { "AES-256-ECB-ENC", IMB_CIPHER_ECB, IMB_DIR_ENCRYPT, 32, 0, 16, 16, 16 },
        { "AES-256-ECB-DEC", IMB_CIPHER_ECB, IMB_DIR_DECRYPT, 32, 0, 16, 16, 16 },
        /* AES-CFB (stream) */
        { "AES-128-CFB-ENC", IMB_CIPHER_CFB, IMB_DIR_ENCRYPT, 16, 16, 1, 1, 1 },
        { "AES-128-CFB-DEC", IMB_CIPHER_CFB, IMB_DIR_DECRYPT, 16, 16, 1, 1, 1 },
        /* DES-CBC (block size 8) */
        { "DES-CBC-ENC", IMB_CIPHER_DES, IMB_DIR_ENCRYPT, 8, 8, 8, 8, 8 },
        { "DES-CBC-DEC", IMB_CIPHER_DES, IMB_DIR_DECRYPT, 8, 8, 8, 8, 8 },
        /* 3DES-CBC (block size 8) */
        { "3DES-CBC-ENC", IMB_CIPHER_DES3, IMB_DIR_ENCRYPT, 24, 8, 8, 8, 8 },
        { "3DES-CBC-DEC", IMB_CIPHER_DES3, IMB_DIR_DECRYPT, 24, 8, 8, 8, 8 },
        /* DOCSIS-DES (partial blocks) */
        { "DOCSIS-DES-ENC", IMB_CIPHER_DOCSIS_DES, IMB_DIR_ENCRYPT, 8, 8, 1, 1, 1 },
        { "DOCSIS-DES-DEC", IMB_CIPHER_DOCSIS_DES, IMB_DIR_DECRYPT, 8, 8, 1, 1, 1 },
        /* DOCSIS-SEC-BPI (partial blocks) */
        { "DOCSIS-BPI-ENC", IMB_CIPHER_DOCSIS_SEC_BPI, IMB_DIR_ENCRYPT, 16, 16, 1, 1, 1 },
        { "DOCSIS-BPI-DEC", IMB_CIPHER_DOCSIS_SEC_BPI, IMB_DIR_DECRYPT, 16, 16, 1, 1, 1 },
        /* CHACHA20 (stream) */
        { "CHACHA20-ENC", IMB_CIPHER_CHACHA20, IMB_DIR_ENCRYPT, 32, 12, 1, 1, 1 },
        { "CHACHA20-DEC", IMB_CIPHER_CHACHA20, IMB_DIR_DECRYPT, 32, 12, 1, 1, 1 },
        /* SM4-ECB (block size 16) */
        { "SM4-ECB-ENC", IMB_CIPHER_SM4_ECB, IMB_DIR_ENCRYPT, 16, 0, 16, 16, 16 },
        { "SM4-ECB-DEC", IMB_CIPHER_SM4_ECB, IMB_DIR_DECRYPT, 16, 0, 16, 16, 16 },
        /* SM4-CBC (block size 16) */
        { "SM4-CBC-ENC", IMB_CIPHER_SM4_CBC, IMB_DIR_ENCRYPT, 16, 16, 16, 16, 16 },
        { "SM4-CBC-DEC", IMB_CIPHER_SM4_CBC, IMB_DIR_DECRYPT, 16, 16, 16, 16, 16 },
        /* SM4-CTR (stream) */
        { "SM4-CTR-ENC", IMB_CIPHER_SM4_CNTR, IMB_DIR_ENCRYPT, 16, 16, 1, 1, 1 },
        { "SM4-CTR-DEC", IMB_CIPHER_SM4_CNTR, IMB_DIR_DECRYPT, 16, 16, 1, 1, 1 },
        /* ZUC-EEA3 (stream) */
        { "ZUC-EEA3-ENC", IMB_CIPHER_ZUC_EEA3, IMB_DIR_ENCRYPT, 16, 16, 1, 1, 1 },
        { "ZUC-EEA3-DEC", IMB_CIPHER_ZUC_EEA3, IMB_DIR_DECRYPT, 16, 16, 1, 1, 1 },
        /* SNOW3G-UEA2 (stream) */
        { "SNOW3G-UEA2-ENC", IMB_CIPHER_SNOW3G_UEA2, IMB_DIR_ENCRYPT, 16, 16, 1, 1, 1 },
        { "SNOW3G-UEA2-DEC", IMB_CIPHER_SNOW3G_UEA2, IMB_DIR_DECRYPT, 16, 16, 1, 1, 1 },
        /* KASUMI-UEA1 (stream) */
        { "KASUMI-UEA1-ENC", IMB_CIPHER_KASUMI_UEA1, IMB_DIR_ENCRYPT, 16, 8, 1, 1, 1 },
        { "KASUMI-UEA1-DEC", IMB_CIPHER_KASUMI_UEA1, IMB_DIR_DECRYPT, 16, 8, 1, 1, 1 },
        /* AES-NEA5 (stream) */
        { "AES-NEA5-ENC", IMB_CIPHER_AES_NEA5, IMB_DIR_ENCRYPT, 32, 16, 1, 1, 1 },
        { "AES-NEA5-DEC", IMB_CIPHER_AES_NEA5, IMB_DIR_DECRYPT, 32, 16, 1, 1, 1 },
        /* ZUC-NEA6 (stream) */
        { "ZUC-NEA6-ENC", IMB_CIPHER_ZUC_NEA6, IMB_DIR_ENCRYPT, 32, 16, 1, 1, 1 },
        { "ZUC-NEA6-DEC", IMB_CIPHER_ZUC_NEA6, IMB_DIR_DECRYPT, 32, 16, 1, 1, 1 },
        /* SNOW5G-NEA4 (stream) */
        { "SNOW5G-NEA4-ENC", IMB_CIPHER_SNOW5G_NEA4, IMB_DIR_ENCRYPT, 32, 16, 1, 1, 1 },
        { "SNOW5G-NEA4-DEC", IMB_CIPHER_SNOW5G_NEA4, IMB_DIR_DECRYPT, 32, 16, 1, 1, 1 },
};

/**
 * @brief Set up a cipher job for OOB testing.
 *
 * @param [out] job  job structure to configure
 * @param [in]  tv   cipher test vector descriptor
 * @param [in]  src  source pointer (guard-protected)
 * @param [in]  dst  destination pointer (guard-protected)
 * @param [in]  iv   IV buffer (valid memory)
 */
static void
setup_cipher_job(IMB_JOB *job, const struct cipher_test_vec *tv, const uint8_t *src, uint8_t *dst,
                 const uint8_t *iv)
{
        memset(job, 0, sizeof(*job));
        job->cipher_mode = tv->cipher;
        job->cipher_direction = tv->dir;
        job->chain_order = IMB_ORDER_CIPHER_HASH;
        job->src = src;
        job->dst = dst;
        job->iv = iv;
        job->iv_len_in_bytes = tv->iv_len;
        job->hash_alg = IMB_AUTH_NULL;
        job->key_len_in_bytes = tv->key_len;

        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = tv->msg_len;

        if (tv->cipher == IMB_CIPHER_DES3) {
                job->enc_keys = ks_ptrs;
                job->dec_keys = ks_ptrs;
        } else {
                job->enc_keys = key_store;
                job->dec_keys = key_store;
        }
}

/**
 * @brief Buffer pointers for OOB tests.
 *
 * Declared volatile in test functions so values survive sigsetjmp/longjmp.
 */
struct test_bufs {
        uint8_t *src;
        uint8_t *dst;
        uint8_t *tag;
        uint8_t *iv;
        uint8_t *aad;
};

/**
 * @brief Set up guard-page-backed OOB buffers with fill patterns.
 *
 * @param [out] b         buffer pointers (written via volatile pointer)
 * @param [in]  mem       OOB memory allocations
 * @param [in]  oob       overrun or underrun
 * @param [in]  msg_len   message (src/dst) length
 * @param [in]  iv_len    IV length (0 to skip)
 * @param [in]  tag_len   tag length (0 to skip)
 * @param [in]  aad_len   AAD length (0 to skip)
 * @param [in]  need_dst  non-zero to allocate dst buffer
 *
 * Fills: src=0xCC, dst=0x00, iv=0xBB, tag=0x00, aad=0xDD.
 */
static void
setup_oob_bufs(volatile struct test_bufs *b, struct oob_mem *mem, const enum oob_type oob,
               const unsigned msg_len, const unsigned iv_len, const unsigned tag_len,
               const unsigned aad_len, const int need_dst)
{
        b->src = oob_buf(&mem->src, msg_len, oob);
        memset(b->src, 0xCC, msg_len);

        if (need_dst) {
                b->dst = oob_buf(&mem->dst, msg_len, oob);
                memset(b->dst, 0x00, msg_len);
        } else {
                b->dst = NULL;
        }

        b->iv = oob_buf(&mem->iv, iv_len, oob);
        memset(b->iv, 0xBB, iv_len);

        b->tag = oob_buf(&mem->tag, tag_len, oob);
        memset(b->tag, 0, tag_len);

        b->aad = oob_buf(&mem->aad, aad_len, oob);
        memset(b->aad, 0xDD, aad_len);
}

/**
 * @brief Test cipher OOB via JOB API.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] tv          cipher test vector
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction (overrun / underrun)
 * @param [in] use_nocheck non-zero to use NOCHECK API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail (segfault or error)
 */
static int
test_cipher_oob(IMB_MGR *mgr, const struct cipher_test_vec *tv, struct oob_mem *mem,
                const enum oob_type oob, const int use_nocheck)
{
        volatile struct test_bufs b;

        setup_oob_bufs(&b, mem, oob, tv->msg_len, tv->iv_len, 0, 0, 1);

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u SEGFAULT during %s submit (%s)\n", tv->name,
                               tv->msg_len, use_nocheck ? "NOCHECK" : "CHECKED",
                               oob_type_name[oob]);
                }
                return -1;
        }

        IMB_JOB *job = IMB_GET_NEXT_JOB(mgr);

        if (job == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_JOB returned NULL\n", tv->name);
                return -1;
        }

        setup_cipher_job(job, tv, b.src, b.dst, b.iv);

        if (use_nocheck)
                job = IMB_SUBMIT_JOB_NOCHECK(mgr);
        else
                job = IMB_SUBMIT_JOB(mgr);

        (void) job;

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        return 0;
}

/**
 * @brief Test cipher OOB via type-specific burst API.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] tv          cipher test vector
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction
 * @param [in] use_nocheck non-zero to use NOCHECK API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_cipher_burst_oob(IMB_MGR *mgr, const struct cipher_test_vec *tv, struct oob_mem *mem,
                      const enum oob_type oob, const int use_nocheck)
{
        volatile struct test_bufs b;
        IMB_JOB jobs[1];

        setup_oob_bufs(&b, mem, oob, tv->msg_len, tv->iv_len, 0, 0, 1);

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u (burst) SEGFAULT during %s submit (%s)\n",
                               tv->name, tv->msg_len, use_nocheck ? "NOCHECK" : "CHECKED",
                               oob_type_name[oob]);
                }
                return -1;
        }

        setup_cipher_job(&jobs[0], tv, b.src, b.dst, b.iv);

        if (use_nocheck)
                IMB_SUBMIT_CIPHER_BURST_NOCHECK(mgr, jobs, 1, tv->cipher, tv->dir, tv->key_len);
        else
                IMB_SUBMIT_CIPHER_BURST(mgr, jobs, 1, tv->cipher, tv->dir, tv->key_len);

        return 0;
}

/**
 * @brief Test cipher OOB via generic burst API.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] tv          cipher test vector
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction
 * @param [in] use_nocheck non-zero to use NOCHECK API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_cipher_generic_burst_oob(IMB_MGR *mgr, const struct cipher_test_vec *tv, struct oob_mem *mem,
                              const enum oob_type oob, const int use_nocheck)
{
        volatile struct test_bufs b;
        IMB_JOB *jobs[1];

        setup_oob_bufs(&b, mem, oob, tv->msg_len, tv->iv_len, 0, 0, 1);

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u (generic burst) SEGFAULT during %s submit (%s)\n",
                               tv->name, tv->msg_len, use_nocheck ? "NOCHECK" : "CHECKED",
                               oob_type_name[oob]);
                }
                return -1;
        }

        const uint32_t n = IMB_GET_NEXT_BURST(mgr, 1, jobs);

        if (n == 0 || jobs[0] == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_BURST returned 0\n", tv->name);
                return -1;
        }

        setup_cipher_job(jobs[0], tv, b.src, b.dst, b.iv);
        imb_set_session(mgr, jobs[0]);

        if (use_nocheck)
                IMB_SUBMIT_BURST_NOCHECK(mgr, 1, jobs);
        else
                IMB_SUBMIT_BURST(mgr, 1, jobs);

        IMB_FLUSH_BURST(mgr, 1, jobs);

        return 0;
}

/* ========================================================================== */
/* Hash test vectors and functions                                            */
/* ========================================================================== */

/** Indicates which union fields to populate in the job for a given hash */
enum hash_setup {
        HASH_PLAIN,       /**< no special union fields (SHA, CRC, SHA3, etc.) */
        HASH_HMAC,        /**< u.HMAC ipad/opad */
        HASH_XCBC,        /**< u.XCBC k1/k2/k3 */
        HASH_CMAC,        /**< u.CMAC key_expanded/skey1/skey2 */
        HASH_GMAC,        /**< u.GMAC key/iv/iv_len */
        HASH_GHASH,       /**< u.GHASH key/init_tag */
        HASH_POLY1305,    /**< u.POLY1305 key */
        HASH_ZUC,         /**< u.ZUC_EIA3 key/iv */
        HASH_SNOW3G,      /**< u.SNOW3G_UIA2 key/iv */
        HASH_KASUMI,      /**< u.KASUMI_UIA1 key */
        HASH_AES_NIA5,    /**< u.AES_NIA5 expanded_auth_key/iv */
        HASH_SNOW5G_NIA4, /**< u.SNOW5G_NIA4 key/iv */
};

/** Hash test vector descriptor */
struct hash_test_vec {
        const char *name;      /**< test name for display */
        IMB_HASH_ALG hash;     /**< hash algorithm to test */
        unsigned tag_len;      /**< authentication tag length in bytes */
        unsigned tag_min;      /**< minimum tag length for sweep (0 = fixed only) */
        unsigned tag_max;      /**< maximum tag length for sweep (0 = fixed only) */
        unsigned tag_step;     /**< tag length increment step (0 = fixed only) */
        unsigned iv_len;       /**< IV length in bytes (0 if not used) */
        enum hash_setup setup; /**< which union fields to configure */
        unsigned msg_len;      /**< message length (set by runner) */
        unsigned min_len;      /**< minimum test length in bytes */
        unsigned step;         /**< length increment step */
};

/** Table of hash algorithms to test */
static const struct hash_test_vec hash_tests[] = {
        /* HMAC -- tag range 4..digest_len, step 1 */
        { "HMAC-SHA-1", IMB_AUTH_HMAC_SHA_1, 12, 4, 20, 1, 0, HASH_HMAC, 1, 1, 1 },
        { "HMAC-SHA-224", IMB_AUTH_HMAC_SHA_224, 14, 4, 28, 1, 0, HASH_HMAC, 1, 1, 1 },
        { "HMAC-SHA-256", IMB_AUTH_HMAC_SHA_256, 16, 4, 32, 1, 0, HASH_HMAC, 1, 1, 1 },
        { "HMAC-SHA-384", IMB_AUTH_HMAC_SHA_384, 24, 4, 48, 1, 0, HASH_HMAC, 1, 1, 1 },
        { "HMAC-SHA-512", IMB_AUTH_HMAC_SHA_512, 32, 4, 64, 1, 0, HASH_HMAC, 1, 1, 1 },
        /* HMAC-MD5 -- only 12 (ipsec) or 16 (fips) accepted */
        { "HMAC-MD5", IMB_AUTH_MD5, 12, 12, 16, 4, 0, HASH_HMAC, 1, 1, 1 },
        /* HMAC-SM3 -- tag range 1..32, step 1 */
        { "HMAC-SM3", IMB_AUTH_HMAC_SM3, 32, 1, 32, 1, 0, HASH_HMAC, 1, 1, 1 },
        /* SHA (plain) -- fixed tag size only */
        { "SHA-1", IMB_AUTH_SHA_1, 20, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "SHA-224", IMB_AUTH_SHA_224, 28, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "SHA-256", IMB_AUTH_SHA_256, 32, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "SHA-384", IMB_AUTH_SHA_384, 48, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "SHA-512", IMB_AUTH_SHA_512, 64, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        /* SM3 -- tag range 1..32, step 1 */
        { "SM3", IMB_AUTH_SM3, 32, 1, 32, 1, 0, HASH_PLAIN, 1, 1, 1 },
        /* AES-XCBC -- fixed 12 only */
        { "AES-XCBC", IMB_AUTH_AES_XCBC, 12, 0, 0, 0, 0, HASH_XCBC, 1, 1, 1 },
        /* AES-CMAC -- tag range 1..16, step 1 */
        { "AES-CMAC", IMB_AUTH_AES_CMAC, 16, 1, 16, 1, 0, HASH_CMAC, 1, 1, 1 },
        { "AES-CMAC-256", IMB_AUTH_AES_CMAC_256, 16, 1, 16, 1, 0, HASH_CMAC, 1, 1, 1 },
        /* AES-GMAC (standalone) -- tag range 1..16, step 1 */
        { "AES-GMAC-128", IMB_AUTH_AES_GMAC_128, 16, 1, 16, 1, 12, HASH_GMAC, 1, 1, 1 },
        { "AES-GMAC-192", IMB_AUTH_AES_GMAC_192, 16, 1, 16, 1, 12, HASH_GMAC, 1, 1, 1 },
        { "AES-GMAC-256", IMB_AUTH_AES_GMAC_256, 16, 1, 16, 1, 12, HASH_GMAC, 1, 1, 1 },
        /* GHASH -- fixed 16 only (implementation always writes 16 bytes) */
        { "GHASH", IMB_AUTH_GHASH, 16, 0, 0, 0, 0, HASH_GHASH, 16, 16, 16 },
        /* POLY1305 -- fixed 16 only */
        { "POLY1305", IMB_AUTH_POLY1305, 16, 0, 0, 0, 0, HASH_POLY1305, 1, 1, 1 },
        /* CRC variants -- fixed 4 only */
        { "CRC32-ETH-FCS", IMB_AUTH_CRC32_ETHERNET_FCS, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC32-SCTP", IMB_AUTH_CRC32_SCTP, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC32-WIMAX", IMB_AUTH_CRC32_WIMAX_OFDMA_DATA, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC24-LTE-A", IMB_AUTH_CRC24_LTE_A, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC24-LTE-B", IMB_AUTH_CRC24_LTE_B, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC16-X25", IMB_AUTH_CRC16_X25, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC16-FP-DATA", IMB_AUTH_CRC16_FP_DATA, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC11-FP-HDR", IMB_AUTH_CRC11_FP_HEADER, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC10-IUUP", IMB_AUTH_CRC10_IUUP_DATA, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC8-WIMAX-HCS", IMB_AUTH_CRC8_WIMAX_OFDMA_HCS, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC7-FP-HDR", IMB_AUTH_CRC7_FP_HEADER, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "CRC6-IUUP-HDR", IMB_AUTH_CRC6_IUUP_HEADER, 4, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        /* 3GPP integrity algorithms -- fixed 4 only */
        { "ZUC-EIA3", IMB_AUTH_ZUC_EIA3, 4, 0, 0, 0, 16, HASH_ZUC, 1, 1, 1 },
        { "SNOW3G-UIA2", IMB_AUTH_SNOW3G_UIA2, 4, 0, 0, 0, 16, HASH_SNOW3G, 1, 1, 1 },
        { "KASUMI-UIA1", IMB_AUTH_KASUMI_UIA1, 4, 0, 0, 0, 0, HASH_KASUMI, 1, 1, 1 },
        /* SHA3 -- fixed tag size only */
        { "SHA3-224", IMB_AUTH_SHA3_224, 28, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "SHA3-256", IMB_AUTH_SHA3_256, 32, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "SHA3-384", IMB_AUTH_SHA3_384, 48, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        { "SHA3-512", IMB_AUTH_SHA3_512, 64, 0, 0, 0, 0, HASH_PLAIN, 1, 1, 1 },
        /* HMAC-SHA3 -- tag range 4..digest_size, step 1 */
        { "HMAC-SHA3-224", IMB_AUTH_HMAC_SHA3_224, 28, 4, 28, 1, 0, HASH_HMAC, 1, 1, 1 },
        { "HMAC-SHA3-256", IMB_AUTH_HMAC_SHA3_256, 32, 4, 32, 1, 0, HASH_HMAC, 1, 1, 1 },
        { "HMAC-SHA3-384", IMB_AUTH_HMAC_SHA3_384, 48, 4, 48, 1, 0, HASH_HMAC, 1, 1, 1 },
        { "HMAC-SHA3-512", IMB_AUTH_HMAC_SHA3_512, 64, 4, 64, 1, 0, HASH_HMAC, 1, 1, 1 },
        /* SHAKE -- tag range 1..16, step 1 (variable, no check constraint) */
        { "SHAKE128", IMB_AUTH_SHAKE128, 16, 1, 16, 1, 0, HASH_PLAIN, 1, 1, 1 },
        { "SHAKE256", IMB_AUTH_SHAKE256, 32, 1, 32, 1, 0, HASH_PLAIN, 1, 1, 1 },
        /* 5G NIA integrity algorithms -- tag range 4..16 */
        { "AES-NIA5", IMB_AUTH_AES_NIA5, 16, 4, 16, 1, 16, HASH_AES_NIA5, 1, 1, 1 },
        { "ZUC-NIA6", IMB_AUTH_ZUC_NIA6, 16, 4, 16, 1, 16, HASH_ZUC, 1, 1, 1 },
        { "SNOW5G-NIA4", IMB_AUTH_SNOW5G_NIA4, 16, 4, 16, 1, 16, HASH_SNOW5G_NIA4, 1, 1, 1 },
};

/**
 * @brief Populate hash-specific union fields in \a job.
 *
 * @param [in,out] job   job structure
 * @param [in]     setup which union to configure
 */
static void
setup_hash_fields(IMB_JOB *job, const enum hash_setup setup, const uint8_t *iv)
{
        switch (setup) {
        case HASH_HMAC:
                job->u.HMAC._hashed_auth_key_xor_ipad = key_store;
                job->u.HMAC._hashed_auth_key_xor_opad = key_store + 256;
                break;
        case HASH_XCBC:
                job->u.XCBC._k1_expanded = (const uint32_t *) key_store;
                job->u.XCBC._k2 = key_store + 256;
                job->u.XCBC._k3 = key_store + 512;
                break;
        case HASH_CMAC:
                job->u.CMAC._key_expanded = key_store;
                job->u.CMAC._skey1 = key_store + 256;
                job->u.CMAC._skey2 = key_store + 512;
                break;
        case HASH_GMAC:
                job->u.GMAC._key = (const struct gcm_key_data *) key_store;
                job->u.GMAC._iv = iv;
                job->u.GMAC.iv_len_in_bytes = 12;
                break;
        case HASH_GHASH:
                job->u.GHASH._key = (const struct gcm_key_data *) key_store;
                job->u.GHASH._init_tag = key_store + 4096;
                break;
        case HASH_POLY1305:
                job->u.POLY1305._key = key_store;
                break;
        case HASH_ZUC:
                job->u.ZUC_EIA3._key = key_store;
                job->u.ZUC_EIA3._iv = iv;
                break;
        case HASH_SNOW3G:
                job->u.SNOW3G_UIA2._key = key_store;
                job->u.SNOW3G_UIA2._iv = iv;
                break;
        case HASH_KASUMI:
                job->u.KASUMI_UIA1._key = key_store;
                break;
        case HASH_AES_NIA5:
                job->u.NIA._key = key_store;
                job->u.NIA._iv = iv;
                break;
        case HASH_SNOW5G_NIA4:
                job->u.NIA._key = key_store;
                job->u.NIA._iv = iv;
                break;
        case HASH_PLAIN:
        default:
                break;
        }
}

/**
 * @brief Test hash OOB via JOB API.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] tv          hash test vector
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction
 * @param [in] use_nocheck non-zero to use NOCHECK API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_hash_oob(IMB_MGR *mgr, const struct hash_test_vec *tv, struct oob_mem *mem,
              const enum oob_type oob, const int use_nocheck)
{
        volatile struct test_bufs b;

        setup_oob_bufs(&b, mem, oob, tv->msg_len, tv->iv_len, tv->tag_len, 0, 0);

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u SEGFAULT during %s submit (%s)\n", tv->name,
                               tv->msg_len, use_nocheck ? "NOCHECK" : "CHECKED",
                               oob_type_name[oob]);
                }
                return -1;
        }

        IMB_JOB *job = IMB_GET_NEXT_JOB(mgr);

        if (job == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_JOB returned NULL\n", tv->name);
                return -1;
        }

        memset(job, 0, sizeof(*job));
        job->hash_alg = tv->hash;
        job->chain_order = IMB_ORDER_HASH_CIPHER;
        job->cipher_mode = IMB_CIPHER_NULL;
        job->src = b.src;
        job->hash_start_src_offset_in_bytes = 0;
        job->auth_tag_output = b.tag;
        job->auth_tag_output_len_in_bytes = tv->tag_len;

        job->msg_len_to_hash_in_bytes = tv->msg_len;

        setup_hash_fields(job, tv->setup, b.iv);

        if (use_nocheck)
                job = IMB_SUBMIT_JOB_NOCHECK(mgr);
        else
                job = IMB_SUBMIT_JOB(mgr);

        (void) job;

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        return 0;
}

/**
 * @brief Test hash OOB via type-specific burst API.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] tv          hash test vector
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction
 * @param [in] use_nocheck non-zero to use NOCHECK API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_hash_burst_oob(IMB_MGR *mgr, const struct hash_test_vec *tv, struct oob_mem *mem,
                    const enum oob_type oob, const int use_nocheck)
{
        volatile struct test_bufs b;

        setup_oob_bufs(&b, mem, oob, tv->msg_len, tv->iv_len, tv->tag_len, 0, 0);

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u (burst) SEGFAULT during %s submit (%s)\n",
                               tv->name, tv->msg_len, use_nocheck ? "NOCHECK" : "CHECKED",
                               oob_type_name[oob]);
                }
                return -1;
        }

        IMB_JOB jobs[1];

        memset(&jobs[0], 0, sizeof(jobs[0]));

        jobs[0].hash_alg = tv->hash;
        jobs[0].chain_order = IMB_ORDER_HASH_CIPHER;
        jobs[0].cipher_mode = IMB_CIPHER_NULL;
        jobs[0].src = b.src;
        jobs[0].hash_start_src_offset_in_bytes = 0;
        jobs[0].auth_tag_output = b.tag;
        jobs[0].auth_tag_output_len_in_bytes = tv->tag_len;
        jobs[0].msg_len_to_hash_in_bytes = tv->msg_len;

        setup_hash_fields(&jobs[0], tv->setup, b.iv);

        if (use_nocheck)
                IMB_SUBMIT_HASH_BURST_NOCHECK(mgr, jobs, 1, tv->hash);
        else
                IMB_SUBMIT_HASH_BURST(mgr, jobs, 1, tv->hash);

        return 0;
}

/**
 * @brief Test hash OOB via generic burst API.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] tv          hash test vector
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction
 * @param [in] use_nocheck non-zero to use NOCHECK API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_hash_generic_burst_oob(IMB_MGR *mgr, const struct hash_test_vec *tv, struct oob_mem *mem,
                            const enum oob_type oob, const int use_nocheck)
{
        volatile struct test_bufs b;

        setup_oob_bufs(&b, mem, oob, tv->msg_len, tv->iv_len, tv->tag_len, 0, 0);

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u (generic burst) SEGFAULT during %s submit (%s)\n",
                               tv->name, tv->msg_len, use_nocheck ? "NOCHECK" : "CHECKED",
                               oob_type_name[oob]);
                }
                return -1;
        }

        IMB_JOB *jobs[1];

        const uint32_t n = IMB_GET_NEXT_BURST(mgr, 1, jobs);

        if (n == 0 || jobs[0] == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_BURST returned 0\n", tv->name);
                return -1;
        }

        memset(jobs[0], 0, sizeof(*jobs[0]));
        jobs[0]->hash_alg = tv->hash;
        jobs[0]->chain_order = IMB_ORDER_HASH_CIPHER;
        jobs[0]->cipher_mode = IMB_CIPHER_NULL;
        jobs[0]->src = b.src;
        jobs[0]->hash_start_src_offset_in_bytes = 0;
        jobs[0]->auth_tag_output = b.tag;
        jobs[0]->auth_tag_output_len_in_bytes = tv->tag_len;
        jobs[0]->msg_len_to_hash_in_bytes = tv->msg_len;

        setup_hash_fields(jobs[0], tv->setup, b.iv);
        imb_set_session(mgr, jobs[0]);

        if (use_nocheck)
                IMB_SUBMIT_BURST_NOCHECK(mgr, 1, jobs);
        else
                IMB_SUBMIT_BURST(mgr, 1, jobs);

        IMB_FLUSH_BURST(mgr, 1, jobs);

        return 0;
}

/* ========================================================================== */
/* AEAD test vectors and functions                                            */
/* ========================================================================== */

/** AEAD test vector descriptor */
struct aead_test_vec {
        const char *name;         /**< test name for display */
        IMB_CIPHER_MODE cipher;   /**< cipher mode */
        IMB_HASH_ALG hash;        /**< hash algorithm (paired) */
        IMB_CIPHER_DIRECTION dir; /**< encrypt or decrypt */
        unsigned key_len;         /**< key length in bytes */
        unsigned iv_len;          /**< IV length in bytes */
        unsigned tag_len;         /**< authentication tag length */
        unsigned tag_min;         /**< minimum tag length for sweep (0 = fixed) */
        unsigned tag_max;         /**< maximum tag length for sweep (0 = fixed) */
        unsigned tag_step;        /**< tag length increment step (0 = fixed) */
        unsigned msg_len;         /**< message length (set by runner) */
        unsigned aad_len;         /**< AAD length in bytes (set by runner) */
        unsigned min_len;         /**< minimum message length in bytes */
        unsigned step;            /**< message length increment step */
        unsigned aad_min;         /**< minimum AAD length */
        unsigned aad_max;         /**< maximum AAD length (0 = use max_test_len) */
        unsigned aad_step;        /**< AAD length increment step */
};

/** Table of AEAD algorithms to test */
static const struct aead_test_vec aead_tests[] = {
        /* AES-GCM -- tag range 1..16, step 1 */
        { "AES-GCM-128-ENC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_ENCRYPT, 16, 12, 16, 1, 16,
          1, 0, 0, 1, 1, 0, 0, 1 },
        { "AES-GCM-128-DEC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_DECRYPT, 16, 12, 16, 1, 16,
          1, 0, 0, 1, 1, 0, 0, 1 },
        { "AES-GCM-192-ENC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_ENCRYPT, 24, 12, 16, 1, 16,
          1, 0, 0, 1, 1, 0, 0, 1 },
        { "AES-GCM-192-DEC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_DECRYPT, 24, 12, 16, 1, 16,
          1, 0, 0, 1, 1, 0, 0, 1 },
        { "AES-GCM-256-ENC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_ENCRYPT, 32, 12, 16, 1, 16,
          1, 0, 0, 1, 1, 0, 0, 1 },
        { "AES-GCM-256-DEC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_DECRYPT, 32, 12, 16, 1, 16,
          1, 0, 0, 1, 1, 0, 0, 1 },
        /* AES-CCM -- tag even values 4,6,8,10,12,14,16 */
        { "AES-CCM-128-ENC", IMB_CIPHER_CCM, IMB_AUTH_AES_CCM, IMB_DIR_ENCRYPT, 16, 13, 8, 4, 16, 2,
          0, 0, 1, 1, 0, 46, 1 },
        { "AES-CCM-128-DEC", IMB_CIPHER_CCM, IMB_AUTH_AES_CCM, IMB_DIR_DECRYPT, 16, 13, 8, 4, 16, 2,
          0, 0, 1, 1, 0, 46, 1 },
        /* CHACHA20-POLY1305 -- fixed tag 16 only */
        { "CHACHA20-POLY-ENC", IMB_CIPHER_CHACHA20_POLY1305, IMB_AUTH_CHACHA20_POLY1305,
          IMB_DIR_ENCRYPT, 32, 12, 16, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1 },
        { "CHACHA20-POLY-DEC", IMB_CIPHER_CHACHA20_POLY1305, IMB_AUTH_CHACHA20_POLY1305,
          IMB_DIR_DECRYPT, 32, 12, 16, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1 },
        /* SM4-GCM -- tag range 1..16, step 1 */
        { "SM4-GCM-ENC", IMB_CIPHER_SM4_GCM, IMB_AUTH_SM4_GCM, IMB_DIR_ENCRYPT, 16, 12, 16, 1, 16,
          1, 0, 0, 1, 1, 0, 0, 1 },
        { "SM4-GCM-DEC", IMB_CIPHER_SM4_GCM, IMB_AUTH_SM4_GCM, IMB_DIR_DECRYPT, 16, 12, 16, 1, 16,
          1, 0, 0, 1, 1, 0, 0, 1 },
        /* AES-NCA5 -- tag range 4..16, step 1 */
        { "AES-NCA5-ENC", IMB_CIPHER_AES_NCA5, IMB_AUTH_AES_NCA5, IMB_DIR_ENCRYPT, 32, 16, 16, 4,
          16, 1, 0, 0, 1, 1, 0, 0, 1 },
        { "AES-NCA5-DEC", IMB_CIPHER_AES_NCA5, IMB_AUTH_AES_NCA5, IMB_DIR_DECRYPT, 32, 16, 16, 4,
          16, 1, 0, 0, 1, 1, 0, 0, 1 },
        /* ZUC-NCA6 -- tag range 4..16, step 1 */
        { "ZUC-NCA6-ENC", IMB_CIPHER_ZUC_NCA6, IMB_AUTH_ZUC_NCA6, IMB_DIR_ENCRYPT, 32, 16, 16, 4,
          16, 1, 0, 0, 1, 1, 0, 0, 1 },
        { "ZUC-NCA6-DEC", IMB_CIPHER_ZUC_NCA6, IMB_AUTH_ZUC_NCA6, IMB_DIR_DECRYPT, 32, 16, 16, 4,
          16, 1, 0, 0, 1, 1, 0, 0, 1 },
        /* SNOW5G-NCA4 -- tag range 4..16, step 1 */
        { "SNOW5G-NCA4-ENC", IMB_CIPHER_SNOW5G_NCA4, IMB_AUTH_SNOW5G_NCA4, IMB_DIR_ENCRYPT, 32, 16,
          16, 4, 16, 1, 0, 0, 1, 1, 0, 0, 1 },
        { "SNOW5G-NCA4-DEC", IMB_CIPHER_SNOW5G_NCA4, IMB_AUTH_SNOW5G_NCA4, IMB_DIR_DECRYPT, 32, 16,
          16, 4, 16, 1, 0, 0, 1, 1, 0, 0, 1 },
};

/**
 * @brief Set up an AEAD job for OOB testing.
 *
 * @param [out] job     job structure
 * @param [in]  tv      AEAD test vector
 * @param [in]  src     source pointer (guard-protected)
 * @param [in]  dst     destination pointer (guard-protected)
 * @param [in]  iv      IV buffer (valid memory)
 * @param [out] tag     authentication tag output buffer
 * @param [in]  aad     AAD pointer (guard-protected)
 */
static void
setup_aead_job(IMB_JOB *job, const struct aead_test_vec *tv, const uint8_t *src, uint8_t *dst,
               const uint8_t *iv, uint8_t *tag, const uint8_t *aad)
{
        memset(job, 0, sizeof(*job));
        job->cipher_mode = tv->cipher;
        job->cipher_direction = tv->dir;
        job->hash_alg = tv->hash;
        job->chain_order = IMB_ORDER_CIPHER_HASH;
        job->src = src;
        job->dst = dst;
        job->iv = iv;
        job->iv_len_in_bytes = tv->iv_len;
        job->enc_keys = key_store;
        job->dec_keys = key_store;
        job->key_len_in_bytes = tv->key_len;
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = tv->msg_len;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = tv->msg_len;
        job->auth_tag_output = tag;
        job->auth_tag_output_len_in_bytes = tv->tag_len;

        switch (tv->hash) {
        case IMB_AUTH_AES_GMAC:
        case IMB_AUTH_SM4_GCM:
                job->u.GCM.aad = aad;
                job->u.GCM.aad_len_in_bytes = tv->aad_len;
                break;
        case IMB_AUTH_AES_CCM:
                job->u.CCM.aad = aad;
                job->u.CCM.aad_len_in_bytes = tv->aad_len;
                break;
        case IMB_AUTH_CHACHA20_POLY1305:
                job->u.CHACHA20_POLY1305.aad = aad;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = tv->aad_len;
                break;
        case IMB_AUTH_AES_NCA5:
        case IMB_AUTH_ZUC_NCA6:
        case IMB_AUTH_SNOW5G_NCA4:
                job->u.NCA.aad = aad;
                job->u.NCA.aad_len_in_bytes = tv->aad_len;
                break;
        default:
                break;
        }
}

/**
 * @brief Test AEAD OOB via JOB API.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] tv          AEAD test vector
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction
 * @param [in] use_nocheck non-zero to use NOCHECK API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_aead_oob(IMB_MGR *mgr, const struct aead_test_vec *tv, struct oob_mem *mem,
              const enum oob_type oob, const int use_nocheck)
{
        volatile struct test_bufs b;

        setup_oob_bufs(&b, mem, oob, tv->msg_len, tv->iv_len, tv->tag_len, tv->aad_len, 1);

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u aad=%u SEGFAULT during %s submit (%s)\n",
                               tv->name, tv->msg_len, tv->aad_len,
                               use_nocheck ? "NOCHECK" : "CHECKED", oob_type_name[oob]);
                }
                return -1;
        }

        IMB_JOB *job = IMB_GET_NEXT_JOB(mgr);

        if (job == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_JOB returned NULL\n", tv->name);
                return -1;
        }

        setup_aead_job(job, tv, b.src, b.dst, b.iv, b.tag, b.aad);

        if (use_nocheck)
                job = IMB_SUBMIT_JOB_NOCHECK(mgr);
        else
                job = IMB_SUBMIT_JOB(mgr);

        (void) job;

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        return 0;
}

/**
 * @brief Test AEAD OOB via type-specific burst API.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] tv          AEAD test vector
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction
 * @param [in] use_nocheck non-zero to use NOCHECK API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_aead_burst_oob(IMB_MGR *mgr, const struct aead_test_vec *tv, struct oob_mem *mem,
                    const enum oob_type oob, const int use_nocheck)
{
        volatile struct test_bufs b;

        setup_oob_bufs(&b, mem, oob, tv->msg_len, tv->iv_len, tv->tag_len, tv->aad_len, 1);

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u aad=%u (burst) SEGFAULT during %s submit (%s)\n",
                               tv->name, tv->msg_len, tv->aad_len,
                               use_nocheck ? "NOCHECK" : "CHECKED", oob_type_name[oob]);
                }
                return -1;
        }

        IMB_JOB jobs[1];

        setup_aead_job(&jobs[0], tv, b.src, b.dst, b.iv, b.tag, b.aad);

        if (use_nocheck)
                IMB_SUBMIT_AEAD_BURST_NOCHECK(mgr, jobs, 1, tv->cipher, tv->dir, tv->key_len);
        else
                IMB_SUBMIT_AEAD_BURST(mgr, jobs, 1, tv->cipher, tv->dir, tv->key_len);

        return 0;
}

/**
 * @brief Test AEAD OOB via generic burst API.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] tv          AEAD test vector
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction
 * @param [in] use_nocheck non-zero to use NOCHECK API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_aead_generic_burst_oob(IMB_MGR *mgr, const struct aead_test_vec *tv, struct oob_mem *mem,
                            const enum oob_type oob, const int use_nocheck)
{
        volatile struct test_bufs b;

        setup_oob_bufs(&b, mem, oob, tv->msg_len, tv->iv_len, tv->tag_len, tv->aad_len, 1);

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u aad=%u (generic burst) SEGFAULT during %s submit "
                               "(%s)\n",
                               tv->name, tv->msg_len, tv->aad_len,
                               use_nocheck ? "NOCHECK" : "CHECKED", oob_type_name[oob]);
                }
                return -1;
        }

        IMB_JOB *jobs[1];

        const uint32_t n = IMB_GET_NEXT_BURST(mgr, 1, jobs);

        if (n == 0 || jobs[0] == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_BURST returned 0\n", tv->name);
                return -1;
        }

        setup_aead_job(jobs[0], tv, b.src, b.dst, b.iv, b.tag, b.aad);
        imb_set_session(mgr, jobs[0]);

        if (use_nocheck)
                IMB_SUBMIT_BURST_NOCHECK(mgr, 1, jobs);
        else
                IMB_SUBMIT_BURST(mgr, 1, jobs);

        IMB_FLUSH_BURST(mgr, 1, jobs);

        return 0;
}

/* ========================================================================== */
/* Special combined-mode tests (PON, DOCSIS-CRC32)                           */
/* ========================================================================== */

/**
 * @brief Test PON cipher+BIP OOB via JOB API.
 *
 * PON requires an 8-byte XGEM header always hashed (BIP), plus a cipher
 * payload. The total buffer (header + cipher data) is placed next to a
 * guard page so any overread/overwrite is detected.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] dir         encrypt or decrypt direction
 * @param [in] name        test name for display
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction
 * @param [in] use_nocheck non-zero to use NOCHECK API
 * @param [in] cipher_len  cipher payload length in bytes
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_pon_oob(IMB_MGR *mgr, IMB_CIPHER_DIRECTION dir, const char *name, struct oob_mem *mem,
             const enum oob_type oob, const int use_nocheck, const unsigned cipher_len)
{
        const unsigned xgem_hdr_len = 8;
        const unsigned total_len = xgem_hdr_len + cipher_len;
        uint8_t *volatile tag;
        uint8_t *volatile iv;
        uint8_t *volatile buf;

        tag = oob_buf(&mem->tag, 8, oob);
        memset(tag, 0, 8);

        iv = oob_buf(&mem->iv, 16, oob);
        memset(iv, 0xBB, 16);

        buf = oob_buf(&mem->src, total_len, oob);
        memset(buf, 0x00, total_len);

        /*
         * PON reads PLI (Payload Length Indicator) from the XGEM header to
         * determine how many bytes to CRC. PLI is 14 MSBs of the 8-byte
         * big-endian header: PLI = (byte[0] << 6) | (byte[1] >> 2).
         * Set PLI = cipher_len so bytes_to_crc = cipher_len - 4 (CRC size).
         */
        buf[0] = (uint8_t) ((cipher_len >> 6) & 0xFF);
        buf[1] = (uint8_t) ((cipher_len << 2) & 0xFF);

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u SEGFAULT during %s submit (%s)\n", name,
                               cipher_len, use_nocheck ? "NOCHECK" : "CHECKED", oob_type_name[oob]);
                }
                return -1;
        }

        IMB_JOB *job = IMB_GET_NEXT_JOB(mgr);

        if (job == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_JOB returned NULL\n", name);
                return -1;
        }

        memset(job, 0, sizeof(*job));

        job->cipher_mode = IMB_CIPHER_PON_AES_CNTR;
        job->cipher_direction = dir;
        job->chain_order = IMB_ORDER_CIPHER_HASH;
        job->hash_alg = IMB_AUTH_PON_CRC_BIP;

        job->src = buf;
        job->dst = buf + xgem_hdr_len;
        job->cipher_start_src_offset_in_bytes = xgem_hdr_len;
        job->hash_start_src_offset_in_bytes = 0;

        job->msg_len_to_cipher_in_bytes = cipher_len;
        job->enc_keys = key_store;
        job->dec_keys = key_store;
        job->key_len_in_bytes = 16;
        job->iv = iv;
        job->iv_len_in_bytes = 16;

        job->msg_len_to_hash_in_bytes = total_len;
        job->auth_tag_output = tag;
        job->auth_tag_output_len_in_bytes = 8;

        if (use_nocheck)
                job = IMB_SUBMIT_JOB_NOCHECK(mgr);
        else
                job = IMB_SUBMIT_JOB(mgr);

        (void) job;

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        return 0;
}

/**
 * @brief Test DOCSIS-CRC32 OOB via JOB API.
 *
 * @param [in] mgr         multi-buffer manager
 * @param [in] dir         encrypt or decrypt direction
 * @param [in] name        test name for display
 * @param [in] mem         OOB memory allocations
 * @param [in] oob         OOB direction
 * @param [in] use_nocheck non-zero to use NOCHECK API
 * @param [in] hash_len    hash payload length in bytes (before CRC)
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_docsis_crc32_oob(IMB_MGR *mgr, IMB_CIPHER_DIRECTION dir, const char *name, struct oob_mem *mem,
                      const enum oob_type oob, const int use_nocheck, const unsigned hash_len)
{
        /*
         * DOCSIS CRC32 encrypt appends 4-byte CRC to plaintext in the source
         * buffer before encryption. Cipher length must include the CRC and
         * buffers must be large enough for hash_len + CRC (4 bytes).
         */
        const unsigned crc_len = 4;
        const unsigned buf_len = hash_len + crc_len;
        volatile struct test_bufs b;

        setup_oob_bufs(&b, mem, oob, buf_len, 16, 4, 0, 1);

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                if (fail_print_remaining > 0) {
                        fail_print_remaining--;
                        printf("  FAIL: %s len=%u SEGFAULT during %s submit (%s)\n", name, hash_len,
                               use_nocheck ? "NOCHECK" : "CHECKED", oob_type_name[oob]);
                }
                return -1;
        }

        IMB_JOB *job = IMB_GET_NEXT_JOB(mgr);

        if (job == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_JOB returned NULL\n", name);
                return -1;
        }

        memset(job, 0, sizeof(*job));
        job->cipher_mode = IMB_CIPHER_DOCSIS_SEC_BPI;
        job->cipher_direction = dir;
        job->hash_alg = IMB_AUTH_DOCSIS_CRC32;

        if (dir == IMB_DIR_ENCRYPT)
                job->chain_order = IMB_ORDER_HASH_CIPHER;
        else
                job->chain_order = IMB_ORDER_CIPHER_HASH;

        job->src = b.src;
        job->dst = b.dst;
        job->iv = b.iv;
        job->iv_len_in_bytes = 16;
        job->enc_keys = key_store;
        job->dec_keys = key_store;
        job->key_len_in_bytes = 16;

        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = buf_len;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = hash_len;
        job->auth_tag_output = b.tag;
        job->auth_tag_output_len_in_bytes = 4;

        if (use_nocheck)
                job = IMB_SUBMIT_JOB_NOCHECK(mgr);
        else
                job = IMB_SUBMIT_JOB(mgr);

        (void) job;

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        return 0;
}

/* ========================================================================== */
/* Test runner                                                                */
/* ========================================================================== */

/* ========================================================================== */
/* Per-category test runners                                                  */
/* ========================================================================== */

/** Function pointer type for individual cipher OOB test */
typedef int (*cipher_test_fn_t)(IMB_MGR *, const struct cipher_test_vec *, struct oob_mem *,
                                const enum oob_type, const int);

/** Function pointer type for individual hash OOB test */
typedef int (*hash_test_fn_t)(IMB_MGR *, const struct hash_test_vec *, struct oob_mem *,
                              const enum oob_type, const int);

/** Function pointer type for individual AEAD OOB test */
typedef int (*aead_test_fn_t)(IMB_MGR *, const struct aead_test_vec *, struct oob_mem *,
                              const enum oob_type, const int);

/**
 * @brief Run cipher OOB tests across single-job, burst and generic-burst APIs.
 *
 * @param [in]     mgr         multi-buffer manager
 * @param [in]     arch        architecture (for reinit after SEGFAULT)
 * @param [in]     mem         OOB memory allocations
 * @param [in]     oob         overrun / underrun
 * @param [in]     use_nocheck non-zero to use NOCHECK API
 * @param [in,out] pass        running pass count
 * @param [in,out] fail        running fail count
 */
static void
run_cipher_oob_tests(IMB_MGR *mgr, const IMB_ARCH arch, struct oob_mem *mem,
                     const enum oob_type oob, const int use_nocheck, unsigned *pass, unsigned *fail)
{
        static const struct {
                cipher_test_fn_t fn;
                const char *label;
        } apis[] = {
                { test_cipher_oob, "job" },
                { test_cipher_burst_oob, "cipher-burst" },
                { test_cipher_generic_burst_oob, "burst" },
        };
        const char *api_name = use_nocheck ? "NOCHECK" : "CHECKED";

        for (unsigned a = 0; a < DIM(apis); a++) {
                const char *lbl = apis[a].label;

                if (!quiet_mode)
                        printf("  Cipher tests (%s %s, %s):\n", lbl, api_name, oob_type_name[oob]);

                for (unsigned i = 0; i < DIM(cipher_tests); i++) {
                        struct cipher_test_vec tv = cipher_tests[i];
                        int vec_fail = 0;

                        fail_print_remaining = MAX_FAIL_PRINT;

                        for (unsigned len = tv.min_len; len <= max_test_len; len += tv.step) {
                                tv.msg_len = len;
                                if (apis[a].fn(mgr, &tv, mem, oob, use_nocheck) == 0) {
                                        (*pass)++;
                                } else {
                                        (*fail)++;
                                        vec_fail++;
                                        init_mgr_for_arch(mgr, arch);
                                        if (vec_fail >= MAX_VEC_FAIL)
                                                break;
                                }
                        }
                        if (!quiet_mode && vec_fail == 0) {
                                printf("    %-28s PASS (%s, len %u..%u step %u, %s)\n", tv.name,
                                       lbl, tv.min_len, max_test_len, tv.step, oob_type_name[oob]);
                        } else if (vec_fail > 0) {
                                printf("    %-28s %d FAIL(s) (%s, len %u..%u, %s)\n", tv.name,
                                       vec_fail, lbl, tv.min_len, max_test_len, oob_type_name[oob]);
                        }
                }
        }
}

/**
 * @brief Run hash OOB tests across single-job, burst and generic-burst APIs.
 *
 * @param [in]     mgr         multi-buffer manager
 * @param [in]     arch        architecture (for reinit after SEGFAULT)
 * @param [in]     mem         OOB memory allocations
 * @param [in]     oob         overrun / underrun
 * @param [in]     use_nocheck non-zero to use NOCHECK API
 * @param [in,out] pass        running pass count
 * @param [in,out] fail        running fail count
 */
static void
run_hash_oob_tests(IMB_MGR *mgr, const IMB_ARCH arch, struct oob_mem *mem, const enum oob_type oob,
                   const int use_nocheck, unsigned *pass, unsigned *fail)
{
        static const struct {
                hash_test_fn_t fn;
                const char *label;
        } apis[] = {
                { test_hash_oob, "job" },
                { test_hash_burst_oob, "hash-burst" },
                { test_hash_generic_burst_oob, "burst" },
        };
        const char *api_name = use_nocheck ? "NOCHECK" : "CHECKED";
        const unsigned fixed_msg = 64;

        for (unsigned a = 0; a < DIM(apis); a++) {
                const char *lbl = apis[a].label;

                if (!quiet_mode)
                        printf("  Hash tests (%s %s, %s):\n", lbl, api_name, oob_type_name[oob]);

                for (unsigned i = 0; i < DIM(hash_tests); i++) {
                        struct hash_test_vec tv = hash_tests[i];
                        int vec_fail = 0;

                        fail_print_remaining = MAX_FAIL_PRINT;

                        /* --- Pass 1: sweep message length with default tag --- */
                        for (unsigned len = tv.min_len; len <= max_test_len; len += tv.step) {
                                tv.msg_len = len;
                                if (apis[a].fn(mgr, &tv, mem, oob, use_nocheck) == 0) {
                                        (*pass)++;
                                } else {
                                        (*fail)++;
                                        vec_fail++;
                                        init_mgr_for_arch(mgr, arch);
                                        if (vec_fail >= MAX_VEC_FAIL)
                                                break;
                                }
                        }

                        /* --- Pass 2: sweep tag length with fixed message --- */
                        if (tv.tag_step > 0) {
                                tv.msg_len = fixed_msg;
                                for (unsigned tlen = tv.tag_min; tlen <= tv.tag_max;
                                     tlen += tv.tag_step) {
                                        tv.tag_len = tlen;
                                        if (apis[a].fn(mgr, &tv, mem, oob, use_nocheck) == 0) {
                                                (*pass)++;
                                        } else {
                                                (*fail)++;
                                                vec_fail++;
                                                init_mgr_for_arch(mgr, arch);
                                                if (vec_fail >= MAX_VEC_FAIL)
                                                        break;
                                        }
                                }
                        }

                        if (!quiet_mode && vec_fail == 0) {
                                if (tv.tag_step > 0)
                                        printf("    %-28s PASS (%s, len %u..%u,"
                                               " tag %u..%u, %s)\n",
                                               tv.name, lbl, tv.min_len, max_test_len, tv.tag_min,
                                               tv.tag_max, oob_type_name[oob]);
                                else
                                        printf("    %-28s PASS (%s, len %u..%u, %s)\n", tv.name,
                                               lbl, tv.min_len, max_test_len, oob_type_name[oob]);
                        } else if (vec_fail > 0) {
                                if (tv.tag_step > 0)
                                        printf("    %-28s %d FAIL(s) (%s, len %u..%u,"
                                               " tag %u..%u, %s)\n",
                                               tv.name, vec_fail, lbl, tv.min_len, max_test_len,
                                               tv.tag_min, tv.tag_max, oob_type_name[oob]);
                                else
                                        printf("    %-28s %d FAIL(s) (%s, len %u..%u, %s)\n",
                                               tv.name, vec_fail, lbl, tv.min_len, max_test_len,
                                               oob_type_name[oob]);
                        }
                }
        }
}

/**
 * @brief Run AEAD OOB tests across single-job, burst and generic-burst APIs.
 *
 * For each API variant and vector, two sweeps are performed:
 *   1. Message length sweep (min_len..max_test_len) with a fixed AAD size.
 *   2. AAD length sweep (aad_min..max_test_len) with a fixed message size.
 * This exercises guard-page protection on both the src/dst and AAD buffers.
 *
 * @param [in]     mgr         multi-buffer manager
 * @param [in]     arch        architecture (for reinit after SEGFAULT)
 * @param [in]     mem         OOB memory allocations
 * @param [in]     oob         overrun / underrun
 * @param [in]     use_nocheck non-zero to use NOCHECK API
 * @param [in,out] pass        running pass count
 * @param [in,out] fail        running fail count
 */
static void
run_aead_oob_tests(IMB_MGR *mgr, const IMB_ARCH arch, struct oob_mem *mem, const enum oob_type oob,
                   const int use_nocheck, unsigned *pass, unsigned *fail)
{
        static const struct {
                aead_test_fn_t fn;
                const char *label;
        } apis[] = {
                { test_aead_oob, NULL },
                { test_aead_burst_oob, "burst" },
                { test_aead_generic_burst_oob, "generic" },
        };
        const char *api_name = use_nocheck ? "NOCHECK" : "CHECKED";
        const unsigned fixed_aad = 32;
        const unsigned fixed_msg = 64;

        for (unsigned a = 0; a < DIM(apis); a++) {
                const char *lbl = apis[a].label;

                if (!quiet_mode)
                        printf("  AEAD tests (%s %s, %s):\n", lbl ? lbl : "single-job", api_name,
                               oob_type_name[oob]);

                for (unsigned i = 0; i < DIM(aead_tests); i++) {
                        struct aead_test_vec tv = aead_tests[i];
                        int vec_fail = 0;
                        const unsigned aad_limit = (tv.aad_max > 0) ? tv.aad_max : max_test_len;

                        fail_print_remaining = MAX_FAIL_PRINT;

                        /* --- Pass 1: sweep message length with fixed AAD --- */
                        tv.aad_len = (fixed_aad <= aad_limit) ? fixed_aad : aad_limit;
                        for (unsigned len = tv.min_len; len <= max_test_len; len += tv.step) {
                                tv.msg_len = len;
                                if (apis[a].fn(mgr, &tv, mem, oob, use_nocheck) == 0) {
                                        (*pass)++;
                                } else {
                                        (*fail)++;
                                        vec_fail++;
                                        init_mgr_for_arch(mgr, arch);
                                        if (vec_fail >= MAX_VEC_FAIL)
                                                break;
                                }
                        }

                        /* --- Pass 2: sweep AAD length with fixed message --- */
                        tv.msg_len = fixed_msg;
                        tv.tag_len = aead_tests[i].tag_len; /* restore default */
                        for (unsigned alen = tv.aad_min; alen <= aad_limit; alen += tv.aad_step) {
                                tv.aad_len = alen;
                                if (apis[a].fn(mgr, &tv, mem, oob, use_nocheck) == 0) {
                                        (*pass)++;
                                } else {
                                        (*fail)++;
                                        vec_fail++;
                                        init_mgr_for_arch(mgr, arch);
                                        if (vec_fail >= MAX_VEC_FAIL)
                                                break;
                                }
                        }

                        /* --- Pass 3: sweep tag length with fixed message --- */
                        if (tv.tag_step > 0) {
                                tv.msg_len = fixed_msg;
                                tv.aad_len = (fixed_aad <= aad_limit) ? fixed_aad : aad_limit;
                                for (unsigned tlen = tv.tag_min; tlen <= tv.tag_max;
                                     tlen += tv.tag_step) {
                                        tv.tag_len = tlen;
                                        if (apis[a].fn(mgr, &tv, mem, oob, use_nocheck) == 0) {
                                                (*pass)++;
                                        } else {
                                                (*fail)++;
                                                vec_fail++;
                                                init_mgr_for_arch(mgr, arch);
                                                if (vec_fail >= MAX_VEC_FAIL)
                                                        break;
                                        }
                                }
                        }

                        if (!quiet_mode && vec_fail == 0) {
                                if (lbl)
                                        printf("    %-28s PASS (%s, len %u..%u,"
                                               " aad %u..%u",
                                               tv.name, lbl, tv.min_len, max_test_len, tv.aad_min,
                                               aad_limit);
                                else
                                        printf("    %-28s PASS (len %u..%u,"
                                               " aad %u..%u",
                                               tv.name, tv.min_len, max_test_len, tv.aad_min,
                                               aad_limit);
                                if (tv.tag_step > 0)
                                        printf(", tag %u..%u", tv.tag_min, tv.tag_max);
                                printf(", %s)\n", oob_type_name[oob]);
                        } else if (vec_fail > 0) {
                                if (lbl)
                                        printf("    %-28s %d FAIL(s) (%s, len %u..%u,"
                                               " aad %u..%u",
                                               tv.name, vec_fail, lbl, tv.min_len, max_test_len,
                                               tv.aad_min, aad_limit);
                                else
                                        printf("    %-28s %d FAIL(s) (len %u..%u,"
                                               " aad %u..%u",
                                               tv.name, vec_fail, tv.min_len, max_test_len,
                                               tv.aad_min, aad_limit);
                                if (tv.tag_step > 0)
                                        printf(", tag %u..%u", tv.tag_min, tv.tag_max);
                                printf(", %s)\n", oob_type_name[oob]);
                        }
                }
        }
}

/**
 * @brief Run special combined-mode OOB tests (PON and DOCSIS-CRC32).
 *
 * @param [in]     mgr         multi-buffer manager
 * @param [in]     arch        architecture (for reinit after SEGFAULT)
 * @param [in]     mem         OOB memory allocations
 * @param [in]     oob         overrun / underrun
 * @param [in]     use_nocheck non-zero to use NOCHECK API
 * @param [in,out] pass        running pass count
 * @param [in,out] fail        running fail count
 */
static void
run_special_oob_tests(IMB_MGR *mgr, const IMB_ARCH arch, struct oob_mem *mem,
                      const enum oob_type oob, const int use_nocheck, unsigned *pass,
                      unsigned *fail)
{
        static const struct {
                const char *name;
                IMB_CIPHER_DIRECTION dir;
                int is_pon;
                unsigned min_len;
                unsigned step;
        } special_tests[] = {
                { "PON-OOB-ENC", IMB_DIR_ENCRYPT, 1, 8, 1 },
                { "PON-OOB-DEC", IMB_DIR_DECRYPT, 1, 8, 1 },
                { "DOCSIS-CRC32-OOB-ENC", IMB_DIR_ENCRYPT, 0, 1, 1 },
                { "DOCSIS-CRC32-OOB-DEC", IMB_DIR_DECRYPT, 0, 1, 1 },
        };
        const char *api_name = use_nocheck ? "NOCHECK" : "CHECKED";

        if (!quiet_mode)
                printf("  Special combined mode tests (%s, %s):\n", api_name, oob_type_name[oob]);

        for (unsigned i = 0; i < DIM(special_tests); i++) {
                int vec_fail = 0;

                fail_print_remaining = MAX_FAIL_PRINT;

                for (unsigned len = special_tests[i].min_len; len <= max_test_len;
                     len += special_tests[i].step) {
                        int ok;

                        if (special_tests[i].is_pon)
                                ok = test_pon_oob(mgr, special_tests[i].dir, special_tests[i].name,
                                                  mem, oob, use_nocheck, len);
                        else
                                ok = test_docsis_crc32_oob(mgr, special_tests[i].dir,
                                                           special_tests[i].name, mem, oob,
                                                           use_nocheck, len);
                        if (ok == 0) {
                                (*pass)++;
                        } else {
                                (*fail)++;
                                vec_fail++;
                                init_mgr_for_arch(mgr, arch);
                                if (vec_fail >= MAX_VEC_FAIL)
                                        break;
                        }
                }
                if (!quiet_mode && vec_fail == 0)
                        printf("    %-28s PASS (len %u..%u step %u, %s)\n", special_tests[i].name,
                               special_tests[i].min_len, max_test_len, special_tests[i].step,
                               oob_type_name[oob]);
                else if (vec_fail > 0)
                        printf("    %-28s %d FAIL(s) (len %u..%u, %s)\n", special_tests[i].name,
                               vec_fail, special_tests[i].min_len, max_test_len,
                               oob_type_name[oob]);
        }
}

/* ========================================================================== */
/* PQC (ML-DSA / ML-KEM) OOB tests                                            */
/* ========================================================================== */

/*
 * The PQC APIs are direct, context based APIs rather than IMB_JOB based ones,
 * so they need their own buffers, test vectors and runner.
 *
 * Detection works exactly as for the job API tests: every buffer handed to the
 * library is sized to exactly the length declared to the API and placed flush
 * against a guard page, so any access past the declared boundary faults. PQC
 * buffer sizes are fixed by the parameter set, so the overrun and underrun
 * passes together cover both ends of every buffer.
 *
 * Return codes are checked on every call, and results are cross-checked where
 * the API allows it (a derived public key must match the reference, a
 * decapsulated shared secret must match the encapsulated one), which catches
 * short writes that no guard page can see.
 */

/** Largest encoded PQC object: ML-DSA-87 private key */
#define PQC_MAX_KEY_BYTES IMB_ML_DSA_87_PRIVKEY_BYTES
/** Largest PQC signature / ciphertext: ML-DSA-87 signature */
#define PQC_MAX_SIG_BYTES IMB_ML_DSA_87_SIG_BYTES
/** Largest PQC public key: ML-DSA-87 public key */
#define PQC_MAX_PUB_BYTES IMB_ML_DSA_87_PUBKEY_BYTES
/** Largest PQC seed / randomizer / mu input */
#define PQC_MAX_SEED_BYTES IMB_ML_DSA_MU_BYTES

/** Set to zero by the --no-pqc command line option */
static int pqc_enabled = 1;

/** Set to zero by the --pqc-only command line option */
static int job_api_enabled = 1;

/**
 * @brief Guard memory allocations for PQC OOB testing.
 *
 * Kept separate from struct oob_mem because PQC objects (up to 4896 bytes)
 * are larger than the job API message lengths this tool sweeps over, and
 * because several distinct inputs are live at the same time within a single
 * API call.
 */
struct pqc_oob_mem {
        struct guard_mem pubkey;  /**< ML-DSA pk / ML-KEM ek */
        struct guard_mem privkey; /**< ML-DSA sk / ML-KEM dk */
        struct guard_mem sig;     /**< ML-DSA signature / ML-KEM ciphertext */
        struct guard_mem msg;     /**< message or pre-computed mu */
        struct guard_mem ctxstr;  /**< ML-DSA context string */
        struct guard_mem seed;    /**< keygen seed / sign randomizer / encap m */
        struct guard_mem ss;      /**< ML-KEM shared secret */
};

/**
 * @brief Allocate all guard memory regions for PQC OOB testing.
 *
 * @param [in,out] mem      PQC OOB memory structure to initialize
 * @param [in]     msg_size usable size of the message region
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 failure
 */
static int
pqc_mem_alloc(struct pqc_oob_mem *mem, const size_t msg_size)
{
        memset(mem, 0, sizeof(*mem));

        if (guard_mem_alloc(&mem->pubkey, PQC_MAX_PUB_BYTES) != 0 ||
            guard_mem_alloc(&mem->privkey, PQC_MAX_KEY_BYTES) != 0 ||
            guard_mem_alloc(&mem->sig, PQC_MAX_SIG_BYTES) != 0 ||
            guard_mem_alloc(&mem->msg, msg_size) != 0 ||
            guard_mem_alloc(&mem->ctxstr, IMB_ML_DSA_MAX_CTX_BYTES) != 0 ||
            guard_mem_alloc(&mem->seed, PQC_MAX_SEED_BYTES) != 0 ||
            guard_mem_alloc(&mem->ss, IMB_ML_KEM_SHARED_SECRET_BYTES) != 0)
                return -1;

        return 0;
}

/**
 * @brief Free all PQC guard memory regions.
 *
 * @param [in] mem PQC OOB memory structure to free
 */
static void
pqc_mem_free(struct pqc_oob_mem *mem)
{
        guard_mem_free(&mem->pubkey);
        guard_mem_free(&mem->privkey);
        guard_mem_free(&mem->sig);
        guard_mem_free(&mem->msg);
        guard_mem_free(&mem->ctxstr);
        guard_mem_free(&mem->seed);
        guard_mem_free(&mem->ss);
}

/** Shared state for a sequence of PQC OOB sub-tests */
struct pqc_test_ctx {
        const char *variant; /**< e.g. "ML-DSA-87" */
        const char *op;      /**< current operation name, for messages */
        enum oob_type oob;   /**< overrun / underrun */
        unsigned *pass;      /**< running pass count */
        unsigned *fail;      /**< running fail count */
        unsigned vec_fail;   /**< failures recorded for this variant */
};

/**
 * @brief Report a PQC sub-test failure, honouring the per-vector print limit.
 *
 * @param [in] t    PQC test context
 * @param [in] what failure description
 */
static void
pqc_fail(const struct pqc_test_ctx *t, const char *what)
{
        if (fail_print_remaining > 0) {
                fail_print_remaining--;
                printf("  FAIL: %s %s: %s (%s)\n", t->variant, t->op, what, oob_type_name[t->oob]);
        }
}

/**
 * @brief Check an unexpected PQC API return code.
 *
 * @param [in] t  PQC test context
 * @param [in] rc return code from the API
 *
 * @return Check status
 * @retval 0 success (rc == 0)
 * @retval -1 unexpected error
 */
static int
pqc_check_rc(const struct pqc_test_ctx *t, const int rc)
{
        if (rc == 0)
                return 0;

        pqc_fail(t, imb_get_strerror(rc));
        return -1;
}

/**
 * @brief Record the outcome of a PQC sub-test.
 *
 * @param [in,out] t  PQC test context
 * @param [in]     ok 0 for pass, non-zero for fail
 */
static void
pqc_record(struct pqc_test_ctx *t, const int ok)
{
        if (ok == 0) {
                (*t->pass)++;
        } else {
                (*t->fail)++;
                t->vec_fail++;
        }
}

/**
 * @brief Set up a guarded PQC operation checkpoint.
 *
 * Names the operation for failure messages and installs the SEGFAULT
 * recovery point. Evaluates to non-zero when a fault was caught.
 */
#define PQC_GUARD(t, opname) (((t)->op = (opname)), TEST_SETJMP())

/* -------------------------------------------------------------------------- */
/* ML-DSA                                                                     */
/* -------------------------------------------------------------------------- */

/** ML-DSA variant descriptor */
struct ml_dsa_test_vec {
        const char *name;   /**< display name */
        IMB_ML_DSA_ALG alg; /**< parameter set selector */
        size_t pk_len;      /**< encoded public key size */
        size_t sk_len;      /**< encoded private key size */
        size_t sig_len;     /**< signature size */
};

static const struct ml_dsa_test_vec ml_dsa_tests[] = {
        { "ML-DSA-44", IMB_ML_DSA_44, IMB_ML_DSA_44_PUBKEY_BYTES, IMB_ML_DSA_44_PRIVKEY_BYTES,
          IMB_ML_DSA_44_SIG_BYTES },
        { "ML-DSA-65", IMB_ML_DSA_65, IMB_ML_DSA_65_PUBKEY_BYTES, IMB_ML_DSA_65_PRIVKEY_BYTES,
          IMB_ML_DSA_65_SIG_BYTES },
        { "ML-DSA-87", IMB_ML_DSA_87, IMB_ML_DSA_87_PUBKEY_BYTES, IMB_ML_DSA_87_PRIVKEY_BYTES,
          IMB_ML_DSA_87_SIG_BYTES },
};

/** ML-KEM variant descriptor */
struct ml_kem_test_vec {
        const char *name;   /**< display name */
        IMB_ML_KEM_ALG alg; /**< parameter set selector */
        size_t ek_len;      /**< encoded encapsulation (public) key size */
        size_t dk_len;      /**< encoded decapsulation (private) key size */
        size_t ct_len;      /**< ciphertext size */
};

static const struct ml_kem_test_vec ml_kem_tests[] = {
        { "ML-KEM-512", IMB_ML_KEM_512, IMB_ML_KEM_512_PUBKEY_BYTES, IMB_ML_KEM_512_PRIVKEY_BYTES,
          IMB_ML_KEM_512_CIPHERTEXT_BYTES },
        { "ML-KEM-768", IMB_ML_KEM_768, IMB_ML_KEM_768_PUBKEY_BYTES, IMB_ML_KEM_768_PRIVKEY_BYTES,
          IMB_ML_KEM_768_CIPHERTEXT_BYTES },
        { "ML-KEM-1024", IMB_ML_KEM_1024, IMB_ML_KEM_1024_PUBKEY_BYTES,
          IMB_ML_KEM_1024_PRIVKEY_BYTES, IMB_ML_KEM_1024_CIPHERTEXT_BYTES },
};

/**
 * @brief Message lengths swept by the ML-DSA sign/verify OOB tests.
 *
 * A coarse list rather than a dense sweep: ML-DSA sign is ~0.4 ms, so a
 * per-byte sweep would dominate the tool's run time without adding coverage.
 * The values cluster around the SHAKE256 rate (136 bytes) and power-of-two
 * boundaries, where block handling bugs are most likely to appear. Values
 * above max_test_len are skipped.
 */
static const unsigned pqc_msg_lens[] = {
        0,   1,   2,   3,   15,  16,  17,  31,  32,  33,  63,  64,   65,   127,  128,  129, 135,
        136, 137, 255, 256, 257, 271, 272, 273, 511, 512, 513, 1023, 1024, 1025, 2047, 2048
};

/** ML-DSA context string lengths exercised by sign/verify */
static const unsigned pqc_ctx_lens[] = { 0, 1, 135, 136, IMB_ML_DSA_MAX_CTX_BYTES };

/** Reference key material and signature, held in normal (non-guarded) memory */
static uint8_t ref_pk[PQC_MAX_PUB_BYTES];
static uint8_t ref_sk[PQC_MAX_KEY_BYTES];
static uint8_t ref_sig[PQC_MAX_SIG_BYTES];
static uint8_t ref_ct[PQC_MAX_SIG_BYTES];
static uint8_t ref_seed[PQC_MAX_SEED_BYTES];
static uint8_t ref_ctxstr[IMB_ML_DSA_MAX_CTX_BYTES];

/**
 * @brief Deterministically fill a buffer with a test pattern.
 *
 * @param [out] buf  buffer to fill
 * @param [in]  len  buffer length in bytes
 * @param [in]  salt pattern salt (distinguishes different buffers)
 */
static void
pqc_fill_pattern(uint8_t *buf, const size_t len, const uint8_t salt)
{
        for (size_t i = 0; i < len; i++)
                buf[i] = (uint8_t) ((i * 7u) + salt);
}

/**
 * @brief Test imb_ml_dsa_keypair() for OOB accesses.
 *
 * @param [in,out] t      PQC test context
 * @param [in]     ctx    ML-DSA context
 * @param [in]     tv     ML-DSA variant descriptor
 * @param [in]     mem    PQC guard memory
 * @param [in]     seeded non-zero to supply a 32-byte seed (deterministic keygen)
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_ml_dsa_keypair_oob(struct pqc_test_ctx *t, IMB_ML_DSA *ctx, const struct ml_dsa_test_vec *tv,
                        struct pqc_oob_mem *mem, const int seeded)
{
        uint8_t *const pk = oob_buf(&mem->pubkey, tv->pk_len, t->oob);
        uint8_t *const sk = oob_buf(&mem->privkey, tv->sk_len, t->oob);
        uint8_t *const xi = oob_buf(&mem->seed, IMB_ML_DSA_KEYGEN_SEED_BYTES, t->oob);
        IMB_ML_DSA_KEYGEN_PARAMS params;

        memcpy(xi, ref_seed, IMB_ML_DSA_KEYGEN_SEED_BYTES);

        IMB_ML_DSA_KEYGEN_PARAMS_INIT(&params);
        if (seeded) {
                params.xi_32 = xi;
                params.xi_len = IMB_ML_DSA_KEYGEN_SEED_BYTES;
        }

        if (PQC_GUARD(t, seeded ? "keypair (seeded)" : "keypair")) {
                pqc_fail(t, "SEGFAULT");
                return -1;
        }

        if (pqc_check_rc(t, imb_ml_dsa_keypair(ctx, pk, tv->pk_len, sk, tv->sk_len, &params)) != 0)
                return -1;

        return 0;
}

/**
 * @brief Test the ML-DSA key binding and validation entry points for OOB
 *        accesses: set_privkey, set_pubkey, privkey_validate, pubkey_validate
 *        and pubkey_from_privkey.
 *
 * Each call receives an exactly sized, guard-page adjacent copy of the
 * reference key material.
 *
 * @param [in,out] t   PQC test context
 * @param [in]     ctx ML-DSA context
 * @param [in]     tv  ML-DSA variant descriptor
 * @param [in]     mem PQC guard memory
 *
 * @return number of failed sub-tests
 */
static int
test_ml_dsa_keyops_oob(struct pqc_test_ctx *t, IMB_ML_DSA *ctx, const struct ml_dsa_test_vec *tv,
                       struct pqc_oob_mem *mem)
{
        static const struct {
                const char *name;
                int is_pubkey; /**< operates on pk (1) or sk (0) */
                int is_bind;   /**< set_*key (1) or *_validate (0) */
        } ops[] = {
                { "set_privkey", 0, 1 },
                { "set_pubkey", 1, 1 },
                { "privkey_validate", 0, 0 },
                { "pubkey_validate", 1, 0 },
        };
        int fails = 0;

        /* volatile: these stay live across the TEST_SETJMP() checkpoint below */
        for (volatile unsigned i = 0; i < DIM(ops); i++) {
                struct guard_mem *const volatile gm =
                        ops[i].is_pubkey ? &mem->pubkey : &mem->privkey;
                const volatile size_t len = ops[i].is_pubkey ? tv->pk_len : tv->sk_len;
                const uint8_t *const ref = ops[i].is_pubkey ? ref_pk : ref_sk;
                uint8_t *const volatile key = oob_buf(gm, len, t->oob);
                int rc;

                memcpy(key, ref, len);

                if (PQC_GUARD(t, ops[i].name)) {
                        pqc_fail(t, "SEGFAULT");
                        pqc_record(t, -1);
                        fails++;
                        continue;
                }

                if (ops[i].is_bind)
                        rc = ops[i].is_pubkey ? imb_ml_dsa_set_pubkey(ctx, key, len)
                                              : imb_ml_dsa_set_privkey(ctx, key, len);
                else
                        rc = ops[i].is_pubkey ? imb_ml_dsa_pubkey_validate(ctx, key, len)
                                              : imb_ml_dsa_privkey_validate(ctx, key, len);

                const int ok = (pqc_check_rc(t, rc) != 0) ? -1 : 0;

                pqc_record(t, ok);
                if (ok != 0)
                        fails++;
        }

        /* pubkey_from_privkey(): guarded sk input and guarded pk output */
        {
                /* volatile: live across the TEST_SETJMP() checkpoint below */
                uint8_t *const volatile sk = oob_buf(&mem->privkey, tv->sk_len, t->oob);
                uint8_t *const volatile pk = oob_buf(&mem->pubkey, tv->pk_len, t->oob);
                int ok = 0;

                memcpy(sk, ref_sk, tv->sk_len);

                if (PQC_GUARD(t, "pubkey_from_privkey")) {
                        pqc_fail(t, "SEGFAULT");
                        pqc_record(t, -1);
                        return fails + 1;
                }

                if (pqc_check_rc(t, imb_ml_dsa_pubkey_from_privkey(ctx, sk, tv->sk_len, pk,
                                                                   tv->pk_len)) != 0)
                        ok = -1;
                else if (memcmp(pk, ref_pk, tv->pk_len) != 0) {
                        pqc_fail(t, "derived public key mismatch");
                        ok = -1;
                }

                pqc_record(t, ok);
                if (ok != 0)
                        fails++;
        }

        /* re-bind the private key: it carries the public component too */
        if (PQC_GUARD(t, "set_privkey (re-bind)")) {
                pqc_fail(t, "SEGFAULT");
                pqc_record(t, -1);
                return fails + 1;
        }
        if (pqc_check_rc(t, imb_ml_dsa_set_privkey(ctx, ref_sk, tv->sk_len)) != 0) {
                pqc_record(t, -1);
                return fails + 1;
        }

        return fails;
}

/**
 * @brief Test imb_ml_dsa_sign() followed by imb_ml_dsa_verify() for OOB accesses.
 *
 * All of msg, sig, ctx string and the optional randomizer are placed flush
 * against guard pages. The signature produced by the guarded sign call is
 * copied out and fed back into a guarded verify call, which additionally
 * proves the sign path did not silently truncate its output.
 *
 * @param [in,out] t        PQC test context
 * @param [in]     ctx      ML-DSA context with a bound private key
 * @param [in]     tv       ML-DSA variant descriptor
 * @param [in]     mem      PQC guard memory
 * @param [in]     msg_len  message length in bytes
 * @param [in]     ctx_len  context string length in bytes
 * @param [in]     hedged   non-zero for hedged signing (NULL randomizer)
 * @param [in]     msg_is_mu non-zero to pass a pre-computed mu instead of a message
 *
 * @return number of failed sub-tests
 */
static int
test_ml_dsa_sign_verify_oob(struct pqc_test_ctx *t, IMB_ML_DSA *ctx,
                            const struct ml_dsa_test_vec *tv, struct pqc_oob_mem *mem,
                            const unsigned msg_len, const unsigned ctx_len, const int hedged,
                            const int msg_is_mu)
{
        uint8_t *msg = oob_buf(&mem->msg, msg_len, t->oob);
        uint8_t *sig = oob_buf(&mem->sig, tv->sig_len, t->oob);
        uint8_t *cstr = oob_buf(&mem->ctxstr, ctx_len, t->oob);
        uint8_t *rnd = oob_buf(&mem->seed, IMB_ML_DSA_SIGN_RND_BYTES, t->oob);
        IMB_ML_DSA_SIGN_PARAMS sp;
        IMB_ML_DSA_VERIFY_PARAMS vp;
        size_t sig_len = tv->sig_len;
        int fails = 0;

        pqc_fill_pattern(msg, msg_len, 1);
        memcpy(cstr, ref_ctxstr, ctx_len);
        memcpy(rnd, ref_seed, IMB_ML_DSA_SIGN_RND_BYTES);

        IMB_ML_DSA_SIGN_PARAMS_INIT(&sp);
        sp.msg_is_mu = msg_is_mu;
        if (!msg_is_mu && ctx_len != 0) {
                sp.ctx = cstr;
                sp.ctx_len = ctx_len;
        }
        if (!hedged) {
                sp.rnd_32 = rnd;
                sp.rnd_len = IMB_ML_DSA_SIGN_RND_BYTES;
        }

        if (PQC_GUARD(t, msg_is_mu ? "sign (mu)" : "sign")) {
                pqc_fail(t, "SEGFAULT");
                pqc_record(t, -1);
                return 1;
        }

        if (pqc_check_rc(t, imb_ml_dsa_sign(ctx, sig, &sig_len, msg, msg_len, &sp)) != 0) {
                pqc_record(t, -1);
                return 1;
        }

        if (sig_len != tv->sig_len) {
                pqc_fail(t, "unexpected signature length");
                pqc_record(t, -1);
                return 1;
        }

        pqc_record(t, 0);

        /* keep a copy: the guard buffers are re-armed for the verify call */
        memcpy(ref_sig, sig, sig_len);

        msg = oob_buf(&mem->msg, msg_len, t->oob);
        sig = oob_buf(&mem->sig, tv->sig_len, t->oob);
        cstr = oob_buf(&mem->ctxstr, ctx_len, t->oob);

        pqc_fill_pattern(msg, msg_len, 1);
        memcpy(sig, ref_sig, tv->sig_len);
        memcpy(cstr, ref_ctxstr, ctx_len);

        IMB_ML_DSA_VERIFY_PARAMS_INIT(&vp);
        vp.msg_is_mu = msg_is_mu;
        if (!msg_is_mu && ctx_len != 0) {
                vp.ctx = cstr;
                vp.ctx_len = ctx_len;
        }

        if (PQC_GUARD(t, msg_is_mu ? "verify (mu)" : "verify")) {
                pqc_fail(t, "SEGFAULT");
                pqc_record(t, -1);
                return fails + 1;
        }

        if (pqc_check_rc(t, imb_ml_dsa_verify(ctx, msg, msg_len, sig, tv->sig_len, &vp)) != 0) {
                pqc_record(t, -1);
                fails++;
        } else {
                pqc_record(t, 0);
        }

        /*
         * Rejection path: corrupting the last signature byte forces the
         * decode/verify code down a different, early-exit branch.
         */
        sig = oob_buf(&mem->sig, tv->sig_len, t->oob);
        memcpy(sig, ref_sig, tv->sig_len);
        sig[tv->sig_len - 1] ^= 0xff;

        if (PQC_GUARD(t, "verify (corrupted)")) {
                pqc_fail(t, "SEGFAULT");
                pqc_record(t, -1);
                return fails + 1;
        }

        const int rc = imb_ml_dsa_verify(ctx, msg, msg_len, sig, tv->sig_len, &vp);

        if (rc != IMB_ERR_PQC_VERIFY_FAILED) {
                pqc_fail(t, rc == 0 ? "corrupted signature accepted" : imb_get_strerror(rc));
                pqc_record(t, -1);
                fails++;
        } else {
                pqc_record(t, 0);
        }

        return fails;
}

/**
 * @brief Run all ML-DSA OOB tests for one parameter set.
 *
 * @param [in]     mgr  multi-buffer manager
 * @param [in]     tv   ML-DSA variant descriptor
 * @param [in]     mem  PQC guard memory
 * @param [in]     oob  overrun / underrun
 * @param [in,out] pass running pass count
 * @param [in,out] fail running fail count
 */
static void
run_ml_dsa_variant(IMB_MGR *mgr, const struct ml_dsa_test_vec *tv, struct pqc_oob_mem *mem,
                   const enum oob_type oob, unsigned *pass, unsigned *fail)
{
        struct pqc_test_ctx tctx = { tv->name, "new", oob, pass, fail, 0 };
        IMB_ML_DSA *ctx = NULL;
        int rc;

        fail_print_remaining = MAX_FAIL_PRINT;

        if (PQC_GUARD(&tctx, "new")) {
                pqc_fail(&tctx, "SEGFAULT");
                pqc_record(&tctx, -1);
                return;
        }

        rc = imb_ml_dsa_new(mgr, tv->alg, &ctx);
        if (rc != 0 || ctx == NULL) {
                pqc_fail(&tctx, imb_get_strerror(rc));
                pqc_record(&tctx, -1);
                return;
        }

        /* reference key material in normal memory - not part of the OOB test */
        if (PQC_GUARD(&tctx, "reference keypair")) {
                pqc_fail(&tctx, "SEGFAULT");
                pqc_record(&tctx, -1);
                return; /* context state is unknown - deliberately not freed */
        }

        rc = imb_ml_dsa_keypair(ctx, ref_pk, tv->pk_len, ref_sk, tv->sk_len, NULL);
        if (rc != 0) {
                tctx.op = "reference keypair";
                pqc_fail(&tctx, imb_get_strerror(rc));
                pqc_record(&tctx, -1);
                goto done;
        }

        /* keygen with and without a caller supplied seed */
        for (int seeded = 0; seeded <= 1; seeded++)
                pqc_record(&tctx, test_ml_dsa_keypair_oob(&tctx, ctx, tv, mem, seeded));

        (void) test_ml_dsa_keyops_oob(&tctx, ctx, tv, mem);

        /*
         * A caught fault unwinds out of the library, so the context may no
         * longer be trustworthy - stop this variant rather than report a
         * cascade of follow-on failures.
         */
        if (tctx.vec_fail >= MAX_VEC_FAIL)
                goto done;

        /* message length sweep, no context string, hedged signing */
        for (unsigned i = 0; i < DIM(pqc_msg_lens); i++) {
                if (pqc_msg_lens[i] > max_test_len)
                        break;
                (void) test_ml_dsa_sign_verify_oob(&tctx, ctx, tv, mem, pqc_msg_lens[i], 0, 1, 0);
                if (tctx.vec_fail >= MAX_VEC_FAIL)
                        goto done;
        }

        /* context string length sweep with a caller supplied randomizer */
        for (unsigned i = 0; i < DIM(pqc_ctx_lens); i++) {
                (void) test_ml_dsa_sign_verify_oob(&tctx, ctx, tv, mem, 32, pqc_ctx_lens[i], 0, 0);
                if (tctx.vec_fail >= MAX_VEC_FAIL)
                        goto done;
        }

        /* pre-computed mu path: the message is exactly IMB_ML_DSA_MU_BYTES */
        (void) test_ml_dsa_sign_verify_oob(&tctx, ctx, tv, mem, IMB_ML_DSA_MU_BYTES, 0, 1, 1);

done:
        /*
         * A fault caught earlier unwound out of the library, so the context may
         * be inconsistent and freeing it could fault again. Guard the free and
         * leak the context rather than take down the whole test run - the leak
         * is bounded by the number of variants.
         */
        if (PQC_GUARD(&tctx, "free")) {
                pqc_fail(&tctx, "SEGFAULT");
                pqc_record(&tctx, -1);
        } else {
                imb_ml_dsa_free(ctx);
        }

        if (!quiet_mode && tctx.vec_fail == 0)
                printf("    %-28s PASS (%s)\n", tv->name, oob_type_name[oob]);
        else if (tctx.vec_fail > 0)
                printf("    %-28s %u FAIL(s) (%s)\n", tv->name, tctx.vec_fail, oob_type_name[oob]);
}

/* -------------------------------------------------------------------------- */
/* ML-KEM                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * @brief Test imb_ml_kem_keypair() for OOB accesses.
 *
 * @param [in,out] t      PQC test context
 * @param [in]     ctx    ML-KEM context
 * @param [in]     tv     ML-KEM variant descriptor
 * @param [in]     mem    PQC guard memory
 * @param [in]     seeded non-zero to supply a 64-byte (d || z) seed
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_ml_kem_keypair_oob(struct pqc_test_ctx *t, IMB_ML_KEM *ctx, const struct ml_kem_test_vec *tv,
                        struct pqc_oob_mem *mem, const int seeded)
{
        uint8_t *const ek = oob_buf(&mem->pubkey, tv->ek_len, t->oob);
        uint8_t *const dk = oob_buf(&mem->privkey, tv->dk_len, t->oob);
        uint8_t *const seed = oob_buf(&mem->seed, IMB_ML_KEM_KEYGEN_SEED_BYTES, t->oob);
        IMB_ML_KEM_KEYGEN_PARAMS params;

        memcpy(seed, ref_seed, IMB_ML_KEM_KEYGEN_SEED_BYTES);

        IMB_ML_KEM_KEYGEN_PARAMS_INIT(&params);
        if (seeded) {
                params.seed_d_z = seed;
                params.seed_d_z_len = IMB_ML_KEM_KEYGEN_SEED_BYTES;
        }

        if (PQC_GUARD(t, seeded ? "keypair (seeded)" : "keypair")) {
                pqc_fail(t, "SEGFAULT");
                return -1;
        }

        if (pqc_check_rc(t, imb_ml_kem_keypair(ctx, ek, tv->ek_len, dk, tv->dk_len, &params)) != 0)
                return -1;

        return 0;
}

/**
 * @brief Test the ML-KEM key binding and validation entry points for OOB
 *        accesses: set_privkey, set_pubkey, privkey_validate, pubkey_validate.
 *
 * @param [in,out] t   PQC test context
 * @param [in]     ctx ML-KEM context
 * @param [in]     tv  ML-KEM variant descriptor
 * @param [in]     mem PQC guard memory
 */
static void
test_ml_kem_keyops_oob(struct pqc_test_ctx *t, IMB_ML_KEM *ctx, const struct ml_kem_test_vec *tv,
                       struct pqc_oob_mem *mem)
{
        static const struct {
                const char *name;
                int is_pubkey;
                int is_bind;
        } ops[] = {
                { "set_privkey", 0, 1 },
                { "set_pubkey", 1, 1 },
                { "privkey_validate", 0, 0 },
                { "pubkey_validate", 1, 0 },
        };

        /* volatile: these stay live across the TEST_SETJMP() checkpoint below */
        for (volatile unsigned i = 0; i < DIM(ops); i++) {
                struct guard_mem *const volatile gm =
                        ops[i].is_pubkey ? &mem->pubkey : &mem->privkey;
                const volatile size_t len = ops[i].is_pubkey ? tv->ek_len : tv->dk_len;
                const uint8_t *const ref = ops[i].is_pubkey ? ref_pk : ref_sk;
                uint8_t *const volatile key = oob_buf(gm, len, t->oob);
                int rc;

                memcpy(key, ref, len);

                if (PQC_GUARD(t, ops[i].name)) {
                        pqc_fail(t, "SEGFAULT");
                        pqc_record(t, -1);
                        continue;
                }

                if (ops[i].is_bind)
                        rc = ops[i].is_pubkey ? imb_ml_kem_set_pubkey(ctx, key, len)
                                              : imb_ml_kem_set_privkey(ctx, key, len);
                else
                        rc = ops[i].is_pubkey ? imb_ml_kem_pubkey_validate(ctx, key, len)
                                              : imb_ml_kem_privkey_validate(ctx, key, len);

                const int ok = (pqc_check_rc(t, rc) != 0) ? -1 : 0;

                pqc_record(t, ok);
        }
}

/**
 * @brief Test imb_ml_kem_encap() followed by imb_ml_kem_decap() for OOB accesses.
 *
 * The shared secret recovered by decapsulation is compared against the one
 * produced by encapsulation, which additionally proves neither side operated
 * on truncated data. A corrupted ciphertext is then decapsulated to exercise
 * the implicit rejection branch.
 *
 * @param [in,out] t      PQC test context
 * @param [in]     ctx    ML-KEM context
 * @param [in]     tv     ML-KEM variant descriptor
 * @param [in]     mem    PQC guard memory
 * @param [in]     seeded non-zero to supply the 32-byte encapsulation randomness
 */
static void
test_ml_kem_encap_decap_oob(struct pqc_test_ctx *t, IMB_ML_KEM *ctx,
                            const struct ml_kem_test_vec *tv, struct pqc_oob_mem *mem,
                            const int seeded)
{
        uint8_t ref_ss[IMB_ML_KEM_SHARED_SECRET_BYTES];
        uint8_t *ct = oob_buf(&mem->sig, tv->ct_len, t->oob);
        uint8_t *ss = oob_buf(&mem->ss, IMB_ML_KEM_SHARED_SECRET_BYTES, t->oob);
        uint8_t *const m = oob_buf(&mem->seed, IMB_ML_KEM_ENCAP_SEED_BYTES, t->oob);
        IMB_ML_KEM_ENCAP_PARAMS params;

        memcpy(m, ref_seed, IMB_ML_KEM_ENCAP_SEED_BYTES);

        IMB_ML_KEM_ENCAP_PARAMS_INIT(&params);
        if (seeded) {
                params.m_32 = m;
                params.m_len = IMB_ML_KEM_ENCAP_SEED_BYTES;
        }

        if (PQC_GUARD(t, "set_pubkey (encap)")) {
                pqc_fail(t, "SEGFAULT");
                pqc_record(t, -1);
                return;
        }

        if (pqc_check_rc(t, imb_ml_kem_set_pubkey(ctx, ref_pk, tv->ek_len)) != 0) {
                pqc_record(t, -1);
                return;
        }

        if (PQC_GUARD(t, seeded ? "encap (seeded)" : "encap")) {
                pqc_fail(t, "SEGFAULT");
                pqc_record(t, -1);
                return;
        }

        if (pqc_check_rc(t, imb_ml_kem_encap(ctx, ct, tv->ct_len, ss,
                                             IMB_ML_KEM_SHARED_SECRET_BYTES, &params)) != 0) {
                pqc_record(t, -1);
                return;
        }

        pqc_record(t, 0);

        memcpy(ref_ss, ss, sizeof(ref_ss));
        memcpy(ref_ct, ct, tv->ct_len);

        if (PQC_GUARD(t, "set_privkey (decap)")) {
                pqc_fail(t, "SEGFAULT");
                pqc_record(t, -1);
                return;
        }

        if (pqc_check_rc(t, imb_ml_kem_set_privkey(ctx, ref_sk, tv->dk_len)) != 0) {
                pqc_record(t, -1);
                return;
        }

        /* volatile: stays live across the TEST_SETJMP() checkpoint below */
        for (volatile int corrupt = 0; corrupt <= 1; corrupt++) {
                ct = oob_buf(&mem->sig, tv->ct_len, t->oob);
                ss = oob_buf(&mem->ss, IMB_ML_KEM_SHARED_SECRET_BYTES, t->oob);

                for (size_t i = 0; i < sizeof(ref_ss); i++)
                        ss[i] = ref_ss[i] ^ 0xff;
                memcpy(ct, ref_ct, tv->ct_len);
                if (corrupt)
                        ct[tv->ct_len - 1] ^= 0xff;

                if (PQC_GUARD(t, corrupt ? "decap (implicit reject)" : "decap")) {
                        pqc_fail(t, "SEGFAULT");
                        pqc_record(t, -1);
                        continue;
                }

                if (pqc_check_rc(t, imb_ml_kem_decap(ctx, ss, IMB_ML_KEM_SHARED_SECRET_BYTES, ct,
                                                     tv->ct_len, NULL)) != 0) {
                        pqc_record(t, -1);
                        continue;
                }

                /*
                 * A valid ciphertext must recover the encapsulated secret; a
                 * corrupted one must implicitly reject and return a different
                 * (but still fully written) secret.
                 */
                const int same = (memcmp(ss, ref_ss, sizeof(ref_ss)) == 0);

                if (same == corrupt) {
                        pqc_fail(t, corrupt ? "implicit reject returned the real secret"
                                            : "shared secret mismatch");
                        pqc_record(t, -1);
                } else {
                        pqc_record(t, 0);
                }
        }
}

/**
 * @brief Run all ML-KEM OOB tests for one parameter set.
 *
 * @param [in]     mgr  multi-buffer manager
 * @param [in]     tv   ML-KEM variant descriptor
 * @param [in]     mem  PQC guard memory
 * @param [in]     oob  overrun / underrun
 * @param [in,out] pass running pass count
 * @param [in,out] fail running fail count
 */
static void
run_ml_kem_variant(IMB_MGR *mgr, const struct ml_kem_test_vec *tv, struct pqc_oob_mem *mem,
                   const enum oob_type oob, unsigned *pass, unsigned *fail)
{
        struct pqc_test_ctx tctx = { tv->name, "new", oob, pass, fail, 0 };
        IMB_ML_KEM *ctx = NULL;
        int rc;

        fail_print_remaining = MAX_FAIL_PRINT;

        if (PQC_GUARD(&tctx, "new")) {
                pqc_fail(&tctx, "SEGFAULT");
                pqc_record(&tctx, -1);
                return;
        }

        rc = imb_ml_kem_new(mgr, tv->alg, &ctx);
        if (rc != 0 || ctx == NULL) {
                pqc_fail(&tctx, imb_get_strerror(rc));
                pqc_record(&tctx, -1);
                return;
        }

        /* reference key material in normal memory - not part of the OOB test */
        if (PQC_GUARD(&tctx, "reference keypair")) {
                pqc_fail(&tctx, "SEGFAULT");
                pqc_record(&tctx, -1);
                return; /* context state is unknown - deliberately not freed */
        }

        rc = imb_ml_kem_keypair(ctx, ref_pk, tv->ek_len, ref_sk, tv->dk_len, NULL);
        if (rc != 0) {
                tctx.op = "reference keypair";
                pqc_fail(&tctx, imb_get_strerror(rc));
                pqc_record(&tctx, -1);
                goto done;
        }

        for (int seeded = 0; seeded <= 1; seeded++)
                pqc_record(&tctx, test_ml_kem_keypair_oob(&tctx, ctx, tv, mem, seeded));

        test_ml_kem_keyops_oob(&tctx, ctx, tv, mem);

        for (int seeded = 0; seeded <= 1; seeded++)
                test_ml_kem_encap_decap_oob(&tctx, ctx, tv, mem, seeded);

done:
        /* see run_ml_dsa_variant(): guard the free, leak on fault */
        if (PQC_GUARD(&tctx, "free")) {
                pqc_fail(&tctx, "SEGFAULT");
                pqc_record(&tctx, -1);
        } else {
                imb_ml_kem_free(ctx);
        }

        if (!quiet_mode && tctx.vec_fail == 0)
                printf("    %-28s PASS (%s)\n", tv->name, oob_type_name[oob]);
        else if (tctx.vec_fail > 0)
                printf("    %-28s %u FAIL(s) (%s)\n", tv->name, tctx.vec_fail, oob_type_name[oob]);
}

/**
 * @brief Run the PQC (ML-DSA and ML-KEM) OOB tests.
 *
 * @param [in]     mgr  multi-buffer manager
 * @param [in]     arch architecture (for reinit after SEGFAULT)
 * @param [in]     mem  PQC guard memory
 * @param [in]     oob  overrun / underrun
 * @param [in,out] pass running pass count
 * @param [in,out] fail running fail count
 */
static void
run_pqc_oob_tests(IMB_MGR *mgr, const IMB_ARCH arch, struct pqc_oob_mem *mem,
                  const enum oob_type oob, unsigned *pass, unsigned *fail)
{
        if (!pqc_enabled)
                return;

        if (!quiet_mode)
                printf("  PQC tests (%s):\n", oob_type_name[oob]);

        pqc_fill_pattern(ref_seed, sizeof(ref_seed), 0x31);
        pqc_fill_pattern(ref_ctxstr, sizeof(ref_ctxstr), 0x42);

        const unsigned fail_before = *fail;

        for (unsigned i = 0; i < DIM(ml_dsa_tests); i++)
                run_ml_dsa_variant(mgr, &ml_dsa_tests[i], mem, oob, pass, fail);

        for (unsigned i = 0; i < DIM(ml_kem_tests); i++)
                run_ml_kem_variant(mgr, &ml_kem_tests[i], mem, oob, pass, fail);

        /*
         * A caught SEGFAULT unwinds out of the library, so restore the manager
         * to a known good state before the next test category runs.
         */
        if (*fail != fail_before)
                init_mgr_for_arch(mgr, arch);
}

/* ========================================================================== */
/* Top-level test runner                                                      */
/* ========================================================================== */

/**
 * @brief Run all OOB tests for a given architecture.
 *
 * Iterates over cipher, hash, AEAD and special combined-mode tests for
 * both overrun and underrun directions, using checked and NOCHECK submit
 * paths across single-job, type-specific burst and generic burst APIs.
 * Each test vector is exercised across a range of message lengths from
 * min_len to max_test_len in algorithm-appropriate steps.
 *
 * @param [in] mgr      multi-buffer manager
 * @param [in] arch     architecture type (for manager reinitialization after SEGFAULT)
 * @param [in] mem      OOB memory allocations
 * @param [in] pqc_mem  PQC OOB memory allocations
 *
 * @return Aggregate status
 * @retval 0 all tests passed
 * @retval -1 one or more tests failed
 */
static int
run_tests_for_arch(IMB_MGR *mgr, const IMB_ARCH arch, struct oob_mem *mem,
                   struct pqc_oob_mem *pqc_mem)
{
        /* Install signal/exception handler */
#ifdef _WIN32
        LPTOP_LEVEL_EXCEPTION_FILTER prev_handler;

        prev_handler = SetUnhandledExceptionFilter(test_exception_handler);
#else
        struct sigaction sa_old, sa_new;

        memset(&sa_new, 0, sizeof(sa_new));
        sa_new.sa_handler = test_sigsegv_handler;
        sa_new.sa_flags = SA_NODEFER; /* don't block SIGSEGV in handler */
        sigaction(SIGSEGV, &sa_new, &sa_old);
#endif

        unsigned pass = 0, fail = 0;
        /* with --pqc-only there is no CHECKED / NOCHECK dimension to sweep */
        const int total_passes = job_api_enabled ? (OOB_NUM * 2) : OOB_NUM;
        int combo = 0;

        for (enum oob_type oob = OOB_OVERRUN; oob < OOB_NUM; oob++) {
                for (int use_nocheck = 0; use_nocheck <= 1; use_nocheck++) {
                        const char *api_name = use_nocheck ? "NOCHECK" : "CHECKED";

                        /*
                         * The PQC API's have no CHECKED / NOCHECK distinction.
                         * Here, they are tested together with CHECKED JOB API test iteration.
                         * If JOB API is disabled and NOCHECK variant is to be tested then
                         * there is nothing to do in this iteration.
                         */
                        if (!job_api_enabled && use_nocheck)
                                continue;

                        printf("  [%d/%d] Testing %s %s (pass=%u, fail=%u) ...\n", ++combo,
                               total_passes, oob_type_name[oob], api_name, pass, fail);
                        fflush(stdout);

                        if (job_api_enabled) {
                                run_cipher_oob_tests(mgr, arch, mem, oob, use_nocheck, &pass,
                                                     &fail);
                                run_hash_oob_tests(mgr, arch, mem, oob, use_nocheck, &pass, &fail);
                                run_aead_oob_tests(mgr, arch, mem, oob, use_nocheck, &pass, &fail);
                                run_special_oob_tests(mgr, arch, mem, oob, use_nocheck, &pass,
                                                      &fail);
                        }

                        /*
                         * The PQC APIs are direct APIs with no CHECKED /
                         * NOCHECK distinction, so run them once per OOB
                         * direction rather than once per submit path.
                         */
                        if (!use_nocheck)
                                run_pqc_oob_tests(mgr, arch, pqc_mem, oob, &pass, &fail);
                }
        }

        /* Restore signal/exception handler */
#ifdef _WIN32
        SetUnhandledExceptionFilter(prev_handler);
#else
        sigaction(SIGSEGV, &sa_old, NULL);
#endif

        printf("  Results: %u passed, %u failed\n", pass, fail);
        fflush(stdout);
        return (fail > 0) ? -1 : 0;
}

/* ========================================================================== */
/* Usage                                                                      */
/* ========================================================================== */

/**
 * @brief Print command-line usage information.
 *
 * @param [in] prog program name (argv[0])
 */
static void
usage(const char *prog)
{
        printf("Usage: %s [options]\n"
               "Options:\n"
               "  --no-sse      Skip SSE architecture\n"
               "  --no-avx2     Skip AVX2 architecture\n"
               "  --no-avx512   Skip AVX512 architecture\n"
               "  --no-avx10    Skip AVX10 architecture\n"
               "  --shani-on    Enable SHA-NI extensions\n"
               "  --shani-off   Disable SHA-NI extensions\n"
               "  --gfni-on     Enable GFNI extensions\n"
               "  --gfni-off    Disable GFNI extensions\n"
               "  --max-len N   Maximum message length to test (default: %u)\n"
               "  --no-pqc      Skip PQC (ML-DSA / ML-KEM) tests\n"
               "  --pqc-only    Run only the PQC (ML-DSA / ML-KEM) tests\n"
               "  --verbose     Increase tool verbosity\n"
               "  -h, --help    Show this help\n",
               prog, MAX_TEST_LEN_DEFAULT);
}

/* ========================================================================== */
/* Algorithm coverage check                                                   */
/* ========================================================================== */

/**
 * @brief Verify that every cipher mode and hash algorithm is covered
 *        by at least one of the test arrays (cipher, hash, AEAD, special).
 *
 * Uses the IMB_CIPHER_NUM / IMB_AUTH_NUM sentinel values so this check
 * automatically catches newly added enum values that have no test entry.
 *
 * @return number of uncovered algorithms (0 = full coverage)
 */
static int
check_algorithm_coverage(void)
{
        int missing = 0;
        uint8_t cipher_seen[IMB_CIPHER_NUM];
        uint8_t hash_seen[IMB_AUTH_NUM];

        memset(cipher_seen, 0, sizeof(cipher_seen));
        memset(hash_seen, 0, sizeof(hash_seen));

        /* Scan cipher_tests[] */
        for (unsigned i = 0; i < DIM(cipher_tests); i++)
                cipher_seen[cipher_tests[i].cipher] = 1;

        /* Scan hash_tests[] */
        for (unsigned i = 0; i < DIM(hash_tests); i++)
                hash_seen[hash_tests[i].hash] = 1;

        /* Scan aead_tests[] (covers both cipher and hash) */
        for (unsigned i = 0; i < DIM(aead_tests); i++) {
                cipher_seen[aead_tests[i].cipher] = 1;
                hash_seen[aead_tests[i].hash] = 1;
        }

        /* Algorithms tested in run_special_oob_tests() or intentionally skipped */
        cipher_seen[IMB_CIPHER_NULL] = 1;
        cipher_seen[IMB_CIPHER_PON_AES_CNTR] = 1;          /* tested in run_special_oob_tests */
        cipher_seen[IMB_CIPHER_GCM_SGL] = 1;               /* SGL variant */
        cipher_seen[IMB_CIPHER_CHACHA20_POLY1305_SGL] = 1; /* SGL variant */

        hash_seen[IMB_AUTH_NULL] = 1;
        hash_seen[IMB_AUTH_PON_CRC_BIP] = 1;           /* tested in run_special_oob_tests */
        hash_seen[IMB_AUTH_DOCSIS_CRC32] = 1;          /* tested in run_special_oob_tests */
        hash_seen[IMB_AUTH_GCM_SGL] = 1;               /* SGL variant */
        hash_seen[IMB_AUTH_CHACHA20_POLY1305_SGL] = 1; /* SGL variant */

        for (int i = 1; i < IMB_CIPHER_NUM; i++) {
                if (!cipher_seen[i]) {
                        printf("WARNING: cipher mode %d not tested\n", i);
                        missing++;
                }
        }

        for (int i = 1; i < IMB_AUTH_NUM; i++) {
                if (!hash_seen[i]) {
                        printf("WARNING: hash algorithm %d not tested\n", i);
                        missing++;
                }
        }

        /*
         * PQC parameter sets. The enums carry no _NUM sentinel, so the last
         * defined value is used as the upper bound - a newly added parameter
         * set needs this bound bumped along with the test vector arrays.
         */
        uint8_t ml_dsa_seen[IMB_ML_DSA_87 + 1];
        uint8_t ml_kem_seen[IMB_ML_KEM_1024 + 1];

        memset(ml_dsa_seen, 0, sizeof(ml_dsa_seen));
        memset(ml_kem_seen, 0, sizeof(ml_kem_seen));

        for (unsigned i = 0; i < DIM(ml_dsa_tests); i++)
                ml_dsa_seen[ml_dsa_tests[i].alg] = 1;

        for (unsigned i = 0; i < DIM(ml_kem_tests); i++)
                ml_kem_seen[ml_kem_tests[i].alg] = 1;

        for (int i = IMB_ML_DSA_44; i <= IMB_ML_DSA_87; i++) {
                if (!ml_dsa_seen[i]) {
                        printf("WARNING: ML-DSA parameter set %d not tested\n", i);
                        missing++;
                }
        }

        for (int i = IMB_ML_KEM_512; i <= IMB_ML_KEM_1024; i++) {
                if (!ml_kem_seen[i]) {
                        printf("WARNING: ML-KEM parameter set %d not tested\n", i);
                        missing++;
                }
        }

        return missing;
}

/* ========================================================================== */
/* Main                                                                       */
/* ========================================================================== */

int
main(int argc, char **argv)
{
        uint8_t arch_support[IMB_ARCH_NUM];
        uint8_t arch_select[IMB_ARCH_NUM];
        struct oob_mem mem;
        struct pqc_oob_mem pqc_mem;
        int errors = 0;
        uint64_t flags = 0;

        memset(arch_select, 0xff, sizeof(arch_select));

        /* reduce verbosity by default */
        quiet_mode = 1;

        for (int i = 1; i < argc; i++) {
                if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                        usage(argv[0]);
                        return EXIT_SUCCESS;
                } else if (update_flags_and_archs(argv[i], arch_select, &flags)) {
                        continue;
                } else if (strcmp(argv[i], "--verbose") == 0) {
                        quiet_mode = 0;
                } else if (strcmp(argv[i], "--no-pqc") == 0) {
                        if (!job_api_enabled) {
                                printf("--no-pqc cannot be combined with --pqc-only\n");
                                return EXIT_FAILURE;
                        }
                        pqc_enabled = 0;
                } else if (strcmp(argv[i], "--pqc-only") == 0) {
                        if (!pqc_enabled) {
                                printf("--pqc-only cannot be combined with --no-pqc\n");
                                return EXIT_FAILURE;
                        }
                        job_api_enabled = 0;
                } else if (strcmp(argv[i], "--max-len") == 0) {
                        if (i + 1 >= argc) {
                                printf("--max-len requires a numeric argument\n");
                                usage(argv[0]);
                                return EXIT_FAILURE;
                        }
                        max_test_len = (unsigned) atoi(argv[++i]);
                        if (max_test_len == 0 || max_test_len > 4000) {
                                printf("--max-len must be between 1 and 4000\n");
                                return EXIT_FAILURE;
                        }
                } else {
                        printf("Unknown option: %s\n", argv[i]);
                        usage(argv[0]);
                        return EXIT_FAILURE;
                }
        }

        /* Initialize key_store with dummy data and 3DES key schedule pointers */
        memset(key_store, 0xAA, sizeof(key_store));
        ks_ptrs[0] = key_store;
        ks_ptrs[1] = key_store + 256;
        ks_ptrs[2] = key_store + 512;

        /* PON needs 8 and DOCSIS CRC 4 extra bytes */
        if (oob_mem_alloc(&mem, max_test_len + 8) != 0) {
                printf("Error allocating OOB guard memory!\n");
                oob_mem_free(&mem);
                return EXIT_FAILURE;
        }

        /* the ML-DSA mu path needs at least IMB_ML_DSA_MU_BYTES of message */
        const size_t pqc_msg_size =
                (max_test_len > IMB_ML_DSA_MU_BYTES) ? max_test_len : IMB_ML_DSA_MU_BYTES;

        if (pqc_mem_alloc(&pqc_mem, pqc_msg_size) != 0) {
                printf("Error allocating PQC OOB guard memory!\n");
                pqc_mem_free(&pqc_mem);
                oob_mem_free(&mem);
                return EXIT_FAILURE;
        }

        printf("Out-of-Bounds Memory Access Test\n"
               "Library version: %s\n",
               imb_get_version_str());

        /* Warn if any algorithm is missing from the test arrays */
        check_algorithm_coverage();

        /* Detect available architectures */
        if (detect_arch(arch_support, flags) < 0) {
                pqc_mem_free(&pqc_mem);
                oob_mem_free(&mem);
                return EXIT_FAILURE;
        }

        /* Run tests for each supported architecture */
        for (IMB_ARCH atype = IMB_ARCH_SSE; atype < IMB_ARCH_NUM; atype++) {

                arch_support[atype] = arch_support[atype] & arch_select[atype];

                if (!arch_support[atype])
                        continue;

                IMB_MGR *mgr = alloc_mb_mgr(flags);

                if (mgr == NULL) {
                        printf("Error allocating MB_MGR structure!\n");
                        pqc_mem_free(&pqc_mem);
                        oob_mem_free(&mem);
                        return EXIT_FAILURE;
                }

                if (init_mgr_for_arch(mgr, atype) != 0) {
                        free_mb_mgr(mgr);
                        continue;
                }

                uint64_t features = 0;

                (void) imb_get_features(mgr, &features);
                print_tested_arch(features, atype);

                if (run_tests_for_arch(mgr, atype, &mem, &pqc_mem) != 0)
                        errors++;

                free_mb_mgr(mgr);
        }

        pqc_mem_free(&pqc_mem);
        oob_mem_free(&mem);

        if (errors == 0)
                printf("ALL TESTS PASSED\n");
        else
                printf("TESTS FAILED (%d architecture(s) with failures)\n", errors);

        return (errors == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
