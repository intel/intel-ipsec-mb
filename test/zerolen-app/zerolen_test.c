/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

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
*****************************************************************************/

/**
 * @brief Zero-length message NOCHECK and checked API regression test
 *
 * Verifies that submitting zero-length cipher, hash and AEAD jobs through the
 * checked and NOCHECK single-job, type-specific burst and generic burst submit
 * paths does not cause buffer overreads, overwrites, or crashes.
 *
 * Technique: a single guard page (PROT_NONE / PAGE_NOACCESS) is allocated and
 * src/dst pointers are aimed directly at it. Since the message length is zero,
 * no memory access should occur. Any read or write to src/dst triggers a
 * hardware page fault (SIGSEGV / EXCEPTION_ACCESS_VIOLATION), which is caught
 * and reported as a test failure.
 *
 * Special combined modes (PON, DOCSIS-CRC32) that require a minimum non-zero
 * hash length use a small read/write buffer for the header portion, with the
 * cipher payload length set to zero.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <intel-ipsec-mb.h>
#include "utils.h"

/* ========================================================================== */
/* Guard page allocator                                                       */
/* ========================================================================== */

/** Opaque handle for a guard-page allocation */
struct guard_page {
        void *ptr;   /**< pointer to start of unmapped page */
        size_t size; /**< allocation size (one page) */
};

/**
 * @brief Detects page size in bytes
 *
 * @param [in/out] p_page_bytes pointer at which page size in bytes is stored
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 input error
 * @retval -2 sysconf() failed
 */
static int
get_page_size(size_t *p_page_bytes)
{
        if (p_page_bytes == NULL)
                return -1;
#ifdef _WIN32
        SYSTEM_INFO si;

        GetSystemInfo(&si);
        const size_t page_bytes = (size_t) si.dwPageSize;
#else
        const long ret = sysconf(_SC_PAGESIZE);

        if (ret < 0)
                return -2; /* sysconf error */

        const size_t page_bytes = (size_t) ret;
#endif
        *p_page_bytes = page_bytes;
        return 0;
}

/**
 * @brief Allocate a single page with no access permissions (guard page).
 *
 * Any read or write to the returned pointer triggers a fault.
 *
 * @param [in/out] gp guard page structure to initialize
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 failure
 */
static int
guard_page_alloc(struct guard_page *gp)
{
        memset(gp, 0, sizeof(*gp));

        size_t page_bytes = 0;
        const int ret = get_page_size(&page_bytes);

        if (ret != 0 || page_bytes == 0)
                return -1;
#ifdef _WIN32
        gp->ptr = VirtualAlloc(NULL, page_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
        if (gp->ptr == NULL)
                return -1;
#else
        gp->ptr = mmap(NULL, page_bytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (gp->ptr == MAP_FAILED) {
                gp->ptr = NULL;
                return -1;
        }
#endif
        gp->size = page_bytes;
        return 0;
}

/**
 * @brief Free a guard page allocation.
 *
 * @param [in] gp guard page structure to free
 */
static void
guard_page_free(struct guard_page *gp)
{
        if (gp->ptr == NULL)
                return;
#ifdef _WIN32
        VirtualFree(gp->ptr, 0, MEM_RELEASE);
#else
        munmap(gp->ptr, gp->size);
#endif
        memset(gp, 0, sizeof(*gp));
}

/**
 * @brief Usable memory region immediately followed by a guard page.
 *
 * Used by PON tests that need a small readable buffer (XGEM header)
 * with guard-page protection immediately after the data area.
 *
 * Layout: [ RW page(s) ][ Guard page (PROT_NONE) ]
 *
 * The usable pointer is placed at the end of the RW region so that
 * (usable + size) sits exactly at the guard page boundary.
 */
struct guard_mem {
        void *base;   /**< base of allocation */
        size_t total; /**< total allocation size (usable + guard) */
        void *usable; /**< pointer to usable region */
        size_t size;  /**< usable size in bytes */
};

/**
 * @brief Allocate a usable RW region followed by a guard page.
 *
 * The usable data is placed at the END of the RW pages, right before
 * the guard page. Any access past \a usable_size bytes hits the guard.
 *
 * @param [in/out] gm       guard memory structure to initialize
 * @param [in] usable_bytes bytes of usable memory needed
 *
 * @return Operation status
 * @retval 0 success
 * @retval -1 allocation failed
 * @retval -2 sysconf() failed
 */
static int
guard_mem_alloc(struct guard_mem *gm, const size_t usable_bytes)
{
        memset(gm, 0, sizeof(*gm));

        size_t page_bytes = 0;
        const int ret = get_page_size(&page_bytes);

        if (ret != 0 || page_bytes == 0)
                return ret;

        /* Align usable and total sizes to multiple of page size */
        const size_t usable_bytes_aligned = (usable_bytes + page_bytes - 1) & ~(page_bytes - 1);
        const size_t total_bytes_aligned = usable_bytes_aligned + page_bytes;

#ifdef _WIN32
        gm->base =
                VirtualAlloc(NULL, total_bytes_aligned, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (gm->base == NULL)
                return -1;

        DWORD old_protect;

        if (!VirtualProtect((uint8_t *) gm->base + usable_bytes_aligned, page_bytes, PAGE_NOACCESS,
                            &old_protect)) {
                VirtualFree(gm->base, 0, MEM_RELEASE);
                return -1;
        }
#else
        gm->base = mmap(NULL, total_bytes_aligned, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (gm->base == MAP_FAILED) {
                gm->base = NULL;
                return -1;
        }
        if (mprotect((uint8_t *) gm->base + usable_bytes_aligned, page_bytes, PROT_NONE) != 0) {
                munmap(gm->base, total_bytes_aligned);
                gm->base = NULL;
                return -1;
        }
#endif

        gm->total = total_bytes_aligned;
        gm->size = usable_bytes;
        gm->usable = (uint8_t *) gm->base + usable_bytes_aligned - usable_bytes;
        return 0;
}

/**
 * @brief Free a guard memory allocation.
 *
 * @param [in] gm guard memory structure to free
 */
static void
guard_mem_free(struct guard_mem *gm)
{
        if (gm->base == NULL)
                return;
#ifdef _WIN32
        VirtualFree(gm->base, 0, MEM_RELEASE);
#else
        munmap(gm->base, gm->total);
#endif
        memset(gm, 0, sizeof(*gm));
}

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
 * Uses siglongjmp to restore the signal mask so that subsequent SIGSEGV
 * signals are not blocked after recovery.
 *
 * @param [in] signum signal number (unused)
 */
static void
test_sigsegv_handler(int signum)
{
        (void) signum;
        signal(SIGSEGV, test_sigsegv_handler);
        siglongjmp(test_jmp_env, 1);
}

#define TEST_SETJMP() sigsetjmp(test_jmp_env, 1)
#endif

/* ========================================================================== */
/* Constants and shared buffers                                               */
/* ========================================================================== */

#define IV_SIZE_MAX  32 /**< max IV size across all algorithms */
#define TAG_SIZE_MAX 64 /**< max auth tag size (SHA-512 = 64 bytes) */

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
/* Architecture init helper                                                   */
/* ========================================================================== */

/**
 * @brief Initialize \a mgr for a specific architecture.
 *
 * @param [in,out] mgr multi-buffer manager to initialize
 * @param [in] arch target architecture
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
                printf("zerolen-app: %s\n", imb_get_strerror(ret));
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
};

/** Table of cipher algorithms to test with zero-length messages */
static const struct cipher_test_vec cipher_tests[] = {
        /* AES-CBC decrypt */
        { "AES-128-CBC-DEC", IMB_CIPHER_CBC, IMB_DIR_DECRYPT, 16, 16 },
        { "AES-192-CBC-DEC", IMB_CIPHER_CBC, IMB_DIR_DECRYPT, 24, 16 },
        { "AES-256-CBC-DEC", IMB_CIPHER_CBC, IMB_DIR_DECRYPT, 32, 16 },
        /* AES-CBC encrypt */
        { "AES-128-CBC-ENC", IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, 16, 16 },
        { "AES-192-CBC-ENC", IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, 24, 16 },
        { "AES-256-CBC-ENC", IMB_CIPHER_CBC, IMB_DIR_ENCRYPT, 32, 16 },
        /* AES-CTR */
        { "AES-128-CTR-ENC", IMB_CIPHER_CNTR, IMB_DIR_ENCRYPT, 16, 16 },
        { "AES-192-CTR-ENC", IMB_CIPHER_CNTR, IMB_DIR_ENCRYPT, 24, 16 },
        { "AES-256-CTR-ENC", IMB_CIPHER_CNTR, IMB_DIR_ENCRYPT, 32, 16 },
        { "AES-128-CTR-DEC", IMB_CIPHER_CNTR, IMB_DIR_DECRYPT, 16, 16 },
        { "AES-192-CTR-DEC", IMB_CIPHER_CNTR, IMB_DIR_DECRYPT, 24, 16 },
        { "AES-256-CTR-DEC", IMB_CIPHER_CNTR, IMB_DIR_DECRYPT, 32, 16 },
        /* AES-ECB */
        { "AES-128-ECB-ENC", IMB_CIPHER_ECB, IMB_DIR_ENCRYPT, 16, 0 },
        { "AES-128-ECB-DEC", IMB_CIPHER_ECB, IMB_DIR_DECRYPT, 16, 0 },
        { "AES-192-ECB-ENC", IMB_CIPHER_ECB, IMB_DIR_ENCRYPT, 24, 0 },
        { "AES-192-ECB-DEC", IMB_CIPHER_ECB, IMB_DIR_DECRYPT, 24, 0 },
        { "AES-256-ECB-ENC", IMB_CIPHER_ECB, IMB_DIR_ENCRYPT, 32, 0 },
        { "AES-256-ECB-DEC", IMB_CIPHER_ECB, IMB_DIR_DECRYPT, 32, 0 },
        /* AES-CFB */
        { "AES-128-CFB-ENC", IMB_CIPHER_CFB, IMB_DIR_ENCRYPT, 16, 16 },
        { "AES-128-CFB-DEC", IMB_CIPHER_CFB, IMB_DIR_DECRYPT, 16, 16 },
        /* DES-CBC */
        { "DES-CBC-ENC", IMB_CIPHER_DES, IMB_DIR_ENCRYPT, 8, 8 },
        { "DES-CBC-DEC", IMB_CIPHER_DES, IMB_DIR_DECRYPT, 8, 8 },
        /* 3DES-CBC */
        { "3DES-CBC-ENC", IMB_CIPHER_DES3, IMB_DIR_ENCRYPT, 24, 8 },
        { "3DES-CBC-DEC", IMB_CIPHER_DES3, IMB_DIR_DECRYPT, 24, 8 },
        /* DOCSIS-DES */
        { "DOCSIS-DES-ENC", IMB_CIPHER_DOCSIS_DES, IMB_DIR_ENCRYPT, 8, 8 },
        { "DOCSIS-DES-DEC", IMB_CIPHER_DOCSIS_DES, IMB_DIR_DECRYPT, 8, 8 },
        /* DOCSIS-SEC-BPI (AES) */
        { "DOCSIS-BPI-ENC", IMB_CIPHER_DOCSIS_SEC_BPI, IMB_DIR_ENCRYPT, 16, 16 },
        { "DOCSIS-BPI-DEC", IMB_CIPHER_DOCSIS_SEC_BPI, IMB_DIR_DECRYPT, 16, 16 },
        /* CHACHA20 */
        { "CHACHA20-ENC", IMB_CIPHER_CHACHA20, IMB_DIR_ENCRYPT, 32, 12 },
        { "CHACHA20-DEC", IMB_CIPHER_CHACHA20, IMB_DIR_DECRYPT, 32, 12 },
        /* SM4-ECB */
        { "SM4-ECB-ENC", IMB_CIPHER_SM4_ECB, IMB_DIR_ENCRYPT, 16, 0 },
        { "SM4-ECB-DEC", IMB_CIPHER_SM4_ECB, IMB_DIR_DECRYPT, 16, 0 },
        /* SM4-CBC */
        { "SM4-CBC-ENC", IMB_CIPHER_SM4_CBC, IMB_DIR_ENCRYPT, 16, 16 },
        { "SM4-CBC-DEC", IMB_CIPHER_SM4_CBC, IMB_DIR_DECRYPT, 16, 16 },
        /* SM4-CTR */
        { "SM4-CTR-ENC", IMB_CIPHER_SM4_CNTR, IMB_DIR_ENCRYPT, 16, 16 },
        { "SM4-CTR-DEC", IMB_CIPHER_SM4_CNTR, IMB_DIR_DECRYPT, 16, 16 },
        /* ZUC-EEA3 (3GPP cipher) */
        { "ZUC-EEA3-ENC", IMB_CIPHER_ZUC_EEA3, IMB_DIR_ENCRYPT, 16, 16 },
        { "ZUC-EEA3-DEC", IMB_CIPHER_ZUC_EEA3, IMB_DIR_DECRYPT, 16, 16 },
        /* SNOW3G-UEA2 (3GPP cipher, bitlen) */
        { "SNOW3G-UEA2-ENC", IMB_CIPHER_SNOW3G_UEA2_BITLEN, IMB_DIR_ENCRYPT, 16, 16 },
        { "SNOW3G-UEA2-DEC", IMB_CIPHER_SNOW3G_UEA2_BITLEN, IMB_DIR_DECRYPT, 16, 16 },
        /* KASUMI-UEA1 (3GPP cipher, bitlen) */
        { "KASUMI-UEA1-ENC", IMB_CIPHER_KASUMI_UEA1_BITLEN, IMB_DIR_ENCRYPT, 16, 8 },
        { "KASUMI-UEA1-DEC", IMB_CIPHER_KASUMI_UEA1_BITLEN, IMB_DIR_DECRYPT, 16, 8 },
};

/**
 * @brief Set up a cipher job for zero-length testing.
 *
 * Configures all required fields on \a job for cipher mode \a tv with
 * msg_len_to_cipher = 0. The \a src and \a dst pointers should point
 * to a guard page so that any access triggers a fault.
 *
 * @param [out] job  job structure to configure
 * @param [in]  tv   cipher test vector descriptor
 * @param [in]  src  source pointer (guard page)
 * @param [in]  dst  destination pointer (guard page)
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
        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_alg = IMB_AUTH_NULL;
        job->key_len_in_bytes = tv->key_len;

        if (tv->cipher == IMB_CIPHER_DES3) {
                job->enc_keys = ks_ptrs;
                job->dec_keys = ks_ptrs;
        } else {
                job->enc_keys = key_store;
                job->dec_keys = key_store;
        }
}

/**
 * @brief Test zero-length cipher via JOB API.
 *
 * Points src and dst at a guard page. If the implementation incorrectly
 * reads or writes any bytes, the CPU triggers a SIGSEGV.
 *
 * @param [in] mgr  multi-buffer manager (re-initialized before call)
 * @param [in] tv   cipher test vector
 * @param [in] gp   guard page allocation
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail (segfault or error)
 */
static int
test_cipher_zerolen(IMB_MGR *mgr, const struct cipher_test_vec *tv, const struct guard_page *gp,
                    const int use_nocheck)
{
        uint8_t iv[IV_SIZE_MAX];
        IMB_JOB *job;
        int segfault;

        memset(iv, 0xBB, sizeof(iv));

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        segfault = TEST_SETJMP();
        if (segfault) {
                printf("  FAIL: %s SEGFAULT during %s submit\n", tv->name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
                return -1;
        }

        job = IMB_GET_NEXT_JOB(mgr);
        if (job == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_JOB returned NULL\n", tv->name);
                return -1;
        }

        setup_cipher_job(job, tv, (const uint8_t *) gp->ptr, (uint8_t *) gp->ptr, iv);

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
 * @brief Test zero-length cipher via burst API.
 *
 * @param [in] mgr  multi-buffer manager (re-initialized before call)
 * @param [in] tv   cipher test vector
 * @param [in] gp   guard page allocation
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail (segfault or error)
 */
static int
test_cipher_burst_zerolen(IMB_MGR *mgr, const struct cipher_test_vec *tv,
                          const struct guard_page *gp, const int use_nocheck)
{
        uint8_t iv[IV_SIZE_MAX];
        IMB_JOB jobs[1];
        int segfault;

        memset(iv, 0xBB, sizeof(iv));

        segfault = TEST_SETJMP();
        if (segfault) {
                printf("  FAIL: %s (burst) SEGFAULT during %s submit\n", tv->name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
                return -1;
        }

        setup_cipher_job(&jobs[0], tv, (const uint8_t *) gp->ptr, (uint8_t *) gp->ptr, iv);

        if (use_nocheck)
                IMB_SUBMIT_CIPHER_BURST_NOCHECK(mgr, jobs, 1, tv->cipher, tv->dir, tv->key_len);
        else
                IMB_SUBMIT_CIPHER_BURST(mgr, jobs, 1, tv->cipher, tv->dir, tv->key_len);

        return 0;
}

/**
 * @brief Test zero-length cipher via generic burst API.
 *
 * Uses IMB_GET_NEXT_BURST / imb_set_session / IMB_SUBMIT_BURST path
 * rather than the cipher-specific burst API.
 *
 * @param [in] mgr  multi-buffer manager
 * @param [in] tv   cipher test vector
 * @param [in] gp   guard page allocation
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail (segfault or error)
 */
static int
test_cipher_generic_burst_zerolen(IMB_MGR *mgr, const struct cipher_test_vec *tv,
                                  const struct guard_page *gp, const int use_nocheck)
{
        uint8_t iv[IV_SIZE_MAX];
        IMB_JOB *jobs[1];

        memset(iv, 0xBB, sizeof(iv));

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();
        if (segfault) {
                printf("  FAIL: %s (generic burst) SEGFAULT during %s submit\n", tv->name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
                return -1;
        }

        const uint32_t n = IMB_GET_NEXT_BURST(mgr, 1, jobs);
        if (n == 0 || jobs[0] == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_BURST returned 0\n", tv->name);
                return -1;
        }

        setup_cipher_job(jobs[0], tv, (const uint8_t *) gp->ptr, (uint8_t *) gp->ptr, iv);
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
        HASH_PLAIN,    /**< no special union fields (SHA, CRC, SHA3, etc.) */
        HASH_HMAC,     /**< u.HMAC ipad/opad */
        HASH_XCBC,     /**< u.XCBC k1/k2/k3 */
        HASH_CMAC,     /**< u.CMAC key_expanded/skey1/skey2 */
        HASH_GMAC,     /**< u.GMAC key/iv/iv_len */
        HASH_GHASH,    /**< u.GHASH key/init_tag */
        HASH_POLY1305, /**< u.POLY1305 key */
        HASH_ZUC,      /**< u.ZUC_EIA3 key/iv */
        HASH_SNOW3G,   /**< u.SNOW3G_UIA2 key/iv */
        HASH_KASUMI,   /**< u.KASUMI_UIA1 key */
};

/** Hash test vector descriptor */
struct hash_test_vec {
        const char *name;      /**< test name for display */
        IMB_HASH_ALG hash;     /**< hash algorithm to test */
        unsigned tag_len;      /**< authentication tag length in bytes */
        enum hash_setup setup; /**< which union fields to configure */
};

/** Table of hash algorithms to test with zero-length messages */

static const struct hash_test_vec hash_tests[] = {
        /* HMAC */
        { "HMAC-SHA-1", IMB_AUTH_HMAC_SHA_1, 12, HASH_HMAC },
        { "HMAC-SHA-224", IMB_AUTH_HMAC_SHA_224, 14, HASH_HMAC },
        { "HMAC-SHA-256", IMB_AUTH_HMAC_SHA_256, 16, HASH_HMAC },
        { "HMAC-SHA-384", IMB_AUTH_HMAC_SHA_384, 24, HASH_HMAC },
        { "HMAC-SHA-512", IMB_AUTH_HMAC_SHA_512, 32, HASH_HMAC },
        { "HMAC-MD5", IMB_AUTH_MD5, 12, HASH_HMAC },
        { "HMAC-SM3", IMB_AUTH_HMAC_SM3, 32, HASH_HMAC },
        /* SHA (plain) */
        { "SHA-1", IMB_AUTH_SHA_1, 20, HASH_PLAIN },
        { "SHA-224", IMB_AUTH_SHA_224, 28, HASH_PLAIN },
        { "SHA-256", IMB_AUTH_SHA_256, 32, HASH_PLAIN },
        { "SHA-384", IMB_AUTH_SHA_384, 48, HASH_PLAIN },
        { "SHA-512", IMB_AUTH_SHA_512, 64, HASH_PLAIN },
        /* SM3 */
        { "SM3", IMB_AUTH_SM3, 32, HASH_PLAIN },
        /* AES-XCBC */
        { "AES-XCBC", IMB_AUTH_AES_XCBC, 12, HASH_XCBC },
        /* AES-CMAC */
        { "AES-CMAC", IMB_AUTH_AES_CMAC, 16, HASH_CMAC },
        { "AES-CMAC-256", IMB_AUTH_AES_CMAC_256, 16, HASH_CMAC },
        { "AES-CMAC-BITLEN", IMB_AUTH_AES_CMAC_BITLEN, 4, HASH_CMAC },
        /* AES-GMAC (standalone, not paired with GCM cipher) */
        { "AES-GMAC-128", IMB_AUTH_AES_GMAC_128, 16, HASH_GMAC },
        { "AES-GMAC-192", IMB_AUTH_AES_GMAC_192, 16, HASH_GMAC },
        { "AES-GMAC-256", IMB_AUTH_AES_GMAC_256, 16, HASH_GMAC },
        /* GHASH */
        { "GHASH", IMB_AUTH_GHASH, 16, HASH_GHASH },
        /* POLY1305 */
        { "POLY1305", IMB_AUTH_POLY1305, 16, HASH_POLY1305 },
        /* CRC variants */
        { "CRC32-ETH-FCS", IMB_AUTH_CRC32_ETHERNET_FCS, 4, HASH_PLAIN },
        { "CRC32-SCTP", IMB_AUTH_CRC32_SCTP, 4, HASH_PLAIN },
        { "CRC32-WIMAX", IMB_AUTH_CRC32_WIMAX_OFDMA_DATA, 4, HASH_PLAIN },
        { "CRC24-LTE-A", IMB_AUTH_CRC24_LTE_A, 4, HASH_PLAIN },
        { "CRC24-LTE-B", IMB_AUTH_CRC24_LTE_B, 4, HASH_PLAIN },
        { "CRC16-X25", IMB_AUTH_CRC16_X25, 4, HASH_PLAIN },
        { "CRC16-FP-DATA", IMB_AUTH_CRC16_FP_DATA, 4, HASH_PLAIN },
        { "CRC11-FP-HDR", IMB_AUTH_CRC11_FP_HEADER, 4, HASH_PLAIN },
        { "CRC10-IUUP", IMB_AUTH_CRC10_IUUP_DATA, 4, HASH_PLAIN },
        { "CRC8-WIMAX-HCS", IMB_AUTH_CRC8_WIMAX_OFDMA_HCS, 4, HASH_PLAIN },
        { "CRC7-FP-HDR", IMB_AUTH_CRC7_FP_HEADER, 4, HASH_PLAIN },
        { "CRC6-IUUP-HDR", IMB_AUTH_CRC6_IUUP_HEADER, 4, HASH_PLAIN },
        /* 3GPP integrity algorithms */
        { "ZUC-EIA3", IMB_AUTH_ZUC_EIA3_BITLEN, 4, HASH_ZUC },
        { "SNOW3G-UIA2", IMB_AUTH_SNOW3G_UIA2_BITLEN, 4, HASH_SNOW3G },
        { "KASUMI-UIA1", IMB_AUTH_KASUMI_UIA1, 4, HASH_KASUMI },
        /* SHA3 */
        { "SHA3-224", IMB_AUTH_SHA3_224, 28, HASH_PLAIN },
        { "SHA3-256", IMB_AUTH_SHA3_256, 32, HASH_PLAIN },
        { "SHA3-384", IMB_AUTH_SHA3_384, 48, HASH_PLAIN },
        { "SHA3-512", IMB_AUTH_SHA3_512, 64, HASH_PLAIN },
        /* SHAKE */
        { "SHAKE128", IMB_AUTH_SHAKE128, 16, HASH_PLAIN },
        { "SHAKE256", IMB_AUTH_SHAKE256, 32, HASH_PLAIN },
};

/**
 * @brief Populate hash-specific union fields in \a job.
 *
 * @param [in,out] job   job structure
 * @param [in]     setup which union to configure
 */
static void
setup_hash_fields(IMB_JOB *job, const enum hash_setup setup)
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
                job->u.GMAC._iv = key_store + 4096;
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
                job->u.ZUC_EIA3._iv = key_store + 256;
                break;
        case HASH_SNOW3G:
                job->u.SNOW3G_UIA2._key = key_store;
                job->u.SNOW3G_UIA2._iv = key_store + 256;
                break;
        case HASH_KASUMI:
                job->u.KASUMI_UIA1._key = key_store;
                break;
        case HASH_PLAIN:
        default:
                break;
        }
}

/**
 * @brief Test zero-length hash via JOB API.
 *
 * @param [in] mgr  multi-buffer manager
 * @param [in] tv   hash test vector
 * @param [in] gp   guard page allocation
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_hash_zerolen(IMB_MGR *mgr, const struct hash_test_vec *tv, const struct guard_page *gp,
                  const int use_nocheck)
{
        uint8_t tag[TAG_SIZE_MAX];

        memset(tag, 0, sizeof(tag));

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                printf("  FAIL: %s SEGFAULT during %s submit\n", tv->name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
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
        job->src = (const uint8_t *) gp->ptr;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = 0;
        job->auth_tag_output = tag;
        job->auth_tag_output_len_in_bytes = tv->tag_len;

        setup_hash_fields(job, tv->setup);

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
 * @brief Test zero-length hash via burst API.
 *
 * @param [in] mgr  multi-buffer manager
 * @param [in] tv   hash test vector
 * @param [in] gp   guard page allocation
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_hash_burst_zerolen(IMB_MGR *mgr, const struct hash_test_vec *tv, const struct guard_page *gp,
                        const int use_nocheck)
{
        uint8_t tag[TAG_SIZE_MAX];

        memset(tag, 0, sizeof(tag));

        const int segfault = TEST_SETJMP();

        if (segfault) {
                printf("  FAIL: %s (burst) SEGFAULT during %s submit\n", tv->name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
                return -1;
        }

        IMB_JOB jobs[1];

        memset(&jobs[0], 0, sizeof(jobs[0]));

        jobs[0].hash_alg = tv->hash;
        jobs[0].chain_order = IMB_ORDER_HASH_CIPHER;
        jobs[0].cipher_mode = IMB_CIPHER_NULL;
        jobs[0].src = (const uint8_t *) gp->ptr;
        jobs[0].hash_start_src_offset_in_bytes = 0;
        jobs[0].msg_len_to_hash_in_bytes = 0;
        jobs[0].auth_tag_output = tag;
        jobs[0].auth_tag_output_len_in_bytes = tv->tag_len;

        setup_hash_fields(&jobs[0], tv->setup);

        if (use_nocheck)
                IMB_SUBMIT_HASH_BURST_NOCHECK(mgr, jobs, 1, tv->hash);
        else
                IMB_SUBMIT_HASH_BURST(mgr, jobs, 1, tv->hash);

        return 0;
}

/**
 * @brief Test zero-length hash via generic burst API.
 *
 * Uses IMB_GET_NEXT_BURST / imb_set_session / IMB_SUBMIT_BURST path
 * rather than the hash-specific burst API.
 *
 * @param [in] mgr  multi-buffer manager
 * @param [in] tv   hash test vector
 * @param [in] gp   guard page allocation
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_hash_generic_burst_zerolen(IMB_MGR *mgr, const struct hash_test_vec *tv,
                                const struct guard_page *gp, const int use_nocheck)
{
        uint8_t tag[TAG_SIZE_MAX];

        memset(tag, 0, sizeof(tag));

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                printf("  FAIL: %s (generic burst) SEGFAULT during %s submit\n", tv->name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
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
        jobs[0]->src = (const uint8_t *) gp->ptr;
        jobs[0]->hash_start_src_offset_in_bytes = 0;
        jobs[0]->msg_len_to_hash_in_bytes = 0;
        jobs[0]->auth_tag_output = tag;
        jobs[0]->auth_tag_output_len_in_bytes = tv->tag_len;

        setup_hash_fields(jobs[0], tv->setup);
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
};

/** Table of AEAD algorithms to test with zero-length messages */
static const struct aead_test_vec aead_tests[] = {
        /* AES-GCM */
        { "AES-GCM-128-ENC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_ENCRYPT, 16, 12, 16 },
        { "AES-GCM-128-DEC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_DECRYPT, 16, 12, 16 },
        { "AES-GCM-192-ENC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_ENCRYPT, 24, 12, 16 },
        { "AES-GCM-192-DEC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_DECRYPT, 24, 12, 16 },
        { "AES-GCM-256-ENC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_ENCRYPT, 32, 12, 16 },
        { "AES-GCM-256-DEC", IMB_CIPHER_GCM, IMB_AUTH_AES_GMAC, IMB_DIR_DECRYPT, 32, 12, 16 },
        /* AES-CCM */
        { "AES-CCM-128-ENC", IMB_CIPHER_CCM, IMB_AUTH_AES_CCM, IMB_DIR_ENCRYPT, 16, 13, 8 },
        { "AES-CCM-128-DEC", IMB_CIPHER_CCM, IMB_AUTH_AES_CCM, IMB_DIR_DECRYPT, 16, 13, 8 },
        /* CHACHA20-POLY1305 */
        { "CHACHA20-POLY-ENC", IMB_CIPHER_CHACHA20_POLY1305, IMB_AUTH_CHACHA20_POLY1305,
          IMB_DIR_ENCRYPT, 32, 12, 16 },
        { "CHACHA20-POLY-DEC", IMB_CIPHER_CHACHA20_POLY1305, IMB_AUTH_CHACHA20_POLY1305,
          IMB_DIR_DECRYPT, 32, 12, 16 },
        /* SM4-GCM */
        { "SM4-GCM-ENC", IMB_CIPHER_SM4_GCM, IMB_AUTH_SM4_GCM, IMB_DIR_ENCRYPT, 16, 12, 16 },
        { "SM4-GCM-DEC", IMB_CIPHER_SM4_GCM, IMB_AUTH_SM4_GCM, IMB_DIR_DECRYPT, 16, 12, 16 },
};

/**
 * @brief Set up an AEAD job for zero-length testing.
 *
 * @param [out] job  job structure
 * @param [in]  tv   AEAD test vector
 * @param [in]  src  source pointer (guard page)
 * @param [in]  dst  destination pointer (guard page)
 * @param [in]  iv   IV buffer (valid memory)
 * @param [out] tag  authentication tag output buffer
 */
static void
setup_aead_job(IMB_JOB *job, const struct aead_test_vec *tv, const uint8_t *src, uint8_t *dst,
               const uint8_t *iv, uint8_t *tag)
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
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = 0;
        job->auth_tag_output = tag;
        job->auth_tag_output_len_in_bytes = tv->tag_len;

        /* re-use protected \a src pointer for AAD */
        switch (tv->hash) {
        case IMB_AUTH_AES_GMAC:
        case IMB_AUTH_SM4_GCM:
                job->u.GCM.aad = src;
                job->u.GCM.aad_len_in_bytes = 0;
                break;
        case IMB_AUTH_AES_CCM:
                job->u.CCM.aad = src;
                job->u.CCM.aad_len_in_bytes = 0;
                break;
        case IMB_AUTH_CHACHA20_POLY1305:
                job->u.CHACHA20_POLY1305.aad = src;
                job->u.CHACHA20_POLY1305.aad_len_in_bytes = 0;
                break;
        default:
                break;
        }
}

/**
 * @brief Test zero-length AEAD via JOB API.
 *
 * @param [in] mgr  multi-buffer manager
 * @param [in] tv   AEAD test vector
 * @param [in] gp   guard page allocation
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_aead_zerolen(IMB_MGR *mgr, const struct aead_test_vec *tv, const struct guard_page *gp,
                  int use_nocheck)
{
        uint8_t iv[IV_SIZE_MAX];
        uint8_t tag[TAG_SIZE_MAX];

        memset(iv, 0xBB, sizeof(iv));
        memset(tag, 0, sizeof(tag));

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                printf("  FAIL: %s SEGFAULT during %s submit\n", tv->name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
                return -1;
        }

        IMB_JOB *job = IMB_GET_NEXT_JOB(mgr);

        if (job == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_JOB returned NULL\n", tv->name);
                return -1;
        }

        setup_aead_job(job, tv, (const uint8_t *) gp->ptr, (uint8_t *) gp->ptr, iv, tag);

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
 * @brief Test zero-length AEAD via burst API.
 *
 * @param [in] mgr  multi-buffer manager
 * @param [in] tv   AEAD test vector
 * @param [in] gp   guard page allocation
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_aead_burst_zerolen(IMB_MGR *mgr, const struct aead_test_vec *tv, const struct guard_page *gp,
                        const int use_nocheck)
{
        uint8_t iv[IV_SIZE_MAX];
        uint8_t tag[TAG_SIZE_MAX];

        memset(iv, 0xBB, sizeof(iv));
        memset(tag, 0, sizeof(tag));

        const int segfault = TEST_SETJMP();
        if (segfault) {
                printf("  FAIL: %s (burst) SEGFAULT during %s submit\n", tv->name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
                return -1;
        }

        IMB_JOB jobs[1];

        setup_aead_job(&jobs[0], tv, (const uint8_t *) gp->ptr, (uint8_t *) gp->ptr, iv, tag);

        if (use_nocheck)
                IMB_SUBMIT_AEAD_BURST_NOCHECK(mgr, jobs, 1, tv->cipher, tv->dir, tv->key_len);
        else
                IMB_SUBMIT_AEAD_BURST(mgr, jobs, 1, tv->cipher, tv->dir, tv->key_len);

        return 0;
}

/**
 * @brief Test zero-length AEAD via generic burst API.
 *
 * Uses IMB_GET_NEXT_BURST / imb_set_session / IMB_SUBMIT_BURST path
 * rather than the AEAD-specific burst API.
 *
 * @param [in] mgr  multi-buffer manager
 * @param [in] tv   AEAD test vector
 * @param [in] gp   guard page allocation
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_aead_generic_burst_zerolen(IMB_MGR *mgr, const struct aead_test_vec *tv,
                                const struct guard_page *gp, const int use_nocheck)
{
        uint8_t iv[IV_SIZE_MAX];
        uint8_t tag[TAG_SIZE_MAX];

        memset(iv, 0xBB, sizeof(iv));
        memset(tag, 0, sizeof(tag));

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();
        if (segfault) {
                printf("  FAIL: %s (generic burst) SEGFAULT during %s submit\n", tv->name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
                return -1;
        }

        IMB_JOB *jobs[1];

        const uint32_t n = IMB_GET_NEXT_BURST(mgr, 1, jobs);
        if (n == 0 || jobs[0] == NULL) {
                printf("  FAIL: %s IMB_GET_NEXT_BURST returned 0\n", tv->name);
                return -1;
        }

        setup_aead_job(jobs[0], tv, (const uint8_t *) gp->ptr, (uint8_t *) gp->ptr, iv, tag);
        imb_set_session(mgr, jobs[0]);

        if (use_nocheck)
                IMB_SUBMIT_BURST_NOCHECK(mgr, 1, jobs);
        else
                IMB_SUBMIT_BURST(mgr, 1, jobs);

        IMB_FLUSH_BURST(mgr, 1, jobs);

        return 0;
}

/* ========================================================================== */
/* Test: Special combined cipher+hash modes (PON, DOCSIS-CRC32)              */
/*       These have unique coupling constraints and are tested separately.    */
/* ========================================================================== */

/* ========================================================================== */
/* Special combined-mode tests (PON, DOCSIS-CRC32)                           */
/* ========================================================================== */

/**
 * @brief Test PON BIP-only mode (zero cipher length) via JOB API.
 *
 * PON requires an 8-byte XGEM header that is always hashed (BIP). The cipher
 * payload length is set to zero so the BIP computation covers only the header.
 * The guard_mem allocation places the 8-byte header right before a guard page
 * so any overread past the XGEM header triggers a fault.
 *
 * @param [in] mgr  multi-buffer manager
 * @param [in] dir  encrypt or decrypt direction
 * @param [in] name test name for display
 * @param [in] gm   guard memory allocation (8 bytes usable)
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_pon_zerolen(IMB_MGR *mgr, IMB_CIPHER_DIRECTION dir, const char *name,
                 const struct guard_mem *gm, const int use_nocheck)
{
        const uint64_t xgem_offset = 8;
        uint8_t tag[8];

        memset(gm->usable, 0, gm->size);
        memset(tag, 0, sizeof(tag));

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();
        if (segfault) {
                printf("  FAIL: %s SEGFAULT during %s submit\n", name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
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

        job->src = (const uint8_t *) gm->usable;
        job->dst = (uint8_t *) gm->usable + xgem_offset;
        job->cipher_start_src_offset_in_bytes = xgem_offset;
        job->hash_start_src_offset_in_bytes = 0;

        job->msg_len_to_cipher_in_bytes = 0;
        job->enc_keys = NULL;
        job->dec_keys = NULL;
        job->key_len_in_bytes = 0;
        job->iv = NULL;
        job->iv_len_in_bytes = 0;

        job->msg_len_to_hash_in_bytes = 8;
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
 * @brief Test DOCSIS-CRC32 with zero cipher and hash length via JOB API.
 *
 * Both msg_len_to_cipher and msg_len_to_hash are set to zero. The src/dst
 * pointers point at a guard page so any access triggers a fault.
 *
 * @param [in] mgr  multi-buffer manager
 * @param [in] dir  encrypt or decrypt direction
 * @param [in] name test name for display
 * @param [in] gp   guard page allocation
 * @param [in] use_nocheck non-zero to use NOCHECK API, 0 for checked API
 *
 * @return Test status
 * @retval 0 pass
 * @retval -1 fail
 */
static int
test_docsis_crc32_zerolen(IMB_MGR *mgr, IMB_CIPHER_DIRECTION dir, const char *name,
                          const struct guard_page *gp, const int use_nocheck)
{
        uint8_t iv[IV_SIZE_MAX];
        uint8_t tag[TAG_SIZE_MAX];

        memset(iv, 0xBB, sizeof(iv));
        memset(tag, 0, sizeof(tag));

        while (IMB_FLUSH_JOB(mgr) != NULL)
                ;

        const int segfault = TEST_SETJMP();

        if (segfault) {
                printf("  FAIL: %s SEGFAULT during %s submit\n", name,
                       use_nocheck ? "NOCHECK" : "CHECKED");
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

        job->src = (const uint8_t *) gp->ptr;
        job->dst = (uint8_t *) gp->ptr;
        job->iv = iv;
        job->iv_len_in_bytes = 16;
        job->enc_keys = key_store;
        job->dec_keys = key_store;
        job->key_len_in_bytes = 16;

        job->cipher_start_src_offset_in_bytes = 0;
        job->msg_len_to_cipher_in_bytes = 0;
        job->hash_start_src_offset_in_bytes = 0;
        job->msg_len_to_hash_in_bytes = 0;
        job->auth_tag_output = tag;
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

/**
 * @brief Run all zero-length tests for a given architecture.
 *
 * Iterates over cipher, hash, AEAD and special combined-mode tests,
 * catching any SIGSEGV or EXCEPTION_ACCESS_VIOLATION as a test failure.
 * Each test category is run with NOCHECK and CHECKED submit paths for
 * single-job, type-specific burst and generic burst APIs.
 *
 * @param [in] mgr  multi-buffer manager
 * @param [in] arch architecture to test
 * @param [in] gp   guard page allocation
 * @param [in] gm   guard memory allocation (for PON tests)
 *
 * @return Aggregate status
 * @retval 0 all tests passed
 * @retval -1 one or more tests failed
 */
static int
run_tests_for_arch(IMB_MGR *mgr, const struct guard_page *gp, const struct guard_mem *gm)
{
        unsigned pass = 0, fail = 0;
#ifdef _WIN32
        LPTOP_LEVEL_EXCEPTION_FILTER prev_handler;
#else
        void (*prev_handler)(int);
#endif

        static const struct {
                const char *name;
                IMB_CIPHER_DIRECTION dir;
                int is_pon; /* 1 = PON, 0 = DOCSIS-CRC32 */
        } special_tests[] = {
                { "PON-BIP-ONLY-ENC", IMB_DIR_ENCRYPT, 1 },
                { "PON-BIP-ONLY-DEC", IMB_DIR_DECRYPT, 1 },
                { "DOCSIS-CRC32-ENC", IMB_DIR_ENCRYPT, 0 },
                { "DOCSIS-CRC32-DEC", IMB_DIR_DECRYPT, 0 },
        };

        /* Install signal/exception handler */
#ifdef _WIN32
        prev_handler = SetUnhandledExceptionFilter(test_exception_handler);
#else
        prev_handler = signal(SIGSEGV, test_sigsegv_handler);
#endif

        for (int use_nocheck = 0; use_nocheck <= 1; use_nocheck++) {
                const char *api_name = use_nocheck ? "NOCHECK" : "CHECKED";

                /* ---- Cipher tests (single job) ---- */
                if (!quiet_mode)
                        printf("  Cipher tests (single-job %s, msg_len=0):\n", api_name);

                for (unsigned i = 0; i < DIM(cipher_tests); i++) {
                        if (test_cipher_zerolen(mgr, &cipher_tests[i], gp, use_nocheck) == 0) {
                                pass++;
                                if (!quiet_mode)
                                        printf("    %-28s PASS\n", cipher_tests[i].name);
                        } else {
                                fail++;
                                printf("    %-28s FAIL\n", cipher_tests[i].name);
                        }
                }

                /* ---- Cipher tests (burst) ---- */
                if (!quiet_mode)
                        printf("  Cipher tests (burst %s, msg_len=0):\n", api_name);

                for (unsigned i = 0; i < DIM(cipher_tests); i++) {
                        if (test_cipher_burst_zerolen(mgr, &cipher_tests[i], gp, use_nocheck) ==
                            0) {
                                pass++;
                                if (!quiet_mode)
                                        printf("    %-28s PASS (burst)\n", cipher_tests[i].name);
                        } else {
                                fail++;
                                printf("    %-28s FAIL (burst)\n", cipher_tests[i].name);
                        }
                }

                /* ---- Cipher tests (generic burst) ---- */
                if (!quiet_mode)
                        printf("  Cipher tests (generic burst %s, msg_len=0):\n", api_name);

                for (unsigned i = 0; i < DIM(cipher_tests); i++) {
                        if (test_cipher_generic_burst_zerolen(mgr, &cipher_tests[i], gp,
                                                              use_nocheck) == 0) {
                                pass++;
                                if (!quiet_mode)
                                        printf("    %-28s PASS (generic burst)\n",
                                               cipher_tests[i].name);
                        } else {
                                fail++;
                                printf("    %-28s FAIL (generic burst)\n", cipher_tests[i].name);
                        }
                }

                /* ---- Hash tests (single job) ---- */
                if (!quiet_mode)
                        printf("  Hash tests (single-job %s, msg_len=0):\n", api_name);

                for (unsigned i = 0; i < DIM(hash_tests); i++) {
                        if (test_hash_zerolen(mgr, &hash_tests[i], gp, use_nocheck) == 0) {
                                pass++;
                                if (!quiet_mode)
                                        printf("    %-28s PASS\n", hash_tests[i].name);
                        } else {
                                fail++;
                                printf("    %-28s FAIL\n", hash_tests[i].name);
                        }
                }

                /* ---- Hash tests (burst) ---- */
                if (!quiet_mode)
                        printf("  Hash tests (burst %s, msg_len=0):\n", api_name);

                for (unsigned i = 0; i < DIM(hash_tests); i++) {
                        if (test_hash_burst_zerolen(mgr, &hash_tests[i], gp, use_nocheck) == 0) {
                                pass++;
                                if (!quiet_mode)
                                        printf("    %-28s PASS (burst)\n", hash_tests[i].name);
                        } else {
                                fail++;
                                printf("    %-28s FAIL (burst)\n", hash_tests[i].name);
                        }
                }

                /* ---- Hash tests (generic burst) ---- */
                if (!quiet_mode)
                        printf("  Hash tests (generic burst %s, msg_len=0):\n", api_name);

                for (unsigned i = 0; i < DIM(hash_tests); i++) {
                        if (test_hash_generic_burst_zerolen(mgr, &hash_tests[i], gp, use_nocheck) ==
                            0) {
                                pass++;
                                if (!quiet_mode)
                                        printf("    %-28s PASS (generic burst)\n",
                                               hash_tests[i].name);
                        } else {
                                fail++;
                                printf("    %-28s FAIL (generic burst)\n", hash_tests[i].name);
                        }
                }

                /* ---- AEAD tests (single job) ---- */
                if (!quiet_mode)
                        printf("  AEAD tests (single-job %s, msg_len=0):\n", api_name);

                for (unsigned i = 0; i < DIM(aead_tests); i++) {
                        if (test_aead_zerolen(mgr, &aead_tests[i], gp, use_nocheck) == 0) {
                                pass++;
                                if (!quiet_mode)
                                        printf("    %-28s PASS\n", aead_tests[i].name);
                        } else {
                                fail++;
                                printf("    %-28s FAIL\n", aead_tests[i].name);
                        }
                }

                /* ---- AEAD tests (burst) ---- */
                if (!quiet_mode)
                        printf("  AEAD tests (burst %s, msg_len=0):\n", api_name);

                for (unsigned i = 0; i < DIM(aead_tests); i++) {
                        if (test_aead_burst_zerolen(mgr, &aead_tests[i], gp, use_nocheck) == 0) {
                                pass++;
                                if (!quiet_mode)
                                        printf("    %-28s PASS (burst)\n", aead_tests[i].name);
                        } else {
                                fail++;
                                printf("    %-28s FAIL (burst)\n", aead_tests[i].name);
                        }
                }

                /* ---- AEAD tests (generic burst) ---- */
                if (!quiet_mode)
                        printf("  AEAD tests (generic burst %s, msg_len=0):\n", api_name);

                for (unsigned i = 0; i < DIM(aead_tests); i++) {
                        if (test_aead_generic_burst_zerolen(mgr, &aead_tests[i], gp, use_nocheck) ==
                            0) {
                                pass++;
                                if (!quiet_mode)
                                        printf("    %-28s PASS (generic burst)\n",
                                               aead_tests[i].name);
                        } else {
                                fail++;
                                printf("    %-28s FAIL (generic burst)\n", aead_tests[i].name);
                        }
                }

                /* ---- Special combined mode tests (PON, DOCSIS-CRC32) ---- */
                if (!quiet_mode)
                        printf("  Special combined mode tests (%s, cipher_len=0):\n", api_name);

                for (unsigned i = 0; i < DIM(special_tests); i++) {
                        int ok;

                        if (special_tests[i].is_pon)
                                ok = test_pon_zerolen(mgr, special_tests[i].dir,
                                                      special_tests[i].name, gm, use_nocheck);
                        else
                                ok = test_docsis_crc32_zerolen(mgr, special_tests[i].dir,
                                                               special_tests[i].name, gp,
                                                               use_nocheck);
                        if (ok == 0) {
                                pass++;
                                if (!quiet_mode)
                                        printf("    %-28s PASS\n", special_tests[i].name);
                        } else {
                                fail++;
                                printf("    %-28s FAIL\n", special_tests[i].name);
                        }
                }
        }

        /* Restore signal/exception handler */
#ifdef _WIN32
        SetUnhandledExceptionFilter(prev_handler);
#else
        signal(SIGSEGV, prev_handler);
#endif

        printf("  Results: %u passed, %u failed\n", pass, fail);
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
               "  --verbose     Increase tool verbosity\n"
               "  -h, --help    Show this help\n",
               prog);
}

/* ========================================================================== */
/* Main                                                                       */
/* ========================================================================== */

int
main(int argc, char **argv)
{
        uint8_t arch_support[IMB_ARCH_NUM];
        uint8_t arch_select[IMB_ARCH_NUM];
        struct guard_page gp;
        struct guard_mem gm;
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

        /* Allocate a single guard page used by all tests */
        if (guard_page_alloc(&gp) != 0) {
                printf("Error allocating guard page!\n");
                return EXIT_FAILURE;
        }

        /* Allocate guard memory for PON tests (8-byte XGEM header) */
        if (guard_mem_alloc(&gm, 8) != 0) {
                printf("Error allocating guard memory!\n");
                guard_page_free(&gp);
                return EXIT_FAILURE;
        }

        printf("Zero-Length Message Test\n"
               "Library version: %s\n",
               imb_get_version_str());

        /* Detect available architectures */
        if (detect_arch(arch_support, flags) < 0) {
                guard_mem_free(&gm);
                guard_page_free(&gp);
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
                        guard_mem_free(&gm);
                        guard_page_free(&gp);
                        return EXIT_FAILURE;
                }

                if (init_mgr_for_arch(mgr, atype) != 0) {
                        free_mb_mgr(mgr);
                        continue;
                }

                print_tested_arch(mgr->features, atype);

                if (run_tests_for_arch(mgr, &gp, &gm) != 0)
                        errors++;

                free_mb_mgr(mgr);
        }

        guard_mem_free(&gm);
        guard_page_free(&gp);

        if (errors == 0)
                printf("ALL TESTS PASSED\n");
        else
                printf("TESTS FAILED (%d architecture(s) with failures)\n", errors);

        return (errors == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
