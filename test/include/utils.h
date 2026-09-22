/*****************************************************************************
 Copyright (c) 2018-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef TESTAPP_UTILS_H
#define TESTAPP_UTILS_H

#include <stdio.h>
#include <fcntl.h>
#ifdef _WIN32
#include <malloc.h>
#endif
#include <intel-ipsec-mb.h>

#ifdef _WIN32
#include <io.h>
#define IMB_DUP     _dup
#define IMB_DUP2    _dup2
#define IMB_OPEN    _open
#define IMB_CLOSE   _close
#define IMB_DEVNULL "NUL"
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif
#else
#include <unistd.h>
#define IMB_DUP     dup
#define IMB_DUP2    dup2
#define IMB_OPEN    open
#define IMB_CLOSE   close
#define IMB_DEVNULL "/dev/null"
#endif

#define DIM(_x)            (sizeof(_x) / sizeof(_x[0]))
#define DIV_ROUND_UP(x, y) ((x + y - 1) / y)

/*
 * Reduced maximum number of jobs used by KAT tests. Set to the widest
 * multi-buffer OOO manager lane count plus 1 (AVX512_NUM_MD5_LANES + 1 = 33), which is
 * enough to exercise all submit/flush code paths (lane fill, refill and flush
 * of a partial batch) without the runtime cost of processing
 * IMB_MAX_BURST_SIZE (128) jobs.
 */
#define TEST_MAX_NUM_JOBS 33

#if TEST_MAX_NUM_JOBS > IMB_MAX_BURST_SIZE
#error "TEST_MAX_NUM_JOBS must not exceed IMB_MAX_BURST_SIZE"
#endif

extern int quiet_mode;
extern const unsigned test_num_jobs[];
extern const size_t test_num_jobs_size;
struct mac_test;
struct cipher_test;

void
hexdump(FILE *fp, const char *msg, const void *p, size_t len);
void
hexdump_ex(FILE *fp, const char *msg, const void *p, size_t len, const void *start_ptr);
void
byte_hexdump(const char *message, const uint8_t *ptr, int len);

int
update_flags_and_archs(const char *arg, uint8_t arch_support[IMB_ARCH_NUM], uint64_t *flags);
int
detect_arch(uint8_t arch_support[IMB_ARCH_NUM], const uint64_t flags);
void
print_tested_arch(const uint64_t features, const IMB_ARCH arch);

struct test_suite_context {
        unsigned pass;
        unsigned fail;
        const char *alg_name;
};

void
test_suite_start(struct test_suite_context *ctx, const char *alg_name);
void
test_suite_update(struct test_suite_context *ctx, const unsigned passed, const unsigned failed);
int
test_suite_end(struct test_suite_context *ctx);

void
generate_random_buf(uint8_t *buf, const uint32_t length);

void
memory_copy(void *dst, const void *src, size_t length);
void
memory_set(void *dst, const int val, size_t length);

/**
 * @brief Sets GCM family (AES-GCM, AES-GCM-SGL and SM4-GCM) job key pointers
 *
 * The library uses enc_keys for encrypt direction and dec_keys for decrypt
 * direction, so only the direction specific pointer is set here.
 * The pattern of setting both pointers to the same key structure is covered
 * by other test applications.
 *
 * @param job        pointer to job structure
 * @param key        pointer to GCM key structure
 * @param cipher_dir cipher direction of \a job
 */
static inline void
set_gcm_job_keys(struct IMB_JOB *job, const void *key, const IMB_CIPHER_DIRECTION cipher_dir)
{
        job->enc_keys = (cipher_dir == IMB_DIR_ENCRYPT) ? key : NULL;
        job->dec_keys = (cipher_dir == IMB_DIR_ENCRYPT) ? NULL : key;
}

void *
test_aligned_alloc(const size_t alignment, const size_t size);

void *
test_aligned_alloc_copy(const size_t alignment, const void *src, const size_t size);

void
test_aligned_free(void *ptr);

/* Directory containing JSON vector files (set by --vector-dir; default: "<app>/vectors") */
extern const char *kat_vector_dir;

int
suppress_stderr(void);
void
restore_stderr(int saved);

#include "vector_utils.h"

#endif /* TESTAPP_UTILS_H */
