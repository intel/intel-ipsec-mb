/**********************************************************************
  Copyright(c) 2026, Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************/

/**
 * @brief x86-64 ABI check application
 *
 * Scans all algorithms accessible through the job API (cipher-only,
 * hash-only and combined AEAD algorithms) and checks that the registers
 * the host calling convention declares callee-saved keep their value
 * across IMB_SUBMIT_JOB() and IMB_FLUSH_JOB() calls.
 *
 * On Windows x64 that is XMM6-XMM15 plus the callee-saved general purpose
 * registers (RBX, RBP, RSI, RDI, R12-R15). On System V AMD64 (Linux,
 * FreeBSD) no XMM register is callee-saved, so only RBX, RBP and R12-R15
 * are checked there. The optional --check-vzeroupper pass is available on
 * both platforms.
 *
 * The application does not verify any cryptographic results.
 * Use the imb-xvalid application for cross architecture result validation.
 *
 * This is a diagnostic application, it does not fix or
 * work around any register preservation problem it finds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <intel-ipsec-mb.h>

#include "algo_maps.h"
#include "job_params.h"
#include "job_utils.h"
#include "utils.h"
#include "abi_probe.h"

#define JOB_BUF_SIZE 256 /**< size of the message buffer used for every probed job */

/**
 * IV buffer must be large enough for the widest iv_len_in_bytes fill_job()
 * sets (e.g. 25 bytes for ZUC-EEA3-256), not just the common 16-byte case
 */
#define MAX_IV_SIZE 32

/** safety cap on flush calls needed to drain outstanding jobs */
#define MAX_FLUSH_TRIES (TEST_MAX_NUM_JOBS + 8)

/** maximum number of distinct algorithm/arch/stage failures recorded */
#define MAX_FAILURES 4096

/**
 * Per-algorithm scratch data for up to TEST_MAX_NUM_JOBS jobs.
 *
 * TEST_MAX_NUM_JOBS (see utils.h) is one more than the widest multi-buffer
 * OOO manager lane count in the library, so submitting that many jobs is
 * guaranteed to fill and complete at least one lane through IMB_SUBMIT_JOB()
 * alone, without ever needing IMB_FLUSH_JOB() to force a job through.
 */
struct probe_data {
        DECLARE_ALIGNED(uint8_t test_buf[TEST_MAX_NUM_JOBS][JOB_BUF_SIZE], 16);
        DECLARE_ALIGNED(uint8_t src_dst_buf[TEST_MAX_NUM_JOBS][JOB_BUF_SIZE], 16);
        uint8_t in_digest[TEST_MAX_NUM_JOBS][MAX_DIGEST_SIZE];
        uint8_t out_digest[TEST_MAX_NUM_JOBS][MAX_DIGEST_SIZE];
        struct job_ctx ctx[TEST_MAX_NUM_JOBS];
        IMB_JOB job_template[TEST_MAX_NUM_JOBS];
};

/** architectures to test, indexed with IMB_ARCH; IMB_ARCH_NONE is never tested */
static uint8_t archs[IMB_ARCH_NUM] = { 0, 1, 1, 1, 1 };
static uint64_t flags = 0; /**< flags passed to alloc_mb_mgr() */
static int verbose = 0;    /**< non-zero to print extra information */

/**
 * Best-effort check for a missing VZEROUPPER on the AVX2/AVX512/AVX10 code
 * paths (see xmm_abi_probe()'s check_vzeroupper parameter). Off by default:
 * it cannot distinguish "never touched AVX/YMM state" from "used it and
 * forgot to clean up", so it produces false positives for any algorithm
 * that doesn't happen to execute an AVX-encoded instruction on the probed
 * call, which is common (e.g. NULL-CIPHER, or a submit call that just
 * buffers the job without doing any vector work yet). Enable with
 * --check-vzeroupper and manually review the reported hits.
 */
static int check_vzeroupper_opt = 0;

/** record of one algorithm/architecture/stage register corruption */
struct failure {
        char algo[40];
        IMB_ARCH arch;
        const char *stage;
        uint32_t mask;  /**< union of all corrupted registers seen for this combination */
        unsigned count; /**< number of probe calls that detected a corruption */
};

static struct failure failures[MAX_FAILURES];
static unsigned num_failures = 0;
static unsigned num_skipped_failures = 0;

/**
 * number of times an algorithm failed to fully drain its outstanding jobs;
 * treated as a hard error since it can misattribute later corruption
 * reports to the wrong algorithm
 */
static unsigned num_drain_errors = 0;

/**
 * @brief Format a corrupted register bitmask as e.g. "xmm6,xmm9,rbx".
 *
 * @param [in] mask      bitmask of corrupted registers, as returned by
 *                       xmm_abi_probe()
 * @param [out] buf      buffer receiving the NULL terminated register list
 * @param [in] buf_size  size of \a buf in bytes
 */
static void
mask_to_str(const uint32_t mask, char *buf, const size_t buf_size)
{
        static const char *gp_names[ABI_PROBE_NUM_GP] = ABI_PROBE_GP_NAMES;

        buf[0] = '\0';
#if ABI_PROBE_NUM_XMM > 0
        for (unsigned i = 0; i < ABI_PROBE_NUM_XMM; i++) {
                if (mask & (1u << ABI_PROBE_XMM_BIT(i))) {
                        char tmp[16];

                        snprintf(tmp, sizeof(tmp), "%sxmm%u", (buf[0] != '\0') ? "," : "",
                                 ABI_PROBE_FIRST_XMM + i);
                        strncat(buf, tmp, buf_size - strlen(buf) - 1);
                }
        }
#endif
        for (unsigned i = 0; i < ABI_PROBE_NUM_GP; i++) {
                if (mask & (1u << ABI_PROBE_GP_BIT(i))) {
                        char tmp[16];

                        snprintf(tmp, sizeof(tmp), "%s%s", (buf[0] != '\0') ? "," : "",
                                 gp_names[i]);
                        strncat(buf, tmp, buf_size - strlen(buf) - 1);
                }
        }
        if (mask & (1u << ABI_PROBE_VZEROUPPER_BIT)) {
                char tmp[16];

                snprintf(tmp, sizeof(tmp), "%svzeroupper", (buf[0] != '\0') ? "," : "");
                strncat(buf, tmp, buf_size - strlen(buf) - 1);
        }
}

/**
 * @brief Record a corrupted-register detection.
 *
 * The detection is merged into an existing entry for the same
 * algorithm/architecture/stage (OR-ing the register mask and incrementing
 * the occurrence count) instead of adding a duplicate row, so that e.g.
 * many identical SUBMIT detections while an OOO manager's lanes fill up
 * are reported as a single line.
 *
 * @param [in] algo   algorithm name
 * @param [in] arch   architecture the algorithm was probed on
 * @param [in] stage  probed entry point ("SUBMIT" or "FLUSH")
 * @param [in] mask   bitmask of corrupted registers
 */
static void
record_failure(const char *algo, const IMB_ARCH arch, const char *stage, const uint32_t mask)
{
        for (unsigned i = 0; i < num_failures; i++) {
                struct failure *f = &failures[i];

                if (f->arch == arch && strcmp(f->stage, stage) == 0 && strcmp(f->algo, algo) == 0) {
                        f->mask |= mask;
                        f->count++;
                        return;
                }
        }

        if (num_failures >= MAX_FAILURES) {
                num_skipped_failures++;
                return;
        }

        struct failure *f = &failures[num_failures++];

        snprintf(f->algo, sizeof(f->algo), "%s", algo);
        f->arch = arch;
        f->stage = stage;
        f->mask = mask;
        f->count = 1;
}

/**
 * @brief Probe one algorithm for callee-saved register corruption.
 *
 * Submits jobs for the given algorithm one at a time, checking callee-saved
 * register preservation after every IMB_SUBMIT_JOB() call, until a job
 * completes.
 *
 * - If the very first submit completes the job, the algorithm is processed
 *   synchronously (single-buffer / non-OOO code path) and no flush is
 *   needed at all.
 * - If it takes more than one submit to complete a job, the algorithm
 *   batches jobs in an out-of-order manager. In that case a single,
 *   separately-checked IMB_FLUSH_JOB() call is made to force the first
 *   completion (this isolates the OOO manager's "flush" entry point from
 *   its "submit" entry point). Any further jobs still outstanding after
 *   that are drained with plain, unchecked IMB_FLUSH_JOB() calls, since
 *   they exercise the same flush code path that has already been checked.
 *
 * This lets a failure be attributed to one of two places: the submit path
 * (buffering and/or in-line processing) or the flush entry point that
 * forces a partially filled batch through.
 *
 * @param [in,out] mb_mgr     multi-buffer manager to submit the jobs to
 * @param [in] arch           architecture \a mb_mgr is initialized for
 * @param [in] params         cipher and hash parameters of the algorithm
 * @param [in] algo_name      algorithm name used in the failure report
 * @param [in,out] pd         scratch job and buffer data used for probing
 * @param [in] check_vzu      non-zero to also run the missing VZEROUPPER
 *                            check (see xmm_abi_probe())
 *
 * @return Probe status
 * @retval 0  algorithm probed (or skipped as unsupported)
 * @retval -1 not every submitted job could be drained (\a mb_mgr is left
 *            with outstanding jobs in that case, so the caller must
 *            re-initialize it before probing the next algorithm)
 */
static int
probe_algo(IMB_MGR *mb_mgr, const IMB_ARCH arch, const struct params_s *params,
           const char *algo_name, struct probe_data *pd, const int check_vzu)
{
        uint8_t aad[MAX_AAD_SIZE];
        uint8_t cipher_iv[MAX_IV_SIZE];
        uint8_t auth_iv[MAX_IV_SIZE];
        uint8_t ciph_key[MAX_KEY_SIZE];
        uint8_t auth_key[MAX_KEY_SIZE];
        uint8_t tag_sizes[NUM_TAG_SIZES];
        struct cipher_auth_keys keys;
        IMB_JOB *job;
        void *ret_ptr = NULL;
        uint32_t buf_size;
        uint32_t mask;
        unsigned num_tags;
        uint8_t tag_size;
        unsigned n_jobs, n_completed, flush_tries;

        if (!is_valid_combination(params->cipher_mode, params->hash_alg))
                return 0;

        for (buf_size = 64; buf_size <= JOB_BUF_SIZE; buf_size += 16)
                if (is_valid_job_size(params, buf_size))
                        break;
        if (buf_size > JOB_BUF_SIZE)
                return 0;

        memset(&keys, 0, sizeof(keys));

        generate_random_buf(cipher_iv, MAX_IV_SIZE);
        generate_random_buf(auth_iv, MAX_IV_SIZE);
        generate_random_buf(ciph_key, MAX_KEY_SIZE);
        generate_random_buf(auth_key, MAX_KEY_SIZE);
        if (get_max_aad_size(params) != 0)
                generate_random_buf(aad, get_max_aad_size(params));
        else
                memset(aad, 0, sizeof(aad));

        if (fill_keys(mb_mgr, &keys, ciph_key, auth_key, params, NULL) < 0)
                return 0;

        num_tags = get_tag_sizes(params, tag_sizes);
        tag_size = (num_tags != 0) ? tag_sizes[0] : 0;

        /* build TEST_MAX_NUM_JOBS distinct jobs up-front, enough to fill and
         * complete the widest OOO manager lane through submit alone
         */
        for (n_jobs = 0; n_jobs < TEST_MAX_NUM_JOBS; n_jobs++) {
                struct job_ctx *ctx = &pd->ctx[n_jobs];

                if (set_job_ctx(ctx, params, buf_size, JOB_BUF_SIZE, pd->in_digest[n_jobs],
                                pd->out_digest[n_jobs], tag_size, pd->test_buf[n_jobs],
                                pd->src_dst_buf[n_jobs], generate_random_buf) < 0)
                        return 0;

                memory_copy(pd->src_dst_buf[n_jobs], pd->test_buf[n_jobs], ctx->buf_size);

                if (fill_job(&pd->job_template[n_jobs], params, pd->src_dst_buf[n_jobs],
                             pd->in_digest[n_jobs], aad, ctx->buf_size, ctx->tag_size_to_check,
                             IMB_DIR_ENCRYPT, &keys, cipher_iv, auth_iv, n_jobs) < 0)
                        return 0;
        }

        if (verbose) {
                printf("[INFO] ");
                print_algo_info(params);
                printf("\n");
        }

        /* submit jobs one at a time, checking registers after every submit,
         * until a job completes or TEST_MAX_NUM_JOBS is reached
         */
        n_jobs = 0;
        while (n_jobs < TEST_MAX_NUM_JOBS) {
                job = IMB_GET_NEXT_JOB(mb_mgr);
                *job = pd->job_template[n_jobs];
                n_jobs++; /* count this submit */

                ret_ptr = NULL;
                mask = xmm_abi_probe((void *) (uintptr_t) imb_submit_job, mb_mgr, &ret_ptr,
                                     check_vzu);
                if (mask != 0)
                        record_failure(algo_name, arch, "SUBMIT", mask);

                if (ret_ptr != NULL)
                        break;
        }

        n_completed = (ret_ptr != NULL) ? 1 : 0;

        if (n_jobs == 1 && n_completed == 1) {
                /* single-buffer algorithm: processed synchronously inside
                 * IMB_SUBMIT_JOB(), no flush required
                 */
                return 0;
        }

        if (n_completed == 0) {
                fprintf(stderr, "[ERROR] %s: no job completed after %u IMB_SUBMIT_JOB() calls\n",
                        algo_name, n_jobs);
                return -1;
        }

        /* transition flush: forces the OOO manager's flush entry point,
         * checked and reported separately from later drain flushes
         */
        ret_ptr = NULL;
        mask = xmm_abi_probe((void *) (uintptr_t) imb_flush_job, mb_mgr, &ret_ptr, check_vzu);
        if (mask != 0)
                record_failure(algo_name, arch, "FLUSH", mask);
        if (ret_ptr != NULL)
                n_completed++;

        /* drain any remaining outstanding jobs without further register
         * checks: the flush entry point has already been exercised and
         * checked above, further drain calls run the same code path
         */
        flush_tries = 0;
        while (n_completed < n_jobs && flush_tries < MAX_FLUSH_TRIES) {
                IMB_JOB *drained = IMB_FLUSH_JOB(mb_mgr);

                if (drained != NULL)
                        n_completed++;
                flush_tries++;
        }

        if (n_completed < n_jobs) {
                fprintf(stderr,
                        "[ERROR] %s: only %u/%u jobs completed after draining with "
                        "IMB_FLUSH_JOB()\n",
                        algo_name, n_completed, n_jobs);
                return -1;
        }

        return 0;
}

/**
 * @brief Initialize \a mb_mgr for a specific architecture.
 *
 * Exits the application if \a arch is not a valid architecture.
 *
 * @param [in,out] mb_mgr  multi-buffer manager to initialize
 * @param [in] arch        target architecture
 */
static void
init_arch_mgr(IMB_MGR *mb_mgr, const IMB_ARCH arch)
{
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
}

/**
 * @brief Probe every cipher, hash and AEAD algorithm on one architecture.
 *
 * @param [in] arch  architecture to test
 */
static void
run_arch(const IMB_ARCH arch)
{
        IMB_MGR *mb_mgr = alloc_mb_mgr(flags);
        struct params_s params;
        struct probe_data *pd;

        if (mb_mgr == NULL) {
                fprintf(stderr, "MB MGR could not be allocated\n");
                exit(EXIT_FAILURE);
        }

        pd = malloc(sizeof(*pd));
        if (pd == NULL) {
                fprintf(stderr, "Probe data could not be allocated\n");
                free_mb_mgr(mb_mgr);
                exit(EXIT_FAILURE);
        }

        init_arch_mgr(mb_mgr, arch);

        uint64_t features = 0;

        if (imb_get_features(mb_mgr, &features) != 0 || imb_get_errno(mb_mgr) != 0) {
                fprintf(stderr, "Error initializing MB_MGR structure! %s\n",
                        imb_get_strerror(imb_get_errno(mb_mgr)));
                free(pd);
                free_mb_mgr(mb_mgr);
                exit(EXIT_FAILURE);
        }

        printf("Testing ");
        print_tested_arch(features, arch);

        /*
         * The VZEROUPPER check executes AVX instructions in the probe itself
         * and only makes sense for architectures that run AVX+ code paths:
         * SSE never dirties the upper YMM6-YMM15 halves, so checking there
         * would just report the probe's own untouched seed pattern as
         * "dirty". Requiring AVX to be reported by the manager as well keeps
         * the probe from executing an unsupported instruction, independently
         * of the architecture filtering done in main().
         */
        const int check_vzu = check_vzeroupper_opt && (arch != IMB_ARCH_SSE) &&
                              ((features & IMB_FEATURE_AVX) != 0);

        /* cipher algorithms, paired with NULL-HASH */
        for (size_t i = 0; i < num_cipher_algo_str_map; i++) {
                memset(&params, 0, sizeof(params));
                params.cipher_mode = cipher_algo_str_map[i].values.job_params.cipher_mode;
                params.key_size = cipher_algo_str_map[i].values.job_params.key_size;
                params.hash_alg = IMB_AUTH_NULL;
                if (probe_algo(mb_mgr, arch, &params, cipher_algo_str_map[i].name, pd, check_vzu) <
                    0) {
                        num_drain_errors++;
                        init_arch_mgr(mb_mgr, arch);
                }
        }

        /* hash algorithms, paired with NULL-CIPHER */
        for (size_t i = 0; i < num_hash_algo_str_map; i++) {
                memset(&params, 0, sizeof(params));
                params.cipher_mode = IMB_CIPHER_NULL;
                params.hash_alg = hash_algo_str_map[i].values.job_params.hash_alg;
                if (probe_algo(mb_mgr, arch, &params, hash_algo_str_map[i].name, pd, check_vzu) <
                    0) {
                        num_drain_errors++;
                        init_arch_mgr(mb_mgr, arch);
                }
        }

        /* combined AEAD algorithms (cipher and hash tied together, e.g. AES-GCM/CCM) */
        for (size_t i = 0; i < num_aead_algo_str_map; i++) {
                memset(&params, 0, sizeof(params));
                params.cipher_mode = aead_algo_str_map[i].values.job_params.cipher_mode;
                params.hash_alg = aead_algo_str_map[i].values.job_params.hash_alg;
                params.key_size = aead_algo_str_map[i].values.job_params.key_size;
                if (probe_algo(mb_mgr, arch, &params, aead_algo_str_map[i].name, pd, check_vzu) <
                    0) {
                        num_drain_errors++;
                        init_arch_mgr(mb_mgr, arch);
                }
        }

        free(pd);
        free_mb_mgr(mb_mgr);
}

/**
 * @brief Print the set of callee-saved registers checked on the host ABI.
 */
static void
print_checked_regs(void)
{
        const uint32_t all_regs = (1u << (ABI_PROBE_NUM_XMM + ABI_PROBE_NUM_GP)) - 1;
        char reg_str[256];

        mask_to_str(all_regs, reg_str, sizeof(reg_str));
        printf("Checking %s ABI callee-saved registers: %s\n",
#ifdef _WIN32
               "Windows x64",
#else
               "System V AMD64",
#endif
               reg_str);
}

/**
 * @brief Print the summary of all detected register corruptions.
 */
static void
print_report(void)
{
        printf("\n");
        if (num_failures == 0 && num_drain_errors == 0) {
                printf("PASS: no callee-saved register corruption detected "
                       "across IMB_SUBMIT_JOB()/IMB_FLUSH_JOB()\n");
                return;
        }

        if (num_drain_errors != 0)
                fprintf(stderr,
                        "[ERROR] %u algorithm(s) failed to fully drain their jobs; results for "
                        "algorithms tested immediately afterwards may be incomplete\n",
                        num_drain_errors);

        if (num_failures == 0)
                return;

        printf("FAIL: %u distinct algorithm/architecture/stage combination(s) corrupted "
               "callee-saved registers\n\n",
               num_failures);
        printf("%-30s %-8s %-12s %-8s %s\n", "ALGORITHM", "ARCH", "STAGE", "COUNT", "REGISTERS");
        for (unsigned i = 0; i < num_failures; i++) {
                char reg_str[128];

                mask_to_str(failures[i].mask, reg_str, sizeof(reg_str));
                printf("%-30s %-8s %-12s %-8u %s\n", failures[i].algo,
                       arch_str_map[failures[i].arch].name, failures[i].stage, failures[i].count,
                       reg_str);
        }

        if (num_skipped_failures != 0)
                fprintf(stderr, "[WARN] %u additional failure(s) not recorded (limit reached)\n",
                        num_skipped_failures);
}

/**
 * @brief Print the application usage information.
 *
 * @param [in] app_name  application name to display
 */
static void
usage(const char *app_name)
{
        fprintf(stderr,
                "Usage: %s [args], where args are zero or more\n"
                "-h: print this message\n"
                "-v: verbose, prints extra information\n"
                "--check-vzeroupper: also do a best-effort check for a missing "
                "VZEROUPPER on AVX2/AVX512/AVX10 (may report false positives "
                "for algorithms/stages that don't touch AVX state), default: off\n"
                "--arch: architecture to test (SSE/AVX2/AVX512/AVX10), "
                "default: test all architectures\n"
                "--no-avx10: don't do AVX10\n"
                "--no-avx512: don't do AVX512\n"
                "--no-avx2: don't do AVX2\n"
                "--no-sse: don't do SSE\n"
                "--shani-on: use SHA extensions, default: auto-detect\n"
                "--shani-off: don't use SHA extensions\n"
                "--gfni-on: use Galois Field extensions, default: auto-detect\n"
                "--gfni-off: don't use Galois Field extensions\n",
                app_name);
}

/**
 * @brief Application entry point.
 *
 * @param [in] argc  number of command line arguments
 * @param [in] argv  command line argument vector
 *
 * @return Application status
 * @retval EXIT_SUCCESS no register corruption detected
 * @retval EXIT_FAILURE register corruption detected or invalid arguments
 */
int
main(int argc, char *argv[])
{
        uint8_t arch_support[IMB_ARCH_NUM];

        for (int i = 1; i < argc; i++)
                if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                        usage(argv[0]);
                        return EXIT_SUCCESS;
                } else if (strcmp(argv[i], "-v") == 0) {
                        verbose = 1;
                } else if (strcmp(argv[i], "--check-vzeroupper") == 0) {
                        check_vzeroupper_opt = 1;
                } else if (update_flags_and_archs(argv[i], archs, &flags)) {
                        /* architecture and feature flags updated */
                } else if (strcmp(argv[i], "--arch") == 0) {
                        const union params *values;

                        /* skip arch_str_map[0] == IMB_ARCH_NONE */
                        values = check_string_arg(argv[i], argv[i + 1], arch_str_map + 1,
                                                  num_arch_str_map - 1);
                        if (values == NULL)
                                return EXIT_FAILURE;

                        memset(archs, 0, sizeof(archs));
                        archs[values->arch_type] = 1;
                        i++;
                } else {
                        usage(argv[0]);
                        return EXIT_FAILURE;
                }

        if (detect_arch(arch_support, flags) < 0)
                return EXIT_FAILURE;

        print_checked_regs();

        for (unsigned int arch_id = IMB_ARCH_SSE; arch_id < IMB_ARCH_NUM; arch_id++) {
                if (arch_support[arch_id] == 0) {
                        archs[arch_id] = 0;
                        fprintf(stderr, "%s not supported. Disabling %s tests\n",
                                arch_str_map[arch_id].name, arch_str_map[arch_id].name);
                }
        }

        for (IMB_ARCH arch = IMB_ARCH_SSE; arch < IMB_ARCH_NUM; arch++) {
                if (archs[arch] == 0)
                        continue;
                run_arch(arch);
        }

        print_report();

        return (num_failures == 0 && num_drain_errors == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
