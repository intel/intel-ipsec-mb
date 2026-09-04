/*****************************************************************************
 Copyright (c) 2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef TESTAPP_FUZZ_COMMON_H
#define TESTAPP_FUZZ_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <intel-ipsec-mb.h>

#ifndef DIM
#define DIM(_x) (sizeof(_x) / sizeof(_x[0]))
#endif

enum fuzz_api_type { FUZZ_API_JOB, FUZZ_API_BURST, FUZZ_API_CIPHER_BURST, FUZZ_API_HASH_BURST };

struct fuzz_args {
        IMB_ARCH arch;
        uint64_t flags;
        IMB_CIPHER_DIRECTION dir;
        enum fuzz_api_type api;
        unsigned num_jobs;
        unsigned key_length;
        IMB_HASH_ALG hash;
        IMB_CIPHER_MODE cipher;
};

/**
 * @brief Sets the fuzzer argument structure to its defaults: automatic
 *        architecture detection, no manager flags, job API, encrypt
 *        direction, 10 jobs per burst and a 16 byte cipher key. The cipher
 *        mode and hash algorithm are left at 0, which means "not selected"
 *        and lets the application take them from the fuzz input.
 *
 * @param [out] p  Fuzzer argument structure, ignored when NULL
 */
static void
fuzz_args_init(struct fuzz_args *p)
{
        if (p == NULL)
                return;

        *p = (struct fuzz_args){ .arch = IMB_ARCH_NONE,
                                 .flags = 0,
                                 .dir = IMB_DIR_ENCRYPT,
                                 .api = FUZZ_API_JOB,
                                 .num_jobs = 10,
                                 .key_length = 16,
                                 .hash = 0,
                                 .cipher = 0 };
}

/** Hash algorithm names accepted on the command line */
static const struct {
        const char *name;
        IMB_HASH_ALG alg;
} hash_alg_names[] = {
        { "IMB_AUTH_HMAC_SHA_1", IMB_AUTH_HMAC_SHA_1 },
        { "IMB_AUTH_HMAC_SHA_224", IMB_AUTH_HMAC_SHA_224 },
        { "IMB_AUTH_HMAC_SHA_256", IMB_AUTH_HMAC_SHA_256 },
        { "IMB_AUTH_HMAC_SHA_384", IMB_AUTH_HMAC_SHA_384 },
        { "IMB_AUTH_HMAC_SHA_512", IMB_AUTH_HMAC_SHA_512 },
        { "IMB_AUTH_AES_XCBC", IMB_AUTH_AES_XCBC },
        { "IMB_AUTH_MD5", IMB_AUTH_MD5 },
        { "IMB_AUTH_NULL", IMB_AUTH_NULL },
        { "IMB_AUTH_AES_GMAC", IMB_AUTH_AES_GMAC },
        { "IMB_AUTH_AES_CCM", IMB_AUTH_AES_CCM },
        { "IMB_AUTH_AES_CMAC", IMB_AUTH_AES_CMAC },
        { "IMB_AUTH_SHA_1", IMB_AUTH_SHA_1 },
        { "IMB_AUTH_SHA_224", IMB_AUTH_SHA_224 },
        { "IMB_AUTH_SHA_256", IMB_AUTH_SHA_256 },
        { "IMB_AUTH_SHA_384", IMB_AUTH_SHA_384 },
        { "IMB_AUTH_SHA_512", IMB_AUTH_SHA_512 },
        { "IMB_AUTH_PON_CRC_BIP", IMB_AUTH_PON_CRC_BIP },
        { "IMB_AUTH_ZUC_EIA3", IMB_AUTH_ZUC_EIA3 },
        { "IMB_AUTH_DOCSIS_CRC32", IMB_AUTH_DOCSIS_CRC32 },
        { "IMB_AUTH_SNOW3G_UIA2", IMB_AUTH_SNOW3G_UIA2 },
        { "IMB_AUTH_KASUMI_UIA1", IMB_AUTH_KASUMI_UIA1 },
        { "IMB_AUTH_AES_GMAC_128", IMB_AUTH_AES_GMAC_128 },
        { "IMB_AUTH_AES_GMAC_192", IMB_AUTH_AES_GMAC_192 },
        { "IMB_AUTH_AES_GMAC_256", IMB_AUTH_AES_GMAC_256 },
        { "IMB_AUTH_AES_CMAC_256", IMB_AUTH_AES_CMAC_256 },
        { "IMB_AUTH_POLY1305", IMB_AUTH_POLY1305 },
        { "IMB_AUTH_CHACHA20_POLY1305", IMB_AUTH_CHACHA20_POLY1305 },
        { "IMB_AUTH_CHACHA20_POLY1305_SGL", IMB_AUTH_CHACHA20_POLY1305_SGL },
        { "IMB_AUTH_GCM_SGL", IMB_AUTH_GCM_SGL },
        { "IMB_AUTH_CRC32_ETHERNET_FCS", IMB_AUTH_CRC32_ETHERNET_FCS },
        { "IMB_AUTH_CRC32_SCTP", IMB_AUTH_CRC32_SCTP },
        { "IMB_AUTH_CRC32_WIMAX_OFDMA_DATA", IMB_AUTH_CRC32_WIMAX_OFDMA_DATA },
        { "IMB_AUTH_CRC24_LTE_A", IMB_AUTH_CRC24_LTE_A },
        { "IMB_AUTH_CRC24_LTE_B", IMB_AUTH_CRC24_LTE_B },
        { "IMB_AUTH_CRC16_X25", IMB_AUTH_CRC16_X25 },
        { "IMB_AUTH_CRC16_FP_DATA", IMB_AUTH_CRC16_FP_DATA },
        { "IMB_AUTH_CRC11_FP_HEADER", IMB_AUTH_CRC11_FP_HEADER },
        { "IMB_AUTH_CRC10_IUUP_DATA", IMB_AUTH_CRC10_IUUP_DATA },
        { "IMB_AUTH_CRC8_WIMAX_OFDMA_HCS", IMB_AUTH_CRC8_WIMAX_OFDMA_HCS },
        { "IMB_AUTH_CRC7_FP_HEADER", IMB_AUTH_CRC7_FP_HEADER },
        { "IMB_AUTH_CRC6_IUUP_HEADER", IMB_AUTH_CRC6_IUUP_HEADER },
        { "IMB_AUTH_GHASH", IMB_AUTH_GHASH },
        { "IMB_AUTH_SM3", IMB_AUTH_SM3 },
        { "IMB_AUTH_HMAC_SM3", IMB_AUTH_HMAC_SM3 },
        { "IMB_AUTH_SM4_GCM", IMB_AUTH_SM4_GCM },
        { "IMB_AUTH_SHA3_224", IMB_AUTH_SHA3_224 },
        { "IMB_AUTH_SHA3_256", IMB_AUTH_SHA3_256 },
        { "IMB_AUTH_SHA3_384", IMB_AUTH_SHA3_384 },
        { "IMB_AUTH_SHA3_512", IMB_AUTH_SHA3_512 },
        { "IMB_AUTH_SHAKE128", IMB_AUTH_SHAKE128 },
        { "IMB_AUTH_SHAKE256", IMB_AUTH_SHAKE256 },
        { "IMB_AUTH_AES_NIA5", IMB_AUTH_AES_NIA5 },
        { "IMB_AUTH_AES_NCA5", IMB_AUTH_AES_NCA5 },
        { "IMB_AUTH_ZUC_NIA6", IMB_AUTH_ZUC_NIA6 },
        { "IMB_AUTH_ZUC_NCA6", IMB_AUTH_ZUC_NCA6 },
        { "IMB_AUTH_SNOW5G_NIA4", IMB_AUTH_SNOW5G_NIA4 },
        { "IMB_AUTH_SNOW5G_NCA4", IMB_AUTH_SNOW5G_NCA4 },
        { "IMB_AUTH_HMAC_SHA3_224", IMB_AUTH_HMAC_SHA3_224 },
        { "IMB_AUTH_HMAC_SHA3_256", IMB_AUTH_HMAC_SHA3_256 },
        { "IMB_AUTH_HMAC_SHA3_384", IMB_AUTH_HMAC_SHA3_384 },
        { "IMB_AUTH_HMAC_SHA3_512", IMB_AUTH_HMAC_SHA3_512 },
};

/**
 * @brief Looks up a hash algorithm by its IMB_AUTH_xxx name and stores it in
 *        the fuzzer argument structure. The comparison is case insensitive.
 *
 * @param [in] a           Argument string to match against the algorithm names
 * @param [in,out] p_args  Fuzzer argument structure, updated on a match
 *
 * @return 0 when \a a names a hash algorithm, 1 when there is no match
 */
static int
hash_selection(const char *a, struct fuzz_args *p_args)
{
        for (unsigned i = 0; i < (unsigned) DIM(hash_alg_names); i++) {
                if (strcasecmp(a, hash_alg_names[i].name) == 0) {
                        p_args->hash = hash_alg_names[i].alg;
                        return 0;
                }
        }

        /* no match found */
        return 1;
}

/** Cipher mode names accepted on the command line */
static const struct {
        const char *name;
        IMB_CIPHER_MODE alg;
} cipher_mode_names[] = {
        { "IMB_CIPHER_CBC", IMB_CIPHER_CBC },
        { "IMB_CIPHER_CNTR", IMB_CIPHER_CNTR },
        { "IMB_CIPHER_CTR", IMB_CIPHER_CTR },
        { "IMB_CIPHER_NULL", IMB_CIPHER_NULL },
        { "IMB_CIPHER_DOCSIS_SEC_BPI", IMB_CIPHER_DOCSIS_SEC_BPI },
        { "IMB_CIPHER_GCM", IMB_CIPHER_GCM },
        { "IMB_CIPHER_DES", IMB_CIPHER_DES },
        { "IMB_CIPHER_DOCSIS_DES", IMB_CIPHER_DOCSIS_DES },
        { "IMB_CIPHER_CCM", IMB_CIPHER_CCM },
        { "IMB_CIPHER_DES3", IMB_CIPHER_DES3 },
        { "IMB_CIPHER_PON_AES_CNTR", IMB_CIPHER_PON_AES_CNTR },
        { "IMB_CIPHER_ECB", IMB_CIPHER_ECB },
        { "IMB_CIPHER_ZUC_EEA3", IMB_CIPHER_ZUC_EEA3 },
        { "IMB_CIPHER_SNOW3G_UEA2", IMB_CIPHER_SNOW3G_UEA2 },
        { "IMB_CIPHER_KASUMI_UEA1", IMB_CIPHER_KASUMI_UEA1 },
        { "IMB_CIPHER_CHACHA20", IMB_CIPHER_CHACHA20 },
        { "IMB_CIPHER_CHACHA20_POLY1305", IMB_CIPHER_CHACHA20_POLY1305 },
        { "IMB_CIPHER_CHACHA20_POLY1305_SGL", IMB_CIPHER_CHACHA20_POLY1305_SGL },
        { "IMB_CIPHER_GCM_SGL", IMB_CIPHER_GCM_SGL },
        { "IMB_CIPHER_SM4_ECB", IMB_CIPHER_SM4_ECB },
        { "IMB_CIPHER_SM4_CBC", IMB_CIPHER_SM4_CBC },
        { "IMB_CIPHER_CFB", IMB_CIPHER_CFB },
        { "IMB_CIPHER_SM4_CNTR", IMB_CIPHER_SM4_CNTR },
        { "IMB_CIPHER_SM4_CTR", IMB_CIPHER_SM4_CTR },
        { "IMB_CIPHER_SM4_GCM", IMB_CIPHER_SM4_GCM },
        { "IMB_CIPHER_ZUC_NEA6", IMB_CIPHER_ZUC_NEA6 },
        { "IMB_CIPHER_SNOW5G_NEA4", IMB_CIPHER_SNOW5G_NEA4 },
        { "IMB_CIPHER_AES_NEA5", IMB_CIPHER_AES_NEA5 },
        { "IMB_CIPHER_AES_NCA5", IMB_CIPHER_AES_NCA5 },
        { "IMB_CIPHER_ZUC_NCA6", IMB_CIPHER_ZUC_NCA6 },
        { "IMB_CIPHER_SNOW5G_NCA4", IMB_CIPHER_SNOW5G_NCA4 },
};

/**
 * @brief Looks up a cipher mode by its IMB_CIPHER_xxx name and stores it in
 *        the fuzzer argument structure. The comparison is case insensitive.
 *
 * @param [in] a           Argument string to match against the cipher names
 * @param [in,out] p_args  Fuzzer argument structure, updated on a match
 *
 * @return 0 when \a a names a cipher mode, 1 when there is no match
 */
static int
cipher_selection(const char *a, struct fuzz_args *p_args)
{
        for (unsigned i = 0; i < (unsigned) DIM(cipher_mode_names); i++) {
                if (strcasecmp(a, cipher_mode_names[i].name) == 0) {
                        p_args->cipher = cipher_mode_names[i].alg;
                        return 0;
                }
        }

        /* no match found */
        return 1;
}

/**
 * @brief Verify that every library cipher mode and hash algorithm can be
 *        selected, and that the application is up to date with the latest library header file.
 *
 * @note The function may terminate the process if cipher and hash tables are not updated with
 *       the latest library header file.
 */
static void
check_algorithm_coverage(void)
{
        int missing = 0;
        uint8_t cipher_seen[IMB_CIPHER_NUM] = { 0 };
        uint8_t hash_seen[IMB_AUTH_NUM] = { 0 };

        for (unsigned i = 0; i < (unsigned) DIM(cipher_mode_names); i++) {
                const IMB_CIPHER_MODE alg = cipher_mode_names[i].alg;

                if (alg > 0 && alg < IMB_CIPHER_NUM)
                        cipher_seen[alg] = 1;
        }

        for (unsigned i = 0; i < (unsigned) DIM(hash_alg_names); i++) {
                const IMB_HASH_ALG alg = hash_alg_names[i].alg;

                if (alg > 0 && alg < IMB_AUTH_NUM)
                        hash_seen[alg] = 1;
        }

        for (int i = 1; i < IMB_CIPHER_NUM; i++) {
                if (!cipher_seen[i]) {
                        printf("error: cipher %d missing in the table\n", i);
                        missing++;
                }
        }

        for (int i = 1; i < IMB_AUTH_NUM; i++) {
                if (!hash_seen[i]) {
                        printf("error: hash %d missing in the table\n", i);
                        missing++;
                }
        }

        if (missing != 0)
                exit(EXIT_FAILURE);
}

/**
 * @brief Parse an unsigned integer argument.
 *
 * Parses an argument of the form: <arg_name>=<value>
 *
 * The value may be specified in any format supported by
 * strtoul() with base 0.
 *
 * @param[in]  arg_name Argument name without '='.
 * @param[in]  argv     Argument string to parse.
 * @param[out] arg_val  Parsed value.
 *
 * @retval 0   Success.
 * @retval -1  Invalid parameter or malformed argument syntax.
 * @retval -2  Conversion error or value out of range.
 */
static int
parse_unsigned_arg(const char *arg_name, const char *argv, unsigned *arg_val)
{
        if (arg_name == NULL || argv == NULL || arg_val == NULL)
                return -1;

        const size_t arg_name_len = strlen(arg_name);

        if (strncasecmp(argv, arg_name, arg_name_len) != 0 || argv[arg_name_len] != '=') {
                printf("error: malformed argument \"%s\"!\n", argv);
                return -1;
        }

        const char *cp = argv + arg_name_len + 1; /* skip "<name>=" */

        /* skip leading whitespace after '=' */
        while (isspace((unsigned char) *cp))
                cp++;

        /* reject negative numbers */
        if (*cp == '-') {
                printf("error: \"%s\" argument is assigned negative value!\n", arg_name);
                return -2;
        }

        char *end;

        errno = 0;

        unsigned long val = strtoul(cp, &end, 0); /* auto-detect base */

        if (cp == end) {
                /* no digits found */
                printf("error: empty definition of \"%s\" argument!\n", arg_name);
                return -2;
        }

        /* consume any potential trailing whitespaces */
        while (isspace((unsigned char) *end))
                end++;

        if (errno == ERANGE) {
                /* overflow */
                printf("error: overflow in conversion of \"%s\" argument!\n", arg_name);
                return -2;
        }

        if (*end != '\0') {
                /* trailing garbage */
                printf("error: conversion error for \"%s\" argument!\n", arg_name);
                return -2;
        }

        if (val > UINT_MAX) {
                /* won't fit in destination type */
                printf("error: \"%s\" argument value too large!\n", arg_name);
                return -2;
        }

        *arg_val = (unsigned) val;
        return 0;
}

/**
 * @brief Parse the application specific arguments that follow "--":
 *        architecture selection, CPU feature disable switches, API type,
 *        number of jobs, key length, cipher direction and cipher and hash
 *        algorithm selection. Unrecognized arguments are ignored.
 *
 * @param [in] argc        Number of arguments following "--"
 * @param [in] argv        Arguments following "--"
 * @param [in,out] p_args  Fuzzer argument structure, ignored when NULL
 */
static void
parse_matched(int argc, char **argv, struct fuzz_args *p_args)
{
        if (p_args == NULL || argv == NULL)
                return;

        for (int i = 0; i < argc; i++) {
                /* architecture selection */
                if ((strcasecmp(argv[i], "SSE") == 0) || (strcasecmp(argv[i], "ARCH=SSE") == 0)) {
                        p_args->arch = IMB_ARCH_SSE;
                        continue;
                }
                if ((strcasecmp(argv[i], "AVX2") == 0) || (strcasecmp(argv[i], "ARCH=AVX2") == 0)) {
                        p_args->arch = IMB_ARCH_AVX2;
                        continue;
                }
                if ((strcasecmp(argv[i], "AVX512") == 0) ||
                    (strcasecmp(argv[i], "ARCH=AVX512") == 0)) {
                        p_args->arch = IMB_ARCH_AVX512;
                        continue;
                }
                if ((strcasecmp(argv[i], "AVX10") == 0) ||
                    (strcasecmp(argv[i], "ARCH=AVX10") == 0)) {
                        p_args->arch = IMB_ARCH_AVX10;
                        continue;
                }

                /* manager initialization flags */
                if ((strcasecmp(argv[i], "SHANI-OFF") == 0) ||
                    (strcasecmp(argv[i], "FLAGS=SHANI-OFF") == 0)) {
                        p_args->flags |= IMB_FLAG_SHANI_OFF;
                        continue;
                }
                if ((strcasecmp(argv[i], "GFNI-OFF") == 0) ||
                    (strcasecmp(argv[i], "FLAGS=GFNI-OFF") == 0)) {
                        p_args->flags |= IMB_FLAG_GFNI_OFF;
                        continue;
                }

                /* number of jobs */
                if (strncasecmp(argv[i], "NJOBS=", 6) == 0) {
                        if (parse_unsigned_arg("NJOBS", argv[i], &p_args->num_jobs) != 0)
                                exit(EXIT_FAILURE);
                        continue;
                }

                /* key length */
                if (strncasecmp(argv[i], "KEYLEN=", 7) == 0) {
                        if (parse_unsigned_arg("KEYLEN", argv[i], &p_args->key_length) != 0)
                                exit(EXIT_FAILURE);
                        continue;
                }

                /* cipher direction */
                if ((strcasecmp(argv[i], "DECRYPT") == 0) ||
                    (strcasecmp(argv[i], "DIR=DECRYPT") == 0)) {
                        p_args->dir = IMB_DIR_DECRYPT;
                        continue;
                }
                if ((strcasecmp(argv[i], "ENCRYPT") == 0) ||
                    (strcasecmp(argv[i], "DIR=ENCRYPT") == 0)) {
                        p_args->dir = IMB_DIR_ENCRYPT;
                        continue;
                }

                /* API type */
                if ((strcasecmp(argv[i], "SINGLE") == 0) || (strcasecmp(argv[i], "API=JOB") == 0) ||
                    (strcasecmp(argv[i], "API=SINGLE") == 0)) {
                        p_args->api = FUZZ_API_JOB;
                        continue;
                }
                if ((strcasecmp(argv[i], "BURST") == 0) ||
                    (strcasecmp(argv[i], "API=BURST") == 0)) {
                        p_args->api = FUZZ_API_BURST;
                        continue;
                }
                if ((strcasecmp(argv[i], "CIPHER_BURST") == 0) ||
                    (strcasecmp(argv[i], "CIPHER-BURST") == 0) ||
                    (strcasecmp(argv[i], "API=CIPHER-BURST") == 0)) {
                        p_args->api = FUZZ_API_CIPHER_BURST;
                        continue;
                }
                if ((strcasecmp(argv[i], "HASH_BURST") == 0) ||
                    (strcasecmp(argv[i], "HASH-BURST") == 0) ||
                    (strcasecmp(argv[i], "API=HASH-BURST") == 0)) {
                        p_args->api = FUZZ_API_HASH_BURST;
                        continue;
                }

                /* cipher algorithm */
                if (cipher_selection(argv[i], p_args) == 0)
                        continue;

                /* hash algorithm */
                if (hash_selection(argv[i], p_args) == 0)
                        continue;
        }
}

/**
 * @brief Helper for the libFuzzer initialization hook. Locates the "--"
 *        separator, hands the arguments following it to the application
 *        specific parser and truncates the command line at that point, so
 *        that libfuzzer does not see them.
 *
 * @note The function may terminate the process if cipher and hash tables are
 *       not updated with the latest library header file.
 *
 * @param [in,out] argc    Argument count, truncated at the "--" argument
 * @param [in,out] argv    Argument vector
 * @param [in,out] p_args  Fuzzer argument structure
 *
 * @return 0 always
 */
static int
parse_args(int *argc, char ***argv, struct fuzz_args *p_args)
{
        for (int i = 0; i < *argc; i++) {
                /*
                 * Check if the current argument matches the
                 * argument we are looking for.
                 */
                if (strcasecmp((*argv)[i], "--") == 0) {
                        parse_matched(*argc - (i + 1), &((*argv)[i + 1]), p_args);
                        /*
                         *  Remove the matching argument and all arguments
                         * after it from the command line.
                         */
                        *argc = i;

                        break;
                }
        }

        /* exit if any algorithm is missing from the name tables */
        check_algorithm_coverage();

        return 0;
}

/**
 * @brief Allocates and initializes the multi-buffer manager on first use.
 *        Does nothing if \a *pp_mgr is already set, so that the manager is
 *        created once and reused across fuzz iterations. The manager is
 *        initialized for the architecture selected in \a p_args, or for the
 *        best architecture available on the CPU if none was selected.
 *
 * @param [in,out] pp_mgr  Location of the manager pointer, set on allocation
 * @param [in] p_args      Fuzzer argument structure
 *
 * @return 0 on success, -1 when \a pp_mgr is NULL or the allocation failed
 */
static int
allocate_init_mb_mgr(IMB_MGR **pp_mgr, struct fuzz_args *p_args)
{
        if (pp_mgr == NULL)
                return -1;

        IMB_MGR *p_mgr = *pp_mgr;

        /* allocate multi-buffer manager */
        if (p_mgr == NULL) {
                p_mgr = alloc_mb_mgr(p_args->flags);
                if (p_mgr == NULL) {
                        printf("Error allocating MB_MGR structure!\n");
                        return -1;
                }

                IMB_ARCH arch_to_run = IMB_ARCH_NUM;

                if (p_args->arch == IMB_ARCH_SSE)
                        init_mb_mgr_sse(p_mgr);
                else if (p_args->arch == IMB_ARCH_AVX2)
                        init_mb_mgr_avx2(p_mgr);
                else if (p_args->arch == IMB_ARCH_AVX512)
                        init_mb_mgr_avx512(p_mgr);
                else if (p_args->arch == IMB_ARCH_AVX10)
                        init_mb_mgr_avx10(p_mgr);
                else
                        init_mb_mgr_auto(p_mgr, &arch_to_run);

                *pp_mgr = p_mgr;
        }

        return 0;
}

#endif /* TESTAPP_FUZZ_COMMON_H */
