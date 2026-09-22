/*******************************************************************************
  Copyright (c) 2024-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "intel-ipsec-mb.h"
#include "include/mb_mgr.h"
#include "ipsec_ooo_mgr.h"

int
imb_hash_burst_get_size(const IMB_MGR *mb_mgr, const IMB_HASH_ALG algo, unsigned *out_burst_size)
{
#ifdef SAFE_PARAM
        if (mb_mgr == NULL)
                return IMB_ERR_NULL_MBMGR;

        if (out_burst_size == NULL)
                return IMB_ERR_NULL_BURST;
#endif

        switch (algo) {
        case IMB_AUTH_HMAC_SHA_1:
                *out_burst_size =
                        ((MB_MGR_HMAC_SHA_1_OOO *) (mb_mgr->hmac_sha_1_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_SHA_1:
                *out_burst_size = ((MB_MGR_SHA_1_OOO *) (mb_mgr->sha_1_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_HMAC_SHA_224:
                *out_burst_size =
                        ((MB_MGR_HMAC_SHA_256_OOO *) (mb_mgr->hmac_sha_224_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_SHA_224:
                *out_burst_size = ((MB_MGR_SHA_256_OOO *) (mb_mgr->sha_224_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_HMAC_SHA_256:
                *out_burst_size =
                        ((MB_MGR_HMAC_SHA_256_OOO *) (mb_mgr->hmac_sha_256_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_SHA_256:
                *out_burst_size = ((MB_MGR_SHA_256_OOO *) (mb_mgr->sha_256_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_HMAC_SHA_384:
                *out_burst_size =
                        ((MB_MGR_HMAC_SHA_512_OOO *) (mb_mgr->hmac_sha_384_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_SHA_384:
                *out_burst_size = ((MB_MGR_SHA_512_OOO *) (mb_mgr->sha_384_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_HMAC_SHA_512:
                *out_burst_size =
                        ((MB_MGR_HMAC_SHA_512_OOO *) (mb_mgr->hmac_sha_512_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_SHA_512:
                *out_burst_size = ((MB_MGR_SHA_512_OOO *) (mb_mgr->sha_512_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_AES_CMAC:
                *out_burst_size = ((MB_MGR_CMAC_OOO *) (mb_mgr->aes_cmac_ooo))->total_num_lanes;
                break;
        case IMB_AUTH_AES_CMAC_256:
                *out_burst_size = ((MB_MGR_CMAC_OOO *) (mb_mgr->aes256_cmac_ooo))->total_num_lanes;
                break;
        default:
                *out_burst_size = 0;
                return IMB_ERR_HASH_ALGO;
        }

        return 0;
}

int
imb_cipher_burst_get_size(const IMB_MGR *mb_mgr, const IMB_CIPHER_MODE cipher_mode,
                          unsigned *out_burst_size)
{
        switch (cipher_mode) {
        case IMB_CIPHER_ECB:
        case IMB_CIPHER_CNTR:
                *out_burst_size = 1;
                break;
        case IMB_CIPHER_CFB:
                *out_burst_size = ((MB_MGR_AES_OOO *) (mb_mgr->aes_cfb_128_ooo))->total_num_lanes;
                break;
        case IMB_CIPHER_CBC:
                *out_burst_size = ((MB_MGR_AES_OOO *) (mb_mgr->aes128_ooo))->total_num_lanes;
                break;
        default:
                *out_burst_size = 0;
                return IMB_ERR_CIPH_MODE;
        }

        return 0;
}

int
imb_aead_burst_get_size(const IMB_MGR *mb_mgr, const IMB_CIPHER_MODE cipher_mode,
                        unsigned *out_burst_size)
{
        if (cipher_mode == IMB_CIPHER_CCM) {
                *out_burst_size = ((MB_MGR_CCM_OOO *) (mb_mgr->aes_ccm_ooo))->total_num_lanes;
                return 0;
        } else {
                *out_burst_size = 0;
                return IMB_ERR_CIPH_MODE;
        }
}

int
imb_get_arch_type_string(const IMB_MGR *state, const char **arch_type, const char **description)
{
#ifdef SAFE_PARAM
        if (state == NULL)
                return IMB_ERR_NULL_MBMGR;
        if (arch_type == NULL)
                return EINVAL;
#endif
        struct arch_type_map {
                IMB_ARCH arch;
                uint8_t type;
                const char *arch_type;
                const char *description;
        };

        const struct arch_type_map arch_type_mappings[] = {
                { IMB_ARCH_SSE, 1, "SSE Type 1", "CPU ISA: AES, PCLMUL, SSE" },
                { IMB_ARCH_SSE, 2, "SSE Type 2", "CPU ISA: AES, PCLMUL, SSE, SHA-NI" },
                { IMB_ARCH_SSE, 3, "SSE Type 3", "CPU ISA: AES, PCLMUL, SSE, SHA-NI, GFNI" },
                { IMB_ARCH_AVX2, 1, "AVX2 Type 1", "CPU ISA: AES, PCLMUL, SSE, AVX, AVX2" },
                { IMB_ARCH_AVX2, 2, "AVX2 Type 2",
                  "CPU ISA: VAES, VPCLMUL, SSE, AVX, AVX2, SHA-NI, GFNI" },
                { IMB_ARCH_AVX2, 3, "AVX2 Type 3",
                  "CPU ISA: VAES, VPCLMUL, SSE, AVX, AVX2, SHA-NI, GFNI, IFMA" },
                { IMB_ARCH_AVX2, 4, "AVX2 Type 4",
                  "CPU ISA: VAES, VPCLMUL, SSE, AVX, AVX2, SHA-NI, GFNI, IFMA, SHA512-NI, SM3-NI, "
                  "SM4-NI" },
                { IMB_ARCH_AVX512, 1, "AVX512 Type 1",
                  "CPU ISA: AES, PCLMUL, SSE, AVX, AVX2, AVX512" },
                { IMB_ARCH_AVX512, 2, "AVX512 Type 2",
                  "CPU ISA: VAES, VPCLMUL, SSE, AVX, AVX2, AVX512, GFNI, SHA-NI" },
                { IMB_ARCH_AVX10, 1, "AVX10 Type 1",
                  "CPU ISA: VAES, VPCLMUL, SSE, AVX, AVX2, AVX512, GFNI, SHA-NI, IFMA, SHA512-NI, "
                  "SM3-NI, SM4-NI" },
        };

        for (unsigned int i = 0; i < IMB_DIM(arch_type_mappings); i++) {
                if (arch_type_mappings[i].arch == state->used_arch &&
                    arch_type_mappings[i].type == state->used_arch_type) {
                        *arch_type = arch_type_mappings[i].arch_type;
                        if (description != NULL)
                                *description = arch_type_mappings[i].description;

                        break;
                }
                *arch_type = "Invalid arch type";
        }
        return 0;
}
