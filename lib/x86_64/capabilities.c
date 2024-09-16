/*******************************************************************************
  Copyright (c) 2024, Intel Corporation

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
*******************************************************************************/

#include "intel-ipsec-mb.h"
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
        case IMB_AUTH_AES_CMAC_BITLEN:
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
                { IMB_ARCH_AVX, 1, "AVX Type 1", "CPU ISA: AES, PCLMUL, SSE, AVX" },
                { IMB_ARCH_AVX, 2, "AVX Type 2", "CPU ISA: AES, PCLMUL, SSE, AVX, SHA-NI" },
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
