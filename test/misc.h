/*****************************************************************************
 Copyright (c) 2019-2022, Intel Corporation

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

#ifdef __WIN32
#include <intrin.h>
#endif

#include <intel-ipsec-mb.h>

#ifndef XVALIDAPP_MISC_H
#define XVALIDAPP_MISC_H

/* RAX, RBX, RCX, RDX, RDI, RSI, R8-R15 */
#define GP_MEM_SIZE 14*8

#define XMM_MEM_SIZE 16*16
#define YMM_MEM_SIZE 16*32
#define ZMM_MEM_SIZE 32*64

/* Memory allocated in BSS section in misc.asm */
extern uint8_t gps[GP_MEM_SIZE];
extern uint8_t simd_regs[ZMM_MEM_SIZE];

/* Read RSP pointer */
void *rdrsp(void);

/* Functions to dump all registers into predefined memory */
void dump_gps(void);
void dump_xmms_sse(void);
void dump_xmms_avx(void);
void dump_ymms(void);
void dump_zmms(void);

/* Functions to clear all scratch SIMD registers */
void clr_scratch_xmms_sse(void);
void clr_scratch_xmms_avx(void);
void clr_scratch_ymms(void);
void clr_scratch_zmms(void);

/* custom replacement for memset() */
void *nosimd_memset(void *p, int c, size_t n);

/* custom replacement for memcpy() */
void *nosimd_memcpy(void *dst, const void *src, size_t n);

/*
 * Detects if SIMD registers are in the state that
 * can cause AVX-SSE transition penalty
 */
uint32_t avx_sse_transition_check(void);

#define MISC_AVX_SSE_YMM0_15_ISSUE  (1 << 2)
#define MISC_AVX_SSE_ZMM0_15_ISSUE  (1 << 6)
#define MISC_AVX_SSE_ISSUE          (MISC_AVX_SSE_YMM0_15_ISSUE | \
                                     MISC_AVX_SSE_ZMM0_15_ISSUE)

/* CPUID feature detection code follows here */

struct misc_cpuid_regs {
        uint32_t eax;
        uint32_t ebx;
        uint32_t ecx;
        uint32_t edx;
};

/**
 * @brief C wrapper for CPUID opcode
 *
 * @param leaf[in]    CPUID leaf number (EAX)
 * @param subleaf[in] CPUID sub-leaf number (ECX)
 * @param out[out]    registers structure to store results of CPUID into
 */
static void
misc_cpuid(const unsigned leaf, const unsigned subleaf,
           struct misc_cpuid_regs *out)
{
#ifdef _WIN32
        /* Windows */
        int regs[4];

        __cpuidex(regs, leaf, subleaf);
        out->eax = regs[0];
        out->ebx = regs[1];
        out->ecx = regs[2];
        out->edx = regs[3];
#else
        /* Linux */
        asm volatile("mov %4, %%eax\n\t"
                     "mov %5, %%ecx\n\t"
                     "cpuid\n\t"
                     "mov %%eax, %0\n\t"
                     "mov %%ebx, %1\n\t"
                     "mov %%ecx, %2\n\t"
                     "mov %%edx, %3\n\t"
                     : "=g" (out->eax), "=g" (out->ebx), "=g" (out->ecx),
                       "=g" (out->edx)
                     : "g" (leaf), "g" (subleaf)
                     : "%eax", "%ebx", "%ecx", "%edx");
#endif /* Linux */
}

/**
 * @brief Detects if XGETBV instruction is available to use.
 *        Call it before calling avx_sse_transition_check().
 *
 * @retval 0 XGETBV NOT available
 * @retval 1 XGETBV available
 */
static int avx_sse_detectability(void)
{
        struct misc_cpuid_regs r;

        /* Get highest supported CPUID leaf number */
        misc_cpuid(0x0, 0x0, &r);

        const unsigned hi_leaf_number = r.eax;

        if (hi_leaf_number < 0xd)
                return 0;

        /* Get CPUID leaf 0xd subleaf 0x1 */
        misc_cpuid(0xd, 0x1, &r);

        /* return bit 2 from EAX */
        return (r.eax >> 2) & 1;
}

/* decodes cipher mode to string */
static const char *misc_cipher_mode_to_str(const IMB_CIPHER_MODE mode)
{
        static char cb[64];

        switch (mode) {
        case IMB_CIPHER_CBC:
                return "aes-cbc";
        case IMB_CIPHER_CNTR:
                return "aes-ctr";
        case IMB_CIPHER_NULL:
                return "null";
        case IMB_CIPHER_DOCSIS_SEC_BPI:
                return "aes-docsis";
        case IMB_CIPHER_GCM:
                return "aead-aes-gcm";
        case IMB_CIPHER_CUSTOM:
                return "custom";
        case IMB_CIPHER_DES:
                return "des-cbc";
        case IMB_CIPHER_DOCSIS_DES:
                return "des-docsis";
        case IMB_CIPHER_CCM:
                return "aes-ccm";
        case IMB_CIPHER_DES3:
                return "3des-cbc";
        case IMB_CIPHER_PON_AES_CNTR:
                return "pon-aes-ctr";
        case IMB_CIPHER_ECB:
                return "aes-ecb";
        case IMB_CIPHER_CNTR_BITLEN:
                return "aes-ctr (bitlen)";
        case IMB_CIPHER_ZUC_EEA3:
                return "zuc-eea3";
        case IMB_CIPHER_SNOW3G_UEA2_BITLEN:
                return "snow3g-uea2";
        case IMB_CIPHER_KASUMI_UEA1_BITLEN:
                return "kasumi-uea1";
        case IMB_CIPHER_CBCS_1_9:
                return "aes-cbcs-1-9";
        case IMB_CIPHER_CHACHA20:
                return "chacha20";
        case IMB_CIPHER_CHACHA20_POLY1305:
                return "aead-chacha20-poly1305";
        case IMB_CIPHER_CHACHA20_POLY1305_SGL:
                return "aead-chacha20-poly1305-sgl";
        case IMB_CIPHER_SNOW_V:
                return "snow-v";
        case IMB_CIPHER_SNOW_V_AEAD:
                return "aead-snow-v";
        case IMB_CIPHER_GCM_SGL:
                return "aead-aes-gcm-sgl";
        case IMB_CIPHER_NUM:
        default:
                break;
        }

        memset(cb, 0, sizeof(cb));
        snprintf(cb, sizeof(cb) - 1, "unknown<%u>", (unsigned) mode);
        return cb;
}

/* decodes hash algorithm to string */
static const char *misc_hash_alg_to_str(const IMB_HASH_ALG mode)
{
        static char cb[64];

        switch (mode) {
        case IMB_AUTH_HMAC_SHA_1:
                return "hmac-sha1";
        case IMB_AUTH_HMAC_SHA_224:
                return "hmac-sha224";
        case IMB_AUTH_HMAC_SHA_256:
                return "hmac-sha256";
        case IMB_AUTH_HMAC_SHA_384:
                return "hmac-sha384";
        case IMB_AUTH_HMAC_SHA_512:
                return "hmac-sha512";
        case IMB_AUTH_AES_XCBC:
                return "aes-xcbc";
        case IMB_AUTH_MD5:
                return "hmac-md5";
        case IMB_AUTH_NULL:
                return "null";
        case IMB_AUTH_AES_GMAC:
                return "aead-aes-gcm";
        case IMB_AUTH_CUSTOM:
                return "custom";
        case IMB_AUTH_AES_CCM:
                return "aes-ccm";
        case IMB_AUTH_AES_CMAC:
                return "aes-cmac-128";
        case IMB_AUTH_SHA_1:
                return "sha1";
        case IMB_AUTH_SHA_224:
                return "sha224";
        case IMB_AUTH_SHA_256:
                return "sha256";
        case IMB_AUTH_SHA_384:
                return "sha384";
        case IMB_AUTH_SHA_512:
                return "sha512";
        case IMB_AUTH_AES_CMAC_BITLEN:
                return "aes-cmac (bitlen)";
        case IMB_AUTH_PON_CRC_BIP:
                return "pon-crc-bip";
        case IMB_AUTH_ZUC_EIA3_BITLEN:
                return "zuc-eia3";
        case IMB_AUTH_DOCSIS_CRC32:
                return "docsis-crc32";
        case IMB_AUTH_SNOW3G_UIA2_BITLEN:
                return "snow3g-uia2";
        case IMB_AUTH_KASUMI_UIA1:
                return "kasumi-uia1";
        case IMB_AUTH_AES_GMAC_128:
                return "aes-gmac-128";
        case IMB_AUTH_AES_GMAC_192:
                return "aes-gmac-192";
        case IMB_AUTH_AES_GMAC_256:
                return "aes-gmac-256";
        case IMB_AUTH_AES_CMAC_256:
                return "aes-cmac-256";
        case IMB_AUTH_POLY1305:
                return "poly1305";
        case IMB_AUTH_CHACHA20_POLY1305:
                return "aead-chacha20-poly1305";
        case IMB_AUTH_CHACHA20_POLY1305_SGL:
                return "aead-chacha20-poly1305-sgl";
        case IMB_AUTH_ZUC256_EIA3_BITLEN:
                return "zuc256-eia3";
        case IMB_AUTH_SNOW_V_AEAD:
                return "aead-snow-v";
        case IMB_AUTH_GCM_SGL:
                return "aead-aes-gcm-sgl";
        case IMB_AUTH_CRC32_ETHERNET_FCS:
                return "crc32-ethernet-fcs";
        case IMB_AUTH_CRC32_SCTP:
                return "crc32-sctp";
        case IMB_AUTH_CRC32_WIMAX_OFDMA_DATA:
                return "crc32-wimax-ofdma-data";
        case IMB_AUTH_CRC24_LTE_A:
                return "crc24-lte-a";
        case IMB_AUTH_CRC24_LTE_B:
                return "crc24-lte-b";
        case IMB_AUTH_CRC16_X25:
                return "crc16-x25";
        case IMB_AUTH_CRC16_FP_DATA:
                return "crc16-fp-data";
        case IMB_AUTH_CRC11_FP_HEADER:
                return "crc11-fp-header";
        case IMB_AUTH_CRC10_IUUP_DATA:
                return "crc10-iuup-data";
        case IMB_AUTH_CRC8_WIMAX_OFDMA_HCS:
                return "crc8-wimax-ofdma-hcs";
        case IMB_AUTH_CRC7_FP_HEADER:
                return "crc7-fp-header";
        case IMB_AUTH_CRC6_IUUP_HEADER:
                return "crc6-iuup-header";
        case IMB_AUTH_GHASH:
                return "ghash";
        case IMB_AUTH_NUM:
        default:
                break;
        }

        memset(cb, 0, sizeof(cb));
        snprintf(cb, sizeof(cb) - 1, "unknown<%u>", (unsigned) mode);
        return cb;
}
#endif /* XVALIDAPP_MISC_H */
