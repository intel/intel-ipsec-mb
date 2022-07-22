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

#endif /* XVALIDAPP_MISC_H */
