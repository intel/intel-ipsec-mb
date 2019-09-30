/*******************************************************************************
 Copyright (c) 2019, Intel Corporation

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

#ifndef CLEAR_REGS_H
#define CLEAR_REGS_H

/*
 * memset_s() is only guaranteed to be available if
 * __STDC_LIB_EXT1__ is defined by the implementation
 * and if the user defines __STDC_WANT_LIB_EXT1__ to
 * the integer constant 1 before including string.h
 */
#ifdef __WIN32
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>

#define CLEAR_SCRATCH_GPS clear_scratch_gps
static inline void
clear_mem(void *mem, const size_t size)
{
#ifdef LINUX
        asm volatile (" " : : : "memory");
#endif
#ifdef __STDC_LIB_EXT1__
        memset_s(mem, size, 0, size);
#else
        memset(mem, 0, size);
#endif
}

static inline void
clear_var(void *var, const size_t size)
{
#ifdef LINUX
        asm volatile (" " : : : "memory");
#endif
#ifdef __STDC_LIB_EXT1__
        memset_s(var, size, 0, size);
#else
        memset(var, 0, size);
#endif
}

void clear_scratch_gps(void);
void clear_scratch_xmms_sse(void);
void clear_scratch_xmms_avx(void);
void clear_scratch_ymms(void);
void clear_scratch_zmms(void);

#endif /* CLEAR_REGS_H */
