/*
 * Copyright (c) 2012-2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __OS_H
#define __OS_H

#ifdef LINUX
#define DECLARE_ALIGNED(decl, alignval) \
        decl __attribute__((aligned(alignval)))
#define __forceinline \
        static inline __attribute__((always_inline))

#if __GNUC__ >= 4
#define IMB_DLL_EXPORT __attribute__ ((visibility ("default")))
#define IMB_DLL_LOCAL  __attribute__ ((visibility ("hidden")))
#else /* GNU C 4.0 and later */
#define IMB_DLL_EXPORT
#define IMB_DLL_LOCAL
#endif /* different C compiler */

#else

#define DECLARE_ALIGNED(decl, alignval) \
        __declspec(align(alignval)) decl
#define __forceinline \
        static __forceinline

/* Windows DLL export is done via DEF file */
#define IMB_DLL_EXPORT
#define IMB_DLL_LOCAL

#endif

#ifdef DEBUG
#include <assert.h>
#define IMB_ASSERT(x) assert(x)
#else
#define IMB_ASSERT(x)
#endif

#ifndef IMB_DIM
#define IMB_DIM(x) (sizeof(x) / sizeof(x[0]))
#endif

#endif // end ifndef __OS_H
