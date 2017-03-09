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

/*
 * Author: Shuzo Ichiyoshi
 */

#ifndef _IPSEC_MB_DEBUG_H_
#define	_IPSEC_MB_DEBUG_H_

#ifdef DEBUG
#include <stdio.h>

#define START_MARK()	fprintf(stderr, "%s:%d start\n", __func__, __LINE__)
#define END_MARK()	fprintf(stderr, "%s:%d end\n", __func__, __LINE__)
#define PRINT_JOB(j)                                                    \
        do {                                                            \
                if (j) {                                                \
                        fprintf(stderr, "%s:%d Job:%p STS:%0x\n", __func__, __LINE__, j, j->status); \
                } else {                                                \
                        fprintf(stderr, "%s:%d Job:NULL\n", __func__, __LINE__); \
                }                                                       \
        } while (0)

//#define TRACE(fmt, ...)	fprintf(stderr, "%s:%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define TRACE(fmt, ...)

static inline void
hexdump(FILE *fp,
        const char *msg,
        const void *p,
        size_t len)
{
        unsigned int i, out, ofs;
        const unsigned char *data = p;

        fprintf(fp, "%s:%p %zu\n", msg, p, len);

        ofs = 0;
        while (ofs < len) {
                char line[120];

                out = snprintf(line, sizeof(line), "%08x:", ofs);
                for (i = 0; ((ofs + i) < len) && (i < 16); i++)
                        out += snprintf(line + out, sizeof(line) - out,
                                        " %02x", (data[ofs + i] & 0xff));
                for (; i <= 16; i++)
                        out += snprintf(line + out, sizeof(line) - out, " | ");
                for (i = 0; (ofs < len) && (i < 16); i++, ofs++) {
                        unsigned char c = data[ofs];
                        if ( (c < ' ') || (c > '~'))
                                c = '.';
                        out += snprintf(line + out, sizeof(line) - out, "%c", c);
                }
                fprintf(fp, "%s\n", line);
        }
}

static inline UINT64
rdtsc(void)
{
        union {
                UINT64 tsc_64;
                struct {
                        UINT32 lo_32;
                        UINT32 hi_32;
                };
        } tsc;

        asm volatile("rdtsc" :
                     "=a" (tsc.lo_32),
                     "=d" (tsc.hi_32));
        return tsc.tsc_64;
}

static inline void
prefetch0(const volatile void *p)
{
        asm volatile ("prefetcht0 %[p]" : : [p] "m" (*(const volatile char *) p));
}
#else
# define START_MARK()
# define END_MARK()
# define PRINT_JOB(j) (void) (j)
#endif	/* DEBUG */

#endif	/* !_IPSEC_MB_DEBUG_H_ */
