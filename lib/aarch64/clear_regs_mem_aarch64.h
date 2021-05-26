/**********************************************************************
  Copyright(c) 2021 Arm Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Arm Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/
#ifndef CLEAR_REGS_H
#define CLEAR_REGS_H

#include <string.h>

#define GPR_EOR_SELF(reg) "eor " #reg "," #reg "," #reg ";"

#define CLEAR_SCRATCH_GPS() \
do {\
    asm volatile(\
            GPR_EOR_SELF(x0) \
            GPR_EOR_SELF(x1) \
            GPR_EOR_SELF(x2) \
            GPR_EOR_SELF(x3) \
            GPR_EOR_SELF(x4) \
            GPR_EOR_SELF(x5) \
            GPR_EOR_SELF(x6) \
            GPR_EOR_SELF(x7) \
            GPR_EOR_SELF(x8) \
            GPR_EOR_SELF(x9) \
            GPR_EOR_SELF(x10) \
            GPR_EOR_SELF(x11) \
            GPR_EOR_SELF(x12) \
            GPR_EOR_SELF(x13) \
            GPR_EOR_SELF(x14) \
            GPR_EOR_SELF(x15) \
            GPR_EOR_SELF(x16) \
            GPR_EOR_SELF(x17) \
            GPR_EOR_SELF(x18) \
        :::"x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11", \
        "x12","x13","x14","x15","x16","x17","x18","x19","x20","x21","x22", \
	"x23","x24","x25","x26","x27","x28"); \
} while(0)

#define SIMD_EOR_SELF(reg) "eor " #reg ".16b," #reg ".16b," #reg ".16b;"

#define CLEAR_SCRATCH_SIMD_REGS() \
do{\
    asm volatile(\
            SIMD_EOR_SELF(v0) \
            SIMD_EOR_SELF(v1) \
            SIMD_EOR_SELF(v2) \
            SIMD_EOR_SELF(v3) \
            SIMD_EOR_SELF(v4) \
            SIMD_EOR_SELF(v5) \
            SIMD_EOR_SELF(v6) \
            SIMD_EOR_SELF(v7) \
            SIMD_EOR_SELF(v16) \
            SIMD_EOR_SELF(v17) \
            SIMD_EOR_SELF(v18) \
            SIMD_EOR_SELF(v19) \
            SIMD_EOR_SELF(v20) \
            SIMD_EOR_SELF(v21) \
            SIMD_EOR_SELF(v22) \
            SIMD_EOR_SELF(v23) \
            SIMD_EOR_SELF(v24) \
            SIMD_EOR_SELF(v25) \
            SIMD_EOR_SELF(v26) \
            SIMD_EOR_SELF(v27) \
            SIMD_EOR_SELF(v28) \
            SIMD_EOR_SELF(v29) \
            SIMD_EOR_SELF(v30) \
            SIMD_EOR_SELF(v31) \
        :::"v0","v1","v2","v3","v4","v5","v6","v7","v16","v17","v18", \
        "v19","v20","v21","v22","v23","v24","v25","v26","v27","v28", \
        "v29","v30","v31"); \
}while(0)

static inline void
clear_mem(void *mem, const size_t size)
{
        memset(mem, 0, size);
}

static inline void
clear_var(void *var, const size_t size)
{
        memset(var, 0, size);
}

#endif /* CLEAR_REGS_H */
