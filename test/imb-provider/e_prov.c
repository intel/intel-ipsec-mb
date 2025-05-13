/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e_prov.h"
#include "prov_evp.h"
#include "prov_sw_gcm.h"

/* __cpuid(unsigned int info[4], unsigned int leaf, unsigned int subleaf); */
#define __cpuid(x, y, z)                                                                           \
        asm volatile("cpuid" : "=a"(x[0]), "=b"(x[1]), "=c"(x[2]), "=d"(x[3]) : "a"(y), "c"(z))

#define Genu 0x756e6547
#define ineI 0x49656e69
#define ntel 0x6c65746e

const char *prov_id = "imb-provider";

int
prov_sw_cpu_support(void)
{
        unsigned int info[4] = { 0, 0, 0, 0 };
        unsigned int *ebx, *ecx, *edx;

        ebx = &info[1];
        ecx = &info[2];
        edx = &info[3];

        /* Is this an Intel CPU? */
        __cpuid(info, 0x00, 0);
        if (*ebx != Genu || *ecx != ntel || *edx != ineI)
                return 0;

        __cpuid(info, 0x07, 0);

        return 1;
}

int
bind_prov(void)
{
        if (!prov_sw_cpu_support()) {
                fprintf(stderr, "imb-provider is restricted to run on Intel CPU only\n");
                return 0;
        }

        if (!init_ipsec_mb_mgr()) {
                fprintf(stderr, "IPSecMB manager init failed (sync)\n");
                return 0;
        }

        prov_create_ciphers();
        return 1;
}
