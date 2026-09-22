/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
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
