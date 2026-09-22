/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef E_PROV_H
#define E_PROV_H

#include "prov_sw_freelist.h"

extern const char *prov_id;

int
bind_prov(void);
int
prov_sw_cpu_support(void);

mb_thread_data *
mb_check_thread_local(void);

void
mb_cleanup_thread_local(void);

#endif /* E_PROV_H */
