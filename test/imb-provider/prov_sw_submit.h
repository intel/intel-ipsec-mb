/*******************************************************************************
 Copyright (c) 2025-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/
#include <stdio.h>
#include <string.h>

#include "e_prov.h"
#include "prov_sw_freelist.h"
#include <intel-ipsec-mb.h>

int
check_for_stuck_jobs(mb_thread_data *tlv);
int
async_update(mb_thread_data *tlv, ALG_CTX *ctx, ASYNC_JOB *async_job, IMB_JOB *imb_job);
