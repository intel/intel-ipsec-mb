/*****************************************************************************
 Copyright (c) 2024-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef MP_IMB_H
#define MP_IMB_H

#include <intel-ipsec-mb.h>
#include "mp_alloc.h"

/*
 * =============================================================================
 * =============================================================================
 * IMB submit, flush and init API
 */

int
flush_aes_cbc_enc_jobs(IMB_MGR *p_mgr, unsigned *jobs_received);

int
submit_aes_cbc_enc_jobs(IMB_MGR *p_mgr, void **in, void **out, const size_t n,
                        unsigned *jobs_received, unsigned *jobs_sent, void *exp_enc_key, void *iv,
                        const size_t msg_size);

IMB_MGR *
init_imb(IMB_MGR *in_mb_mgr, struct allocator *app_alloc, const int is_pri);

#endif /* MP_IMB_H */
