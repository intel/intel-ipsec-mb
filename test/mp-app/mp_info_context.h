/*****************************************************************************
 Copyright (c) 2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef INFO_CONTEXT_H
#define INFO_CONTEXT_H

#include <intel-ipsec-mb.h>

const size_t buffer_size = 17 * 16;

struct info_context {
        unsigned jobs_sent;
        unsigned jobs_received;

        void *app_mmap;

        IMB_MGR *mb_mgr;
        void *exp_enc_key;
        void *exp_dec_key;
        void *aes_key;
        void *iv;
        void *buffer_table_in_out[15];
        void *buffer_table_ref[15];
};

#endif /* INFO_CONTEXT_H */
