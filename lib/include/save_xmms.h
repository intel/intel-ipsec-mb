/*******************************************************************************
 Copyright (c) 2012-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef SAVE_XMMS_H
#define SAVE_XMMS_H

#include "intel-ipsec-mb.h"

void
save_xmms(imb_uint128_t array[10]);
void
restore_xmms(imb_uint128_t array[10]);

void
save_xmms_avx(imb_uint128_t array[10]);
void
restore_xmms_avx(imb_uint128_t array[10]);

#endif /* SAVE_XMMS_H */
