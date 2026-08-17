/*******************************************************************************
 Copyright (c) 2025, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include "e_prov.h"

void
get_sem_wait_abs_time(struct timespec *polling_abs_timeout, const struct timespec polling_timeout);

void *
multibuff_timer_poll_func(void *ih);
