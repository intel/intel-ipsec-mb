/*******************************************************************************
 Copyright (c) 2019-2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef CLEAR_REGS_H
#define CLEAR_REGS_H

#define CLEAR_SCRATCH_GPS clear_scratch_gps

void
force_memset_zero(void *mem, const size_t size);

static inline void
clear_mem(void *mem, const size_t size)
{
        force_memset_zero(mem, size);
}

void
force_memset_zero_vol(volatile void *mem, const size_t size);

static inline void
clear_var(void *var, const size_t size)
{
        force_memset_zero(var, size);
}

void
clear_scratch_gps(void);
void
clear_scratch_xmms_sse(void);
void
clear_scratch_xmms_avx(void);
void
clear_scratch_ymms(void);
void
clear_scratch_zmms(void);

#endif /* CLEAR_REGS_H */
