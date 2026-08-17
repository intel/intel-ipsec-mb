/*******************************************************************************
 Copyright (c) 2020-2024, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef MEMCPY_H
#define MEMCPY_H

/* Memcpy up to 16 bytes with SSE instructions */
void
memcpy_fn_sse_16(void *dst, const void *src, const size_t size);

/* Memcpy up to 16 bytes with AVX instructions */
void
memcpy_fn_avx_16(void *dst, const void *src, const size_t size);

/* Memcpy 128 bytes with SSE instructions */
void
memcpy_fn_sse_128(void *dst, const void *src);

/* Basic memcpy that doesn't use stack */
void
safe_memcpy(void *dst, const void *src, const size_t size);

#endif /* MEMCPY_H */
