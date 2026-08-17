/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef IMB_RAND_H
#define IMB_RAND_H

#include <stddef.h>
#include <intel-ipsec-mb.h>

/**
 * @brief Fill a buffer with cryptographically secure random bytes.
 *
 * Uses getrandom(2) on Linux/FreeBSD (with a /dev/urandom fallback) and
 * BCryptGenRandom() on Windows.  Used by the PQC key/signature generation
 * paths when the caller does not supply explicit entropy.
 *
 * @param buf  destination buffer
 * @param len  number of random bytes to write
 * @return 0 on success, -1 on failure
 */
IMB_DLL_LOCAL int
imb_get_random(void *buf, size_t len);

#endif /* IMB_RAND_H */
