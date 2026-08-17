/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#include <stddef.h>

#include "imb_rand.h"

#if defined(_WIN32) || defined(_WIN64)

#if defined(__MINGW32__) || defined(__MINGW64__)
/*
 * Avoid <windows.h> on MinGW: winnt.h declares NtCurrentTeb,
 * GetCurrentFiber and GetFiberData as both extern and FORCEINLINE
 * (static) in the same translation unit, which GCC rejects as a
 * constraint violation.  Forward-declare only what we need.
 */
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002UL
long __stdcall BCryptGenRandom(void *hAlgorithm, unsigned char *pbBuffer, unsigned long cbBuffer,
                               unsigned long dwFlags);
#else
#include <windows.h>
#include <bcrypt.h>
#endif /* __MINGW32__ || __MINGW64__ */

int
imb_get_random(void *buf, size_t len)
{
        if (buf == NULL)
                return -1;
        if (len == 0)
                return 0;

        if (BCryptGenRandom(NULL, (unsigned char *) buf, (unsigned long) len,
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
                return -1;
        return 0;
}

#else /* Unix-like */

#include <errno.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

#include <fcntl.h>
#include <unistd.h>

static int
read_dev_urandom(unsigned char *p, size_t len)
{
        int fd;
        size_t off = 0;

        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0)
                return -1;

        while (off < len) {
                ssize_t n = read(fd, p + off, len - off);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        (void) close(fd);
                        return -1;
                }
                if (n == 0)
                        break;
                off += (size_t) n;
        }
        (void) close(fd);
        return (off == len) ? 0 : -1;
}

int
imb_get_random(void *buf, size_t len)
{
        unsigned char *p = (unsigned char *) buf;
        size_t off = 0;

        if (buf == NULL)
                return -1;
        if (len == 0)
                return 0;

#if defined(__linux__)
        while (off < len) {
                ssize_t n = getrandom(p + off, len - off, 0);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        /* getrandom() unavailable - fall back to /dev/urandom */
                        return read_dev_urandom(p + off, len - off);
                }
                off += (size_t) n;
        }
        return 0;
#else
        return read_dev_urandom(p + off, len);
#endif
}

#endif /* platform */
