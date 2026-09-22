/*****************************************************************************
 Copyright (c) 2024-2026, Intel Corporation

 SPDX-License-Identifier: BSD-3-Clause
*****************************************************************************/

#ifndef MP_SHARED_MEM_H
#define MP_SHARED_MEM_H

#include <stdlib.h>

/*
 * =============================================================================
 * =============================================================================
 * Shared memory definitions
 */

#if defined(__MINGW32__)

struct shared_memory {
        size_t size;
        const char *name;
        void *ptr;
};

#else

#ifdef _WIN32
/*
 * Disable C5105 to workaround warning coming from winbase.h file
 * "Windows Kits\10\include\10.0.19041.0\um\winbase.h(9531): warning
 * C5105: macro expansion producing 'defined' has undefined behavior"
 */
#pragma warning(disable : 5105)

#include <stdint.h>
#include <windows.h>
#endif

struct shared_memory {
        size_t size;
#ifdef _WIN32
        const TCHAR *name;
        HANDLE fd;
#else
        const char *name;
#endif
        void *ptr;
};

#define SHM_DATA_SIZE (2ULL * 1024ULL * 1024ULL)
#define SHM_INFO_SIZE (4ULL * 1024ULL)

#ifdef _WIN32
#define SHM_DATA_NAME TEXT("Local\\MpAppShmData")
#define SHM_INFO_NAME TEXT("Local\\MpAppShmInfo")
#endif

#ifdef __linux__
#define SHM_DATA_NAME "mp-app-shm-data"
#define SHM_INFO_NAME "mp-app-shm-info"
#endif

#ifdef __FreeBSD__
#define SHM_DATA_NAME "/tmp/mp-app-shm-data"
#define SHM_INFO_NAME "/tmp/mp-app-shm-info"
#endif

#endif /* _WIN32 || __linux__ || __FreeBSD__ */

/*
 * =============================================================================
 * =============================================================================
 * Shared memory API
 */

int
shm_destroy(struct shared_memory *sm, const int is_pri);

int
shm_create(struct shared_memory *sm, const int is_pri, const char *name, const size_t size,
           void *mmap_ptr);

#endif /* MP_SHARED_MEM_H */
