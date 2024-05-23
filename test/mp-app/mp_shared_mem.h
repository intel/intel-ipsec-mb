/*****************************************************************************
 Copyright (c) 2024, Intel Corporation

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
