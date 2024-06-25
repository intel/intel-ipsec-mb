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

#include "mp_shared_mem.h"

#if defined(__MINGW32__)

int
shm_destroy(struct shared_memory *sm, const int is_pri)
{
        (void) is_pri;
        sm->name = NULL;
        sm->size = 0;
        sm->ptr = NULL;
        return 0;
}

int
shm_create(struct shared_memory *sm, const int is_pri, const char *name, const size_t size,
           void *mmap_ptr)
{
        (void) is_pri;
        (void) mmap_ptr;
        sm->name = name;
        sm->size = size;
        sm->ptr = NULL;
        return 0;
}

#else

#if defined(__linux__) || defined(__FreeBSD__)
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#endif

#ifdef _WIN32
/*
 * Disable C5105 to workaround warning coming from winbase.h file
 * "Windows Kits\10\include\10.0.19041.0\um\winbase.h(9531): warning
 * C5105: macro expansion producing 'defined' has undefined behavior"
 */
#pragma warning(disable : 5105)

#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#endif

/*
 * =============================================================================
 * =============================================================================
 * Linux & FreeBSD: Shared memory create and destroy
 */

#if defined(__FreeBSD__) || defined(__linux__)
int
shm_destroy(struct shared_memory *sm, const int is_pri)
{
        int ret = 0;

        if (!is_pri)
                if (munmap(sm->ptr, sm->size) != 0) {
                        perror("shm_destroy()");
                        ret = -1;
                }
        sm->ptr = NULL;

        if (is_pri)
                if (shm_unlink(sm->name) != 0) {
                        perror("shm_destroy()");
                        ret = -1;
                }

        sm->name = NULL;
        sm->size = 0;
        return ret;
}

int
shm_create(struct shared_memory *sm, const int is_pri, const char *name, const size_t size,
           void *mmap_ptr)
{
        int fd = -1;

        sm->name = name;
        sm->size = size;
        sm->ptr = MAP_FAILED;

        /* create the shared memory object */
        if (is_pri) {
                fd = shm_open(sm->name, O_RDWR, 0666);
                if (fd != -1) {
                        printf("shm_open(): %s already exists!\n", sm->name);
                        close(fd);
                        return -1;
                }
                fd = shm_open(sm->name, O_CREAT | O_RDWR, 0666);
        } else {
                fd = shm_open(sm->name, O_RDWR, 0666);
        }

        if (fd == -1) {
                perror("shm_create()");
                return -1;
        }

        /* configure the size of the shared memory object */
        if (is_pri) {
                if (ftruncate(fd, sm->size) != 0) {
                        perror("shm_create()");
                        (void) shm_destroy(sm, is_pri);
                        close(fd);
                        return -1;
                }
        }

        /*
         * memory map the shared memory object
         * - secondary process maps shared memory into the same region as the primary process
         */
        if (is_pri) {
#ifdef __FreeBSD__
                static char *base = (char *) 0x900000000; /* arbitrary VA to start mapping from */
                const size_t page_sz = (size_t) (getpagesize() - 1);

                sm->ptr = mmap((void *) base, sm->size, PROT_READ | PROT_WRITE,
                               MAP_FIXED | MAP_PREFAULT_READ | MAP_SHARED, fd, 0);
                base += ((sm->size + page_sz) & (~page_sz));
#else
                sm->ptr = mmap(0, sm->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
#endif
        } else {
                if (mmap_ptr == NULL) {
#ifdef __FreeBSD__
                        const int flags = MAP_PREFAULT_READ | MAP_SHARED;
#else
                        const int flags = MAP_SHARED;
#endif

                        sm->ptr = mmap(NULL, sm->size, PROT_READ | PROT_WRITE, flags, fd, 0);
                } else {
#ifdef __FreeBSD__
                        const int flags = MAP_PREFAULT_READ | MAP_SHARED | MAP_FIXED;
#else
                        const int flags = MAP_SHARED | MAP_FIXED;
#endif

                        sm->ptr = mmap(mmap_ptr, sm->size, PROT_READ | PROT_WRITE, flags, fd, 0);
                        if (mmap_ptr != sm->ptr) {
                                printf("mmap() %p != mmap_ptr %p\n", sm->ptr, mmap_ptr);
                                (void) shm_destroy(sm, is_pri);
                                return -1;
                        }
                }
        }

        close(fd);

        if (sm->ptr == MAP_FAILED) {
                perror("shm_create()");
                fprintf(stderr, "!mmap() of %s shared memory error\n", sm->name);
                (void) shm_destroy(sm, is_pri);
                return -1;
        }

        return 0;
}
#endif /* __linux__ || __FreeBSD__ */

/*
 * =============================================================================
 * =============================================================================
 * Windows: Shared memory create and destroy
 */

#ifdef _WIN32
static void
printLastError(const DWORD error)
{
        LPSTR message = NULL;

        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                               FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &message, 0,
                       NULL);

        if (message) {
                fprintf(stderr, "ERROR: %s\n", message);
                LocalFree(message);
        }
}

int
shm_destroy(struct shared_memory *sm, const int is_pri)
{
        int ret = 0;

        if (sm->ptr != NULL)
                UnmapViewOfFile(sm->ptr);

        if (sm->fd != INVALID_HANDLE_VALUE)
                CloseHandle(sm->fd);

        sm->ptr = NULL;
        sm->name = NULL;
        sm->size = 0;
        sm->fd = INVALID_HANDLE_VALUE;
        return ret;
}

int
shm_create(struct shared_memory *sm, const int is_pri, const TCHAR *name, const size_t size,
           void *mmap_ptr)
{
        static char *base = NULL;
        static SYSTEM_INFO si;

        if (base == NULL) {
                GetSystemInfo(&si);

                const size_t allocMask = si.dwAllocationGranularity - 1;
                const uintptr_t new_base = (uintptr_t) si.lpMaximumApplicationAddress;

                /* align base mapping address to allocation granularity */
                base = (char *) (new_base & (~allocMask));
        }

        HANDLE fd = INVALID_HANDLE_VALUE;

        sm->name = name;
        sm->size = size;
        sm->ptr = NULL;
        sm->fd = INVALID_HANDLE_VALUE;

        if (is_pri) {
                fd = CreateFileMappingA((HANDLE) INVALID_HANDLE_VALUE, /* Use the page file */
                                        NULL, PAGE_READWRITE, 0, (DWORD) sm->size, sm->name);
        } else {
                fd = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, sm->name);
        }

        if (fd == INVALID_HANDLE_VALUE) {
                fprintf(stderr, "ERROR: %s failed to create shared memory object (%d)\n", sm->name,
                        GetLastError());
                printLastError(GetLastError());
                return -1;
        }

        /* Map the shared memory object into the address space of the current process */
        if (is_pri) {
                const size_t allocMask = si.dwAllocationGranularity - 1;
                const size_t allocAlignedSize = (size + allocMask) & (~allocMask);

                /* adjust mapping address to allocation size (aligned to allocation granularity) */
                base = base - allocAlignedSize;

                sm->ptr = (void *) MapViewOfFileEx(fd, FILE_MAP_ALL_ACCESS, /* Read/write access */
                                                   0, 0,                    /* offset = 0 */
                                                   0 /* map all object */, (LPVOID) base);

                if (sm->ptr != (void *) base) {
                        fprintf(stderr, "!mmap(%p) = %p %s shared memory error\n", base, sm->ptr,
                                sm->name);
                        printLastError(GetLastError());
                        (void) shm_destroy(sm, is_pri);
                        return -1;
                }
        } else {
                sm->ptr = (void *) MapViewOfFileEx(fd, FILE_MAP_ALL_ACCESS, /* Read/write access */
                                                   0, 0,                    /* Offset = 0 */
                                                   0 /* map all object */, (LPVOID) mmap_ptr);
                if ((mmap_ptr != NULL) && (sm->ptr != mmap_ptr)) {
                        fprintf(stderr, "!mmap(%p) = %p %s shared memory error\n", mmap_ptr,
                                sm->ptr, sm->name);
                        printLastError(GetLastError());
                        (void) shm_destroy(sm, is_pri);
                        return -1;
                }
        }

        if (sm->ptr == NULL) {
                fprintf(stderr, "ERROR: %s failed to map view of shared memory (%d)\n", sm->name,
                        GetLastError());
                printLastError(GetLastError());
                (void) shm_destroy(sm, is_pri);
                return -1;
        }

        sm->fd = fd;
        return 0;
}
#endif

#endif /* _WIN32 || __linux__ || __FreeBSD__ */
