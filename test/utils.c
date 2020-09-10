/*****************************************************************************
 Copyright (c) 2018-2020, Intel Corporation

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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "utils.h"

static uint8_t hex_buffer[16 * 1024];

/**
 * @brief Simplistic memory copy (intentionally not using libc)
 *
 * @param dst destination buffer pointer
 * @param src source buffer pointer
 * @param length length of the buffer to copy in bytes
 */
static void memory_copy(void *dst, const void *src, size_t length)
{
        uint8_t *d = (uint8_t *) dst;
        const uint8_t *s = (const uint8_t *) src;

        while (length--)
                *d++ = *s++;
}

/**
 * @brief Dumps fragment of memory in hex and ASCII into `fp`
 *
 * @note It is not multithread safe.
 * @note It works on buffer sizes up to 16,384 bytes.
 *
 * @param fp file stream to print into
 * @param msg optional extra header string message to print
 * @param p start address of data block to be dumped
 * @param len size of the data block to dump in bytes
 * @param start_ptr can be
 *          - pointer to data being dumped then first column of the dump will
 *            display addresses
 *          - NULL pointer then first column witll display indexes
 */
void
hexdump_ex(FILE *fp,
           const char *msg,
           const void *p,
           size_t len,
           const void *start_ptr)
{
        size_t ofs = 0;
        const unsigned char *data = hex_buffer;
        const char *start = (const char *) start_ptr;

        if (p == NULL)
                return;

        if (len > sizeof(hex_buffer))
                len = sizeof(hex_buffer);

        /*
         * Make copy of the buffer and work on it.
         * This is helping cases where stack area is printed and
         * libc API's put data on the stack
         */
        memory_copy(hex_buffer, p, len);

        if (msg != NULL)
                fprintf(fp, "%s\n", msg);

        while (ofs < len) {
                unsigned int i;

                fprintf(fp, "%p:", &start[ofs]);

                for (i = 0; ((ofs + i) < len) && (i < 16); i++)
                        fprintf(fp, " %02x", (data[ofs + i] & 0xff));

                for (; i <= 16; i++)
                        fprintf(fp, " | ");

                for (i = 0; (ofs < len) && (i < 16); i++, ofs++) {
                        unsigned char c = data[ofs];

                        if (!isprint(c))
                                c = '.';
                        fprintf(fp, "%c", c);
                }
                fprintf(fp, "\n");
        }
}

/**
 * @brief Simpler version of hexdump_ex() displaying data indexes only
 *
 * @param fp file stream to print into
 * @param msg optional extra header string message to print
 * @param p start address of data block to be dumped
 * @param len size of the data block to dump in bytes
 */
void
hexdump(FILE *fp,
        const char *msg,
        const void *p,
        size_t len)
{
        hexdump_ex(fp, msg, p, len, NULL);
}
