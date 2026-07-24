/*******************************************************************************
  Copyright (c) 2026, Intel Corporation

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
*******************************************************************************/

/**
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * Minimal self-contained replacement for OpenSSL's "internal/packet.h",
 * implementing only the read (PACKET) and write (WPACKET) helpers referenced
 * by the vendored ML-DSA (FIPS 204) encoders:
 *
 *   PACKET_buf_init, PACKET_remaining, PACKET_get_bytes, PACKET_copy_bytes
 *   WPACKET_init_static_len, WPACKET_allocate_bytes, WPACKET_memcpy,
 *   WPACKET_get_total_written, WPACKET_finish
 *
 * ML-DSA only ever uses WPACKET over a caller-provided fixed buffer with no
 * length prefix (lenbytes == 0) and no sub-packets, so the growable BUF_MEM /
 * sub-packet machinery of the full implementation is intentionally omitted.
 * The behaviour of the functions below is byte-for-byte equivalent to OpenSSL
 * for that usage.
 *
 * The PACKET struct layout and the packet_forward() / PACKET_remaining() /
 * PACKET_buf_init() functions below are copied near-verbatim from OpenSSL's
 * "internal/packet.h" and therefore carry the OpenSSL copyright/license
 * notice above alongside the Intel one. The WPACKET struct and its
 * functions are an original, reduced-scope reimplementation matching
 * OpenSSL's documented WPACKET semantics for the fixed-buffer, no-length-
 * prefix, no-sub-packet case used by ML-DSA.
 */

#ifndef IMB_ML_DSA_COMPAT_INTERNAL_PACKET_H
#define IMB_ML_DSA_COMPAT_INTERNAL_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "openssl_compat.h" /* ossl_inline, ossl_unused, __owur, ossl_assert */

/* ------------------------------------------------------------------------- */
/* PACKET - sequential read of a fixed input buffer.                         */
/* ------------------------------------------------------------------------- */
typedef struct {
        /* Pointer to where we are currently reading from */
        const unsigned char *curr;
        /* Pointer to the start of the message */
        const unsigned char *msgstart;
        /* Number of bytes remaining */
        size_t remaining;
} PACKET;

/* Internal unchecked shorthand; don't use outside this file. */
static ossl_inline ossl_unused void
packet_forward(PACKET *pkt, size_t len)
{
        pkt->curr += len;
        pkt->remaining -= len;
}

/* Returns the number of bytes remaining to be read in the PACKET. */
static ossl_inline ossl_unused size_t
PACKET_remaining(const PACKET *pkt)
{
        return pkt->remaining;
}

__owur static ossl_inline ossl_unused int
PACKET_buf_init(PACKET *pkt, const unsigned char *buf, size_t len)
{
        /* Sanity check for negative values. */
        if (len > (size_t) (SIZE_MAX / 2))
                return 0;

        pkt->curr = pkt->msgstart = buf;
        pkt->remaining = len;
        return 1;
}

__owur static ossl_inline ossl_unused int
PACKET_peek_bytes(const PACKET *pkt, const unsigned char **data, size_t len)
{
        if (PACKET_remaining(pkt) < len)
                return 0;

        *data = pkt->curr;
        return 1;
}

__owur static ossl_inline ossl_unused int
PACKET_get_bytes(PACKET *pkt, const unsigned char **data, size_t len)
{
        if (!PACKET_peek_bytes(pkt, data, len))
                return 0;

        packet_forward(pkt, len);
        return 1;
}

__owur static ossl_inline ossl_unused int
PACKET_copy_bytes(PACKET *pkt, unsigned char *data, size_t len)
{
        if (PACKET_remaining(pkt) < len)
                return 0;

        memcpy(data, pkt->curr, len);
        packet_forward(pkt, len);
        return 1;
}

/* ------------------------------------------------------------------------- */
/* WPACKET - sequential write into a fixed, caller-provided buffer.          */
/* ------------------------------------------------------------------------- */
typedef struct {
        /* The fixed-size output buffer. */
        unsigned char *staticbuf;
        /* Offset into the buffer where we are currently writing. */
        size_t curr;
        /* Number of bytes written so far. */
        size_t written;
        /* Maximum number of bytes we will allow to be written. */
        size_t maxsize;
} WPACKET;

__owur static ossl_inline ossl_unused int
WPACKET_init_static_len(WPACKET *pkt, unsigned char *buf, size_t len, size_t lenbytes)
{
        /* ML-DSA never uses a length prefix. */
        if (!ossl_assert(buf != NULL && len > 0 && lenbytes == 0))
                return 0;

        pkt->staticbuf = buf;
        pkt->maxsize = len;
        pkt->curr = 0;
        pkt->written = 0;
        return 1;
}

__owur static ossl_inline ossl_unused int
WPACKET_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
        if (pkt->maxsize - pkt->written < len)
                return 0;

        if (allocbytes != NULL)
                *allocbytes = pkt->staticbuf + pkt->curr;
        pkt->written += len;
        pkt->curr += len;
        return 1;
}

__owur static ossl_inline ossl_unused int
WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len)
{
        unsigned char *dest;

        if (len == 0)
                return 1;

        if (!WPACKET_allocate_bytes(pkt, len, &dest))
                return 0;

        memcpy(dest, src, len);
        return 1;
}

__owur static ossl_inline ossl_unused int
WPACKET_get_total_written(WPACKET *pkt, size_t *written)
{
        if (!ossl_assert(written != NULL))
                return 0;

        *written = pkt->written;
        return 1;
}

/**
 * Close the top-level WPACKET.  With no length prefix and no sub-packets there
 * is nothing to back-fill, so this simply succeeds.
 */
static ossl_inline ossl_unused int
WPACKET_finish(WPACKET *pkt)
{
        (void) pkt;
        return 1;
}

#endif /* IMB_ML_DSA_COMPAT_INTERNAL_PACKET_H */
