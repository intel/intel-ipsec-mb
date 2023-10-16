/*******************************************************************************
  Copyright (c) 2009-2023, Intel Corporation

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

#ifndef _WIRELESS_COMMON_H_
#define _WIRELESS_COMMON_H_

#include <string.h>
#ifdef LINUX
#include <x86intrin.h>
#else
#include <intrin.h>
#endif

#define NUM_PACKETS_1  1
#define NUM_PACKETS_2  2
#define NUM_PACKETS_3  3
#define NUM_PACKETS_4  4
#define NUM_PACKETS_8  8
#define NUM_PACKETS_16 16

#ifdef LINUX
#define BSWAP32 __builtin_bswap32
#define BSWAP64 __builtin_bswap64
#else
#define BSWAP32 _byteswap_ulong
#define BSWAP64 _byteswap_uint64
#endif

typedef union _m128_u {
        uint8_t byte[16];
        uint16_t word[8];
        uint32_t dword[4];
        uint64_t qword[2];
        __m128i m;
} m128_t;

typedef union _m64_u {
        uint8_t byte[8];
        uint16_t word[4];
        uint32_t dword[2];
        uint64_t m;
} m64_t;

static inline uint32_t
bswap4(const uint32_t val)
{
        return BSWAP32(val);
}

/*************************************************************************
 * @description - this function is used to copy the right number of bytes
 *                from the source to destination buffer
 *
 * @param pSrc [IN] - pointer to an input Byte array (at least len bytes
 *                    available)
 * @param pDst [IN] - pointer to the output buffer (at least len bytes available)
 * @param len  [IN] - length in bytes to copy (0 to 4)
 *
 *************************************************************************/
static inline void
memcpy_keystream_32(uint8_t *pDst, const uint8_t *pSrc, const uint32_t len)
{
        switch (len) {
        case 4:
                *(uint32_t *) pDst = *(const uint32_t *) pSrc;
                break;
        case 3:
                pDst[2] = pSrc[2];
                /* fall-through */
        case 2:
                pDst[1] = pSrc[1];
                /* fall-through */
        case 1:
                pDst[0] = pSrc[0];
                /* fall-through */
        }
}

/*************************************************************************
 * @description - this function is used to XOR the right number of bytes
 *                from a keystrea and a source into a destination buffer
 *
 * @param pSrc [IN] - pointer to an input Byte array (at least 4 bytes available)
 * @param pDst [IN] - pointer to the output buffer (at least 4 bytes available)
 * @param KS  [IN]  - 4 bytes of keystream number, must be reversed
 *                    into network byte order before XOR
 *
 *************************************************************************/
static inline void
xor_keystream_reverse_32(uint8_t *pDst, const uint8_t *pSrc, const uint32_t KS)
{
        *(uint32_t *) pDst = (*(const uint32_t *) pSrc) ^ BSWAP32(KS);
}

/******************************************************************************
 * @description - this function is used to do a keystream operation
 * @param pSrc [IN] - pointer to an input Byte array (at least 8 bytes
 *                    available)
 * @param pDst [IN] - pointer to the output buffer (at least 8 bytes available)
 * @param keyStream [IN] -  the Keystream value (8 bytes)
 ******************************************************************************/
static inline const uint8_t *
xor_keystrm_rev(uint8_t *pDst, const uint8_t *pSrc, uint64_t keyStream)
{
        /* default: XOR ONLY, read the input buffer, update the output buffer */
        const uint64_t *pSrc64 = (const uint64_t *) pSrc;
        uint64_t *pDst64 = (uint64_t *) pDst;
        *pDst64 = *pSrc64 ^ BSWAP64(keyStream);
        return (const uint8_t *) (pSrc64 + 1);
}

/******************************************************************************
 * @description - this function is used to copy the right number of bytes
 *                from the source to destination buffer
 * @param pSrc [IN] - pointer to an input Byte array (at least len bytes
 *                    available)
 * @param pDst [IN] - pointer to the output buffer (at least len bytes
 *                    available)
 * @param len  [IN] - length in bytes to copy
 ******************************************************************************/
static inline void
memcpy_keystrm(uint8_t *pDst, const uint8_t *pSrc, const uint32_t len)
{
        switch (len) {
        case 8:
                *(uint64_t *) pDst = *(const uint64_t *) pSrc;
                break;
        case 7:
                pDst[6] = pSrc[6];
                /* fall-through */
        case 6:
                pDst[5] = pSrc[5];
                /* fall-through */
        case 5:
                pDst[4] = pSrc[4];
                /* fall-through */
        case 4:
                *(uint32_t *) pDst = *(const uint32_t *) pSrc;
                break;
        case 3:
                pDst[2] = pSrc[2];
                /* fall-through */
        case 2:
                pDst[1] = pSrc[1];
                /* fall-through */
        case 1:
                pDst[0] = pSrc[0];
                /* fall-through */
        }
}

/**
 * @brief Save start and end of the buffer around message
 *
 * @param msg message buffer (destination buffer)
 * @param bit_offset message offset in bits (0- 7)
 * @param bit_length message length in bits
 * @param save_start place to store start byte
 * @param save_end place to store end byte
 */
static inline void
msg_save_start_end(const void *msg, const size_t bit_offset, const size_t bit_length,
                   uint8_t *save_start, uint8_t *save_end)
{
        *save_start = 0;
        *save_end = 0;

        if (bit_length == 0 || bit_offset == 0)
                return;

        /* 0xff << (8 - i) */
        static const uint8_t mtab_shl[8] = { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };
        const uint8_t *msg_ptr = (const uint8_t *) msg;

        *save_start = *msg_ptr & mtab_shl[bit_offset];

        /* 0xff >> i */
        static const uint8_t mtab_shr[8] = { 0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01 };
        const size_t blast = bit_offset + bit_length;
        const size_t bend = blast & 7; /* non-inclusive */

        if (blast < 8) {
                *save_end = msg_ptr[0] & mtab_shr[bend];
        } else {
                const size_t i = ((bend == 0) ? (blast - 8) : blast) / 8;

                *save_end = msg_ptr[i] & mtab_shr[bend];
        }
}

/**
 * @brief Reconstruct start and end of the buffer around message
 *
 * @param msg message buffer (destination buffer)
 * @param bit_offset message offset in bits (0 to 7)
 * @param bit_length message length in bits
 * @param save_start saved start byte to be restored
 * @param save_end saved end byte to be restored
 */
static inline void
msg_restore_start_end(void *msg, const size_t bit_offset, const size_t bit_length,
                      const uint8_t save_start, const uint8_t save_end)
{
        if (bit_length == 0 || bit_offset == 0)
                return;

        uint8_t *msg_ptr = (uint8_t *) msg;

        if (save_start != 0)
                msg_ptr[bit_offset >> 3] |= save_start;

        if (save_end != 0) {
                const size_t blast = bit_offset + bit_length;

                if (blast < 8) {
                        msg_ptr[0] |= save_end;
                } else {
                        const size_t bend = blast & 7; /* non-inclusive */
                        const size_t i = ((bend == 0) ? (blast - 8) : blast) / 8;

                        msg_ptr[i] |= save_end;
                }
        }
}

/**
 * @brief Copy bit message from \a src to \dst
 *
 * When reading data from \a src, shift left \a src by \a src_bit_offset number bits
 *
 * @param dst destination buffer
 * @param src source buffer
 * @param src_bit_offset offset from in bits from \a src (0 - 7)
 * @param bit_length message length in bits
 */
static inline void
msg_shl_copy(void *dst, const void *src, const size_t src_bit_offset, const size_t bit_length)
{
        uint8_t *dp = (uint8_t *) dst;
        const uint8_t *sp = (const uint8_t *) src;

        const size_t bit_start = src_bit_offset;
        const size_t byte_length = bit_length / 8;

        size_t i;

        for (i = 0; i < byte_length; i++) {
                if (bit_start == 0) {
                        dp[i] = sp[i];
                } else {
                        const uint8_t nibble1 = sp[i] << bit_start;
                        const uint8_t nibble2 = sp[i + 1] >> (8 - bit_start);

                        dp[i] = nibble1 | nibble2;
                }
        }

        const size_t last_byte_bits = bit_length & 7;

        if (last_byte_bits != 0) {
                if (bit_start == 0) {
                        dp[i] = sp[i];
                } else {
                        if (last_byte_bits <= (8 - bit_start)) {
                                const uint8_t nibble = sp[i] << bit_start;

                                dp[i] = nibble;
                        } else {
                                const uint8_t nibble1 = sp[i] << bit_start;
                                const uint8_t nibble2 = sp[i + 1] >> (8 - bit_start);

                                dp[i] = nibble1 | nibble2;
                        }
                }

                /* 0xff << (8 - i) */
                static const uint8_t mtab_shl[8] = {
                        0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe
                };

                dp[i] = dp[i] & mtab_shl[last_byte_bits];
        }
}

/**
 * @brief Shift right bit message (in place)
 *
 * Message bits:
 *      BYTE 0           BYTE 1
 * |<- MSB  LSB ->| |<- MSB  LSB ->|
 * A7A6A5A4A3A2A1A0 B7B6B5B4B3B2B1B0
 *
 * Shift 1:
 * 00A7A6A5A4A3A2A1 A0B7B6B5B4B3B2B1 B0
 *
 * @param msg message buffer
 * @param bit_offset number of bits to shift \a msg right by (0 to 7)
 * @param bit_length message length in bits
 */
static inline void
msg_shr(void *msg, const size_t nbits, const size_t bit_length)
{
        if (nbits == 0 || bit_length == 0)
                return;

        uint8_t *dp = (uint8_t *) msg;
        const size_t byte_length = bit_length / 8;
        uint8_t carry = 0;
        size_t i;

        for (i = 0; i < byte_length; i++) {
                const uint8_t nibble = dp[i];

                dp[i] = (carry << (8 - nbits)) | (nibble >> nbits);
                carry = nibble;
        }

        /* 0xff << (8 - i) */
        static const uint8_t mtab_shl[8] = { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };
        const size_t last_byte_bits = bit_length & 7;
        const uint8_t nibble = (last_byte_bits != 0) ? (dp[i] & mtab_shl[last_byte_bits]) : 0;

        dp[i] = (carry << (8 - nbits)) | (nibble >> nbits);

        if ((last_byte_bits + nbits) > 8)
                dp[i + 1] = nibble << (8 - nbits);
}

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external SSE function that XOR's 16 bytes of input
 *      with 16 bytes of keystream, swapping keystream bytes every 4 bytes.
 *
 * @param[in]  pIn              Pointer to the input buffer
 * @param[out] pOut             Pointer to the output buffer
 * @param[in]  pKey             Pointer to the new 16 byte keystream
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL void
asm_XorKeyStream16B_sse(const void *pIn, void *pOut, const void *pKey);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external AVX function that XOR's 16 bytes of input
 *      with 16 bytes of keystream, swapping keystream bytes every 4 bytes.
 *
 * @param[in]  pIn              Pointer to the input buffer
 * @param[out] pOut             Pointer to the output buffer
 * @param[in]  pKey             Pointer to the new 16 byte keystream
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL void
asm_XorKeyStream16B_avx(const void *pIn, void *pOut, const void *pKey);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external AVX2 function that XOR's 32 bytes of input
 *      with 32 bytes of keystream, swapping keystream bytes every 4 bytes.
 *
 * @param[in]  pIn              Pointer to the input buffer
 * @param[out] pOut             Pointer to the output buffer
 * @param[in]  pKey             Pointer to the new 32 byte keystream
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL void
asm_XorKeyStream32B_avx2(const void *pIn, void *pOut, const void *pKey);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external AVX512 function that XOR's 64 bytes of input
 *      with 64 bytes of keystream, swapping keystream bytes every 4 bytes.
 *
 * @param[in]  pIn              Pointer to the input buffer
 * @param[out] pOut             Pointer to the output buffer
 * @param[in]  pKey             Pointer to the new 64 byte keystream
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL void
asm_XorKeyStream64B_avx512(const void *pIn, void *pOut, const void *pKey);

#endif /* _WIRELESS_COMMON_H_ */
