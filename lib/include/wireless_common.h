/*******************************************************************************
  Copyright (c) 2009-2022, Intel Corporation

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

#define NUM_PACKETS_1 1
#define NUM_PACKETS_2 2
#define NUM_PACKETS_3 3
#define NUM_PACKETS_4 4
#define NUM_PACKETS_8 8
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

static inline uint32_t bswap4(const uint32_t val)
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
static inline void memcpy_keystream_32(uint8_t *pDst,
                                       const uint8_t *pSrc,
                                       const uint32_t len)
{
        switch (len) {
        case 4:
                *(uint32_t *)pDst = *(const uint32_t *)pSrc;
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
static inline void xor_keystream_reverse_32(uint8_t *pDst,
                                            const uint8_t *pSrc,
                                            const uint32_t KS)
{
        *(uint32_t *)pDst = (*(const uint32_t *)pSrc) ^ BSWAP32(KS);
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
        const uint64_t *pSrc64 = (const uint64_t *)pSrc;
        uint64_t *pDst64 = (uint64_t *)pDst;
        *pDst64 = *pSrc64 ^ BSWAP64(keyStream);
        return (const uint8_t *)(pSrc64 + 1);
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
                *(uint64_t *)pDst = *(const uint64_t *)pSrc;
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
                *(uint32_t *)pDst = *(const uint32_t *)pSrc;
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
 * @param bit_offset message offset in bits
 * @param bit_length message length in bits
 * @param save_start place to store start byte
 * @param save_end place to store end byte
 */
static inline void
save_msg_start_end(const void *msg,
                   const size_t bit_offset, const size_t bit_length,
                   uint8_t *save_start, uint8_t *save_end)
{
        const uint8_t *msg_ptr = (const uint8_t *) msg;
        const size_t mstart_bit = bit_offset & 7; /* inclusive */
        const size_t mend_bit =
                (mstart_bit + bit_length) & 7; /* non-inclusive */

        *save_start = 0;
        *save_end = 0;

        if (bit_length == 0)
                return;

        if (mstart_bit != 0) {
                const uint8_t msg_start = msg_ptr[bit_offset >> 3];

                *save_start = msg_start & (0xff << (8 - mstart_bit));
        }

        if (mend_bit != 0) {
                const uint8_t msg_end = msg_ptr[(bit_offset + bit_length) >> 3];

                *save_end = msg_end & (0xff >> mend_bit);
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
restore_msg_start_end(void *msg,
                      const size_t bit_offset, const size_t bit_length,
                      const uint8_t save_start, const uint8_t save_end)
{
        uint8_t *msg_ptr = (uint8_t *) msg;

        if (bit_length == 0)
                return;

        if (save_start != 0)
                msg_ptr[bit_offset >> 3] |= save_start;

        if (save_end != 0)
                msg_ptr[(bit_offset + bit_length) >> 3] |= save_end;
}

/**
 * @brief Copy bit message from \a src to \dst
 *
 * @param dst destination buffer
 * @param src source buffer
 * @param bit_offset offset from in bits from \a src
 * @param bit_length message length in bits
 */
static inline void
copy_bits(void *dst, const void *src,
          const size_t bit_offset, const size_t bit_length)
{
        uint8_t *dp = (uint8_t *) dst;
        const uint8_t *sp = &((const uint8_t *) src)[bit_offset >> 3];
        const size_t mstart_bit = bit_offset & 7;
        const size_t mend_bit = (bit_offset + bit_length) & 7;
        size_t byte_length = (bit_length + 7) >> 3;

        if (bit_length == 0)
                return;

        for ( ; byte_length >= 1; byte_length--) {
                if (mstart_bit == 0) {
                        *dp++ = *sp++;
                } else {
                        *dp++ = (sp[0] << mstart_bit) |
                                (sp[1] >> (8 - mstart_bit));
                        sp++;
                }
        }

        if (mstart_bit == 0) {
                if (mend_bit == 0)
                        *dp = *sp;
                else
                        *dp = *sp & (0xff << (8 - mend_bit));
        } else {
                if (mend_bit == 0)
                        *dp = *sp << mstart_bit;
                else
                        *dp = (*sp & (0xff << (8 - mend_bit))) << mstart_bit;
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
 * @param bit_offset number of bits to shift \a msg right by
 * @param bit_length message length in bits
 */
static inline void
shift_bits(void *msg, const size_t bit_offset, const size_t bit_length)
{
        uint8_t *dst = (uint8_t *) msg;
        const size_t mstart_bit = bit_offset & 7;
        const size_t mend_bit = (bit_offset + bit_length) & 7;
        size_t byte_length = (bit_length + 7) >> 3;

        if (bit_length == 0)
                return;

        if (mstart_bit != 0) {
                uint8_t byte_save = 0;

                if (byte_length == 1) {
                        *dst = (*dst & (0xff << (8 - mend_bit))) >> mstart_bit;
                        return;
                }

                for ( ; byte_length >= 1; byte_length--) {
                        const uint8_t c = *dst;

                        *dst++ = (c >> mstart_bit) | byte_save;
                        byte_save = c << (8 - mstart_bit);
                }

                *dst = byte_save;
        } else {
                if (mend_bit != 0)
                        dst[byte_length] &= (0xff << (8 - mend_bit));
        }
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
IMB_DLL_LOCAL void asm_XorKeyStream16B_sse(const void *pIn, void *pOut,
                                           const void *pKey);

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
IMB_DLL_LOCAL void asm_XorKeyStream16B_avx(const void *pIn, void *pOut,
                                           const void *pKey);

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
IMB_DLL_LOCAL void asm_XorKeyStream32B_avx2(const void *pIn, void *pOut,
                                            const void *pKey);

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
IMB_DLL_LOCAL void asm_XorKeyStream64B_avx512(const void *pIn, void *pOut,
                                              const void *pKey);

#endif /* _WIRELESS_COMMON_H_ */
