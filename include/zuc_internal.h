/*******************************************************************************
  Copyright (c) 2009-2020, Intel Corporation

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
 ******************************************************************************
 * @file zuc_internal.h
 *
 * @description
 *      This header file defines the internal API's and data types for the
 *      3GPP algorithm ZUC.
 *
 *****************************************************************************/

#ifndef ZUC_INTERNAL_H_
#define ZUC_INTERNAL_H_

#include <stdio.h>
#include <stdint.h>

#include "intel-ipsec-mb.h"
#include "immintrin.h"
#include "include/wireless_common.h"

/* 64 bytes of Keystream will be generated */
#define ZUC_KEYSTR_LEN                      (64)
#define NUM_LFSR_STATES                     (16)
#define ZUC_WORD                            (32)

/* Range of input data for ZUC is from 1 to 65504 bits */
#define ZUC_MIN_BITLEN     1
#define ZUC_MAX_BITLEN     65504
#define ZUC_MIN_BYTELEN    1
#define ZUC_MAX_BYTELEN    (ZUC_MAX_BITLEN / 8)

#ifdef DEBUG
#ifdef _WIN32
#define DEBUG_PRINT(_fmt, ...) \
        fprintf(stderr, "%s()::%d " _fmt , __FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define DEBUG_PRINT(_fmt, ...) \
        fprintf(stderr, "%s()::%d " _fmt , __func__, __LINE__, __VA_ARGS__)
#endif
#else
#define DEBUG_PRINT(_fmt, ...)
#endif

/**
 ******************************************************************************
 * @description
 *      Macro will loop through keystream of length 64bytes and xor with the
 *      input buffer placing the result in the output buffer.
 *      KeyStream bytes must be swaped on 32bit boundary before this operation
 *
 *****************************************************************************/
#define ZUC_XOR_KEYSTREAM(pIn64, pOut64, pKeyStream64)		\
{									\
	int i =0;							\
	union SwapBytes_t {						\
		uint64_t l64;						\
		uint32_t w32[2];					\
	}swapBytes;							\
	/* loop through the key stream and xor 64 bits at a time */	\
	for(i =0; i < ZUC_KEYSTR_LEN/8; i++) {				\
		swapBytes.l64 = *pKeyStream64++;			\
		swapBytes.w32[0] = bswap4(swapBytes.w32[0]); \
		swapBytes.w32[1] = bswap4(swapBytes.w32[1]); \
		*pOut64++ = *pIn64++ ^ swapBytes.l64;			\
	}								\
}

/**
 *****************************************************************************
 * @description
 *      Packed structure to store the ZUC state for a single packet. *
 *****************************************************************************/
typedef struct zuc_state_s {
    uint32_t lfsrState[16];
    /**< State registers of the LFSR */
    uint32_t fR1;
    /**< register of F */
    uint32_t fR2;
    /**< register of F */
    uint32_t bX0;
    /**< Output X0 of the bit reorganization */
    uint32_t bX1;
    /**< Output X1 of the bit reorganization */
    uint32_t bX2;
    /**< Output X2 of the bit reorganization */
    uint32_t bX3;
    /**< Output X3 of the bit reorganization */
} ZucState_t;

/**
 *****************************************************************************
 * @description
 *      Packed structure to store the ZUC state for 4 packets. *
 *****************************************************************************/
typedef struct zuc_state_4_s {
    uint32_t lfsrState[16][4];
    /**< State registers of the LFSR */
    uint32_t fR1[4];
    /**< register of F */
    uint32_t fR2[4];
    /**< register of F */
    uint32_t bX0[4];
    /**< Output X0 of the bit reorganization for 4 packets */
    uint32_t bX1[4];
    /**< Output X1 of the bit reorganization for 4 packets */
    uint32_t bX2[4];
    /**< Output X2 of the bit reorganization for 4 packets */
    uint32_t bX3[4];
    /**< Output X3 of the bit reorganization for 4 packets */
} ZucState4_t;

/**
 *****************************************************************************
 * @description
 *      Structure to store pointers to the 4 keys to be used as input to
 *      @ref asm_ZucInitialization_4 and @ref asm_ZucGenKeystream64B_4
 *****************************************************************************/
typedef struct zuc_key_4_s {
    const uint8_t *pKey1;
    /**< Pointer to 128-bit key for packet 1 */
    const uint8_t *pKey2;
    /**< Pointer to 128-bit key for packet 2 */
    const uint8_t *pKey3;
    /**< Pointer to 128-bit key for packet 3 */
    const uint8_t *pKey4;
    /**< Pointer to 128-bit key for packet 4 */
} ZucKey4_t;

/**
 *****************************************************************************
 * @description
 *      Structure to store pointers to the 4 IV's to be used as input to
 *      @ref asm_ZucInitialization_4 and @ref asm_ZucGenKeystream64B_4
 *****************************************************************************/
typedef struct zuc_iv_4_s {
    const uint8_t *pIv1;
    /**< Pointer to 128-bit initialization vector for packet 1 */
    const uint8_t *pIv2;
    /**< Pointer to 128-bit initialization vector for packet 2 */
    const uint8_t *pIv3;
    /**< Pointer to 128-bit initialization vector for packet 3 */
    const uint8_t *pIv4;
    /**< Pointer to 128-bit initialization vector for packet 4 */
} ZucIv4_t;

/**
 *****************************************************************************
 * @description
 *      Packed structure to store the ZUC state for 8 packets. *
 *****************************************************************************/
typedef struct zuc_state_8_s {
    uint32_t lfsrState[16][8];
    /**< State registers of the LFSR */
    uint32_t fR1[8];
    /**< register of F */
    uint32_t fR2[8];
    /**< register of F */
    uint32_t bX0[8];
    /**< Output X0 of the bit reorganization for 8 packets */
    uint32_t bX1[8];
    /**< Output X1 of the bit reorganization for 8 packets */
    uint32_t bX2[8];
    /**< Output X2 of the bit reorganization for 8 packets */
    uint32_t bX3[8];
    /**< Output X3 of the bit reorganization for 8 packets */
} ZucState8_t;

/**
 *****************************************************************************
 * @description
 *      Structure to store pointers to the 8 keys to be used as input to
 *      @ref asm_ZucInitialization_8 and @ref asm_ZucGenKeystream64B_8
 *****************************************************************************/
typedef struct zuc_key_8_s {
    const uint8_t *pKeys[8];
    /**< Array of pointers to 128-bit keys for the 8 packets */
} ZucKey8_t;

/**
 *****************************************************************************
 * @description
 *      Structure to store pointers to the 8 IV's to be used as input to
 *      @ref asm_ZucInitialization_8 and @ref asm_ZucGenKeystream64B_8
 *****************************************************************************/
typedef struct zuc_iv_8_s {
    const uint8_t *pIvs[8];
    /**< Array of pointers to 128-bit IV's for the 8 packets */
} ZucIv8_t;

/**
 *****************************************************************************
 * @description
 *      Packed structure to store the ZUC state for 16 packets. *
 *****************************************************************************/
typedef struct zuc_state_16_s {
    uint32_t lfsrState[16][16];
    /**< State registers of the LFSR */
    uint32_t fR1[16];
    /**< register of F */
    uint32_t fR2[16];
    /**< register of F */
    uint32_t bX0[16];
    /**< Output X0 of the bit reorganization for 16 packets */
    uint32_t bX1[16];
    /**< Output X1 of the bit reorganization for 16 packets */
    uint32_t bX2[16];
    /**< Output X2 of the bit reorganization for 16 packets */
    uint32_t bX3[16];
    /**< Output X3 of the bit reorganization for 16 packets */
} ZucState16_t;

/**
 *****************************************************************************
 * @description
 *      Structure to store pointers to the 16 keys to be used as input to
 *      @ref asm_ZucInitialization_16 and @ref asm_ZucGenKeystream64B_16
 *****************************************************************************/
typedef struct zuc_key_16_s {
    const uint8_t *pKeys[16];
    /**< Array of pointers to 128-bit keys for the 16 packets */
} ZucKey16_t;

/**
 *****************************************************************************
 * @description
 *      Structure to store pointers to the 16 IV's to be used as input to
 *      @ref asm_ZucInitialization_16 and @ref asm_ZucGenKeystream64B_16
 *****************************************************************************/
typedef struct zuc_iv_16_s {
    const uint8_t *pIvs[16];
    /**< Array of pointers to 128-bit IV's for the 16 packets */
} ZucIv16_t;

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the initialization
 *      stage of the ZUC algorithm. The function will initialize the state
 *      for a single packet operation.
 *
 * @param[in] pKey                  Pointer to the 128-bit initial key that
 *                                  will be used when initializing the ZUC
 *                                  state.
 * @param[in] pIv                   Pointer to the 128-bit initial vector that
 *                                  will be used when initializing the ZUC
 *                                  state.
 * @param[in,out] pState            Pointer to a ZUC state structure of type
 *                                  @ref ZucState_t that will be populated
 *                                  with the initialized ZUC state.
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucInitialization_sse(const void *pKey,
                                             const void *pIv,
                                             ZucState_t *pState);

IMB_DLL_LOCAL void asm_ZucInitialization_sse_no_aesni(const void *pKey,
                                                      const void *pIv,
                                                      ZucState_t *pState);

IMB_DLL_LOCAL void asm_ZucInitialization_avx(const void *pKey,
                                             const void *pIv,
                                             ZucState_t *pState);

/**
 ******************************************************************************
 * @description
 *      Definition of the external function that implements the initialization
 *      stage of the ZUC algorithm for 4 packets. The function will initialize
 *      the state for 4 individual packets.
 *
 * @param[in] pKey                  Pointer to an array of 128-bit initial keys
 *                                  that will be used when initializing the ZUC
 *                                  state.
 * @param[in] pIv                   Pointer to an array of 128-bit initial
 *                                  vectors that will be used when initializing
 *                                  the ZUC state.
 * @param[in,out] pState            Pointer to a ZUC state structure of type
 *                                  @ref ZucState4_t that will be populated
 *                                  with the initialized ZUC state.
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucInitialization_4_sse(ZucKey4_t *pKeys,
                                               ZucIv4_t *pIvs,
                                               ZucState4_t *pState);

IMB_DLL_LOCAL void asm_ZucInitialization_4_sse_no_aesni(ZucKey4_t *pKeys,
                                                        ZucIv4_t *pIvs,
                                                        ZucState4_t *pState);

IMB_DLL_LOCAL void asm_ZucInitialization_4_avx(ZucKey4_t *pKeys,
                                               ZucIv4_t *pIvs,
                                               ZucState4_t *pState);

/**
 ******************************************************************************
 * @description
 *      Definition of the external function that implements the initialization
 *      stage of the ZUC algorithm for 8 packets. The function will initialize
 *      the state for 8 individual packets.
 *
 * @param[in] pKey                  Pointer to an array of 128-bit initial keys
 *                                  that will be used when initializing the ZUC
 *                                  state.
 * @param[in] pIv                   Pointer to an array of 128-bit initial
 *                                  vectors that will be used when initializing
 *                                  the ZUC state.
 * @param[in,out] pState            Pointer to a ZUC state structure of type
 *                                  @ref ZucState8_t that will be populated
 *                                  with the initialized ZUC state.
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucInitialization_8_avx2(ZucKey8_t *pKeys,
                                                ZucIv8_t *pIvs,
                                                ZucState8_t *pState);

/**
 ******************************************************************************
 * @description
 *      Definition of the external function that implements the initialization
 *      stage of the ZUC algorithm for 16 packets. The function will initialize
 *      the state for 16 individual packets.
 *
 * @param[in] pKey                  Pointer to an array of 128-bit initial keys
 *                                  that will be used when initializing the ZUC
 *                                  state.
 * @param[in] pIv                   Pointer to an array of 128-bit initial
 *                                  vectors that will be used when initializing
 *                                  the ZUC state.
 * @param[in,out] pState            Pointer to a ZUC state structure of type
 *                                  @ref ZucState16_t that will be populated
 *                                  with the initialized ZUC state.
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucInitialization_16_avx512(ZucKey16_t *pKeys,
                                                   ZucIv16_t *pIvs,
                                                   ZucState16_t *pState);

IMB_DLL_LOCAL void asm_ZucInitialization_16_gfni_avx512(ZucKey16_t *pKeys,
                                                        ZucIv16_t *pIvs,
                                                        ZucState16_t *pState);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 64 bytes of
 *      keystream.
 *
 * @param[in,out] pKeystream        Pointer to an input buffer that will
 *                                  contain the generated keystream.

 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState_t
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucGenKeystream64B_sse(uint32_t *pKeystream,
                                              ZucState_t *pState);

IMB_DLL_LOCAL void asm_ZucGenKeystream64B_sse_no_aesni(uint32_t *pKeystream,
                                                       ZucState_t *pState);

IMB_DLL_LOCAL void asm_ZucGenKeystream64B_avx(uint32_t *pKeystream,
                                              ZucState_t *pState);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 8 bytes of
 *      keystream.
 *
 * @param[in,out] pKeystream        Pointer to an input buffer that will
 *                                  contain the generated keystream.

 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState_t
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucGenKeystream8B_sse(void *pKeystream,
                                             ZucState_t *pState);

IMB_DLL_LOCAL void asm_ZucGenKeystream8B_sse_no_aesni(void *pKeystream,
                                                      ZucState_t *pState);

IMB_DLL_LOCAL void asm_ZucGenKeystream8B_avx(void *pKeystream,
                                             ZucState_t *pState);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate N*4 bytes of
 *      keystream, being N the number of rounds specified
 *      in the numRounds parameter (from 1 to 16 rounds,
 *      equal to from 4 to 64 bytes)
 *
 * @param[in,out] pKeystream        Pointer to an input buffer that will
 *                                  contain the generated keystream.

 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState_t
 *
 * @param[in] numRounds             Number of 4-byte rounds (1 to 16 rounds)
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucGenKeystream_sse(void *pKeystream,
                                           ZucState_t *pState,
                                           uint64_t numRounds);

IMB_DLL_LOCAL void asm_ZucGenKeystream_sse_no_aesni(void *pKeystream,
                                                    ZucState_t *pState,
                                                    uint64_t numRounds);

IMB_DLL_LOCAL void asm_ZucGenKeystream_avx(void *pKeystream,
                                           ZucState_t *pState,
                                           uint64_t numRounds);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 64 bytes of
 *      keystream for four packets in parallel.
 *
 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState4_t
 *
 * @param[in,out] pKeyStr1          Pointer to an input buffer that will
 *                                  contain the generated keystream for packet
 *                                  one.
 * @param[in,out] pKeyStr2          Pointer to an input buffer that will
 *                                  contain the generated keystream for packet
 *                                  two.
 * @param[in,out] pKeyStr3          Pointer to an input buffer that will
 *                                  contain the generated keystream for packet
 *                                  three.
 * @param[in,out] pKeyStr4          Pointer to an input buffer that will
 *                                  contain the generated keystream for packet
 *                                  four.
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization_4 to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucGenKeystream64B_4_sse(ZucState4_t *pState,
                                                uint32_t *pKeyStr1,
                                                uint32_t *pKeyStr2,
                                                uint32_t *pKeyStr3,
                                                uint32_t *pKeyStr4);

IMB_DLL_LOCAL void asm_ZucGenKeystream64B_4_sse_no_aesni(ZucState4_t *pState,
                                                         uint32_t *pKeyStr1,
                                                         uint32_t *pKeyStr2,
                                                         uint32_t *pKeyStr3,
                                                         uint32_t *pKeyStr4);

IMB_DLL_LOCAL void asm_ZucGenKeystream64B_4_avx(ZucState4_t *pState,
                                                uint32_t *pKeyStr1,
                                                uint32_t *pKeyStr2,
                                                uint32_t *pKeyStr3,
                                                uint32_t *pKeyStr4);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 64 bytes of
 *      keystream for eight packets in parallel.
 *
 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState8_t
 *
 * @param[in,out] pKeyStr           Array of pointers to 8 input buffers that
 *                                  will contain the generated keystream for
 *                                  these 8 packets.
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization_8 to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucGenKeystream64B_8_avx2(ZucState8_t *pState,
                                                 uint32_t *pKeyStr[8]);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 64 bytes of
 *      keystream for four packets in parallel.
 *
 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState16_t
 *
 * @param[in,out] pKeyStr           Array of pointers to 16 input buffers
 *                                  that will contain the generated keystream
 *                                  for these 16 packets.
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization_4 to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucGenKeystream64B_16_avx512(ZucState16_t *pState,
                                                    uint32_t *pKeyStr[16]);

IMB_DLL_LOCAL void asm_ZucGenKeystream64B_16_gfni_avx512(ZucState16_t *pState,
                                                         uint32_t *pKeyStr[16]);
/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 8 bytes of
 *      keystream for four packets in parallel.
 *
 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState4_t
 *
 * @param[in,out] pKeyStr1          Pointer to an input buffer that will
 *                                  contain the generated keystream for packet
 *                                  one.
 * @param[in,out] pKeyStr2          Pointer to an input buffer that will
 *                                  contain the generated keystream for packet
 *                                  two.
 * @param[in,out] pKeyStr3          Pointer to an input buffer that will
 *                                  contain the generated keystream for packet
 *                                  three.
 * @param[in,out] pKeyStr4          Pointer to an input buffer that will
 *                                  contain the generated keystream for packet
 *                                  four.
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization_4 to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucGenKeystream8B_4_sse(ZucState4_t *pState,
                                               uint32_t *pKeyStr1,
                                               uint32_t *pKeyStr2,
                                               uint32_t *pKeyStr3,
                                               uint32_t *pKeyStr4);

IMB_DLL_LOCAL void asm_ZucGenKeystream8B_4_sse_no_aesni(ZucState4_t *pState,
                                                        uint32_t *pKeyStr1,
                                                        uint32_t *pKeyStr2,
                                                        uint32_t *pKeyStr3,
                                                        uint32_t *pKeyStr4);

IMB_DLL_LOCAL void asm_ZucGenKeystream8B_4_avx(ZucState4_t *pState,
                                               uint32_t *pKeyStr1,
                                               uint32_t *pKeyStr2,
                                               uint32_t *pKeyStr3,
                                               uint32_t *pKeyStr4);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 8 bytes of
 *      keystream for eight packets in parallel.
 *
 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState8_t
 *
 * @param[in,out] pKeyStr           Array of pointers to 8 input buffers that
 *                                  will contain the generated keystream for
 *                                  these 8 packets.
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization_8 to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucGenKeystream8B_8_avx2(ZucState8_t *pState,
                                                uint32_t *pKeyStr[8]);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 8 bytes of
 *      keystream for sixteen packets in parallel.
 *
 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState16_t
 *
 * @param[in,out] pKeyStr           Array of pointers to 16 input buffers
 *                                  that will contain the generated keystream
 *                                  for these 16 packets.
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization_16 to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucGenKeystream8B_16_avx512(ZucState16_t *pState,
                                                   uint32_t *pKeyStr[16]);

IMB_DLL_LOCAL void asm_ZucGenKeystream8B_16_gfni_avx512(ZucState16_t *pState,
                                                        uint32_t *pKeyStr[16]);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 64 bytes of
 *      keystream for four packets in parallel and will XOR this keystream
 *      with the input text, producing 64 bytes of output for all four packets.
 *
 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState4_t
 *
 * @param[in,out] pKeyStr           Array of pointers to buffers that will
 *                                  contain the generated keystreams for all
 *                                  4 packets.
 * @param[in] pIn                   Array of pointers to 4 input buffers.
 * @param[out] pOut                 Array of pointers to 4 output buffers.
 * @param[in] bufOffset             Offset into pIn and pOut
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization_4 to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucCipher64B_4_sse(ZucState4_t *pState,
                                          uint32_t *pKeyStr[4],
                                          const uint64_t *pIn[4],
                                          uint64_t *pOut[4],
                                          uint64_t bufOffset);

IMB_DLL_LOCAL void asm_ZucCipher64B_4_sse_no_aesni(ZucState4_t *pState,
                                                   uint32_t *pKeyStr[4],
                                                   const uint64_t *pIn[4],
                                                   uint64_t *pOut[4],
                                                   uint64_t bufOffset);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 64 bytes of
 *      keystream for four packets in parallel and will XOR this keystream
 *      with the input text, producing 64 bytes of output for all four packets.
 *
 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState4_t
 *
 * @param[in,out] pKeyStr           Array of pointers to buffers that will
 *                                  contain the generated keystreams for all
 *                                  4 packets.
 * @param[in] pIn                   Array of pointers to 4 input buffers.
 * @param[out] pOut                 Array of pointers to 4 output buffers.
 * @param[in] bufOffset             Offset into pIn and pOut
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization_4 to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucCipher64B_4_avx(ZucState4_t *pState,
                                          uint32_t *pKeyStr[4],
                                          const uint64_t *pIn[4],
                                          uint64_t *pOut[4],
                                          uint64_t bufOffset);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 64 bytes of
 *      keystream for eight packets in parallel and will XOR this keystream
 *      with the input text, producing 64 bytes of output for all eight packets.
 *
 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState8_t
 *
 * @param[in,out] pKeyStr           Array of pointers to buffers that will
 *                                  contain the generated keystreams for all
 *                                  8 packets.
 * @param[in] pIn                   Array of pointers to 8 input buffers.
 * @param[out] pOut                 Array of pointers to 8 output buffers.
 * @param[in] bufOffset             Offset into pIn and pOut
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization_8 to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucCipher64B_8_avx2(ZucState8_t *pState,
                                           uint32_t *pKeyStr[8],
                                           const uint64_t *pIn[8],
                                           uint64_t *pOut[8],
                                           uint64_t bufOffset);

/**
 ******************************************************************************
 *
 * @description
 *      Definition of the external function that implements the working
 *      stage of the ZUC algorithm. The function will generate 64 bytes of
 *      keystream for sixteen packets in parallel and will XOR this keystream
 *      with the input text, producing 64 bytes of output for all 16 packets.
 *
 * @param[in] pState                Pointer to a ZUC state structure of type
 *                                  @ref ZucState16_t
 * @param[in] pIn                   Array of pointers to 16 input buffers.
 * @param[out] pOut                 Array of pointers to 16 output buffers.
 * @param[in] bufOffset             Offset into pIn and pOut
 *
 * @pre
 *      A successful call to @ref asm_ZucInitialization_16 to initialize the ZUC
 *      state.
 *
 *****************************************************************************/
IMB_DLL_LOCAL void asm_ZucCipher64B_16_avx512(ZucState16_t *pState,
                                              const uint64_t *pIn[16],
                                              uint64_t *pOut[16],
                                              uint64_t bufOffset);

IMB_DLL_LOCAL void asm_ZucCipher64B_16_gfni_avx512(ZucState16_t *pState,
                                                   const uint64_t *pIn[16],
                                                   uint64_t *pOut[16],
                                                   uint64_t bufOffset);

/**
 ******************************************************************************
 * @description
 *      Definition of the external function to update the authentication tag
 *      based on keystream and data (SSE varient)
 *
 * @param[in] T                     Authentication tag
 *
 * @param[in] ks                    Pointer to key stream
 *
 * @param[in] data                  Pointer to the data
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL uint32_t asm_Eia3Round64BSSE(uint32_t T, const void *ks,
                                           const void *data);

/**
 ******************************************************************************
 * @description
 *      Definition of the external function to return the authentication
 *      update value to be XOR'ed with current authentication tag (SSE variant)
 *
 * @param[in] ks                    Pointer to key stream
 *
 * @param[in] data                  Pointer to the data
 *
 * @param[in] n_words               Number of data bits to be processed
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL uint32_t asm_Eia3RemainderSSE(const void *ks, const void *data,
                                            const uint64_t n_words);

/**
 ******************************************************************************
 * @description
 *      Definition of the external function to update the authentication tag
 *      based on keystream and data (AVX variant)
 *
 * @param[in] T                     Authentication tag
 *
 * @param[in] ks                    Pointer to key stream
 *
 * @param[in] data                  Pointer to the data
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL uint32_t asm_Eia3Round64BAVX(uint32_t T, const void *ks,
                                           const void *data);

/**
 ******************************************************************************
 * @description
 *      Definition of the external function to return the authentication
 *      update value to be XOR'ed with current authentication tag (AVX variant)
 *
 * @param[in] ks                    Pointer to key stream
 *
 * @param[in] data                  Pointer to the data
 *
 * @param[in] n_words               Number of data bits to be processed
 *
 * @pre
 *      None
 *
 *****************************************************************************/
IMB_DLL_LOCAL uint32_t asm_Eia3RemainderAVX(const void *ks, const void *data,
                                            const uint64_t n_words);


IMB_DLL_LOCAL
void zuc_eea3_4_buffer_job_sse(const void * const pKey[4],
                               const void * const pIv[4],
                               const void * const pBufferIn[4],
                               void *pBufferOut[4],
                               const uint16_t lengthInBytes[4],
                               const void * const job_in_lane[4]);

IMB_DLL_LOCAL
void zuc_eea3_4_buffer_job_sse_no_aesni(const void * const pKey[4],
                                        const void * const pIv[4],
                                        const void * const pBufferIn[4],
                                        void *pBufferOut[4],
                                        const uint16_t lengthInBytes[4],
                                        const void * const job_in_lane[4]);

IMB_DLL_LOCAL
void zuc_eea3_4_buffer_job_avx(const void * const pKey[4],
                               const void * const pIv[4],
                               const void * const pBufferIn[4],
                               void *pBufferOut[4],
                               const uint16_t lengthInBytes[4],
                               const void * const job_in_lane[4]);

IMB_DLL_LOCAL
void zuc_eea3_8_buffer_job_avx2(const void * const pKey[8],
                                const void * const pIv[8],
                                const void * const pBufferIn[8],
                                void *pBufferOut[8],
                                const uint16_t lengthInBytes[8],
                                const void * const job_in_lane[8]);

IMB_DLL_LOCAL
void zuc_eea3_16_buffer_job_no_gfni_avx512(const void * const pKey[16],
                                           const void * const pIv[16],
                                           const void * const pBufferIn[16],
                                           void *pBufferOut[16],
                                           const uint16_t lengthInBytes[16],
                                           const void * const job_in_lane[16]);

IMB_DLL_LOCAL
void zuc_eea3_16_buffer_job_gfni_avx512(const void * const pKey[16],
                                        const void * const pIv[16],
                                        const void * const pBufferIn[16],
                                        void *pBufferOut[16],
                                        const uint16_t lengthInBytes[16],
                                        const void * const job_in_lane[16]);

IMB_DLL_LOCAL
void zuc_eia3_4_buffer_job_sse(const void * const pKey[4],
                               const void * const pIv[4],
                               const void * const pBufferIn[4],
                               uint32_t *pMacI[4],
                               const uint16_t lengthInBits[4],
                               const void * const job_in_lane[4]);

IMB_DLL_LOCAL
void zuc_eia3_4_buffer_job_sse_no_aesni(const void * const pKey[4],
                                        const void * const pIv[4],
                                        const void * const pBufferIn[4],
                                        uint32_t *pMacI[4],
                                        const uint16_t lengthInBits[4],
                                        const void * const job_in_lane[4]);

IMB_DLL_LOCAL
void zuc_eia3_4_buffer_job_avx(const void * const pKey[4],
                               const void * const pIv[4],
                               const void * const pBufferIn[4],
                               uint32_t *pMacI[4],
                               const uint16_t lengthInBits[4],
                               const void * const job_in_lane[4]);

IMB_DLL_LOCAL
void zuc_eia3_8_buffer_job_avx2(const void * const pKey[8],
                                const void * const pIv[8],
                                const void * const pBufferIn[8],
                                uint32_t *pMacI[8],
                                const uint16_t lengthInBits[8],
                                const void * const job_in_lane[8]);

IMB_DLL_LOCAL
void zuc_eia3_16_buffer_job_no_gfni_avx512(const void * const pKey[16],
                                           const void * const pIv[16],
                                           const void * const pBufferIn[16],
                                           uint32_t *pMacI[16],
                                           const uint16_t lengthInBits[16],
                                           const void * const job_in_lane[16]);

IMB_DLL_LOCAL
void zuc_eia3_16_buffer_job_gfni_avx512(const void * const pKey[16],
                                        const void * const pIv[16],
                                        const void * const pBufferIn[16],
                                        uint32_t *pMacI[16],
                                        const uint16_t lengthInBits[16],
                                        const void * const job_in_lane[16]);

/* the s-boxes */
extern const uint8_t S0[256];
extern const uint8_t S1[256];

void zuc_eea3_1_buffer_sse(const void *pKey, const void *pIv,
                           const void *pBufferIn, void *pBufferOut,
                           const uint32_t lengthInBytes);

void zuc_eea3_4_buffer_sse(const void * const pKey[4],
                           const void * const pIv[4],
                           const void * const pBufferIn[4],
                           void *pBufferOut[4],
                           const uint32_t lengthInBytes[4]);

void zuc_eea3_n_buffer_sse(const void * const pKey[], const void * const pIv[],
                           const void * const pBufferIn[], void *pBufferOut[],
                           const uint32_t lengthInBytes[],
                           const uint32_t numBuffers);

void zuc_eia3_1_buffer_sse(const void *pKey, const void *pIv,
                           const void *pBufferIn, const uint32_t lengthInBits,
                           uint32_t *pMacI);

void zuc_eia3_n_buffer_sse(const void * const pKey[],
                           const void * const pIv[],
                           const void * const pBufferIn[],
                           const uint32_t lengthInBits[],
                           uint32_t *pMacI[],
                           const uint32_t numBuffers);

void zuc_eea3_1_buffer_sse_no_aesni(const void *pKey, const void *pIv,
                                    const void *pBufferIn, void *pBufferOut,
                                    const uint32_t lengthInBytes);

void zuc_eea3_4_buffer_sse_no_aesni(const void * const pKey[4],
                                    const void * const pIv[4],
                                    const void * const pBufferIn[4],
                                    void *pBufferOut[4],
                                    const uint32_t lengthInBytes[4]);

void zuc_eea3_n_buffer_sse_no_aesni(const void * const pKey[],
                                    const void * const pIv[],
                                    const void * const pBufferIn[],
                                    void *pBufferOut[],
                                    const uint32_t lengthInBytes[],
                                    const uint32_t numBuffers);

void zuc_eia3_1_buffer_sse_no_aesni(const void *pKey, const void *pIv,
                                    const void *pBufferIn,
                                    const uint32_t lengthInBits,
                                    uint32_t *pMacI);

void zuc_eia3_n_buffer_sse_no_aesni(const void * const pKey[],
                                    const void * const pIv[],
                                    const void * const pBufferIn[],
                                    const uint32_t lengthInBits[],
                                    uint32_t *pMacI[],
                                    const uint32_t numBuffers);

void zuc_eea3_1_buffer_avx(const void *pKey, const void *pIv,
                           const void *pBufferIn, void *pBufferOut,
                           const uint32_t lengthInBytes);

void zuc_eea3_4_buffer_avx(const void * const pKey[4],
                           const void * const pIv[4],
                           const void * const pBufferIn[4],
                           void *pBufferOut[4],
                           const uint32_t lengthInBytes[4]);

void zuc_eea3_n_buffer_avx(const void * const pKey[], const void * const pIv[],
                           const void * const pBufferIn[], void *pBufferOut[],
                           const uint32_t lengthInBytes[],
                           const uint32_t numBuffers);

void zuc_eia3_1_buffer_avx(const void *pKey, const void *pIv,
                           const void *pBufferIn, const uint32_t lengthInBits,
                           uint32_t *pMacI);

void zuc_eia3_n_buffer_avx(const void * const pKey[],
                           const void * const pIv[],
                           const void * const pBufferIn[],
                           const uint32_t lengthInBits[],
                           uint32_t *pMacI[],
                           const uint32_t numBuffers);


void zuc_eea3_1_buffer_avx2(const void *pKey, const void *pIv,
                            const void *pBufferIn, void *pBufferOut,
                            const uint32_t lengthInBytes);

void zuc_eea3_n_buffer_avx2(const void * const pKey[], const void * const pIv[],
                            const void * const pBufferIn[], void *pBufferOut[],
                            const uint32_t lengthInBytes[],
                            const uint32_t numBuffers);

void zuc_eia3_1_buffer_avx2(const void *pKey, const void *pIv,
                            const void *pBufferIn, const uint32_t lengthInBits,
                            uint32_t *pMacI);

void zuc_eia3_n_buffer_avx2(const void * const pKey[],
                            const void * const pIv[],
                            const void * const pBufferIn[],
                            const uint32_t lengthInBits[],
                            uint32_t *pMacI[],
                            const uint32_t numBuffers);

void zuc_eea3_1_buffer_avx512(const void *pKey, const void *pIv,
                              const void *pBufferIn, void *pBufferOut,
                              const uint32_t lengthInBytes);

void zuc_eea3_n_buffer_avx512(const void * const pKey[],
                              const void * const pIv[],
                              const void * const pBufferIn[],
                              void *pBufferOut[],
                              const uint32_t lengthInBytes[],
                              const uint32_t numBuffers);

void zuc_eea3_n_buffer_gfni_avx512(const void * const pKey[],
                                   const void * const pIv[],
                                   const void * const pBufferIn[],
                                   void *pBufferOut[],
                                   const uint32_t lengthInBytes[],
                                   const uint32_t numBuffers);

void zuc_eia3_1_buffer_avx512(const void *pKey, const void *pIv,
                              const void *pBufferIn,
                              const uint32_t lengthInBits,
                              uint32_t *pMacI);

void zuc_eia3_n_buffer_avx512(const void * const pKey[],
                              const void * const pIv[],
                              const void * const pBufferIn[],
                              const uint32_t lengthInBits[],
                              uint32_t *pMacI[],
                              const uint32_t numBuffers);

void zuc_eia3_n_buffer_gfni_avx512(const void * const pKey[],
                                   const void * const pIv[],
                                   const void * const pBufferIn[],
                                   const uint32_t lengthInBits[],
                                   uint32_t *pMacI[],
                                   const uint32_t numBuffers);

/* Internal API */
IMB_DLL_LOCAL
void _zuc_eea3_4_buffer_avx(const void * const pKey[4],
                            const void * const pIv[4],
                            const void * const pBufferIn[4],
                            void *pBufferOut[4],
                            const uint32_t length[4]);

IMB_DLL_LOCAL
void _zuc_eia3_4_buffer_avx(const void * const pKey[4],
                            const void * const pIv[4],
                            const void * const pBufferIn[4],
                            const uint32_t lengthInBits[4],
                            uint32_t *pMacI[4]);

IMB_DLL_LOCAL
void _zuc_eea3_8_buffer_avx2(const void * const pKey[8],
                             const void * const pIv[8],
                             const void * const pBufferIn[8],
                             void *pBufferOut[8],
                             const uint32_t length[8]);

IMB_DLL_LOCAL
void _zuc_eia3_8_buffer_avx2(const void * const pKey[8],
                             const void * const pIv[8],
                             const void * const pBufferIn[8],
                             const uint32_t lengthInBits[8],
                             uint32_t *pMacI[8]);

#endif /* ZUC_INTERNAL_H_ */

