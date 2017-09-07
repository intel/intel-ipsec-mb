/*
 * Copyright (c) 2017, Intel Corporation
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef DES_X16_AVX512_H
#define DES_X16_AVX512_H

#include <stdint.h>
#include "asm_types.h"
#include "mb_mgr.h"

/**
 * @brief DES CBC dencryption
 *
 * @param data DES operation arguments for 16 lanes
 * @param data_length number of bytes to process on all lanes.
 *        It has to be multiple of block size.
 */
void des_x16_cbc_dec_avx512(DES_ARGS_x16* data, const uint32_t data_length);

/**
 * @brief DES CBC encryption
 *
 * @param data DES operation arguments for 16 lanes
 * @param data_length number of bytes to process on all lanes.
 *        It has to be multiple of block size.
 */
void des_x16_cbc_enc_avx512(DES_ARGS_x16* data, const uint32_t data_length);

/**
 * @brief DOCSIS DES dencryption
 *
 * @param data DES operation arguments for 16 lanes
 * @param data_length number of bytes to process on all lanes.
 *        It has to be multiple of block size. Partials are tracked seprately.
 */
void docsis_des_x16_dec_avx512(DES_ARGS_x16* data, const uint32_t data_length);

/**
 * @brief DOCSIS DES encryption
 *
 * @param data DES operation arguments for 16 lanes
 * @param data_length number of bytes to process on all lanes.
 *        It has to be multiple of block size. Partials are tracked seprately.
 */
void docsis_des_x16_enc_avx512(DES_ARGS_x16* data, const uint32_t data_length);

#endif /* DES_X16_AVX512_H */
