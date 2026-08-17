;;
;; Copyright (c) 2022-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%ifndef _GCM_COMMON_INC_
%define _GCM_COMMON_INC_

%include "include/reg_sizes.inc"

;; ***
;; *** SSE and AVX
;; ***

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; READ_SMALL_DATA_INPUT: Packs xmm register with data when data input is less than 16 bytes.
; Returns 0 if data has length 0.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro READ_SMALL_DATA_INPUT 5
%define %%OUTPUT                %1 ; [out] xmm register
%define %%INPUT                 %2 ; [in] gp with input address
%define %%LENGTH                %3 ; [in] gp with data length (0 to 16 bytes)
%define %%TMP1                  %4 ; [clobbered] temporary gp register
%define %%ARCH                  %5 ; [in] "SSE" or "AVX"

        mov             DWORD(%%TMP1), 16
        cmp             %%LENGTH, %%TMP1
        cmovb           %%TMP1, %%LENGTH

%ifidn %%ARCH, SSE
        simd_load_sse_16        %%OUTPUT, %%INPUT, %%TMP1
%else
        simd_load_avx_16        %%OUTPUT, %%INPUT, %%TMP1
%endif

%endmacro ; READ_SMALL_DATA_INPUT

%macro READ_SMALL_DATA_INPUT_SSE 4
        READ_SMALL_DATA_INPUT %1, %2, %3, %4, SSE
%endmacro ; READ_SMALL_DATA_INPUT_SSE

%macro READ_SMALL_DATA_INPUT_AVX 4
        READ_SMALL_DATA_INPUT %1, %2, %3, %4, AVX
%endmacro ; READ_SMALL_DATA_INPUT_AVX

;; ***
;; *** AVX512 and VAES AVX512
;; ***

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; READ_SMALL_DATA_INPUT: Packs xmm register with data when data input is less than 16 bytes.
; Returns 0 if data has length 0.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro READ_SMALL_DATA_INPUT_AVX512 5
%define %%OUTPUT        %1 ; [out] xmm register
%define %%INPUT         %2 ; [in] buffer pointer to read from
%define %%LENGTH        %3 ; [in] number of bytes to read (0 to 16 bytes)
%define %%TMP1          %4 ; [clobbered]
%define %%MASK          %5 ; [out] k1 to k7 register to store the partial block mask

        lea             %%TMP1, [rel byte_len_to_mask_table]
%ifidn __OUTPUT_FORMAT__, win64
        add             %%TMP1, %%LENGTH
        add             %%TMP1, %%LENGTH
        kmovw           %%MASK, [%%TMP1]
%else
        kmovw           %%MASK, [%%TMP1 + %%LENGTH*2]
%endif
        vmovdqu8        XWORD(%%OUTPUT){%%MASK}{z}, [%%INPUT]

%endmacro ; READ_SMALL_DATA_INPUT_AVX512

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; READ_SMALL_DATA_INPUT
;;; - accepts input length bigger than 16 (one can pass plain/cipher text length directly)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro READ_SMALL_DATA_INPUT_LEN_BT16_AVX512 6
%define %%OUTPUT        %1 ; [out] xmm register
%define %%INPUT         %2 ; [in] buffer pointer to read from
%define %%LENGTH        %3 ; [in] number of bytes to read (any length accepted)
%define %%TMP1          %4 ; [clobbered]
%define %%TMP2          %5 ; [clobbered]
%define %%MASK          %6 ; [out] k1 to k7 register to store the partial block mask

        mov             DWORD(%%TMP2), 16
        cmp             %%LENGTH, %%TMP2
        cmovb           %%TMP2, %%LENGTH
        READ_SMALL_DATA_INPUT_AVX512 %%OUTPUT, %%INPUT, %%TMP2, %%TMP1, %%MASK
%endmacro ; READ_SMALL_DATA_INPUT_LEN_BT16_AVX512

%endif ; end ifndef _GCM_COMMON_INC_
