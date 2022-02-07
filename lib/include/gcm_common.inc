;;
;; Copyright (c) 2022, Intel Corporation
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met:
;;
;;     * Redistributions of source code must retain the above copyright notice,
;;       this list of conditions and the following disclaimer.
;;     * Redistributions in binary form must reproduce the above copyright
;;       notice, this list of conditions and the following disclaimer in the
;;       documentation and/or other materials provided with the distribution.
;;     * Neither the name of Intel Corporation nor the names of its contributors
;;       may be used to endorse or promote products derived from this software
;;       without specific prior written permission.
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
;; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
;; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
;; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;

%ifndef _GCM_COMMON_INC_
%define _GCM_COMMON_INC_

%include "include/reg_sizes.asm"

;; ***
;; *** SSE and AVX
;; ***

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; READ_SMALL_DATA_INPUT: Packs xmm register with data when data input is less than 16 bytes.
; Returns 0 if data has length 0.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro READ_SMALL_DATA_INPUT 7
%define	%%OUTPUT		%1 ; [out] xmm register
%define	%%INPUT			%2 ; [in] gp with input address
%define	%%LENGTH		%3 ; [in] gp with data length (0 to 16 bytes)
%define	%%UNUSED	        %4 ; [unused] gp register
%define	%%COUNTER		%5 ; [clobbered] gp register
%define	%%TMP1			%6 ; [clobbered] gp register
%define %%ARCH                  %7 ; [in] "SSE" or "AVX"

%ifidn %%ARCH, SSE
	pxor	%%OUTPUT, %%OUTPUT
%else
	vpxor	%%OUTPUT, %%OUTPUT
%endif
	mov	%%COUNTER, %%LENGTH
        or      %%COUNTER, %%COUNTER
        jz      %%_done

	xor	%%TMP1, %%TMP1

	cmp	%%COUNTER, 8
	jb	%%_byte_loop_2
%ifidn %%ARCH, SSE
	movq	%%OUTPUT, [%%INPUT]
%else
	vmovq	%%OUTPUT, [%%INPUT]
%endif
	je	%%_done

	sub	%%COUNTER, 8

%%_byte_loop_1:					;Read 1 byte at a time
	shl	%%TMP1, 8			;This loop handles case when 8 bytes were read in
	dec	%%COUNTER
	mov	BYTE(%%TMP1), BYTE [%%INPUT + %%COUNTER + 8]
	jnz	%%_byte_loop_1
%ifidn %%ARCH, SSE
	pinsrq	%%OUTPUT, %%TMP1, 1
%else
	vpinsrq	%%OUTPUT, %%TMP1, 1
%endif
	jmp	%%_done

%%_byte_loop_2:					;Read 1 byte at a time
	shl	%%TMP1, 8			;This loop handles case when no bytes were read in
	dec	%%COUNTER
	mov	BYTE(%%TMP1), BYTE [%%INPUT + %%COUNTER]
	jnz	%%_byte_loop_2
%ifidn %%ARCH, SSE
	movq	%%OUTPUT, %%TMP1
%else
	vmovq	%%OUTPUT, %%TMP1
%endif
%%_done:

%endmacro ; READ_SMALL_DATA_INPUT

%macro READ_SMALL_DATA_INPUT_SSE 6
        READ_SMALL_DATA_INPUT %1, %2, %3, %4, %5, %6, SSE
%endmacro ; READ_SMALL_DATA_INPUT_SSE

%macro READ_SMALL_DATA_INPUT_AVX 6
        READ_SMALL_DATA_INPUT %1, %2, %3, %4, %5, %6, AVX
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
