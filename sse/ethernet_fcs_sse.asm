;;
;; Copyright (c) 2019-2020, Intel Corporation
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

%include "include/os.asm"
%include "include/memcpy.asm"

%ifdef LINUX
%define arg1	rdi
%define arg2	rsi
%define arg3	rdx
%define arg4	rcx
%else
%define arg1	rcx
%define arg2	rdx
%define arg3	r8
%define arg4	r9
%endif

%define tmp arg4
section .data
default rel

;;; Precomputed constants for CRC32 (Ethernet FCS)
;;;   Details of the CRC algorithm and 4 byte buffer of
;;;   {0x01, 0x02, 0x03, 0x04}:
;;;     Result     Poly       Init        RefIn  RefOut  XorOut
;;;     0xB63CFBCD 0x04C11DB7 0xFFFFFFFF  true   true    0xFFFFFFFF
align 16
rk1:
        dq 0x00000000ccaa009e, 0x00000001751997d0

align 16
rk5:
        dq 0x00000000ccaa009e, 0x0000000163cd6124

align 16
rk7:
        dq 0x00000001f7011640, 0x00000001db710640

align 16
pshufb_shf_table:
        ;;  use these values for shift registers with the pshufb instruction
        dq 0x8786858483828100, 0x8f8e8d8c8b8a8988
        dq 0x0706050403020100, 0x000e0d0c0b0a0908

align 16
init_crc_value:
        dq 0x00000000FFFFFFFF, 0x0000000000000000

align 16
mask:
        dq 0xFFFFFFFFFFFFFFFF, 0x0000000000000000

align 16
mask2:
        dq 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF
align 16
mask3:
        dq 0x8080808080808080, 0x8080808080808080

section .text

;;; ============================================================================
;;; CRC32 calculation on 16 byte data
;;;
%macro CRC_UPDATE16 6
%define %%INP           %1  ; [in/out] GP with input text pointer or "no_load"
%define %%XCRC_IN_OUT   %2  ; [in/out] XMM with CRC (can be anything if "no_crc" below)
%define %%XCRC_MUL      %3  ; [in] XMM with CRC multiplier constant
%define %%TXMM1         %4  ; [clobbered|in] XMM temporary or data in (no_load)
%define %%TXMM2         %5  ; [clobbered] XMM temporary
%define %%CRC_TYPE      %6  ; [in] "first_crc" or "next_crc" or "no_crc"

        ;; load data and increment in pointer
%ifnidn %%INP, no_load
        movdqu          %%TXMM1, [%%INP]
        add             %%INP,  16
%endif

        ;; CRC calculation
%ifidn %%CRC_TYPE, next_crc
        movdqa          %%TXMM2, %%XCRC_IN_OUT
        pclmulqdq       %%TXMM2, %%XCRC_MUL, 0x01
        pclmulqdq       %%XCRC_IN_OUT, %%XCRC_MUL, 0x10
        pxor            %%XCRC_IN_OUT, %%TXMM1
        pxor            %%XCRC_IN_OUT, %%TXMM2
%endif
%ifidn %%CRC_TYPE, first_crc
        ;; in the first run just XOR initial CRC with the first block
        pxor            %%XCRC_IN_OUT, %%TXMM1
%endif

%endmacro

;; =============================================================================
;; Barrett reduction from 128-bits to 32-bits modulo Ethernet FCS polynomial

%macro CRC32_REDUCE_128_TO_32 6
%define %%CRC   %1         ; [out] GP to store 32-bit Ethernet FCS value
%define %%XCRC  %2         ; [in/clobbered] XMM with CRC
%define %%XT1   %3         ; [clobbered] temporary xmm register
%define %%XT2   %4         ; [clobbered] temporary xmm register
%define %%XT3   %5         ; [clobbered] temporary xmm register
%define %%FOLD  %6         ; skip fold for less than 4 bytes - values "fold" or "no_fold"

%define %%XCRCKEY %%XT3

%ifidn %%FOLD, fold
        ;;  compute CRC of a 128-bit value
        movdqa          %%XCRCKEY, [rel rk5]

        ;; 64b fold
        movdqa          %%XT1, %%XCRC
        pclmulqdq       %%XT1, %%XCRCKEY, 0x00
        psrldq          %%XCRC, 8
        pxor            %%XCRC, %%XT1

        ;; 32b fold
        movdqa          %%XT1, %%XCRC
        pslldq          %%XT1, 4
        pclmulqdq       %%XT1, %%XCRCKEY, 0x10
        pxor            %%XCRC, %%XT1
%endif

%%_crc_barrett:
        ;; Barrett reduction
        pand            %%XCRC, [rel mask2]
        movdqa          %%XT1, %%XCRC
        movdqa          %%XT2, %%XCRC
        movdqa          %%XCRCKEY, [rel rk7]

        pclmulqdq       %%XCRC, %%XCRCKEY, 0x00
        pxor            %%XCRC, %%XT2
        pand            %%XCRC, [rel mask]
        movdqa          %%XT2, %%XCRC
        pclmulqdq       %%XCRC, %%XCRCKEY, 0x10
        pxor            %%XCRC, %%XT2
        pxor            %%XCRC, %%XT1
        pextrd          DWORD(%%CRC), %%XCRC, 2 ; 32-bit CRC value
        not             DWORD(%%CRC)
%endmacro

;;; ============================================================================
;;; ETHERNET FCS CRC
%macro ETHERNET_FCS_CRC 11
%define %%p_in          %1  ; [in] pointer to the buffer (GPR)
%define %%bytes_to_crc  %2  ; [in] number of bytes in the buffer (GPR)
%define %%p_fcs_out     %3  ; [in] pointer to store CRC value - can be NULL (GPR)
%define %%ethernet_fcs  %4  ; [out] GPR to put CRC value into (32 bits)
%define %%tmp           %5  ; [clobbered] temporary GPR
%define %%xtmp1         %6  ; [clobbered] temporary XMM
%define %%xtmp2         %7  ; [clobbered] temporary XMM
%define %%xtmp3         %8  ; [clobbered] temporary XMM
%define %%xcrc          %9  ; [clobbered] temporary XMM
%define %%xcrckey       %10 ; [clobbered] temporary XMM
%define %%xmm0          %11 ; [clobbered] xmm0 XMM register (needs to be)

        ;; load initial CRC value
        movdqa  %%xcrc, [rel init_crc_value]

        ;; load CRC constants
        movdqa  %%xcrckey, [rel rk1] ; rk1 and rk2 in xcrckey

        cmp     %%bytes_to_crc, 32
        jae     %%_at_least_32_bytes

        ;; less than 32 bytes
        cmp	%%bytes_to_crc, 4
	jl	%%_only_less_than_4

        ;; more than 3 bytes
        cmp     %%bytes_to_crc, 16
        je      %%_exact_16_left
        jl      %%_less_than_16_left

        ;; load the plain-text
        movdqu  %%xtmp1, [%%p_in]
        pxor    %%xcrc, %%xtmp1   ; xor the initial crc value
        add     %%p_in, 16
        sub     %%bytes_to_crc, 16
        jmp     %%_crc_two_xmms

%%_exact_16_left:
        movdqu  %%xtmp1, [%%p_in]
        pxor    %%xcrc, %%xtmp1 ; xor the initial CRC value
        jmp     %%_128_done

%%_less_than_16_left:
        simd_load_sse_15_1 %%xtmp1, %%p_in, %%bytes_to_crc
        pxor    %%xcrc, %%xtmp1 ; xor the initial CRC value

        lea     %%tmp, [rel pshufb_shf_table]
        movdqu  %%xtmp1, [%%tmp + %%bytes_to_crc]
        pshufb  %%xcrc, %%xtmp1
        jmp     %%_128_done

%%_at_least_32_bytes:
        CRC_UPDATE16 %%p_in, %%xcrc, %%xcrckey, %%xtmp1, %%xtmp2, first_crc
        sub     %%bytes_to_crc, 16

%%_main_loop:
        cmp     %%bytes_to_crc, 16
        jb      %%_exit_loop
        CRC_UPDATE16 %%p_in, %%xcrc, %%xcrckey, %%xtmp1, %%xtmp2, next_crc
        sub     %%bytes_to_crc, 16
        jz      %%_128_done
        jmp     %%_main_loop

%%_exit_loop:

        ;; Partial bytes left - complete CRC calculation
%%_crc_two_xmms:
        lea             %%tmp, [rel pshufb_shf_table]
        movdqu          %%xtmp2, [%%tmp + %%bytes_to_crc]
        movdqu          %%xtmp1, [%%p_in - 16 + %%bytes_to_crc]  ; xtmp1 = data for CRC
        movdqa          %%xtmp3, %%xcrc
        pshufb          %%xcrc, %%xtmp2  ; top num_bytes with LSB xcrc
        pxor            %%xtmp2, [rel mask3]
        pshufb          %%xtmp3, %%xtmp2 ; bottom (16 - num_bytes) with MSB xcrc

        ;; data num_bytes (top) blended with MSB bytes of CRC (bottom)
        movdqa          %%xmm0, %%xtmp2
        pblendvb        %%xtmp3, %%xtmp1 ; xmm0 implicit

        ;; final CRC calculation
        movdqa          %%xtmp1, %%xcrc
        pclmulqdq       %%xtmp1, %%xcrckey, 0x01
        pclmulqdq       %%xcrc, %%xcrckey, 0x10
        pxor            %%xcrc, %%xtmp3
        pxor            %%xcrc, %%xtmp1

%%_128_done:
        CRC32_REDUCE_128_TO_32 %%ethernet_fcs, %%xcrc, %%xtmp1, %%xtmp2, %%xcrckey, fold
        jmp     %%_crc_done

%%_only_less_than_4:
        simd_load_sse_15_1 %%xtmp1, %%p_in, %%bytes_to_crc
        pxor   %%xcrc, %%xtmp1 ; xor the initial CRC value

        cmp	%%bytes_to_crc, 3
	jl	%%_only_less_than_3

	pslldq	%%xcrc, 5
        CRC32_REDUCE_128_TO_32 %%ethernet_fcs, %%xcrc, %%xtmp1, %%xtmp2, %%xcrckey, no_fold
	jmp	%%_crc_done

%%_only_less_than_3:
	cmp	%%bytes_to_crc, 2
	jl	%%_only_less_than_2

	pslldq	%%xcrc, 6
        CRC32_REDUCE_128_TO_32 %%ethernet_fcs, %%xcrc, %%xtmp1, %%xtmp2, %%xcrckey, no_fold
	jmp	%%_crc_done

%%_only_less_than_2:
	pslldq	%%xcrc, 7
        CRC32_REDUCE_128_TO_32 %%ethernet_fcs, %%xcrc, %%xtmp1, %%xtmp2, %%xcrckey, no_fold

%%_crc_done:
        or              %%p_fcs_out, %%p_fcs_out
        jz              %%_skip_writing_crc
        mov             [%%p_fcs_out], DWORD(%%ethernet_fcs)
%%_skip_writing_crc:
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; arg3 - place to store computed CRC value (can be NULL)
;; Returns CRC value through RAX
align 32
MKGLOBAL(ethernet_fcs_sse,function,internal)
ethernet_fcs_sse:
        ETHERNET_FCS_CRC arg1, arg2, arg3, rax, tmp, xmm1, xmm2, xmm3, xmm4, xmm5, xmm0
	ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
