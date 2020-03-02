;;
;; Copyright (c) 2020, Intel Corporation
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;       Function API:
;       uint32_t ethernet_fcs_avx512(
;                        const void *msg, //buffer pointer to calculate CRC on
;                        uint64_t len, //buffer length in bytes (64-bit data)
;                        const void *tag_ouput // buffer pointer to store CRC
;       );
;
;       Authors:
;               Erdinc Ozturk
;               Vinodh Gopal
;               James Guilford
;
;       Reference paper titled "Fast CRC Computation for Generic Polynomials Using PCLMULQDQ Instruction"
;       URL: http://download.intel.com/design/intarch/papers/323102.pdf
;
;       As explained here:
;       http://docs.oracle.com/javase/7/docs/api/java/util/zip/package-summary.html
;       CRC-32 checksum is described in RFC 1952
;       Implementing RFC 1952 CRC:
;       http://www.ietf.org/rfc/rfc1952.txt

%include "include/os.asm"
%include "include/reg_sizes.asm"
%include "include/clear_regs.asm"

%define	fetch_dist	1024

default rel
section .text


%ifndef LINUX
	%xdefine	arg1 rcx
	%xdefine	arg2 rdx
	%xdefine	arg3 r8
        %xdefine        arg4 r9 ;; not currently used - see note on line 92
%else
	%xdefine	arg1 rdi
	%xdefine	arg2 rsi
	%xdefine	arg3 rdx
        %xdefine        arg4 rcx ;; not currently used
%endif

%define rsp_save        r10
%define msg             arg1
%define len             arg2
%define out             arg3
%define init_crc        arg4
%define init_crc_low32  DWORD(arg4)


%ifndef LINUX
	%define VARIABLE_OFFSET 16*10
%endif

align 16

MKGLOBAL(ethernet_fcs_avx512,function,internal)
ethernet_fcs_avx512:

        ;; Note: Passing initial CRC not currently supported
        ;not		init_crc_low32             ;; uncomment to enabled initial CRC passing
        mov             init_crc_low32, 0xffffffff ;; remove line to enable initial CRC passing

%ifndef LINUX
        mov             rsp_save, rsp
	sub		rsp, VARIABLE_OFFSET
        and             rsp, -16

	; push the xmm registers into the stack to maintain
	vmovdqa		[rsp + 16*0], xmm6
	vmovdqa		[rsp + 16*1], xmm7
	vmovdqa		[rsp + 16*2], xmm8
	vmovdqa		[rsp + 16*3], xmm9
	vmovdqa		[rsp + 16*4], xmm10
	vmovdqa		[rsp + 16*5], xmm11
	vmovdqa		[rsp + 16*6], xmm12
	vmovdqa		[rsp + 16*7], xmm13
	vmovdqa		[rsp + 16*8], xmm14
	vmovdqa		[rsp + 16*9], xmm15
%endif

	; check if smaller than 256B
	cmp		len, 256
	jl		less_than_256

	; load the initial crc value
        vmovd		xmm10, init_crc_low32     ; initial crc

	; receive the initial 64B data, xor the initial crc value
	vmovdqu8	zmm0, [msg+16*0]
	vmovdqu8	zmm4, [msg+16*4]
	vpxorq		zmm0, zmm10
	vbroadcasti32x4	zmm10, [rk3]	;xmm10 has rk3 and rk4
					;imm value of pclmulqdq instruction will determine which constant to use

	sub		len, 256
	cmp		len, 256
	jl		fold_128_B_loop

	vmovdqu8	zmm7, [msg+16*8]
	vmovdqu8	zmm8, [msg+16*12]
	vbroadcasti32x4 zmm16, [rk_1]	;zmm16 has rk-1 and rk-2
	sub		len, 256

fold_256_B_loop:
	add		msg, 256
	vmovdqu8	zmm3, [msg+16*0]
	vpclmulqdq	zmm1, zmm0, zmm16, 0x10
	vpclmulqdq	zmm0, zmm0, zmm16, 0x01
        vpternlogq      zmm0, zmm1, zmm3, 0x96

	vmovdqu8	zmm9, [msg+16*4]
	vpclmulqdq	zmm5, zmm4, zmm16, 0x10
	vpclmulqdq	zmm4, zmm4, zmm16, 0x01
        vpternlogq      zmm4, zmm5, zmm9, 0x96

	vmovdqu8	zmm11, [msg+16*8]
	vpclmulqdq	zmm12, zmm7, zmm16, 0x10
	vpclmulqdq	zmm7, zmm7, zmm16, 0x01
        vpternlogq      zmm7, zmm12, zmm11, 0x96

	vmovdqu8	zmm17, [msg+16*12]
	vpclmulqdq	zmm14, zmm8, zmm16, 0x10
	vpclmulqdq	zmm8, zmm8, zmm16, 0x01
        vpternlogq      zmm8, zmm14, zmm17, 0x96

	sub		len, 256
	jge     	fold_256_B_loop

	;; Fold 256 into 128
	add		msg, 256
	vpclmulqdq	zmm1, zmm0, zmm10, 0x01
	vpclmulqdq	zmm2, zmm0, zmm10, 0x10
	vpternlogq	zmm7, zmm1, zmm2, 0x96	; xor ABC

	vpclmulqdq	zmm5, zmm4, zmm10, 0x01
	vpclmulqdq	zmm6, zmm4, zmm10, 0x10
	vpternlogq	zmm8, zmm5, zmm6, 0x96	; xor ABC

	vmovdqa32	zmm0, zmm7
	vmovdqa32	zmm4, zmm8

	add		len, 128
	jmp		fold_128_B_register



	; at this section of the code, there is 128*x+y (0<=y<128) bytes of buffer. The fold_128_B_loop
	; loop will fold 128B at a time until we have 128+y Bytes of buffer

	; fold 128B at a time. This section of the code folds 8 xmm registers in parallel
fold_128_B_loop:
	add		msg, 128
	vmovdqu8	zmm8, [msg+16*0]
	vpclmulqdq	zmm2, zmm0, zmm10, 0x10
	vpclmulqdq	zmm0, zmm0, zmm10, 0x01
        vpternlogq      zmm0, zmm2, zmm8, 0x96

	vmovdqu8	zmm9, [msg+16*4]
	vpclmulqdq	zmm5, zmm4, zmm10, 0x10
	vpclmulqdq	zmm4, zmm4, zmm10, 0x01
        vpternlogq      zmm4, zmm5, zmm9, 0x96

	sub		len, 128
	jge		fold_128_B_loop
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	add		msg, 128
	; at this point, the buffer pointer is pointing at the last y Bytes of the buffer, where 0 <= y < 128
	; the 128B of folded data is in 2 zmm registers: zmm0 and zmm4

fold_128_B_register:
	; fold the 8 128b parts into 1 xmm register with different constants
	vmovdqu8	zmm16, [rk9]		; multiply by rk9-rk16
	vmovdqu8	zmm11, [rk17]		; multiply by rk17-rk20, rk1,rk2, 0,0
	vpclmulqdq	zmm1, zmm0, zmm16, 0x01
	vpclmulqdq	zmm2, zmm0, zmm16, 0x10
	vextracti64x2	xmm7, zmm4, 3		; save last that has no multiplicand

	vpclmulqdq	zmm5, zmm4, zmm11, 0x01
	vpclmulqdq	zmm6, zmm4, zmm11, 0x10
	vmovdqa		xmm10, [rk1]		; Needed later in reduction loop
	vpternlogq	zmm1, zmm2, zmm5, 0x96	; xor ABC
	vpternlogq	zmm1, zmm6, zmm7, 0x96	; xor ABC

	vshufi64x2      zmm8, zmm1, zmm1, 0x4e ; Swap 1,0,3,2 - 01 00 11 10
	vpxorq          ymm8, ymm8, ymm1
	vextracti64x2   xmm5, ymm8, 1
	vpxorq          xmm7, xmm5, xmm8

	; instead of 128, we add 128-16 to the loop counter to save 1 instruction from the loop
	; instead of a cmp instruction, we use the negative flag with the jl instruction
	add		len, 128-16
	jl		final_reduction_for_128

	; now we have 16+y bytes left to reduce. 16 Bytes is in register xmm7 and the rest is in memory
	; we can fold 16 bytes at a time if y>=16
	; continue folding 16B at a time

reduction_loop_16B:
	vpclmulqdq	xmm8, xmm7, xmm10, 0x1
	vpclmulqdq	xmm7, xmm7, xmm10, 0x10
	vpxor		xmm7, xmm8
	vmovdqu		xmm0, [msg]
	vpxor		xmm7, xmm0
	add		msg, 16
	sub		len, 16
	; instead of a cmp instruction, we utilize the flags with the jge instruction
	; equivalent of: cmp len, 16-16
	; check if there is any more 16B in the buffer to be able to fold
	jge		reduction_loop_16B

	;now we have 16+z bytes left to reduce, where 0<= z < 16.
	;first, we reduce the data in the xmm7 register


final_reduction_for_128:
	add		len, 16
	je		done_128

	; here we are getting data that is less than 16 bytes.
	; since we know that there was data before the pointer, we can offset
	; the input pointer before the actual point, to receive exactly 16 bytes.
	; after that the registers need to be adjusted.
get_last_two_xmms:

	vmovdqa		xmm2, xmm7
	vmovdqu		xmm1, [msg - 16 + len]

	; get rid of the extra data that was loaded before
	; load the shift constant
	lea		rax, [pshufb_shf_table]
	add		rax, len
	vmovdqu		xmm0, [rax]

	vpshufb		xmm7, xmm0
	vpxor		xmm0, [mask3]
	vpshufb		xmm2, xmm0

	vpblendvb	xmm2, xmm2, xmm1, xmm0
	;;;;;;;;;;
	vpclmulqdq	xmm8, xmm7, xmm10, 0x1
	vpclmulqdq	xmm7, xmm7, xmm10, 0x10
        vpternlogq      zmm7, zmm2, zmm8, 0x96

done_128:
	; compute crc of a 128-bit value
	vmovdqa		xmm10, [rk5]
	vmovdqa		xmm0, xmm7

	;64b fold
	vpclmulqdq	xmm7, xmm10, 0
	vpsrldq		xmm0, 8
	vpxor		xmm7, xmm0

	;32b fold
	vmovdqa		xmm0, xmm7
	vpslldq		xmm7, 4
	vpclmulqdq	xmm7, xmm10, 0x10
	vpxor		xmm7, xmm0


	;barrett reduction
barrett:
	vpand		xmm7, [mask2]
	vmovdqa		xmm1, xmm7
	vmovdqa		xmm2, xmm7
	vmovdqa		xmm10, [rk7]

	vpclmulqdq	xmm7, xmm10, 0
        vpternlogq      xmm7, xmm2, [mask], 0x28
	vmovdqa		xmm2, xmm7
	vpclmulqdq	xmm7, xmm10, 0x10
        vpternlogq      zmm7, zmm2, zmm1, 0x96
	vpextrd		eax, xmm7, 2

cleanup:
	not		eax
        or              out, out
        jz              skip_writing_crc
        mov             [out], eax

skip_writing_crc:


%ifndef LINUX
	vmovdqa		xmm6, [rsp + 16*0]
	vmovdqa		xmm7, [rsp + 16*1]
	vmovdqa		xmm8, [rsp + 16*2]
	vmovdqa		xmm9, [rsp + 16*3]
	vmovdqa		xmm10, [rsp + 16*4]
	vmovdqa		xmm11, [rsp + 16*5]
	vmovdqa		xmm12, [rsp + 16*6]
	vmovdqa		xmm13, [rsp + 16*7]
	vmovdqa		xmm14, [rsp + 16*8]
	vmovdqa		xmm15, [rsp + 16*9]

        mov		rsp, rsp_save
%endif
	ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align 16
less_than_256:

	; check if there is enough buffer to be able to fold 16B at a time
	cmp	len, 32
	jl	less_than_32

	; if there is, load the constants
	vmovdqa	xmm10, [rk1]    ; rk1 and rk2 in xmm10

	vmovd	xmm0, init_crc_low32	; get the initial crc value
	vmovdqu	xmm7, [msg]		; load the plaintext
	vpxor	xmm7, xmm0

	; update the buffer pointer
	add	msg, 16

	; update the counter. subtract 32 instead of 16 to save one instruction from the loop
	sub	len, 32

	jmp	reduction_loop_16B


align 16
less_than_32:
	; mov initial crc to the return value. this is necessary for zero-length buffers.
        mov	eax, init_crc_low32
	test	len, len
	je	cleanup

	vmovd	xmm0, init_crc_low32	; get the initial crc value

	cmp	len, 16
	je	exact_16_left
	jl	less_than_16_left

	vmovdqu	xmm7, [msg]		; load the plaintext
	vpxor	xmm7, xmm0		; xor the initial crc value
	add	msg, 16
	sub	len, 16
	vmovdqa	xmm10, [rk1]		; rk1 and rk2 in xmm10
	jmp	get_last_two_xmms

align 16
less_than_16_left:
	; use stack space to load data less than 16 bytes, zero-out the 16B in memory first.

        lea     r11, [rel byte_len_to_mask_table]
        kmovw   k2, [r11 + len*2]
        vmovdqu8 xmm7{k2}{z}, [msg]
	vpxor	xmm7, xmm0	; xor the initial crc value

        cmp	len, 4
	jl	only_less_than_4

	lea	rax,[pshufb_shf_table]
	vmovdqu	xmm0, [rax + len]
	vpshufb	xmm7,xmm0
	jmp	done_128

only_less_than_4:
	cmp	len, 3
	jl	only_less_than_3

	vpslldq	xmm7, 5
	jmp	barrett

only_less_than_3:
	cmp	len, 2
	jl	only_less_than_2

	vpslldq	xmm7, 6
	jmp	barrett

only_less_than_2:
	vpslldq	xmm7, 7
	jmp	barrett

align 16
exact_16_left:
	vmovdqu	xmm7, [msg]
	vpxor	xmm7, xmm0      ; xor the initial crc value
	jmp	done_128


section .data
align 32

%ifndef USE_CONSTS
; precomputed constants
rk_1: dq 0x00000000e95c1271
rk_2: dq 0x00000000ce3371cb
rk1:  dq 0x00000000ccaa009e
rk2:  dq 0x00000001751997d0
rk3:  dq 0x000000014a7fe880
rk4:  dq 0x00000001e88ef372
rk5:  dq 0x00000000ccaa009e
rk6:  dq 0x0000000163cd6124
rk7:  dq 0x00000001f7011640
rk8:  dq 0x00000001db710640
rk9:  dq 0x00000001d7cfc6ac
rk10: dq 0x00000001ea89367e
rk11: dq 0x000000018cb44e58
rk12: dq 0x00000000df068dc2
rk13: dq 0x00000000ae0b5394
rk14: dq 0x00000001c7569e54
rk15: dq 0x00000001c6e41596
rk16: dq 0x0000000154442bd4
rk17: dq 0x0000000174359406
rk18: dq 0x000000003db1ecdc
rk19: dq 0x000000015a546366
rk20: dq 0x00000000f1da05aa

rk_1b: dq 0x00000000ccaa009e
rk_2b: dq 0x00000001751997d0
	dq 0x0000000000000000
	dq 0x0000000000000000
%else
INCLUDE_CONSTS
%endif

pshufb_shf_table:
; use these values for shift constants for the pshufb instruction
; different alignments result in values as shown:
;       dq 0x8887868584838281, 0x008f8e8d8c8b8a89 ; shl 15 (16-1) / shr1
;       dq 0x8988878685848382, 0x01008f8e8d8c8b8a ; shl 14 (16-3) / shr2
;       dq 0x8a89888786858483, 0x0201008f8e8d8c8b ; shl 13 (16-4) / shr3
;       dq 0x8b8a898887868584, 0x030201008f8e8d8c ; shl 12 (16-4) / shr4
;       dq 0x8c8b8a8988878685, 0x04030201008f8e8d ; shl 11 (16-5) / shr5
;       dq 0x8d8c8b8a89888786, 0x0504030201008f8e ; shl 10 (16-6) / shr6
;       dq 0x8e8d8c8b8a898887, 0x060504030201008f ; shl 9  (16-7) / shr7
;       dq 0x8f8e8d8c8b8a8988, 0x0706050403020100 ; shl 8  (16-8) / shr8
;       dq 0x008f8e8d8c8b8a89, 0x0807060504030201 ; shl 7  (16-9) / shr9
;       dq 0x01008f8e8d8c8b8a, 0x0908070605040302 ; shl 6  (16-10) / shr10
;       dq 0x0201008f8e8d8c8b, 0x0a09080706050403 ; shl 5  (16-11) / shr11
;       dq 0x030201008f8e8d8c, 0x0b0a090807060504 ; shl 4  (16-12) / shr12
;       dq 0x04030201008f8e8d, 0x0c0b0a0908070605 ; shl 3  (16-13) / shr13
;       dq 0x0504030201008f8e, 0x0d0c0b0a09080706 ; shl 2  (16-14) / shr14
;       dq 0x060504030201008f, 0x0e0d0c0b0a090807 ; shl 1  (16-15) / shr15
dq 0x8786858483828100, 0x8f8e8d8c8b8a8988
dq 0x0706050403020100, 0x000e0d0c0b0a0908

mask:  dq     0xFFFFFFFFFFFFFFFF, 0x0000000000000000
mask2: dq     0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF
mask3: dq     0x8080808080808080, 0x8080808080808080

align 64
byte_len_to_mask_table:
        dw      0x0000, 0x0001, 0x0003, 0x0007,
        dw      0x000f, 0x001f, 0x003f, 0x007f,
        dw      0x00ff, 0x01ff, 0x03ff, 0x07ff,
        dw      0x0fff, 0x1fff, 0x3fff, 0x7fff,
        dw      0xffff
