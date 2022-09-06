;;
;; Copyright (c) 2012-2022, Intel Corporation
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

;; Stack must be aligned to 32 bytes before call
;;
;; Registers:		RAX RBX RCX RDX RBP RSI RDI R8  R9  R10 R11 R12 R13 R14 R15
;;			-----------------------------------------------------------
;; Windows clobbers:	RAX         RDX             R8  R9  R10 R11 R12 R13 R14 R15
;; Windows preserves:	    RBX RCX     RBP RSI RDI
;;			-----------------------------------------------------------
;; Linux clobbers:	RAX         RDX     RSI         R9  R10 R11 R12 R13 R14 R15
;; Linux preserves:	    RBX RCX     RBP     RDI R8
;;			-----------------------------------------------------------
;; Clobbers ZMM0-31

%include "include/os.asm"
;%define DO_DBGPRINT
%include "include/dbgprint.asm"
%include "include/mb_mgr_datastruct.asm"
%include "include/transpose_avx512.asm"
%include "include/reg_sizes.asm"
%include "include/clear_regs.asm"
mksection .rodata
default rel
align 64
K00_19:	;ddq 0x5A8279995A8279995A8279995A827999
	;ddq 0x5A8279995A8279995A8279995A827999
	;ddq 0x5A8279995A8279995A8279995A827999
	;ddq 0x5A8279995A8279995A8279995A827999
	dq 0x5A8279995A827999, 0x5A8279995A827999
	dq 0x5A8279995A827999, 0x5A8279995A827999
	dq 0x5A8279995A827999, 0x5A8279995A827999
	dq 0x5A8279995A827999, 0x5A8279995A827999
K20_39: ;ddq 0x6ED9EBA16ED9EBA16ED9EBA16ED9EBA1
	;ddq 0x6ED9EBA16ED9EBA16ED9EBA16ED9EBA1
	;ddq 0x6ED9EBA16ED9EBA16ED9EBA16ED9EBA1
	;ddq 0x6ED9EBA16ED9EBA16ED9EBA16ED9EBA1
	dq 0x6ED9EBA16ED9EBA1, 0x6ED9EBA16ED9EBA1
	dq 0x6ED9EBA16ED9EBA1, 0x6ED9EBA16ED9EBA1
	dq 0x6ED9EBA16ED9EBA1, 0x6ED9EBA16ED9EBA1
	dq 0x6ED9EBA16ED9EBA1, 0x6ED9EBA16ED9EBA1
K40_59: ;ddq 0x8F1BBCDC8F1BBCDC8F1BBCDC8F1BBCDC
	;ddq 0x8F1BBCDC8F1BBCDC8F1BBCDC8F1BBCDC
	;ddq 0x8F1BBCDC8F1BBCDC8F1BBCDC8F1BBCDC
	;ddq 0x8F1BBCDC8F1BBCDC8F1BBCDC8F1BBCDC
	dq 0x8F1BBCDC8F1BBCDC, 0x8F1BBCDC8F1BBCDC
	dq 0x8F1BBCDC8F1BBCDC, 0x8F1BBCDC8F1BBCDC
	dq 0x8F1BBCDC8F1BBCDC, 0x8F1BBCDC8F1BBCDC
	dq 0x8F1BBCDC8F1BBCDC, 0x8F1BBCDC8F1BBCDC
K60_79: ;ddq 0xCA62C1D6CA62C1D6CA62C1D6CA62C1D6
	;ddq 0xCA62C1D6CA62C1D6CA62C1D6CA62C1D6
	;ddq 0xCA62C1D6CA62C1D6CA62C1D6CA62C1D6
	;ddq 0xCA62C1D6CA62C1D6CA62C1D6CA62C1D6
	dq 0xCA62C1D6CA62C1D6, 0xCA62C1D6CA62C1D6
	dq 0xCA62C1D6CA62C1D6, 0xCA62C1D6CA62C1D6
	dq 0xCA62C1D6CA62C1D6, 0xCA62C1D6CA62C1D6
	dq 0xCA62C1D6CA62C1D6, 0xCA62C1D6CA62C1D6

PSHUFFLE_BYTE_FLIP_MASK: ;ddq 0x0c0d0e0f08090a0b0405060700010203
			 ;ddq 0x0c0d0e0f08090a0b0405060700010203
			 ;ddq 0x0c0d0e0f08090a0b0405060700010203
			 ;ddq 0x0c0d0e0f08090a0b0405060700010203
	dq 0x0405060700010203, 0x0c0d0e0f08090a0b
	dq 0x0405060700010203, 0x0c0d0e0f08090a0b
	dq 0x0405060700010203, 0x0c0d0e0f08090a0b
	dq 0x0405060700010203, 0x0c0d0e0f08090a0b

mksection .text

%define APPEND(a,b) a %+ b

%define XMM_STORAGE     16*10
%define GP_STORAGE      8*5

%define VARIABLE_OFFSET XMM_STORAGE + GP_STORAGE
%define GP_OFFSET XMM_STORAGE

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

%define state	arg1
%define SIZE	arg2
%define IDX	arg3

%define A	zmm0
%define B	zmm1
%define C	zmm2
%define D	zmm3
%define E	zmm4
%define KT  	zmm5
%define AA	zmm6
%define BB	zmm7
%define CC	zmm8
%define DD	zmm9
%define EE	zmm10
%define TMP0	zmm11
%define TMP1	zmm12
%define TMP2	zmm13
%define TMP3	zmm14
%define TMP4	zmm15

%define W0	zmm16
%define W1	zmm17
%define W2	zmm18
%define W3	zmm19
%define W4	zmm20
%define W5	zmm21
%define W6	zmm22
%define W7	zmm23
%define W8	zmm24
%define W9	zmm25
%define W10	zmm26
%define W11	zmm27
%define W12	zmm28
%define W13	zmm29
%define W14	zmm30
%define W15	zmm31

%define inp0	r9
%define inp1	r10
%define inp2	r11
%define inp3	r12
%define inp4	r13
%define inp5	r14
%define inp6	r15
%define inp7	rax

%macro ROTATE_ARGS 0
%xdefine TMP_ E
%xdefine E D
%xdefine D C
%xdefine C B
%xdefine B A
%xdefine A TMP_
%endm

%macro PROCESS_LOOP 2
%define %%WT		%1
%define %%F_IMMED	%2

	; T = ROTL_5(A) + Ft(B,C,D) + E + Kt + Wt
	; E=D, D=C, C=ROTL_30(B), B=A, A=T

	; Ft
	;  0-19 Ch(B,C,D) = (B&C) ^ (~B&D)
	; 20-39, 60-79 Parity(B,C,D) = B ^ C ^ D
	; 40-59 Maj(B,C,D) = (B&C) ^ (B&D) ^ (C&D)

	vmovdqa32	TMP1, B			; Copy B
	vpaddd		E, E, %%WT		; E = E + Wt
	vpternlogd	TMP1, C, D, %%F_IMMED	; TMP1 = Ft(B,C,D)
	vpaddd		E, E, KT		; E = E + Wt + Kt
	vprold		TMP0, A, 5		; TMP0 = ROTL_5(A)
	vpaddd		E, E, TMP1		; E = Ft(B,C,D) + E + Kt + Wt
	vprold		B, B, 30		; B = ROTL_30(B)
	vpaddd		E, E, TMP0		; E = T

	ROTATE_ARGS
%endmacro

%macro MSG_SCHED_ROUND_16_79 4
%define %%WT	%1
%define %%WTp2	%2
%define %%WTp8	%3
%define %%WTp13	%4
	; Wt = ROTL_1(Wt-3 ^ Wt-8 ^ Wt-14 ^ Wt-16)
	; Wt+16 = ROTL_1(Wt+13 ^ Wt+8 ^ Wt+2 ^ Wt)
	vpternlogd	%%WT, %%WTp2, %%WTp8, 0x96
	vpxord		%%WT, %%WT, %%WTp13
	vprold		%%WT, %%WT, 1
%endmacro

; Note this is reading in two blocks of data from each lane,
; in preparation for the upcoming needed transpose to build msg schedule.
; Each register will contain 32 bytes from one lane plus 32 bytes
; from another lane.
; The first 8 registers will contain the first 32 bytes of all lanes,
; where register X (0 <= X <= 7) will contain bytes 0-31 from lane X in the first half
; and 0-31 bytes from lane X+8 in the second half.
; The last 8 registers will contain the last 32 bytes of all lanes,
; where register Y (8 <= Y <= 15) will contain bytes 32-63 from lane Y-8 in the first half
; and 32-63 bytes from lane Y in the second half.
; This method helps reducing the number of shuffles required to transpose the data.
%macro MSG_SCHED_ROUND_00_15 6
%define %%Wt         %1 ; [out] zmm register to load the next block
%define %%LANE_IDX   %2 ; [in] lane index (0-15)
%define %%BASE_PTR   %3 ; [in] base address of the input data
%define %%OFFSET_PTR %4 ; [in] offset to get next block of data from the lane
%define %%TMP1       %5 ; [clobbered] temporary gp register
%define %%TMP2       %6 ; [clobbered] temporary gp register
%if (%%LANE_IDX < 8)
	mov	      %%TMP1,	   [%%BASE_PTR + %%LANE_IDX*PTR_SZ]
	mov	      %%TMP2,      [%%BASE_PTR + (%%LANE_IDX+8)*PTR_SZ]
	vmovups       YWORD(%%Wt), [%%TMP1+%%OFFSET_PTR]
	vinserti64x4  %%Wt, %%Wt,  [%%TMP2+%%OFFSET_PTR], 0x01
%else
	mov	     %%TMP1,      [%%BASE_PTR + (%%LANE_IDX-8)*PTR_SZ]
	mov	     %%TMP2,      [%%BASE_PTR + %%LANE_IDX*PTR_SZ]
	vmovups      YWORD(%%Wt), [%%TMP1+%%OFFSET_PTR+32]
	vinserti64x4 %%Wt, %%Wt,  [%%TMP2+%%OFFSET_PTR+32], 0x01
%endif
%endmacro

%macro FUNC_SAVE 0
    mov     r11, rsp
    sub     rsp, VARIABLE_OFFSET
%ifndef LINUX
    vmovdqa32  [rsp + 0*16], xmm6
    vmovdqa32  [rsp + 1*16], xmm7
    vmovdqa32  [rsp + 2*16], xmm8
    vmovdqa32  [rsp + 3*16], xmm9
    vmovdqa32  [rsp + 4*16], xmm10
    vmovdqa32  [rsp + 5*16], xmm11
    vmovdqa32  [rsp + 6*16], xmm12
    vmovdqa32  [rsp + 7*16], xmm13
    vmovdqa32  [rsp + 8*16], xmm14
    vmovdqa32  [rsp + 9*16], xmm15
%endif
    mov     [rsp + GP_OFFSET], r12
    mov     [rsp + GP_OFFSET + 8], r13
    mov     [rsp + GP_OFFSET + 2*8], r14
    mov     [rsp + GP_OFFSET + 3*8], r15
    mov     [rsp + GP_OFFSET + 4*8], r11 ;; rsp pointer
%endmacro

%macro FUNC_RESTORE 0
%ifndef LINUX
    vmovdqa32  xmm6, [rsp + 0*16]
    vmovdqa32  xmm7, [rsp + 1*16]
    vmovdqa32  xmm8, [rsp + 2*16]
    vmovdqa32  xmm9, [rsp + 3*16]
    vmovdqa32  xmm10, [rsp + 4*16]
    vmovdqa32  xmm11, [rsp + 5*16]
    vmovdqa32  xmm12, [rsp + 6*16]
    vmovdqa32  xmm13, [rsp + 7*16]
    vmovdqa32  xmm14, [rsp + 8*16]
    vmovdqa32  xmm15, [rsp + 9*16]

%ifdef SAFE_DATA
    vpxord     xmm5, xmm5, xmm5
    vmovdqa32  [rsp + 0*16], xmm5
    vmovdqa32  [rsp + 1*16], xmm5
    vmovdqa32  [rsp + 2*16], xmm5
    vmovdqa32  [rsp + 3*16], xmm5
    vmovdqa32  [rsp + 4*16], xmm5
    vmovdqa32  [rsp + 5*16], xmm5
    vmovdqa32  [rsp + 6*16], xmm5
    vmovdqa32  [rsp + 7*16], xmm5
    vmovdqa32  [rsp + 8*16], xmm5
    vmovdqa32  [rsp + 9*16], xmm5
%endif
%endif
    mov     r12, [rsp + GP_OFFSET]
    mov     r13, [rsp + GP_OFFSET + 8]
    mov     r14, [rsp + GP_OFFSET + 2*8]
    mov     r15, [rsp + GP_OFFSET + 3*8]
    mov     rsp, [rsp + GP_OFFSET + 4*8] ;; rsp pointer
%endmacro

;; FRAMESZ must be an odd multiple of 8
%define FRAMESZ	16*10 + 8

align 64
; void sha1_mult_x16_avx3(void **input_data, UINT128 *digest, UINT32 size)
; arg 1 : pointer to SHA1 args structure
; arg 2 : size (in blocks) ;; assumed to be >= 1
MKGLOBAL(sha1_x16_avx512,function,internal)
sha1_x16_avx512:
%ifndef LINUX
	sub	rsp, FRAMESZ

        vmovdqa  [rsp + 0*16], xmm6
        vmovdqa  [rsp + 1*16], xmm7
        vmovdqa  [rsp + 2*16], xmm8
        vmovdqa  [rsp + 3*16], xmm9
        vmovdqa  [rsp + 4*16], xmm10
        vmovdqa  [rsp + 5*16], xmm11
        vmovdqa  [rsp + 6*16], xmm12
        vmovdqa  [rsp + 7*16], xmm13
        vmovdqa  [rsp + 8*16], xmm14
        vmovdqa  [rsp + 9*16], xmm15
%endif
	;; Initialize digests
	vmovdqu32	A, [state + 0*SHA1_DIGEST_ROW_SIZE]
	vmovdqu32	B, [state + 1*SHA1_DIGEST_ROW_SIZE]
	vmovdqu32	C, [state + 2*SHA1_DIGEST_ROW_SIZE]
	vmovdqu32	D, [state + 3*SHA1_DIGEST_ROW_SIZE]
	vmovdqu32	E, [state + 4*SHA1_DIGEST_ROW_SIZE]
	DBGPRINTL_ZMM "Sha1-AVX512 incoming transposed digest", A, B, C, D, E
	DBGPRINTL64   "SIZE", SIZE

	xor IDX, IDX

	;; Load first blocks of data into ZMM registers before
	;; performing a 16x16 32-bit transpose.
	;; To speed up the transpose, data is loaded in chunks of 32 bytes,
	;; interleaving data between lane X and lane X+8.
	;; This way, final shuffles between top half and bottom half
	;; of the matrix are avoided.
	mov	inp0, [state + _data_ptr_sha1 + 0*PTR_SZ]
	mov	inp1, [state + _data_ptr_sha1 + 1*PTR_SZ]
	mov	inp2, [state + _data_ptr_sha1 + 2*PTR_SZ]
	mov	inp3, [state + _data_ptr_sha1 + 3*PTR_SZ]
	mov	inp4, [state + _data_ptr_sha1 + 4*PTR_SZ]
	mov	inp5, [state + _data_ptr_sha1 + 5*PTR_SZ]
	mov	inp6, [state + _data_ptr_sha1 + 6*PTR_SZ]
	mov	inp7, [state + _data_ptr_sha1 + 7*PTR_SZ]

	TRANSPOSE16_U32_LOAD_FIRST8 W0, W1, W2,  W3,  W4,  W5,  W6,  W7, \
				    W8, W9, W10, W11, W12, W13, W14, W15, \
				    inp0, inp1, inp2, inp3, inp4, inp5, \
				    inp6, inp7, IDX

	mov	inp0, [state + _data_ptr_sha1 + 8*PTR_SZ]
	mov	inp1, [state + _data_ptr_sha1 + 9*PTR_SZ]
	mov	inp2, [state + _data_ptr_sha1 +10*PTR_SZ]
	mov	inp3, [state + _data_ptr_sha1 +11*PTR_SZ]
	mov	inp4, [state + _data_ptr_sha1 +12*PTR_SZ]
	mov	inp5, [state + _data_ptr_sha1 +13*PTR_SZ]
	mov	inp6, [state + _data_ptr_sha1 +14*PTR_SZ]
	mov	inp7, [state + _data_ptr_sha1 +15*PTR_SZ]

	TRANSPOSE16_U32_LOAD_LAST8 W0, W1, W2,  W3,  W4,  W5,  W6,  W7, \
				   W8, W9, W10, W11, W12, W13, W14, W15, \
				   inp0, inp1, inp2, inp3, inp4, inp5, \
				   inp6, inp7, IDX
lloop:
	vmovdqa32	TMP2, [rel PSHUFFLE_BYTE_FLIP_MASK]

	add	IDX, 64

	TRANSPOSE16_U32_PRELOADED W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, \
                                  W11, W12, W13, W14, W15, TMP0, TMP1, TMP3, TMP4
	DBGPRINTL_ZMM "Sha1-AVX512 incoming transposed input", W0, W1, W2, W3, W4, \
                                  W6, W7, W8, W9, W10, W11, W12, W13, W14, W15

%assign I 0
%rep 16
       	vpshufb	APPEND(W,I), APPEND(W,I), TMP2
%assign I (I+1)
%endrep

	; Save digests for later addition
	vmovdqa32	AA, A
	vmovdqa32	BB, B
	vmovdqa32	CC, C
	vmovdqa32	DD, D
	vmovdqa32	EE, E

	vmovdqa32	KT, [rel K00_19]
%assign I 0xCA
%assign J 0
%assign K 2
%assign L 8
%assign M 13
%assign N 0
%rep 64
	PROCESS_LOOP  APPEND(W,J),  I
	MSG_SCHED_ROUND_16_79  APPEND(W,J), APPEND(W,K), APPEND(W,L), APPEND(W,M)
	%if N = 19
		vmovdqa32	KT, [rel K20_39]
		%assign I 0x96
	%elif N = 39
		vmovdqa32	KT, [rel K40_59]
		%assign I 0xE8
	%elif N = 59
		vmovdqa32	KT, [rel K60_79]
		%assign I 0x96
	%endif
%assign J ((J+1)% 16)
%assign K ((K+1)% 16)
%assign L ((L+1)% 16)
%assign M ((M+1)% 16)
%assign N (N+1)
%endrep

	; Check if this is the last block
	sub 	SIZE, 1
	je	lastLoop

%assign I 0x96
%assign J 0
%rep 16
	PROCESS_LOOP  APPEND(W,J),  I
	MSG_SCHED_ROUND_00_15 APPEND(W,J), J, state + _data_ptr_sha1, IDX, inp0, inp1
%assign J (J+1)
%endrep

	; Add old digest
	vpaddd		A,A,AA
	vpaddd		B,B,BB
	vpaddd		C,C,CC
	vpaddd		D,D,DD
	vpaddd		E,E,EE

	jmp lloop

lastLoop:
; Need to reset argument rotation values to Round 64 values
%xdefine TMP_ A
%xdefine A B
%xdefine B C
%xdefine C D
%xdefine D E
%xdefine E TMP_

	; Process last 16 rounds
%assign I 0x96
%assign J 0
%rep 16
	PROCESS_LOOP  APPEND(W,J), I
%assign J (J+1)
%endrep

	; Add old digest
	vpaddd		A,A,AA
	vpaddd		B,B,BB
	vpaddd		C,C,CC
	vpaddd		D,D,DD
	vpaddd		E,E,EE

	; Write out digest
	; Do we need to untranspose digests???
	vmovdqu32	[state + 0*SHA1_DIGEST_ROW_SIZE], A
	vmovdqu32	[state + 1*SHA1_DIGEST_ROW_SIZE], B
	vmovdqu32	[state + 2*SHA1_DIGEST_ROW_SIZE], C
	vmovdqu32	[state + 3*SHA1_DIGEST_ROW_SIZE], D
	vmovdqu32	[state + 4*SHA1_DIGEST_ROW_SIZE], E
	DBGPRINTL_ZMM "Sha1-AVX512 outgoing transposed digest", A, B, C, D, E

	;; update input pointers
	mov	inp0, [state + _data_ptr_sha1 + 0*PTR_SZ]
	mov	inp1, [state + _data_ptr_sha1 + 1*PTR_SZ]
	mov	inp2, [state + _data_ptr_sha1 + 2*PTR_SZ]
	mov	inp3, [state + _data_ptr_sha1 + 3*PTR_SZ]
	mov	inp4, [state + _data_ptr_sha1 + 4*PTR_SZ]
	mov	inp5, [state + _data_ptr_sha1 + 5*PTR_SZ]
	mov	inp6, [state + _data_ptr_sha1 + 6*PTR_SZ]
	mov	inp7, [state + _data_ptr_sha1 + 7*PTR_SZ]
	add	inp0, IDX
	add	inp1, IDX
	add	inp2, IDX
	add	inp3, IDX
	add	inp4, IDX
	add	inp5, IDX
	add	inp6, IDX
	add	inp7, IDX
	mov	[state + _data_ptr_sha1 + 0*PTR_SZ], inp0
	mov	[state + _data_ptr_sha1 + 1*PTR_SZ], inp1
	mov	[state + _data_ptr_sha1 + 2*PTR_SZ], inp2
	mov	[state + _data_ptr_sha1 + 3*PTR_SZ], inp3
	mov	[state + _data_ptr_sha1 + 4*PTR_SZ], inp4
	mov	[state + _data_ptr_sha1 + 5*PTR_SZ], inp5
	mov	[state + _data_ptr_sha1 + 6*PTR_SZ], inp6
	mov	[state + _data_ptr_sha1 + 7*PTR_SZ], inp7

	mov	inp0, [state + _data_ptr_sha1 + 8*PTR_SZ]
	mov	inp1, [state + _data_ptr_sha1 + 9*PTR_SZ]
	mov	inp2, [state + _data_ptr_sha1 + 10*PTR_SZ]
	mov	inp3, [state + _data_ptr_sha1 + 11*PTR_SZ]
	mov	inp4, [state + _data_ptr_sha1 + 12*PTR_SZ]
	mov	inp5, [state + _data_ptr_sha1 + 13*PTR_SZ]
	mov	inp6, [state + _data_ptr_sha1 + 14*PTR_SZ]
	mov	inp7, [state + _data_ptr_sha1 + 15*PTR_SZ]
	add	inp0, IDX
	add	inp1, IDX
	add	inp2, IDX
	add	inp3, IDX
	add	inp4, IDX
	add	inp5, IDX
	add	inp6, IDX
	add	inp7, IDX
	mov	[state + _data_ptr_sha1 + 8*PTR_SZ], inp0
	mov	[state + _data_ptr_sha1 + 9*PTR_SZ], inp1
	mov	[state + _data_ptr_sha1 + 10*PTR_SZ], inp2
	mov	[state + _data_ptr_sha1 + 11*PTR_SZ], inp3
	mov	[state + _data_ptr_sha1 + 12*PTR_SZ], inp4
	mov	[state + _data_ptr_sha1 + 13*PTR_SZ], inp5
	mov	[state + _data_ptr_sha1 + 14*PTR_SZ], inp6
	mov	[state + _data_ptr_sha1 + 15*PTR_SZ], inp7

%ifdef SAFE_DATA
	clear_scratch_zmms_asm
%else
        vzeroupper
%endif ;; SAFE_DATA

%ifndef LINUX
        vmovdqa  xmm6, [rsp + 0*16]
        vmovdqa  xmm7, [rsp + 1*16]
        vmovdqa  xmm8, [rsp + 2*16]
        vmovdqa  xmm9, [rsp + 3*16]
        vmovdqa  xmm10, [rsp + 4*16]
        vmovdqa  xmm11, [rsp + 5*16]
        vmovdqa  xmm12, [rsp + 6*16]
        vmovdqa  xmm13, [rsp + 7*16]
        vmovdqa  xmm14, [rsp + 8*16]
        vmovdqa  xmm15, [rsp + 9*16]

%ifdef SAFE_DATA
	; xmm0 already 0
%assign i 0
%rep 10
        vmovdqa	[rsp + i*16], xmm0
%assign i (i+1)
%endrep
%endif ;SAFE_DATA
	add 	rsp, FRAMESZ
%endif ; !LINUX
	ret

; void call_sha1_x16_avx512_from_c(SHA1_ARGS *args, UINT32 size_in_blocks);
MKGLOBAL(call_sha1_x16_avx512_from_c,function,internal)
call_sha1_x16_avx512_from_c:
	FUNC_SAVE
	call sha1_x16_avx512
	FUNC_RESTORE
	ret

mksection stack-noexec
