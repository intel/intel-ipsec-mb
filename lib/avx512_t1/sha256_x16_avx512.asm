;;
;; Copyright (c) 2017-2024, Intel Corporation
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
;; Windows clobbers:	RAX         RDX     RSI RDI     R9  R10 R11 R12 R13 R14 R15
;; Windows preserves:	        RCX
;;			-----------------------------------------------------------
;; Linux clobbers:	RAX     RCX RDX     RSI         R9  R10 R11 R12 R13 R14 R15
;; Linux preserves:	                        RDI
;;			-----------------------------------------------------------
;; Clobbers ZMM0-31

%include "include/os.inc"
;%define DO_DBGPRINT
%include "include/dbgprint.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/transpose_avx512.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"
%include "include/align_avx512.inc"
; re-use K256 from sha256_oct_avx2.asm
extern K256

;; code to compute x16 SHA256 using AVX512

%define APPEND(a,b) a %+ b

; Define Stack Layout
START_FIELDS
;;;     name            size    align
FIELD	_DIGEST_SAVE,	8*64,	64
FIELD	_rsp,		8,	8
%assign STACK_SPACE	_FIELD_OFFSET

%ifdef LINUX
; Linux register definitions
     %define arg1 	rdi
     %define arg2	rsi
     %define arg3	rcx
     %define arg4	rdx
%else
; Windows definitions
     %define arg1 	rcx
     %define arg2 	rdx
     %define arg3	rsi
     %define arg4	rdi
%endif

%define STATE		arg1
%define INP_SIZE	arg2
%define IDX		arg3
%define TBL		arg4

%define A	zmm0
%define B	zmm1
%define C	zmm2
%define D	zmm3
%define E	zmm4
%define F	zmm5
%define G	zmm6
%define H	zmm7
%define T1	zmm8
%define TMP0	zmm9
%define TMP1	zmm10
%define TMP2	zmm11
%define TMP3	zmm12
%define TMP4	zmm13
%define TMP5	zmm14
%define TMP6	zmm15

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
%xdefine TMP_ H
%xdefine H G
%xdefine G F
%xdefine F E
%xdefine E D
%xdefine D C
%xdefine C B
%xdefine B A
%xdefine A TMP_
%endm

;;  CH(A, B, C) = (A&B) ^ (~A&C)
;; MAJ(E, F, G) = (E&F) ^ (E&G) ^ (F&G)
;; SIGMA0 = ROR_2  ^ ROR_13 ^ ROR_22
;; SIGMA1 = ROR_6  ^ ROR_11 ^ ROR_25
;; sigma0 = ROR_7  ^ ROR_18 ^ SHR_3
;; sigma1 = ROR_17 ^ ROR_19 ^ SHR_10

; Main processing loop per round
%macro PROCESS_LOOP 2
%define %%WT	%1
%define %%ROUND	%2
	;; T1 = H + SIGMA1(E) + CH(E, F, G) + Kt + Wt
	;; T2 = SIGMA0(A) + MAJ(A, B, C)
	;; H=G, G=F, F=E, E=D+T1, D=C, C=B, B=A, A=T1+T2

	;; H becomes T2, then add T1 for A
	;; D becomes D + T1 for E

	vpaddd		T1, H, TMP3		; T1 = H + Kt
	vmovdqa32	TMP0, E
	vprord		TMP1, E, 6 		; ROR_6(E)
	vprord		TMP2, E, 11 		; ROR_11(E)
	vprord		TMP3, E, 25 		; ROR_25(E)
	vpternlogd	TMP0, F, G, 0xCA	; TMP0 = CH(E,F,G)
	vpaddd		T1, T1, %%WT		; T1 = T1 + Wt
	vpternlogd	TMP1, TMP2, TMP3, 0x96	; TMP1 = SIGMA1(E)
	vpaddd		T1, T1, TMP0		; T1 = T1 + CH(E,F,G)
	vpaddd		T1, T1, TMP1		; T1 = T1 + SIGMA1(E)
	vpaddd		D, D, T1		; D = D + T1

	vprord		H, A, 2 		; ROR_2(A)
	vprord		TMP2, A, 13 		; ROR_13(A)
	vprord		TMP3, A, 22 		; ROR_22(A)
	vmovdqa32	TMP0, A
	vpternlogd	TMP0, B, C, 0xE8	; TMP0 = MAJ(A,B,C)
	vpternlogd	H, TMP2, TMP3, 0x96	; H(T2) = SIGMA0(A)
	vpaddd		H, H, TMP0		; H(T2) = SIGMA0(A) + MAJ(A,B,C)
	vpaddd		H, H, T1		; H(A) = H(T2) + T1

	vpbroadcastd	TMP3, [TBL + ((%%ROUND+1)*4)]	; Next Kt

	;; Rotate the args A-H (rotation of names associated with regs)
	ROTATE_ARGS
%endmacro

; This is supposed to be SKL optimized assuming:
; vpternlog, vpaddd ports 5,8
; vprord ports 1,8
; However, vprord is only working on port 8
;
; Main processing loop per round
; Get the msg schedule word 16 from the current, now unnecessary word
%macro PROCESS_LOOP_00_47 5
%define %%WT	%1
%define %%ROUND	%2
%define %%WTp1	%3
%define %%WTp9	%4
%define %%WTp14	%5
	;; T1 = H + SIGMA1(E) + CH(E, F, G) + Kt + Wt
	;; T2 = SIGMA0(A) + MAJ(A, B, C)
	;; H=G, G=F, F=E, E=D+T1, D=C, C=B, B=A, A=T1+T2

	;; H becomes T2, then add T1 for A
	;; D becomes D + T1 for E

	;; For next value in msg schedule
	;; Wt+16 = sigma1(Wt+14) + Wt+9 + sigma0(Wt+1) + Wt

	vmovdqa32	TMP0, E
	vprord		TMP1, E, 6 		; ROR_6(E)
	vprord		TMP2, E, 11 		; ROR_11(E)
	vprord		TMP3, E, 25 		; ROR_25(E)
	vpternlogd	TMP0, F, G, 0xCA	; TMP0 = CH(E,F,G)
	vpaddd		T1, H, %%WT		; T1 = H + Wt
	vpternlogd	TMP1, TMP2, TMP3, 0x96	; TMP1 = SIGMA1(E)
	vpaddd		T1, T1, TMP6		; T1 = T1 + Kt
	vprord		H, A, 2 		; ROR_2(A)
	vpaddd		T1, T1, TMP0		; T1 = T1 + CH(E,F,G)
	vprord		TMP2, A, 13 		; ROR_13(A)
	vmovdqa32	TMP0, A
	vprord		TMP3, A, 22 		; ROR_22(A)
	vpaddd		T1, T1, TMP1		; T1 = T1 + SIGMA1(E)
	vpternlogd	TMP0, B, C, 0xE8	; TMP0 = MAJ(A,B,C)
	vpaddd		D, D, T1		; D = D + T1
	vpternlogd	H, TMP2, TMP3, 0x96	; H(T2) = SIGMA0(A)
	vprord		TMP4, %%WTp14, 17 	; ROR_17(Wt-2)
	vpaddd		H, H, TMP0		; H(T2) = SIGMA0(A) + MAJ(A,B,C)
	vprord		TMP5, %%WTp14, 19 	; ROR_19(Wt-2)
	vpsrld		TMP6, %%WTp14, 10 	; SHR_10(Wt-2)
	vpaddd		H, H, T1		; H(A) = H(T2) + T1
	vpternlogd	TMP4, TMP5, TMP6, 0x96	; TMP4 = sigma1(Wt-2)
	vpaddd		%%WT, %%WT, TMP4	; Wt = Wt-16 + sigma1(Wt-2)
	vprord		TMP4, %%WTp1, 7 	; ROR_7(Wt-15)
	vprord		TMP5, %%WTp1, 18 	; ROR_18(Wt-15)
	vpaddd		%%WT, %%WT, %%WTp9	; Wt = Wt-16 + sigma1(Wt-2) + Wt-7
	vpsrld		TMP6, %%WTp1, 3 	; SHR_3(Wt-15)
	vpternlogd	TMP4, TMP5, TMP6, 0x96	; TMP4 = sigma0(Wt-15)
	vpaddd		%%WT, %%WT, TMP4	; Wt = Wt-16 + sigma1(Wt-2) +
						;      Wt-7 + sigma0(Wt-15) +

	vpbroadcastd	TMP6, [TBL + ((%%ROUND+1)*4)]	; Next Kt

	;; Rotate the args A-H (rotation of names associated with regs)
	ROTATE_ARGS
%endmacro

%macro MSG_SCHED_ROUND_16_63 4
%define %%WT	%1
%define %%WTp1	%2
%define %%WTp9	%3
%define %%WTp14	%4
	vprord		TMP4, %%WTp14, 17 	; ROR_17(Wt-2)
	vprord		TMP5, %%WTp14, 19 	; ROR_19(Wt-2)
	vpsrld		TMP6, %%WTp14, 10 	; SHR_10(Wt-2)
	vpternlogd	TMP4, TMP5, TMP6, 0x96	; TMP4 = sigma1(Wt-2)

	vpaddd		%%WT, %%WT, TMP4	; Wt = Wt-16 + sigma1(Wt-2)
	vpaddd		%%WT, %%WT, %%WTp9	; Wt = Wt-16 + sigma1(Wt-2) + Wt-7

	vprord		TMP4, %%WTp1, 7 	; ROR_7(Wt-15)
	vprord		TMP5, %%WTp1, 18 	; ROR_18(Wt-15)
	vpsrld		TMP6, %%WTp1, 3 	; SHR_3(Wt-15)
	vpternlogd	TMP4, TMP5, TMP6, 0x96	; TMP4 = sigma0(Wt-15)

	vpaddd		%%WT, %%WT, TMP4	; Wt = Wt-16 + sigma1(Wt-2) +
						;      Wt-7 + sigma0(Wt-15) +
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

        mksection .rodata
default rel
align 64
TABLE:
	dd	0x428a2f98, 0x71374491
	dd	0xb5c0fbcf, 0xe9b5dba5
	dd	0x3956c25b, 0x59f111f1
	dd	0x923f82a4, 0xab1c5ed5
	dd	0xd807aa98, 0x12835b01
	dd	0x243185be, 0x550c7dc3
	dd	0x72be5d74, 0x80deb1fe
	dd	0x9bdc06a7, 0xc19bf174
	dd	0xe49b69c1, 0xefbe4786
	dd	0x0fc19dc6, 0x240ca1cc
	dd	0x2de92c6f, 0x4a7484aa
	dd	0x5cb0a9dc, 0x76f988da
	dd	0x983e5152, 0xa831c66d
	dd	0xb00327c8, 0xbf597fc7
	dd	0xc6e00bf3, 0xd5a79147
	dd	0x06ca6351, 0x14292967
	dd	0x27b70a85, 0x2e1b2138
	dd	0x4d2c6dfc, 0x53380d13
	dd	0x650a7354, 0x766a0abb
	dd	0x81c2c92e, 0x92722c85
	dd	0xa2bfe8a1, 0xa81a664b
	dd	0xc24b8b70, 0xc76c51a3
	dd	0xd192e819, 0xd6990624
	dd	0xf40e3585, 0x106aa070
	dd	0x19a4c116, 0x1e376c08
	dd	0x2748774c, 0x34b0bcb5
	dd	0x391c0cb3, 0x4ed8aa4a
	dd	0x5b9cca4f, 0x682e6ff3
	dd	0x748f82ee, 0x78a5636f
	dd	0x84c87814, 0x8cc70208
	dd	0x90befffa, 0xa4506ceb
	dd	0xbef9a3f7, 0xc67178f2

align 16
PSHUFFLE_BYTE_FLIP_MASK:
	 dq 0x0405060700010203, 0x0c0d0e0f08090a0b

mksection .text

%define XMM_STORAGE     10*16
%define GP_STORAGE      9*8

%define VARIABLE_OFFSET XMM_STORAGE + GP_STORAGE
%define GP_OFFSET XMM_STORAGE

%macro FUNC_SAVE 0
    mov      r11, rsp
    sub      rsp, VARIABLE_OFFSET
    and      rsp, ~31	; align rsp to 32 bytes

    mov      [rsp + 0*8],  rbx
    mov      [rsp + 1*8],  rbp
    mov      [rsp + 2*8],  r12
    mov      [rsp + 3*8],  r13
    mov      [rsp + 4*8],  r14
    mov      [rsp + 5*8],  r15
%ifndef LINUX
    mov        [rsp + 6*8],  rsi
    mov        [rsp + 7*8],  rdi
    vmovdqa32  [rsp + 4*16], xmm6
    vmovdqa32  [rsp + 5*16], xmm7
    vmovdqa32  [rsp + 6*16], xmm8
    vmovdqa32  [rsp + 7*16], xmm9
    vmovdqa32  [rsp + 8*16], xmm10
    vmovdqa32  [rsp + 9*16], xmm11
    vmovdqa32  [rsp + 10*16], xmm12
    vmovdqa32  [rsp + 11*16], xmm13
    vmovdqa32  [rsp + 12*16], xmm14
    vmovdqa32  [rsp + 13*16], xmm15
%endif ; LINUX
    mov        [rsp + 14*16], r11 ;; rsp pointer
%endmacro

%macro FUNC_RESTORE 0
    mov      rbx,  [rsp + 0*8]
    mov      rbp,  [rsp + 1*8]
    mov      r12,  [rsp + 2*8]
    mov      r13,  [rsp + 3*8]
    mov      r14,  [rsp + 4*8]
    mov      r15,  [rsp + 5*8]
%ifndef LINUX
    mov        rsi,   [rsp + 6*8]
    mov        rdi,   [rsp + 7*8]
    vmovdqa32  xmm6,  [rsp + 4*16]
    vmovdqa32  xmm7,  [rsp + 5*16]
    vmovdqa32  xmm8,  [rsp + 6*16]
    vmovdqa32  xmm9,  [rsp + 7*16]
    vmovdqa32  xmm10, [rsp + 8*16]
    vmovdqa32  xmm11, [rsp + 9*16]
    vmovdqa32  xmm12, [rsp + 10*16]
    vmovdqa32  xmm13, [rsp + 11*16]
    vmovdqa32  xmm14, [rsp + 12*16]
    vmovdqa32  xmm15, [rsp + 13*16]

%ifdef SAFE_DATA
    vpxord     xmm5, xmm5, xmm5
    vmovdqa32  xmm5,  [rsp + 4*16]
    vmovdqa32  xmm5,  [rsp + 5*16]
    vmovdqa32  xmm5,  [rsp + 6*16]
    vmovdqa32  xmm5,  [rsp + 7*16]
    vmovdqa32  xmm5,  [rsp + 8*16]
    vmovdqa32  xmm5,  [rsp + 9*16]
    vmovdqa32  xmm5,  [rsp + 10*16]
    vmovdqa32  xmm5,  [rsp + 11*16]
    vmovdqa32  xmm5,  [rsp + 12*16]
    vmovdqa32  xmm5,  [rsp + 13*16]
%endif
%endif ; LINUX
    mov        rsp,   [rsp + 14*16] ;; rsp pointer
%endmacro

;; void sha256_x16_avx512(void **input_data, UINT128 *digest[16], UINT64 size)
;; arg 1 : pointer to SHA256 args structure
;; arg 2 : size (in blocks) ;; assumed to be >= 1
;; arg 1 : rcx : pointer to array of pointers to input data
;; arg 2 : rdx : pointer to array of pointers to digest
;; arg 3 : r8  : size of input in bytes
MKGLOBAL(sha256_x16_avx512,function,internal)
align_function
sha256_x16_avx512:
	mov	rax, rsp
        sub     rsp, STACK_SPACE
	and	rsp, ~63	; align stack to multiple of 64
	mov	[rsp + _rsp], rax

	;; Initialize digests
	vmovdqu32	A, [STATE + 0*SHA256_DIGEST_ROW_SIZE]
	vmovdqu32	B, [STATE + 1*SHA256_DIGEST_ROW_SIZE]
	vmovdqu32	C, [STATE + 2*SHA256_DIGEST_ROW_SIZE]
	vmovdqu32	D, [STATE + 3*SHA256_DIGEST_ROW_SIZE]
	vmovdqu32	E, [STATE + 4*SHA256_DIGEST_ROW_SIZE]
	vmovdqu32	F, [STATE + 5*SHA256_DIGEST_ROW_SIZE]
	vmovdqu32	G, [STATE + 6*SHA256_DIGEST_ROW_SIZE]
	vmovdqu32	H, [STATE + 7*SHA256_DIGEST_ROW_SIZE]

	lea		TBL, [rel TABLE]

	; Do we need to transpose digests???
	; SHA1 does not, but SHA256 has been

	xor IDX, IDX

	;; Load first blocks of data into ZMM registers before
	;; performing a 16x16 32-bit transpose.
	;; To speed up the transpose, data is loaded in chunks of 32 bytes,
	;; interleaving data between lane X and lane X+8.
	;; This way, final shuffles between top half and bottom half
	;; of the matrix are avoided.
	mov	inp0, [STATE + _data_ptr_sha256 + 0*PTR_SZ]
	mov	inp1, [STATE + _data_ptr_sha256 + 1*PTR_SZ]
	mov	inp2, [STATE + _data_ptr_sha256 + 2*PTR_SZ]
	mov	inp3, [STATE + _data_ptr_sha256 + 3*PTR_SZ]
	mov	inp4, [STATE + _data_ptr_sha256 + 4*PTR_SZ]
	mov	inp5, [STATE + _data_ptr_sha256 + 5*PTR_SZ]
	mov	inp6, [STATE + _data_ptr_sha256 + 6*PTR_SZ]
	mov	inp7, [STATE + _data_ptr_sha256 + 7*PTR_SZ]

	TRANSPOSE16_U32_LOAD_FIRST8 W0, W1, W2,  W3,  W4,  W5,  W6,  W7, \
				    W8, W9, W10, W11, W12, W13, W14, W15, \
				    inp0, inp1, inp2, inp3, inp4, inp5, \
				    inp6, inp7, IDX

	mov	inp0, [STATE + _data_ptr_sha256 + 8*PTR_SZ]
	mov	inp1, [STATE + _data_ptr_sha256 + 9*PTR_SZ]
	mov	inp2, [STATE + _data_ptr_sha256 +10*PTR_SZ]
	mov	inp3, [STATE + _data_ptr_sha256 +11*PTR_SZ]
	mov	inp4, [STATE + _data_ptr_sha256 +12*PTR_SZ]
	mov	inp5, [STATE + _data_ptr_sha256 +13*PTR_SZ]
	mov	inp6, [STATE + _data_ptr_sha256 +14*PTR_SZ]
	mov	inp7, [STATE + _data_ptr_sha256 +15*PTR_SZ]

	TRANSPOSE16_U32_LOAD_LAST8 W0, W1, W2,  W3,  W4,  W5,  W6,  W7, \
				   W8, W9, W10, W11, W12, W13, W14, W15, \
				   inp0, inp1, inp2, inp3, inp4, inp5, \
				   inp6, inp7, IDX

align_loop
lloop:
	vbroadcasti32x4	TMP2, [rel PSHUFFLE_BYTE_FLIP_MASK]

	vpbroadcastd	TMP3, [TBL]	; First K

	; Save digests for later addition
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*0], A
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*1], B
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*2], C
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*3], D
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*4], E
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*5], F
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*6], G
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*7], H

	add	IDX, 64

	TRANSPOSE16_U32_PRELOADED W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, \
                                  W11, W12, W13, W14, W15, TMP0, TMP1, TMP4, TMP5

%assign I 0
%rep 16
       	vpshufb	APPEND(W,I), APPEND(W,I), TMP2
%assign I (I+1)
%endrep

	; MSG Schedule for W0-W15 is now complete in registers
	; Process first 48 rounds
	; Calculate next Wt+16 after processing is complete and Wt is unneeded

	; PROCESS_LOOP_00_47 APPEND(W,J), I, APPEND(W,K), APPEND(W,L), APPEND(W,M)
%assign I 0
%assign J 0
%assign K 1
%assign L 9
%assign M 14
%rep 48
	PROCESS_LOOP  APPEND(W,J),  I
	MSG_SCHED_ROUND_16_63  APPEND(W,J), APPEND(W,K), APPEND(W,L), APPEND(W,M)
%assign I (I+1)
%assign J ((J+1)% 16)
%assign K ((K+1)% 16)
%assign L ((L+1)% 16)
%assign M ((M+1)% 16)
%endrep

	; Check is this is the last block
	sub 	INP_SIZE, 1
	je	lastLoop

	; Process last 16 rounds
	; Read in next block msg data for use in first 16 words of msg sched
%assign I 48
%assign J 0
%rep 16
	PROCESS_LOOP  APPEND(W,J), I
	MSG_SCHED_ROUND_00_15 APPEND(W,J), J, STATE + _data_ptr_sha256, IDX, inp0, inp1
%assign I (I+1)
%assign J (J+1)
%endrep

	; Add old digest
        vpaddd		A, A, [rsp + _DIGEST_SAVE + 64*0]
        vpaddd		B, B, [rsp + _DIGEST_SAVE + 64*1]
        vpaddd		C, C, [rsp + _DIGEST_SAVE + 64*2]
        vpaddd		D, D, [rsp + _DIGEST_SAVE + 64*3]
        vpaddd		E, E, [rsp + _DIGEST_SAVE + 64*4]
        vpaddd		F, F, [rsp + _DIGEST_SAVE + 64*5]
        vpaddd		G, G, [rsp + _DIGEST_SAVE + 64*6]
        vpaddd		H, H, [rsp + _DIGEST_SAVE + 64*7]

	jmp	lloop

align_label
lastLoop:
	; Process last 16 rounds
%assign I 48
%assign J 0
%rep 16
	PROCESS_LOOP  APPEND(W,J), I
%assign I (I+1)
%assign J (J+1)
%endrep

	; Add old digest
        vpaddd		A, A, [rsp + _DIGEST_SAVE + 64*0]
        vpaddd		B, B, [rsp + _DIGEST_SAVE + 64*1]
        vpaddd		C, C, [rsp + _DIGEST_SAVE + 64*2]
        vpaddd		D, D, [rsp + _DIGEST_SAVE + 64*3]
        vpaddd		E, E, [rsp + _DIGEST_SAVE + 64*4]
        vpaddd		F, F, [rsp + _DIGEST_SAVE + 64*5]
        vpaddd		G, G, [rsp + _DIGEST_SAVE + 64*6]
        vpaddd		H, H, [rsp + _DIGEST_SAVE + 64*7]

	; Write out digest
	; Do we need to untranspose digests???
	vmovdqu32	[STATE + 0*SHA256_DIGEST_ROW_SIZE], A
	vmovdqu32	[STATE + 1*SHA256_DIGEST_ROW_SIZE], B
	vmovdqu32	[STATE + 2*SHA256_DIGEST_ROW_SIZE], C
	vmovdqu32	[STATE + 3*SHA256_DIGEST_ROW_SIZE], D
	vmovdqu32	[STATE + 4*SHA256_DIGEST_ROW_SIZE], E
	vmovdqu32	[STATE + 5*SHA256_DIGEST_ROW_SIZE], F
	vmovdqu32	[STATE + 6*SHA256_DIGEST_ROW_SIZE], G
	vmovdqu32	[STATE + 7*SHA256_DIGEST_ROW_SIZE], H

	; update input pointers
%assign I 0
%rep 16
	add	[STATE + _data_ptr_sha256 + I*PTR_SZ], IDX
%assign I (I+1)
%endrep

%ifdef SAFE_DATA
        ;; Clear stack frame (8*64 bytes)
	clear_all_zmms_asm

%assign i 0
%rep 8
	vmovdqa64 [rsp + i*64], zmm0
%assign i (i+1)
%endrep
%else
        vzeroupper
%endif

        mov     rsp, [rsp + _rsp]
        ret

; void call_sha256_x16_avx512_from_c(SHA256_ARGS *args, UINT32 size_in_blocks);
MKGLOBAL(call_sha256_x16_avx512_from_c,function,internal)
align_function
call_sha256_x16_avx512_from_c:
	FUNC_SAVE
	call sha256_x16_avx512
	FUNC_RESTORE
	ret

mksection stack-noexec
