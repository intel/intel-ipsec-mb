;;
;; Copyright (c) 2023, Intel Corporation
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

;; macro to do a AES-CB, AES-CBC-MAC and AES-XCBC

;; clobbers all registers except for ARG1 and rbp
%use smartalign

%include "include/os.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/clear_regs.inc"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; struct AES_ARGS {
;;     void*    in[8];
;;     void*    out[8];
;;     UINT128* keys[8];
;;     UINT128  IV[8];
;; }
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cbc_enc_128_x8(AES_ARGS *args, UINT64 len);
;; arg 1: ARG : addr of AES_ARGS structure
;; arg 2: LEN : len (in units of bytes)

struc STACK
_gpr_save:	resq	8
_len:		resq	1
endstruc

%define GPR_SAVE_AREA	rsp + _gpr_save
%define LEN_AREA	rsp + _len

%ifdef LINUX
%define arg1	rdi
%define arg2	rsi
%define arg3	rcx
%define arg4	rdx
%else
%define arg1	rcx
%define arg2	rdx
%define arg3	rdi
%define arg4	rsi
%endif

%define ARG     arg1
%define LEN     arg2

%define IDX	rax
%define TMP	rbx

%define KEYS0	arg3
%define KEYS1	arg4
%define KEYS2	rbp
%define KEYS3	r8
%define KEYS4	r9
%define KEYS5	r10
%define KEYS6	r11
%define KEYS7	r12

%define IN0	r13
%define IN2	r14
%define IN4	r15
%define IN6	LEN

%define XDATA0		xmm0
%define XDATA1		xmm1
%define XDATA2		xmm2
%define XDATA3		xmm3
%define XDATA4		xmm4
%define XDATA5		xmm5
%define XDATA6		xmm6
%define XDATA7		xmm7

%define XKEY0_3		xmm8
%define XKEY1_4		xmm9
%define XKEY2_5		xmm10
%define XKEY3_6		xmm11
%define XKEY4_7		xmm12
%define XKEY5_8		xmm13
%define XKEY6_9		xmm14
%define XTMP		xmm15

%macro AES_CBC_X8 6-7
%define %%MODE          %1      ;; [in] CBC_XCBC_MAC or CBC
%define %%NROUNDS       %2      ;; [in] number of AES rounds (9 - AES128, 11 - AES192, AES256 - 13)
%define %%OFFSET        %3      ;; [in] numeric constant index increment
%define %%ARG_IV        %4      ;; [in] pointer to array with IV pointers
%define %%ARG_KEYS      %5      ;; [in] pointer to array with expanded key pointers
%define %%ARG_IN        %6      ;; [in] pointer to array with input pointers (plain text)
%define %%ARG_OUT       %7      ;; [in] pointer to array with destination pointers (cipher text)

        sub	rsp, STACK_size
	mov	[GPR_SAVE_AREA + 8*0], rbp
%ifidn %%MODE, CBC_XCBC_MAC
	mov	[GPR_SAVE_AREA + 8*1], rbx
	mov	[GPR_SAVE_AREA + 8*2], r12
	mov	[GPR_SAVE_AREA + 8*3], r13
	mov	[GPR_SAVE_AREA + 8*4], r14
	mov	[GPR_SAVE_AREA + 8*5], r15
%ifndef LINUX
	mov	[GPR_SAVE_AREA + 8*6], rsi
	mov	[GPR_SAVE_AREA + 8*7], rdi
%endif
%endif

	mov	IDX, %%OFFSET
	mov	[LEN_AREA], LEN

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	mov	        IN0,	[%%ARG_IN + 8*0]
	mov	        IN2,	[%%ARG_IN + 8*2]
	mov	        IN4,	[%%ARG_IN + 8*4]
	mov	        IN6,	[%%ARG_IN + 8*6]

	mov		TMP, [%%ARG_IN + 8*1]
	vmovdqu		XDATA0, [IN0]		; load first block of plain text
	vmovdqu		XDATA1, [TMP]		; load first block of plain text
	mov		TMP, [%%ARG_IN + 8*3]
	vmovdqu		XDATA2, [IN2]		; load first block of plain text
	vmovdqu		XDATA3, [TMP]		; load first block of plain text
	mov		TMP, [%%ARG_IN + 8*5]
	vmovdqu		XDATA4, [IN4]		; load first block of plain text
	vmovdqu		XDATA5, [TMP]		; load first block of plain text
	mov		TMP, [%%ARG_IN + 8*7]
	vmovdqu		XDATA6, [IN6]		; load first block of plain text
	vmovdqu		XDATA7, [TMP]		; load first block of plain text

	vpxor		XDATA0, XDATA0, [%%ARG_IV + 16*0]  ; plaintext XOR IV
	vpxor		XDATA1, XDATA1, [%%ARG_IV + 16*1]  ; plaintext XOR IV
	vpxor		XDATA2, XDATA2, [%%ARG_IV + 16*2]  ; plaintext XOR IV
	vpxor		XDATA3, XDATA3, [%%ARG_IV + 16*3]  ; plaintext XOR IV
	vpxor		XDATA4, XDATA4, [%%ARG_IV + 16*4]  ; plaintext XOR IV
	vpxor		XDATA5, XDATA5, [%%ARG_IV + 16*5]  ; plaintext XOR IV
	vpxor		XDATA6, XDATA6, [%%ARG_IV + 16*6]  ; plaintext XOR IV
	vpxor		XDATA7, XDATA7, [%%ARG_IV + 16*7]  ; plaintext XOR IV

	mov		KEYS0,	[%%ARG_KEYS + 8*0]
	mov		KEYS1,	[%%ARG_KEYS + 8*1]
	mov		KEYS2,	[%%ARG_KEYS + 8*2]
	mov		KEYS3,	[%%ARG_KEYS + 8*3]
	mov		KEYS4,	[%%ARG_KEYS + 8*4]
	mov		KEYS5,	[%%ARG_KEYS + 8*5]
	mov		KEYS6,	[%%ARG_KEYS + 8*6]
	mov		KEYS7,	[%%ARG_KEYS + 8*7]

	vpxor		XDATA0, XDATA0, [KEYS0 + 16*0]		; 0. ARK
	vpxor		XDATA1, XDATA1, [KEYS1 + 16*0]		; 0. ARK
	vpxor		XDATA2, XDATA2, [KEYS2 + 16*0]		; 0. ARK
	vpxor		XDATA3, XDATA3, [KEYS3 + 16*0]		; 0. ARK
	vpxor		XDATA4, XDATA4, [KEYS4 + 16*0]		; 0. ARK
	vpxor		XDATA5, XDATA5, [KEYS5 + 16*0]		; 0. ARK
	vpxor		XDATA6, XDATA6, [KEYS6 + 16*0]		; 0. ARK
	vpxor		XDATA7, XDATA7, [KEYS7 + 16*0]		; 0. ARK

	vaesenc		XDATA0, [KEYS0 + 16*1]	; 1. ENC
	vaesenc		XDATA1, [KEYS1 + 16*1]	; 1. ENC
	vaesenc		XDATA2, [KEYS2 + 16*1]	; 1. ENC
	vaesenc		XDATA3, [KEYS3 + 16*1]	; 1. ENC
	vaesenc		XDATA4, [KEYS4 + 16*1]	; 1. ENC
	vaesenc		XDATA5, [KEYS5 + 16*1]	; 1. ENC
	vaesenc		XDATA6, [KEYS6 + 16*1]	; 1. ENC
	vaesenc		XDATA7, [KEYS7 + 16*1]	; 1. ENC

	vmovdqa		XKEY0_3, [KEYS0 + 16*3]	; load round 3 key

	vaesenc		XDATA0, [KEYS0 + 16*2]	; 2. ENC
	vaesenc		XDATA1, [KEYS1 + 16*2]	; 2. ENC
	vaesenc		XDATA2, [KEYS2 + 16*2]	; 2. ENC
	vaesenc		XDATA3, [KEYS3 + 16*2]	; 2. ENC
	vaesenc		XDATA4, [KEYS4 + 16*2]	; 2. ENC
	vaesenc		XDATA5, [KEYS5 + 16*2]	; 2. ENC
	vaesenc		XDATA6, [KEYS6 + 16*2]	; 2. ENC
	vaesenc		XDATA7, [KEYS7 + 16*2]	; 2. ENC

	vmovdqa		XKEY1_4, [KEYS1 + 16*4]	; load round 4 key

	vaesenc		XDATA0, XKEY0_3       	; 3. ENC
	vaesenc		XDATA1, [KEYS1 + 16*3]	; 3. ENC
	vaesenc		XDATA2, [KEYS2 + 16*3]	; 3. ENC
	vaesenc		XDATA3, [KEYS3 + 16*3]	; 3. ENC
	vaesenc		XDATA4, [KEYS4 + 16*3]	; 3. ENC
	vaesenc		XDATA5, [KEYS5 + 16*3]	; 3. ENC
	vaesenc		XDATA6, [KEYS6 + 16*3]	; 3. ENC
	vaesenc		XDATA7, [KEYS7 + 16*3]	; 3. ENC

	vaesenc		XDATA0, [KEYS0 + 16*4]	; 4. ENC
	vmovdqa		XKEY2_5, [KEYS2 + 16*5]	; load round 5 key
	vaesenc		XDATA1, XKEY1_4       	; 4. ENC
	vaesenc		XDATA2, [KEYS2 + 16*4]	; 4. ENC
	vaesenc		XDATA3, [KEYS3 + 16*4]	; 4. ENC
	vaesenc		XDATA4, [KEYS4 + 16*4]	; 4. ENC
	vaesenc		XDATA5, [KEYS5 + 16*4]	; 4. ENC
	vaesenc		XDATA6, [KEYS6 + 16*4]	; 4. ENC
	vaesenc		XDATA7, [KEYS7 + 16*4]	; 4. ENC

	vaesenc		XDATA0, [KEYS0 + 16*5]	; 5. ENC
	vaesenc		XDATA1, [KEYS1 + 16*5]	; 5. ENC
	vmovdqa		XKEY3_6, [KEYS3 + 16*6]	; load round 6 key
	vaesenc		XDATA2, XKEY2_5       	; 5. ENC
	vaesenc		XDATA3, [KEYS3 + 16*5]	; 5. ENC
	vaesenc		XDATA4, [KEYS4 + 16*5]	; 5. ENC
	vaesenc		XDATA5, [KEYS5 + 16*5]	; 5. ENC
	vaesenc		XDATA6, [KEYS6 + 16*5]	; 5. ENC
	vaesenc		XDATA7, [KEYS7 + 16*5]	; 5. ENC

	vaesenc		XDATA0, [KEYS0 + 16*6]	; 6. ENC
	vaesenc		XDATA1, [KEYS1 + 16*6]	; 6. ENC
	vaesenc		XDATA2, [KEYS2 + 16*6]	; 6. ENC
	vmovdqa		XKEY4_7, [KEYS4 + 16*7]	; load round 7 key
	vaesenc		XDATA3, XKEY3_6       	; 6. ENC
	vaesenc		XDATA4, [KEYS4 + 16*6]	; 6. ENC
	vaesenc		XDATA5, [KEYS5 + 16*6]	; 6. ENC
	vaesenc		XDATA6, [KEYS6 + 16*6]	; 6. ENC
	vaesenc		XDATA7, [KEYS7 + 16*6]	; 6. ENC

	vaesenc		XDATA0, [KEYS0 + 16*7]	; 7. ENC
	vaesenc		XDATA1, [KEYS1 + 16*7]	; 7. ENC
	vaesenc		XDATA2, [KEYS2 + 16*7]	; 7. ENC
	vaesenc		XDATA3, [KEYS3 + 16*7]	; 7. ENC
	vmovdqa		XKEY5_8, [KEYS5 + 16*8]	; load round 8 key
	vaesenc		XDATA4, XKEY4_7       	; 7. ENC
	vaesenc		XDATA5, [KEYS5 + 16*7]	; 7. ENC
	vaesenc		XDATA6, [KEYS6 + 16*7]	; 7. ENC
	vaesenc		XDATA7, [KEYS7 + 16*7]	; 7. ENC

	vaesenc		XDATA0, [KEYS0 + 16*8]	; 8. ENC
	vaesenc		XDATA1, [KEYS1 + 16*8]	; 8. ENC
	vaesenc		XDATA2, [KEYS2 + 16*8]	; 8. ENC
	vaesenc		XDATA3, [KEYS3 + 16*8]	; 8. ENC
	vaesenc		XDATA4, [KEYS4 + 16*8]	; 8. ENC
	vmovdqa		XKEY6_9, [KEYS6 + 16*9]	; load round 9 key
	vaesenc		XDATA5, XKEY5_8       	; 8. ENC
	vaesenc		XDATA6, [KEYS6 + 16*8]	; 8. ENC
	vaesenc		XDATA7, [KEYS7 + 16*8]	; 8. ENC

	vaesenc		XDATA0, [KEYS0 + 16*9]	; 9. ENC
	vaesenc		XDATA1, [KEYS1 + 16*9]	; 9. ENC
	vaesenc		XDATA2, [KEYS2 + 16*9]	; 9. ENC
	vaesenc		XDATA3, [KEYS3 + 16*9]	; 9. ENC
	vaesenc		XDATA4, [KEYS4 + 16*9]	; 9. ENC
	vaesenc		XDATA5, [KEYS5 + 16*9]	; 9. ENC
%ifnidn %%MODE, CBC_XCBC_MAC
	mov		TMP, [%%ARG_OUT + 8*0]
%endif
	vaesenc		XDATA6, XKEY6_9       	; 9. ENC
	vaesenc		XDATA7, [KEYS7 + 16*9]	; 9. ENC

%assign i (%%NROUNDS - 9)
%assign j 10
%rep i
	vaesenc		XDATA0, [KEYS0 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA1, [KEYS1 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA2, [KEYS2 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA3, [KEYS3 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA4, [KEYS4 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA5, [KEYS5 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA6, [KEYS6 + 16*j]  ; 10,..13 ENC
	vaesenc		XDATA7, [KEYS7 + 16*j]	; 10,..13 ENC
%assign j (j + 1)
%endrep

        vaesenclast	XDATA0, [KEYS0 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA1, [KEYS1 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA2, [KEYS2 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA3, [KEYS3 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA4, [KEYS4 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA5, [KEYS5 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA6, [KEYS6 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA7, [KEYS7 + 16*j]	; 10/12/14 ENC

%ifnidn %%MODE, CBC_XCBC_MAC
	vmovdqu		[TMP], XDATA0		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*1]
	vmovdqu		[TMP], XDATA1		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*2]
	vmovdqu		[TMP], XDATA2		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*3]
	vmovdqu		[TMP], XDATA3		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*4]
	vmovdqu		[TMP], XDATA4		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*5]
	vmovdqu		[TMP], XDATA5		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*6]
	vmovdqu		[TMP], XDATA6		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*7]
	vmovdqu		[TMP], XDATA7		; write back ciphertext
%endif
	cmp		[LEN_AREA], IDX
	jle		%%_done

align   32

%%_main_loop:
	mov		TMP, [%%ARG_IN + 8*1]
	vpxor		XDATA0, XDATA0, [IN0 + IDX]	; load next block of plain text
	vpxor		XDATA1, XDATA1, [TMP + IDX]	; load next block of plain text
	mov		TMP, [%%ARG_IN + 8*3]
	vpxor		XDATA2, XDATA2, [IN2 + IDX]	; load next block of plain text
	vpxor		XDATA3, XDATA3, [TMP + IDX]	; load next block of plain text
	mov		TMP, [%%ARG_IN + 8*5]
	vpxor		XDATA4, XDATA4, [IN4 + IDX]	; load next block of plain text
	vpxor		XDATA5, XDATA5, [TMP + IDX]	; load next block of plain text
	mov		TMP, [%%ARG_IN + 8*7]
	vpxor		XDATA6, XDATA6, [IN6 + IDX]	; load next block of plain text
	vpxor		XDATA7, XDATA7, [TMP + IDX]	; load next block of plain text

	vpxor		XDATA0, XDATA0, [KEYS0 + 16*0]		; 0. ARK
	vpxor		XDATA1, XDATA1, [KEYS1 + 16*0]		; 0. ARK
	vpxor		XDATA2, XDATA2, [KEYS2 + 16*0]		; 0. ARK
	vpxor		XDATA3, XDATA3, [KEYS3 + 16*0]		; 0. ARK
	vpxor		XDATA4, XDATA4, [KEYS4 + 16*0]		; 0. ARK
	vpxor		XDATA5, XDATA5, [KEYS5 + 16*0]		; 0. ARK
	vpxor		XDATA6, XDATA6, [KEYS6 + 16*0]		; 0. ARK
	vpxor		XDATA7, XDATA7, [KEYS7 + 16*0]		; 0. ARK

	vaesenc		XDATA0, [KEYS0 + 16*1]	; 1. ENC
	vaesenc		XDATA1, [KEYS1 + 16*1]	; 1. ENC
	vaesenc		XDATA2, [KEYS2 + 16*1]	; 1. ENC
	vaesenc		XDATA3, [KEYS3 + 16*1]	; 1. ENC
	vaesenc		XDATA4, [KEYS4 + 16*1]	; 1. ENC
	vaesenc		XDATA5, [KEYS5 + 16*1]	; 1. ENC
	vaesenc		XDATA6, [KEYS6 + 16*1]	; 1. ENC
	vaesenc		XDATA7, [KEYS7 + 16*1]	; 1. ENC

	vaesenc		XDATA0, [KEYS0 + 16*2]	; 2. ENC
	vaesenc		XDATA1, [KEYS1 + 16*2]	; 2. ENC
	vaesenc		XDATA2, [KEYS2 + 16*2]	; 2. ENC
	vaesenc		XDATA3, [KEYS3 + 16*2]	; 2. ENC
	vaesenc		XDATA4, [KEYS4 + 16*2]	; 2. ENC
	vaesenc		XDATA5, [KEYS5 + 16*2]	; 2. ENC
	vaesenc		XDATA6, [KEYS6 + 16*2]	; 2. ENC
	vaesenc		XDATA7, [KEYS7 + 16*2]	; 2. ENC

	vaesenc		XDATA0, XKEY0_3       	; 3. ENC
	vaesenc		XDATA1, [KEYS1 + 16*3]	; 3. ENC
	vaesenc		XDATA2, [KEYS2 + 16*3]	; 3. ENC
	vaesenc		XDATA3, [KEYS3 + 16*3]	; 3. ENC
	vaesenc		XDATA4, [KEYS4 + 16*3]	; 3. ENC
	vaesenc		XDATA5, [KEYS5 + 16*3]	; 3. ENC
	vaesenc		XDATA6, [KEYS6 + 16*3]	; 3. ENC
	vaesenc		XDATA7, [KEYS7 + 16*3]	; 3. ENC

	vaesenc		XDATA0, [KEYS0 + 16*4]	; 4. ENC
	vaesenc		XDATA1, XKEY1_4       	; 4. ENC
	vaesenc		XDATA2, [KEYS2 + 16*4]	; 4. ENC
	vaesenc		XDATA3, [KEYS3 + 16*4]	; 4. ENC
	vaesenc		XDATA4, [KEYS4 + 16*4]	; 4. ENC
	vaesenc		XDATA5, [KEYS5 + 16*4]	; 4. ENC
	vaesenc		XDATA6, [KEYS6 + 16*4]	; 4. ENC
	vaesenc		XDATA7, [KEYS7 + 16*4]	; 4. ENC

	vaesenc		XDATA0, [KEYS0 + 16*5]	; 5. ENC
	vaesenc		XDATA1, [KEYS1 + 16*5]	; 5. ENC
	vaesenc		XDATA2, XKEY2_5       	; 5. ENC
	vaesenc		XDATA3, [KEYS3 + 16*5]	; 5. ENC
	vaesenc		XDATA4, [KEYS4 + 16*5]	; 5. ENC
	vaesenc		XDATA5, [KEYS5 + 16*5]	; 5. ENC
	vaesenc		XDATA6, [KEYS6 + 16*5]	; 5. ENC
	vaesenc		XDATA7, [KEYS7 + 16*5]	; 5. ENC

	vaesenc		XDATA0, [KEYS0 + 16*6]	; 6. ENC
	vaesenc		XDATA1, [KEYS1 + 16*6]	; 6. ENC
	vaesenc		XDATA2, [KEYS2 + 16*6]	; 6. ENC
	vaesenc		XDATA3, XKEY3_6       	; 6. ENC
	vaesenc		XDATA4, [KEYS4 + 16*6]	; 6. ENC
	vaesenc		XDATA5, [KEYS5 + 16*6]	; 6. ENC
	vaesenc		XDATA6, [KEYS6 + 16*6]	; 6. ENC
	vaesenc		XDATA7, [KEYS7 + 16*6]	; 6. ENC

	vaesenc		XDATA0, [KEYS0 + 16*7]	; 7. ENC
	vaesenc		XDATA1, [KEYS1 + 16*7]	; 7. ENC
	vaesenc		XDATA2, [KEYS2 + 16*7]	; 7. ENC
	vaesenc		XDATA3, [KEYS3 + 16*7]	; 7. ENC
	vaesenc		XDATA4, XKEY4_7       	; 7. ENC
	vaesenc		XDATA5, [KEYS5 + 16*7]	; 7. ENC
	vaesenc		XDATA6, [KEYS6 + 16*7]	; 7. ENC
	vaesenc		XDATA7, [KEYS7 + 16*7]	; 7. ENC

	vaesenc		XDATA0, [KEYS0 + 16*8]	; 8. ENC
	vaesenc		XDATA1, [KEYS1 + 16*8]	; 8. ENC
	vaesenc		XDATA2, [KEYS2 + 16*8]	; 8. ENC
	vaesenc		XDATA3, [KEYS3 + 16*8]	; 8. ENC
	vaesenc		XDATA4, [KEYS4 + 16*8]	; 8. ENC
	vaesenc		XDATA5, XKEY5_8       	; 8. ENC
	vaesenc		XDATA6, [KEYS6 + 16*8]	; 8. ENC
	vaesenc		XDATA7, [KEYS7 + 16*8]	; 8. ENC

	vaesenc		XDATA0, [KEYS0 + 16*9]	; 9. ENC
	vaesenc		XDATA1, [KEYS1 + 16*9]	; 9. ENC
	vaesenc		XDATA2, [KEYS2 + 16*9]	; 9. ENC
	vaesenc		XDATA3, [KEYS3 + 16*9]	; 9. ENC
	vaesenc		XDATA4, [KEYS4 + 16*9]	; 9. ENC
	vaesenc		XDATA5, [KEYS5 + 16*9]	; 9. ENC
%ifnidn %%MODE, CBC_XCBC_MAC
	mov		TMP, [%%ARG_OUT + 8*0]
%endif
	vaesenc		XDATA6, XKEY6_9       	; 9. ENC
	vaesenc		XDATA7, [KEYS7 + 16*9]	; 9. ENC

%assign i (%%NROUNDS - 9)
%assign j 10
%rep i
	vaesenc		XDATA0, [KEYS0 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA1, [KEYS1 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA2, [KEYS2 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA3, [KEYS3 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA4, [KEYS4 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA5, [KEYS5 + 16*j]	; 10,..13 ENC
	vaesenc		XDATA6, [KEYS6 + 16*j]  ; 10,..13 ENC
	vaesenc		XDATA7, [KEYS7 + 16*j]	; 10,..13 ENC
%assign j (j + 1)
%endrep

        vaesenclast	XDATA0, [KEYS0 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA1, [KEYS1 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA2, [KEYS2 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA3, [KEYS3 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA4, [KEYS4 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA5, [KEYS5 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA6, [KEYS6 + 16*j]	; 10/12/14 ENC
	vaesenclast	XDATA7, [KEYS7 + 16*j]	; 10/12/14 ENC

%ifnidn %%MODE, CBC_XCBC_MAC
        ;; no ciphertext write back for CBC-MAC
	vmovdqu		[TMP + IDX], XDATA0		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*1]
	vmovdqu		[TMP + IDX], XDATA1		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*2]
	vmovdqu		[TMP + IDX], XDATA2		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*3]
	vmovdqu		[TMP + IDX], XDATA3		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*4]
	vmovdqu		[TMP + IDX], XDATA4		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*5]
	vmovdqu		[TMP + IDX], XDATA5		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*6]
	vmovdqu		[TMP + IDX], XDATA6		; write back ciphertext
	mov		TMP, [%%ARG_OUT + 8*7]
	vmovdqu		[TMP + IDX], XDATA7		; write back ciphertext
%endif
	add	IDX, %%OFFSET
	cmp	[LEN_AREA], IDX
	ja	%%_main_loop

%%_done:
	;; update IV for AES128-CBC / store digest for CBC-MAC
	vmovdqa	[%%ARG_IV + 16*0], XDATA0
	vmovdqa	[%%ARG_IV + 16*1], XDATA1
	vmovdqa	[%%ARG_IV + 16*2], XDATA2
	vmovdqa	[%%ARG_IV + 16*3], XDATA3
	vmovdqa	[%%ARG_IV + 16*4], XDATA4
	vmovdqa	[%%ARG_IV + 16*5], XDATA5
	vmovdqa	[%%ARG_IV + 16*6], XDATA6
	vmovdqa	[%%ARG_IV + 16*7], XDATA7

	;; update IN and OUT
	vmovd	xmm0, [LEN_AREA]
	vpshufd	xmm0, xmm0, 0x44
	vpaddq	xmm1, xmm0, [%%ARG_IN + 16*0]
	vpaddq	xmm2, xmm0, [%%ARG_IN + 16*1]
	vpaddq	xmm3, xmm0, [%%ARG_IN + 16*2]
	vpaddq	xmm4, xmm0, [%%ARG_IN + 16*3]
	vmovdqa	[%%ARG_IN + 16*0], xmm1
	vmovdqa	[%%ARG_IN + 16*1], xmm2
	vmovdqa	[%%ARG_IN + 16*2], xmm3
	vmovdqa	[%%ARG_IN + 16*3], xmm4
%ifnidn %%MODE, CBC_XCBC_MAC
	vpaddq	xmm5, xmm0, [%%ARG_OUT + 16*0]
	vpaddq	xmm6, xmm0, [%%ARG_OUT + 16*1]
	vpaddq	xmm7, xmm0, [%%ARG_OUT + 16*2]
	vpaddq	xmm8, xmm0, [%%ARG_OUT + 16*3]
	vmovdqa	[%%ARG_OUT + 16*0], xmm5
	vmovdqa	[%%ARG_OUT + 16*1], xmm6
	vmovdqa	[%%ARG_OUT + 16*2], xmm7
	vmovdqa	[%%ARG_OUT + 16*3], xmm8
%endif

        ;; XMMs are saved at a higher level
	mov	rbp, [GPR_SAVE_AREA + 8*0]
%ifidn %%MODE, CBC_XCBC_MAC
	mov	rbx, [GPR_SAVE_AREA + 8*1]
	mov	r12, [GPR_SAVE_AREA + 8*2]
	mov	r13, [GPR_SAVE_AREA + 8*3]
	mov	r14, [GPR_SAVE_AREA + 8*4]
	mov	r15, [GPR_SAVE_AREA + 8*5]
%ifndef LINUX
	mov	rsi, [GPR_SAVE_AREA + 8*6]
	mov	rdi, [GPR_SAVE_AREA + 8*7]
%endif
%endif

	add	rsp, STACK_size

%ifdef SAFE_DATA
	clear_all_xmms_avx_asm
%endif ;; SAFE_DATA

%endmacro

mksection stack-noexec
