;;
;; Copyright (c) 2012-2020, Intel Corporation
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

;;; routine to do 128 bit AES XCBC
;;; process 4 buffers at a time, single data structure as input
;;; Updates In pointer at end

;; clobbers all registers except for ARG1 and rbp

%include "include/os.asm"
%include "mb_mgr_datastruct.asm"
%include "include/clear_regs.asm"

%ifndef AES_XCBC_X4
%define AES_XCBC_X4 aes_xcbc_mac_128_x4
%endif

%define	MOVDQ movdqu ;; assume buffers not aligned
%macro pxor2 2
	MOVDQ	XTMP, %2
	pxor	%1, XTMP
%endm

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; struct AES_XCBC_ARGS_x8 {
;;     void*    in[8];
;;     UINT128* keys[8];
;;     UINT128  ICV[8];
;; }
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_xcbc_mac_128_x4(AES_XCBC_ARGS_x8 *args, UINT64 len);
;; arg 1: ARG : addr of AES_XCBC_ARGS_x8 structure
;; arg 2: LEN : len (in units of bytes)

%ifdef LINUX
%define ARG	rdi
%define LEN	rsi
%define REG3	rcx
%define REG4	rdx
%else
%define ARG	rcx
%define LEN	rdx
%define REG3	rsi
%define REG4	rdi
%endif

%define IDX	rax

%define IN0	r8
%define KEYS0	rbx
%define OUT0	r9

%define IN1	r10
%define KEYS1	REG3
%define OUT1	r11

%define IN2	r12
%define KEYS2	REG4
%define OUT2	r13

%define IN3	r14
%define KEYS3	rbp
%define OUT3	r15


%define XDATA0		xmm0
%define XDATA1		xmm1
%define XDATA2		xmm2
%define XDATA3		xmm3

%define XKEY0_3		xmm4
%define XKEY0_6		[KEYS0 + 16*6]
%define XTMP		xmm5
%define XKEY0_9		xmm6

%define XKEY1_3		xmm7
%define XKEY1_6		xmm8
%define XKEY1_9		xmm9

%define XKEY2_3		xmm10
%define XKEY2_6		xmm11
%define XKEY2_9		xmm12

%define XKEY3_3		xmm13
%define XKEY3_6		xmm14
%define XKEY3_9		xmm15

section .text

MKGLOBAL(AES_XCBC_X4,function,internal)
AES_XCBC_X4:

	push	rbp

	mov	IDX, 16

	mov	IN0,	[ARG + _aesxcbcarg_in + 8*0]
	mov	IN1,	[ARG + _aesxcbcarg_in + 8*1]
	mov	IN2,	[ARG + _aesxcbcarg_in + 8*2]
	mov	IN3,	[ARG + _aesxcbcarg_in + 8*3]

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	MOVDQ		XDATA0, [IN0]		; load first block of plain text
	MOVDQ		XDATA1, [IN1]		; load first block of plain text
	MOVDQ		XDATA2, [IN2]		; load first block of plain text
	MOVDQ		XDATA3, [IN3]		; load first block of plain text

	mov		KEYS0,	[ARG + _aesxcbcarg_keys + 8*0]
	mov		KEYS1,	[ARG + _aesxcbcarg_keys + 8*1]
	mov		KEYS2,	[ARG + _aesxcbcarg_keys + 8*2]
	mov		KEYS3,	[ARG + _aesxcbcarg_keys + 8*3]

	pxor		XDATA0, [ARG + _aesxcbcarg_ICV + 16*0] ; plaintext XOR ICV
	pxor		XDATA1, [ARG + _aesxcbcarg_ICV + 16*1] ; plaintext XOR ICV
	pxor		XDATA2, [ARG + _aesxcbcarg_ICV + 16*2] ; plaintext XOR ICV
	pxor		XDATA3, [ARG + _aesxcbcarg_ICV + 16*3] ; plaintext XOR ICV

	pxor		XDATA0, [KEYS0 + 16*0]		; 0. ARK
	pxor		XDATA1, [KEYS1 + 16*0]		; 0. ARK
	pxor		XDATA2, [KEYS2 + 16*0]		; 0. ARK
	pxor		XDATA3, [KEYS3 + 16*0]		; 0. ARK

	aesenc		XDATA0, [KEYS0 + 16*1]	; 1. ENC
	aesenc		XDATA1, [KEYS1 + 16*1]	; 1. ENC
	aesenc		XDATA2, [KEYS2 + 16*1]	; 1. ENC
	aesenc		XDATA3, [KEYS3 + 16*1]	; 1. ENC

	aesenc		XDATA0, [KEYS0 + 16*2]	; 2. ENC
	aesenc		XDATA1, [KEYS1 + 16*2]	; 2. ENC
	aesenc		XDATA2, [KEYS2 + 16*2]	; 2. ENC
	aesenc		XDATA3, [KEYS3 + 16*2]	; 2. ENC

	movdqa		XKEY0_3, [KEYS0 + 16*3]	; load round 3 key
	movdqa		XKEY1_3, [KEYS1 + 16*3]	; load round 3 key
	movdqa		XKEY2_3, [KEYS2 + 16*3]	; load round 3 key
	movdqa		XKEY3_3, [KEYS3 + 16*3]	; load round 3 key

	aesenc		XDATA0, XKEY0_3		; 3. ENC
	aesenc		XDATA1, XKEY1_3		; 3. ENC
	aesenc		XDATA2, XKEY2_3		; 3. ENC
	aesenc		XDATA3, XKEY3_3		; 3. ENC

	aesenc		XDATA0, [KEYS0 + 16*4]	; 4. ENC
	aesenc		XDATA1, [KEYS1 + 16*4]	; 4. ENC
	aesenc		XDATA2, [KEYS2 + 16*4]	; 4. ENC
	aesenc		XDATA3, [KEYS3 + 16*4]	; 4. ENC

	aesenc		XDATA0, [KEYS0 + 16*5]	; 5. ENC
	aesenc		XDATA1, [KEYS1 + 16*5]	; 5. ENC
	aesenc		XDATA2, [KEYS2 + 16*5]	; 5. ENC
	aesenc		XDATA3, [KEYS3 + 16*5]	; 5. ENC

	movdqa		XKEY1_6, [KEYS1 + 16*6]	; load round 6 key
	movdqa		XKEY2_6, [KEYS2 + 16*6]	; load round 6 key
	movdqa		XKEY3_6, [KEYS3 + 16*6]	; load round 6 key

	aesenc		XDATA0, XKEY0_6		; 6. ENC
	aesenc		XDATA1, XKEY1_6		; 6. ENC
	aesenc		XDATA2, XKEY2_6		; 6. ENC
	aesenc		XDATA3, XKEY3_6		; 6. ENC

	aesenc		XDATA0, [KEYS0 + 16*7]	; 7. ENC
	aesenc		XDATA1, [KEYS1 + 16*7]	; 7. ENC
	aesenc		XDATA2, [KEYS2 + 16*7]	; 7. ENC
	aesenc		XDATA3, [KEYS3 + 16*7]	; 7. ENC

	aesenc		XDATA0, [KEYS0 + 16*8]	; 8. ENC
	aesenc		XDATA1, [KEYS1 + 16*8]	; 8. ENC
	aesenc		XDATA2, [KEYS2 + 16*8]	; 8. ENC
	aesenc		XDATA3, [KEYS3 + 16*8]	; 8. ENC

	movdqa		XKEY0_9, [KEYS0 + 16*9]	; load round 9 key
	movdqa		XKEY1_9, [KEYS1 + 16*9]	; load round 9 key
	movdqa		XKEY2_9, [KEYS2 + 16*9]	; load round 9 key
	movdqa		XKEY3_9, [KEYS3 + 16*9]	; load round 9 key

	aesenc		XDATA0, XKEY0_9		; 9. ENC
	aesenc		XDATA1, XKEY1_9		; 9. ENC
	aesenc		XDATA2, XKEY2_9		; 9. ENC
	aesenc		XDATA3, XKEY3_9		; 9. ENC

	aesenclast	XDATA0, [KEYS0 + 16*10]	; 10. ENC
	aesenclast	XDATA1, [KEYS1 + 16*10]	; 10. ENC
	aesenclast	XDATA2, [KEYS2 + 16*10]	; 10. ENC
	aesenclast	XDATA3, [KEYS3 + 16*10]	; 10. ENC

	cmp		LEN, IDX
	je		done

main_loop:
	pxor2		XDATA0, [IN0 + IDX]	; plaintext XOR ICV
	pxor2		XDATA1, [IN1 + IDX]	; plaintext XOR ICV
	pxor2		XDATA2, [IN2 + IDX]	; plaintext XOR ICV
	pxor2		XDATA3, [IN3 + IDX]	; plaintext XOR ICV

	pxor		XDATA0, [KEYS0 + 16*0] 	; 0. ARK
	pxor		XDATA1, [KEYS1 + 16*0] 	; 0. ARK
	pxor		XDATA2, [KEYS2 + 16*0] 	; 0. ARK
	pxor		XDATA3, [KEYS3 + 16*0] 	; 0. ARK

	aesenc		XDATA0, [KEYS0 + 16*1]	; 1. ENC
	aesenc		XDATA1, [KEYS1 + 16*1]	; 1. ENC
	aesenc		XDATA2, [KEYS2 + 16*1]	; 1. ENC
	aesenc		XDATA3, [KEYS3 + 16*1]	; 1. ENC

	aesenc		XDATA0, [KEYS0 + 16*2]	; 2. ENC
	aesenc		XDATA1, [KEYS1 + 16*2]	; 2. ENC
	aesenc		XDATA2, [KEYS2 + 16*2]	; 2. ENC
	aesenc		XDATA3, [KEYS3 + 16*2]	; 2. ENC

	aesenc		XDATA0, XKEY0_3		; 3. ENC
	aesenc		XDATA1, XKEY1_3		; 3. ENC
	aesenc		XDATA2, XKEY2_3		; 3. ENC
	aesenc		XDATA3, XKEY3_3		; 3. ENC

	aesenc		XDATA0, [KEYS0 + 16*4]	; 4. ENC
	aesenc		XDATA1, [KEYS1 + 16*4]	; 4. ENC
	aesenc		XDATA2, [KEYS2 + 16*4]	; 4. ENC
	aesenc		XDATA3, [KEYS3 + 16*4]	; 4. ENC

	aesenc		XDATA0, [KEYS0 + 16*5]	; 5. ENC
	aesenc		XDATA1, [KEYS1 + 16*5]	; 5. ENC
	aesenc		XDATA2, [KEYS2 + 16*5]	; 5. ENC
	aesenc		XDATA3, [KEYS3 + 16*5]	; 5. ENC

	aesenc		XDATA0, XKEY0_6		; 6. ENC
	aesenc		XDATA1, XKEY1_6		; 6. ENC
	aesenc		XDATA2, XKEY2_6		; 6. ENC
	aesenc		XDATA3, XKEY3_6		; 6. ENC

	aesenc		XDATA0, [KEYS0 + 16*7]	; 7. ENC
	aesenc		XDATA1, [KEYS1 + 16*7]	; 7. ENC
	aesenc		XDATA2, [KEYS2 + 16*7]	; 7. ENC
	aesenc		XDATA3, [KEYS3 + 16*7]	; 7. ENC

	aesenc		XDATA0, [KEYS0 + 16*8]	; 8. ENC
	aesenc		XDATA1, [KEYS1 + 16*8]	; 8. ENC
	aesenc		XDATA2, [KEYS2 + 16*8]	; 8. ENC
	aesenc		XDATA3, [KEYS3 + 16*8]	; 8. ENC

	aesenc		XDATA0, XKEY0_9		; 9. ENC
	aesenc		XDATA1, XKEY1_9		; 9. ENC
	aesenc		XDATA2, XKEY2_9		; 9. ENC
	aesenc		XDATA3, XKEY3_9		; 9. ENC

	aesenclast	XDATA0, [KEYS0 + 16*10]	; 10. ENC
	aesenclast	XDATA1, [KEYS1 + 16*10]	; 10. ENC
	aesenclast	XDATA2, [KEYS2 + 16*10]	; 10. ENC
	aesenclast	XDATA3, [KEYS3 + 16*10]	; 10. ENC

	add	IDX, 16
	cmp	LEN, IDX
	jne	main_loop

done:
	;; update ICV
	movdqa	[ARG + _aesxcbcarg_ICV + 16*0], XDATA0
	movdqa	[ARG + _aesxcbcarg_ICV + 16*1], XDATA1
	movdqa	[ARG + _aesxcbcarg_ICV + 16*2], XDATA2
	movdqa	[ARG + _aesxcbcarg_ICV + 16*3], XDATA3

	;; update IN
	add	IN0, LEN
	mov	[ARG + _aesxcbcarg_in + 8*0], IN0
	add	IN1, LEN
	mov	[ARG + _aesxcbcarg_in + 8*1], IN1
	add	IN2, LEN
	mov	[ARG + _aesxcbcarg_in + 8*2], IN2
	add	IN3, LEN
	mov	[ARG + _aesxcbcarg_in + 8*3], IN3

	pop	rbp

%ifdef SAFE_DATA
	clear_all_xmms_sse_asm
%endif ;; SAFE_DATA

	ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
