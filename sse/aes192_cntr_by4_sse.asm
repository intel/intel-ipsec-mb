;;
;; Copyright (c) 2012-2016, Intel Corporation
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

; routine to do AES192 CNTR enc/decrypt "by4"

; XMM registers are clobbered. Saving/restoring must be done at a higher level

extern byteswap_const, ddq_add_1, ddq_add_2, ddq_add_3, ddq_add_4


%define CONCAT(a,b) a %+ b
%define MOVDQ movdqu

%define xdata0	xmm0
%define xdata1	xmm1
%define xdata2	xmm2
%define xdata3	xmm3
%define xdata4	xmm4
%define xdata5	xmm5
%define xdata6	xmm6
%define xdata7	xmm7
%define xcounter xmm8
%define xbyteswap xmm9
%define xkey0 	xmm10
%define xkey4 	xmm11
%define xkey8 	xmm12
%define xkey12	xmm13
%define xkeyA	xmm14
%define xkeyB	xmm15

%ifdef LINUX
%define p_in	rdi
%define p_IV	rsi
%define p_keys	rdx
%define p_out	rcx
%define num_bytes r8
%else
%define p_in	rcx
%define p_IV	rdx
%define p_keys	r8
%define p_out	r9
%define num_bytes rax
%endif

%define tmp	r10

%macro do_aes_load 1
	do_aes %1, 1
%endmacro

%macro do_aes_noload 1
	do_aes %1, 0
%endmacro


; do_aes num_in_par load_keys
; This increments p_in, but not p_out
%macro do_aes 2
%define %%by %1
%define %%load_keys %2

%if (%%load_keys)
	movdqa	xkey0, [p_keys + 0*16]
%endif

	movdqa	xdata0, xcounter
	pshufb	xdata0, xbyteswap
%assign i 1
%rep (%%by - 1)
	movdqa	CONCAT(xdata,i), xcounter
	paddd	CONCAT(xdata,i), [rel CONCAT(ddq_add_,i)]
	pshufb	CONCAT(xdata,i), xbyteswap
%assign i (i + 1)
%endrep

	movdqa	xkeyA, [p_keys + 1*16]

	pxor	xdata0, xkey0
	paddd	xcounter, [rel CONCAT(ddq_add_,%%by)]
%assign i 1
%rep (%%by - 1)
	pxor	CONCAT(xdata,i), xkey0
%assign i (i + 1)
%endrep

	movdqa	xkeyB, [p_keys + 2*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyA		; key 1
%assign i (i+1)
%endrep

	movdqa	xkeyA, [p_keys + 3*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyB		; key 2
%assign i (i+1)
%endrep

	add	p_in, 16*%%by

%if (%%load_keys)
	movdqa	xkey4, [p_keys + 4*16]
%endif
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyA		; key 3
%assign i (i+1)
%endrep

	movdqa	xkeyA, [p_keys + 5*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkey4		; key 4
%assign i (i+1)
%endrep

	movdqa	xkeyB, [p_keys + 6*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyA		; key 5
%assign i (i+1)
%endrep

	movdqa	xkeyA, [p_keys + 7*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyB		; key 6
%assign i (i+1)
%endrep

%if (%%load_keys)
	movdqa	xkey8, [p_keys + 8*16]
%endif
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyA		; key 7
%assign i (i+1)
%endrep

	movdqa	xkeyA, [p_keys + 9*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkey8		; key 8
%assign i (i+1)
%endrep

	movdqa	xkeyB, [p_keys + 10*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyA		; key 9
%assign i (i+1)
%endrep

	movdqa	xkeyA, [p_keys + 11*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyB		; key 10
%assign i (i+1)
%endrep

%if (%%load_keys)
	movdqa	xkey12, [p_keys + 12*16]
%endif
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyA		; key 11
%assign i (i+1)
%endrep

%assign i 0
%rep %%by
	aesenclast	CONCAT(xdata,i), xkey12	; key 12
%assign i (i+1)
%endrep

%assign i 0
%rep (%%by / 2)
%assign j (i+1)
	MOVDQ	xkeyA, [p_in + i*16 - 16*%%by]
	MOVDQ	xkeyB, [p_in + j*16 - 16*%%by]
	pxor	CONCAT(xdata,i), xkeyA
	pxor	CONCAT(xdata,j), xkeyB
%assign i (i+2)
%endrep
%if (i < %%by)
	MOVDQ	xkeyA, [p_in + i*16 - 16*%%by]
	pxor	CONCAT(xdata,i), xkeyA
%endif

%assign i 0
%rep %%by
	MOVDQ	[p_out  + i*16], CONCAT(xdata,i)
%assign i (i+1)
%endrep
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; aes_cntr_192_sse(void *in, void *IV, void *keys, void *out, UINT64 num_bytes)
global aes_cntr_192_sse:function
aes_cntr_192_sse:

%ifndef LINUX
	mov	num_bytes, [rsp + 8*5]
%endif

	movdqa	xbyteswap, [rel byteswap_const]
	movdqu	xcounter, [p_IV]
	pshufb	xcounter, xbyteswap

	mov	tmp, num_bytes
	and	tmp, 3*16
	jz	mult_of_4_blks

	; 1 <= tmp <= 3
	cmp	tmp, 2*16
	jg	eq3
	je	eq2
eq1:
	do_aes_load	1
	add	p_out, 1*16
	and	num_bytes, ~3*16
	jz	do_return2
	jmp	main_loop2

eq2:	
	do_aes_load	2
	add	p_out, 2*16
	and	num_bytes, ~3*16
	jz	do_return2
	jmp	main_loop2

eq3:	
	do_aes_load	3
	add	p_out, 3*16
	and	num_bytes, ~3*16
	jz	do_return2
	jmp	main_loop2

mult_of_4_blks:
	movdqa	xkey0, [p_keys + 0*16]
	movdqa	xkey4, [p_keys + 4*16]
	movdqa	xkey8, [p_keys + 8*16]
	movdqa	xkey12, [p_keys + 12*16]
	
main_loop2:
	; num_bytes is a multiple of 4 and >0
	do_aes_noload	4
	add	p_out,	4*16
	sub	num_bytes, 4*16
	jne	main_loop2

do_return2:

	; don't return updated IV
;	pshufb	xcounter, xbyteswap
;	movdqu	[p_IV], xcounter
	ret

