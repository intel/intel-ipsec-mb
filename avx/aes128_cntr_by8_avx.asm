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

; routine to do AES128 CNTR enc/decrypt "by8"

; XMM registers are clobbered. Saving/restoring must be done at a higher level
section .data
default rel

global byteswap_const
global ddq_add_1, ddq_add_2, ddq_add_3, ddq_add_4
global ddq_add_5, ddq_add_6, ddq_add_7, ddq_add_8
global CNTR_SHIFT_MASK, CNTR_ALL_F
	
align 16
byteswap_const:	;DDQ 0x000102030405060708090A0B0C0D0E0F
		DQ 0x08090A0B0C0D0E0F, 0x0001020304050607
ddq_add_1:	;DDQ 0x00000000000000000000000000000001
		DQ 0x0000000000000001, 0x0000000000000000
ddq_add_2:	;DDQ 0x00000000000000000000000000000002
		DQ 0x0000000000000002, 0x0000000000000000
ddq_add_3:	;DDQ 0x00000000000000000000000000000003
		DQ 0x0000000000000003, 0x0000000000000000
ddq_add_4:	;DDQ 0x00000000000000000000000000000004
		DQ 0x0000000000000004, 0x0000000000000000
ddq_add_5:	;DDQ 0x00000000000000000000000000000005
		DQ 0x0000000000000005, 0x0000000000000000
ddq_add_6:	;DDQ 0x00000000000000000000000000000006
		DQ 0x0000000000000006, 0x0000000000000000
ddq_add_7:	;DDQ 0x00000000000000000000000000000007
		DQ 0x0000000000000007, 0x0000000000000000
ddq_add_8:	;DDQ 0x00000000000000000000000000000008
		DQ 0x0000000000000008, 0x0000000000000000

; order of these constants should not change.
; more specifically, CNTR_ALL_F should follow CNTR_SHIFT_MASK
CNTR_SHIFT_MASK:	;DDQ	0x0f0e0d0c0b0a09080706050403020100
	DQ	0x0706050403020100, 0x0f0e0d0c0b0a0908
CNTR_ALL_F:		;DDQ	0xffffffffffffffffffffffffffffffff
	DQ	0xffffffffffffffff, 0xffffffffffffffff

section .text

%define CONCAT(a,b) a %+ b
%define VMOVDQ vmovdqu

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
%define xkey3 	xmm11
%define xkey6 	xmm12
%define xkey9	xmm13
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
%define num_bytes r10
%endif

%define tmp	r11

;;;Encryption of a single block for AVX
;;; ENCRYPT_SSE(%%by)
%macro ENCRYPT_AVX 1
%define %%by    %1
        vpshufb	xcounter, xbyteswap
        vmovdqa	xdata0, xcounter
        vpxor   xdata0, [p_keys + 16*0]
%assign i 1
%rep %%by
        aesenc  xdata0, [p_keys + 16*i]
%assign i (i+1)
%endrep
;;; created keystream
        aesenclast xdata0, [p_keys + 16*i]

;;; load target
        add     p_in, num_bytes
        vmovdqu  xdata1, [p_in - 16]
        
        lea     rax, [rel CNTR_SHIFT_MASK + 16]
        sub     rax, num_bytes
        vmovdqu xdata2, [rax]
        vpshufb xdata1, xdata2

%%_last_xor:
;;; xor keystream
        vpxor   xdata0, xdata1 

;;; store
        movq    rax, xdata0     ; mov lower
        cmp     num_bytes, 8
        jle     %%_less_than_8_bytes_left

        mov     [p_out], rax
        add     p_out, 8
        vpsrldq xdata0, 8       ; shift 8byte
        vmovq   rax, xdata0     ; mov lower
        sub     num_bytes, 8
        
%%_less_than_8_bytes_left:
        mov     BYTE [p_out], al
        add     p_out, 1
        shr     rax, 8
        sub     num_bytes, 1
        jne     %%_less_than_8_bytes_left
%endmacro
        
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
	vmovdqa	xkey0, [p_keys + 0*16]
%endif

	vpshufb	xdata0, xcounter, xbyteswap
%assign i 1
%rep (%%by - 1)
	vpaddd	CONCAT(xdata,i), xcounter, [rel CONCAT(ddq_add_,i)]
	vpshufb	CONCAT(xdata,i), CONCAT(xdata,i), xbyteswap
%assign i (i + 1)
%endrep

	vmovdqa	xkeyA, [p_keys + 1*16]

	vpxor	xdata0, xkey0
	vpaddd	xcounter, xcounter, [rel CONCAT(ddq_add_,%%by)]
%assign i 1
%rep (%%by - 1)
	vpxor	CONCAT(xdata,i), xkey0
%assign i (i + 1)
%endrep

	vmovdqa	xkeyB, [p_keys + 2*16]
%assign i 0
%rep %%by
	vaesenc	CONCAT(xdata,i), CONCAT(xdata,i), xkeyA		; key 1
%assign i (i+1)
%endrep

%if (%%load_keys)
	vmovdqa	xkey3, [p_keys + 3*16]
%endif
%assign i 0
%rep %%by
	vaesenc	CONCAT(xdata,i), CONCAT(xdata,i), xkeyB		; key 2
%assign i (i+1)
%endrep

	add	p_in, 16*%%by

	vmovdqa	xkeyB, [p_keys + 4*16]
%assign i 0
%rep %%by
	vaesenc	CONCAT(xdata,i), CONCAT(xdata,i), xkey3		; key 3
%assign i (i+1)
%endrep

	vmovdqa	xkeyA, [p_keys + 5*16]
%assign i 0
%rep %%by
	vaesenc	CONCAT(xdata,i), CONCAT(xdata,i), xkeyB		; key 4
%assign i (i+1)
%endrep

%if (%%load_keys)
	vmovdqa	xkey6, [p_keys + 6*16]
%endif
%assign i 0
%rep %%by
	vaesenc	CONCAT(xdata,i), CONCAT(xdata,i), xkeyA		; key 5
%assign i (i+1)
%endrep

	vmovdqa	xkeyA, [p_keys + 7*16]
%assign i 0
%rep %%by
	vaesenc	CONCAT(xdata,i), CONCAT(xdata,i), xkey6		; key 6
%assign i (i+1)
%endrep

	vmovdqa	xkeyB, [p_keys + 8*16]
%assign i 0
%rep %%by
	vaesenc	CONCAT(xdata,i), CONCAT(xdata,i), xkeyA		; key 7
%assign i (i+1)
%endrep

%if (%%load_keys)
	vmovdqa	xkey9, [p_keys + 9*16]
%endif
%assign i 0
%rep %%by
	vaesenc	CONCAT(xdata,i), CONCAT(xdata,i), xkeyB		; key 8
%assign i (i+1)
%endrep

	vmovdqa	xkeyB, [p_keys + 10*16]
%assign i 0
%rep %%by
	vaesenc	CONCAT(xdata,i), CONCAT(xdata,i), xkey9		; key 9
%assign i (i+1)
%endrep

%assign i 0
%rep %%by
	vaesenclast	CONCAT(xdata,i), CONCAT(xdata,i), xkeyB		; key 10
%assign i (i+1)
%endrep

%assign i 0
%rep (%%by / 2)
%assign j (i+1)
	VMOVDQ	xkeyA, [p_in + i*16 - 16*%%by]
	VMOVDQ	xkeyB, [p_in + j*16 - 16*%%by]
	vpxor	CONCAT(xdata,i), CONCAT(xdata,i), xkeyA
	vpxor	CONCAT(xdata,j), CONCAT(xdata,j), xkeyB
%assign i (i+2)
%endrep
%if (i < %%by)
	VMOVDQ	xkeyA, [p_in + i*16 - 16*%%by]
	vpxor	CONCAT(xdata,i), CONCAT(xdata,i), xkeyA
%endif

%assign i 0
%rep %%by
	VMOVDQ	[p_out  + i*16], CONCAT(xdata,i)
%assign i (i+1)
%endrep
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;; aes_cntr_128_avx(void *in, void *IV, void *keys, void *out, UINT64 num_bytes)
global aes_cntr_128_avx
aes_cntr_128_avx:

%ifndef LINUX
	mov	num_bytes, [rsp + 8*5]
%endif

	vmovdqa	xbyteswap, [rel byteswap_const]
	vmovdqu	xcounter, [p_IV]
	vpshufb	xcounter, xcounter, xbyteswap

	mov	tmp, num_bytes
	and	tmp, 7*16
	jz	chk             ; x8 > or < 15 (not 7 lines)

	; 1 <= tmp <= 7
	cmp	tmp, 4*16
	jg	gt4
	je	eq4

lt4:
	cmp	tmp, 2*16
	jg	eq3
	je	eq2
eq1:
	do_aes_load	1
	add	p_out, 1*16
	and	num_bytes, ~(7*16)
	jz	do_return2
        
        cmp     num_bytes, 16
        jg      main_loop2
	jmp	last

eq2:	
	do_aes_load	2
	add	p_out, 2*16
	and	num_bytes, ~(7*16)
	jz	do_return2
        
        cmp     num_bytes, 16
        jg      main_loop2
	jmp	last

eq3:	
	do_aes_load	3
	add	p_out, 3*16
	and	num_bytes, ~(7*16)
	jz	do_return2
        
        cmp     num_bytes, 16
        jg      main_loop2
	jmp	last

eq4:	
	do_aes_load	4
	add	p_out, 4*16
	and	num_bytes, ~(7*16)
	jz	do_return2
        
        cmp     num_bytes, 16
        jg      main_loop2
	jmp	last

gt4:
	cmp	tmp, 6*16
	jg	eq7
	je	eq6

eq5:
	do_aes_load	5
	add	p_out, 5*16
	and	num_bytes, ~(7*16)
	jz	do_return2
        
        cmp     num_bytes, 16
        jg      main_loop2
	jmp	last

eq6:
	do_aes_load	6
	add	p_out, 6*16
	and	num_bytes, ~(7*16)
	jz	do_return2
        
        cmp     num_bytes, 16
        jg      main_loop2
	jmp	last

eq7:
	do_aes_load	7
	add	p_out, 7*16
	and	num_bytes, ~(7*16)
	jz	do_return2
        
        cmp     num_bytes, 16
        jg      main_loop2
	jmp	last

chk:
        cmp	num_bytes, 16
        jg      mult_of_8_blks
        jmp     last

mult_of_8_blks:
	vmovdqa	xkey0, [p_keys + 0*16]
	vmovdqa	xkey3, [p_keys + 3*16]
	vmovdqa	xkey6, [p_keys + 6*16]
	vmovdqa	xkey9, [p_keys + 9*16]

main_loop2:
	; num_bytes is a multiple of 8 and >0
	do_aes_noload	8
	add	p_out,	8*16
	sub	num_bytes, 8*16
        jz      do_return2
        cmp	num_bytes, 16
	jg	main_loop2

last:
        ENCRYPT_AVX 9
        
do_return2:
; don't return updated IV
;	vpshufb	xcounter, xcounter, xbyteswap
;	vmovdqu	[p_IV], xcounter
	ret

