;;
;; Copyright (c) 2012-2019, Intel Corporation
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
%include "job_aes_hmac.asm"
%include "include/memcpy.asm"
%include "include/const.inc"

; routine to do AES128 CNTR enc/decrypt "by4"
; XMM registers are clobbered. Saving/restoring must be done at a higher level

%ifndef AES_CNTR_128
%define AES_CNTR_128 aes_cntr_128_sse
%define AES_CNTR_BIT_128 aes_cntr_bit_128_sse
%endif

extern byteswap_const, set_byte15, ddq_add_1, ddq_add_2, ddq_add_3, ddq_add_4

%define CONCAT(a,b) a %+ b
%define MOVDQ movdqu

%define xdata0	xmm0
%define xdata1	xmm1
%define xpart	xmm1
%define xdata2	xmm2
%define xtmp    xmm2
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

%ifdef CNTR_CCM_SSE
%ifdef LINUX
%define job	  rdi
%define p_in	  rsi
%define p_keys	  rdx
%define p_out	  rcx
%define num_bytes r8
%define p_ivlen   r9
%else ;; LINUX
%define job	  rcx
%define p_in	  rdx
%define p_keys	  r8
%define p_out	  r9
%define num_bytes r10
%define p_ivlen   rax
%endif ;; LINUX
%define p_IV    r11
%else ;; CNTR_CCM_SSE
%ifdef LINUX
%define p_in	  rdi
%define p_IV	  rsi
%define p_keys	  rdx
%define p_out	  rcx
%define num_bytes r8
%define num_bits  r8
%define p_ivlen   r9
%else ;; LINUX
%define p_in	  rcx
%define p_IV	  rdx
%define p_keys	  r8
%define p_out	  r9
%define num_bytes r10
%define num_bits  r10
%define p_ivlen   qword [rsp + 8*6]
%endif ;; LINUX
%endif ;; CNTR_CCM_SSE

%define tmp	r11
%define flags   r11

%define r_bits   r12
%define tmp2    r13
%define mask    r14

%macro do_aes_load 2
	do_aes %1, %2, 1
%endmacro

%macro do_aes_noload 2
	do_aes %1, %2, 0
%endmacro

; do_aes num_in_par load_keys
; This increments p_in, but not p_out
%macro do_aes 3
%define %%by %1
%define %%cntr_type %2
%define %%load_keys %3

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
%ifidn %%cntr_type, CNTR_BIT
	paddq	xcounter, [rel CONCAT(ddq_add_,%%by)]
%else
	paddd	xcounter, [rel CONCAT(ddq_add_,%%by)]
%endif

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

%if (%%load_keys)
	movdqa	xkey3, [p_keys + 3*16]
%endif
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyB		; key 2
%assign i (i+1)
%endrep

	add	p_in, 16*%%by

	movdqa	xkeyB, [p_keys + 4*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkey3		; key 3
%assign i (i+1)
%endrep

	movdqa	xkeyA, [p_keys + 5*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyB		; key 4
%assign i (i+1)
%endrep

%if (%%load_keys)
	movdqa	xkey6, [p_keys + 6*16]
%endif
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyA		; key 5
%assign i (i+1)
%endrep

	movdqa	xkeyA, [p_keys + 7*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkey6		; key 6
%assign i (i+1)
%endrep

	movdqa	xkeyB, [p_keys + 8*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyA		; key 7
%assign i (i+1)
%endrep

%if (%%load_keys)
	movdqa	xkey9, [p_keys + 9*16]
%endif
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkeyB		; key 8
%assign i (i+1)
%endrep

	movdqa	xkeyB, [p_keys + 10*16]
%assign i 0
%rep %%by
	aesenc	CONCAT(xdata,i), xkey9		; key 9
%assign i (i+1)
%endrep

%assign i 0
%rep %%by
	aesenclast	CONCAT(xdata,i), xkeyB		; key 10
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
section .text

;; Macro perforning AES-CTR.
;;
%macro DO_CNTR 1
%define %%CNTR_TYPE %1 ; [in] Type of CNTR operation to do (CNTR/CNTR_BIT/CCM)

%ifidn %%CNTR_TYPE, CCM
        mov     p_in, [job + _src]
        add     p_in, [job + _cipher_start_src_offset_in_bytes]
        mov     p_ivlen, [job + _iv_len_in_bytes]
        mov	num_bytes, [job + _msg_len_to_cipher_in_bytes]
        mov     p_keys, [job + _aes_enc_key_expanded]
        mov     p_out, [job + _dst]

	movdqa	xbyteswap, [rel byteswap_const]
        ;; Prepare IV ;;

        ;; Byte 0: flags with L'
        ;; Calculate L' = 15 - Nonce length - 1 = 14 - IV length
        mov     flags, 14
        sub     flags, p_ivlen
        movd    xcounter, DWORD(flags)
        ;; Bytes 1 - 13: Nonce (7 - 13 bytes long)

        ;; Bytes 1 - 7 are always copied (first 7 bytes)
        mov     p_IV, [job + _iv]
        pinsrb	xcounter, [p_IV], 1
        pinsrw	xcounter, [p_IV + 1], 1
        pinsrd  xcounter, [p_IV + 3], 1

        cmp     p_ivlen, 7
        je      _finish_nonce_move

        cmp     p_ivlen, 8
        je      _iv_length_8
        cmp     p_ivlen, 9
        je      _iv_length_9
        cmp     p_ivlen, 10
        je      _iv_length_10
        cmp     p_ivlen, 11
        je      _iv_length_11
        cmp     p_ivlen, 12
        je      _iv_length_12

        ;; Bytes 8 - 13
_iv_length_13:
        pinsrb 	xcounter, [p_IV + 12], 13
_iv_length_12:
        pinsrb 	xcounter, [p_IV + 11], 12
_iv_length_11:
        pinsrd	xcounter, [p_IV + 7], 2
        jmp     _finish_nonce_move
_iv_length_10:
        pinsrb	xcounter, [p_IV + 9], 10
_iv_length_9:
        pinsrb	xcounter, [p_IV + 8], 9
_iv_length_8:
        pinsrb	xcounter, [p_IV + 7], 8

_finish_nonce_move:
        ; last byte = 1
        por     xcounter, [rel set_byte15]
%else ;; CNTR/CNTR_BIT
%ifndef LINUX
	mov	num_bytes, [rsp + 8*5] ; arg5
%endif

%ifidn %%CNTR_TYPE, CNTR_BIT
        push r12
        push r13
        push r14
%endif

	movdqa	xbyteswap, [rel byteswap_const]
%ifidn %%CNTR_TYPE, CNTR
        test    p_ivlen, 16
        jnz     %%iv_is_16_bytes
        ; Read 12 bytes: Nonce + ESP IV. Then pad with block counter 0x00000001
        mov     DWORD(tmp), 0x01000000
        pinsrq  xcounter, [p_IV], 0
        pinsrd  xcounter, [p_IV + 8], 2
        pinsrd  xcounter, DWORD(tmp), 3

%else ;; CNTR_BIT
        ; Read 16 byte IV: Nonce + 8-byte block counter (BE)
        movdqu  xcounter, [p_IV]
%endif
%endif ;; CNTR/CNTR_BIT/CCM
%%bswap_iv:
	pshufb	xcounter, xbyteswap

        ;; calculate len
        ;; convert bits to bytes (message length in bits for CNTR_BIT)
%ifidn %%CNTR_TYPE, CNTR_BIT
        mov     r_bits, num_bits
        shr     num_bits, 3 ; "num_bits" and "num_bytes" registers are the same
        and     r_bits, 7   ; Check if there are remainder bits (0-7)
%endif
	mov	tmp, num_bytes
	and	tmp, 3*16
	jz	%%chk             ; x4 > or < 15 (not 3 lines)

	; 1 <= tmp <= 3
	cmp	tmp, 2*16
	jg	%%eq3
	je	%%eq2
%%eq1:
	do_aes_load	1, %%CNTR_TYPE	; 1 block
	add	p_out, 1*16
        jmp     %%chk

%%eq2:
	do_aes_load	2, %%CNTR_TYPE	; 2 blocks
	add	p_out, 2*16
        jmp      %%chk

%%eq3:
	do_aes_load	3, %%CNTR_TYPE	; 3 blocks
	add	p_out, 3*16
	; fall through to chk
%%chk:
        and	num_bytes, ~(3*16)
%ifidn %%CNTR_TYPE, CNTR_BIT
        jz      %%check_rbits
%else
	jz	%%do_return2
%endif
        cmp	num_bytes, 16
        jb	%%last

	; process multiples of 4 blocks
	movdqa	xkey0, [p_keys + 0*16]
	movdqa	xkey3, [p_keys + 3*16]
	movdqa	xkey6, [p_keys + 6*16]
	movdqa	xkey9, [p_keys + 9*16]

align 32
%%main_loop2:
	; num_bytes is a multiple of 4 blocks + partial bytes
	do_aes_noload	4, %%CNTR_TYPE
	add	p_out,	4*16
	sub	num_bytes, 4*16
        cmp	num_bytes, 4*16
	jae	%%main_loop2

        ; Check if there is a partial block
	or      num_bytes, num_bytes
        jnz    %%last

%%check_rbits:
;; Check here for number of remaining bits, in case there are no "full" bytes
%ifidn %%CNTR_TYPE, CNTR_BIT
        or      r_bits, r_bits
        jnz     %%last
%endif

%%do_return2:
%ifidn %%CNTR_TYPE, CCM
	mov	rax, job
	or	dword [rax + _status], STS_COMPLETED_AES
%endif

%ifidn %%CNTR_TYPE, CNTR_BIT
        pop r14
        pop r13
        pop r12
%endif

	ret

%%last:

%ifidn %%CNTR_TYPE, CNTR_BIT
        ;; Do not load another block if there is only a partial byte left
        or      num_bytes, num_bytes
        jz     %%final_ctr_enc
%endif
	; load partial block into XMM register
	simd_load_sse_15_1 xpart, p_in, num_bytes

%%final_ctr_enc:
	; Encryption of a single partial block
        pshufb	xcounter, xbyteswap
        movdqa	xdata0, xcounter
        pxor    xdata0, [p_keys + 16*0]
%assign i 1
%rep 9
        aesenc  xdata0, [p_keys + 16*i]
%assign i (i+1)
%endrep
	; created keystream
        aesenclast xdata0, [p_keys + 16*i]

%ifidn %%CNTR_TYPE, CNTR_BIT
        ;; Do not store another block if there is only a partial byte left
        or      num_bytes, num_bytes
        jz     %%encrypt_last_bits
%endif
	; xor keystream with the message (scratch)
        pxor	xpart, xdata0
	; copy result into the output buffer
	simd_store_sse p_out, xpart, num_bytes, tmp, rax

%%encrypt_last_bits:
%ifidn %%CNTR_TYPE, CNTR_BIT
        or      r_bits, r_bits
        jz      %%do_return2

        ;; Shift the byte from the encrypted counter block to use to the LSB
        XPSRLB xdata0, num_bytes, xtmp, tmp2

        ;; There are bits remaining, need to read another byte from input
        ;; and output and XOR input with encrypted CTR block, preserving
        ;; the ouput bits that are not to be ciphered

        ;; Save RCX in temporary XMM register
        movq    xtmp, rcx
        mov     DWORD(mask), 0xff
%ifidn r_bits, rcx
%error "r_bits cannot be mapped to rcx!"
%endif
        mov     cl, BYTE(r_bits)
        shr     DWORD(mask), cl   ;; e.g. 3 remaining bits -> mask = 00011111
        movq    rcx, xtmp

        mov     BYTE(tmp), [p_out + num_bytes]
        and     BYTE(tmp), BYTE(mask) ;; Keep only bits not to be ciphered
        pextrb  tmp2, xdata0, 0
        not     mask    ;; e.g. 3 remaining bits -> mask = 11100000

        ;; Keep first bits that will XOR with input "valid" bits
        and     BYTE(tmp2), BYTE(mask)
        or      BYTE(tmp), BYTE(tmp2)

        ;; Zero out "non-valid" bits
        mov     BYTE(tmp2), [p_in + num_bytes]
        and     BYTE(tmp2), BYTE(mask)

        ;; OUT = (IN | 0s)  XOR (ENC CTR block | OUT)
        xor     BYTE(tmp), BYTE(tmp2)
        mov     [p_out + num_bytes], BYTE(tmp)
%endif

	jmp	%%do_return2

%%iv_is_16_bytes:
        ; Read 16 byte IV: Nonce + ESP IV + block counter (BE)
        movdqu  xcounter, [p_IV]
        jmp     %%bswap_iv
%endmacro

align 32
%ifdef CNTR_CCM_SSE
; JOB_AES_HMAC * aes_cntr_ccm_128_sse(JOB_AES_HMAC *job)
; arg 1 : job
MKGLOBAL(AES_CNTR_CCM_128,function,internal)
AES_CNTR_CCM_128:
        DO_CNTR CCM
%else
;; aes_cntr_128_sse(void *in, void *IV, void *keys, void *out, UINT64 num_bytes, UINT64 iv_len)
MKGLOBAL(AES_CNTR_128,function,internal)
AES_CNTR_128:
        DO_CNTR CNTR

;; aes_cntr_bit_128_sse(void *in, void *IV, void *keys, void *out, UINT64 num_bits, UINT64 iv_len)
MKGLOBAL(AES_CNTR_BIT_128,function,internal)
AES_CNTR_BIT_128:
        DO_CNTR CNTR_BIT
%endif ;; CNTR_CCM_SSE

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
