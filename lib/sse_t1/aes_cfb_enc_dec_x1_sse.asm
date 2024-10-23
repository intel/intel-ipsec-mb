;;
;; Copyright (c) 2024, Intel Corporation
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

%include "include/os.inc"
%include "include/memcpy.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/error.inc"

;;; Routines to do 128/192/256 bit CFB AES encrypt/decrypt operations on one
;;; buffer at a time.

%define ENC 0
%define DEC 1

%ifdef LINUX
%define arg1	rdi
%define arg2	rsi
%define arg3	rdx
%define arg4	rcx
%define arg5	r8
%else   ;; WIN_ABI
%define arg1	rcx
%define arg2	rdx
%define arg3	r8
%define arg4	r9
%define arg5	[rsp + 5*8]
%endif

%define OUT	arg1
%define IN	arg2
%define IV	arg3
%define KEYS	arg4

%ifdef LINUX
%define LEN	arg5
%else
%define LEN2	arg5
%define LEN	r11
%endif

%define OUT_CPY	r10

%define XDATA	xmm0
%define XIN	xmm1

%define IDX     rax

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Input: %%NROUNDS: number of aesenc rounds depending on key size:
;; 128b key: (10 - 1) rounds
;; 192b key: (12 - 1) rounds
;; 256b key: (14 - 1) rounds
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro do_cfb 2
%define %%NROUNDS               %1
%define %%DIRECTION             %2

%ifdef WIN_ABI
	mov	LEN, LEN2
%endif

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; AES CFB enc/dec entry point
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	mov	        IDX, 16
	movdqu		XDATA, [IV]     ; IV, used for 1st block only

%%main_loop:
	pxor		XDATA, [KEYS]	; key XOR ciphertext/plaintext

        cmp             LEN, IDX
        jb              %%_last_block

        movdqu		XIN, [IN + IDX - 16]

%assign i 16
%rep %%NROUNDS
	aesenc		XDATA, [KEYS + i]       ; ENC with round key ()
%assign i (i+16)
%endrep
	aesenclast	XDATA, [KEYS + i]

	pxor		XDATA, XIN
        movdqu          [OUT + IDX - 16], XDATA
	cmp		LEN, IDX
        je              %%_done         ;; length was multiple of 16 bytes

        add	        IDX, 16
%if %%DIRECTION == DEC
        movdqu          XDATA, XIN ;; use ciphertext as input for next block
%endif
	jmp		%%main_loop

%%_last_block: ;; 1 - 15 bytes left to process
        ;; use LEN and IN as temp
        and             LEN, 15
        add             IN, IDX
        sub             IN, 16
        simd_load_sse_16 XIN, IN, LEN

%assign i 16
%rep %%NROUNDS
	aesenc		XDATA, [KEYS + i]	; ENC with round key ()
%assign i (i+16)
%endrep
	aesenclast	XDATA, [KEYS + i]
	pxor		XDATA, XIN
        mov             OUT_CPY, OUT
        add             OUT_CPY, IDX
        sub             OUT_CPY, 16

        simd_store_sse	OUT_CPY, XDATA, LEN, IN, IDX

%%_done:
%ifdef SAFE_DATA
        ;; XDATA and XIN are the only scratch SIMD registers used
        clear_xmms_sse  XDATA, XIN
        clear_scratch_gps_asm
%endif

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cfb_/*128/192/256*/_/*enc/dec*/_sse
;;(void *out, void *in, void *iv, void *keys, uint64_t len)
;; arg 1: OUT : addr to put clear/cipher text out
;; arg 2: IN  : addr to take cipher/clear text from
;; arg 3: IV  : initialization vector
;; arg 4: KEYS: pointer to expanded keys structure (16 byte aligned)
;; arg 5: LEN:  length of the text to encrypt/decrypt
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifndef AES_CFB_128_ENC
%define AES_CFB_128_ENC aes_cfb_128_enc_sse
%define AES_CFB_192_ENC aes_cfb_192_enc_sse
%define AES_CFB_256_ENC aes_cfb_256_enc_sse
%define AES_CFB_128_DEC aes_cfb_128_dec_sse
%define AES_CFB_192_DEC aes_cfb_192_dec_sse
%define AES_CFB_256_DEC aes_cfb_256_dec_sse
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES CFB 128
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cfb_128_enc
align 32
MKGLOBAL(AES_CFB_128_ENC,function,)
AES_CFB_128_ENC:
endbranch64
        do_cfb 9, ENC
	ret

;; void aes_cfb_128_dec
align 32
MKGLOBAL(AES_CFB_128_DEC,function,)
AES_CFB_128_DEC:
endbranch64
        do_cfb 9, DEC
	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES CFB 192
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cfb_192_enc
align 32
MKGLOBAL(AES_CFB_192_ENC,function,)
AES_CFB_192_ENC:
endbranch64
        do_cfb 11, ENC
	ret

;; void aes_cfb_192_dec
align 32
MKGLOBAL(AES_CFB_192_DEC,function,)
AES_CFB_192_DEC:
endbranch64
        do_cfb 11, DEC
	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES CFB 256
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cfb_256_enc
align 32
MKGLOBAL(AES_CFB_256_ENC,function,)
AES_CFB_256_ENC:
endbranch64
        do_cfb 13, ENC
	ret

;; void aes_cfb_256_dec
align 32
MKGLOBAL(AES_CFB_256_DEC,function,)
AES_CFB_256_DEC:
endbranch64
        do_cfb 13, DEC
	ret

mksection stack-noexec