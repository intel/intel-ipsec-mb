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

; Routine to do AES key expansion
%include "include/os.asm"
%define NO_AESNI_RENAME
%include "include/aesni_emu.inc"
%include "include/clear_regs.asm"

%macro key_expansion_128_sse 0
	;; Assumes the xmm3 includes all zeros at this point.
        pshufd	xmm2, xmm2, 11111111b
        shufps	xmm3, xmm1, 00010000b
        pxor	xmm1, xmm3
        shufps	xmm3, xmm1, 10001100b
        pxor	xmm1, xmm3
	pxor	xmm1, xmm2
%endmacro

%macro key_expansion_128_avx 0
	;; Assumes the xmm3 includes all zeros at this point.
        vpshufd	xmm2, xmm2, 11111111b
        vshufps	xmm3, xmm3, xmm1, 00010000b
        vpxor	xmm1, xmm1, xmm3
        vshufps	xmm3, xmm3, xmm1, 10001100b
        vpxor	xmm1, xmm1, xmm3
	vpxor	xmm1, xmm1, xmm2
%endmacro

%ifdef LINUX
%define KEY		rdi
%define EXP_ENC_KEYS	rsi
%define EXP_DEC_KEYS	rdx
%else
%define KEY		rcx
%define EXP_ENC_KEYS	rdx
%define EXP_DEC_KEYS	r8
%endif

section .text

; void aes_keyexp_128(UINT128 *key,
;                     UINT128 *enc_exp_keys,
;                     UINT128 *dec_exp_keys);
;
; arg 1: rcx: pointer to key
; arg 2: rdx: pointer to expanded key array for encrypt
; arg 3: r8:  pointer to expanded key array for decrypt
;
MKGLOBAL(aes_keyexp_128_sse,function,)
aes_keyexp_128_sse:

%ifdef SAFE_PARAM
        cmp     KEY, 0
        jz      aes_keyexp_128_sse_return
        cmp     EXP_ENC_KEYS, 0
        jz      aes_keyexp_128_sse_return
        cmp     EXP_DEC_KEYS, 0
        jz      aes_keyexp_128_sse_return
%endif

        movdqu	xmm1, [KEY]	; loading the AES key
	movdqa	[EXP_ENC_KEYS + 16*0], xmm1
        movdqa	[EXP_DEC_KEYS + 16*10], xmm1  ; Storing key in memory
	pxor	xmm3, xmm3

        aeskeygenassist	xmm2, xmm1, 0x1     ; Generating round key 1
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*1], xmm1
        aesimc	xmm4, xmm1
        movdqa	[EXP_DEC_KEYS + 16*9], xmm4

        aeskeygenassist xmm2, xmm1, 0x2     ; Generating round key 2
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*2], xmm1
        aesimc	xmm5, xmm1
        movdqa	[EXP_DEC_KEYS + 16*8], xmm5

        aeskeygenassist xmm2, xmm1, 0x4     ; Generating round key 3
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*3], xmm1
        aesimc	xmm4, xmm1
        movdqa	[EXP_DEC_KEYS + 16*7], xmm4

        aeskeygenassist xmm2, xmm1, 0x8     ; Generating round key 4
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*4], xmm1
        aesimc	xmm5, xmm1
        movdqa	[EXP_DEC_KEYS + 16*6], xmm5

        aeskeygenassist xmm2, xmm1, 0x10    ; Generating round key 5
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*5], xmm1
        aesimc	xmm4, xmm1
        movdqa	[EXP_DEC_KEYS + 16*5], xmm4

        aeskeygenassist xmm2, xmm1, 0x20    ; Generating round key 6
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*6], xmm1
        aesimc	xmm5, xmm1
        movdqa	[EXP_DEC_KEYS + 16*4], xmm5

        aeskeygenassist xmm2, xmm1, 0x40    ; Generating round key 7
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*7], xmm1
        aesimc	xmm4, xmm1
        movdqa	[EXP_DEC_KEYS + 16*3], xmm4

        aeskeygenassist xmm2, xmm1, 0x80    ; Generating round key 8
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*8], xmm1
        aesimc	xmm5, xmm1
        movdqa	[EXP_DEC_KEYS + 16*2], xmm5

        aeskeygenassist xmm2, xmm1, 0x1b    ; Generating round key 9
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*9], xmm1
        aesimc	xmm4, xmm1
        movdqa	[EXP_DEC_KEYS + 16*1], xmm4

        aeskeygenassist xmm2, xmm1, 0x36    ; Generating round key 10
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*10], xmm1
        movdqa	[EXP_DEC_KEYS + 16*0], xmm1

aes_keyexp_128_sse_return:

%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_scratch_xmms_sse_asm
%endif
	ret

MKGLOBAL(aes_keyexp_128_sse_no_aesni,function,)
aes_keyexp_128_sse_no_aesni:

%ifdef SAFE_PARAM
        cmp     KEY, 0
        jz      aes_keyexp_128_sse_no_aesni_return
        cmp     EXP_ENC_KEYS, 0
        jz      aes_keyexp_128_sse_no_aesni_return
        cmp     EXP_DEC_KEYS, 0
        jz      aes_keyexp_128_sse_no_aesni_return
%endif

        movdqu	xmm1, [KEY]	; loading the AES key
	movdqa	[EXP_ENC_KEYS + 16*0], xmm1
        movdqa	[EXP_DEC_KEYS + 16*10], xmm1  ; Storing key in memory
	pxor	xmm3, xmm3

        EMULATE_AESKEYGENASSIST	xmm2, xmm1, 0x1     ; Generating round key 1
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*1], xmm1
        EMULATE_AESIMC	xmm4, xmm1
        movdqa	[EXP_DEC_KEYS + 16*9], xmm4

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x2     ; Generating round key 2
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*2], xmm1
        EMULATE_AESIMC	xmm5, xmm1
        movdqa	[EXP_DEC_KEYS + 16*8], xmm5

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x4     ; Generating round key 3
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*3], xmm1
        EMULATE_AESIMC	xmm4, xmm1
        movdqa	[EXP_DEC_KEYS + 16*7], xmm4

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x8     ; Generating round key 4
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*4], xmm1
        EMULATE_AESIMC	xmm5, xmm1
        movdqa	[EXP_DEC_KEYS + 16*6], xmm5

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x10    ; Generating round key 5
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*5], xmm1
        EMULATE_AESIMC	xmm4, xmm1
        movdqa	[EXP_DEC_KEYS + 16*5], xmm4

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x20    ; Generating round key 6
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*6], xmm1
        EMULATE_AESIMC	xmm5, xmm1
        movdqa	[EXP_DEC_KEYS + 16*4], xmm5

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x40    ; Generating round key 7
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*7], xmm1
        EMULATE_AESIMC	xmm4, xmm1
        movdqa	[EXP_DEC_KEYS + 16*3], xmm4

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x80    ; Generating round key 8
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*8], xmm1
        EMULATE_AESIMC	xmm5, xmm1
        movdqa	[EXP_DEC_KEYS + 16*2], xmm5

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x1b    ; Generating round key 9
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*9], xmm1
        EMULATE_AESIMC	xmm4, xmm1
        movdqa	[EXP_DEC_KEYS + 16*1], xmm4

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x36    ; Generating round key 10
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*10], xmm1
        movdqa	[EXP_DEC_KEYS + 16*0], xmm1

aes_keyexp_128_sse_no_aesni_return:

%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_scratch_xmms_sse_asm
%endif
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

MKGLOBAL(aes_keyexp_128_avx,function,)
MKGLOBAL(aes_keyexp_128_avx2,function,)
MKGLOBAL(aes_keyexp_128_avx512,function,)
aes_keyexp_128_avx:
aes_keyexp_128_avx2:
aes_keyexp_128_avx512:

%ifdef SAFE_PARAM
        cmp     KEY, 0
        jz      aes_keyexp_128_avx_return
        cmp     EXP_ENC_KEYS, 0
        jz      aes_keyexp_128_avx_return
        cmp     EXP_DEC_KEYS, 0
        jz      aes_keyexp_128_avx_return
%endif

        vmovdqu	xmm1, [KEY]	; loading the AES key
	vmovdqa	[EXP_ENC_KEYS + 16*0], xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*10], xmm1  ; Storing key in memory
	vpxor	xmm3, xmm3, xmm3

        vaeskeygenassist	xmm2, xmm1, 0x1     ; Generating round key 1
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*1], xmm1
        vaesimc	xmm4, xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*9], xmm4

        vaeskeygenassist xmm2, xmm1, 0x2     ; Generating round key 2
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*2], xmm1
        vaesimc	xmm5, xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*8], xmm5

        vaeskeygenassist xmm2, xmm1, 0x4     ; Generating round key 3
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*3], xmm1
        vaesimc	xmm4, xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*7], xmm4

        vaeskeygenassist xmm2, xmm1, 0x8     ; Generating round key 4
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*4], xmm1
        vaesimc	xmm5, xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*6], xmm5

        vaeskeygenassist xmm2, xmm1, 0x10    ; Generating round key 5
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*5], xmm1
        vaesimc	xmm4, xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*5], xmm4

        vaeskeygenassist xmm2, xmm1, 0x20    ; Generating round key 6
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*6], xmm1
        vaesimc	xmm5, xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*4], xmm5

        vaeskeygenassist xmm2, xmm1, 0x40    ; Generating round key 7
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*7], xmm1
        vaesimc	xmm4, xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*3], xmm4

        vaeskeygenassist xmm2, xmm1, 0x80    ; Generating round key 8
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*8], xmm1
        vaesimc	xmm5, xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*2], xmm5

        vaeskeygenassist xmm2, xmm1, 0x1b    ; Generating round key 9
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*9], xmm1
        vaesimc	xmm4, xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*1], xmm4

        vaeskeygenassist xmm2, xmm1, 0x36    ; Generating round key 10
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*10], xmm1
        vmovdqa	[EXP_DEC_KEYS + 16*0], xmm1

aes_keyexp_128_avx_return:

%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_scratch_xmms_avx_asm
%endif
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; void aes_keyexp_128_enc_sse(UINT128 *key,
;                             UINT128 *enc_exp_keys);
;
; arg 1: rcx: pointer to key
; arg 2: rdx: pointer to expanded key array for encrypt
;
MKGLOBAL(aes_keyexp_128_enc_sse,function,)
aes_keyexp_128_enc_sse:

%ifdef SAFE_PARAM
        cmp     KEY, 0
        jz      aes_keyexp_128_enc_sse_return
        cmp     EXP_ENC_KEYS, 0
        jz      aes_keyexp_128_enc_sse_return
%endif

        movdqu	xmm1, [KEY]	; loading the AES key
	movdqa	[EXP_ENC_KEYS + 16*0], xmm1
	pxor	xmm3, xmm3

        aeskeygenassist	xmm2, xmm1, 0x1     ; Generating round key 1
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*1], xmm1

        aeskeygenassist xmm2, xmm1, 0x2     ; Generating round key 2
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*2], xmm1

        aeskeygenassist xmm2, xmm1, 0x4     ; Generating round key 3
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*3], xmm1

        aeskeygenassist xmm2, xmm1, 0x8     ; Generating round key 4
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*4], xmm1

        aeskeygenassist xmm2, xmm1, 0x10    ; Generating round key 5
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*5], xmm1

        aeskeygenassist xmm2, xmm1, 0x20    ; Generating round key 6
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*6], xmm1

        aeskeygenassist xmm2, xmm1, 0x40    ; Generating round key 7
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*7], xmm1

        aeskeygenassist xmm2, xmm1, 0x80    ; Generating round key 8
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*8], xmm1

        aeskeygenassist xmm2, xmm1, 0x1b    ; Generating round key 9
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*9], xmm1

        aeskeygenassist xmm2, xmm1, 0x36    ; Generating round key 10
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*10], xmm1

aes_keyexp_128_enc_sse_return:
	ret

MKGLOBAL(aes_keyexp_128_enc_sse_no_aesni,function,)
aes_keyexp_128_enc_sse_no_aesni:

%ifdef SAFE_PARAM
        cmp     KEY, 0
        jz      aes_keyexp_128_enc_sse_no_aesni_return
        cmp     EXP_ENC_KEYS, 0
        jz      aes_keyexp_128_enc_sse_no_aesni_return
%endif

        movdqu	xmm1, [KEY]	; loading the AES key
	movdqa	[EXP_ENC_KEYS + 16*0], xmm1
	pxor	xmm3, xmm3

        EMULATE_AESKEYGENASSIST	xmm2, xmm1, 0x1     ; Generating round key 1
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*1], xmm1

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x2     ; Generating round key 2
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*2], xmm1

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x4     ; Generating round key 3
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*3], xmm1

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x8     ; Generating round key 4
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*4], xmm1

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x10    ; Generating round key 5
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*5], xmm1

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x20    ; Generating round key 6
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*6], xmm1

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x40    ; Generating round key 7
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*7], xmm1

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x80    ; Generating round key 8
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*8], xmm1

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x1b    ; Generating round key 9
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*9], xmm1

        EMULATE_AESKEYGENASSIST xmm2, xmm1, 0x36    ; Generating round key 10
        key_expansion_128_sse
	movdqa	[EXP_ENC_KEYS + 16*10], xmm1

aes_keyexp_128_enc_sse_no_aesni_return:
	ret

MKGLOBAL(aes_keyexp_128_enc_avx,function,)
MKGLOBAL(aes_keyexp_128_enc_avx2,function,)
MKGLOBAL(aes_keyexp_128_enc_avx512,function,)
aes_keyexp_128_enc_avx:
aes_keyexp_128_enc_avx2:
aes_keyexp_128_enc_avx512:

%ifdef SAFE_PARAM
        cmp     KEY, 0
        jz      aes_keyexp_128_enc_avx_return
        cmp     EXP_ENC_KEYS, 0
        jz      aes_keyexp_128_enc_avx_return
%endif

        vmovdqu	xmm1, [KEY]	; loading the AES key
	vmovdqa	[EXP_ENC_KEYS + 16*0], xmm1
	vpxor	xmm3, xmm3, xmm3

        vaeskeygenassist	xmm2, xmm1, 0x1     ; Generating round key 1
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*1], xmm1

        vaeskeygenassist xmm2, xmm1, 0x2     ; Generating round key 2
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*2], xmm1

        vaeskeygenassist xmm2, xmm1, 0x4     ; Generating round key 3
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*3], xmm1

        vaeskeygenassist xmm2, xmm1, 0x8     ; Generating round key 4
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*4], xmm1

        vaeskeygenassist xmm2, xmm1, 0x10    ; Generating round key 5
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*5], xmm1

        vaeskeygenassist xmm2, xmm1, 0x20    ; Generating round key 6
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*6], xmm1

        vaeskeygenassist xmm2, xmm1, 0x40    ; Generating round key 7
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*7], xmm1

        vaeskeygenassist xmm2, xmm1, 0x80    ; Generating round key 8
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*8], xmm1

        vaeskeygenassist xmm2, xmm1, 0x1b    ; Generating round key 9
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*9], xmm1

        vaeskeygenassist xmm2, xmm1, 0x36    ; Generating round key 10
        key_expansion_128_avx
	vmovdqa	[EXP_ENC_KEYS + 16*10], xmm1

aes_keyexp_128_enc_avx_return:
	ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
