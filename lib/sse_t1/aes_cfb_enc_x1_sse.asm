;;
;; Copyright (c) 2024-2026, Intel Corporation
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
%include "include/align_sse.inc"

;;; Routines to do 128/192/256 bit CFB AES encrypt operations on one
;;; buffer at a time.

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%else   ;; WIN_ABI
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    [rsp + 5*8]
%endif

%define OUT     arg1
%define IN      arg2
%define IV      arg3
%define KEYS    arg4

%ifdef LINUX
%define LEN     arg5
%else
%define LEN2    arg5
%define LEN     r11
%endif

%define NROUNDS r10
%define IDX     rax

%define XDATA0  xmm0
%define XIN     xmm1
%define XIN2    xmm2


mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES enc single block
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; XDATA0  [in] SIMD to encrypt
;; KEYS    [in] pointer to expanded keys structure (16 byte aligned)
;; NROUNDS [in] number of aesenc rounds depending on key size
;;              (128b - 9, 192b - 11, 256b - 13)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
aes_enc_one_block:
        pxor            XDATA0, [KEYS + 0*16]   ; ARK
        aesenc          XDATA0, [KEYS + 1*16]
        aesenc          XDATA0, [KEYS + 2*16]
        aesenc          XDATA0, [KEYS + 3*16]
        aesenc          XDATA0, [KEYS + 4*16]
        aesenc          XDATA0, [KEYS + 5*16]
        aesenc          XDATA0, [KEYS + 6*16]
        aesenc          XDATA0, [KEYS + 7*16]
        aesenc          XDATA0, [KEYS + 8*16]
        aesenc          XDATA0, [KEYS + 9*16]

        cmp             DWORD(NROUNDS), 11
        ja              .key_256b
        je              .key_192b

        ;; fall through for 128b key
        aesenclast      XDATA0, [KEYS + 10*16]
        ret

align_label
.key_192b:
        ;; fall through for 192b key
        aesenc          XDATA0, [KEYS + 10*16]
        aesenc          XDATA0, [KEYS + 11*16]
        aesenclast      XDATA0, [KEYS + 12*16]
        ret

align_label
.key_256b:
        aesenc          XDATA0, [KEYS + 10*16]
        aesenc          XDATA0, [KEYS + 11*16]
        aesenc          XDATA0, [KEYS + 12*16]
        aesenc          XDATA0, [KEYS + 13*16]
        aesenclast      XDATA0, [KEYS + 14*16]
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES CFB enc entry point
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Input:
;; OUT : addr to put cipher text out
;; IN  : addr to take clear text from
;; IV  : initialization vector
;; KEYS: pointer to expanded keys structure (16 byte aligned)
;; LEN:  length of the text to encrypt
;; NROUNDS: number of aesenc rounds depending on key size
;;         128b key: 9 rounds
;;         192b key: 11 rounds
;;         256b key: 13 rounds
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align_function
aes_cfb_enc_sse:
%ifndef LINUX
        push    rsi
        push    rdi
%endif
        or      LEN, LEN
        je      .done

        movdqu  XDATA0, [IV]            ; IV, used for 1st block only

        mov     IDX, LEN
        shr     IDX, 4
        jz      .partial_block

        movdqu  XIN2, [IN]
        add     IN, 16

        cmp     IDX, 2
        jb      .last_iteration

        dec     IDX                     ; account the last iteration

align_loop
.loop:
        call    aes_enc_one_block

        movdqa  XIN, XIN2
        movdqu  XIN2, [IN]              ; IN is 1 block (16 bytes) ahead of OUT
        add     IN, 16

        pxor    XDATA0, XIN

        movdqu  [OUT], XDATA0
        add     OUT, 16

        dec     IDX
        jnz     .loop

align_label
.last_iteration:
        call    aes_enc_one_block

        movdqa  XIN, XIN2
        pxor    XDATA0, XIN
        movdqu  [OUT], XDATA0

align_label
.partial_block:
        and     DWORD(LEN), 15
        jz      .done

        ;; 1 - 15 bytes left to process
        simd_load_sse_15_1 XIN, IN, LEN

        call    aes_enc_one_block

        pxor    XDATA0, XIN

        ;; use IN and IDX as temp
        simd_store_sse  OUT, XDATA0, LEN, IN, IDX

align_label
.done:
%ifdef SAFE_DATA
        ;; XDATA and XIN are the only scratch SIMD registers used
        clear_xmms_sse  XDATA0, XIN, XIN2
        clear_gps       LEN, IN, IDX
%endif

%ifndef LINUX
        pop     rdi
        pop     rsi
%endif
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cfb_[128|192|256]_enc_sse
;;(void *out, void *in, void *iv, void *keys, uint64_t len)
;; arg 1: OUT : addr to put cipher text out
;; arg 2: IN  : addr to take clear text from
;; arg 3: IV  : initialization vector
;; arg 4: KEYS: pointer to expanded keys structure (16 byte aligned)
;; arg 5: LEN:  length of the text to encrypt
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; void aes_cfb_128_enc
MKGLOBAL(aes_cfb_128_enc_sse,function,)
align_function
aes_cfb_128_enc_sse:
        endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        mov     DWORD(NROUNDS), 9
        jmp     aes_cfb_enc_sse

;; void aes_cfb_192_enc
MKGLOBAL(aes_cfb_192_enc_sse,function,)
align_function
aes_cfb_192_enc_sse:
        endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        mov     DWORD(NROUNDS), 11
        jmp     aes_cfb_enc_sse

;; void aes_cfb_256_enc
MKGLOBAL(aes_cfb_256_enc_sse,function,)
align_function
aes_cfb_256_enc_sse:
        endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        mov     DWORD(NROUNDS), 13
        jmp     aes_cfb_enc_sse

mksection stack-noexec
