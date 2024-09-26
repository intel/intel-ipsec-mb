;;
;; Copyright (c) 2020-2023, Intel Corporation
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

;; AES-CBCS-128_1-9 decrypt by8

; arg 1: IN:   pointer to input (cipher text)
; arg 2: IV:   pointer to IV
; arg 3: KEYS: pointer to keys
; arg 4: OUT:  pointer to output (plain text)
; arg 5: LEN:  length in bytes (multiple of 16)
; arg 6: NEXT_IV:  pointer to buffer for IV

%ifdef LINUX
%define arg1	rdi
%define arg2	rsi
%define arg3	rdx
%define arg4	rcx
%define arg5    r8
%define arg6    r9
%else
%define arg1	rcx
%define arg2	rdx
%define arg3	r8
%define arg4	r9
%define arg5    rax
%define arg6    r11
%endif

%include "include/aes_cbcs_dec_by8_avx.inc"

mksection .text

align 64
MKGLOBAL(aes_cbcs_1_9_dec_128_avx,function,internal)
aes_cbcs_1_9_dec_128_avx:
%ifndef LINUX
        mov     arg5, [rsp + 5*8]
        mov     arg6, [rsp + 6*8]
%endif
        AES_CBCS_DEC arg1, arg2, arg3, arg4, arg5, r10, 9, 160, arg6
        ret

mksection stack-noexec
