;;
;; Copyright (c) 2019, Intel Corporation
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

section .text
;
; This function clears all scratch GP registers
;
; void clear_gps(void)
MKGLOBAL(clear_gps,function,internal)
clear_gps:
        xor     rax, rax
        xor     rcx, rcx
        xor     rdx, rdx
; On Linux, rdi and rsi are scratch registers
%ifndef LINUX
        xor     rdi, rdi
        xor     rsi, rsi
%endif
        xor     r8,  r8
        xor     r9,  r9
        xor     r10, r10
        xor     r11, r11

        ret

;
; This function clears all scratch XMM registers
;
; void clear_xmms_sse(void)
MKGLOBAL(clear_xmms_sse,function,internal)
clear_xmms_sse:
; On Linux, all XMM registers are scratch registers
%ifdef LINUX
%assign i 0
%rep 16
        pxor    xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
; On Windows, XMM0-XMM5 registers are scratch registers
%else
%assign i 0
%rep 6
        pxor    xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
%endif
        ret

;
; This function clears all scratch XMM registers
;
; It should be called before restoring the XMM registers
; for Windows (XMM6-XMM15)
;
; void clear_xmms_avx(void)
MKGLOBAL(clear_xmms_avx,function,internal)
clear_xmms_avx:
; On Linux, all XMM registers are scratch registers
%ifdef LINUX
%assign i 0
%rep 16
        vpxor   xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
; On Windows, XMM0-XMM5 registers are scratch registers
%else
%assign i 0
%rep 6
        vpxor   xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
%endif
        ret


%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
