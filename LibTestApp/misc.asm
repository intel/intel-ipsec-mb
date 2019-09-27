;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2019, Intel Corporation All rights reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions
;  are met:
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in
;      the documentation and/or other materials provided with the
;      distribution.
;    * Neither the name of Intel Corporation nor the names of its
;      contributors may be used to endorse or promote products derived
;      from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


%ifdef LINUX
;;; macro to declare global symbols
;;;  - name : symbol name
;;;  - type : funtion or data
;;;  - scope : internal, private, default
%define MKGLOBAL(name,type,scope) global name %+ : %+ type scope
%endif

%ifdef WIN_ABI
;;; macro to declare global symbols
;;;  - name : symbol name
;;;  - type : funtion or data
;;;  - scope : internal, private, default (ignored in win64 coff format)
%define MKGLOBAL(name,type,scope) global name
%endif

section .bss
default rel

MKGLOBAL(gps,data,)
gps:	        resq	14

MKGLOBAL(simd_regs,data,)
alignb 64
simd_regs:	resb	32*64

section .text

;; Returns RSP pointer with the value BEFORE the call, so 8 bytes need
;; to be added
MKGLOBAL(rdrsp,function,)
rdrsp:
        lea rax, [rsp + 8]
        ret

MKGLOBAL(dump_gps,function,)
dump_gps:

        mov     [rel gps],      rax
        mov     [rel gps + 8],  rbx
        mov     [rel gps + 16], rcx
        mov     [rel gps + 24], rdx
        mov     [rel gps + 32], rdi
        mov     [rel gps + 40], rsi

%assign i 8
%assign j 0
%rep 8
        mov     [rel gps + 48 + j], r %+i
%assign i (i+1)
%assign j (j+8)
%endrep

        ret

MKGLOBAL(dump_xmms_sse,function,)
dump_xmms_sse:

%assign i 0
%assign j 0
%rep 16
        movdqa  [rel simd_regs + j], xmm %+i
%assign i (i+1)
%assign j (j+16)
%endrep

        ret

MKGLOBAL(dump_xmms_avx,function,)
dump_xmms_avx:

%assign i 0
%assign j 0
%rep 16
        vmovdqa [rel simd_regs + j], xmm %+i
%assign i (i+1)
%assign j (j+16)
%endrep

        ret

MKGLOBAL(dump_ymms,function,)
dump_ymms:

%assign i 0
%assign j 0
%rep 16
        vmovdqa [rel simd_regs + j], ymm %+i
%assign i (i+1)
%assign j (j+32)
%endrep

        ret

MKGLOBAL(dump_zmms,function,)
dump_zmms:

%assign i 0
%assign j 0
%rep 32
        vmovdqa64 [rel simd_regs + j], zmm %+i
%assign i (i+1)
%assign j (j+64)
%endrep

        ret
