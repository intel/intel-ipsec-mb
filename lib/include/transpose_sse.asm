;;
;; Copyright (c) 2022, Intel Corporation
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

%ifndef _TRANSPOSE_SSE_ASM_
%define _TRANSPOSE_SSE_ASM_

;; transpose r0, r1, r2, r3, t0, t1
;; "transpose" data in {r0..r3} using temps {t0..t3}
;; Input looks like: {r0 r1 r2 r3}
;; r0 = {a3 a2 a1 a0}
;; r1 = {b3 b2 b1 b0}
;; r2 = {c3 c2 c1 c0}
;; r3 = {d3 d2 d1 d0}
;;
;; output looks like: {t0 r1 r0 r3}
;; t0 = {d0 c0 b0 a0}
;; r1 = {d1 c1 b1 a1}
;; r0 = {d2 c2 b2 a2}
;; r3 = {d3 c3 b3 a3}

%macro TRANSPOSE4_U32 6
%define %%r0 %1
%define %%r1 %2
%define %%r2 %3
%define %%r3 %4
%define %%t0 %5
%define %%t1 %6
        movdqa  %%t0, %%r0
        shufps  %%t0, %%r1, 0x44        ; t0 = {b1 b0 a1 a0}
        shufps  %%r0, %%r1, 0xEE        ; r0 = {b3 b2 a3 a2}

        movdqa  %%t1, %%r2
        shufps  %%t1, %%r3, 0x44        ; t1 = {d1 d0 c1 c0}
        shufps  %%r2, %%r3, 0xEE        ; r2 = {d3 d2 c3 c2}

        movdqa  %%r1, %%t0
        shufps  %%r1, %%t1, 0xDD        ; r1 = {d1 c1 b1 a1}

        movdqa  %%r3, %%r0
        shufps  %%r3, %%r2, 0xDD        ; r3 = {d3 c3 b3 a3}

        shufps  %%r0, %%r2, 0x88        ; r0 = {d2 c2 b2 a2}
        shufps  %%t0, %%t1, 0x88        ; t0 = {d0 c0 b0 a0}
%endmacro

%endif ;; _TRANSPOSE_SSE_ASM_