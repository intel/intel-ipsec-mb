;;
;; Copyright (c) 2018, Intel Corporation
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

%ifndef _CONST_INC_
%define _CONST_INC_

;;; Tables used to insert word into a SIMD register
extern len_shift_tab
extern len_mask_tab

;;; Size of len_shift_tab defined in const.asm module
%define len_tab_diff 128

; PINSRW_COMMON insert word into SIMD register
%macro PINSRW_COMMON 7

%define %%type          %1 ; instruction type - sse or avx
%define %%dest          %2 ; dest XMM reg to insert word
%define %%tmp_simd      %3 ; XMM reg to clobber
%define %%tmp_gp        %4 ; GP reg to clobber
%define %%idx           %5 ; word index to insert value into XMM
%define %%val           %6 ; word value to insert into idx
%define %%scale_idx     %7 ; flag to set if index is to be scaled x16

%ifidn  %%scale_idx, scale_x16
        shl     %%idx, 4     ; scale idx up x16
%endif
%ifnum  %%val
        ;; immediate value passed on
        mov     DWORD(%%tmp_gp), %%val
        movd    %%tmp_simd, DWORD(%%tmp_gp)
%else
        ;; register name passed on
        movd    %%tmp_simd, DWORD(%%val)
%endif
        lea     %%tmp_gp, [rel len_shift_tab]
        ;; check type - SSE or AVX
%ifidn  %%type, sse
        pshufb  %%tmp_simd, [%%tmp_gp + %%idx]
        pand    %%dest, [%%tmp_gp + len_tab_diff + %%idx]
        por     %%dest, %%tmp_simd
%else
        vpshufb %%tmp_simd, [%%tmp_gp + %%idx]
        vpand   %%dest, [%%tmp_gp + len_tab_diff + %%idx]
        vpor    %%dest, %%tmp_simd
%endif
%ifidn  %%scale_idx, scale_x16
        shr     %%idx, 4     ; reset idx
%endif
%endmacro

;;; Call SSE macro
%define XPINSRW PINSRW_COMMON sse,

;;; Call AVX macro
%define XVPINSRW PINSRW_COMMON avx,

%endif ; end ifndef _CONST_INC_
