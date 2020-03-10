;;
;; Copyright (c) 2018-2020, Intel Corporation
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
extern shift_tab_16

;;; Table to do 0x80 byte shift for padding prefix
extern padding_0x80_tab16

;;; Size of len_shift_tab defined in const.asm module
%define len_tab_diff 128

; PINSRW_COMMON insert word into 128 bit SIMD register
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
%ifidn  %%type, sse
        movd    %%tmp_simd, DWORD(%%tmp_gp)
%else
        vmovd   %%tmp_simd, DWORD(%%tmp_gp)
%endif
%else
        ;; register name passed on
%ifidn  %%type, sse
        movd    %%tmp_simd, DWORD(%%val)
%else
        vmovd   %%tmp_simd, DWORD(%%val)
%endif
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


;;; VPINSRW_M256 insert word into 32 byte memory range
%macro VPINSRW_M256 8

%define %%mem_addr      %1 ; 16 byte aligned memory address to insert word
%define %%tmp_simd1     %2 ; XMM reg to clobber
%define %%tmp_simd2     %3 ; XMM reg to clobber
%define %%tmp_gp        %4 ; GP reg to clobber
%define %%offset        %5 ; GP reg used to store offset
%define %%idx           %6 ; word index to insert value
%define %%val           %7 ; word value to insert into idx
%define %%scale_idx     %8 ; flag to set if index is to be scaled x16

        mov     %%offset, %%idx
        and     %%offset, 0x8   ; set offset 0 or 8
        and     %%idx, 0x7      ; remove offset from idx
        vmovdqa %%tmp_simd1, [%%mem_addr + %%offset*2]
        XVPINSRW %%tmp_simd1, %%tmp_simd2, %%tmp_gp, %%idx, %%val, %%scale_idx
        vmovdqa [%%mem_addr + %%offset*2], %%tmp_simd1
        or      %%idx, %%offset ; reset offset
%endmacro

;;; PSLB_COMMON shift bytes 128 bit SIMD register
%macro PSLB_COMMON 6

%define %%type          %1 ; [in] instruction type - sse or avx
%define %%dir           %2 ; [in] shift direction - left or right
%define %%reg           %3 ; [in/out] XMM reg to shift bytes
%define %%num           %4 ; [in] GP reg containing number of bytes to shift
%define %%shuf_tab      %5 ; [out] XMM reg to store shuffle table
%define %%tmp_gp        %6 ; [clobbered] GP reg to clobber

        ;; load shift table into %%shuf_tab
        lea     %%tmp_gp, [rel shift_tab_16 + 16]
%ifidn %%dir, left
        sub     %%tmp_gp, %%num
%else
        add     %%tmp_gp, %%num
%endif

%ifidn  %%type, sse
        movdqu  %%shuf_tab, [%%tmp_gp]
        pshufb  %%reg, %%shuf_tab
%else
        vmovdqu %%shuf_tab, [%%tmp_gp]
        vpshufb %%reg, %%shuf_tab
%endif
%endmacro

;;; Call SSE left shift macro
%macro XPSLLB 4
        PSLB_COMMON sse, left, %1,%2,%3,%4
%endm

;;; Call SSE right shift macro
%macro XPSRLB 4
        PSLB_COMMON sse, right, %1,%2,%3,%4
%endm

;;; Call AVX left shift macro
%macro XVPSLLB 4
        PSLB_COMMON avx, left, %1,%2,%3,%4
%endm

;;; Call AVX right shift macro
%macro XVPSRLB 4
        PSLB_COMMON avx, right, %1,%2,%3,%4
%endm

%endif ; end ifndef _CONST_INC_
