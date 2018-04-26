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

;;; Tables used to insert job length into proper lane
extern len_shift_tab
extern len_mask_tab

;;; Size of len_shift_tab
;;; If modified, please update equivalent
;;; definition in 'mb_mgr_aes_submit_sse.asm'
%define len_tab_diff 64

; XPINSRW insert word into XMM register
%macro XPINSRW 6

%define %%dest     %1 ; dest XMM reg to insert word
%define %%tmp_simd %2 ; XMM reg to clobber
%define %%tmp_gp   %3 ; GP reg to clobber
%define %%idx      %4 ; word index to insert value into XMM
%define %%val      %5 ; word value to insert into idx
%define %%scaled   %6 ; flag to set if index is already scaled

%ifnidn %%scaled, 1
        shl     %%idx, 4     ; scale idx up x16
%endif
        movd    %%tmp_simd, DWORD(%%val)
        lea     %%tmp_gp, [rel len_shift_tab]
        pshufb  %%tmp_simd, [%%tmp_gp + %%idx]
        pand    %%dest, [%%tmp_gp + len_tab_diff + %%idx]
        por     %%dest, %%tmp_simd
%ifnidn %%scaled, 1
        shr     %%idx, 4     ; reset idx
%endif
%endmacro

%endif ; end ifndef _CONST_INC_
