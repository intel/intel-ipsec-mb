;;
;; Copyright (c) 2012-2024, Intel Corporation
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

%ifndef GCM_DEFINES_INC_INCLUDED
%define GCM_DEFINES_INC_INCLUDED

;
; Authors:
;       Erdinc Ozturk
;       Vinodh Gopal
;       James Guilford

%ifdef WIN_ABI
        %xdefine GCM_MAX_LENGTH r10
%else
        %xdefine GCM_MAX_LENGTH [rel gcm_max_len]
%endif

%macro INIT_GCM_MAX_LENGTH 0
%ifdef WIN_ABI
        mov     GCM_MAX_LENGTH, qword [rel gcm_max_len]
%endif
%endm

%define reg(q) xmm %+ q
%define regy(q) ymm %+ q
%define regz(q) zmm %+ q

%ifdef WIN_ABI
        %xdefine arg1 rcx
        %xdefine arg2 rdx
        %xdefine arg3 r8
        %xdefine arg4 r9
        %xdefine arg5  qword [r14 + 8*5]
        %xdefine arg6  qword [r14 + 8*6]
        %xdefine arg7  qword [r14 + 8*7]
        %xdefine arg8  qword [r14 + 8*8]
        %xdefine arg9  qword [r14 + 8*9]
        %xdefine arg10 qword [r14 + 8*10]
        %xdefine arg11 qword [r14 + 8*11]
%else
        %xdefine arg1 rdi
        %xdefine arg2 rsi
        %xdefine arg3 rdx
        %xdefine arg4 rcx
        %xdefine arg5 r8
        %xdefine arg6 r9
        %xdefine arg7  qword [r14 + 8*1]
        %xdefine arg8  qword [r14 + 8*2]
        %xdefine arg9  qword [r14 + 8*3]
        %xdefine arg10 qword [r14 + 8*4]
        %xdefine arg11 qword [r14 + 8*5]
%endif

%ifdef NT_LDST
        %define NT_LD
        %define NT_ST
%endif

;;; Use Non-temporal load/stor
%ifdef NT_LD
        %define XLDR     movntdqa
        %define VXLDR    vmovntdqa
        %define VX512LDR vmovntdqa
%else
        %define XLDR     movdqu
        %define VXLDR    vmovdqu
        %define VX512LDR vmovdqu8
%endif

;;; Use Non-temporal load/stor
%ifdef NT_ST
        %define XSTR     movntdq
        %define VXSTR    vmovntdq
        %define VX512STR vmovntdq
%else
        %define XSTR     movdqu
        %define VXSTR    vmovdqu
        %define VX512STR vmovdqu8
%endif

%endif ; GCM_DEFINES_INC_INCLUDED
