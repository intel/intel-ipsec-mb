;;
;; Copyright (c) 2023-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; https://datatracker.ietf.org/doc/html/draft-shen-sm3-hash

extern sm3_base_init
extern sm3_base_update

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/align_sse.inc"

%ifdef LINUX

%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx

%else

%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9

%endif


mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sm3_one_block_sm3(void *tag, const void *msg)
MKGLOBAL(sm3_one_block_sse,function,internal)
align_function
sm3_one_block_sse:
        call    sm3_base_init
        mov     DWORD(arg3), 1
        call    sm3_base_update
        ret

mksection stack-noexec
