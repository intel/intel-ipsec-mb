;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/memcpy.inc"
%include "include/align_avx.inc"

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%endif

mksection .text

; void memcpy_fn_avx_16(void *dst, const void *src, const size_t size)
MKGLOBAL(memcpy_fn_avx_16,function,internal)
align_function
memcpy_fn_avx_16:
        memcpy_avx_16 arg1, arg2, arg3, r10, r11

        ret

mksection stack-noexec
