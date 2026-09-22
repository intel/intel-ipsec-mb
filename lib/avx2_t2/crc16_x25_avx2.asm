;;
;; Copyright (c) 2020-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/crc32_refl_const.inc"
%include "include/cet.inc"
%include "include/align_avx.inc"

[bits 64]
default rel

%ifndef CRC16_X25_FN
%define CRC16_X25_FN crc16_x25_avx2
%endif

%ifdef LINUX
%define arg1            rdi
%define arg2            rsi
%define arg3            rdx
%define arg4            rcx
%else
%define arg1            rcx
%define arg2            rdx
%define arg3            r8
%define arg4            r9
%endif

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
align_function
MKGLOBAL(CRC16_X25_FN, function,)
CRC16_X25_FN:
        endbranch64
        lea             arg4, [rel crc16_x25_ccitt_const]
        mov             arg3, arg2
        mov             arg2, arg1
        mov             DWORD(arg1), 0xffff             ; XorIn = 0xFFFF for X25

        call            crc32_refl_vclmul_avx2

        not             eax                             ; XorOut = 0xFFFF for X25
        and             eax, 0xffff

        ret

mksection stack-noexec
