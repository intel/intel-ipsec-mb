;;
;; Copyright (c) 2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/crc32_const.inc"
%include "include/cet.inc"
%include "include/align_avx.inc"

[bits 64]
default rel

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
MKGLOBAL(crc10_iuup_data_avx2, function,)
crc10_iuup_data_avx2:
        endbranch64
        lea             arg4, [rel crc32_iuup_data_crc10_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_vclmul_avx2

        shr             eax, 22          ; adjust for 10-bit poly

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
align_function
MKGLOBAL(crc6_iuup_header_avx2, function,)
crc6_iuup_header_avx2:
        endbranch64
        lea             arg4, [rel crc32_iuup_header_crc6_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_vclmul_avx2

        shr             eax, 26          ; adjust for 6-bit poly

        ret

mksection stack-noexec
