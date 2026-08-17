;;
;; Copyright (c) 2020-2024, Intel Corporation
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
MKGLOBAL(crc16_fp_data_avx, function,)
crc16_fp_data_avx:
        endbranch64

        lea             arg4, [rel crc32_fp_data_crc16_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_by8_avx

        shr             eax, 16          ; adjust for 16-bit poly

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
align_function
MKGLOBAL(crc11_fp_header_avx, function,)
crc11_fp_header_avx:
        endbranch64

        lea             arg4, [rel crc32_fp_header_crc11_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_by8_avx

        shr             eax, 21          ; adjust for 11-bit poly

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
align_function
MKGLOBAL(crc7_fp_header_avx, function,)
crc7_fp_header_avx:
        endbranch64

        lea             arg4, [rel crc32_fp_header_crc7_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_by8_avx

        shr             eax, 25          ; adjust for 7-bit poly

        ret

mksection stack-noexec
