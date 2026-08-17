;;
;; Copyright (c) 2020-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/crc32_const.inc"
%include "include/cet.inc"
%include "include/align_sse.inc"

[bits 64]
default rel

%ifndef CRC32_LTE24A_FN
%define CRC32_LTE24A_FN crc24_lte_a_sse
%endif

%ifndef CRC32_LTE24B_FN
%define CRC32_LTE24B_FN crc24_lte_b_sse
%endif

%ifndef CRC32_FN
%define CRC32_FN crc32_by8_sse
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
MKGLOBAL(CRC32_LTE24A_FN, function,)
align_function
CRC32_LTE24A_FN:
        endbranch64

        lea             arg4, [rel crc32_lte24_a_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            CRC32_FN

        shr             eax, 8  ; adjust to 24-bit poly

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
MKGLOBAL(CRC32_LTE24B_FN, function,)
align_function
CRC32_LTE24B_FN:
        endbranch64

        lea             arg4, [rel crc32_lte24_b_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            CRC32_FN

        shr             eax, 8  ; adjust to 24-bit poly

        ret

mksection stack-noexec
