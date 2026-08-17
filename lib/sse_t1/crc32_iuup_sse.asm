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

%ifndef CRC10_IUUP_DATA_FN
%define CRC10_IUUP_DATA_FN crc10_iuup_data_sse
%endif

%ifndef CRC6_IUUP_HEADER_FN
%define CRC6_IUUP_HEADER_FN crc6_iuup_header_sse
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
MKGLOBAL(CRC10_IUUP_DATA_FN, function,)
align_function
CRC10_IUUP_DATA_FN:
        endbranch64

        lea             arg4, [rel crc32_iuup_data_crc10_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            CRC32_FN

        shr             eax, 22  ; adjust to 10-bit poly

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
MKGLOBAL(CRC6_IUUP_HEADER_FN, function,)
align_function
CRC6_IUUP_HEADER_FN:
        endbranch64

        lea             arg4, [rel crc32_iuup_header_crc6_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            CRC32_FN

        shr             eax, 26  ; adjust to 7-bit poly

        ret

mksection stack-noexec
