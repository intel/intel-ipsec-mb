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

%ifndef CRC16_FP_DATA_FN
%define CRC16_FP_DATA_FN crc16_fp_data_sse
%endif

%ifndef CRC11_FP_HEADER_FN
%define CRC11_FP_HEADER_FN crc11_fp_header_sse
%endif

%ifndef CRC7_FP_HEADER_FN
%define CRC7_FP_HEADER_FN crc7_fp_header_sse
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
MKGLOBAL(CRC16_FP_DATA_FN, function,)
align_function
CRC16_FP_DATA_FN:
        endbranch64

        lea             arg4, [rel crc32_fp_data_crc16_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            CRC32_FN

        shr             eax, 16  ; adjust to 16-bit poly

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
MKGLOBAL(CRC11_FP_HEADER_FN, function,)
align_function
CRC11_FP_HEADER_FN:
        endbranch64

        lea             arg4, [rel crc32_fp_header_crc11_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            CRC32_FN

        shr             eax, 21  ; adjust to 11-bit poly

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
MKGLOBAL(CRC7_FP_HEADER_FN, function,)
align_function
CRC7_FP_HEADER_FN:
        endbranch64

        lea             arg4, [rel crc32_fp_header_crc7_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            CRC32_FN

        shr             eax, 25  ; adjust to 7-bit poly

        ret

mksection stack-noexec
