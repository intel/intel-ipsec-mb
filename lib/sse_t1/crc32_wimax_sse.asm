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

%ifndef CRC32_WIMAX_DATA_FN
%define CRC32_WIMAX_DATA_FN crc32_wimax_ofdma_data_sse
%endif

%ifndef CRC8_WIMAX_HCS_FN
%define CRC8_WIMAX_HCS_FN crc8_wimax_ofdma_hcs_sse
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
MKGLOBAL(CRC32_WIMAX_DATA_FN, function,)
align_function
CRC32_WIMAX_DATA_FN:
        endbranch64

        lea             arg4, [rel crc32_wimax_ofdma_data_const]
        mov             arg3, arg2
        mov             arg2, arg1
        mov             DWORD(arg1), 0xffff_ffff

        call            CRC32_FN

        not             eax

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
MKGLOBAL(CRC8_WIMAX_HCS_FN, function,)
align_function
CRC8_WIMAX_HCS_FN:
        endbranch64

        lea             arg4, [rel crc32_wimax_ofdma_hcs8_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            CRC32_FN

        shr             eax, 24  ; adjust to 8-bit poly

        ret

mksection stack-noexec
