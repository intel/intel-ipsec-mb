;;
;; Copyright (c) 2020-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/crc32_refl_const.inc"
%include "include/crc32_refl.inc"
%include "include/cet.inc"
%include "include/align_avx512.inc"

%ifndef LINUX
%xdefine        arg1 rcx
%xdefine        arg2 rdx
%xdefine        arg3 r8
%xdefine        arg4 r9
%else
%xdefine        arg1 rdi
%xdefine        arg2 rsi
%xdefine        arg3 rdx
%xdefine        arg4 rcx
%endif

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
align_function
MKGLOBAL(crc16_x25_avx512, function,)
crc16_x25_avx512:
        endbranch64
        lea             arg4, [rel crc16_x25_ccitt_const]
        mov             arg3, arg2
        mov             arg2, arg1
        mov             DWORD(arg1), 0xffff0000

        call            crc32_refl_by16_vclmul_avx512

        and             eax, 0xffff

        ret

mksection stack-noexec
