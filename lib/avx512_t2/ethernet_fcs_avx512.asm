;;
;; Copyright (c) 2020-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/crc32_refl_const.inc"
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

struc STACK_FRAME
_gpr_save:      resq    1
_rsp_save:      resq    1
endstruc

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
align_function
MKGLOBAL(ethernet_fcs_avx512, function,)
ethernet_fcs_avx512:
        endbranch64
        lea             arg4, [rel crc32_ethernet_fcs_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_refl_by16_vclmul_avx512

        ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; arg3 - place to store computed CRC value (can be NULL)
;; Returns CRC value through RAX
align_function
MKGLOBAL(ethernet_fcs_avx512_local, function,internal)
ethernet_fcs_avx512_local:
        endbranch64
        mov             rax, rsp
        sub             rsp, STACK_FRAME_size
        and             rsp, -16

        mov             [rsp + _rsp_save], rax
        mov             [rsp + _gpr_save], arg3

        lea             arg4, [rel crc32_ethernet_fcs_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_refl_by16_vclmul_avx512

        mov             arg3, [rsp + _gpr_save]
        or              arg3, arg3
        je              .local_fn_exit

        mov             [arg3], eax

align_label
.local_fn_exit:
        mov             rsp, [rsp + _rsp_save]
        ret

mksection stack-noexec
