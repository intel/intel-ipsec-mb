;;
;; Copyright (c) 2019-2024, Intel Corporation
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

%ifndef ETHERNET_FCS_FN
%define ETHERNET_FCS_FN ethernet_fcs_avx2
%endif

%ifndef ETHERNET_FCS_FN_LOCAL
%define ETHERNET_FCS_FN_LOCAL ethernet_fcs_avx2_local
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
MKGLOBAL(ETHERNET_FCS_FN, function,)
ETHERNET_FCS_FN:
        endbranch64
        lea             arg4, [rel crc32_ethernet_fcs_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)
        not             DWORD(arg1)             ; XorIn = 0xFFFFFFFF for Ethernet FCS

        call            crc32_refl_vclmul_avx2

        not             eax                     ; XorOut = 0xFFFFFFFF for Ethernet FCS

        ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; arg3 - place to store computed CRC value (can be NULL)
;; Returns CRC value through RAX
align_function
MKGLOBAL(ETHERNET_FCS_FN_LOCAL, function,internal)
ETHERNET_FCS_FN_LOCAL:
        mov             rax, rsp
        sub             rsp, STACK_FRAME_size
        and             rsp, -16

        mov             [rsp + _rsp_save], rax
        mov             [rsp + _gpr_save], arg3

        lea             arg4, [rel crc32_ethernet_fcs_const]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_refl_vclmul_avx2

        mov             arg3, [rsp + _gpr_save]
        or              arg3, arg3
        je              .local_fn_exit

        mov             [arg3], eax

align_label
.local_fn_exit:
        mov             rsp, [rsp + _rsp_save]
        ret

mksection stack-noexec
