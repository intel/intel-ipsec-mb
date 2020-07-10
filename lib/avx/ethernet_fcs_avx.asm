;;
;; Copyright (c) 2019-2020, Intel Corporation
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met:
;;
;;     * Redistributions of source code must retain the above copyright notice,
;;       this list of conditions and the following disclaimer.
;;     * Redistributions in binary form must reproduce the above copyright
;;       notice, this list of conditions and the following disclaimer in the
;;       documentation and/or other materials provided with the distribution.
;;     * Neither the name of Intel Corporation nor the names of its contributors
;;       may be used to endorse or promote products derived from this software
;;       without specific prior written permission.
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
;; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
;; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
;; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;

%include "include/os.asm"
%include "include/memcpy.asm"
%include "include/reg_sizes.asm"

extern crc32_refl_by8_avx

[bits 64]
default rel

%ifndef ETHERNET_FCS_FN
%define ETHERNET_FCS_FN ethernet_fcs_avx
%endif

%ifndef ETHERNET_FCS_FN_LOCAL
%define ETHERNET_FCS_FN_LOCAL ethernet_fcs_avx_local
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
_scratch_buf:   resq    2
_gpr_save:      resq    1
_rsp_save:      resq    1
_xmm_save:      resq    8 * 2
endstruc

section .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; Returns CRC value through RAX
align 32
MKGLOBAL(ETHERNET_FCS_FN, function,)
ETHERNET_FCS_FN:
        mov             rax, rsp
        sub             rsp, STACK_FRAME_size
        and             rsp, -16
        mov             [rsp + _rsp_save], rax
%ifndef LINUX
        vmovdqa         [rsp + _xmm_save + 16*0], xmm6
        vmovdqa         [rsp + _xmm_save + 16*1], xmm7
        vmovdqa         [rsp + _xmm_save + 16*2], xmm8
        vmovdqa         [rsp + _xmm_save + 16*3], xmm9
        vmovdqa         [rsp + _xmm_save + 16*4], xmm10
        vmovdqa         [rsp + _xmm_save + 16*5], xmm11
        vmovdqa         [rsp + _xmm_save + 16*6], xmm12
        vmovdqa         [rsp + _xmm_save + 16*7], xmm13
%endif
        lea             arg4, [rel rk1]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_refl_by8_avx

%ifndef LINUX
        vmovdqa         xmm6,  [rsp + _xmm_save + 16*0]
        vmovdqa         xmm7,  [rsp + _xmm_save + 16*1]
        vmovdqa         xmm8,  [rsp + _xmm_save + 16*2]
        vmovdqa         xmm9,  [rsp + _xmm_save + 16*3]
        vmovdqa         xmm10, [rsp + _xmm_save + 16*4]
        vmovdqa         xmm11, [rsp + _xmm_save + 16*5]
        vmovdqa         xmm12, [rsp + _xmm_save + 16*6]
        vmovdqa         xmm13, [rsp + _xmm_save + 16*7]
%endif
        mov             rsp, [rsp + _rsp_save]
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; arg1 - buffer pointer
;; arg2 - buffer size in bytes
;; arg3 - place to store computed CRC value (can be NULL)
;; Returns CRC value through RAX
align 32
MKGLOBAL(ETHERNET_FCS_FN_LOCAL, function,internal)
ETHERNET_FCS_FN_LOCAL:
        mov             rax, rsp
        sub             rsp, STACK_FRAME_size
        and             rsp, -16

        mov             [rsp + _rsp_save], rax
        mov             [rsp + _gpr_save], arg3

        lea             arg4, [rel rk1]
        mov             arg3, arg2
        mov             arg2, arg1
        xor             DWORD(arg1), DWORD(arg1)

        call            crc32_refl_by8_avx

        mov             arg3, [rsp + _gpr_save]
        or              arg3, arg3
        je              .local_fn_exit

        mov             [arg3], eax

.local_fn_exit:
        mov             rsp, [rsp + _rsp_save]
        ret

section .data

; precomputed constants
align 16
rk1:  dq 0x00000000ccaa009e
rk2:  dq 0x00000001751997d0
rk3:  dq 0x000000014a7fe880
rk4:  dq 0x00000001e88ef372
rk5:  dq 0x00000000ccaa009e
rk6:  dq 0x0000000163cd6124
rk7:  dq 0x00000001f7011640
rk8:  dq 0x00000001db710640
rk9:  dq 0x00000001d7cfc6ac
rk10: dq 0x00000001ea89367e
rk11: dq 0x000000018cb44e58
rk12: dq 0x00000000df068dc2
rk13: dq 0x00000000ae0b5394
rk14: dq 0x00000001c7569e54
rk15: dq 0x00000001c6e41596
rk16: dq 0x0000000154442bd4
rk17: dq 0x0000000174359406
rk18: dq 0x000000003db1ecdc
rk19: dq 0x000000015a546366
rk20: dq 0x00000000f1da05aa

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
