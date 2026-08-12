;;
;; Copyright (c) 2020-2024, Intel Corporation
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
