;;
;; Copyright (c) 2025, Intel Corporation
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

%use smartalign
; %define AES_CTR_DECLARE_DATA 1
%define CNTR_CCM_AVX2 1

%include "include/aes_cntr_by16_vaes_avx2.inc"
%include "include/align_avx.inc"

%include "include/cet.inc"

; STACK_SPACE needs to be an odd multiple of 8
; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    6
_rsp_save:      resq    1
endstruc

;; Save registers states
%macro FUNC_SAVE 0
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -32

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*4], rsi
        mov     [rsp + _gpr_save + 8*5], rdi
%endif
        mov     [rsp + _rsp_save], rax  ; original SP
%endmacro

;; Restore registers states
%macro FUNC_RESTORE 0
        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*4]
        mov     rdi, [rsp + _gpr_save + 8*5]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP
%endmacro

align_function
; IMB_JOB * aes_cntr_ccm_128_vaes_avx2(IMB_JOB *job)
; arg 1 : job
MKGLOBAL(aes_cntr_ccm_128_vaes_avx2,function,internal)
aes_cntr_ccm_128_vaes_avx2:
        endbranch64
        FUNC_SAVE
        DO_CNTR 128, CCM
        FUNC_RESTORE
        ret

align_function
; IMB_JOB * aes_cntr_ccm_256_vaes_avx2(IMB_JOB *job)
; arg 1 : job
MKGLOBAL(aes_cntr_ccm_256_vaes_avx2,function,internal)
aes_cntr_ccm_256_vaes_avx2:
        endbranch64
        FUNC_SAVE
        DO_CNTR 256, CCM
        FUNC_RESTORE
        ret

mksection stack-noexec
