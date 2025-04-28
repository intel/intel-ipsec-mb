;;
;; Copyright (c) 2023-2024, Intel Corporation
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

;; https://datatracker.ietf.org/doc/html/draft-shen-sm3-hash

extern sm3_base_init
extern sm3_update_ni_x1

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/memcpy.inc"
%include "include/imb_job.inc"
%include "include/align_avx.inc"

%ifdef LINUX

%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx

%define t1      rax
%define t2      r8
%define t3      r9
%define t4      r10
%define t5      r11
%define t6      r12
%define t7      r13
%define t8      r14
%define t9      r15
%define t10     rbx
%define t11     rbp

%else

%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9

%define t1      rax
%define t2      r10
%define t3      r11
%define t4      rdi
%define t5      rsi
%define t6      r12
%define t7      r13
%define t8      r14
%define t9      r15
%define t10     rbx
%define t11     rbp

%endif

%xdefine r1     t6
%xdefine r2     t7
%xdefine r3     t8
%xdefine r4     t9
%xdefine r5     t10
%xdefine r6     t11

%define arg_tag         r1
%define arg_tag_length  r2
%define arg_msg         r3
%define arg_msg_length  r4

;; SM3 stack frame
struc STACK
_B:             resb    64      ; one SM3 block (aligned to 16)
_D:             resd    8       ; digest
_gpr_save:      resq    8       ; space for GPR's
_rsp_save:      resq    1       ; space for rsp pointer
endstruc

mksection .rodata

align 16
SHUFF_MASK:
	db 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

mksection .text

;; =============================================================================
;; Save registers on the stack and create stack frame
;; =============================================================================

%macro FUNC_START 0
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16
        mov     [rsp + _rsp_save], rax
        mov     [rsp + _gpr_save + 0*8], rbx
        mov     [rsp + _gpr_save + 1*8], rbp
        mov     [rsp + _gpr_save + 2*8], r12
        mov     [rsp + _gpr_save + 3*8], r13
        mov     [rsp + _gpr_save + 4*8], r14
        mov     [rsp + _gpr_save + 5*8], r15
%ifidn __OUTPUT_FORMAT__, win64
        mov     [rsp + _gpr_save + 6*8], rdi
        mov     [rsp + _gpr_save + 7*8], rsi
%endif
%endmacro

;; =============================================================================
;; Restore registers from the stack
;; =============================================================================

%macro FUNC_END 0
        mov     rbx, [rsp + _gpr_save + 0*8]
        mov     rbp, [rsp + _gpr_save + 1*8]
        mov     r12, [rsp + _gpr_save + 2*8]
        mov     r13, [rsp + _gpr_save + 3*8]
        mov     r14, [rsp + _gpr_save + 4*8]
        mov     r15, [rsp + _gpr_save + 5*8]
%ifidn __OUTPUT_FORMAT__, win64
        mov     rdi, [rsp + _gpr_save + 6*8]
        mov     rsi, [rsp + _gpr_save + 7*8]
%endif
        mov     rsp, [rsp + _rsp_save]
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sm3_tag_store_avx(void *tag_ptr, const uint64_t tag_length, xmm1:xmm0 tag)
;; NOTE: may clobber t1 & t2 (rax & r10)
align_function
MKGLOBAL(sm3_tag_store_avx,function,internal)
sm3_tag_store_avx:
        cmp     arg2, 32
        je      .tag_store_32

        cmp     arg2, 16
        jb      .tag_store_1_15
        je      .tag_store_16

align_label
.tag_store_16_31:
        vmovdqu [arg1 + 0*16], xmm0
        lea     arg1, [arg1 + 16]
        vmovdqa xmm0, xmm1
        sub     arg2, 16
        ;; fall through to store remaining tag bytes

align_label
.tag_store_1_15:
        simd_store_avx  arg1, xmm0, arg2, t1, t2
        jmp     .tag_store_end

align_label
.tag_store_32:
        vmovdqu [arg1 + 1*16], xmm1
        ;; fall through to store 1st 16 bytes

align_label
.tag_store_16:
        vmovdqu [arg1 + 0*16], xmm0
        ;; fall through

align_label
.tag_store_end:
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sm3_msg_ni_avx2(void *tag, const uint64_t tag_length, const void *msg, const uint64_t msg_length)
align_function
MKGLOBAL(sm3_msg_ni_avx2,function,internal)
sm3_msg_ni_avx2:
        FUNC_START

        ;; save input arguments
        mov     arg_tag, arg1
        mov     arg_tag_length, arg2
        mov     arg_msg, arg3
        mov     arg_msg_length, arg4

        ;; init the digest
        lea     arg1, [rsp + _D]
        call    sm3_base_init

        ;; update digest for full number of blocks
        ;; - arg1 stays unchanged
        mov     arg2, arg_msg
        mov     arg3, arg_msg_length
        shr     arg3, 6         ;; msg_length / SM3_BLOCK_SIZE
        call    sm3_update_ni_x1

        ;; prepare partial block
        mov     DWORD(arg3), 63
        not     arg3
        and     arg3, arg_msg_length    ;; number of bytes processed already
        add     arg_msg, arg3           ;; move message pointer to start of the partial block
        mov     r5, arg_msg_length
        sub     r5, arg3                ;; r5 =  number of bytes left

        xor     DWORD(arg1), DWORD(arg1)
align_loop
.partial_block_copy:
        cmp     DWORD(arg1), DWORD(r5)
        je      .partial_block_copy_exit
        mov     BYTE(t1), [arg_msg + arg1]
        mov     [rsp + _B + arg1], BYTE(t1)
        inc     DWORD(arg1)
        jmp     .partial_block_copy

align_label
.partial_block_copy_exit:
        ;; put end of message marker
        mov     BYTE [rsp + _B + arg1], 0x80
        inc     DWORD(arg1)

        xor     DWORD(t1), DWORD(t1)
align_loop
.partial_block_zero:
        cmp     DWORD(arg1), 64
        je      .partial_block_zero_exit
        mov     [rsp + _B + arg1], BYTE(t1)
        inc     DWORD(arg1)
        jmp     .partial_block_zero

align_label
.partial_block_zero_exit:
        cmp     DWORD(r5), 64 - 8
        jb      .add_msg_length

        ;; if length field doesn't fit into this partial block
        ;; - compute digest on the current block
        ;; - clear the block for the length to be put into it next
        lea     arg1, [rsp + _D]
        lea     arg2, [rsp + _B]
        mov     DWORD(arg3), 1
        call    sm3_update_ni_x1

        xor     DWORD(t1), DWORD(t1)
        mov     [rsp + _B + 0*8], t1
        mov     [rsp + _B + 1*8], t1
        mov     [rsp + _B + 2*8], t1
        mov     [rsp + _B + 3*8], t1
        mov     [rsp + _B + 4*8], t1
        mov     [rsp + _B + 5*8], t1
        mov     [rsp + _B + 6*8], t1

align_label
.add_msg_length:
        lea     t1, [arg_msg_length*8]  ;; original message length in bits
        movbe   [rsp + _B + 7*8], t1

        lea     arg1, [rsp + _D]
        lea     arg2, [rsp + _B]
        mov     DWORD(arg3), 1
        call    sm3_update_ni_x1

align_label
.tag_store_start:
        ;; byte swap the digest and write it back
        vmovdqa xmm0, [rsp + _D + 0*16]
        vmovdqa xmm1, [rsp + _D + 1*16]
        vpshufb xmm0, xmm0, [rel SHUFF_MASK]
        vpshufb xmm1, xmm1, [rel SHUFF_MASK]

        mov     arg1, arg_tag
        mov     arg2, arg_tag_length
        call    sm3_tag_store_avx

%ifdef SAFE_DATA
        vpxor   xmm0, xmm0, xmm0
        vpxor   xmm1, xmm1, xmm1

        vmovdqu [rsp + _B + 0*16], ymm0
        vmovdqu [rsp + _B + 2*16], ymm0
%endif
        FUNC_END
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; IMB_JOB *sm3_msg_submit_ni_avx2(IMB_JOB *)
align_function
MKGLOBAL(sm3_msg_submit_ni_avx2,function,internal)
sm3_msg_submit_ni_avx2:
        push    arg1

        mov     arg4, [arg1 + _msg_len_to_hash_in_bytes]
        mov     arg3, [arg1 + _src]
        add     arg3, [arg1 + _hash_start_src_offset]
        mov     arg2, [arg1 + _auth_tag_output_len_in_bytes]
        mov     arg1, [arg1 + _auth_tag_output]
        call    sm3_msg_ni_avx2

        pop     rax
        or      dword [rax + _status], IMB_STATUS_COMPLETED_AUTH
        ret

mksection stack-noexec
