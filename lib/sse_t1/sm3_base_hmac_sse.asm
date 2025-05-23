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
extern sm3_base_update

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/imb_job.inc"
%include "include/memcpy.inc"
%include "include/align_sse.inc"

%ifdef LINUX

%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx

%define gp1     rax
%define gp2     r8
%define gp3     r9
%define gp4     r10
%define gp5     r11
%define gp6     arg4
%define gp7     r12
%define gp8     r13
%define gp9     r14
%define gp10    r15
%define gp11    rbx
%define gp12    rbp

%else

%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9

%define gp1     rax
%define gp2     r10
%define gp3     r11
%define gp4     arg4
%define gp5     rdi
%define gp6     rsi
%define gp7     r12
%define gp8     r13
%define gp9     r14
%define gp10    r15
%define gp11    rbx
%define gp12    rbp

%endif

%xdefine t1     gp1
%xdefine t2     gp2
%xdefine t3     gp3
%xdefine t4     gp4

%xdefine r1     gp12
%xdefine r2     gp11
%xdefine r3     gp10

%define arg_job         r1
%define arg_msg         r2
%define arg_msg_length  r3

;; HMAC-SM3 stack frame
struc STACK
_B:             resb    64      ; two SM3 blocks (aligned to 16)
_D:             resd    8       ; digest
_gpr_save:      resq    8       ; space for GPR's
_rsp_save:      resq    1       ; space for rsp pointer
endstruc

mksection .rodata

align 16
SHUFF_MASK:
	db 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

;; PAD BLOCKS are used for OPAD where digest of IPAD + message is put into the block.
;; The blocks below fill up top 32 bytes of the block,
;; low 32 bytes get filled with the digest.
align 16
PAD_BLOCK1:
	db 0x80, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00

align 16
PAD_BLOCK2:
        ;; last qword has to encode length in bits of: BLOCK size + DIGEST size
        ;; (64 + 32) * 8 = 768 = 0x300 in hex
	db 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x00, 0x00
	db 0x00, 0x00, 0x03, 0x00

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
;; IMB_JOB *sm3_hmac_submit_sse(IMB_JOB *job)
MKGLOBAL(sm3_hmac_submit_sse,function,internal)
align_function
sm3_hmac_submit_sse:
        FUNC_START

        ;; save input arguments
        mov     arg_job, arg1

        ;; init the digest with IPAD
        mov     t1, [arg_job + _auth_key_xor_ipad]
        movdqu  xmm0, [t1 + 0*16]
        movdqu  xmm1, [t1 + 1*16]
        movdqa  [rsp + _D + 0*16], xmm0
        movdqa  [rsp + _D + 1*16], xmm1

        ;; update digest for full number of blocks
        lea     arg1, [rsp + _D]
        mov     arg2, [arg_job + _src]
        add     arg2, [arg_job + _hash_start_src_offset]
        mov     arg_msg, arg2
        mov     arg_msg_length, [arg_job + _msg_len_to_hash_in_bytes]
        mov     arg3, arg_msg_length
        shr     arg3, 6         ;; msg_length / SM3_BLOCK_SIZE
        call    sm3_base_update

        ;; prepare partial block
        mov     DWORD(arg3), 63
        not     arg3
        and     arg3, arg_msg_length    ;; number of bytes processed already
        add     arg_msg, arg3           ;; move message pointer to start of the partial block
        mov     t2, arg_msg_length
        sub     t2, arg3                ;; t2 =  number of bytes left

        xor     DWORD(arg1), DWORD(arg1)

align_loop
.partial_block_copy:
        cmp     DWORD(arg1), DWORD(t2)
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
        cmp     DWORD(t2), 64 - 8
        jb      .add_msg_length

        ;; if length field doesn't fit into this partial block
        ;; - compute digest on the current block
        ;; - clear the block for the length to be put into it next
        lea     arg1, [rsp + _D]
        lea     arg2, [rsp + _B]
        mov     DWORD(arg3), 1
        call    sm3_base_update

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
        lea     t1, [arg_msg_length*8 + 64*8]  ;; original message length in bits + 1 IPAD block
        bswap   t1
        mov     [rsp + _B + 7*8], t1

        lea     arg1, [rsp + _D]
        lea     arg2, [rsp + _B]
        mov     DWORD(arg3), 1
        call    sm3_base_update

align_label
.process_opad:
        movdqa  xmm0, [rsp + _D + 0*16]
        movdqa  xmm1, [rsp + _D + 1*16]
        movdqa  xmm2, [rel PAD_BLOCK1]
        movdqa  xmm3, [rel PAD_BLOCK2]
        pshufb  xmm0, [rel SHUFF_MASK]
        pshufb  xmm1, [rel SHUFF_MASK]
        movdqa  [rsp + _B + 0*16], xmm0
        movdqa  [rsp + _B + 1*16], xmm1
        movdqa  [rsp + _B + 2*16], xmm2
        movdqa  [rsp + _B + 3*16], xmm3

        ;; init the digest with OPAD
        mov     t1, [arg_job + _auth_key_xor_opad]
        movdqu  xmm0, [t1 + 0*16]
        movdqu  xmm1, [t1 + 1*16]
        movdqa  [rsp + _D + 0*16], xmm0
        movdqa  [rsp + _D + 1*16], xmm1

        lea     arg1, [rsp + _D]
        lea     arg2, [rsp + _B]
        mov     DWORD(arg3), 1
        call    sm3_base_update

align_label
.tag_store_start:
        ;; byte swap the digest and write it back
        lea     arg1, [rsp + _D]
        movdqa  xmm0, [arg1 + 0*16]
        movdqa  xmm1, [arg1 + 1*16]
        pshufb  xmm0, [rel SHUFF_MASK]
        pshufb  xmm1, [rel SHUFF_MASK]

        mov     t1, [arg_job + _auth_tag_output]
        mov     t2, [arg_job + _auth_tag_output_len_in_bytes]
        cmp     t2, 32
        je      .tag_store_32

        cmp     t2, 16
        jb      .tag_store_1_15
        je      .tag_store_16

align_label
.tag_store_16_31:
        movdqu  [t1 + 0*16], xmm0
        lea     t1, [t1 + 16]
        movdqa  xmm1, xmm0
        sub     t2, 16
        ;; fall through to store remaining tag bytes

align_label
.tag_store_1_15:
        simd_store_sse  t1, xmm0, t2, t3, t4
        jmp     .tag_store_end

align_label
.tag_store_32:
        movdqu  [t1 + 1*16], xmm1
        ;; fall through to store 1st 16 bytes

align_label
.tag_store_16:
        movdqu  [t1 + 0*16], xmm0
        ;; fall through

align_label
.tag_store_end:

%ifdef SAFE_DATA
        pxor    xmm0, xmm0
        pxor    xmm1, xmm1
        pxor    xmm2, xmm2
        pxor    xmm3, xmm3

        movdqu  [rsp + _B + 0*16], xmm0
        movdqu  [rsp + _B + 1*16], xmm0
        movdqu  [rsp + _B + 2*16], xmm0
        movdqu  [rsp + _B + 3*16], xmm0
%endif

        mov     rax, arg_job
        or      dword [arg_job + _status], IMB_STATUS_COMPLETED_AUTH
        FUNC_END
        ret

mksection stack-noexec
