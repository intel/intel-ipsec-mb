;;
;; Copyright (c) 2018, Intel Corporation
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


%include "os.asm"
%include "job_aes_hmac.asm"
%include "mb_mgr_datastruct.asm"

%include "reg_sizes.asm"
%include "memcpy.asm"
%include "const.inc"
;%define DO_DBGPRINT
%include "dbgprint.asm"

%define AES128_CBC_MAC aes128_cbc_mac_x8
%define SUBMIT_JOB_AES_CMAC_AUTH submit_job_aes_cmac_auth_avx
%define FLUSH_JOB_AES_CMAC_AUTH flush_job_aes_cmac_auth_avx

extern AES128_CBC_MAC

section .data
default rel

align 16
len_masks:
	;ddq 0x0000000000000000000000000000FFFF
	dq 0x000000000000FFFF, 0x0000000000000000
	;ddq 0x000000000000000000000000FFFF0000
	dq 0x00000000FFFF0000, 0x0000000000000000
	;ddq 0x00000000000000000000FFFF00000000
	dq 0x0000FFFF00000000, 0x0000000000000000
	;ddq 0x0000000000000000FFFF000000000000
	dq 0xFFFF000000000000, 0x0000000000000000
	;ddq 0x000000000000FFFF0000000000000000
	dq 0x0000000000000000, 0x000000000000FFFF
	;ddq 0x00000000FFFF00000000000000000000
	dq 0x0000000000000000, 0x00000000FFFF0000
	;ddq 0x0000FFFF000000000000000000000000
	dq 0x0000000000000000, 0x0000FFFF00000000
	;ddq 0xFFFF0000000000000000000000000000
	dq 0x0000000000000000, 0xFFFF000000000000
dupw:
	;ddq 0x01000100010001000100010001000100
	dq 0x0100010001000100, 0x0100010001000100
one:	dq  1
two:	dq  2
three:	dq  3
four:	dq  4
five:	dq  5
six:	dq  6
seven:	dq  7

section .text

%define APPEND(a,b) a %+ b

%ifdef LINUX
%define arg1	rdi
%define arg2	rsi
%else
%define arg1	rcx
%define arg2	rdx
%endif

%define state	arg1
%define job	arg2
%define len2	arg2

%define job_rax          rax

; idx needs to be in rbp
%define len              rbp
%define idx              rbp
%define tmp              rbp

%define lane             r8

%define iv               r9
%define m_last           r10
%define n                r11

%define unused_lanes     rbx
%define r                rbx

%define tmp3             r12
%define tmp4             r13
%define tmp2             r14

%define flag             r15
%define good_lane        r15

; STACK_SPACE needs to be an odd multiple of 8
; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:	resq	8
_rsp_save:	resq	1
endstruc

;;; ===========================================================================
;;; ===========================================================================
;;; MACROS
;;; ===========================================================================
;;; ===========================================================================

;;; ===========================================================================
;;; AES CMAC job submit & flush
;;; ===========================================================================
;;; SUBMIT_FLUSH [in] - SUBMIT, FLUSH job selection
%macro GENERIC_SUBMIT_FLUSH_JOB_AES_CMAC_AVX 1
%define %%SUBMIT_FLUSH %1

        mov	rax, rsp
        sub	rsp, STACK_size
        and	rsp, -16

	mov	[rsp + _gpr_save + 8*0], rbx
	mov	[rsp + _gpr_save + 8*1], rbp
	mov	[rsp + _gpr_save + 8*2], r12
	mov	[rsp + _gpr_save + 8*3], r13
	mov	[rsp + _gpr_save + 8*4], r14
	mov	[rsp + _gpr_save + 8*5], r15
%ifndef LINUX
	mov	[rsp + _gpr_save + 8*6], rsi
	mov	[rsp + _gpr_save + 8*7], rdi
%endif
	mov	[rsp + _rsp_save], rax	; original SP

        ;; Find free lane
 	mov	unused_lanes, [state + _aes_cmac_unused_lanes]

%ifidn %%SUBMIT_FLUSH, SUBMIT
        mov     flag, 0

 	mov	lane, unused_lanes
        and	lane, 0xF
 	shr	unused_lanes, 4
 	mov	[state + _aes_cmac_unused_lanes], unused_lanes

        ;; Copy job info into lane
 	mov	[state + _aes_cmac_job_in_lane + lane*8], job
        ;; Copy keys into lane args
 	mov	tmp, [job + _key_expanded]
 	mov	[state + _aes_cmac_args_keys + lane*8], tmp
        mov     tmp, lane
        shl     tmp, 4  ; lane*16

        ;; Zero IV to store digest
        vpxor   xmm0, xmm0
        vmovdqa [state + _aes_cmac_args_IV + tmp], xmm0

        lea     m_last, [state + _aes_cmac_scratch + tmp]

        ;; Check number of blocks and for partial block
        mov     len, [job + _msg_len_to_hash_in_bytes]

        mov     r, len  ; set remainder
        and     r, 0xf

        lea     n, [len + 0xf] ; set num blocks
        shr     n, 4

        jz      %%_lt_one_block ; check one or more blocks?

        ;; One or more blocks, potentially partial
        mov     word [state + _aes_cmac_init_done + lane*2], 0

        mov     tmp2, [job + _src]
        add     tmp2, [job + _hash_start_src_offset_in_bytes]
        mov     [state + _aes_cmac_args_in + lane*8], tmp2

        ;; len = (n-1)*16
        lea     tmp2, [n - 1]
        shl     tmp2, 4
        vmovdqa xmm0, [state + _aes_cmac_lens]
        XVPINSRW xmm0, xmm1, tmp, lane, tmp2, scale_x16
        vmovdqa [state + _aes_cmac_lens], xmm0

        ;; Set flag = (r == 0)
        or      r, r
        jz      %%_complete_block

%%_not_complete_block:
        ;; M_last = padding(M_n) XOR K2
        vpxor   xmm1, xmm1 ; zero *M_last
        vmovdqa [m_last], xmm1

        mov     tmp, [job + _src]
        add     tmp, [job + _hash_start_src_offset_in_bytes]
        lea     tmp3, [n - 1]
        shl     tmp3, 4
        add     tmp, tmp3

        memcpy_avx_16 m_last, tmp, r, tmp4, iv

        ;; src + n + r
        mov     byte [m_last + r], 0x80
        mov     tmp3, [job + _skey2]
        vmovdqu xmm0, [tmp3]
        vpxor   xmm0, [m_last]
        vmovdqa [m_last], xmm0

%%_step_5:
        ;; Find min length
        vmovdqa xmm0, [state + _aes_cmac_lens]
        vphminposuw xmm1, xmm0

        cmp     byte [state + _aes_cmac_unused_lanes], 0xf
        jne     %%_return_null

%else ; end SUBMIT

        ;; Check at least one job
        bt      unused_lanes, 35
        jc      %%_return_null

        ;; Find a lane with a non-null job
        xor     good_lane, good_lane
        cmp     qword [state + _aes_cmac_job_in_lane + 1*8], 0
        cmovne  good_lane, [rel one]
        cmp     qword [state + _aes_cmac_job_in_lane + 2*8], 0
        cmovne  good_lane, [rel two]
        cmp     qword [state + _aes_cmac_job_in_lane + 3*8], 0
        cmovne  good_lane, [rel three]
        cmp     qword [state + _aes_cmac_job_in_lane + 4*8], 0
        cmovne  good_lane, [rel four]
        cmp     qword [state + _aes_cmac_job_in_lane + 5*8], 0
        cmovne  good_lane, [rel five]
        cmp     qword [state + _aes_cmac_job_in_lane + 6*8], 0
        cmovne  good_lane, [rel six]
        cmp     qword [state + _aes_cmac_job_in_lane + 7*8], 0
        cmovne  good_lane, [rel seven]

        ; Copy good_lane to empty lanes
        mov     tmp2, [state + _aes_cmac_args_in + good_lane*8]
        mov     tmp3, [state + _aes_cmac_args_keys + good_lane*8]
        shl     good_lane, 4 ; multiply by 16
        vmovdqa xmm2, [state + _aes_cmac_args_IV + good_lane]
        vmovdqa xmm0, [state + _aes_cmac_lens]

%assign I 0
%rep 8
        cmp     qword [state + _aes_cmac_job_in_lane + I*8], 0
        jne     APPEND(skip_,I)
        mov     [state + _aes_cmac_args_in + I*8], tmp2
        mov     [state + _aes_cmac_args_keys + I*8], tmp3
        vmovdqa [state + _aes_cmac_args_IV + I*16], xmm2
        vpor    xmm0, [rel len_masks + 16*I]
APPEND(skip_,I):
%assign I (I+1)
%endrep
        ;; Find min length
        vphminposuw xmm1, xmm0

%endif ; end FLUSH

%%_cmac_round:
        vpextrw DWORD(len2), xmm1, 0   ; min value
        vpextrw DWORD(idx), xmm1, 1    ; min index (0...3)
        cmp     len2, 0
        je      %%_len_is_0
        vpshufb xmm1, xmm1, [rel dupw]   ; duplicate words across all lanes
        vpsubw  xmm0, xmm1
	vmovdqa [state + _aes_cmac_lens], xmm0

        ; "state" and "args" are the same address, arg1
        ; len2 is arg2
        call    AES128_CBC_MAC
        ; state and idx are intact

%%_len_is_0:
        ; Check if job complete
        test    word [state + _aes_cmac_init_done + idx*2], 0xffff
        jnz     %%_copy_complete_digest

        ; Finish step 6
        mov     word [state + _aes_cmac_init_done + idx*2], 1

        vmovdqa xmm0, [state + _aes_cmac_lens]
        XVPINSRW xmm0, xmm1, tmp3, idx, 16, scale_x16
        vmovdqa [state + _aes_cmac_lens], xmm0

        vphminposuw xmm1, xmm0 ; find min length

        mov     tmp3, idx
        shl     tmp3, 4  ; idx*16
        lea     m_last, [state + _aes_cmac_scratch + tmp3]
        mov     [state + _aes_cmac_args_in + idx*8], m_last

        jmp     %%_cmac_round

%%_copy_complete_digest:
        ; Job complete, copy digest to AT output
 	mov	job_rax, [state + _aes_cmac_job_in_lane + idx*8]

        mov     tmp4, idx
        shl     tmp4, 4
        lea     tmp3, [state + _aes_cmac_args_IV + tmp4]
        mov     tmp4, [job_rax + _auth_tag_output_len_in_bytes]
        mov     tmp2, [job_rax + _auth_tag_output]

        cmp     tmp4, 16
        jne     %%_ne_16_copy

        ;; 16 byte AT copy
        vmovdqa xmm0, [tmp3]
        vmovdqu [tmp2], xmm0
        jmp     %%_update_lanes

%%_ne_16_copy:
        memcpy_avx_16 tmp2, tmp3, tmp4, lane, iv

%%_update_lanes:
        ; Update unused lanes
        mov	unused_lanes, [state + _aes_cmac_unused_lanes]
        shl	unused_lanes, 4
 	or	unused_lanes, idx
 	mov	[state + _aes_cmac_unused_lanes], unused_lanes

        ; Set return job
        mov	job_rax, [state + _aes_cmac_job_in_lane + idx*8]

 	mov	qword [state + _aes_cmac_job_in_lane + idx*8], 0
 	or	dword [job_rax + _status], STS_COMPLETED_HMAC

%%_return:
	mov	rbx, [rsp + _gpr_save + 8*0]
	mov	rbp, [rsp + _gpr_save + 8*1]
	mov	r12, [rsp + _gpr_save + 8*2]
	mov	r13, [rsp + _gpr_save + 8*3]
	mov	r14, [rsp + _gpr_save + 8*4]
	mov	r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
	mov	rsi, [rsp + _gpr_save + 8*6]
	mov	rdi, [rsp + _gpr_save + 8*7]
%endif
	mov	rsp, [rsp + _rsp_save]	; original SP
	ret

%%_return_null:
	xor	job_rax, job_rax
	jmp	%%_return

%ifidn %%SUBMIT_FLUSH, SUBMIT
%%_complete_block:
        mov     flag, 1

        ;; Block size aligned
        mov     tmp2, [job + _src]
        add     tmp2, [job + _hash_start_src_offset_in_bytes]
        lea     tmp3, [n - 1]
        shl     tmp3, 4
        add     tmp2, tmp3

        ;; M_last = M_n XOR K1
        mov     tmp3, [job + _skey1]
        vmovdqu xmm0, [tmp3]
        vmovdqu xmm1, [tmp2]
        vpxor   xmm0, xmm1
        vmovdqa [m_last], xmm0

        jmp     %%_step_5

%%_lt_one_block:
        ;; Single partial block
        mov     word [state + _aes_cmac_init_done + lane*2], 1
        mov     [state + _aes_cmac_args_in + lane*8], m_last

        vmovdqa xmm0, [state + _aes_cmac_lens]
        XVPINSRW xmm0, xmm1, tmp2, lane, 16, scale_x16
        vmovdqa [state + _aes_cmac_lens], xmm0

        mov     n, 1
        jmp     %%_not_complete_block
%endif
%endmacro


align 64
; JOB_AES_HMAC * submit_job_aes_cmac_auth_avx(MB_MGR_CCM_OOO *state, JOB_AES_HMAC *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_AES_CMAC_AUTH,function,internal)
SUBMIT_JOB_AES_CMAC_AUTH:
        GENERIC_SUBMIT_FLUSH_JOB_AES_CMAC_AVX SUBMIT

; JOB_AES_HMAC * flush_job_aes_cmac_auth_avx(MB_MGR_CCM_OOO *state)
; arg 1 : state
MKGLOBAL(FLUSH_JOB_AES_CMAC_AUTH,function,internal)
FLUSH_JOB_AES_CMAC_AUTH:
        GENERIC_SUBMIT_FLUSH_JOB_AES_CMAC_AVX FLUSH


%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
