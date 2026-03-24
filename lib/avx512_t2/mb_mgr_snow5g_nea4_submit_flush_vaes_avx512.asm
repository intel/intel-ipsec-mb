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

%include "include/mb_mgr_datastruct.inc"
%include "include/datastruct.inc"
%include "include/transpose_avx512.inc"
%include "include/imb_job.inc"
%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/align_avx512.inc"

%include "include/snow5g_x8_vaes_avx512.inc"

%ifndef SUBMIT_JOB_SNOW5G_NEA4
%define SUBMIT_JOB_SNOW5G_NEA4_GEN2 submit_job_snow5g_nea4_vaes_avx512
%define FLUSH_JOB_SNOW5G_NEA4_GEN2 flush_job_snow5g_nea4_vaes_avx512

%endif

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define tmp_gp1 rcx
%define tmp_gp2 rdx
%else
%define arg1    rcx
%define arg2    rdx
%define tmp_gp1 rdi
%define tmp_gp2 rsi
%endif

%define state    arg1
%define job      arg2

%define job_rax  rax

%define tmp_gp3  rbx
%define tmp_gp4  rbp
%define tmp_gp5  r9
%define tmp_gp6  r10
%define tmp_gp7  r11
%define tmp_gp8  r12
%define tmp_gp9  r13
%define tmp_gp10 r14
%define tmp_gp11 r15

mksection .rodata
default rel

align 2
lane_set_mask:
        db 0x3, 0xC

align 2
lane_clr_mask:
        db ~0x3, ~0xC

mksection .text

;; Update LP_INIT_MASK bits for a specific lane in memory
%macro UPDATE_LP_INIT_MASK 6
%define %%LANE            %1  ;; [in] lane index (0-1)
%define %%LANE_PAIR       %2  ;; [in] lane pair index (lane >> 1, pre-calculated)
%define %%TGP0            %3  ;; [clobbered] GP register
%define %%TGP1            %4  ;; [clobbered] GP register
%define %%TGP2            %5  ;; [clobbered] GP register
%define %%OP              %6  ;; [in] set/clear

        mov             BYTE(%%TGP0), byte [state + _snow5g_arg_LP_INIT_MASK + %%LANE_PAIR]
        mov             DWORD(%%TGP2), DWORD(%%LANE)
        and             DWORD(%%TGP2), 1                        ; %%TGP2 = lane & 1
%ifidn %%OP, set
        lea             %%TGP1, [rel lane_set_mask]
        or              BYTE(%%TGP0), [%%TGP1 + %%TGP2]
%else
        lea             %%TGP1, [rel lane_clr_mask]
        and             BYTE(%%TGP0), [%%TGP1 + %%TGP2]
%endif
        mov             [state + _snow5g_arg_LP_INIT_MASK + %%LANE_PAIR], BYTE(%%TGP0)

%endmacro


%macro SUBMIT_FLUSH_JOB_SNOW5G_NEA4 12
%define %%SUBMIT_FLUSH    %1  ;; [in] submit/flush selector
%define %%UNUSED_LANES    %2  ;; [clobbered] GP register
%define %%LANE            %3  ;; [clobbered] GP register
%define %%TGP0            %4  ;; [clobbered] GP register
%define %%TGP1            %5  ;; [clobbered] GP register
%define %%TGP2            %6  ;; [clobbered] GP register
%define %%LANE_PAIR       %7  ;; [clobbered] GP register
%define %%TGP4            %8  ;; [clobbered] GP register
%define %%TGP5            %9  ;; [clobbered] GP register
%define %%MIN_COMMON_LEN  %10 ;; [clobbered] GP register
%define %%OFFSET          %11 ;; [clobbered] GP register
%define %%GEN             %12 ;; [in] avx512_gen1/avx512_gen2

        xor     job_rax, job_rax        ;; assume NULL return job

%ifidn %%SUBMIT_FLUSH, submit
        ;; unused lanes is a list of all unused lane ids (0-1)
        mov     %%UNUSED_LANES, [state + _snow5g_unused_lanes]
        mov     %%LANE, %%UNUSED_LANES
        and     %%LANE, 0x1
        shr     %%UNUSED_LANES, 4
        mov     [state + _snow5g_unused_lanes], %%UNUSED_LANES
        add     qword [state + _snow5g_lanes_in_use], 1
        mov     [state + _snow5g_job_in_lane + %%LANE*8], job

        ;; Initialize LFSR and FSM registers
        mov             %%TGP1, [job + _enc_keys]
        mov             %%TGP2, [job + _iv]

        SNOW_5G_LFSR_FSM_INIT_SUBMIT state, %%LANE, %%TGP1, %%TGP2, ymm0, ymm1, %%TGP5

        bts             word [state + _snow5g_INIT_MASK], WORD(%%LANE)

        ;; Set LP_INIT_MASK bits for this lane
        ;; Each byte controls a lane pair: bits [0:1] for even lane, bits [2:3] for odd lane
        mov             DWORD(%%LANE_PAIR), DWORD(%%LANE)
        shr             DWORD(%%LANE_PAIR), 1                   ; lane_pair = lane >> 1
        UPDATE_LP_INIT_MASK %%LANE, %%LANE_PAIR, %%TGP0, %%TGP1, %%TGP2, set

%%_submit_lp_updated:
        ;; 15 iterations of FSM and LFSR clock are needed for SNOW5G initialization
        ;; LD_ST_MASK is used to determine if any data should
        ;; be read from src and written to dst
        ;; When set to 0 so no reads/writes occur.
        ;; In this case, input/output pointers are set to a valid address.
        mov             word [state + _snow5g_args_LD_ST_MASK + %%LANE*2], 0
        mov             [state + _snow5g_args_in + %%LANE*8], state
        mov             [state + _snow5g_args_out + %%LANE*8], state

        mov             dword [state + _snow5g_lens_dqw + %%LANE*4], 15

        ;; insert length into proper lane
        mov             %%TGP0, [job + _msg_len_to_cipher_in_bytes]
        mov             [state + _snow5g_args_byte_length + %%LANE*8], %%TGP0

        cmp             qword [state + _snow5g_lanes_in_use], 2
        jne             %%return_nea4   ;; RAX is NULL
%else   ;; FLUSH
        cmp             qword [state + _snow5g_lanes_in_use], job_rax
        je              %%return_nea4   ;; RAX is NULL

        ;; Set unused lane to max length to prevent selection
        mov             DWORD(%%UNUSED_LANES), [state + _snow5g_unused_lanes]
        and             DWORD(%%UNUSED_LANES), 0x1
        mov             dword [state + _snow5g_lens_dqw + %%UNUSED_LANES*4], 0xFFFFFFFF
%endif

        ;; ---------------------------------------------------------------------
        ;; All lanes are busy or flush is called - process used lanes until
        ;; one job is done.
        ;; ---------------------------------------------------------------------
        ;; State of the job is identified with:
        ;;   _snow5g_INIT_MASK - if bit set then init xor
        ;;   _snow5g_args_LD_ST_MASK - no output written
        ;;   _snow5g_args_byte_length - message lengths to be processed (bytes)
        ;;
        ;; START -> INIT1 -> INIT2 -> WORK1 -> COMPLETE <-+
        ;;                              |                 |
        ;;                              +-> WORK2 --------+
        ;;
        ;; Each of the lanes can be in any of 4 states (INIT1, INIT2, WORK1 or
        ;; WORK2) and they can be processed in parallel by the algorithmic code.
        ;; ---------------------------------------------------------------------

align_loop
%%_find_min:
        ;; Find minimum length across 2 lanes
        mov             DWORD(%%MIN_COMMON_LEN), [state + _snow5g_lens_dqw]
        mov             DWORD(%%TGP0), [state + _snow5g_lens_dqw + 4]
        xor             DWORD(%%LANE), DWORD(%%LANE)
        cmp             DWORD(%%TGP0), DWORD(%%MIN_COMMON_LEN)
        cmovb           DWORD(%%MIN_COMMON_LEN), DWORD(%%TGP0)
        adc             DWORD(%%LANE), 0
        xor             DWORD(%%LANE_PAIR), DWORD(%%LANE_PAIR)
        test            DWORD(%%MIN_COMMON_LEN), DWORD(%%MIN_COMMON_LEN)
        jz              %%_len_is_0

        ;; subtract common minimum length from lane lengths
        sub             [state + _snow5g_lens_dqw], DWORD(%%MIN_COMMON_LEN)
        sub             [state + _snow5g_lens_dqw + 4], DWORD(%%MIN_COMMON_LEN)

        kmovb           k1, byte [state + _snow5g_arg_LP_INIT_MASK]

        SNOW5G_KEYSTREAM_X2 state, %%MIN_COMMON_LEN, {state + _snow5g_args_in}, \
                        {state + _snow5g_args_out}, %%OFFSET, %%TGP0, %%TGP1, k1

        ;; Update src/dst pointers for lanes not in INIT
        mov             BYTE(%%TGP0), [state + _snow5g_arg_LP_INIT_MASK]
        test            BYTE(%%TGP0), 0x3
        jnz             %%_skip_ptr_0
        add             [state + _snow5g_args_in], %%OFFSET
        add             [state + _snow5g_args_out], %%OFFSET
%%_skip_ptr_0:
        test            BYTE(%%TGP0), 0xC
        jnz             %%_skip_ptr_1
        add             [state + _snow5g_args_in + 8], %%OFFSET
        add             [state + _snow5g_args_out + 8], %%OFFSET
%%_skip_ptr_1:

align_label
%%_len_is_0:
        ;; Four states are possible here:
        ;;   INIT1) initialization phase is complete
        ;;   INIT2) round 15,16
        ;;   WORK1) message processed for the size aligned to 16 bytes
        ;;   WORK2) message processed for the trailing bytes below 16 bytes

        ;; check if the job is in one of INIT1 or INIT2 state
        test            word [state + _snow5g_args_LD_ST_MASK + %%LANE*2], 0xffff
        jz              %%_init_phase_in_progress

        ;; The job is in WORK1 or WORK2 state
        ;; - This is determined by content of _snow5g_args_byte_length.
        ;;   If it is zero then this is WORK2 state and the job processing is complete
        ;; - Non-zero content with odd bytes requiring processing => WORK1
        mov             %%TGP0, [state + _snow5g_args_byte_length + %%LANE*8]
        and             %%TGP0, 0xF
        jz              %%process_completed_job_submit_nea4

        ;; WORK1->WORK2
        ;; Outstanding bytes to process (less than 16 bytes)
        xor             WORD(%%TGP2), WORD(%%TGP2)
        bts             WORD(%%TGP2), WORD(%%TGP0)
        dec             WORD(%%TGP2)
        mov             [state + _snow5g_args_LD_ST_MASK + %%LANE*2], WORD(%%TGP2)

        ;; set length in 16-byte blocks to 1
        mov             dword [state + _snow5g_lens_dqw + %%LANE*4], 1

        ;; clear the length so that the job can transition to completion
        mov             qword [state + _snow5g_args_byte_length + %%LANE*8], 0
        jmp             %%_find_min

align_label
%%_init_phase_in_progress:
        ;; This is INIT1 or INIT2 state
        bt              word [state + _snow5g_INIT_MASK], WORD(%%LANE)
        jnc             %%_init_done

        ;; The lane is INIT1
        ;; - the job finished first phase of initialization (16 rounds)
        ;; - it can transition to INIT2 (1 iteration)

        ;; XOR FSM1 with key low part (16 bytes)
        mov             %%TGP0, [state + _snow5g_args_keys + %%LANE*8]                                 ;; Get key pointer
        mov             %%TGP1, %%LANE
        shl             %%TGP1, 4                                        ;; %%TGP1 = %%LANE * 16
        vmovdqu         xmm0, [state + _snow5g_args_FSM_1 + %%TGP1]     ;; Load FSM1 for this lane
        vmovdqu         xmm1, [%%TGP0]                                  ;; Load key low part
        vpxor           xmm0, xmm0, xmm1
        vmovdqu         [state + _snow5g_args_FSM_1 + %%TGP1], xmm0     ;; Store back modified FSM1

        btr             word [state + _snow5g_INIT_MASK], WORD(%%LANE)  ;; INIT_MASK[LANE] = 0

        mov             dword [state + _snow5g_lens_dqw + %%LANE*4], 1
        jmp             %%_find_min

align_label
%%_init_done:
        ;; The lane is in INIT2 state
        ;; - just finished 2nd phase of initialization (1 iteration)
        ;; - it can transition to WORK1 state
        ;; XOR FSM1 with key high part (16 bytes)
        mov             %%TGP0,[state + _snow5g_args_keys + %%LANE*8]   ;; Get key pointer
        mov             %%TGP1, %%LANE
        shl             %%TGP1, 4                                       ;; %%TGP1 = %%LANE * 16
        vmovdqu         xmm0, [state + _snow5g_args_FSM_1 + %%TGP1]     ;; Load FSM1 for this lane
        vmovdqu         xmm1, [%%TGP0 + 16]                             ;; Load key high part
        vpxor           xmm0, xmm0, xmm1
        vmovdqu         [state + _snow5g_args_FSM_1 + %%TGP1], xmm0     ;; Store back modified FSM1


        ;; Clear LP_INIT_MASK bits for this lane (INIT2 -> WORK1 transition)
        UPDATE_LP_INIT_MASK %%LANE, %%LANE_PAIR, %%TGP0, %%TGP1, %%TGP2, clear

        mov             word [state + _snow5g_args_LD_ST_MASK + %%LANE*2], 0xffff

        ;; length in 16-byte blocks = original length in bytes / 16
        ;; - odd bytes are processed later
        mov             %%TGP0, [state + _snow5g_args_byte_length + %%LANE*8]
        shr             %%TGP0, 4
        mov             [state + _snow5g_lens_dqw + %%LANE*4], DWORD(%%TGP0)

        ;; set the correct in & out pointers
        mov             %%TGP0, [state + _snow5g_job_in_lane + %%LANE*8]
        mov             %%TGP1, [%%TGP0 + _cipher_start_src_offset_in_bytes]

        mov             %%TGP2, [%%TGP0 + _dst]
        mov             [state + _snow5g_args_out + %%LANE*8], %%TGP2

        add             %%TGP1, [%%TGP0 + _src]
        mov             [state + _snow5g_args_in + %%LANE*8], %%TGP1

        jmp             %%_find_min

align_label
%%process_completed_job_submit_nea4:
        ;; COMPLETE: return job, change job length to UINT32_MAX
        mov             dword [state + _snow5g_lens_dqw + %%LANE*4], 0xFFFFFFFF

        ;; required in case of flush
        ;; Input/output pointers are set to a valid address.
        mov             word [state + _snow5g_args_LD_ST_MASK + %%LANE*2], 0
        mov             [state + _snow5g_args_in + %%LANE*8], state
        mov             [state + _snow5g_args_out + %%LANE*8], state

        ;; decrement number of jobs in use
        dec             qword [state + _snow5g_lanes_in_use]

        mov             job_rax, [state + _snow5g_job_in_lane + %%LANE*8]
        or              qword [job_rax + _status], IMB_STATUS_COMPLETED_CIPHER

        mov             %%UNUSED_LANES, [state + _snow5g_unused_lanes]
        mov             qword [state + _snow5g_job_in_lane + %%LANE*8], 0
        shl             %%UNUSED_LANES, 4
        or              %%UNUSED_LANES, %%LANE
        mov             [state + _snow5g_unused_lanes], %%UNUSED_LANES

        ;; Clear LP_INIT_MASK bits for this lane
        UPDATE_LP_INIT_MASK %%LANE, %%LANE_PAIR, %%TGP0, %%TGP1, %%TGP2, clear

%ifdef SAFE_DATA
        ;; clear finished job lane, %%LANE is an index of finished job
        ;; Each lane occupies 16 bytes (128 bits) in the LFSR and FSM arrays

        ;; Clear LFSR and FSM registers for this lane (16 bytes each)
        vpxorq          xmm0, xmm0, xmm0
        shl             %%LANE, 4                               ;; offset = %%LANE * 16
        vmovdqu         [state + _snow5g_args_LFSRA_LO + %%LANE], xmm0
        vmovdqu         [state + _snow5g_args_LFSRA_HI + %%LANE], xmm0
        vmovdqu         [state + _snow5g_args_LFSRB_LO + %%LANE], xmm0
        vmovdqu         [state + _snow5g_args_LFSRB_HI + %%LANE], xmm0
        vmovdqu         [state + _snow5g_args_FSM_1 + %%LANE], xmm0
        vmovdqu         [state + _snow5g_args_FSM_2 + %%LANE], xmm0
        vmovdqu         [state + _snow5g_args_FSM_3 + %%LANE], xmm0

%endif

align_label
%%return_nea4:
%ifdef SAFE_DATA
        ;; Clear STACK structure containing temporary LFSR and keystream data
        ;; Each field is exactly one YMM register (32 bytes)
        ;; clear register contents
        clear_scratch_ymms_asm

        vmovdqa32       [rsp + _LFSR_A_HDQ_01], ymm0
        vmovdqa32       [rsp + _LFSR_B_HDQ_01], ymm0
        vmovdqa32       [rsp + _keystream_01], ymm0
%else
        vzeroupper
%endif

%endmacro

;; JOB* SUBMIT_JOB_SNOW5G_NEA4(MB_MGR_SNOW5G_OOO *state, IMB_JOB *job)
;; arg 1 : state
;; arg 2 : job
MKGLOBAL(SUBMIT_JOB_SNOW5G_NEA4_GEN2,function,internal)
align_function
SUBMIT_JOB_SNOW5G_NEA4_GEN2:
        SNOW5G_FUNC_START
        SUBMIT_FLUSH_JOB_SNOW5G_NEA4 submit, tmp_gp2, tmp_gp3, tmp_gp4, tmp_gp5, tmp_gp6, tmp_gp7, tmp_gp8, tmp_gp9, tmp_gp10, tmp_gp11, avx512_gen2
        SNOW5G_FUNC_END
        ret

;; JOB* FLUSH_JOB_SNOW5G_NEA4(MB_MGR_SNOW5G_OOO *state)
;; arg 1 : state
MKGLOBAL(FLUSH_JOB_SNOW5G_NEA4_GEN2,function,internal)
align_function
FLUSH_JOB_SNOW5G_NEA4_GEN2:
        SNOW5G_FUNC_START
        SUBMIT_FLUSH_JOB_SNOW5G_NEA4 flush, tmp_gp2, tmp_gp3, tmp_gp4, tmp_gp5, tmp_gp6, tmp_gp7, tmp_gp8, tmp_gp9, tmp_gp10, tmp_gp11, avx512_gen2
        SNOW5G_FUNC_END
        ret

mksection stack-noexec
