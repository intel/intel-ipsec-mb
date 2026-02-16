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

%include "include/snow5g_nea4_x8_vaes_avx512.inc"

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

align 64
dd_0_to_7:
        dd 0, 1, 2, 3, 4, 5, 6, 7

align 64
all_fs:
times 8 dd 0xffffffff

align 2
lane_set_mask:
        db 0x3, 0xC

align 2
lane_clr_mask:
        db ~0x3, ~0xC

mksection .text

;; Update LP_INIT_MASK bits for a specific lane in memory
%macro UPDATE_LP_INIT_MASK 6
%define %%LANE            %1  ;; [in] lane index (0-7)
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
        ;; unused lanes is a list of all unused lane ids (0-7)
        mov     %%UNUSED_LANES, [state + _snow5g_unused_lanes]
        mov     %%LANE, %%UNUSED_LANES
        and     %%LANE, 0x7 ; max 8 lanes
        shr     %%UNUSED_LANES, 4
        mov     [state + _snow5g_unused_lanes], %%UNUSED_LANES
        add     qword [state + _snow5g_lanes_in_use], 1
        mov     [state + _snow5g_job_in_lane + %%LANE*8], job

        ;; set lane mask
        xor             %%TGP0, %%TGP0
        bts             DWORD(%%TGP0), DWORD(%%LANE)
        kmovd           k1, DWORD(%%TGP0)

        ;; Initialize LFSR and FSM registers
        mov             %%TGP1, [job + _enc_keys]
        mov             %%TGP2, [job + _iv]

        SNOW_5G_LFSR_FSM_INIT_SUBMIT state, %%LANE, %%TGP1, %%TGP2, ymm0, ymm1, %%TGP5

        ;; _INIT_MASK is common mask for clocking loop
        kmovw           k6, [state + _snow5g_INIT_MASK]
        korw            k6, k1, k6
        kmovw           [state + _snow5g_INIT_MASK], k6

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

        vmovdqa32       ymm0, [state + _snow5g_lens_dqw]
        mov             DWORD(%%TGP0), 15
        vpbroadcastd    ymm0{k1}, DWORD(%%TGP0)
        vmovdqa32       [state + _snow5g_lens_dqw], ymm0

        ;; insert length into proper lane
        mov             %%TGP0, [job + _msg_len_to_cipher_in_bytes]
        mov             [state + _snow5g_args_byte_length + %%LANE*8], %%TGP0

        cmp             qword [state + _snow5g_lanes_in_use], 8
        jne             %%return_nea4   ;; RAX is NULL
        ;; if all lanes are busy fall through to %%process_job_nea4
%else   ;; FLUSH
        cmp             qword [state + _snow5g_lanes_in_use], job_rax
        je              %%return_nea4   ;; RAX is NULL
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
        ;; Find minimum length
        vmovdqa32       ymm0, [state + _snow5g_lens_dqw]
        vpslld          ymm0, ymm0, 4
        vpord           ymm0, ymm0, [rel dd_0_to_7]
        vextracti32x4   xmm1, ymm0, 1                   ; extract upper 128 bits

        vpminud         xmm0, xmm0, xmm1
        vpsrldq         xmm1, xmm0, 8
        vpminud         xmm0, xmm0, xmm1
        vpsrldq         xmm1, xmm0, 4
        vpminud         xmm0, xmm0, xmm1

        vmovd           DWORD(%%MIN_COMMON_LEN), xmm0
        mov             DWORD(%%LANE), DWORD(%%MIN_COMMON_LEN)
        and             DWORD(%%LANE), 7                ;; keep lane index on 3 least significant bits
        mov             DWORD(%%LANE_PAIR), DWORD(%%LANE)
        shr             DWORD(%%LANE_PAIR), 1           ;; lane_pair = lane >> 1 (0-3)
        xor             DWORD(%%TGP0), DWORD(%%TGP0)
        bts             DWORD(%%TGP0), DWORD(%%LANE)
        kmovd           k7, DWORD(%%TGP0)                               ;; k7 holds mask of the min LANE
        shr             DWORD(%%MIN_COMMON_LEN), 4      ;; remove index from 4 least significant bits
        jz              %%_len_is_0

        ;; subtract common minimum length from all lanes lengths
        vmovdqa32       ymm0, [state + _snow5g_lens_dqw]
        vpbroadcastd    ymm1, DWORD(%%MIN_COMMON_LEN)
%ifidn %%SUBMIT_FLUSH, submit
        vpsubd          ymm0, ymm0, ymm1
%else ; FLUSH
        vpcmpd          k6, ymm0, [rel all_fs], 4      ; 4 = not-equal
        vpsubd          ymm0{k6}, ymm0, ymm1
%endif
        vmovdqa32       [state + _snow5g_lens_dqw], ymm0

        ;; Load LP_INIT_MASK bytes into k-registers right before SNOW5G_KEYSTREAM
        kmovb           k1, byte [state + _snow5g_arg_LP_INIT_MASK + 0]
        kmovb           k2, byte [state + _snow5g_arg_LP_INIT_MASK + 1]
        kmovb           k3, byte [state + _snow5g_arg_LP_INIT_MASK + 2]
        kmovb           k4, byte [state + _snow5g_arg_LP_INIT_MASK + 3]

        ;; Do cipher / clock operation for all lanes and given common length
        SNOW5G_KEYSTREAM state, %%MIN_COMMON_LEN, {state + _snow5g_args_in}, \
                        {state + _snow5g_args_out}, %%OFFSET, %%TGP0, %%TGP1, %%TGP2, k1, k2, k3, k4, k5, k6

        ;; Combine lane pair masks for ymm registers
        ;; k1-k4 contain LP_INIT_MASK bits (set for INIT lanes, clear for WORK lanes)
        kunpckbw        k5, k1, k2          ; Combine k1[1:0] and k2[1:0] into k5[3:0] for lanes 0-3
        kunpckbw        k6, k3, k4          ; Combine k3[1:0] and k4[1:0] into k6[3:0] for lanes 4-7

        ;; Invert to create update masks (update pointers when NOT in INIT)
        knotb           k5, k5              ; k5 = NOT(k1|k2) - update mask for lanes 0-3
        knotb           k6, k6              ; k6 = NOT(k3|k4) - update mask for lanes 4-7

        ;; Add offsets to SRC and DST ptrs for lanes not in INIT
        vpbroadcastq    ymm0, %%OFFSET
        vmovdqa64       ymm1, [state + _snow5g_args_in + 0*8]
        vmovdqa64       ymm2, [state + _snow5g_args_in + 4*8]
        vmovdqa64       ymm3, [state + _snow5g_args_out + 0*8]
        vmovdqa64       ymm4, [state + _snow5g_args_out + 4*8]

        vpaddq          ymm1{k5}, ymm1, ymm0    ; Update lanes 0-3 if NOT in INIT
        vpaddq          ymm2{k6}, ymm2, ymm0    ; Update lanes 4-7 if NOT in INIT
        vpaddq          ymm3{k5}, ymm3, ymm0    ; Update lanes 0-3 if NOT in INIT
        vpaddq          ymm4{k6}, ymm4, ymm0    ; Update lanes 6-7 if NOT in INIT

        vmovdqa64       [state + _snow5g_args_in + 0*8], ymm1
        vmovdqa64       [state + _snow5g_args_in + 4*8], ymm2
        vmovdqa64       [state + _snow5g_args_out + 0*8], ymm3
        vmovdqa64       [state + _snow5g_args_out + 4*8], ymm4

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
        vmovdqa32       ymm0, [state + _snow5g_lens_dqw]
        mov             DWORD(%%TGP0), 1
        vpbroadcastd    ymm0{k7}, DWORD(%%TGP0)
        vmovdqa32       [state + _snow5g_lens_dqw], ymm0

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

        vmovdqa32       ymm0, [state + _snow5g_lens_dqw]
        mov             DWORD(%%TGP0), 1
        vpbroadcastd    ymm0{k7}, DWORD(%%TGP0)
        vmovdqa32       [state + _snow5g_lens_dqw], ymm0
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
        vmovdqa32       ymm0, [state + _snow5g_lens_dqw]
        vpbroadcastd    ymm0{k7}, DWORD(%%TGP0)
        vmovdqa32       [state + _snow5g_lens_dqw], ymm0

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
        vmovdqa32       ymm0, [state + _snow5g_lens_dqw]
        vpbroadcastd    ymm0{k7}, [rel all_fs]
        vmovdqa32       [state + _snow5g_lens_dqw], ymm0

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

        ;; Clear LFSR_A_HDQ fields (4 fields × 32 bytes each)
        vmovdqa32       [rsp + _LFSR_A_HDQ_01], ymm0
        vmovdqa32       [rsp + _LFSR_A_HDQ_23], ymm0
        vmovdqa32       [rsp + _LFSR_A_HDQ_45], ymm0
        vmovdqa32       [rsp + _LFSR_A_HDQ_67], ymm0

        ;; Clear LFSR_B_HDQ fields (4 fields × 32 bytes each)
        vmovdqa32       [rsp + _LFSR_B_HDQ_01], ymm0
        vmovdqa32       [rsp + _LFSR_B_HDQ_23], ymm0
        vmovdqa32       [rsp + _LFSR_B_HDQ_45], ymm0
        vmovdqa32       [rsp + _LFSR_B_HDQ_67], ymm0

        ;; Clear keystream fields (4 fields × 32 bytes each)
        vmovdqa32       [rsp + _keystream_01], ymm0
        vmovdqa32       [rsp + _keystream_23], ymm0
        vmovdqa32       [rsp + _keystream_45], ymm0
        vmovdqa32       [rsp + _keystream_67], ymm0
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
