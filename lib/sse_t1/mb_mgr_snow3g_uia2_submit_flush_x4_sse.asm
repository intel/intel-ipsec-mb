;;
;; Copyright (c) 2022, Intel Corporation
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
%include "include/imb_job.asm"
%include "include/mb_mgr_datastruct.asm"
%include "include/reg_sizes.asm"
%include "include/clear_regs.asm"
%include "sse_t1/snow3g_uea2_by4_sse.asm"

%define SUBMIT_JOB_SNOW3G_UIA2 submit_job_snow3g_uia2_sse
%define FLUSH_JOB_SNOW3G_UIA2 flush_job_snow3g_uia2_sse
%define SNOW3G_F9_1_BUFFER_INT snow3g_f9_1_buffer_internal_sse

%define APPEND(a,b) a %+ b

extern SNOW3G_F9_1_BUFFER_INT

mksection .text
%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%endif

%define state      arg1
%define job        arg2
%define job_rax    rax

%define tmp_gp0    rbx
%define tmp_gp1    rbp
%define tmp_gp2    r9
%define tmp_gp3    r10
%define init_lanes r11
%define tmp_state  r12
%define tmp_gp4    r13
%define tmp_gp5    r14
%define tmp_gp6    r15

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Get lane nr from ptr to the list of unused lanes.
;; Remove returned lane nr from the list
;; Increase lanes in use.
;; Put job ptr in appropriate lane field in state (arg %3)
;; Assumptions:
;; In (arg %1) single lane nr takes 4 bits and 1st free lane nr is lowest 4 bits
;; Job ptr in (arg %3) takes 8 bytes
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro GET_UNUSED_LANE_SSE 6
%define %%LANE_LIST       %1  ;; [in]  ptr to unused lane list
%define %%LANES_IN_USE    %2  ;; [in]  ptr to lanes in use count
%define %%JOB_LANES       %3  ;; [in]  ptr to list of jobs
%define %%JOB             %4  ;; [in]  ptr to job structure
%define %%LANE_NR         %5  ;; [out] GP register to fill with unused lane nr
%define %%UNUSED_LANES    %6  ;; [clobbered] GP register

        mov     DWORD(%%UNUSED_LANES), [%%LANE_LIST]
        mov     DWORD(%%LANE_NR), DWORD(%%UNUSED_LANES)
        and     DWORD(%%LANE_NR), 0x3
        ;; remove picked lane nr from list of unused lanes
        shr     DWORD(%%UNUSED_LANES), 4
        mov     [%%LANE_LIST], DWORD(%%UNUSED_LANES)

        add	qword [%%LANES_IN_USE], 1
        mov     [%%JOB_LANES + %%LANE_NR*8], %%JOB
%endmacro

%macro SUBMIT_FLUSH_JOB_SNOW3G_UIA2 24
%define %%SUBMIT_FLUSH          %1    ;; [in] submit/flush selector
%define %%UNUSED_LANES          %2    ;; [clobbered] GP register
%define %%LANE                  %3    ;; [clobbered] GP register
%define %%TGP0                  %4    ;; [clobbered] GP register
%define %%TGP1                  %5    ;; [clobbered] GP register
%define %%TGP2                  %6    ;; [clobbered] GP register
%define %%TGP3                  %7    ;; [clobbered] GP register
%define %%TGP4                  %8    ;; [clobbered] GP register
%define %%TMP_XMM_0             %9    ;; [clobbered] xmm register
%define %%TMP_XMM_1             %10   ;; [clobbered] xmm register
%define %%TMP_XMM_2             %11   ;; [clobbered] xmm register
%define %%TMP_XMM_3             %12   ;; [clobbered] xmm register
%define %%TMP_XMM_4             %13   ;; [clobbered] xmm register
%define %%TMP_XMM_5             %14   ;; [clobbered] xmm register
%define %%TMP_XMM_6             %15   ;; [clobbered] xmm register
%define %%TMP_XMM_7             %16   ;; [clobbered] xmm register
%define %%TMP_XMM_8             %17   ;; [clobbered] xmm register
%define %%TMP_XMM_9             %18   ;; [clobbered] xmm register
%define %%TMP_XMM_10            %19   ;; [clobbered] xmm register
%define %%TMP_XMM_11            %20   ;; [clobbered] xmm register
%define %%TMP_XMM_12            %21   ;; [clobbered] xmm register
%define %%TMP_XMM_13            %22   ;; [clobbered] xmm register
%define %%TMP_XMM_14            %23   ;; [clobbered] xmm register
%define %%TMP_XMM_15            %24   ;; [clobbered] xmm register

        SNOW3G_FUNC_START
        xor     job_rax, job_rax        ;; assume NULL return job

%ifidn %%SUBMIT_FLUSH, submit
        GET_UNUSED_LANE_SSE state + _snow3g_unused_lanes, \
                            state + _snow3g_lanes_in_use, \
                            state + _snow3g_job_in_lane,  \
                            job, %%LANE, %%UNUSED_LANES

        ;; copy src, key, iv and len to OOO mgr
        mov     %%TGP0, [job + _hash_start_src_offset_in_bytes]
        add     %%TGP0, [job + _src]
        mov     [state + _snow3g_args_in + %%LANE*8], %%TGP0

        mov     %%TGP0, [job + _snow3g_uia2_key]
        mov     [state + _snow3g_args_keys + %%LANE*8], %%TGP0

        mov     %%TGP0, [job + _snow3g_uia2_iv]
        mov     [state + _snow3g_args_IV + %%LANE*8], %%TGP0

        mov     %%TGP0, [job + _msg_len_to_hash_in_bits]
        mov     [state + _snow3g_lens + %%LANE*4], DWORD(%%TGP0)

        cmp     qword [state + _snow3g_lanes_in_use], 4
        jne     %%return_null_uia2

        ;; all lanes full but no jobs initialized - do init
        ;; at least 1 job initialized - process next job
        cmp     word [state + _snow3g_init_done], 0
        jz      %%init_all_lanes_uia2

        ;; find next initialized job lane
        xor     DWORD(%%LANE), DWORD(%%LANE)
        bsf     WORD(%%LANE), [state + _snow3g_init_done]

%else   ;; FLUSH

        ;; check ooo mgr empty
        cmp     qword [state + _snow3g_lanes_in_use], 0
        jz      %%return_null_uia2

        ;; check for initialized jobs
        xor     %%LANE, %%LANE
        movzx   DWORD(%%TGP0), word [state + _snow3g_init_done]
        bsf     WORD(%%LANE), WORD(%%TGP0)
        jnz     %%process_job_uia2

        ;; no initialized jobs found
        ;; - find valid job
        ;; - copy valid job fields to empty lanes
        ;; - initialize all lanes

        ;; find a valid lane
        xor     init_lanes, init_lanes
%assign i 0
%rep 4
	cmp     qword [state + _snow3g_job_in_lane + (i*8)], 0
        je      APPEND(skip_lane_,i)
        mov     WORD(%%LANE), i
        bts     WORD(init_lanes), i ;; build init lanes mask
APPEND(skip_lane_,i):
%assign i (i+1)
%endrep

        ;; copy valid lane pointers to empty lanes
        mov     %%TGP0, [state + _snow3g_args_in + %%LANE*8]
        mov     %%TGP1, [state + _snow3g_args_keys + %%LANE*8]
        mov     %%TGP2, [state + _snow3g_args_IV + %%LANE*8]

%assign i 0
%rep 4
        bt      WORD(init_lanes), i
        jc      APPEND(skip_lane_copy_,i) ;; skip copy for valid lanes
        ;; empty lane - copy good job pointers
        mov     [state + _snow3g_args_in + i*8], %%TGP0
        mov     [state + _snow3g_args_keys + i*8], %%TGP1
        mov     [state + _snow3g_args_IV + i*8], %%TGP2
APPEND(skip_lane_copy_,i):
%assign i (i+1)
%endrep
        jmp     %%init_lanes_uia2

%endif ;;submit/flush

%%process_job_uia2:
        ;; preserve state for function call
        mov     tmp_state, state

        mov     arg1, [tmp_state + _snow3g_args_in + %%LANE*8]
        lea     arg2, [%%LANE*8]
        lea     arg2, [tmp_state + _snow3g_ks + arg2*4]   ;; arg2*4 = %%LANE*32
        mov     DWORD(arg3), [tmp_state + _snow3g_lens + %%LANE*4]

        call    SNOW3G_F9_1_BUFFER_INT

        ;; restore state
        mov     state, tmp_state

        ;; copy digest temporarily
        mov     DWORD(%%TGP0), eax

%%process_completed_job_submit_uia2:
        ; process completed job "%%LANE"
        ;; - decrement number of jobs in use
        sub     qword [state + _snow3g_lanes_in_use], 1
        mov     job_rax, [state + _snow3g_job_in_lane + %%LANE*8]
        mov     %%UNUSED_LANES, [state + _snow3g_unused_lanes]
        mov     qword [state + _snow3g_job_in_lane + %%LANE*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
        ; Copy digest to auth tag output
        mov     %%TGP1, [job_rax + _auth_tag_output]
        mov     [%%TGP1], DWORD(%%TGP0)
        shl     %%UNUSED_LANES, 4
        or      %%UNUSED_LANES, %%LANE
        mov     [state + _snow3g_unused_lanes], %%UNUSED_LANES
        btr     [state + _snow3g_init_done], WORD(%%LANE)

%ifdef SAFE_DATA
        ;; clear keystream for processed job
        pxor    %%TMP_XMM_0, %%TMP_XMM_0
        shl     WORD(%%LANE), 5 ;; ks stored at 32 byte offsets
        movdqa  [state + _snow3g_ks + %%LANE], %%TMP_XMM_0
        movdqa  [state + _snow3g_ks + 16 + %%LANE], %%TMP_XMM_0
%endif

        jmp     %%return_uia2

%%init_all_lanes_uia2:
        ;; set initialized lanes mask for all 4 lanes
        ;; this is used to update OOO MGR after initialization
        mov     DWORD(init_lanes), 0xf

%%init_lanes_uia2:

        ;; multi-buffer init + 5 dw of KS gen
        lea     %%TGP0, [state + _snow3g_ks]

        SNOW3G_AUTH_INIT_5_BY_4 {state + _snow3g_args_keys},              \
                                {state + _snow3g_args_IV},                \
                                %%TGP0, %%TGP1, %%TGP2, %%TGP3, %%TGP4,   \
                                %%TMP_XMM_0, %%TMP_XMM_1, %%TMP_XMM_2,    \
                                %%TMP_XMM_3, %%TMP_XMM_4, %%TMP_XMM_5,    \
                                %%TMP_XMM_6, %%TMP_XMM_7, %%TMP_XMM_8,    \
                                %%TMP_XMM_9, %%TMP_XMM_10, %%TMP_XMM_11,  \
                                %%TMP_XMM_12, %%TMP_XMM_13, %%TMP_XMM_14, \
                                %%TMP_XMM_15, state

        ;; update init_done for valid initialized lanes
        mov     [state + _snow3g_init_done], WORD(init_lanes)
        bsf     WORD(%%LANE), WORD(init_lanes)

        ;; process first job
        jmp     %%process_job_uia2

%%return_null_uia2:
        xor     job_rax, job_rax

%%return_uia2:
        SNOW3G_FUNC_END

%endmacro

; JOB* SUBMIT_JOB_SNOW3G_UIA2(MB_MGR_SNOW3G_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_SNOW3G_UIA2,function,internal)
SUBMIT_JOB_SNOW3G_UIA2:
        SUBMIT_FLUSH_JOB_SNOW3G_UIA2 submit, tmp_gp0, tmp_gp1, \
                                     tmp_gp2, tmp_gp3, tmp_gp4, tmp_gp5, \
                                     tmp_gp6, xmm0, xmm1, xmm2, xmm3, xmm4, \
                                     xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, \
                                     xmm11, xmm12, xmm13, xmm14, xmm15
        ret

; JOB* FLUSH_JOB_SNOW3G_UIA2(MB_MGR_SNOW3G_OOO *state)
; arg 1 : state
MKGLOBAL(FLUSH_JOB_SNOW3G_UIA2,function,internal)
FLUSH_JOB_SNOW3G_UIA2:
        SUBMIT_FLUSH_JOB_SNOW3G_UIA2 flush, tmp_gp0, tmp_gp1, \
                                     tmp_gp2, tmp_gp3, tmp_gp4, tmp_gp5, \
                                     tmp_gp6, xmm0, xmm1, xmm2, xmm3, xmm4, \
                                     xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, \
                                     xmm11, xmm12, xmm13, xmm14, xmm15
        ret

mksection stack-noexec
