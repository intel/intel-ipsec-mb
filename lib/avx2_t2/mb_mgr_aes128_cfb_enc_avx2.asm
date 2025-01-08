;;
;; Copyright (c) 2024, Intel Corporation
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
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/const.inc"
%include "include/clear_regs.inc"

%ifndef AES_ENC_X16
%define AES_ENC_X16 aes_cfb_enc_128_vaes_avx2
%define MODE CFB
%define NUM_KEYS 11
%define SUBMIT_JOB_AES_ENC submit_job_aes128_cfb_enc_vaes_avx2
%define FLUSH_JOB_AES_ENC flush_job_aes128_cfb_enc_vaes_avx2
%endif

; void AES_ENC_X16(AES_ARGS_X16 *args, UINT64 len_in_bytes);
extern AES_ENC_X16

mksection .text

%ifdef LINUX
%define arg1            rdi
%define arg2            rsi
%else
%define arg1            rcx
%define arg2            rdx
%endif

%define state           arg1
%define job             arg2
%define min_len         arg2    ;; min_len is passed to AES_ENC_X16 call
%define job_rax         rax

%define idx             rbp
%define unused_lanes    rbx
%define lane            r8
%define iv              r9
%define TMP_GP_1        r10
%define TMP_GP_2        r11
%define TMP_GP_3        r12
%define TMP_GP_4        r13

%define YMM_TMP_0       ymm0
%define YMM_TMP_1       ymm1
%define YMM_TMP_2       ymm2
%define YMM_TMP_3       ymm3
%define YMM_TMP_4       ymm4
%define YMM_TMP_5       ymm5
%define YMM_TMP_6       ymm6
%define YMM_TMP_7       ymm7

%define XMM_TMP_0       xmm0
%define XMM_TMP_1       xmm1
%define XMM_TMP_2       xmm2
%define XMM_TMP_3       xmm3
%define XMM_TMP_4       xmm4
%define XMM_TMP_5       xmm5
%define XMM_TMP_6       xmm6
%define XMM_TMP_7       xmm7
%define XMM_TMP_8       xmm8
%define XMM_TMP_9       xmm9
%define XMM_TMP_10      xmm10
%define XMM_TMP_11      xmm11
%define XMM_TMP_12      xmm12
%define XMM_TMP_13      xmm13
%define XMM_TMP_14      xmm14
%define XMM_TMP_15      xmm15

%define SUBMIT          0
%define FLUSH           1

; STACK_SPACE needs to be an odd multiple of 8
; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    8
_xmm_save:      resq    10*2
_rsp_save:      resq    1
endstruc

;; Save registers states
%macro FUNC_SAVE 0
        mov             rax, rsp
        sub             rsp, STACK_size
        and             rsp, -32

        mov             [rsp + _gpr_save + 8*0], rbx
        mov             [rsp + _gpr_save + 8*1], rbp
        mov             [rsp + _gpr_save + 8*2], r12
        mov             [rsp + _gpr_save + 8*3], r13
        mov             [rsp + _gpr_save + 8*4], r14
        mov             [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov             [rsp + _gpr_save + 8*6], rsi
        mov             [rsp + _gpr_save + 8*7], rdi
        vmovdqa         [rsp + _xmm_save + 0*16], xmm6
        vmovdqa         [rsp + _xmm_save + 1*16], xmm7
        vmovdqa         [rsp + _xmm_save + 2*16], xmm8
        vmovdqa         [rsp + _xmm_save + 3*16], xmm9
        vmovdqa         [rsp + _xmm_save + 4*16], xmm10
        vmovdqa         [rsp + _xmm_save + 5*16], xmm11
        vmovdqa         [rsp + _xmm_save + 6*16], xmm12
        vmovdqa         [rsp + _xmm_save + 7*16], xmm13
        vmovdqa         [rsp + _xmm_save + 8*16], xmm14
        vmovdqa         [rsp + _xmm_save + 9*16], xmm15
%endif
        mov     [rsp + _rsp_save], rax  ; original SP
%endmacro

;; Restore registers states
%macro FUNC_RESTORE 0
        mov             rbx, [rsp + _gpr_save + 8*0]
        mov             rbp, [rsp + _gpr_save + 8*1]
        mov             r12, [rsp + _gpr_save + 8*2]
        mov             r13, [rsp + _gpr_save + 8*3]
        mov             r14, [rsp + _gpr_save + 8*4]
        mov             r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov             rsi, [rsp + _gpr_save + 8*6]
        mov             rdi, [rsp + _gpr_save + 8*7]
        vmovdqa         [rsp + _xmm_save + 0*16], xmm6
        vmovdqa         [rsp + _xmm_save + 1*16], xmm7
        vmovdqa         [rsp + _xmm_save + 2*16], xmm8
        vmovdqa         [rsp + _xmm_save + 3*16], xmm9
        vmovdqa         [rsp + _xmm_save + 4*16], xmm10
        vmovdqa         [rsp + _xmm_save + 5*16], xmm11
        vmovdqa         [rsp + _xmm_save + 6*16], xmm12
        vmovdqa         [rsp + _xmm_save + 7*16], xmm13
        vmovdqa         [rsp + _xmm_save + 8*16], xmm14
        vmovdqa         [rsp + _xmm_save + 9*16], xmm15
%endif
        mov             rsp, [rsp + _rsp_save]  ; original SP
%endmacro

;; this macro uses ymm regisers YMM_TMP_ 0:7
%macro INSERT_KEYS 3
%define %%DST           %1 ; [clobbered] GP reg
%define %%SRC           %2 ; [clobbered] GP reg
%define %%OFFSET        %3 ; [clobbered] GP reg

        mov             %%OFFSET, lane
        shl             %%OFFSET, 4
        mov             %%SRC, [job + _enc_keys]

        lea             %%DST, [state + _aes_args_key_tab]
        add             %%DST, %%OFFSET

        ;; 11 keys are guaranteed (11 total round keys for AES128)
%assign i 0
%rep 5
        vmovdqu         YMM_TMP_ %+ i, [%%SRC + 32 * i]
        vmovdqu         [%%DST + 16 * 16 * 2 * i],  XMM_TMP_ %+ i
        vextracti128    [%%DST + 16 * 16 * (2 * i + 1)], YMM_TMP_ %+ i, 1
%assign i (i + 1)
%endrep
%assign SRC_OFFSET (10 * 16)
%assign DST_OFFSET (16 * 16 * 10)

%if NUM_KEYS > 11 ; 13 or 15
        vmovdqu         YMM_TMP_5, [%%SRC + SRC_OFFSET]
        vmovdqu         [%%DST + DST_OFFSET],  XMM_TMP_5
        vextracti128    [%%DST + DST_OFFSET + 16 * 16 ], YMM_TMP_5, 1

%assign SRC_OFFSET (12 * 16)
%assign DST_OFFSET (16 * 16 * 12)
%endif

%if NUM_KEYS > 13
        vmovdqu         YMM_TMP_6, [%%SRC + SRC_OFFSET]
        vmovdqu         [%%DST + DST_OFFSET],  XMM_TMP_6
        vextracti128    [%%DST + DST_OFFSET + 16 * 16 ], YMM_TMP_6, 1
%assign SRC_OFFSET (14 * 16)
%assign DST_OFFSET (16 * 16 * 14)
%endif

        vmovdqu         XMM_TMP_7, [%%SRC + SRC_OFFSET]
        vmovdqu         [%%DST + DST_OFFSET], XMM_TMP_7
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Copy Expanded keys, IN/OUT pointers and IV from lane  %%GOOD_LANE_INDEX
; to all lanes without job pointers
; Uses TMP_GP_(1-4) and  XMM_TMP_(0-15)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro COPY_GOOD_LANE_DATA 1
%define %%GOOD_LANE_INDEX        %1     ;; [in] index of lane that has valid job in it

%define %%GOOD_LANE_IN_PTR        TMP_GP_1
%define %%GOOD_LANE_OUT_PTR       TMP_GP_2

        ;; Collect data from the good lane
        mov             TMP_GP_4, %%GOOD_LANE_INDEX
        shl             TMP_GP_4, 4
        ;; Get in / out ptrs
        mov             %%GOOD_LANE_IN_PTR, [state + _aes_args_in + %%GOOD_LANE_INDEX * 8]
        mov             %%GOOD_LANE_OUT_PTR, [state + _aes_args_out + %%GOOD_LANE_INDEX * 8]
        ;; Get 1st key pointer
        lea             TMP_GP_3, [state + _aes_args_key_tab + TMP_GP_4]

        ;; Read all expanded keys into XMM_TMP_(0-NUM_KEYS)
%assign KEY 0
%rep NUM_KEYS
        vmovdqu         XMM_TMP_%+KEY, [TMP_GP_3 + KEY*16*16]
%assign KEY (KEY+1)
%endrep

        ;; Put IV in XMM_TMP_15
        vmovdqu         XMM_TMP_15, [state + _aes_args_IV + TMP_GP_4]
        lea             TMP_GP_3, [state + _aes_args_key_tab]

        ;; Copy good lane data to empty lanes
%assign LANE_ID 0
%rep 16
        cmp             qword [state + _aes_job_in_lane + LANE_ID*8], 0
        jne             %%skip_copy_ %+ LANE_ID
        mov             [state + _aes_args_in + LANE_ID*8], %%GOOD_LANE_IN_PTR
        mov             [state + _aes_args_out + LANE_ID*8], %%GOOD_LANE_OUT_PTR
        vmovdqu         [state + _aes_args_IV + (LANE_ID << 4)], XMM_TMP_15
;; Copy expanded keys
%assign KEY 0
%rep NUM_KEYS
        vmovdqu         [TMP_GP_3 + (LANE_ID << 4) + KEY*16*16], XMM_TMP_%+KEY
%assign KEY (KEY+1)
%endrep

%%skip_copy_ %+ LANE_ID:
%assign LANE_ID (LANE_ID+1)
%endrep

%endmacro ;; COPY_GOOD_LANE_DATA

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; For each unused lane (with job ptr set to 0) set length to UINT16_MAX(0xffff)
; Updates [state + _aes_lens]
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SET_LENGTHS_TO_MAX 4
%define %%LENGTH_LO        %1     ;; [clobbered] temp YMM reg
%define %%LENGTH_HI        %2     ;; [clobbered] temp XMM reg
%define %%TEMP_XMM         %3     ;; [clobbered] temp XMM reg
%define %%TEMP_GP          %4     ;; [clobbered] temp GP reg

        ; Set len to UINT16_MAX(0xffff) for unused lanes
        vmovdqa         XWORD(%%LENGTH_LO), [state + _aes_lens]
        vmovdqa         XWORD(%%LENGTH_HI), [state + _aes_lens + 16]

%assign I 0
%rep 8
        cmp     qword [state + _aes_job_in_lane + I * 8], 0
        jne     %%skip_copy_ffs_ %+ I
        mov     idx, (I << 4)
        XVPINSRW XWORD(%%LENGTH_LO), %%TEMP_XMM, %%TEMP_GP, idx, 0xffff, no_scale
%%skip_copy_ffs_ %+ I:
        cmp     qword [state + _aes_job_in_lane + ( I + 8 ) * 8], 0
        jne     %%skip_copy_ffs_hi_ %+ I
        mov     idx, (I << 4)
        XVPINSRW %%LENGTH_HI, %%TEMP_XMM, %%TEMP_GP, idx, 0xffff, no_scale
%%skip_copy_ffs_hi_ %+ I:
%assign I (I+1)
%endrep
        vmovdqa [state + _aes_lens], XWORD(%%LENGTH_LO)
        vmovdqa [state + _aes_lens + 8*2], %%LENGTH_HI

%endmacro ;; SET_LENGTHS_TO_MAX

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Fill data in state for current lane with data from job
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro STORE_JOB_DATA 4
%define %%JOB                   %1      ;; [in] job ptr
%define %%LANE_IDX              %2      ;; [in] index for job
%define %%TMP_GP_1              %3      ;; [clobbered] temp GP reg
%define %%TMP_GP_2              %4      ;; [clobbered] temp GP reg
        ;; Store job ptr
        mov     [state + _aes_job_in_lane + %%LANE_IDX*8], %%JOB
        ;; Store length
        mov     %%TMP_GP_1, [%%JOB + _msg_len_to_cipher_in_bytes]

%ifidn MODE, CBC
	and	%%TMP_GP_1, -16		; DOCSIS may pass size unaligned to block size
%endif
        mov     [state + _aes_lens + 2*%%LANE_IDX], WORD(%%TMP_GP_1)
        ;; Store IV
        mov     iv, [%%JOB + _iv]
        vmovdqu XMM_TMP_0, [iv]
        mov     %%TMP_GP_2, %%LANE_IDX
        shl     %%TMP_GP_2, 4
        vmovdqu [state + _aes_args_IV + %%TMP_GP_2], XMM_TMP_0
        ;; Store input ptr with offset
        mov     %%TMP_GP_1, [%%JOB + _src]
        add     %%TMP_GP_1, [%%JOB + _cipher_start_src_offset_in_bytes]
        mov     [state + _aes_args_in + %%LANE_IDX*8], %%TMP_GP_1
        ;; Store expanded keys
        mov     %%TMP_GP_1, [%%JOB + _enc_keys]
        INSERT_KEYS %%TMP_GP_1, %%TMP_GP_2, TMP_GP_3
        ;; Store output ptr
        mov     %%TMP_GP_1, [%%JOB + _dst]
        mov     [state + _aes_args_out + %%LANE_IDX*8], %%TMP_GP_1

%endmacro ;; STORE_JOB_DATA

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Handle both SUBMIT and FLUSH calls for AES CFB/CBC encryption
; Allows to process 16 lanes in parallel
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SUBMIT_FLUSH_AES_ENC 1
%define %%SUBMIT_FLUSH          %1

%if %%SUBMIT_FLUSH == FLUSH
        ; Check if there are any jobs to process
        cmp     qword [state + _aes_lanes_in_use], 0
        je      %%return_null

        SET_LENGTHS_TO_MAX YMM_TMP_0, XMM_TMP_1, XMM_TMP_2, TMP_GP_3

%else   ;; SUBMIT
        ;; Get indexes of unused lanes
        mov     unused_lanes, [state + _aes_unused_lanes]
        mov     lane, unused_lanes
        ; Pick job index from lowest 4 bits
        and     lane, 0xF
        ;; Remove obtained index from unused lanes
        shr     unused_lanes, 4
        mov     [state + _aes_unused_lanes], unused_lanes
        ;; Increase lanes in use count
        add     qword [state + _aes_lanes_in_use], 1

        STORE_JOB_DATA job, lane, TMP_GP_1, TMP_GP_2

        ;; If not all 16 jobs are in use wait for more jobs
        cmp     qword [state + _aes_lanes_in_use], 16
        jne     %%return_null
%endif
        ; Find minimum length
        vmovdqa         YMM_TMP_0, [state + _aes_lens]
        vphminposuw     XMM_TMP_2, XMM_TMP_0  ; for lanes 0...7
        vpextrw         min_len, XMM_TMP_2, 0        ; min value
        vpextrw         idx, XMM_TMP_2, 1            ; min index (for lanes 0...7)

        vextracti128    XMM_TMP_1, YMM_TMP_0, 1      ; for lanes 8...15
        vphminposuw     XMM_TMP_2, XMM_TMP_1
        vpextrw         DWORD(TMP_GP_1), XMM_TMP_2, 0    ; min value
        cmp             DWORD(min_len), DWORD(TMP_GP_1)
        jbe             %%use_min                               ; check if new value is lower
        ;; Min value is from lanes 8...15
        vpextrw         idx, XMM_TMP_2, 1         ; min index (0-7)
        add             idx, 8                           ; index + 8
        mov             min_len, TMP_GP_1                       ; min len
%%use_min:
        ; Check for zero length, to retrieve already encrypted buffers
        cmp             min_len, 0
        je              %%len_is_0

%if %%SUBMIT_FLUSH == FLUSH
        COPY_GOOD_LANE_DATA idx         ; copy good_lane data to empty lanes
%endif

        vmovdqa         YMM_TMP_0, [state + _aes_lens]

        ; subtract common minimum length from all lanes lengths
        vmovq           XMM_TMP_3, min_len
        vpbroadcastw    YMM_TMP_3, XMM_TMP_3
        vpsubw          YMM_TMP_0, YMM_TMP_0, YMM_TMP_3
        vmovdqa         [state + _aes_lens], YMM_TMP_0

        ; state == AES_ARGS == arg1
        ; min_len == arg2
        call    AES_ENC_X16
        ; state and idx are intact

%%len_is_0:
        ; job with id == index is completed - set status to completed
        mov     job_rax, [state + _aes_job_in_lane + idx * 8]
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_CIPHER

        ; return used lane to _aes_unused_lanes, decrease _aes_lanes_in_use and
        ; remove job ptr from _aes_job_in_lane
        mov     unused_lanes, [state + _aes_unused_lanes]
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _aes_unused_lanes], unused_lanes
        sub     qword [state + _aes_lanes_in_use], 1
        mov     qword [state + _aes_job_in_lane + idx * 8], 0

%ifdef SAFE_DATA
        ;; Clear expanded keys
        vpxor   xmm0, xmm0
%if %%SUBMIT_FLUSH == FLUSH
        ;; Clear expanded keys for all unused lanes
%assign LANE_ID 0
%rep 16
        cmp             qword [state + _aes_job_in_lane + LANE_ID*8], 0
        jne             %%skip_clear_ %+ LANE_ID
        ;; Clear expanded keys per lane
%assign KEY 0
%rep NUM_KEYS
        vmovdqa         [state + _aes_args_key_tab + (LANE_ID << 4) + KEY*16*16], xmm0
%assign KEY (KEY+1)
%endrep

%%skip_clear_ %+ LANE_ID:
%assign LANE_ID (LANE_ID+1)
%endrep

%else ;; SUBMIT
        shl     idx, 4
        ;; Clear expanded keys for processed lane
%assign key_round 0
%rep NUM_KEYS
        vmovdqa [state + _aesarg_key_tab + key_round * (16*16) + idx], xmm0
%assign key_round (key_round + 1)
%endrep
%endif ;;  SUBMIT/FLUSH

%endif ;; SAFE_DATA

        jmp %%done

%%return_null:
        xor     job_rax, job_rax

%%done:
%ifdef SAFE_DATA
	clear_all_ymms_asm
%else
        vzeroupper
%endif ;; SAFE_DATA
%endmacro

; JOB* SUBMIT_JOB_AES_ENC(MB_MGR_AES_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
align 32
MKGLOBAL(SUBMIT_JOB_AES_ENC,function,internal)
SUBMIT_JOB_AES_ENC:
        FUNC_SAVE
        SUBMIT_FLUSH_AES_ENC SUBMIT
        FUNC_RESTORE
        ret

; JOB* FLUSH_JOB_AES_ENC(MB_MGR_AES_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
align 32
MKGLOBAL(FLUSH_JOB_AES_ENC,function,internal)
FLUSH_JOB_AES_ENC:
        FUNC_SAVE
        SUBMIT_FLUSH_AES_ENC FLUSH
        FUNC_RESTORE
        ret
mksection stack-noexec

