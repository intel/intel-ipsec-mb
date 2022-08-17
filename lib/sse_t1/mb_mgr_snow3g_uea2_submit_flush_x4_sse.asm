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
%include "sse_t1/snow3g_uea2_by4_sse.asm"

%define SUBMIT_JOB_SNOW3G_UEA2 submit_job_snow3g_uea2_sse
%define FLUSH_JOB_SNOW3G_UEA2 flush_job_snow3g_uea2_sse

mksection .rodata
default rel

align 64
last_3_bytes:
dd 0x00000003, 0x00000003, 0x00000003, 0x00000003
align 64
zero_xmm:
dd 0x00000000, 0x00000000, 0x00000000, 0x00000000

mksection .text
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

%define tmp_gp3  rbx
%define tmp_gp4  rbp
%define tmp_gp5  r9
%define tmp_gp6  r10
%define tmp_gp7  r11
%define tmp_gp8  r12

%define state    arg1
%define job      arg2

%define job_rax  rax

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

        mov     DWORD(%%UNUSED_LANES), dword [%%LANE_LIST]
        mov     %%LANE_NR, %%UNUSED_LANES
        and     %%LANE_NR, 0x3
        ;; remove picked lane nr from list of unused lanes
        shr     %%UNUSED_LANES, 4
        mov     dword [%%LANE_LIST], DWORD(%%UNUSED_LANES)

        add	word [%%LANES_IN_USE], 1
        mov     [%%JOB_LANES + %%LANE_NR*8], %%JOB
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Find minimum value in table of 4 dwords
;; Outputs (%4) min value and (%5) position of that value in the table
;; Additionally (%2) contains list of lane lengths extracted from (%1)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro GET_MIN_LENGTH_X4_SSE 4
%define %%LANE_LENS_LIST_PTR    %1 ;; [in]  ptr to list of lane lengths
%define %%TEMP_64               %2 ;; [clobbered] tmp 64bit register
%define %%LENGTH                %3 ;; [out] gp register to put min length in
%define %%INDEX                 %4 ;; [out] gp register to put index in

        mov     DWORD(%%LENGTH), [%%LANE_LENS_LIST_PTR + 4*0]
        xor     %%INDEX, %%INDEX
        mov     %%TEMP_64, 1

        cmp     DWORD(%%LENGTH), [%%LANE_LENS_LIST_PTR + 4*1]
        cmova   DWORD(%%LENGTH), [%%LANE_LENS_LIST_PTR + 4*1]
        cmova   %%INDEX, %%TEMP_64
        inc     %%TEMP_64

        cmp     DWORD(%%LENGTH), [%%LANE_LENS_LIST_PTR + 4*2]
        cmova   DWORD(%%LENGTH), [%%LANE_LENS_LIST_PTR + 4*2]
        cmova   %%INDEX, %%TEMP_64
        inc     %%TEMP_64

        cmp     DWORD(%%LENGTH), [%%LANE_LENS_LIST_PTR + 4*3]
        cmova   DWORD(%%LENGTH), [%%LANE_LENS_LIST_PTR + 4*3]
        cmova   %%INDEX, %%TEMP_64
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Depending on %1:
;; submit: Submit single SNOW3G request to be later processed, setup masks and
;;         initial FSM/LFSR state. After that, if there is full 4 requests
;;         submitted proceed with flush operation.
;; flush:  Do SNOW3G encrypt/decrypt processing for 4 buffers until one of them
;;         is fully processed. Return job pointer corresponding to finished
;;         request.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SUBMIT_FLUSH_JOB_SNOW3G_UEA2_SSE 25
%define %%SUBMIT_FLUSH          %1    ;; [in] submit/flush selector
%define %%UNUSED_LANES          %2    ;; [clobbered] GP register
%define %%LANE                  %3    ;; [clobbered] GP register
%define %%TGP0                  %4    ;; [clobbered] GP register
%define %%TGP1                  %5    ;; [clobbered] GP register
%define %%TGP2                  %6    ;; [clobbered] GP register
%define %%TGP3                  %7    ;; [clobbered] GP register
%define %%TGP4                  %8    ;; [clobbered] GP register
%define %%TGP5                  %9    ;; [clobbered] GP register
%define %%TMP_XMM_0             %10   ;; [clobbered] xmm register
%define %%TMP_XMM_1             %11   ;; [clobbered] xmm register
%define %%TMP_XMM_2             %12   ;; [clobbered] xmm register
%define %%TMP_XMM_3             %13   ;; [clobbered] xmm register
%define %%TMP_XMM_4             %14   ;; [clobbered] xmm register
%define %%TMP_XMM_5             %15   ;; [clobbered] xmm register
%define %%TMP_XMM_6             %16   ;; [clobbered] xmm register
%define %%TMP_XMM_7             %17   ;; [clobbered] xmm register
%define %%TMP_XMM_8             %18   ;; [clobbered] xmm register
%define %%TMP_XMM_9             %19   ;; [clobbered] xmm register
%define %%TMP_XMM_10            %20   ;; [clobbered] xmm register
%define %%TMP_XMM_11            %21   ;; [clobbered] xmm register
%define %%TMP_XMM_12            %22   ;; [clobbered] xmm register
%define %%TMP_XMM_13            %23   ;; [clobbered] xmm register
%define %%TMP_XMM_14            %24   ;; [clobbered] xmm register
%define %%TMP_XMM_15            %25   ;; [clobbered] xmm register

        SNOW3G_FUNC_START
        xor     job_rax, job_rax        ;; assume NULL return job

%ifidn %%SUBMIT_FLUSH, submit
        GET_UNUSED_LANE_SSE state + _snow3g_unused_lanes, \
                            state + _snow3g_lanes_in_use, \
                            state + _snow3g_job_in_lane,  \
                            job, %%LANE, %%UNUSED_LANES

        mov             %%TGP1, [job + _enc_keys]
        mov             %%TGP2, [job + _iv]

        ;; ---------------------------------------------------------------------
        ;; Initialize LFSR and FSM registers
        ;; [LD_ST_MASK + 4*%%LANE] = 0
        ;; [LD_ST_MASK + 4*4+ 4*%%LANE] = 0
        ;; LD_ST_MASK field from state is later used to determine if any data
        ;; should be read from src and written to dst.
        ;; When mask is set to 0 so no reads/writes occur.
        SNOW3G_INIT_LANE_SSE state, %%LANE, %%TGP1, %%TGP2, %%TMP_XMM_0, \
                             %%TMP_XMM_1, %%TMP_XMM_2

        ;; 32 iterations in Init mode are required
        ;; details of _snow3g_lens dw fields are in FLUSH section
        mov             dword [state + _snow3g_lens + 32 + 4*%%LANE], 32
        mov             dword [state + _snow3g_lens + 4*%%LANE], 4

        mov             %%TGP0, [job + _msg_len_to_cipher_in_bits]
        shr             %%TGP0, 3

        mov             dword [state + _snow3g_args_byte_length + %%LANE*4], DWORD(%%TGP0)

        mov             %%TGP0, [job + _cipher_start_offset_in_bits]
        shr             %%TGP0, 3      ;; convert from bits to bytes (src & dst)
        mov             %%TGP1, [job + _dst]
        add             %%TGP1, %%TGP0
        add             %%TGP0, [job + _src]

        mov             [state + _snow3g_args_in + %%LANE*8], %%TGP0
        mov             [state + _snow3g_args_out + %%LANE*8], %%TGP1

        cmp             word [state + _snow3g_lanes_in_use], 4
        jne             %%return_uea2
        ;; if all lanes are busy fall through to %%process_job_uea2

%else   ;; FLUSH
        ;; ---------------------------------------------------------------------
        ;; All lanes are busy or flush is called - process used lanes until
        ;; one job is done.
        ;; ---------------------------------------------------------------------
        ;; Each of the lanes can be in any stage: INIT1, INIT2, KEYGEN, FINISHED
        ;; and they can be processed in parallel by the algorithmic code.
        ;; START -> INIT1 -> INIT2 -> KEYGEN -> COMPLETE
        ;; ---------------------------------------------------------------------
        ;; State of the job is identified with:
        ;; _snow3g_args_LD_ST_MASK
        ;;      *dwords 4:7 - determines if INIT1 phase is done
        ;;      *dwords 0:3 - determines if lane is KEYGEN state
        ;;                  -> yes: all bits set in dw per given lane
        ;;                  -> no : set to 0
        ;; _snow3g_args_byte_length
        ;;      message lengths to be processed (bytes). Decreased appropriately
        ;;      if particular lane is in KEYGEN phase
        ;; _snow3g_lens:
        ;;      *dwords 0:3 - indicating final 0-4 bytes to be outputted for the
        ;;                    lane per SNOW3G_INIT_LANE_SSE macro call
        ;;      *dword 4    - common minimum length in double words (rounded up)
        ;;      *dwords 5:7 - unused
        ;;      *dwords 8:11 - length in dwords to be processed per lane in
        ;;                     given processing phase(rounded up)
        ;; ---------------------------------------------------------------------
        cmp             word [state + _snow3g_lanes_in_use], 0
        je              %%return_uea2
%endif

%%_find_min:
%define ROUNDED_DW_LENS _snow3g_lens+32
%define KEYGEN_STAGE    _snow3g_args_LD_ST_MASK
%define INIT1_DONE      _snow3g_args_LD_ST_MASK+16
        ;; Find minimum length. If lane is empty min length is set to 0xffffffff
        GET_MIN_LENGTH_X4_SSE   state + ROUNDED_DW_LENS, %%TGP1, %%TGP0, %%LANE
        or              %%TGP0, %%TGP0
        jz              %%_len_is_0

        ;; fill %%TMP_XMM_0 with common length values per initialized length
        ;; to be subtracted from remaining byte lengths and rounded dw lengths
        movd            %%TMP_XMM_0, DWORD(%%TGP0)
        pshufd	        %%TMP_XMM_0, %%TMP_XMM_0, 0

        ;; Create mask with lanes in use
        pxor            %%TMP_XMM_2, %%TMP_XMM_2
        pxor            %%TMP_XMM_3, %%TMP_XMM_3
        pcmpeqq         %%TMP_XMM_2, [state + _snow3g_job_in_lane]
        pcmpeqq         %%TMP_XMM_3, [state + _snow3g_job_in_lane + 16]
        pshufd          %%TMP_XMM_2, %%TMP_XMM_2, 0x88 ;; lane order: 1,0,1,0
        pshufd          %%TMP_XMM_3, %%TMP_XMM_3, 0x88 ;; lane order: 3,2,3,2
        pblendw         %%TMP_XMM_2, %%TMP_XMM_3, 0xf0
        pandn           %%TMP_XMM_2, %%TMP_XMM_0

        ;; Decrease rouded dw lengths remaining for processing
        movdqa          %%TMP_XMM_5, [state + ROUNDED_DW_LENS]
        psubd           %%TMP_XMM_5, %%TMP_XMM_2
        movdqa          [state + ROUNDED_DW_LENS], %%TMP_XMM_5

        ;; Set all bits in dws where rounded dw length is bigger than original
        ;; byte lengths and lane is initialized
        pslld           %%TMP_XMM_0, 2          ;; common length in bytes
        pand            %%TMP_XMM_0, [state + KEYGEN_STAGE]
        movdqa          %%TMP_XMM_1, %%TMP_XMM_0
        pcmpgtd         %%TMP_XMM_1, [state + _snow3g_args_byte_length]
        movdqa          %%TMP_XMM_2, %%TMP_XMM_1
        pand            %%TMP_XMM_1, [state + _snow3g_args_byte_length]

        pxor            %%TMP_XMM_2, [rel all_fs]
        pand            %%TMP_XMM_0, %%TMP_XMM_2
        por             %%TMP_XMM_0, %%TMP_XMM_1

        ;; Write outstanding bytes to _snow3g_lens dwords [0:3] and adjust
        ;; _snow3g_args_byte_length so after common dw length subtraction
        ;; it is set to 0
        pand            %%TMP_XMM_1, [rel last_3_bytes]
        pand            %%TMP_XMM_2, [state+_snow3g_lens]
        por             %%TMP_XMM_1, %%TMP_XMM_2
        movdqa          [state + _snow3g_lens], %%TMP_XMM_1

        ;; Subtract Common dw length from all byte lengths
        movdqa        %%TMP_XMM_4, [state+_snow3g_args_byte_length]
        psubd         %%TMP_XMM_4, %%TMP_XMM_0
        movdqa        [state+_snow3g_args_byte_length], %%TMP_XMM_4

        ;; Do cipher / clock operation for all lanes and given common length
        SNOW3G_ENC_DEC  state, %%TGP0, %%TGP1, %%TGP2, %%TGP3, %%TGP4, %%TGP5, \
                        %%TMP_XMM_0, %%TMP_XMM_1, %%TMP_XMM_2, %%TMP_XMM_3,    \
                        %%TMP_XMM_4, %%TMP_XMM_5, %%TMP_XMM_6, %%TMP_XMM_7,    \
                        %%TMP_XMM_8, %%TMP_XMM_9, %%TMP_XMM_10, %%TMP_XMM_11,  \
                        %%TMP_XMM_12, %%TMP_XMM_13, %%TMP_XMM_14, %%TMP_XMM_15

        jmp %%_find_min

%%_len_is_0:
        ;; ---------------------------------------------------------------------
        ;; 3 states are possible here for the lane with length 0:
        ;; INIT1 done -> set DW length to 1 and update LD_ST_MASK
        ;; INIT2 done -> set DW length to bytelength rounded up to dws and
        ;;               update LD_ST_MASK
        ;; COMPLETED -> update length and return job
        ;; check if the job is in one of INIT1 or INIT2
        ;; lane with len 0 index is %%LANE
        ;; ---------------------------------------------------------------------
        test            dword [state + KEYGEN_STAGE + %%LANE*4], 0xffffffff
        jne             %%process_completed_job_submit_uea2

        ;; check if INIT1 stage is done
        test            dword [state + INIT1_DONE + %%LANE*4], 0xffffffff
        jne             %%_init_done

        ;; mark INIT1 completed and set length to 1DW for INIT2 stage
        mov             dword [state + INIT1_DONE + %%LANE*4], 0xffffffff
        mov             dword [state + ROUNDED_DW_LENS + %%LANE*4], 1

        jmp             %%_find_min

%%_init_done:
        mov             dword [state + KEYGEN_STAGE + %%LANE*4], 0xffffffff

        ;; length in double words = original length in bytes / 4
        ;; odd bytes are rounded up
        mov             DWORD(%%TGP0), [state + _snow3g_args_byte_length + %%LANE*4]
        mov             DWORD(%%TGP1), DWORD(%%TGP0)
        shr             %%TGP0, 2
        and             %%TGP1, 3
        je              %%_no_rounding_up
        inc             %%TGP0
%%_no_rounding_up:
        mov             dword [state + ROUNDED_DW_LENS + %%LANE*4], DWORD (%%TGP0)
        jmp             %%_find_min

%%process_completed_job_submit_uea2:
        ;; COMPLETE: return job, change job dw length to UINT32_MAX, set masks
        ;; to not initialized
        mov             dword [state + ROUNDED_DW_LENS + %%LANE*4], 0xffffffff
        mov             dword [state + KEYGEN_STAGE + %%LANE*4], 0
        mov             dword [state + INIT1_DONE + %%LANE*4], 0

        ;; decrement number of jobs in use
        dec             word [state + _snow3g_lanes_in_use]

        mov             job_rax, [state + _snow3g_job_in_lane + %%LANE*8]
        or              qword [job_rax + _status], IMB_STATUS_COMPLETED_CIPHER

        mov             %%UNUSED_LANES, [state + _snow3g_unused_lanes]
        mov             qword [state + _snow3g_job_in_lane + %%LANE*8], 0
        shl             %%UNUSED_LANES, 4
        or              %%UNUSED_LANES, %%LANE
        mov             [state + _snow3g_unused_lanes], %%UNUSED_LANES

%ifdef SAFE_DATA
        ;; clear finished job lane, %%LANE is an index of finished job
        mov             dword [state + _snow3g_args_LFSR_0 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_1 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_2 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_3 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_4 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_5 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_6 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_7 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_8 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_9 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_10 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_11 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_12 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_13 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_14 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_LFSR_15 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_FSM_1 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_FSM_2 + 4*%%LANE], 0
        mov             dword [state + _snow3g_args_FSM_3 + 4*%%LANE], 0

        ;; clear key stream stack frame
        pxor            %%TMP_XMM_0, %%TMP_XMM_0
        ;; _keystream clean is part of submit as well under return_uea2 label
        movdqa          [rsp + _keystream + 1 * 16], %%TMP_XMM_0
        movdqa          [rsp + _keystream + 2 * 16], %%TMP_XMM_0
        movdqa          [rsp + _keystream + 3 * 16], %%TMP_XMM_0
%endif

%%return_uea2:

%ifdef SAFE_DATA
        ;; clear temporarily stored swapped IV (done inside of submit)
        pxor            %%TMP_XMM_0, %%TMP_XMM_0
        movdqa          [rsp + _keystream], %%TMP_XMM_0
%endif

        SNOW3G_FUNC_END

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; JOB* SUBMIT_JOB_SNOW3G_UEA2(MB_MGR_SNOW3G_OOO *state, IMB_JOB *job)
;; arg 1 : state
;; arg 2 : job
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(SUBMIT_JOB_SNOW3G_UEA2,function,internal)
SUBMIT_JOB_SNOW3G_UEA2:
        SUBMIT_FLUSH_JOB_SNOW3G_UEA2_SSE submit, tmp_gp1, tmp_gp2, tmp_gp3,     \
                                     tmp_gp4, tmp_gp5, tmp_gp6, tmp_gp7,    \
                                     tmp_gp8, xmm0, xmm1, xmm2, xmm3, xmm4, \
                                     xmm5, xmm6, xmm7, xmm8, xmm9, xmm10,   \
                                     xmm11, xmm12, xmm13, xmm14, xmm15

        ret

MKGLOBAL(FLUSH_JOB_SNOW3G_UEA2,function,internal)
FLUSH_JOB_SNOW3G_UEA2:
        SUBMIT_FLUSH_JOB_SNOW3G_UEA2_SSE flush, tmp_gp1, tmp_gp2, tmp_gp3, tmp_gp4,\
                                     tmp_gp5, tmp_gp6, tmp_gp7, tmp_gp8, xmm0, \
                                     xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, \
                                     xmm8, xmm9, xmm10, xmm11, xmm12, xmm13,   \
                                     xmm14, xmm15
        ret
mksection stack-noexec
