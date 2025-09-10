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

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/const.inc"
%include "include/memcpy.inc"
%include "include/cet.inc"
%include "include/align_avx.inc"
%include "include/clear_regs.inc"

%ifndef AES_CBC_MAC

%define AES_CBC_MAC aes128_cbc_mac_vaes_avx2
%define SUBMIT_JOB_AES_CCM_AUTH submit_job_aes128_ccm_auth_vaes_avx2
%define FLUSH_JOB_AES_CCM_AUTH flush_job_aes128_ccm_auth_vaes_avx2
%define NUM_KEYS 11

%endif

extern AES_CBC_MAC

mksection .rodata
default rel

counter_mask:
        dq 0xFFFFFFFFFFFFFF07, 0x0000FFFFFFFFFFFF

mksection .text

%define APPEND(a,b) a %+ b

%ifndef NROUNDS
%define NROUNDS 9 ; AES-CCM-128
%endif
%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%else
%define arg1    rcx
%define arg2    rdx
%endif

%define state   arg1
%define job     arg2
%define len2    arg2

%define job_rax          rax
%define tmp4             rax
%define auth_len_aad     rax

%define min_idx          rbp
%define flags            rbp

%define lane             r8

%define iv_len           r9
%define auth_len         r9

%define aad_len          r10
%define init_block_addr  r11

%define unused_lanes     rbx
%define r                rbx

%define tmp1              r12
%define tmp2             r13
%define tmp3             r14

%define good_lane        r15
%define min_job          r15

%define init_block0      xmm0
%define ccm_lens         ymm1
%define min_len_idx      xmm2
%define xtmp0            xmm3
%define xtmp1            xmm4
%define xtmp2            xmm5
%define xtmp3            xmm6
%define xtmp4            xmm7
%define xtmp5            xmm8
%define xtmp6            xmm9
%define xtmp7            xmm10
%define xtmp8            xmm11
%define xtmp9            xmm12
%define xtmp10           xmm13
%define xtmp11           xmm14
%define xtmp12           xmm15
%define xtmp13           xmm0
%define xtmp14           xmm1
%define xtmp15           xmm2

%define ytmp0            ymm3
%define ytmp1            ymm4
%define ytmp2            ymm5
%define ytmp3            ymm6
%define ytmp4            ymm7
%define ytmp5            ymm8
%define ytmp6            ymm9
%define ytmp7            ymm10

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

%macro ENCRYPT_SINGLE_BLOCK 2
%define %%KP   %1
%define %%XDATA %2

                vpxor           %%XDATA, [%%KP + 0*(16*16)]
%assign i 1
%rep NROUNDS
                vaesenc         %%XDATA, [%%KP + i*(16*16)]
%assign i (i+1)
%endrep
                vaesenclast     %%XDATA, [%%KP + i*(16*16)]
%endmacro

;; this macro uses ymm registers ytmp 0:7
%macro INSERT_KEYS 3
%define %%DST           %1 ; [clobbered] GP reg
%define %%SRC           %2 ; [clobbered] GP reg
%define %%OFFSET        %3 ; [clobbered] GP reg

        mov             %%OFFSET, lane
        shl             %%OFFSET, 4
        mov             %%SRC, [job + _enc_keys]

        lea             %%DST, [state + _aes_ccm_args_key_tab]
        add             %%DST, %%OFFSET

        ;; 11 keys are guaranteed (11 total round keys for AES128)
%assign i 0
%rep 5
        vmovdqu         ytmp %+ i, [%%SRC + 32 * i]
        vmovdqu         [%%DST + 16 * 16 * 2 * i],  xtmp %+ i
        vextracti128    [%%DST + 16 * 16 * (2 * i + 1)], ytmp %+ i, 1
%assign i (i + 1)
%endrep
%assign SRC_OFFSET (10 * 16)
%assign DST_OFFSET (16 * 16 * 10)

%if NUM_KEYS > 11 ; 13 or 15
        vmovdqu         ytmp5, [%%SRC + SRC_OFFSET]
        vmovdqu         [%%DST + DST_OFFSET],  xtmp5
        vextracti128    [%%DST + DST_OFFSET + 16 * 16 ], ytmp5, 1

%assign SRC_OFFSET (12 * 16)
%assign DST_OFFSET (16 * 16 * 12)
%endif

%if NUM_KEYS > 13
        vmovdqu         ytmp6, [%%SRC + SRC_OFFSET]
        vmovdqu         [%%DST + DST_OFFSET],  xtmp6
        vextracti128    [%%DST + DST_OFFSET + 16 * 16 ], ytmp6, 1
%assign SRC_OFFSET (14 * 16)
%assign DST_OFFSET (16 * 16 * 14)
%endif

        vmovdqu         xtmp7, [%%SRC + SRC_OFFSET]
        vmovdqu         [%%DST + DST_OFFSET], xtmp7
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Copy Expanded keys, IN/OUT pointers and IV from lane  %%GOOD_LANE_INDEX
; to all lanes without job pointers
; Uses tmp(1-4) and  xtmp(0-15)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro COPY_GOOD_LANE_DATA 1
%define %%GOOD_LANE_INDEX        %1     ;; [in] index of lane that has valid job in it

%define %%GOOD_LANE_IN_PTR        tmp1

        ;; Collect data from the good lane
        mov             tmp2, %%GOOD_LANE_INDEX
        shl             tmp2, 4
        ;; Get input ptrs
        mov             %%GOOD_LANE_IN_PTR, [state + _aes_ccm_args_in + %%GOOD_LANE_INDEX * 8]
        ;; Get 1st key pointer
        lea             tmp3, [state + _aes_ccm_args_key_tab + tmp2]

        ;; Read all expanded keys into xtmp(0-NUM_KEYS)
%assign KEY 0
%rep NUM_KEYS
        vmovdqu         xtmp%+KEY, [tmp3 + KEY*16*16]
%assign KEY (KEY+1)
%endrep

        ;; Put IV in xtmp15
        vmovdqu         xtmp15, [state + _aes_ccm_args_IV + tmp2]
        lea             tmp3, [state + _aes_ccm_args_key_tab]
        movzx           tmp4,  word [state + _aes_ccm_init_done + %%GOOD_LANE_INDEX*2]

        ;; Copy good lane data to empty lanes
%assign LANE_ID 0
%rep 16
        cmp             qword [state + _aes_ccm_job_in_lane + LANE_ID*8], 0
        jne             %%skip_copy_ %+ LANE_ID
        mov             [state + _aes_ccm_args_in + LANE_ID*8], %%GOOD_LANE_IN_PTR
        vmovdqu         [state + _aes_ccm_args_IV + (LANE_ID << 4)], xtmp15
        mov             [state + _aes_ccm_init_done + (LANE_ID*2)], WORD(tmp4)

        ;; Copy expanded keys
%assign KEY 0
%rep NUM_KEYS
        vmovdqu         [tmp3 + (LANE_ID << 4) + KEY*16*16], xtmp%+KEY
%assign KEY (KEY+1)
%endrep

align_label
%%skip_copy_ %+ LANE_ID:
%assign LANE_ID (LANE_ID+1)
%endrep

%endmacro ;; COPY_GOOD_LANE_DATA

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; For each unused lane (with job ptr set to 0) set length to UINT16_MAX(0xffff)
; Updates [state + _aes_ccm_lens]
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SET_NULL_JOB_LENS_TO_MAX 5
%define %%LENGTH_LO        %1     ;; [clobbered] temp YMM reg
%define %%LENGTH_HI        %2     ;; [clobbered] temp XMM reg
%define %%TEMP_XMM         %3     ;; [clobbered] temp XMM reg
%define %%TEMP_GP1         %4     ;; [clobbered] temp GP reg
%define %%TEMP_GP2         %5     ;; [clobbered] temp GP reg

        ; Set len to UINT16_MAX(0xffff) for unused lanes
        vmovdqa         XWORD(%%LENGTH_LO), [state + _aes_ccm_lens]
        vmovdqa         XWORD(%%LENGTH_HI), [state + _aes_ccm_lens + 16]

%assign I 0
%rep 8
        cmp     qword [state + _aes_ccm_job_in_lane + I * 8], 0
        jne     %%skip_copy_ffs_ %+ I
        mov     %%TEMP_GP2, (I << 4)
        XVPINSRW XWORD(%%LENGTH_LO), %%TEMP_XMM, %%TEMP_GP1, %%TEMP_GP2, 0xffff, no_scale
align_label
%%skip_copy_ffs_ %+ I:
        cmp     qword [state + _aes_ccm_job_in_lane + ( I + 8 ) * 8], 0
        jne     %%skip_copy_ffs_hi_ %+ I
        mov     %%TEMP_GP2, (I << 4)
        XVPINSRW %%LENGTH_HI, %%TEMP_XMM, %%TEMP_GP1, %%TEMP_GP2, 0xffff, no_scale
align_label
%%skip_copy_ffs_hi_ %+ I:
%assign I (I+1)
%endrep
        vinserti128 %%LENGTH_LO, %%LENGTH_LO, %%LENGTH_HI, 1
        vmovdqa [state + _aes_ccm_lens], %%LENGTH_LO

%endmacro ;; SET_NULL_JOB_LENS_TO_MAX



;;; ===========================================================================
;;; AES CCM auth job submit & flush
;;; ===========================================================================
;;; SUBMIT_FLUSH [in] - SUBMIT, FLUSH job selection
%macro GENERIC_SUBMIT_FLUSH_JOB_AES_CCM_AUTH_AVX2 1
%define %%SUBMIT_FLUSH %1

        ;; Find free lane
        mov     unused_lanes, [state + _aes_ccm_unused_lanes]

%ifidn %%SUBMIT_FLUSH, SUBMIT

        mov     lane, unused_lanes
        and     lane, 15
        shr     unused_lanes, 4
        mov     [state + _aes_ccm_unused_lanes], unused_lanes

        ;; Increase lanes in use count
        add     qword [state + _aes_ccm_num_lanes_inuse], 1

        ;; Copy job info into lane
        mov     [state + _aes_ccm_job_in_lane + lane*8], job

        ;; Store expanded keys
        INSERT_KEYS tmp1, tmp2, tmp3

        ;; init_done = 0
        mov     word [state + _aes_ccm_init_done + lane*2], 0
        lea     tmp1, [lane * 8]

        vpxor   init_block0, init_block0
        vmovdqa [state + _aes_ccm_args_IV + tmp1*2], init_block0

        ;; Prepare initial Block 0 for CBC-MAC-128

        ;; Byte 0: flags with L' and M' (AAD later)
        ;; Calculate L' = 15 - IV length - 1 = 14 - IV length
        mov     flags, 14
        mov     iv_len, [job + _iv_len_in_bytes]
        sub     flags, iv_len
        ;; Calculate M' = (Digest length - 2) / 2
        mov     tmp1, [job + _auth_tag_output_len_in_bytes]
        sub     tmp1, 2

        shl     tmp1, 2 ; M' << 3 (combine 1xshr, to div by 2, and 3xshl)
        or      flags, tmp1

        ;; Bytes 1 - 13: Nonce (7 - 13 bytes long)

        ;; Bytes 1 - 7 are always copied (first 7 bytes)
        mov     tmp1, [job + _iv]
        vpinsrb init_block0, [tmp1], 1
        vpinsrw init_block0, [tmp1 + 1], 1
        vpinsrd init_block0, [tmp1 + 3], 1

        cmp     iv_len, 10
        je      %%_iv_length_10
        ja      %%_iv_length_11_to_13

        cmp     iv_len, 8
        je      %%_iv_length_8
        jb      %%_finish_nonce_move   ; iv_len = 7
        jmp     %%_iv_length_9         ; iv_len = 9

%%_iv_length_11_to_13:
        cmp     iv_len, 12
        je      %%_iv_length_12
        jb      %%_iv_length_11

        ;; Bytes 8 - 13
%%_iv_length_13:
        vpinsrb init_block0, [tmp1 + 12], 13
%%_iv_length_12:
        vpinsrb init_block0, [tmp1 + 11], 12
%%_iv_length_11:
        vpinsrd init_block0, [tmp1 + 7], 2
        jmp     %%_finish_nonce_move
%%_iv_length_10:
        vpinsrb init_block0, [tmp1 + 9], 10
%%_iv_length_9:
        vpinsrb init_block0, [tmp1 + 8], 9
%%_iv_length_8:
        vpinsrb init_block0, [tmp1 + 7], 8

align_label
%%_finish_nonce_move:

        ;; Bytes 14 & 15 (message length), in Big Endian
        mov     ax, [job + _msg_len_to_hash_in_bytes]
        xchg    al, ah
        vpinsrw init_block0, ax, 7

        mov     aad_len, [job + _cbcmac_aad_len]
        ;; Initial length to authenticate (Block 0)
        mov     auth_len, 16
        ;; Length to authenticate (Block 0 + len(AAD) (2B) + AAD padded,
        ;; so length is multiple of 64B)
        lea     auth_len_aad, [aad_len + (2 + 15) + 16]
        and     auth_len_aad, -16

        or      aad_len, aad_len
        cmovne  auth_len, auth_len_aad
        ;; Update lengths to authenticate and find min length
        vmovdqa ccm_lens, [state + _aes_ccm_lens]
        VPINSRW_256 ccm_lens, xtmp0, xtmp1, tmp2, lane, auth_len, scale_x16
        vmovdqa [state + _aes_ccm_lens], ccm_lens
        vphminposuw min_len_idx, XWORD(ccm_lens)

        mov     tmp1, lane
        shl     tmp1, 6
        lea     init_block_addr, [state + _aes_ccm_init_blocks + tmp1]
        or      aad_len, aad_len
        je      %%_aad_complete

        or      flags, (1 << 6) ; Set Adata bit in flags

        ;; Copy AAD
        ;; Set all 0s in last block (padding)
        lea     tmp1, [init_block_addr + auth_len]
        sub     tmp1, 16
        vpxor   xtmp0, xtmp0
        vmovdqa [tmp1], xtmp0

        ;; Start copying from second block
        lea     tmp1, [init_block_addr+16]
        mov     rax, aad_len
        xchg    al, ah
        mov     [tmp1], ax
        add     tmp1, 2
        mov     tmp2, [job + _cbcmac_aad]
        memcpy_avx_64_1 tmp1, tmp2, aad_len, tmp3, tmp4, xtmp0, xtmp1, xtmp2, xtmp3

align_label
%%_aad_complete:

        ;; Finish Block 0 with Byte 0
        vpinsrb init_block0, BYTE(flags), 0
        vmovdqa [init_block_addr], init_block0

        mov     [state + _aes_ccm_args_in + lane * 8], init_block_addr

        ;; If not all 16 jobs are in use wait for more jobs
        cmp     qword [state + _aes_ccm_num_lanes_inuse], 16
        jne     %%_return_null

%else ; end SUBMIT

        ;; Check at least one job
        cmp     qword [state + _aes_ccm_num_lanes_inuse], 0
        je      %%_return_null

        SET_NULL_JOB_LENS_TO_MAX ccm_lens, xtmp0, xtmp1, tmp1, tmp2

        ;; Find min length
        vphminposuw min_len_idx, XWORD(ccm_lens)
%endif ; end FLUSH

align_loop
%%_ccm_round:
        vpextrw         len2, min_len_idx, 0    ; min value
        vpextrw         min_idx, min_len_idx, 1 ; min index (for lanes 0...7)

        vextracti128    xtmp1, ccm_lens, 1      ; for lanes 8...15
        vphminposuw     xtmp0, xtmp1
        vpextrw         tmp1, xtmp0, 0          ; min value
        cmp             len2, tmp1
        jbe             %%_use_min              ; check if new value is lower
        ;; Min value is from lanes 8...15
        vpextrw         min_idx, xtmp0, 1       ; min index (0-7)
        add             min_idx, 8              ; index + 8
        mov             len2, tmp1              ; min len

align_label
%%_use_min:
        mov             min_job, [state + _aes_ccm_job_in_lane + min_idx*8]

        ; Check for zero length, to retrieve already encrypted buffers
        cmp             len2, 0
        je              %%_len_is_0

%ifidn %%SUBMIT_FLUSH, FLUSH
        ;; copy good_lane data to empty lanes
        COPY_GOOD_LANE_DATA min_idx
%endif

        vmovdqa         ccm_lens, [state + _aes_ccm_lens]

        ; subtract common minimum length from all lanes lengths
        vmovq           xtmp3, len2
        vpbroadcastw    ytmp3, xtmp3
        vpsubw          ccm_lens, ccm_lens, ytmp3
        vmovdqa         [state + _aes_ccm_lens], ccm_lens

        ; state == AES_ARGS == arg1
        ; min_len == arg2
        ; "state" and "args" are the same address, arg1
        ; len2 is arg2
        call    AES_CBC_MAC
        ; state, min_idx and min_job are intact

align_label
%%_len_is_0:

        movzx   tmp1, WORD [state + _aes_ccm_init_done + min_idx*2]
        cmp     WORD(tmp1), 0
        je      %%_prepare_full_blocks_to_auth
        cmp     WORD(tmp1), 1
        je      %%_prepare_partial_block_to_auth

align_label
%%_encrypt_digest:

        ;; Set counter block 0 (reusing previous initial block 0)
        mov     tmp1, min_idx
        shl     tmp1, 3
        vmovdqa init_block0, [state + _aes_ccm_init_blocks + tmp1 * 8]

        vpand   init_block0, [rel counter_mask]

        ; mov     tmp2, [state + _aes_ccm_args_keys + tmp1]
        lea     tmp2, [state + _aes_ccm_args_key_tab + tmp1*2]
        ENCRYPT_SINGLE_BLOCK tmp2, init_block0
        vpxor   init_block0, [state + _aes_ccm_args_IV + tmp1 * 2]

        ;; Copy Mlen bytes into auth_tag_output (Mlen = 4,6,8,10,12,14,16)
        mov     min_job, [state + _aes_ccm_job_in_lane + tmp1]
        mov     tmp3, [min_job + _auth_tag_output_len_in_bytes]
        mov     tmp2, [min_job + _auth_tag_output]

        simd_store_avx tmp2, init_block0, tmp3, tmp1, tmp4
align_label
%%_update_lanes:
        ; Update unused lanes
        mov     unused_lanes, [state + _aes_ccm_unused_lanes]
        shl     unused_lanes, 4
        or      unused_lanes, min_idx
        mov     [state + _aes_ccm_unused_lanes], unused_lanes
        sub     qword [state + _aes_ccm_num_lanes_inuse], 1

        ; Set return job
        mov     job_rax, min_job

        mov     qword [state + _aes_ccm_job_in_lane + min_idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH

%ifdef SAFE_DATA
        ;; Clear expanded keys
        vpxor   xtmp0, xtmp0
%ifidn %%SUBMIT_FLUSH, FLUSH
        xor     tmp1, tmp1      ; tmp1 = LANE_ID * 8, 16 lanes to process
        xor     tmp2, tmp2      ; tmp2 used to compare against zero
align_loop
%%_safe_data_flush:
        cmp     qword [state + _aes_ccm_job_in_lane + tmp1], tmp2
        jne     %%_safe_data_flush_skip

        ;; clear init blocks, tmp1 = LANE_ID * 8, tmp1 * 8 = LANE_ID * 64
        vmovdqa [state + _aes_ccm_init_blocks + tmp1*8 + 0*32], ytmp0
        vmovdqa [state + _aes_ccm_init_blocks + tmp1*8 + 1*32], ytmp0

        ;; Clear expanded keys per lane, tmp1 = LANE_ID * 8, tmp1 * 2 = LANE_ID * 16
        lea     tmp3, [state + _aes_ccm_args_key_tab + tmp1*2]
%assign KEY 0
%rep NUM_KEYS
        vmovdqa [tmp3 + KEY*16*16], xtmp0
%assign KEY (KEY+1)
%endrep

align_label
%%_safe_data_flush_skip:
        add     tmp1, 8
        cmp     tmp1, 16*8
        jne     %%_safe_data_flush

%else ;; SUBMIT_FLUSH
        shl     min_idx, 4
        lea     tmp1, [state + _aes_ccm_args_key_tab + min_idx]
        ;; Clear expanded keys for processed lane
%assign key_round 0
%rep NUM_KEYS
        vmovdqa [tmp1 + key_round * (16*16)], xtmp0
%assign key_round (key_round + 1)
%endrep
        ;; clear init block, min_idx = lane * 16, min_idx * 4 = lane * 64
        vmovdqa [state + _aes_ccm_init_blocks + min_idx*4 + 0*32], ytmp0
        vmovdqa [state + _aes_ccm_init_blocks + min_idx*4 + 1*32], ytmp0
%endif ;;  SUBMIT_FLUSH

%endif ;; SAFE_DATA

align_label
%%_return:
        jmp     %%_done

align_label
%%_return_null:
        xor     job_rax, job_rax
        jmp     %%_done

align_label
%%_prepare_full_blocks_to_auth:

        cmp     dword [min_job + _cipher_direction], 2 ; DECRYPT
        je      %%_decrypt

align_label
%%_encrypt:
        mov     tmp1, [min_job + _src]
        add     tmp1, [min_job + _hash_start_src_offset_in_bytes]
        jmp     %%_set_init_done_1

align_label
%%_decrypt:
        mov     tmp1, [min_job + _dst]

align_label
%%_set_init_done_1:
        mov     [state + _aes_ccm_args_in + min_idx*8], tmp1
        mov     word [state + _aes_ccm_init_done + min_idx*2], 1

        ; Check if there are full blocks to hash
        mov     tmp1, [min_job + _msg_len_to_hash_in_bytes]
        and     tmp1, -16
        je      %%_prepare_partial_block_to_auth

        ;; Update lengths to authenticate and find min length
%ifidn %%SUBMIT_FLUSH, FLUSH
        ; Reset NULL lane lens to UINT16_MAX for flush
        SET_NULL_JOB_LENS_TO_MAX ccm_lens, xtmp1, xtmp2, tmp3, tmp2
%else
        vmovdqa ccm_lens, [state + _aes_ccm_lens]
%endif
        VPINSRW_256 ccm_lens, xtmp0, xtmp1, tmp2, min_idx, tmp1, scale_x16
        vphminposuw min_len_idx, XWORD(ccm_lens)
        vmovdqa [state + _aes_ccm_lens], ccm_lens

        jmp     %%_ccm_round

align_label
%%_prepare_partial_block_to_auth:
        ; Check if partial block needs to be hashed
        mov     auth_len, [min_job + _msg_len_to_hash_in_bytes]
        and     auth_len, 15
        je      %%_encrypt_digest

        mov     word [state + _aes_ccm_init_done + min_idx * 2], 2

        ;; Update lengths to authenticate and find min length
%ifidn %%SUBMIT_FLUSH, FLUSH
        SET_NULL_JOB_LENS_TO_MAX ccm_lens, xtmp1, xtmp2, tmp1, tmp2
%else
        vmovdqa  ccm_lens, [state + _aes_ccm_lens]
%endif
        VPINSRW_256 ccm_lens, xtmp0, xtmp1, tmp2, min_idx, 16, scale_x16
        vphminposuw min_len_idx, XWORD(ccm_lens)
        vmovdqa  [state + _aes_ccm_lens], ccm_lens

        mov     tmp2, min_idx
        shl     tmp2, 6
        add     tmp2, 16 ; pb[AES_BLOCK_SIZE]
        lea     init_block_addr, [state + _aes_ccm_init_blocks + tmp2]
        mov     tmp2, [state + _aes_ccm_args_in + min_idx * 8]

        simd_load_avx_15_1 xtmp0, tmp2, auth_len

align_label
%%_finish_partial_block_copy:
        vmovdqa [init_block_addr], xtmp0
        mov     [state + _aes_ccm_args_in + min_idx * 8], init_block_addr

        jmp     %%_ccm_round

%%_done:
%ifdef SAFE_DATA
        clear_all_ymms_asm
%else
        vzeroupper
%endif ;; SAFE_DATA
%endmacro

align_function
; IMB_JOB * submit_job_aes128/256_ccm_auth_vaes_avx2(MB_MGR_CCM_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_AES_CCM_AUTH,function,internal)
SUBMIT_JOB_AES_CCM_AUTH:
        endbranch64
        FUNC_SAVE
        GENERIC_SUBMIT_FLUSH_JOB_AES_CCM_AUTH_AVX2 SUBMIT
        FUNC_RESTORE
        ret

; IMB_JOB * flush_job_aes128/256_ccm_auth_vaes_avx2(MB_MGR_CCM_OOO *state)
; arg 1 : state
MKGLOBAL(FLUSH_JOB_AES_CCM_AUTH,function,internal)
align_function
FLUSH_JOB_AES_CCM_AUTH:
        endbranch64
        FUNC_SAVE
        GENERIC_SUBMIT_FLUSH_JOB_AES_CCM_AUTH_AVX2 FLUSH
        FUNC_RESTORE
        ret

mksection stack-noexec
