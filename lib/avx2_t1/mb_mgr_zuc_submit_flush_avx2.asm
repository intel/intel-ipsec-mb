;;
;; Copyright (c) 2020-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/cet.inc"
%include "include/reg_sizes.inc"
%include "include/const.inc"
%include "include/clear_regs.inc"
%include "include/align_avx.inc"

%ifndef SUBMIT_JOB_ZUC128_EEA3
%define SUBMIT_JOB_ZUC128_EEA3 submit_job_zuc_eea3_avx2
%define FLUSH_JOB_ZUC128_EEA3 flush_job_zuc_eea3_avx2
%define SUBMIT_JOB_ZUC_NEA6 submit_job_zuc_nea6_avx2
%define FLUSH_JOB_ZUC_NEA6 flush_job_zuc_nea6_avx2
%define SUBMIT_JOB_ZUC128_EIA3 submit_job_zuc_eia3_avx2
%define FLUSH_JOB_ZUC128_EIA3 flush_job_zuc_eia3_avx2
%define ZUC128_INIT_8        asm_ZucInitialization_8_avx2
%define ZUCNEA6_INIT_8       asm_ZucNEA6Initialization_8_avx2
%define ZUC_KEYGEN32B_8     asm_ZucGenKeystream32B_8_avx2
%define ZUC_KEYGEN8B_8      asm_ZucGenKeystream8B_8_avx2
%define ZUC_CIPHER_8      asm_ZucCipher_8_avx2
%endif

mksection .rodata
default rel

align 16
broadcast_word:
db      0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01
db      0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01

align 32
clear_lane_mask_tab:
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,

clear_lane_mask_tab_start:
dd      0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,

align 16
bitmask_to_dword_tab:
dd      0x00000000, 0x00000000, 0x00000000, 0x00000000
dd      0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000
dd      0x00000000, 0xFFFFFFFF, 0x00000000, 0x00000000
dd      0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000
dd      0x00000000, 0x00000000, 0xFFFFFFFF, 0x00000000
dd      0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0x00000000
dd      0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000
dd      0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF
dd      0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF
dd      0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF
dd      0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF
dd      0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF
dd      0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF
dd      0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF

extern ZUC128_INIT_8
extern ZUCNEA6_INIT_8
extern ZUC_CIPHER_8
extern ZUC_KEYGEN32B_8
extern ZUC_KEYGEN8B_8
extern asm_ZucGenKeystream32B_avx
extern asm_ZucGenKeystream8B_avx
extern asm_Eia3Round32B_avx
extern asm_Eia3Remainder_avx

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%define arg6    r9
%define arg7    qword [rsp]
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    qword [rsp + 32]
%define arg6    qword [rsp + 40]
%define arg7    qword [rsp + 48]
%endif

%define state   arg1
%define job     arg2

%define job_rax          rax

; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    10
_null_len_save: resq    2
_rsp_save:      resq    1
endstruc

mksection .text

%define APPEND(a,b) a %+ b
%define APPEND3(a,b,c) a %+ b %+ c

;; Clear state for multiple lanes in the OOO managers
%macro CLEAR_ZUC_STATE 4
%define %%STATE         %1 ;; [in] ZUC OOO manager pointer
%define %%LANE_MASK     %2 ;; [in/clobbered] bitmask with lanes to clear
%define %%TMP           %3 ;; [clobbered] Temporary GP register
%define %%TMP2          %4 ;; [clobbered] Temporary GP register

        ; Load mask for lanes 0-3
        mov     %%TMP, %%LANE_MASK
        and     %%TMP, 0xf
        lea     %%TMP2, [rel bitmask_to_dword_tab]
        shl     %%TMP, 4 ; Multiply by 16 to move through the table
        add     %%TMP2, %%TMP
        vmovdqa xmm0, [%%TMP2] ; Mask for first 4 lanes

        ; Load mask for lanes 4-7
        and     %%LANE_MASK, 0xf0
        lea     %%TMP2, [rel bitmask_to_dword_tab]
        add     %%TMP2, %%LANE_MASK ; lane_mask already multiplied by 16 to move through the table
        vmovdqa xmm1, [%%TMP2]

        ;; Clear state for lanes
%assign I 0
%rep (16 + 6)
        ; First 4 lanes
        vmovdqa xmm2, [%%STATE + _zuc_state + I*32]
        vpandn  xmm2, xmm0, xmm2
        vmovdqa [%%STATE + _zuc_state + I*32], xmm2

        ; Next 4 lanes
        vmovdqa xmm3, [%%STATE + _zuc_state + I*32 + 16]
        vpandn  xmm3, xmm1, xmm3
        vmovdqa [%%STATE + _zuc_state + I*32 + 16], xmm3
%assign I (I + 1)
%endrep
%endmacro

;; Clear state for a specified lane in the OOO manager
%macro CLEAR_ZUC_LANE_STATE 5
%define %%STATE         %1 ;; [in] ZUC OOO manager pointer
%define %%LANE          %2 ;; [in/clobbered] lane index
%define %%TMP           %3 ;; [clobbered] Temporary GP register
%define %%YTMP1         %4 ;; [clobbered] Temporary YMM register
%define %%YTMP2         %5 ;; [clobbered] Temporary YMM register

        shl     %%LANE, 2
        lea     %%TMP, [rel clear_lane_mask_tab_start]
        sub     %%TMP, %%LANE
        vmovdqu %%YTMP1, [%%TMP]
%assign I 0
%rep (16 + 6)
        vmovdqa %%YTMP2, [%%STATE + _zuc_state + I*32]
        vpand   %%YTMP2, %%YTMP1
        vmovdqa [%%STATE + _zuc_state + I*32], %%YTMP2
%assign I (I + 1)
%endrep

%endmacro

%macro SUBMIT_JOB_ZUC_EEA3 1
%define %%ALGO      %1 ; [constant] ZUC128 or ZUCNEA6

; idx needs to be in rbp
%define len              rbp
%define idx              rbp

%define lane             r8
%define unused_lanes     rbx
%define tmp              r11
%define tmp2             r13
%define tmp3             r14
%define min_len          r15

        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif
        mov     [rsp + _gpr_save + 8*8], state
        mov     [rsp + _gpr_save + 8*9], job
        mov     [rsp + _rsp_save], rax  ; original SP

        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     lane, unused_lanes
        and     lane, 0xF ;; just a nibble
        shr     unused_lanes, 4
        mov     tmp, [job + _iv]
        shl     lane, 4
        ; Read the 16 bytes of IV
        vmovdqu xmm0, [tmp]
        vmovdqa [state + _zuc_args_IV + lane], xmm0
        shr     lane, 4
        mov     [state + _zuc_unused_lanes], unused_lanes

        mov     [state + _zuc_job_in_lane + lane*8], job
        ; New job that needs init (update bit in zuc_init_not_done bitmask)
        SHIFT_GP        1, lane, tmp, tmp2, left
        or      [state + _zuc_init_not_done], WORD(tmp)
        not     tmp
        and     [state + _zuc_unused_lane_bitmask], BYTE(tmp)

        mov     tmp, [job + _src]
        add     tmp, [job + _cipher_start_src_offset_in_bytes]
        mov     [state + _zuc_args_in + lane*8], tmp
        mov     tmp, [job + _enc_keys]
        mov     [state + _zuc_args_keys + lane*8], tmp
        mov     tmp, [job + _dst]
        mov     [state + _zuc_args_out + lane*8], tmp

        ;; insert len into proper lane
        mov     len, [job + _msg_len_to_cipher_in_bytes]

        vmovdqa xmm0, [state + _zuc_lens]
        XVPINSRW xmm0, xmm1, tmp, lane, len, scale_x16
        vmovdqa [state + _zuc_lens], xmm0

        cmp     unused_lanes, 0xf
        jne     %%return_null_submit_eea3

        ; Find minimum length (searching for zero length,
        ; to retrieve already encrypted buffers)
        vphminposuw     xmm1, xmm0
        vpextrw min_len, xmm1, 0   ; min value
        vpextrw idx, xmm1, 1    ; min index (0...7)
        cmp     min_len, 0
        je      %%len_is_0_submit_eea3

        ; Move state into r12, as register for state will be used
        ; to pass parameter to next function
        mov     r12, state

        ;; Save state into stack
        sub     rsp, (16*32 + 2*32) ; LFSR registers + R1-R2

%assign I 0
%rep (16 + 2)
        vmovdqa ymm0, [r12 + _zuc_state + 32*I]
        vmovdqu [rsp + 32*I], ymm0
%assign I (I + 1)
%endrep

        RESERVE_STACK_SPACE 5

        lea     arg1, [r12 + _zuc_args_keys]
        lea     arg2, [r12 + _zuc_args_IV]
        lea     arg3, [r12 + _zuc_state]
%ifidn %%ALGO, ZUC128
        call    ZUC128_INIT_8
%else ;; %%ALGO == ZUCNEA6
        call    ZUCNEA6_INIT_8
%endif

        RESTORE_STACK_SPACE 5

        cmp     word [r12 + _zuc_init_not_done], 0xff ; Init done for all lanes
        je      %%skip_submit_restoring_state

        ; Load mask for lanes 0-3
        movzx   DWORD(tmp), word [r12 + _zuc_init_not_done]
        mov     tmp2, tmp
        and     tmp2, 0xf
        lea     tmp3, [rel bitmask_to_dword_tab]
        shl     tmp2, 4 ; Multiply by 16 to move through the table
        add     tmp3, tmp2
        vmovdqa xmm2, [tmp3] ; Mask for first 4 lanes

        ; Load mask for lanes 4-7
        and     tmp, 0xf0
        lea     tmp3, [rel bitmask_to_dword_tab]
        add     tmp3, tmp ; tmp already multiplied by 16 to move through the table
        vmovdqa xmm5, [tmp3]

        ;; Restore state from stack for lanes that did not need init
%assign I 0
%rep (16 + 2)
        ; First 4 lanes
        vmovdqu xmm0, [rsp + 32*I] ; State before init
        vmovdqa xmm1, [r12 + _zuc_state + 32*I] ; State after init

        vpand   xmm3, xmm2, xmm1 ;; Zero out lanes that need to be restored in current state
        vpandn  xmm4, xmm2, xmm0 ;; Zero out lanes that do not need to be restored in saved state
        vpor    xmm4, xmm3       ;; Combine both states
        vmovdqa [r12 + _zuc_state + 32*I], xmm4 ; Save new state

        ; Next 4 lanes
        vmovdqu xmm0, [rsp + 32*I + 16] ; State before init
        vmovdqa xmm1, [r12 + _zuc_state + 32*I + 16] ; State after init
        vpand   xmm3, xmm5, xmm1 ;; Zero out lanes that need to be restored in current state
        vpandn  xmm4, xmm5, xmm0 ;; Zero out lanes that do not need to be restored in saved state
        vpor    xmm4, xmm3       ;; Combine both states
        vmovdqa [r12 + _zuc_state + 32*I + 16], xmm4 ; Save new state
%assign I (I + 1)
%endrep

align_label
%%skip_submit_restoring_state:
%ifdef SAFE_DATA
        ;; Clear stack containing state info
        vpxor   ymm0, ymm0
%assign I 0
%rep (16 + 2)
        vmovdqu [rsp + 32*I], ymm0
%assign I (I + 1)
%endrep
%endif
        add     rsp, (16*32 + 2*32) ; Restore stack pointer

        mov     word [r12 + _zuc_init_not_done], 0 ; Init done for all lanes

        RESERVE_STACK_SPACE 5

        lea     arg1, [r12 + _zuc_state]
        lea     arg2, [r12 + _zuc_args_in]
        lea     arg3, [r12 + _zuc_args_out]
        lea     arg4, [r12 + _zuc_lens]
        mov     arg5, min_len

        call    ZUC_CIPHER_8

        RESTORE_STACK_SPACE 5

        mov     state, [rsp + _gpr_save + 8*8]
        mov     job,   [rsp + _gpr_save + 8*9]

align_label
%%len_is_0_submit_eea3:
        ; process completed job "idx"
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_CIPHER
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes
        SHIFT_GP        1, idx, tmp, tmp2, left
        or      [state + _zuc_unused_lane_bitmask], BYTE(tmp)

%ifdef SAFE_DATA
        ; Clear ZUC state of the lane that is returned
        CLEAR_ZUC_LANE_STATE state, idx, tmp, ymm0, ymm1
%endif

align_label
%%return_submit_eea3:
%ifdef SAFE_DATA
        clear_scratch_ymms_asm
%else
        vzeroupper
%endif

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP

        ret

align_label
%%return_null_submit_eea3:
        xor     job_rax, job_rax
        jmp     %%return_submit_eea3
%endmacro

%macro FLUSH_JOB_ZUC_EEA3 1
%define %%ALGO      %1 ; [constant] ZUC128 or ZUCNEA6

%define unused_lanes     rbx
%define tmp1             rbx

%define tmp2             rax

; idx needs to be in rbp
%define tmp              rbp
%define idx              rbp

%define tmp3             r8
%define tmp4             r9
%define tmp5             r10
%define min_len          r14 ; Will be maintained after function calls

        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif
        mov     [rsp + _gpr_save + 8*8], state
        mov     [rsp + _rsp_save], rax  ; original SP

        ; check for empty
        mov     unused_lanes, [state + _zuc_unused_lanes]
        bt      unused_lanes, 32+3
        jc      %%return_null_flush_eea3

        ; Set length = 0xFFFF in NULL jobs
        vmovdqa xmm0, [state + _zuc_lens]
%assign I 0
%rep 8
        cmp     qword [state + _zuc_job_in_lane + I*8], 0
        jne     APPEND(%%skip_copy_ffs_,I)
        mov     idx, (I << 4)
        XVPINSRW xmm0, xmm1, tmp3, idx, 0xffff, no_scale
APPEND(%%skip_copy_ffs_,I):
%assign I (I+1)
%endrep

        vmovdqa [state + _zuc_lens], xmm0

        ; Find minimum length (searching for zero length,
        ; to retrieve already encrypted buffers)
        vphminposuw     xmm1, xmm0
        vpextrw min_len, xmm1, 0   ; min value
        vpextrw idx, xmm1, 1    ; min index (0...7)
        cmp     min_len, 0
        je      %%len_is_0_flush_eea3

        ; copy good_lane to empty lanes
        mov     tmp1, [state + _zuc_args_in + idx*8]
        mov     tmp2, [state + _zuc_args_out + idx*8]
        mov     tmp3, [state + _zuc_args_keys + idx*8]

%assign I 0
%rep 8
        cmp     qword [state + _zuc_job_in_lane + I*8], 0
        jne     APPEND(%%skip_eea3_,I)
        mov     [state + _zuc_args_in + I*8], tmp1
        mov     [state + _zuc_args_out + I*8], tmp2
        mov     [state + _zuc_args_keys + I*8], tmp3
APPEND(%%skip_eea3_,I):
%assign I (I+1)
%endrep

        ; Move state into r12, as register for state will be used
        ; to pass parameter to next function
        mov     r12, state

        cmp     word [r12 + _zuc_init_not_done], 0
        je      %%skip_flush_init

        ;; Save state into stack
        sub     rsp, (16*32 + 2*32) ; LFSR registers + R1-R2

%assign I 0
%rep (16 + 2)
        vmovdqa ymm0, [r12 + _zuc_state + 32*I]
        vmovdqu [rsp + 32*I], ymm0
%assign I (I + 1)
%endrep

        RESERVE_STACK_SPACE 5

        lea     arg1, [r12 + _zuc_args_keys]
        lea     arg2, [r12 + _zuc_args_IV]
        lea     arg3, [r12 + _zuc_state]

%ifidn %%ALGO, ZUC128
        call    ZUC128_INIT_8
%else ;; %%ALGO == ZUCNEA6
        call    ZUCNEA6_INIT_8
%endif ;; %%ALGO

        RESTORE_STACK_SPACE 5

        cmp     word [r12 + _zuc_init_not_done], 0xff ; Init done for all lanes
        je      %%skip_flush_restoring_state

        ;; Restore state from stack for lanes that did not need init
%assign I 0
%rep (16 + 2)
        ; First 4 lanes
        vmovdqu xmm0, [rsp + 32*I] ; State before init
        vmovdqa xmm1, [r12 + _zuc_state + 32*I] ; State after init
%assign J 0
%rep 4
        test    word [r12 + _zuc_init_not_done], (1 << J)
        jnz     APPEND3(%%skip_flush_lane_,I,J)
        ;; Extract dword from ymm0
        vpextrd r15, xmm0, J ; value
        mov     r8, (J << 4) ; index

        XVPINSRD xmm1, xmm2, r13, r8, r15, no_scale

APPEND3(%%skip_flush_lane_,I,J):
%assign J (J+1)
%endrep
        vmovdqa [r12 + _zuc_state + 32*I], xmm1 ; Save new state

        ; Next 4 lanes
        vmovdqu xmm0, [rsp + 32*I + 16] ; State before init
        vmovdqa xmm1, [r12 + _zuc_state + 32*I + 16] ; State after init
%assign J 4
%assign K 0
%rep 4
        test    word [r12 + _zuc_init_not_done], (1 << J)
        jnz     APPEND3(%%skip_flush_lane_,I,J)
        ;; Extract dword from ymm0
        vpextrd r15, xmm0, K ; value
        mov     r8, (K << 4) ; index

        XVPINSRD xmm1, xmm2, r13, r8, r15, no_scale

APPEND3(%%skip_flush_lane_,I,J):
%assign J (J+1)
%assign K (K+1)
%endrep
        vmovdqa [r12 + _zuc_state + 32*I + 16], xmm1 ; Save new state
%assign I (I + 1)
%endrep

align_label
%%skip_flush_restoring_state:
%ifdef SAFE_DATA
        ;; Clear stack containing state info
        vpxor   ymm0, ymm0
%assign I 0
%rep (16 + 2)
        vmovdqu [rsp + 32*I], ymm0
%assign I (I + 1)
%endrep
%endif
        add     rsp, (16*32 + 2*32) ; Restore stack pointer

        mov     word [r12 + _zuc_init_not_done], 0 ; Init done for all lanes

align_label
%%skip_flush_init:

        ;; Copy state from good lane to NULL lanes
%assign I 0
%rep (16 + 2)
        ; Read dword from good lane and broadcast to NULL lanes
        mov     r13d, [r12 + _zuc_state + 32*I + idx*4]

        ; First 4 lanes
        vmovdqa xmm1, [r12 + _zuc_state + 32*I] ; State after init
%assign J 0
%rep 4
        cmp     qword [r12 + _zuc_job_in_lane + J*8], 0
        jne     APPEND3(%%skip_eea3_copy_,I,J)
        mov     r8, (J << 4) ; index

        XVPINSRD xmm1, xmm2, r15, r8, r13, no_scale

APPEND3(%%skip_eea3_copy_,I,J):
%assign J (J+1)
%endrep
        vmovdqa [r12 + _zuc_state + 32*I], xmm1 ; Save new state

        ; Next 4 lanes
        vmovdqa xmm1, [r12 + _zuc_state + 32*I + 16] ; State after init
%assign J 4
%assign K 0
%rep 4
        cmp     qword [r12 + _zuc_job_in_lane + J*8], 0
        jne     APPEND3(%%skip_eea3_copy_,I,J)
        mov     r8, (K << 4) ; index

        XVPINSRD xmm1, xmm2, r15, r8, r13, no_scale

APPEND3(%%skip_eea3_copy_,I,J):
%assign J (J+1)
%assign K (K+1)
%endrep
        vmovdqa [r12 + _zuc_state + 32*I + 16], xmm1 ; Save new state
%assign I (I+1)
%endrep

        RESERVE_STACK_SPACE 5

        lea     arg1, [r12 + _zuc_state]
        lea     arg2, [r12 + _zuc_args_in]
        lea     arg3, [r12 + _zuc_args_out]
        lea     arg4, [r12 + _zuc_lens]
        mov     arg5, min_len

        call    ZUC_CIPHER_8

        RESTORE_STACK_SPACE 5

        mov     state, [rsp + _gpr_save + 8*8]

        ; Clear ZUC state of the lane that is returned and NULL lanes
%ifdef SAFE_DATA
        SHIFT_GP        1, idx, tmp1, tmp2, left
        movzx   DWORD(tmp3), byte [state + _zuc_unused_lane_bitmask]
        or      tmp3, tmp1 ;; bitmask with NULL lanes and job to return

        CLEAR_ZUC_STATE state, tmp3, tmp2, tmp4
        jmp     %%skip_flush_clear_state
%endif

align_label
%%len_is_0_flush_eea3:
%ifdef SAFE_DATA
        ; Clear ZUC state of the lane that is returned
        mov     tmp2, idx
        CLEAR_ZUC_LANE_STATE state, tmp2, tmp3, ymm0, ymm1

align_label
%%skip_flush_clear_state:
%endif
        ; process completed job "idx"
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_CIPHER
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes

        SHIFT_GP        1, idx, tmp3, tmp4, left
        or      [state + _zuc_unused_lane_bitmask], BYTE(tmp3)
align_label
%%return_flush_eea3:
%ifdef SAFE_DATA
        clear_scratch_ymms_asm
%else
        vzeroupper
%endif

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP

        ret

align_label
%%return_null_flush_eea3:
        xor     job_rax, job_rax
        jmp     %%return_flush_eea3
%endmacro

; JOB* SUBMIT_JOB_ZUC128_EEA3(MB_MGR_ZUC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_ZUC128_EEA3,function,internal)
align_function
SUBMIT_JOB_ZUC128_EEA3:
        SUBMIT_JOB_ZUC_EEA3 ZUC128

; JOB* SUBMIT_JOB_ZUC_NEA6(MB_MGR_ZUC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_ZUC_NEA6,function,internal)
SUBMIT_JOB_ZUC_NEA6:
        SUBMIT_JOB_ZUC_EEA3 ZUCNEA6

; JOB* FLUSH_JOB_ZUC128_EEA3(MB_MGR_ZUC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(FLUSH_JOB_ZUC128_EEA3,function,internal)
align_function
FLUSH_JOB_ZUC128_EEA3:
        FLUSH_JOB_ZUC_EEA3 ZUC128

; JOB* FLUSH_JOB_ZUC_NEA6(MB_MGR_ZUC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(FLUSH_JOB_ZUC_NEA6,function,internal)
FLUSH_JOB_ZUC_NEA6:
        FLUSH_JOB_ZUC_EEA3 ZUCNEA6


%macro SUBMIT_JOB_ZUC_EIA3 0

; idx needs to be in rbp
%define len              rbp
%define idx              rbp
%define tmp              rbp
%define tmp2             r14
%define tmp3             r15

%define lane             r8
%define unused_lanes     rbx
%define len2             r13

        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif
        mov     [rsp + _gpr_save + 8*8], state
        mov     [rsp + _gpr_save + 8*9], job
        mov     [rsp + _rsp_save], rax  ; original SP

        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     lane, unused_lanes
        and     lane, 0xF           ;; just a nibble
        shr     unused_lanes, 4
        mov     tmp, [job + _zuc_eia3_iv]
        shl     lane, 4
        ; Read first 16 bytes of IV
        vmovdqu xmm0, [tmp]
        vmovdqa [state + _zuc_args_IV + lane], xmm0
        shr     lane, 4
        mov     [state + _zuc_unused_lanes], unused_lanes

        mov     [state + _zuc_job_in_lane + lane*8], job
        mov     tmp, [job + _src]
        add     tmp, [job + _hash_start_src_offset_in_bytes]
        mov     [state + _zuc_args_in + lane*8], tmp
        mov     tmp, [job + _zuc_eia3_key]
        mov     [state + _zuc_args_keys + lane*8], tmp
        mov     tmp, [job + _auth_tag_output]
        mov     [state + _zuc_args_out + lane*8], tmp

        ;; insert len into proper lane
        mov     len, [job + _msg_len_to_hash_in_bytes]

        vmovdqa xmm0, [state + _zuc_lens]
        XVPINSRW xmm0, xmm1, tmp, lane, len, scale_x16
        vmovdqa [state + _zuc_lens], xmm0

        cmp     unused_lanes, 0xf
        jne     %%return_null_submit_eia3

        ; Find minimum length (searching for zero length,
        ; to retrieve already encrypted buffers)
        vphminposuw     xmm1, xmm0
        vpextrw len2, xmm1, 0   ; min value
        vpextrw idx, xmm1, 1    ; min index (0...7)
        cmp     len2, 0
        je      %%len_is_0_submit_eia3

        call    zuc_eia3_8_buffer

        mov     state, [rsp + _gpr_save + 8*8]
        mov     job,   [rsp + _gpr_save + 8*9]

        ;; Clear all lengths (function will authenticate all buffers)
        vpxor   xmm0, xmm0
        vmovdqu [state + _zuc_lens], xmm0

align_label
%%len_is_0_submit_eia3:
        ; process completed job "idx"
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
        ;; TODO: fix double store (above setting the length to 0 and now setting to FFFFF)
        mov     word [state + _zuc_lens + idx*2], 0xFFFF
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes

align_label
%%return_submit_eia3:
%ifdef SAFE_DATA
        clear_scratch_ymms_asm
%else
        vzeroupper
%endif

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP

        jmp     %%exit_submit_eia3

align_label
%%return_null_submit_eia3:
        xor     job_rax, job_rax
        jmp     %%return_submit_eia3

align_label
%%exit_submit_eia3:
%endmacro

%macro FLUSH_JOB_ZUC_EIA3 0

%define unused_lanes     rbx
%define tmp1             rbx

%define tmp2             rax

; idx needs to be in rbp
%define tmp              rbp
%define idx              rbp

%define tmp3             r8
%define tmp4             r9
%define tmp5             r10

        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif
        mov     [rsp + _gpr_save + 8*8], state
        mov     [rsp + _rsp_save], rax  ; original SP

        ; check for empty
        mov     unused_lanes, [state + _zuc_unused_lanes]
        bt      unused_lanes, 32+3
        jc      %%return_null_flush_eia3

        ; Find minimum length (searching for zero length,
        ; to retrieve already authenticated buffers)
        vmovdqa xmm0, [state + _zuc_lens]
        vphminposuw     xmm1, xmm0
        vpextrw len2, xmm1, 0   ; min value
        vpextrw idx, xmm1, 1    ; min index (0...7)
        cmp     len2, 0
        je      %%len_is_0_flush_eia3

        ; copy good_lane to empty lanes
        mov     tmp1, [state + _zuc_args_in + idx*8]
        mov     tmp2, [state + _zuc_args_out + idx*8]
        mov     tmp3, [state + _zuc_args_keys + idx*8]
        mov     WORD(tmp5), [state + _zuc_lens + idx*2]

        ; Set valid length in NULL jobs
        vmovd   xmm0, DWORD(tmp5)
        vpshufb xmm0, xmm0, [rel broadcast_word]
        vmovdqa xmm1, [state + _zuc_lens]

        vpcmpeqw xmm2, xmm2 ;; Get all ff's in XMM register
        vpcmpeqw xmm3, xmm1, xmm2 ;; Mask with FFFF in NULL jobs
        vmovdqa [rsp + _null_len_save], xmm3 ;; Save lengths with FFFF in NULL jobs

        vpand   xmm4, xmm3, xmm0 ;; Length of valid job in all NULL jobs

        vpxor   xmm2, xmm3 ;; Mask with 0000 in NULL jobs
        vpand   xmm1, xmm2 ;; Zero out lengths of NULL jobs

        vpor    xmm1, xmm4
        vmovdqa [state + _zuc_lens], xmm1

%assign I 0
%rep 8
        cmp     qword [state + _zuc_job_in_lane + I*8], 0
        jne     APPEND(%%skip_eia3_,I)
        mov     [state + _zuc_args_in + I*8], tmp1
        mov     [state + _zuc_args_out + I*8], tmp2
        mov     [state + _zuc_args_keys + I*8], tmp3
APPEND(%%skip_eia3_,I):
%assign I (I+1)
%endrep

        call    zuc_eia3_8_buffer

        vmovdqa xmm2, [rsp + _null_len_save]

        mov     state, [rsp + _gpr_save + 8*8]

        ;; Clear all lengths of valid jobs and set to FFFF to NULL jobs
        vmovdqu [state + _zuc_lens], xmm2

align_label
%%len_is_0_flush_eia3:
        ; process completed job "idx"
        mov     job_rax, [state + _zuc_job_in_lane + idx*8]
        mov     unused_lanes, [state + _zuc_unused_lanes]
        mov     qword [state + _zuc_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH
        ;; TODO: fix double store (above setting the length to 0 and now setting to FFFFF)
        mov     word [state + _zuc_lens + idx*2], 0xFFFF
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _zuc_unused_lanes], unused_lanes

align_label
%%return_flush_eia3:
%ifdef SAFE_DATA
        clear_scratch_ymms_asm
%else
        vzeroupper
%endif

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP

        jmp     %%exit_flush_eia3

align_label
%%return_null_flush_eia3:
        xor     job_rax, job_rax
        jmp     %%return_flush_eia3

align_label
%%exit_flush_eia3:
%endmacro

struc EIA3_STACK
%ifdef WIN_ABI
; Shadow space for calls to initialization, keystream and digest helpers.
_eia3_abi:      resb    32
%endif
                alignb  32
_eia3_single:   resb    96       ; 88-byte single-packet state, padded to a 32-byte multiple
_eia3_ks_ptr:   resq    8

; Keep the scheduler's completion index outside the SAFE_DATA wipe range.
_eia3_idx:      resq    1
_eia3_rsp:      resq    1
_eia3_equal:    resd    1        ; 0xFFFF when all eight lengths match
endstruc

; void zuc_eia3_8_buffer(MB_MGR_ZUC_OOO *state)
; arg 1 : manager state
; Uses manager state, compact 64-byte keystream slots and eight packed dword tags.
; Only single-packet tail state, keystream pointers and call bookkeeping live on stack.
; Preserves rbp (scheduler completion index); clobbers rbx and r12-r15.
; The outer submit/flush frame preserves these registers for the external caller.
; The including scheduler selects GFNI/non-GFNI initialization and key generation.
align_function
zuc_eia3_8_buffer:
%define p_mgr            r12
%define lane_idx         r13
%define consumed         r14
%define bytes_left       r15
%define p_in             rbx
%define p_ks             rbp

        mov     rax, rsp
        sub     rsp, EIA3_STACK_size
        and     rsp, -32
        mov     [rsp + _eia3_rsp], rax
        mov     [rsp + _eia3_idx], p_ks
        mov     p_mgr, arg1

        ; Equal lengths need only 8 extra keystream bytes after the last common block.
        vmovdqa xmm0, [p_mgr + _zuc_lens]
        vpshufb xmm1, xmm0, [rel broadcast_word]
        vpcmpeqw xmm1, xmm1, xmm0
        vpmovmskb eax, xmm1
        mov     [rsp + _eia3_equal], eax
        vphminposuw xmm0, xmm0
        vpextrw DWORD(bytes_left), xmm0, 0

        vpxor   ymm0, ymm0
        vmovdqa [p_mgr + _zuc_args_digest], ymm0

%assign i 0
%rep 8
        lea     rax, [p_mgr + _zuc_args_KS + i*64]
        mov     [rsp + _eia3_ks_ptr + i*8], rax
%assign i (i + 1)
%endrep

        lea     arg1, [p_mgr + _zuc_args_keys]
        lea     arg2, [p_mgr + _zuc_args_IV]
        lea     arg3, [p_mgr + _zuc_state]
        call    ZUC128_INIT_8

        lea     arg1, [p_mgr + _zuc_state]
        lea     arg2, [rsp + _eia3_ks_ptr]
        call    ZUC_KEYGEN32B_8

        ; Digest helpers slide the next block down; keygen keeps writing the upper half.
%assign i 0
%rep 8
        add     qword [rsp + _eia3_ks_ptr + i*8], 32
%assign i (i + 1)
%endrep
        xor     DWORD(consumed), DWORD(consumed)

align_loop
.common:
        cmp     bytes_left, 32
        jb      .tails
        sub     bytes_left, 32
        add     consumed, 32

        lea     arg1, [p_mgr + _zuc_state]
        lea     arg2, [rsp + _eia3_ks_ptr]
        test    bytes_left, bytes_left
        jne     .common_key32
        cmp     dword [rsp + _eia3_equal], 0xFFFF
        jne     .common_key32
        call    ZUC_KEYGEN8B_8
        jmp     .common_digest

align_label
.common_key32:
        call    ZUC_KEYGEN32B_8

align_label
.common_digest:
        xor     DWORD(lane_idx), DWORD(lane_idx)

align_loop
.common_lane:
        cmp     qword [p_mgr + _zuc_job_in_lane + lane_idx*8], 0
        je      .common_next

        mov     rax, lane_idx
        shl     rax, 6
        lea     arg1, [p_mgr + _zuc_args_digest + lane_idx*4]
        lea     arg2, [p_mgr + _zuc_args_KS + rax]
        ; consumed already includes this block; manager input pointers stay unchanged.
        mov     arg3, [p_mgr + _zuc_args_in + lane_idx*8]
        add     arg3, consumed
        sub     arg3, 32
        call    asm_Eia3Round32B_avx

align_label
.common_next:
        inc     DWORD(lane_idx)
        cmp     DWORD(lane_idx), 8
        jb      .common_lane
        jmp     .common

align_label
.tails:
        ; Finish occupied lanes independently after the shortest common prefix.
        xor     DWORD(lane_idx), DWORD(lane_idx)

align_loop
.tail_lane:
        cmp     qword [p_mgr + _zuc_job_in_lane + lane_idx*8], 0
        je      .tail_next

        movzx   DWORD(bytes_left), word [p_mgr + _zuc_lens + lane_idx*2]
        sub     bytes_left, consumed
        mov     p_in, [p_mgr + _zuc_args_in + lane_idx*8]
        add     p_in, consumed
        mov     p_ks, lane_idx
        shl     p_ks, 6
        lea     p_ks, [p_mgr + _zuc_args_KS + p_ks]

        ; Up to 24 data bytes plus the two final ZUC words fit in the current block.
        cmp     bytes_left, 24
        jbe     .remainder

        ; Gather the canonical eight-lane LFSR and F registers for this packet.
%assign i 0
%rep 18
        mov     eax, [p_mgr + _zuc_state + i*32 + lane_idx*4]
        mov     [rsp + _eia3_single + i*4], eax
%assign i (i + 1)
%endrep

align_loop
.tail_block:
        cmp     bytes_left, 32
        jb      .tail_partial
        sub     bytes_left, 32
        lea     arg1, [p_ks + 32]
        lea     arg2, [rsp + _eia3_single]
        test    bytes_left, bytes_left
        jnz     .tail_key32
        ; An exact final block needs only the two words used to finalize the tag.
        call    asm_ZucGenKeystream8B_avx
        jmp     .tail_digest

align_label
.tail_key32:
        call    asm_ZucGenKeystream32B_avx

align_label
.tail_digest:
        lea     arg1, [p_mgr + _zuc_args_digest + lane_idx*4]
        mov     arg2, p_ks
        mov     arg3, p_in
        call    asm_Eia3Round32B_avx
        add     p_in, 32
        jmp     .tail_block

align_label
.tail_partial:
        ; A 25-31 byte remainder needs two more keystream words for finalization.
        cmp     bytes_left, 24
        jbe     .remainder
        lea     arg1, [p_ks + 32]
        lea     arg2, [rsp + _eia3_single]
        call    asm_ZucGenKeystream8B_avx

align_label
.remainder:
        lea     arg1, [p_mgr + _zuc_args_digest + lane_idx*4]
        mov     arg2, p_ks
        mov     arg3, p_in
        mov     arg4, bytes_left
        call    asm_Eia3Remainder_avx

        mov     rax, [p_mgr + _zuc_args_out + lane_idx*8]
        mov     edx, [p_mgr + _zuc_args_digest + lane_idx*4]
        mov     [rax], edx

align_label
.tail_next:
        inc     DWORD(lane_idx)
        cmp     DWORD(lane_idx), 8
        jb      .tail_lane

%ifdef SAFE_DATA
        ; All lanes are complete; clear manager-owned working data as well as local scratch.
        vpxor   ymm0, ymm0
        vmovdqa [p_mgr + _zuc_args_digest], ymm0
        xor     eax, eax

align_loop
.clear_state:
        ; Clear two 32-byte state vectors per iteration (11 iterations total).
        vmovdqa [p_mgr + _zuc_state + rax], ymm0
        vmovdqa [p_mgr + _zuc_state + rax + 32], ymm0
        add     rax, 64
        cmp     rax, 22*32
        jb      .clear_state

        xor     eax, eax

align_loop
.clear_ks:
        ; Clear two 32-byte keystream vectors per iteration (8 iterations total).
        vmovdqa [p_mgr + _zuc_args_KS + rax], ymm0
        vmovdqa [p_mgr + _zuc_args_KS + rax + 32], ymm0
        add     rax, 64
        cmp     rax, 8*64
        jb      .clear_ks

        xor     eax, eax

align_loop
.clear_local:
        vmovdqa [rsp + _eia3_single + rax], ymm0
        vmovdqa [rsp + _eia3_single + rax + 32], ymm0
        add     rax, 64
        cmp     rax, (_eia3_idx - _eia3_single) - 32
        jb      .clear_local
        ; The 160-byte scratch range leaves one final 32-byte vector.
        vmovdqa [rsp + _eia3_single + rax], ymm0
        clear_scratch_ymms_asm
        clear_scratch_gps_asm
%endif
        vzeroupper

        mov     p_ks, [rsp + _eia3_idx]
        mov     rsp, [rsp + _eia3_rsp]
        ret

; JOB* SUBMIT_JOB_ZUC128_EIA3(MB_MGR_ZUC_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(SUBMIT_JOB_ZUC128_EIA3,function,internal)
align_function
SUBMIT_JOB_ZUC128_EIA3:
        SUBMIT_JOB_ZUC_EIA3
        ret


; JOB* FLUSH_JOB_ZUC128_EIA3(MB_MGR_ZUC_OOO *state)
; arg 1 : state
MKGLOBAL(FLUSH_JOB_ZUC128_EIA3,function,internal)
align_function
FLUSH_JOB_ZUC128_EIA3:
        FLUSH_JOB_ZUC_EIA3
        ret

mksection stack-noexec
