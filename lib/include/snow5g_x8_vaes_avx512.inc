%ifndef _SNOW5G_X8_VAES_AVX512_ASM_
%define _SNOW5G_X8_VAES_AVX512_ASM_

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
%include "include/transpose_avx512.inc"
%include "include/imb_job.inc"
%include "include/constant_lookup.inc"
%include "include/align_avx512.inc"
%include "include/cet.inc"
%include "include/clear_regs.inc"
%include "include/os.inc"

mksection .rodata
default rel

align 64
const_byte_shuff_mask:
        times 4 dq 0x0405060700010203, 0x0c0d0e0f08090a0b

align 64
const_fixup_mask:
        times 8 dq 0x7272727272727272

align 64
const_transf_map:
        dq 0x08A7BE0D0A8FA6C2, 0x9F11D2135945991D
        dq 0xC1588D92A4D4E6AE, 0x3BBC4F9D84C897D0
        dq 0xEEE34E725327EB2D, 0xDB442F5C4DAA7FDA
        dq 0x4C166AC3C5673A3E, 0x19F26270DDD7CC38
        dq 0x0386C9614B980910, 0x8C5D546E335A6BA8
        dq 0x80F8C682F6F71A41, 0xBA7B2C65B3FEC7C0
        dq 0x5FF5730C222AFCB4, 0x143524B2942E6864
        dq 0x0743EDDE48BFFB78, 0x46577D74BDE432B6
        dq 0x55F38A51B7C4373C, 0x93E1A377AB79CF6C
        dq 0x8B7E9A2B5B816DD5, 0x5247A191D385B504
        dq 0xF0268720BBD6ECA5, 0x50CB25CEF4894AAF
        dq 0xA93D219042D93F00, 0xCDFA5E36F10129E7
        dq 0x76A09EFD051B31E5, 0x1CEA569BB075B130
        dq 0xFF1588957A6906EF, 0x0B280FD8230EACCA
        dq 0x9C3966831E63F918, 0xA27C34D1E81F49E2
        dq 0x71ADDFE91202E0B9, 0xDC176040B86F8E96

align 64
sigma:
dq 0xd0905010c080400
dq 0xf0b07030e0a0602
dq 0xd0905010c080400
dq 0xf0b07030e0a0602

align 64
zero:
dq 0x0000000000000000
dq 0x0000000000000000
dq 0x0000000000000000
dq 0x0000000000000000

align 64
alpha:
times 16 dw 0x4a6d
times 16 dw 0x4a6d

align 64
beta:
times 16 dw 0xcc87
times 16 dw 0xcc87

align 64
byte_len_to_mask_table_nca4:
        dw      0x0000, 0x0001, 0x0003, 0x0007
        dw      0x000f, 0x001f, 0x003f, 0x007f
        dw      0x00ff, 0x01ff, 0x03ff, 0x07ff
        dw      0x0fff, 0x1fff, 0x3fff, 0x7fff
        dw      0xffff

mksection .text
%xdefine TEMP0                   ymm0
%xdefine TEMP1                   ymm1
%xdefine TEMP2                   ymm2
%xdefine TEMP3                   ymm3

%xdefine FSM_R1_L01             ymm12
%xdefine FSM_R2_L01             ymm13
%xdefine FSM_R3_L01             ymm14
%xdefine FSM_R1_L23             ymm15
%xdefine FSM_R2_L23             ymm16
%xdefine FSM_R3_L23             ymm17
%xdefine FSM_R1_L45             ymm18
%xdefine FSM_R2_L45             ymm19
%xdefine FSM_R3_L45             ymm20
%xdefine FSM_R1_L67             ymm21
%xdefine FSM_R2_L67             ymm22
%xdefine FSM_R3_L67             ymm23

%xdefine LFSR_A_LDQ_L01         ymm24
%xdefine LFSR_A_HDQ_L01         ymm25
%xdefine LFSR_B_LDQ_L01         ymm26
%xdefine LFSR_B_HDQ_L01         ymm27
%xdefine LFSR_A_LDQ_L23         ymm28
%xdefine LFSR_A_HDQ_L23         ymm29
%xdefine LFSR_B_LDQ_L23         ymm30
%xdefine LFSR_B_HDQ_L23         ymm31

%xdefine LFSR_A_LDQ_L45         ymm11
%xdefine LFSR_A_HDQ_L45         ymm10
%xdefine LFSR_B_LDQ_L45         ymm9
%xdefine LFSR_B_HDQ_L45         ymm8

%xdefine LFSR_A_LDQ_L67         ymm7
%xdefine LFSR_A_HDQ_L67         ymm6
%xdefine LFSR_B_LDQ_L67         ymm5
%xdefine LFSR_B_HDQ_L67         ymm4

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%endif

struc STACK
_LFSR_A_HDQ_01:     resb    (16 * 8)
_LFSR_A_HDQ_23:     resb    (16 * 8)
_LFSR_A_HDQ_45:     resb    (16 * 8)
_LFSR_A_HDQ_67:     resb    (16 * 8)
_LFSR_B_HDQ_01:     resb    (16 * 8)
_LFSR_B_HDQ_23:     resb    (16 * 8)
_LFSR_B_HDQ_45:     resb    (16 * 8)
_LFSR_B_HDQ_67:     resb    (16 * 8)
_keystream_01:      resb    (16 * 8)
_keystream_23:      resb    (16 * 8)
_keystream_45:      resb    (16 * 8)
_keystream_67:      resb    (16 * 8)
_gpr_save:      resq    8
%ifndef LINUX
_xmm_save:      resb    (16 * 10)       ; XMM6-15 save area (Windows only)
%endif
_rsp_save:      resq    1
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Saves register contents and creates stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_FUNC_START 0
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, ~63

        mov     [rsp + _gpr_save + 8 * 0], rbx
        mov     [rsp + _gpr_save + 8 * 1], rbp
        mov     [rsp + _gpr_save + 8 * 2], r12
        mov     [rsp + _gpr_save + 8 * 3], r13
        mov     [rsp + _gpr_save + 8 * 4], r14
        mov     [rsp + _gpr_save + 8 * 5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8 * 6], rsi
        mov     [rsp + _gpr_save + 8 * 7], rdi
        ;; Save XMM6-15 (Windows callee-saved)
        vmovdqa [rsp + _xmm_save + 16 * 0], xmm6
        vmovdqa [rsp + _xmm_save + 16 * 1], xmm7
        vmovdqa [rsp + _xmm_save + 16 * 2], xmm8
        vmovdqa [rsp + _xmm_save + 16 * 3], xmm9
        vmovdqa [rsp + _xmm_save + 16 * 4], xmm10
        vmovdqa [rsp + _xmm_save + 16 * 5], xmm11
        vmovdqa [rsp + _xmm_save + 16 * 6], xmm12
        vmovdqa [rsp + _xmm_save + 16 * 7], xmm13
        vmovdqa [rsp + _xmm_save + 16 * 8], xmm14
        vmovdqa [rsp + _xmm_save + 16 * 9], xmm15
%endif
        mov     [rsp + _rsp_save], rax          ;; original SP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Restores register contents and removes the stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_FUNC_END 0
%ifdef SAFE_DATA
        clear_scratch_ymms_asm
%else
        vzeroupper
%endif
        mov     rbx, [rsp + _gpr_save + 8 * 0]
        mov     rbp, [rsp + _gpr_save + 8 * 1]
        mov     r12, [rsp + _gpr_save + 8 * 2]
        mov     r13, [rsp + _gpr_save + 8 * 3]
        mov     r14, [rsp + _gpr_save + 8 * 4]
        mov     r15, [rsp + _gpr_save + 8 * 5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8 * 6]
        mov     rdi, [rsp + _gpr_save + 8 * 7]
        ;; Restore XMM6-15 (Windows callee-saved)
        vmovdqa xmm6,  [rsp + _xmm_save + 16 * 0]
        vmovdqa xmm7,  [rsp + _xmm_save + 16 * 1]
        vmovdqa xmm8,  [rsp + _xmm_save + 16 * 2]
        vmovdqa xmm9,  [rsp + _xmm_save + 16 * 3]
        vmovdqa xmm10, [rsp + _xmm_save + 16 * 4]
        vmovdqa xmm11, [rsp + _xmm_save + 16 * 5]
        vmovdqa xmm12, [rsp + _xmm_save + 16 * 6]
        vmovdqa xmm13, [rsp + _xmm_save + 16 * 7]
        vmovdqa xmm14, [rsp + _xmm_save + 16 * 8]
        vmovdqa xmm15, [rsp + _xmm_save + 16 * 9]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Clock FSM state machine for 2 lanes
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_FSM_CLOCK_2 6
%define %%FSM_R1               %1  ;; [in/out] ymm with FSM 1 values
%define %%FSM_R2               %2  ;; [in/out] ymm with FSM 2 values
%define %%FSM_R3               %3  ;; [in/out] ymm with FSM 3 values
%define %%LFSR_A_HDQ           %4  ;; [in] ymm with LFSR A high DQW
%define %%TEMP_1               %5  ;; [clobbered] temporary ymm register
%define %%TEMP_2               %6  ;; [clobbered] temporary ymm register

        vpxorq          %%TEMP_1, %%LFSR_A_HDQ, %%FSM_R3        ; TEMP_1 = R3 XOR LFSR_A [0:7]
        vpaddw          %%TEMP_1, %%TEMP_1, %%FSM_R2            ; TEMP_1 += R2
        vaesenc         %%FSM_R3, %%FSM_R2, [rel zero]          ; R3 = AESR(R2) (encryption round key C1 = 0)
        vaesenc         %%FSM_R2, %%FSM_R1, [rel zero]          ; R2 = AESR(R1) (encryption round key C2 = 0)
        vpshufb         %%FSM_R1, %%TEMP_1, [rel sigma]         ; FSM_R1 = sigma(TEMP_1)

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; LFSR & FSM initialization for a new job (single key-iv pair)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW_5G_LFSR_FSM_INIT_SUBMIT 7
%define %%STATE         %1 ;; [in] pointer to state structure
%define %%LANE          %2 ;; [in] lane number 0-7
%define %%KEY           %3 ;; [in] address of key
%define %%IV            %4 ;; [in] address of iv
%define %%TMP1          %5 ;; [clobbered] temporary ymm register
%define %%TMP2          %6 ;; [clobbered] temporary ymm register
%define %%TMP_GP        %7 ;; [clobbered] temporary general purpose register
        vmovdqu      %%TMP1,  [%%KEY]
        ; store copy of the key
        mov [%%STATE + _snow5g_args_keys + %%LANE*8], %%KEY
        vmovdqu      XWORD(%%TMP2),  [%%IV]

        ; Calculate lane offset for 16-byte structures
        mov %%TMP_GP, %%LANE
        shl %%TMP_GP, 4  ; %%TMP_GP = %%LANE * 16

        vmovdqu [%%STATE + _snow5g_args_LFSRA_LO + %%TMP_GP], XWORD(%%TMP2)

        vmovdqu [%%STATE + _snow5g_args_LFSRA_HI + %%TMP_GP], XWORD(%%TMP1)
        vextracti128 XWORD(%%TMP2), %%TMP1, 1
        vmovdqu [%%STATE + _snow5g_args_LFSRB_HI + %%TMP_GP], XWORD(%%TMP2)

        vpxorq XWORD(%%TMP2), XWORD(%%TMP2), XWORD(%%TMP2)
        vmovdqu [%%STATE + _snow5g_args_FSM_1 + %%TMP_GP], XWORD(%%TMP2)
        vmovdqu [%%STATE + _snow5g_args_FSM_2 + %%TMP_GP], XWORD(%%TMP2)
        vmovdqu [%%STATE + _snow5g_args_FSM_3 + %%TMP_GP], XWORD(%%TMP2)
        vmovdqu [%%STATE + _snow5g_args_LFSRB_LO + %%TMP_GP], XWORD(%%TMP2)

%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Update SNOW5G LFSR
;; for i in [0,7]:
;;    tmpa_i = alpha(a_i)  + b_i + a_(i + 7)
;;    tmpb_i = beta(b_i)   + a_i + b_(i + 8)
;;
;; alpha(x) / beta(x):
;;      if  (x & 0x0001): (x << 1) 1 XOR 0x1a6d(alpha) / 0xcc87(beta)
;;      else            : (x << 1) 1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_LFSR_UPDATE 10
%define %%LFSR_A_LDQ        %1 ;; [in/out] ymm with LFSR A low DQW
%define %%LFSR_A_HDQ        %2 ;; [in/out] ymm with LFSR A high DQW
%define %%LFSR_B_LDQ        %3 ;; [in/out] ymm with LFSR B low DQW
%define %%LFSR_B_HDQ        %4 ;; [in/out] ymm with LFSR B high DQW
%define %%LFSR_A_SAVE       %5 ;; [in] stack offset for saving LFSR_A_HDQ
%define %%LFSR_B_SAVE       %6 ;; [in] stack offset for saving LFSR_B_HDQ
%define %%KEYSTREAM_MEM     %7 ;; [in] memory reference to keystream (for INIT phase XOR)
%define %%KREG              %8 ;; [in] k-register mask for INIT phase (0 if not in INIT)
%define %%TEMP1             %9 ;; [clobbered] temporary ymm register
%define %%TEMP2             %10 ;; [clobbered] temporary ymm register

        ;; Save current LFSR_A_HDQ and LFSR_B_HDQ to stack
        vmovdqa32       [rsp + %%LFSR_A_SAVE], %%LFSR_A_HDQ
        vmovdqa32       [rsp + %%LFSR_B_SAVE], %%LFSR_B_HDQ

        vpalignr %%TEMP1, %%LFSR_A_HDQ, %%LFSR_A_LDQ, 14 ; lfsrA [14:7]
        ;; calculate alpha(lfsrA [7:0])
        vpsraw %%TEMP2, %%LFSR_A_LDQ, 15 ; 16-bit mask with sign bits preserved
        vpand  %%TEMP2, %%TEMP2, [rel alpha]

        vpsllw %%LFSR_A_HDQ, %%LFSR_A_LDQ, 1 ; (a_i << 1)
        vpxorq  %%LFSR_A_HDQ, %%LFSR_A_HDQ, %%TEMP2 ; alpha(lfsrA [7:0])

        ;; LFSR_A_HDQ = lfsrA [14:7] XOR alpha(lfsrA[7:0]) XOR LFSR_B_LDQ
        vpternlogq  %%LFSR_A_HDQ, %%TEMP1, %%LFSR_B_LDQ, 0x96 ; triple XOR

        ;; LFSR_B_HDQ = beta (lfsrB [7:0]) XOR lfsrA [7:0]  XOR lfsrB [15:8]
        vpxorq  %%LFSR_B_HDQ, %%LFSR_B_HDQ, %%LFSR_A_LDQ
        ;; calculate beta (lfsrB [7:0])
        vpsllw %%TEMP1, %%LFSR_B_LDQ, 1                       ; (b_i << 1)
        vpsraw %%TEMP2, %%LFSR_B_LDQ, 15                     ; 16-bit mask with sign bits preserved
        vpand  %%TEMP2, %%TEMP2, [rel beta]
        vpternlogq  %%LFSR_B_HDQ, %%TEMP1, %%TEMP2, 0x96     ; LFSR_B_HDQ XOR TEMP1 XOR TEMP2 (triple XOR)

        ;; Restore old values into LDQ registers (shifting the LFSR state)
        vmovdqa32         %%LFSR_A_LDQ, [rsp + %%LFSR_A_SAVE]
        vmovdqa32         %%LFSR_B_LDQ, [rsp + %%LFSR_B_SAVE]

        ;; Update LFSR_A_HDQ (XOR with keystream from stack) - only during INIT1/INIT2 phases
        ;; Use pre-computed K-register mask
        vpxorq          %%LFSR_A_HDQ{%%KREG}, %%LFSR_A_HDQ, %%KEYSTREAM_MEM

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Store/load LFSR and FSM state to/from memory
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro LFSR_FSM_STATE 2
%define %%PTR   %1 ;; [in] pointer to state structure
%define %%TYPE  %2 ;; [in] "STORE" or "LOAD" selector

%ifidn %%TYPE, STORE

%assign i 0
%rep 4
%assign lane_pair_low (i*2)
%assign lane_pair_high (i*2+1)
        vmovdqu64      [%%PTR + _snow5g_args_LFSRA_LO + i*32], LFSR_A_LDQ_L%[lane_pair_low]%[lane_pair_high]
        vmovdqu64      [%%PTR + _snow5g_args_LFSRA_HI + i*32], LFSR_A_HDQ_L%[lane_pair_low]%[lane_pair_high]
        vmovdqu64      [%%PTR + _snow5g_args_LFSRB_LO + i*32], LFSR_B_LDQ_L%[lane_pair_low]%[lane_pair_high]
        vmovdqu64      [%%PTR + _snow5g_args_LFSRB_HI + i*32], LFSR_B_HDQ_L%[lane_pair_low]%[lane_pair_high]
        vmovdqu64      [%%PTR + _snow5g_args_FSM_1 + i*32], FSM_R1_L%[lane_pair_low]%[lane_pair_high]
        vmovdqu64      [%%PTR + _snow5g_args_FSM_2 + i*32], FSM_R2_L%[lane_pair_low]%[lane_pair_high]
        vmovdqu64      [%%PTR + _snow5g_args_FSM_3 + i*32], FSM_R3_L%[lane_pair_low]%[lane_pair_high]
%assign i (i + 1)
%endrep

%else   ;; LOAD
%assign i 0
%rep 4
%assign lane_pair_low (i*2)
%assign lane_pair_high (i*2+1)
        vmovdqu64      LFSR_A_LDQ_L%[lane_pair_low]%[lane_pair_high], [%%PTR + _snow5g_args_LFSRA_LO + i*32]
        vmovdqu64      LFSR_A_HDQ_L%[lane_pair_low]%[lane_pair_high], [%%PTR + _snow5g_args_LFSRA_HI + i*32]
        vmovdqu64      LFSR_B_LDQ_L%[lane_pair_low]%[lane_pair_high], [%%PTR + _snow5g_args_LFSRB_LO + i*32]
        vmovdqu64      LFSR_B_HDQ_L%[lane_pair_low]%[lane_pair_high], [%%PTR + _snow5g_args_LFSRB_HI + i*32]
        vmovdqu64      FSM_R1_L%[lane_pair_low]%[lane_pair_high], [%%PTR + _snow5g_args_FSM_1 + i*32]
        vmovdqu64      FSM_R2_L%[lane_pair_low]%[lane_pair_high], [%%PTR + _snow5g_args_FSM_2 + i*32]
        vmovdqu64      FSM_R3_L%[lane_pair_low]%[lane_pair_high], [%%PTR + _snow5g_args_FSM_3 + i*32]
%assign i (i + 1)
%endrep

%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; XOR keystream with source input and write to destination
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro WRITE_KEYSTREAM_XOR_LANE 12
%define %%KEYSTREAM_MEM       %1  ;; [in] memory reference to keystream (128-bit)
%define %%LANE_PAIR           %2  ;; [in] lane pair index (0,1,2,3)
%define %%LANE_INDEX          %3  ;; [in] lane index within pair (0 or 1)
%define %%TEMP_XMM1           %4  ;; [clobbered] temporary xmm register
%define %%TEMP_XMM2           %5  ;; [clobbered] temporary xmm register
%define %%SRC_PTRS            %6  ;; [in] address of array of pointers to src buffers
%define %%DST_PTRS            %7  ;; [in] address of array of pointers to dst buffers
%define %%STATE_PTR           %8  ;; [in] pointer to state structure
%define %%OFFSET              %9  ;; [in] current offset to src/dst
%define %%TGP0                %10 ;; [clobbered] temporary 64bit register
%define %%TGP1                %11 ;; [clobbered] temporary 64bit register
%define %%KREG                %12 ;; [clobbered] k-register for masking

        ;; Load the keystream from memory
        vmovdqa32       XWORD(%%TEMP_XMM1), %%KEYSTREAM_MEM

        mov             %%TGP0, [%%SRC_PTRS + ((%%LANE_PAIR * 2 + %%LANE_INDEX) * 8)]
        mov             %%TGP1, [%%DST_PTRS + ((%%LANE_PAIR * 2 + %%LANE_INDEX) * 8)]
        kmovw           %%KREG, [%%STATE_PTR + _snow5g_args_LD_ST_MASK + (%%LANE_PAIR * 4 + %%LANE_INDEX * 2)]
        vmovdqu8        XWORD(%%TEMP_XMM2){%%KREG}{z}, [%%TGP0 + %%OFFSET]
        vpxorq          XWORD(%%TEMP_XMM1), XWORD(%%TEMP_XMM1), XWORD(%%TEMP_XMM2)
        vmovdqu8        [%%TGP1 + %%OFFSET]{%%KREG}, XWORD(%%TEMP_XMM1)

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generate keystream, encrypt/decrypt, clock FSM and update LFSR for one lane pair
;; When SKIP_XOR is 1, only generates keystream (for HQP generation)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_ENC_DEC_LANE_PAIR 22
%define %%LANE_PAIR            %1  ;; [in] lane pair index (0,1,2,3)
%define %%FSM_R1               %2  ;; [in/out] FSM R1 register
%define %%FSM_R2               %3  ;; [in/out] FSM R2 register
%define %%FSM_R3               %4  ;; [in/out] FSM R3 register
%define %%LFSR_A_LDQ           %5  ;; [in/out] LFSR A low DQW
%define %%LFSR_A_HDQ           %6  ;; [in/out] LFSR A high DQW
%define %%LFSR_B_LDQ           %7  ;; [in/out] LFSR B low DQW
%define %%LFSR_B_HDQ           %8  ;; [in/out] LFSR B high DQW
%define %%LFSR_A_SAVE          %9  ;; [in] stack offset for LFSR_A_HDQ save
%define %%LFSR_B_SAVE          %10 ;; [in] stack offset for LFSR_B_HDQ save
%define %%KEYSTREAM_SAVE       %11 ;; [in] stack offset for keystream save
%define %%TEMP1                %12 ;; [clobbered] temporary ymm register
%define %%TEMP2                %13 ;; [clobbered] temporary ymm register
%define %%SRC_PTRS             %14 ;; [in] address of array of pointers to src buffers (ignored if SKIP_XOR=1)
%define %%DST_PTRS             %15 ;; [in] address of array of pointers to dst buffers (ignored if SKIP_XOR=1)
%define %%STATE_PTR            %16 ;; [in] pointer to state structure (ignored if SKIP_XOR=1)
%define %%OFFSET               %17 ;; [in] current offset to src/dst (ignored if SKIP_XOR=1)
%define %%TGP0                 %18 ;; [clobbered] temporary 64bit register (ignored if SKIP_XOR=1)
%define %%TGP1                 %19 ;; [clobbered] temporary 64bit register (ignored if SKIP_XOR=1)
%define %%KREG_INIT            %20 ;; [in] k-register mask for INIT phase
%define %%KREG_LDST            %21 ;; [clobbered] k-register for load/store masking (ignored if SKIP_XOR=1)
%define %%SKIP_XOR             %22 ;; [in] 1 to skip XOR/write (keystream only), 0 for normal enc/dec

        ;; Generate keystream
        vpaddw          %%TEMP1, %%LFSR_B_HDQ, %%FSM_R1
        vpxorq          %%TEMP1, %%FSM_R2, %%TEMP1
        vmovdqa32       [rsp + %%KEYSTREAM_SAVE], %%TEMP1

%if (%%SKIP_XOR == 0)
        ;; XOR keystream with input data and write to output
        WRITE_KEYSTREAM_XOR_LANE [rsp + %%KEYSTREAM_SAVE], %%LANE_PAIR, 0, %%TEMP1, %%TEMP2, %%SRC_PTRS, %%DST_PTRS, %%STATE_PTR, \
                                %%OFFSET, %%TGP0, %%TGP1, %%KREG_LDST
        WRITE_KEYSTREAM_XOR_LANE [rsp + %%KEYSTREAM_SAVE + 16], %%LANE_PAIR, 1, %%TEMP1, %%TEMP2, %%SRC_PTRS, %%DST_PTRS, %%STATE_PTR, \
                                %%OFFSET, %%TGP0, %%TGP1, %%KREG_LDST
%endif

        SNOW5G_FSM_CLOCK_2 %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_HDQ, %%TEMP1, %%TEMP2
        SNOW5G_LFSR_UPDATE %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, %%LFSR_A_SAVE, %%LFSR_B_SAVE, [rsp + %%KEYSTREAM_SAVE], %%KREG_INIT, %%TEMP1, %%TEMP2

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SNOW5G cipher - generates required number of 16-byte keystream blocks (8 buffers)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_KEYSTREAM 14
%xdefine %%STATE_PTR            %1  ;; [in] FSM_LFSR state structure pointer
%xdefine %%COUNT                %2  ;; [in/clobbered] number of 16-byte blocks to be processed
%xdefine %%SRC_PTRS             %3  ;; [in] address of array of pointers to 8 src buff
%xdefine %%DST_PTRS             %4  ;; [in] address of array of pointers to 8 dst buff
%xdefine %%OFFSET               %5  ;; [out] 64bit register with current offset to src/dst
%xdefine %%TGP0                 %6  ;; [clobbered] temporary 64bit register
%xdefine %%TGP1                 %7  ;; [clobbered] temporary 64bit register
%xdefine %%TGP3                 %8  ;; [clobbered] temporary 64bit register
%xdefine %%KREG1                %9  ;; [in] k-register with LP_INIT_MASK for lane pair 0-1
%xdefine %%KREG2                %10 ;; [in] k-register with LP_INIT_MASK for lane pair 2-3
%xdefine %%KREG3                %11 ;; [in] k-register with LP_INIT_MASK for lane pair 4-5
%xdefine %%KREG4                %12 ;; [in] k-register with LP_INIT_MASK for lane pair 6-7
%xdefine %%KREG5                %13 ;; [clobbered] k-register for lane pair 6-7
%xdefine %%KREG6                %14 ;; [clobbered] k-register for lane pair 6-7

        test            DWORD(%%COUNT), DWORD(%%COUNT)
        jz              %%end_key_stream

        xor             %%OFFSET,  %%OFFSET
        LFSR_FSM_STATE  %%STATE_PTR, LOAD

align_loop
%%next_keyword:

        SNOW5G_ENC_DEC_LANE_PAIR 0, FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                                _LFSR_A_HDQ_01, _LFSR_B_HDQ_01, _keystream_01, TEMP1, TEMP2, %%SRC_PTRS, %%DST_PTRS, %%STATE_PTR, \
                                %%OFFSET, %%TGP0, %%TGP1, %%KREG1, %%KREG5, 0

        SNOW5G_ENC_DEC_LANE_PAIR 1, FSM_R1_L23, FSM_R2_L23, FSM_R3_L23, LFSR_A_LDQ_L23, LFSR_A_HDQ_L23, LFSR_B_LDQ_L23, LFSR_B_HDQ_L23, \
                                _LFSR_A_HDQ_23, _LFSR_B_HDQ_23, _keystream_23, TEMP1, TEMP2, %%SRC_PTRS, %%DST_PTRS, %%STATE_PTR, \
                                %%OFFSET, %%TGP0, %%TGP1, %%KREG2, %%KREG5, 0

        SNOW5G_ENC_DEC_LANE_PAIR 2, FSM_R1_L45, FSM_R2_L45, FSM_R3_L45, LFSR_A_LDQ_L45, LFSR_A_HDQ_L45, LFSR_B_LDQ_L45, LFSR_B_HDQ_L45, \
                                _LFSR_A_HDQ_45, _LFSR_B_HDQ_45, _keystream_45, TEMP1, TEMP2, %%SRC_PTRS, %%DST_PTRS, %%STATE_PTR, \
                                %%OFFSET, %%TGP0, %%TGP1, %%KREG3, %%KREG5, 0

        SNOW5G_ENC_DEC_LANE_PAIR 3, FSM_R1_L67, FSM_R2_L67, FSM_R3_L67, LFSR_A_LDQ_L67, LFSR_A_HDQ_L67, LFSR_B_LDQ_L67, LFSR_B_HDQ_L67, \
                                _LFSR_A_HDQ_67, _LFSR_B_HDQ_67, _keystream_67, TEMP1, TEMP2, %%SRC_PTRS, %%DST_PTRS, %%STATE_PTR, \
                                %%OFFSET, %%TGP0, %%TGP1, %%KREG4, %%KREG5, 0

        add             %%OFFSET, 16
        dec             %%COUNT
        jnz             %%next_keyword


        ;; save LFSR & FSM registers
        LFSR_FSM_STATE  %%STATE_PTR, STORE

%%end_key_stream:
        ;; bytes unaligned to words are handled by the manager through LD_ST_MASK

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Store keystream for all 4 lane pairs to HQP output
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro HQP_STORE_ALL_KS 3
%define %%HQP_PTR              %1   ;; [in] base pointer to HQP output
%define %%HQP_OFFSET           %2   ;; [in] offset within each lane's HQP (0, 16, or 32)
%define %%TEMP                 %3   ;; [clobbered] temporary ymm register

%assign %%i 0
%rep 4
%assign %%lp_lo (%%i * 2)
%assign %%lp_hi (%%i * 2 + 1)
%assign %%lane0_off (%%lp_lo * 48 + %%HQP_OFFSET)
        vmovdqa32       %%TEMP, [rsp + _keystream_ %+ %%lp_lo %+ %%lp_hi]
        vmovdqu32       [%%HQP_PTR + %%lane0_off], XWORD(%%TEMP)
        vextracti32x4   [%%HQP_PTR + %%lane0_off + 48], %%TEMP, 1
%assign %%i (%%i + 1)
%endrep
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Load key data via pointer array into YMM for a lane pair
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro LOAD_KEY_PAIR 5
%define %%KEY_PTRS      %1  ;; [in] pointer to array of key pointers
%define %%LANE_LO       %2  ;; [in] low lane index
%define %%LANE_HI       %3  ;; [in] high lane index
%define %%OFFSET        %4  ;; [in] offset within key (0 or 16)
%define %%DEST          %5  ;; [out] destination YMM register
        mov     r10, [%%KEY_PTRS + %%LANE_LO * 8]
        mov     r11, [%%KEY_PTRS + %%LANE_HI * 8]
        vmovdqu32 XWORD(%%DEST), [r10 + %%OFFSET]
        vinserti32x4 %%DEST, %%DEST, [r11 + %%OFFSET], 1
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; XOR key data into a register for a lane pair
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro XOR_KEY_INTO_REG 5
%define %%KEY_PTRS      %1  ;; [in] pointer to array of key pointers
%define %%LANE_LO       %2  ;; [in] low lane index
%define %%LANE_HI       %3  ;; [in] high lane index
%define %%OFFSET        %4  ;; [in] offset within key (0 or 16)
%define %%REG           %5  ;; [in/out] register to XOR into
        mov     r10, [%%KEY_PTRS + %%LANE_LO * 8]
        mov     r11, [%%KEY_PTRS + %%LANE_HI * 8]
        vmovdqu32 XWORD(TEMP0), [r10 + %%OFFSET]
        vinserti32x4 TEMP0, TEMP0, [r11 + %%OFFSET], 1
        vpxorq  %%REG, %%REG, TEMP0
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Process all 4 lane pairs (one init/keystream round)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PROCESS_ALL_LANE_PAIRS 1
%define %%KREG_INIT     %1  ;; [in] k-register for LFSR feedback (k1=init, k2=keygen)

        SNOW5G_ENC_DEC_LANE_PAIR 0, FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                                _LFSR_A_HDQ_01, _LFSR_B_HDQ_01, _keystream_01, \
                                TEMP0, TEMP1, 0, 0, 0, 0, r10, r11, %%KREG_INIT, k3, 1
        SNOW5G_ENC_DEC_LANE_PAIR 1, FSM_R1_L23, FSM_R2_L23, FSM_R3_L23, \
                                LFSR_A_LDQ_L23, LFSR_A_HDQ_L23, LFSR_B_LDQ_L23, LFSR_B_HDQ_L23, \
                                _LFSR_A_HDQ_23, _LFSR_B_HDQ_23, _keystream_23, \
                                TEMP0, TEMP1, 0, 0, 0, 0, r10, r11, %%KREG_INIT, k3, 1
        SNOW5G_ENC_DEC_LANE_PAIR 2, FSM_R1_L45, FSM_R2_L45, FSM_R3_L45, \
                                LFSR_A_LDQ_L45, LFSR_A_HDQ_L45, LFSR_B_LDQ_L45, LFSR_B_HDQ_L45, \
                                _LFSR_A_HDQ_45, _LFSR_B_HDQ_45, _keystream_45, \
                                TEMP0, TEMP1, 0, 0, 0, 0, r10, r11, %%KREG_INIT, k3, 1
        SNOW5G_ENC_DEC_LANE_PAIR 3, FSM_R1_L67, FSM_R2_L67, FSM_R3_L67, \
                                LFSR_A_LDQ_L67, LFSR_A_HDQ_L67, LFSR_B_LDQ_L67, LFSR_B_HDQ_L67, \
                                _LFSR_A_HDQ_67, _LFSR_B_HDQ_67, _keystream_67, \
                                TEMP0, TEMP1, 0, 0, 0, 0, r10, r11, %%KREG_INIT, k3, 1
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Initialize LFSR/FSM state from keys and IVs for all 8 lanes
;; LFSRA_LO = IV, LFSRA_HI = key[0:15], LFSRB_LO = 0, LFSRB_HI = key[16:31]
;; FSM R1/R2/R3 = 0
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_INIT_STATE 2
%define %%KEY_PTRS      %1  ;; [in] pointer to array of key pointers
%define %%IV_PTR        %2  ;; [in] pointer to contiguous IVs (16 bytes per lane)

        ;; Clear FSM and LFSRB_LO registers using broadcast zero
        vpxorq  TEMP0, TEMP0, TEMP0
%assign %%i 0
%rep 4
%assign %%lp_lo (%%i * 2)
%assign %%lp_hi (%%i * 2 + 1)
        vmovdqa32  FSM_R1_L %+ %%lp_lo %+ %%lp_hi, TEMP0
        vmovdqa32  FSM_R2_L %+ %%lp_lo %+ %%lp_hi, TEMP0
        vmovdqa32  FSM_R3_L %+ %%lp_lo %+ %%lp_hi, TEMP0
        vmovdqa32  LFSR_B_LDQ_L %+ %%lp_lo %+ %%lp_hi, TEMP0
%assign %%i (%%i + 1)
%endrep

        ;; Load IVs into LFSRA_LO (IVs are contiguous, use single 32-byte loads)
%assign %%i 0
%rep 4
%assign %%lp_lo (%%i * 2)
%assign %%lp_hi (%%i * 2 + 1)
        vmovdqu64  LFSR_A_LDQ_L %+ %%lp_lo %+ %%lp_hi, [%%IV_PTR + %%lp_lo * 16]
%assign %%i (%%i + 1)
%endrep

        ;; Load keys: key[0:15] -> LFSRA_HI, key[16:31] -> LFSRB_HI
%assign %%i 0
%rep 4
%assign %%lp_lo (%%i * 2)
%assign %%lp_hi (%%i * 2 + 1)
        LOAD_KEY_PAIR %%KEY_PTRS, %%lp_lo, %%lp_hi, 0, LFSR_A_HDQ_L %+ %%lp_lo %+ %%lp_hi
        LOAD_KEY_PAIR %%KEY_PTRS, %%lp_lo, %%lp_hi, 16, LFSR_B_HDQ_L %+ %%lp_lo %+ %%lp_hi
%assign %%i (%%i + 1)
%endrep
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Run 17 SNOW5G initialization rounds with key mixing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_INIT_ROUNDS 1
%define %%KEY_PTRS      %1  ;; [in] pointer to array of key pointers

        ;; Set up k-register masks
        kxnord  k1, k1, k1              ;; k1 = all 1s (init phase - feedback)
        kxord   k2, k2, k2              ;; k2 = all 0s (keygen phase - no feedback)

        ;; 15 init rounds with keystream feedback
        mov     DWORD(rbp), 15
align_loop
%%init_loop:
        PROCESS_ALL_LANE_PAIRS k1
        dec     DWORD(rbp)
        jnz     %%init_loop

        ;; Round 16: R1 ^= key[0:15], then init round
%assign %%i 0
%rep 4
%assign %%lp_lo (%%i * 2)
%assign %%lp_hi (%%i * 2 + 1)
        XOR_KEY_INTO_REG %%KEY_PTRS, %%lp_lo, %%lp_hi, 0, FSM_R1_L %+ %%lp_lo %+ %%lp_hi
%assign %%i (%%i + 1)
%endrep
        PROCESS_ALL_LANE_PAIRS k1

        ;; Round 17: R1 ^= key[16:31]
%assign %%i 0
%rep 4
%assign %%lp_lo (%%i * 2)
%assign %%lp_hi (%%i * 2 + 1)
        XOR_KEY_INTO_REG %%KEY_PTRS, %%lp_lo, %%lp_hi, 16, FSM_R1_L %+ %%lp_lo %+ %%lp_hi
%assign %%i (%%i + 1)
%endrep
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; NCA4 cipher: encrypt/decrypt 16 bytes per lane, clock FSM and update LFSR
;; %%LANE_MASK: 2 = both lanes, 0 = lane 0 only (lower xmm), 1 = lane 1 only (upper xmm)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_CIPHER_LANE_PAIR 20
%define %%LANE_PAIR            %1   ;; [in] lane pair index
%define %%FSM_R1               %2   ;; [in/out] FSM R1 register
%define %%FSM_R2               %3   ;; [in/out] FSM R2 register
%define %%FSM_R3               %4   ;; [in/out] FSM R3 register
%define %%LFSR_A_LDQ           %5   ;; [in/out] LFSR A low DQW
%define %%LFSR_A_HDQ           %6   ;; [in/out] LFSR A high DQW
%define %%LFSR_B_LDQ           %7   ;; [in/out] LFSR B low DQW
%define %%LFSR_B_HDQ           %8   ;; [in/out] LFSR B high DQW
%define %%LFSR_A_SAVE          %9   ;; [in] stack offset for LFSR_A_HDQ save
%define %%LFSR_B_SAVE          %10  ;; [in] stack offset for LFSR_B_HDQ save
%define %%KEYSTREAM_SAVE       %11  ;; [in] stack offset for keystream save
%define %%TEMP1                %12  ;; [clobbered] temporary zmm register
%define %%TEMP2                %13  ;; [clobbered] temporary zmm register
%define %%SRC_PTRS             %14  ;; [in] address of array of pointers to src buffers
%define %%DST_PTRS             %15  ;; [in] address of array of pointers to dst buffers
%define %%OFFSET               %16  ;; [in] current byte offset into src/dst buffers
%define %%TGP0                 %17  ;; [clobbered] temporary 64-bit register
%define %%TGP1                 %18  ;; [clobbered] temporary 64-bit register
%define %%KREG_INIT            %19  ;; [in] k-register mask for INIT phase
%define %%LANE_MASK            %20  ;; [in] 2=both lanes, 0=lane0 only, 1=lane1 only

        vpaddw          %%TEMP1, %%LFSR_B_HDQ, %%FSM_R1
        vpxord          %%TEMP1, %%TEMP1, %%FSM_R2
        vmovdqa32       [rsp + %%KEYSTREAM_SAVE], %%TEMP1

%if %%LANE_MASK != 1
        mov             %%TGP0, [%%SRC_PTRS + (%%LANE_PAIR * 2 + 0) * 8]
        mov             %%TGP1, [%%DST_PTRS + (%%LANE_PAIR * 2 + 0) * 8]
        vmovdqu32       XWORD(%%TEMP2), [%%TGP0 + %%OFFSET]
        vpxord          XWORD(%%TEMP2), XWORD(%%TEMP1), XWORD(%%TEMP2)
        vmovdqu32       [%%TGP1 + %%OFFSET], XWORD(%%TEMP2)
%endif

%if %%LANE_MASK != 0
        vextracti32x4   XWORD(%%TEMP1), %%TEMP1, 1
        mov             %%TGP0, [%%SRC_PTRS + (%%LANE_PAIR * 2 + 1) * 8]
        mov             %%TGP1, [%%DST_PTRS + (%%LANE_PAIR * 2 + 1) * 8]
        vmovdqu32       XWORD(%%TEMP2), [%%TGP0 + %%OFFSET]
        vpxord          XWORD(%%TEMP2), XWORD(%%TEMP1), XWORD(%%TEMP2)
        vmovdqu32       [%%TGP1 + %%OFFSET], XWORD(%%TEMP2)
%endif

        SNOW5G_FSM_CLOCK_2 %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_HDQ, %%TEMP1, %%TEMP2
        SNOW5G_LFSR_UPDATE %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, %%LFSR_A_SAVE, %%LFSR_B_SAVE, [rsp + %%KEYSTREAM_SAVE], %%KREG_INIT, %%TEMP1, %%TEMP2
%endmacro

;; NCA4 cipher round: encrypt/decrypt 16 bytes for lane pair L01
%macro NCA4_CIPHER_L01 2
%define %%OFFSET    %1  ;; [in] byte offset register
%define %%LANE_MASK %2  ;; [in] 2=both, 0=lane0 only, 1=lane1 only
        NCA4_CIPHER_LANE_PAIR 0, FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                _LFSR_A_HDQ_01, _LFSR_B_HDQ_01, _keystream_01, \
                TEMP1, TEMP2, arg2, arg3, %%OFFSET, r10, rbp, k1, %%LANE_MASK
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; 2-lane (single lane pair L01) helpers for NCA4
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Init LFSR/FSM state for 2 lanes (uses L01 registers only)
%macro SNOW5G_INIT_STATE_X2 2
%define %%KEY_PTRS      %1
%define %%IV_PTR        %2
        vpxorq          TEMP0, TEMP0, TEMP0
        vmovdqa32       FSM_R1_L01, TEMP0
        vmovdqa32       FSM_R2_L01, TEMP0
        vmovdqa32       FSM_R3_L01, TEMP0
        vmovdqa32       LFSR_B_LDQ_L01, TEMP0
        vmovdqu64       LFSR_A_LDQ_L01, [%%IV_PTR]
        LOAD_KEY_PAIR   %%KEY_PTRS, 0, 1, 0,  LFSR_A_HDQ_L01
        LOAD_KEY_PAIR   %%KEY_PTRS, 0, 1, 16, LFSR_B_HDQ_L01
%endmacro

;; 17-round SNOW5G init for 2 lanes (uses L01 only)
%macro SNOW5G_INIT_ROUNDS_X2 1
%define %%KEY_PTRS      %1
        kxnord  k1, k1, k1
        kxord   k2, k2, k2
        mov     DWORD(rbp), 15
align_loop
%%init_loop_x2:
        SNOW5G_ENC_DEC_LANE_PAIR 0, FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                _LFSR_A_HDQ_01, _LFSR_B_HDQ_01, _keystream_01, \
                TEMP0, TEMP1, 0, 0, 0, 0, r10, r11, k1, k3, 1
        dec     DWORD(rbp)
        jnz     %%init_loop_x2
        XOR_KEY_INTO_REG %%KEY_PTRS, 0, 1, 0,  FSM_R1_L01
        SNOW5G_ENC_DEC_LANE_PAIR 0, FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                _LFSR_A_HDQ_01, _LFSR_B_HDQ_01, _keystream_01, \
                TEMP0, TEMP1, 0, 0, 0, 0, r10, r11, k1, k3, 1
        XOR_KEY_INTO_REG %%KEY_PTRS, 0, 1, 16, FSM_R1_L01
%endmacro

;; Store 2-lane state (lanes 0 and 1, 160 bytes each)
%macro STATE_STORE_NCA4_X2 1
%define %%STATE_PTR     %1
        vmovdqu32       [%%STATE_PTR + 0*160 + 3*16], XWORD(FSM_R1_L01)
        vmovdqu32       [%%STATE_PTR + 0*160 + 4*16], XWORD(FSM_R2_L01)
        vmovdqu32       [%%STATE_PTR + 0*160 + 5*16], XWORD(FSM_R3_L01)
        vmovdqu32       [%%STATE_PTR + 0*160 + 6*16], XWORD(LFSR_A_LDQ_L01)
        vmovdqu32       [%%STATE_PTR + 0*160 + 7*16], XWORD(LFSR_A_HDQ_L01)
        vmovdqu32       [%%STATE_PTR + 0*160 + 8*16], XWORD(LFSR_B_LDQ_L01)
        vmovdqu32       [%%STATE_PTR + 0*160 + 9*16], XWORD(LFSR_B_HDQ_L01)
        vextracti32x4   [%%STATE_PTR + 1*160 + 3*16], FSM_R1_L01, 1
        vextracti32x4   [%%STATE_PTR + 1*160 + 4*16], FSM_R2_L01, 1
        vextracti32x4   [%%STATE_PTR + 1*160 + 5*16], FSM_R3_L01, 1
        vextracti32x4   [%%STATE_PTR + 1*160 + 6*16], LFSR_A_LDQ_L01, 1
        vextracti32x4   [%%STATE_PTR + 1*160 + 7*16], LFSR_A_HDQ_L01, 1
        vextracti32x4   [%%STATE_PTR + 1*160 + 8*16], LFSR_B_LDQ_L01, 1
        vextracti32x4   [%%STATE_PTR + 1*160 + 9*16], LFSR_B_HDQ_L01, 1
%endmacro

;; Load 2-lane state (lanes 0 and 1, 160 bytes each) into L01 registers
%macro STATE_LOAD_NCA4_X2 1
%define %%STATE_PTR     %1
        vmovdqu32       XWORD(FSM_R1_L01),    [%%STATE_PTR + 0*160 + 3*16]
        vinserti32x4    FSM_R1_L01,    FSM_R1_L01,    [%%STATE_PTR + 1*160 + 3*16], 1
        vmovdqu32       XWORD(FSM_R2_L01),    [%%STATE_PTR + 0*160 + 4*16]
        vinserti32x4    FSM_R2_L01,    FSM_R2_L01,    [%%STATE_PTR + 1*160 + 4*16], 1
        vmovdqu32       XWORD(FSM_R3_L01),    [%%STATE_PTR + 0*160 + 5*16]
        vinserti32x4    FSM_R3_L01,    FSM_R3_L01,    [%%STATE_PTR + 1*160 + 5*16], 1
        vmovdqu32       XWORD(LFSR_A_LDQ_L01),[%%STATE_PTR + 0*160 + 6*16]
        vinserti32x4    LFSR_A_LDQ_L01,LFSR_A_LDQ_L01,[%%STATE_PTR + 1*160 + 6*16], 1
        vmovdqu32       XWORD(LFSR_A_HDQ_L01),[%%STATE_PTR + 0*160 + 7*16]
        vinserti32x4    LFSR_A_HDQ_L01,LFSR_A_HDQ_L01,[%%STATE_PTR + 1*160 + 7*16], 1
        vmovdqu32       XWORD(LFSR_B_LDQ_L01),[%%STATE_PTR + 0*160 + 8*16]
        vinserti32x4    LFSR_B_LDQ_L01,LFSR_B_LDQ_L01,[%%STATE_PTR + 1*160 + 8*16], 1
        vmovdqu32       XWORD(LFSR_B_HDQ_L01),[%%STATE_PTR + 0*160 + 9*16]
        vinserti32x4    LFSR_B_HDQ_L01,LFSR_B_HDQ_L01,[%%STATE_PTR + 1*160 + 9*16], 1
%endmacro

mksection stack-noexec

%endif ; _SNOW5G_X8_VAES_AVX512_ASM_
