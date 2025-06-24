;;
;; Copyright (c) 2024-2025 Intel Corporation
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
%include "include/reg_sizes.inc"
%include "include/memcpy.inc"
%include "include/imb_job.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/align_sse.inc"

%define SNOW5G_NEA4 snow_5g_sse
%define SNOW5G_NCA4 snow5g_nca4_sse
mksection .rodata

align 16
alpha:
times 8 dw 0x4a6d

align 16
beta:
times 8 dw 0xcc87

;; permutation: [ 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 ]
align 16
sigma:
dq 0xd0905010c080400
dq 0xf0b07030e0a0602

%ifdef LINUX
        %define arg1      rdi
        %define arg2      rsi
        %define arg3      rdx
        %define arg4      rcx
%else
        %define arg1      rcx
        %define arg2      rdx
        %define arg3      r8
        %define arg4      r9
%endif

%define job     arg1

%ifidn __OUTPUT_FORMAT__, win64
; stack frame for saving registers (windows only)
struc STACK
_xmm_save:      resq    10 * 2  ; space for 10 xmm registers
_rsp_save:      resq    1       ; space for rsp pointer
_gp_save:       resq    1       ; space for r12
endstruc
%else
struc STACK
_rsp_save:      resq    1       ; space for rsp pointer
_gp_save:       resq    1       ; space for r12
endstruc
%endif
mksection .text

;; Registers usage
%define KEYSTREAM       xmm0
%define T1              xmm1    ;;  tap register T1
%define T2              xmm2    ;;  tap register T2
%define TEMP_1          xmm3
%define TEMP_2          xmm4
%define TEMP_3          xmm5
%define FSM_R1          xmm6    ;; FSM R1 
%define FSM_R2          xmm7    ;; FSM R2
%define FSM_R3          xmm8    ;; FSM R3
%define LFSR_A_LDQ      xmm9    ;; LFSR A: (a7, ..., a0)
%define LFSR_A_HDQ      xmm10   ;; LFSR A: (a15, ..., a8)
%define LFSR_B_LDQ      xmm11   ;; LFSR B: (b7, ..., b0)
%define LFSR_B_HDQ      xmm12   ;; LFSR B: (b15, ..., b8)
%define gA              xmm13   ;; constant used in alpha function
%define gB              xmm14   ;; constant used in beta function
%define gSigma          xmm15   ;; constant used for sigma permutation
%define TEMP_GP         rax
%define IN_PTR          r10
%define OUT_PTR         r11
%define offset          r12


; ==============================================================================
%macro FUNC_SAVE 0
        mov     TEMP_GP, rsp
        sub     rsp, STACK_size
        and     rsp, -16
        mov     [rsp + _rsp_save], TEMP_GP

        mov     [rsp + _gp_save], r12

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        movdqa  [rsp + _xmm_save + 0*16], xmm6
        movdqa  [rsp + _xmm_save + 1*16], xmm7
        movdqa  [rsp + _xmm_save + 2*16], xmm8
        movdqa  [rsp + _xmm_save + 3*16], xmm9
        movdqa  [rsp + _xmm_save + 4*16], xmm10
        movdqa  [rsp + _xmm_save + 5*16], xmm11
        movdqa  [rsp + _xmm_save + 6*16], xmm12
        movdqa  [rsp + _xmm_save + 7*16], xmm13
        movdqa  [rsp + _xmm_save + 8*16], xmm14
        movdqa  [rsp + _xmm_save + 9*16], xmm15
%endif
%endmacro ; FUNC_SAVE
; ==============================================================================
%macro FUNC_RESTORE 0
%ifidn __OUTPUT_FORMAT__, win64
        movdqa  xmm6, [rsp + _xmm_save + 0*16]
        movdqa  xmm7, [rsp + _xmm_save + 1*16]
        movdqa  xmm8, [rsp + _xmm_save + 2*16]
        movdqa  xmm9, [rsp + _xmm_save + 3*16]
        movdqa  xmm10, [rsp + _xmm_save + 4*16]
        movdqa  xmm11, [rsp + _xmm_save + 5*16]
        movdqa  xmm12, [rsp + _xmm_save + 6*16]
        movdqa  xmm13, [rsp + _xmm_save + 7*16]
        movdqa  xmm14, [rsp + _xmm_save + 8*16]
        movdqa  xmm15, [rsp + _xmm_save + 9*16]
%endif
        mov     r12, [rsp + _gp_save]
        mov     rsp, [rsp + _rsp_save]

%endmacro ; FUNC_RESTORE

; ==============================================================================
%macro STATE_SAVE 1
%define %%DST  %1 ;; [in] destination address (minimum size 160B, 16B aligned)
        movdqa  [%%DST + 0*16], KEYSTREAM
        movdqa  [%%DST + 1*16], T1
        movdqa  [%%DST + 2*16], T2
        movdqa  [%%DST + 3*16], FSM_R1
        movdqa  [%%DST + 4*16], FSM_R2
        movdqa  [%%DST + 5*16], FSM_R3
        movdqa  [%%DST + 6*16], LFSR_A_LDQ
        movdqa  [%%DST + 7*16], LFSR_A_HDQ
        movdqa  [%%DST + 8*16], LFSR_B_LDQ
        movdqa  [%%DST + 9*16], LFSR_B_HDQ
%endmacro ; STATE_SAVE

; ==============================================================================
; restore state and load constants
%macro STATE_RESTORE 1
%define %%SRC  %1 ;; [in] destination address
        movdqa  gA, [rel alpha]
        movdqa  gB, [rel beta]
        movdqa  gSigma, [rel sigma]

        movdqa  KEYSTREAM, [%%SRC + 0*16], 
        movdqa  T1, [%%SRC + 1*16], 
        movdqa  T2, [%%SRC + 2*16], 
        movdqa  FSM_R1, [%%SRC + 3*16], 
        movdqa  FSM_R2, [%%SRC + 4*16], 
        movdqa  FSM_R3, [%%SRC + 5*16], 
        movdqa  LFSR_A_LDQ, [%%SRC + 6*16], 
        movdqa  LFSR_A_HDQ, [%%SRC + 7*16], 
        movdqa  LFSR_B_LDQ, [%%SRC + 8*16], 
        movdqa  LFSR_B_HDQ, [%%SRC + 9*16], 
%endmacro ; STATE_RESTORE

;------------------------------------------------------------------------------
; snow5g_round_sse
; Performs one SNOW 5G round: generate keystream, update FSM and LFSR
; Register usage:
; Input:  LFSR_B_HDQ, FSM_R1, FSM_R2, LFSR_A_HDQ, FSM_R3, gSigma, 
;         LFSR_A_LDQ, LFSR_B_LDQ, T1, T2, gA, gB
; Output: KEYSTREAM, FSM_R1, FSM_R2, FSM_R3, LFSR_A_HDQ, LFSR_A_LDQ, 
;         LFSR_B_HDQ, LFSR_B_LDQ, T1
; Clobbered: TEMP_1, TEMP_2
;------------------------------------------------------------------------------
align_function
snow5g_round_sse:
        ; SNOW5G_KEYSTREAM
        movdqa          KEYSTREAM, LFSR_B_HDQ
        paddw           KEYSTREAM, FSM_R1
        pxor            KEYSTREAM, FSM_R2

        ; SNOW5G_FSM_UPDATE
        movdqa          TEMP_2, LFSR_A_HDQ
        pxor            TEMP_2, FSM_R3          ; TEMP_2 = R3 XOR LFSR_A [0:7]
        paddw           TEMP_2, FSM_R2          ; TEMP_2 += R2
        pshufb          TEMP_2, gSigma          ; TEMP_2 = sigma(TEMP_2)
        movdqa          FSM_R3, FSM_R2          ; R3 = R2
        movdqa          FSM_R2, FSM_R1          ; R2 = R1
        pxor            TEMP_1, TEMP_1          ; TEMP_1 = 0
        movdqa          FSM_R1, TEMP_2          ; R1 = sigma(TEMP_2)
        aesenc          FSM_R3, TEMP_1          ; R3 = AESR(R2) (encryption round key C1 = 0)
        aesenc          FSM_R2, TEMP_1          ; R2 = AESR(R1) (encryption round key C2 = 0)

        ; ----------------------------------------------------------------------
        ; SNOW5G_LFSR_UPDATE
        ; Update SNOW5G LFSR
        ; for i in [0,7]:
        ;    tmpa_i = alpha(a_i)  + b_i + a_(i + 7)
        ;    tmpb_i = beta(b_i)   + a_i + b_(i + 8)
        ;
        ; alpha(x) / beta(x):
        ;      if  (x & 0x0001): (x << 1) 1 XOR 0x1a6d(alpha) / 0xcc87(beta)
        ;      else            : (x << 1) 1
        ; ----------------------------------------------------------------------
        palignr         LFSR_A_HDQ, LFSR_A_LDQ, 14      ; lfsrA [14:7]
        ; calculate alpha(lfsrA [7:0])
        movdqa          TEMP_1, LFSR_A_LDQ
        psraw           TEMP_1, 15                      ; 16-bit mask with sign bits preserved
        pand            TEMP_1, gA
        movdqa          TEMP_2, LFSR_A_LDQ
        psllw           TEMP_2, 1                       ; (a_i << 1)
        pxor            TEMP_2, TEMP_1                  ; TEMP_2 = alpha(lfsrA [7:0]) 1a
        ; LFSR_A_HDQ = lfsrA [14:7] XOR alpha(lfsrA[7:0]) XOR LFSR_B_LDQ
        pxor            LFSR_A_HDQ, TEMP_2
        pxor            LFSR_A_HDQ, LFSR_B_LDQ

        ; ----------------------------------------------------------------------
        ; LFSR_B_HDQ = beta (lfsrB [7:0]) XOR
        ;              lfsrA [7:0]        XOR
        ;              lfsrB [15:8]
        ; ----------------------------------------------------------------------
        pxor            LFSR_B_HDQ, LFSR_A_LDQ          ; LFSR_B_HDQ =  lfsrB [15:8] XOR lfsrA[7:0] 2bc
        ;; calculate beta (lfsrB [7:0])
        movdqa          TEMP_2, LFSR_B_LDQ
        psllw           TEMP_2, 1                       ; (b_i << 1)
        psraw           LFSR_B_LDQ, 15                  ; 16-bit mask with sign bits preserved
        pand            LFSR_B_LDQ, gB              
        pxor            TEMP_2, LFSR_B_LDQ              ; beta(lfsrB [7:0])
        pxor            LFSR_B_HDQ, TEMP_2              ; lfsrB[15:8]

        ; ----------------------------------------------------------------------
        ; LFSR_A_LDQ   = lfsrA [15:8]
        ; LFSR_B_LDQ   = lfsrB [15:8]
        ; T2 =(a) lfsrA[15:8]
        ; T1 =(a) lfsrB[15:8]
        ; ----------------------------------------------------------------------
        movdqa          LFSR_A_LDQ, T2
        movdqa          LFSR_B_LDQ, T1
        movdqa          T1, LFSR_B_HDQ
        ret

;------------------------------------------------------------------------------
; SNOW5G_INIT <key_ptr>, <iv_ptr>
;   Initialize SNOW 5G cipher state (LFSR, FSM, taps) with key and IV,
;   performing rounds and key mixing as per SNOW 5G spec.
;------------------------------------------------------------------------------
%macro SNOW5G_INIT 2
%define %%KEYS  %1 ;; [in] address
%define %%IV    %2 ;; [in] address

        movdqa          gA, [rel alpha]
        movdqa          gB, [rel beta]
        movdqa          gSigma, [rel sigma]

        ; ----------------------------------------------------------------------
        ; Init LFSR, FSM and tap registers
        mov             TEMP_GP, %%KEYS
        movdqu          LFSR_A_HDQ, [TEMP_GP]
        movdqu          LFSR_B_HDQ, [TEMP_GP + 16]
        mov             TEMP_GP, %%IV
        movdqu          LFSR_A_LDQ, [TEMP_GP]
        pxor            LFSR_B_LDQ, LFSR_B_LDQ
        ; FSM: R1 = R2 = R3 = 0
        pxor            FSM_R1, FSM_R1
        pxor            FSM_R2, FSM_R2
        pxor            FSM_R3, FSM_R3
        movdqa          T1, LFSR_B_HDQ
        movdqa          T2, LFSR_A_HDQ

        mov     DWORD(TEMP_GP), 15
align_loop
%%_init_fsm_lfsr_loop:
        call snow5g_round_sse
        pxor            LFSR_A_HDQ, KEYSTREAM
        movdqa          T2, LFSR_A_HDQ
        dec             DWORD(TEMP_GP)
        jnz             %%_init_fsm_lfsr_loop

;     if t==15 then R1 = R1 ⊕ (k_7,k_6,…,k_0 )
;     if t==16 then R1 = R1 ⊕ (k_15,k_14,…,k_8 )
        mov             TEMP_GP, %%KEYS
        movdqu          TEMP_3, [TEMP_GP]
        pxor            FSM_R1, TEMP_3

        call snow5g_round_sse

        pxor            LFSR_A_HDQ, KEYSTREAM
        movdqa          T2, LFSR_A_HDQ

        movdqu          TEMP_3, [TEMP_GP + 16]
        pxor            FSM_R1, TEMP_3

        ; At this point FSM and LFSR are initialized
%endmacro ;; SNOW5G_INIT

;------------------------------------------------------------------------------
; snow5g_enc_dec_sse
; Encrypts or decrypts the input buffer using the SNOW 5G keystream,
; handling full and partial blocks.
; Register usage:
; Input:  IN_PTR - source data pointer
;         OUT_PTR - destination data pointer
;         TEMP_GP - data length
;         job - job structure pointer (for _msg_len_to_cipher_in_bytes)
; Output: Encrypted/decrypted data in OUT_PTR
; Clobbered: offset, TEMP_GP, TEMP_3, IN_PTR (for partial blocks)
;------------------------------------------------------------------------------
align_function
snow5g_enc_dec_sse:
        xor             offset, offset
        ; deal with partial block less than 16b outside main loop
        and             TEMP_GP, 0xfffffffffffffff0
        jz              .final_bytes
align_loop
.encrypt_loop:
        movdqu          TEMP_3, [IN_PTR + offset]

        call snow5g_round_sse
        movdqa          T2, LFSR_A_HDQ

        pxor            TEMP_3, KEYSTREAM
        movdqu          [OUT_PTR + offset], TEMP_3
        add             offset, 16
        sub             TEMP_GP, 16
        jnz             .encrypt_loop
align_label
.final_bytes:
        mov             TEMP_GP, [job + _msg_len_to_cipher_in_bytes]
        and             TEMP_GP, 0xf
        jz              .no_partial_block_left

        ; load partial block into XMM register
        add             IN_PTR, offset
        simd_load_sse_15_1 TEMP_3, IN_PTR, TEMP_GP
        ; Calculate keystream
        movdqa          KEYSTREAM, LFSR_B_HDQ
        paddw           KEYSTREAM, FSM_R1
        pxor            KEYSTREAM, FSM_R2
        pxor            TEMP_3, KEYSTREAM
        add             OUT_PTR, offset
        ; use IN_PTR and offset as temp [clobbered]
        simd_store_sse_15 OUT_PTR, TEMP_3, TEMP_GP, IN_PTR, offset
align_label
.no_partial_block_left:
        ret

;------------------------------------------------------------------------------
; SNOW5G_NEA (IMB_JOB *job)
;------------------------------------------------------------------------------
MKGLOBAL(SNOW5G_NEA4,function,)
align_function
SNOW5G_NEA4:
        endbranch64
        FUNC_SAVE
        SNOW5G_INIT {[job + _enc_keys]}, {[job + _iv]}

        ; Process input
        mov             IN_PTR, [job + _src]
        add             IN_PTR, [job + _cipher_start_src_offset_in_bytes]
        mov             OUT_PTR, [job + _dst]
        mov             TEMP_GP, [job + _msg_len_to_cipher_in_bytes]
        call            snow5g_enc_dec_sse
        ; Clear registers and return data
%ifdef SAFE_DATA
        clear_scratch_xmms_sse_asm
%endif

        mov             TEMP_GP, job
        or              dword [TEMP_GP + _status], IMB_STATUS_COMPLETED_CIPHER
        FUNC_RESTORE
        ret

;------------------------------------------------------------------------------
; generate_hqp_snow5g_sse(const uint8_t *key, const uint8_t *iv, uint8_t *hqp,
;                         uint8_t *state)
;------------------------------------------------------------------------------
MKGLOBAL(generate_hqp_snow5g_sse,function,)
align_function
generate_hqp_snow5g_sse:
; For NIA4, NULL is passed for state pointer (arg4)
        endbranch64
        FUNC_SAVE

        SNOW5G_INIT arg1, arg2

        ;; Snow 5G.GenerateHQP 
        call snow5g_round_sse
        movdqa          T2, LFSR_A_HDQ
        movdqu          [arg3], KEYSTREAM

        call snow5g_round_sse
        movdqa          T2, LFSR_A_HDQ
        movdqu          [arg3 + 16], KEYSTREAM

        call snow5g_round_sse
        movdqa          T2, LFSR_A_HDQ
        movdqu          [arg3 + 32], KEYSTREAM

        ;; Save state if state pointer is not NULL
        test            arg4, arg4
        jz              .skip_state_save
        STATE_SAVE      arg4
align_label
.skip_state_save:
%ifdef SAFE_DATA
        clear_scratch_xmms_sse_asm
%endif
        FUNC_RESTORE
        ret

;------------------------------------------------------------------------------
; SNOW5G_NCA4(IMB_JOB *job, uint8_t *state)
;------------------------------------------------------------------------------
MKGLOBAL(SNOW5G_NCA4,function,)
align_function
SNOW5G_NCA4:
        endbranch64
        FUNC_SAVE
        STATE_RESTORE arg2

        mov             IN_PTR, [job + _src]
        add             IN_PTR, [job + _cipher_start_src_offset_in_bytes]
        mov             OUT_PTR, [job + _dst]
        mov             TEMP_GP, [job + _msg_len_to_cipher_in_bytes]
        call            snow5g_enc_dec_sse

%ifdef SAFE_DATA
        clear_scratch_xmms_sse_asm
%endif
        FUNC_RESTORE
        ret
