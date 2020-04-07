;;
;; Copyright (c) 2020, Intel Corporation
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
%include "include/reg_sizes.asm"
%include "include/zuc_sbox.inc"
%include "include/transpose_avx512.asm"

%define APPEND(a,b) a %+ b

section .data
default rel

align 64
EK_d64:
dd	0x0044D700, 0x0026BC00, 0x00626B00, 0x00135E00, 0x00578900, 0x0035E200, 0x00713500, 0x0009AF00
dd	0x004D7800, 0x002F1300, 0x006BC400, 0x001AF100, 0x005E2600, 0x003C4D00, 0x00789A00, 0x0047AC00

align 64
shuf_mask_key:
dd      0x00FFFFFF, 0x01FFFFFF, 0x02FFFFFF, 0x03FFFFFF, 0x04FFFFFF, 0x05FFFFFF, 0x06FFFFFF, 0x07FFFFFF,
dd      0x08FFFFFF, 0x09FFFFFF, 0x0AFFFFFF, 0x0BFFFFFF, 0x0CFFFFFF, 0x0DFFFFFF, 0x0EFFFFFF, 0x0FFFFFFF,

align 64
shuf_mask_iv:
dd      0xFFFFFF00, 0xFFFFFF01, 0xFFFFFF02, 0xFFFFFF03, 0xFFFFFF04, 0xFFFFFF05, 0xFFFFFF06, 0xFFFFFF07,
dd      0xFFFFFF08, 0xFFFFFF09, 0xFFFFFF0A, 0xFFFFFF0B, 0xFFFFFF0C, 0xFFFFFF0D, 0xFFFFFF0E, 0xFFFFFF0F,

align 64
mask31:
dd	0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF,
dd	0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF,
dd	0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF,
dd	0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF,

align 64
swap_mask:
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c

align 64
S1_S0_shuf:
db      0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F
db      0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F
db      0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F
db      0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F

align 64
S0_S1_shuf:
db      0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
db      0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
db      0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
db      0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,

align 64
rev_S1_S0_shuf:
db      0x00, 0x08, 0x01, 0x09, 0x02, 0x0A, 0x03, 0x0B, 0x04, 0x0C, 0x05, 0x0D, 0x06, 0x0E, 0x07, 0x0F
db      0x00, 0x08, 0x01, 0x09, 0x02, 0x0A, 0x03, 0x0B, 0x04, 0x0C, 0x05, 0x0D, 0x06, 0x0E, 0x07, 0x0F
db      0x00, 0x08, 0x01, 0x09, 0x02, 0x0A, 0x03, 0x0B, 0x04, 0x0C, 0x05, 0x0D, 0x06, 0x0E, 0x07, 0x0F
db      0x00, 0x08, 0x01, 0x09, 0x02, 0x0A, 0x03, 0x0B, 0x04, 0x0C, 0x05, 0x0D, 0x06, 0x0E, 0x07, 0x0F

align 64
rev_S0_S1_shuf:
db      0x08, 0x00, 0x09, 0x01, 0x0A, 0x02, 0x0B, 0x03, 0x0C, 0x04, 0x0D, 0x05, 0x0E, 0x06, 0x0F, 0x07
db      0x08, 0x00, 0x09, 0x01, 0x0A, 0x02, 0x0B, 0x03, 0x0C, 0x04, 0x0D, 0x05, 0x0E, 0x06, 0x0F, 0x07
db      0x08, 0x00, 0x09, 0x01, 0x0A, 0x02, 0x0B, 0x03, 0x0C, 0x04, 0x0D, 0x05, 0x0E, 0x06, 0x0F, 0x07
db      0x08, 0x00, 0x09, 0x01, 0x0A, 0x02, 0x0B, 0x03, 0x0C, 0x04, 0x0D, 0x05, 0x0E, 0x06, 0x0F, 0x07

section .text
align 64

%define MASK31  zmm12

%define OFS_R1  (16*(4*16))
%define OFS_R2  (OFS_R1 + (4*16))
%define OFS_X0  (OFS_R2 + (4*16))
%define OFS_X1  (OFS_X0 + (4*16))
%define OFS_X2  (OFS_X1 + (4*16))

%ifidn __OUTPUT_FORMAT__, win64
        %define XMM_STORAGE     16*10
        %define GP_STORAGE      8*8
%else
        %define XMM_STORAGE     0
        %define GP_STORAGE      6*8
%endif

%define VARIABLE_OFFSET XMM_STORAGE + GP_STORAGE
%define GP_OFFSET XMM_STORAGE

%macro FUNC_SAVE 0
        mov     r11, rsp
        sub     rsp, VARIABLE_OFFSET
        and     rsp, ~15

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        vmovdqa [rsp + 0*16], xmm6
        vmovdqa [rsp + 1*16], xmm7
        vmovdqa [rsp + 2*16], xmm8
        vmovdqa [rsp + 3*16], xmm9
        vmovdqa [rsp + 4*16], xmm10
        vmovdqa [rsp + 5*16], xmm11
        vmovdqa [rsp + 6*16], xmm12
        vmovdqa [rsp + 7*16], xmm13
        vmovdqa [rsp + 8*16], xmm14
        vmovdqa [rsp + 9*16], xmm15
        mov     [rsp + GP_OFFSET + 48], rdi
        mov     [rsp + GP_OFFSET + 56], rsi
%endif
        mov     [rsp + GP_OFFSET],      r12
        mov     [rsp + GP_OFFSET + 8],  r13
        mov     [rsp + GP_OFFSET + 16], r14
        mov     [rsp + GP_OFFSET + 24], r15
        mov     [rsp + GP_OFFSET + 32], rbx
        mov     [rsp + GP_OFFSET + 40], r11 ;; rsp pointer
%endmacro


%macro FUNC_RESTORE 0

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqa xmm6,  [rsp + 0*16]
        vmovdqa xmm7,  [rsp + 1*16]
        vmovdqa xmm8,  [rsp + 2*16]
        vmovdqa xmm9,  [rsp + 3*16]
        vmovdqa xmm10, [rsp + 4*16]
        vmovdqa xmm11, [rsp + 5*16]
        vmovdqa xmm12, [rsp + 6*16]
        vmovdqa xmm13, [rsp + 7*16]
        vmovdqa xmm14, [rsp + 8*16]
        vmovdqa xmm15, [rsp + 9*16]
        mov     rdi, [rsp + GP_OFFSET + 48]
        mov     rsi, [rsp + GP_OFFSET + 56]
%endif
        mov     r12, [rsp + GP_OFFSET]
        mov     r13, [rsp + GP_OFFSET + 8]
        mov     r14, [rsp + GP_OFFSET + 16]
        mov     r15, [rsp + GP_OFFSET + 24]
        mov     rbx, [rsp + GP_OFFSET + 32]
        mov     rsp, [rsp + GP_OFFSET + 40]
%endmacro


;
;   bits_reorg16()
;
;   params
;       %1 - round number
;       %2 - Calculate X3 (1 = yes)
;       %3 - ZMM register storing X3
;       rax - LFSR pointer
;   uses
;
;   return
;
%macro  bits_reorg16 2-3
    ;
    ; zmm15 = LFSR_S15
    ; zmm14 = LFSR_S14
    ; zmm11 = LFSR_S11
    ; zmm9  = LFSR_S9
    ; zmm7  = LFSR_S7
    ; zmm5  = LFSR_S5
    ; zmm2  = LFSR_S2
    ; zmm0  = LFSR_S0
    ;
    vmovdqa64   zmm15, [rax + ((15 + %1) % 16)*64]
    vmovdqa64   zmm14, [rax + ((14 + %1) % 16)*64]
    vmovdqa64   zmm11, [rax + ((11 + %1) % 16)*64]
    vmovdqa64   zmm9,  [rax + (( 9 + %1) % 16)*64]
    vmovdqa64   zmm7,  [rax + (( 7 + %1) % 16)*64]
    vmovdqa64   zmm5,  [rax + (( 5 + %1) % 16)*64]
    vmovdqa64   zmm2,  [rax + (( 2 + %1) % 16)*64]
    vmovdqa64   zmm0,  [rax + (( 0 + %1) % 16)*64]

    vpxorq      zmm1, zmm1
    vpslld      zmm15, 1
    vpblendmw   zmm3{k1},  zmm14, zmm1
    vpblendmw   zmm15{k1}, zmm3, zmm15

    vmovdqa64   [rax + OFS_X0], zmm15   ; BRC_X0
    vpslld      zmm11, 16
    vpsrld      zmm9, 15
    vporq       zmm11, zmm9
    vmovdqa64   [rax + OFS_X1], zmm11   ; BRC_X1
    vpslld      zmm7, 16
    vpsrld      zmm5, 15
    vporq       zmm7, zmm5
    vmovdqa64   [rax + OFS_X2], zmm7    ; BRC_X2
%if (%2 == 1)
    vpslld      zmm2, 16
    vpsrld      zmm0, 15
    vporq       %3, zmm2, zmm0 ; Store BRC_X3 in ZMM register
%endif
%endmacro

;
;   nonlin_fun16()
;
;   params
;       %1 == 1, then calculate W
;       %2 == 1, then GFNI instructions may be used
;   uses
;
;   return
;       zmm0 = W value, updates F_R1[] / F_R2[]
;
%macro nonlin_fun16  2
%define %%CALC_W     %1
%define %%USE_GFNI   %2

%if (%%CALC_W == 1)
    vmovdqa64   zmm0, [rax + OFS_X0]
    vpxorq      zmm0, [rax + OFS_R1]
    vpaddd      zmm0, [rax + OFS_R2]    ; W = (BRC_X0 ^ F_R1) + F_R2
%endif

    vmovdqa64   zmm1, [rax + OFS_R1]
    vmovdqa64   zmm2, [rax + OFS_R2]
    vpaddd      zmm1, [rax + OFS_X1]    ; W1 = F_R1 + BRC_X1
    vpxorq      zmm2, [rax + OFS_X2]    ; W2 = F_R2 ^ BRC_X2

    vpslld      zmm3, zmm1, 16
    vpsrld      zmm4, zmm1, 16
    vpslld      zmm5, zmm2, 16
    vpsrld      zmm6, zmm2, 16
    vporq       zmm1, zmm3, zmm6
    vporq       zmm2, zmm4, zmm5

    vprold   zmm3, zmm1, 2
    vprold   zmm4, zmm1, 10
    vprold   zmm5, zmm1, 18
    vprold   zmm6, zmm1, 24
    ; ZMM1 = U = L1(P)
    vpternlogq  zmm1, zmm3, zmm4, 0x96 ; (A ^ B) ^ C
    vpternlogq  zmm1, zmm5, zmm6, 0x96 ; (A ^ B) ^ C

    vprold   zmm3, zmm2, 8
    vprold   zmm4, zmm2, 14
    vprold   zmm5, zmm2, 22
    vprold   zmm6, zmm2, 30
    ; ZMM2 = V = L2(Q)
    vpternlogq  zmm2, zmm3, zmm4, 0x96 ; (A ^ B) ^ C
    vpternlogq  zmm2, zmm5, zmm6, 0x96 ; (A ^ B) ^ C

    ; Shuffle U and V to have all S0 lookups in XMM1 and all S1 lookups in XMM2

    ; Compress all S0 and S1 input values in each register
    ; S0: Bytes 0-7,16-23,32-39,48-55 S1: Bytes 8-15,24-31,40-47,56-63
    vpshufb     zmm1, [rel S0_S1_shuf]
    ; S1: Bytes 0-7,16-23,32-39,48-55 S0: Bytes 8-15,24-31,40-47,56-63
    vpshufb     zmm2, [rel S1_S0_shuf]

    vshufpd     zmm3, zmm1, zmm2, 0xAA ; All S0 input values
    vshufpd     zmm4, zmm2, zmm1, 0xAA ; All S1 input values

    ; Compute S0 and S1 values
    S0_comput_AVX512  zmm3, zmm1, zmm2, %%USE_GFNI
    S1_comput_AVX512  zmm4, zmm1, zmm2, zmm5, zmm6, %%USE_GFNI

    ; Need to shuffle back zmm1 & zmm2 before storing output
    ; (revert what was done before S0 and S1 computations)
    vshufpd     zmm1, zmm3, zmm4, 0xAA
    vshufpd     zmm2, zmm4, zmm3, 0xAA

    vpshufb     zmm1, [rel rev_S0_S1_shuf]
    vpshufb     zmm2, [rel rev_S1_S0_shuf]

    vmovdqa64   [rax + OFS_R1], zmm1
    vmovdqa64   [rax + OFS_R2], zmm2
%endmacro

;
;   store_kstr16()
;
%macro  store_kstr16 17
%define %%DATA64B_L0  %1  ; [in] 64 bytes of keystream for lane 0
%define %%DATA64B_L1  %2  ; [in] 64 bytes of keystream for lane 1
%define %%DATA64B_L2  %3  ; [in] 64 bytes of keystream for lane 2
%define %%DATA64B_L3  %4  ; [in] 64 bytes of keystream for lane 3
%define %%DATA64B_L4  %5  ; [in] 64 bytes of keystream for lane 4
%define %%DATA64B_L5  %6  ; [in] 64 bytes of keystream for lane 5
%define %%DATA64B_L6  %7  ; [in] 64 bytes of keystream for lane 6
%define %%DATA64B_L7  %8  ; [in] 64 bytes of keystream for lane 7
%define %%DATA64B_L8  %9  ; [in] 64 bytes of keystream for lane 8
%define %%DATA64B_L9  %10 ; [in] 64 bytes of keystream for lane 9
%define %%DATA64B_L10 %11 ; [in] 64 bytes of keystream for lane 10
%define %%DATA64B_L11 %12 ; [in] 64 bytes of keystream for lane 11
%define %%DATA64B_L12 %13 ; [in] 64 bytes of keystream for lane 12
%define %%DATA64B_L13 %14 ; [in] 64 bytes of keystream for lane 13
%define %%DATA64B_L14 %15 ; [in] 64 bytes of keystream for lane 14
%define %%DATA64B_L15 %16 ; [in] 64 bytes of keystream for lane 15
%define %%KMASK       %17 ; [in] K mask containing which dwords will be stored

    mov         r8,    [pKS]
    mov         r9,    [pKS + 8]
    mov         r10,   [pKS + 16]
    mov         r11,   [pKS + 24]
    vmovdqu32   [r8]{%%KMASK},  %%DATA64B_L0
    vmovdqu32   [r9]{%%KMASK},  %%DATA64B_L1
    vmovdqu32   [r10]{%%KMASK}, %%DATA64B_L2
    vmovdqu32   [r11]{%%KMASK}, %%DATA64B_L3

    mov         r8,    [pKS + 32]
    mov         r9,    [pKS + 40]
    mov         r10,   [pKS + 48]
    mov         r11,   [pKS + 56]
    vmovdqu32   [r8]{%%KMASK},  %%DATA64B_L4
    vmovdqu32   [r9]{%%KMASK},  %%DATA64B_L5
    vmovdqu32   [r10]{%%KMASK}, %%DATA64B_L6
    vmovdqu32   [r11]{%%KMASK}, %%DATA64B_L7

    mov         r8,    [pKS + 64]
    mov         r9,    [pKS + 72]
    mov         r10,   [pKS + 80]
    mov         r11,   [pKS + 88]
    vmovdqu32   [r8]{%%KMASK},  %%DATA64B_L8
    vmovdqu32   [r9]{%%KMASK},  %%DATA64B_L9
    vmovdqu32   [r10]{%%KMASK}, %%DATA64B_L10
    vmovdqu32   [r11]{%%KMASK}, %%DATA64B_L11

    mov         r8,    [pKS + 96]
    mov         r9,    [pKS + 104]
    mov         r10,   [pKS + 112]
    mov         r11,   [pKS + 120]
    vmovdqu32   [r8]{%%KMASK},  %%DATA64B_L12
    vmovdqu32   [r9]{%%KMASK},  %%DATA64B_L13
    vmovdqu32   [r10]{%%KMASK}, %%DATA64B_L14
    vmovdqu32   [r11]{%%KMASK}, %%DATA64B_L15

%endmacro

;
;   add_mod31()
;       add two 32-bit args and reduce mod (2^31-1)
;   params
;       %1  - arg1/res
;       %2  - arg2
;   uses
;       zmm2
;   return
;       %1
%macro  add_mod31   2
    vpaddd      %1, %2
    vpsrld      zmm2, %1, 31
    vpandq      %1, MASK31
    vpaddd      %1, zmm2
%endmacro


;
;   rot_mod31()
;       rotate (mult by pow of 2) 32-bit arg and reduce mod (2^31-1)
;   params
;       %1  - arg
;       %2  - # of bits
;   uses
;       zmm2
;   return
;       %1
%macro  rot_mod31   2

    vpslld      zmm2, %1, %2
    vpsrld      %1, %1, (31 - %2)
    vpternlogq  %1, zmm2, MASK31, 0xA8 ; (A | B) & C
%endmacro


;
;   lfsr_updt16()
;
;   params
;       %1 - round number
;   uses
;       zmm0 as input (ZERO or W)
;   return
;
%macro  lfsr_updt16  1
    ;
    ; zmm1  = LFSR_S0
    ; zmm4  = LFSR_S4
    ; zmm10 = LFSR_S10
    ; zmm13 = LFSR_S13
    ; zmm15 = LFSR_S15
    ;
    vmovdqa64   zmm1,  [rax + (( 0 + %1) % 16)*64]
    vmovdqa64   zmm4,  [rax + (( 4 + %1) % 16)*64]
    vmovdqa64   zmm10, [rax + ((10 + %1) % 16)*64]
    vmovdqa64   zmm13, [rax + ((13 + %1) % 16)*64]
    vmovdqa64   zmm15, [rax + ((15 + %1) % 16)*64]

    ; Calculate LFSR feedback
    add_mod31   zmm0, zmm1
    rot_mod31   zmm1, 8
    add_mod31   zmm0, zmm1
    rot_mod31   zmm4, 20
    add_mod31   zmm0, zmm4
    rot_mod31   zmm10, 21
    add_mod31   zmm0, zmm10
    rot_mod31   zmm13, 17
    add_mod31   zmm0, zmm13
    rot_mod31   zmm15, 15
    add_mod31   zmm0, zmm15

    vmovdqa64   [rax + (( 0 + %1) % 16)*64], zmm0

    ; LFSR_S16 = (LFSR_S15++) = eax
%endmacro

;
; Initialize LFSR registers for a single lane
;
; From spec, s_i (LFSR) registers need to be loaded as follows:
;
; For 0 <= i <= 15, let s_i= k_i || d_i || iv_i.
; Where k_i is each byte of the key, d_i is a 15-bit constant
; and iv_i is each byte of the IV.
;
%macro INIT_LFSR 4
%define %%KEY  %1 ;; [in] Key pointer
%define %%IV   %2 ;; [in] IV pointer
%define %%LFSR %3 ;; [out] ZMM register to contain initialized LFSR regs
%define %%ZTMP %4 ;; [clobbered] ZMM temporary register

    vbroadcasti64x2 %%LFSR, [%%KEY]
    vbroadcasti64x2 %%ZTMP, [%%IV]
    vpshufb         %%LFSR, [rel shuf_mask_key]
    vpsrld          %%LFSR, 1
    vpshufb         %%ZTMP, [rel shuf_mask_iv]
    vpternlogq      %%LFSR, %%ZTMP, [rel EK_d64], 0xFE ; A OR B OR C

%endmacro

%macro INIT_16_AVX512 1
%define %%USE_GFNI   %1 ; [in] If 1, then GFNI instructions may be used

%ifdef LINUX
	%define		pKe	rdi
	%define		pIv	rsi
	%define		pState	rdx
%else
	%define		pKe	rcx
	%define		pIv	rdx
	%define		pState	r8
%endif

    FUNC_SAVE

    push    pState      ; Save LFSR Pointer to stack

    ; Set LFSR registers for Packet 1
    mov     r9, [pKe]   ; Load Key 1 pointer
    mov     r10, [pIv]  ; Load IV 1 pointer
    INIT_LFSR r9, r10, zmm0, zmm1

    ; Set LFSR registers for Packets 2-15
%assign idx 1
%assign reg_lfsr 2
%assign reg_tmp 3
%rep 14
    mov     r9, [pKe+8*idx]  ; Load Key N pointer
    mov     r10, [pIv+8*idx] ; Load IV N pointer
    INIT_LFSR r9, r10, APPEND(zmm, reg_lfsr), APPEND(zmm, reg_tmp)

%assign idx (idx + 1)
%assign reg_lfsr (reg_lfsr + 2)
%assign reg_tmp (reg_tmp + 2)
%endrep

    ; Set LFSR registers for Packet 16
    mov     r9, [pKe+8*15]      ; Load Key 16 pointer
    mov     r10, [pIv+8*15]     ; Load IV 16 pointer
    INIT_LFSR r9, r10, zmm30, zmm31

    ; Store LFSR registers in memory (reordering first, so all S0 regs
    ; are together, then all S1 regs... until S15)
    TRANSPOSE16_U32 zmm0, zmm2, zmm4, zmm6, zmm8, zmm10, zmm12, zmm14, \
                    zmm16, zmm18, zmm20, zmm22, zmm24, zmm26, zmm28, zmm30, \
                    zmm1, zmm3, zmm5, zmm7, zmm9, zmm11, zmm13, zmm15, \
                    zmm17, zmm19, zmm21, zmm23, zmm25, zmm27

%assign i 0
%assign j 0
%rep 16
    vmovdqa64 [pState + 64*i], APPEND(zmm, j)
%assign i (i+1)
%assign j (j+2)
%endrep

    ; Load read-only registers
    vmovdqa64  zmm12, [rel mask31]
    mov        edx, 0xAAAAAAAA
    kmovd      k1, edx

    ; Shift LFSR 32-times, update state variables
%assign N 0
%rep 32
    pop     rdx
    lea     rax, [rdx]
    push    rdx

    bits_reorg16 N, 0
    nonlin_fun16 1, %%USE_GFNI
    vpsrld  zmm0,1         ; Shift out LSB of W

    pop     rdx
    lea     rax, [rdx]
    push    rdx

    lfsr_updt16  N           ; W (zmm0) used in LFSR update - not set to zero
%assign N N+1
%endrep

    ; And once more, initial round from keygen phase = 33 times
    pop     rdx
    lea     rax, [rdx]
    push    rdx

    bits_reorg16 0, 0
    nonlin_fun16 0, %%USE_GFNI

    pop     rdx
    lea     rax, [rdx]

    vpxorq    zmm0, zmm0
    lfsr_updt16  0

    FUNC_RESTORE

%endmacro

;;
;; void asm_ZucInitialization_16_avx512(ZucKey16_t *pKeys, ZucIv16_t *pIvs,
;;                                      ZucState16_t *pState)
;;
MKGLOBAL(asm_ZucInitialization_16_avx512,function,internal)
asm_ZucInitialization_16_avx512:

    INIT_16_AVX512 0

    ret

;;
;; void asm_ZucInitialization_16_gfni_avx512(ZucKey16_t *pKeys, ZucIv16_t *pIvs,
;;                                           ZucState16_t *pState)
;;
MKGLOBAL(asm_ZucInitialization_16_gfni_avx512,function,internal)
asm_ZucInitialization_16_gfni_avx512:

    INIT_16_AVX512 1

    ret

;
; Generate N*4 bytes of keystream
; for 16 buffers (where N is number of rounds)
;
%macro KEYGEN_16_AVX512 2
%define %%NUM_ROUNDS    %1 ; [in] Number of 4-byte rounds
%define %%USE_GFNI      %2 ; [in] If 1, then GFNI instructions may be used

%ifdef LINUX
	%define		pState	rdi
	%define		pKS	rsi
%else
	%define		pState	rcx
	%define		pKS	rdx
%endif

    FUNC_SAVE

    ; Load state pointer in RAX
    mov         rax, pState

    ; Load read-only registers
    vmovdqa64   zmm12, [rel mask31]
    mov         r8d, 0xAAAAAAAA
    kmovd       k1, r8d

    ; Generate N*4B of keystream in N rounds
%assign N 1
%assign idx 16
%rep %%NUM_ROUNDS
    bits_reorg16 N, 1, APPEND(zmm, idx)
    nonlin_fun16 1, %%USE_GFNI
    ; OFS_X3 XOR W (zmm0)
    vpxorq      APPEND(zmm, idx), zmm0
    vpxorq      zmm0, zmm0
    lfsr_updt16  N
%assign N N+1
%assign idx (idx + 1)
%endrep

    mov         r8d, ((1 << %%NUM_ROUNDS) - 1)
    kmovd       k1, r8d
    ; ZMM16-31 contain the keystreams for each round
    ; Perform a 32-bit 16x16 transpose to have up to 64 bytes
    ; (NUM_ROUNDS * 4B) of each lane in a different register
    TRANSPOSE16_U32 zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                    zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31, \
                    zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, \
                    zmm8, zmm9, zmm10, zmm11, zmm12, zmm13

    store_kstr16 zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                 zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31, k1

    FUNC_RESTORE

%endmacro

;;
;; void asm_ZucGenKeystream64B_16_avx512(state16_t *pSta, u32* pKeyStr[16])
;;
MKGLOBAL(asm_ZucGenKeystream64B_16_avx512,function,internal)
asm_ZucGenKeystream64B_16_avx512:

    KEYGEN_16_AVX512 16, 0

    ret

;;
;; void asm_ZucGenKeystream8B_16_avx512(state16_t *pSta, u32* pKeyStr[16])
;;
MKGLOBAL(asm_ZucGenKeystream8B_16_avx512,function,internal)
asm_ZucGenKeystream8B_16_avx512:

    KEYGEN_16_AVX512 2, 0

    ret

;;
;; void asm_ZucGenKeystream64B_16_gfni_avx512(state16_t *pSta, u32* pKeyStr[16])
;;
MKGLOBAL(asm_ZucGenKeystream64B_16_gfni_avx512,function,internal)
asm_ZucGenKeystream64B_16_gfni_avx512:

    KEYGEN_16_AVX512 16, 1

    ret

;;
;; void asm_ZucGenKeystream8B_16_gfni_avx512(state16_t *pSta, u32* pKeyStr[16])
;;
MKGLOBAL(asm_ZucGenKeystream8B_16_gfni_avx512,function,internal)
asm_ZucGenKeystream8B_16_gfni_avx512:

    KEYGEN_16_AVX512 2, 1

    ret

%macro CIPHER64B_16_AVX512 1
%define %%USE_GFNI      %1 ; [in] If 1, then GFNI instructions may be used

%ifdef LINUX
        %define         pState  rdi
        %define         pIn     rsi
        %define         pOut    rdx
        %define         bufOff  rcx
%else
        %define         pState  rcx
        %define         pIn     rdx
        %define         pOut    r8
        %define         bufOff  r9
%endif

        FUNC_SAVE

        ; Load state pointer in RAX
        mov     rax, pState

        ; Load read-only registers
        vmovdqa64 zmm12, [rel mask31]
        mov     r10d, 0xAAAAAAAA
        kmovd   k1, r10d

        ; Generate 64B of keystream in 16 rounds
%assign N 1
%assign idx 16
%rep 16
        bits_reorg16 N, 1, APPEND(zmm, idx)
        nonlin_fun16 1, %%USE_GFNI
        ; OFS_X3 XOR W (zmm0)
        vpxorq  APPEND(zmm, idx), zmm0
        vpxorq   zmm0, zmm0
        lfsr_updt16  N
%assign N N+1
%assign idx (idx + 1)
%endrep

        ; ZMM16-31 contain the keystreams for each round
        ; Perform a 32-bit 16x16 transpose to have the 64 bytes
        ; of each lane in a different register
        TRANSPOSE16_U32 zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                        zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31, \
                        zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, \
                        zmm8, zmm9, zmm10, zmm11, zmm12, zmm13

        ;; XOR Input buffer with keystream

        ;; Read all 16 streams using registers r12-15 into registers zmm0-15
%assign i 0
%assign j 0
%assign k 12
%rep 16
        mov     APPEND(r, k), [pIn + i]
        vmovdqu64 APPEND(zmm, j), [APPEND(r, k) + bufOff]
%assign k 12 + ((j + 1) % 4)
%assign j (j + 1)
%assign i (i + 8)
%endrep

        ;; Shuffle all 16 keystreams in registers zmm16-31
%assign i 16
%rep 16
        vpshufb zmm %+i, [rel swap_mask]
%assign i (i+1)
%endrep

        ;; XOR Input (zmm0-15) with Keystreams (zmm16-31)
%assign i 0
%assign j 16
%rep 16
        vpxorq zmm %+j, zmm %+i
%assign i (i + 1)
%assign j (j + 1)
%endrep

        ;; Write output for all 16 buffers (zmm16-31) using registers r12-15
%assign i 0
%assign j 16
%assign k 12
%rep 16
        mov     APPEND(r, k), [pOut + i]
        vmovdqu64 [APPEND(r, k) + bufOff], APPEND(zmm, j)
%assign k 12 + ((j + 1) % 4)
%assign j (j + 1)
%assign i (i + 8)
%endrep

        FUNC_RESTORE

%endmacro

;;
;; void asm_ZucCipher64B_16_avx512(state16_t *pSta, u64 *pIn[16],
;;                                 u64 *pOut[16], u64 bufOff);
MKGLOBAL(asm_ZucCipher64B_16_avx512,function,internal)
asm_ZucCipher64B_16_avx512:

        CIPHER64B_16_AVX512 0

        ret

;;
;; void asm_ZucCipher64B_16_gfni_avx512(state16_t *pSta, u64 *pIn[16],
;;                                      u64 *pOut[16], u64 bufOff);
MKGLOBAL(asm_ZucCipher64B_16_gfni_avx512,function,internal)
asm_ZucCipher64B_16_gfni_avx512:

        CIPHER64B_16_AVX512 1

        ret
;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
