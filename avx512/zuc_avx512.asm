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

align 32
EK_d:
dw	0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
dw	0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC

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

;;
;;   make_u31()
;;
%macro  make_u31    4

%define %%Rt        %1
%define %%Ke        %2
%define %%Ek        %3
%define %%Iv        %4
    xor         %%Rt, %%Rt
    shrd        %%Rt, %%Iv, 8
    shrd        %%Rt, %%Ek, 15
    shrd        %%Rt, %%Ke, 9
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
;   rot_mod32()
;
;   uses zmm7
;
%macro  rot_mod32   3
    vpslld      %1, %2, %3
    vpsrld      zmm7, %2, (32 - %3)

    vporq       %1, zmm7
%endmacro


;
;   nonlin_fun16()
;
;   params
;       %1 == 1, then calculate W
;   uses
;
;   return
;       zmm0 = W value, updates F_R1[] / F_R2[]
;
%macro nonlin_fun16  1

%if (%1 == 1)
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

    rot_mod32   zmm3, zmm1, 2
    rot_mod32   zmm4, zmm1, 10
    rot_mod32   zmm5, zmm1, 18
    rot_mod32   zmm6, zmm1, 24
    vpxorq      zmm1, zmm3
    vpxorq      zmm1, zmm4
    vpxorq      zmm1, zmm5
    vpxorq      zmm1, zmm6      ; XMM1 = U = L1(P)

    rot_mod32   zmm3, zmm2, 8
    rot_mod32   zmm4, zmm2, 14
    rot_mod32   zmm5, zmm2, 22
    rot_mod32   zmm6, zmm2, 30
    vpxorq      zmm2, zmm3
    vpxorq      zmm2, zmm4
    vpxorq      zmm2, zmm5
    vpxorq      zmm2, zmm6      ; XMM2 = V = L2(Q)

    ; Shuffle U and V to have all S0 lookups in XMM1 and all S1 lookups in XMM2

    ; Compress all S0 and S1 input values in each register
    ; S0: Bytes 0-7,16-23,32-39,48-55 S1: Bytes 8-15,24-31,40-47,56-63
    vpshufb     zmm1, [rel S0_S1_shuf]
    ; S1: Bytes 0-7,16-23,32-39,48-55 S0: Bytes 8-15,24-31,40-47,56-63
    vpshufb     zmm2, [rel S1_S0_shuf]

    vshufpd     zmm3, zmm1, zmm2, 0xAA ; All S0 input values
    vshufpd     zmm4, zmm2, zmm1, 0xAA ; All S1 input values

    ; Compute S0 and S1 values
    S0_comput_AVX512  zmm3, zmm1, zmm2
    S1_comput_AVX512  zmm4, zmm1, zmm2, zmm5, zmm6

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

    vporq       %1, zmm2
    vpandq      %1, MASK31
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
    vpxorq      zmm3, zmm3
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
;   key_expand_16()
;
%macro  key_expand_16  2
    movzx       r8d, byte [rdi +  (%1 + 0)]
    movzx       r9d, word [rbx + ((%1 + 0)*2)]
    movzx       r10d, byte [rsi + (%1 + 0)]
    make_u31    r11d, r8d, r9d, r10d
    mov         [rax +  (((%1 + 0)*64)+(%2*4))], r11d

    movzx       r12d, byte [rdi +  (%1 + 1)]
    movzx       r13d, word [rbx + ((%1 + 1)*2)]
    movzx       r14d, byte [rsi +  (%1 + 1)]
    make_u31    r15d, r12d, r13d, r14d
    mov         [rax +  (((%1 + 1)*64)+(%2*4))], r15d
%endmacro


MKGLOBAL(asm_ZucInitialization_16_avx512,function,internal)
asm_ZucInitialization_16_avx512:

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

    lea     rax, [pState]      ; load pointer to LFSR
    push    pState             ; Save LFSR Pointer to stack

    ; setup the key pointer for first buffer key expand
    mov     rbx, [pKe]      ; load the pointer to the array of keys into rbx

    push    pKe             ; save rdi (key pointer) to the stack
    lea     rdi, [rbx]      ; load the pointer to the first key into rdi


    ; setup the IV pointer for first buffer key expand
    mov     rcx, [pIv]      ; load the pointer to the array of IV's
    push    pIv             ; save the IV pointer to the stack
    lea     rsi, [rcx]      ; load the first IV pointer

    lea     rbx, [EK_d]     ; load D variables

    ; Expand key packet 1
    key_expand_16  0, 0
    key_expand_16  2, 0
    key_expand_16  4, 0
    key_expand_16  6, 0
    key_expand_16  8, 0
    key_expand_16  10, 0
    key_expand_16  12, 0
    key_expand_16  14, 0


    ;; Expand keys for packets 2-15
%assign idx 1
%rep 14
    pop     rdx             ; get IV array pointer from Stack
    mov     rcx, [rdx+8*idx]      ; load offset to next IV in array
    lea     rsi, [rcx]    ; load pointer to next IV

    pop     rbx             ; get Key array pointer from Stack
    mov     rcx, [rbx+8*idx]      ; load offset to next key in array
    lea     rdi, [rcx]    ; load pointer to next Key

    push    rbx             ; save Key pointer
    push    rdx             ; save IV pointer

    lea     rbx, [EK_d]

    ; Expand key packet N
    key_expand_16  0, idx
    key_expand_16  2, idx
    key_expand_16  4, idx
    key_expand_16  6, idx
    key_expand_16  8, idx
    key_expand_16  10, idx
    key_expand_16  12, idx
    key_expand_16  14, idx
%assign idx (idx + 1)
%endrep

    ;; Expand key for sixteenth packet
    pop     rdx             ; get IV array pointer from Stack
    mov     rcx, [rdx+8*15]      ; load offset to IV 16 in array
    lea     rsi, [rcx]   ; load pointer to IV 16

    pop     rbx             ; get Key array pointer from Stack
    mov     rcx, [rbx+8*15]      ; load offset to key 16 in array
    lea     rdi, [rcx]   ; load pointer to Key 16
    lea     rbx, [EK_d]

    ; Expand key packet 16
    key_expand_16  0, 15
    key_expand_16  2, 15
    key_expand_16  4, 15
    key_expand_16  6, 15
    key_expand_16  8, 15
    key_expand_16  10, 15
    key_expand_16  12, 15
    key_expand_16  14, 15

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
    nonlin_fun16 1
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
    nonlin_fun16 0

    pop     rdx
    lea     rax, [rdx]

    vpxorq    zmm0, zmm0
    lfsr_updt16  0

    FUNC_RESTORE

    ret

;
; Generate N*4 bytes of keystream
; for 16 buffers (where N is number of rounds)
;
%macro KEYGEN_16_AVX512 1
%define %%NUM_ROUNDS    %1 ; [in] Number of 4-byte rounds

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
    nonlin_fun16 1
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
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(asm_ZucGenKeystream64B_16_avx512,function,internal)
asm_ZucGenKeystream64B_16_avx512:

    KEYGEN_16_AVX512 16

    ret

;;
;; void asm_ZucGenKeystream8B_16_avx512(state16_t *pSta, u32* pKeyStr[16])
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(asm_ZucGenKeystream8B_16_avx512,function,internal)
asm_ZucGenKeystream8B_16_avx512:

    KEYGEN_16_AVX512 2

    ret

;;
;; void asm_ZucCipher64B_16_avx512(state4_t *pSta, u32 *pKeyStr[16], u64 *pIn[16],
;;                             u64 *pOut[16], u64 bufOff);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;  R8     - pIn
;;  R9     - pOut
;;  rsp+40 - bufOff
;;
;; LIN64
;;  RDI - pSta
;;  RSI - pKeyStr
;;  RDX - pIn
;;  RCX - pOut
;;  R8  - bufOff
;;
MKGLOBAL(asm_ZucCipher64B_16_avx512,function,internal)
asm_ZucCipher64B_16_avx512:

%ifdef LINUX
        %define         pState  rdi
        %define         pKS     rsi
        %define         pIn     rdx
        %define         pOut    rcx
        %define         bufOff  r8
%else
        %define         pState  rcx
        %define         pKS     rdx
        %define         pIn     r8
        %define         pOut    r9
        %define         bufOff  r10
%endif

        ;; Store parameter from stack in register
%ifndef LINUX
        mov     bufOff, [rsp + 40]
%endif
        FUNC_SAVE

        ; Store 16 keystream pointers and input registers in the stack
        sub     rsp, 16*8 + 4*8

%assign i 0
%rep 2
        vmovdqu64 zmm0, [pKS + 64*i]
        vmovdqu64 [rsp + 64*i], zmm0
%assign i (i+1)
%endrep

        mov     [rsp + 128], pKS
        mov     [rsp + 128 + 8], pIn
        mov     [rsp + 128 + 16], pOut
        mov     [rsp + 128 + 24], bufOff

        ; Load state pointer in RAX
        mov     rax, pState

        ; Load read-only registers
        vmovdqa64 zmm12, [rel mask31]
        mov     edx, 0xAAAAAAAA
        kmovd   k1, edx

        ; Generate 64B of keystream in 16 rounds
%assign N 1
%assign idx 16
%rep 16
        bits_reorg16 N, 1, APPEND(zmm, idx)
        nonlin_fun16 1
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

        ;; Restore input parameters
        mov     pKS,    [rsp + 128]
        mov     pIn,    [rsp + 128 + 8]
        mov     pOut,   [rsp + 128 + 16]
        mov     bufOff, [rsp + 128 + 24]

        ;; Restore rsp pointer to value before pushing keystreams
        ;; and input parameters
        add     rsp, 16*8 + 4*8

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

        ret

;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
