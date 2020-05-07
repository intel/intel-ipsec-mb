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
%include "include/transpose_avx2.asm"

%define APPEND(a,b) a %+ b

section .data
default rel

align 32
Ek_d:
dd	0x0044D700, 0x0026BC00, 0x00626B00, 0x00135E00, 0x00578900, 0x0035E200, 0x00713500, 0x0009AF00
dd	0x004D7800, 0x002F1300, 0x006BC400, 0x001AF100, 0x005E2600, 0x003C4D00, 0x00789A00, 0x0047AC00

align 32
shuf_mask_key:
dd      0x00FFFFFF, 0x01FFFFFF, 0x02FFFFFF, 0x03FFFFFF, 0x04FFFFFF, 0x05FFFFFF, 0x06FFFFFF, 0x07FFFFFF,
dd      0x08FFFFFF, 0x09FFFFFF, 0x0AFFFFFF, 0x0BFFFFFF, 0x0CFFFFFF, 0x0DFFFFFF, 0x0EFFFFFF, 0x0FFFFFFF,

align 32
shuf_mask_iv:
dd      0xFFFFFF00, 0xFFFFFF01, 0xFFFFFF02, 0xFFFFFF03, 0xFFFFFF04, 0xFFFFFF05, 0xFFFFFF06, 0xFFFFFF07,
dd      0xFFFFFF08, 0xFFFFFF09, 0xFFFFFF0A, 0xFFFFFF0B, 0xFFFFFF0C, 0xFFFFFF0D, 0xFFFFFF0E, 0xFFFFFF0F,

align 32
mask31:
dd	0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF,
dd	0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF,

align 32
swap_mask:
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c


align 32
S1_S0_shuf:
db      0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F
db      0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F

align 32
S0_S1_shuf:
db      0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
db      0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,

align 32
rev_S1_S0_shuf:
db      0x00, 0x08, 0x01, 0x09, 0x02, 0x0A, 0x03, 0x0B, 0x04, 0x0C, 0x05, 0x0D, 0x06, 0x0E, 0x07, 0x0F
db      0x00, 0x08, 0x01, 0x09, 0x02, 0x0A, 0x03, 0x0B, 0x04, 0x0C, 0x05, 0x0D, 0x06, 0x0E, 0x07, 0x0F

align 32
rev_S0_S1_shuf:
db      0x08, 0x00, 0x09, 0x01, 0x0A, 0x02, 0x0B, 0x03, 0x0C, 0x04, 0x0D, 0x05, 0x0E, 0x06, 0x0F, 0x07
db      0x08, 0x00, 0x09, 0x01, 0x0A, 0x02, 0x0B, 0x03, 0x0C, 0x04, 0x0D, 0x05, 0x0E, 0x06, 0x0F, 0x07

align 32
rot8_mod32:
db      0x03, 0x00, 0x01, 0x02, 0x07, 0x04, 0x05, 0x06,
db      0x0B, 0x08, 0x09, 0x0A, 0x0F, 0x0C, 0x0D, 0x0E
db      0x03, 0x00, 0x01, 0x02, 0x07, 0x04, 0x05, 0x06,
db      0x0B, 0x08, 0x09, 0x0A, 0x0F, 0x0C, 0x0D, 0x0E

align 32
rot16_mod32:
db      0x02, 0x03, 0x00, 0x01, 0x06, 0x07, 0x04, 0x05,
db      0x0A, 0x0B, 0x08, 0x09, 0x0E, 0x0F, 0x0C, 0x0D
db      0x02, 0x03, 0x00, 0x01, 0x06, 0x07, 0x04, 0x05,
db      0x0A, 0x0B, 0x08, 0x09, 0x0E, 0x0F, 0x0C, 0x0D

align 32
rot24_mod32:
db      0x01, 0x02, 0x03, 0x00, 0x05, 0x06, 0x07, 0x04,
db      0x09, 0x0A, 0x0B, 0x08, 0x0D, 0x0E, 0x0F, 0x0C
db      0x01, 0x02, 0x03, 0x00, 0x05, 0x06, 0x07, 0x04,
db      0x09, 0x0A, 0x0B, 0x08, 0x0D, 0x0E, 0x0F, 0x0C

section .text
align 64

%define MASK31  ymm12

%define OFS_R1  (16*(4*8))
%define OFS_R2  (OFS_R1 + (4*8))
%define OFS_X0  (OFS_R2 + (4*8))
%define OFS_X1  (OFS_X0 + (4*8))
%define OFS_X2  (OFS_X1 + (4*8))

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

%macro REORDER_LFSR 1
%define %%STATE      %1

%assign i 0
%rep 16
    vmovdqa APPEND(ymm,i), [%%STATE + 32*i]
%assign i (i+1)
%endrep

%assign i 0
%assign j 8
%rep 16
    vmovdqa [%%STATE + 32*i], APPEND(ymm,j)
%assign i (i+1)
%assign j ((j+1) % 16)
%endrep


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
;   bits_reorg8()
;
;   params
;       %1 - round number
;       %2 - Calculate X3 (1 = yes)
;       %3 - YMM register storing X3
;       rax - LFSR pointer
;   uses
;
;   return
;
%macro  bits_reorg8 2-3
    ;
    ; ymm15 = LFSR_S15
    ; ymm14 = LFSR_S14
    ; ymm11 = LFSR_S11
    ; ymm9  = LFSR_S9
    ; ymm7  = LFSR_S7
    ; ymm5  = LFSR_S5
    ; ymm2  = LFSR_S2
    ; ymm0  = LFSR_S0
    ;
    vmovdqa     ymm15, [rax + ((15 + %1) % 16)*32]
    vmovdqa     ymm14, [rax + ((14 + %1) % 16)*32]
    vmovdqa     ymm11, [rax + ((11 + %1) % 16)*32]
    vmovdqa     ymm9,  [rax + (( 9 + %1) % 16)*32]
    vmovdqa     ymm7,  [rax + (( 7 + %1) % 16)*32]
    vmovdqa     ymm5,  [rax + (( 5 + %1) % 16)*32]
    vmovdqa     ymm2,  [rax + (( 2 + %1) % 16)*32]
    vmovdqa     ymm0,  [rax + (( 0 + %1) % 16)*32]

    vpxor       ymm1, ymm1
    vpslld      ymm15, 1
    vpblendw    ymm3,  ymm14, ymm1, 0xAA
    vpblendw    ymm15, ymm3, ymm15, 0xAA

    vmovdqa     [rax + OFS_X0], ymm15   ; BRC_X0
    vpslld      ymm11, 16
    vpsrld      ymm9, 15
    vpor        ymm11, ymm9
    vmovdqa     [rax + OFS_X1], ymm11   ; BRC_X1
    vpslld      ymm7, 16
    vpsrld      ymm5, 15
    vpor        ymm7, ymm5
    vmovdqa     [rax + OFS_X2], ymm7    ; BRC_X2
%if (%2 == 1)
    vpslld      ymm2, 16
    vpsrld      ymm0, 15
    vpor        %3, ymm2, ymm0 ; Store BRC_X3 in YMM register
%endif
%endmacro

;
;   rot_mod32()
;
;   uses ymm7
;
%macro  rot_mod32   3
%if (%3 == 8)
    vpshufb %1, %2, [rel rot8_mod32]
%elif (%3 == 16)
    vpshufb %1, %2, [rel rot16_mod32]
%elif (%3 == 24)
    vpshufb %1, %2, [rel rot24_mod32]
%else
    vpslld      %1, %2, %3
    vpsrld      ymm7, %2, (32 - %3)

    vpor        %1, ymm7
%endif
%endmacro


;
;   nonlin_fun8()
;
;   params
;       %1 == 1, then calculate W
;   uses
;
;   return
;       ymm0 = W value, updates F_R1[] / F_R2[]
;
%macro nonlin_fun8  1

%if (%1 == 1)
    vmovdqa     ymm0, [rax + OFS_X0]
    vpxor       ymm0, [rax + OFS_R1]
    vpaddd      ymm0, [rax + OFS_R2]    ; W = (BRC_X0 ^ F_R1) + F_R2
%endif

    vmovdqa     ymm1, [rax + OFS_R1]
    vmovdqa     ymm2, [rax + OFS_R2]
    vpaddd      ymm1, [rax + OFS_X1]    ; W1 = F_R1 + BRC_X1
    vpxor       ymm2, [rax + OFS_X2]    ; W2 = F_R2 ^ BRC_X2

    vpslld      ymm3, ymm1, 16
    vpsrld      ymm4, ymm1, 16
    vpslld      ymm5, ymm2, 16
    vpsrld      ymm6, ymm2, 16
    vpor        ymm1, ymm3, ymm6
    vpor        ymm2, ymm4, ymm5

    rot_mod32   ymm3, ymm1, 2
    rot_mod32   ymm4, ymm1, 10
    rot_mod32   ymm5, ymm1, 18
    rot_mod32   ymm6, ymm1, 24
    vpxor       ymm1, ymm3
    vpxor       ymm1, ymm4
    vpxor       ymm1, ymm5
    vpxor       ymm1, ymm6      ; XMM1 = U = L1(P)

    rot_mod32   ymm3, ymm2, 8
    rot_mod32   ymm4, ymm2, 14
    rot_mod32   ymm5, ymm2, 22
    rot_mod32   ymm6, ymm2, 30
    vpxor       ymm2, ymm3
    vpxor       ymm2, ymm4
    vpxor       ymm2, ymm5
    vpxor       ymm2, ymm6      ; XMM2 = V = L2(Q)

    ; Shuffle U and V to have all S0 lookups in XMM1 and all S1 lookups in XMM2

    ; Compress all S0 and S1 input values in each register
    vpshufb     ymm1, [rel S0_S1_shuf] ; S0: Bytes 0-7,16-23 S1: Bytes 8-15,24-31
    vpshufb     ymm2, [rel S1_S0_shuf] ; S1: Bytes 0-7,16-23 S0: Bytes 8-15,24-31

    vshufpd     ymm3, ymm1, ymm2, 0xA ; All S0 input values
    vshufpd     ymm4, ymm2, ymm1, 0xA ; All S1 input values

    ; Compute S0 and S1 values
    S0_comput_AVX2  ymm3, ymm1, ymm2
    S1_comput_AVX2  ymm4, ymm1, ymm2, ymm5

    ; Need to shuffle back ymm1 & ymm2 before storing output
    ; (revert what was done before S0 and S1 computations)
    vshufpd    ymm1, ymm3, ymm4, 0xA
    vshufpd    ymm2, ymm4, ymm3, 0xA

    vpshufb     ymm1, [rel rev_S0_S1_shuf]
    vpshufb     ymm2, [rel rev_S1_S0_shuf]

    vmovdqa     [rax + OFS_R1], ymm1
    vmovdqa     [rax + OFS_R2], ymm2
%endmacro

;
;   store32B_kstr8()
;
%macro  store32B_kstr8 8
%define %%DATA32B_L0  %1  ; [in] 32 bytes of keystream for lane 0
%define %%DATA32B_L1  %2  ; [in] 32 bytes of keystream for lane 1
%define %%DATA32B_L2  %3  ; [in] 32 bytes of keystream for lane 2
%define %%DATA32B_L3  %4  ; [in] 32 bytes of keystream for lane 3
%define %%DATA32B_L4  %5  ; [in] 32 bytes of keystream for lane 4
%define %%DATA32B_L5  %6  ; [in] 32 bytes of keystream for lane 5
%define %%DATA32B_L6  %7  ; [in] 32 bytes of keystream for lane 6
%define %%DATA32B_L7  %8  ; [in] 32 bytes of keystream for lane 7

    mov         rcx, [rsp]
    mov         rdx, [rsp + 8]
    mov         r8,  [rsp + 16]
    mov         r9,  [rsp + 24]
    vmovdqu     [rcx], %%DATA32B_L0
    vmovdqu     [rdx], %%DATA32B_L1
    vmovdqu     [r8],  %%DATA32B_L2
    vmovdqu     [r9],  %%DATA32B_L3

    mov         rcx, [rsp + 32]
    mov         rdx, [rsp + 40]
    mov         r8,  [rsp + 48]
    mov         r9,  [rsp + 56]
    vmovdqu     [rcx], %%DATA32B_L4
    vmovdqu     [rdx], %%DATA32B_L5
    vmovdqu     [r8],  %%DATA32B_L6
    vmovdqu     [r9],  %%DATA32B_L7

%endmacro

;
;   store4B_kstr8()
;
;   params
;
;   %1 - YMM register with OFS_X3
;   return
;
%macro  store4B_kstr8 1
    mov         rcx, [rsp]
    mov         rdx, [rsp + 8]
    mov         r8,  [rsp + 16]
    mov         r9,  [rsp + 24]
    vpextrd     r15d, XWORD(%1), 3
    vpextrd     r14d, XWORD(%1), 2
    vpextrd     r13d, XWORD(%1), 1
    vmovd       r12d, XWORD(%1)
    mov         [r9], r15d
    mov         [r8], r14d
    mov         [rdx], r13d
    mov         [rcx], r12d
    add         rcx, 4
    add         rdx, 4
    add         r8, 4
    add         r9, 4
    mov         [rsp],      rcx
    mov         [rsp + 8],  rdx
    mov         [rsp + 16], r8
    mov         [rsp + 24], r9

    vextracti128 XWORD(%1), %1, 1
    mov         rcx, [rsp + 32]
    mov         rdx, [rsp + 40]
    mov         r8,  [rsp + 48]
    mov         r9,  [rsp + 56]
    vpextrd     r15d, XWORD(%1), 3
    vpextrd     r14d, XWORD(%1), 2
    vpextrd     r13d, XWORD(%1), 1
    vmovd       r12d, XWORD(%1)
    mov         [r9], r15d
    mov         [r8], r14d
    mov         [rdx], r13d
    mov         [rcx], r12d
    add         rcx, 4
    add         rdx, 4
    add         r8, 4
    add         r9, 4
    mov         [rsp + 32], rcx
    mov         [rsp + 40], rdx
    mov         [rsp + 48], r8
    mov         [rsp + 56], r9

%endmacro


;
;   add_mod31()
;       add two 32-bit args and reduce mod (2^31-1)
;   params
;       %1  - arg1/res
;       %2  - arg2
;   uses
;       ymm2
;   return
;       %1
%macro  add_mod31   2
    vpaddd      %1, %2
    vpsrld      ymm2, %1, 31
    vpand       %1, MASK31
    vpaddd      %1, ymm2
%endmacro


;
;   rot_mod31()
;       rotate (mult by pow of 2) 32-bit arg and reduce mod (2^31-1)
;   params
;       %1  - arg
;       %2  - # of bits
;   uses
;       ymm2
;   return
;       %1
%macro  rot_mod31   2

    vpslld      ymm2, %1, %2
    vpsrld      %1, %1, (31 - %2)

    vpor        %1, ymm2
    vpand       %1, MASK31
%endmacro


;
;   lfsr_updt8()
;
;   params
;       %1 - round number
;   uses
;       ymm0 as input (ZERO or W)
;   return
;
%macro  lfsr_updt8  1
    ;
    ; ymm1  = LFSR_S0
    ; ymm4  = LFSR_S4
    ; ymm10 = LFSR_S10
    ; ymm13 = LFSR_S13
    ; ymm15 = LFSR_S15
    ;
    vmovdqa     ymm1,  [rax + (( 0 + %1) % 16)*32]
    vmovdqa     ymm4,  [rax + (( 4 + %1) % 16)*32]
    vmovdqa     ymm10, [rax + ((10 + %1) % 16)*32]
    vmovdqa     ymm13, [rax + ((13 + %1) % 16)*32]
    vmovdqa     ymm15, [rax + ((15 + %1) % 16)*32]

    ; Calculate LFSR feedback
    add_mod31   ymm0, ymm1
    rot_mod31   ymm1, 8
    add_mod31   ymm0, ymm1
    rot_mod31   ymm4, 20
    add_mod31   ymm0, ymm4
    rot_mod31   ymm10, 21
    add_mod31   ymm0, ymm10
    rot_mod31   ymm13, 17
    add_mod31   ymm0, ymm13
    rot_mod31   ymm15, 15
    add_mod31   ymm0, ymm15

    vmovdqa     [rax + (( 0 + %1) % 16)*32], ymm0

    ; LFSR_S16 = (LFSR_S15++) = eax
%endmacro

;
; Initialize LFSR registers for a single lane
;
; This macro initializes 8 LFSR registers are a time.
; so it needs to be called twice.
;
; From spec, s_i (LFSR) registers need to be loaded as follows:
;
; For 0 <= i <= 15, let s_i= k_i || d_i || iv_i.
; Where k_i is each byte of the key, d_i is a 15-bit constant
; and iv_i is each byte of the IV.
;
%macro INIT_LFSR 7
%define %%KEY       %1 ;; [in] Key pointer
%define %%IV        %2 ;; [in] IV pointer
%define %%SHUF_KEY  %3 ;; [in] Shuffle key mask
%define %%SHUF_IV   %4 ;; [in] Shuffle key mask
%define %%EKD_MASK  %5 ;; [in] Shuffle key mask
%define %%LFSR      %6 ;; [out] YMM register to contain initialized LFSR regs
%define %%YTMP      %7 ;; [clobbered] YMM temporary register

    vbroadcastf128  %%LFSR, [%%KEY]
    vbroadcastf128  %%YTMP, [%%IV]
    vpshufb         %%LFSR, %%SHUF_KEY
    vpsrld          %%LFSR, 1
    vpshufb         %%YTMP, %%SHUF_IV
    vpor            %%LFSR, %%YTMP
    vpor            %%LFSR, %%EKD_MASK

%endmacro


MKGLOBAL(asm_ZucInitialization_8_avx2,function,internal)
asm_ZucInitialization_8_avx2:

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

    ;;; Initialize all LFSR registers in two steps:
    ;;; first, registers 0-7, then registers 8-15

%assign off 0
%rep 2
    ; Set read-only registers for shuffle masks for key, IV and Ek_d for 8 registers
    vmovdqa ymm13, [rel shuf_mask_key + off]
    vmovdqa ymm14, [rel shuf_mask_iv + off]
    vmovdqa ymm15, [rel Ek_d + off]

    ; Set 8xLFSR registers for all packets
%assign idx 0
%rep 8
    mov     r9, [pKe+8*idx]  ; Load Key N pointer
    mov     r10, [pIv+8*idx] ; Load IV N pointer
    INIT_LFSR r9, r10, ymm13, ymm14, ymm15, APPEND(ymm, idx), ymm12
%assign idx (idx + 1)
%endrep

    ; Store 8xLFSR registers in memory (reordering first,
    ; so all SX registers are together)
    TRANSPOSE8_U32  ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, ymm9

%assign i 0
%rep 8
    vmovdqa [pState + 8*off + 32*i], APPEND(ymm, i)
%assign i (i+1)
%endrep

%assign off (off + 32)
%endrep

    ; Load read-only registers
    vmovdqa  ymm12, [rel mask31]

    mov rax, pState

    ; Shift LFSR 32-times, update state variables
%assign N 0
%rep 32
    bits_reorg8 N, 0
    nonlin_fun8 1
    vpsrld  ymm0,1         ; Shift out LSB of W
    lfsr_updt8  N           ; W (ymm0) used in LFSR update - not set to zero
%assign N N+1
%endrep

    ; And once more, initial round from keygen phase = 33 times
    bits_reorg8 0, 0
    nonlin_fun8 0

    vpxor    ymm0, ymm0
    lfsr_updt8  0

    FUNC_RESTORE

    ret

;
; Generate N*4 bytes of keystream
; for 8 buffers (where N is number of rounds)
;
%macro KEYGEN_8_AVX2 1
%define %%NUM_ROUNDS    %1 ; [in] Number of 4-byte rounds

%ifdef LINUX
	%define		pState	rdi
	%define		pKS	rsi
%else
	%define		pState	rcx
	%define		pKS	rdx
%endif

    FUNC_SAVE

    ; Store 8 keystream pointers on the stack
    ; and reserve memory for storing keystreams for all 8 buffers
    mov     r10, rsp
    sub     rsp, (8*8 + %%NUM_ROUNDS * 32)
    and     rsp, -31

%assign i 0
%rep 2
    vmovdqa     ymm0, [pKS + 32*i]
    vmovdqa     [rsp + 32*i], ymm0
%assign i (i+1)
%endrep

    ; Load state pointer in RAX
    mov         rax, pState

    ; Load read-only registers
    vmovdqa     ymm12, [rel mask31]

    ; Generate N*4B of keystream in N rounds
%assign N 1
%rep %%NUM_ROUNDS
    bits_reorg8 N, 1, ymm10
    nonlin_fun8 1
    ; OFS_X3 XOR W (ymm0) and store in stack
    vpxor   ymm10, ymm0
    vmovdqa [rsp + 64 + (N-1)*32], ymm10
    vpxor        ymm0, ymm0
    lfsr_updt8  N
%assign N N+1
%endrep

%if (%%NUM_ROUNDS == 8)
    ;; Load all OFS_X3
    vmovdqa xmm0,[rsp + 64]
    vmovdqa xmm1,[rsp + 64 + 32*1]
    vmovdqa xmm2,[rsp + 64 + 32*2]
    vmovdqa xmm3,[rsp + 64 + 32*3]
    vmovdqa xmm4,[rsp + 64 + 16]
    vmovdqa xmm5,[rsp + 64 + 32*1 + 16]
    vmovdqa xmm6,[rsp + 64 + 32*2 + 16]
    vmovdqa xmm7,[rsp + 64 + 32*3 + 16]

    vinserti128 ymm0, ymm0, [rsp + 64 + 32*4], 0x01
    vinserti128 ymm1, ymm1, [rsp + 64 + 32*5], 0x01
    vinserti128 ymm2, ymm2, [rsp + 64 + 32*6], 0x01
    vinserti128 ymm3, ymm3, [rsp + 64 + 32*7], 0x01
    vinserti128 ymm4, ymm4, [rsp + 64 + 32*4 + 16], 0x01
    vinserti128 ymm5, ymm5, [rsp + 64 + 32*5 + 16], 0x01
    vinserti128 ymm6, ymm6, [rsp + 64 + 32*6 + 16], 0x01
    vinserti128 ymm7, ymm7, [rsp + 64 + 32*7 + 16], 0x01

    TRANSPOSE8_U32_PRELOADED ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, ymm9

    store32B_kstr8 ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7

    ;; Reorder LFSR registers, as not all 16 rounds have been completed
    ;; (No need to do if NUM_ROUNDS != 8, as it would indicate that
    ;; these would be the final rounds)
    REORDER_LFSR rax

%else ;; NUM_ROUNDS == 8
%assign idx 0
%rep %%NUM_ROUNDS
    vmovdqa APPEND(ymm, idx), [rsp + 64 + idx*32]
    store4B_kstr8 APPEND(ymm, idx)
%assign idx (idx + 1)
%endrep
%endif ;; NUM_ROUNDS == 8

        ;; Clear stack frame containing keystream information
%ifdef SAFE_DATA
        vpxor   ymm0, ymm0
%assign i 0
%rep (2+%%NUM_ROUNDS)
	vmovdqa [rsp + i*32], ymm0
%assign i (i+1)
%endrep
%endif

    ;; Restore rsp pointer
    mov         rsp, r10

    FUNC_RESTORE

%endmacro

;;
;; void asm_ZucGenKeystream32B_8_avx2(state8_t *pSta, u32* pKeyStr[8])
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(asm_ZucGenKeystream32B_8_avx2,function,internal)
asm_ZucGenKeystream32B_8_avx2:

    KEYGEN_8_AVX2 8

    ret

;;
;; void asm_ZucGenKeystream8B_8_avx2(state8_t *pSta, u32* pKeyStr[8])
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(asm_ZucGenKeystream8B_8_avx2,function,internal)
asm_ZucGenKeystream8B_8_avx2:

    KEYGEN_8_AVX2 2

    ret

;;
;; void asm_ZucCipher32B_8_avx2(state4_t *pSta, u64 *pIn[8],
;;                             u64 *pOut[8], u64 bufOff);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pIn
;;  R8     - pOut
;;  R9     - bufOff
;;
;; LIN64
;;  RDI - pSta
;;  RSI - pIn
;;  RDX - pOut
;;  RCX  - bufOff
;;
MKGLOBAL(asm_ZucCipher32B_8_avx2,function,internal)
asm_ZucCipher32B_8_avx2:

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
        vmovdqa ymm12, [rel mask31]

        ; Allocate stack frame to store keystreams
        mov     r10, rsp
        sub     rsp, 32*8
        and     rsp, -31

        ; Generate 32B of keystream in 8 rounds
%assign idx 0
%assign N 1
%rep 8
        bits_reorg8 N, 1, ymm10
        nonlin_fun8 1
        ; OFS_XR XOR W (ymm0)
        vpxor   ymm10, ymm0
        vmovdqa [rsp + idx*32], ymm10
        vpxor   ymm0, ymm0
        lfsr_updt8  N
%assign N N+1
%assign idx (idx+1)
%endrep

%assign N 0
%assign idx 8
%rep 8
        vmovdqa APPEND(ymm, idx), [rsp + N*32]
%assign N N+1
%assign idx (idx+1)
%endrep

        TRANSPOSE8_U32 ymm8, ymm9, ymm10, ymm11, ymm12, ymm13, ymm14, \
                       ymm15, ymm0, ymm1
        ;; XOR Input buffer with keystream in rounds of 32B

        ;; Read all 8 streams
        mov     r12, [pIn]
        mov     r13, [pIn + 8]
        mov     r14, [pIn + 16]
        mov     r15, [pIn + 24]
        vmovdqu ymm0, [r12 + bufOff]
        vmovdqu ymm1, [r13 + bufOff]
        vmovdqu ymm2, [r14 + bufOff]
        vmovdqu ymm3, [r15 + bufOff]
        mov     r12, [pIn + 32]
        mov     r13, [pIn + 40]
        mov     r14, [pIn + 48]
        mov     r15, [pIn + 56]
        vmovdqu ymm4, [r12 + bufOff]
        vmovdqu ymm5, [r13 + bufOff]
        vmovdqu ymm6, [r14 + bufOff]
        vmovdqu ymm7, [r15 + bufOff]

        ; Shuffle all keystreams
        vpshufb ymm8,  [rel swap_mask]
        vpshufb ymm9,  [rel swap_mask]
        vpshufb ymm10, [rel swap_mask]
        vpshufb ymm11, [rel swap_mask]

        vpshufb ymm12, [rel swap_mask]
        vpshufb ymm13, [rel swap_mask]
        vpshufb ymm14, [rel swap_mask]
        vpshufb ymm15, [rel swap_mask]

        ;; XOR Input with Keystream and write output for all 8 buffers
        vpxor   ymm8,  ymm0
        vpxor   ymm9,  ymm1
        vpxor   ymm10, ymm2
        vpxor   ymm11, ymm3

        vpxor   ymm12, ymm4
        vpxor   ymm13, ymm5
        vpxor   ymm14, ymm6
        vpxor   ymm15, ymm7

        mov     r12, [pOut]
        mov     r13, [pOut + 8]
        mov     r14, [pOut + 16]
        mov     r15, [pOut + 24]

        vmovdqu [r12 + bufOff], ymm8
        vmovdqu [r13 + bufOff], ymm9
        vmovdqu [r14 + bufOff], ymm10
        vmovdqu [r15 + bufOff], ymm11

        mov     r12, [pOut + 32]
        mov     r13, [pOut + 40]
        mov     r14, [pOut + 48]
        mov     r15, [pOut + 56]

        vmovdqu [r12 + bufOff], ymm12
        vmovdqu [r13 + bufOff], ymm13
        vmovdqu [r14 + bufOff], ymm14
        vmovdqu [r15 + bufOff], ymm15

        ;; Reorder LFSR registers, as not all 16 rounds have been completed
        REORDER_LFSR rax

        ;; Clear stack frame containing keystream information
%ifdef SAFE_DATA
        vpxor   ymm0, ymm0
%assign i 0
%rep 8
	vmovdqa [rsp + i*32], ymm0
%assign i (i+1)
%endrep
%endif
        ; Restore rsp
        mov     rsp, r10

        FUNC_RESTORE

        ret

;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
