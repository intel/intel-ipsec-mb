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

section .data
default rel

align 32
EK_d:
dw	0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
dw	0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC

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
%define OFS_X3  (OFS_X2 + (4*8))

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
;   bits_reorg8()
;
;   params
;       %1 - round number
;       rax - LFSR pointer
;   uses
;
;   return
;
%macro  bits_reorg8 1
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
    vpslld      ymm2, 16
    vpsrld      ymm0, 15
    vpor        ymm2, ymm0
    vmovdqa     [rax + OFS_X3], ymm2    ; BRC_X3
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
;   store_kstr8()
;
;   params
;
;   uses
;       ymm0 as input
;   return
;
%macro  store_kstr8 0
    vpxor       ymm0, [rax + OFS_X3]

    mov         rcx, [rsp]
    mov         rdx, [rsp + 8]
    mov         r8,  [rsp + 16]
    mov         r9,  [rsp + 24]
    vpextrd     r15d, xmm0, 3
    vpextrd     r14d, xmm0, 2
    vpextrd     r13d, xmm0, 1
    vmovd       r12d, xmm0
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

    vextracti128   xmm0, ymm0, 1
    mov         rcx, [rsp + 32]
    mov         rdx, [rsp + 40]
    mov         r8,  [rsp + 48]
    mov         r9,  [rsp + 56]
    vpextrd     r15d, xmm0, 3
    vpextrd     r14d, xmm0, 2
    vpextrd     r13d, xmm0, 1
    vmovd       r12d, xmm0
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
;   key_expand_8()
;
%macro  key_expand_8  2
    movzx       r8d, byte [rdi +  (%1 + 0)]
    movzx       r9d, word [rbx + ((%1 + 0)*2)]
    movzx       r10d, byte [rsi + (%1 + 0)]
    make_u31    r11d, r8d, r9d, r10d
    mov         [rax +  (((%1 + 0)*32)+(%2*4))], r11d

    movzx       r12d, byte [rdi +  (%1 + 1)]
    movzx       r13d, word [rbx + ((%1 + 1)*2)]
    movzx       r14d, byte [rsi +  (%1 + 1)]
    make_u31    r15d, r12d, r13d, r14d
    mov         [rax +  (((%1 + 1)*32)+(%2*4))], r15d
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
    key_expand_8  0, 0
    key_expand_8  2, 0
    key_expand_8  4, 0
    key_expand_8  6, 0
    key_expand_8  8, 0
    key_expand_8  10, 0
    key_expand_8  12, 0
    key_expand_8  14, 0


    ;; Expand keys for packets 2-7
%assign idx 1
%rep 6
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
    key_expand_8  0, idx
    key_expand_8  2, idx
    key_expand_8  4, idx
    key_expand_8  6, idx
    key_expand_8  8, idx
    key_expand_8  10, idx
    key_expand_8  12, idx
    key_expand_8  14, idx
%assign idx (idx + 1)
%endrep

    ; Expand eighth packet key
    pop     rdx             ; get IV array pointer from Stack
    mov     rcx, [rdx+56]      ; load offset to IV 8 in array
    lea     rsi, [rcx]   ; load pointer to IV 8

    pop     rbx             ; get Key array pointer from Stack
    mov     rcx, [rbx+56]      ; load offset to key 8 in array
    lea     rdi, [rcx]   ; load pointer to Key 8
    lea     rbx, [EK_d]

    ; Expand key packet 8
    key_expand_8  0, 7
    key_expand_8  2, 7
    key_expand_8  4, 7
    key_expand_8  6, 7
    key_expand_8  8, 7
    key_expand_8  10, 7
    key_expand_8  12, 7
    key_expand_8  14, 7

    ; Load read-only registers
    vmovdqa  ymm12, [rel mask31]

    ; Shift LFSR 32-times, update state variables
%assign N 0
%rep 32
    pop     rdx
    lea     rax, [rdx]
    push    rdx

    bits_reorg8 N
    nonlin_fun8 1
    vpsrld  ymm0,1         ; Shift out LSB of W

    pop     rdx
    lea     rax, [rdx]
    push    rdx

    lfsr_updt8  N           ; W (ymm0) used in LFSR update - not set to zero
%assign N N+1
%endrep

    ; And once more, initial round from keygen phase = 33 times
    pop     rdx
    lea     rax, [rdx]
    push    rdx

    bits_reorg8 0
    nonlin_fun8 0

    pop     rdx
    lea     rax, [rdx]

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
    sub     rsp, 8*8
    mov     r12, [pKS]
    mov     r13, [pKS + 8]
    mov     r14, [pKS + 16]
    mov     r15, [pKS + 24]
    mov     [rsp],      r12
    mov     [rsp + 8],  r13
    mov     [rsp + 16], r14
    mov     [rsp + 24], r15
    mov     r12, [pKS + 32]
    mov     r13, [pKS + 40]
    mov     r14, [pKS + 48]
    mov     r15, [pKS + 56]
    mov     [rsp + 32], r12
    mov     [rsp + 40], r13
    mov     [rsp + 48], r14
    mov     [rsp + 56], r15


    ; Load state pointer in RAX
    mov         rax, pState

    ; Load read-only registers
    vmovdqa     ymm12, [rel mask31]

    ; Generate 64B of keystream in 16 rounds
%assign N 1
%rep %%NUM_ROUNDS
    bits_reorg8 N
    nonlin_fun8 1
    store_kstr8
    vpxor        ymm0, ymm0
    lfsr_updt8  N
%assign N N+1
%endrep

    ;; Restore rsp pointer to value before pushing keystreams
    add         rsp, 8*8

    FUNC_RESTORE

%endmacro

;;
;; void asm_ZucGenKeystream64B_8_avx2(state8_t *pSta, u32* pKeyStr[8])
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(asm_ZucGenKeystream64B_8_avx2,function,internal)
asm_ZucGenKeystream64B_8_avx2:

    KEYGEN_8_AVX2 16

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
;; void asm_ZucCipher64B_8_avx2(state4_t *pSta, u32 *pKeyStr[8], u64 *pIn[8],
;;                             u64 *pOut[8], u64 bufOff);
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
MKGLOBAL(asm_ZucCipher64B_8_avx2,function,internal)
asm_ZucCipher64B_8_avx2:

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

        ; Store 8 keystream pointers and input registers in the stack
        sub     rsp, 12*8
        mov     r12, [pKS]
        mov     r13, [pKS + 8]
        mov     r14, [pKS + 16]
        mov     r15, [pKS + 24]
        mov     [rsp],      r12
        mov     [rsp + 8],  r13
        mov     [rsp + 16], r14
        mov     [rsp + 24], r15
        mov     r12, [pKS + 32]
        mov     r13, [pKS + 40]
        mov     r14, [pKS + 48]
        mov     r15, [pKS + 56]
        mov     [rsp + 32], r12
        mov     [rsp + 40], r13
        mov     [rsp + 48], r14
        mov     [rsp + 56], r15

        mov     [rsp + 64], pKS
        mov     [rsp + 72], pIn
        mov     [rsp + 80], pOut
        mov     [rsp + 88], bufOff

        ; Load state pointer in RAX
        mov     rax, pState

        ; Load read-only registers
        vmovdqa ymm12, [rel mask31]

        ; Generate 64B of keystream in 16 rounds
%assign N 1
%rep 16
        bits_reorg8 N
        nonlin_fun8 1
        store_kstr8
        vpxor   ymm0, ymm0
        lfsr_updt8  N
%assign N N+1
%endrep

        ;; Restore input parameters
        mov     pKS,    [rsp + 64]
        mov     pIn,    [rsp + 72]
        mov     pOut,   [rsp + 80]
        mov     bufOff, [rsp + 88]

        ;; Restore rsp pointer to value before pushing keystreams
        ;; and input parameters
        add     rsp, 12*8

%assign off 0
%rep 2
        ;; XOR Input buffer with keystream in rounds of 32B

        ;; Read all 8 streams
        mov     r12, [pIn]
        mov     r13, [pIn + 8]
        mov     r14, [pIn + 16]
        mov     r15, [pIn + 24]
        vmovdqu ymm0, [r12 + bufOff + off]
        vmovdqu ymm1, [r13 + bufOff + off]
        vmovdqu ymm2, [r14 + bufOff + off]
        vmovdqu ymm3, [r15 + bufOff + off]
        mov     r12, [pIn + 32]
        mov     r13, [pIn + 40]
        mov     r14, [pIn + 48]
        mov     r15, [pIn + 56]
        vmovdqu ymm4, [r12 + bufOff + off]
        vmovdqu ymm5, [r13 + bufOff + off]
        vmovdqu ymm6, [r14 + bufOff + off]
        vmovdqu ymm7, [r15 + bufOff + off]

        ;; Read all 8 keystreams
        mov     r12, [pKS]
        mov     r13, [pKS + 8]
        mov     r14, [pKS + 16]
        mov     r15, [pKS + 24]
        vmovdqa ymm8, [r12 + off]
        vmovdqa ymm9, [r13 + off]
        vmovdqa ymm10, [r14 + off]
        vmovdqa ymm11, [r15 + off]

        mov     r12, [pKS + 32]
        mov     r13, [pKS + 40]
        mov     r14, [pKS + 48]
        mov     r15, [pKS + 56]
        vmovdqa ymm12, [r12 + off]
        vmovdqa ymm13, [r13 + off]
        vmovdqa ymm14, [r14 + off]
        vmovdqa ymm15, [r15 + off]

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

        vmovdqu [r12 + bufOff + off], ymm8
        vmovdqu [r13 + bufOff + off], ymm9
        vmovdqu [r14 + bufOff + off], ymm10
        vmovdqu [r15 + bufOff + off], ymm11

        mov     r12, [pOut + 32]
        mov     r13, [pOut + 40]
        mov     r14, [pOut + 48]
        mov     r15, [pOut + 56]

        vmovdqu [r12 + bufOff + off], ymm12
        vmovdqu [r13 + bufOff + off], ymm13
        vmovdqu [r14 + bufOff + off], ymm14
        vmovdqu [r15 + bufOff + off], ymm15
%assign off (off + 32)
%endrep

        FUNC_RESTORE

        ret

;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
