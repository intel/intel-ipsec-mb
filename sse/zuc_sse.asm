;;
;; Copyright (c) 2009-2020, Intel Corporation
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

%ifndef ZUC_CIPHER64B_4
%define ZUC_CIPHER64B_4 asm_ZucCipher64B_4_sse
%define ZUC_INIT_4 asm_ZucInitialization_4_sse
%define ZUC_KEYGEN64B_4 asm_ZucGenKeystream64B_4_sse
%define ZUC_KEYGEN8B_4 asm_ZucGenKeystream8B_4_sse
%define ZUC_EIA3ROUND64B asm_Eia3Round64BSSE
%define ZUC_EIA3REMAINDER64B asm_Eia3RemainderSSE
%endif

section .data
default rel

EK_d:
dw	0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
dw	0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC

mask31:
dd	0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF

align 16
bit_reverse_table_l:
db	0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e, 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07, 0x0f

align 16
bit_reverse_table_h:
db	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0

align 16
bit_reverse_and_table:
db	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f

align 16
data_mask_64bits:
dd	0xffffffff, 0xffffffff, 0x00000000, 0x00000000

bit_mask_table:
db	0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe

align 16
swap_mask:
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c


align 16
S1_S0_shuf:
db      0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F

align 16
S0_S1_shuf:
db      0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E

align 16
rev_S1_S0_shuf:
db      0x00, 0x08, 0x01, 0x09, 0x02, 0x0A, 0x03, 0x0B, 0x04, 0x0C, 0x05, 0x0D, 0x06, 0x0E, 0x07, 0x0F

align 16
rev_S0_S1_shuf:
db      0x08, 0x00, 0x09, 0x01, 0x0A, 0x02, 0x0B, 0x03, 0x0C, 0x04, 0x0D, 0x05, 0x0E, 0x06, 0x0F, 0x07

align 16
rot8_mod32:
db      0x03, 0x00, 0x01, 0x02, 0x07, 0x04, 0x05, 0x06,
db      0x0B, 0x08, 0x09, 0x0A, 0x0F, 0x0C, 0x0D, 0x0E

align 16
rot16_mod32:
db      0x02, 0x03, 0x00, 0x01, 0x06, 0x07, 0x04, 0x05,
db      0x0A, 0x0B, 0x08, 0x09, 0x0E, 0x0F, 0x0C, 0x0D

align 16
rot24_mod32:
db      0x01, 0x02, 0x03, 0x00, 0x05, 0x06, 0x07, 0x04,
db      0x09, 0x0A, 0x0B, 0x08, 0x0D, 0x0E, 0x0F, 0x0C

section .text

%define MASK31  xmm12

%define OFS_R1  (16*(4*4))
%define OFS_R2  (OFS_R1 + (4*4))
%define OFS_X0  (OFS_R2 + (4*4))
%define OFS_X1  (OFS_X0 + (4*4))
%define OFS_X2  (OFS_X1 + (4*4))
%define OFS_X3  (OFS_X2 + (4*4))

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
        movdqa  [rsp + 0*16], xmm6
        movdqa  [rsp + 1*16], xmm7
        movdqa  [rsp + 2*16], xmm8
        movdqa  [rsp + 3*16], xmm9
        movdqa  [rsp + 4*16], xmm10
        movdqa  [rsp + 5*16], xmm11
        movdqa  [rsp + 6*16], xmm12
        movdqa  [rsp + 7*16], xmm13
        movdqa  [rsp + 8*16], xmm14
        movdqa  [rsp + 9*16], xmm15
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
        movdqa  xmm6,  [rsp + 0*16]
        movdqa  xmm7,  [rsp + 1*16]
        movdqa  xmm8,  [rsp + 2*16]
        movdqa  xmm9,  [rsp + 3*16]
        movdqa  xmm10, [rsp + 4*16]
        movdqa  xmm11, [rsp + 5*16]
        movdqa  xmm12, [rsp + 6*16]
        movdqa  xmm13, [rsp + 7*16]
        movdqa  xmm14, [rsp + 8*16]
        movdqa  xmm15, [rsp + 9*16]
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
;   make_u31()
;
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
;   bits_reorg4()
;
;   params
;       %1 - round number
;       rax - LFSR pointer
;   uses
;
;   return
;
%macro  bits_reorg4 1
    ;
    ; xmm15 = LFSR_S15
    ; xmm14 = LFSR_S14
    ; xmm11 = LFSR_S11
    ; xmm9  = LFSR_S9
    ; xmm7  = LFSR_S7
    ; xmm5  = LFSR_S5
    ; xmm2  = LFSR_S2
    ; xmm0  = LFSR_S0
    ;
    movdqa      xmm15, [rax + ((15 + %1) % 16)*16]
    movdqa      xmm14, [rax + ((14 + %1) % 16)*16]
    movdqa      xmm11, [rax + ((11 + %1) % 16)*16]
    movdqa      xmm9,  [rax + (( 9 + %1) % 16)*16]
    movdqa      xmm7,  [rax + (( 7 + %1) % 16)*16]
    movdqa      xmm5,  [rax + (( 5 + %1) % 16)*16]
    movdqa      xmm2,  [rax + (( 2 + %1) % 16)*16]
    movdqa      xmm0,  [rax + (( 0 + %1) % 16)*16]

    pxor        xmm1, xmm1
    pslld       xmm15, 1
    movdqa      xmm3, xmm14
    pblendw     xmm3, xmm1, 0xAA
    pblendw     xmm15, xmm3, 0x55

    movdqa      [rax + OFS_X0], xmm15   ; BRC_X0
    pslld       xmm11, 16
    psrld       xmm9, 15
    por         xmm11, xmm9
    movdqa      [rax + OFS_X1], xmm11   ; BRC_X1
    pslld       xmm7, 16
    psrld       xmm5, 15
    por         xmm7, xmm5
    movdqa      [rax + OFS_X2], xmm7    ; BRC_X2
    pslld       xmm2, 16
    psrld       xmm0, 15
    por         xmm2, xmm0
    movdqa      [rax + OFS_X3], xmm2    ; BRC_X3
%endmacro

;
;   rot_mod32()
;
;   uses xmm7
;
%macro  rot_mod32   3
    movdqa      %1, %2
%if (%3 == 8)
        pshufb %1, [rel rot8_mod32]
%elif (%3 == 16)
        pshufb %1, [rel rot16_mod32]
%elif (%3 == 24)
        pshufb %1, [rel rot24_mod32]
%else
    pslld       %1, %3
    movdqa      xmm7, %2
    psrld       xmm7, (32 - %3)

    por         %1, xmm7
%endif
%endmacro


;
;   nonlin_fun4()
;
;   params
;       %1 == 1, then calculate W
;   uses
;
;   return
;       xmm0 = W value, updates F_R1[] / F_R2[]
;
%macro nonlin_fun4  1

%if (%1 == 1)
    movdqa      xmm0, [rax + OFS_X0]
    pxor        xmm0, [rax + OFS_R1]
    paddd       xmm0, [rax + OFS_R2]    ; W = (BRC_X0 ^ F_R1) + F_R2
%endif

    movdqa      xmm1, [rax + OFS_R1]
    movdqa      xmm2, [rax + OFS_R2]
    paddd       xmm1, [rax + OFS_X1]    ; W1 = F_R1 + BRC_X1
    pxor        xmm2, [rax + OFS_X2]    ; W2 = F_R2 ^ BRC_X2

    movdqa      xmm3, xmm1
    movdqa      xmm4, xmm2
    pslld       xmm1, 16
    pslld       xmm2, 16
    psrld       xmm3, 16
    psrld       xmm4, 16
    por         xmm1, xmm4
    por         xmm2, xmm3

    rot_mod32   xmm3, xmm1, 2
    rot_mod32   xmm4, xmm1, 10
    rot_mod32   xmm5, xmm1, 18
    rot_mod32   xmm6, xmm1, 24
    pxor        xmm1, xmm3
    pxor        xmm1, xmm4
    pxor        xmm1, xmm5
    pxor        xmm1, xmm6      ; XMM1 = U = L1(P)

    rot_mod32   xmm3, xmm2, 8
    rot_mod32   xmm4, xmm2, 14
    rot_mod32   xmm5, xmm2, 22
    rot_mod32   xmm6, xmm2, 30
    pxor        xmm2, xmm3
    pxor        xmm2, xmm4
    pxor        xmm2, xmm5
    pxor        xmm2, xmm6      ; XMM2 = V = L2(Q)

    ; Shuffle U and V to have all S0 lookups in XMM1 and all S1 lookups in XMM2

    ; Compress all S0 and S1 input values in each register

    pshufb      xmm1, [rel S0_S1_shuf] ; S0: Bytes 0-7, S1: Bytes 8-15
    pshufb      xmm2, [rel S1_S0_shuf] ; S1: Bytes 0-7, S0: Bytes 8-15

    movdqa      xmm3, xmm1
    shufpd      xmm1, xmm2, 0x2 ; All S0 input values
    shufpd      xmm2, xmm3, 0x2 ; All S1 input values

    ; Compute S0 and S1 values
    S0_comput_SSE   xmm1, xmm3, xmm4
    S1_comput_SSE   xmm2, xmm3, xmm4, xmm5

    ; Need to shuffle back xmm1 & xmm2 before storing output
    ; (revert what was done before S0 and S1 computations)
    movdqa      xmm3, xmm1
    shufpd      xmm1, xmm2, 0x2 ; All S0 input values
    shufpd      xmm2, xmm3, 0x2 ; All S1 input values

    pshufb      xmm1, [rel rev_S0_S1_shuf]
    pshufb      xmm2, [rel rev_S1_S0_shuf]

    movdqa      [rax + OFS_R1], xmm1
    movdqa      [rax + OFS_R2], xmm2
%endmacro


;
;   store_kstr4()
;
;   params
;
;   uses
;       xmm0 as input
;   return
;
%macro  store_kstr4 0
    pxor        xmm0, [rax + OFS_X3]

    mov         rcx, [rsp]
    mov         rdx, [rsp + 8]
    mov         r8,  [rsp + 16]
    mov         r9,  [rsp + 24]
    pextrd      r15d, xmm0, 3
    pextrd      r14d, xmm0, 2
    pextrd      r13d, xmm0, 1
    movd        r12d, xmm0
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
%endmacro


;
;   add_mod31()
;       add two 32-bit args and reduce mod (2^31-1)
;   params
;       %1  - arg1/res
;       %2  - arg2
;   uses
;       xmm2
;   return
;       %1
%macro  add_mod31   2
    paddd       %1, %2
    movdqa     xmm2, %1
    psrld      xmm2, 31
    pand        %1, MASK31
    paddd       %1, xmm2
%endmacro


;
;   rot_mod31()
;       rotate (mult by pow of 2) 32-bit arg and reduce mod (2^31-1)
;   params
;       %1  - arg
;       %2  - # of bits
;   uses
;       xmm2
;   return
;       %1
%macro  rot_mod31   2

    movdqa     xmm2, %1
    pslld      xmm2, %2
    psrld      %1, (31 - %2)

    por         %1, xmm2
    pand        %1, MASK31
%endmacro


;
;   lfsr_updt4()
;
;   params
;       %1 - round number
;   uses
;       xmm0 as input (ZERO or W)
;   return
;
%macro  lfsr_updt4  1
    ;
    ; xmm1  = LFSR_S0
    ; xmm4  = LFSR_S4
    ; xmm10 = LFSR_S10
    ; xmm13 = LFSR_S13
    ; xmm15 = LFSR_S15
    ;
    movdqa      xmm1,  [rax + (( 0 + %1) % 16)*16]
    movdqa      xmm4,  [rax + (( 4 + %1) % 16)*16]
    movdqa      xmm10, [rax + ((10 + %1) % 16)*16]
    movdqa      xmm13, [rax + ((13 + %1) % 16)*16]
    movdqa      xmm15, [rax + ((15 + %1) % 16)*16]

    ; Calculate LFSR feedback
    add_mod31   xmm0, xmm1
    rot_mod31   xmm1, 8
    add_mod31   xmm0, xmm1
    rot_mod31   xmm4, 20
    add_mod31   xmm0, xmm4
    rot_mod31   xmm10, 21
    add_mod31   xmm0, xmm10
    rot_mod31   xmm13, 17
    add_mod31   xmm0, xmm13
    rot_mod31   xmm15, 15
    add_mod31   xmm0, xmm15



    movdqa      [rax + (( 0 + %1) % 16)*16], xmm0

    ; LFSR_S16 = (LFSR_S15++) = eax
%endmacro


;
;   key_expand_4()
;
%macro  key_expand_4  2
    movzx       r8d, byte [rdi +  (%1 + 0)]
    movzx       r9d, word [rbx + ((%1 + 0)*2)]
    movzx       r10d, byte [rsi + (%1 + 0)]
    make_u31    r11d, r8d, r9d, r10d
    mov         [rax +  (((%1 + 0)*16)+(%2*4))], r11d

    movzx       r12d, byte [rdi +  (%1 + 1)]
    movzx       r13d, word [rbx + ((%1 + 1)*2)]
    movzx       r14d, byte [rsi +  (%1 + 1)]
    make_u31    r15d, r12d, r13d, r14d
    mov         [rax +  (((%1 + 1)*16)+(%2*4))], r15d
%endmacro

MKGLOBAL(ZUC_INIT_4,function,internal)
ZUC_INIT_4:

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
    key_expand_4  0, 0
    key_expand_4  2, 0
    key_expand_4  4, 0
    key_expand_4  6, 0
    key_expand_4  8, 0
    key_expand_4  10, 0
    key_expand_4  12, 0
    key_expand_4  14, 0


    ;second packet key expand here - reset pointers
    pop     rdx             ; get IV array pointer from Stack
    mov     rcx, [rdx+8]      ; load offset to IV 2 in array
    lea     rsi, [rcx]    ; load pointer to IV2

    pop     rbx             ; get Key array pointer from Stack
    mov     rcx, [rbx+8]      ; load offset to key 2 in array
    lea     rdi, [rcx]    ; load pointer to Key 2

    push    rbx             ; save Key pointer
    push    rdx             ; save IV pointer

    lea     rbx, [EK_d]

    ; Expand key packet 2
    key_expand_4  0, 1
    key_expand_4  2, 1
    key_expand_4  4, 1
    key_expand_4  6, 1
    key_expand_4  8, 1
    key_expand_4  10, 1
    key_expand_4  12, 1
    key_expand_4  14, 1

    ;Third packet key expand here - reset pointers
    pop     rdx             ; get IV array pointer from Stack
    mov     rcx, [rdx+16]      ; load offset to IV 3 in array
    lea     rsi, [rcx]    ; load pointer to IV3

    pop     rbx             ; get Key array pointer from Stack
    mov     rcx, [rbx+16]      ; load offset to key 3 in array
    lea     rdi, [rcx]    ; load pointer to Key 3

    push    rbx             ; save Key pointer
    push    rdx             ; save IV pointer
    lea     rbx, [EK_d]

    ; Expand key packet 3
    key_expand_4  0, 2
    key_expand_4  2, 2
    key_expand_4  4, 2
    key_expand_4  6, 2
    key_expand_4  8, 2
    key_expand_4  10, 2
    key_expand_4  12, 2
    key_expand_4  14, 2

    ;fourth packet key expand here - reset pointers
    pop     rdx             ; get IV array pointer from Stack
    mov     rcx, [rdx+24]      ; load offset to IV 4 in array
    lea     rsi, [rcx]   ; load pointer to IV4

    pop     rbx             ; get Key array pointer from Stack
    mov     rcx, [rbx+24]      ; load offset to key 2 in array
    lea     rdi, [rcx]   ; load pointer to Key 2
    lea     rbx, [EK_d]

    ; Expand key packet 4
    key_expand_4  0, 3
    key_expand_4  2, 3
    key_expand_4  4, 3
    key_expand_4  6, 3
    key_expand_4  8, 3
    key_expand_4  10, 3
    key_expand_4  12, 3
    key_expand_4  14, 3

    ; Load read-only registers
    movdqa  xmm12, [rel mask31]

    ; Shift LFSR 32-times, update state variables
%assign N 0
%rep 32
    pop     rdx
    lea     rax, [rdx]
    push    rdx

    bits_reorg4 N
    nonlin_fun4 1
    psrld  xmm0,1         ; Shift out LSB of W

    pop     rdx
    lea     rax, [rdx]
    push    rdx

    lfsr_updt4  N           ; W (xmm0) used in LFSR update - not set to zero
%assign N N+1
%endrep

    ; And once more, initial round from keygen phase = 33 times
    pop     rdx
    lea     rax, [rdx]
    push    rdx

    bits_reorg4 0
    nonlin_fun4 0

    pop     rdx
    lea     rax, [rdx]

    pxor    xmm0, xmm0
    lfsr_updt4  0

    FUNC_RESTORE

    ret

;
; Generate N*4 bytes of keystream
; for 4 buffers (where N is number of rounds)
;
%macro KEYGEN_4_SSE 1
%define %%NUM_ROUNDS    %1 ; [in] Number of 4-byte rounds

%ifdef LINUX
	%define		pState	rdi
	%define		pKS1	rsi
	%define		pKS2	rdx
	%define		pKS3	rcx
	%define		pKS4	r8
%else
	%define		pState	rcx
	%define		pKS1	rdx
	%define		pKS2	r8
	%define		pKS3	r9
        %define         pKS4    rax
%endif

%ifndef LINUX
    mov         rax, [rsp + 8*5] ; 5th parameter from stack
%endif

    FUNC_SAVE

    ; Store 4 keystream pointers on the stack
    sub     rsp, 4*8
    mov     [rsp],      pKS1
    mov     [rsp + 8],  pKS2
    mov     [rsp + 16], pKS3
    mov     [rsp + 24], pKS4

    ; Load state pointer in RAX
    mov         rax, pState

    ; Load read-only registers
    movdqa      xmm12, [rel mask31]

    ; Generate N*4B of keystream in N rounds
%assign N 1
%rep %%NUM_ROUNDS
    bits_reorg4 N
    nonlin_fun4 1
    store_kstr4
    pxor        xmm0, xmm0
    lfsr_updt4  N
%assign N N+1
%endrep

    ;; Restore rsp pointer to value before pushing keystreams
    add         rsp, 4*8

    FUNC_RESTORE

%endmacro

;;
;; void asm_ZucGenKeystream64B_4_sse(state4_t *pSta, u32* pKeyStr1, u32* pKeyStr2, u32* pKeyStr3, u32* pKeyStr4);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr1
;;  R8     - pKeyStr2
;;  R9     - pKeyStr3
;;  Stack  - pKeyStr4
;;
;; LIN64
;;  RDI - pSta
;;  RSI - pKeyStr1
;;  RDX - pKeyStr2
;;  RCX - pKeyStr3
;;  R8  - pKeyStr4
;;
MKGLOBAL(ZUC_KEYGEN64B_4,function,internal)
ZUC_KEYGEN64B_4:

        KEYGEN_4_SSE 16

        ret

;;
;; void asm_ZucGenKeystream8B_4_sse(state4_t *pSta, u32* pKeyStr1, u32* pKeyStr2, u32* pKeyStr3, u32* pKeyStr4);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr1
;;  R8     - pKeyStr2
;;  R9     - pKeyStr3
;;  Stack  - pKeyStr4
;;
;; LIN64
;;  RDI - pSta
;;  RSI - pKeyStr1
;;  RDX - pKeyStr2
;;  RCX - pKeyStr3
;;  R8  - pKeyStr4
;;
MKGLOBAL(ZUC_KEYGEN8B_4,function,internal)
ZUC_KEYGEN8B_4:

        KEYGEN_4_SSE 2

        ret

;;
;; void asm_ZucCipher64B_4_sse(state4_t *pSta, u32 *pKeyStr[4], u64 *pIn[4],
;;                             u64 *pOut[4], u64 bufOff);
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
MKGLOBAL(ZUC_CIPHER64B_4,function,internal)
ZUC_CIPHER64B_4:

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

%ifndef LINUX
        mov     bufOff, [rsp + 40]
%endif
        FUNC_SAVE

        ; Store 4 keystream pointers and input registers in the stack
        sub     rsp, 8*8
        mov     r12, [pKS]
        mov     r13, [pKS + 8]
        mov     r14, [pKS + 16]
        mov     r15, [pKS + 24]
        mov     [rsp],      r12
        mov     [rsp + 8],  r13
        mov     [rsp + 16], r14
        mov     [rsp + 24], r15

        mov     [rsp + 32], pKS
        mov     [rsp + 40], pIn
        mov     [rsp + 48], pOut
        mov     [rsp + 56], bufOff

        ; Load state pointer in RAX
        mov     rax, pState

        ; Load read-only registers
        movdqa  xmm12, [rel mask31]

        ; Generate 64B of keystream in 16 rounds
%assign N 1
%rep 16
        bits_reorg4 N
        nonlin_fun4 1
        store_kstr4
        pxor    xmm0, xmm0
        lfsr_updt4  N
%assign N N+1
%endrep

        ;; Restore input parameters
        mov     pKS,    [rsp + 32]
        mov     pIn,    [rsp + 40]
        mov     pOut,   [rsp + 48]
        mov     bufOff, [rsp + 56]

        ;; Restore rsp pointer to value before pushing keystreams
        ;; and input parameters
        add     rsp, 8*8

        movdqa  xmm15, [rel swap_mask]

%assign off 0
%rep 4
        ;; XOR Input buffer with keystream in rounds of 16B
        mov     r12, [pIn]
        mov     r13, [pIn + 8]
        mov     r14, [pIn + 16]
        mov     r15, [pIn + 24]
        movdqu  xmm0, [r12 + bufOff + off]
        movdqu  xmm1, [r13 + bufOff + off]
        movdqu  xmm2, [r14 + bufOff + off]
        movdqu  xmm3, [r15 + bufOff + off]

        mov     r12, [pKS]
        mov     r13, [pKS + 8]
        mov     r14, [pKS + 16]
        mov     r15, [pKS + 24]
        movdqa  xmm4, [r12 + off]
        movdqa  xmm5, [r13 + off]
        movdqa  xmm6, [r14 + off]
        movdqa  xmm7, [r15 + off]

        pshufb  xmm4, xmm15
        pshufb  xmm5, xmm15
        pshufb  xmm6, xmm15
        pshufb  xmm7, xmm15

        pxor    xmm4, xmm0
        pxor    xmm5, xmm1
        pxor    xmm6, xmm2
        pxor    xmm7, xmm3

        mov     r12, [pOut]
        mov     r13, [pOut + 8]
        mov     r14, [pOut + 16]
        mov     r15, [pOut + 24]

        movdqu  [r12 + bufOff + off], xmm4
        movdqu  [r13 + bufOff + off], xmm5
        movdqu  [r14 + bufOff + off], xmm6
        movdqu  [r15 + bufOff + off], xmm7
%assign off (off + 16)
%endrep

        FUNC_RESTORE

        ret

;;
;; extern uint32_t Zuc_Eia3_Remainder_sse(const void *ks, const void *data, uint64_t n_bits)
;;
;; Returns authentication update value to be XOR'ed with current authentication tag
;;
;; WIN64
;;	RCX - KS (key stream pointer)
;; 	RDX - DATA (data pointer)
;;      R8  - N_BITS (number data bits to process)
;; LIN64
;;	RDI - KS (key stream pointer)
;;	RSI - DATA (data pointer)
;;      RDX - N_BITS (number data bits to process)
;;
align 16
MKGLOBAL(ZUC_EIA3REMAINDER64B,function,internal)
ZUC_EIA3REMAINDER64B:
%ifdef LINUX
	%define		KS	rdi
	%define		DATA	rsi
	%define		N_BITS	rdx
%else
	%define		KS	rcx
	%define		DATA	rdx
	%define		N_BITS	r8
%endif

        FUNC_SAVE

        movdqa  xmm5, [bit_reverse_table_l]
        movdqa  xmm6, [bit_reverse_table_h]
        movdqa  xmm7, [bit_reverse_and_table]
        movdqa  xmm10, [data_mask_64bits]

        pxor    xmm9, xmm9

%rep 3
        cmp     N_BITS, 128
        jb      Eia3RoundsSSE_dq_end

        ;; read 16 bytes and reverse bits
        movdqu  xmm0, [DATA]
        movdqa  xmm1, xmm0
        pand    xmm1, xmm7

        movdqa  xmm2, xmm7
        pandn   xmm2, xmm0
        psrld   xmm2, 4

        movdqa  xmm8, xmm6      ; bit reverse low nibbles (use high table)
        pshufb  xmm8, xmm1

        movdqa  xmm4, xmm5      ; bit reverse high nibbles (use low table)
        pshufb  xmm4, xmm2

        por     xmm8, xmm4
        ; xmm8 - bit reversed data bytes

        ;; ZUC authentication part
        ;; - 4x32 data bits
        ;; - set up KS
        movdqu  xmm3, [KS + (0*4)]
        movdqu  xmm4, [KS + (2*4)]
        pshufd  xmm0, xmm3, 0x61
        pshufd  xmm1, xmm4, 0x61

        ;;  - set up DATA
        movdqa  xmm2, xmm8
        pand    xmm2, xmm10
        pshufd  xmm3, xmm2, 0xdc
        movdqa  xmm4, xmm3

        psrldq  xmm8, 8
        pshufd  xmm13, xmm8, 0xdc
        movdqa  xmm14, xmm13

        ;; - clmul
        ;; - xor the results from 4 32-bit words together
        pclmulqdq xmm3, xmm0, 0x00
        pclmulqdq xmm4, xmm0, 0x11
        pclmulqdq xmm13, xmm1, 0x00
        pclmulqdq xmm14, xmm1, 0x11

        pxor    xmm3, xmm4
        pxor    xmm13, xmm14
        pxor    xmm9, xmm3
        pxor    xmm9, xmm13
        lea     DATA, [DATA + 16]
        lea     KS, [KS + 16]
        sub     N_BITS, 128
%endrep
Eia3RoundsSSE_dq_end:

%rep 3
        cmp     N_BITS, 32
        jb      Eia3RoundsSSE_dw_end

        ;; swap dwords in KS
        movq    xmm1, [KS]
        pshufd  xmm4, xmm1, 0xf1

        ;;  bit-reverse 4 bytes of data
        movdqa  xmm2, xmm7
        movd    xmm0, [DATA]
        movdqa  xmm1, xmm0
        pand    xmm1, xmm2

        pandn   xmm2, xmm0
        psrld   xmm2, 4

        movdqa  xmm0, xmm6    ; bit reverse low nibbles (use high table)
        pshufb  xmm0, xmm1

        movdqa  xmm3, xmm5    ; bit reverse high nibbles (use low table)
        pshufb  xmm3, xmm2

        por     xmm0, xmm3

        ;; rol & xor
        pclmulqdq xmm0, xmm4, 0
        pxor    xmm9, xmm0

        lea     DATA, [DATA + 4]
        lea     KS, [KS + 4]
        sub     N_BITS, 32
%endrep

Eia3RoundsSSE_dw_end:
        movq    rax, xmm9
        shr     rax, 32

        or      N_BITS, N_BITS
        jz      Eia3RoundsSSE_byte_loop_end

        ;; get 64-bit key stream for the last data bits (less than 32)
        mov     KS, [KS]

;        ;; process remaining data bytes and bits
Eia3RoundsSSE_byte_loop:
        or      N_BITS, N_BITS
        jz      Eia3RoundsSSE_byte_loop_end

        cmp     N_BITS, 8
        jb      Eia3RoundsSSE_byte_partial

        movzx   r11, byte [DATA]
        sub     N_BITS, 8
        jmp     Eia3RoundsSSE_byte_read

Eia3RoundsSSE_byte_partial:
        ;; process remaining bits (up to 7)
        lea     r11, [bit_mask_table]
        movzx   r10, byte [r11 + N_BITS]
        movzx   r11, byte [DATA]
        and     r11, r10
        xor     N_BITS, N_BITS
Eia3RoundsSSE_byte_read:

%assign DATATEST 0x80
%rep 8
        xor     r10, r10
        test    r11, DATATEST
        cmovne  r10, KS
        xor     rax, r10
        rol     KS, 1
%assign DATATEST (DATATEST >> 1)
%endrep                 ; byte boundary
        lea     DATA, [DATA + 1]
        jmp     Eia3RoundsSSE_byte_loop

Eia3RoundsSSE_byte_loop_end:

        ;; eax - holds the return value at this stage

        FUNC_RESTORE

        ret

;;
;;extern uint32_t Zuc_Eia3_Round64B_sse(uint32_t T, const void *KS, const void *DATA)
;;
;; Updates authentication tag T based on keystream KS and DATA.
;; - it processes 64 bytes of DATA
;; - reads data in 16 byte chunks and bit reverses them
;; - reads and re-arranges KS
;; - employs clmul for the XOR & ROL part
;; - copies top 64 butes of KS to bottom (for the next round)
;;
;; WIN64
;;	RCX - T
;;	RDX - KS pointer to key stream (2 x 64 bytes)
;;;     R8  - DATA pointer to data
;; LIN64
;;	RDI - T
;;	RSI - KS pointer to key stream (2 x 64 bytes)
;;      RDX - DATA pointer to data
;;
align 16
MKGLOBAL(ZUC_EIA3ROUND64B,function,internal)
ZUC_EIA3ROUND64B:

%ifdef LINUX
	%define		T	edi
	%define		KS	rsi
	%define		DATA	rdx
%else
	%define		T	ecx
	%define		KS	rdx
	%define		DATA	r8
%endif

        FUNC_SAVE

        movdqa  xmm5, [bit_reverse_table_l]
        movdqa  xmm6, [bit_reverse_table_h]
        movdqa  xmm7, [bit_reverse_and_table]
        movdqa  xmm10, [data_mask_64bits]

        pxor    xmm9, xmm9

%assign I 0
%rep 4
        ;; read 16 bytes and reverse bits
        movdqu  xmm0, [DATA + 16*I]
        movdqa  xmm1, xmm0
        pand    xmm1, xmm7

        movdqa  xmm2, xmm7
        pandn   xmm2, xmm0
        psrld   xmm2, 4

        movdqa  xmm8, xmm6      ; bit reverse low nibbles (use high table)
        pshufb  xmm8, xmm1

        movdqa  xmm4, xmm5      ; bit reverse high nibbles (use low table)
        pshufb  xmm4, xmm2

        por     xmm8, xmm4
        ; xmm8 - bit reversed data bytes

        ;; ZUC authentication part
        ;; - 4x32 data bits
        ;; - set up KS
%if I != 0
        movdqa  xmm0, xmm12
        movdqu  xmm2, [KS + (I*16) + (4*4)]
        movdqa  xmm12, xmm2
        palignr xmm2, xmm0, 8
        pshufd  xmm1, xmm0, 0x61
        pshufd  xmm11, xmm2, 0x61
%else
        movdqu  xmm2, [KS + (I*16) + (0*4)]
        movdqu  xmm3, [KS + (I*16) + (4*4)]
        movdqa  xmm12, xmm3
        palignr xmm3, xmm2, 8
        pshufd  xmm1, xmm2, 0x61
        pshufd  xmm11, xmm3, 0x61
%endif

        ;;  - set up DATA
        movdqa  xmm0, xmm8
        pand    xmm0, xmm10
        pshufd  xmm3, xmm0, 0xdc
        movdqa  xmm0, xmm3

        psrldq  xmm8, 8
        pshufd  xmm13, xmm8, 0xdc
        movdqa  xmm14, xmm13

        ;; - clmul
        ;; - xor the results from 4 32-bit words together
        pclmulqdq xmm0, xmm1, 0x00
        pclmulqdq xmm3, xmm1, 0x11
        pclmulqdq xmm14, xmm11, 0x00
        pclmulqdq xmm13, xmm11, 0x11

        pxor    xmm3, xmm0
        pxor    xmm13, xmm14
        pxor    xmm9, xmm3
        pxor    xmm9, xmm13

%assign I (I + 1)
%endrep

        ;; - update T
        movq    rax, xmm9
        shr     rax, 32
        xor     eax, T

        FUNC_RESTORE

        ret


;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
