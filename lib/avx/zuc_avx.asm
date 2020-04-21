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
align 64

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
    vmovdqa     xmm15, [rax + ((15 + %1) % 16)*16]
    vmovdqa     xmm14, [rax + ((14 + %1) % 16)*16]
    vmovdqa     xmm11, [rax + ((11 + %1) % 16)*16]
    vmovdqa     xmm9,  [rax + (( 9 + %1) % 16)*16]
    vmovdqa     xmm7,  [rax + (( 7 + %1) % 16)*16]
    vmovdqa     xmm5,  [rax + (( 5 + %1) % 16)*16]
    vmovdqa     xmm2,  [rax + (( 2 + %1) % 16)*16]
    vmovdqa     xmm0,  [rax + (( 0 + %1) % 16)*16]

    vpxor       xmm1, xmm1
    vpslld      xmm15, 1
    vpblendw    xmm3,  xmm14, xmm1, 0xAA
    vpblendw    xmm15, xmm3, xmm15, 0xAA

    vmovdqa     [rax + OFS_X0], xmm15   ; BRC_X0
    vpslld      xmm11, 16
    vpsrld      xmm9, 15
    vpor        xmm11, xmm9
    vmovdqa     [rax + OFS_X1], xmm11   ; BRC_X1
    vpslld      xmm7, 16
    vpsrld      xmm5, 15
    vpor        xmm7, xmm5
    vmovdqa     [rax + OFS_X2], xmm7    ; BRC_X2
    vpslld      xmm2, 16
    vpsrld      xmm0, 15
    vpor        xmm2, xmm0
    vmovdqa     [rax + OFS_X3], xmm2    ; BRC_X3
%endmacro

;
;   rot_mod32()
;
;   uses xmm7
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
    vpsrld      xmm7, %2, (32 - %3)

    vpor        %1, xmm7
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
    vmovdqa     xmm0, [rax + OFS_X0]
    vpxor       xmm0, [rax + OFS_R1]
    vpaddd      xmm0, [rax + OFS_R2]    ; W = (BRC_X0 ^ F_R1) + F_R2
%endif

    vmovdqa     xmm1, [rax + OFS_R1]
    vmovdqa     xmm2, [rax + OFS_R2]
    vpaddd      xmm1, [rax + OFS_X1]    ; W1 = F_R1 + BRC_X1
    vpxor       xmm2, [rax + OFS_X2]    ; W2 = F_R2 ^ BRC_X2

    vpslld      xmm3, xmm1, 16
    vpsrld      xmm4, xmm1, 16
    vpslld      xmm5, xmm2, 16
    vpsrld      xmm6, xmm2, 16
    vpor        xmm1, xmm3, xmm6
    vpor        xmm2, xmm4, xmm5

    rot_mod32   xmm3, xmm1, 2
    rot_mod32   xmm4, xmm1, 10
    rot_mod32   xmm5, xmm1, 18
    rot_mod32   xmm6, xmm1, 24
    vpxor       xmm1, xmm3
    vpxor       xmm1, xmm4
    vpxor       xmm1, xmm5
    vpxor       xmm1, xmm6      ; XMM1 = U = L1(P)

    rot_mod32   xmm3, xmm2, 8
    rot_mod32   xmm4, xmm2, 14
    rot_mod32   xmm5, xmm2, 22
    rot_mod32   xmm6, xmm2, 30
    vpxor       xmm2, xmm3
    vpxor       xmm2, xmm4
    vpxor       xmm2, xmm5
    vpxor       xmm2, xmm6      ; XMM2 = V = L2(Q)

    ; Shuffle U and V to have all S0 lookups in XMM1 and all S1 lookups in XMM2

    ; Compress all S0 and S1 input values in each register
    vpshufb     xmm1, [rel S0_S1_shuf] ; S0: Bytes 0-7, S1: Bytes 8-15
    vpshufb     xmm2, [rel S1_S0_shuf] ; S1: Bytes 0-7, S0: Bytes 8-15

    vshufpd     xmm3, xmm1, xmm2, 0x2 ; All S0 input values
    vshufpd     xmm4, xmm2, xmm1, 0x2 ; All S1 input values

    ; Compute S0 and S1 values
    S0_comput_AVX   xmm3, xmm1, xmm2
    S1_comput_AVX   xmm4, xmm1, xmm2, xmm5

    ; Need to shuffle back xmm1 & xmm2 before storing output
    ; (revert what was done before S0 and S1 computations)
    vshufpd    xmm1, xmm3, xmm4, 0x2
    vshufpd    xmm2, xmm4, xmm3, 0x2

    vpshufb     xmm1, [rel rev_S0_S1_shuf]
    vpshufb     xmm2, [rel rev_S1_S0_shuf]

    vmovdqa     [rax + OFS_R1], xmm1
    vmovdqa     [rax + OFS_R2], xmm2
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
    vpxor       xmm0, [rax + OFS_X3]
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
    vpaddd      %1, %2
    vpsrld      xmm2, %1, 31
    vpand       %1, MASK31
    vpaddd      %1, xmm2
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

    vpslld      xmm2, %1, %2
    vpsrld      %1, %1, (31 - %2)

    vpor        %1, xmm2
    vpand       %1, MASK31
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
    vmovdqa     xmm1,  [rax + (( 0 + %1) % 16)*16]
    vmovdqa     xmm4,  [rax + (( 4 + %1) % 16)*16]
    vmovdqa     xmm10, [rax + ((10 + %1) % 16)*16]
    vmovdqa     xmm13, [rax + ((13 + %1) % 16)*16]
    vmovdqa     xmm15, [rax + ((15 + %1) % 16)*16]

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



    vmovdqa     [rax + (( 0 + %1) % 16)*16], xmm0

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


MKGLOBAL(asm_ZucInitialization_4_avx,function,internal)
asm_ZucInitialization_4_avx:

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
    vmovdqa  xmm12, [rel mask31]

    ; Shift LFSR 32-times, update state variables
%assign N 0
%rep 32
    pop     rdx
    lea     rax, [rdx]
    push    rdx

    bits_reorg4 N
    nonlin_fun4 1
    vpsrld  xmm0,1         ; Shift out LSB of W

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

    vpxor    xmm0, xmm0
    lfsr_updt4  0

    FUNC_RESTORE

    ret

;
; Generate N*4 bytes of keystream
; for 4 buffers (where N is number of rounds)
;
%macro KEYGEN_4_AVX 1
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
    vmovdqa     xmm12, [rel mask31]

    ; Generate N*4B of keystream in N rounds
%assign N 1
%rep %%NUM_ROUNDS
    bits_reorg4 N
    nonlin_fun4 1
    store_kstr4
    vpxor        xmm0, xmm0
    lfsr_updt4  N
%assign N N+1
%endrep

    ;; Restore rsp pointer to value before pushing keystreams
    add         rsp, 4*8

    FUNC_RESTORE


%endmacro

;
;; void asm_ZucGenKeystream64B_4_avx(state4_t *pSta, u32* pKeyStr1, u32* pKeyStr2, u32* pKeyStr3, u32* pKeyStr4);
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
MKGLOBAL(asm_ZucGenKeystream64B_4_avx,function,internal)
asm_ZucGenKeystream64B_4_avx:

    KEYGEN_4_AVX 16

    ret

;
;; void asm_ZucGenKeystream8B_4_avx(state4_t *pSta, u32* pKeyStr1, u32* pKeyStr2, u32* pKeyStr3, u32* pKeyStr4);
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
MKGLOBAL(asm_ZucGenKeystream8B_4_avx,function,internal)
asm_ZucGenKeystream8B_4_avx:

    KEYGEN_4_AVX 2

    ret

;;
;; void asm_ZucCipher64B_4_avx(state4_t *pSta, u32 *pKeyStr[4], u64 *pIn[4],
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
MKGLOBAL(asm_ZucCipher64B_4_avx,function,internal)
asm_ZucCipher64B_4_avx:

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
        vmovdqa xmm12, [rel mask31]

        ; Generate 64B of keystream in 16 rounds
%assign N 1
%rep 16
        bits_reorg4 N
        nonlin_fun4 1
        store_kstr4
        vpxor   xmm0, xmm0
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

        vmovdqa  xmm15, [rel swap_mask]

%assign off 0
%rep 4
        ;; XOR Input buffer with keystream in rounds of 16B
        mov     r12, [pIn]
        mov     r13, [pIn + 8]
        mov     r14, [pIn + 16]
        mov     r15, [pIn + 24]
        vmovdqu xmm0, [r12 + bufOff + off]
        vmovdqu xmm1, [r13 + bufOff + off]
        vmovdqu xmm2, [r14 + bufOff + off]
        vmovdqu xmm3, [r15 + bufOff + off]

        mov     r12, [pKS]
        mov     r13, [pKS + 8]
        mov     r14, [pKS + 16]
        mov     r15, [pKS + 24]
        vmovdqa xmm4, [r12 + off]
        vmovdqa xmm5, [r13 + off]
        vmovdqa xmm6, [r14 + off]
        vmovdqa xmm7, [r15 + off]

        vpshufb xmm4, xmm15
        vpshufb xmm5, xmm15
        vpshufb xmm6, xmm15
        vpshufb xmm7, xmm15

        vpxor   xmm4, xmm0
        vpxor   xmm5, xmm1
        vpxor   xmm6, xmm2
        vpxor   xmm7, xmm3

        mov     r12, [pOut]
        mov     r13, [pOut + 8]
        mov     r14, [pOut + 16]
        mov     r15, [pOut + 24]

        vmovdqu [r12 + bufOff + off], xmm4
        vmovdqu [r13 + bufOff + off], xmm5
        vmovdqu [r14 + bufOff + off], xmm6
        vmovdqu [r15 + bufOff + off], xmm7
%assign off (off + 16)
%endrep

        FUNC_RESTORE

        ret

;;
;; extern uint32_t asm_Eia3RemainderAVX(const void *ks, const void *data, uint64_t n_bits)
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
align 64
MKGLOBAL(asm_Eia3RemainderAVX,function,internal)
asm_Eia3RemainderAVX:

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

        vmovdqa  xmm5, [bit_reverse_table_l]
        vmovdqa  xmm6, [bit_reverse_table_h]
        vmovdqa  xmm7, [bit_reverse_and_table]
        vmovdqa  xmm10, [data_mask_64bits]
        vpxor    xmm9, xmm9

%rep 3
        cmp     N_BITS, 128
        jb      Eia3RoundsAVX_dq_end

        ;; read 16 bytes and reverse bits
        vmovdqu xmm0, [DATA]
        vmovdqa xmm1, xmm0
        vpand   xmm1, xmm7

        vmovdqa xmm2, xmm7
        vpandn  xmm2, xmm0
        vpsrld  xmm2, 4

        vmovdqa xmm8, xmm6      ; bit reverse low nibbles (use high table)
        vpshufb xmm8, xmm1

        vmovdqa xmm4, xmm5      ; bit reverse high nibbles (use low table)
        vpshufb xmm4, xmm2

        vpor    xmm8, xmm4
        ; xmm8 - bit reversed data bytes

        ;; ZUC authentication part
        ;; - 4x32 data bits
        ;; - set up KS
        vmovdqu xmm3, [KS + (0*4)]
        vmovdqu xmm4, [KS + (2*4)]
        vpshufd xmm0, xmm3, 0x61
        vpshufd xmm1, xmm4, 0x61

        ;;  - set up DATA
        vmovdqa xmm2, xmm8
        vpand   xmm2, xmm10
        vpshufd xmm3, xmm2, 0xdc
        vmovdqa xmm4, xmm3

        vpsrldq xmm8, 8
        vpshufd xmm13, xmm8, 0xdc
        vmovdqa xmm14, xmm13

        ;; - clmul
        ;; - xor the results from 4 32-bit words together
        vpclmulqdq xmm3, xmm0, 0x00
        vpclmulqdq xmm4, xmm0, 0x11
        vpclmulqdq xmm13, xmm1, 0x00
        vpclmulqdq xmm14, xmm1, 0x11

        vpxor    xmm3, xmm4
        vpxor    xmm13, xmm14
        vpxor    xmm9, xmm3
        vpxor    xmm9, xmm13
        lea     DATA, [DATA + 16]
        lea     KS, [KS + 16]
        sub     N_BITS, 128
%endrep
Eia3RoundsAVX_dq_end:

%rep 3
        cmp     N_BITS, 32
        jb      Eia3RoundsAVX_dw_end

        ;; swap dwords in KS
        vmovq   xmm1, [KS]
        vpshufd xmm4, xmm1, 0xf1

        ;;  bit-reverse 4 bytes of data
        vmovdqa xmm2, xmm7
        vmovd   xmm0, [DATA]
        vmovdqa xmm1, xmm0
        vpand   xmm1, xmm2

        vpandn  xmm2, xmm0
        vpsrld  xmm2, 4

        vmovdqa xmm0, xmm6    ; bit reverse low nibbles (use high table)
        vpshufb xmm0, xmm1

        vmovdqa xmm3, xmm5    ; bit reverse high nibbles (use low table)
        vpshufb xmm3, xmm2

        vpor    xmm0, xmm3

        ;; rol & xor
        vpclmulqdq xmm0, xmm4, 0
        vpxor    xmm9, xmm0

        lea     DATA, [DATA + 4]
        lea     KS, [KS + 4]
        sub     N_BITS, 32
%endrep

Eia3RoundsAVX_dw_end:
        vmovq   rax, xmm9
        shr     rax, 32

        or      N_BITS, N_BITS
        jz      Eia3RoundsAVX_byte_loop_end

        ;; get 64-bit key stream for the last data bits (less than 32)
        mov     KS, [KS]

        ;; process remaining data bytes and bits
Eia3RoundsAVX_byte_loop:
        or      N_BITS, N_BITS
        jz      Eia3RoundsAVX_byte_loop_end

        cmp     N_BITS, 8
        jb      Eia3RoundsAVX_byte_partial

        movzx   r11, byte [DATA]
        sub     N_BITS, 8
        jmp     Eia3RoundsAVX_byte_read

Eia3RoundsAVX_byte_partial:
        ;; process remaining bits (up to 7)
        lea     r11, [bit_mask_table]
        movzx   r10, byte [r11 + N_BITS]
        movzx   r11, byte [DATA]
        and     r11, r10
        xor     N_BITS, N_BITS
Eia3RoundsAVX_byte_read:

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
        jmp     Eia3RoundsAVX_byte_loop

Eia3RoundsAVX_byte_loop_end:

        ;; eax - holds the return value at this stage
        FUNC_RESTORE

        ret

;;
;;extern uint32_t asm_Eia3Round64BAVX(uint32_t T, const void *KS, const void *DATA)
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
align 64
MKGLOBAL(asm_Eia3Round64BAVX,function,internal)
asm_Eia3Round64BAVX:

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

        vmovdqa  xmm5, [bit_reverse_table_l]
        vmovdqa  xmm6, [bit_reverse_table_h]
        vmovdqa  xmm7, [bit_reverse_and_table]
        vmovdqa  xmm10, [data_mask_64bits]

        vpxor    xmm9, xmm9
%assign I 0
%rep 4
        ;; read 16 bytes and reverse bits
        vmovdqu  xmm0, [DATA + 16*I]
        vpand    xmm1, xmm0, xmm7

        vpandn   xmm2, xmm7, xmm0
        vpsrld   xmm2, 4

        vpshufb  xmm8, xmm6, xmm1       ; bit reverse low nibbles (use high table)
        vpshufb  xmm4, xmm5, xmm2       ; bit reverse high nibbles (use low table)

        vpor     xmm8, xmm4
        ; xmm8 - bit reversed data bytes

        ;; ZUC authentication part
        ;; - 4x32 data bits
        ;; - set up KS
%if I != 0
        vmovdqa  xmm11, xmm12
        vmovdqu  xmm12, [KS + (I*16) + (4*4)]
%else
        vmovdqu  xmm11, [KS + (I*16) + (0*4)]
        vmovdqu  xmm12, [KS + (I*16) + (4*4)]
%endif
        vpalignr xmm13, xmm12, xmm11, 8
        vpshufd  xmm2, xmm11, 0x61
        vpshufd  xmm3, xmm13, 0x61

        ;;  - set up DATA
        vpand    xmm13, xmm10, xmm8
        vpshufd  xmm0, xmm13, 0xdc

        vpsrldq  xmm8, 8
        vpshufd  xmm1, xmm8, 0xdc

        ;; - clmul
        ;; - xor the results from 4 32-bit words together
%if I != 0
        vpclmulqdq xmm13, xmm0, xmm2, 0x00
        vpclmulqdq xmm14, xmm0, xmm2, 0x11
        vpclmulqdq xmm15, xmm1, xmm3, 0x00
        vpclmulqdq xmm8,  xmm1, xmm3, 0x11

        vpxor    xmm13, xmm14
        vpxor    xmm15, xmm8
        vpxor    xmm9, xmm13
        vpxor    xmm9, xmm15
%else
        vpclmulqdq xmm9, xmm0, xmm2, 0x00
        vpclmulqdq xmm13, xmm0, xmm2, 0x11
        vpclmulqdq xmm14, xmm1, xmm3, 0x00
        vpclmulqdq xmm15, xmm1, xmm3, 0x11

        vpxor    xmm14, xmm15
        vpxor    xmm9, xmm13
        vpxor    xmm9, xmm14
%endif


%assign I (I + 1)
%endrep

        ;; - update T
        vmovq   rax, xmm9
        shr     rax, 32
        xor     eax, T

        FUNC_RESTORE

        ret


;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
