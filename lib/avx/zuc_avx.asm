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

%define APPEND(a,b) a %+ b

section .data
default rel

align 16
Ek_d:
dd      0x0044D700, 0x0026BC00, 0x00626B00, 0x00135E00,
dd      0x00578900, 0x0035E200, 0x00713500, 0x0009AF00
dd      0x004D7800, 0x002F1300, 0x006BC400, 0x001AF100,
dd      0x005E2600, 0x003C4D00, 0x00789A00, 0x0047AC00

align 16
shuf_mask_key:
dd      0x00FFFFFF, 0x01FFFFFF, 0x02FFFFFF, 0x03FFFFFF,
dd      0x04FFFFFF, 0x05FFFFFF, 0x06FFFFFF, 0x07FFFFFF,
dd      0x08FFFFFF, 0x09FFFFFF, 0x0AFFFFFF, 0x0BFFFFFF,
dd      0x0CFFFFFF, 0x0DFFFFFF, 0x0EFFFFFF, 0x0FFFFFFF,

align 16
shuf_mask_iv:
dd      0xFFFFFF00, 0xFFFFFF01, 0xFFFFFF02, 0xFFFFFF03,
dd      0xFFFFFF04, 0xFFFFFF05, 0xFFFFFF06, 0xFFFFFF07,
dd      0xFFFFFF08, 0xFFFFFF09, 0xFFFFFF0A, 0xFFFFFF0B,
dd      0xFFFFFF0C, 0xFFFFFF0D, 0xFFFFFF0E, 0xFFFFFF0F,

align 16
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

%macro TRANSPOSE4_U32 6
%define %%r0 %1
%define %%r1 %2
%define %%r2 %3
%define %%r3 %4
%define %%t0 %5
%define %%t1 %6

	vshufps	%%t0, %%r0, %%r1, 0x44	; t0 = {b1 b0 a1 a0}
	vshufps	%%r0, %%r0, %%r1, 0xEE	; r0 = {b3 b2 a3 a2}
	vshufps %%t1, %%r2, %%r3, 0x44	; t1 = {d1 d0 c1 c0}
	vshufps	%%r2, %%r2, %%r3, 0xEE	; r2 = {d3 d2 c3 c2}

	vshufps	%%r1, %%t0, %%t1, 0xDD	; r1 = {d1 c1 b1 a1}
	vshufps	%%r3, %%r0, %%r2, 0xDD	; r3 = {d3 c3 b3 a3}
	vshufps	%%r2, %%r0, %%r2, 0x88	; r2 = {d2 c2 b2 a2}
	vshufps	%%r0, %%t0, %%t1, 0x88	; r0 = {d0 c0 b0 a0}
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
;       %2 - XMM register storing X3
;       rax - LFSR pointer
;   uses
;
;   return
;
%macro  bits_reorg4 1-2
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
%if (%0 == 2)
    vpslld      xmm2, 16
    vpsrld      xmm0, 15
    vpor        %2, xmm2, xmm0
%endif
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
;   store16B_kstr4()
;
%macro  store16B_kstr4 4
%define %%DATA16B_L0  %1  ; [in] 16 bytes of keystream for lane 0
%define %%DATA16B_L1  %2  ; [in] 16 bytes of keystream for lane 1
%define %%DATA16B_L2  %3  ; [in] 16 bytes of keystream for lane 2
%define %%DATA16B_L3  %4  ; [in] 16 bytes of keystream for lane 3

    mov         rcx, [rsp]
    mov         rdx, [rsp + 8]
    mov         r8,  [rsp + 16]
    mov         r9,  [rsp + 24]
    vmovdqu     [rcx], %%DATA16B_L0
    vmovdqu     [rdx], %%DATA16B_L1
    vmovdqu     [r8],  %%DATA16B_L2
    vmovdqu     [r9],  %%DATA16B_L3
%endmacro

;
;   store4B_kstr4()
;
;   params
;
;   %1 - XMM register with OFS_X3
;   return
;
%macro  store4B_kstr4 1
    mov         rcx, [rsp]
    mov         rdx, [rsp + 8]
    mov         r8,  [rsp + 16]
    mov         r9,  [rsp + 24]
    vpextrd     [r9], %1, 3
    vpextrd     [r8], %1, 2
    vpextrd     [rdx], %1, 1
    vmovd       [rcx], %1
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
; Initialize LFSR registers for a single lane
;
; This macro initializes 4 LFSR registers at a time.
; so it needs to be called four times.
;
; From spec, s_i (LFSR) registers need to be loaded as follows:
;
; For 0 <= i <= 15, let s_i= k_i || d_i || iv_i.
; Where k_i is each byte of the key, d_i is a 15-bit constant
; and iv_i is each byte of the IV.
;
%macro INIT_LFSR 7
%define %%KEY       %1 ;; [in] XMM register containing 16-byte key
%define %%IV        %2 ;; [in] XMM register containing 16-byte IV
%define %%SHUF_KEY  %3 ;; [in] Shuffle key mask
%define %%SHUF_IV   %4 ;; [in] Shuffle key mask
%define %%EKD_MASK  %5 ;; [in] Shuffle key mask
%define %%LFSR      %6 ;; [out] XMM register to contain initialized LFSR regs
%define %%XTMP      %7 ;; [clobbered] XMM temporary register

    vpshufb         %%LFSR, %%KEY, %%SHUF_KEY
    vpsrld          %%LFSR, 1
    vpshufb         %%XTMP, %%IV, %%SHUF_IV
    vpor            %%LFSR, %%XTMP
    vpor            %%LFSR, %%EKD_MASK

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

    mov     rax, pState

    ;; Load key and IVs
%assign off 0
%assign i 4
%assign j 8
%rep 4
    mov     r9,  [pKe + off]
    mov     r10, [pIv + off]
    vmovdqu APPEND(xmm,i), [r9]
    vmovdqu APPEND(xmm,j), [r10]
%assign off (off + 8)
%assign i (i + 1)
%assign j (j + 1)
%endrep

    ;;; Initialize all LFSR registers in two steps:
    ;;; first, registers 0-3, then registers 4-7, 8-11, 12-15

%assign off 0
%rep 4
    ; Set read-only registers for shuffle masks for key, IV and Ek_d for 8 registers
    vmovdqa xmm13, [rel shuf_mask_key + off]
    vmovdqa xmm14, [rel shuf_mask_iv + off]
    vmovdqa xmm15, [rel Ek_d + off]

    ; Set 4xLFSR registers for all packets
%assign idx 0
%assign i 4
%assign j 8
%rep 4
    INIT_LFSR APPEND(xmm,i), APPEND(xmm,j), xmm13, xmm14, xmm15, APPEND(xmm, idx), xmm12
%assign idx (idx + 1)
%assign i (i + 1)
%assign j (j + 1)
%endrep

    ; Store 4xLFSR registers in memory (reordering first,
    ; so all SX registers are together)
    TRANSPOSE4_U32  xmm0, xmm1, xmm2, xmm3, xmm13, xmm14

%assign i 0
%rep 4
    vmovdqa [pState + 4*off + 16*i], APPEND(xmm, i)
%assign i (i+1)
%endrep

%assign off (off + 16)
%endrep

    ; Load read-only registers
    vmovdqa  xmm12, [rel mask31]

    ; Shift LFSR 32-times, update state variables
%assign N 0
%rep 32
    bits_reorg4 N
    nonlin_fun4 1
    vpsrld  xmm0,1         ; Shift out LSB of W
    lfsr_updt4  N           ; W (xmm0) used in LFSR update - not set to zero
%assign N N+1
%endrep

    ; And once more, initial round from keygen phase = 33 times
    bits_reorg4 0
    nonlin_fun4 0
    vpxor    xmm0, xmm0
    lfsr_updt4  0

    FUNC_RESTORE

    ret

%macro REORDER_LFSR 2
%define %%STATE      %1
%define %%NUM_ROUNDS %2

%assign %%i 0
%rep 16
    vmovdqa APPEND(xmm,%%i), [%%STATE + 16*%%i]
%assign %%i (%%i+1)
%endrep

%assign %%i 0
%assign %%j %%NUM_ROUNDS
%rep 16
    vmovdqa [%%STATE + 16*%%i], APPEND(xmm,%%j)
%assign %%i (%%i+1)
%assign %%j ((%%j+1) % 16)
%endrep

%endmacro

;
; Generate N*4 bytes of keystream
; for 4 buffers (where N is number of rounds)
;
%macro KEYGEN_4_AVX 1
%define %%NUM_ROUNDS    %1 ; [in] Number of 4-byte rounds

%ifdef LINUX
	%define		pState	rdi
	%define		pKS	rsi
%else
	%define		pState	rcx
	%define		pKS	rdx
%endif

    FUNC_SAVE

    ; Store 4 keystream pointers on the stack
    ; and reserve memory for storing keystreams for all 4 buffers
    mov     r10, rsp
    sub     rsp, (4*8 + %%NUM_ROUNDS * 16)
    and     rsp, -15

%assign i 0
%rep 2
    vmovdqa     xmm0, [pKS + 16*i]
    vmovdqa     [rsp + 16*i], xmm0
%assign i (i+1)
%endrep

    ; Load state pointer in RAX
    mov         rax, pState

    ; Load read-only registers
    vmovdqa     xmm12, [rel mask31]

    ; Generate N*4B of keystream in N rounds
%assign N 1
%rep %%NUM_ROUNDS
    bits_reorg4 N, xmm10
    nonlin_fun4 1
    ; OFS_X3 XOR W (xmm0) and store in stack
    vpxor       xmm10, xmm0
    vmovdqa [rsp + 4*8 + (N-1)*16], xmm10
    vpxor       xmm0, xmm0
    lfsr_updt4  N
%assign N N+1
%endrep

%if (%%NUM_ROUNDS == 4)
    ;; Load all OFS_X3
%assign i 0
%rep 4
    vmovdqa     APPEND(xmm,i), [rsp + 4*8 + i*16]
%assign i (i+1)
%endrep

    TRANSPOSE4_U32 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5

    store16B_kstr4 xmm0, xmm1, xmm2, xmm3
%else ;; NUM_ROUNDS != 4
%assign idx 0
%rep %%NUM_ROUNDS
    vmovdqa APPEND(xmm, idx), [rsp + 4*8 + idx*16]
    store4B_kstr4 APPEND(xmm, idx)
%assign idx (idx + 1)
%endrep
%endif ;; NUM_ROUNDS == 4

        ;; Clear stack frame containing keystream information
%ifdef SAFE_DATA
    vpxor   xmm0, xmm0
%assign i 0
%rep (2+%%NUM_ROUNDS)
    vmovdqa [rsp + i*16], xmm0
%assign i (i+1)
%endrep
%endif

    ;; Reorder memory for LFSR registers, as not all 16 rounds
    ;; will be completed (can be 4 or 2)
    REORDER_LFSR rax, %%NUM_ROUNDS

    ;; Restore rsp pointer to value before pushing keystreams
    mov         rsp, r10

    FUNC_RESTORE


%endmacro

;
;; void asm_ZucGenKeystream16B_4_avx(state4_t *pSta, u32* pKeyStr[4]);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(asm_ZucGenKeystream16B_4_avx,function,internal)
asm_ZucGenKeystream16B_4_avx:

    KEYGEN_4_AVX 4

    ret

;
;; void asm_ZucGenKeystream8B_4_avx(state4_t *pSta, u32* pKeyStr[4]);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(asm_ZucGenKeystream8B_4_avx,function,internal)
asm_ZucGenKeystream8B_4_avx:

    KEYGEN_4_AVX 2

    ret

;;
;; void asm_ZucCipher16B_4_avx(state4_t *pSta, u32 *pKeyStr[4], u64 *pIn[4],
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
MKGLOBAL(asm_ZucCipher16B_4_avx,function,internal)
asm_ZucCipher16B_4_avx:

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
        mov     r10, rsp
        sub     rsp, 8*8
        and     rsp, -15
%assign i 0
%rep 2
        vmovdqa xmm0, [pKS + 16*i]
        vmovdqa [rsp + 16*i], xmm0
%assign i (i+1)
%endrep
        mov     [rsp + 32], pKS
        mov     [rsp + 40], pIn
        mov     [rsp + 48], pOut
        mov     [rsp + 56], bufOff

        ; Load state pointer in RAX
        mov     rax, pState

        ; Load read-only registers
        vmovdqa xmm12, [rel mask31]

        ; Generate 16B of keystream in 4 rounds
%assign N 1
%rep 4
        bits_reorg4 N, xmm10
        nonlin_fun4 1
        ; OFS_XR XOR W (xmm0)
        vpxor   xmm10, xmm0
        store4B_kstr4 xmm10
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
        mov     rsp, r10

        vmovdqa  xmm15, [rel swap_mask]

        ;; XOR Input buffer with keystream in rounds of 16B
        mov     r12, [pIn]
        mov     r13, [pIn + 8]
        mov     r14, [pIn + 16]
        mov     r15, [pIn + 24]
        vmovdqu xmm0, [r12 + bufOff]
        vmovdqu xmm1, [r13 + bufOff]
        vmovdqu xmm2, [r14 + bufOff]
        vmovdqu xmm3, [r15 + bufOff]

        mov     r12, [pKS]
        mov     r13, [pKS + 8]
        mov     r14, [pKS + 16]
        mov     r15, [pKS + 24]
        vmovdqa xmm4, [r12]
        vmovdqa xmm5, [r13]
        vmovdqa xmm6, [r14]
        vmovdqa xmm7, [r15]

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

        vmovdqu [r12 + bufOff], xmm4
        vmovdqu [r13 + bufOff], xmm5
        vmovdqu [r14 + bufOff], xmm6
        vmovdqu [r15 + bufOff], xmm7

        ;; Reorder memory for LFSR registers, as not all 16 rounds
        ;; will be completed
        REORDER_LFSR rax, 4

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
        vpand   xmm1, xmm0, xmm7

        vpandn  xmm2, xmm7, xmm0
        vpsrld  xmm2, 4

        vpshufb xmm8, xmm6, xmm1 ; bit reverse low nibbles (use high table)
        vpshufb xmm4, xmm5, xmm2 ; bit reverse high nibbles (use low table)

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
        vpand   xmm2, xmm8, xmm10
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
        vmovd   xmm0, [DATA]
        vpand   xmm1, xmm0, xmm7

        vpandn  xmm2, xmm7, xmm0
        vpsrld  xmm2, 4

        vpshufb xmm0, xmm6, xmm1 ; bit reverse low nibbles (use high table)
        vpshufb xmm3, xmm5, xmm2 ; bit reverse high nibbles (use low table)

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

%macro EIA3_ROUND 1
%define %%NUM_16B_ROUNDS %1

%ifdef LINUX
	%define		T	edi
	%define		KS	rsi
	%define		DATA	rdx
%else
	%define		T	ecx
	%define		KS	rdx
	%define		DATA	r8
%endif

        vmovdqa  xmm5, [bit_reverse_table_l]
        vmovdqa  xmm6, [bit_reverse_table_h]
        vmovdqa  xmm7, [bit_reverse_and_table]
        vmovdqa  xmm10, [data_mask_64bits]

        vpxor    xmm9, xmm9
%assign I 0
%rep %%NUM_16B_ROUNDS
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

%endmacro

;;
;;extern uint32_t asm_Eia3Round64BAVX(uint32_t T, const void *KS, const void *DATA)
;;
;; Updates authentication tag T based on keystream KS and DATA.
;; - it processes 64 bytes of DATA
;; - reads data in 16 byte chunks and bit reverses them
;; - reads and re-arranges KS
;; - employs clmul for the XOR & ROL part
;; - copies top 64 bytes of KS to bottom (for the next round)
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

        FUNC_SAVE

        EIA3_ROUND 4

        FUNC_RESTORE

        ret

;;
;;extern uint32_t asm_Eia3Round32BAVX(uint32_t T, const void *KS, const void *DATA)
;;
;; Updates authentication tag T based on keystream KS and DATA.
;; - it processes 32 bytes of DATA
;; - reads data in 16 byte chunks and bit reverses them
;; - reads and re-arranges KS
;; - employs clmul for the XOR & ROL part
;; - copies top 32 bytes of KS to bottom (for the next round)
;;
;; WIN64
;;	RCX - T
;;	RDX - KS pointer to key stream (2 x 32 bytes)
;;;     R8  - DATA pointer to data
;; LIN64
;;	RDI - T
;;	RSI - KS pointer to key stream (2 x 32 bytes)
;;      RDX - DATA pointer to data
;;
align 64
MKGLOBAL(asm_Eia3Round32BAVX,function,internal)
asm_Eia3Round32BAVX:

        FUNC_SAVE

        EIA3_ROUND 2

        FUNC_RESTORE

        ret

;;
;;extern uint32_t asm_Eia3Round16BAVX(uint32_t T, const void *KS, const void *DATA)
;;
;; Updates authentication tag T based on keystream KS and DATA.
;; - it processes 16 bytes of DATA
;; - reads data in 16 byte chunks and bit reverses them
;; - reads and re-arranges KS
;; - employs clmul for the XOR & ROL part
;; - copies top 16 bytes of KS to bottom (for the next round)
;;
;; WIN64
;;	RCX - T
;;	RDX - KS pointer to key stream (2 x 16 bytes)
;;;     R8  - DATA pointer to data
;; LIN64
;;	RDI - T
;;	RSI - KS pointer to key stream (2 x 16 bytes)
;;      RDX - DATA pointer to data
;;
align 64
MKGLOBAL(asm_Eia3Round16BAVX,function,internal)
asm_Eia3Round16BAVX:

        FUNC_SAVE

        EIA3_ROUND 1

        FUNC_RESTORE

        ret

;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
