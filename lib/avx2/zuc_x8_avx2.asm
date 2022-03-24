;;
;; Copyright (c) 2020-2022, Intel Corporation
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
%include "include/memcpy.asm"
%include "include/mb_mgr_datastruct.asm"
%include "include/cet.inc"

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    qword [rsp + 40]
%endif

%define APPEND(a,b) a %+ b

mksection .rodata
default rel

align 32
Ek_d:
dd	0x0044D700, 0x0026BC00, 0x00626B00, 0x00135E00, 0x00578900, 0x0035E200, 0x00713500, 0x0009AF00
dd	0x004D7800, 0x002F1300, 0x006BC400, 0x001AF100, 0x005E2600, 0x003C4D00, 0x00789A00, 0x0047AC00

; Constants to be used to initialize the LFSR registers
; The tables contain four different sets of constants:
; 0-63 bytes: Encryption
; 64-127 bytes: Authentication with tag size = 4
; 128-191 bytes: Authentication with tag size = 8
; 192-255 bytes: Authentication with tag size = 16
align 16
EK256_d64:
dd      0x00220000, 0x002F0000, 0x00240000, 0x002A0000,
dd      0x006D0000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00520000, 0x00100000, 0x00300000

align 16
EK256_EIA3_4:
dd      0x00220000, 0x002F0000, 0x00250000, 0x002A0000,
dd      0x006D0000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00520000, 0x00100000, 0x00300000

align 16
EK256_EIA3_8:
dd      0x00230000, 0x002F0000, 0x00240000, 0x002A0000,
dd      0x006D0000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00520000, 0x00100000, 0x00300000

align 16
EK256_EIA3_16:
dd      0x00230000, 0x002F0000, 0x00250000, 0x002A0000,
dd      0x006D0000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00520000, 0x00100000, 0x00300000

align 32
shuf_mask_key:
dd      0x00FFFFFF, 0x01FFFFFF, 0x02FFFFFF, 0x03FFFFFF, 0x04FFFFFF, 0x05FFFFFF, 0x06FFFFFF, 0x07FFFFFF,
dd      0x08FFFFFF, 0x09FFFFFF, 0x0AFFFFFF, 0x0BFFFFFF, 0x0CFFFFFF, 0x0DFFFFFF, 0x0EFFFFFF, 0x0FFFFFFF,

align 32
shuf_mask_iv:
dd      0xFFFFFF00, 0xFFFFFF01, 0xFFFFFF02, 0xFFFFFF03, 0xFFFFFF04, 0xFFFFFF05, 0xFFFFFF06, 0xFFFFFF07,
dd      0xFFFFFF08, 0xFFFFFF09, 0xFFFFFF0A, 0xFFFFFF0B, 0xFFFFFF0C, 0xFFFFFF0D, 0xFFFFFF0E, 0xFFFFFF0F,

align 16
shuf_mask_iv_17_19:
db      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0x02, 0xFF

align 16
clear_iv_mask:
db      0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x3F, 0x00

align 16
shuf_mask_iv_20_23:
db      0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0x02, 0xFF, 0xFF, 0xFF, 0x03, 0xFF

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
S0_S1_shuf:
db      0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
db      0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,

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

align 16
broadcast_word:
db      0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01
db      0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01

align 16
all_threes:
dw      0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003

align 16
all_fffcs:
dw      0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc

align 16
all_1fs:
dw      0x001f, 0x001f, 0x001f, 0x001f, 0x001f, 0x001f, 0x001f, 0x001f

align 16
all_20s:
dw      0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020, 0x0020

mksection .text
align 64

%define OFS_R1  (16*(2*16))
%define OFS_R2  (OFS_R1 + (2*16))
%define OFS_X0  (OFS_R2 + (2*16))
%define OFS_X1  (OFS_X0 + (2*16))
%define OFS_X2  (OFS_X1 + (2*16))

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
; Transpose 4 YMM registers, double word granularity
;
%macro TRANSPOSE4_U32 8
%define %%R0 %1 ; [in/out] Input / Output row 0
%define %%R1 %2 ; [in/out] Input / Output row 1
%define %%R2 %3 ; [in/out] Input / Output row 2
%define %%R3 %4 ; [in/out] Input / Output row 3
%define %%T0 %5 ; [clobbered] Temporary YMM register
%define %%T1 %6 ; [clobbered] Temporary YMM register
%define %%T2 %7 ; [clobbered] Temporary YMM register
%define %%T3 %8 ; [clobbered] Temporary YMM register

        vshufps %%T0, %%R0, %%R1, 0x44  ; T0 = {b5 b4 a5 a4   b1 b0 a1 a0}
        vshufps %%R0, %%R0, %%R1, 0xEE  ; R0 = {b7 b6 a7 a6   b3 b2 a3 a2}
        vshufps %%T1, %%R2, %%R3, 0x44  ; T1 = {d5 d4 c5 c4   d1 d0 c1 c0}
        vshufps %%R2, %%R2, %%R3, 0xEE  ; R2 = {d7 d6 c7 c6   d3 d2 c3 c2}

        vshufps %%T3, %%T0, %%T1, 0xDD  ; T3 = {d5 c5 b5 a5   d1 c1 b1 a1}
        vshufps %%T2, %%R0, %%R2, 0x88  ; T2 = {d6 c6 b6 a6   d2 c2 b2 a2}
        vshufps %%R0, %%R0, %%R2, 0xDD  ; R0 = {d7 c7 b7 a7   d3 c3 b3 a3}
        vshufps %%T0, %%T0, %%T1, 0x88  ; T0 = {d4 c4 b4 a4   d0 c0 b0 a0}

        vperm2i128 %%R2, %%T0, %%T3, 0x31  ; {d5 c5 b5 a5 d4 c4 b4 a4}
        vperm2i128 %%R1, %%T2, %%R0, 0x20  ; {d3 c3 b3 a3 d2 c2 b2 a2}
        vperm2i128 %%R3, %%T2, %%R0, 0x31  ; {d7 c7 b7 a7 d6 c6 b6 a6}
        vperm2i128 %%R0, %%T0, %%T3, 0x20  ; {d1 c1 b1 a1 d0 c0 b0 a0}
%endmacro

; This macro reorder the LFSR registers
; after N rounds (1 <= N <= 15), since the registers
; are shifted every round
;
; The macro clobbers YMM0-15
;
%macro REORDER_LFSR 2
%define %%STATE      %1 ; [in] Pointer to LFSR state
%define %%NUM_ROUNDS %2 ; [immediate] Number of key generation rounds

%if %%NUM_ROUNDS != 16
%assign i 0
%rep 16
        vmovdqa APPEND(ymm,i), [%%STATE + 32*i]
%assign i (i+1)
%endrep

%assign i 0
%assign j %%NUM_ROUNDS
%rep 16
        vmovdqa [%%STATE + 32*i], APPEND(ymm,j)
%assign i (i+1)
%assign j ((j+1) % 16)
%endrep
%endif ;; %%NUM_ROUNDS != 16

%endmacro

;
; Calculates X0-X3 from LFSR registers
;
%macro  BITS_REORG8 12-13
%define %%STATE         %1  ; [in] ZUC state
%define %%ROUND_NUM     %2  ; [in] Round number
%define %%LFSR_0        %3  ; [clobbered] LFSR_0
%define %%LFSR_2        %4  ; [clobbered] LFSR_2
%define %%LFSR_5        %5  ; [clobbered] LFSR_5
%define %%LFSR_7        %6  ; [clobbered] LFSR_7
%define %%LFSR_9        %7  ; [clobbered] LFSR_9
%define %%LFSR_11       %8  ; [clobbered] LFSR_11
%define %%LFSR_14       %9  ; [clobbered] LFSR_14
%define %%LFSR_15       %10 ; [clobbered] LFSR_15
%define %%YTMP1         %11 ; [clobbered] Temporary YMM register
%define %%YTMP2         %12 ; [clobbered] Temporary YMM register
%define %%X3            %13 ; [out] YMM register containing X3 of all lanes (only for work mode)
        vmovdqa %%LFSR_15, [%%STATE + ((15 + %%ROUND_NUM) % 16)*32]
        vmovdqa %%LFSR_14, [%%STATE + ((14 + %%ROUND_NUM) % 16)*32]
        vmovdqa %%LFSR_11, [%%STATE + ((11 + %%ROUND_NUM) % 16)*32]
        vmovdqa %%LFSR_9,  [%%STATE + (( 9 + %%ROUND_NUM) % 16)*32]
        vmovdqa %%LFSR_7,  [%%STATE + (( 7 + %%ROUND_NUM) % 16)*32]
        vmovdqa %%LFSR_5,  [%%STATE + (( 5 + %%ROUND_NUM) % 16)*32]
%if (%0 == 13) ;Only needed when generating X3 (for "working" mode)
        vmovdqa %%LFSR_2,  [%%STATE + (( 2 + %%ROUND_NUM) % 16)*32]
        vmovdqa %%LFSR_0,  [%%STATE + (( 0 + %%ROUND_NUM) % 16)*32]
%endif

        vpxor   %%YTMP1, %%YTMP1
        vpslld  %%LFSR_15, 1
        vpblendw %%YTMP2,  %%LFSR_14, %%YTMP1, 0xAA
        vpblendw %%LFSR_15, %%LFSR_15, %%YTMP2, 0x55

        vmovdqa [%%STATE + OFS_X0], %%LFSR_15   ; BRC_X0
        vpslld  %%LFSR_11, 16
        vpsrld  %%LFSR_9, 15
        vpor    %%LFSR_11, %%LFSR_9
        vmovdqa [%%STATE + OFS_X1], %%LFSR_11   ; BRC_X1
        vpslld  %%LFSR_7, 16
        vpsrld  %%LFSR_5, 15
        vpor    %%LFSR_7, %%LFSR_5
        vmovdqa [%%STATE + OFS_X2], %%LFSR_7    ; BRC_X2
%if (%0 == 13)
        vpslld  %%LFSR_2, 16
        vpsrld  %%LFSR_0, 15
        vpor    %%X3, %%LFSR_2, %%LFSR_0
%endif
%endmacro

;
;  Rotate dwords by N_BITS
;
%macro  ROT_MOD32 4
%define %%OUT    %1 ; [out] YMM register
%define %%IN     %2 ; [in] YMM register
%define %%YTMP   %3 ; [clobbered] YMM register
%define %%N_BITS %4 ; [constant] Number of bits

%if (%%N_BITS == 8)
        vpshufb %%OUT, %%IN, [rel rot8_mod32]
%elif (%%N_BITS == 16)
        vpshufb %%OUT, %%IN, [rel rot16_mod32]
%elif (%%N_BITS == 24)
        vpshufb %%OUT, %%IN, [rel rot24_mod32]
%else
        vpslld  %%OUT, %%IN, %%N_BITS
        vpsrld  %%YTMP, %%IN, (32 - %%N_BITS)
        vpor    %%OUT, %%YTMP
%endif
%endmacro

;
; Updates R1-R2, using X0-X3 and generates W (if needed)
;
%macro NONLIN_FUN8  8-9
%define %%STATE     %1  ; [in] ZUC state
%define %%YTMP1     %2  ; [clobbered] Temporary YMM register
%define %%YTMP2     %3  ; [clobbered] Temporary YMM register
%define %%YTMP3     %4  ; [clobbered] Temporary YMM register
%define %%YTMP4     %5  ; [clobbered] Temporary YMM register
%define %%YTMP5     %6  ; [clobbered] Temporary YMM register
%define %%YTMP6     %7  ; [clobbered] Temporary YMM register
%define %%YTMP7     %8  ; [clobbered] Temporary YMM register
%define %%W         %9  ; [out] ZMM register to contain W for all lanes

%if (%0 == 9)
        vmovdqa %%W, [%%STATE + OFS_X0]
        vpxor   %%W, [%%STATE + OFS_R1]
        vpaddd  %%W, [%%STATE + OFS_R2]    ; W = (BRC_X0 ^ F_R1) + F_R2
%endif

        vmovdqa %%YTMP1, [%%STATE + OFS_R1]
        vmovdqa %%YTMP2, [%%STATE + OFS_R2]
        vpaddd  %%YTMP1, [%%STATE + OFS_X1]    ; W1 = F_R1 + BRC_X1
        vpxor   %%YTMP2, [%%STATE + OFS_X2]    ; W2 = F_R2 ^ BRC_X2

        vpslld  %%YTMP3, %%YTMP1, 16
        vpsrld  %%YTMP4, %%YTMP1, 16
        vpslld  %%YTMP5, %%YTMP2, 16
        vpsrld  %%YTMP6, %%YTMP2, 16
        vpor    %%YTMP1, %%YTMP3, %%YTMP6
        vpor    %%YTMP2, %%YTMP4, %%YTMP5

        ROT_MOD32 %%YTMP3, %%YTMP1, %%YTMP7, 2
        ROT_MOD32 %%YTMP4, %%YTMP1, %%YTMP7, 10
        ROT_MOD32 %%YTMP5, %%YTMP1, %%YTMP7, 18
        ROT_MOD32 %%YTMP6, %%YTMP1, %%YTMP7, 24
        vpxor     %%YTMP1, %%YTMP3
        vpxor     %%YTMP1, %%YTMP4
        vpxor     %%YTMP1, %%YTMP5
        vpxor     %%YTMP1, %%YTMP6      ; XMM1 = U = L1(P)

        ROT_MOD32 %%YTMP3, %%YTMP2, %%YTMP7, 8
        ROT_MOD32 %%YTMP4, %%YTMP2, %%YTMP7, 14
        ROT_MOD32 %%YTMP5, %%YTMP2, %%YTMP7, 22
        ROT_MOD32 %%YTMP6, %%YTMP2, %%YTMP7, 30
        vpxor     %%YTMP2, %%YTMP3
        vpxor     %%YTMP2, %%YTMP4
        vpxor     %%YTMP2, %%YTMP5
        vpxor     %%YTMP2, %%YTMP6      ; XMM2 = V = L2(Q)

        ; Shuffle U and V to have all S0 lookups in %%YTMP1 and all S1 lookups in %%YTMP2

        ; Compress all S0 and S1 input values in each register
        vpshufb %%YTMP1, [rel S0_S1_shuf] ; S0: Bytes 0-7, S1: Bytes 8-15
        vpshufb %%YTMP2, [rel S0_S1_shuf] ; S0: Bytes 0-7, S1: Bytes 8-15

        vshufpd %%YTMP3, %%YTMP1, %%YTMP2, 0x00 ; All S0 input values
        vshufpd %%YTMP4, %%YTMP2, %%YTMP1, 0xFF ; All S1 input values

        ; Compute S0 and S1 values
        S0_comput_AVX2 %%YTMP3, %%YTMP1, %%YTMP2
        S1_comput_AVX2 %%YTMP4, %%YTMP1, %%YTMP2, %%YTMP5

        ; Need to shuffle back %%YTMP1 & %%YTMP2 before storing output
        ; (revert what was done before S0 and S1 computations)
        vshufpd %%YTMP1, %%YTMP3, %%YTMP4, 0xAA
        vshufpd %%YTMP2, %%YTMP3, %%YTMP4, 0x55

        vpshufb %%YTMP1, [rel rev_S0_S1_shuf]
        vpshufb %%YTMP2, [rel rev_S0_S1_shuf]

        vmovdqa [%%STATE + OFS_R1], %%YTMP1
        vmovdqa [%%STATE + OFS_R2], %%YTMP2
%endmacro

;
; Stores 32 bytes of keystream for 8 lanes
;
%macro  STORE32B_KSTR8 13
%define %%DATA32B_L0  %1  ; [in] 32 bytes of keystream for lane 0
%define %%DATA32B_L1  %2  ; [in] 32 bytes of keystream for lane 1
%define %%DATA32B_L2  %3  ; [in] 32 bytes of keystream for lane 2
%define %%DATA32B_L3  %4  ; [in] 32 bytes of keystream for lane 3
%define %%DATA32B_L4  %5  ; [in] 32 bytes of keystream for lane 4
%define %%DATA32B_L5  %6  ; [in] 32 bytes of keystream for lane 5
%define %%DATA32B_L6  %7  ; [in] 32 bytes of keystream for lane 6
%define %%DATA32B_L7  %8  ; [in] 32 bytes of keystream for lane 7
%define %%OUT_PTRS    %9  ; [in] Keystream pointers for all 8 lanes
%define %%TMP1        %10 ; [clobbered] Temporary GP register
%define %%TMP2        %11 ; [clobbered] Temporary GP register
%define %%TMP3        %12 ; [clobbered] Temporary GP register
%define %%TMP4        %13 ; [clobbered] Temporary GP register

        mov     %%TMP1, [%%OUT_PTRS]
        mov     %%TMP2, [%%OUT_PTRS + 8]
        mov     %%TMP3, [%%OUT_PTRS + 16]
        mov     %%TMP4, [%%OUT_PTRS + 24]
        vmovdqu [%%TMP1], %%DATA32B_L0
        vmovdqu [%%TMP2], %%DATA32B_L1
        vmovdqu [%%TMP3], %%DATA32B_L2
        vmovdqu [%%TMP4], %%DATA32B_L3

        mov     %%TMP1, [%%OUT_PTRS + 32]
        mov     %%TMP2, [%%OUT_PTRS + 40]
        mov     %%TMP3, [%%OUT_PTRS + 48]
        mov     %%TMP4, [%%OUT_PTRS + 56]
        vmovdqu [%%TMP1], %%DATA32B_L4
        vmovdqu [%%TMP2], %%DATA32B_L5
        vmovdqu [%%TMP3], %%DATA32B_L6
        vmovdqu [%%TMP4], %%DATA32B_L7

%endmacro

;
; Stores 4 bytes of keystream for 8 lanes
;
%macro  STORE4B_KSTR8 6
%define %%DATA4B_L07  %1 ; [in] 4 bytes of keystream for lanes 0-7
%define %%OUT_PTRS    %2 ; [in] Keystream pointers for all 8 lanes
%define %%TMP1        %3 ; [clobbered] Temporary GP register
%define %%TMP2        %4 ; [clobbered] Temporary GP register
%define %%TMP3        %5 ; [clobbered] Temporary GP register
%define %%TMP4        %6 ; [clobbered] Temporary GP register

        mov     %%TMP1, [%%OUT_PTRS]
        mov     %%TMP2, [%%OUT_PTRS + 8]
        mov     %%TMP3, [%%OUT_PTRS + 16]
        mov     %%TMP4, [%%OUT_PTRS + 24]
        vpextrd [%%TMP4], XWORD(%%DATA4B_L07), 3
        vpextrd [%%TMP3], XWORD(%%DATA4B_L07), 2
        vpextrd [%%TMP2], XWORD(%%DATA4B_L07), 1
        vmovd   [%%TMP1], XWORD(%%DATA4B_L07)
        mov     DWORD(%%TMP1), 4
        add     [%%OUT_PTRS],      %%TMP1
        add     [%%OUT_PTRS + 8],  %%TMP1
        add     [%%OUT_PTRS + 16], %%TMP1
        add     [%%OUT_PTRS + 24], %%TMP1

        vextracti128 XWORD(%1), %1, 1
        mov     %%TMP1, [%%OUT_PTRS + 32]
        mov     %%TMP2, [%%OUT_PTRS + 40]
        mov     %%TMP3, [%%OUT_PTRS + 48]
        mov     %%TMP4, [%%OUT_PTRS + 56]
        vpextrd [%%TMP4], XWORD(%%DATA4B_L07), 3
        vpextrd [%%TMP3], XWORD(%%DATA4B_L07), 2
        vpextrd [%%TMP2], XWORD(%%DATA4B_L07), 1
        vmovd   [%%TMP1], XWORD(%%DATA4B_L07)
        mov     DWORD(%%TMP1), 4
        add     [%%OUT_PTRS + 32], %%TMP1
        add     [%%OUT_PTRS + 40], %%TMP1
        add     [%%OUT_PTRS + 48], %%TMP1
        add     [%%OUT_PTRS + 56], %%TMP1

%endmacro

;
; Add two 32-bit args and reduce mod (2^31-1)
;
%macro  ADD_MOD31 4
%define %%IN_OUT        %1 ; [in/out] YMM register with first input and output
%define %%IN2           %2 ; [in] YMM register with second input
%define %%YTMP          %3 ; [clobbered] Temporary YMM register
%define %%MASK31        %4 ; [in] YMM register containing 0x7FFFFFFF's in all dwords
        vpaddd  %%IN_OUT, %%IN2
        vpsrld  %%YTMP, %%IN_OUT, 31
        vpand   %%IN_OUT, %%MASK31
        vpaddd  %%IN_OUT, %%YTMP
%endmacro

;
; Rotate (mult by pow of 2) 32-bit arg and reduce mod (2^31-1)
;
%macro  ROT_MOD31   4
%define %%IN_OUT        %1 ; [in/out] YMM register with input and output
%define %%YTMP          %2 ; [clobbered] Temporary YMM register
%define %%MASK31        %3 ; [in] YMM register containing 0x7FFFFFFF's in all dwords
%define %%N_BITS        %4 ; [immediate] Number of bits to rotate for each dword

        vpslld  %%YTMP, %%IN_OUT, %%N_BITS
        vpsrld  %%IN_OUT, (31 - %%N_BITS)

        vpor    %%IN_OUT, %%YTMP
        vpand   %%IN_OUT, %%MASK31
%endmacro

;
; Update LFSR registers, calculating S_16
;
; S_16 = [ 2^15*S_15 + 2^17*S_13 + 2^21*S_10 + 2^20*S_4 + (1 + 2^8)*S_0 ] mod (2^31 - 1)
; If init mode, add W to the calculation above.
; S_16 -> S_15 for next round
;
%macro  LFSR_UPDT8  11
%define %%STATE     %1  ; [in] ZUC state
%define %%ROUND_NUM %2  ; [in] Round number
%define %%LFSR_0    %3  ; [clobbered] LFSR_0 (YMM)
%define %%LFSR_4    %4  ; [clobbered] LFSR_4 (YMM)
%define %%LFSR_10   %5  ; [clobbered] LFSR_10 (YMM)
%define %%LFSR_13   %6  ; [clobbered] LFSR_13 (YMM)
%define %%LFSR_15   %7  ; [clobbered] LFSR_15 (YMM)
%define %%YTMP      %8  ; [clobbered] Temporary YMM register
%define %%MASK_31   %9  ; [in] Mask_31
%define %%W         %10 ; [in/clobbered] In init mode, contains W for all 4 lanes
%define %%MODE      %11 ; [constant] "init" / "work" mode

        vmovdqa %%LFSR_0,  [%%STATE + (( 0 + %%ROUND_NUM) % 16)*32]
        vmovdqa %%LFSR_4,  [%%STATE + (( 4 + %%ROUND_NUM) % 16)*32]
        vmovdqa %%LFSR_10, [%%STATE + ((10 + %%ROUND_NUM) % 16)*32]
        vmovdqa %%LFSR_13, [%%STATE + ((13 + %%ROUND_NUM) % 16)*32]
        vmovdqa %%LFSR_15, [%%STATE + ((15 + %%ROUND_NUM) % 16)*32]

        ; Calculate LFSR feedback (S_16)

        ; In Init mode, W is added to the S_16 calculation
%ifidn %%MODE, init
        ADD_MOD31 %%W, %%LFSR_0, %%YTMP, %%MASK_31
%else
        vmovdqa %%W, %%LFSR_0
%endif
        ROT_MOD31 %%LFSR_0, %%YTMP, %%MASK_31, 8
        ADD_MOD31 %%W, %%LFSR_0, %%YTMP, %%MASK_31
        ROT_MOD31 %%LFSR_4, %%YTMP, %%MASK_31, 20
        ADD_MOD31 %%W, %%LFSR_4, %%YTMP, %%MASK_31
        ROT_MOD31 %%LFSR_10, %%YTMP, %%MASK_31, 21
        ADD_MOD31 %%W, %%LFSR_10, %%YTMP, %%MASK_31
        ROT_MOD31 %%LFSR_13, %%YTMP, %%MASK_31, 17
        ADD_MOD31 %%W, %%LFSR_13, %%YTMP, %%MASK_31
        ROT_MOD31 %%LFSR_15, %%YTMP, %%MASK_31, 15
        ADD_MOD31 %%W, %%LFSR_15, %%YTMP, %%MASK_31

        ; Store LFSR_S16
        vmovdqa [%%STATE + (( 0 + %%ROUND_NUM) % 16)*32], %%W
%endmacro

;
; Initialize LFSR registers for a single lane, for ZUC-128
;
; This macro initializes 8 LFSR registers at time.
; so it needs to be called twice.
;
; From spec, s_i (LFSR) registers need to be loaded as follows:
;
; For 0 <= i <= 15, let s_i= k_i || d_i || iv_i.
; Where k_i is each byte of the key, d_i is a 15-bit constant
; and iv_i is each byte of the IV.
;
%macro INIT_LFSR_128 7
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

;
; Initialize LFSR registers for a single lane, for ZUC-256
;
%macro INIT_LFSR_256 8
%define %%KEY       %1 ;; [in] Key pointer
%define %%IV        %2 ;; [in] IV pointer
%define %%LFSR0_7   %3 ;; [out] YMM register to contain initialized LFSR regs 0-7
%define %%LFSR8_15  %4 ;; [out] YMM register to contain initialized LFSR regs 8-15
%define %%XTMP      %5 ;; [clobbered] XMM temporary register
%define %%XTMP2     %6 ;; [clobbered] XMM temporary register
%define %%TMP       %7 ;; [clobbered] GP temporary register
%define %%TAG_SIZE  %8 ;; [in] Tag size (0, 4, 8 or 16 bytes)

%if %%TAG_SIZE == 0
%define %%CONSTANTS rel EK256_d64
%elif %%TAG_SIZE == 4
%define %%CONSTANTS rel EK256_EIA3_4
%elif %%TAG_SIZE == 8
%define %%CONSTANTS rel EK256_EIA3_8
%elif %%TAG_SIZE == 16
%define %%CONSTANTS rel EK256_EIA3_16
%endif

        ; s0 - s7
        vpxor   %%LFSR0_7, %%LFSR0_7
        vpinsrb XWORD(%%LFSR0_7), [%%KEY], 3      ; s0
        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 1], 7  ; s1
        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 2], 11 ; s2
        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 3], 15 ; s3

        vpsrld  XWORD(%%LFSR0_7), 1

        vpor    XWORD(%%LFSR0_7), [%%CONSTANTS] ; s0 - s3

        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 21], 1 ; s0
        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 16], 0 ; s0

        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 22], 5 ; s1
        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 17], 4 ; s1

        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 23], 9 ; s2
        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 18], 8 ; s2

        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 24], 13 ; s3
        vpinsrb XWORD(%%LFSR0_7), [%%KEY + 19], 12 ; s3

        vpxor   %%XTMP, %%XTMP
        vpinsrb %%XTMP, [%%KEY + 4], 3   ; s4
        vpinsrb %%XTMP, [%%IV], 7        ; s5
        vpinsrb %%XTMP, [%%IV + 1], 11   ; s6
        vpinsrb %%XTMP, [%%IV + 10], 15  ; s7

        vpsrld  %%XTMP, 1

        vpinsrb %%XTMP, [%%KEY + 25], 1 ; s4
        vpinsrb %%XTMP, [%%KEY + 20], 0 ; s4

        vpinsrb %%XTMP, [%%KEY + 5], 5 ; s5
        vpinsrb %%XTMP, [%%KEY + 26], 4 ; s5

        vpinsrb %%XTMP, [%%KEY + 6], 9 ; s6
        vpinsrb %%XTMP, [%%KEY + 27], 8 ; s6

        vpinsrb %%XTMP, [%%KEY + 7], 13 ; s7
        vpinsrb %%XTMP, [%%IV + 2], 12 ; s7

        vpor    %%XTMP, [%%CONSTANTS + 16] ; s4 - s7

        vmovd   %%XTMP2, [%%IV + 17]
        vpshufb %%XTMP2, [rel shuf_mask_iv_17_19]
        vpand   %%XTMP2, [rel clear_iv_mask]

        vpor    %%XTMP, %%XTMP2

        vinserti128 %%LFSR0_7, %%XTMP, 1

        ; s8 - s15
        vpxor   %%LFSR8_15, %%LFSR8_15
        vpinsrb XWORD(%%LFSR8_15), [%%KEY + 8], 3   ; s8
        vpinsrb XWORD(%%LFSR8_15), [%%KEY + 9], 7   ; s9
        vpinsrb XWORD(%%LFSR8_15), [%%IV + 5], 11   ; s10
        vpinsrb XWORD(%%LFSR8_15), [%%KEY + 11], 15 ; s11

        vpsrld  XWORD(%%LFSR8_15), 1

        vpinsrb XWORD(%%LFSR8_15), [%%IV + 3], 1 ; s8
        vpinsrb XWORD(%%LFSR8_15), [%%IV + 11], 0 ; s8

        vpinsrb XWORD(%%LFSR8_15), [%%IV + 12], 5 ; s9
        vpinsrb XWORD(%%LFSR8_15), [%%IV + 4], 4 ; s9

        vpinsrb XWORD(%%LFSR8_15), [%%KEY + 10], 9 ; s10
        vpinsrb XWORD(%%LFSR8_15), [%%KEY + 28], 8 ; s10

        vpinsrb XWORD(%%LFSR8_15), [%%IV + 6], 13 ; s11
        vpinsrb XWORD(%%LFSR8_15), [%%IV + 13], 12 ; s11

        vpor    XWORD(%%LFSR8_15), [%%CONSTANTS + 32] ; s8 - s11

        vmovd   %%XTMP, [%%IV + 20]
        vpshufb %%XTMP, [rel shuf_mask_iv_20_23]
        vpand   %%XTMP, [rel clear_iv_mask]

        vpor    XWORD(%%LFSR8_15), %%XTMP

        vpxor   %%XTMP, %%XTMP
        vpinsrb %%XTMP, [%%KEY + 12], 3   ; s12
        vpinsrb %%XTMP, [%%KEY + 13], 7   ; s13
        vpinsrb %%XTMP, [%%KEY + 14], 11  ; s14
        vpinsrb %%XTMP, [%%KEY + 15], 15  ; s15

        vpsrld  %%XTMP, 1

        vpinsrb %%XTMP, [%%IV + 7], 1 ; s12
        vpinsrb %%XTMP, [%%IV + 14], 0 ; s12

        vpinsrb %%XTMP, [%%IV + 15], 5 ; s13
        vpinsrb %%XTMP, [%%IV + 8], 4 ; s13

        vpinsrb %%XTMP, [%%IV + 16], 9 ; s14
        vpinsrb %%XTMP, [%%IV + 9], 8 ; s14

        vpinsrb %%XTMP, [%%KEY + 30], 13 ; s15
        vpinsrb %%XTMP, [%%KEY + 29], 12 ; s15

        vpor    %%XTMP, [%%CONSTANTS + 48] ; s12 - s15

        movzx   DWORD(%%TMP), byte [%%IV + 24]
        and     DWORD(%%TMP), 0x0000003f
        shl     DWORD(%%TMP), 16
        vmovd   %%XTMP2, DWORD(%%TMP)

        movzx   DWORD(%%TMP), byte [%%KEY + 31]
        shl     DWORD(%%TMP), 12
        and     DWORD(%%TMP), 0x000f0000 ; high nibble of K_31
        vpinsrd %%XTMP2, DWORD(%%TMP), 2

        movzx   DWORD(%%TMP), byte [%%KEY + 31]
        shl     DWORD(%%TMP), 16
        and     DWORD(%%TMP), 0x000f0000 ; low nibble of K_31
        vpinsrd %%XTMP2, DWORD(%%TMP), 3

        vpor    %%XTMP, %%XTMP2
        vinserti128 %%LFSR8_15, %%XTMP, 1
%endmacro

%macro ZUC_INIT_8 2-3
%define %%KEY_SIZE %1 ; [constant] Key size (128 or 256)
%define %%TAG_SIZE %2 ; [in] Tag size (0 (for cipher), 4, 8 or 16)
%define %%TAGS     %3 ; [in] Array of temporary tags

%define pKe     arg1
%define pIv     arg2
%define pState  arg3

%define %%YTMP1  ymm0
%define %%YTMP2  ymm1
%define %%YTMP3  ymm2
%define %%YTMP4  ymm3
%define %%YTMP5  ymm4
%define %%YTMP6  ymm5
%define %%YTMP7  ymm6
%define %%YTMP8  ymm7
%define %%YTMP9  ymm8
%define %%YTMP10 ymm9
%define %%YTMP11 ymm10
%define %%YTMP12 ymm11
%define %%YTMP13 ymm12
%define %%YTMP14 ymm13
%define %%YTMP15 ymm14
%define %%YTMP16 ymm15

%define %%W     %%YTMP10
%define %%X3    %%YTMP11
%define %%KSTR1 %%YTMP12
%define %%KSTR2 %%YTMP13
%define %%KSTR3 %%YTMP14
%define %%KSTR4 %%YTMP15
%define %%MASK_31 %%YTMP16

        FUNC_SAVE

        ; Zero out R1/R2
        vpxor   %%YTMP1, %%YTMP1
        vmovdqa [pState + OFS_R1], %%YTMP1
        vmovdqa [pState + OFS_R2], %%YTMP1

        ;;; Initialize all LFSR registers in two steps:
        ;;; first, registers 0-7, then registers 8-15

%if %%KEY_SIZE == 128
%assign %%OFF 0
%rep 2
        ; Set read-only registers for shuffle masks for key, IV and Ek_d for 8 registers
        vmovdqa %%YTMP13, [rel shuf_mask_key + %%OFF]
        vmovdqa %%YTMP14, [rel shuf_mask_iv + %%OFF]
        vmovdqa %%YTMP15, [rel Ek_d + %%OFF]

        ; Set 8xLFSR registers for all packets
%assign %%I 1
%assign %%OFF_PTR 0
%rep 8
        mov     r9, [pKe + %%OFF_PTR]  ; Load Key N pointer
        lea     r10, [pIv + 4*%%OFF_PTR] ; Load IV N pointer
        INIT_LFSR_128 r9, r10, %%YTMP13, %%YTMP14, %%YTMP15, APPEND(%%YTMP, %%I), %%YTMP12
%assign %%I (%%I + 1)
%assign %%OFF_PTR (%%OFF_PTR + 8)
%endrep

        ; Store 8xLFSR registers in memory (reordering first,
        ; so all SX registers are together)
        TRANSPOSE8_U32  %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10

%assign %%I 1
%rep 8
        vmovdqa [pState + 8*%%OFF + 32*(%%I-1)], APPEND(%%YTMP, %%I)
%assign %%I (%%I+1)
%endrep

%assign %%OFF (%%OFF + 32)
%endrep
%else ;; %%KEY_SIZE == 256

    ;;; Initialize all LFSR registers
%assign %%OFF 0
%rep 8
        ;; Load key and IV for each packet
        mov     r15, [pKe + %%OFF]
        lea     r10, [pIv + 4*%%OFF] ; Load IV N pointer

        ; Initialize S0-15 for each packet
        INIT_LFSR_256 r15, r10, %%YTMP1, %%YTMP2, XWORD(%%YTMP3), XWORD(%%YTMP4), r11, %%TAG_SIZE

        vmovdqa [pState + 4*%%OFF], %%YTMP1
        vmovdqa [pState + 256 + 4*%%OFF], %%YTMP2

%assign %%OFF (%%OFF + 8)
%endrep

    ; Read, transpose and store, so all S_X from the 8 packets are in the same register
%assign %%OFF 0
%rep 2

%assign %%I 1
%rep 8
        vmovdqa APPEND(%%YTMP, %%I), [pState + 32*(%%I-1) + %%OFF]
%assign %%I (%%I+1)
%endrep

        TRANSPOSE8_U32 %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10

%assign %%I 1
%rep 8
        vmovdqa [pState + 32*(%%I-1) + %%OFF], APPEND(%%YTMP, %%I)
%assign %%I (%%I+1)
%endrep

%assign %%OFF (%%OFF + 256)
%endrep
%endif ;; %%KEY_SIZE == 256

        ; Load read-only registers
        vmovdqa %%MASK_31, [rel mask31]

        ; Shift LFSR 32-times, update state variables
%assign %%N 0
%rep 32
        BITS_REORG8 pState, %%N, %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, \
                    %%YTMP6, %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10
        NONLIN_FUN8 pState, %%YTMP1, %%YTMP2, %%YTMP3, \
                    %%YTMP4, %%YTMP5, %%YTMP6, %%YTMP7, %%W
        vpsrld  %%W, 1 ; Shift out LSB of W
        LFSR_UPDT8  pState, %%N, %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, \
                    %%MASK_31, %%W, init ; W used in LFSR update
%assign %%N %%N+1
%endrep

        ; And once more, initial round from keygen phase = 33 times
        BITS_REORG8 pState, 0, %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, \
                    %%YTMP6, %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10
        NONLIN_FUN8 pState, %%YTMP1, %%YTMP2, %%YTMP3, \
                    %%YTMP4, %%YTMP5, %%YTMP6, %%YTMP7, %%W
        LFSR_UPDT8  pState, 0, %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, \
                    %%MASK_31, %%YTMP8, work

    ; Generate extra 4, 8 or 16 bytes of KS for initial tags
%if %%TAG_SIZE == 4
%define %%NUM_ROUNDS 1
%elif %%TAG_SIZE == 8
%define %%NUM_ROUNDS 2
%elif %%TAG_SIZE == 16
%define %%NUM_ROUNDS 4
%else
%define %%NUM_ROUNDS 0
%endif

%assign %%N 1
%rep %%NUM_ROUNDS
        BITS_REORG8 pState, %%N, %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, \
                    %%YTMP6, %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10, APPEND(%%KSTR,%%N)
        NONLIN_FUN8 pState, %%YTMP1, %%YTMP2, %%YTMP3, \
                    %%YTMP4, %%YTMP5, %%YTMP6, %%YTMP7, %%W
        ; OFS_X3 XOR W and store in stack
        vpxor   APPEND(%%KSTR, %%N), %%W
        LFSR_UPDT8  pState, %%N, %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, \
                    %%MASK_31, %%YTMP8, work
%assign %%N %%N+1
%endrep

%if %%TAG_SIZE == 4
        vmovdqa [%%TAGS], %%KSTR1
        REORDER_LFSR pState, 1
%elif %%TAG_SIZE == 8
        ; Transpose the keystream and store the 8 bytes per buffer consecutively,
        ; being the initial tag for each buffer
        vpunpckldq %%YTMP1, %%KSTR1, %%KSTR2
        vpunpckhdq %%YTMP2, %%KSTR1, %%KSTR2
        vperm2i128 %%KSTR1, %%YTMP1, %%YTMP2, 0x20
        vperm2i128 %%KSTR2, %%YTMP1, %%YTMP2, 0x31

        vmovdqa [%%TAGS], %%KSTR1
        vmovdqa [%%TAGS + 32], %%KSTR2
        REORDER_LFSR pState, 2
%elif %%TAG_SIZE == 16
        TRANSPOSE4_U32 %%KSTR1, %%KSTR2, %%KSTR3, %%KSTR4, \
                       %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4

        vmovdqa [%%TAGS], %%KSTR1
        vmovdqa [%%TAGS + 32], %%KSTR2
        vmovdqa [%%TAGS + 32*2], %%KSTR3
        vmovdqa [%%TAGS + 32*3], %%KSTR4
        REORDER_LFSR pState, 4
%endif
        FUNC_RESTORE
%endmacro

MKGLOBAL(asm_ZucInitialization_8_avx2,function,internal)
asm_ZucInitialization_8_avx2:
        endbranch64
        ZUC_INIT_8 128, 0

        ret

MKGLOBAL(asm_Zuc256Initialization_8_avx2,function,internal)
asm_Zuc256Initialization_8_avx2:
%define tags   arg4
%define tag_sz arg5

        endbranch64

        cmp tag_sz, 0
        je  init_for_cipher

        cmp tag_sz, 8
        je init_for_auth_tag_8B
        jb init_for_auth_tag_4B

        ; Fall-through for tag size = 16 bytes
init_for_auth_tag_16B:
        ZUC_INIT_8 256, 16, tags
        ret

init_for_auth_tag_8B:
        ZUC_INIT_8 256, 8, tags
        ret

init_for_auth_tag_4B:
        ZUC_INIT_8 256, 4, tags
        ret

init_for_cipher:
        ZUC_INIT_8 256, 0
        ret

;
; Generate N*4 bytes of keystream
; for 8 buffers (where N is number of rounds)
;
%macro KEYGEN_8_AVX2 1
%define %%NUM_ROUNDS    %1 ; [in] Number of 4-byte rounds

%define pState  arg1
%define pKS     arg2

%define %%YTMP1  ymm0
%define %%YTMP2  ymm1
%define %%YTMP3  ymm2
%define %%YTMP4  ymm3
%define %%YTMP5  ymm4
%define %%YTMP6  ymm5
%define %%YTMP7  ymm6
%define %%YTMP8  ymm7
%define %%YTMP9  ymm8
%define %%YTMP10 ymm9
%define %%YTMP11 ymm10
%define %%YTMP12 ymm11
%define %%YTMP13 ymm12
%define %%YTMP14 ymm13
%define %%YTMP15 ymm14
%define %%YTMP16 ymm15

%define %%W     %%YTMP10
%define %%X3    %%YTMP11
%define %%MASK_31 %%YTMP16

        FUNC_SAVE

        ; Store 8 keystream pointers on the stack
        ; and reserve memory for storing keystreams for all 8 buffers
        mov     r10, rsp
        sub     rsp, (8*8 + %%NUM_ROUNDS * 32)
        and     rsp, -32

        vmovdqa ymm0, [pKS]
        vmovdqa [rsp], ymm0
        vmovdqa ymm0, [pKS + 32]
        vmovdqa [rsp + 32], ymm0

        ; Load read-only registers
        vmovdqa %%MASK_31, [rel mask31]

        ; Generate N*4B of keystream in N rounds
%assign %%N 1
%rep %%NUM_ROUNDS
        BITS_REORG8 pState, %%N, %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, \
                    %%YTMP6, %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10, %%X3
        NONLIN_FUN8 pState, %%YTMP1, %%YTMP2, %%YTMP3, \
                    %%YTMP4, %%YTMP5, %%YTMP6, %%YTMP7, %%W
        ; OFS_X3 XOR W and store in stack
        vpxor       %%X3, %%W
        vmovdqa     [rsp + 8*8 + (%%N-1)*32], %%X3
        LFSR_UPDT8  pState, %%N, %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, \
                    %%MASK_31, %%YTMP8, work
%assign %%N %%N+1
%endrep

%if (%%NUM_ROUNDS == 8)
        ;; Load all OFS_X3
        vmovdqa XWORD(%%YTMP1), [rsp + 8*8]
        vmovdqa XWORD(%%YTMP2), [rsp + 8*8 + 32*1]
        vmovdqa XWORD(%%YTMP3), [rsp + 8*8 + 32*2]
        vmovdqa XWORD(%%YTMP4), [rsp + 8*8 + 32*3]
        vmovdqa XWORD(%%YTMP5), [rsp + 8*8 + 16]
        vmovdqa XWORD(%%YTMP6), [rsp + 8*8 + 32*1 + 16]
        vmovdqa XWORD(%%YTMP7), [rsp + 8*8 + 32*2 + 16]
        vmovdqa XWORD(%%YTMP8), [rsp + 8*8 + 32*3 + 16]

        vinserti128 %%YTMP1, %%YTMP1, [rsp + 8*8 + 32*4], 0x01
        vinserti128 %%YTMP2, %%YTMP2, [rsp + 8*8 + 32*5], 0x01
        vinserti128 %%YTMP3, %%YTMP3, [rsp + 8*8 + 32*6], 0x01
        vinserti128 %%YTMP4, %%YTMP4, [rsp + 8*8 + 32*7], 0x01
        vinserti128 %%YTMP5, %%YTMP5, [rsp + 8*8 + 32*4 + 16], 0x01
        vinserti128 %%YTMP6, %%YTMP6, [rsp + 8*8 + 32*5 + 16], 0x01
        vinserti128 %%YTMP7, %%YTMP7, [rsp + 8*8 + 32*6 + 16], 0x01
        vinserti128 %%YTMP8, %%YTMP8, [rsp + 8*8 + 32*7 + 16], 0x01

        TRANSPOSE8_U32_PRELOADED %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10

        STORE32B_KSTR8 %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, %%YTMP7, %%YTMP8, rsp, r12, r13, r14, r15

%else ;; NUM_ROUNDS == 8
%assign %%I 1
%rep %%NUM_ROUNDS
        vmovdqa APPEND(%%YTMP, %%I), [rsp + 8*8 + (%%I-1)*32]
        STORE4B_KSTR8 APPEND(%%YTMP, %%I), rsp, r12, r13, r14, r15
%assign %%I (%%I + 1)
%endrep
%endif ;; NUM_ROUNDS == 8

        ;; Reorder LFSR registers, as not all 16 rounds have been completed
        REORDER_LFSR pState, %%NUM_ROUNDS

        ;; Clear stack frame containing keystream information
%ifdef SAFE_DATA
        vpxor   %%YTMP1, %%YTMP1
%assign %%I 0
%rep (2+%%NUM_ROUNDS)
	vmovdqa [rsp + %%I*32], %%YTMP1
%assign %%I (%%I+1)
%endrep
%endif

        ;; Restore rsp pointer
        mov     rsp, r10

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
        endbranch64
        KEYGEN_8_AVX2 8
        vzeroupper
        ret

;;
;; void asm_ZucGenKeystream16B_8_avx2(state8_t *pSta, u32* pKeyStr[8])
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(asm_ZucGenKeystream16B_8_avx2,function,internal)
asm_ZucGenKeystream16B_8_avx2:
        endbranch64
        KEYGEN_8_AVX2 4
        vzeroupper
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
        endbranch64
        KEYGEN_8_AVX2 2
        vzeroupper
        ret

;;
;; void asm_ZucGenKeystream4B_8_avx2(state8_t *pSta, u32* pKeyStr[8])
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(asm_ZucGenKeystream4B_8_avx2,function,internal)
asm_ZucGenKeystream4B_8_avx2:
        endbranch64
        KEYGEN_8_AVX2 1
        vzeroupper
        ret

;;
;; Encrypt N*4B bytes on all 8 buffers
;; where N is number of rounds (up to 8)
;; In final call, an array of final bytes is read
;; from memory and only these final bytes are of
;; plaintext are read and XOR'ed.
%macro CIPHERNx4B_8 4
%define %%NROUNDS        %1
%define %%INITIAL_ROUND  %2
%define %%OFFSET         %3
%define %%LAST_CALL      %4

%ifdef LINUX
%define %%TMP1 r8
%define %%TMP2 r9
%else
%define %%TMP1 rdi
%define %%TMP2 rsi
%endif

%define %%YTMP1  ymm0
%define %%YTMP2  ymm1
%define %%YTMP3  ymm2
%define %%YTMP4  ymm3
%define %%YTMP5  ymm4
%define %%YTMP6  ymm5
%define %%YTMP7  ymm6
%define %%YTMP8  ymm7
%define %%YTMP9  ymm8
%define %%YTMP10 ymm9
%define %%YTMP11 ymm10
%define %%YTMP12 ymm11
%define %%YTMP13 ymm12
%define %%YTMP14 ymm13
%define %%YTMP15 ymm14
%define %%YTMP16 ymm15

%define %%W     %%YTMP10
%define %%X3    %%YTMP11
%define %%MASK_31 %%YTMP16

        ; Load read-only registers
        vmovdqa %%MASK_31, [rel mask31]

        ; Generate N*4B of keystream in N rounds
%assign %%N 1
%assign %%round (%%INITIAL_ROUND + %%N)
%rep %%NROUNDS
        BITS_REORG8 pState, %%round, %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, \
                    %%YTMP6, %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10, %%X3
        NONLIN_FUN8 pState, %%YTMP1, %%YTMP2, %%YTMP3, \
                    %%YTMP4, %%YTMP5, %%YTMP6, %%YTMP7, %%W
        ; OFS_X3 XOR W and store in stack
        vpxor       %%X3, %%W
        vmovdqa     [rsp + (%%N-1)*32], %%X3
        LFSR_UPDT8  pState, %%round, %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, \
                    %%MASK_31, %%YTMP8, work
%assign %%N (%%N + 1)
%assign %%round (%%round + 1)
%endrep

%assign %%N 1
%rep %%NROUNDS
        vmovdqa APPEND(%%YTMP, %%N), [rsp + (%%N-1)*32]
%assign %%N (%%N + 1)
%endrep

        TRANSPOSE8_U32 %%YTMP1, %%YTMP2, %%YTMP3, %%YTMP4, %%YTMP5, %%YTMP6, \
                       %%YTMP7, %%YTMP8, %%YTMP9, %%YTMP10
        ;; XOR Input buffer with keystream in rounds of 32B

        mov     r12, [pIn]
        mov     r13, [pIn + 8]
        mov     r14, [pIn + 16]
        mov     r15, [pIn + 24]
%if (%%LAST_CALL == 1)
        ;; Save GP registers
        mov     [rsp + 32*8 + 16 + 8],  %%TMP1
        mov     [rsp + 32*8 + 16 + 16], %%TMP2

        ;; Read in r10 the word containing the number of final bytes to read for each lane
        movzx  r10d, word [rsp + 8*32]
        simd_load_avx2 %%YTMP9, r12 + %%OFFSET, r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 2]
        simd_load_avx2 %%YTMP10, r13 + %%OFFSET, r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 4]
        simd_load_avx2 %%YTMP11, r14 + %%OFFSET, r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 6]
        simd_load_avx2 %%YTMP12, r15 + %%OFFSET, r10, %%TMP1, %%TMP2
%else
        vmovdqu %%YTMP9, [r12 + %%OFFSET]
        vmovdqu %%YTMP10, [r13 + %%OFFSET]
        vmovdqu %%YTMP11, [r14 + %%OFFSET]
        vmovdqu %%YTMP12, [r15 + %%OFFSET]
%endif

        mov     r12, [pIn + 32]
        mov     r13, [pIn + 40]
        mov     r14, [pIn + 48]
        mov     r15, [pIn + 56]
%if (%%LAST_CALL == 1)
        movzx  r10d, word [rsp + 8*32 + 8]
        simd_load_avx2 %%YTMP13, r12 + %%OFFSET, r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 10]
        simd_load_avx2 %%YTMP14, r13 + %%OFFSET, r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 12]
        simd_load_avx2 %%YTMP15, r14 + %%OFFSET, r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 14]
        simd_load_avx2 %%YTMP16, r15 + %%OFFSET, r10, %%TMP1, %%TMP2
%else
        vmovdqu %%YTMP13, [r12 + %%OFFSET]
        vmovdqu %%YTMP14, [r13 + %%OFFSET]
        vmovdqu %%YTMP15, [r14 + %%OFFSET]
        vmovdqu %%YTMP16, [r15 + %%OFFSET]
%endif
        ; Shuffle all keystreams and XOR with plaintext
%assign %%I 1
%assign %%J 9
%rep 8
        vpshufb APPEND(%%YTMP, %%I), [rel swap_mask]
        vpxor   APPEND(%%YTMP, %%I), APPEND(%%YTMP, %%J)
%assign %%I (%%I + 1)
%assign %%J (%%J + 1)
%endrep

        ;; Write output
        mov     r12, [pOut]
        mov     r13, [pOut + 8]
        mov     r14, [pOut + 16]
        mov     r15, [pOut + 24]

%if (%%LAST_CALL == 1)
        add     r12, %%OFFSET
        add     r13, %%OFFSET
        add     r14, %%OFFSET
        add     r15, %%OFFSET
        ;; Read in r10 the word containing the number of final bytes to write for each lane
        movzx  r10d, word [rsp + 8*32]
        simd_store_avx2 r12, %%YTMP1,  r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 2]
        simd_store_avx2 r13, %%YTMP2,  r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 4]
        simd_store_avx2 r14, %%YTMP3, r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 6]
        simd_store_avx2 r15, %%YTMP4, r10, %%TMP1, %%TMP2
%else
        vmovdqu [r12 + %%OFFSET], %%YTMP1
        vmovdqu [r13 + %%OFFSET], %%YTMP2
        vmovdqu [r14 + %%OFFSET], %%YTMP3
        vmovdqu [r15 + %%OFFSET], %%YTMP4
%endif

        mov     r12, [pOut + 32]
        mov     r13, [pOut + 40]
        mov     r14, [pOut + 48]
        mov     r15, [pOut + 56]

%if (%%LAST_CALL == 1)
        add     r12, %%OFFSET
        add     r13, %%OFFSET
        add     r14, %%OFFSET
        add     r15, %%OFFSET
        movzx  r10d, word [rsp + 8*32 + 8]
        simd_store_avx2 r12, %%YTMP5, r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 10]
        simd_store_avx2 r13, %%YTMP6, r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 12]
        simd_store_avx2 r14, %%YTMP7, r10, %%TMP1, %%TMP2
        movzx  r10d, word [rsp + 8*32 + 14]
        simd_store_avx2 r15, %%YTMP8, r10, %%TMP1, %%TMP2

        ; Restore registers
        mov     %%TMP1, [rsp + 32*8 + 16 + 8]
        mov     %%TMP2, [rsp + 32*8 + 16 + 16]
%else
        vmovdqu [r12 + %%OFFSET], %%YTMP5
        vmovdqu [r13 + %%OFFSET], %%YTMP6
        vmovdqu [r14 + %%OFFSET], %%YTMP7
        vmovdqu [r15 + %%OFFSET], %%YTMP8
%endif

%endmacro

;;
;; void asm_ZucCipher_8_avx2(state16_t *pSta, u64 *pIn[8],
;;                           u64 *pOut[8], u16 lengths, u64 min_length);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pIn
;;  R8     - pOut
;;  R9     - lengths
;;  rsp + 40 - min_length
;;
;; LIN64
;;  RDI - pSta
;;  RSI - pIn
;;  RDX - pOut
;;  RCX - lengths
;;  R8  - min_length
;;
MKGLOBAL(asm_ZucCipher_8_avx2,function,internal)
asm_ZucCipher_8_avx2:
%define pState  arg1
%define pIn     arg2
%define pOut    arg3
%define lengths arg4

%define min_length r10
%define buf_idx r11

        endbranch64
        mov     min_length, arg5

        or      min_length, min_length
        jz      exit_cipher32

        FUNC_SAVE

        ;; Convert all lengths from UINT16_MAX (indicating that lane is not valid) to min length
        vmovd   xmm0, DWORD(min_length)
        vpshufb xmm0, xmm0, [rel broadcast_word]
        vmovdqa xmm1, [lengths]
        vpcmpeqw xmm2, xmm2 ;; Get all ff's in XMM register
        vpcmpeqw xmm3, xmm1, xmm2 ;; Mask with FFFF in NULL jobs

        vpand   xmm4, xmm3, xmm0 ;; Length of valid job in all NULL jobs
        vpxor   xmm2, xmm3 ;; Mask with 0000 in NULL jobs
        vpand   xmm1, xmm2 ;; Zero out lengths of NULL jobs
        vpor    xmm1, xmm4 ;; XMM1 contain updated lengths

        ; Round up to nearest multiple of 4 bytes
        vpaddw  xmm0, [rel all_threes]
        vpand   xmm0, [rel all_fffcs]

        ; Calculate remaining bytes to encrypt after function call
        vpsubw  xmm2, xmm1, xmm0
        vpxor   xmm3, xmm3
        vpcmpgtw xmm4, xmm2, xmm3 ;; Mask with FFFF in lengths > 0
        ; Set to zero the lengths of the lanes which are going to be completed (lengths < 0)
        vpand   xmm2, xmm4
        vmovdqa [lengths], xmm2 ; Update in memory the final updated lengths

        ; Calculate number of bytes to encrypt after round of 32 bytes (up to 31 bytes),
        ; for each lane, and store it in stack to be used in the last round
        vpsubw  xmm1, xmm2 ; Bytes to encrypt in all lanes
        vpand   xmm1, [rel all_1fs] ; Number of final bytes (up to 31 bytes) for each lane
        vpcmpeqw xmm2, xmm1, xmm3 ;; Mask with FFFF in lengths == 0
        vpand   xmm2, [rel all_20s] ;; 32 in positions where lengths was 0
        vpor    xmm1, xmm2          ;; Number of final bytes (up to 32 bytes) for each lane

        ; Allocate stack frame to store keystreams (32*8 bytes), number of final bytes (16 bytes),
        ; space for rsp (8 bytes) and 2 GP registers (16 bytes) that will be clobbered later
        mov     rax, rsp
        sub     rsp, (32*8 + 16 + 16 + 8)
        and     rsp, -32
        xor     buf_idx, buf_idx
        vmovdqu [rsp + 32*8], xmm1
        mov     [rsp + 32*8 + 16], rax

        ; Load state pointer in RAX
        mov     rax, pState

loop_cipher64:
        cmp     min_length, 64
        jl      exit_loop_cipher64

        CIPHERNx4B_8 8, 0, buf_idx, 0

        add     buf_idx, 32
        sub     min_length, 32

        CIPHERNx4B_8 8, 8, buf_idx, 0

        add     buf_idx, 32
        sub     min_length, 32

        jmp     loop_cipher64
exit_loop_cipher64:

        ; Check if at least 32 bytes are left to encrypt
        cmp     min_length, 32
        jl      less_than_32

        CIPHERNx4B_8 8, 0, buf_idx, 0
        REORDER_LFSR rax, 8

        add     buf_idx, 32
        sub     min_length, 32

        ; Check if there are more bytes left to encrypt
less_than_32:

        mov     r15, min_length
        add     r15, 3
        shr     r15, 2 ;; number of rounds left (round up length to nearest multiple of 4B)
        jz      exit_final_rounds

_final_rounds_is_1_8:
        cmp     r15, 4
        je      _num_final_rounds_is_4
        jl      _final_rounds_is_1_3

        ; Final rounds 5-8
        cmp     r15, 8
        je      _num_final_rounds_is_8
        cmp     r15, 7
        je      _num_final_rounds_is_7
        cmp     r15, 6
        je      _num_final_rounds_is_6
        cmp     r15, 5
        je      _num_final_rounds_is_5

_final_rounds_is_1_3:
        cmp     r15, 3
        je      _num_final_rounds_is_3
        cmp     r15, 2
        je      _num_final_rounds_is_2

        jmp     _num_final_rounds_is_1

        ; Perform encryption of last bytes (<= 31 bytes) and reorder LFSR registers
%assign I 1
%rep 8
APPEND(_num_final_rounds_is_,I):
        CIPHERNx4B_8 I, 0, buf_idx, 1
        REORDER_LFSR rax, I
        add     buf_idx, (I*4)
        jmp     exit_final_rounds
%assign I (I + 1)
%endrep

exit_final_rounds:
        ;; update in/out pointers

        ; Broadcast buf_idx in all qwords of ymm0
        vmovq           xmm0, buf_idx
        vpshufd         xmm0, xmm0, 0x44
        vperm2f128      ymm0, ymm0, 0x0
        vpaddq          ymm1, ymm0, [pIn]
        vpaddq          ymm2, ymm0, [pIn + 32]
        vmovdqa         [pIn], ymm1
        vmovdqa         [pIn + 32], ymm2
        vpaddq          ymm1, ymm0, [pOut]
        vpaddq          ymm2, ymm0, [pOut + 32]
        vmovdqa         [pOut], ymm1
        vmovdqa         [pOut + 32], ymm2

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
        mov     rsp, [rsp + 32*8 + 16]

        FUNC_RESTORE

exit_cipher32:
        vzeroupper
        ret

;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

mksection stack-noexec
