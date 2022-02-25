;;
;; Copyright (c) 2009-2022, Intel Corporation
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
%include "include/memcpy.asm"
%include "include/mb_mgr_datastruct.asm"
%include "include/cet.inc"
%include "include/const.inc"

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

align 16
Ek_d:
dd      0x0044D700, 0x0026BC00, 0x00626B00, 0x00135E00,
dd      0x00578900, 0x0035E200, 0x00713500, 0x0009AF00
dd      0x004D7800, 0x002F1300, 0x006BC400, 0x001AF100,
dd      0x005E2600, 0x003C4D00, 0x00789A00, 0x0047AC00

; Constants to be used to initialize the LFSR registers
; This table contains four different sets of constants:
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
dd      0x00220000, 0x002F0000, 0x00250000, 0x002A0000,
dd      0x006D0000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00520000, 0x00100000, 0x00300000
dd      0x00230000, 0x002F0000, 0x00240000, 0x002A0000,
dd      0x006D0000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00520000, 0x00100000, 0x00300000
dd      0x00230000, 0x002F0000, 0x00250000, 0x002A0000,
dd      0x006D0000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00520000, 0x00100000, 0x00300000

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
shuf_mask_iv_17_19:
db      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0x02, 0xFF

align 16
clear_iv_mask:
db      0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x3F, 0x00

align 16
shuf_mask_iv_20_23:
db      0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0x02, 0xFF, 0xFF, 0xFF, 0x03, 0xFF

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

align 16
swap_mask:
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c

align 16
S0_S1_shuf:
db      0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E

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
all_0fs:
dw      0x000f, 0x000f, 0x000f, 0x000f, 0x000f, 0x000f, 0x000f, 0x000f

align 16
all_10s:
dw      0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010

align 16
bit_mask_table:
db      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
db      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80
db      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0
db      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0
db      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0
db      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8
db      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc
db      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe

align 16
shuf_mask_dw0_0_dw1_0:
db      0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff
db      0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff

align 16
shuf_mask_dw2_0_dw3_0:
db      0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
db      0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff

; Stack frame for ZucCipher function
struc STACK
_keystr_save    resq  2*4 ; Space for 4 keystreams
_rsp_save:      resq    1 ; Space for rsp pointer
_gpr_save:      resq    2 ; Space for GP registers
_rem_bytes_save resq    1 ; Space for number of remaining bytes
endstruc

mksection .text
align 64

%define OFS_R1  (16*16)
%define OFS_R2  (OFS_R1 + 16)
%define OFS_X0  (OFS_R2 + 16)
%define OFS_X1  (OFS_X0 + 16)
%define OFS_X2  (OFS_X1 + 16)

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

;
; Calculates X0-X3 from LFSR registers
;
%macro  BITS_REORG4 12-13
%define %%STATE         %1 ; [in] ZUC state
%define %%ROUND_NUM     %2 ; [in] Round number
%define %%LFSR_0        %3  ; [clobbered] LFSR_0
%define %%LFSR_2        %4  ; [clobbered] LFSR_2
%define %%LFSR_5        %5  ; [clobbered] LFSR_5
%define %%LFSR_7        %6  ; [clobbered] LFSR_7
%define %%LFSR_9        %7  ; [clobbered] LFSR_9
%define %%LFSR_11       %8  ; [clobbered] LFSR_11
%define %%LFSR_14       %9  ; [clobbered] LFSR_14
%define %%LFSR_15       %10 ; [clobbered] LFSR_15
%define %%XTMP1         %11 ; [clobbered] Temporary XMM register
%define %%XTMP2         %12 ; [clobbered] Temporary XMM register
%define %%X3            %13 ; [out] XMM register containing X3 of all lanes (only for work mode)
        vmovdqa %%LFSR_15, [%%STATE + ((15 + %%ROUND_NUM) % 16)*16]
        vmovdqa %%LFSR_14, [%%STATE + ((14 + %%ROUND_NUM) % 16)*16]
        vmovdqa %%LFSR_11, [%%STATE + ((11 + %%ROUND_NUM) % 16)*16]
        vmovdqa %%LFSR_9,  [%%STATE + (( 9 + %%ROUND_NUM) % 16)*16]
        vmovdqa %%LFSR_7,  [%%STATE + (( 7 + %%ROUND_NUM) % 16)*16]
        vmovdqa %%LFSR_5,  [%%STATE + (( 5 + %%ROUND_NUM) % 16)*16]
%if (%0 == 13) ;Only needed when generating X3 (for "working" mode)
        vmovdqa %%LFSR_2,  [%%STATE + (( 2 + %%ROUND_NUM) % 16)*16]
        vmovdqa %%LFSR_0,  [%%STATE + (( 0 + %%ROUND_NUM) % 16)*16]
%endif

        vpxor   %%XTMP1, %%XTMP1
        vpslld  %%LFSR_15, 1
        vpblendw %%XTMP2,  %%LFSR_14, %%XTMP1, 0xAA
        vpblendw %%LFSR_15, %%LFSR_15, %%XTMP2, 0x55

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
%define %%OUT    %1 ; [out] XMM register
%define %%IN     %2 ; [in] XMM register
%define %%XTMP   %3 ; [clobbered] XMM register
%define %%N_BITS %4 ; [constant] Number of bits

%if (%%N_BITS == 8)
        vpshufb %%OUT, %%IN, [rel rot8_mod32]
%elif (%%N_BITS == 16)
        vpshufb %%OUT, %%IN, [rel rot16_mod32]
%elif (%%N_BITS == 24)
        vpshufb %%OUT, %%IN, [rel rot24_mod32]
%else
        vpslld  %%OUT, %%IN, %%N_BITS
        vpsrld  %%XTMP, %%IN, (32 - %%N_BITS)
        vpor    %%OUT, %%XTMP
%endif
%endmacro

;
; Updates R1-R2, using X0-X3 and generates W (if needed)
;
%macro NONLIN_FUN4  8-9
%define %%STATE     %1  ; [in] ZUC state
%define %%XTMP1     %2  ; [clobbered] Temporary XMM register
%define %%XTMP2     %3  ; [clobbered] Temporary XMM register
%define %%XTMP3     %4  ; [clobbered] Temporary XMM register
%define %%XTMP4     %5  ; [clobbered] Temporary XMM register
%define %%XTMP5     %6  ; [clobbered] Temporary XMM register
%define %%XTMP6     %7  ; [clobbered] Temporary XMM register
%define %%XTMP7     %8  ; [clobbered] Temporary XMM register
%define %%W         %9  ; [out] ZMM register to contain W for all lanes

%if (%0 == 9)
        vmovdqa %%W, [%%STATE + OFS_X0]
        vpxor   %%W, [%%STATE + OFS_R1]
        vpaddd  %%W, [%%STATE + OFS_R2]    ; W = (BRC_X0 ^ F_R1) + F_R2
%endif

        vmovdqa %%XTMP1, [%%STATE + OFS_R1]
        vmovdqa %%XTMP2, [%%STATE + OFS_R2]
        vpaddd  %%XTMP1, [%%STATE + OFS_X1]    ; W1 = F_R1 + BRC_X1
        vpxor   %%XTMP2, [%%STATE + OFS_X2]    ; W2 = F_R2 ^ BRC_X2

        vpslld  %%XTMP3, %%XTMP1, 16
        vpsrld  %%XTMP4, %%XTMP1, 16
        vpslld  %%XTMP5, %%XTMP2, 16
        vpsrld  %%XTMP6, %%XTMP2, 16
        vpor    %%XTMP1, %%XTMP3, %%XTMP6
        vpor    %%XTMP2, %%XTMP4, %%XTMP5

        ROT_MOD32 %%XTMP3, %%XTMP1, %%XTMP7, 2
        ROT_MOD32 %%XTMP4, %%XTMP1, %%XTMP7, 10
        ROT_MOD32 %%XTMP5, %%XTMP1, %%XTMP7, 18
        ROT_MOD32 %%XTMP6, %%XTMP1, %%XTMP7, 24
        vpxor     %%XTMP1, %%XTMP3
        vpxor     %%XTMP1, %%XTMP4
        vpxor     %%XTMP1, %%XTMP5
        vpxor     %%XTMP1, %%XTMP6      ; XMM1 = U = L1(P)

        ROT_MOD32 %%XTMP3, %%XTMP2, %%XTMP7, 8
        ROT_MOD32 %%XTMP4, %%XTMP2, %%XTMP7, 14
        ROT_MOD32 %%XTMP5, %%XTMP2, %%XTMP7, 22
        ROT_MOD32 %%XTMP6, %%XTMP2, %%XTMP7, 30
        vpxor     %%XTMP2, %%XTMP3
        vpxor     %%XTMP2, %%XTMP4
        vpxor     %%XTMP2, %%XTMP5
        vpxor     %%XTMP2, %%XTMP6      ; XMM2 = V = L2(Q)

        ; Shuffle U and V to have all S0 lookups in XMM1 and all S1 lookups in XMM2

        ; Compress all S0 and S1 input values in each register
        vpshufb %%XTMP1, [rel S0_S1_shuf] ; S0: Bytes 0-7, S1: Bytes 8-15
        vpshufb %%XTMP2, [rel S0_S1_shuf] ; S0: Bytes 0-7, S1: Bytes 8-15

        vshufpd %%XTMP3, %%XTMP1, %%XTMP2, 0x0 ; All S0 input values
        vshufpd %%XTMP4, %%XTMP2, %%XTMP1, 0x3 ; All S1 input values

        ; Compute S0 and S1 values
        S0_comput_AVX %%XTMP3, %%XTMP1, %%XTMP2
        S1_comput_AVX %%XTMP4, %%XTMP1, %%XTMP2, %%XTMP5

        ; Need to shuffle back %%XTMP1 & %%XTMP2 before storing output
        ; (revert what was done before S0 and S1 computations)
        vshufpd %%XTMP1, %%XTMP3, %%XTMP4, 0x2
        vshufpd %%XTMP2, %%XTMP3, %%XTMP4, 0x1

        vpshufb %%XTMP1, [rel rev_S0_S1_shuf]
        vpshufb %%XTMP2, [rel rev_S0_S1_shuf]

        vmovdqa [%%STATE + OFS_R1], %%XTMP1
        vmovdqa [%%STATE + OFS_R2], %%XTMP2
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
; Add two 32-bit args and reduce mod (2^31-1)
;
%macro  ADD_MOD31 4
%define %%IN_OUT        %1 ; [in/out] XMM register with first input and output
%define %%IN2           %2 ; [in] XMM register with second input
%define %%XTMP          %3 ; [clobbered] Temporary XMM register
%define %%MASK31        %4 ; [in] XMM register containing 0x7FFFFFFF's in all dwords
        vpaddd  %%IN_OUT, %%IN2
        vpsrld  %%XTMP, %%IN_OUT, 31
        vpand   %%IN_OUT, %%MASK31
        vpaddd  %%IN_OUT, %%XTMP
%endmacro

;
; Rotate (mult by pow of 2) 32-bit arg and reduce mod (2^31-1)
;
%macro  ROT_MOD31   4
%define %%IN_OUT        %1 ; [in/out] XMM register with input and output
%define %%XTMP          %2 ; [clobbered] Temporary XMM register
%define %%MASK31        %3 ; [in] XMM register containing 0x7FFFFFFF's in all dwords
%define %%N_BITS        %4 ; [immediate] Number of bits to rotate for each dword

        vpslld  %%XTMP, %%IN_OUT, %%N_BITS
        vpsrld  %%IN_OUT, (31 - %%N_BITS)

        vpor    %%IN_OUT, %%XTMP
        vpand   %%IN_OUT, %%MASK31
%endmacro

;
; Update LFSR registers, calculating S_16
;
; S_16 = [ 2^15*S_15 + 2^17*S_13 + 2^21*S_10 + 2^20*S_4 + (1 + 2^8)*S_0 ] mod (2^31 - 1)
; If init mode, add W to the calculation above.
; S_16 -> S_15 for next round
;
%macro  LFSR_UPDT4  11
%define %%STATE     %1  ; [in] ZUC state
%define %%ROUND_NUM %2  ; [in] Round number
%define %%LFSR_0    %3  ; [clobbered] LFSR_0 (XMM)
%define %%LFSR_4    %4  ; [clobbered] LFSR_4 (XMM)
%define %%LFSR_10   %5  ; [clobbered] LFSR_10 (XMM)
%define %%LFSR_13   %6  ; [clobbered] LFSR_13 (XMM)
%define %%LFSR_15   %7  ; [clobbered] LFSR_15 (XMM)
%define %%XTMP      %8  ; [clobbered] Temporary XMM register
%define %%MASK_31   %9  ; [in] Mask_31
%define %%W         %10 ; [in/clobbered] In init mode, contains W for all 4 lanes
%define %%MODE      %11 ; [constant] "init" / "work" mode

        vmovdqa %%LFSR_0,  [%%STATE + (( 0 + %%ROUND_NUM) % 16)*16]
        vmovdqa %%LFSR_4,  [%%STATE + (( 4 + %%ROUND_NUM) % 16)*16]
        vmovdqa %%LFSR_10, [%%STATE + ((10 + %%ROUND_NUM) % 16)*16]
        vmovdqa %%LFSR_13, [%%STATE + ((13 + %%ROUND_NUM) % 16)*16]
        vmovdqa %%LFSR_15, [%%STATE + ((15 + %%ROUND_NUM) % 16)*16]

        ; Calculate LFSR feedback (S_16)

        ; In Init mode, W is added to the S_16 calculation
%ifidn %%MODE, init
        ADD_MOD31 %%W, %%LFSR_0, %%XTMP, %%MASK_31
%else
        vmovdqa %%W, %%LFSR_0
%endif
        ROT_MOD31   %%LFSR_0, %%XTMP, %%MASK_31, 8
        ADD_MOD31   %%W, %%LFSR_0, %%XTMP, %%MASK_31
        ROT_MOD31   %%LFSR_4, %%XTMP, %%MASK_31, 20
        ADD_MOD31   %%W, %%LFSR_4, %%XTMP, %%MASK_31
        ROT_MOD31   %%LFSR_10, %%XTMP, %%MASK_31, 21
        ADD_MOD31   %%W, %%LFSR_10, %%XTMP, %%MASK_31
        ROT_MOD31   %%LFSR_13, %%XTMP, %%MASK_31, 17
        ADD_MOD31   %%W, %%LFSR_13, %%XTMP, %%MASK_31
        ROT_MOD31   %%LFSR_15, %%XTMP, %%MASK_31, 15
        ADD_MOD31   %%W, %%LFSR_15, %%XTMP, %%MASK_31

        ; Store LFSR_S16
        vmovdqa [%%STATE + (( 0 + %%ROUND_NUM) % 16)*16], %%W
%endmacro

;
; Initialize LFSR registers for a single lane, for ZUC-128
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
%macro INIT_LFSR_128 7
%define %%KEY       %1 ;; [in] XMM register containing 16-byte key
%define %%IV        %2 ;; [in] XMM register containing 16-byte IV
%define %%SHUF_KEY  %3 ;; [in] Shuffle key mask
%define %%SHUF_IV   %4 ;; [in] Shuffle key mask
%define %%EKD_MASK  %5 ;; [in] Shuffle key mask
%define %%LFSR      %6 ;; [out] XMM register to contain initialized LFSR regs
%define %%XTMP      %7 ;; [clobbered] XMM temporary register

        vpshufb %%LFSR, %%KEY, %%SHUF_KEY
        vpsrld  %%LFSR, 1
        vpshufb %%XTMP, %%IV, %%SHUF_IV
        vpor    %%LFSR, %%XTMP
        vpor    %%LFSR, %%EKD_MASK

%endmacro

;
; Initialize LFSR registers for a single lane, for ZUC-256
;
%macro INIT_LFSR_256 9
%define %%KEY       %1 ;; [in] Key pointer
%define %%IV        %2 ;; [in] IV pointer
%define %%LFSR0_3   %3 ;; [out] XMM register to contain initialized LFSR regs 0-3
%define %%LFSR4_7   %4 ;; [out] XMM register to contain initialized LFSR regs 4-7
%define %%LFSR8_11  %5 ;; [out] XMM register to contain initialized LFSR regs 8-11
%define %%LFSR12_15 %6 ;; [out] XMM register to contain initialized LFSR regs 12-15
%define %%XTMP      %7 ;; [clobbered] XMM temporary register
%define %%TMP       %8 ;; [clobbered] GP temporary register
%define %%CONSTANTS %9 ;; [in] Address to constants

        ; s0 - s3
        vpxor   %%LFSR0_3, %%LFSR0_3
        vpinsrb %%LFSR0_3, [%%KEY], 3      ; s0
        vpinsrb %%LFSR0_3, [%%KEY + 1], 7  ; s1
        vpinsrb %%LFSR0_3, [%%KEY + 2], 11 ; s2
        vpinsrb %%LFSR0_3, [%%KEY + 3], 15 ; s3

        vpsrld  %%LFSR0_3, 1

        vpor    %%LFSR0_3, [%%CONSTANTS] ; s0 - s3

        vpinsrb %%LFSR0_3, [%%KEY + 21], 1 ; s0
        vpinsrb %%LFSR0_3, [%%KEY + 16], 0 ; s0

        vpinsrb %%LFSR0_3, [%%KEY + 22], 5 ; s1
        vpinsrb %%LFSR0_3, [%%KEY + 17], 4 ; s1

        vpinsrb %%LFSR0_3, [%%KEY + 23], 9 ; s2
        vpinsrb %%LFSR0_3, [%%KEY + 18], 8 ; s2

        vpinsrb %%LFSR0_3, [%%KEY + 24], 13 ; s3
        vpinsrb %%LFSR0_3, [%%KEY + 19], 12 ; s3

        ; s4 - s7
        vpxor   %%LFSR4_7, %%LFSR4_7
        vpinsrb %%LFSR4_7, [%%KEY + 4], 3   ; s4
        vpinsrb %%LFSR4_7, [%%IV], 7        ; s5
        vpinsrb %%LFSR4_7, [%%IV + 1], 11   ; s6
        vpinsrb %%LFSR4_7, [%%IV + 10], 15  ; s7

        vpsrld  %%LFSR4_7, 1

        vpinsrb %%LFSR4_7, [%%KEY + 25], 1 ; s4
        vpinsrb %%LFSR4_7, [%%KEY + 20], 0 ; s4

        vpinsrb %%LFSR4_7, [%%KEY + 5], 5 ; s5
        vpinsrb %%LFSR4_7, [%%KEY + 26], 4 ; s5

        vpinsrb %%LFSR4_7, [%%KEY + 6], 9 ; s6
        vpinsrb %%LFSR4_7, [%%KEY + 27], 8 ; s6

        vpinsrb %%LFSR4_7, [%%KEY + 7], 13 ; s7
        vpinsrb %%LFSR4_7, [%%IV + 2], 12 ; s7

        vpor    %%LFSR4_7, [%%CONSTANTS + 16] ; s4 - s7

        vmovd   %%XTMP, [%%IV + 17]
        vpshufb %%XTMP, [rel shuf_mask_iv_17_19]
        vpand   %%XTMP, [rel clear_iv_mask]

        vpor    %%LFSR4_7, %%XTMP

        ; s8 - s11
        vpxor   %%LFSR8_11, %%LFSR8_11
        vpinsrb %%LFSR8_11, [%%KEY + 8], 3   ; s8
        vpinsrb %%LFSR8_11, [%%KEY + 9], 7   ; s9
        vpinsrb %%LFSR8_11, [%%IV + 5], 11   ; s10
        vpinsrb %%LFSR8_11, [%%KEY + 11], 15 ; s11

        vpsrld  %%LFSR8_11, 1

        vpinsrb %%LFSR8_11, [%%IV + 3], 1 ; s8
        vpinsrb %%LFSR8_11, [%%IV + 11], 0 ; s8

        vpinsrb %%LFSR8_11, [%%IV + 12], 5 ; s9
        vpinsrb %%LFSR8_11, [%%IV + 4], 4 ; s9

        vpinsrb %%LFSR8_11, [%%KEY + 10], 9 ; s10
        vpinsrb %%LFSR8_11, [%%KEY + 28], 8 ; s10

        vpinsrb %%LFSR8_11, [%%IV + 6], 13 ; s11
        vpinsrb %%LFSR8_11, [%%IV + 13], 12 ; s11

        vpor    %%LFSR8_11, [%%CONSTANTS + 32] ; s8 - s11

        vmovd   %%XTMP, [%%IV + 20]
        vpshufb %%XTMP, [rel shuf_mask_iv_20_23]
        vpand   %%XTMP, [rel clear_iv_mask]

        vpor    %%LFSR8_11, %%XTMP

        ; s12 - s15
        vpxor   %%LFSR12_15, %%LFSR12_15
        vpinsrb %%LFSR12_15, [%%KEY + 12], 3   ; s12
        vpinsrb %%LFSR12_15, [%%KEY + 13], 7   ; s13
        vpinsrb %%LFSR12_15, [%%KEY + 14], 11  ; s14
        vpinsrb %%LFSR12_15, [%%KEY + 15], 15  ; s15

        vpsrld  %%LFSR12_15, 1

        vpinsrb %%LFSR12_15, [%%IV + 7], 1 ; s12
        vpinsrb %%LFSR12_15, [%%IV + 14], 0 ; s12

        vpinsrb %%LFSR12_15, [%%IV + 15], 5 ; s13
        vpinsrb %%LFSR12_15, [%%IV + 8], 4 ; s13

        vpinsrb %%LFSR12_15, [%%IV + 16], 9 ; s14
        vpinsrb %%LFSR12_15, [%%IV + 9], 8 ; s14

        vpinsrb %%LFSR12_15, [%%KEY + 30], 13 ; s15
        vpinsrb %%LFSR12_15, [%%KEY + 29], 12 ; s15

        vpor    %%LFSR12_15, [%%CONSTANTS + 48] ; s12 - s15

        movzx   DWORD(%%TMP), byte [%%IV + 24]
        and     DWORD(%%TMP), 0x0000003f
        shl     DWORD(%%TMP), 16
        vmovd   %%XTMP, DWORD(%%TMP)

        movzx   DWORD(%%TMP), byte [%%KEY + 31]
        shl     DWORD(%%TMP), 12
        and     DWORD(%%TMP), 0x000f0000 ; high nibble of K_31
        vpinsrd %%XTMP, DWORD(%%TMP), 2

        movzx   DWORD(%%TMP), byte [%%KEY + 31]
        shl     DWORD(%%TMP), 16
        and     DWORD(%%TMP), 0x000f0000 ; low nibble of K_31
        vpinsrd %%XTMP, DWORD(%%TMP), 3

        vpor    %%LFSR12_15, %%XTMP
%endmacro

%macro ZUC_INIT_4 1
%define %%KEY_SIZE %1 ; [constant] Key size (128 or 256)

%define pKe	arg1
%define pIv	arg2
%define pState	arg3
%define tag_sz	arg4 ; Only used in ZUC-256

%define %%XTMP1  xmm0
%define %%XTMP2  xmm1
%define %%XTMP3  xmm2
%define %%XTMP4  xmm3
%define %%XTMP5  xmm4
%define %%XTMP6  xmm5
%define %%XTMP7  xmm6
%define %%XTMP8  xmm7
%define %%XTMP9  xmm8
%define %%XTMP10 xmm9
%define %%XTMP11 xmm10
%define %%XTMP12 xmm11
%define %%XTMP13 xmm12
%define %%XTMP14 xmm13
%define %%XTMP15 xmm14
%define %%XTMP16 xmm15

%define %%W     %%XTMP10
%define %%X3    %%XTMP11
%define %%MASK_31 %%XTMP16

        FUNC_SAVE

        ; Zero out R1-R2
        vpxor   %%XTMP1, %%XTMP1
        vmovdqa [pState + OFS_R1], %%XTMP1
        vmovdqa [pState + OFS_R2], %%XTMP1

%if %%KEY_SIZE == 128

        ;; Load key and IVs
%assign %%OFF 0
%assign %%I 1
%assign %%J 5
%rep 4
        mov     r15,  [pKe + %%OFF]
        vmovdqu APPEND(%%XTMP, %%I), [r15]
        ; Read 16 bytes of IV
        vmovdqa APPEND(%%XTMP, %%J), [pIv + %%OFF*4]
%assign %%OFF (%%OFF + 8)
%assign %%I (%%I + 1)
%assign %%J (%%J + 1)
%endrep

        ;;; Initialize all LFSR registers in four steps:
        ;;; first, registers 0-3, then registers 4-7, 8-11, 12-15
%assign %%OFF 0
%rep 4
        ; Set read-only registers for shuffle masks for key, IV and Ek_d for 8 registers
        vmovdqa %%XTMP13, [rel shuf_mask_key + %%OFF]
        vmovdqa %%XTMP14, [rel shuf_mask_iv + %%OFF]
        vmovdqa %%XTMP15, [rel Ek_d + %%OFF]

        ; Set 4xLFSR registers for all packets
%assign %%IDX 9
%assign %%I 1
%assign %%J 5
%rep 4
        INIT_LFSR_128 APPEND(%%XTMP,%%I), APPEND(%%XTMP,%%J), %%XTMP13, %%XTMP14, \
                      %%XTMP15, APPEND(%%XTMP, %%IDX), %%XTMP16
%assign %%IDX (%%IDX + 1)
%assign %%I (%%I + 1)
%assign %%J (%%J + 1)
%endrep

        ; Store 4xLFSR registers in memory (reordering first,
        ; so all SX registers are together)
        TRANSPOSE4_U32  %%XTMP9, %%XTMP10, %%XTMP11, %%XTMP12, %%XTMP13, %%XTMP14

        vmovdqa [pState + 4*%%OFF], %%XTMP9
        vmovdqa [pState + 4*%%OFF + 16], %%XTMP10
        vmovdqa [pState + 4*%%OFF + 16*2], %%XTMP11
        vmovdqa [pState + 4*%%OFF + 16*3], %%XTMP12

%assign %%OFF (%%OFF + 16)
%endrep

%else ;; %%KEY_SIZE == 256

        ; Get pointer to constants (depending on tag size, this will point at
        ; constants for encryption, authentication with 4-byte, 8-byte or 16-byte tags)
        lea    r13, [rel EK256_d64]
        bsf    DWORD(tag_sz), DWORD(tag_sz)
        dec    DWORD(tag_sz)
        shl    DWORD(tag_sz), 6
        add    r13, tag_sz

    ;;; Initialize all LFSR registers
%assign %%OFF 0
%rep 4
        ;; Load key and IV for each packet
        mov     r15, [pKe + %%OFF]
        lea     r10, [pIv + %%OFF*4]

        ; Initialize S0-15 for each packet
        INIT_LFSR_256 r15, r10, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, r11, r13

        vmovdqa [pState + 2*%%OFF], %%XTMP1
        vmovdqa [pState + 2*%%OFF + 64], %%XTMP2
        vmovdqa [pState + 2*%%OFF + 64*2], %%XTMP3
        vmovdqa [pState + 2*%%OFF + 64*3], %%XTMP4
%assign %%OFF (%%OFF + 8)
%endrep

        ; Read, transpose and store, so all S_X from the 4 packets are
        ; in the same register
%assign %%OFF 0
%rep 4
        vmovdqa %%XTMP1, [pState + %%OFF]
        vmovdqa %%XTMP2, [pState + %%OFF + 16]
        vmovdqa %%XTMP3, [pState + %%OFF + 16*2]
        vmovdqa %%XTMP4, [pState + %%OFF + 16*3]

        TRANSPOSE4_U32  %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6

        vmovdqa [pState + %%OFF], %%XTMP1
        vmovdqa [pState + %%OFF + 16], %%XTMP2
        vmovdqa [pState + %%OFF + 16*2], %%XTMP3
        vmovdqa [pState + %%OFF + 16*3], %%XTMP4

%assign %%OFF (%%OFF + 64)
%endrep
%endif ;; %%KEY_SIZE == 256

        ; Load read-only registers
        vmovdqa %%MASK_31, [rel mask31]

    ; Shift LFSR 32-times, update state variables
%assign N 0
%rep 32
        BITS_REORG4 pState, N, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, \
                    %%XTMP6, %%XTMP7, %%XTMP8, %%XTMP9, %%XTMP10
        NONLIN_FUN4 pState, %%XTMP1, %%XTMP2, %%XTMP3, \
                    %%XTMP4, %%XTMP5, %%XTMP6, %%XTMP7, %%W
        vpsrld  %%W, 1 ; Shift out LSB of W
        LFSR_UPDT4  pState, N, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6, \
                    %%MASK_31, %%W, init ; W used in LFSR update
%assign N N+1
%endrep

        ; And once more, initial round from keygen phase = 33 times
        BITS_REORG4 pState, 0, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, \
                    %%XTMP6, %%XTMP7, %%XTMP8, %%XTMP9, %%XTMP10
        NONLIN_FUN4 pState, %%XTMP1, %%XTMP2, %%XTMP3, \
                    %%XTMP4, %%XTMP5, %%XTMP6, %%XTMP7, %%W
        LFSR_UPDT4  pState, 0, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6, \
                    %%MASK_31, %%XTMP8, work

        FUNC_RESTORE

        ret
%endmacro

MKGLOBAL(asm_ZucInitialization_4_avx,function,internal)
asm_ZucInitialization_4_avx:
        ZUC_INIT_4 128

MKGLOBAL(asm_Zuc256Initialization_4_avx,function,internal)
asm_Zuc256Initialization_4_avx:
        ZUC_INIT_4 256

; This macro reorder the LFSR registers
; after N rounds (1 <= N <= 15), since the registers
; are shifted every round
;
; The macro clobbers XMM0-15
;
%macro REORDER_LFSR 2
%define %%STATE      %1
%define %%NUM_ROUNDS %2

%if %%NUM_ROUNDS != 16
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
%endif ;; %%NUM_ROUNDS != 16

%endmacro

;
; Generate N*4 bytes of keystream
; for 4 buffers (where N is number of rounds)
;
%macro KEYGEN_4_AVX 1
%define %%NUM_ROUNDS    %1 ; [in] Number of 4-byte rounds

%define	pState  arg1
%define	pKS     arg2

%define %%XTMP1  xmm0
%define %%XTMP2  xmm1
%define %%XTMP3  xmm2
%define %%XTMP4  xmm3
%define %%XTMP5  xmm4
%define %%XTMP6  xmm5
%define %%XTMP7  xmm6
%define %%XTMP8  xmm7
%define %%XTMP9  xmm8
%define %%XTMP10 xmm9
%define %%XTMP11 xmm10
%define %%XTMP12 xmm11
%define %%XTMP13 xmm12
%define %%XTMP14 xmm13
%define %%XTMP15 xmm14
%define %%XTMP16 xmm15

%define %%W     %%XTMP10
%define %%X3    %%XTMP11
%define %%MASK_31 %%XTMP16

        FUNC_SAVE

        ; Store 4 keystream pointers on the stack
        ; and reserve memory for storing keystreams for all 4 buffers
        mov     r10, rsp
        sub     rsp, (4*8 + %%NUM_ROUNDS * 16)
        and     rsp, -16

        vmovdqa %%XTMP1, [pKS]
        vmovdqa %%XTMP2, [pKS + 16]
        vmovdqa [rsp], %%XTMP1
        vmovdqa [rsp + 8*2], %%XTMP2

        ; Load read-only registers
        vmovdqa %%MASK_31, [rel mask31]


    ; Generate N*4B of keystream in N rounds
%assign %%N 1
%rep %%NUM_ROUNDS
        BITS_REORG4 pState, %%N, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, \
                    %%XTMP6, %%XTMP7, %%XTMP8, %%XTMP9, %%XTMP10, %%X3
        NONLIN_FUN4 pState, %%XTMP1, %%XTMP2, %%XTMP3, \
                    %%XTMP4, %%XTMP5, %%XTMP6, %%XTMP7, %%W
        ; OFS_X3 XOR W and store in stack
        vpxor       %%X3, %%W
        vmovdqa     [rsp + 4*8 + (%%N-1)*16], %%X3
        LFSR_UPDT4  pState, %%N, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6, \
                    %%MASK_31, %%XTMP8, work
%assign %%N (%%N + 1)
%endrep

%if (%%NUM_ROUNDS == 4)
        ;; Load all OFS_X3
        vmovdqa %%XTMP1, [rsp + 4*8]
        vmovdqa %%XTMP2, [rsp + 4*8 + 16]
        vmovdqa %%XTMP3, [rsp + 4*8 + 16*2]
        vmovdqa %%XTMP4, [rsp + 4*8 + 16*3]

        TRANSPOSE4_U32 %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6

        store16B_kstr4 %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4
%else ;; NUM_ROUNDS != 4
%assign %%IDX 1
%rep %%NUM_ROUNDS
        vmovdqa APPEND(%%XTMP, %%IDX), [rsp + 4*8 + (%%IDX-1)*16]
        store4B_kstr4 APPEND(%%XTMP, %%IDX)
%assign %%IDX (%%IDX + 1)
%endrep
%endif ;; NUM_ROUNDS == 4

        ;; Clear stack frame containing keystream information
%ifdef SAFE_DATA
        vpxor   %%XTMP1, %%XTMP1
%assign %%I 0
%rep (2 + %%NUM_ROUNDS)
        vmovdqa [rsp + %%I*16], %%XTMP1
%assign %%I (%%I + 1)
%endrep
%endif

        ;; Reorder memory for LFSR registers, as not all 16 rounds
        ;; will be completed (can be 4 or 2)
        REORDER_LFSR pState, %%NUM_ROUNDS

        ;; Restore rsp pointer to value before pushing keystreams
        mov     rsp, r10

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

;
;; void asm_ZucGenKeystream4B_4_avx(state4_t *pSta, u32* pKeyStr[4]);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(asm_ZucGenKeystream4B_4_avx,function,internal)
asm_ZucGenKeystream4B_4_avx:

    KEYGEN_4_AVX 1

    ret

;;
;; Encrypt N*4B bytes on all 4 buffers
;; where N is number of rounds (up to 4)
;; In final call, an array of final bytes is read
;; from memory and only these final bytes are of
;; plaintext are read and XOR'ed.
;;
%macro CIPHERNx4B_4 4
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

%define %%XTMP1  xmm0
%define %%XTMP2  xmm1
%define %%XTMP3  xmm2
%define %%XTMP4  xmm3
%define %%XTMP5  xmm4
%define %%XTMP6  xmm5
%define %%XTMP7  xmm6
%define %%XTMP8  xmm7
%define %%XTMP9  xmm8
%define %%XTMP10 xmm9
%define %%XTMP11 xmm10
%define %%XTMP12 xmm11
%define %%XTMP13 xmm12
%define %%XTMP14 xmm13
%define %%XTMP15 xmm14
%define %%XTMP16 xmm15

%define %%W     %%XTMP10
%define %%X3    %%XTMP11
%define %%MASK_31 %%XTMP16

        ; Load read-only registers
        vmovdqa %%MASK_31, [rel mask31]

        ; Generate N*4B of keystream in N rounds
%assign %%N 1
%assign %%round (%%INITIAL_ROUND + %%N)
%rep %%NROUNDS
        BITS_REORG4 pState, %%round, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, \
                    %%XTMP6, %%XTMP7, %%XTMP8, %%XTMP9, %%XTMP10, %%X3
        NONLIN_FUN4 pState, %%XTMP1, %%XTMP2, %%XTMP3, \
                    %%XTMP4, %%XTMP5, %%XTMP6, %%XTMP7, %%W
        ; OFS_X3 XOR W and store in stack
        vpxor       %%X3, %%W
        vmovdqa     [rsp + _keystr_save + (%%N-1)*16], %%X3
        LFSR_UPDT4  pState, %%round, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6, \
                    %%MASK_31, %%XTMP8, work
%assign %%N (%%N + 1)
%assign %%round (%%round + 1)
%endrep

%assign %%N 1
%rep %%NROUNDS
        vmovdqa APPEND(%%XTMP, %%N), [rsp + _keystr_save + (%%N-1)*16]
%assign %%N (%%N + 1)
%endrep

        TRANSPOSE4_U32 %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6

        vmovdqa %%XTMP15, [rel swap_mask]

        ;; XOR Input buffer with keystream in rounds of 16B
        mov     r12, [pIn]
        mov     r13, [pIn + 8]
        mov     r14, [pIn + 16]
        mov     r15, [pIn + 24]
%if (%%LAST_CALL == 4)
        ;; Save GP registers
        mov     [rsp + _gpr_save],  %%TMP1
        mov     [rsp + _gpr_save + 8], %%TMP2

        ;; Read in r10 the word containing the number of final bytes to read for each lane
        movzx  r10d, word [rsp + _rem_bytes_save]
        simd_load_avx_16_1 %%XTMP5, r12 + %%OFFSET, r10
        movzx  r10d, word [rsp + _rem_bytes_save + 2]
        simd_load_avx_16_1 %%XTMP6, r13 + %%OFFSET, r10
        movzx  r10d, word [rsp + _rem_bytes_save + 4]
        simd_load_avx_16_1 %%XTMP7, r14 + %%OFFSET, r10
        movzx  r10d, word [rsp + _rem_bytes_save + 6]
        simd_load_avx_16_1 %%XTMP8, r15 + %%OFFSET, r10
%else
        vmovdqu %%XTMP5, [r12 + %%OFFSET]
        vmovdqu %%XTMP6, [r13 + %%OFFSET]
        vmovdqu %%XTMP7, [r14 + %%OFFSET]
        vmovdqu %%XTMP8, [r15 + %%OFFSET]
%endif

        vpshufb %%XTMP1, %%XTMP15
        vpshufb %%XTMP2, %%XTMP15
        vpshufb %%XTMP3, %%XTMP15
        vpshufb %%XTMP4, %%XTMP15

        vpxor   %%XTMP1, %%XTMP5
        vpxor   %%XTMP2, %%XTMP6
        vpxor   %%XTMP3, %%XTMP7
        vpxor   %%XTMP4, %%XTMP8

        mov     r12, [pOut]
        mov     r13, [pOut + 8]
        mov     r14, [pOut + 16]
        mov     r15, [pOut + 24]

%if (%%LAST_CALL == 1)
        movzx  r10d, word [rsp + _rem_bytes_save]
        simd_store_avx r12, %%XTMP1, r10, %%TMP1, %%TMP2, %%OFFSET
        movzx  r10d, word [rsp + _rem_bytes_save + 2]
        simd_store_avx r13, %%XTMP2, r10, %%TMP1, %%TMP2, %%OFFSET
        movzx  r10d, word [rsp + _rem_bytes_save + 4]
        simd_store_avx r14, %%XTMP3, r10, %%TMP1, %%TMP2, %%OFFSET
        movzx  r10d, word [rsp + _rem_bytes_save + 6]
        simd_store_avx r15, %%XTMP4, r10, %%TMP1, %%TMP2, %%OFFSET

        ; Restore registers
        mov     %%TMP1, [rsp + _gpr_save]
        mov     %%TMP2, [rsp + _gpr_save + 8]
%else
        vmovdqu [r12 + %%OFFSET], %%XTMP1
        vmovdqu [r13 + %%OFFSET], %%XTMP2
        vmovdqu [r14 + %%OFFSET], %%XTMP3
        vmovdqu [r15 + %%OFFSET], %%XTMP4
%endif
%endmacro

;;
;; void asm_ZucCipher_4_avx(state16_t *pSta, u64 *pIn[4],
;;                          u64 *pOut[4], u16 *length[4], u64 min_length);
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
MKGLOBAL(asm_ZucCipher_4_avx,function,internal)
asm_ZucCipher_4_avx:

%define pState  arg1
%define pIn     arg2
%define pOut    arg3
%define lengths arg4

%ifdef LINUX
        %define nrounds r8
%else
        %define nrounds rdi
%endif

%define min_length r10
%define buf_idx r11

        mov     min_length, arg5

        or      min_length, min_length
        jz      exit_cipher

        FUNC_SAVE

        ;; Convert all lengths from UINT16_MAX (indicating that lane is not valid) to min length
        vmovd   xmm0, DWORD(min_length)
        vpshufb xmm0, [rel broadcast_word]
        vmovq   xmm1, [lengths]
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
        vmovq   [lengths], xmm2 ; Update in memory the final updated lengths

        ; Calculate number of bytes to encrypt after rounds of 16 bytes (up to 15 bytes),
        ; for each lane, and store it in stack to be used in the last round
        vpsubw  xmm1, xmm2 ; Bytes to encrypt in all lanes
        vpand   xmm1, [rel all_0fs] ; Number of final bytes (up to 15 bytes) for each lane
        vpcmpeqw xmm2, xmm1, xmm3 ;; Mask with FFFF in lengths == 0
        vpand   xmm2, [rel all_10s] ;; 16 in positions where lengths was 0
        vpor    xmm1, xmm2          ;; Number of final bytes (up to 16 bytes) for each lane

        ; Allocate stack frame to store keystreams (16*4 bytes), number of final bytes (8 bytes),
        ; space for rsp (8 bytes) and 2 GP registers (16 bytes) that will be clobbered later
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16
        xor     buf_idx, buf_idx
        vmovq   [rsp + _rem_bytes_save], xmm1
        mov     [rsp + _rsp_save], rax

loop_cipher64:
        cmp     min_length, 64
        jl      exit_loop_cipher64

%assign round_off 0
%rep 4
        CIPHERNx4B_4 4, round_off, buf_idx, 0

        add     buf_idx, 16
        sub     min_length, 16
%assign round_off (round_off + 4)
%endrep
        jmp     loop_cipher64
exit_loop_cipher64:

        ; Check if there are more bytes left to encrypt
        mov     r15, min_length
        add     r15, 3
        shr     r15, 2 ;; number of rounds left (round up length to nearest multiple of 4B)
        jz      exit_final_rounds

        cmp     r15, 8
        je      _num_final_rounds_is_8
        jb      _final_rounds_is_1_7

        ; Final blocks 9-16
        cmp     r15, 12
        je      _num_final_rounds_is_12
        ja      _final_rounds_is_13_16

        ; Final blocks 9-11
        cmp     r15, 10
        je      _num_final_rounds_is_10
        jb      _num_final_rounds_is_9
        ja      _num_final_rounds_is_11

_final_rounds_is_13_16:
        cmp     r15, 16
        je      _num_final_rounds_is_16
        cmp     r15, 14
        je      _num_final_rounds_is_14
        jb      _num_final_rounds_is_13
        ja      _num_final_rounds_is_15

_final_rounds_is_1_7:
        cmp     r15, 4
        je      _num_final_rounds_is_4
        jl      _final_rounds_is_1_3

        ; Final blocks 5-7
        cmp     r15, 6
        je      _num_final_rounds_is_6
        jb      _num_final_rounds_is_5
        ja      _num_final_rounds_is_7

_final_rounds_is_1_3:
        cmp     r15, 2
        je      _num_final_rounds_is_2
        ja      _num_final_rounds_is_3

        ; Perform encryption of last bytes (<= 63 bytes) and reorder LFSR registers
%assign I 1
%rep 4
APPEND(_num_final_rounds_is_,I):
        CIPHERNx4B_4 I, 0, buf_idx, 1
        REORDER_LFSR pState, I
        add     buf_idx, (I*4)
        jmp     exit_final_rounds
%assign I (I + 1)
%endrep

%assign I 5
%rep 4
APPEND(_num_final_rounds_is_,I):
        CIPHERNx4B_4 4, 0, buf_idx, 0
        add     buf_idx, 16
        CIPHERNx4B_4 (I-4), 4, buf_idx, 1
        add     buf_idx, ((I-4)*4)
        REORDER_LFSR pState, I
        jmp     exit_final_rounds
%assign I (I + 1)
%endrep

%assign I 9
%rep 4
APPEND(_num_final_rounds_is_,I):
        CIPHERNx4B_4 4, 0, buf_idx, 0
        add     buf_idx, 16
        CIPHERNx4B_4 4, 4, buf_idx, 0
        add     buf_idx, 16
        CIPHERNx4B_4 (I-8), 8, buf_idx, 1
        add     buf_idx, ((I-8)*4)
        REORDER_LFSR pState, I
        jmp     exit_final_rounds
%assign I (I + 1)
%endrep

%assign I 13
%rep 4
APPEND(_num_final_rounds_is_,I):
        CIPHERNx4B_4 4, 0, buf_idx, 0
        add     buf_idx, 16
        CIPHERNx4B_4 4, 4, buf_idx, 0
        add     buf_idx, 16
        CIPHERNx4B_4 4, 8, buf_idx, 0
        add     buf_idx, 16
        CIPHERNx4B_4 (I-12), 12, buf_idx, 1
        add     buf_idx, ((I-12)*4)
        REORDER_LFSR pState, I
        jmp     exit_final_rounds
%assign I (I + 1)
%endrep

exit_final_rounds:
        ;; update in/out pointers
        vmovq   xmm0, buf_idx
        vpshufd xmm0, xmm0, 0x44
        vpaddq  xmm1, xmm0, [pIn]
        vpaddq  xmm2, xmm0, [pIn + 16]
        vmovdqa [pIn], xmm1
        vmovdqa [pIn + 16], xmm2
        vpaddq  xmm1, xmm0, [pOut]
        vpaddq  xmm2, xmm0, [pOut + 16]
        vmovdqa [pOut], xmm1
        vmovdqa [pOut + 16], xmm2

        ;; Clear stack frame containing keystream information
%ifdef SAFE_DATA
        vpxor   xmm0, xmm0
%assign i 0
%rep 4
	vmovdqa [rsp + _keystr_save + i*16], xmm0
%assign i (i+1)
%endrep
%endif
        ; Restore rsp
        mov     rsp, [rsp + _rsp_save]

        FUNC_RESTORE

exit_cipher:

        ret

;
; Processes 16 bytes of data and updates the digest
;
%macro DIGEST_16_BYTES 12
%define %%KS            %1  ; [in] Pointer to 24-byte keystream
%define %%BIT_REV_L     %2  ; [in] Bit reverse low table (XMM)
%define %%BIT_REV_H     %3  ; [in] Bit reverse high table (XMM)
%define %%BIT_REV_AND   %4  ; [in] Bit reverse and table (XMM)
%define %%XDIGEST       %5  ; [in/out] Temporary digest (XMM)
%define %%XTMP1         %6  ; [clobbered] Temporary XMM register
%define %%XTMP2         %7  ; [clobbered] Temporary XMM register
%define %%XTMP3         %8  ; [clobbered] Temporary XMM register
%define %%XTMP4         %9  ; [clobbered] Temporary XMM register
%define %%KS_L          %10 ; [clobbered] Temporary XMM register
%define %%KS_H          %11 ; [clobbered] Temporary XMM register
%define %%OFF           %12 ; [in] Offset into KS

        vpand   %%XTMP2, %%XTMP1, %%BIT_REV_AND

        vpandn  %%XTMP3, %%BIT_REV_AND, %%XTMP1
        vpsrld  %%XTMP3, 4

        vpshufb %%XTMP4, %%BIT_REV_H, %%XTMP2
        vpshufb %%XTMP1, %%BIT_REV_L, %%XTMP3
        vpor    %%XTMP4, %%XTMP1 ;; %%XTMP4 - bit reverse data bytes

        ;; ZUC authentication part
        ;; - 4x32 data bits
        ;; - set up KS
        vpshufd %%KS_L, [%%KS + %%OFF + (0*4)], 0x61
        vpshufd %%KS_H, [%%KS + %%OFF + (2*4)], 0x61

        ;;  - set up DATA
        ; Data bytes [31:0 0s 63:32 0s]
        vpshufb %%XTMP1, %%XTMP4, [rel shuf_mask_dw0_0_dw1_0]

        ; Data bytes [95:64 0s 127:96 0s]
        vpshufb %%XTMP3, %%XTMP4, [rel shuf_mask_dw2_0_dw3_0]

        ;; - clmul
        ;; - xor the results from 4 32-bit words together
        vpclmulqdq %%XTMP2, %%XTMP1, %%KS_L, 0x11
        vpclmulqdq %%XTMP1, %%KS_L, 0x00
        vpclmulqdq %%XTMP4, %%XTMP3, %%KS_H, 0x00
        vpclmulqdq %%XTMP3, %%KS_H, 0x11

        vpxor   %%XTMP2, %%XTMP1
        vpxor   %%XTMP4, %%XTMP3
        vpxor   %%XDIGEST, %%XTMP2
        vpxor   %%XDIGEST, %%XTMP4
%endmacro

%macro REMAINDER 18
%define %%T             %1  ; [in] Pointer to authentication tag
%define %%KS            %2  ; [in/clobbered] Pointer to 32-byte keystream
%define %%DATA          %3  ; [in/clobbered] Pointer to input data
%define %%N_BITS        %4  ; [in/clobbered] Number of bits to digest
%define %%N_BYTES       %5  ; [clobbered] Number of bytes to digest
%define %%TMP           %6  ; [clobbered] Temporary GP register
%define %%TMP2          %7  ; [clobbered] Temporary GP register
%define %%TMP3          %8  ; [clobbered] Temporary GP register
%define %%BIT_REV_L     %9  ; [in] Bit reverse low table (XMM)
%define %%BIT_REV_H     %10 ; [in] Bit reverse high table (XMM)
%define %%BIT_REV_AND   %11 ; [in] Bit reverse and table (XMM)
%define %%XDIGEST       %12 ; [clobbered] Temporary digest (XMM)
%define %%XTMP1         %13 ; [clobbered] Temporary XMM register
%define %%XTMP2         %14 ; [clobbered] Temporary XMM register
%define %%XTMP3         %15 ; [clobbered] Temporary XMM register
%define %%XTMP4         %16 ; [clobbered] Temporary XMM register
%define %%KS_L          %17 ; [clobbered] Temporary XMM register
%define %%KS_H          %18 ; [clobbered] Temporary XMM register

        FUNC_SAVE

        vpxor   %%XDIGEST, %%XDIGEST

        ; Length between 1 and 255 bits
        test    %%N_BITS, 128
        jz      %%Eia3RoundsAVX_dq_end

        ;; read up to 16 bytes of data and reverse bits
        vmovdqu %%XTMP1, [%%DATA]
        DIGEST_16_BYTES %%KS, %%BIT_REV_L, %%BIT_REV_H, %%BIT_REV_AND, \
                        %%XDIGEST, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, \
                        %%KS_L, %%KS_H, 0

        add     %%DATA, 16
        add     %%KS, 16
        sub     %%N_BITS, 128
%%Eia3RoundsAVX_dq_end:

        or      %%N_BITS, %%N_BITS
        jz      %%Eia3RoundsAVX_end

        ; Get number of bytes
        lea     %%N_BYTES, [%%N_BITS + 7]
        shr     %%N_BYTES, 3

        ;; read up to 16 bytes of data, zero bits not needed if partial byte and bit-reverse
        simd_load_avx_16_1 %%XTMP1, %%DATA, %%N_BYTES
        ; check if there is a partial byte (less than 8 bits in last byte)
        mov     %%TMP, %%N_BITS
        and     %%TMP, 0x7
        shl     %%TMP, 4
        lea     %%TMP2, [rel bit_mask_table]
        add     %%TMP2, %%TMP

        ; Get mask to clear last bits
        vmovdqa %%XTMP2, [%%TMP2]

        ; Shift left 16-N bytes to have the last byte always at the end of the XMM register
        ; to apply mask, then restore by shifting right same amount of bytes
        mov     %%TMP2, 16
        sub     %%TMP2, %%N_BYTES
        XVPSLLB %%XTMP1, %%TMP2, %%XTMP3, %%TMP
        vpand   %%XTMP1, %%XTMP2
        XVPSRLB %%XTMP1, %%TMP2, %%XTMP3, %%TMP

        DIGEST_16_BYTES %%KS, %%BIT_REV_L, %%BIT_REV_H, %%BIT_REV_AND, \
                        %%XDIGEST, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, \
                        %%KS_L, %%KS_H, 0

%%Eia3RoundsAVX_end:

%define %%TAG DWORD(%%TMP)
        ;; - update T
        mov     %%TAG, [%%T]
        vmovq   %%TMP2, %%XDIGEST
        shr     %%TMP2, 32
        xor     %%TAG, DWORD(%%TMP2)

        ;; XOR with keyStr[n_bits] (Z_length, from spec)

        ; Read keyStr[N_BITS / 32]
        mov     %%TMP2, %%N_BITS
        shr     %%TMP2, 5
        mov     %%TMP3, [%%KS + %%TMP2*4]

        ; Rotate left by N_BITS % 32
        mov     %%TMP2, rcx ; Save RCX
        mov     rcx, %%N_BITS
        and     rcx, 0x1F
        rol     %%TMP3, cl
        mov     rcx, %%TMP2 ; Restore RCX

        ; XOR with previous digest calculation
        xor     %%TAG, DWORD(%%TMP3)

        ;; XOR with keyStr[L-1]

        ; Read keyStr[L - 1] (last double word of keyStr)
        mov     %%TMP2, %%N_BITS
        add     %%TMP2, (31 + 64 - 32) ; (32 is subtracted here to get L - 1)
        shr     %%TMP2, 5 ; L - 1
        ; XOR with previous digest calculation
        xor     %%TAG, [%%KS + %%TMP2 * 4]

        bswap   %%TAG
        mov     [%%T], %%TAG

        FUNC_RESTORE

%endmacro

;;
;; extern void asm_Eia3Remainder_avx(void *T, const void *ks, const void *data, uint64_t n_bits)
;;
;; Returns authentication update value to be XOR'ed with current authentication tag
;;
;;  @param [in] T (digest pointer)
;;  @param [in] KS (key stream pointer)
;;  @param [in] DATA (data pointer)
;;  @param [in] N_BITS (number of bits to digest)
;;
align 64
MKGLOBAL(asm_Eia3Remainder_avx,function,internal)
asm_Eia3Remainder_avx:

%define T       arg1
%define KS      arg2
%define DATA    arg3
%define N_BITS  arg4

        vmovdqa  xmm0, [rel bit_reverse_table_l]
        vmovdqa  xmm1, [rel bit_reverse_table_h]
        vmovdqa  xmm2, [rel bit_reverse_and_table]

        REMAINDER T, KS, DATA, N_BITS, r12, r13, r14, r15, \
                  xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, \
                  xmm8, xmm9

        ret

%macro EIA3_ROUND 15
%define %%T              %1  ; [in] Pointer to authentication tag
%define %%KS             %2  ; [in/clobbered] Pointer to 32-byte keystream
%define %%DATA           %3  ; [in/clobbered] Pointer to input data
%define %%TMP            %4  ; [clobbered] Temporary GP register
%define %%BIT_REV_L      %5  ; [in] Bit reverse low table (XMM)
%define %%BIT_REV_H      %6  ; [in] Bit reverse high table (XMM)
%define %%BIT_REV_AND    %7  ; [in] Bit reverse and table (XMM)
%define %%XDIGEST        %8  ; [clobbered] Temporary digest (XMM)
%define %%XTMP1          %9  ; [clobbered] Temporary XMM register
%define %%XTMP2          %10 ; [clobbered] Temporary XMM register
%define %%XTMP3          %11 ; [clobbered] Temporary XMM register
%define %%XTMP4          %12 ; [clobbered] Temporary XMM register
%define %%KS_L           %13 ; [clobbered] Temporary XMM register
%define %%KS_H           %14 ; [clobbered] Temporary XMM register
%define %%NUM_16B_ROUNDS %15 ; [in] Number of 16-byte rounds

        vpxor   %%XDIGEST, %%XDIGEST

%assign %%OFF 0
%rep %%NUM_16B_ROUNDS
        vmovdqu %%XTMP1, [%%DATA + %%OFF]

        DIGEST_16_BYTES %%KS, %%BIT_REV_L, %%BIT_REV_H, %%BIT_REV_AND, \
                        %%XDIGEST, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, \
                        %%KS_L, %%KS_H, %%OFF

%assign %%OFF (%%OFF + 16)
%endrep

        ;; - update T
        vmovq   %%TMP, %%XDIGEST
        shr     %%TMP, 32
        xor     [%%T], DWORD(%%TMP)

%endmacro

;;
;;extern void asm_Eia3Round32B_avx(void *T, const void *KS, const void *DATA)
;;
;; Updates authentication tag T based on keystream KS and DATA.
;; - it processes 32 bytes of DATA
;; - reads data in 16 byte chunks and bit reverses them
;; - reads and re-arranges KS
;; - employs clmul for the XOR & ROL part
;; - copies top 32 bytes of KS to bottom (for the next round)
;;
;;  @param [in] T (digest pointer)
;;  @param [in] KS (key stream pointer)
;;  @param [in] DATA (data pointer)
;;
align 64
MKGLOBAL(asm_Eia3Round32B_avx,function,internal)
asm_Eia3Round32B_avx:

%define T	arg1
%define	KS	arg2
%define	DATA	arg3

        FUNC_SAVE

        vmovdqa  xmm0, [bit_reverse_table_l]
        vmovdqa  xmm1, [bit_reverse_table_h]
        vmovdqa  xmm2, [bit_reverse_and_table]

        EIA3_ROUND T, KS, DATA, r11, \
                  xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, \
                  xmm8, xmm9, 2

        ;; Copy last 32 bytes of KS to the front
        vmovdqa xmm0, [KS + 32]
        vmovdqa xmm1, [KS + 48]
        vmovdqa [KS], xmm0
        vmovdqa [KS + 16], xmm1

        FUNC_RESTORE

        ret

;;
;;extern void asm_Eia3Round16B_avx(void *T, const void *KS, const void *DATA)
;;
;; Updates authentication tag T based on keystream KS and DATA.
;; - it processes 16 bytes of DATA
;; - reads data in 16 byte chunks and bit reverses them
;; - reads and re-arranges KS
;; - employs clmul for the XOR & ROL part
;; - copies top 16 bytes of KS to bottom (for the next round)
;;
;;  @param [in] T (digest pointer)
;;  @param [in] KS (key stream pointer)
;;  @param [in] DATA (data pointer)
;;
align 64
MKGLOBAL(asm_Eia3Round16B_avx,function,internal)
asm_Eia3Round16B_avx:

%define T	arg1
%define	KS	arg2
%define	DATA	arg3

        FUNC_SAVE

        vmovdqa  xmm0, [bit_reverse_table_l]
        vmovdqa  xmm1, [bit_reverse_table_h]
        vmovdqa  xmm2, [bit_reverse_and_table]

        EIA3_ROUND T, KS, DATA, r11, \
                  xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, \
                  xmm8, xmm9, 1

        ;; Copy last 16 bytes of KS to the front
        vmovdqa xmm0, [KS + 16]
        vmovdqa [KS], xmm0

        FUNC_RESTORE

        ret

;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

mksection stack-noexec
