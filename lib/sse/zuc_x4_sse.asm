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

%ifndef ZUC_CIPHER_4
%define ZUC_CIPHER_4 asm_ZucCipher_4_sse
%define ZUC128_INIT_4 asm_ZucInitialization_4_sse
%define ZUC256_INIT_4 asm_Zuc256Initialization_4_sse
%define ZUC_KEYGEN16B_4 asm_ZucGenKeystream16B_4_sse
%define ZUC_KEYGEN8B_4 asm_ZucGenKeystream8B_4_sse
%define ZUC_KEYGEN4B_4 asm_ZucGenKeystream4B_4_sse
%define ZUC_EIA3ROUND16B asm_Eia3Round16B_sse
%define ZUC_EIA3REMAINDER asm_Eia3Remainder_sse
%define USE_GFNI 0
%endif

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%define arg6    r9
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    qword [rsp + 40]
%define arg6    qword [rsp + 48]
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
bit_reverse_table:
times 2 db      0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

; Stack frame for ZucCipher function
struc STACK
_keystr_save    resq  2*4 ; Space for 4 keystreams
_rsp_save:      resq    1 ; Space for rsp pointer
_gpr_save:      resq    2 ; Space for GP registers
_rem_bytes_save resq    1 ; Space for number of remaining bytes
endstruc

mksection .text

%define MASK31  xmm12

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

%macro TRANSPOSE4_U32 6
%define %%r0 %1
%define %%r1 %2
%define %%r2 %3
%define %%r3 %4
%define %%t0 %5
%define %%t1 %6

        movdqa  %%t0, %%r0
	shufps	%%t0, %%r1, 0x44	; t0 = {b1 b0 a1 a0}
	shufps	%%r0, %%r1, 0xEE	; r0 = {b3 b2 a3 a2}
        movdqa  %%t1, %%r2
	shufps  %%t1, %%r3, 0x44	; t1 = {d1 d0 c1 c0}
	shufps	%%r2, %%r3, 0xEE	; r2 = {d3 d2 c3 c2}

        movdqa  %%r1, %%t0
	shufps	%%r1, %%t1, 0xDD	; r1 = {d1 c1 b1 a1}
        movdqa  %%r3, %%r0
	shufps	%%r3, %%r2, 0xDD	; r3 = {d3 c3 b3 a3}
	shufps	%%r0, %%r2, 0x88	; r2 = {d2 c2 b2 a2}
        movdqa  %%r2, %%r0
	shufps	%%t0, %%t1, 0x88	; r0 = {d0 c0 b0 a0}
        movdqa  %%r0, %%t0
%endmacro

;;
;; Load LFSR register from memory into XMM register
;;
%macro LOAD_LFSR 5
%define %%STATE     %1 ;; [in] ZUC state
%define %%ROUND_NUM %2 ;; [in] GP Register with Round number
%define %%REG_IDX   %3 ;; [in] Register index to load (immediate)
%define %%TMP       %4 ;; [clobbered] Temp GP reg
%define %%LFSR      %5 ;; [out] XMM register to contain LFSR

    mov         %%TMP, %%ROUND_NUM
    add         %%TMP, %%REG_IDX
    and         %%TMP, 0xf
    shl         %%TMP, 4
    add         %%TMP, %%STATE
    movdqa      %%LFSR, [%%TMP]

%endmacro

;;
;; Store LFSR register to memory from XMM register
;;
%macro store_lfsr 5
%define %%STATE     %1 ;; [in] ZUC state
%define %%ROUND_NUM %2 ;; [in] GP Register with Round number
%define %%REG_IDX   %3 ;; [in] Register index to load (immediate)
%define %%TMP       %4 ;; [clobbered] Temp GP reg
%define %%LFSR      %5 ;; [in] XMM register to contain LFSR

    mov         %%TMP, %%ROUND_NUM
    add         %%TMP, %%REG_IDX
    and         %%TMP, 0xf
    shl         %%TMP, 4
    add         %%TMP, %%STATE
    movdqa      [%%TMP], %%LFSR

%endmacro

;
; Calculates X0-X3 from LFSR registers
;
%macro  BITS_REORG4 13-14
%define %%STATE         %1 ; [in] ZUC state
%define %%ROUND_NUM     %2 ; [in] Round number
%define %%TMP           %3 ; [clobbered] Temporary GP register (used when ROUND_NUM is a register)
%define %%LFSR_0        %4  ; [clobbered] LFSR_0
%define %%LFSR_2        %5  ; [clobbered] LFSR_2
%define %%LFSR_5        %6  ; [clobbered] LFSR_5
%define %%LFSR_7        %7  ; [clobbered] LFSR_7
%define %%LFSR_9        %8  ; [clobbered] LFSR_9
%define %%LFSR_11       %9  ; [clobbered] LFSR_11
%define %%LFSR_14       %10 ; [clobbered] LFSR_14
%define %%LFSR_15       %11 ; [clobbered] LFSR_15
%define %%XTMP1         %12 ; [clobbered] Temporary XMM register
%define %%XTMP2         %13 ; [clobbered] Temporary XMM register
%define %%X3            %14 ; [out] XMM register containing X3 of all lanes (only for work mode)

%ifnum %%ROUND_NUM
        movdqa  %%LFSR_15, [%%STATE + ((15 + %%ROUND_NUM) % 16)*16]
        movdqa  %%LFSR_14, [%%STATE + ((14 + %%ROUND_NUM) % 16)*16]
        movdqa  %%LFSR_11, [%%STATE + ((11 + %%ROUND_NUM) % 16)*16]
        movdqa  %%LFSR_9,  [%%STATE + (( 9 + %%ROUND_NUM) % 16)*16]
        movdqa  %%LFSR_7,  [%%STATE + (( 7 + %%ROUND_NUM) % 16)*16]
        movdqa  %%LFSR_5,  [%%STATE + (( 5 + %%ROUND_NUM) % 16)*16]
%if (%0 == 14) ;Only needed when generating X3 (for "working" mode)
        movdqa  %%LFSR_2,  [%%STATE + (( 2 + %%ROUND_NUM) % 16)*16]
        movdqa  %%LFSR_0,  [%%STATE + (( 0 + %%ROUND_NUM) % 16)*16]
%endif
%else ; %%ROUND_NUM is num
        LOAD_LFSR %%STATE, %%ROUND_NUM, 15, %%TMP, %%LFSR_15
        LOAD_LFSR %%STATE, %%ROUND_NUM, 14, %%TMP, %%LFSR_14
        LOAD_LFSR %%STATE, %%ROUND_NUM, 11, %%TMP, %%LFSR_11
        LOAD_LFSR %%STATE, %%ROUND_NUM, 9, %%TMP, %%LFSR_9
        LOAD_LFSR %%STATE, %%ROUND_NUM, 7, %%TMP, %%LFSR_7
        LOAD_LFSR %%STATE, %%ROUND_NUM, 5, %%TMP, %%LFSR_5
%if (%0 == 14) ; Only needed when generating X3 (for "working" mode)
        LOAD_LFSR %%STATE, %%ROUND_NUM, 2, %%TMP, %%LFSR_2
        LOAD_LFSR %%STATE, %%ROUND_NUM, 0, %%TMP, %%LFSR_0
%endif
%endif

        pxor    %%XTMP1, %%XTMP1
        pslld   %%LFSR_15, 1
        movdqa  %%XTMP2, %%LFSR_14
        pblendw %%XTMP2, %%XTMP1, 0xAA
        pblendw %%LFSR_15, %%XTMP2, 0x55

        movdqa  [%%STATE + OFS_X0], %%LFSR_15   ; BRC_X0
        pslld   %%LFSR_11, 16
        psrld   %%LFSR_9, 15
        por     %%LFSR_11, %%LFSR_9
        movdqa  [%%STATE + OFS_X1], %%LFSR_11   ; BRC_X1
        pslld   %%LFSR_7, 16
        psrld   %%LFSR_5, 15
        por     %%LFSR_7, %%LFSR_5
        movdqa  [%%STATE + OFS_X2], %%LFSR_7    ; BRC_X2
%if (%0 == 14)
        pslld   %%LFSR_2, 16
        psrld   %%LFSR_0, 15
        por     %%LFSR_2, %%LFSR_0
        movdqa  %%X3, %%LFSR_2    ; BRC_X3
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

        movdqa  %%OUT, %%IN

%if (%%N_BITS == 8)
        pshufb  %%OUT, [rel rot8_mod32]
%elif (%%N_BITS == 16)
        pshufb  %%OUT, [rel rot16_mod32]
%elif (%%N_BITS == 24)
        pshufb  %%OUT, [rel rot24_mod32]
%else
        pslld   %%OUT, %%N_BITS
        movdqa  %%XTMP, %%IN
        psrld   %%XTMP, (32 - %%N_BITS)
        por     %%OUT, %%XTMP
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
        movdqa  %%W, [%%STATE + OFS_X0]
        pxor    %%W, [%%STATE + OFS_R1]
        paddd   %%W, [%%STATE + OFS_R2]    ; W = (BRC_X0 ^ F_R1) + F_R2
%endif

        movdqa  %%XTMP1, [%%STATE + OFS_R1]
        movdqa  %%XTMP2, [%%STATE + OFS_R2]
        paddd   %%XTMP1, [%%STATE + OFS_X1]    ; W1 = F_R1 + BRC_X1
        pxor    %%XTMP2, [%%STATE + OFS_X2]    ; W2 = F_R2 ^ BRC_X2

        movdqa  %%XTMP3, %%XTMP1
        movdqa  %%XTMP4, %%XTMP2
        pslld   %%XTMP1, 16
        pslld   %%XTMP2, 16
        psrld   %%XTMP3, 16
        psrld   %%XTMP4, 16
        por     %%XTMP1, %%XTMP4
        por     %%XTMP2, %%XTMP3

        ROT_MOD32 %%XTMP3, %%XTMP1, %%XTMP7, 2
        ROT_MOD32 %%XTMP4, %%XTMP1, %%XTMP7, 10
        ROT_MOD32 %%XTMP5, %%XTMP1, %%XTMP7, 18
        ROT_MOD32 %%XTMP6, %%XTMP1, %%XTMP7, 24
        pxor    %%XTMP1, %%XTMP3
        pxor    %%XTMP1, %%XTMP4
        pxor    %%XTMP1, %%XTMP5
        pxor    %%XTMP1, %%XTMP6      ; XMM1 = U = L1(P)

        ROT_MOD32 %%XTMP3, %%XTMP2, %%XTMP7, 8
        ROT_MOD32 %%XTMP4, %%XTMP2, %%XTMP7, 14
        ROT_MOD32 %%XTMP5, %%XTMP2, %%XTMP7, 22
        ROT_MOD32 %%XTMP6, %%XTMP2, %%XTMP7, 30
        pxor    %%XTMP2, %%XTMP3
        pxor    %%XTMP2, %%XTMP4
        pxor    %%XTMP2, %%XTMP5
        pxor    %%XTMP2, %%XTMP6      ; XMM2 = V = L2(Q)

        ; Shuffland V to have all S0 lookups in XMM1 and all S1 lookups in XMM2

        ; Compress all S0 and S1 input values in each register

        pshufb  %%XTMP1, [rel S0_S1_shuf] ; S0: Bytes 0-7, S1: Bytes 8-15
        pshufb  %%XTMP2, [rel S1_S0_shuf] ; S1: Bytes 0-7, S0: Bytes 8-15

        movdqa  %%XTMP3, %%XTMP1
        shufpd  %%XTMP1, %%XTMP2, 0x2 ; All S0 input values
        shufpd  %%XTMP2, %%XTMP3, 0x2 ; All S1 input values

        ; Compute S0 and S1 values
        S0_comput_SSE   %%XTMP1, %%XTMP3, %%XTMP4, USE_GFNI
        S1_comput_SSE   %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, USE_GFNI

        ; Need to shuffle back %%XTMP1 & %%XTMP2 before storing output
        ; (revert what was done before S0 and S1 computations)
        movdqa  %%XTMP3, %%XTMP1
        shufpd  %%XTMP1, %%XTMP2, 0x2 ; All S0 input values
        shufpd  %%XTMP2, %%XTMP3, 0x2 ; All S1 input values

        pshufb  %%XTMP1, [rel rev_S0_S1_shuf]
        pshufb  %%XTMP2, [rel rev_S1_S0_shuf]

        movdqa  [%%STATE + OFS_R1], %%XTMP1
        movdqa  [%%STATE + OFS_R2], %%XTMP2
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
    movdqu      [rcx], %%DATA16B_L0
    movdqu      [rdx], %%DATA16B_L1
    movdqu      [r8],  %%DATA16B_L2
    movdqu      [r9],  %%DATA16B_L3
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
    pextrd      [r9], %1, 3
    pextrd      [r8], %1, 2
    pextrd      [rdx], %1, 1
    movd        [rcx], %1
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
%macro  lfsr_updt4  4
%define %%STATE     %1 ; [in] ZUC state
%define %%ROUND_NUM %2 ; [in] Round number
%define %%TMP       %3 ; [clobbered] Temporary GP register (used when ROUND_NUM is a register)
%define %%W         %4 ; [in/clobbered] XMM register to contain W for all lanes
    ;
    ; xmm1  = LFSR_S0
    ; xmm4  = LFSR_S4
    ; xmm10 = LFSR_S10
    ; xmm13 = LFSR_S13
    ; xmm15 = LFSR_S15
    ;
%ifnum %%ROUND_NUM
    movdqa      xmm1,  [%%STATE + (( 0 + %%ROUND_NUM) % 16)*16]
    movdqa      xmm4,  [%%STATE + (( 4 + %%ROUND_NUM) % 16)*16]
    movdqa      xmm10, [%%STATE + ((10 + %%ROUND_NUM) % 16)*16]
    movdqa      xmm13, [%%STATE + ((13 + %%ROUND_NUM) % 16)*16]
    movdqa      xmm15, [%%STATE + ((15 + %%ROUND_NUM) % 16)*16]
%else
    LOAD_LFSR %%STATE, %%ROUND_NUM, 0, %%TMP, xmm1
    LOAD_LFSR %%STATE, %%ROUND_NUM, 4, %%TMP, xmm4
    LOAD_LFSR %%STATE, %%ROUND_NUM, 10, %%TMP, xmm10
    LOAD_LFSR %%STATE, %%ROUND_NUM, 13, %%TMP, xmm13
    LOAD_LFSR %%STATE, %%ROUND_NUM, 15, %%TMP, xmm15
%endif

    ; Calculate LFSR feedback
    add_mod31   %%W, xmm1
    rot_mod31   xmm1, 8
    add_mod31   %%W, xmm1
    rot_mod31   xmm4, 20
    add_mod31   %%W, xmm4
    rot_mod31   xmm10, 21
    add_mod31   %%W, xmm10
    rot_mod31   xmm13, 17
    add_mod31   %%W, xmm13
    rot_mod31   xmm15, 15
    add_mod31   %%W, xmm15

%ifnum %%ROUND_NUM
    movdqa      [%%STATE + (( 0 + %%ROUND_NUM) % 16)*16], %%W
%else
    store_lfsr %%STATE, %%ROUND_NUM, 0, %%TMP, %%W
%endif
    ; LFSR_S16 = (LFSR_S15++) = eax
%endmacro

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
    movdqa APPEND(xmm,%%i), [%%STATE + 16*%%i]
%assign %%i (%%i+1)
%endrep

%assign %%i 0
%assign %%j %%NUM_ROUNDS
%rep 16
    movdqa [%%STATE + 16*%%i], APPEND(xmm,%%j)
%assign %%i (%%i+1)
%assign %%j ((%%j+1) % 16)
%endrep
%endif ;; %%NUM_ROUNDS != 16

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

    movdqa          %%LFSR, %%KEY
    movdqa          %%XTMP, %%IV
    pshufb          %%LFSR, %%SHUF_KEY
    psrld           %%LFSR, 1
    pshufb          %%XTMP, %%SHUF_IV
    por             %%LFSR, %%XTMP
    por             %%LFSR, %%EKD_MASK

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
%define %%TAG_SIZE  %9 ;; [in] Tag size (0, 4, 8 or 16 bytes)

%if %%TAG_SIZE == 0
%define %%CONSTANTS rel EK256_d64
%elif %%TAG_SIZE == 4
%define %%CONSTANTS rel EK256_EIA3_4
%endif
    ; s0 - s3
    pxor           %%LFSR0_3, %%LFSR0_3
    pinsrb         %%LFSR0_3, [%%KEY], 3      ; s0
    pinsrb         %%LFSR0_3, [%%KEY + 1], 7  ; s1
    pinsrb         %%LFSR0_3, [%%KEY + 2], 11 ; s2
    pinsrb         %%LFSR0_3, [%%KEY + 3], 15 ; s3

    psrld          %%LFSR0_3, 1

    por            %%LFSR0_3, [%%CONSTANTS] ; s0 - s3

    pinsrb         %%LFSR0_3, [%%KEY + 21], 1 ; s0
    pinsrb         %%LFSR0_3, [%%KEY + 16], 0 ; s0

    pinsrb         %%LFSR0_3, [%%KEY + 22], 5 ; s1
    pinsrb         %%LFSR0_3, [%%KEY + 17], 4 ; s1

    pinsrb         %%LFSR0_3, [%%KEY + 23], 9 ; s2
    pinsrb         %%LFSR0_3, [%%KEY + 18], 8 ; s2

    pinsrb         %%LFSR0_3, [%%KEY + 24], 13 ; s3
    pinsrb         %%LFSR0_3, [%%KEY + 19], 12 ; s3

    ; s4 - s7
    pxor           %%LFSR4_7, %%LFSR4_7
    pinsrb         %%LFSR4_7, [%%KEY + 4], 3   ; s4
    pinsrb         %%LFSR4_7, [%%IV], 7        ; s5
    pinsrb         %%LFSR4_7, [%%IV + 1], 11   ; s6
    pinsrb         %%LFSR4_7, [%%IV + 10], 15  ; s7

    psrld          %%LFSR4_7, 1

    pinsrb         %%LFSR4_7, [%%KEY + 25], 1 ; s4
    pinsrb         %%LFSR4_7, [%%KEY + 20], 0 ; s4

    pinsrb         %%LFSR4_7, [%%KEY + 5], 5 ; s5
    pinsrb         %%LFSR4_7, [%%KEY + 26], 4 ; s5

    pinsrb         %%LFSR4_7, [%%KEY + 6], 9 ; s6
    pinsrb         %%LFSR4_7, [%%KEY + 27], 8 ; s6

    pinsrb         %%LFSR4_7, [%%KEY + 7], 13 ; s7
    pinsrb         %%LFSR4_7, [%%IV + 2], 12 ; s7

    por            %%LFSR4_7, [%%CONSTANTS + 16] ; s4 - s7

    movd           %%XTMP, [%%IV + 17]
    pshufb         %%XTMP, [rel shuf_mask_iv_17_19]
    pand           %%XTMP, [rel clear_iv_mask]

    por            %%LFSR4_7, %%XTMP

    ; s8 - s11
    pxor           %%LFSR8_11, %%LFSR8_11
    pinsrb         %%LFSR8_11, [%%KEY + 8], 3   ; s8
    pinsrb         %%LFSR8_11, [%%KEY + 9], 7   ; s9
    pinsrb         %%LFSR8_11, [%%IV + 5], 11   ; s10
    pinsrb         %%LFSR8_11, [%%KEY + 11], 15 ; s11

    psrld          %%LFSR8_11, 1

    pinsrb         %%LFSR8_11, [%%IV + 3], 1 ; s8
    pinsrb         %%LFSR8_11, [%%IV + 11], 0 ; s8

    pinsrb         %%LFSR8_11, [%%IV + 12], 5 ; s9
    pinsrb         %%LFSR8_11, [%%IV + 4], 4 ; s9

    pinsrb         %%LFSR8_11, [%%KEY + 10], 9 ; s10
    pinsrb         %%LFSR8_11, [%%KEY + 28], 8 ; s10

    pinsrb         %%LFSR8_11, [%%IV + 6], 13 ; s11
    pinsrb         %%LFSR8_11, [%%IV + 13], 12 ; s11

    por            %%LFSR8_11, [%%CONSTANTS + 32] ; s8 - s11

    movd           %%XTMP, [%%IV + 20]
    pshufb         %%XTMP, [rel shuf_mask_iv_20_23]
    pand           %%XTMP, [rel clear_iv_mask]

    por            %%LFSR8_11, %%XTMP

    ; s12 - s15
    pxor           %%LFSR12_15, %%LFSR12_15
    pinsrb         %%LFSR12_15, [%%KEY + 12], 3   ; s12
    pinsrb         %%LFSR12_15, [%%KEY + 13], 7   ; s13
    pinsrb         %%LFSR12_15, [%%KEY + 14], 11  ; s14
    pinsrb         %%LFSR12_15, [%%KEY + 15], 15  ; s15

    psrld          %%LFSR12_15, 1

    pinsrb         %%LFSR12_15, [%%IV + 7], 1 ; s12
    pinsrb         %%LFSR12_15, [%%IV + 14], 0 ; s12

    pinsrb         %%LFSR12_15, [%%IV + 15], 5 ; s13
    pinsrb         %%LFSR12_15, [%%IV + 8], 4 ; s13

    pinsrb         %%LFSR12_15, [%%IV + 16], 9 ; s14
    pinsrb         %%LFSR12_15, [%%IV + 9], 8 ; s14

    pinsrb         %%LFSR12_15, [%%KEY + 30], 13 ; s15
    pinsrb         %%LFSR12_15, [%%KEY + 29], 12 ; s15

    por            %%LFSR12_15, [%%CONSTANTS + 48] ; s12 - s15

    movzx          DWORD(%%TMP), byte [%%IV + 24]
    and            DWORD(%%TMP), 0x0000003f
    shl            DWORD(%%TMP), 16
    movd           %%XTMP, DWORD(%%TMP)

    movzx          DWORD(%%TMP), byte [%%KEY + 31]
    shl            DWORD(%%TMP), 12
    and            DWORD(%%TMP), 0x000f0000 ; high nibble of K_31
    pinsrd         %%XTMP, DWORD(%%TMP), 2

    movzx          DWORD(%%TMP), byte [%%KEY + 31]
    shl            DWORD(%%TMP), 16
    and            DWORD(%%TMP), 0x000f0000 ; low nibble of K_31
    pinsrd         %%XTMP, DWORD(%%TMP), 3

    por            %%LFSR12_15, %%XTMP
%endmacro

%macro ZUC_INIT_4 2-3
%define %%KEY_SIZE %1 ; [constant] Key size (128 or 256)
%define %%TAG_SIZE %2 ; [in] Tag size (0 (for cipher), 4, 8 or 16)
%define %%TAGS     %3 ; [in] Array of temporary tags

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

    ; Zero out R1-R2 (only lower 128 bits)
    pxor    xmm0, xmm0
%assign I 0
%rep 2
    movdqa  [pState + OFS_R1 + I*16], xmm0
%assign I (I + 1)
%endrep

%if %%KEY_SIZE == 128

    ;; Load key and IVs
%assign off 0
%assign i 4
%assign j 8
%rep 4
    mov     r15,  [pKe + off]
    movdqu  APPEND(xmm,i), [r15]
    ; Read 16 bytes of IV
    movdqa  APPEND(xmm,j), [pIv + off*4]
%assign off (off + 8)
%assign i (i + 1)
%assign j (j + 1)
%endrep

    ;;; Initialize all LFSR registers in four steps:
    ;;; first, registers 0-3, then registers 4-7, 8-11, 12-15

%assign off 0
%rep 4
    ; Set read-only registers for shuffle masks for key, IV and Ek_d for 8 registers
    movdqa  xmm13, [rel shuf_mask_key + off]
    movdqa  xmm14, [rel shuf_mask_iv + off]
    movdqa  xmm15, [rel Ek_d + off]

    ; Set 4xLFSR registers for all packets
%assign idx 0
%assign i 4
%assign j 8
%rep 4
    INIT_LFSR_128 APPEND(xmm,i), APPEND(xmm,j), xmm13, xmm14, xmm15, APPEND(xmm, idx), xmm12
%assign idx (idx + 1)
%assign i (i + 1)
%assign j (j + 1)
%endrep

    ; Store 4xLFSR registers in memory (reordering first,
    ; so all SX registers are together)
    TRANSPOSE4_U32  xmm0, xmm1, xmm2, xmm3, xmm13, xmm14

%assign i 0
%rep 4
    movdqa  [pState + 4*off + 16*i], APPEND(xmm, i)
%assign i (i+1)
%endrep

%assign off (off + 16)
%endrep

%else ;; %%KEY_SIZE == 256
    ;;; Initialize all LFSR registers
%assign off 0
%rep 4
    ;; Load key and IV for each packet
    mov     r15,  [pKe + off]
    lea     r10, [pIv + off*4]

    ; Initialize S0-15 for each packet
    INIT_LFSR_256 r15, r10, xmm0, xmm1, xmm2, xmm3, xmm4, r11, %%TAG_SIZE

%assign i 0
%rep 4
    movdqa  [pState + 64*i + 2*off], APPEND(xmm, i)
%assign i (i+1)
%endrep

%assign off (off + 8)
%endrep

    ; Read, transpose and store, so all S_X from the 4 packets are in the same register
%assign off 0
%rep 4

%assign i 0
%rep 4
    movdqa  APPEND(xmm, i), [pState + 16*i + off]
%assign i (i+1)
%endrep

    TRANSPOSE4_U32 xmm0, xmm1, xmm2, xmm3, xmm14, xmm15

%assign i 0
%rep 4
    movdqa  [pState + 16*i + off], APPEND(xmm, i)
%assign i (i+1)
%endrep

%assign off (off + 64)
%endrep
%endif ;; %%KEY_SIZE == 256

    ; Load read-only registers
    movdqa  xmm12, [rel mask31]

    mov r15, 0
%%start_loop:
    cmp r15, 32
    je  %%exit_loop
    ; Shift LFSR 32-times, update state variables
    BITS_REORG4 rax, r15, r14, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, \
                xmm6, xmm7, xmm8, xmm9
    NONLIN_FUN4 rax, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
    psrld  xmm7,1                ; Shift out LSB of W
    lfsr_updt4  rax, r15, r14, xmm7     ; W (xmm7) used in LFSR update
    inc r15
    jmp %%start_loop

%%exit_loop:
    ; And once more, initial round from keygen phase = 33 times
    BITS_REORG4 rax, 0, no_reg, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, \
                xmm6, xmm7, xmm8, xmm9
    NONLIN_FUN4 rax, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6
    pxor    xmm0, xmm0
    lfsr_updt4 rax, 0, no_reg, xmm0

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

%if %%NUM_ROUNDS != 0
    mov         r10, rsp
    sub         rsp, (%%NUM_ROUNDS * 16)
    and         rsp, -16
%endif

%assign N 1
%rep %%NUM_ROUNDS
    BITS_REORG4 rax, N, no_reg, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, \
                xmm6, xmm7, xmm8, xmm9, xmm10
    NONLIN_FUN4 rax, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
    ; OFS_X3 XOR W (xmm7) and store in stack
    pxor        xmm10, xmm7
    movdqa [rsp + (N-1)*16], xmm10
    pxor        xmm0, xmm0
    lfsr_updt4  rax, N, no_reg, xmm0
%assign N N+1
%endrep

%if %%TAG_SIZE == 4
    movdqa      xmm0, [rsp]
    movdqa      [%%TAGS], xmm0
    REORDER_LFSR rax, 1
%elif %%TAG_SIZE == 8 ;;TODO
%elif %%TAG_SIZE == 16 ;;TODO
%endif

%if %%NUM_ROUNDS != 0
    mov         rsp, r10
%endif

    FUNC_RESTORE

    ret
%endmacro

MKGLOBAL(ZUC128_INIT_4,function,internal)
ZUC128_INIT_4:
        ZUC_INIT_4 128, 0

MKGLOBAL(ZUC256_INIT_4,function,internal)
ZUC256_INIT_4:

%define tags   arg4
%define tag_sz arg5

    cmp tag_sz, 0
    je  init_for_cipher

    ;; TODO: Check for 8B and 16B tags
    cmp tag_sz, 4
    je init_for_auth_tag_4B

init_for_cipher:
    ZUC_INIT_4 256, 0

init_for_auth_tag_4B:
    ZUC_INIT_4 256, 4, tags

;
; Generate N*4 bytes of keystream
; for 4 buffers (where N is number of rounds)
;
%macro KEYGEN_4_SSE 1
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
    mov         r10, rsp
    sub         rsp, (4*8 + %%NUM_ROUNDS * 16)
    and         rsp, -16

%assign i 0
%rep 2
    movdqa      xmm0, [pKS + 16*i]
    movdqa      [rsp + 16*i], xmm0
%assign i (i+1)
%endrep

    ; Load state pointer in RAX
    mov         rax, pState

    ; Load read-only registers
    movdqa      xmm12, [rel mask31]

    ; Generate N*4B of keystream in N rounds
%assign N 1
%rep %%NUM_ROUNDS
    BITS_REORG4 rax, N, no_reg, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, \
                xmm6, xmm7, xmm8, xmm9, xmm10
    NONLIN_FUN4 rax, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
    ; OFS_X3 XOR W (xmm7) and store in stack
    pxor        xmm10, xmm7
    movdqa [rsp + 4*8 + (N-1)*16], xmm10
    pxor        xmm0, xmm0
    lfsr_updt4  rax, N, no_reg, xmm0
%assign N N+1
%endrep

%if (%%NUM_ROUNDS == 4)
    ;; Load all OFS_X3
%assign i 0
%rep 4
    movdqa      APPEND(xmm,i), [rsp + 4*8 + i*16]
%assign i (i+1)
%endrep

    TRANSPOSE4_U32 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5

    store16B_kstr4 xmm0, xmm1, xmm2, xmm3
%else ;; NUM_ROUNDS != 4
%assign idx 0
%rep %%NUM_ROUNDS
    movdqa  APPEND(xmm, idx), [rsp + 4*8 + idx*16]
    store4B_kstr4 APPEND(xmm, idx)
%assign idx (idx + 1)
%endrep
%endif ;; NUM_ROUNDS == 4

        ;; Clear stack frame containing keystream information
%ifdef SAFE_DATA
    pxor    xmm0, xmm0
%assign i 0
%rep (2+%%NUM_ROUNDS)
    movdqa  [rsp + i*16], xmm0
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

;;
;; void asm_ZucGenKeystream16B_4_sse(state4_t *pSta, u32* pKeyStr[4]);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(ZUC_KEYGEN16B_4,function,internal)
ZUC_KEYGEN16B_4:

        KEYGEN_4_SSE 4

        ret

;;
;; void asm_ZucGenKeystream8B_4_sse(state4_t *pSta, u32* pKeyStr[4]);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(ZUC_KEYGEN8B_4,function,internal)
ZUC_KEYGEN8B_4:

        KEYGEN_4_SSE 2

        ret

;;
;; void asm_ZucGenKeystream4B_4_sse(state4_t *pSta, u32* pKeyStr[4]);
;;
;; WIN64
;;  RCX    - pSta
;;  RDX    - pKeyStr
;;
;; LIN64
;;  RDI    - pSta
;;  RSI    - pKeyStr
;;
MKGLOBAL(ZUC_KEYGEN4B_4,function,internal)
ZUC_KEYGEN4B_4:

        KEYGEN_4_SSE 1

        ret

;;
;; Encrypt N*4B bytes on all 4 buffers
;; where N is number of rounds (up to 4)
;; In final call, an array of final bytes is read
;; from memory and only these final bytes are of
;; plaintext are read and XOR'ed.
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
        ; Load read-only registers
        movdqa  xmm12, [rel mask31]

        ; Generate N*4B of keystream in N rounds
%assign %%N 1
%assign %%round (%%INITIAL_ROUND + %%N)
%rep %%NROUNDS
        BITS_REORG4 rax, %%round, no_reg, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, \
                    xmm6, xmm7, xmm8, xmm9, xmm10
        NONLIN_FUN4 rax, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
        ; OFS_XR XOR W (xmm7) and store in stack
        pxor    xmm10, xmm7
        movdqa  [rsp + _keystr_save + (%%N-1)*16], xmm10
        pxor    xmm0, xmm0
        lfsr_updt4  rax, %%round, no_reg, xmm0
%assign %%N (%%N + 1)
%assign %%round (%%round + 1)
%endrep

%assign %%N 0
%assign %%idx 4
%rep %%NROUNDS
        movdqa  APPEND(xmm, %%idx), [rsp + _keystr_save + %%N*16]
%assign %%N (%%N + 1)
%assign %%idx (%%idx+1)
%endrep

        TRANSPOSE4_U32 xmm4, xmm5, xmm6, xmm7, xmm8, xmm9

        movdqa  xmm15, [rel swap_mask]

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
        simd_load_sse_16_1 xmm0, r12 + %%OFFSET, r10
        movzx  r10d, word [rsp + _rem_bytes_save + 2]
        simd_load_sse_16_1 xmm1, r13 + %%OFFSET, r10
        movzx  r10d, word [rsp + _rem_bytes_save + 4]
        simd_load_sse_16_1 xmm2, r14 + %%OFFSET, r10
        movzx  r10d, word [rsp + _rem_bytes_save + 6]
        simd_load_sse_16_1 xmm3, r15 + %%OFFSET, r10
%else
        movdqu  xmm0, [r12 + %%OFFSET]
        movdqu  xmm1, [r13 + %%OFFSET]
        movdqu  xmm2, [r14 + %%OFFSET]
        movdqu  xmm3, [r15 + %%OFFSET]
%endif

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

%if (%%LAST_CALL == 1)
        movzx  r10d, word [rsp + _rem_bytes_save]
        simd_store_sse r12, xmm4, r10, %%TMP1, %%TMP2, %%OFFSET
        movzx  r10d, word [rsp + _rem_bytes_save + 2]
        simd_store_sse r13, xmm5, r10, %%TMP1, %%TMP2, %%OFFSET
        movzx  r10d, word [rsp + _rem_bytes_save + 4]
        simd_store_sse r14, xmm6, r10, %%TMP1, %%TMP2, %%OFFSET
        movzx  r10d, word [rsp + _rem_bytes_save + 6]
        simd_store_sse r15, xmm7, r10, %%TMP1, %%TMP2, %%OFFSET

        ; Restore registers
        mov     %%TMP1, [rsp + _gpr_save]
        mov     %%TMP2, [rsp + _gpr_save + 8]
%else
        movdqu  [r12 + %%OFFSET], xmm4
        movdqu  [r13 + %%OFFSET], xmm5
        movdqu  [r14 + %%OFFSET], xmm6
        movdqu  [r15 + %%OFFSET], xmm7
%endif
%endmacro

;;
;; void asm_ZucCipher_4_sse(state4_t *pSta, u64 *pIn[4],
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
MKGLOBAL(ZUC_CIPHER_4,function,internal)
ZUC_CIPHER_4:

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
        movd    xmm0, DWORD(min_length)
        pshufb  xmm0, [rel broadcast_word]
        movq    xmm1, [lengths]
        pcmpeqw xmm2, xmm2 ;; Get all ff's in XMM register
        movdqa  xmm3, xmm1
        pcmpeqw xmm3, xmm2 ;; Mask with FFFF in NULL jobs

        movdqa  xmm4, xmm3
        pand    xmm4, xmm0 ;; Length of valid job in all NULL jobs
        pxor    xmm2, xmm3 ;; Mask with 0000 in NULL jobs
        pand    xmm1, xmm2 ;; Zero out lengths of NULL jobs
        por     xmm1, xmm4 ;; XMM1 contain updated lengths

        ; Round up to nearest multiple of 4 bytes
        paddw   xmm0, [rel all_threes]
        pand    xmm0, [rel all_fffcs]

        ; Calculate remaining bytes to encrypt after function call
        movdqa  xmm2, xmm1
        psubw   xmm2, xmm0
        pxor    xmm3, xmm3
        movdqa  xmm4, xmm2
        pcmpgtw xmm4, xmm3 ;; Mask with FFFF in lengths > 0
        ; Set to zero the lengths of the lanes which are going to be completed (lengths < 0)
        pand    xmm2, xmm4
        movq    [lengths], xmm2 ; Update in memory the final updated lengths

        ; Calculate number of bytes to encrypt after rounds of 16 bytes (up to 15 bytes),
        ; for each lane, and store it in stack to be used in the last round
        psubw   xmm1, xmm2 ; Bytes to encrypt in all lanes
        pand    xmm1, [rel all_0fs] ; Number of final bytes (up to 15 bytes) for each lane
        movdqa  xmm2, xmm1
        pcmpeqw xmm2, xmm3 ;; Mask with FFFF in lengths == 0
        pand    xmm2, [rel all_10s] ;; 16 in positions where lengths was 0
        por     xmm1, xmm2          ;; Number of final bytes (up to 16 bytes) for each lane

        ; Allocate stack frame to store keystreams (16*4 bytes), number of final bytes (8 bytes),
        ; space for rsp (8 bytes) and 2 GP registers (16 bytes) that will be clobbered later
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16
        xor     buf_idx, buf_idx
        movq    [rsp + _rem_bytes_save], xmm1
        mov     [rsp + _rsp_save], rax

        ; Load state pointer in RAX
        mov     rax, pState

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
        REORDER_LFSR rax, I
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
        REORDER_LFSR rax, I
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
        REORDER_LFSR rax, I
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
        REORDER_LFSR rax, I
        jmp     exit_final_rounds
%assign I (I + 1)
%endrep

exit_final_rounds:
        ;; update in/out pointers
        movq           xmm0, buf_idx
        pshufd         xmm0, xmm0, 0x44
        movdqa         xmm1, xmm0
        movdqa         xmm2, xmm0
        paddq          xmm1, [pIn]
        paddq          xmm2, [pIn + 16]
        movdqa         [pIn], xmm1
        movdqa         [pIn + 16], xmm2
        movdqa         xmm1, xmm0
        movdqa         xmm2, xmm0
        paddq          xmm1, [pOut]
        paddq          xmm2, [pOut + 16]
        movdqa         [pOut], xmm1
        movdqa         [pOut + 16], xmm2

        ;; Clear stack frame containing keystream information
%ifdef SAFE_DATA
        pxor    xmm0, xmm0
%assign i 0
%rep 4
	movdqa  [rsp + _keystr_save + i*16], xmm0
%assign i (i+1)
%endrep
%endif
        ; Restore rsp
        mov     rsp, [rsp + _rsp_save]

        FUNC_RESTORE

exit_cipher:

        ret

%macro DIGEST_16_BYTES 9
%define %%KS      %1 ; [in] Pointer to keystream
%define %%XDATA   %2 ; [in] XMM register with input data
%define %%XDIGEST %3 ; [out] XMM register with result digest
%define %%XTMP1   %4 ; [clobbered] Temporary XMM register
%define %%XTMP2   %5 ; [clobbered] Temporary XMM register
%define %%XTMP3   %6 ; [clobbered] Temporary XMM register
%define %%XTMP4   %7 ; [clobbered] Temporary XMM register
%define %%KS_L    %8 ; [clobbered] Temporary XMM register
%define %%KS_H    %9 ; [clobbered] Temporary XMM register

        ; Reverse data bytes
%if USE_GFNI == 1
        movdqa  %%XTMP4, %%XDATA
        gf2p8affineqb   %%XTMP4, [rel bit_reverse_table], 0x00
%else
        movdqa  %%XTMP3, [rel bit_reverse_and_table]
        movdqa  %%XTMP2, %%XDATA
        pand    %%XTMP2, %%XTMP3

        pandn   %%XTMP3, %%XDATA
        psrld   %%XTMP3, 4

        movdqa  %%XTMP4, [rel bit_reverse_table_h] ; bit reverse low nibbles (use high table)
        pshufb  %%XTMP4, %%XTMP2

        movdqa  %%XTMP1, [rel bit_reverse_table_l] ; bit reverse high nibbles (use low table)
        pshufb  %%XTMP1, %%XTMP3

        por     %%XTMP4, %%XTMP1 ;; %%XTMP4 - bit reverse data bytes
%endif

        ;; ZUC authentication part
        ;; - 4x32 data bits
        ;; - set up KS
        movdqu  %%XTMP1, [%%KS + (0*4)]
        movdqu  %%XTMP2, [%%KS + (2*4)]
        pshufd  %%KS_L, %%XTMP1, 0x61
        pshufd  %%KS_H, %%XTMP2, 0x61

        ;;  - set up DATA
        movdqa  %%XTMP1, %%XTMP4
        pand    %%XTMP1, [rel data_mask_64bits]
        pshufd  %%XTMP2, %%XTMP1, 0xdc
        movdqa  %%XTMP1, %%XTMP2 ;; %%XTMP1/2 - Data bytes [31:0 0s 63:32 0s]

        psrldq  %%XTMP4, 8
        pshufd  %%XTMP3, %%XTMP4, 0xdc
        movdqa  %%XDIGEST, %%XTMP3 ;; %%XDIGEST/XTMP3 - Data bytes [95:64 0s 127:96 0s]

        ;; - clmul
        ;; - xor the results from 4 32-bit words together
        pclmulqdq %%XTMP1, %%KS_L, 0x00
        pclmulqdq %%XTMP2, %%KS_L, 0x11
        pclmulqdq %%XDIGEST, %%KS_H, 0x00
        pclmulqdq %%XTMP3, %%KS_H, 0x11

        pxor    %%XTMP2, %%XTMP1
        pxor    %%XDIGEST, %%XTMP3
        pxor    %%XDIGEST, %%XTMP2

%endmacro

%macro REMAINDER 18
%define %%T             %1  ; [in] Pointer to authentication tag
%define %%KS            %2  ; [in] Pointer to 32-byte keystream
%define %%DATA          %3  ; [in] Pointer to input data
%define %%N_BITS        %4  ; [in] Number of bits to digest
%define %%N_BYTES       %5  ; [clobbered] Number of bytes to digest
%define %%TMP1          %6  ; [clobbered] Temporary GP register
%define %%TMP2          %7  ; [clobbered] Temporary GP register
%define %%TMP3          %8  ; [clobbered] Temporary GP register
%define %%XTMP1         %9  ; [clobbered] Temporary XMM register
%define %%XTMP2         %10 ; [clobbered] Temporary XMM register
%define %%XTMP3         %11 ; [clobbered] Temporary XMM register
%define %%XTMP4         %12 ; [clobbered] Temporary XMM register
%define %%XTMP5         %13 ; [clobbered] Temporary XMM register
%define %%XTMP6         %14 ; [clobbered] Temporary XMM register
%define %%KS_L          %15 ; [clobbered] Temporary XMM register
%define %%KS_H          %16 ; [clobbered] Temporary XMM register
%define %%KEY_SZ        %17 ; [in] Key size (128 or 256)
%define %%TAG_SZ        %18 ; [in] Key size (4, 8 or 16)

%define %%N_BYTES %%TMP3

        FUNC_SAVE

        pxor    %%XTMP6, %%XTMP6

        or      %%N_BITS, %%N_BITS
        jz      %%Eia3RoundsSSE_end

        ; Get number of bytes
        mov     %%N_BYTES, %%N_BITS
        add     %%N_BYTES, 7
        shr     %%N_BYTES, 3

        ; read up to 16 bytes of data, zero bits not needed if partial byte and bit-reverse
        simd_load_sse_16_1 %%XTMP1, %%DATA, %%N_BYTES
        ; check if there is a partial byte (less than 8 bits in last byte)
        mov     %%TMP1, %%N_BITS
        and     %%TMP1, 0x7
        shl     %%TMP1, 4
        lea     %%TMP2, [rel bit_mask_table]
        add     %%TMP2, %%TMP1

        ; Get mask to clear last bits
        movdqa  %%XTMP2, [%%TMP2]

        ; Shift left 16-N bytes to have the last byte always at the end of the XMM register
        ; to apply mask, then restore by shifting right same amount of bytes
        mov     %%TMP2, 16
        sub     %%TMP2, %%N_BYTES
        XPSLLB  %%XTMP1, %%TMP2, %%XTMP3, %%TMP1
        pand    %%XTMP1, %%XTMP2
        XPSRLB  %%XTMP1, %%TMP2, %%XTMP3, %%TMP1

        DIGEST_16_BYTES %%KS, %%XTMP1, %%XTMP6, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%KS_L, %%KS_H

%%Eia3RoundsSSE_end:

%define %%TAG DWORD(%%TMP1)
        ;; - update T
        mov     %%TAG, [%%T]
        movq    %%TMP2, %%XTMP6
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

%if %%KEY_SZ == 128
        ;; XOR with keyStr[L-1]

        ; Read keyStr[L - 1] (last double word of keyStr)
        mov     %%TMP2, %%N_BITS
        add     %%TMP2, (31 + 64)
        shr     %%TMP2, 5 ; L
        dec     %%TMP2
        mov     DWORD(%%TMP3), [%%KS + %%TMP2 * 4]
        ; XOR with previous digest calculation
        xor     %%TAG, DWORD(%%TMP3)

%endif
        bswap   %%TAG
        mov     [%%T], %%TAG

        FUNC_RESTORE

%endmacro

;;
;; extern void asm_Eia3RemainderSSE(void *T, const void *ks,
;;                                  const void *data, const uint64_t n_bits,
;;                                  const uint64_t key_size,
;;                                  const uint64_t tag_size);
;;
;; Returns authentication update value to be XOR'ed with current authentication tag
;;
;;  @param [in] T (digest pointer)
;;  @param [in] KS (key stream pointer)
;;  @param [in] DATA (data pointer)
;;  @param [in] N_BITS (number of bits to digest)
;;  @param [in] KEY_SZ (Key size: 128 or 256 bits)
;;  @param [in] TAG_SZ (Tag size: 4, 8 or 16 bytes)
;;
align 16
MKGLOBAL(ZUC_EIA3REMAINDER,function,internal)
ZUC_EIA3REMAINDER:
%define T       arg1
%define KS      arg2
%define DATA    arg3
%define N_BITS  arg4
%define KEY_SZ  arg5
%define TAG_SZ  arg6

        cmp     KEY_SZ, 128
        je      remainder_key_sz_128

        ; Key size = 256
        ;; TODO: Handle tag sizes of 8 and 16 bytes
        REMAINDER T, KS, DATA, N_BITS, r12, r13, r14, r15, \
                  xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, 256, 4

        ret

remainder_key_sz_128:
        REMAINDER T, KS, DATA, N_BITS, r12, r13, r14, r15, \
                  xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, 128, 4

        ret

%macro ROUND 12
%define %%T             %1  ; [in] Pointer to authentication tag
%define %%KS            %2  ; [in] Pointer to 32-byte keystream
%define %%DATA          %3  ; [in] Pointer to input data
%define %%TMP           %4  ; [clobbered] Temporary GP register
%define %%XTMP1         %5  ; [clobbered] Temporary XMM register
%define %%XTMP2         %6  ; [clobbered] Temporary XMM register
%define %%XTMP3         %7  ; [clobbered] Temporary XMM register
%define %%XTMP4         %8  ; [clobbered] Temporary XMM register
%define %%XTMP5         %9  ; [clobbered] Temporary XMM register
%define %%XTMP6         %10 ; [clobbered] Temporary XMM register
%define %%KS_L          %11 ; [clobbered] Temporary XMM register
%define %%KS_H          %12 ; [clobbered] Temporary XMM register

        FUNC_SAVE

        ;; read 16 bytes and reverse bits
        movdqu  %%XTMP1, [%%DATA]
        DIGEST_16_BYTES %%KS, %%XTMP1, %%XTMP6, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%KS_L, %%KS_H

        ;; - update T
        movq    %%TMP, %%XTMP6
        shr     %%TMP, 32
        xor     [%%T], DWORD(%%TMP)

        ;; Copy last 16 bytes of KS to the front
        movdqa  %%XTMP1, [%%KS + 16]
        movdqa  [%%KS], %%XTMP1

        FUNC_RESTORE

%endmacro

;;
;;extern void asm_Eia3Round16BSSE(void *T, const void *KS, const void *DATA,
;;                                const uint64_t tag_sz)
;;
;; Updates authentication tag T based on keystream KS and DATA.
;; - it processes 16 bytes of DATA
;; - reads data in 16 byte chunks and bit reverses them
;; - reads and re-arranges KS
;; - employs clmul for the XOR & ROL part
;; - copies last 16 bytes of KS to top 16 bytes
;;
;;  @param [in] T (digest pointer)
;;  @param [in] KS (key stream pointer)
;;  @param [in] DATA (data pointer)
;;  @param [in] TAG_SZ (Tag size: 4, 8 or 16 bytes)
;;
align 16
MKGLOBAL(ZUC_EIA3ROUND16B,function,internal)
ZUC_EIA3ROUND16B:

%define	T       arg1
%define	KS      arg2
%define	DATA    arg3
%define TAG_SZ  arg4

        ;; TODO: Handle tag sizes of 8 and 16 bytes
        cmp     TAG_SZ, 4
        je      round_tag_4B

round_tag_4B:
        ROUND T, KS, DATA, rax, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7

        ret

;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

mksection stack-noexec
