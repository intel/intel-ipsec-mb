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
%include "include/const.inc"
%include "mb_mgr_datastruct.asm"

%define APPEND(a,b) a %+ b
%define APPEND3(a,b,c) a %+ b %+ c

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

align 64
bit_reverse_table_l:
db	0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e, 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07, 0x0f
db	0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e, 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07, 0x0f
db	0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e, 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07, 0x0f
db	0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e, 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07, 0x0f

align 64
bit_reverse_table_h:
db	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0
db	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0
db	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0
db	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0

align 64
bit_reverse_and_table:
db	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f
db	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f
db	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f
db	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f

align 64
data_mask_64bits:
dd	0xffffffff, 0xffffffff, 0x00000000, 0x00000000
dd	0xffffffff, 0xffffffff, 0x00000000, 0x00000000
dd	0xffffffff, 0xffffffff, 0x00000000, 0x00000000
dd	0xffffffff, 0xffffffff, 0x00000000, 0x00000000

align 64
shuf_mask_tags:
dd      0x01, 0x05, 0x09, 0x0D, 0x11, 0x15, 0x19, 0x1D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
dd      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x05, 0x09, 0x0D, 0x11, 0x15, 0x19, 0x1D

align 64
all_ffs:
dw      0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
dw      0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff

align 64
all_threes:
dw      0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003
dw      0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003

align 64
all_fffcs:
dw      0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc
dw      0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc, 0xfffc

align 64
all_3fs:
dw      0x003f, 0x003f, 0x003f, 0x003f, 0x003f, 0x003f, 0x003f, 0x003f
dw      0x003f, 0x003f, 0x003f, 0x003f, 0x003f, 0x003f, 0x003f, 0x003f

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

byte64_len_to_mask_table:
        dq      0x0000000000000000, 0x0000000000000001
        dq      0x0000000000000003, 0x0000000000000007
        dq      0x000000000000000f, 0x000000000000001f
        dq      0x000000000000003f, 0x000000000000007f
        dq      0x00000000000000ff, 0x00000000000001ff
        dq      0x00000000000003ff, 0x00000000000007ff
        dq      0x0000000000000fff, 0x0000000000001fff
        dq      0x0000000000003fff, 0x0000000000007fff
        dq      0x000000000000ffff, 0x000000000001ffff
        dq      0x000000000003ffff, 0x000000000007ffff
        dq      0x00000000000fffff, 0x00000000001fffff
        dq      0x00000000003fffff, 0x00000000007fffff
        dq      0x0000000000ffffff, 0x0000000001ffffff
        dq      0x0000000003ffffff, 0x0000000007ffffff
        dq      0x000000000fffffff, 0x000000001fffffff
        dq      0x000000003fffffff, 0x000000007fffffff
        dq      0x00000000ffffffff, 0x00000001ffffffff
        dq      0x00000003ffffffff, 0x00000007ffffffff
        dq      0x0000000fffffffff, 0x0000001fffffffff
        dq      0x0000003fffffffff, 0x0000007fffffffff
        dq      0x000000ffffffffff, 0x000001ffffffffff
        dq      0x000003ffffffffff, 0x000007ffffffffff
        dq      0x00000fffffffffff, 0x00001fffffffffff
        dq      0x00003fffffffffff, 0x00007fffffffffff
        dq      0x0000ffffffffffff, 0x0001ffffffffffff
        dq      0x0003ffffffffffff, 0x0007ffffffffffff
        dq      0x000fffffffffffff, 0x001fffffffffffff
        dq      0x003fffffffffffff, 0x007fffffffffffff
        dq      0x00ffffffffffffff, 0x01ffffffffffffff
        dq      0x03ffffffffffffff, 0x07ffffffffffffff
        dq      0x0fffffffffffffff, 0x1fffffffffffffff
        dq      0x3fffffffffffffff, 0x7fffffffffffffff
        dq      0xffffffffffffffff

align 64
add_64:
dq      64, 64, 64, 64, 64, 64, 64, 64

align 32
all_512w:
dw      512, 512, 512, 512, 512, 512, 512, 512
dw      512, 512, 512, 512, 512, 512, 512, 512

align 64
bswap_mask:
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db      0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db      0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c

align 64
all_31w:
dw      31, 31, 31, 31, 31, 31, 31, 31
dw      31, 31, 31, 31, 31, 31, 31, 31

align 64
all_ffe0w:
dw      0xffe0, 0xffe0, 0xffe0, 0xffe0, 0xffe0, 0xffe0, 0xffe0, 0xffe0
dw      0xffe0, 0xffe0, 0xffe0, 0xffe0, 0xffe0, 0xffe0, 0xffe0, 0xffe0

section .text
align 64

%ifdef LINUX
%define arg1 rdi
%define arg2 rsi
%define arg3 rdx
%else
%define arg1 rcx
%define arg2 rdx
%define arg3 r8
%endif

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

; This macro reorder the LFSR registers
; after N rounds (1 <= N <= 15), since the registers
; are shifted every round
;
; The macro clobbers ZMM0-15
;
%macro REORDER_LFSR 3
%define %%STATE      %1
%define %%NUM_ROUNDS %2
%define %%LANE_MASK  %3

%if %%NUM_ROUNDS != 16
%assign i 0
%rep 16
    vmovdqa32 APPEND(zmm,i){%%LANE_MASK}, [%%STATE + 64*i]
%assign i (i+1)
%endrep

%assign i 0
%assign j %%NUM_ROUNDS
%rep 16
    vmovdqa32 [%%STATE + 64*i]{%%LANE_MASK}, APPEND(zmm,j)
%assign i (i+1)
%assign j ((j+1) % 16)
%endrep
%endif ;; %%NUM_ROUNDS != 16

%endmacro


;
;   bits_reorg16()
;
%macro  bits_reorg16 7-8
%define %%STATE     %1 ; [in] ZUC state
%define %%ROUND_NUM %2 ; [in] Round number
%define %%LANE_MASK %3 ; [in] Mask register with lanes to update
%define %%MODE      %4 ; [in] Mode = init or working
%define %%X0    %5 ; [out] X0
%define %%X1    %6 ; [out] X1
%define %%X2    %7 ; [out] X2
%define %%X3    %8 ; [out] ZMM register containing X3 of all lanes

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
    vmovdqa64   zmm15, [%%STATE + ((15 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm14, [%%STATE + ((14 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm11, [%%STATE + ((11 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm9,  [%%STATE + (( 9 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm7,  [%%STATE + (( 7 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm5,  [%%STATE + (( 5 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm2,  [%%STATE + (( 2 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm0,  [%%STATE + (( 0 + %%ROUND_NUM) % 16)*64]

%ifidn %%MODE, init
    vpxorq      zmm1, zmm1
    vpslld      zmm15, 1
    vpblendmw   zmm3{k1}, zmm14, zmm1
    vpblendmw   %%X0{k1}, zmm3, zmm15

    vpslld      zmm11, 16
    vpsrld      zmm9, 15
    vporq       %%X1, zmm11, zmm9
    vpslld      zmm7, 16
    vpsrld      zmm5, 15
    vporq       %%X2, zmm7, zmm5
%else
    vpxorq      zmm1, zmm1
    vpslld      zmm15, 1
    vpblendmw   zmm3{k1},  zmm14, zmm1
    vpblendmw   zmm15{k1}, zmm3, zmm15

    vmovdqa32   [%%STATE + OFS_X0]{%%LANE_MASK}, zmm15   ; BRC_X0
    vpslld      zmm11, 16
    vpsrld      zmm9, 15
    vporq       zmm11, zmm9
    vmovdqa32   [%%STATE + OFS_X1]{%%LANE_MASK}, zmm11   ; BRC_X1
    vpslld      zmm7, 16
    vpsrld      zmm5, 15
    vporq       zmm7, zmm5
    vmovdqa32   [%%STATE + OFS_X2]{%%LANE_MASK}, zmm7    ; BRC_X2
%endif
%if (%0 == 8)
    vpslld      zmm2, 16
    vpsrld      zmm0, 15
    vporq       %%X3, zmm2, zmm0 ; Store BRC_X3 in ZMM register
%endif
%endmacro

;
;   nonlin_fun16()
;
;   return
;       W value, updates F_R1[] / F_R2[]
;
%macro nonlin_fun16  9-10
%define %%STATE     %1  ; [in] ZUC state
%define %%LANE_MASK %2  ; [in] Mask register with lanes to update
%define %%USE_GFNI  %3  ; [in] Use GFNI instructions
%define %%MODE      %4  ; [in] Mode = init or working
%define %%X0        %5  ; [out] X0
%define %%X1        %6  ; [out] X1
%define %%X2        %7  ; [out] X2
%define %%R1        %8  ; [out] R1
%define %%R2        %9  ; [out] R2
%define %%W         %10 ; [out] ZMM register to contain W for all lanes

%ifidn %%MODE, init
%if (%0 == 10)
    vpxorq      %%W, %%X0, %%R1
    vpaddd      %%W, %%R2    ; W = (BRC_X0 ^ F_R1) + F_R2
%endif

    vpaddd      zmm1, %%R1, %%X1    ; W1 = F_R1 + BRC_X1
    vpxorq      zmm2, %%R2, %%X2    ; W2 = F_R2 ^ BRC_X2
%else
%if (%0 == 10)
    vmovdqa64   %%W, [%%STATE + OFS_X0]
    vpxorq      %%W, [%%STATE + OFS_R1]
    vpaddd      %%W, [%%STATE + OFS_R2]    ; W = (BRC_X0 ^ F_R1) + F_R2
%endif

    vmovdqa64   zmm1, [%%STATE + OFS_R1]
    vmovdqa64   zmm2, [%%STATE + OFS_R2]
    vpaddd      zmm1, [%%STATE + OFS_X1]    ; W1 = F_R1 + BRC_X1
    vpxorq      zmm2, [%%STATE + OFS_X2]    ; W2 = F_R2 ^ BRC_X2
%endif

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

%ifidn %%MODE, init
    vpshufb     %%R1, zmm1, [rel rev_S0_S1_shuf]
    vpshufb     %%R2, zmm2, [rel rev_S1_S0_shuf]
%else
    vpshufb     zmm1, [rel rev_S0_S1_shuf]
    vpshufb     zmm2, [rel rev_S1_S0_shuf]

    vmovdqa32   [%%STATE + OFS_R1]{%%LANE_MASK}, zmm1
    vmovdqa32   [%%STATE + OFS_R2]{%%LANE_MASK}, zmm2
%endif
%endmacro

;
;   store_kstr16()
;
%macro  store_kstr16 21
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
%define %%TMP0        %17 ; [clobbered] Temporary GP register
%define %%TMP1        %18 ; [clobbered] Temporary GP register
%define %%TMP2        %19 ; [clobbered] Temporary GP register
%define %%TMP3        %20 ; [clobbered] Temporary GP register
%define %%KMASK       %21 ; [in] K mask containing which dwords will be stored

    mov         %%TMP0,   [pKS]
    mov         %%TMP1,   [pKS + 8]
    mov         %%TMP2,   [pKS + 16]
    mov         %%TMP3,   [pKS + 24]
    vmovdqu32   [%%TMP0]{%%KMASK}, %%DATA64B_L0
    vmovdqu32   [%%TMP1]{%%KMASK},  %%DATA64B_L1
    vmovdqu32   [%%TMP2]{%%KMASK}, %%DATA64B_L2
    vmovdqu32   [%%TMP3]{%%KMASK}, %%DATA64B_L3

    mov         %%TMP0,   [pKS + 32]
    mov         %%TMP1,    [pKS + 40]
    mov         %%TMP2,   [pKS + 48]
    mov         %%TMP3,   [pKS + 56]
    vmovdqu32   [%%TMP0]{%%KMASK}, %%DATA64B_L4
    vmovdqu32   [%%TMP1]{%%KMASK},  %%DATA64B_L5
    vmovdqu32   [%%TMP2]{%%KMASK}, %%DATA64B_L6
    vmovdqu32   [%%TMP3]{%%KMASK}, %%DATA64B_L7

    mov         %%TMP0,   [pKS + 64]
    mov         %%TMP1,    [pKS + 72]
    mov         %%TMP2,   [pKS + 80]
    mov         %%TMP3,   [pKS + 88]
    vmovdqu32   [%%TMP0]{%%KMASK}, %%DATA64B_L8
    vmovdqu32   [%%TMP1]{%%KMASK},  %%DATA64B_L9
    vmovdqu32   [%%TMP2]{%%KMASK}, %%DATA64B_L10
    vmovdqu32   [%%TMP3]{%%KMASK}, %%DATA64B_L11

    mov         %%TMP0,   [pKS + 96]
    mov         %%TMP1,    [pKS + 104]
    mov         %%TMP2,   [pKS + 112]
    mov         %%TMP3,   [pKS + 120]
    vmovdqu32   [%%TMP0]{%%KMASK}, %%DATA64B_L12
    vmovdqu32   [%%TMP1]{%%KMASK},  %%DATA64B_L13
    vmovdqu32   [%%TMP2]{%%KMASK}, %%DATA64B_L14
    vmovdqu32   [%%TMP3]{%%KMASK}, %%DATA64B_L15

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
%macro  lfsr_updt16  4
%define %%STATE     %1 ; [in] ZUC state
%define %%ROUND_NUM %2 ; [in] Round number
%define %%LANE_MASK %3 ; [in] Mask register with lanes to update
%define %%W         %4 ; [out] ZMM register to contain W for all lanes
    ;
    ; zmm1  = LFSR_S0
    ; zmm4  = LFSR_S4
    ; zmm10 = LFSR_S10
    ; zmm13 = LFSR_S13
    ; zmm15 = LFSR_S15
    ;
    vmovdqa64   zmm1,  [%%STATE + (( 0 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm4,  [%%STATE + (( 4 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm10, [%%STATE + ((10 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm13, [%%STATE + ((13 + %%ROUND_NUM) % 16)*64]
    vmovdqa64   zmm15, [%%STATE + ((15 + %%ROUND_NUM) % 16)*64]

    ; Calculate LFSR feedback
    add_mod31   %%W, zmm1
    rot_mod31   zmm1, 8
    add_mod31   %%W, zmm1
    rot_mod31   zmm4, 20
    add_mod31   %%W, zmm4
    rot_mod31   zmm10, 21
    add_mod31   %%W, zmm10
    rot_mod31   zmm13, 17
    add_mod31   %%W, zmm13
    rot_mod31   zmm15, 15
    add_mod31   %%W, zmm15

    vmovdqa32   [%%STATE + (( 0 + %%ROUND_NUM) % 16)*64]{%%LANE_MASK}, %%W

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
	%define		pKe	  rdi
	%define		pIv	  rsi
	%define		pState	  rdx
        %define         lane_mask ecx
%else
	%define		pKe	  rcx
	%define		pIv	  rdx
	%define		pState	  r8
        %define         lane_mask r9d
%endif

%define         %%X0    zmm16
%define         %%X1    zmm17
%define         %%X2    zmm18
%define         %%W     zmm19
%define         %%R1    zmm20
%define         %%R2    zmm21

    FUNC_SAVE

    mov rax, pState

    kmovw   k2, lane_mask

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
    vmovdqa32 [pState + 64*i]{k2}, APPEND(zmm, j)
%assign i (i+1)
%assign j (j+2)
%endrep

    ; Load read-only registers
    vmovdqa64  zmm12, [rel mask31]
    mov        edx, 0xAAAAAAAA
    kmovd      k1, edx

    ; Zero out R1, R2
    vpxorq %%R1, %%R1
    vpxorq %%R2, %%R2

    ; Shift LFSR 32-times, update state variables
%assign N 0
%rep 32
    bits_reorg16 rax, N, k2, init, %%X0, %%X1, %%X2
    nonlin_fun16 rax, k2, %%USE_GFNI, init, %%X0, %%X1, %%X2, %%R1, %%R2, %%W
    vpsrld  %%W,1         ; Shift out LSB of W

    lfsr_updt16  rax, N, k2, %%W  ; W used in LFSR update - not set to zero
%assign N N+1
%endrep

    ; And once more, initial round from keygen phase = 33 times
    bits_reorg16 rax, 0, k2, init, %%X0, %%X1, %%X2
    nonlin_fun16 rax, k2, %%USE_GFNI, init, %%X0, %%X1, %%X2, %%R1, %%R2

    vpxorq    %%W, %%W
    lfsr_updt16  rax, 0, k2, %%W  ; W used in LFSR update - set to zero

    ; Update R1, R2
    vmovdqa32   [rax + OFS_R1]{k2}, %%R1
    vmovdqa32   [rax + OFS_R2]{k2}, %%R2
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
%macro KEYGEN_16_AVX512 2-3
%define %%NUM_ROUNDS    %1 ; [in] Number of 4-byte rounds
%define %%USE_GFNI      %2 ; [in] If 1, then GFNI instructions may be used
%define %%LANE_MASK     %3 ; [in] Lane mask with lanes to generate keystream

    %define	pState	  arg1
    %define     pKS	  arg2
    %define     numRounds arg3

%ifnum %%NUM_ROUNDS
%define %%MAX_ROUNDS %%NUM_ROUNDS
%else
%define %%MAX_ROUNDS 16
%endif
    FUNC_SAVE

    ; Load state pointer in RAX
    mov         rax, pState

    ; Load read-only registers
    vmovdqa64   zmm12, [rel mask31]
    mov         r10d, 0xAAAAAAAA
    kmovd       k1, r10d

%if (%0 == 3)
    kmovd       k2, DWORD(%%LANE_MASK)
%else
    mov         r10d, 0x0000FFFF
    kmovd       k2, r10d
%endif

    ; Generate N*4B of keystream in N rounds
%ifnnum %%NUM_ROUNDS
        mov r10, numRounds
%endif
%assign N 1
%assign idx 16
%rep %%MAX_ROUNDS
    bits_reorg16 rax, N, k2, working, none, none, none, APPEND(zmm, idx)
    nonlin_fun16 rax, k2, %%USE_GFNI, working, none, none, none, none, none, zmm0
    ; OFS_X3 XOR W (zmm0)
    vpxorq      APPEND(zmm, idx), zmm0
    vpxorq      zmm0, zmm0
    lfsr_updt16  rax, N, k2, zmm0  ; W (zmm0) used in LFSR update - not set to zero
%ifnnum %%NUM_ROUNDS
    dec r10
    jz  %%exit_loop
%endif
%assign N N+1
%assign idx (idx + 1)
%endrep

%%exit_loop:
%ifnum %%NUM_ROUNDS
    mov         r12d, ((1 << %%NUM_ROUNDS) - 1)
%else
    lea         r13, [rel byte64_len_to_mask_table]
    mov         r12, [r13 + numRounds*8]
%endif
    kmovd       k1, r12d
    ; ZMM16-31 contain the keystreams for each round
    ; Perform a 32-bit 16x16 transpose to have up to 64 bytes
    ; (NUM_ROUNDS * 4B) of each lane in a different register
    TRANSPOSE16_U32 zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                    zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31, \
                    zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, \
                    zmm8, zmm9, zmm10, zmm11, zmm12, zmm13

    store_kstr16 zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                 zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31, \
                 rbx, r9, r10, r11, k1

    ; Reorder LFSR registers
%ifnum %%NUM_ROUNDS
    REORDER_LFSR rax, %%NUM_ROUNDS, k2
%else
    cmp     numRounds, 16
    je      %%_skip_reorder

    cmp     numRounds, 8
    je      %%_num_rounds_is_8
    jb      %%_rounds_is_1_7

    ; Final blocks 9-16
    cmp     numRounds, 12
    je      %%_num_rounds_is_12
    jb      %%_rounds_is_9_11

    ; Final blocks 13-15
    cmp     numRounds, 14
    je      %%_num_rounds_is_14
    ja      %%_num_rounds_is_15
    jb      %%_num_rounds_is_13

%%_rounds_is_9_11:
    cmp     numRounds, 10
    je      %%_num_rounds_is_10
    ja      %%_num_rounds_is_11
    jb      %%_num_rounds_is_9

%%_rounds_is_1_7:
    cmp     numRounds, 4
    je      %%_num_rounds_is_4
    jb      %%_rounds_is_1_3

    ; Final blocks 5-7
    cmp     numRounds, 6
    je      %%_num_rounds_is_6
    ja      %%_num_rounds_is_7
    jb      %%_num_rounds_is_5

%%_rounds_is_1_3:
    cmp     numRounds, 2
    je      %%_num_rounds_is_2
    ja      %%_num_rounds_is_3

    ; Rounds = 1 if fall-through
%assign I 1
%rep 15
APPEND(%%_num_rounds_is_,I):
    REORDER_LFSR rax, I, k2
    jmp     %%_skip_reorder
%assign I (I + 1)
%endrep

%%_skip_reorder:
%endif
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
;; void asm_ZucGenKeystream8B_16_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                      const u32 lane_mask)
;;
MKGLOBAL(asm_ZucGenKeystream8B_16_avx512,function,internal)
asm_ZucGenKeystream8B_16_avx512:

    KEYGEN_16_AVX512 2, 0, arg3

    ret

;;
;; void asm_ZucGenKeystream64B_16_gfni_avx512(state16_t *pSta, u32* pKeyStr[16])
;;
MKGLOBAL(asm_ZucGenKeystream64B_16_gfni_avx512,function,internal)
asm_ZucGenKeystream64B_16_gfni_avx512:

    KEYGEN_16_AVX512 16, 1

    ret

;;
;; void asm_ZucGenKeystream8B_16_gfni_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                           const u32 lane_mask)
;;
MKGLOBAL(asm_ZucGenKeystream8B_16_gfni_avx512,function,internal)
asm_ZucGenKeystream8B_16_gfni_avx512:

    KEYGEN_16_AVX512 2, 1, arg3

    ret

;;
;; void asm_ZucGenKeystream_16_avx512(state16_t *pSta, u32* pKeyStr[16], u64 numRounds)
;;
MKGLOBAL(asm_ZucGenKeystream_16_avx512,function,internal)
asm_ZucGenKeystream_16_avx512:

    KEYGEN_16_AVX512 arg3, 0

    ret

;;
;; void asm_ZucGenKeystream_16_gfni_avx512(state16_t *pSta, u32* pKeyStr[16], u64 numRounds)
;;
MKGLOBAL(asm_ZucGenKeystream_16_gfni_avx512,function,internal)
asm_ZucGenKeystream_16_gfni_avx512:

    KEYGEN_16_AVX512 arg3, 1

    ret

%macro CIPHER64B 6
%define %%NROUNDS    %1
%define %%BYTE_MASK  %2
%define %%LANE_MASK  %3
%define %%USE_GFNI   %4
%define %%OFFSET     %5
%define %%LAST_ROUND %6

        ; Generate N*4B of keystream in N rounds
%assign N 1
%assign idx 16
%rep %%NROUNDS
        bits_reorg16 rax, N, %%LANE_MASK, working, none, none, none, APPEND(zmm, idx)
        nonlin_fun16 rax, %%LANE_MASK, %%USE_GFNI, working, none, none, none, none, none, zmm0
        ; OFS_X3 XOR W (zmm0)
        vpxorq  APPEND(zmm, idx), zmm0
        vpxorq   zmm0, zmm0
        lfsr_updt16  rax, N, %%LANE_MASK, zmm0  ; W (zmm0) used in LFSR update - not set to zero
%assign N (N + 1)
%assign idx (idx + 1)
%endrep

        ;; Shuffle all 16 keystreams in registers zmm16-31
%assign i 16
%rep %%NROUNDS
        vpshufb zmm %+i, [rel swap_mask]
%assign i (i+1)
%endrep
        ; ZMM16-31 contain the keystreams for each round
        ; Perform a 32-bit 16x16 transpose to have the 64 bytes
        ; of each lane in a different register
        TRANSPOSE16_U32 zmm16, zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, \
                        zmm24, zmm25, zmm26, zmm27, zmm28, zmm29, zmm30, zmm31, \
                        zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, \
                        zmm8, zmm9, zmm10, zmm11, zmm12, zmm13

        ;; XOR Input buffer with keystream
%if %%LAST_ROUND == 1
        lea     rbx, [rel byte64_len_to_mask_table]
%endif
        ;; Read all 16 streams using registers r12-15 into registers zmm0-15
%assign i 0
%assign j 0
%assign k 12
%rep 16
%if %%LAST_ROUND == 1
        ;; Read number of bytes left to encrypt for the lane stored in stack
        ;; and construct byte mask to read from input pointer
        movzx   r12d, word [rsp + j*2]
        kmovq   %%BYTE_MASK, [rbx + r12*8]
%endif
        mov     APPEND(r, k), [pIn + i]
        vmovdqu8 APPEND(zmm, j){%%BYTE_MASK}{z}, [APPEND(r, k) + %%OFFSET]
%assign k 12 + ((j + 1) % 4)
%assign j (j + 1)
%assign i (i + 8)
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
%if %%LAST_ROUND == 1
        ;; Read length to encrypt for the lane stored in stack
        ;; and construct byte mask to write to output pointer
        movzx   r12d, word [rsp + (j-16)*2]
        kmovq   %%BYTE_MASK, [rbx + r12*8]
%endif
        mov     APPEND(r, k), [pOut + i]
        vmovdqu8 [APPEND(r, k) + %%OFFSET]{%%BYTE_MASK}, APPEND(zmm, j)
%assign k 12 + ((j + 1) % 4)
%assign j (j + 1)
%assign i (i + 8)
%endrep

%endmacro

%macro CIPHER_16_AVX512 1
%define %%USE_GFNI      %1 ; [in] If 1, then GFNI instructions may be used

%ifdef LINUX
        %define         pState  rdi
        %define         pIn     rsi
        %define         pOut    rdx
        %define         lengths rcx
        %define         arg5    r8
%else
        %define         pState  rcx
        %define         pIn     rdx
        %define         pOut    r8
        %define         lengths r9
        %define         arg5    [rsp + 40]
%endif

%define min_length r10
%define buf_idx    r11

        mov     min_length, arg5

        FUNC_SAVE

        ; Convert all lengths set to UINT16_MAX (indicating that lane is not valid) to min length
        vpbroadcastw ymm0, min_length
        vmovdqa ymm1, [lengths]
        vpcmpw k1, ymm1, [rel all_ffs], 0
        vmovdqu16 ymm1{k1}, ymm0 ; YMM1 contain updated lengths

        ; Round up to nearest multiple of 4 bytes
        vpaddw  ymm0, [rel all_threes]
        vpandq  ymm0, [rel all_fffcs]

        ; Calculate remaining bytes to encrypt after function call
        vpsubw  ymm2, ymm1, ymm0
        vpxorq  ymm3, ymm3
        vpcmpw  k1, ymm2, ymm3, 1 ; Get mask of lengths < 0
        ; Set to zero the lengths of the lanes which are going to be completed
        vmovdqu16 ymm2{k1}, ymm3 ; YMM2 contain final lengths
        vmovdqa [lengths], ymm2 ; Update in memory the final updated lengths

        ; Calculate number of bytes to encrypt after round of 64 bytes (up to 63 bytes),
        ; for each lane, and store it in stack to be used in the last round
        vpsubw  ymm1, ymm2 ; Bytes to encrypt in all lanes
        vpandq  ymm1, [rel all_3fs] ; Number of final bytes (up to 63 bytes) for each lane
        sub     rsp, 32
        vmovdqu [rsp], ymm1

        ; Load state pointer in RAX
        mov     rax, pState

        ; Load read-only registers
        mov     r12d, 0xAAAAAAAA
        kmovd   k1, r12d
        mov     r12, 0xFFFFFFFFFFFFFFFF
        kmovq   k2, r12
        mov     r12d, 0x0000FFFF
        kmovd   k3, r12d

        xor     buf_idx, buf_idx

        ;; Perform rounds of 64 bytes, where LFSR reordering is not needed
%%loop:
        cmp     min_length, 64
        jl      %%exit_loop

        vmovdqa64 zmm12, [rel mask31]

        CIPHER64B 16, k2, k3, %%USE_GFNI, buf_idx, 0

        sub     min_length, 64
        add     buf_idx, 64
        jmp     %%loop

%%exit_loop:

        mov     r15, min_length
        add     r15, 3
        shr     r15, 2 ;; numbers of rounds left (round up length to nearest multiple of 4B)
        jz      %%_no_final_rounds

        vmovdqa64 zmm12, [rel mask31]

        cmp     r15, 8
        je      %%_num_final_rounds_is_8
        jl      %%_final_rounds_is_1_7

        ; Final blocks 9-16
        cmp     r15, 12
        je      %%_num_final_rounds_is_12
        jl      %%_final_rounds_is_9_11

        ; Final blocks 13-16
        cmp     r15, 16
        je      %%_num_final_rounds_is_16
        cmp     r15, 15
        je      %%_num_final_rounds_is_15
        cmp     r15, 14
        je      %%_num_final_rounds_is_14
        cmp     r15, 13
        je      %%_num_final_rounds_is_13

%%_final_rounds_is_9_11:
        cmp     r15, 11
        je      %%_num_final_rounds_is_11
        cmp     r15, 10
        je      %%_num_final_rounds_is_10
        cmp     r15, 9
        je      %%_num_final_rounds_is_9

%%_final_rounds_is_1_7:
        cmp     r15, 4
        je      %%_num_final_rounds_is_4
        jl      %%_final_rounds_is_1_3

        ; Final blocks 5-7
        cmp     r15, 7
        je      %%_num_final_rounds_is_7
        cmp     r15, 6
        je      %%_num_final_rounds_is_6
        cmp     r15, 5
        je      %%_num_final_rounds_is_5

%%_final_rounds_is_1_3:
        cmp     r15, 3
        je      %%_num_final_rounds_is_3
        cmp     r15, 2
        je      %%_num_final_rounds_is_2

        jmp     %%_num_final_rounds_is_1

        ; Perform encryption of last bytes (<= 64 bytes) and reorder LFSR registers
        ; if needed (if not all 16 rounds of 4 bytes are done)
%assign I 1
%rep 16
APPEND(%%_num_final_rounds_is_,I):
        CIPHER64B I, k2, k3, %%USE_GFNI, buf_idx, 1
        REORDER_LFSR rax, I, k3
        add     buf_idx, min_length
        jmp     %%_no_final_rounds
%assign I (I + 1)
%endrep

%%_no_final_rounds:
        add             rsp, 32
        ;; update in/out pointers
        add             buf_idx, 3
        and             buf_idx, 0xfc
        vpbroadcastq    zmm0, buf_idx
        vpaddq          zmm1, zmm0, [pIn]
        vpaddq          zmm2, zmm0, [pIn + 64]
        vmovdqa64       [pIn], zmm1
        vmovdqa64       [pIn + 64], zmm2
        vpaddq          zmm1, zmm0, [pOut]
        vpaddq          zmm2, zmm0, [pOut + 64]
        vmovdqa64       [pOut], zmm1
        vmovdqa64       [pOut + 64], zmm2

        FUNC_RESTORE

%endmacro

;;
;; void asm_ZucCipher_16_avx512(state16_t *pSta, u64 *pIn[16],
;;                              u64 *pOut[16], u16 lengths[16],
;;                              u64 min_length);
MKGLOBAL(asm_ZucCipher_16_avx512,function,internal)
asm_ZucCipher_16_avx512:

        CIPHER_16_AVX512 0

        ret

;;
;; void asm_ZucCipher_16_gfni_avx512(state16_t *pSta, u64 *pIn[16],
;;                                   u64 *pOut[16], u16 lengths[16],
;;                                   u64 min_length);
MKGLOBAL(asm_ZucCipher_16_gfni_avx512,function,internal)
asm_ZucCipher_16_gfni_avx512:

        CIPHER_16_AVX512 1

        ret

;;
;;extern void asm_Eia3Round64B_16_VPCLMUL(uint32_t *T, const void **KS, const void **DATA,
;;                                        uint16_t *LEN)
;;
;; Updates authentication tag T of 16 buffers based on keystream KS and DATA.
;; - it processes 64 bytes of DATA
;; - reads data in 16 byte chunks and bit reverses them
;; - reads and re-arranges KS
;; - employs clmul for the XOR & ROL part
;; - copies top 64 bytes of KS to bottom (for the next round)
;; - Updates Data pointers for next rounds
;; - Updates array of lengths
;;
;; WIN64
;;	RCX - T: Array of digests for all 16 buffers
;;	RDX - KS: Array of pointers to key stream (2 x 64 bytes) for all 16 buffers
;;      R8  - DATA: Array of pointers to data for all 16 buffers
;;      R9  - LEN: Array of lengths for all 16 buffers
;; LIN64
;;	RDI - T: Array of digests for all 16 buffers
;;	RSI - KS: Array of pointers to key stream (2 x 64 bytes) for all 16 buffers
;;      RDX - DATA: Array of pointers to data for all 16 buffers
;;      RCX - LEN: Array of lengths for all 16 buffers
;;
align 64
MKGLOBAL(asm_Eia3Round64B_16_VPCLMUL,function,internal)
asm_Eia3Round64B_16_VPCLMUL:

%ifdef LINUX
	%define		T	rdi
	%define		KS	rsi
	%define		DATA	rdx
	%define		LEN	rcx
%else
	%define		T	rcx
	%define		KS	rdx
	%define		DATA	r8
	%define		LEN	r9
%endif

%define         DATA_ADDR0      rbx
%define         DATA_ADDR1      r10
%define         DATA_ADDR2      r11
%define         DATA_ADDR3      r12
%define         KS_ADDR0        r13
%define         KS_ADDR1        r14
%define         KS_ADDR2        r15
%define         KS_ADDR3        rax

%define         DATA_TRANS0     zmm16
%define         DATA_TRANS1     zmm17
%define         DATA_TRANS2     zmm18
%define         DATA_TRANS3     zmm19

%define         KS_TRANS0       zmm20
%define         KS_TRANS1       zmm21
%define         KS_TRANS2       zmm22
%define         KS_TRANS3       zmm23

%define         DIGEST_0        zmm28
%define         DIGEST_1        zmm29
%define         DIGEST_2        zmm30
%define         DIGEST_3        zmm31

        FUNC_SAVE

        vmovdqa64       zmm5,  [rel bit_reverse_table_l]
        vmovdqa64       zmm6,  [rel bit_reverse_table_h]
        vmovdqa64       zmm7,  [rel bit_reverse_and_table]
        vmovdqa64       zmm10, [rel data_mask_64bits]


%assign IDX 0
%rep 4
        vpxorq          APPEND(DIGEST_, IDX), APPEND(DIGEST_, IDX)

        mov             DATA_ADDR0, [DATA + IDX*32 + 0*8]
        mov             DATA_ADDR1, [DATA + IDX*32 + 1*8]
        mov             DATA_ADDR2, [DATA + IDX*32 + 2*8]
        mov             DATA_ADDR3, [DATA + IDX*32 + 3*8]

        TRANSPOSE4_U128 DATA_ADDR0, DATA_ADDR1, DATA_ADDR2, DATA_ADDR3, \
                        DATA_TRANS0, DATA_TRANS1, DATA_TRANS2, DATA_TRANS3, \
                        zmm24, zmm25, zmm26, zmm27

        mov             KS_ADDR0,   [KS + IDX*32 + 0*8]
        mov             KS_ADDR1,   [KS + IDX*32 + 1*8]
        mov             KS_ADDR2,   [KS + IDX*32 + 2*8]
        mov             KS_ADDR3,   [KS + IDX*32 + 3*8]

        TRANSPOSE4_U128 KS_ADDR0, KS_ADDR1, KS_ADDR2, KS_ADDR3, \
                        KS_TRANS0, KS_TRANS1, KS_TRANS2, KS_TRANS3, \
                        zmm24, zmm25, zmm26, zmm27
%assign I 0
%assign J 1
%rep 4
        ;; Reverse bits of next 16 bytes from all 4 buffers
        vpandq          zmm1, APPEND(DATA_TRANS,I), zmm7

        vpandnq         zmm2, zmm7, APPEND(DATA_TRANS, I)
        vpsrld          zmm2, 4

        vpshufb         zmm8, zmm6, zmm1       ; bit reverse low nibbles (use high table)
        vpshufb         zmm4, zmm5, zmm2       ; bit reverse high nibbles (use low table)

        vporq           zmm8, zmm4
        ; zmm8 - bit reversed data bytes

        ;; ZUC authentication part
        ;; - 4x32 data bits
        ;; - set up KS
        vmovdqa64       zmm11, APPEND(KS_TRANS, I)
%if I != 3
        vmovdqa64       zmm12, APPEND(KS_TRANS, J)
%else
        ; Bytes 64-79 from the keystreams that were not loaded yet
        vmovdqu         xmm12, [KS_ADDR0 + 64]
        vinserti32x4    zmm12, [KS_ADDR1 + 64], 1
        vinserti32x4    zmm12, [KS_ADDR2 + 64], 2
        vinserti32x4    zmm12, [KS_ADDR3 + 64], 3
%endif
        vpalignr        zmm13, zmm12, zmm11, 8
        vpshufd         zmm2, zmm11, 0x61
        vpshufd         zmm3, zmm13, 0x61

        ;;  - set up DATA
        vpandq          zmm13, zmm10, zmm8
        vpshufd         APPEND(DATA_TRANS, I), zmm13, 0xdc

        vpsrldq         zmm8, 8
        vpshufd         zmm1, zmm8, 0xdc

        ;; - clmul
        ;; - xor the results from 4 32-bit words together
        vpclmulqdq      zmm13, APPEND(DATA_TRANS, I), zmm2, 0x00
        vpclmulqdq      zmm14, APPEND(DATA_TRANS, I), zmm2, 0x11
        vpclmulqdq      zmm15, zmm1, zmm3, 0x00
        vpclmulqdq      zmm8,  zmm1, zmm3, 0x11

        vpternlogq      zmm13, zmm14, zmm8, 0x96
        vpternlogq      APPEND(DIGEST_, IDX), zmm13, zmm15, 0x96

%assign J (J + 1)
%assign I (I + 1)
%endrep

        ; Memcpy KS 64-127 bytes to 0-63 bytes
        vmovdqu64       zmm0, [KS_ADDR0 + 64]
        vmovdqu64       zmm1, [KS_ADDR1 + 64]
        vmovdqu64       zmm2, [KS_ADDR2 + 64]
        vmovdqu64       zmm3, [KS_ADDR3 + 64]
        vmovdqu64       [KS_ADDR0], zmm0
        vmovdqu64       [KS_ADDR1], zmm1
        vmovdqu64       [KS_ADDR2], zmm2
        vmovdqu64       [KS_ADDR3], zmm3

%assign IDX (IDX + 1)
%endrep

        ;; - update tags
        mov             r12, 0x00FF
        mov             r13, 0xFF00
        kmovq           k1, r12
        kmovq           k2, r13

        vmovdqu64       zmm4, [T] ; Input tags
        vmovdqa64       zmm0, [rel shuf_mask_tags]
        vmovdqa64       zmm1, [rel shuf_mask_tags + 64]
        ; Get result tags for 16 buffers in different position in each lane
        ; and blend these tags into an ZMM register.
        ; Then, XOR the results with the previous tags and write out the result.
        vpermt2d        DIGEST_0{k1}{z}, zmm0, DIGEST_1
        vpermt2d        DIGEST_2{k2}{z}, zmm1, DIGEST_3
        vpternlogq      zmm4, DIGEST_0, DIGEST_2, 0x96 ; A XOR B XOR C
        vmovdqu64       [T], zmm4

        ; Update data pointers
        vmovdqu64       zmm0, [DATA]
        vmovdqu64       zmm1, [DATA + 64]
        vpaddq          zmm0, [rel add_64]
        vpaddq          zmm1, [rel add_64]
        vmovdqu64       [DATA], zmm0
        vmovdqu64       [DATA + 64], zmm1

        ; Update array of lengths (subtract 512 bits from all lengths if valid lane)
        vmovdqa         ymm2, [LEN]
        vpcmpw          k1, ymm2, [rel all_ffs], 4
        vpsubw          ymm2{k1}, [rel all_512w]
        vmovdqa         [LEN], ymm2

        FUNC_RESTORE

        ret

;;
;; extern void asm_Eia3RemainderAVX512(uint32_t *T, const void *ks,
;;                                     const void *data, uint64_t n_bits)
;;
;; Returns authentication update value to be XOR'ed with current authentication tag
;;
;; WIN64
;;	RCX - T (digest pointer)
;;	RDX - KS (key stream pointer)
;; 	R8  - DATA (data pointer)
;;      R9  - N_BITS (number data bits to process)
;; LIN64
;;      RDI - T (digest pointer)
;;	RSI - KS (key stream pointer)
;;	RDX - DATA (data pointer)
;;      RCX - N_BITS (number data bits to process)
;;
align 64
MKGLOBAL(asm_Eia3RemainderAVX512,function,internal)
asm_Eia3RemainderAVX512:

%ifdef LINUX
	%define		T	rdi
	%define		KS	rsi
	%define		DATA	rdx
	%define		N_BITS	rcx
%else
        %define         T       rcx
	%define		KS	rdx
	%define		DATA	r8
	%define		N_BITS	r9
%endif

%define N_BYTES rbx
%define OFFSET  r15

        FUNC_SAVE

        vmovdqa  xmm5, [bit_reverse_table_l]
        vmovdqa  xmm6, [bit_reverse_table_h]
        vmovdqa  xmm7, [bit_reverse_and_table]
        vmovdqa  xmm10, [data_mask_64bits]
        vpxor    xmm9, xmm9

        xor     OFFSET, OFFSET
%assign I 0
%rep 3
        cmp     N_BITS, 128
        jb      Eia3RoundsAVX512_dq_end

        ;; read 16 bytes and reverse bits
        vmovdqu xmm0, [DATA + OFFSET]
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
%if I != 0
        vmovdqa  xmm11, xmm12
        vmovdqu  xmm12, [KS + OFFSET + (4*4)]
%else
        vmovdqu  xmm11, [KS + (0*4)]
        vmovdqu  xmm12, [KS + (4*4)]
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
        vpclmulqdq xmm13, xmm0, xmm2, 0x00
        vpclmulqdq xmm14, xmm0, xmm2, 0x11
        vpclmulqdq xmm15, xmm1, xmm3, 0x00
        vpclmulqdq xmm8,  xmm1, xmm3, 0x11

        vpternlogq xmm13, xmm14, xmm8, 0x96
        vpternlogq xmm9, xmm13, xmm15, 0x96

        add     OFFSET, 16
        sub     N_BITS, 128
%assign I (I + 1)
%endrep
Eia3RoundsAVX512_dq_end:

        or      N_BITS, N_BITS
        jz      Eia3RoundsAVX_end

        ; Get number of bytes
        mov     N_BYTES, N_BITS
        add     N_BYTES, 7
        shr     N_BYTES, 3

        lea     r10, [rel byte64_len_to_mask_table]
        kmovq   k1, [r10 + N_BYTES*8]

        ;; Set up KS
        vmovdqu xmm1, [KS + OFFSET]
        vmovdqu xmm2, [KS + OFFSET + 16]
        vpalignr xmm13, xmm2, xmm1, 8
        vpshufd xmm11, xmm1, 0x61
        vpshufd xmm12, xmm13, 0x61

        ;; read up to 16 bytes of data, zero bits not needed if partial byte and bit-reverse
        vmovdqu8 xmm0{k1}{z}, [DATA + OFFSET]
        ; check if there is a partial byte (less than 8 bits in last byte)
        mov     rax, N_BITS
        and     rax, 0x7
        shl     rax, 4
        lea     r10, [rel bit_mask_table]
        add     r10, rax

        ; Get mask to clear last bits
        vmovdqa xmm3, [r10]

        ; Shift left 16-N bytes to have the last byte always at the end of the XMM register
        ; to apply mask, then restore by shifting right same amount of bytes
        mov     r10, 16
        sub     r10, N_BYTES
        XVPSLLB xmm0, r10, xmm4, r11
        vpandq  xmm0, xmm3
        XVPSRLB xmm0, r10, xmm4, r11

        ; Bit reverse input data
        vpand   xmm1, xmm0, xmm7

        vpandn  xmm2, xmm7, xmm0
        vpsrld  xmm2, 4

        vpshufb xmm8, xmm6, xmm1 ; bit reverse low nibbles (use high table)
        vpshufb xmm3, xmm5, xmm2 ; bit reverse high nibbles (use low table)

        vpor    xmm8, xmm3

        ;; Set up DATA
        vpand   xmm13, xmm10, xmm8
        vpshufd xmm0, xmm13, 0xdc ; D 0-3 || Os || D 4-7 || 0s

        vpsrldq xmm8, 8
        vpshufd xmm1, xmm8, 0xdc ; D 8-11 || 0s || D 12-15 || 0s

        ;; - clmul
        ;; - xor the results from 4 32-bit words together
        vpclmulqdq xmm13, xmm0, xmm11, 0x00
        vpclmulqdq xmm14, xmm0, xmm11, 0x11
        vpclmulqdq xmm15, xmm1, xmm12, 0x00
        vpclmulqdq xmm8, xmm1, xmm12, 0x11
        vpternlogq xmm9, xmm14, xmm13, 0x96
        vpternlogq xmm9, xmm15, xmm8, 0x96

Eia3RoundsAVX_end:
        mov     r11d, [T]
        vmovq   rax, xmm9
        shr     rax, 32
        xor     eax, r11d

        ; Read keyStr[N_BITS / 32]
        lea     r10, [N_BITS + OFFSET*8] ; Restore original N_BITS
        shr     r10, 5
        mov     r11, [KS + r10*4]

        ; Rotate left by N_BITS % 32
        mov     r12, rcx ; Save RCX
        mov     rcx, N_BITS
        and     rcx, 0x1F
        rol     r11, cl
        mov     rcx, r12 ; Restore RCX

        ; XOR with previous digest calculation
        xor     eax, r11d

       ; Read keyStr[L - 1] (last double word of keyStr)
        lea     r10, [N_BITS + OFFSET*8] ; Restore original N_BITS
        add     r10, (31 + 64)
        shr     r10, 5 ; L
        dec     r10
        mov     r11d, [KS + r10 * 4]

        ; XOR with previous digest calculation and bswap it
        xor     eax, r11d
        bswap   eax
        mov     [T], eax

        FUNC_RESTORE

        ret

;;
;; extern void asm_Eia3RemainderAVX512_16(uint32_t *T, const void **ks, const void **data, uint64_t n_bits)
;;
;; WIN64
;;      RCX - T: Array of digests for all 16 buffers
;;      RDX - KS : Array of pointers to key stream for all 16 buffers
;;      R8  - DATA : Array of pointers to data for all 16 buffers
;;      R9  - N_BITS (number data bits to process)
;; LIN64
;;      RDI  - T: Array of digests for all 16 buffers
;;      RSI  - KS : Array of pointers to key stream for all 16 buffers
;;      RDX  - DATA : Array of pointers to data for all 16 buffers
;;      RCX  - N_BITS (number data bits to process)
;;
align 64
MKGLOBAL(asm_Eia3RemainderAVX512_16,function,internal)
asm_Eia3RemainderAVX512_16:

%ifdef LINUX
        %define         T       rdi
        %define	        KS      rsi
        %define	        DATA    rdx
        %define         LEN     rcx
        %define	        arg5    r8
%else
        %define         T       rcx
        %define	        KS      rdx
        %define	        DATA    r8
        %define	        LEN     r9
        %define         arg5    [rsp + 40]
%endif

%define DIGEST_0        zmm28
%define DIGEST_1        zmm29
%define DIGEST_2        zmm30
%define DIGEST_3        zmm31

%define DATA_ADDR       r12
%define KS_ADDR         r13

%define N_BYTES         r14
%define OFFSET          r15

%define MIN_LEN         r10
%define IDX             rax

        mov     MIN_LEN, arg5

        FUNC_SAVE

        vpbroadcastw ymm0, MIN_LEN
        ; Get mask of non-NULL lanes (lengths not set to UINT16_MAX, indicating that lane is not valid)
        vmovdqa ymm1, [LEN]
        vpcmpw k1, ymm1, [rel all_ffs], 4

        ; Round up to nearest multiple of 32 bits
        vpaddw  ymm0{k1}, [rel all_31w]
        vpandq  ymm0, [rel all_ffe0w]

        ; Calculate remaining bits to authenticate after function call
        vpsubw  ymm2{k1}, ymm1, ymm0
        vpxorq  ymm3, ymm3
        vpcmpw  k2, ymm2, ymm3, 1 ; Get mask of lengths < 0
        ; Set to zero the lengths of the lanes which are going to be completed
        vmovdqu16 ymm2{k2}, ymm3 ; YMM2 contain final lengths
        vmovdqu16 [LEN]{k1}, ymm2 ; Update in memory the final updated lengths

        ; Calculate number of bits to authenticate (up to 511 bits),
        ; for each lane, and store it in stack to be used later
        vpsubw  ymm1{k1}{z}, ymm2 ; Bits to authenticate in all lanes (zero out length of NULL lanes)
        sub     rsp, 32
        vmovdqu [rsp], ymm1

        xor     OFFSET, OFFSET

        vmovdqa  xmm5, [bit_reverse_table_l]
        vmovdqa  xmm6, [bit_reverse_table_h]
        vmovdqa  xmm7, [bit_reverse_and_table]
        vmovdqa  xmm10, [data_mask_64bits]

%assign I 0
%rep 4
%assign J 0
%rep 4

        ; Read  length to authenticate for each buffer
        movzx   MIN_LEN, word [rsp + 2*(I*4 + J)]

        vpxor   xmm9, xmm9

        xor     OFFSET, OFFSET
        mov     DATA_ADDR, [DATA + 8*(I*4 + J)]
        mov     KS_ADDR, [KS + 8*(I*4 + J)]

%assign K 0
%rep 4
        cmp     MIN_LEN, 128
        jb      APPEND3(Eia3RoundsAVX512_dq_end,I,J)

        ;; read 16 bytes and reverse bits
        vmovdqu xmm0, [DATA_ADDR + OFFSET]
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
%if K != 0
        vmovdqa  xmm11, xmm12
        vmovdqu  xmm12, [KS_ADDR + OFFSET + (4*4)]
%else
        vmovdqu  xmm11, [KS_ADDR + (0*4)]
        vmovdqu  xmm12, [KS_ADDR + (4*4)]
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
        vpclmulqdq xmm13, xmm0, xmm2, 0x00
        vpclmulqdq xmm14, xmm0, xmm2, 0x11
        vpclmulqdq xmm15, xmm1, xmm3, 0x00
        vpclmulqdq xmm8,  xmm1, xmm3, 0x11

        vpternlogq xmm13, xmm14, xmm8, 0x96
        vpternlogq xmm9, xmm13, xmm15, 0x96
        add     OFFSET, 16
        sub     MIN_LEN, 128
%assign K (K + 1)
%endrep
APPEND3(Eia3RoundsAVX512_dq_end,I,J):

        or      MIN_LEN, MIN_LEN
        jz      APPEND3(Eia3RoundsAVX_end,I,J)

        ; Get number of bytes
        mov     N_BYTES, MIN_LEN
        add     N_BYTES, 7
        shr     N_BYTES, 3

        lea     r11, [rel byte64_len_to_mask_table]
        kmovq   k1, [r11 + N_BYTES*8]

        ;; Set up KS
        vmovdqu xmm1, [KS_ADDR + OFFSET]
        vmovdqu xmm2, [KS_ADDR + OFFSET + 16]
        vpalignr xmm13, xmm2, xmm1, 8
        vpshufd xmm11, xmm1, 0x61
        vpshufd xmm12, xmm13, 0x61

        ;; read up to 16 bytes of data, zero bits not needed if partial byte and bit-reverse
        vmovdqu8 xmm0{k1}{z}, [DATA_ADDR + OFFSET]
        ; check if there is a partial byte (less than 8 bits in last byte)
        mov     rax, MIN_LEN
        and     rax, 0x7
        shl     rax, 4
        lea     r11, [rel bit_mask_table]
        add     r11, rax

        ; Get mask to clear last bits
        vmovdqa xmm3, [r11]

        ; Shift left 16-N bytes to have the last byte always at the end of the XMM register
        ; to apply mask, then restore by shifting right same amount of bytes
        mov     r11, 16
        sub     r11, N_BYTES
        ; r13 = DATA_ADDR can be used at this stage
        XVPSLLB xmm0, r11, xmm4, r13
        vpandq  xmm0, xmm3
        XVPSRLB xmm0, r11, xmm4, r13

        ; Bit reverse input data
        vpand   xmm1, xmm0, xmm7

        vpandn  xmm2, xmm7, xmm0
        vpsrld  xmm2, 4

        vpshufb xmm8, xmm6, xmm1 ; bit reverse low nibbles (use high table)
        vpshufb xmm3, xmm5, xmm2 ; bit reverse high nibbles (use low table)

        vpor    xmm8, xmm3

        ;; Set up DATA
        vpand   xmm13, xmm10, xmm8
        vpshufd xmm0, xmm13, 0xdc ; D 0-3 || Os || D 4-7 || 0s

        vpsrldq xmm8, 8
        vpshufd xmm1, xmm8, 0xdc ; D 8-11 || 0s || D 12-15 || 0s

        ;; - clmul
        ;; - xor the results from 4 32-bit words together
        vpclmulqdq xmm13, xmm0, xmm11, 0x00
        vpclmulqdq xmm14, xmm0, xmm11, 0x11
        vpclmulqdq xmm15, xmm1, xmm12, 0x00
        vpclmulqdq xmm8, xmm1, xmm12, 0x11
        vpternlogq xmm9, xmm14, xmm13, 0x96
        vpternlogq xmm9, xmm15, xmm8, 0x96

APPEND3(Eia3RoundsAVX_end,I,J):
        vinserti32x4 APPEND(DIGEST_, I), xmm9, J
%assign J (J + 1)
%endrep
%assign I (I + 1)
%endrep

        ;; - update tags
        mov             rbx, 0x00FF
        mov             r10, 0xFF00
        kmovq           k1, rbx
        kmovq           k2, r10

        vmovdqu64       zmm4, [T] ; Input tags
        vmovdqa64       zmm0, [rel shuf_mask_tags]
        vmovdqa64       zmm1, [rel shuf_mask_tags + 64]
        ; Get result tags for 16 buffers in different position in each lane
        ; and blend these tags into an ZMM register.
        ; Then, XOR the results with the previous tags and write out the result.
        vpermt2d        DIGEST_0{k1}{z}, zmm0, DIGEST_1
        vpermt2d        DIGEST_2{k2}{z}, zmm1, DIGEST_3
        vpternlogq      zmm4, DIGEST_0, DIGEST_2, 0x96 ; A XOR B XOR C

        vmovdqa64       [T], zmm4 ; Store temporary digests

        ; These last steps should be done only for the buffers that
        ; have no more data to authenticate
        xor     IDX, IDX
start_loop:
        ; Update data pointer
        movzx   ebx, word [rsp + IDX*2]
        shr     ebx, 3 ; length authenticated in bytes
        add     [DATA + IDX*8], rbx

        cmp     word [LEN + 2*IDX], 0
        jnz     skip_comput

        ; Read digest
        mov     ebx, [T + 4*IDX]

        mov     KS_ADDR, [KS + IDX*8]

        ; Read keyStr[MIN_LEN / 32]
        movzx   MIN_LEN, word [rsp + 2*IDX]
        mov     r15, MIN_LEN
        shr     r15, 5
        mov     r11, [KS_ADDR +r15*4]
        ; Rotate left by MIN_LEN % 32
        mov     r15, rcx
        mov     rcx, MIN_LEN
        and     rcx, 0x1F
        rol     r11, cl
        mov     rcx, r15
        ; XOR with current digest
        xor     ebx, r11d

        ; Read keystr[L - 1] (last dword of keyStr)
        add     MIN_LEN, (31 + 64)
        shr     MIN_LEN, 5 ; L
        dec     MIN_LEN
        mov     r11d, [KS_ADDR + MIN_LEN * 4]
        ; XOR with current digest
        xor     ebx, r11d

        ; byte swap and write digest out
        bswap   ebx
        mov     [T + 4*IDX], ebx

skip_comput:
        inc     IDX
        cmp     IDX, 16
        jne     start_loop

        add     rsp, 32

        FUNC_RESTORE

        ret

;;
;;extern void asm_Eia3Round64BAVX512(uint32_t *T, const void *KS, const void *DATA)
;;
;; Updates authentication tag T based on keystream KS and DATA.
;; - it processes 64 bytes of DATA
;; - reads data in 16 byte chunks and bit reverses them
;; - reads and re-arranges KS
;; - employs clmul for the XOR & ROL part
;;
;; WIN64
;;	RCX - T pointer to digest
;;	RDX - KS pointer to key stream (2 x 64 bytes)
;;;     R8  - DATA pointer to data
;; LIN64
;;	RDI - T pointer to digest
;;	RSI - KS pointer to key stream (2 x 64 bytes)
;;      RDX - DATA pointer to data
;;
align 64
MKGLOBAL(asm_Eia3Round64BAVX512,function,internal)
asm_Eia3Round64BAVX512:

%ifdef LINUX
	%define		T	rdi
	%define		KS	rsi
	%define		DATA	rdx
%else
	%define		T	rcx
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

        vpshufb  xmm8, xmm6, xmm1 ; bit reverse low nibbles (use high table)
        vpshufb  xmm4, xmm5, xmm2 ; bit reverse high nibbles (use low table)

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
        vpclmulqdq xmm13, xmm0, xmm2, 0x00
        vpclmulqdq xmm14, xmm0, xmm2, 0x11
        vpclmulqdq xmm15, xmm1, xmm3, 0x00
        vpclmulqdq xmm8,  xmm1, xmm3, 0x11

        vpternlogq xmm13, xmm14, xmm8, 0x96
        vpternlogq xmm9, xmm13, xmm15, 0x96

%assign I (I + 1)
%endrep

        ;; - update T
        vmovq   rax, xmm9
        shr     rax, 32
        mov     r10d, [T]
        xor     eax, r10d
        mov     [T], eax

        FUNC_RESTORE

        ret

align 64
MKGLOBAL(asm_Eia3Round64BAVX512_16,function,internal)
asm_Eia3Round64BAVX512_16:

%ifdef LINUX
	%define		T	rdi
	%define		KS	rsi
	%define		DATA	rdx
	%define		LEN	rcx
%else
	%define		T	rcx
	%define		KS	rdx
	%define		DATA	r8
	%define		LEN	r9
%endif

%define         DIGEST_0        zmm28
%define         DIGEST_1        zmm29
%define         DIGEST_2        zmm30
%define         DIGEST_3        zmm31

%define         DATA_ADDR       r10
%define         KS_ADDR         r11

        FUNC_SAVE

        vmovdqa  xmm5, [bit_reverse_table_l]
        vmovdqa  xmm6, [bit_reverse_table_h]
        vmovdqa  xmm7, [bit_reverse_and_table]
        vmovdqa  xmm10, [data_mask_64bits]

%assign I 0
%rep 4
%assign J 0
%rep 4

        vpxor   xmm9, xmm9
        mov     DATA_ADDR, [DATA + 8*(I*4 + J)]
        mov     KS_ADDR, [KS + 8*(I*4 + J)]

%assign K 0
%rep 4
        ;; read 16 bytes and reverse bits
        vmovdqu  xmm0, [DATA_ADDR + 16*K]
        vpand    xmm1, xmm0, xmm7

        vpandn   xmm2, xmm7, xmm0
        vpsrld   xmm2, 4

        vpshufb  xmm8, xmm6, xmm1 ; bit reverse low nibbles (use high table)
        vpshufb  xmm4, xmm5, xmm2 ; bit reverse high nibbles (use low table)

        vpor     xmm8, xmm4
        ; xmm8 - bit reversed data bytes

        ;; ZUC authentication part
        ;; - 4x32 data bits
        ;; - set up KS
%if K != 0
        vmovdqa  xmm11, xmm12
        vmovdqu  xmm12, [KS_ADDR + (K*16) + (4*4)]
%else
        vmovdqu  xmm11, [KS_ADDR + (K*16) + (0*4)]
        vmovdqu  xmm12, [KS_ADDR + (K*16) + (4*4)]
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
        vpclmulqdq xmm13, xmm0, xmm2, 0x00
        vpclmulqdq xmm14, xmm0, xmm2, 0x11
        vpclmulqdq xmm15, xmm1, xmm3, 0x00
        vpclmulqdq xmm8,  xmm1, xmm3, 0x11

        vpternlogq xmm13, xmm14, xmm8, 0x96
        vpternlogq xmm9, xmm13, xmm15, 0x96

%assign K (K + 1)
%endrep

        vinserti32x4 APPEND(DIGEST_, I), xmm9, J
        ; Memcpy KS 64-127 bytes to 0-63 bytes
        vmovdqu64       zmm0, [KS_ADDR + 64]
        vmovdqu64       [KS_ADDR], zmm0
%assign J (J + 1)
%endrep
%assign I (I + 1)
%endrep

        ;; - update tags
        mov             r12, 0x00FF
        mov             r13, 0xFF00
        kmovq           k1, r12
        kmovq           k2, r13

        vmovdqu64       zmm4, [T] ; Input tags
        vmovdqa64       zmm0, [rel shuf_mask_tags]
        vmovdqa64       zmm1, [rel shuf_mask_tags + 64]
        ; Get result tags for 16 buffers in different position in each lane
        ; and blend these tags into an ZMM register.
        ; Then, XOR the results with the previous tags and write out the result.
        vpermt2d        DIGEST_0{k1}{z}, zmm0, DIGEST_1
        vpermt2d        DIGEST_2{k2}{z}, zmm1, DIGEST_3
        vpternlogq      zmm4, DIGEST_0, DIGEST_2, 0x96 ; A XOR B XOR C
        vmovdqu64       [T], zmm4

        ; Update data pointers
        vmovdqu64       zmm0, [DATA]
        vmovdqu64       zmm1, [DATA + 64]
        vpaddq          zmm0, [rel add_64]
        vpaddq          zmm1, [rel add_64]
        vmovdqu64       [DATA], zmm0
        vmovdqu64       [DATA + 64], zmm1

        ; Update array of lengths (if lane is valid, so length < UINT16_MAX)
        vmovdqa         ymm2, [LEN]
        vpcmpw          k1, ymm2, [rel all_ffs], 4 ; k1 -> valid lanes
        vpsubw          ymm2{k1}, [rel all_512w]
        vmovdqa         [LEN], ymm2

        FUNC_RESTORE

        ret


;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
