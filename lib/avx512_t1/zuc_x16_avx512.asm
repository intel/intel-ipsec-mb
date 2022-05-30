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
%include "include/transpose_avx512.asm"
%include "include/const.inc"
%include "include/mb_mgr_datastruct.asm"
%include "include/cet.inc"
%define APPEND(a,b) a %+ b
%define APPEND3(a,b,c) a %+ b %+ c

%ifndef CIPHER_16
%define USE_GFNI_VAES_VPCLMUL 0
%define CIPHER_16 asm_ZucCipher_16_avx512
%define ZUC128_INIT asm_ZucInitialization_16_avx512
%define ZUC256_INIT asm_Zuc256Initialization_16_avx512
%define ZUC128_REMAINDER_16 asm_Eia3RemainderAVX512_16
%define ZUC256_REMAINDER_16 asm_Eia3_256_RemainderAVX512_16
%define ZUC_KEYGEN64B_16 asm_ZucGenKeystream64B_16_avx512
%define ZUC_KEYGEN8B_16 asm_ZucGenKeystream8B_16_avx512
%define ZUC_KEYGEN_16 asm_ZucGenKeystream_16_avx512
%define ZUC_KEYGEN64B_SKIP16_16 asm_ZucGenKeystream64B_16_skip16_avx512
%define ZUC_KEYGEN_SKIP16_16 asm_ZucGenKeystream_16_skip16_avx512
%define ZUC_KEYGEN64B_SKIP8_16 asm_ZucGenKeystream64B_16_skip8_avx512
%define ZUC_KEYGEN_SKIP8_16 asm_ZucGenKeystream_16_skip8_avx512
%define ZUC_KEYGEN64B_SKIP4_16 asm_ZucGenKeystream64B_16_skip4_avx512
%define ZUC_KEYGEN_SKIP4_16 asm_ZucGenKeystream_16_skip4_avx512
%define ZUC_ROUND64B_16 asm_Eia3Round64BAVX512_16
%define ZUC_EIA3_N64B asm_Eia3_Nx64B_AVX512_16
%endif

mksection .rodata
default rel

align 64
EK_d64:
dd	0x0044D700, 0x0026BC00, 0x00626B00, 0x00135E00, 0x00578900, 0x0035E200, 0x00713500, 0x0009AF00
dd	0x004D7800, 0x002F1300, 0x006BC400, 0x001AF100, 0x005E2600, 0x003C4D00, 0x00789A00, 0x0047AC00

; Constants to be used to initialize the LFSR registers
; The tables contain four different sets of constants:
; 0-63 bytes: Encryption
; 64-127 bytes: Authentication with tag size = 4
; 128-191 bytes: Authentication with tag size = 8
; 192-255 bytes: Authentication with tag size = 16
align 64
EK256_d64:
dd      0x00220000, 0x002F0000, 0x00240000, 0x002A0000, 0x006D0000, 0x00400000, 0x00400000, 0x00400000
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000, 0x00400000, 0x00520000, 0x00100000, 0x00300000

align 64
EK256_EIA3_4:
dd      0x00220000, 0x002F0000, 0x00250000, 0x002A0000,
dd      0x006D0000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00520000, 0x00100000, 0x00300000

align 64
EK256_EIA3_8:
dd      0x00230000, 0x002F0000, 0x00240000, 0x002A0000,
dd      0x006D0000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00520000, 0x00100000, 0x00300000

align 64
EK256_EIA3_16:
dd      0x00230000, 0x002F0000, 0x00250000, 0x002A0000,
dd      0x006D0000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00400000, 0x00400000, 0x00400000,
dd      0x00400000, 0x00520000, 0x00100000, 0x00300000

align 64
shuf_mask_key:
dd      0x00FFFFFF, 0x01FFFFFF, 0x02FFFFFF, 0x03FFFFFF, 0x04FFFFFF, 0x05FFFFFF, 0x06FFFFFF, 0x07FFFFFF,
dd      0x08FFFFFF, 0x09FFFFFF, 0x0AFFFFFF, 0x0BFFFFFF, 0x0CFFFFFF, 0x0DFFFFFF, 0x0EFFFFFF, 0x0FFFFFFF,

align 64
shuf_mask_iv:
dd      0xFFFFFF00, 0xFFFFFF01, 0xFFFFFF02, 0xFFFFFF03, 0xFFFFFF04, 0xFFFFFF05, 0xFFFFFF06, 0xFFFFFF07,
dd      0xFFFFFF08, 0xFFFFFF09, 0xFFFFFF0A, 0xFFFFFF0B, 0xFFFFFF0C, 0xFFFFFF0D, 0xFFFFFF0E, 0xFFFFFF0F,

align 64
shuf_mask_key256_first_high:
dd      0x00FFFFFF, 0x01FFFFFF, 0x02FFFFFF, 0x03FFFFFF, 0x04FFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
dd      0x08FFFFFF, 0x09FFFFFF, 0xFFFFFFFF, 0x0BFFFFFF, 0x0CFFFFFF, 0x0DFFFFFF, 0x0EFFFFFF, 0x0FFFFFFF,

align 64
shuf_mask_key256_first_low:
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF05FF, 0xFFFF06FF, 0xFFFF07FF,
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF0AFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,

align 64
shuf_mask_key256_second:
dd      0xFFFF0500, 0xFFFF0601, 0xFFFF0702, 0xFFFF0803, 0xFFFF0904, 0xFFFFFF0A, 0xFFFFFF0B, 0xFFFFFFFF,
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFF0C, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF0FFFFF, 0xFF0F0E0D,

align 64
shuf_mask_iv256_first_high:
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00FFFFFF, 0x01FFFFFF, 0x0AFFFFFF,
dd      0xFFFFFFFF, 0xFFFFFFFF, 0x05FFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,

align 64
shuf_mask_iv256_first_low:
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFF02,
dd      0xFFFF030B, 0xFFFF0C04, 0xFFFFFFFF, 0xFFFF060D, 0xFFFF070E, 0xFFFF0F08, 0xFFFFFF09, 0xFFFFFFFF,

align 64
shuf_mask_iv256_second:
dd      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF01FFFF, 0xFF02FFFF, 0xFF03FFFF,
dd      0xFF04FFFF, 0xFF05FFFF, 0xFF06FFFF, 0xFF07FFFF, 0xFF08FFFF, 0xFFFFFFFF, 0xFFFF00FF, 0xFFFFFFFF,

align 64
key_mask_low_4:
dq      0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff
dq      0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xff0fffffffff0fff

align 64
iv_mask_low_6:
dq      0x3f3f3f3f3f3f3fff, 0x000000000000003f

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
bit_reverse_table:
times 8 db      0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

align 64
shuf_mask_4B_tags_0_1_2_3:
dd      0x01, 0x05, 0x09, 0x0D, 0x11, 0x15, 0x19, 0x1D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
dd      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x05, 0x09, 0x0D, 0x11, 0x15, 0x19, 0x1D

align 64
shuf_mask_4B_tags_0_4_8_12:
dd      0x01, 0x11, 0xFF, 0xFF, 0x05, 0x15, 0xFF, 0xFF, 0x09, 0x19, 0xFF, 0xFF, 0x0D, 0x1D, 0xFF, 0xFF
dd      0xFF, 0xFF, 0x01, 0x11, 0xFF, 0xFF, 0x05, 0x15, 0xFF, 0xFF, 0x09, 0x19, 0xFF, 0xFF, 0x0D, 0x1D

align 64
shuf_mask_8B_tags_0_1_4_5:
dq      0x00, 0x08, 0xFF, 0xFF, 0x02, 0x0A, 0xFF, 0xFF

align 64
shuf_mask_8B_tags_2_3_6_7:
dq      0xFF, 0xFF, 0x00, 0x08, 0xFF, 0xFF, 0x02, 0x0A

align 64
shuf_mask_8B_tags_8_9_12_13:
dq      0x04, 0x0C, 0xFF, 0xFF, 0x06, 0x0E, 0xFF, 0xFF

align 64
shuf_mask_8B_tags_10_11_14_15:
dq      0xFF, 0xFF, 0x04, 0x0C, 0xFF, 0xFF, 0x06, 0x0E

align 64
shuf_mask_8B_tags:
dq      0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E

align 64
all_ffs:
dw      0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
dw      0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
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
        dq      0xffffffffffffffff, 0x0000000000000001
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

align 32
permw_mask:
dw      0, 4, 8, 12, 1, 5, 8, 13, 2, 6, 10, 14, 3, 7, 11, 15

extr_bits_0_4_8_12:
db      00010001b, 00010001b, 00000000b, 00000000b

extr_bits_1_5_9_13:
db      00100010b, 00100010b, 00000000b, 00000000b

extr_bits_2_6_10_14:
db      01000100b, 01000100b, 00000000b, 00000000b

extr_bits_3_7_11_15:
db      10001000b, 10001000b, 00000000b, 00000000b

alignr_mask:
dw      0xffff, 0xffff, 0xffff, 0xffff
dw      0x0000, 0xffff, 0xffff, 0xffff
dw      0xffff, 0x0000, 0xffff, 0xffff
dw      0x0000, 0x0000, 0xffff, 0xffff
dw      0xffff, 0xffff, 0x0000, 0xffff
dw      0x0000, 0xffff, 0x0000, 0xffff
dw      0xffff, 0x0000, 0x0000, 0xffff
dw      0x0000, 0x0000, 0x0000, 0xffff
dw      0xffff, 0xffff, 0xffff, 0x0000
dw      0x0000, 0xffff, 0xffff, 0x0000
dw      0xffff, 0x0000, 0xffff, 0x0000
dw      0x0000, 0x0000, 0xffff, 0x0000
dw      0xffff, 0xffff, 0x0000, 0x0000
dw      0x0000, 0xffff, 0x0000, 0x0000
dw      0xffff, 0x0000, 0x0000, 0x0000
dw      0x0000, 0x0000, 0x0000, 0x0000

mov_16B_mask:
dw      0000000000000000b, 0000000000001111b, 0000000011110000b, 0000000011111111b
dw      0000111100000000b, 0000111100001111b, 0000111111110000b, 0000111111111111b
dw      1111000000000000b, 1111000000001111b, 1111000011110000b, 1111000011111111b
dw      1111111100000000b, 1111111100001111b, 1111111111110000b, 1111111111111111b

mov_8B_mask:
dw      1100110011001100b, 1100110011001111b, 1100110011111100b, 1100110011111111b
dw      1100111111001100b, 1100111111001111b, 1100111111111100b, 1100111111111111b
dw      1111110011001100b, 1111110011001111b, 1111110011111100b, 1111110011111111b
dw      1111111111001100b, 1111111111001111b, 1111111111111100b, 1111111111111111b

mov_4B_mask:
dw      1110111011101110b, 1110111011101111b, 1110111011111110b, 1110111011111111b
dw      1110111111101110b, 1110111111101111b, 1110111111111110b, 1110111111111111b
dw      1111111011101110b, 1111111011101111b, 1111111011111110b, 1111111011111111b
dw      1111111111101110b, 1111111111101111b, 1111111111111110b, 1111111111111111b

align 64
idx_tags_64_0_7:
dd      0x00, 0x10, 0x01, 0x11, 0x02, 0x12, 0x03, 0x13
dd      0x04, 0x14, 0x05, 0x15, 0x06, 0x16, 0x07, 0x17

align 64
idx_tags_64_8_15:
dd      0x08, 0x18, 0x09, 0x19, 0x0A, 0x1A, 0x0B, 0x1B
dd      0x0C, 0x1C, 0x0D, 0x1D, 0x0E, 0x1E, 0x0F, 0x1F

align 64
bits_32_63:
times 4 dd 0x00000000, 0xffffffff, 0x00000000, 0x00000000

align 64
shuf_mask_0_0_0_dw1:
times 4 db 0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff

expand_mask:
db      0x00, 0x03, 0x0c, 0x0f, 0x30, 0x33, 0x3c, 0x3f
db      0xc0, 0xc3, 0xcc, 0xcf, 0xf0, 0xf3, 0xfc, 0xff

align 64
shuf_mask_0_dw1_0_0:
times 4 db 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff

align 64
shuf_mask_dw1_0_0_0:
times 4 db 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x04, 0x05, 0x06, 0x07

;; Calculate address for next bytes of keystream (KS)
;; Memory for KS is laid out in the following way:
;; - There are 128 bytes of KS for each buffer spread in chunks of 16 bytes,
;;   interleaving with KS from other 3 buffers, every 512 bytes
;; - There are 16 bytes of KS every 64 bytes, for every buffer

;; - To access the 512-byte chunk, containing the 128 bytes of KS for the 4 buffers,
;;   lane4_idx
;; - To access the next 16 bytes of KS for a buffer, bytes16_idx is used
;; - To access a 16-byte chunk inside a 64-byte chunk, ks_idx is used
%define GET_KS(base, lane4_idx, bytes16_idx, ks_idx) (base + lane4_idx * 512 + bytes16_idx * 64 + ks_idx * 16)

; Define Stack Layout
START_FIELDS
;;;     name                    size            align
FIELD	_TEMP_DIGEST_SAVE,	16*64,	        64
FIELD	_RSP,		        8,	        8
%assign STACK_SPACE	_FIELD_OFFSET

mksection .text
align 64

%ifdef LINUX
%define arg1 rdi
%define arg2 rsi
%define arg3 rdx
%define arg4 rcx
%define arg5 r8
%define arg6 r9d
%define arg7 qword [rsp + 8]
%else
%define arg1 rcx
%define arg2 rdx
%define arg3 r8
%define arg4 r9
%define arg5 qword [rsp + 40]
%define arg6 qword [rsp + 48]
%define arg7 qword [rsp + 56]
%endif

%define OFS_R1  (16*(4*16))
%define OFS_R2  (OFS_R1 + (4*16))

%ifidn __OUTPUT_FORMAT__, win64
        %define XMM_STORAGE     16*10
        %define GP_STORAGE      8*8
%else
        %define XMM_STORAGE     0
        %define GP_STORAGE      6*8
%endif
%define LANE_STORAGE    64

%define VARIABLE_OFFSET XMM_STORAGE + GP_STORAGE + LANE_STORAGE
%define GP_OFFSET XMM_STORAGE

%macro FUNC_SAVE 0
        mov     rax, rsp
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
        mov     [rsp + GP_OFFSET + 40], rax ;; rsp pointer
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
%define %%STATE      %1 ; [in] Pointer to LFSR state
%define %%NUM_ROUNDS %2 ; [immediate] Number of key generation rounds
%define %%LANE_MASK  %3  ; [in] Mask register with lanes to update

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
; Perform a partial 16x16 transpose (as opposed to a full 16x16 transpose),
; where the output is chunks of 16 bytes from 4 different buffers interleaved
; in each register (all ZMM registers)
;
; Input:
; a0 a1 a2 a3 a4 a5 a6 a7 .... a15
; b0 b1 b2 b3 b4 b5 b6 b7 .... b15
; c0 c1 c2 c3 c4 c5 c6 c7 .... c15
; d0 d1 d2 d3 d4 d5 d6 d7 .... d15
;
; Output:
; a0 b0 c0 d0 a4 b4 c4 d4 .... d12
; a1 b1 c1 d1 a5 b5 c5 d5 .... d13
; a2 b2 c2 d2 a6 b6 c6 d6 .... d14
; a3 b3 c3 d3 a7 b7 c7 d7 .... d15
;
%macro TRANSPOSE16_U32_INTERLEAVED 26
%define %%IN00  %1 ; [in/out] Bytes 0-3 for all buffers (in) / Bytes 0-15 for buffers 3,7,11,15 (out)
%define %%IN01  %2 ; [in/out] Bytes 4-7 for all buffers (in) / Bytes 16-31 for buffers 3,7,11,15 (out)
%define %%IN02  %3 ; [in/out] Bytes 8-11 for all buffers (in) / Bytes 32-47 for buffers 3,7,11,15 (out)
%define %%IN03  %4 ; [in/out] Bytes 12-15 for all buffers (in) / Bytes 48-63 for buffers 3,7,11,15 (out)
%define %%IN04  %5 ; [in/clobbered] Bytes 16-19 for all buffers (in)
%define %%IN05  %6 ; [in/clobbered] Bytes 20-23 for all buffers (in)
%define %%IN06  %7 ; [in/clobbered] Bytes 24-27 for all buffers (in)
%define %%IN07  %8 ; [in/clobbered] Bytes 28-31 for all buffers (in)
%define %%IN08  %9 ; [in/clobbered] Bytes 32-35 for all buffers (in)
%define %%IN09 %10 ; [in/clobbered] Bytes 36-39 for all buffers (in)
%define %%IN10 %11 ; [in/clobbered] Bytes 40-43 for all buffers (in)
%define %%IN11 %12 ; [in/clobbered] Bytes 44-47 for all buffers (in)
%define %%IN12 %13 ; [in/out] Bytes 48-51 for all buffers (in) / Bytes 0-15 for buffers 2,6,10,14 (out)
%define %%IN13 %14 ; [in/out] Bytes 52-55 for all buffers (in) / Bytes 16-31 for buffers 2,6,10,14 (out)
%define %%IN14 %15 ; [in/out] Bytes 56-59 for all buffers (in) / Bytes 32-47 for buffers 2,6,10,14 (out)
%define %%IN15 %16 ; [in/out] Bytes 60-63 for all buffers (in) / Bytes 48-63 for buffers 2,6,10,14 (out)
%define %%T0   %17 ; [out] Bytes 32-47 for buffers 1,5,9,13 (out)
%define %%T1   %18 ; [out] Bytes 48-63 for buffers 1,5,9,13 (out)
%define %%T2   %19 ; [out] Bytes 32-47 for buffers 0,4,8,12 (out)
%define %%T3   %20 ; [out] Bytes 48-63 for buffers 0,4,8,12 (out)
%define %%K0   %21 ; [out] Bytes 0-15 for buffers 1,5,9,13 (out)
%define %%K1   %22 ; [out] Bytes 16-31for buffers 1,5,9,13 (out)
%define %%K2   %23 ; [out] Bytes 0-15 for buffers 0,4,8,12 (out)
%define %%K3   %24 ; [out] Bytes 16-31 for buffers 0,4,8,12 (out)
%define %%K4   %25 ; [clobbered] Temporary register
%define %%K5   %26 ; [clobbered] Temporary register

        vpunpckldq      %%K0, %%IN00, %%IN01
        vpunpckhdq      %%K1, %%IN00, %%IN01
        vpunpckldq      %%T0, %%IN02, %%IN03
        vpunpckhdq      %%T1, %%IN02, %%IN03

        vpunpckldq      %%IN00, %%IN04, %%IN05
        vpunpckhdq      %%IN01, %%IN04, %%IN05
        vpunpckldq      %%IN02, %%IN06, %%IN07
        vpunpckhdq      %%IN03, %%IN06, %%IN07

        vpunpcklqdq     %%K2, %%K0, %%T0
        vpunpckhqdq     %%K3, %%K0, %%T0
        vpunpcklqdq     %%T2, %%K1, %%T1
        vpunpckhqdq     %%T3, %%K1, %%T1

        vpunpcklqdq     %%K0, %%IN00, %%IN02
        vpunpckhqdq     %%K1, %%IN00, %%IN02
        vpunpcklqdq     %%T0, %%IN01, %%IN03
        vpunpckhqdq     %%T1, %%IN01, %%IN03

        vpunpckldq      %%K4, %%IN08, %%IN09
        vpunpckhdq      %%K5, %%IN08, %%IN09
        vpunpckldq      %%IN04, %%IN10, %%IN11
        vpunpckhdq      %%IN05, %%IN10, %%IN11
        vpunpckldq      %%IN06, %%IN12, %%IN13
        vpunpckhdq      %%IN07, %%IN12, %%IN13
        vpunpckldq      %%IN10, %%IN14, %%IN15
        vpunpckhdq      %%IN11, %%IN14, %%IN15

        vpunpcklqdq     %%IN12, %%K4, %%IN04
        vpunpckhqdq     %%IN13, %%K4, %%IN04
        vpunpcklqdq     %%IN14, %%K5, %%IN05
        vpunpckhqdq     %%IN15, %%K5, %%IN05
        vpunpcklqdq     %%IN00, %%IN06, %%IN10
        vpunpckhqdq     %%IN01, %%IN06, %%IN10
        vpunpcklqdq     %%IN02, %%IN07, %%IN11
        vpunpckhqdq     %%IN03, %%IN07, %%IN11
%endmacro

;
; Perform a partial 4x16 transpose
; where the output is chunks of 16 bytes from 4 different buffers interleaved
; in each register (all ZMM registers)
;
; Input:
; a0 a1 a2 a3 a4 a5 a6 a7 .... a15
; b0 b1 b2 b3 b4 b5 b6 b7 .... b15
; c0 c1 c2 c3 c4 c5 c6 c7 .... c15
; d0 d1 d2 d3 d4 d5 d6 d7 .... d15
;
; Output:
; a0 b0 c0 d0 a4 b4 c4 d4 .... d12
; a1 b1 c1 d1 a5 b5 c5 d5 .... d13
; a2 b2 c2 d2 a6 b6 c6 d6 .... d14
; a3 b3 c3 d3 a7 b7 c7 d7 .... d15
;
%macro TRANSPOSE4_U32_INTERLEAVED 8
%define %%IN00  %1 ; [in/out] Bytes 0-3 for all buffers (in) / Bytes 0-15 for buffers 0,4,8,12 (out)
%define %%IN01  %2 ; [in/out] Bytes 4-7 for all buffers (in) / Bytes 0-15 for buffers 1,5,9,13 (out)
%define %%IN02  %3 ; [in/out] Bytes 8-11 for all buffers (in) / Bytes 0-15 for buffers 2,6,10,14 (out)
%define %%IN03  %4 ; [in/out] Bytes 12-15 for all buffers (in) / Bytes 0-15 for buffers 3,7,11,15 (out)
%define %%T0   %5 ; [clobbered] Temporary ZMM register
%define %%T1   %6 ; [clobbered] Temporary ZMM register
%define %%K0   %7 ; [clobbered] Temporary ZMM register
%define %%K1   %8 ; [clobbered] Temporary ZMM register

        vpunpckldq      %%K0, %%IN00, %%IN01
        vpunpckhdq      %%K1, %%IN00, %%IN01
        vpunpckldq      %%T0, %%IN02, %%IN03
        vpunpckhdq      %%T1, %%IN02, %%IN03

        vpunpcklqdq     %%IN00, %%K0, %%T0
        vpunpckhqdq     %%IN01, %%K0, %%T0
        vpunpcklqdq     %%IN02, %%K1, %%T1
        vpunpckhqdq     %%IN03, %%K1, %%T1
%endmacro

;
; Performs a 4x16 32-bit transpose
;
; Input (each item is a 32-bit word):
; A0 A1 .. A15
; B0 B1 .. B15
; C0 C1 .. C15
; D0 D1 .. D15
;
; Output (each item is a 32-bit word):
; A0  B0  C0  D0  A1  B1 ..  C3  D3
; A4  B4  C4  D4  A5  B5 ..  C7  D7
; A8  B8  C8  D8  A9  B9 ..  C11 D11
; A12 B12 C12 D12 A13 B13 .. C15 D15
;
%macro TRANSPOSE4_U32 16
%define %%IN00 %1  ; [in/out] Input row 0 / Output column 0
%define %%IN01 %2  ; [in/out] Input row 1 / Output column 1
%define %%IN02 %3  ; [in/out] Input row 2 / Output column 2
%define %%IN03 %4  ; [in/out] Input row 3 / Output column 3
%define %%T0   %5  ; [clobbered] Temporary ZMM register
%define %%T1   %6  ; [clobbered] Temporary ZMM register
%define %%T2   %7  ; [clobbered] Temporary ZMM register
%define %%T3   %8  ; [clobbered] Temporary ZMM register
%define %%K0   %9  ; [clobbered] Temporary ZMM register
%define %%K1   %10 ; [clobbered] Temporary ZMM register
%define %%K2   %11 ; [clobbered] Temporary ZMM register
%define %%K3   %12 ; [clobbered] Temporary ZMM register
%define %%H0   %13 ; [clobbered] Temporary ZMM register
%define %%H1   %14 ; [clobbered] Temporary ZMM register
%define %%H2   %15 ; [clobbered] Temporary ZMM register
%define %%H3   %16 ; [clobbered] Temporary ZMM register

        vpunpckldq      %%K0, %%IN00, %%IN01
        vpunpckhdq      %%K1, %%IN00, %%IN01
        vpunpckldq      %%T0, %%IN02, %%IN03
        vpunpckhdq      %%T1, %%IN02, %%IN03

        vpunpcklqdq     %%K2, %%K0, %%T0
        vpunpckhqdq     %%T2, %%K0, %%T0
        vpunpcklqdq     %%K3, %%K1, %%T1
        vpunpckhqdq     %%T3, %%K1, %%T1

        vshufi64x2      %%H0, %%K2, %%T2, 0x44
        vshufi64x2      %%H1, %%K2, %%T2, 0xee
        vshufi64x2      %%H2, %%K3, %%T3, 0x44
        vshufi64x2      %%H3, %%K3, %%T3, 0xee

        vshufi64x2      %%IN00, %%H0, %%H2, 0x88
        vshufi64x2      %%IN01, %%H0, %%H2, 0xdd
        vshufi64x2      %%IN02, %%H1, %%H3, 0x88
        vshufi64x2      %%IN03, %%H1, %%H3, 0xdd

%endmacro

;
; Calculates X0-X3 from LFSR registers
;
%macro  BITS_REORG16 16-17
%define %%STATE         %1  ; [in] ZUC state
%define %%ROUND_NUM     %2  ; [in] Round number
%define %%LANE_MASK     %3  ; [in] Mask register with lanes to update
%define %%LFSR_0        %4  ; [clobbered] LFSR_0
%define %%LFSR_2        %5  ; [clobbered] LFSR_2
%define %%LFSR_5        %6  ; [clobbered] LFSR_5
%define %%LFSR_7        %7  ; [clobbered] LFSR_7
%define %%LFSR_9        %8  ; [clobbered] LFSR_9
%define %%LFSR_11       %9  ; [clobbered] LFSR_11
%define %%LFSR_14       %10 ; [clobbered] LFSR_14
%define %%LFSR_15       %11 ; [clobbered] LFSR_15
%define %%ZTMP          %12 ; [clobbered] Temporary ZMM register
%define %%BLEND_KMASK   %13 ; [in] Blend K-mask
%define %%X0            %14 ; [out] ZMM register containing X0 of all lanes
%define %%X1            %15 ; [out] ZMM register containing X1 of all lanes
%define %%X2            %16 ; [out] ZMM register containing X2 of all lanes
%define %%X3            %17 ; [out] ZMM register containing X3 of all lanes (only for work mode)

        vmovdqa64   %%LFSR_15, [%%STATE + ((15 + %%ROUND_NUM) % 16)*64]
        vmovdqa64   %%LFSR_14, [%%STATE + ((14 + %%ROUND_NUM) % 16)*64]
        vmovdqa64   %%LFSR_11, [%%STATE + ((11 + %%ROUND_NUM) % 16)*64]
        vmovdqa64   %%LFSR_9,  [%%STATE + (( 9 + %%ROUND_NUM) % 16)*64]
        vmovdqa64   %%LFSR_7,  [%%STATE + (( 7 + %%ROUND_NUM) % 16)*64]
        vmovdqa64   %%LFSR_5,  [%%STATE + (( 5 + %%ROUND_NUM) % 16)*64]
%if (%0 == 17) ; Only needed when generating X3 (for "working" mode)
        vmovdqa64   %%LFSR_2,  [%%STATE + (( 2 + %%ROUND_NUM) % 16)*64]
        vmovdqa64   %%LFSR_0,  [%%STATE + (( 0 + %%ROUND_NUM) % 16)*64]
%endif

%if USE_GFNI_VAES_VPCLMUL == 1
        vpsrld  %%LFSR_15, 15
        vpslld  %%LFSR_14, 16
        vpslld  %%LFSR_9, 1
        vpslld  %%LFSR_5, 1
        vpshldd %%X0, %%LFSR_15, %%LFSR_14, 16
        vpshldd %%X1, %%LFSR_11, %%LFSR_9, 16
        vpshldd %%X2, %%LFSR_7, %%LFSR_5, 16
%if (%0 == 17)
        vpslld  %%LFSR_0, 1
        vpshldd %%X3, %%LFSR_2, %%LFSR_0, 16
%endif
%else ; USE_GFNI_VAES_VPCLMUL == 1
        vpxorq  %%ZTMP, %%ZTMP
        vpslld  %%LFSR_15, 1
        vpblendmw   %%ZTMP{%%BLEND_KMASK}, %%LFSR_14, %%ZTMP
        vpblendmw   %%X0{%%BLEND_KMASK}, %%ZTMP, %%LFSR_15
        vpslld  %%LFSR_11, 16
        vpsrld  %%LFSR_9, 15
        vporq   %%X1, %%LFSR_11, %%LFSR_9
        vpslld  %%LFSR_7, 16
        vpsrld  %%LFSR_5, 15
        vporq   %%X2, %%LFSR_7, %%LFSR_5
%if (%0 == 17)
        vpslld  %%LFSR_2, 16
        vpsrld  %%LFSR_0, 15
        vporq   %%X3, %%LFSR_2, %%LFSR_0 ; Store BRC_X3 in ZMM register
%endif ; %0 == 17
%endif ; USE_GFNI_VAES_VPCLMUL == 1
%endmacro

;
; Updates R1-R2, using X0-X3 and generates W (if needed)
;
%macro NONLIN_FUN16  13-14
%define %%STATE     %1  ; [in] ZUC state
%define %%LANE_MASK %2  ; [in] Mask register with lanes to update
%define %%X0        %3  ; [in] ZMM register containing X0 of all lanes
%define %%X1        %4  ; [in] ZMM register containing X1 of all lanes
%define %%X2        %5  ; [in] ZMM register containing X2 of all lanes
%define %%R1        %6  ; [in/out] ZMM register to contain R1 for all lanes
%define %%R2        %7  ; [in/out] ZMM register to contain R2 for all lanes
%define %%ZTMP1     %8  ; [clobbered] Temporary ZMM register
%define %%ZTMP2     %9  ; [clobbered] Temporary ZMM register
%define %%ZTMP3     %10 ; [clobbered] Temporary ZMM register
%define %%ZTMP4     %11 ; [clobbered] Temporary ZMM register
%define %%ZTMP5     %12 ; [clobbered] Temporary ZMM register
%define %%ZTMP6     %13 ; [clobbered] Temporary ZMM register
%define %%W         %14 ; [out] ZMM register to contain W for all lanes

%define %%W1 %%ZTMP5
%define %%W2 %%ZTMP6

%if (%0 == 14)
        vpxorq  %%W, %%X0, %%R1
        vpaddd  %%W, %%R2    ; W = (BRC_X0 ^ F_R1) + F_R2
%endif

        vpaddd  %%W1, %%R1, %%X1    ; W1 = F_R1 + BRC_X1
        vpxorq  %%W2, %%R2, %%X2    ; W2 = F_R2 ^ BRC_X2

%if USE_GFNI_VAES_VPCLMUL == 1
        vpshldd %%ZTMP1, %%W1, %%W2, 16
        vpshldd %%ZTMP2, %%W2, %%W1, 16
%else
        vpslld  %%ZTMP3, %%W1, 16
        vpsrld  %%ZTMP4, %%W1, 16
        vpslld  %%ZTMP5, %%W2, 16
        vpsrld  %%ZTMP6, %%W2, 16
        vporq   %%ZTMP1, %%ZTMP3, %%ZTMP6
        vporq   %%ZTMP2, %%ZTMP4, %%ZTMP5
%endif

        vprold  %%ZTMP3, %%ZTMP1, 10
        vprold  %%ZTMP4, %%ZTMP1, 18
        vprold  %%ZTMP5, %%ZTMP1, 24
        vprold  %%ZTMP6, %%ZTMP1, 2
        ; ZMM1 = U = L1(P)
        vpternlogq  %%ZTMP1, %%ZTMP3, %%ZTMP4, 0x96 ; (A ^ B) ^ C
        vpternlogq  %%ZTMP1, %%ZTMP5, %%ZTMP6, 0x96 ; (A ^ B) ^ C

        vprold  %%ZTMP3, %%ZTMP2, 8
        vprold  %%ZTMP4, %%ZTMP2, 14
        vprold  %%ZTMP5, %%ZTMP2, 22
        vprold  %%ZTMP6, %%ZTMP2, 30
        ; ZMM2 = V = L2(Q)
        vpternlogq  %%ZTMP2, %%ZTMP3, %%ZTMP4, 0x96 ; (A ^ B) ^ C
        vpternlogq  %%ZTMP2, %%ZTMP5, %%ZTMP6, 0x96 ; (A ^ B) ^ C

        ; Shuffle U and V to have all S0 lookups in XMM1 and all S1 lookups in XMM2

        ; Compress all S0 and S1 input values in each register
        ; S0: Bytes 0-7,16-23,32-39,48-55 S1: Bytes 8-15,24-31,40-47,56-63
        vpshufb %%ZTMP1, [rel S0_S1_shuf]
        ; S1: Bytes 0-7,16-23,32-39,48-55 S0: Bytes 8-15,24-31,40-47,56-63
        vpshufb %%ZTMP2, [rel S1_S0_shuf]

        vshufpd %%ZTMP3, %%ZTMP1, %%ZTMP2, 0xAA ; All S0 input values
        vshufpd %%ZTMP4, %%ZTMP2, %%ZTMP1, 0xAA ; All S1 input values

        ; Compute S0 and S1 values
        S0_comput_AVX512  %%ZTMP3, %%ZTMP1, %%ZTMP2, USE_GFNI_VAES_VPCLMUL
        S1_comput_AVX512  %%ZTMP4, %%ZTMP1, %%ZTMP2, %%ZTMP5, %%ZTMP6, USE_GFNI_VAES_VPCLMUL

        ; Need to shuffle back %%ZTMP1 & %%ZTMP2 before storing output
        ; (revert what was done before S0 and S1 computations)
        vshufpd %%ZTMP1, %%ZTMP3, %%ZTMP4, 0xAA
        vshufpd %%ZTMP2, %%ZTMP4, %%ZTMP3, 0xAA

        vpshufb %%R1, %%ZTMP1, [rel rev_S0_S1_shuf]
        vpshufb %%R2, %%ZTMP2, [rel rev_S1_S0_shuf]
%endmacro

;
; Function to store 64 bytes of keystream for 16 buffers
; Note: all the 64*16 bytes are not store contiguously,
;       the first 256 bytes (containing 64 bytes from 4 buffers)
;       are stored in the first half of the first 512 bytes,
;       then there is a gap of 256 bytes and then the next 256 bytes
;       are written, and so on.
;
%macro  STORE_KSTR16 18-25
%define %%KS          %1  ; [in] Pointer to keystream
%define %%DATA64B_L0  %2  ; [in] 64 bytes of keystream for lane 0
%define %%DATA64B_L1  %3  ; [in] 64 bytes of keystream for lane 1
%define %%DATA64B_L2  %4  ; [in] 64 bytes of keystream for lane 2
%define %%DATA64B_L3  %5  ; [in] 64 bytes of keystream for lane 3
%define %%DATA64B_L4  %6  ; [in] 64 bytes of keystream for lane 4
%define %%DATA64B_L5  %7  ; [in] 64 bytes of keystream for lane 5
%define %%DATA64B_L6  %8  ; [in] 64 bytes of keystream for lane 6
%define %%DATA64B_L7  %9  ; [in] 64 bytes of keystream for lane 7
%define %%DATA64B_L8  %10 ; [in] 64 bytes of keystream for lane 8
%define %%DATA64B_L9  %11 ; [in] 64 bytes of keystream for lane 9
%define %%DATA64B_L10 %12 ; [in] 64 bytes of keystream for lane 10
%define %%DATA64B_L11 %13 ; [in] 64 bytes of keystream for lane 11
%define %%DATA64B_L12 %14 ; [in] 64 bytes of keystream for lane 12
%define %%DATA64B_L13 %15 ; [in] 64 bytes of keystream for lane 13
%define %%DATA64B_L14 %16 ; [in] 64 bytes of keystream for lane 14
%define %%DATA64B_L15 %17 ; [in] 64 bytes of keystream for lane 15
%define %%KEY_OFF     %18 ; [in] Offset to start writing Keystream
%define %%LANE_MASK   %19 ; [in] Lane mask with lanes to generate all keystream words
%define %%ALIGN_MASK  %20 ; [in] Address with alignr masks
%define %%MOV_MASK    %21 ; [in] Address with move masks
%define %%TMP         %22 ; [in] Temporary GP register
%define %%KMASK1      %23 ; [clobbered] Temporary K mask
%define %%KMASK2      %24 ; [clobbered] Temporary K mask
%define %%SKIP_ROUNDS %25 ; [constant] Number of rounds to skip (1, 2 or 4)

%if (%0 == 18)
        vmovdqu64 [%%KS + %%KEY_OFF*4], %%DATA64B_L0
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 64], %%DATA64B_L1
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 2*64], %%DATA64B_L2
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 3*64], %%DATA64B_L3

        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512], %%DATA64B_L4
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512 + 64], %%DATA64B_L5
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512 + 2*64], %%DATA64B_L6
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512 + 3*64], %%DATA64B_L7

        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512*2], %%DATA64B_L8
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512*2 + 64], %%DATA64B_L9
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512*2 + 64*2], %%DATA64B_L10
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512*2 + 64*3], %%DATA64B_L11

        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512*3], %%DATA64B_L12
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512*3 + 64], %%DATA64B_L13
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512*3 + 64*2], %%DATA64B_L14
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 512*3 + 64*3], %%DATA64B_L15
%else
        pext      DWORD(%%TMP), DWORD(%%LANE_MASK), [rel extr_bits_0_4_8_12]
        kmovq     %%KMASK1, [%%ALIGN_MASK + 8*%%TMP]
        kmovw     %%KMASK2, [%%MOV_MASK + 2*%%TMP]
        ; Shifting left 4/8/16 bytes of KS for lanes which first 4/8/16 bytes are skipped
%if %%SKIP_ROUNDS == 4
        vmovdqu8 %%DATA64B_L3{%%KMASK1}, %%DATA64B_L2
        vmovdqu8 %%DATA64B_L2{%%KMASK1}, %%DATA64B_L1
        vmovdqu8 %%DATA64B_L1{%%KMASK1}, %%DATA64B_L0
%else
        vpalignr  %%DATA64B_L3{%%KMASK1}, %%DATA64B_L3, %%DATA64B_L2, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L2{%%KMASK1}, %%DATA64B_L2, %%DATA64B_L1, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L1{%%KMASK1}, %%DATA64B_L1, %%DATA64B_L0, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L0{%%KMASK1}, %%DATA64B_L0, %%DATA64B_L3, (16 - %%SKIP_ROUNDS * 4)
%endif
        vmovdqu32 [%%KS + %%KEY_OFF*4]{%%KMASK2}, %%DATA64B_L0
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 64], %%DATA64B_L1
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 2*64], %%DATA64B_L2
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 3*64], %%DATA64B_L3

        pext      DWORD(%%TMP), DWORD(%%LANE_MASK), [rel extr_bits_1_5_9_13]
        kmovq     %%KMASK1, [%%ALIGN_MASK + 8*%%TMP]
        kmovw     %%KMASK2, [%%MOV_MASK + 2*%%TMP]
%if %%SKIP_ROUNDS == 4
        vmovdqu8 %%DATA64B_L7{%%KMASK1}, %%DATA64B_L6
        vmovdqu8 %%DATA64B_L6{%%KMASK1}, %%DATA64B_L5
        vmovdqu8 %%DATA64B_L5{%%KMASK1}, %%DATA64B_L4
%else
        vpalignr  %%DATA64B_L7{%%KMASK1}, %%DATA64B_L7, %%DATA64B_L6, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L6{%%KMASK1}, %%DATA64B_L6, %%DATA64B_L5, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L5{%%KMASK1}, %%DATA64B_L5, %%DATA64B_L4, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L4{%%KMASK1}, %%DATA64B_L4, %%DATA64B_L7, (16 - %%SKIP_ROUNDS * 4)
%endif
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512]{%%KMASK2}, %%DATA64B_L4
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512 + 64], %%DATA64B_L5
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512 + 64*2], %%DATA64B_L6
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512 + 64*3], %%DATA64B_L7

        pext      DWORD(%%TMP), DWORD(%%LANE_MASK), [rel extr_bits_2_6_10_14]
        kmovq     %%KMASK1, [%%ALIGN_MASK + 8*%%TMP]
        kmovw     %%KMASK2, [%%MOV_MASK + 2*%%TMP]
%if %%SKIP_ROUNDS == 4
        vmovdqu8 %%DATA64B_L11{%%KMASK1}, %%DATA64B_L10
        vmovdqu8 %%DATA64B_L10{%%KMASK1}, %%DATA64B_L9
        vmovdqu8 %%DATA64B_L9{%%KMASK1}, %%DATA64B_L8
%else
        vpalignr  %%DATA64B_L11{%%KMASK1}, %%DATA64B_L11, %%DATA64B_L10, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L10{%%KMASK1}, %%DATA64B_L10, %%DATA64B_L9, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L9{%%KMASK1}, %%DATA64B_L9, %%DATA64B_L8, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L8{%%KMASK1}, %%DATA64B_L8, %%DATA64B_L11, (16 - %%SKIP_ROUNDS * 4)
%endif
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512*2]{%%KMASK2}, %%DATA64B_L8
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512*2 + 64], %%DATA64B_L9
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512*2 + 64*2], %%DATA64B_L10
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512*2 + 64*3], %%DATA64B_L11

        pext      DWORD(%%TMP), DWORD(%%LANE_MASK), [rel extr_bits_3_7_11_15]
        kmovq     %%KMASK1, [%%ALIGN_MASK + 8*%%TMP]
        kmovw     %%KMASK2, [%%MOV_MASK + 2*%%TMP]
%if %%SKIP_ROUNDS == 4
        vmovdqu8 %%DATA64B_L15{%%KMASK1}, %%DATA64B_L14
        vmovdqu8 %%DATA64B_L14{%%KMASK1}, %%DATA64B_L13
        vmovdqu8 %%DATA64B_L13{%%KMASK1}, %%DATA64B_L12
%else
        vpalignr  %%DATA64B_L15{%%KMASK1}, %%DATA64B_L15, %%DATA64B_L14, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L14{%%KMASK1}, %%DATA64B_L14, %%DATA64B_L13, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L13{%%KMASK1}, %%DATA64B_L13, %%DATA64B_L12, (16 - %%SKIP_ROUNDS * 4)
        vpalignr  %%DATA64B_L12{%%KMASK1}, %%DATA64B_L12, %%DATA64B_L15, (16 - %%SKIP_ROUNDS * 4)
%endif
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512*3]{%%KMASK2}, %%DATA64B_L12
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512*3 + 64], %%DATA64B_L13
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512*3 + 64*2], %%DATA64B_L14
        vmovdqu32 [%%KS + %%KEY_OFF*4 + 512*3 + 64*3], %%DATA64B_L15
%endif
%endmacro

;
; Function to store 64 bytes of keystream for 4 buffers
; Note: all the 64*4 bytes are not store contiguously.
;       Each 64 bytes are stored every 512 bytes, being written in
;       qword index 0, 1, 2 or 3 inside the 512 bytes, depending on the lane.
%macro  STORE_KSTR4 7
%define %%KS          %1  ; [in] Pointer to keystream
%define %%DATA64B_L0  %2  ; [in] 64 bytes of keystream for lane 0
%define %%DATA64B_L1  %3  ; [in] 64 bytes of keystream for lane 1
%define %%DATA64B_L2  %4  ; [in] 64 bytes of keystream for lane 2
%define %%DATA64B_L3  %5  ; [in] 64 bytes of keystream for lane 3
%define %%KEY_OFF     %6  ; [in] Offset to start writing Keystream
%define %%LANE_GROUP  %7  ; [immediate] 0, 1, 2 or 3

        vmovdqu64 [%%KS + %%KEY_OFF*4 + 64*%%LANE_GROUP], %%DATA64B_L0
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 64*%%LANE_GROUP + 512], %%DATA64B_L1
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 64*%%LANE_GROUP + 512*2], %%DATA64B_L2
        vmovdqu64 [%%KS + %%KEY_OFF*4 + 64*%%LANE_GROUP + 512*3], %%DATA64B_L3
%endmacro

;
; Add two 32-bit args and reduce mod (2^31-1)
;
%macro  ADD_MOD31 4
%define %%IN_OUT        %1 ; [in/out] ZMM register with first input and output
%define %%IN2           %2 ; [in] ZMM register with second input
%define %%ZTMP          %3 ; [clobbered] Temporary ZMM register
%define %%MASK31        %4 ; [in] ZMM register containing 0x7FFFFFFF's in all dwords

        vpaddd  %%IN_OUT, %%IN2
        vpsrld  %%ZTMP, %%IN_OUT, 31
        vpandq  %%IN_OUT, %%MASK31
        vpaddd  %%IN_OUT, %%ZTMP
%endmacro

;
; Rotate (mult by pow of 2) 32-bit arg and reduce mod (2^31-1)
;
%macro  ROT_MOD31   4
%define %%IN_OUT        %1 ; [in/out] ZMM register with input and output
%define %%ZTMP          %2 ; [clobbered] Temporary ZMM register
%define %%MASK31        %3 ; [in] ZMM register containing 0x7FFFFFFF's in all dwords
%define %%N_BITS        %4 ; [immediate] Number of bits to rotate for each dword

        vpslld     %%ZTMP, %%IN_OUT, %%N_BITS
        vpsrld     %%IN_OUT, %%IN_OUT, (31 - %%N_BITS)
        vpternlogq %%IN_OUT, %%ZTMP, %%MASK31, 0xA8 ; (A | B) & C
%endmacro

;
; Update LFSR registers, calculating S_16
;
; S_16 = [ 2^15*S_15 + 2^17*S_13 + 2^21*S_10 + 2^20*S_4 + (1 + 2^8)*S_0 ] mod (2^31 - 1)
; If init mode, add W to the calculation above.
; S_16 -> S_15 for next round
;
%macro  LFSR_UPDT16  12
%define %%STATE     %1  ; [in] ZUC state
%define %%ROUND_NUM %2  ; [in] Round number
%define %%LANE_MASK %3  ; [in] Mask register with lanes to update
%define %%LFSR_0    %4  ; [clobbered] LFSR_0
%define %%LFSR_4    %5  ; [clobbered] LFSR_2
%define %%LFSR_10   %6  ; [clobbered] LFSR_5
%define %%LFSR_13   %7  ; [clobbered] LFSR_7
%define %%LFSR_15   %8  ; [clobbered] LFSR_9
%define %%ZTMP      %9  ; [clobbered] Temporary ZMM register
%define %%MASK_31   %10 ; [in] Mask_31
%define %%W         %11 ; [in/clobbered] In init mode, contains W for all 16 lanes
%define %%MODE      %12 ; [constant] "init" / "work" mode

        vmovdqa64 %%LFSR_0,  [%%STATE + (( 0 + %%ROUND_NUM) % 16)*64]
        vmovdqa64 %%LFSR_4,  [%%STATE + (( 4 + %%ROUND_NUM) % 16)*64]
        vmovdqa64 %%LFSR_10, [%%STATE + ((10 + %%ROUND_NUM) % 16)*64]
        vmovdqa64 %%LFSR_13, [%%STATE + ((13 + %%ROUND_NUM) % 16)*64]
        vmovdqa64 %%LFSR_15, [%%STATE + ((15 + %%ROUND_NUM) % 16)*64]

        ; Calculate LFSR feedback (S_16)

        ; In Init mode, W is added to the S_16 calculation
%ifidn %%MODE, init
        ADD_MOD31 %%W, %%LFSR_0, %%ZTMP, %%MASK_31
%else
        vmovdqa64 %%W, %%LFSR_0
%endif
        ROT_MOD31 %%LFSR_0, %%ZTMP, %%MASK_31, 8
        ADD_MOD31 %%W, %%LFSR_0, %%ZTMP, %%MASK_31
        ROT_MOD31 %%LFSR_4, %%ZTMP, %%MASK_31, 20
        ADD_MOD31 %%W, %%LFSR_4, %%ZTMP, %%MASK_31
        ROT_MOD31 %%LFSR_10, %%ZTMP, %%MASK_31, 21
        ADD_MOD31 %%W, %%LFSR_10, %%ZTMP, %%MASK_31
        ROT_MOD31 %%LFSR_13, %%ZTMP, %%MASK_31, 17
        ADD_MOD31 %%W, %%LFSR_13, %%ZTMP, %%MASK_31
        ROT_MOD31 %%LFSR_15, %%ZTMP, %%MASK_31, 15
        ADD_MOD31 %%W, %%LFSR_15, %%ZTMP, %%MASK_31

        vmovdqa32 [%%STATE + (( 0 + %%ROUND_NUM) % 16)*64]{%%LANE_MASK}, %%W

        ; LFSR_S16 = (LFSR_S15++) = eax
%endmacro

;
; Initialize LFSR registers for a single lane, for ZUC-128
;
; From spec, s_i (LFSR) registers need to be loaded as follows:
;
; For 0 <= i <= 15, let s_i= k_i || d_i || iv_i.
; Where k_i is each byte of the key, d_i is a 15-bit constant
; and iv_i is each byte of the IV.
;
%macro INIT_LFSR_128 4
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

;
; Initialize LFSR registers for a single lane, for ZUC-256
;
%macro INIT_LFSR_256 11
%define %%KEY         %1 ;; [in] Key pointer
%define %%IV          %2 ;; [in] IV pointer
%define %%LFSR        %3 ;; [out] ZMM register to contain initialized LFSR regs
%define %%ZTMP1       %4 ;; [clobbered] ZMM temporary register
%define %%ZTMP2       %5 ;; [clobbered] ZMM temporary register
%define %%ZTMP3       %6 ;; [clobbered] ZMM temporary register
%define %%ZTMP4       %7 ;; [clobbered] ZMM temporary register
%define %%ZTMP5       %8 ;; [clobbered] ZMM temporary register
%define %%SHIFT_MASK  %9 ;; [in] Mask register to shift K_31
%define %%IV_MASK    %10 ;; [in] Mask register to read IV (last 10 bytes)
%define %%TAG_SIZE   %11 ;; [in] Tag size (0, 4, 8 or 16 bytes)

%if %%TAG_SIZE == 0
%define %%CONSTANTS rel EK256_d64
%elif %%TAG_SIZE == 4
%define %%CONSTANTS rel EK256_EIA3_4
%elif %%TAG_SIZE == 8
%define %%CONSTANTS rel EK256_EIA3_8
%elif %%TAG_SIZE == 16
%define %%CONSTANTS rel EK256_EIA3_16
%endif
        vmovdqu8        XWORD(%%ZTMP4){%%IV_MASK}, [%%IV + 16]
        ; Zero out first 2 bits of IV bytes 17-24
        vpandq          XWORD(%%ZTMP4), [rel iv_mask_low_6]
        vshufi32x4      %%ZTMP4, %%ZTMP4, 0
        vbroadcasti64x2 %%ZTMP1, [%%KEY]
        vbroadcasti64x2 %%ZTMP2, [%%KEY + 16]
        vbroadcasti64x2 %%ZTMP3, [%%IV]

        vpshufb         %%ZTMP5, %%ZTMP1, [rel shuf_mask_key256_first_high]
        vpshufb         %%LFSR, %%ZTMP3, [rel shuf_mask_iv256_first_high]
        vporq           %%LFSR, %%ZTMP5
        vpsrld          %%LFSR, 1

        vpshufb         %%ZTMP5, %%ZTMP2, [rel shuf_mask_key256_second]
        vpsrld          %%ZTMP5{%%SHIFT_MASK}, 4
        vpandq          %%ZTMP5, [rel key_mask_low_4]

        vpshufb         %%ZTMP1, [rel shuf_mask_key256_first_low]
        vpshufb         %%ZTMP3, [rel shuf_mask_iv256_first_low]
        vpshufb         %%ZTMP4, [rel shuf_mask_iv256_second]

        vpternlogq      %%LFSR, %%ZTMP5, %%ZTMP1, 0xFE
        vpternlogq      %%LFSR, %%ZTMP3, %%ZTMP4, 0xFE

        vporq           %%LFSR, [%%CONSTANTS]
%endmacro

%macro INIT_16_AVX512 8-9
%define %%KEY           %1 ; [in] Array of 16 key pointers
%define %%IV            %2 ; [in] Array of 16 IV pointers
%define %%STATE         %3 ; [in] State
%define %%LANE_MASK     %4 ; [in] Mask register with lanes to update
%define %%TMP           %5 ; [clobbered] Temporary GP register
%define %%TMP2          %6 ; [clobbered] Temporary GP register
%define %%KEY_SIZE      %7 ; [in] Key size (128 or 256)
%define %%TAG_SIZE      %8 ; [in] Tag size (0, 4, 8 or 16 bytes)
%define %%TAGS          %9 ; [in] Array of temporary tags

%define %%TMP           r14
%define %%TMP2          r15

%define %%ZTMP1  zmm0
%define %%ZTMP2  zmm1
%define %%ZTMP3  zmm2
%define %%ZTMP4  zmm3
%define %%ZTMP5  zmm4
%define %%ZTMP6  zmm5
%define %%ZTMP7  zmm6
%define %%ZTMP8  zmm7
%define %%ZTMP9  zmm8
%define %%ZTMP10 zmm9
%define %%ZTMP11 zmm10
%define %%ZTMP12 zmm11
%define %%ZTMP13 zmm12
%define %%ZTMP14 zmm13
%define %%ZTMP15 zmm14
%define %%ZTMP16 zmm15

%define %%LFSR1  zmm16
%define %%LFSR2  zmm17
%define %%LFSR3  zmm18
%define %%LFSR4  zmm19
%define %%LFSR5  zmm20
%define %%LFSR6  zmm21
%define %%LFSR7  zmm22
%define %%LFSR8  zmm23
%define %%LFSR9  zmm24
%define %%LFSR10 zmm25
%define %%LFSR11 zmm26
%define %%LFSR12 zmm27
%define %%LFSR13 zmm28
%define %%LFSR14 zmm29
%define %%LFSR15 zmm30
%define %%LFSR16 zmm31

%define %%X0     %%ZTMP10
%define %%X1     %%ZTMP11
%define %%X2     %%ZTMP12
%define %%W      %%ZTMP13
%define %%R1     %%ZTMP14
%define %%R2     %%ZTMP15
%define %%MASK31 %%ZTMP16

%define %%KSTR1 zmm16
%define %%KSTR2 zmm17
%define %%KSTR3 zmm18
%define %%KSTR4 zmm19

%define %%BLEND_KMASK     k1 ; Mask to blend LFSRs 14&15
%define %%INIT_LANE_KMASK k2 ; Mask containing lanes to initialize
%define %%SHIFT_KMASK     k3 ; Mask to shift 4 bytes only in the 15th dword
%define %%IV_KMASK        k4 ; Mask to read 10 bytes of IV

%define %%TMP_KMASK1      k3
%define %%TMP_KMASK2      k4
%define %%TMP_KMASK3      k5
%define %%TMP_KMASK4      k6

        kmovw   %%INIT_LANE_KMASK, DWORD(%%LANE_MASK)

%if %%KEY_SIZE == 256
        mov    %%TMP, 0x4000 ; Mask to shift 4 bits only in the 15th dword
        kmovq  %%SHIFT_KMASK, %%TMP
        mov    %%TMP, 0x3ff ; Mask to read 10 bytes of IV
        kmovq  %%IV_KMASK, %%TMP
%endif

        ; Set LFSR registers for Packets 1-16
%assign %%IDX 0
%assign %%LFSR_IDX 1
%rep 16
        mov     %%TMP, [pKe + 8*%%IDX]  ; Load Key N pointer
        lea     %%TMP2, [pIv + 32*%%IDX] ; Load IV N pointer
%if %%KEY_SIZE == 128
        INIT_LFSR_128 %%TMP, %%TMP2, APPEND(%%LFSR, %%LFSR_IDX), %%ZTMP1
%else
        INIT_LFSR_256 %%TMP, %%TMP2, APPEND(%%LFSR, %%LFSR_IDX), %%ZTMP1, \
                      %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                      %%SHIFT_KMASK, %%IV_KMASK, %%TAG_SIZE
%endif
%assign %%IDX (%%IDX + 1)
%assign %%LFSR_IDX (%%LFSR_IDX + 1)
%endrep

        ; Store LFSR registers in memory (reordering first, so all S0 regs
        ; are together, then all S1 regs... until S15)
        TRANSPOSE16_U32 %%LFSR1, %%LFSR2, %%LFSR3, %%LFSR4, %%LFSR5, %%LFSR6, %%LFSR7, %%LFSR8, \
                        %%LFSR9, %%LFSR10, %%LFSR11, %%LFSR12, %%LFSR13, %%LFSR14, %%LFSR15, %%LFSR16, \
                        %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                        %%ZTMP9, %%ZTMP10, %%ZTMP11, %%ZTMP12, %%ZTMP13, %%ZTMP14

%assign %%IDX 0
%assign %%LFSR_IDX 1
%rep 16
        vmovdqa32 [pState + 64*%%IDX]{%%INIT_LANE_KMASK}, APPEND(%%LFSR, %%LFSR_IDX)
%assign %%IDX (%%IDX+1)
%assign %%LFSR_IDX (%%LFSR_IDX+1)
%endrep

        ; Load read-only registers
        vmovdqa64  %%MASK31, [rel mask31]
        mov        DWORD(%%TMP), 0xAAAAAAAA
        kmovd      %%BLEND_KMASK, DWORD(%%TMP)

        ; Zero out R1, R2
        vpxorq  %%R1, %%R1
        vpxorq  %%R2, %%R2

    ; Shift LFSR 32-times, update state variables
%assign %%N 0
%rep 32
        BITS_REORG16 %%STATE, %%N, %%INIT_LANE_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                     %%ZTMP7, %%ZTMP8, %%ZTMP9, %%BLEND_KMASK, %%X0, %%X1, %%X2
        NONLIN_FUN16 %%STATE, %%INIT_LANE_KMASK, %%X0, %%X1, %%X2, %%R1, %%R2, \
                     %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%W
        vpsrld  %%W, 1         ; Shift out LSB of W

        LFSR_UPDT16  %%STATE, %%N, %%INIT_LANE_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                     %%ZTMP6, %%MASK31, %%W, init  ; W used in LFSR update
%assign %%N (%%N + 1)
%endrep

        ; And once more, initial round from keygen phase = 33 times
        BITS_REORG16 %%STATE, 0, %%INIT_LANE_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, \
                     %%ZTMP8, %%ZTMP9, %%BLEND_KMASK, %%X0, %%X1, %%X2
        NONLIN_FUN16 %%STATE, %%INIT_LANE_KMASK, %%X0, %%X1, %%X2, %%R1, %%R2, \
                     %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6

        LFSR_UPDT16  %%STATE, 0, %%INIT_LANE_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                     %%ZTMP6, %%MASK31, %%W, work

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
        BITS_REORG16 %%STATE, %%N, %%INIT_LANE_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                     %%ZTMP7, %%ZTMP8, %%ZTMP9, %%BLEND_KMASK, %%X0, %%X1, %%X2, APPEND(%%KSTR, %%N)
        NONLIN_FUN16 %%STATE, %%INIT_LANE_KMASK, %%X0, %%X1, %%X2, %%R1, %%R2, \
                     %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%W
        ; OFS_X3 XOR W
        vpxorq      APPEND(%%KSTR, %%N), %%W
        LFSR_UPDT16  %%STATE, %%N, %%INIT_LANE_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                     %%ZTMP6, %%MASK31, %%ZTMP7, work
%assign %%N %%N+1
%endrep

        ; Update R1, R2
        vmovdqa32   [%%STATE + OFS_R1]{%%INIT_LANE_KMASK}, %%R1
        vmovdqa32   [%%STATE + OFS_R2]{%%INIT_LANE_KMASK}, %%R2

        ; Transpose (if needed) the keystream generated and store it
        ; for each lane as their initial digest
%if %%TAG_SIZE == 4
        vmovdqa32 [%%TAGS]{%%INIT_LANE_KMASK}, %%KSTR1
        REORDER_LFSR %%STATE, 1, %%INIT_LANE_KMASK
%elif %%TAG_SIZE == 8
        mov     DWORD(%%TMP), 0xff
        kmovd   %%TMP_KMASK1, DWORD(%%TMP)
        kandd   %%TMP_KMASK1, %%TMP_KMASK1, %%INIT_LANE_KMASK ; First 8 lanes
        kshiftrd %%TMP_KMASK2, %%INIT_LANE_KMASK, 8 ; Second 8 lanes
        vmovdqa64 %%ZTMP1, [rel idx_tags_64_0_7]
        vmovdqa64 %%ZTMP2, [rel idx_tags_64_8_15]
        vpermi2d  %%ZTMP1, %%KSTR1, %%KSTR2
        vpermi2d  %%ZTMP2, %%KSTR1, %%KSTR2
        vmovdqa64 [%%TAGS]{%%TMP_KMASK1}, %%ZTMP1
        vmovdqa64 [%%TAGS + 64]{%%TMP_KMASK2}, %%ZTMP2
        REORDER_LFSR %%STATE, 2, %%INIT_LANE_KMASK
%elif %%TAG_SIZE == 16
        lea     %%TMP, [rel expand_mask]
        kmovd   DWORD(%%TMP2), %%INIT_LANE_KMASK
        and     DWORD(%%TMP2), 0xf
        kmovb   %%TMP_KMASK1, [%%TMP + %%TMP2] ; First 4 lanes
        kmovd   DWORD(%%TMP2), %%INIT_LANE_KMASK
        shr     DWORD(%%TMP2), 4
        and     DWORD(%%TMP2), 0xf
        kmovb   %%TMP_KMASK2, [%%TMP + %%TMP2] ; Second 4 lanes

        kmovd   DWORD(%%TMP2), %%INIT_LANE_KMASK
        shr     DWORD(%%TMP2), 8
        and     DWORD(%%TMP2), 0xf
        kmovb   %%TMP_KMASK3, [%%TMP + %%TMP2] ; Third 4 lanes
        kmovd   DWORD(%%TMP2), %%INIT_LANE_KMASK
        shr     DWORD(%%TMP2), 12
        kmovb   %%TMP_KMASK4, [%%TMP + %%TMP2] ; Fourth 4 lanes

        TRANSPOSE4_U32 %%KSTR1, %%KSTR2, %%KSTR3, %%KSTR4, \
                       %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                       %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                       %%ZTMP9, %%ZTMP10, %%ZTMP11, %%ZTMP12
        vmovdqa64 [%%TAGS]{%%TMP_KMASK1}, %%KSTR1
        vmovdqa64 [%%TAGS + 64]{%%TMP_KMASK2}, %%KSTR2
        vmovdqa64 [%%TAGS + 64*2]{%%TMP_KMASK3}, %%KSTR3
        vmovdqa64 [%%TAGS + 64*3]{%%TMP_KMASK4}, %%KSTR4
        REORDER_LFSR %%STATE, 4, %%INIT_LANE_KMASK
%endif

%endmacro ; INIT_16_AVX512

;;
;; void asm_ZucInitialization_16_avx512(ZucKey16_t *pKeys, ZucIv16_t *pIvs,
;;                                      ZucState16_t *pState,
;;                                      const uint64_t lane_mask)
;;
MKGLOBAL(ZUC128_INIT,function,internal)
ZUC128_INIT:
%define pKe             arg1
%define pIv             arg2
%define pState          arg3
%define lane_mask       arg4

        endbranch64

        FUNC_SAVE

        INIT_16_AVX512 pKe, pIv, pState, lane_mask, r12, r13, 128, 0

        FUNC_RESTORE

        ret

;;
;; void asm_Zuc256Initialization_16_avx512(ZucKey16_t *pKeys, ZucIv16_t *pIvs,
;;                                         ZucState16_t *pState,
;;                                         const uint64_t lane_mask,
;;                                         const uint32_t tag_sz,
;;                                         void *tags)
;;
MKGLOBAL(ZUC256_INIT,function,internal)
ZUC256_INIT:
%define pKe             arg1
%define pIv             arg2
%define pState          arg3
%define lane_mask       arg4
%define tag_sz          r10
%define tags            r11

        endbranch64

        or      tag_sz, tag_sz
        jz      init_for_cipher

        cmp     tag_sz, 8
        je      init_for_auth_tag_8B
        jb      init_for_auth_tag_4B

init_for_auth_tag_16B:
        FUNC_SAVE

        INIT_16_AVX512 pKe, pIv, pState, lane_mask, r12, r13, 256, 16, tags

        FUNC_RESTORE

        ret

init_for_cipher:
        FUNC_SAVE

        INIT_16_AVX512 pKe, pIv, pState, lane_mask, r12, r13, 256, 0, tags

        FUNC_RESTORE

        ret

init_for_auth_tag_4B:
        FUNC_SAVE

        INIT_16_AVX512 pKe, pIv, pState, lane_mask, r12, r13, 256, 4, tags

        FUNC_RESTORE

        ret

init_for_auth_tag_8B:
        FUNC_SAVE

        INIT_16_AVX512 pKe, pIv, pState, lane_mask, r12, r13, 256, 8, tags

        FUNC_RESTORE

        ret

;
; Generate N*4 bytes of keystream
; for 16 buffers (where N is number of rounds)
;
%macro KEYGEN_16_AVX512 3-4
%define %%NUM_ROUNDS    %1 ; [in] Number of 4-byte rounds
%define %%KEY_OFF       %2 ; [in] Offset to start writing Keystream
%define %%SKIP_ROUNDS   %3 ; [constant] Number of rounds to skip (1, 2 or 4)
%define %%LANE_MASK     %4 ; [in] Lane mask with lanes to generate all keystream words

%define pState  arg1
%define pKS     arg2

%define %%TMP1  r10
%define %%TMP2  r12
%define %%TMP3  r13

%define %%ZTMP1  zmm0
%define %%ZTMP2  zmm1
%define %%ZTMP3  zmm2
%define %%ZTMP4  zmm3
%define %%ZTMP5  zmm4
%define %%ZTMP6  zmm5
%define %%ZTMP7  zmm6
%define %%ZTMP8  zmm7
%define %%ZTMP9  zmm8
%define %%ZTMP10 zmm9
%define %%ZTMP11 zmm10
%define %%ZTMP12 zmm11
%define %%ZTMP13 zmm12
%define %%ZTMP14 zmm13
%define %%ZTMP15 zmm14
%define %%ZTMP16 zmm15

%define %%KSTR1  zmm16
%define %%KSTR2  zmm17
%define %%KSTR3  zmm18
%define %%KSTR4  zmm19
%define %%KSTR5  zmm20
%define %%KSTR6  zmm21
%define %%KSTR7  zmm22
%define %%KSTR8  zmm23
%define %%KSTR9  zmm24
%define %%KSTR10 zmm25
%define %%KSTR11 zmm26
%define %%KSTR12 zmm27
%define %%KSTR13 zmm28
%define %%KSTR14 zmm29
%define %%KSTR15 zmm30
%define %%KSTR16 zmm31

%define %%X0     %%ZTMP10
%define %%X1     %%ZTMP11
%define %%X2     %%ZTMP12
%define %%W      %%ZTMP13
%define %%R1     %%ZTMP14
%define %%R2     %%ZTMP15
%define %%MASK31 %%ZTMP16

%define %%BLEND_KMASK     k1 ; Mask to blend LFSRs 14&15
%define %%FULL_LANE_KMASK k2 ; Mask with lanes to generate all keystream words
%define %%ALL_KMASK       k3 ; Mask with all 1's
%define %%SKIP_LANE_KMASK k4 ; Mask with lanes to skip some keystream words
%define %%TMP_KMASK1      k5
%define %%TMP_KMASK2      k6

        ; Load read-only registers
        vmovdqa64   %%MASK31, [rel mask31]
        mov         DWORD(%%TMP1), 0xAAAAAAAA
        kmovd       %%BLEND_KMASK, DWORD(%%TMP1)

%if (%0 == 4)
        kmovd       %%FULL_LANE_KMASK, DWORD(%%LANE_MASK)
        knotd       %%SKIP_LANE_KMASK, %%FULL_LANE_KMASK
        mov         DWORD(%%TMP1), 0x0000FFFF
        kmovd       %%ALL_KMASK, DWORD(%%TMP1)
%else
        mov         DWORD(%%TMP1), 0x0000FFFF
        kmovd       %%FULL_LANE_KMASK, DWORD(%%TMP1)
        kmovd       %%ALL_KMASK, %%FULL_LANE_KMASK
%endif

        ; Read R1/R2
        vmovdqa32   %%R1, [pState + OFS_R1]
        vmovdqa32   %%R2, [pState + OFS_R2]

        ; Store all 4 bytes of keystream in a single 64-byte buffer
%if (%%NUM_ROUNDS <= %%SKIP_ROUNDS)
        BITS_REORG16 pState, 1, %%FULL_LANE_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                     %%ZTMP7, %%ZTMP8, %%ZTMP9, %%BLEND_KMASK, %%X0, %%X1, %%X2, %%KSTR1
        NONLIN_FUN16 pState, %%FULL_LANE_KMASK, %%X0, %%X1, %%X2, %%R1, %%R2, \
                     %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%W
        ; OFS_X3 XOR W
        vpxorq  %%KSTR1, %%W
        LFSR_UPDT16  pState, 1, %%FULL_LANE_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                     %%ZTMP6, %%MASK31, %%ZTMP7, work
        vmovdqa32    [pState + OFS_R1]{%%FULL_LANE_KMASK}, %%R1
        vmovdqa32    [pState + OFS_R2]{%%FULL_LANE_KMASK}, %%R2
%else ;; %%NUM_ROUNDS > %%SKIP_ROUNDS
        ; Generate N*4B of keystream in N rounds
        ; Generate first bytes of KS for all lanes
%assign %%N 1
%assign %%IDX 1
%rep (%%NUM_ROUNDS-%%SKIP_ROUNDS)
        BITS_REORG16 pState, %%N, %%ALL_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                     %%ZTMP7, %%ZTMP8, %%ZTMP9, %%BLEND_KMASK, %%X0, %%X1, %%X2, APPEND(%%KSTR, %%IDX)
        NONLIN_FUN16 pState, %%ALL_KMASK, %%X0, %%X1, %%X2, %%R1, %%R2, \
                     %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%W
        ; OFS_X3 XOR W
        vpxorq      APPEND(%%KSTR, %%IDX), %%W
        LFSR_UPDT16  pState, %%N, %%ALL_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                     %%ZTMP6, %%MASK31, %%ZTMP7, work
%assign %%N %%N+1
%assign %%IDX (%%IDX + 1)
%endrep
%if (%%NUM_ROUNDS > %%SKIP_ROUNDS)
        vmovdqa32   [pState + OFS_R1]{%%ALL_KMASK}, %%R1
        vmovdqa32   [pState + OFS_R2]{%%ALL_KMASK}, %%R2
%endif

       ; Generate rest of the KS bytes (last 8 bytes) for selected lanes
%rep %%SKIP_ROUNDS
        BITS_REORG16 pState, %%N, %%FULL_LANE_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                     %%ZTMP7, %%ZTMP8, %%ZTMP9, %%BLEND_KMASK, %%X0, %%X1, %%X2, APPEND(%%KSTR, %%IDX)
        NONLIN_FUN16 pState, %%FULL_LANE_KMASK, %%X0, %%X1, %%X2, %%R1, %%R2, \
                     %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%W
        ; OFS_X3 XOR W
        vpxorq       APPEND(%%KSTR, %%IDX), %%W
        LFSR_UPDT16  pState, %%N, %%FULL_LANE_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                     %%ZTMP6, %%MASK31, %%ZTMP7, work
%assign %%N %%N+1
%assign %%IDX (%%IDX + 1)
%endrep
        vmovdqa32   [pState + OFS_R1]{%%FULL_LANE_KMASK}, %%R1
        vmovdqa32   [pState + OFS_R2]{%%FULL_LANE_KMASK}, %%R2
%endif ;; (%%NUM_ROUNDS == 1)

        ; Perform a 32-bit 16x16 transpose to have up to 64 bytes
        ; (NUM_ROUNDS * 4B) of each lane in a different register
        TRANSPOSE16_U32_INTERLEAVED %%KSTR1, %%KSTR2, %%KSTR3, %%KSTR4, %%KSTR5, %%KSTR6, %%KSTR7, %%KSTR8, \
                        %%KSTR9, %%KSTR10, %%KSTR11, %%KSTR12, %%KSTR13, %%KSTR14, %%KSTR15, %%KSTR16, \
                        %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                        %%ZTMP9, %%ZTMP10

%if (%0 == 4)
        lea         %%TMP1, [rel alignr_mask]
%if %%SKIP_ROUNDS == 1
        lea         %%TMP2, [rel mov_4B_mask]
%elif %%SKIP_ROUNDS == 2
        lea         %%TMP2, [rel mov_8B_mask]
%else ; %%SKIP_ROUNDS == 4
        lea         %%TMP2, [rel mov_16B_mask]
%endif
        STORE_KSTR16 pKS, %%ZTMP7, %%ZTMP5, %%KSTR13, %%KSTR1, %%ZTMP8, %%ZTMP6, %%KSTR14, %%KSTR2, \
                     %%ZTMP3, %%ZTMP1, %%KSTR15, %%KSTR3, %%ZTMP4, %%ZTMP2, %%KSTR16, %%KSTR4, %%KEY_OFF, \
                     %%LANE_MASK, %%TMP1, %%TMP2, %%TMP3, %%TMP_KMASK1, %%TMP_KMASK2, %%SKIP_ROUNDS
%else
        STORE_KSTR16 pKS, %%ZTMP7, %%ZTMP5, %%KSTR13, %%KSTR1, %%ZTMP8, %%ZTMP6, %%KSTR14, %%KSTR2, \
                     %%ZTMP3, %%ZTMP1, %%KSTR15, %%KSTR3, %%ZTMP4, %%ZTMP2, %%KSTR16, %%KSTR4, %%KEY_OFF
%endif

        ; Reorder LFSR registers
%if (%0 == 4)
        REORDER_LFSR pState, %%NUM_ROUNDS, %%FULL_LANE_KMASK
%if (%%NUM_ROUNDS >= %%SKIP_ROUNDS)
        REORDER_LFSR pState, (%%NUM_ROUNDS - %%SKIP_ROUNDS), %%SKIP_LANE_KMASK ; 1/2/4 less rounds for "old" buffers
%endif
%else
        REORDER_LFSR pState, %%NUM_ROUNDS, %%FULL_LANE_KMASK
%endif

%endmacro ; KEYGEN_16_AVX512

;;
;; Reverse bits of each byte of a XMM register
;;
%macro REVERSE_BITS 7
%define %%DATA_IN       %1 ; [in] Input data
%define %%DATA_OUT      %2 ; [out] Output data
%define %%TABLE_L       %3 ; [in] Table to shuffle low nibbles
%define %%TABLE_H       %4 ; [in] Table to shuffle high nibbles
%define %%REV_AND_TABLE %5 ; [in] Mask to keep low nibble of each byte
%define %%XTMP1         %6 ; [clobbered] Temporary XMM register
%define %%XTMP2         %7 ; [clobbered] Temporary XMM register

        vpandq   %%XTMP1, %%DATA_IN, %%REV_AND_TABLE

        vpandnq  %%XTMP2, %%REV_AND_TABLE, %%DATA_IN
        vpsrld   %%XTMP2, 4

        vpshufb  %%DATA_OUT, %%TABLE_H, %%XTMP1 ; bit reverse low nibbles (use high table)
        vpshufb  %%XTMP2, %%TABLE_L, %%XTMP2 ; bit reverse high nibbles (use low table)

        vporq    %%DATA_OUT, %%XTMP2
%endmacro

;;
;; Set up data and KS bytes and use PCLMUL to digest data,
;; then the result gets XOR'ed with the previous digest.
;; This macro can be used with XMM (for 1 buffer),
;; YMM (for 2 buffers) or ZMM registers (for 4 buffers).
;; To use it with YMM and ZMM registers, VPCMULQDQ must be
;; supported.
;;
%macro DIGEST_DATA 14-16
%define %%DATA          %1  ; [in] Input data (16 bytes) per buffer
%define %%KS_L          %2  ; [in/clobbered] Lower 16 bytes of KS per buffer
%define %%KS_H          %3  ; [in/clobbered] Higher 16 bytes of KS per buffer
%define %%KS_M1         %4  ; [clobbered] Temporary XMM/YMM/ZMM register
%define %%KS_M2         %5  ; [cloberred] Temporary XMM/YMM/ZMM register
%define %%IN_OUT        %6  ; [in/out] Accumulated digest
%define %%KMASK         %7  ; [in] Shuffle mask register
%define %%TMP1          %8  ; [clobbered] Temporary XMM/YMM/ZMM register
%define %%TMP2          %9  ; [clobbered] Temporary XMM/YMM/ZMM register
%define %%TMP3          %10 ; [clobbered] Temporary XMM/YMM/ZMM register
%define %%TMP4          %11 ; [clobbered] Temporary XMM/YMM/ZMM register
%define %%TMP5          %12 ; [clobbered] Temporary XMM/YMM/ZMM register
%define %%TMP6          %13 ; [clobbered] Temporary XMM/YMM/ZMM register
%define %%TAG_SIZE      %14 ; [constant] Tag size (4, 8 or 16 bytes)
%define %%LANE_GROUP    %15 ; [constant] Lane group (0-3)
%define %%IDX           %16 ; [constant] Index inside lane group (0-3)

%if %0 == 15
%define %%IDX 0
%endif
        ;; Set up KS
        ;;
        ;; KS_L contains bytes 15:0 of KS (for 1, 2 or 4 buffers)
        ;; KS_H contains bytes 31:16 of KS (for 1, 2 or 4 buffers)
        ;; TMP1 to contain bytes in the following order [7:4 11:8 3:0 7:4]
        ;; TMP2 to contain bytes in the following order [15:12 19:16 11:8 15:12]
        vpalignr        %%TMP1, %%KS_H, %%KS_L, 8
%if %%TAG_SIZE != 4 ;; TAG_SIZE == 8 or 16
        vpshufd         %%KS_M2, %%KS_H, 0x61 ; KS bits [191:160 159:128 223:192 191:160]
%endif
%if %%TAG_SIZE == 16
        vpshufd         %%KS_H, %%KS_H, 0xBB ; KS bits [255:224 223:192 255:224 223:192]
%endif
        vpshufd         %%KS_L, %%KS_L, 0x61
        vpshufd         %%KS_M1, %%TMP1, 0x61

        ;; Set up DATA
        ;;
        ;; DATA contains 16 bytes of input data (for 1, 2 or 4 buffers)
        ;; TMP3 to contain bytes in the following order [4*0's 7:4 4*0's 3:0]
        ;; TMP3 to contain bytes in the following order [4*0's 15:12 4*0's 11:8]
        vpshufd         %%TMP1{%%KMASK}{z}, %%DATA, 0x10
        vpshufd         %%TMP2{%%KMASK}{z}, %%DATA, 0x32

        ;; PCMUL the KS's with the DATA
        ;; XOR the results from 4 32-bit words together
        vpclmulqdq      %%TMP3, %%TMP1, %%KS_L, 0x00
        vpclmulqdq      %%TMP4, %%TMP1, %%KS_L, 0x11
        vpclmulqdq      %%TMP5, %%TMP2, %%KS_M1, 0x00
        vpclmulqdq      %%TMP6, %%TMP2, %%KS_M1, 0x11
        vpternlogq      %%TMP5, %%TMP3, %%TMP4, 0x96
%if %%TAG_SIZE == 4
        vpternlogq      %%IN_OUT, %%TMP5, %%TMP6, 0x96
%endif ; %%TAG_SIZE == 4
%if %%TAG_SIZE >= 8
        ; Move previous result to low 32 bits and XOR with previous digest
%if %0 > 14
        vpternlogq      %%TMP5, %%TMP6, [rsp + 256*%%LANE_GROUP + %%IDX*16], 0x96
        vmovdqa64       [rsp + 256*%%LANE_GROUP + %%IDX*16], %%TMP5
%else
        vpxorq          %%TMP5, %%TMP5, %%TMP6
        vpshufb         %%TMP5, %%TMP5, [rel shuf_mask_0_0_0_dw1]
        vpxorq          %%IN_OUT, %%IN_OUT, %%TMP5
%endif

        vpclmulqdq      %%TMP3, %%TMP1, %%KS_L, 0x10
        vpclmulqdq      %%TMP4, %%TMP1, %%KS_M1, 0x01
        vpclmulqdq      %%TMP5, %%TMP2, %%KS_M1, 0x10
        vpclmulqdq      %%TMP6, %%TMP2, %%KS_M2, 0x01

        ; XOR all the products and keep only 32-63 bits
        vpternlogq      %%TMP5, %%TMP3, %%TMP4, 0x96
%if %0 > 14
        vpternlogq      %%TMP5, %%TMP6, [rsp + 256*%%LANE_GROUP + 64 + %%IDX*16], 0x96
        vmovdqa64       [rsp + 256*%%LANE_GROUP + 64 + %%IDX*16], %%TMP5
%else
        vpxorq          %%TMP5, %%TMP5, %%TMP6
        vpandq          %%TMP5, %%TMP5, [rel bits_32_63]

        ; XOR with bits 32-63 of previous digest
        vpxorq          %%IN_OUT, %%TMP5
%endif
%if %%TAG_SIZE == 16
        ; Prepare data and calculate bits 95-64 of tag
        vpclmulqdq      %%TMP3, %%TMP1, %%KS_M1, 0x00
        vpclmulqdq      %%TMP4, %%TMP1, %%KS_M1, 0x11
        vpclmulqdq      %%TMP5, %%TMP2, %%KS_M2, 0x00
        vpclmulqdq      %%TMP6, %%TMP2, %%KS_M2, 0x11

        ; XOR all the products and move bits 63-32 to bits 95-64
        vpternlogq      %%TMP5, %%TMP3, %%TMP4, 0x96
%if %0 > 14
        vpternlogq      %%TMP5, %%TMP6, [rsp + 256*%%LANE_GROUP + 64*2 + %%IDX*16], 0x96
        vmovdqa64       [rsp + 256*%%LANE_GROUP + 64*2 + %%IDX*16], %%TMP5
%else
        vpxorq          %%TMP5, %%TMP5, %%TMP6
        vpshufb         %%TMP5, %%TMP5, [rel shuf_mask_0_dw1_0_0]

        ; XOR with previous bits 64-95 of previous digest
        vpxorq          %%IN_OUT, %%TMP5
%endif

        ; Prepare data and calculate bits 127-96 of tag
        vpclmulqdq      %%TMP3, %%TMP1, %%KS_M1, 0x10
        vpclmulqdq      %%TMP4, %%TMP1, %%KS_M2, 0x01
        vpclmulqdq      %%TMP5, %%TMP2, %%KS_M2, 0x10
        vpclmulqdq      %%TMP6, %%TMP2, %%KS_H, 0x01

        ; XOR all the products and move bits 63-32 to bits 127-96
        vpternlogq      %%TMP5, %%TMP3, %%TMP4, 0x96
%if %0 > 14
        vpternlogq      %%TMP5, %%TMP6, [rsp + 256*%%LANE_GROUP + 64*3 + %%IDX*16], 0x96
        vmovdqa64       [rsp + 256*%%LANE_GROUP + 64*3 + %%IDX*16], %%TMP5
%else
        vpxorq          %%TMP5, %%TMP5, %%TMP6
        vpshufb         %%TMP5, %%TMP5, [rel shuf_mask_dw1_0_0_0]

        ; XOR with lower 96 bits, to construct 128 bits of tag
        vpxorq          %%IN_OUT, %%TMP5
%endif

%endif ; %%TAG_SIZE == 16
%endif ; %%TAG_SIZE >= 8
%endmacro

%macro UPDATE_TAGS 13-14
%define %%T                  %1 ; [in] Pointer to digests
%define %%TAG_SIZE           %2 ; [constant] Tag size (4, 8 or 16 bytes)
%define %%ORDER_TAGS         %3 ; [constant] Order of tags (order_0_4_8_12 or order_0_1_2_3)
%define %%TMP                %4 ; [clobbered] Temporary GP register
%define %%PERM_DIGEST_KMASK1 %5 ; [clobbered] Permutation mask for digests
%define %%PERM_DIGEST_KMASK2 %6 ; [clobbered] Permulation mask for digests
%define %%DIGEST_0           %7  ; [in/clobbered] Digests for lanes 0,4,8,12 or 0,1,2,3
%define %%DIGEST_1           %8  ; [in] Digests for lanes 1,5,9,13 or 4,5,6,7
%define %%DIGEST_2           %9  ; [in/clobbered] Digests for lanes 2,6,10,14 or 8,9,10,11
%define %%DIGEST_3           %10 ; [in] Digests for lanes 3,7,11,15 or 12,13,14,15
%define %%ZTMP1              %11 ; [clobbered] Temporary ZMM register
%define %%ZTMP2              %12 ; [clobbered] Temporary ZMM register
%define %%ZTMP3              %13 ; [clobbered] Temporary ZMM register
%define %%ZTMP4              %14 ; [clobbered] Temporary ZMM register

%if %%TAG_SIZE == 4
%ifidn %%ORDER_TAGS, order_0_4_8_12
        mov             DWORD(%%TMP), 0x3333
        kmovd           %%PERM_DIGEST_KMASK1, DWORD(%%TMP)
        kshiftld        %%PERM_DIGEST_KMASK2, %%PERM_DIGEST_KMASK1, 2
        vmovdqa64       %%ZTMP2, [rel shuf_mask_4B_tags_0_4_8_12]
        vmovdqa64       %%ZTMP3, [rel shuf_mask_4B_tags_0_4_8_12 + 64]
%else
        mov             DWORD(%%TMP), 0x00FF
        kmovd           %%PERM_DIGEST_KMASK1, DWORD(%%TMP)
        kshiftld        %%PERM_DIGEST_KMASK2, %%PERM_DIGEST_KMASK1, 8
        vmovdqa64       %%ZTMP2, [rel shuf_mask_4B_tags_0_1_2_3]
        vmovdqa64       %%ZTMP3, [rel shuf_mask_4B_tags_0_1_2_3 + 64]
%endif
        ; Get result tags for 16 buffers in different position in each lane
        ; and blend these tags into an ZMM register.
        ; Then, XOR the results with the previous tags and write out the result.
        vpermt2d        %%DIGEST_0{%%PERM_DIGEST_KMASK1}{z}, %%ZTMP2, %%DIGEST_1
        vpermt2d        %%DIGEST_2{%%PERM_DIGEST_KMASK2}{z}, %%ZTMP3, %%DIGEST_3
        vpternlogq      %%DIGEST_0, %%DIGEST_2, [%%T], 0x96 ; A XOR B XOR C
        vmovdqu64       [%%T], %%DIGEST_0

%elif %%TAG_SIZE == 8
%ifidn %%ORDER_TAGS, order_0_4_8_12
        mov             DWORD(%%TMP), 0x33
        kmovd           %%PERM_DIGEST_KMASK1, DWORD(%%TMP)
        kshiftld        %%PERM_DIGEST_KMASK2, %%PERM_DIGEST_KMASK1, 2

        vmovdqa64       %%ZTMP1, [rel shuf_mask_8B_tags_0_1_4_5]
        vmovdqa64       %%ZTMP2, [rel shuf_mask_8B_tags_2_3_6_7]
        vmovdqa64       %%ZTMP3, [rel shuf_mask_8B_tags_8_9_12_13]
        vmovdqa64       %%ZTMP4, [rel shuf_mask_8B_tags_10_11_14_15]

        ; Get result tags for 16 buffers in different positions in each lane
        ; and blend these tags into two ZMM registers
        ; Then, XOR the results with the previous tags and write out the result.

        vpermi2q        %%ZTMP1{%%PERM_DIGEST_KMASK1}{z}, %%DIGEST_0, %%DIGEST_1
        vpermi2q        %%ZTMP2{%%PERM_DIGEST_KMASK2}{z}, %%DIGEST_2, %%DIGEST_3
        vpermi2q        %%ZTMP3{%%PERM_DIGEST_KMASK1}{z}, %%DIGEST_0, %%DIGEST_1
        vpermi2q        %%ZTMP4{%%PERM_DIGEST_KMASK2}{z}, %%DIGEST_2, %%DIGEST_3

        vpternlogq      %%ZTMP1, %%ZTMP2, [%%T], 0x96 ; A XOR B XOR C
        vpternlogq      %%ZTMP3, %%ZTMP4, [%%T + 64], 0x96 ; A XOR B XOR C

%else ; %%ORDER_TAGS == order_0_1_2_3
        vmovdqa64       %%ZTMP3, [rel shuf_mask_8B_tags]
        ; Get result tags for 16 buffers in different position in each lane
        ; and blend these tags into an ZMM register.
        ; Then, XOR the results with the previous tags and write out the result.
        vpermt2q        %%DIGEST_0, %%ZTMP3, %%DIGEST_1
        vpermt2q        %%DIGEST_2, %%ZTMP3, %%DIGEST_3
        vpxorq          %%ZTMP1, %%DIGEST_0, [%%T]
        vpxorq          %%ZTMP3, %%DIGEST_2, [%%T + 64]
%endif
        vmovdqu64       [%%T], %%ZTMP1
        vmovdqu64       [%%T + 64], %%ZTMP3
%else ;; %%TAG_SIZE == 16
%ifidn %%ORDER_TAGS, order_0_4_8_12
        ; Get result tags for 16 buffers in different positions in each lane
        ; from 0,4,8,12 to 0,1,2,3
        ; Then, XOR the results with the previous tags and write out the result.

        TRANSPOSE4_U128_INPLACE %%DIGEST_0, %%DIGEST_1, %%DIGEST_2, %%DIGEST_3, \
                                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4

%endif

        ; XOR with previous tags and store
        vpxorq  %%DIGEST_0, [%%T]
        vpxorq  %%DIGEST_1, [%%T + 64]
        vpxorq  %%DIGEST_2, [%%T + 64*2]
        vpxorq  %%DIGEST_3, [%%T + 64*3]
        vmovdqa64  [%%T], %%DIGEST_0
        vmovdqa64  [%%T + 64], %%DIGEST_1
        vmovdqa64  [%%T + 64*2], %%DIGEST_2
        vmovdqa64  [%%T + 64*3], %%DIGEST_3
%endif ; %%TAG_SIZE
%endmacro
;
; Generate 64 bytes of keystream
; for 16 buffers and authenticate 64 bytes of data
;
%macro ZUC_EIA3_16_64B_AVX512 7
%define %%STATE         %1 ; [in] ZUC state
%define %%KS            %2 ; [in] Pointer to keystream (128x16 bytes)
%define %%T             %3 ; [in] Pointer to digests
%define %%DATA          %4 ; [in] Pointer to array of pointers to data buffers
%define %%LEN           %5 ; [in] Pointer to array of remaining length to digest
%define %%NROUNDS       %6 ; [in/clobbered] Number of rounds of 64 bytes of data to digest
%define %%TAG_SIZE      %7 ; [in] Tag size (4 or 8 bytes)

%define %%TMP           r12
%define %%DATA_ADDR0    rbx
%define %%DATA_ADDR1    r12
%define %%DATA_ADDR2    r13
%define %%DATA_ADDR3    r14
%define %%OFFSET        r15

%define %%DIGEST_0      zmm28
%define %%DIGEST_1      zmm29
%define %%DIGEST_2      zmm30
%define %%DIGEST_3      zmm31

%define %%ZTMP1         zmm1
%define %%ZTMP2         zmm2
%define %%ZTMP3         zmm3
%define %%ZTMP4         zmm4
%define %%ZTMP5         zmm5
%define %%ZTMP6         zmm6
%define %%ZTMP7         zmm7
%define %%ZTMP8         zmm8
%define %%ZTMP9         zmm9
%define %%ZTMP10        zmm0

%define %%ZKS_L         %%ZTMP9
%define %%ZKS_H         zmm21

%define %%XTMP1         xmm1
%define %%XTMP2         xmm2
%define %%XTMP3         xmm3
%define %%XTMP4         xmm4
%define %%XTMP5         xmm5
%define %%XTMP6         xmm6
%define %%XTMP7         xmm7
%define %%XTMP8         xmm8
%define %%XTMP9         xmm9
%define %%XTMP10        xmm0
%define %%KS_L          %%XTMP9
%define %%KS_H          xmm15
%define %%XDIGEST_0     xmm13
%define %%XDIGEST_1     xmm14
%define %%XDIGEST_2     xmm19
%define %%XDIGEST_3     xmm20
%define %%Z_TEMP_DIGEST zmm21
%define %%REV_TABLE_L   xmm16
%define %%REV_TABLE_H   xmm17
%define %%REV_AND_TABLE xmm18

; Defines used in KEYGEN
%define %%MASK31        zmm0

%define %%X0            zmm10
%define %%X1            zmm11
%define %%X2            zmm12
%define %%R1            zmm22
%define %%R2            zmm23

%define %%KS_0          zmm24
%define %%KS_1          zmm25
%define %%KS_2          zmm26
%define %%KS_3          zmm27

%define %%BLEND_KMASK        k1 ; Mask to blend LFSRs 14&15
%define %%ALL_KMASK          k2 ; Mask with all 1's
%define %%SHUF_DATA_KMASK    k3 ; Mask to shuffle data
%define %%TMP_KMASK1         k4
%define %%TMP_KMASK2         k5

%if %%TAG_SIZE != 4
        mov     %%TMP, rsp
        ; Reserve stack space to store temporary digest products
        sub     rsp, STACK_SPACE
        and     rsp, ~63
        mov     [rsp + _RSP], %%TMP

        vpxorq  %%ZTMP1, %%ZTMP1
%assign %%I 0
%rep 16
        vmovdqa64 [rsp + 64*%%I], %%ZTMP1
%assign %%I (%%I + 1)
%endrep
%endif

        xor     %%OFFSET, %%OFFSET

        mov     DWORD(%%TMP), 0xAAAAAAAA
        kmovd   %%BLEND_KMASK, DWORD(%%TMP)

        mov     DWORD(%%TMP), 0x0000FFFF
        kmovd   %%ALL_KMASK, DWORD(%%TMP)

        mov     DWORD(%%TMP), 0x55555555
        kmovd   %%SHUF_DATA_KMASK, DWORD(%%TMP)

%if %%TAG_SIZE == 4
        vpxorq     %%DIGEST_0, %%DIGEST_0
        vpxorq     %%DIGEST_1, %%DIGEST_1
        vpxorq     %%DIGEST_2, %%DIGEST_2
        vpxorq     %%DIGEST_3, %%DIGEST_3
%endif

%if USE_GFNI_VAES_VPCLMUL == 0
        vmovdqa64  %%REV_TABLE_L, [rel bit_reverse_table_l]
        vmovdqa64  %%REV_TABLE_H, [rel bit_reverse_table_h]
        vmovdqa64  %%REV_AND_TABLE, [rel bit_reverse_and_table]
%endif

        ; Read R1/R2
        vmovdqa32   %%R1, [%%STATE + OFS_R1]
        vmovdqa32   %%R2, [%%STATE + OFS_R2]

        ;;
        ;; Generate keystream and digest 64 bytes on each iteration
        ;;
%%_loop:
        ;; Generate 64B of keystream in 16 (4x4) rounds
        ;; N goes from 1 to 16, within two nested reps of 4 iterations
        ;; The outer "rep" loop iterates through 4 groups of lanes (4 buffers each),
        ;; the inner "rep" loop iterates through the data for each group:
        ;; each iteration digests 16 bytes of data (in case of having VPCLMUL
        ;; data from the 4 buffers is digested in one go (using ZMM registers), otherwise,
        ;; data is digested in 4 iterations (using XMM registers)
%assign %%N 1
%assign %%LANE_GROUP 0
%rep 4
        mov             %%DATA_ADDR0, [%%DATA + %%LANE_GROUP*8 + 0*32]
        mov             %%DATA_ADDR1, [%%DATA + %%LANE_GROUP*8 + 1*32]
        mov             %%DATA_ADDR2, [%%DATA + %%LANE_GROUP*8 + 2*32]
        mov             %%DATA_ADDR3, [%%DATA + %%LANE_GROUP*8 + 3*32]

%assign %%idx 0
%rep 4
        ; Load read-only registers
        vmovdqa64   %%MASK31, [rel mask31]

        BITS_REORG16 %%STATE, %%N, %%ALL_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                     %%ZTMP7, %%ZTMP8, %%ZTMP9, %%BLEND_KMASK, %%X0, %%X1, %%X2, APPEND(%%KS_, %%idx)
        NONLIN_FUN16 %%STATE, %%ALL_KMASK, %%X0, %%X1, %%X2, %%R1, %%R2, \
                     %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7
        ; OFS_X3 XOR W (%%ZTMP7)
        vpxorq  APPEND(%%KS_, %%idx), %%ZTMP7
        LFSR_UPDT16  %%STATE, %%N, %%ALL_KMASK, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                      %%ZTMP6, %%MASK31, %%ZTMP7, work

        ;; Transpose and store KS every 16 bytes
%if %%idx == 3
        TRANSPOSE4_U32_INTERLEAVED %%KS_0, %%KS_1, %%KS_2, %%KS_3, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4

        STORE_KSTR4 %%KS, %%KS_0, %%KS_1, %%KS_2, %%KS_3, 64, %%LANE_GROUP
%endif

        ;; Digest next 16 bytes of data for 4 buffers
%if USE_GFNI_VAES_VPCLMUL == 1
        ;; If VPCMUL is available, read chunks of 16x4 bytes of data
        ;; and digest them with 24x4 bytes of KS, then XOR their digest
        ;; with previous digest (with DIGEST_DATA)

        ; Read 4 blocks of 16 bytes of data and put them in a register
        vmovdqu64       %%XTMP1, [%%DATA_ADDR0 + 16*%%idx + %%OFFSET]
        vinserti32x4    %%ZTMP1, [%%DATA_ADDR1 + 16*%%idx + %%OFFSET], 1
        vinserti32x4    %%ZTMP1, [%%DATA_ADDR2 + 16*%%idx + %%OFFSET], 2
        vinserti32x4    %%ZTMP1, [%%DATA_ADDR3 + 16*%%idx + %%OFFSET], 3

        ; Read 8 blocks of 16 bytes of KS
        vmovdqa64       %%ZKS_L, [GET_KS(%%KS, %%LANE_GROUP, %%idx, 0)]
        vmovdqa64       %%ZKS_H, [GET_KS(%%KS, %%LANE_GROUP, (%%idx + 1), 0)]

        ; Reverse bits of next 16 bytes from all 4 buffers
        vgf2p8affineqb  %%ZTMP7, %%ZTMP1, [rel bit_reverse_table], 0x00

        ; Digest 16 bytes of data with 24 bytes of KS, for 4 buffers
        DIGEST_DATA %%ZTMP7, %%ZKS_L, %%ZKS_H, %%ZTMP8, %%ZTMP10, \
                    APPEND(%%DIGEST_, %%LANE_GROUP), %%SHUF_DATA_KMASK, \
                    %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, %%ZTMP6, \
                    %%TAG_SIZE, %%LANE_GROUP

%else ; USE_GFNI_VAES_VPCLMUL == 1
        ;; If VPCMUL is NOT available, read chunks of 16 bytes of data
        ;; and digest them with 24 bytes of KS, and repeat this for 4 different buffers
        ;; then insert these digests into a ZMM register and XOR with previous digest

%assign %%J 0
%rep 4
%if %%TAG_SIZE == 4
%if %%idx == 0
        ; Reset temporary digests (for the first 16 bytes)
        vpxorq  APPEND(%%XDIGEST_, %%J), APPEND(%%XDIGEST_, %%J)
%endif
%endif
        ; Read the next 2 blocks of 16 bytes of KS
        vmovdqa64  %%KS_L, [GET_KS(%%KS, %%LANE_GROUP, %%idx, %%J)]
        vmovdqa64  %%KS_H, [GET_KS(%%KS, %%LANE_GROUP, (%%idx + 1), %%J)]

        ;; read 16 bytes and reverse bits
        vmovdqu64  %%XTMP1, [APPEND(%%DATA_ADDR, %%J) + %%idx*16 + %%OFFSET]
        REVERSE_BITS %%XTMP1, %%XTMP7, %%REV_TABLE_L, %%REV_TABLE_H, \
                     %%REV_AND_TABLE, %%XTMP2, %%XTMP3

        ; Digest 16 bytes of data with 24 bytes of KS, for one buffer
        DIGEST_DATA %%XTMP7, %%KS_L, %%KS_H, %%XTMP8, %%XTMP10, \
                    APPEND(%%XDIGEST_, %%J), %%SHUF_DATA_KMASK, \
                    %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6, %%TAG_SIZE, \
                    %%LANE_GROUP, %%J

        ; Once all 64 bytes of data have been digested, insert them in temporary ZMM register
%if %%TAG_SIZE == 4
%if %%idx == 3
        vinserti32x4 %%Z_TEMP_DIGEST, APPEND(%%XDIGEST_, %%J), %%J
%endif
%endif
%assign %%J (%%J + 1)
%endrep ; %rep 4 %%J

        ; XOR with previous digest
%if %%TAG_SIZE == 4
%if %%idx == 3
        vpxorq  APPEND(%%DIGEST_, %%LANE_GROUP), %%Z_TEMP_DIGEST
%endif
%endif
%endif ;; USE_GFNI_VAES_VPCLMUL == 0
%assign %%idx (%%idx + 1)
%assign %%N %%N+1
%endrep ; %rep 4 %%idx

%assign %%LANE_GROUP (%%LANE_GROUP + 1)
%endrep ; %rep 4 %%LANE_GROUP

%assign %%LANE_GROUP 0
%rep 4
        ; Memcpy KS 64-127 bytes to 0-63 bytes
        vmovdqa64       %%ZTMP3, [%%KS + %%LANE_GROUP*512 + 64*4]
        vmovdqa64       %%ZTMP4, [%%KS + %%LANE_GROUP*512 + 64*5]
        vmovdqa64       %%ZTMP5, [%%KS + %%LANE_GROUP*512 + 64*6]
        vmovdqa64       %%ZTMP6, [%%KS + %%LANE_GROUP*512 + 64*7]
        vmovdqa64       [%%KS + %%LANE_GROUP*512], %%ZTMP3
        vmovdqa64       [%%KS + %%LANE_GROUP*512 + 64], %%ZTMP4
        vmovdqa64       [%%KS + %%LANE_GROUP*512 + 64*2], %%ZTMP5
        vmovdqa64       [%%KS + %%LANE_GROUP*512 + 64*3], %%ZTMP6
%assign %%LANE_GROUP (%%LANE_GROUP + 1)
%endrep ; %rep 4 %%LANE_GROUP

        add     %%OFFSET, 64

        dec     %%NROUNDS
        jnz     %%_loop

        ; Read from stack to extract the products and arrange them to XOR later
        ; against previous digests (only for 8-byte and 16-byte tag)
%if %%TAG_SIZE != 4
%assign %%I 0
%rep 4
        vmovdqa64       %%ZTMP1, [rsp + %%I*256]
        vmovdqa64       %%ZTMP2, [rsp + %%I*256 + 64]
        vpshufb         %%ZTMP1, %%ZTMP1, [rel shuf_mask_0_0_0_dw1]
        vpandq          %%ZTMP2, %%ZTMP2, [rel bits_32_63]
%if %%TAG_SIZE == 16
        vmovdqa64       %%ZTMP3, [rsp + %%I*256 + 64*2]
        vmovdqa64       %%ZTMP4, [rsp + %%I*256 + 64*3]
        vpshufb         %%ZTMP3, %%ZTMP3, [rel shuf_mask_0_dw1_0_0]
        vpshufb         %%ZTMP4, %%ZTMP4, [rel shuf_mask_dw1_0_0_0]
        vpternlogq      %%ZTMP1, %%ZTMP2, %%ZTMP3, 0x96
        vpxorq          APPEND(%%DIGEST_, %%I), %%ZTMP1, %%ZTMP4
%else ; %%TAG_SIZE == 8
        vpxorq          APPEND(%%DIGEST_, %%I), %%ZTMP1, %%ZTMP2
%endif
%assign %%I (%%I + 1)
%endrep
%endif ; %%TAG_SIZE != 4

        UPDATE_TAGS %%T, %%TAG_SIZE, order_0_4_8_12, %%TMP, %%TMP_KMASK1, %%TMP_KMASK2, \
                    %%DIGEST_0, %%DIGEST_1, %%DIGEST_2, %%DIGEST_3, \
                    %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4

        ; Update R1/R2
        vmovdqa64   [%%STATE + OFS_R1], %%R1
        vmovdqa64   [%%STATE + OFS_R2], %%R2

        ; Update data pointers
        vmovdqu64       %%ZTMP1, [%%DATA]
        vmovdqu64       %%ZTMP2, [%%DATA + 64]
        vpbroadcastq    %%ZTMP3, %%OFFSET
        vpaddq          %%ZTMP1, %%ZTMP3
        vpaddq          %%ZTMP2, %%ZTMP3
        vmovdqu64       [%%DATA], %%ZTMP1
        vmovdqu64       [%%DATA + 64], %%ZTMP2

        ; Update array of lengths (if lane is valid, so length < UINT16_MAX)
        vmovdqa64       YWORD(%%ZTMP2), [%%LEN]
        vpcmpw          %%TMP_KMASK1, YWORD(%%ZTMP2), [rel all_ffs], 4 ; valid lanes
        shl             %%OFFSET, 3 ; Convert to bits
        vpbroadcastw    YWORD(%%ZTMP1), DWORD(%%OFFSET)
        vpsubw          YWORD(%%ZTMP2){%%TMP_KMASK1}, YWORD(%%ZTMP1)
        vmovdqa64       [%%LEN], YWORD(%%ZTMP2)

%if %%TAG_SIZE != 4
%ifdef SAFE_DATA
        vpxorq  %%ZTMP1, %%ZTMP1
%assign %%I 0
%rep 16
        vmovdqa64 [rsp + %%I*64], %%ZTMP1
%assign %%I (%%I + 1)
%endrep
%endif

        mov     rsp, [rsp + _RSP]
%endif
%endmacro

;;
;; void asm_ZucGenKeystream64B_16_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                       const u32 key_off)
;;
MKGLOBAL(ZUC_KEYGEN64B_16,function,internal)
ZUC_KEYGEN64B_16:
        endbranch64

        FUNC_SAVE

        KEYGEN_16_AVX512 16, arg3, 0

        FUNC_RESTORE

        ret
;;
;; void asm_Eia3_Nx64B_AVX512_16(ZucState16_t *pState,
;;                               uint32_t *pKeyStr,
;;                               uint32_t *T,
;;                               const void **data,
;;                               uint16_t *len,
;;                               const uint64_t numRounds,
;;                               const uint64_t tag_size);
MKGLOBAL(ZUC_EIA3_N64B,function,internal)
ZUC_EIA3_N64B:
%define STATE         arg1
%define KS            arg2
%define T             arg3
%define DATA          arg4

%ifdef LINUX
%define LEN           arg5
%define NROUNDS       arg6
%else
%define LEN           r10
%define NROUNDS       r11
%endif
%define TAG_SIZE      arg7

        endbranch64

%ifndef LINUX
        mov     LEN, arg5
        mov     NROUNDS, arg6
%endif

        cmp     TAG_SIZE, 8
        je      Eia3_N64B_tag_8B
        ja      Eia3_N64B_tag_16B

        ; Fall-through for 4 bytes
Eia3_N64B_tag_4B:
        FUNC_SAVE

        ZUC_EIA3_16_64B_AVX512 STATE, KS, T, DATA, LEN, NROUNDS, 4

        FUNC_RESTORE

        ret

Eia3_N64B_tag_8B:
        FUNC_SAVE

        ZUC_EIA3_16_64B_AVX512 STATE, KS, T, DATA, LEN, NROUNDS, 8

        FUNC_RESTORE

        ret

Eia3_N64B_tag_16B:
        FUNC_SAVE

        ZUC_EIA3_16_64B_AVX512 STATE, KS, T, DATA, LEN, NROUNDS, 16

        FUNC_RESTORE

        ret

;
;; void asm_ZucGenKeystream64B_16_skip16_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                             const u32 key_off,
;;                                             const u16 lane_mask)
;;
MKGLOBAL(ZUC_KEYGEN64B_SKIP16_16,function,internal)
ZUC_KEYGEN64B_SKIP16_16:
        endbranch64

        FUNC_SAVE

        KEYGEN_16_AVX512 16, arg3, 4, arg4

        FUNC_RESTORE

        ret

;
;; void asm_ZucGenKeystream64B_16_skip8_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                             const u32 key_off,
;;                                             const u16 lane_mask)
;;
MKGLOBAL(ZUC_KEYGEN64B_SKIP8_16,function,internal)
ZUC_KEYGEN64B_SKIP8_16:
        endbranch64

        FUNC_SAVE

        KEYGEN_16_AVX512 16, arg3, 2, arg4

        FUNC_RESTORE

        ret

;; void asm_ZucGenKeystream64B_16_skip4_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                             const u32 key_off,
;;                                             const u16 lane_mask)
;;
MKGLOBAL(ZUC_KEYGEN64B_SKIP4_16,function,internal)
ZUC_KEYGEN64B_SKIP4_16:
        endbranch64

        FUNC_SAVE

        KEYGEN_16_AVX512 16, arg3, 1, arg4

        FUNC_RESTORE

        ret

;;
;; void asm_ZucGenKeystream8B_16_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                      const u32 key_off)
;;
MKGLOBAL(ZUC_KEYGEN8B_16,function,internal)
ZUC_KEYGEN8B_16:
        endbranch64

        FUNC_SAVE

        KEYGEN_16_AVX512 2, arg3, 0

        FUNC_RESTORE

        ret

%macro KEYGEN_VAR_16_AVX512 3-4
%define %%NUM_ROUNDS    %1 ; [in] Number of 4-byte rounds (GP dowrd register)
%define %%KEY_OFF       %2 ; [in] Offset to start writing Keystream
%define %%SKIP_ROUNDS   %3 ; [constant] Number of rounds to skip (1, 2 or 4)
%define %%LANE_MASK     %4 ; [in] Lane mask with lanes to generate full keystream (rest 1-2 words less)

        cmp     %%NUM_ROUNDS, 16
        je      %%_num_rounds_is_16
        cmp     %%NUM_ROUNDS, 8
        je      %%_num_rounds_is_8
        jb      %%_rounds_is_1_7

        ; Final blocks 9-16
        cmp     %%NUM_ROUNDS, 12
        je      %%_num_rounds_is_12
        jb      %%_rounds_is_9_11

        ; Final blocks 13-15
        cmp     %%NUM_ROUNDS, 14
        je      %%_num_rounds_is_14
        ja      %%_num_rounds_is_15
        jb      %%_num_rounds_is_13

%%_rounds_is_9_11:
        cmp     %%NUM_ROUNDS, 10
        je      %%_num_rounds_is_10
        ja      %%_num_rounds_is_11
        jb      %%_num_rounds_is_9

%%_rounds_is_1_7:
        cmp     %%NUM_ROUNDS, 4
        je      %%_num_rounds_is_4
        jb      %%_rounds_is_1_3

        ; Final blocks 5-7
        cmp     %%NUM_ROUNDS, 6
        je      %%_num_rounds_is_6
        ja      %%_num_rounds_is_7
        jb      %%_num_rounds_is_5

%%_rounds_is_1_3:
        cmp     %%NUM_ROUNDS, 2
        je      %%_num_rounds_is_2
        ja      %%_num_rounds_is_3

        ; Rounds = 1 if fall-through
%assign %%I 1
%rep 16
APPEND(%%_num_rounds_is_,%%I):
%if (%0 == 4)
        KEYGEN_16_AVX512 %%I, %%KEY_OFF, %%SKIP_ROUNDS, %%LANE_MASK
%else
        KEYGEN_16_AVX512 %%I, %%KEY_OFF, 0
%endif
        jmp     %%_done

%assign %%I (%%I + 1)
%endrep

%%_done:
%endmacro

;;
;; void asm_ZucGenKeystream_16_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                    const u32 key_off,
;;                                    const u32 numRounds)
;;
MKGLOBAL(ZUC_KEYGEN_16,function,internal)
ZUC_KEYGEN_16:
        endbranch64

        FUNC_SAVE

        KEYGEN_VAR_16_AVX512 arg4, arg3, 0

        FUNC_RESTORE

        ret

;;
;; void asm_ZucGenKeystream_16_skip16_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                          const u32 key_off,
;;                                          const u16 lane_mask,
;;                                          u32 numRounds)
;;
MKGLOBAL(ZUC_KEYGEN_SKIP16_16,function,internal)
ZUC_KEYGEN_SKIP16_16:
        endbranch64

        mov     r10, arg5

        FUNC_SAVE

        KEYGEN_VAR_16_AVX512 r10d, arg3, 4, arg4

        FUNC_RESTORE

        ret
;;
;; void asm_ZucGenKeystream_16_skip8_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                          const u32 key_off,
;;                                          const u16 lane_mask,
;;                                          u32 numRounds)
;;
MKGLOBAL(ZUC_KEYGEN_SKIP8_16,function,internal)
ZUC_KEYGEN_SKIP8_16:
        endbranch64

        mov     r10, arg5

        FUNC_SAVE

        KEYGEN_VAR_16_AVX512 r10d, arg3, 2, arg4

        FUNC_RESTORE

        ret

;;
;; void asm_ZucGenKeystream_16_skip4_avx512(state16_t *pSta, u32* pKeyStr[16],
;;                                          const u32 key_off,
;;                                          const u16 lane_mask,
;;                                          u32 numRounds)
;;
MKGLOBAL(ZUC_KEYGEN_SKIP4_16,function,internal)
ZUC_KEYGEN_SKIP4_16:
        endbranch64

        mov     r10, arg5

        FUNC_SAVE

        KEYGEN_VAR_16_AVX512 r10d, arg3, 1, arg4

        FUNC_RESTORE

        ret

;;
;; Encrypts up to 64 bytes of data
;;
;; 1 - Reads R1 & R2
;; 2 - Generates up to 64 bytes of keystream (16 rounds of 4 bytes)
;; 3 - Writes R1 & R2
;; 4 - Transposes the registers containing chunks of 4 bytes of KS for each buffer
;; 5 - ZMM16-31 will contain 64 bytes of KS for each buffer
;; 6 - Reads 64 bytes of data for each buffer, XOR with KS and writes the ciphertext
;;
%macro CIPHER64B 12
%define %%NROUNDS    %1
%define %%BYTE_MASK  %2
%define %%LANE_MASK  %3
%define %%OFFSET     %4
%define %%LAST_ROUND %5
%define %%MASK_31    %6
%define %%X0         %7
%define %%X1         %8
%define %%X2         %9
%define %%W          %10
%define %%R1         %11
%define %%R2         %12

        ; Read R1/R2
        vmovdqa32   %%R1, [rax + OFS_R1]
        vmovdqa32   %%R2, [rax + OFS_R2]

        ; Generate N*4B of keystream in N rounds
%assign N 1
%assign idx 16
%rep %%NROUNDS
        BITS_REORG16 rax, N, %%LANE_MASK, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, \
                     zmm7, zmm8, zmm9, k1, %%X0, %%X1, %%X2, APPEND(zmm, idx)
        NONLIN_FUN16 rax, %%LANE_MASK, %%X0, %%X1, %%X2, %%R1, %%R2, \
                     zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7
        ; OFS_X3 XOR W (zmm7)
        vpxorq      APPEND(zmm, idx), zmm7
        ; Shuffle bytes within KS words to XOR with plaintext later
        vpshufb APPEND(zmm, idx), [rel swap_mask]
        LFSR_UPDT16  rax, N, %%LANE_MASK, zmm1, zmm2, zmm3, zmm4, zmm5, \
                     zmm6, %%MASK_31, zmm7, work
%assign N (N + 1)
%assign idx (idx + 1)
%endrep
        vmovdqa32   [rax + OFS_R1]{%%LANE_MASK}, %%R1
        vmovdqa32   [rax + OFS_R2]{%%LANE_MASK}, %%R2

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

;;
;; void asm_ZucCipher_16_avx512(state16_t *pSta, u64 *pIn[16],
;;                              u64 *pOut[16], u16 lengths[16],
;;                              u64 min_length);
MKGLOBAL(CIPHER_16,function,internal)
CIPHER_16:

%define pState     arg1
%define pIn        arg2
%define pOut       arg3
%define lengths    arg4

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
loop:
        cmp     min_length, 64
        jl      exit_loop

        vmovdqa64 zmm0, [rel mask31]

        CIPHER64B 16, k2, k3, buf_idx, 0, zmm0, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15

        sub     min_length, 64
        add     buf_idx, 64
        jmp     loop

exit_loop:

        mov     r15, min_length
        add     r15, 3
        shr     r15, 2 ;; numbers of rounds left (round up length to nearest multiple of 4B)
        jz      _no_final_rounds

        vmovdqa64 zmm0, [rel mask31]

        cmp     r15, 8
        je      _num_final_rounds_is_8
        jl      _final_rounds_is_1_7

        ; Final blocks 9-16
        cmp     r15, 12
        je      _num_final_rounds_is_12
        jl      _final_rounds_is_9_11

        ; Final blocks 13-16
        cmp     r15, 16
        je      _num_final_rounds_is_16
        cmp     r15, 15
        je      _num_final_rounds_is_15
        cmp     r15, 14
        je      _num_final_rounds_is_14
        cmp     r15, 13
        je      _num_final_rounds_is_13

_final_rounds_is_9_11:
        cmp     r15, 11
        je      _num_final_rounds_is_11
        cmp     r15, 10
        je      _num_final_rounds_is_10
        cmp     r15, 9
        je      _num_final_rounds_is_9

_final_rounds_is_1_7:
        cmp     r15, 4
        je      _num_final_rounds_is_4
        jl      _final_rounds_is_1_3

        ; Final blocks 5-7
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

        ; Perform encryption of last bytes (<= 64 bytes) and reorder LFSR registers
        ; if needed (if not all 16 rounds of 4 bytes are done)
%assign I 1
%rep 16
APPEND(_num_final_rounds_is_,I):
        CIPHER64B I, k2, k3, buf_idx, 1, zmm0, zmm10, zmm11, zmm12, zmm13, zmm14, zmm15
        REORDER_LFSR rax, I, k3
        add     buf_idx, min_length
        jmp     _no_final_rounds
%assign I (I + 1)
%endrep

_no_final_rounds:
        add             rsp, 32
        ;; update in/out pointers
        add             buf_idx, 3
        and             buf_idx, 0xfffffffffffffffc
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

        ret


;;
;; Updates authentication tag T of 16 buffers based on keystream KS and DATA
;; (GFNI/VAES/VPCLMULQDQ version)
;;
%macro ROUND64B_16_GFNI 11
%define %%T             %1  ; [in] Pointer to digests
%define %%KS            %2  ; [in] Pointer to keystream (128x16 bytes)
%define %%DATA          %3  ; [in] Pointer to array of pointers to data buffers
%define %%LEN           %4  ; [in] Pointer to array of remaining length to digest
%define %%TMP1          %5  ; [clobbered] Temporary GP register
%define %%TMP2          %6  ; [clobbered] Temporary GP register
%define %%TMP3          %7  ; [clobbered] Temporary GP register
%define %%TMP4          %8  ; [clobbered] Temporary GP register
%define %%TMP5          %9  ; [clobbered] Temporary GP register
%define %%TMP6          %10 ; [clobbered] Temporary GP register
%define %%TAG_SIZE      %11 ; [constant] Tag size (4, 8 or 16 bytes)

%define %%SHUF_DATA_KMASK    k1 ; Mask to shuffle data
%define %%TMP_KMASK1         k2
%define %%TMP_KMASK2         k3

%define %%DATA_ADDR0    %%TMP3
%define %%DATA_ADDR1    %%TMP4
%define %%DATA_ADDR2    %%TMP5
%define %%DATA_ADDR3    %%TMP6

%define %%DATA_TRANS0   zmm19
%define %%DATA_TRANS1   zmm20
%define %%DATA_TRANS2   zmm21
%define %%DATA_TRANS3   zmm22
%define %%DATA_TRANS0x  xmm19
%define %%DATA_TRANS1x  xmm20
%define %%DATA_TRANS2x  xmm21
%define %%DATA_TRANS3x  xmm22

%define %%KS_TRANS0     zmm23
%define %%KS_TRANS1     zmm24
%define %%KS_TRANS2     zmm25
%define %%KS_TRANS3     zmm26
%define %%KS_TRANS4     zmm27
%define %%KS_TRANS0x    xmm23
%define %%KS_TRANS1x    xmm24
%define %%KS_TRANS2x    xmm25
%define %%KS_TRANS3x    xmm26
%define %%KS_TRANS4x    xmm27

%define %%DIGEST_0      zmm28
%define %%DIGEST_1      zmm29
%define %%DIGEST_2      zmm30
%define %%DIGEST_3      zmm31

%define %%ZTMP1         zmm0
%define %%ZTMP2         zmm1
%define %%ZTMP3         zmm2
%define %%ZTMP4         zmm3
%define %%ZTMP5         zmm4
%define %%ZTMP6         zmm5
%define %%ZTMP7         zmm6
%define %%ZTMP8         zmm7
%define %%ZTMP9         zmm8

%define %%YTMP1         YWORD(%%ZTMP1)

%if %%TAG_SIZE != 4
        mov             %%TMP1, rsp
        ; Reserve stack space to store temporary digest products
        sub             rsp, STACK_SPACE
        and             rsp, ~63
        mov             [rsp + _RSP], %%TMP1

        vpxorq          %%ZTMP1, %%ZTMP1
%assign %%I 0
%rep 16
        vmovdqa64       [rsp + 64*%%I], %%ZTMP1
%assign %%I (%%I + 1)
%endrep
%endif ; %%TAG_SIZE != 4

        mov             DWORD(%%TMP1), 0x55555555
        kmovd           %%SHUF_DATA_KMASK, DWORD(%%TMP1)
        ;; Read first buffers 0,4,8,12; then 1,5,9,13, and so on,
        ;; since the keystream is laid out this way, with chunks of
        ;; 16 bytes interleaved. First the 128 bytes for
        ;; buffers 0,4,8,12 (total of 512 bytes), then the 128 bytes
        ;; for buffers 1,5,9,13, and so on.
%assign %%IDX 0
%rep 4
%if %%TAG_SIZE == 4
        vpxorq          APPEND(%%DIGEST_, %%IDX), APPEND(%%DIGEST_, %%IDX)
%endif
        mov             %%DATA_ADDR0, [%%DATA + %%IDX*8 + 0*32]
        mov             %%DATA_ADDR1, [%%DATA + %%IDX*8 + 1*32]
        mov             %%DATA_ADDR2, [%%DATA + %%IDX*8 + 2*32]
        mov             %%DATA_ADDR3, [%%DATA + %%IDX*8 + 3*32]

%assign %%I 0
%assign %%J 1
%rep 4
        vmovdqu64       XWORD(APPEND(%%DATA_TRANS, %%I)), [%%DATA_ADDR0 + 16*%%I]
        vinserti32x4    APPEND(%%DATA_TRANS, %%I), [%%DATA_ADDR1 + 16*%%I], 1
        vinserti32x4    APPEND(%%DATA_TRANS, %%I), [%%DATA_ADDR2 + 16*%%I], 2
        vinserti32x4    APPEND(%%DATA_TRANS, %%I), [%%DATA_ADDR3 + 16*%%I], 3

        vmovdqu64       APPEND(%%KS_TRANS, %%I), [%%KS + %%IDX*64*2*4 + 64*%%I]
        vmovdqu64       APPEND(%%KS_TRANS, %%J), [%%KS + %%IDX*64*2*4 + 64*%%J]

        ;; Reverse bits of next 16 bytes from all 4 buffers
        vgf2p8affineqb  %%ZTMP1, APPEND(%%DATA_TRANS,%%I), [rel bit_reverse_table], 0x00

        ; Digest 16 bytes of data with 24 bytes of KS, for 4 buffers
        DIGEST_DATA %%ZTMP1, APPEND(%%KS_TRANS, %%I), APPEND(%%KS_TRANS, %%J), \
                    %%ZTMP8, %%ZTMP9, APPEND(%%DIGEST_, %%IDX), %%SHUF_DATA_KMASK, \
                    %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                    %%ZTMP6, %%ZTMP7, %%TAG_SIZE, %%IDX

%assign %%J (%%J + 1)
%assign %%I (%%I + 1)
%endrep

        ; Memcpy KS 64-127 bytes to 0-63 bytes
        vmovdqa64       %%ZTMP4, [%%KS + %%IDX*4*64*2 + 64*4]
        vmovdqa64       %%ZTMP1, [%%KS + %%IDX*4*64*2 + 64*5]
        vmovdqa64       %%ZTMP2, [%%KS + %%IDX*4*64*2 + 64*6]
        vmovdqa64       %%ZTMP3, [%%KS + %%IDX*4*64*2 + 64*7]
        vmovdqa64       [%%KS + %%IDX*4*64*2], %%ZTMP4
        vmovdqa64       [%%KS + %%IDX*4*64*2 + 64], %%ZTMP1
        vmovdqa64       [%%KS + %%IDX*4*64*2 + 64*2], %%ZTMP2
        vmovdqa64       [%%KS + %%IDX*4*64*2 + 64*3], %%ZTMP3

%assign %%IDX (%%IDX + 1)
%endrep

        ; Read from stack to extract the products and arrange them to XOR later
        ; against previous digests (only for 8-byte and 16-byte tag)
%if %%TAG_SIZE != 4
%assign %%I 0
%rep 4
        vmovdqa64       %%ZTMP1, [rsp + %%I*256]
        vmovdqa64       %%ZTMP2, [rsp + %%I*256 + 64]
        vpshufb         %%ZTMP1, %%ZTMP1, [rel shuf_mask_0_0_0_dw1]
        vpandq          %%ZTMP2, %%ZTMP2, [rel bits_32_63]
%if %%TAG_SIZE == 16
        vmovdqa64       %%ZTMP3, [rsp + %%I*256 + 64*2]
        vmovdqa64       %%ZTMP4, [rsp + %%I*256 + 64*3]
        vpshufb         %%ZTMP3, %%ZTMP3, [rel shuf_mask_0_dw1_0_0]
        vpshufb         %%ZTMP4, %%ZTMP4, [rel shuf_mask_dw1_0_0_0]
        vpternlogq      %%ZTMP1, %%ZTMP2, %%ZTMP3, 0x96
        vpxorq          APPEND(%%DIGEST_, %%I), %%ZTMP1, %%ZTMP4
%else ; %%TAG_SIZE == 8
        vpxorq          APPEND(%%DIGEST_, %%I), %%ZTMP1, %%ZTMP2
%endif
%assign %%I (%%I + 1)
%endrep
%endif ; %%TAG_SIZE != 4

        UPDATE_TAGS %%T, %%TAG_SIZE, order_0_4_8_12, %%TMP1, %%TMP_KMASK1, %%TMP_KMASK2, \
                    %%DIGEST_0, %%DIGEST_1,  %%DIGEST_2, %%DIGEST_3, \
                    %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4

        ; Update data pointers
        vmovdqu64       %%ZTMP1, [%%DATA]
        vmovdqu64       %%ZTMP2, [%%DATA + 64]
        vpaddq          %%ZTMP1, [rel add_64]
        vpaddq          %%ZTMP2, [rel add_64]
        vmovdqu64       [%%DATA], %%ZTMP1
        vmovdqu64       [%%DATA + 64], %%ZTMP2

        ; Update array of lengths (subtract 512 bits from all lengths if valid lane)
        vmovdqa64       %%YTMP1, [LEN]
        vpcmpw          %%TMP_KMASK1, %%YTMP1, [rel all_ffs], 4
        vpsubw          %%YTMP1{%%TMP_KMASK1}, [rel all_512w]
        vmovdqa64       [%%LEN], %%YTMP1

%if %%TAG_SIZE != 4
%ifdef SAFE_DATA
        vpxorq          %%ZTMP1, %%ZTMP1
%assign %%I 0
%rep 16
        vmovdqa64       [rsp + %%I*64], %%ZTMP1
%assign %%I (%%I + 1)
%endrep
%endif

        mov             rsp, [rsp + _RSP]
%endif ; %%TAG_SIZE != 4
%endmacro


;;
;; Updates authentication tag T of 16 buffers based on keystream KS and DATA.
;;
%macro ROUND64B_16_NO_GFNI 11
%define %%T             %1  ; [in] Pointer to digests
%define %%KS            %2  ; [in] Pointer to keystream (128x16 bytes)
%define %%DATA          %3  ; [in] Pointer to array of pointers to data buffers
%define %%LEN           %4  ; [in] Pointer to array of remaining length to digest
%define %%TMP1          %5  ; [clobbered] Temporary GP register
%define %%TMP2          %6  ; [clobbered] Temporary GP register
%define %%TMP3          %7  ; [clobbered] Temporary GP register
%define %%TMP4          %8  ; [clobbered] Temporary GP register
%define %%TMP5          %9  ; [clobbered] Temporary GP register
%define %%TMP6          %10 ; [clobbered] Temporary GP register
%define %%TAG_SIZE      %11 ; [constant] Tag size (4, 8 or 16 bytes)

%define %%SHUF_DATA_KMASK    k1 ; Mask to shuffle data
%define %%TMP_KMASK1         k2
%define %%TMP_KMASK2         k3

%define %%REV_TABLE_L     xmm0
%define %%REV_TABLE_H     xmm1
%define %%REV_AND_TABLE   xmm2
%define %%TEMP_DIGEST     xmm3
%define %%KS_L            xmm4
%define %%KS_H            xmm5
%define %%XDATA           xmm6
%define %%XTMP1           xmm7
%define %%XTMP2           xmm8
%define %%XTMP3           xmm9
%define %%XTMP4           xmm10
%define %%XTMP5           xmm11
%define %%XTMP6           xmm12
%define %%XTMP7           xmm13
%define %%XTMP8           xmm14

%define %%ZTMP1           zmm22
%define %%ZTMP2           zmm23
%define %%ZTMP3           zmm24
%define %%ZTMP4           zmm25
%define %%DIGEST_0        zmm28
%define %%DIGEST_1        zmm29
%define %%DIGEST_2        zmm30
%define %%DIGEST_3        zmm31

%define %%YTMP1           ymm24

%define %%DATA_ADDR       %%TMP3

%if %%TAG_SIZE != 4
        mov             %%TMP1, rsp
        ; Reserve stack space to store temporary digest products
        sub             rsp, STACK_SPACE
        and             rsp, ~63
        mov             [rsp + _RSP], %%TMP1

        vpxorq          %%ZTMP1, %%ZTMP1
%assign %%I 0
%rep 16
        vmovdqa64       [rsp + 64*%%I], %%ZTMP1
%assign %%I (%%I + 1)
%endrep
%endif ; %%TAG_SIZE != 4

        vmovdqa  %%REV_TABLE_L, [rel bit_reverse_table_l]
        vmovdqa  %%REV_TABLE_H, [rel bit_reverse_table_h]
        vmovdqa  %%REV_AND_TABLE, [rel bit_reverse_and_table]

        mov      DWORD(%%TMP1), 0x55555555
        kmovd    %%SHUF_DATA_KMASK, DWORD(%%TMP1)

        ;; Read first buffers 0,4,8,12; then 1,5,9,13, and so on,
        ;; since the keystream is laid out this way, which chunks of
        ;; 16 bytes interleved. First the 128 bytes for
        ;; buffers 0,4,8,12 (total of 512 bytes), then the 128 bytes
        ;; for buffers 1,5,9,13, and so on
%assign %%I 0
%rep 4
%assign %%J 0
%rep 4

%if %%TAG_SIZE == 4
        vpxor   %%TEMP_DIGEST, %%TEMP_DIGEST
%endif
        mov     %%DATA_ADDR, [%%DATA + 8*(%%J*4 + %%I)]

%assign %%K 0
%rep 4
        ;; read 16 bytes and reverse bits
        vmovdqu  %%XTMP1, [%%DATA_ADDR + 16*%%K]
        vpand    %%XTMP2, %%XTMP1, %%REV_AND_TABLE

        vpandn   %%XTMP3, %%REV_AND_TABLE, %%XTMP1
        vpsrld   %%XTMP3, 4

        vpshufb  %%XDATA, %%REV_TABLE_H, %%XTMP2 ; bit reverse low nibbles (use high table)
        vpshufb  %%XTMP4, %%REV_TABLE_L, %%XTMP3 ; bit reverse high nibbles (use low table)

        vpor     %%XDATA, %%XDATA, %%XTMP4 ; %%DATA - bit reversed data bytes

        ; Read the next 2 blocks of 16 bytes of KS
        vmovdqu  %%KS_L, [%%KS + (16*%%J + %%I*512) + %%K*(16*4)]
        vmovdqu  %%KS_H, [%%KS + (16*%%J + %%I*512) + (%%K + 1)*(16*4)]
        ; Digest 16 bytes of data with 24 bytes of KS, for 4 buffers
        DIGEST_DATA %%XDATA, %%KS_L, %%KS_H, %%XTMP7, %%XTMP8, %%TEMP_DIGEST, %%SHUF_DATA_KMASK, \
                    %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6, %%TAG_SIZE, %%I, %%J

%assign %%K (%%K + 1)
%endrep

        vinserti32x4 APPEND(%%DIGEST_, %%I), %%TEMP_DIGEST, %%J
%assign %%J (%%J + 1)
%endrep
        ; Memcpy KS 64-127 bytes to 0-63 bytes
        vmovdqa64       %%ZTMP1, [%%KS + %%I*4*64*2 + 64*4]
        vmovdqa64       %%ZTMP2, [%%KS + %%I*4*64*2 + 64*5]
        vmovdqa64       %%ZTMP3, [%%KS + %%I*4*64*2 + 64*6]
        vmovdqa64       %%ZTMP4, [%%KS + %%I*4*64*2 + 64*7]
        vmovdqa64       [%%KS + %%I*4*64*2], %%ZTMP1
        vmovdqa64       [%%KS + %%I*4*64*2 + 64], %%ZTMP2
        vmovdqa64       [%%KS + %%I*4*64*2 + 64*2], %%ZTMP3
        vmovdqa64       [%%KS + %%I*4*64*2 + 64*3], %%ZTMP4
%assign %%I (%%I + 1)
%endrep

        ; Read from stack to extract the products and arrange them to XOR later
        ; against previous digests (only for 8-byte and 16-byte tag)
%if %%TAG_SIZE != 4
%assign %%I 0
%rep 4
        vmovdqa64       %%ZTMP1, [rsp + %%I*256]
        vmovdqa64       %%ZTMP2, [rsp + %%I*256 + 64]
        vpshufb         %%ZTMP1, %%ZTMP1, [rel shuf_mask_0_0_0_dw1]
        vpandq          %%ZTMP2, %%ZTMP2, [rel bits_32_63]
%if %%TAG_SIZE == 16
        vmovdqa64       %%ZTMP3, [rsp + %%I*256 + 64*2]
        vmovdqa64       %%ZTMP4, [rsp + %%I*256 + 64*3]
        vpshufb         %%ZTMP3, %%ZTMP3, [rel shuf_mask_0_dw1_0_0]
        vpshufb         %%ZTMP4, %%ZTMP4, [rel shuf_mask_dw1_0_0_0]
        vpternlogq      %%ZTMP1, %%ZTMP2, %%ZTMP3, 0x96
        vpxorq          APPEND(%%DIGEST_, %%I), %%ZTMP1, %%ZTMP4
%else ; %%TAG_SIZE == 8
        vpxorq          APPEND(%%DIGEST_, %%I), %%ZTMP1, %%ZTMP2
%endif
%assign %%I (%%I + 1)
%endrep
%endif ; %%TAG_SIZE != 4
        UPDATE_TAGS %%T, %%TAG_SIZE, order_0_4_8_12, %%TMP1, %%TMP_KMASK1, %%TMP_KMASK2, \
                    %%DIGEST_0, %%DIGEST_1,  %%DIGEST_2, %%DIGEST_3, \
                    %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4

        ; Update data pointers
        vmovdqu64       %%ZTMP2, [%%DATA]
        vmovdqu64       %%ZTMP3, [%%DATA + 64]
        vpaddq          %%ZTMP2, [rel add_64]
        vpaddq          %%ZTMP3, [rel add_64]
        vmovdqu64       [%%DATA], %%ZTMP2
        vmovdqu64       [%%DATA + 64], %%ZTMP3

        ; Update array of lengths (if lane is valid, so length < UINT16_MAX)
        vmovdqa64       %%YTMP1, [%%LEN]
        vpcmpw          %%TMP_KMASK1, %%YTMP1, [rel all_ffs], 4 ; valid lanes
        vpsubw          %%YTMP1{%%TMP_KMASK1}, [rel all_512w]
        vmovdqa64       [%%LEN], %%YTMP1

%if %%TAG_SIZE != 4
%ifdef SAFE_DATA
        vpxorq          %%ZTMP1, %%ZTMP1
%assign %%I 0
%rep 16
        vmovdqa64       [rsp + %%I*64], %%ZTMP1
%assign %%I (%%I + 1)
%endrep
%endif

        mov             rsp, [rsp + _RSP]
%endif ; %%TAG_SIZE != 4
%endmacro

;;
;;extern void asm_Eia3Round64B_16(void *T, const void *KS,
;;                                const void **DATA, uint16_t *LEN);
;;
;; Updates authentication tag T of 16 buffers based on keystream KS and DATA.
;; - it processes 64 bytes of DATA of buffers
;; - reads data in 16 byte chunks from different buffers
;;   (first buffers 0,4,8,12; then 1,5,9,13; etc) and bit reverses them
;; - reads KS (when utilizing VPCLMUL instructions, it reads 64 bytes directly,
;;   containing 16 bytes of KS for 4 different buffers)
;; - employs clmul for the XOR & ROL part
;; - copies top 64 bytes of KS to bottom (for the next round)
;; - Updates Data pointers for next rounds
;; - Updates array of lengths
;;
;;  @param [in] T: Array of digests for all 16 buffers
;;  @param [in] KS: Pointer to 128 bytes of keystream for all 16 buffers (2048 bytes in total)
;;  @param [in] DATA: Array of pointers to data for all 16 buffers
;;  @param [in] LEN: Array of lengths for all 16 buffers
;;  @param [in] TAG_SZ: Tag size (4, 8 or 16 bytes)
;;
align 64
MKGLOBAL(ZUC_ROUND64B_16,function,internal)
ZUC_ROUND64B_16:
%define T         arg1
%define KS        arg2
%define DATA      arg3
%define LEN       arg4
%define TAG_SIZE  arg5

        endbranch64

        cmp     TAG_SIZE, 8
        je      round_8B
        jb      round_4B

        ;; Fall-through for 16-byte tag
round_16B:

        FUNC_SAVE

%if USE_GFNI_VAES_VPCLMUL == 1
        ROUND64B_16_GFNI T, KS, DATA, LEN, rbx, r10, r11, r12, r13, r14, 16
%else
        ROUND64B_16_NO_GFNI T, KS, DATA, LEN, rbx, r10, r11, r12, r13, r14, 16
%endif

        FUNC_RESTORE

        ret

round_8B:

        FUNC_SAVE

%if USE_GFNI_VAES_VPCLMUL == 1
        ROUND64B_16_GFNI T, KS, DATA, LEN, rbx, r10, r11, r12, r13, r14, 8
%else
        ROUND64B_16_NO_GFNI T, KS, DATA, LEN, rbx, r10, r11, r12, r13, r14, 8
%endif

        FUNC_RESTORE

        ret
round_4B:

        FUNC_SAVE

%if USE_GFNI_VAES_VPCLMUL == 1
        ROUND64B_16_GFNI T, KS, DATA, LEN, rbx, r10, r11, r12, r13, r14, 4
%else
        ROUND64B_16_NO_GFNI T, KS, DATA, LEN, rbx, r10, r11, r12, r13, r14, 4
%endif

        FUNC_RESTORE

        ret


;
; Reads a qword of KS, rotates it by LEN % 32, and store the results as a single dword
;
%macro READ_AND_ROTATE_KS_DWORD 4
%define %%KS_ADDR          %1 ; [in] Base address of KS to read
%define %%LEN_BUF          %2 ; [in] Remaining bytes of data
%define %%IN_OFFSET_OUT_KS %3 ; [in/out] Offset to read qwords of KS
%define %%TMP1             %4 ; [clobbered] Temporary GP register

        mov     %%TMP1, %%IN_OFFSET_OUT_KS
        and     %%TMP1, 0xf
        ; Read last two dwords of KS, which can be scattered or contiguous
        ; (First dword can be at the end of a 16-byte chunk)
        cmp     %%TMP1, 12
        je      %%_read_2dwords
        mov     %%IN_OFFSET_OUT_KS, [%%KS_ADDR + %%IN_OFFSET_OUT_KS]
        jmp     %%_ks_qword_read

        ;; The 8 bytes of %%KS are separated
%%_read_2dwords:
        mov     DWORD(%%TMP1), [%%KS_ADDR + %%IN_OFFSET_OUT_KS]
        mov     DWORD(%%IN_OFFSET_OUT_KS), [%%KS_ADDR + %%IN_OFFSET_OUT_KS + (4+48)]
        shl     %%IN_OFFSET_OUT_KS, 32
        or      %%IN_OFFSET_OUT_KS, %%TMP1
%%_ks_qword_read:
        ; Rotate left by MIN_LEN % 32
        mov     %%TMP1, rcx
        mov     rcx, %%LEN_BUF
        and     rcx, 0x1F
        rol     %%IN_OFFSET_OUT_KS, cl
        mov     rcx, %%TMP1
%endmacro
;
; Reads two qwords of KS, overlapped by 4 bytes (e.g. KS[0-7] and KS[4-11]),
; rotates both qwords by LEN % 32, and store the results as a single qword,
; where lower dword is the result of rotation on first qword, and upper dword
; is the rotation on second dword.
;
%macro READ_AND_ROTATE_KS_QWORD 5
%define %%KS_ADDR          %1 ; [in] Base address of KS to read
%define %%LEN_BUF          %2 ; [in] Remaining bytes of data
%define %%IN_OFFSET_OUT_KS %3 ; [in/out] Offset to read qwords of KS
%define %%TMP1             %4 ; [clobbered] Temporary GP register
%define %%TMP2             %5 ; [clobbered] Temporary GP register

        mov     %%TMP2, %%IN_OFFSET_OUT_KS
        and     %%TMP2, 0xf
        ; Read last three dwords of KS, which can be scattered or contiguous
        ; (First dword can be at the end of a 16-byte chunk and the other
        ;  two dwords in the next chunk; first two dwords can be at the end of
        ;  a 16-byte chunk and the other dword in the next chunk; or all three
        ;  dwords can be in the same 16-byte chunk)
        cmp     %%TMP2, 8
        je      %%_read_8B_4B
        cmp     %%TMP2, 12
        je      %%_read_4B_8B

        ;; All 12 bytes of KS are contiguous
%%_read_12B:
        mov     %%TMP1, [%%KS_ADDR + %%IN_OFFSET_OUT_KS]
        mov     %%IN_OFFSET_OUT_KS, [%%KS_ADDR + %%IN_OFFSET_OUT_KS + 4]
        jmp     %%_ks_qwords_read

        ;; The first 8 bytes of KS are contiguous, the other 4 are separated
%%_read_8B_4B:
        mov     %%TMP1, [%%KS_ADDR + %%IN_OFFSET_OUT_KS]
        ; Read last 4 bytes of first segment and first 4 bytes of second segment
        mov     DWORD(%%TMP2), [%%KS_ADDR + %%IN_OFFSET_OUT_KS + 4]
        mov     DWORD(%%IN_OFFSET_OUT_KS), [%%KS_ADDR + %%IN_OFFSET_OUT_KS + (8+48)]
        shl     %%IN_OFFSET_OUT_KS, 32
        or      %%IN_OFFSET_OUT_KS, %%TMP2

        jmp     %%_ks_qwords_read
        ;; The first 8 bytes of KS are separated, the other 8 are contiguous
%%_read_4B_8B:
        mov     DWORD(%%TMP1), [%%KS_ADDR + %%IN_OFFSET_OUT_KS]
        mov     DWORD(%%TMP2), [%%KS_ADDR + %%IN_OFFSET_OUT_KS + (4+48)]
        shl     %%TMP2, 32
        or      %%TMP1, %%TMP2
        mov     %%IN_OFFSET_OUT_KS, [%%KS_ADDR + %%IN_OFFSET_OUT_KS + (4+48)]
%%_ks_qwords_read:
        ; Rotate left by LEN_BUF % 32
        mov     %%TMP2, rcx
        mov     rcx, %%LEN_BUF
        and     rcx, 0x1F
        rol     %%TMP1, cl
        rol     %%IN_OFFSET_OUT_KS, cl
        mov     rcx, %%TMP2

        shl     %%IN_OFFSET_OUT_KS, 32
        mov     DWORD(%%TMP1), DWORD(%%TMP1) ; Clear top 32 bits
        or      %%IN_OFFSET_OUT_KS, %%TMP1
%endmacro

%macro REMAINDER_16 14
%define %%T             %1 ; [in] Pointer to digests
%define %%KS            %2 ; [in] Pointer to keystream (128x16 bytes)
%define %%DATA          %3 ; [in] Pointer to array of pointers to data buffers
%define %%LEN           %4 ; [in] Pointer to array of remaining length to digest
%define %%MIN_LEN       %5 ; [in] Minimum common length
%define %%TMP1          %6 ; [clobbered] Temporary GP register
%define %%TMP2          %7 ; [clobbered] Temporary GP register
%define %%TMP3          %8 ; [clobbered] Temporary GP register
%define %%TMP4          %9 ; [clobbered] Temporary GP register
%define %%TMP5          %10 ; [clobbered] Temporary GP register
%define %%TMP6          %11 ; [clobbered] Temporary GP register
%define %%TMP7          %12 ; [clobbered] Temporary GP register
%define %%KEY_SIZE      %13 ; [constant] Key size (128 or 256)
%define %%TAG_SIZE      %14 ; [constant] Tag size (4, 8 or 16 bytes)

%define %%DIGEST_0     zmm28
%define %%DIGEST_1     zmm29
%define %%DIGEST_2     zmm30
%define %%DIGEST_3     zmm31

;;
;; There are two main parts in this code:
;;   - 1st part: digest data
;;   - 2nd part: reading final KS words and XOR'ing with digest
;;
%define %%DATA_ADDR    %%TMP2 ; %%DATA_ADDR only used in 1st part / %%TMP2 only used in 2nd part
%define %%OFFSET       %%TMP3 ; %%OFFSET only used in 1st part / %%TMP3 only used in 2nd part
%define %%KS_ADDR      %%TMP7 ; %%KS_ADDR used in all code
%define %%N_BYTES      %%TMP6 ; %%N_BYTES only  used in 1st part

%define %%LEN_BUF      %%TMP4 ; %%LEN_BUF only used in 2nd part
%define %%IDX          %%TMP5 ; %%IDX Only used in 2nd part
%define %%DIGEST       %%TMP6 ; %%DIGEST only used in 2nd part

%define %%YTMP1         ymm7
%define %%YTMP2         ymm8
%define %%YTMP3         ymm9
%define %%YTMP4         ymm10

%define %%REV_TABLE_L   xmm0
%define %%REV_TABLE_H   xmm1
%define %%REV_AND_TABLE xmm2
%define %%TEMP_DIGEST   xmm3
%define %%KS_L          xmm4
%define %%KS_H          xmm5
%define %%XDATA         xmm6
%define %%XTMP1         xmm7
%define %%XTMP2         xmm8
%define %%XTMP3         xmm9
%define %%XTMP4         xmm10
%define %%XTMP5         xmm11
%define %%XTMP6         xmm12
%define %%XTMP7         xmm13
%define %%XTMP8         xmm14

%define %%ZTMP1         zmm7
%define %%ZTMP2         zmm8
%define %%ZTMP3         zmm9
%define %%ZTMP4         zmm10

%define %%VALID_KMASK        k1 ; Mask with valid lanes
%define %%SHUF_DATA_KMASK    k2 ; Mask to shuffle data
%define %%TMP_KMASK1         k3
%define %%TMP_KMASK2         k4

        vpbroadcastw %%YTMP1, DWORD(%%MIN_LEN)
        ; Get mask of non-NULL lanes (lengths not set to UINT16_MAX, indicating that lane is not valid)
        vmovdqa %%YTMP2, [%%LEN]
        vpcmpw %%VALID_KMASK, %%YTMP2, [rel all_ffs], 4 ; NEQ

        ; Round up to nearest multiple of 32 bits
        vpaddw  %%YTMP1{%%VALID_KMASK}, [rel all_31w]
        vpandq  %%YTMP1, [rel all_ffe0w]

        ; Calculate remaining bits to authenticate after function call
        vpcmpuw %%TMP_KMASK1, %%YTMP2, %%YTMP1, 1 ; Get mask of lengths that will be < 0 after subtracting
        vpsubw  %%YTMP3{%%VALID_KMASK}, %%YTMP2, %%YTMP1
        vpxorq  %%YTMP4, %%YTMP4
        ; Set to zero the lengths of the lanes which are going to be completed
        vmovdqu16 %%YTMP3{%%TMP_KMASK1}, %%YTMP4 ; YMM2 contain final lengths
        vmovdqu16 [%%LEN]{%%VALID_KMASK}, %%YTMP3 ; Update in memory the final updated lengths

        ; Calculate number of bits to authenticate (up to 511 bits),
        ; for each lane, and store it in stack to be used later
        vpsubw  %%YTMP2{%%VALID_KMASK}{z}, %%YTMP3 ; Bits to authenticate in all lanes (zero out length of NULL lanes)
        sub     rsp, 32
        vmovdqu [rsp], %%YTMP2

        xor     %%OFFSET, %%OFFSET

%if USE_GFNI_VAES_VPCLMUL != 1
        vmovdqa  %%REV_TABLE_L, [rel bit_reverse_table_l]
        vmovdqa  %%REV_TABLE_H, [rel bit_reverse_table_h]
        vmovdqa  %%REV_AND_TABLE, [rel bit_reverse_and_table]
%endif

        mov             r12d, 0x55555555
        kmovd           %%SHUF_DATA_KMASK, r12d

        ;; Read first buffers 0,4,8,12; then 1,5,9,13, and so on,
        ;; since the keystream is laid out this way, which chunks of
        ;; 16 bytes interleved. First the 128 bytes for
        ;; buffers 0,4,8,12 (total of 512 bytes), then the 128 bytes
        ;; for buffers 1,5,9,13, and so on
%assign I 0
%rep 4
%assign J 0
%rep 4

        ; Read  length to authenticate for each buffer
        movzx   %%LEN_BUF, word [rsp + 2*(I*4 + J)]

        vpxor   %%TEMP_DIGEST, %%TEMP_DIGEST

        xor     %%OFFSET, %%OFFSET
        mov     %%DATA_ADDR, [%%DATA + 8*(I*4 + J)]

%assign K 0
%rep 4
        cmp     %%LEN_BUF, 128
        jb      APPEND3(%%Eia3RoundsAVX512_dq_end,I,J)

        ;; read 16 bytes and reverse bits
        vmovdqu %%XTMP1, [%%DATA_ADDR + %%OFFSET]
%if USE_GFNI_VAES_VPCLMUL == 1
        vgf2p8affineqb  %%XDATA, %%XTMP1, [rel bit_reverse_table], 0x00
%else
        vpand   %%XTMP2, %%XTMP1, %%REV_AND_TABLE

        vpandn  %%XTMP3, %%REV_AND_TABLE, %%XTMP1
        vpsrld  %%XTMP3, 4

        vpshufb %%XDATA, %%REV_TABLE_H, %%XTMP2 ; bit reverse low nibbles (use high table)
        vpshufb %%XTMP4, %%REV_TABLE_L, %%XTMP3 ; bit reverse high nibbles (use low table)

        vpor    %%XDATA, %%XTMP4
%endif
        ; %%XDATA - bit reversed data bytes

        ; Read the next 2 blocks of 16 bytes of %%KS
        vmovdqu  %%KS_L, [%%KS + (16*I + J*512) + %%OFFSET*4]
        vmovdqu  %%KS_H, [%%KS + (16*I + J*512) + %%OFFSET*4 + (16*4)]
        ; Digest 16 bytes of data with 24 bytes of KS, for 4 buffers
        DIGEST_DATA %%XDATA, %%KS_L, %%KS_H, %%XTMP7, %%XTMP8, %%TEMP_DIGEST, %%SHUF_DATA_KMASK, \
                    %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6, %%TAG_SIZE
        add     %%OFFSET, 16
        sub     %%LEN_BUF, 128
%assign K (K + 1)
%endrep
APPEND3(%%Eia3RoundsAVX512_dq_end,I,J):

        or      %%LEN_BUF, %%LEN_BUF
        jz      APPEND3(%%Eia3RoundsAVX_end,I,J)

        ; Get number of bytes
        mov     %%N_BYTES, %%LEN_BUF
        add     %%N_BYTES, 7
        shr     %%N_BYTES, 3

        lea     %%TMP1, [rel byte64_len_to_mask_table]
        kmovq   %%TMP_KMASK1, [%%TMP1 + %%N_BYTES*8]

        ;; read up to 16 bytes of data, zero bits not needed if partial byte and bit-reverse
        vmovdqu8 %%XTMP1{%%TMP_KMASK1}{z}, [%%DATA_ADDR + %%OFFSET]
        ; check if there is a partial byte (less than 8 bits in last byte)
        mov     %%TMP2, %%LEN_BUF
        and     %%TMP2, 0x7
        shl     %%TMP2, 4
        lea     %%TMP1, [rel bit_mask_table]
        add     %%TMP1, %%TMP2

        ; Get mask to clear last bits
        vmovdqa %%XTMP4, [%%TMP1]

        ; Shift left 16-N bytes to have the last byte always at the end of the XMM register
        ; to apply mask, then restore by shifting right same amount of bytes
        mov     %%TMP1, 16
        sub     %%TMP1, %%N_BYTES
        XVPSLLB %%XTMP1, %%TMP1, %%XTMP5, %%TMP2
        vpandq  %%XTMP1, %%XTMP4
        XVPSRLB %%XTMP1, %%TMP1, %%XTMP5, %%TMP2

%if USE_GFNI_VAES_VPCLMUL == 1
        vgf2p8affineqb  %%XDATA, %%XTMP1, [rel bit_reverse_table], 0x00
%else
        ; Bit reverse input data
        vpand   %%XTMP2, %%XTMP1, %%REV_AND_TABLE

        vpandn  %%XTMP3, %%REV_AND_TABLE, %%XTMP1
        vpsrld  %%XTMP3, 4

        vpshufb %%XDATA, %%REV_TABLE_H, %%XTMP2 ; bit reverse low nibbles (use high table)
        vpshufb %%XTMP4, %%REV_TABLE_L, %%XTMP3 ; bit reverse high nibbles (use low table)

        vpor    %%XDATA, %%XTMP4
%endif

        ; Read the next 2 blocks of 16 bytes of KS
        shl     %%OFFSET, 2
        vmovdqu %%KS_L, [%%KS + (16*I + J*512) + %%OFFSET]
        vmovdqu %%KS_H, [%%KS + (16*I + J*512) + %%OFFSET + 16*4]
        shr     %%OFFSET, 2

        ; Digest 16 bytes of data with 24 bytes of KS, for 4 buffers
        DIGEST_DATA %%XDATA, %%KS_L, %%KS_H, %%XTMP7, %%XTMP8, %%TEMP_DIGEST, %%SHUF_DATA_KMASK, \
                    %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP5, %%XTMP6, %%TAG_SIZE
APPEND3(%%Eia3RoundsAVX_end,I,J):
        vinserti32x4 APPEND(%%DIGEST_, I), %%TEMP_DIGEST, J
%assign J (J + 1)
%endrep
%assign I (I + 1)
%endrep

        UPDATE_TAGS %%T, %%TAG_SIZE, order_0_1_2_3, %%TMP1, %%TMP_KMASK1, %%TMP_KMASK2, \
                    %%DIGEST_0, %%DIGEST_1,  %%DIGEST_2, %%DIGEST_3, \
                    %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4

        ; These last steps should be done only for the buffers that
        ; have no more data to authenticate
        xor     %%IDX, %%IDX
%%start_loop:
        ; Update data pointer
        movzx   DWORD(%%TMP1), word [rsp + %%IDX*2]
        shr     DWORD(%%TMP1), 3 ; length authenticated in bytes
        add     [%%DATA + %%IDX*8], %%TMP1

        cmp     word [%%LEN + 2*%%IDX], 0
        jnz     %%skip_comput

        ; Load base address of keystream for lane %%IDX
        ; Fist, find the offset for the 512-byte set (containing the 128-byte KS for 4 lanes)
        mov     %%TMP1, %%IDX
        and     %%TMP1, 0x3
        shl     %%TMP1, 9 ; * 512

        ; Then, find the offset within the 512-byte set, based on the lane,
        ; and add to the previous offset
        mov     %%TMP2, %%IDX
        shr     %%TMP2, 2
        shl     %%TMP2, 4 ; * 16
        add     %%TMP1, %%TMP2
        ;; Load pointer to the base address of keystream for lane %%IDX
        lea     %%KS_ADDR, [%%KS + %%TMP1]

        ; Read keyStr[MIN_LEN / 32] (last dwords of KS, based on tag_size)
        movzx   %%LEN_BUF, word [rsp + 2*%%IDX]
        mov     %%TMP2, %%LEN_BUF
        shr     %%TMP2, 5
        mov     %%TMP3, %%TMP2
        shr     %%TMP2, 2
        shl     %%TMP2, (4+2)
        and     %%TMP3, 0x3
        shl     %%TMP3, 2
        add     %%TMP2, %%TMP3 ;; Offset to last dwords of KS, from base address
%if %%TAG_SIZE == 4
        ; Read 4-byte digest
        mov     DWORD(%%DIGEST), [%%T + 4*%%IDX]

        READ_AND_ROTATE_KS_DWORD %%KS_ADDR, %%LEN_BUF, %%TMP2, %%TMP1
        ; XOR with current digest
        xor     DWORD(%%DIGEST), DWORD(%%TMP2)

%if %%KEY_SIZE == 128
        ; Read keystr[L - 1] (last dword of keyStr)
        add     %%LEN_BUF, (31 + 64)
        shr     %%LEN_BUF, 5 ; L
        dec     %%LEN_BUF
        mov     %%TMP2, %%LEN_BUF
        shr     %%TMP2, 2
        shl     %%TMP2, (4+2)
        and     %%LEN_BUF, 0x3
        shl     %%LEN_BUF, 2
        add     %%LEN_BUF, %%TMP2
        mov     DWORD(%%TMP2), [%%KS_ADDR + %%LEN_BUF]
        ; XOR with current digest
        xor     DWORD(%%DIGEST), DWORD(%%TMP2)
%endif

        ; byte swap and write digest out
        bswap   DWORD(%%DIGEST)
        mov     [%%T + 4*%%IDX], DWORD(%%DIGEST)
%elif %%TAG_SIZE == 8
        ; Read 8-byte digest
        mov     %%DIGEST, [%%T + 8*%%IDX]

        READ_AND_ROTATE_KS_QWORD %%KS_ADDR, %%LEN_BUF, %%TMP2, %%TMP1, %%TMP3

        ; XOR with current digest
        xor     %%DIGEST, %%TMP2

        ; byte swap and write digest out
        bswap   %%DIGEST
        ror     %%DIGEST, 32
        mov     [%%T + 8*%%IDX], %%DIGEST
%else ; %%TAG_SIZE == 16
        ;; Update digest in two steps:
        ;; - First, read the first 12 bytes of KS[MIN_LEN/32],
        ;;   rotate them and XOR the qword with first qword of digest
        ;; - Last, skip 8 bytes of KS[MIN_LEN/32] and read another 12 bytes,
        ;;   rotate them and XOR the qword with second qword of digest
        shl     %%IDX, 4
        ; Read first 8 bytes of digest
        mov     %%DIGEST, [%%T + %%IDX]

        READ_AND_ROTATE_KS_QWORD %%KS_ADDR, %%LEN_BUF, %%TMP2, %%TMP1, %%TMP3

        ; XOR with current first half of digest
        xor     %%DIGEST, %%TMP2

        ; byte swap and write first half of digest out
        bswap   %%DIGEST
        ror     %%DIGEST, 32
        mov     [%%T + %%IDX], %%DIGEST

        ; Read next 8 bytes after keyStr[MIN_LEN / 32]
        mov     %%TMP2, %%LEN_BUF
        shr     %%TMP2, 5
        add     %%TMP2, 2 ; Add 2 dwords to offset
        mov     %%TMP3, %%TMP2
        shr     %%TMP2, 2
        shl     %%TMP2, (4+2)
        and     %%TMP3, 0x3
        shl     %%TMP3, 2
        add     %%TMP2, %%TMP3 ;; Offset to last dwords of KS, from base address

        ; Read second 8 bytes of digest
        mov     %%DIGEST, [%%T + %%IDX + 8]

        READ_AND_ROTATE_KS_QWORD %%KS_ADDR, %%LEN_BUF, %%TMP2, %%TMP1, %%TMP3

        ; XOR with current second half of digest
        xor     %%DIGEST, %%TMP2

        ; byte swap and write second half of digest out
        bswap   %%DIGEST
        ror     %%DIGEST, 32
        mov     [%%T + %%IDX + 8], %%DIGEST
        shr     %%IDX, 4
%endif

%%skip_comput:
        inc     %%IDX
        cmp     %%IDX, 16
        jne     %%start_loop

        add     rsp, 32

        add     DWORD(%%MIN_LEN), 31
        shr     DWORD(%%MIN_LEN), 5
        shl     DWORD(%%MIN_LEN), 2 ; Offset where to copy the last 4/8 bytes from

%if %%KEY_SIZE == 128
%define %%KS_WORDS_TO_COPY 2
%else ;; %%KEY_SIZE == 256
%if %%TAG_SIZE == 4
%define %%KS_WORDS_TO_COPY 1
%elif %%TAG_SIZE == 8
%define %%KS_WORDS_TO_COPY 2
%else ;; %%TAG_SIZE == 16
%define %%KS_WORDS_TO_COPY 4
%endif
%endif ;; %%KEY_SIZE

        mov     DWORD(%%TMP1), DWORD(%%MIN_LEN)
        shr     DWORD(%%MIN_LEN), 4
        shl     DWORD(%%MIN_LEN), (4+2)
        and     DWORD(%%TMP1), 0xf
        add     DWORD(%%MIN_LEN), DWORD(%%TMP1)
%if %%KS_WORDS_TO_COPY == 4
        ; Memcpy last 16 bytes of KS into start
        or      DWORD(%%TMP1), DWORD(%%TMP1)
        jz      %%_copy_16bytes

        cmp     DWORD(%%TMP1), 8
        je      %%_copy_8bytes_8bytes
        ja      %%_copy_4bytes_12bytes

        ; Fall-through if 16 bytes to copy are 12 contiguous bytes and 4 separated bytes
%%_copy_12bytes_4bytes:
%assign %%i 0
%rep 4
%assign %%j 0
%rep 4
        mov     %%TMP1, [%%KS + 512*%%i + 16*%%j + %%MIN_LEN]
        mov     [%%KS + 512*%%i + 16*%%j], %%TMP1
        mov     DWORD(%%TMP1), [%%KS + 512*%%i + 16*%%j + %%MIN_LEN + 8]
        mov     [%%KS + 512*%%i + 16*%%j + 8], DWORD(%%TMP1)
        mov     DWORD(%%TMP1), [%%KS + 512*%%i + 16*%%j + (48+12) + %%MIN_LEN]
        mov     [%%KS + 512*%%i + 16*%%j + 12], DWORD(%%TMP1)
%assign %%j (%%j + 1)
%endrep
%assign %%i (%%i + 1)
%endrep
        jmp     %%_ks_copied

%%_copy_8bytes_8bytes:
%assign %%i 0
%rep 4
%assign %%j 0
%rep 4
        mov     %%TMP1, [%%KS + 512*%%i + 16*%%j + %%MIN_LEN]
        mov     [%%KS + 512*%%i + 16*%%j], %%TMP1
        mov     %%TMP1, [%%KS + 512*%%i + 16*%%j + (48+8) + %%MIN_LEN]
        mov     [%%KS + 512*%%i + 16*%%j + 8], %%TMP1
%assign %%j (%%j + 1)
%endrep
%assign %%i (%%i + 1)
%endrep
        jmp     %%_ks_copied
%%_copy_4bytes_12bytes:
%assign %%i 0
%rep 4
%assign %%j 0
%rep 4
        mov     DWORD(%%TMP1), [%%KS + 512*%%i + 16*%%j + %%MIN_LEN]
        mov     [%%KS + 512*%%i + 16*%%j], DWORD(%%TMP1)
        mov     %%TMP1, [%%KS + 512*%%i + 16*%%j + (48+4) + %%MIN_LEN]
        mov     [%%KS + 512*%%i + 16*%%j + 4], %%TMP1
        mov     DWORD(%%TMP1), [%%KS + 512*%%i + 16*%%j + (48+4) + %%MIN_LEN + 8]
        mov     [%%KS + 512*%%i + 16*%%j + 12], DWORD(%%TMP1)
%assign %%j (%%j + 1)
%endrep
%assign %%i (%%i + 1)
%endrep
        jmp     %%_ks_copied
%%_copy_16bytes:
%assign %%i 0
%rep 4
%assign %%j 0
%rep 4
        vmovdqa64 %%XTMP1, [%%KS + 512*%%i + 16*%%j + %%MIN_LEN]
        vmovdqa64 [%%KS + 512*%%i + 16*%%j], %%XTMP1
%assign %%j (%%j + 1)
%endrep
%assign %%i (%%i + 1)
%endrep

%elif %%KS_WORDS_TO_COPY == 2
        ; Memcpy last 8 bytes of KS into start
        cmp     DWORD(%%TMP1), 12
        je      %%_copy_2dwords

%assign %%i 0
%rep 4
%assign %%j 0
%rep 4
        mov     %%TMP1, [%%KS + 512*%%i + 16*%%j + %%MIN_LEN]
        mov     [%%KS + 512*%%i + 16*%%j], %%TMP1
%assign %%j (%%j + 1)
%endrep
%assign %%i (%%i + 1)
%endrep
        jmp     %%_ks_copied

        ;; The 8 bytes of %%KS are separated
%%_copy_2dwords:
%assign %%i 0
%rep 4
%assign %%j 0
%rep 4
        mov     DWORD(%%TMP1), [%%KS + 512*%%i + 16*%%j + %%MIN_LEN]
        mov     [%%KS + 512*%%i + 16*%%j], DWORD(%%TMP1)
        mov     DWORD(%%TMP1), [%%KS + 512*%%i + 16*%%j + (48+4) + %%MIN_LEN]
        mov     [%%KS + 512*%%i + 16*%%j + 4], DWORD(%%TMP1)
%assign %%j (%%j + 1)
%endrep
%assign %%i (%%i + 1)
%endrep
%elif %%KS_WORDS_TO_COPY == 1
        ; Memcpy last 4 bytes of KS into start
%assign %%i 0
%rep 4
%assign %%j 0
%rep 4
        mov     DWORD(%%TMP1), [%%KS + 512*%%i + 16*%%j + %%MIN_LEN]
        mov     [%%KS + 512*%%i + 16*%%j], DWORD(%%TMP1)
%assign %%j (%%j + 1)
%endrep
%assign %%i (%%i + 1)
%endrep
%endif ; %%KS_WORDS_TO_COPY
%%_ks_copied:
        vzeroupper
%endmacro ; REMAINDER_16

;;
;; extern void asm_Eia3RemainderAVX512_16(uint32_t *T, const void **ks,
;;                                        const void **data, uint16_t *len,
;;                                        const uint64_t n_bits)
;;
;;  @param [in] T: Array of digests for all 16 buffers
;;  @param [in] KS : Array of pointers to key stream for all 16 buffers
;;  @param [in] DATA : Array of pointers to data for all 16 buffers
;;  @param [in] N_BITS : Number of common data bits to process
;;
align 64
MKGLOBAL(ZUC128_REMAINDER_16,function,internal)
ZUC128_REMAINDER_16:

%define T       arg1
%define KS      arg2
%define DATA    arg3
%define LEN     arg4

%define N_BITS r10

        endbranch64

        mov     N_BITS, arg5

        FUNC_SAVE

        REMAINDER_16 T, KS, DATA, LEN, N_BITS, rax, rbx, r11, r12, r13, r14, r15, 128, 4

        FUNC_RESTORE

        ret
;;
;; extern void asm_Eia3_256_RemainderAVX512_16(void *T, const void **ks,
;;                                             const void **data, uint16_t *len,
;;                                             const uint64_t n_bits,
;;                                             const uint64_t tag_size)
;;
;;  @param [in] T: Array of digests for all 16 buffers
;;  @param [in] KS : Array of pointers to key stream for all 16 buffers
;;  @param [in] DATA : Array of pointers to data for all 16 buffers
;;  @param [in] N_BITS : Number data bits to process
;;  @param [in] TAG_SIZE : Tag size (4, 8 or 16 bytes)
;;
align 64
MKGLOBAL(ZUC256_REMAINDER_16,function,internal)
ZUC256_REMAINDER_16:

%define T       arg1
%define KS      arg2
%define DATA    arg3
%define LEN     arg4

%define N_BITS r10

%define TAG_SIZE  arg6

        endbranch64

        mov     N_BITS, arg5

        cmp     TAG_SIZE, 8
        je      remainder_8B
        jb      remainder_4B

        ; Fall-through for 16-byte tag
remainder_16B:
        FUNC_SAVE

        REMAINDER_16 T, KS, DATA, LEN, N_BITS, rax, rbx, r11, r12, r13, r14, r15, 256, 16

        FUNC_RESTORE

        ret
remainder_8B:
        FUNC_SAVE

        REMAINDER_16 T, KS, DATA, LEN, N_BITS, rax, rbx, r11, r12, r13, r14, r15, 256, 8

        FUNC_RESTORE

        ret
remainder_4B:
        FUNC_SAVE

        REMAINDER_16 T, KS, DATA, LEN, N_BITS, rax, rbx, r11, r12, r13, r14, r15, 256, 4

        FUNC_RESTORE

        ret

; Following functions only need AVX512 instructions (no VAES, GFNI, etc.)
%if USE_GFNI_VAES_VPCLMUL == 0
;;
;; extern void asm_Eia3RemainderAVX512(uint32_t *T, const void *ks,
;;                                     const void *data, uint64_t n_bits)
;;
;; Returns authentication update value to be XOR'ed with current authentication tag
;;
;;  @param [in] T (digest pointer)
;;  @param [in] KS (key stream pointer)
;;  @param [in] DATA (data pointer)
;;  @param [in] N_BITS (number data bits to process)
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

        endbranch64

        FUNC_SAVE

        vmovdqa  xmm5, [rel bit_reverse_table_l]
        vmovdqa  xmm6, [rel bit_reverse_table_h]
        vmovdqa  xmm7, [rel bit_reverse_and_table]
        vpxor    xmm9, xmm9
        mov      r12d, 0x55555555
        kmovd    k2, r12d

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
        vpshufd xmm0{k2}{z}, xmm8, 0x10
        vpshufd xmm1{k2}{z}, xmm8, 0x32

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
        vpshufd xmm0{k2}{z}, xmm8, 0x10 ; D 0-3 || Os || D 4-7 || 0s
        vpshufd xmm1{k2}{z}, xmm8, 0x32 ; D 8-11 || 0s || D 12-15 || 0s

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
;;extern void asm_Eia3Round64BAVX512(uint32_t *T, const void *KS, const void *DATA)
;;
;; Updates authentication tag T based on keystream KS and DATA.
;; - it processes 64 bytes of DATA
;; - reads data in 16 byte chunks and bit reverses them
;; - reads and re-arranges KS
;; - employs clmul for the XOR & ROL part
;;
;;  @param [in] T (digest pointer)
;;  @param [in] KS (key stream pointer)
;;  @param [in] DATA (data pointer)
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

        endbranch64

        FUNC_SAVE

        vmovdqa  xmm5, [rel bit_reverse_table_l]
        vmovdqa  xmm6, [rel bit_reverse_table_h]
        vmovdqa  xmm7, [rel bit_reverse_and_table]
        vpxor    xmm9, xmm9

        mov      r12d, 0x55555555
        kmovd    k1, r12d
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
        vpshufd xmm0{k1}{z}, xmm8, 0x10
        vpshufd xmm1{k1}{z}, xmm8, 0x32

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

%endif ; USE_GFNI_VAES_VPCLMUL == 0

;----------------------------------------------------------------------------------------
;----------------------------------------------------------------------------------------

mksection stack-noexec
