;;
;; Copyright (c) 2022, Intel Corporation
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
%include "include/memcpy.asm"
%include "include/imb_job.asm"
%include "include/clear_regs.asm"
%include "include/mb_mgr_datastruct.asm"
%include "include/memcpy.asm"
%include "include/transpose_sse.asm"

extern snow3g_table_A_mul
extern snow3g_table_A_div
extern snow3g_table_S2

align 64
const_fixup_mask:
times 2 dq 0x7272727272727272

align 64
const_byte_mix_col_rev:
dd 0x00030201, 0x04070605, 0x080b0a09, 0x0c0f0e0d

align 16
snow3g_inv_SR_SQ:
db      0xC2, 0xA6, 0x8F, 0x0A, 0x0D, 0xBE, 0xA7, 0x08
db      0x1D, 0x99, 0x45, 0x59, 0x13, 0xD2, 0x11, 0x9F
db      0xAE, 0xE6, 0xD4, 0xA4, 0x92, 0x8D, 0x58, 0xC1
db      0xD0, 0x97, 0xC8, 0x84, 0x9D, 0x4F, 0xBC, 0x3B
db      0x2D, 0xEB, 0x27, 0x53, 0x72, 0x4E, 0xE3, 0xEE
db      0xDA, 0x7F, 0xAA, 0x4D, 0x5C, 0x2F, 0x44, 0xDB
db      0x3E, 0x3A, 0x67, 0xC5, 0xC3, 0x6A, 0x16, 0x4C
db      0x38, 0xCC, 0xD7, 0xDD, 0x70, 0x62, 0xF2, 0x19
db      0x10, 0x09, 0x98, 0x4B, 0x61, 0xC9, 0x86, 0x03
db      0xA8, 0x6B, 0x5A, 0x33, 0x6E, 0x54, 0x5D, 0x8C
db      0x41, 0x1A, 0xF7, 0xF6, 0x82, 0xC6, 0xF8, 0x80
db      0xC0, 0xC7, 0xFE, 0xB3, 0x65, 0x2C, 0x7B, 0xBA
db      0xB4, 0xFC, 0x2A, 0x22, 0x0C, 0x73, 0xF5, 0x5F
db      0x64, 0x68, 0x2E, 0x94, 0xB2, 0x24, 0x35, 0x14
db      0x78, 0xFB, 0xBF, 0x48, 0xDE, 0xED, 0x43, 0x07
db      0xB6, 0x32, 0xE4, 0xBD, 0x74, 0x7D, 0x57, 0x46
db      0x3C, 0x37, 0xC4, 0xB7, 0x51, 0x8A, 0xF3, 0x55
db      0x6C, 0xCF, 0x79, 0xAB, 0x77, 0xA3, 0xE1, 0x93
db      0xD5, 0x6D, 0x81, 0x5B, 0x2B, 0x9A, 0x7E, 0x8B
db      0x04, 0xB5, 0x85, 0xD3, 0x91, 0xA1, 0x47, 0x52
db      0xA5, 0xEC, 0xD6, 0xBB, 0x20, 0x87, 0x26, 0xF0
db      0xAF, 0x4A, 0x89, 0xF4, 0xCE, 0x25, 0xCB, 0x50
db      0x00, 0x3F, 0xD9, 0x42, 0x90, 0x21, 0x3D, 0xA9
db      0xE7, 0x29, 0x01, 0xF1, 0x36, 0x5E, 0xFA, 0xCD
db      0xE5, 0x31, 0x1B, 0x05, 0xFD, 0x9E, 0xA0, 0x76
db      0x30, 0xB1, 0x75, 0xB0, 0x9B, 0x56, 0xEA, 0x1C
db      0xEF, 0x06, 0x69, 0x7A, 0x95, 0x88, 0x15, 0xFF
db      0xCA, 0xAC, 0x0E, 0x23, 0xD8, 0x0F, 0x28, 0x0B
db      0x18, 0xF9, 0x63, 0x1E, 0x83, 0x66, 0x39, 0x9C
db      0xE2, 0x49, 0x1F, 0xE8, 0xD1, 0x34, 0x7C, 0xA2
db      0xB9, 0xE0, 0x02, 0x12, 0xE9, 0xDF, 0xAD, 0x71
db      0x96, 0x8E, 0x6F, 0xB8, 0x40, 0x60, 0x17, 0xDC

align 64
xmm_bswap:
dd 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f

;; used for inverse of AESENC shift rows operation
align 64
const_fixed_rotate_mask:
dq 0x0b0e0104070a0d00, 0x0306090c0f020508

align 64
idx_rows_sse:
times 4 dd 0x00000000
times 4 dd 0x10101010
times 4 dd 0x20202020
times 4 dd 0x30303030
times 4 dd 0x40404040
times 4 dd 0x50505050
times 4 dd 0x60606060
times 4 dd 0x70707070
times 4 dd 0x80808080
times 4 dd 0x90909090
times 4 dd 0xa0a0a0a0
times 4 dd 0xb0b0b0b0
times 4 dd 0xc0c0c0c0
times 4 dd 0xd0d0d0d0
times 4 dd 0xe0e0e0e0
times 4 dd 0xf0f0f0f0

align 64
ms_byte_mask:
dd 0x0f0b0703
dd 0x80808080
dd 0x80808080
dd 0x80808080

align 64
ls_byte_mask:
dd 0x0c080400
dd 0x80808080
dd 0x80808080
dd 0x80808080

align 64
low_nibble_byte_mask:
times 4 dd 0x0f0f0f0f

align 64
mul_alpha:
db 0x00, 0x13, 0x26, 0x35, 0x4C, 0x5F, 0x6A, 0x79
db 0x98, 0x8B, 0xBE, 0xAD, 0xD4, 0xC7, 0xF2, 0xE1
db 0x00, 0xCF, 0x37, 0xF8, 0x6E, 0xA1, 0x59, 0x96
db 0xDC, 0x13, 0xEB, 0x24, 0xB2, 0x7D, 0x85, 0x4A
db 0x00, 0x9F, 0x97, 0x08, 0x87, 0x18, 0x10, 0x8F
db 0xA7, 0x38, 0x30, 0xAF, 0x20, 0xBF, 0xB7, 0x28
db 0x00, 0xE1, 0x6B, 0x8A, 0xD6, 0x37, 0xBD, 0x5C
db 0x05, 0xE4, 0x6E, 0x8F, 0xD3, 0x32, 0xB8, 0x59
db 0x00, 0x99, 0x9B, 0x02, 0x9F, 0x06, 0x04, 0x9D
db 0x97, 0x0E, 0x0C, 0x95, 0x08, 0x91, 0x93, 0x0A
db 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
db 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
db 0x00, 0xE7, 0x67, 0x80, 0xCE, 0x29, 0xA9, 0x4E
db 0x35, 0xD2, 0x52, 0xB5, 0xFB, 0x1C, 0x9C, 0x7B
db 0x00, 0x0A, 0x14, 0x1E, 0x28, 0x22, 0x3C, 0x36
db 0x50, 0x5A, 0x44, 0x4E, 0x78, 0x72, 0x6C, 0x66

align 64
div_alpha:
db 0x00, 0xCD, 0x33, 0xFE, 0x66, 0xAB, 0x55, 0x98
db 0xCC, 0x01, 0xFF, 0x32, 0xAA, 0x67, 0x99, 0x54
db 0x00, 0x40, 0x80, 0xC0, 0xA9, 0xE9, 0x29, 0x69
db 0xFB, 0xBB, 0x7B, 0x3B, 0x52, 0x12, 0xD2, 0x92
db 0x00, 0x0F, 0x1E, 0x11, 0x3C, 0x33, 0x22, 0x2D
db 0x78, 0x77, 0x66, 0x69, 0x44, 0x4B, 0x5A, 0x55
db 0x00, 0x18, 0x30, 0x28, 0x60, 0x78, 0x50, 0x48
db 0xC0, 0xD8, 0xF0, 0xE8, 0xA0, 0xB8, 0x90, 0x88
db 0x00, 0x31, 0x62, 0x53, 0xC4, 0xF5, 0xA6, 0x97
db 0x21, 0x10, 0x43, 0x72, 0xE5, 0xD4, 0x87, 0xB6
db 0x00, 0x5F, 0xBE, 0xE1, 0xD5, 0x8A, 0x6B, 0x34
db 0x03, 0x5C, 0xBD, 0xE2, 0xD6, 0x89, 0x68, 0x37
db 0x00, 0xF0, 0x49, 0xB9, 0x92, 0x62, 0xDB, 0x2B
db 0x8D, 0x7D, 0xC4, 0x34, 0x1F, 0xEF, 0x56, 0xA6
db 0x00, 0x29, 0x52, 0x7B, 0xA4, 0x8D, 0xF6, 0xDF
db 0xE1, 0xC8, 0xB3, 0x9A, 0x45, 0x6C, 0x17, 0x3E

align 64
all_fs:
times 4 dd 0xffffffff

mksection .text

struc STACK
_keystream:     resb    (4 * 16)
_gpr_save:      resq    10
_rsp_save:      resq    1
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Stores register contents and create the stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW3G_FUNC_START 0
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, ~63

        mov     [rsp + _gpr_save + 8 * 0], rbx
        mov     [rsp + _gpr_save + 8 * 1], rbp
        mov     [rsp + _gpr_save + 8 * 2], r12
        mov     [rsp + _gpr_save + 8 * 3], rsi
        mov     [rsp + _gpr_save + 8 * 4], rdi
        mov     [rsp + _gpr_save + 8 * 5], r13
        mov     [rsp + _gpr_save + 8 * 6], r14
        mov     [rsp + _gpr_save + 8 * 7], r15

%ifdef LINUX
        mov     [rsp + _gpr_save + 8 * 8], r9
%else
        mov     [rsp + _gpr_save + 8 * 8], rcx
        mov     [rsp + _gpr_save + 8 * 9], rdx
%endif
        mov     [rsp + _rsp_save], rax  ;; original SP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Restores register contents and removes the stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW3G_FUNC_END 0
        mov     rbx, [rsp + _gpr_save + 8 * 0]
        mov     rbp, [rsp + _gpr_save + 8 * 1]
        mov     r12, [rsp + _gpr_save + 8 * 2]
        mov     rsi, [rsp + _gpr_save + 8 * 3]
        mov     rdi, [rsp + _gpr_save + 8 * 4]
        mov     r13, [rsp + _gpr_save + 8 * 5]
        mov     r14, [rsp + _gpr_save + 8 * 6]
        mov     r15, [rsp + _gpr_save + 8 * 7]
%ifdef LINUX
        mov     r9, [rsp + _gpr_save + 8 * 8]
%else
        mov     rcx, [rsp + _gpr_save + 8 * 8]
        mov     rdx, [rsp + _gpr_save + 8 * 9]
%endif
        mov     rsp, [rsp + _rsp_save]  ;; original SP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SSE_LOOKUP_16X8BIT: Search 16 8-bit values in lookup table
;; arg 1   [in] : xmm register with 16x8bit indexes to search
;; arg 2   [in] : memory with 16 8-bit indices to be looked up
;; arg3-15 [clobbered]: xmm registers used as temp variables
;; arg 16  [out]: xmm register to write 16 8-bit values from the table
;; in and out xmm register must be different registers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SSE_LOOKUP_16X8BIT 15
%define %%IN_INDEXES_H          %1      ;; [in/out] xmm reg with indexes
%define %%TMP_INDEXES_L         %2      ;; [clobbered] xmm register
%define %%TMP1                  %3      ;; [clobbered] xmm register
%define %%TMP2                  %4      ;; [clobbered] xmm register
%define %%TMP3                  %5      ;; [clobbered] xmm register
%define %%TMP4                  %6      ;; [clobbered] xmm register
%define %%TMP5                  %7      ;; [clobbered] xmm register
%define %%TMP6                  %8      ;; [clobbered] xmm register
%define %%TMPARG_TAB_VAL_0      %9      ;; [clobbered] xmm register
%define %%TMPARG_TAB_VAL_1      %10     ;; [clobbered] xmm register
%define %%TMPARG_TAB_VAL_2      %11     ;; [clobbered] xmm register
%define %%TMPARG_TAB_VAL_3      %12     ;; [clobbered] xmm register
%define %%TMPARG_TAB_VAL_4      %13     ;; [clobbered] xmm register
%define %%TMPARG_TAB_VAL_5      %14     ;; [clobbered] xmm register
%define %%OUT_SUBSTITUTE_VAL    %15     ;; [out] xmm register


        movdqa          %%TMP1, [rel idx_rows_sse + (15 * 16)] ;; 4x0xf0f0f0f0
        movdqa          %%TMP2, %%TMP1
        psrlq           %%TMP2, 4                              ;; 4x0x0f0f0f0f
        movdqa          %%TMP_INDEXES_L, %%IN_INDEXES_H
        pand            %%IN_INDEXES_H, %%TMP1        ;; index top nibble
        pand            %%TMP_INDEXES_L, %%TMP2       ;; index low nibble

        movdqa          %%TMP1,  %%IN_INDEXES_H
        movdqa          %%TMP3, %%IN_INDEXES_H
        movdqa          %%TMP4, %%IN_INDEXES_H
        movdqa          %%TMP5, %%IN_INDEXES_H
        movdqa          %%TMP6, %%IN_INDEXES_H
        movdqa          %%TMP2, %%IN_INDEXES_H
        pcmpeqb         %%TMP1, [rel idx_rows_sse + (0 * 16)]
        movdqa          %%TMPARG_TAB_VAL_0, [rel snow3g_inv_SR_SQ + (0 * 16)]
        pcmpeqb         %%TMP3, [rel idx_rows_sse + (1 * 16)]
        movdqa          %%TMPARG_TAB_VAL_1, [rel snow3g_inv_SR_SQ + (1 * 16)]
        pcmpeqb         %%TMP4, [rel idx_rows_sse + (2 * 16)]
        movdqa          %%TMPARG_TAB_VAL_2, [rel snow3g_inv_SR_SQ + (2 * 16)]
        pcmpeqb         %%TMP5, [rel idx_rows_sse + (3 * 16)]
        movdqa          %%TMPARG_TAB_VAL_3, [rel snow3g_inv_SR_SQ + (3 * 16)]
        pcmpeqb         %%TMP6, [rel idx_rows_sse + (4 * 16)]
        movdqa          %%TMPARG_TAB_VAL_4, [rel snow3g_inv_SR_SQ + (4 * 16)]
        pcmpeqb         %%TMP2, [rel idx_rows_sse + (5 * 16)]
        movdqa          %%TMPARG_TAB_VAL_5, [rel snow3g_inv_SR_SQ + (5 * 16)]

        pshufb          %%TMPARG_TAB_VAL_0, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_1, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_2, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_3, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_4, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_5, %%TMP_INDEXES_L

        pand            %%TMP1,  %%TMPARG_TAB_VAL_0
        pand            %%TMP3, %%TMPARG_TAB_VAL_1
        pand            %%TMP4, %%TMPARG_TAB_VAL_2
        pand            %%TMP5, %%TMPARG_TAB_VAL_3
        pand            %%TMP6, %%TMPARG_TAB_VAL_4
        pand            %%TMP2, %%TMPARG_TAB_VAL_5

        por             %%TMP1,  %%TMP3
        por             %%TMP4, %%TMP5
        por             %%TMP2, %%TMP6
        movdqa          %%OUT_SUBSTITUTE_VAL, %%TMP1
        por             %%OUT_SUBSTITUTE_VAL, %%TMP4

        ;; %%OUT_SUBSTITUTE_VAL & %%TMP2 carry current OR result.

        movdqa          %%TMP1,  %%IN_INDEXES_H
        movdqa          %%TMP3, %%IN_INDEXES_H
        movdqa          %%TMP4, %%IN_INDEXES_H
        movdqa          %%TMP5, %%IN_INDEXES_H
        movdqa          %%TMP6, %%IN_INDEXES_H

        pcmpeqb         %%TMP1,  [rel idx_rows_sse + (6 * 16)]
        movdqa          %%TMPARG_TAB_VAL_0, [rel snow3g_inv_SR_SQ + (6 * 16)]
        pcmpeqb         %%TMP3, [rel idx_rows_sse + (7 * 16)]
        movdqa          %%TMPARG_TAB_VAL_1, [rel snow3g_inv_SR_SQ + (7 * 16)]
        pcmpeqb         %%TMP4, [rel idx_rows_sse + (8 * 16)]
        movdqa          %%TMPARG_TAB_VAL_2, [rel snow3g_inv_SR_SQ + (8 * 16)]
        pcmpeqb         %%TMP5, [rel idx_rows_sse + (9 * 16)]
        movdqa          %%TMPARG_TAB_VAL_3, [rel snow3g_inv_SR_SQ + (9 * 16)]
        pcmpeqb         %%TMP6, [rel idx_rows_sse + (10 * 16)]
        movdqa          %%TMPARG_TAB_VAL_4, [rel snow3g_inv_SR_SQ + (10 * 16)]

        pshufb          %%TMPARG_TAB_VAL_0, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_1, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_2, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_3, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_4, %%TMP_INDEXES_L

        pand            %%TMP1,  %%TMPARG_TAB_VAL_0
        pand            %%TMP3, %%TMPARG_TAB_VAL_1
        pand            %%TMP4, %%TMPARG_TAB_VAL_2
        pand            %%TMP5, %%TMPARG_TAB_VAL_3
        pand            %%TMP6, %%TMPARG_TAB_VAL_4

        por             %%TMP1,  %%TMP3
        por             %%TMP4, %%TMP5
        por             %%TMP2, %%TMP6
        por             %%OUT_SUBSTITUTE_VAL, %%TMP1
        por             %%TMP2, %%TMP4

        ;; %%OUT_SUBSTITUTE_VAL & %%TMP1 carry current OR result

        movdqa          %%TMP1,  %%IN_INDEXES_H
        movdqa          %%TMP3, %%IN_INDEXES_H
        movdqa          %%TMP4, %%IN_INDEXES_H
        movdqa          %%TMP5, %%IN_INDEXES_H
        movdqa          %%TMP6, %%IN_INDEXES_H

        pcmpeqb         %%TMP1,  [rel idx_rows_sse + (11 * 16)]
        movdqa          %%TMPARG_TAB_VAL_0, [rel snow3g_inv_SR_SQ + (11 * 16)]
        pcmpeqb         %%TMP3, [rel idx_rows_sse + (12 * 16)]
        movdqa          %%TMPARG_TAB_VAL_1, [rel snow3g_inv_SR_SQ + (12 * 16)]
        pcmpeqb         %%TMP4, [rel idx_rows_sse + (13 * 16)]
        movdqa          %%TMPARG_TAB_VAL_2, [rel snow3g_inv_SR_SQ + (13 * 16)]
        pcmpeqb         %%TMP5, [rel idx_rows_sse + (14 * 16)]
        movdqa          %%TMPARG_TAB_VAL_3, [rel snow3g_inv_SR_SQ + (14 * 16)]
        pcmpeqb         %%TMP6, [rel idx_rows_sse + (15 * 16)]
        movdqa          %%TMPARG_TAB_VAL_4, [rel snow3g_inv_SR_SQ + (15 * 16)]

        pshufb          %%TMPARG_TAB_VAL_0, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_1, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_2, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_3, %%TMP_INDEXES_L
        pshufb          %%TMPARG_TAB_VAL_4, %%TMP_INDEXES_L

        pand            %%TMP1,  %%TMPARG_TAB_VAL_0
        pand            %%TMP3, %%TMPARG_TAB_VAL_1
        pand            %%TMP4, %%TMPARG_TAB_VAL_2
        pand            %%TMP5, %%TMPARG_TAB_VAL_3
        pand            %%TMP6, %%TMPARG_TAB_VAL_4

        por             %%TMP1,  %%TMP3
        por             %%TMP4, %%TMP5
        por             %%TMP2, %%TMP6
        por             %%OUT_SUBSTITUTE_VAL, %%TMP1
        por             %%TMP2, %%TMP4
        por             %%OUT_SUBSTITUTE_VAL, %%TMP2
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Search SNOW3G S2 box value per byte from FSM2 indicated in args.
;; Fill single dword in output depending on given lane nr
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro S2_BOX_BYTE_SEARCH 7
%define %%OUT         %1        ;; [out] xmm register (1 dword filled)
%define %%FSM_R2      %2        ;; [in] ptr to FSM2 values per 4 lanes
%define %%TABLE_PTR   %3        ;; [in] address of table for search
%define %%LANE        %4        ;; [in] lane nr
%define %%BYTE_NR     %5        ;; [in] byte number for search (from FSM2)
%define %%BYTE_OFFSET %6        ;; [in] byte offset for output
%define %%TMP_64_1    %7        ;; [clobbered] temp gpr

        movzx           %%TMP_64_1, byte[%%FSM_R2 + %%LANE*4 + %%BYTE_NR]
        pinsrd          %%OUT, [%%TABLE_PTR + %%TMP_64_1*8 + %%BYTE_OFFSET], %%LANE

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SNOW3G S2 box calculation for 4 32-bit values passed in 1st input parameter.
;; Clobbers all 15 input xmm registers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro S2_BOX_SSE 15
%define %%TMP1        %1  ;; [in/clobbered] xmm containing 4 dwords
%define %%TMP2        %2  ;; [clobbered] temp xmm register
%define %%TMP3        %3  ;; [clobbered] temp xmm register
%define %%TMP4        %4  ;; [clobbered] temp xmm register
%define %%TMP5        %5  ;; [clobbered] temp xmm register
%define %%TMP6        %6  ;; [clobbered] temp xmm register
%define %%TMP7        %7  ;; [clobbered] temp xmm register
%define %%TMP8        %8  ;; [clobbered] temp xmm register
%define %%TMP9        %9  ;; [clobbered] temp xmm register
%define %%TMP10       %10 ;; [clobbered] temp xmm register
%define %%TMP11       %11 ;; [clobbered] temp xmm register
%define %%TMP12       %12 ;; [clobbered] temp xmm register
%define %%TMP13       %13 ;; [clobbered] temp xmm register
%define %%TMP14       %14 ;; [clobbered] temp xmm register
%define %%TMPOUT      %15 ;; [out] xmm containing S2 box for 4 input dwords

        ;; Perform invSR(SQ(x)) transform
        SSE_LOOKUP_16X8BIT %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,  \
                           %%TMP6, %%TMP7, %%TMP8, %%TMP9, %%TMP10, \
                           %%TMP11, %%TMP12, %%TMP13, %%TMP14,        \
                           %%TMPOUT

        pshufb          %%TMPOUT, [rel const_fixed_rotate_mask]
        pxor            %%TMP1, %%TMP1
        movdqa          %%TMP2, %%TMPOUT

        ;; aesenclast does not perform mix column operation and
        ;; allows to determine the fix-up value to be applied
        ;; on result of aesenc to produce correct result for SNOW3G
        aesenclast      %%TMP2, %%TMP1
        aesenc          %%TMPOUT, %%TMP1

        ;; Using signed compare to return 0xFF when the most significant bit of
        ;; no_mixc is set
        pcmpgtb         %%TMP1, %%TMP2
        movdqa          %%TMP5, %%TMP1
        pshufb          %%TMP5, [rel const_byte_mix_col_rev]
        pxor            %%TMP1, %%TMP5
        pand            %%TMP1, [rel const_fixup_mask]
        pxor            %%TMPOUT, %%TMP1
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Perform SNOW3G FSM clock operation for 4 buffers.
;; Passed addresses for FSM_R1-FSM_R3 and LFSR_5 are interpreted as list of 4
;; 32-bit values each.
;; Values under FSM_R1-FSM_R3 are updated as a result of this macro.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW3G_FSM_CLOCK 11-20
%define %%FSM_R1        %1      ;; [in] address of 4 FSM values R1
%define %%FSM_R2        %2      ;; [in] address of 4 FSM values R2
%define %%FSM_R3        %3      ;; [in] address of 4 FSM values R3
%define %%TMP1          %4      ;; [clobbered] temp xmm register
%define %%TMP2          %5      ;; [clobbered] temp xmm register
%define %%TMP3          %6      ;; [clobbered] temp xmm register
%define %%TMP4          %7      ;; [clobbered] temp xmm register
%define %%TMP5          %8      ;; [clobbered] temp xmm register
%ifdef SAFE_LOOKUP
%define %%TMP6          %9      ;; [clobbered] temp xmm register
%define %%TMP7          %10     ;; [clobbered] temp xmm register
%define %%TMP8          %11     ;; [clobbered] temp xmm register
%define %%TMP9          %12     ;; [clobbered] temp xmm register
%define %%TMP10         %13     ;; [clobbered] temp xmm register
%define %%TMP11         %14     ;; [clobbered] temp xmm register
%define %%TMP12         %15     ;; [clobbered] temp xmm register
%define %%TMP13         %16     ;; [clobbered] temp xmm register
%define %%TMP14         %17     ;; [clobbered] temp xmm register
%define %%TMP15         %18     ;; [clobbered] temp xmm register
%define %%TMP16         %19     ;; [clobbered] temp xmm register
%define %%LFSR_5        %20     ;; [in] address of 4 LFSR 5 values
%else
%define %%TMP_64        %9      ;; [clobbered] temp gp register
%define %%TMP_64_1      %10     ;; [clobbered] temp gp register
%define %%LFSR_5        %11     ;; [in] address of 4 LFSR 5 values

%endif  ;; SAFE_LOOKUP

        ;; FSM_3 = S2_box(FSM_2)
%ifdef SAFE_LOOKUP
        movdqa          %%TMP15, [ %%FSM_R2 ]
        S2_BOX_SSE      %%TMP15, %%TMP2, %%TMP3, %%TMP4, %%TMP5,  \
                        %%TMP6, %%TMP7, %%TMP8, %%TMP9, %%TMP10, \
                        %%TMP11, %%TMP12, %%TMP13, %%TMP14, %%TMP1
%else
        lea             %%TMP_64, [rel snow3g_table_S2]
        ;; w0= S2[(x >> 24) & 0xff];
        ;; w1= S2[(x >> 16) & 0xff];
        ;; w2= S2[(x >> 8) & 0xff];
        ;; w3= S2[x & 0xff];
        S2_BOX_BYTE_SEARCH      %%TMP1, %%FSM_R2, %%TMP_64, 0, 3, 0, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP2, %%FSM_R2, %%TMP_64, 0, 2, 1, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP3, %%FSM_R2, %%TMP_64, 0, 1, 2, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP4, %%FSM_R2, %%TMP_64, 0, 0, 3, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP1, %%FSM_R2, %%TMP_64, 1, 3, 0, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP2, %%FSM_R2, %%TMP_64, 1, 2, 1, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP3, %%FSM_R2, %%TMP_64, 1, 1, 2, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP4, %%FSM_R2, %%TMP_64, 1, 0, 3, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP1, %%FSM_R2, %%TMP_64, 2, 3, 0, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP2, %%FSM_R2, %%TMP_64, 2, 2, 1, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP3, %%FSM_R2, %%TMP_64, 2, 1, 2, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP4, %%FSM_R2, %%TMP_64, 2, 0, 3, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP1, %%FSM_R2, %%TMP_64, 3, 3, 0, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP2, %%FSM_R2, %%TMP_64, 3, 2, 1, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP3, %%FSM_R2, %%TMP_64, 3, 1, 2, %%TMP_64_1
        S2_BOX_BYTE_SEARCH      %%TMP4, %%FSM_R2, %%TMP_64, 3, 0, 3, %%TMP_64_1

        pxor            %%TMP4, %%TMP3
        pxor            %%TMP1, %%TMP2
        pxor            %%TMP1, %%TMP4
%endif  ;; SAFE_LOOKUP

        ;; R = (FSM_R3 ^ LFSR_5) + FSM_R2
        movdqa          %%TMP5, [%%FSM_R3]
        pxor            %%TMP5, [%%LFSR_5]
        paddd           %%TMP5, [%%FSM_R2]

        ;; FSM_3 = S2_box(FSM_2)
        movdqa          [%%FSM_R3], %%TMP1

        ;; FSM_R2 = S1_box(FSM_R1)
        movdqa          %%TMP3, [%%FSM_R1]

        ;; S1 box calculation
        pshufb          %%TMP3, [rel const_fixed_rotate_mask]
        pxor            %%TMP2, %%TMP2
        aesenc          %%TMP3, %%TMP2

        movdqa          [%%FSM_R2], %%TMP3

        ;; FSM_1 = R
        movdqa          [%%FSM_R1], %%TMP5

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Perform SNOW3G mul_alpha or div_alpha depending on table passed in %2:
;; (MULxPOW(c, 23, 0xA9) || MULxPOW(c, 245, 0xA9) || MULxPOW(c, 48, 0xA9)
;; || MULxPOW(c, 239, 0xA9))
;; c = %%LFSR_X
;; Result of mul_alpha and div_alpha operations are precalculated and expected
;; under %%OP_TABLE address. This function searches those tables.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifdef SAFE_LOOKUP
%macro ALPHA_OP 7
%define %%LFSR_X        %1 ;; [in/clobbered] xmm with LFSR value
%define %%OP_TABLE      %2 ;; [in] address of mulalpha/divalpha val table
%define %%TMP1        %3 ;; [out] temporary xmm register
%define %%TMP2        %4 ;; [clobbered] temporary xmm register
%define %%TMP3        %5 ;; [clobbered] temporary xmm register
%define %%TMP4        %6 ;; [clobbered] temporary xmm register
%define %%TMP5        %7 ;; [clobbered] temporary xmm register

        movdqa          %%TMP2, [rel low_nibble_byte_mask]
        pand            %%TMP2, %%LFSR_X ;; lower part of each byte of LFSR
        movdqa          %%TMP1, [rel %%OP_TABLE]
        pshufb          %%TMP1, %%TMP2
        movdqa          %%TMP3, [rel %%OP_TABLE + 16]
        movdqa          %%TMP4, [rel %%OP_TABLE + 32]
        movdqa          %%TMP5, [rel %%OP_TABLE + 48]

        pshufb          %%TMP3, %%TMP2
        pshufb          %%TMP4, %%TMP2
        pshufb          %%TMP5, %%TMP2

        punpcklbw       %%TMP1, %%TMP3
        punpcklbw       %%TMP4, %%TMP5
        movdqa          %%TMP2, %%TMP1
        punpcklwd       %%TMP2, %%TMP4

        movdqa  %%TMP1, [rel low_nibble_byte_mask]
        psrld   %%LFSR_X, 4
        pand    %%LFSR_X, %%TMP1

        movdqa  %%TMP1, [rel %%OP_TABLE + 64]
        movdqa  %%TMP3, [rel %%OP_TABLE + 80]
        movdqa  %%TMP4, [rel %%OP_TABLE + 96]
        movdqa  %%TMP5, [rel %%OP_TABLE + 112]

        pshufb  %%TMP1, %%LFSR_X
        pshufb  %%TMP3, %%LFSR_X
        pshufb  %%TMP4, %%LFSR_X
        pshufb  %%TMP5, %%LFSR_X

        punpcklbw       %%TMP1, %%TMP3
        punpcklbw       %%TMP4, %%TMP5
        punpcklwd       %%TMP1, %%TMP4
        pxor            %%TMP1, %%TMP2
%endmacro

%else   ;; SAFE_LOOKUP

%macro ALPHA_OP_NOT_SAFE 5
%define %%LFSR_PTR      %1 ;; [in] r64 with address of LFSR register
                             ;;      for mulalpha pass LFSR
                             ;;      for divalpha pass LSFR 11
%define %%OP_TABLE      %2 ;; [in] address of mulalpha/divalpha val table
%define %%TMP1          %3 ;; [out] temporary xmm register
%define %%TMP_64        %4 ;; [clobbered] temporary gp register
%define %%TMP_64_1      %5 ;; [clobbered] temporary gp register
        lea             %%TMP_64, [rel %%OP_TABLE]

%ifidn %%OP_TABLE, snow3g_table_A_div
        movzx           %%TMP_64_1, byte[%%LFSR_PTR]
%else
        movzx           %%TMP_64_1, byte[%%LFSR_PTR+3]
%endif
        movd            %%TMP1, [%%TMP_64 + %%TMP_64_1*4]

%ifidn %%OP_TABLE, snow3g_table_A_div
        movzx           %%TMP_64_1, byte[%%LFSR_PTR+4]
%else
        movzx           %%TMP_64_1, byte[%%LFSR_PTR+7]
%endif
        pinsrd          %%TMP1, [%%TMP_64 + %%TMP_64_1*4], 1
%ifidn %%OP_TABLE, snow3g_table_A_div
        movzx           %%TMP_64_1, byte[%%LFSR_PTR+8]
%else
        movzx           %%TMP_64_1, byte[%%LFSR_PTR+11]
%endif
        pinsrd          %%TMP1, [%%TMP_64 + %%TMP_64_1*4], 2
%ifidn %%OP_TABLE, snow3g_table_A_div
        movzx           %%TMP_64_1, byte[%%LFSR_PTR+12]
%else
        movzx           %%TMP_64_1, byte[%%LFSR_PTR+15]
%endif
        pinsrd          %%TMP1, [%%TMP_64 + %%TMP_64_1*4], 3
%endmacro

%endif  ;; SAFE_LOOKUP

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Perform SNOW3G LFSR shift operation.
;; This operation is common for initialization mode and keystream mode, the only
;; difference is in init mode %1 = keystream otherwise %1 needs ti be set to 0.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SHIFT_LFSRS 9
%define %%STATE         %1  ;; [in] state ptr
%define %%KEYSTREAM     %2  ;; [in] in init mode keystream, else 0
%define %%TMP1        %3  ;; [clobbered] temporary xmm register
%define %%TMP2        %4  ;; [clobbered] temporary xmm register
%define %%TMP3        %5  ;; [clobbered] temporary xmm register
%define %%TMP4        %6  ;; [clobbered] temporary xmm register
%define %%TMP5        %7  ;; [clobbered] temporary xmm register
%define %%TMP6        %8  ;; [clobbered] temporary xmm register
%define %%TMP7        %9  ;; [clobbered] temporary xmm register

        ;; LFSR_0:LFSR_15: LFSR_i = LFSR_(i + 1);
        ;; LFSR_15 = keystream / 0
        movdqa          %%TMP1, [%%STATE + _snow3g_args_LFSR_1]
        movdqa          %%TMP2, [%%STATE + _snow3g_args_LFSR_2]
        movdqa          %%TMP3, [%%STATE + _snow3g_args_LFSR_3]
        movdqa          %%TMP4, [%%STATE + _snow3g_args_LFSR_4]
        movdqa          %%TMP5, [%%STATE + _snow3g_args_LFSR_5]
        movdqa          %%TMP6, [%%STATE + _snow3g_args_LFSR_6]
        movdqa          [%%STATE + _snow3g_args_LFSR_0], %%TMP1
        movdqa          [%%STATE + _snow3g_args_LFSR_1], %%TMP2
        movdqa          [%%STATE + _snow3g_args_LFSR_2], %%TMP3
        movdqa          [%%STATE + _snow3g_args_LFSR_3], %%TMP4
        movdqa          [%%STATE + _snow3g_args_LFSR_4], %%TMP5
        movdqa          [%%STATE + _snow3g_args_LFSR_5], %%TMP6

        movdqa          %%TMP1, [%%STATE + _snow3g_args_LFSR_7]
        movdqa          %%TMP2, [%%STATE + _snow3g_args_LFSR_8]
        movdqa          %%TMP3, [%%STATE + _snow3g_args_LFSR_9]
        movdqa          %%TMP4, [%%STATE + _snow3g_args_LFSR_10]
        movdqa          %%TMP5, [%%STATE + _snow3g_args_LFSR_11]
        movdqa          %%TMP6, [%%STATE + _snow3g_args_LFSR_12]
        movdqa          [%%STATE + _snow3g_args_LFSR_6], %%TMP1
        movdqa          [%%STATE + _snow3g_args_LFSR_7], %%TMP2
        movdqa          [%%STATE + _snow3g_args_LFSR_8], %%TMP3
        movdqa          [%%STATE + _snow3g_args_LFSR_9 ], %%TMP4
        movdqa          [%%STATE + _snow3g_args_LFSR_10], %%TMP5
        movdqa          [%%STATE + _snow3g_args_LFSR_11], %%TMP6

        movdqa          %%TMP1, [%%STATE + _snow3g_args_LFSR_13]
        movdqa          %%TMP2, [%%STATE + _snow3g_args_LFSR_14]
        movdqa          %%TMP3, [%%STATE + _snow3g_args_LFSR_15]

        movdqa          [%%STATE + _snow3g_args_LFSR_12], %%TMP1
        movdqa          [%%STATE + _snow3g_args_LFSR_13], %%TMP2
        movdqa          [%%STATE + _snow3g_args_LFSR_14], %%TMP3

        movdqa          [%%STATE + _snow3g_args_LFSR_15], %%KEYSTREAM
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generate SNOW3G keystream per 4 buffers. Update LFSR/FSM state.
;; This macro is used both in initialization and keystream modes.
;; In initialization mode F is stored on stack.
;; In keystream mode keystream is stored on stack.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW3G_KEY_GEN_SSE 12-18
%define %%STATE       %1  ;; [in] ptr to LFSR/FSM struct
%define %%TMP1        %2  ;; [clobbered] temporary xmm register
%define %%TMP2        %3  ;; [clobbered] temporary xmm register
%define %%TMP3        %4  ;; [clobbered] temporary xmm register
%define %%TMP4        %5  ;; [clobbered] temporary xmm register
%define %%TMP5        %6  ;; [clobbered] temporary xmm register
%define %%TMP6        %7  ;; [clobbered] temporary xmm register
%define %%TMP7        %8  ;; [clobbered] temporary xmm register
%ifdef SAFE_LOOKUP
%define %%TMP8        %9  ;; [clobbered] temporary xmm register
%define %%TMP9        %10 ;; [clobbered] temporary xmm register
%define %%TMP10       %11 ;; [clobbered] temporary xmm register
%define %%TMP11       %12 ;; [clobbered] temporary xmm register
%define %%TMP12       %13 ;; [clobbered] temporary xmm register
%define %%TMP13       %14 ;; [clobbered] temporary xmm register
%define %%TMP14       %15 ;; [clobbered] temporary xmm register
%define %%TMP15       %16 ;; [clobbered] temporary xmm register
%define %%TMP16       %17 ;; [clobbered] temporary xmm register
%define %%DWORD_ITER  %18 ;; [in] gp reg with offset for stack storing keystream
%else   ;;SAFE_LOOKUP
%define %%TMP15       %9  ;; [clobbered] temporary xmm register
%define %%TMP_64_1    %10 ;; [clobbered] temp gpr
%define %%TMP_64_2    %11 ;; [clobbered] temp gpr
%define %%DWORD_ITER  %12 ;; [in] gp reg with offset for stack storing keystream
%endif  ;;SAFE_LOOKUP


        ;; Calculate F = (LFSR_S[15] + FSM_R1) ^ FSM_R2;
        movdqa          %%TMP1, [ %%STATE + _snow3g_args_LFSR_15 ]
        paddd           %%TMP1, [ %%STATE + _snow3g_args_FSM_1 ]
        pxor            %%TMP1, [ %%STATE + _snow3g_args_FSM_2 ]

        ;; Store F/keystream on stack
        movdqa          %%TMP2, [%%STATE + _snow3g_args_LD_ST_MASK + 4*4]
        pandn           %%TMP2, %%TMP1          ;; zero in keystream mode
        movdqa          %%TMP3, [%%STATE + _snow3g_args_LD_ST_MASK + 4*4]
        ;; keystream mode: ks = F xor LFSR_0
        pxor            %%TMP1, [%%STATE + _snow3g_args_LFSR_0]
        pand            %%TMP3, %%TMP1          ;; zero in init mode
        por             %%TMP2, %%TMP3
        shl             %%DWORD_ITER, 4
        movdqa          [rsp + _keystream + %%DWORD_ITER], %%TMP2

        ;; FSM Clock
%ifdef SAFE_LOOKUP
        SNOW3G_FSM_CLOCK {%%STATE + _snow3g_args_FSM_1},  \
                         {%%STATE + _snow3g_args_FSM_2},  \
                         {%%STATE + _snow3g_args_FSM_3}, %%TMP1, %%TMP2,    \
                         %%TMP3, %%TMP4, %%TMP5, %%TMP6, %%TMP7,    \
                         %%TMP8, %%TMP9, %%TMP10, %%TMP11, %%TMP12, \
                         %%TMP13, %%TMP14, %%TMP15, %%TMP16,          \
                         %%STATE + _snow3g_args_LFSR_5
        movdqa          %%TMP15, [ %%STATE + _snow3g_args_LFSR_0 ]
        movdqa          %%TMP2, [rel ms_byte_mask]
        pshufb          %%TMP15,  %%TMP2
        ALPHA_OP        %%TMP15, mul_alpha, %%TMP2, %%TMP3, %%TMP4,    \
                        %%TMP5, %%TMP6
        ; LFSR clock: div alpha

        movdqa          %%TMP15, [%%STATE + _snow3g_args_LFSR_11 ]
        movdqa          %%TMP7, [rel ls_byte_mask]
        pshufb          %%TMP15,  %%TMP7
        ALPHA_OP        %%TMP15, div_alpha, %%TMP7, %%TMP3, %%TMP4,    \
                        %%TMP5, %%TMP6
%else
        SNOW3G_FSM_CLOCK {%%STATE + _snow3g_args_FSM_1},  \
                         {%%STATE + _snow3g_args_FSM_2},  \
                         {%%STATE + _snow3g_args_FSM_3}, %%TMP1, %%TMP2,    \
                         %%TMP3, %%TMP4, %%TMP5, %%TMP_64_1, %%TMP_64_2, \
                         %%STATE + _snow3g_args_LFSR_5
        ALPHA_OP_NOT_SAFE {%%STATE + _snow3g_args_LFSR_0}, snow3g_table_A_mul, \
                          %%TMP2, %%TMP_64_1, %%TMP_64_2


        ALPHA_OP_NOT_SAFE {%%STATE + _snow3g_args_LFSR_11}, snow3g_table_A_div, \
                          %%TMP7, %%TMP_64_1, %%TMP_64_2
%endif  ;; SAFE_LOOKUP

        movdqa          %%TMP15, [%%STATE + _snow3g_args_LFSR_2 ]
        pxor            %%TMP15, %%TMP2
        pxor            %%TMP15, %%TMP7

        movdqa          %%TMP3, [%%STATE + _snow3g_args_LFSR_0 ]
        movdqa          %%TMP4, [%%STATE + _snow3g_args_LFSR_11 ]
        pslld           %%TMP3, 8
        psrld           %%TMP4, 8
        pxor            %%TMP15, %%TMP3
        pxor            %%TMP15, %%TMP4

        ;; in init mode mask is 0, so this is applies only in init mode
        movdqa          %%TMP2, [%%STATE + _snow3g_args_LD_ST_MASK + 4*4]
        pandn           %%TMP2, [rsp + _keystream + %%DWORD_ITER]
        pxor            %%TMP15, %%TMP2

        SHIFT_LFSRS     %%STATE, %%TMP15, %%TMP1, %%TMP2, %%TMP3,      \
                        %%TMP4, %%TMP5, %%TMP6, %%TMP7
        ;; restore offset
        shr             %%DWORD_ITER, 4
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Read and transpose keystreams from stack
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro TRANSPOSE_4X32 6
%define %%OUT_XMM_LANE_0      %1 ;; [out] 128bit keystream for lane 0
%define %%OUT_XMM_LANE_1      %2 ;; [out] 128bit keystream for lane 1
%define %%OUT_XMM_LANE_2      %3 ;; [out] 128bit keystream for lane 0
%define %%OUT_XMM_LANE_3      %4 ;; [out] 128bit keystream for lane 3
%define %%XTMP0               %5 ;; [clobbered] temporary xmm register
%define %%XTMP1               %6 ;; [clobbered] temporary xmm register

        movdqa  %%OUT_XMM_LANE_2, [rsp + _keystream + 0 * 16]
        movdqa  %%OUT_XMM_LANE_1, [rsp + _keystream + 1 * 16]
        movdqa  %%XTMP1, [rsp + _keystream + 2 * 16]
        movdqa  %%OUT_XMM_LANE_3, [rsp + _keystream + 3 * 16]

        ;; output looks like: {t0 r1 r0 r3}
        TRANSPOSE4_U32  %%OUT_XMM_LANE_2, %%OUT_XMM_LANE_1, %%XTMP1,      \
                        %%OUT_XMM_LANE_3, %%OUT_XMM_LANE_0, %%XTMP0

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Checks the masks for init/keystream phases and outputs keystream from stack
;; xored with input, depending on given lane, if phase is keystream.
;; Input arguments and size of output data is controlled by %SIZE:
;; - 16: 8 arguments, output full xmm value passed by %8
;; -  4: 7 arguments, output exactly 1 DW
;; - other: 7 arguments, output 1-4 bytes depending on %7
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW3G_OUTPUT 7-10
%define %%SIZE          %1  ;; [in] size indicating nr of bytes to output
%define %%STATE         %2  ;; [in] ptr to LFSR/FSM struct
%define %%LANE          %3  ;; [in] lane nr
%define %%TMP64         %4  ;; [clobbered] r64 gp reg temp
%define %%IN_PTR        %5  ;; [clobbered] r64 gp reg temp
%define %%OUT_PTR       %6  ;; [clobbered] r64 gp reg temp
%define %%TMP           %7  ;; [in] temp xmm, if size is 16
%define %%LENGTH        %7  ;; [clobbered] r64 gp reg temp, if size is not 16
%define %%VALUE         %8  ;; [in] xmm_val, if size is 16


        ;; Check if phase for given lane
        mov             DWORD(%%TMP64), \
                        [%%STATE + _snow3g_args_LD_ST_MASK + %%LANE*4]
        or              DWORD(%%TMP64),DWORD(%%TMP64)
        je              %%no_output ;; skip output if in init phase
        ;; read in/out ptrs
        mov             %%IN_PTR, [%%STATE + _snow3g_args_in + %%LANE * 8]
        mov             %%OUT_PTR, [%%STATE + _snow3g_args_out + %%LANE * 8]

        ;; output == input XOR keysteram
%ifidn %%SIZE, 16
        movdqu          %%TMP, [%%IN_PTR]
        pshufb          %%VALUE, [rel xmm_bswap]
        pxor            %%VALUE, %%TMP
        movdqu          [%%OUT_PTR], %%VALUE
        add             %%IN_PTR, %%SIZE
        add             %%OUT_PTR, %%SIZE
%else
        ;; there is always at least 1DW of keystream generated on stack
        mov             DWORD(%%TMP64), [rsp + _keystream + %%LANE*4]
        bswap           DWORD(%%TMP64)
%ifidn %%SIZE, 4
        xor             DWORD(%%TMP64), [%%IN_PTR]
        mov             [%%OUT_PTR], DWORD(%%TMP64)
%else ;; up to 4 bytes (defined by %%length)
        mov             DWORD(%%LENGTH), [%%STATE + _snow3g_lens + %%LANE * 4]
        cmp             %%LENGTH, 4
        jne             %%_not_dw
        xor             DWORD(%%TMP64), [%%IN_PTR]
        mov             dword [%%OUT_PTR], DWORD(%%TMP64)
        jmp             %%_write_done
%%_not_dw:
        and             %%LENGTH, 3
        cmp             %%LENGTH, 2
        jl              %%_write_single_byte

        ;; write 2 bytes
        xor             WORD(%%TMP64), [%%IN_PTR]
        mov             word [%%OUT_PTR], WORD(%%TMP64)
        add             %%IN_PTR, 2
        add             %%OUT_PTR, 2
        and             %%LENGTH, 1
        je              %%_write_done
        shr             %%TMP64, 16
%%_write_single_byte:
        xor             BYTE(%%TMP64), [%%IN_PTR]
        mov             byte [%%OUT_PTR], BYTE(%%TMP64)
%%_write_done:
%endif
        ;; if %%LENGTH is less then 4 bytes per given lane that's the last bytes
        ;; of total request so pointers are never used again
        add             %%IN_PTR, 4
        add             %%OUT_PTR, 4
%endif
        ;; Update input/output pointers
        mov             [%%STATE + _snow3g_args_in + %%LANE*8], %%IN_PTR
        mov             [%%STATE + _snow3g_args_out + %%LANE*8], %%OUT_PTR

%%no_output:
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Initialize LFSR, FSM registers and write mask for given lane
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW3G_INIT_LANE_SSE 7
%define %%STATE         %1 ;; [in] ptr to MB_MGR_SNOW3G_OOO structure
%define %%LANE          %2 ;; [in] nr of lane initialize data in
%define %%P_KEY         %3 ;; [in] ptr to key
%define %%P_IV          %4 ;; [in] ptr to IV
%define %%TMPXMM_1      %5 ;; [clobbered] temporary xmm reg
%define %%TMPXMM_2      %6 ;; [clobbered] temporary xmm reg
%define %%TMPXMM_3      %7 ;; [clobbered] temporary xmm reg

        movd            %%TMPXMM_1, [%%P_KEY]         ;; key
        movdqa          %%TMPXMM_2, %%TMPXMM_1
        pxor            %%TMPXMM_2, [rel all_fs]      ;; ~key

        movdqu          %%TMPXMM_3,  [%%P_IV]
        pshufb          %%TMPXMM_3, [rel xmm_bswap]

        ;; temporarily store swapped IV on stack
        movdqu          [rsp + _keystream], %%TMPXMM_3

        ;; LFSR initialisation
        movd            [%%STATE + _snow3g_args_LFSR_0 + 4*%%LANE], %%TMPXMM_2
        movd            [%%STATE + _snow3g_args_LFSR_8 + 4*%%LANE], %%TMPXMM_2
        movd            [%%STATE + _snow3g_args_LFSR_4 + 4*%%LANE], %%TMPXMM_1
        movd            %%TMPXMM_3, [rsp + _keystream + 8]
        pxor            %%TMPXMM_1, %%TMPXMM_3  ;; LFSR_12 ^= IV[2](swapped)
        movd            [%%STATE + _snow3g_args_LFSR_12 + 4*%%LANE], %%TMPXMM_1

        movd            %%TMPXMM_1, [%%P_KEY + 4]
        movd            %%TMPXMM_2, [%%P_KEY + 4]
        pxor            %%TMPXMM_2, [rel all_fs]

        movd            [%%STATE + _snow3g_args_LFSR_1 + 4*%%LANE], %%TMPXMM_2
        movd            %%TMPXMM_3, [rsp + _keystream]
        pxor            %%TMPXMM_2, %%TMPXMM_3   ;; LFSR_9 ^= IV[0](swapped)
        movd            [%%STATE + _snow3g_args_LFSR_9 + 4*%%LANE], %%TMPXMM_2
        movd            [%%STATE + _snow3g_args_LFSR_5 + 4*%%LANE], %%TMPXMM_1
        movd            [%%STATE + _snow3g_args_LFSR_13 + 4*%%LANE], %%TMPXMM_1

        movd            %%TMPXMM_1, [%%P_KEY + 8]
        movd            %%TMPXMM_2, [%%P_KEY + 8]
        pxor            %%TMPXMM_2, [rel all_fs]

        movd            [%%STATE + _snow3g_args_LFSR_2 + 4*%%LANE], %%TMPXMM_2
        movd            %%TMPXMM_3, [rsp + _keystream + 4]
        pxor            %%TMPXMM_2, %%TMPXMM_3  ;; LFSR_10 ^= IV[1](swapped)
        movd            [%%STATE + _snow3g_args_LFSR_10 + 4*%%LANE], %%TMPXMM_2
        movd            [%%STATE + _snow3g_args_LFSR_6 + 4*%%LANE], %%TMPXMM_1
        movd            [%%STATE + _snow3g_args_LFSR_14 + 4*%%LANE], %%TMPXMM_1

        movd            %%TMPXMM_1, [%%P_KEY + 12]
        movdqa          %%TMPXMM_2, %%TMPXMM_1
        pxor            %%TMPXMM_2, [rel all_fs]

        movd            [%%STATE + _snow3g_args_LFSR_3 + 4*%%LANE], %%TMPXMM_2
        movd            [%%STATE + _snow3g_args_LFSR_11 + 4*%%LANE], %%TMPXMM_2
        movd            [%%STATE + _snow3g_args_LFSR_7 + 4*%%LANE], %%TMPXMM_1
        movd            %%TMPXMM_3, [rsp + _keystream + 12]
        pxor            %%TMPXMM_1, %%TMPXMM_3  ;; LFSR_15 ^= IV[3](swapped)
        movd            [%%STATE + _snow3g_args_LFSR_15 + 4*%%LANE], %%TMPXMM_1

        ; FSM initialization: FSM_1 = FSM_2 = FSM_3 = 0
        pxor    %%TMPXMM_1,  %%TMPXMM_1
        movd    [%%STATE + _snow3g_args_FSM_1 + 4*%%LANE],  %%TMPXMM_1
        movd    [%%STATE + _snow3g_args_FSM_2 + 4*%%LANE], %%TMPXMM_1
        movd    [%%STATE + _snow3g_args_FSM_3 + 4*%%LANE],  %%TMPXMM_1

        movd    [%%STATE + _snow3g_args_LD_ST_MASK + 4*%%LANE], %%TMPXMM_1
        movd    [%%STATE + _snow3g_args_LD_ST_MASK + 16+ 4*%%LANE], %%TMPXMM_1
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Perform SNOW3G encrypt/decrypt operation steps for 4 buffers. Generate number
;; of dwords indicated by %%COMMON_LEN, update LFSR, FSM state.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW3G_ENC_DEC 23
%define %%STATE         %1      ;; [in] ptr to LFSR/FSM struct
%define %%COMMON_LEN    %2      ;; [in/clobbered] dw aligned common length
%define %%IN            %3      ;; [clobbered] r64 gp reg temp
%define %%OUT           %4      ;; [clobbered] r64 gp reg temp
%define %%LENGTH        %5      ;; [clobbered] r64 gp reg temp
%define %%TMP1_64       %6      ;; [clobbered] r64 gp reg temp
%define %%TMP2_64       %7      ;; [clobbered] r64 gp reg temp
%define %%TMP1          %8      ;; [clobbered] temporary xmm register
%define %%TMP2          %9      ;; [clobbered] temporary xmm register
%define %%TMP3          %10     ;; [clobbered] temporary xmm register
%define %%TMP4          %11     ;; [clobbered] temporary xmm register
%define %%TMP5          %12     ;; [clobbered] temporary xmm register
%define %%TMP6          %13     ;; [clobbered] temporary xmm register
%define %%TMP7          %14     ;; [clobbered] temporary xmm register
%define %%TMP8          %15     ;; [clobbered] temporary xmm register
%define %%TMP9          %16     ;; [clobbered] temporary xmm register
%define %%TMP10         %17     ;; [clobbered] temporary xmm register
%define %%TMP11         %18     ;; [clobbered] temporary xmm register
%define %%TMP12         %19     ;; [clobbered] temporary xmm register
%define %%TMP13         %20     ;; [clobbered] temporary xmm register
%define %%TMP14         %21     ;; [clobbered] temporary xmm register
%define %%TMP15         %22     ;; [clobbered] temporary xmm register
%define %%TMP16         %23     ;; [clobbered] temporary xmm register

        sub             %%COMMON_LEN, 1
        mov             %%LENGTH, %%COMMON_LEN

        shr             %%LENGTH, 2
        je              %%no_dqws


%%next_dqw:
        xor             %%TMP1_64, %%TMP1_64

%%next_dqw_round:
%ifdef SAFE_LOOKUP
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP8, %%TMP9, %%TMP10, %%TMP11,   \
                           %%TMP12, %%TMP13, %%TMP14, %%TMP15, %%TMP16, %%TMP1_64
%else
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP15, %%TMP2_64, %%IN, %%TMP1_64
%endif

        inc             %%TMP1_64
        cmp             %%TMP1_64, 4
        jb              %%next_dqw_round

        TRANSPOSE_4X32  %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5, %%TMP6
        SNOW3G_OUTPUT   16, %%STATE, 0, %%IN, %%OUT, %%TMP1_64, %%TMP5, %%TMP1
        SNOW3G_OUTPUT   16, %%STATE, 1, %%IN, %%OUT, %%TMP1_64, %%TMP5, %%TMP2
        SNOW3G_OUTPUT   16, %%STATE, 2, %%IN, %%OUT, %%TMP1_64, %%TMP5, %%TMP3
        SNOW3G_OUTPUT   16, %%STATE, 3, %%IN, %%OUT, %%TMP1_64, %%TMP5, %%TMP4

        sub             %%LENGTH, 1
        jne             %%next_dqw

%%no_dqws:
        and             %%COMMON_LEN, 0x3
        cmp             %%COMMON_LEN, 0

        je              %%no_full_dws_to_write_out

%%next_dw:
        xor             %%TMP1_64,  %%TMP1_64
%ifdef SAFE_LOOKUP
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP8, %%TMP9, %%TMP10, %%TMP11,   \
                           %%TMP12, %%TMP13, %%TMP14, %%TMP15, %%TMP16, %%TMP1_64
%else
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP15, %%TMP2_64, %%IN, %%TMP1_64
%endif

        SNOW3G_OUTPUT       4, %%STATE, 0, %%IN, %%OUT, %%TMP1_64, %%TMP2_64
        SNOW3G_OUTPUT       4, %%STATE, 1, %%IN, %%OUT, %%TMP1_64, %%TMP2_64
        SNOW3G_OUTPUT       4, %%STATE, 2, %%IN, %%OUT, %%TMP1_64, %%TMP2_64
        SNOW3G_OUTPUT       4, %%STATE, 3, %%IN, %%OUT, %%TMP1_64, %%TMP2_64

        sub                     %%COMMON_LEN, 1
        jne                     %%next_dw

%%no_full_dws_to_write_out:
        ;; Process last dw/bytes:
        xor             %%TMP1_64,  %%TMP1_64
%ifdef SAFE_LOOKUP
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP8, %%TMP9, %%TMP10, %%TMP11,   \
                           %%TMP12, %%TMP13, %%TMP14, %%TMP15, %%TMP16, %%TMP1_64
%else
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP15, %%TMP2_64, %%IN, %%TMP1_64
%endif

        SNOW3G_OUTPUT      3, %%STATE,  0, %%IN, %%OUT, %%TMP1_64, %%LENGTH
        SNOW3G_OUTPUT      3, %%STATE,  1, %%IN, %%OUT, %%TMP1_64, %%LENGTH
        SNOW3G_OUTPUT      3, %%STATE,  2, %%IN, %%OUT, %%TMP1_64, %%LENGTH
        SNOW3G_OUTPUT      3, %%STATE,  3, %%IN, %%OUT, %%TMP1_64, %%LENGTH

%%zero_bytes:
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generate 5 double words of key stream for SNOW3G authentication
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro   SNOW3G_AUTH_INIT_5_BY_4 24
%define %%KEY           %1   ;; [in] array of pointers to 4 keys
%define %%IV            %2   ;; [in] array of pointers to 4 IV's
%define %%DST_PTR       %3   ;; [in] destination buffer to put 5DW of keystream for each lane
%define %%TMP1_64       %4   ;; [clobbered] r64 gp reg temp
%define %%TMP2_64       %5   ;; [clobbered] r64 gp reg temp
%define %%TMP3_64       %6   ;; [clobbered] r64 gp reg temp
%define %%TMP4_64       %7   ;; [clobbered] r64 gp reg temp
%define %%TMP1          %8   ;; [clobbered] temporary xmm register
%define %%TMP2          %9   ;; [clobbered] temporary xmm register
%define %%TMP3          %10  ;; [clobbered] temporary xmm register
%define %%TMP4          %11  ;; [clobbered] temporary xmm register
%define %%TMP5          %12  ;; [clobbered] temporary xmm register
%define %%TMP6          %13  ;; [clobbered] temporary xmm register
%define %%TMP7          %14  ;; [clobbered] temporary xmm register
%define %%TMP8          %15  ;; [clobbered] temporary xmm register
%define %%TMP9          %16  ;; [clobbered] temporary xmm register
%define %%TMP10         %17  ;; [clobbered] temporary xmm register
%define %%TMP11         %18  ;; [clobbered] temporary xmm register
%define %%TMP12         %19  ;; [clobbered] temporary xmm register
%define %%TMP13         %20  ;; [clobbered] temporary xmm register
%define %%TMP14         %21  ;; [clobbered] temporary xmm register
%define %%TMP15         %22  ;; [clobbered] temporary xmm register
%define %%TMP16         %23  ;; [clobbered] temporary xmm register
%define %%STATE         %24  ;; [in] ptr to LFSR/FSM struct

%define KEYGEN_STAGE    _snow3g_args_LD_ST_MASK
%define INIT1_DONE      _snow3g_args_LD_ST_MASK+16

        ;; Initialize LFSR and FSM registers
%assign i 0
%rep 4
        mov     %%TMP1_64, [%%KEY + i*8]
        mov     %%TMP2_64, [%%IV + i*8]
        SNOW3G_INIT_LANE_SSE %%STATE, i, %%TMP1_64, %%TMP2_64, %%TMP1, %%TMP2, %%TMP3
%assign i (i+1)
%endrep

        ;; Run 32 iteration in INIT mode (reject keystreams)
        mov     %%TMP1_64, 32
        xor     %%TMP2_64, %%TMP2_64

%%next_auth_round:
%ifdef SAFE_LOOKUP
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP8, %%TMP9, %%TMP10, %%TMP11,   \
                           %%TMP12, %%TMP13, %%TMP14, %%TMP15, %%TMP16, %%TMP2_64
%else
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP15, %%TMP3_64, %%TMP4_64, %%TMP2_64
%endif
        dec     %%TMP1_64
        jnz     %%next_auth_round

        ;; Mark INIT1 phase done for all lanes
        movdqa  %%TMP1, [rel all_fs]
        movdqa  [state + INIT1_DONE], %%TMP1

%ifdef SAFE_LOOKUP
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP8, %%TMP9, %%TMP10, %%TMP11,   \
                           %%TMP12, %%TMP13, %%TMP14, %%TMP15, %%TMP16, %%TMP2_64
%else
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP15, %%TMP3_64, %%TMP4_64, %%TMP2_64
%endif

        ;; Put all lanes in KEYGEN state
        movdqa  %%TMP1, [rel all_fs]
        movdqa  [state + KEYGEN_STAGE], %%TMP1

        ;; Generate 4 dw of keystream for each lane
        xor     %%TMP1_64, %%TMP1_64

%%next_auth_round2:
%ifdef SAFE_LOOKUP
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP8, %%TMP9, %%TMP10, %%TMP11,   \
                           %%TMP12, %%TMP13, %%TMP14, %%TMP15, %%TMP16, %%TMP1_64
%else
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP15, %%TMP3_64, %%TMP4_64, %%TMP1_64
%endif
        inc     %%TMP1_64
        cmp     %%TMP1_64, 4
        jb      %%next_auth_round2

        TRANSPOSE_4X32  %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5, %%TMP6

        ;; Store 4 dw of keystream for each lane
        movdqu  [%%DST_PTR + 0*32], %%TMP1
        movdqu  [%%DST_PTR + 1*32], %%TMP2
        movdqu  [%%DST_PTR + 2*32], %%TMP3
        movdqu  [%%DST_PTR + 3*32], %%TMP4

        ;; Generate final dw of keystream for each lane
%ifdef SAFE_LOOKUP
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP8, %%TMP9, %%TMP10, %%TMP11,   \
                           %%TMP12, %%TMP13, %%TMP14, %%TMP15, %%TMP16, %%TMP2_64
%else
        SNOW3G_KEY_GEN_SSE %%STATE, %%TMP1, %%TMP2, %%TMP3, %%TMP4, %%TMP5,    \
                           %%TMP6, %%TMP7, %%TMP15, %%TMP3_64, %%TMP4_64, %%TMP2_64
%endif

        ;; Store final dw of keystream for each lane
        mov     DWORD(%%TMP1_64), [rsp + _keystream + 0*4]
        mov     [%%DST_PTR + 16 + (0*32)], DWORD(%%TMP1_64)
        mov     DWORD(%%TMP1_64), [rsp + _keystream + 1*4]
        mov     [%%DST_PTR + 16 + (1 * 32)], DWORD(%%TMP1_64)
        mov     DWORD(%%TMP1_64), [rsp + _keystream + 2*4]
        mov     [%%DST_PTR + 16 + (2*32)], DWORD(%%TMP1_64)
        mov     DWORD(%%TMP1_64), [rsp + _keystream + 3*4]
        mov     [%%DST_PTR + 16 + (3 * 32)], DWORD(%%TMP1_64)

%endmacro

mksection stack-noexec
