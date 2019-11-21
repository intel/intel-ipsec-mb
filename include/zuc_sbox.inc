;;
;; Copyright (c) 2019, Intel Corporation
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

%ifndef _ZUC_SBOX_INC_
%define _ZUC_SBOX_INC_

section .data
default rel
align 16
P1:
db      0x09, 0x0F, 0x00, 0x0E, 0x0F, 0x0F, 0x02, 0x0A, 0x00, 0x04, 0x00, 0x0C, 0x07, 0x05, 0x03, 0x09

align 16
P2:
db      0x08, 0x0D, 0x06, 0x05, 0x07, 0x00, 0x0C, 0x04, 0x0B, 0x01, 0x0E, 0x0A, 0x0F, 0x03, 0x09, 0x02

align 16
P3:
db      0x02, 0x06, 0x0A, 0x06, 0x00, 0x0D, 0x0A, 0x0F, 0x03, 0x03, 0x0D, 0x05, 0x00, 0x09, 0x0C, 0x0D

align 16
Low_nibble_mask:
        db 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f

align 16
High_nibble_mask:
        db 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0

align 16
Top3_bits_of_the_byte:
dd 0xe0e0e0e0, 0xe0e0e0e0, 0xe0e0e0e0, 0xe0e0e0e0

align 16
Bottom5_bits_of_the_byte:
dd 0x1f1f1f1f, 0x1f1f1f1f, 0x1f1f1f1f, 0x1f1f1f1f

align 16
Aes_to_Zuc_mul_low_nibble:
        db 0x00, 0x01, 0x82, 0x83, 0x9e, 0x9f, 0x1c, 0x1d, 0x24, 0x25, 0xa6, 0xa7, 0xba, 0xbb, 0x38, 0x39

align 16
Aes_to_Zuc_mul_high_nibble:
        db 0x00, 0xd5, 0x08, 0xdd, 0x7c, 0xa9, 0x74, 0xa1, 0x9c, 0x49, 0x94, 0x41, 0xe0, 0x35, 0xe8, 0x3d

align 16
Comb_matrix_mul_low_nibble:
        db 0x55, 0x41, 0xff, 0xeb, 0x24, 0x30, 0x8e, 0x9a, 0xe2, 0xf6, 0x48, 0x5c, 0x93, 0x87, 0x39, 0x2d

align 16
Comb_matrix_mul_high_nibble:
        db 0x55, 0xba, 0xcc, 0x23, 0x15, 0xfa, 0x8c, 0x63, 0x09, 0xe6, 0x90, 0x7f, 0x49, 0xa6, 0xd0, 0x3f

align 16
Shuf_mask:
        db 0x00, 0x0D, 0x0A, 0x07, 0x04, 0x01, 0x0e, 0x0b, 0x08, 0x05, 0x02, 0x0f, 0x0C, 0x09, 0x06, 0x03

align 16
Cancel_aes:
        db 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63

align 16
Const_comb_matrix:
        db 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55

;
; Rotate left 5 bits in each byte, within an XMM register
;
%macro Rotl_5_SSE 2
%define %%XDATA         %1 ; [in/out] XMM register to rotate
%define %%XTMP0         %2 ; [clobbered] Temporary XMM register

        movdqa  %%XTMP0, %%XDATA
        pslld   %%XTMP0, 5
        psrld   %%XDATA, 3
        pand    %%XTMP0, [rel Top3_bits_of_the_byte]
        pand    %%XDATA, [rel Bottom5_bits_of_the_byte]
        por     %%XDATA, %%XTMP0

%endmacro

;
; Compute 16 S0 box values from 16 bytes, stored in XMM register
;
%macro S0_comput_SSE 3
%define %%IN_OUT        %1 ; [in/out] XMM reg with input values which will contain the output values
%define %%XTMP1         %2 ; [clobbered] Temporary XMM register
%define %%XTMP2         %3 ; [clobbered] Temporary XMM register

        movdqa  %%XTMP1, %%IN_OUT

        pand    %%IN_OUT, [rel Low_nibble_mask] ; x2

        pand    %%XTMP1, [rel High_nibble_mask]
        psrlq   %%XTMP1, 4                 ; x1

        movdqa  %%XTMP2, [rel P1]
        pshufb  %%XTMP2, %%IN_OUT ; P1[x2]
        pxor    %%XTMP2, %%XTMP1  ; q = x1 ^ P1[x2] ; %%XTMP1 free

        movdqa  %%XTMP1, [rel P2]
        pshufb  %%XTMP1, %%XTMP2 ; P2[q]
        pxor    %%XTMP1, %%IN_OUT ; r = x2 ^ P2[q] ; %%IN_OUT free

        movdqa  %%IN_OUT, [rel P3]
        pshufb  %%IN_OUT, %%XTMP1 ; P3[r]
        pxor    %%IN_OUT, %%XTMP2 ; s = q ^ P3[r] ; %%XTMP2 free

        ; s << 4 (since high nibble of each byte is 0, no masking is required)
        psllq   %%IN_OUT, 4
        por     %%IN_OUT, %%XTMP1 ; t = (s << 4) | r

        Rotl_5_SSE  %%IN_OUT, %%XTMP1
%endmacro

;
; Rotate left 5 bits in each byte, within an XMM register
;
%macro Rotl_5_AVX 2
%define %%XDATA         %1 ; [in/out] XMM register to rotate
%define %%XTMP0         %2 ; [clobbered] Temporary XMM register

        vpslld  %%XTMP0, %%XDATA, 5
        vpsrld  %%XDATA, 3
        vpand   %%XTMP0, [rel Top3_bits_of_the_byte]
        vpand   %%XDATA, [rel Bottom5_bits_of_the_byte]
        vpor    %%XDATA, %%XTMP0

%endmacro

;
; Compute 16 S0 box values from 16 bytes, stored in XMM register
;
%macro S0_comput_AVX 3
%define %%IN_OUT        %1 ; [in/out] XMM reg with input values which will contain the output values
%define %%XTMP1         %2 ; [clobbered] Temporary XMM register
%define %%XTMP2         %3 ; [clobbered] Temporary XMM register

        vpand    %%XTMP1, %%IN_OUT, [rel High_nibble_mask]
        vpsrlq   %%XTMP1, 4                 ; x1

        vpand    %%IN_OUT, [rel Low_nibble_mask] ; x2

        vmovdqa  %%XTMP2, [rel P1]
        vpshufb  %%XTMP2, %%IN_OUT ; P1[x2]
        vpxor    %%XTMP2, %%XTMP1  ; q = x1 ^ P1[x2] ; %%XTMP1 free

        vmovdqa  %%XTMP1, [rel P2]
        vpshufb  %%XTMP1, %%XTMP2 ; P2[q]
        vpxor    %%XTMP1, %%IN_OUT ; r = x2 ^ P2[q] ; %%IN_OUT free

        vmovdqa  %%IN_OUT, [rel P3]
        vpshufb  %%IN_OUT, %%XTMP1 ; P3[r]
        vpxor    %%IN_OUT, %%XTMP2 ; s = q ^ P3[r] ; %%XTMP2 free

        ; s << 4 (since high nibble of each byte is 0, no masking is required)
        vpsllq   %%IN_OUT, 4
        vpor     %%IN_OUT, %%XTMP1 ; t = (s << 4) | r

        Rotl_5_AVX   %%IN_OUT, %%XTMP1
%endmacro

;
; Perform 8x8 matrix multiplication using lookup tables with partial results
; for high and low nible of each input byte
;
%macro MUL_PSHUFB_SSE 4
%define %%XIN     %1      ; [in] XMM reg containing input vector
%define %%XLO     %2      ; [in/clobbered] XMM reg containing low nibble table
%define %%XHI_OUT %3      ; [in/out] XMM reg with high nibble table as input and which outputs the resulted vector
%define %%XTMP    %4      ; [clobbered] Temp XMM register

        ; Get low nibble of input data
        movdqa  %%XTMP, [rel Low_nibble_mask]
        pand    %%XTMP, %%XIN

        ; Get low nibble of output
        pshufb  %%XLO, %%XTMP

        ; Get high nibble of input data
        movdqa  %%XTMP, [rel High_nibble_mask]
        pand    %%XTMP, %%XIN
        psrlq   %%XTMP, 4

        ; Get high nibble of output
        pshufb  %%XHI_OUT, %%XTMP

        ; XOR high and low nibbles to get full bytes
        pxor    %%XHI_OUT, %%XLO

%endmacro

;
; Compute 16 S1 box values from 16 bytes, stored in XMM register
;
%macro S1_comput_SSE 4
%define %%XIN_OUT       %1 ; [in/out] XMM reg with input values which will contain the output values
%define %%XTMP1         %2 ; [clobbered] Temporary XMM register
%define %%XTMP2         %3 ; [clobbered] Temporary XMM register
%define %%XTMP3         %4 ; [clobbered] Temporary XMM register

        movdqa          %%XTMP1, [rel Aes_to_Zuc_mul_low_nibble]
        movdqa          %%XTMP2, [rel Aes_to_Zuc_mul_high_nibble]
        MUL_PSHUFB_SSE  %%XIN_OUT, %%XTMP1, %%XTMP2, %%XTMP3

        pshufb          %%XTMP2, [rel Shuf_mask]
        aesenclast      %%XTMP2, [rel Cancel_aes]

        movdqa          %%XTMP1, [rel Comb_matrix_mul_low_nibble]
        movdqa          %%XIN_OUT, [rel Comb_matrix_mul_high_nibble]
        MUL_PSHUFB_SSE  %%XTMP2, %%XTMP1, %%XIN_OUT, %%XTMP3
        pxor            %%XIN_OUT, [rel Const_comb_matrix]

%endmacro

;
; Perform 8x8 matrix multiplication using lookup tables with partial results
; for high and low nible of each input byte
;
%macro MUL_PSHUFB_AVX 4
%define %%XIN     %1      ; [in] XMM reg containing input vector
%define %%XLO     %2      ; [in/clobbered] XMM reg containing low nibble table
%define %%XHI_OUT %3      ; [in/out] XMM reg with high nibble table as input and which outputs the resulted vector
%define %%XTMP    %4      ; [clobbered] Temp XMM register

        ; Get low nibble of input data
        vpand   %%XTMP, %%XIN, [rel Low_nibble_mask]

        ; Get low nibble of output
        vpshufb %%XLO, %%XTMP

        ; Get high nibble of input data
        vpand   %%XTMP, %%XIN, [rel High_nibble_mask]
        vpsrlq  %%XTMP, 4

        ; Get high nibble of output
        vpshufb %%XHI_OUT, %%XTMP

        ; XOR high and low nibbles to get full bytes
        vpxor   %%XHI_OUT, %%XLO

%endmacro

;
; Compute 16 S1 box values from 16 bytes, stored in XMM register
;
%macro S1_comput_AVX 4
%define %%XIN_OUT       %1 ; [in/out] XMM reg with input values which will contain the output values
%define %%XTMP1         %2 ; [clobbered] Temporary XMM register
%define %%XTMP2         %3 ; [clobbered] Temporary XMM register
%define %%XTMP3         %4 ; [clobbered] Temporary XMM register

        vmovdqa         %%XTMP1, [rel Aes_to_Zuc_mul_low_nibble]
        vmovdqa         %%XTMP2, [rel Aes_to_Zuc_mul_high_nibble]
        MUL_PSHUFB_AVX  %%XIN_OUT, %%XTMP1, %%XTMP2, %%XTMP3

        vpshufb         %%XTMP2, [rel Shuf_mask]
        vaesenclast     %%XTMP2, [rel Cancel_aes]

        vmovdqa         %%XTMP1, [rel Comb_matrix_mul_low_nibble]
        vmovdqa         %%XIN_OUT, [rel Comb_matrix_mul_high_nibble]
        MUL_PSHUFB_AVX  %%XTMP2, %%XTMP1, %%XIN_OUT, %%XTMP3
        vpxor           %%XIN_OUT, [rel Const_comb_matrix]

%endmacro
%endif ; end ifndef _ZUC_SBOX_INC_
