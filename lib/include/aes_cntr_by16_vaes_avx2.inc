;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2023-2024, Intel Corporation All rights reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions
;  are met:
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in
;      the documentation and/or other materials provided with the
;      distribution.
;    * Neither the name of Intel Corporation nor the names of its
;      contributors may be used to endorse or promote products derived
;      from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifndef AES_CNTR_VAES_AVX2_INC
%define AES_CNTR_VAES_AVX2_INC

%use smartalign

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/memcpy.inc"
%include "include/reg_sizes.inc"
%include "include/aes_common.inc"
%include "include/clear_regs.inc"
%include "include/align_avx.inc"

;; YMM registers are clobbered and then scratch ones get cleared.
;; Windows YMM saving/restoring must be done at a higher level.

;; =============================================================================
;; DATA PART
;; =============================================================================

mksection .rodata
default rel

%ifdef AES_CTR_DECLARE_DATA

MKGLOBAL(vavx2_byteswap_const2,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_1_0,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_1,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_3_2,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_2,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_3,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_5_4,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_4,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_5,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_7_6,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_6,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_7,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_8,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_8_8,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_16,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_16_16,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_1_0,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_1,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_3_2,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_2,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_3,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_5_4,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_4,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_5,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_7_6,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_6,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_7,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_8,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_8_8,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_16,data,internal)
MKGLOBAL(vavx2_ctr_ddq_add_be_16_16,data,internal)

align 32
vavx2_byteswap_const2:
                DQ 0x08090A0B0C0D0E0F, 0x0001020304050607
                DQ 0x08090A0B0C0D0E0F, 0x0001020304050607

align 32
vavx2_ctr_ddq_add_1_0:
                DQ 0x0000000000000000, 0x0000000000000000
vavx2_ctr_ddq_add_1:
                DQ 0x0000000000000001, 0x0000000000000000
vavx2_ctr_ddq_add_3_2:
vavx2_ctr_ddq_add_2:
                DQ 0x0000000000000002, 0x0000000000000000
vavx2_ctr_ddq_add_3:
                DQ 0x0000000000000003, 0x0000000000000000
vavx2_ctr_ddq_add_5_4:
vavx2_ctr_ddq_add_4:
                DQ 0x0000000000000004, 0x0000000000000000
vavx2_ctr_ddq_add_5:
                DQ 0x0000000000000005, 0x0000000000000000
vavx2_ctr_ddq_add_7_6:
vavx2_ctr_ddq_add_6:
                DQ 0x0000000000000006, 0x0000000000000000
vavx2_ctr_ddq_add_7:
                DQ 0x0000000000000007, 0x0000000000000000
vavx2_ctr_ddq_add_8:
vavx2_ctr_ddq_add_8_8:
                DQ 0x0000000000000008, 0x0000000000000000
                DQ 0x0000000000000008, 0x0000000000000000

vavx2_ctr_ddq_add_16:
vavx2_ctr_ddq_add_16_16:
                DQ 0x0000000000000010, 0x0000000000000000
                DQ 0x0000000000000010, 0x0000000000000000

align 32
vavx2_ctr_ddq_add_be_1_0:
                DQ 0x0000000000000000, 0x0000000000000000
vavx2_ctr_ddq_add_be_1:
                DQ 0x0000000000000000, 0x0100000000000000
vavx2_ctr_ddq_add_be_3_2:
vavx2_ctr_ddq_add_be_2:
                DQ 0x0000000000000000, 0x0200000000000000
vavx2_ctr_ddq_add_be_3:
                DQ 0x0000000000000000, 0x0300000000000000
vavx2_ctr_ddq_add_be_5_4:
vavx2_ctr_ddq_add_be_4:
                DQ 0x0000000000000000, 0x0400000000000000
vavx2_ctr_ddq_add_be_5:
                DQ 0x0000000000000000, 0x0500000000000000
vavx2_ctr_ddq_add_be_7_6:
vavx2_ctr_ddq_add_be_6:
                DQ 0x0000000000000000, 0x0600000000000000
vavx2_ctr_ddq_add_be_7:
                DQ 0x0000000000000000, 0x0700000000000000
vavx2_ctr_ddq_add_be_8:
vavx2_ctr_ddq_add_be_8_8:
                DQ 0x0000000000000000, 0x0800000000000000
                DQ 0x0000000000000000, 0x0800000000000000

vavx2_ctr_ddq_add_be_16:
vavx2_ctr_ddq_add_be_16_16:
                DQ 0x0000000000000000, 0x1000000000000000
                DQ 0x0000000000000000, 0x1000000000000000
%else
;; constants already declared - reuse them inseatd of copying
extern vavx2_byteswap_const2
extern vavx2_ctr_ddq_add_1_0
extern vavx2_ctr_ddq_add_1
extern vavx2_ctr_ddq_add_3_2
extern vavx2_ctr_ddq_add_2
extern vavx2_ctr_ddq_add_3
extern vavx2_ctr_ddq_add_5_4
extern vavx2_ctr_ddq_add_4
extern vavx2_ctr_ddq_add_5
extern vavx2_ctr_ddq_add_7_6
extern vavx2_ctr_ddq_add_6
extern vavx2_ctr_ddq_add_7
extern vavx2_ctr_ddq_add_8
extern vavx2_ctr_ddq_add_8_8
extern vavx2_ctr_ddq_add_16
extern vavx2_ctr_ddq_add_16_16
extern vavx2_ctr_ddq_add_be_1_0
extern vavx2_ctr_ddq_add_be_1
extern vavx2_ctr_ddq_add_be_3_2
extern vavx2_ctr_ddq_add_be_2
extern vavx2_ctr_ddq_add_be_3
extern vavx2_ctr_ddq_add_be_5_4
extern vavx2_ctr_ddq_add_be_4
extern vavx2_ctr_ddq_add_be_5
extern vavx2_ctr_ddq_add_be_7_6
extern vavx2_ctr_ddq_add_be_6
extern vavx2_ctr_ddq_add_be_7
extern vavx2_ctr_ddq_add_be_8
extern vavx2_ctr_ddq_add_be_8_8
extern vavx2_ctr_ddq_add_be_16
extern vavx2_ctr_ddq_add_be_16_16
%endif

extern set_byte15

;; =============================================================================
;; CODE PART
;; =============================================================================

mksection .text

%define CONCAT(a,b) a %+ b

%define xdata0    xmm0
%define xdata1    xmm1
%define xdata2    xmm2
%define xdata3    xmm3
%define xpart     xmm4
%define xcounter  xmm5

%define xbyteswap xmm7
%define xkey      xmm8
%define xdata4    xmm9
%define xdata5    xmm10
%define xdata6    xmm11
%define xdata7    xmm12

%define ydata0    ymm0
%define ydata1    ymm1
%define ydata2    ymm2
%define ydata3    ymm3

%define ycounter  ymm5

%define ybyteswap ymm7
%define ykey      ymm8
%define ydata4    ymm9
%define ydata5    ymm10
%define ydata6    ymm11
%define ydata7    ymm12

%ifdef CNTR_CCM_AVX2
%ifdef LINUX
%define job       rdi
%define p_in      rsi
%define p_keys    rdx
%define p_out     rcx
%define num_bytes r8
%define arg_ivlen r9
%else ;; LINUX
%define job       rcx
%define p_in      rdx
%define p_keys    r8
%define p_out     r9
%define num_bytes r10
%define arg_ivlen r13
%define p_ivlen   rax
%endif ;; LINUX
%define p_IV    r11
%define flags   r12

%else ;; CNTR_CCM_AVX2

%ifdef LINUX
%define p_in      rdi
%define p_IV      rsi
%define p_keys    rdx
%define p_out     rcx
%define num_bytes r8
%define arg_ivlen r9
%else ;; LINUX
%define p_in      rcx
%define p_IV      rdx
%define p_keys    r8
%define p_out     r9
%define num_bytes r10
%define arg_ivlen r11
%endif ;; LINUX
%endif ;; CNTR_CCM_AVX2

%define tmp     r11

;; =============================================================================
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; do_aes
;; - increments p_in and p_out
;; - updates ycounter
;; - clobbers ydata & ykey
;; - uses tmp to track counter overflow condition
%macro do_aes 2
%define %%by            %1 ;; [in] number of blocks to encrypt/decrypt
%define %%rounds        %2 ;; [in] number of aesenc rounds

        ;; prepare counter blocks
%if %%by == 1
        ;; single block only
        vmovdqa         xdata0, xcounter
        vpaddd          xcounter, xcounter, [rel vavx2_ctr_ddq_add_1]

%elif %%by == 16

        ;; most optimized case - 16 blocks
        cmp             tmp, 255-16
        ja              %%_by16_overflow

        vpaddd          ydata0, ycounter, [rel vavx2_ctr_ddq_add_be_1_0]
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_be_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_be_5_4]
        vpaddd          ydata3, ycounter, [rel vavx2_ctr_ddq_add_be_7_6]
        vpaddd          ydata4, ydata0,   [rel vavx2_ctr_ddq_add_be_8_8]
        vpaddd          ydata5, ydata1,   [rel vavx2_ctr_ddq_add_be_8_8]
        vpaddd          ydata6, ydata2,   [rel vavx2_ctr_ddq_add_be_8_8]
        vpaddd          ydata7, ydata3,   [rel vavx2_ctr_ddq_add_be_8_8]
        vpaddd          ycounter, ycounter, [rel vavx2_ctr_ddq_add_be_16_16]
        jmp             %%_by16_end

align_label
%%_by16_overflow:
        vpshufb         ycounter, ycounter, ybyteswap
        vpaddd          ydata0, ycounter, [rel vavx2_ctr_ddq_add_1_0]
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          ydata3, ycounter, [rel vavx2_ctr_ddq_add_7_6]
        vpaddd          ydata4, ydata0,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          ydata5, ydata1,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          ydata6, ydata2,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          ydata7, ydata3,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          ycounter, ycounter, [rel vavx2_ctr_ddq_add_16_16]
        vpshufb         ydata0, ydata0, ybyteswap
        vpshufb         ydata1, ydata1, ybyteswap
        vpshufb         ydata2, ydata2, ybyteswap
        vpshufb         ydata3, ydata3, ybyteswap
        vpshufb         ydata4, ydata4, ybyteswap
        vpshufb         ydata5, ydata5, ybyteswap
        vpshufb         ydata6, ydata6, ybyteswap
        vpshufb         ydata7, ydata7, ybyteswap
        vpshufb         ycounter, ycounter, ybyteswap

align_label
%%_by16_end:
        add             tmp, 16
        and             tmp, 255

%else
        ;; from 2 to 15 blocks
        vinserti128     ycounter, xcounter, 1
        vpaddd          ydata0, ycounter, [rel vavx2_ctr_ddq_add_1_0]

%if %%by == 2
        vpaddd          xcounter, xcounter, [rel vavx2_ctr_ddq_add_2]
%elif %%by == 3
        vpaddd          xdata1, xcounter, [rel vavx2_ctr_ddq_add_2]
        vpaddd          xcounter, xcounter, [rel vavx2_ctr_ddq_add_3]
%elif %%by == 4
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          xcounter, xcounter, [rel vavx2_ctr_ddq_add_4]
%elif %%by == 5
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          xdata2, xcounter, [rel vavx2_ctr_ddq_add_4]
        vpaddd          xcounter, xcounter, [rel vavx2_ctr_ddq_add_5]
%elif %%by == 6
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          xcounter, xcounter, [rel vavx2_ctr_ddq_add_6]
%elif %%by == 7
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          xdata3, xcounter, [rel vavx2_ctr_ddq_add_6]
        vpaddd          xcounter, xcounter, [rel vavx2_ctr_ddq_add_7]
%elif %%by == 8
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          ydata3, ycounter, [rel vavx2_ctr_ddq_add_7_6]
        vpaddd          xcounter, xcounter, [rel vavx2_ctr_ddq_add_8]
%elif %%by == 9
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          ydata3, ycounter, [rel vavx2_ctr_ddq_add_7_6]
        vpaddd          xdata4, xdata0,   [rel vavx2_ctr_ddq_add_8]
        vpaddd          xcounter, xdata1, [rel vavx2_ctr_ddq_add_7]
%elif %%by == 10
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          ydata3, ycounter, [rel vavx2_ctr_ddq_add_7_6]
        vpaddd          ydata4, ydata0,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          xcounter, xdata1, [rel vavx2_ctr_ddq_add_8]
%elif %%by == 11
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          ydata3, ycounter, [rel vavx2_ctr_ddq_add_7_6]
        vpaddd          ydata4, ydata0,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          xdata5, xdata1,   [rel vavx2_ctr_ddq_add_8]
        vpaddd          xcounter, xdata2, [rel vavx2_ctr_ddq_add_7]
%elif %%by == 12
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          ydata3, ycounter, [rel vavx2_ctr_ddq_add_7_6]
        vpaddd          ydata4, ydata0,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          ydata5, ydata1,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          xcounter, xdata2, [rel vavx2_ctr_ddq_add_8]
%elif %%by == 13
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          ydata3, ycounter, [rel vavx2_ctr_ddq_add_7_6]
        vpaddd          ydata4, ydata0,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          ydata5, ydata1,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          xdata6, xdata2,   [rel vavx2_ctr_ddq_add_8]
        vpaddd          xcounter, xdata3, [rel vavx2_ctr_ddq_add_7]
%elif %%by == 14
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          ydata3, ycounter, [rel vavx2_ctr_ddq_add_7_6]
        vpaddd          ydata4, ydata0,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          ydata5, ydata1,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          ydata6, ydata2,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          xcounter, xdata3, [rel vavx2_ctr_ddq_add_8]
%elif %%by == 15
        vpaddd          ydata1, ycounter, [rel vavx2_ctr_ddq_add_3_2]
        vpaddd          ydata2, ycounter, [rel vavx2_ctr_ddq_add_5_4]
        vpaddd          ydata3, ycounter, [rel vavx2_ctr_ddq_add_7_6]
        vpaddd          ydata4, ydata0,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          ydata5, ydata1,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          ydata6, ydata2,   [rel vavx2_ctr_ddq_add_8_8]
        vpaddd          xdata7, xdata3,   [rel vavx2_ctr_ddq_add_8]
        vpaddd          xcounter, xdata4, [rel vavx2_ctr_ddq_add_7]
%endif  ;; %%by = 2 to 15

%endif  ;; %%by

        ;; shuffle counter blocks
%if %%by != 16
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%by, vpshufb, \
                        ydata0, ydata1, ydata2, ydata3, ydata4, ydata5, ydata6, ydata7, \
                        ydata0, ydata1, ydata2, ydata3, ydata4, ydata5, ydata6, ydata7, \
                        ybyteswap, ybyteswap, ybyteswap, ybyteswap, \
                        ybyteswap, ybyteswap, ybyteswap, ybyteswap
%endif
        ;;  ARK
        vbroadcasti128  ykey, [p_keys + 0*16]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%by, vpxor, \
                        ydata0, ydata1, ydata2, ydata3, ydata4, ydata5, ydata6, ydata7, \
                        ydata0, ydata1, ydata2, ydata3, ydata4, ydata5, ydata6, ydata7, \
                        ykey, ykey, ykey, ykey, ykey, ykey, ykey, ykey

        ;; AESENC rounds
%assign K 1
%rep %%rounds
        vbroadcasti128  ykey, [p_keys + K*16]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%by, vaesenc, \
                        ydata0, ydata1, ydata2, ydata3, ydata4, ydata5, ydata6, ydata7, \
                        ydata0, ydata1, ydata2, ydata3, ydata4, ydata5, ydata6, ydata7, \
                        ykey, ykey, ykey, ykey, ykey, ykey, ykey, ykey
%assign K (K + 1)
%endrep                         ; AESENC keys

        ;; AESENCLAST round
        vbroadcasti128  ykey, [p_keys + K*16]
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%by, vaesenclast, \
                        ydata0, ydata1, ydata2, ydata3, ydata4, ydata5, ydata6, ydata7, \
                        ydata0, ydata1, ydata2, ydata3, ydata4, ydata5, ydata6, ydata7, \
                        ykey, ykey, ykey, ykey, ykey, ykey, ykey, ykey

        ;; xor with plain/cipher text and store
%assign i 0
%rep (%%by / 2)
        vmovdqu         ykey, [p_in + i*32]
        vpxor           CONCAT(ydata,i), CONCAT(ydata,i), ykey
        vmovdqu         [p_out + i*32], CONCAT(ydata,i)
%assign i (i + 1)
%endrep
%if (%%by % 2) == 1
        vmovdqu         xkey, [p_in + i*32]
        vpxor           CONCAT(xdata,i), CONCAT(xdata,i), xkey
        vmovdqu         [p_out + i*32], CONCAT(xdata,i)
%endif

        add             p_in, 16*%%by
        add             p_out, 16*%%by

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;
;; Macro generating AES-CTR implementation for specific key size
;;
%macro DO_CNTR 2
%define %%KEY_SIZE_BITS %1      ;; [in] Numeric value: 128, 192 or 256
%define %%CNTR_TYPE     %2      ;; [in] Type of CNTR operation to do (CNTR/CCM)

%if %%KEY_SIZE_BITS == 128
%define %%NROUNDS 9
%elif %%KEY_SIZE_BITS == 256
%define %%NROUNDS 13
%elif %%KEY_SIZE_BITS == 192
%define %%NROUNDS 11
%else
%error "AES-CTR AVX2 VAES: unsupported key size!"
%endif

        vmovdqa         ybyteswap, [rel vavx2_byteswap_const2]

%ifidn %%CNTR_TYPE, CCM
        mov     p_in, [job + _src]
        add     p_in, [job + _cipher_start_src_offset_in_bytes]
        mov     arg_ivlen, [job + _iv_len_in_bytes]
        mov     num_bytes, [job + _msg_len_to_cipher_in_bytes]
        mov     p_keys, [job + _enc_keys]
        mov     p_out, [job + _dst]
        ;; Prepare IV

        ;; Byte 0: flags with L'
        ;; Calculate L' = 15 - Nonce length - 1 = 14 - IV length
        mov     flags, 14
        sub     flags, arg_ivlen
        vmovd   xcounter, DWORD(flags)
        ;; Bytes 1 - 13: Nonce (7 - 13 bytes long)

        ;; Bytes 1 - 7 are always copied (first 7 bytes)
        mov     p_IV, [job + _iv]
        vpinsrb xcounter, [p_IV], 1
        vpinsrw xcounter, [p_IV + 1], 1
        vpinsrd xcounter, [p_IV + 3], 1

        cmp     arg_ivlen, 7
        je      %%_finish_nonce_move

        cmp     arg_ivlen, 8
        je      %%_iv_length_8
        cmp     arg_ivlen, 9
        je      %%_iv_length_9
        cmp     arg_ivlen, 10
        je      %%_iv_length_10
        cmp     arg_ivlen, 11
        je      %%_iv_length_11
        cmp     arg_ivlen, 12
        je      %%_iv_length_12

        ;; Bytes 8 - 13
%%_iv_length_13:
        vpinsrb xcounter, [p_IV + 12], 13
%%_iv_length_12:
        vpinsrb xcounter, [p_IV + 11], 12
%%_iv_length_11:
        vpinsrd xcounter, [p_IV + 7], 2
        jmp     %%_finish_nonce_move
%%_iv_length_10:
        vpinsrb xcounter, [p_IV + 9], 10
%%_iv_length_9:
        vpinsrb xcounter, [p_IV + 8], 9
%%_iv_length_8:
        vpinsrb xcounter, [p_IV + 7], 8

align_label
%%_finish_nonce_move:
        ; last byte = 1
        vpor    xcounter, [rel set_byte15]

%else ;; CNTR/CCM

%ifndef LINUX
        mov             num_bytes, [rsp + 8*5] ; arg5
        mov             arg_ivlen, [rsp + 8*6] ; arg6
%endif

        ;; Read 16 byte IV: Nonce + 8-byte block counter (BE)
        test            arg_ivlen, 16
        jnz             %%iv_is_16_bytes

        ;; Read 12 bytes: Nonce + ESP IV. Then pad with block counter 0x00000001
        mov             DWORD(tmp), 0x01000000
        vmovq           xcounter, [p_IV]
        vpinsrd         xcounter, [p_IV + 8], 2
        vpinsrd         xcounter, DWORD(tmp), 3
        jmp             %%_bswap_xcounter

align_label
%%iv_is_16_bytes:
        vmovdqu         xcounter, [p_IV]
%endif ;; CCM

align_label
%%_bswap_xcounter:
        vpshufb         xcounter, xbyteswap
        ;; calculate len
        ;; convert bits to bytes (message length in bits for CNTR_BIT)
        mov             DWORD(tmp), DWORD(num_bytes)
        and             DWORD(tmp), 15*16
        jz              %%chk             ; multiple of 16x16 or zero

        ; 1 <= tmp <= 15
        cmp             DWORD(tmp), 2*16
        je              %%eq2
        jb              %%eq1
        cmp             DWORD(tmp), 14*16
        je              %%eq14
        ja              %%eq15
        cmp             DWORD(tmp), 4*16
        je              %%eq4
        jb              %%eq3
        cmp             DWORD(tmp), 12*16
        je              %%eq12
        ja              %%eq13
        cmp             DWORD(tmp), 6*16
        je              %%eq6
        jb              %%eq5
        cmp             DWORD(tmp), 10*16
        je              %%eq10
        ja              %%eq11
        cmp             DWORD(tmp), 8*16
        je              %%eq8
        jb              %%eq7
        jmp             %%eq9

%assign L 1

%rep 15

align 32
%%eq %+ L :
        do_aes  L, %%NROUNDS
%if L < 15
        jmp     %%chk
%else
        ; fall through to chk
%endif

%assign L (L + 1)
%endrep

align_label
%%chk:
        and             num_bytes, ~(15 * 16)
        jz              %%do_return2

        cmp             num_bytes, 16
        jb              %%last

        ;; prep for by16 loop
        vmovd           DWORD(tmp), xcounter
        and             DWORD(tmp), 255
        vinserti128     ycounter, xcounter, 1
        vpshufb         ycounter, ycounter, ybyteswap
align_loop
%%main_loop2:
        ; num_bytes is a multiple of 16 blocks + partial bytes
        do_aes          16, %%NROUNDS
        sub             num_bytes, 16*16
        cmp             num_bytes, 16*16
        jae             %%main_loop2

        ; Check if there is a partial block
        or              num_bytes, num_bytes
        jz              %%do_return2

        ;; get counter block back to LE
        vpshufb         xcounter, xcounter, xbyteswap

align_label
%%last:
        ; load partial block into XMM register
        simd_load_avx_15_1 xpart, p_in, num_bytes

align_label
%%final_ctr_enc:
        ; Encryption of a single partial block
        vpshufb         xdata0, xcounter, xbyteswap
        vpxor           xdata0, xdata0, [p_keys + 16*0]
%assign i 1
%rep %%NROUNDS
        vaesenc         xdata0, xdata0, [p_keys + 16*i]
%assign i (i+1)
%endrep
        ; created keystream
        vaesenclast     xdata0, xdata0, [p_keys + 16*i]

        ; xor keystream with the message (scratch)
        vpxor           xdata0, xdata0, xpart

align_label
%%store_output:
        ; copy result into the output buffer
        simd_store_avx_15 p_out, xdata0, num_bytes, tmp, rax

align_label
%%do_return2:
%ifidn %%CNTR_TYPE, CCM
        mov     rax, job
        or      dword [rax + _status], IMB_STATUS_COMPLETED_CIPHER
%endif

%ifdef SAFE_DATA
        clear_all_ymms_asm
%endif ;; SAFE_DATA

%endmacro

%endif  ; AES_CNTR_VAES_AVX2_INC
