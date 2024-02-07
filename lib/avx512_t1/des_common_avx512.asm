;
;; Copyright (c) 2024, Intel Corporation
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

;; Collection of functions generated by DES_ENC_DEC macro with preset input/output arguments.
;; This method allows to reduce code footprint while maintaining identical performance.
;;
;; If register usage changes then generated functions below may need to be corrected.
;; See DES_ENC_DEC macro for more details.

%include "include/des_avx512.inc"

;;; ========================================================
;;; DATA

extern des_mask_values_avx512
extern des_init_perm_consts_avx512
extern des_S_box_flipped_avx512
extern des_vec_ones_32b_avx512
extern des_and_eu_avx512
extern des_and_ed_avx512
extern des_idx_e_avx512
extern des_reg_values16bit_7_avx512
extern des_shuffle_reg_avx512

;;; ========================================================
;;; CODE
mksection .text

;;; >>>>>>>>>>>>>> ENCRYPT FUNCTIONS

;;; r15  : key schedule pointer
;;; zmm0 : [in/out] R
;;; zmm1 : [in/out] L
align 64
MKGLOBAL(des_enc_zmm0_zmm1_avx512,function,internal)
des_enc_zmm0_zmm1_avx512:
        DES_ENC_DEC_EXP ENC,zmm0,zmm1,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15  : key schedule pointer
;;; zmm2 : [in/out] R
;;; zmm3 : [in/out] L
align 64
MKGLOBAL(des_enc_zmm2_zmm3_avx512,function,internal)
des_enc_zmm2_zmm3_avx512:
        DES_ENC_DEC_EXP ENC,zmm2,zmm3,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15  : key schedule pointer
;;; zmm4 : [in/out] R
;;; zmm5 : [in/out] L
align 64
MKGLOBAL(des_enc_zmm4_zmm5_avx512,function,internal)
des_enc_zmm4_zmm5_avx512:
        DES_ENC_DEC_EXP ENC,zmm4,zmm5,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15  : key schedule pointer
;;; zmm6 : [in/out] R
;;; zmm7 : [in/out] L
align 64
MKGLOBAL(des_enc_zmm6_zmm7_avx512,function,internal)
des_enc_zmm6_zmm7_avx512:
        DES_ENC_DEC_EXP ENC,zmm6,zmm7,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15  : key schedule pointer
;;; zmm8 : [in/out] R
;;; zmm9 : [in/out] L
align 64
MKGLOBAL(des_enc_zmm8_zmm9_avx512,function,internal)
des_enc_zmm8_zmm9_avx512:
        DES_ENC_DEC_EXP ENC,zmm8,zmm9,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15   : key schedule pointer
;;; zmm10 : [in/out] R
;;; zmm11 : [in/out] L
align 64
MKGLOBAL(des_enc_zmm10_zmm11_avx512,function,internal)
des_enc_zmm10_zmm11_avx512:
        DES_ENC_DEC_EXP ENC,zmm10,zmm11,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15   : key schedule pointer
;;; zmm12 : [in/out] R
;;; zmm13 : [in/out] L
align 64
MKGLOBAL(des_enc_zmm12_zmm13_avx512,function,internal)
des_enc_zmm12_zmm13_avx512:
        DES_ENC_DEC_EXP ENC,zmm12,zmm13,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15   : key schedule pointer
;;; zmm14 : [in/out] R
;;; zmm15 : [in/out] L
align 64
MKGLOBAL(des_enc_zmm14_zmm15_avx512,function,internal)
des_enc_zmm14_zmm15_avx512:
        DES_ENC_DEC_EXP ENC,zmm14,zmm15,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; CFB ONE use case
;;; r15   : key schedule pointer
;;; zmm18 : [in/out] R
;;; zmm19 : [in/out] L
align 64
MKGLOBAL(des_enc_zmm18_zmm19_avx512,function,internal)
des_enc_zmm18_zmm19_avx512:
        DES_ENC_DEC_EXP ENC,zmm18,zmm19,r15,zmm2,zmm3,zmm4,zmm5,zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13
        ret

;;; >>>>>>>>>>>>>> DECRYPT FUNCTIONS

;;; r15  : key schedule pointer
;;; zmm0 : [in/out] R
;;; zmm1 : [in/out] L
align 64
MKGLOBAL(des_dec_zmm0_zmm1_avx512,function,internal)
des_dec_zmm0_zmm1_avx512:
        DES_ENC_DEC_EXP DEC,zmm0,zmm1,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15  : key schedule pointer
;;; zmm2 : [in/out] R
;;; zmm3 : [in/out] L
align 64
MKGLOBAL(des_dec_zmm2_zmm3_avx512,function,internal)
des_dec_zmm2_zmm3_avx512:
        DES_ENC_DEC_EXP DEC,zmm2,zmm3,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15  : key schedule pointer
;;; zmm4 : [in/out] R
;;; zmm5 : [in/out] L
align 64
MKGLOBAL(des_dec_zmm4_zmm5_avx512,function,internal)
des_dec_zmm4_zmm5_avx512:
        DES_ENC_DEC_EXP DEC,zmm4,zmm5,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15  : key schedule pointer
;;; zmm6 : [in/out] R
;;; zmm7 : [in/out] L
align 64
MKGLOBAL(des_dec_zmm6_zmm7_avx512,function,internal)
des_dec_zmm6_zmm7_avx512:
        DES_ENC_DEC_EXP DEC,zmm6,zmm7,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15  : key schedule pointer
;;; zmm8 : [in/out] R
;;; zmm9 : [in/out] L
align 64
MKGLOBAL(des_dec_zmm8_zmm9_avx512,function,internal)
des_dec_zmm8_zmm9_avx512:
        DES_ENC_DEC_EXP DEC,zmm8,zmm9,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15   : key schedule pointer
;;; zmm10 : [in/out] R
;;; zmm11 : [in/out] L
align 64
MKGLOBAL(des_dec_zmm10_zmm11_avx512,function,internal)
des_dec_zmm10_zmm11_avx512:
        DES_ENC_DEC_EXP DEC,zmm10,zmm11,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15   : key schedule pointer
;;; zmm12 : [in/out] R
;;; zmm13 : [in/out] L
align 64
MKGLOBAL(des_dec_zmm12_zmm13_avx512,function,internal)
des_dec_zmm12_zmm13_avx512:
        DES_ENC_DEC_EXP DEC,zmm12,zmm13,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; r15   : key schedule pointer
;;; zmm14 : [in/out] R
;;; zmm15 : [in/out] L
align 64
MKGLOBAL(des_dec_zmm14_zmm15_avx512,function,internal)
des_dec_zmm14_zmm15_avx512:
        DES_ENC_DEC_EXP DEC,zmm14,zmm15,r15,zmm18,zmm19,zmm20,zmm21,zmm22,zmm23,zmm24,zmm25,zmm26,zmm27,zmm28,zmm29
        ret

;;; CFB ONE use case
;;; r15   : key schedule pointer
;;; zmm18 : [in/out] R
;;; zmm19 : [in/out] L
align 64
MKGLOBAL(des_dec_zmm18_zmm19_avx512,function,internal)
des_dec_zmm18_zmm19_avx512:
        DES_ENC_DEC_EXP DEC,zmm18,zmm19,r15,zmm2,zmm3,zmm4,zmm5,zmm6,zmm7,zmm8,zmm9,zmm10,zmm11,zmm12,zmm13
        ret

mksection stack-noexec