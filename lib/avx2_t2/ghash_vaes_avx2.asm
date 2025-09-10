;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2024, Intel Corporation All rights reserved.
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

%define GCM128_MODE

%use smartalign

%define GHASH_API_IMPLEMENTATION
%include "include/gcm_vaes_avx2.inc"
%include "include/align_avx.inc"

mksection .text
default rel

;; IN:
;;   arg1      - key pointer
;;   ymm1-ymm8 - input data blocks
;; OUT:
;;   xmm14     - contains the final hash
;; CLOBBERS:
;;   xmm0, xmm10-xmm13

%assign NB 1

%rep 16
align_function
MKGLOBAL(ghash_ %+ NB %+ _vaes_avx2,function,internal)
ghash_ %+ NB %+ _vaes_avx2:
        GHASH_N_BLOCKS arg1, NB
        ret
%assign NB (NB + 1)
%endrep

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   ghash_pre_vaes_avx2
;       (const void *key, struct gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(ghash_pre_vaes_avx2,function,)
ghash_pre_vaes_avx2:
        endbranch64
;; Parameter is passed through register
%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key != NULL
        cmp     arg1, 0
        jz      .error_ghash_pre

        ;; Check key_data != NULL
        cmp     arg2, 0
        jz      .error_ghash_pre
%endif

%ifidn __OUTPUT_FORMAT__, win64
        sub     rsp, 1*16

        ; only xmm6 needs to be maintained
        vmovdqu [rsp + 0*16], xmm6
%endif
        vmovdqu  xmm6, [arg1]
        vpshufb  xmm6, [rel SHUF_MASK]
        ;;;;;;;;;;;;;;;  PRECOMPUTATION of HashKey<<1 mod poly from the HashKey;;;;;;;;;;;;;;;
        vpsrlq   xmm2, xmm6, 63
        vpsllq   xmm6, xmm6, 1
        vpsrldq  xmm1, xmm2, 8
        vpslldq  xmm2, xmm2, 8
        vpor     xmm6, xmm6, xmm2
        ;reduction
        vpshufd  xmm2, xmm1, 00100100b
        vpcmpeqd xmm2, [rel TWOONE]
        vpand    xmm2, xmm2, [rel POLY]
        vpxor    xmm6, xmm6, xmm2                       ; xmm6 holds the HashKey<<1 mod poly
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqu  [arg2 + HashKey_1], xmm6               ; store HashKey<<1 mod poly

        PRECOMPUTE arg2, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5

%ifdef SAFE_DATA
        clear_scratch_xmms_avx_asm
%endif
%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu xmm6, [rsp + 0*16]
        add     rsp, 1*16
%endif
align_label
.exit_ghash_pre:
        ret

%ifdef SAFE_PARAM
align_label
.error_ghash_pre:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_KEY

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_EXP_KEY

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     .exit_ghash_pre
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; ghash_internal_vaes_avx2
;; [in] r12 = A_IN
;; [in] r13 = A_LEN
;; [in] arg1 = GDATA_KEY
;; [in/out] xmm0 = hash in/out
;; [clobbered] xmm1-xmm6
;; [clobbered] r10, r11, rax
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(ghash_internal_vaes_avx2,function,internal)
ghash_internal_vaes_avx2:
        CALC_AAD_HASH r12, r13, xmm0, arg1, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, \
                        r10, r11, rax
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; partial_block_gmac_vaes_avx2
;; [in] arg2 = GDATA_CTX
;; [in] arg3 = PLAIN_IN
;; [in] arg4 = PLAIN_LEN
;; [out] r11 = DATA_OFFSET
;; [in/out] xmm0 = hash in/out
;; [in] xmm13 = hash key
;; [in] xmm14 = hash-K key
;; [clobbered] xmm1-xmm6, xmm8, xmm9, xmm10
;; [clobbered] r10, r12, r13, r15, rax
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(partial_block_gmac_vaes_avx2,function,internal)
partial_block_gmac_vaes_avx2:
        PARTIAL_BLOCK_GMAC arg2, arg3, arg4, r11, xmm0, xmm13, xmm14, \
                        xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm8, xmm9, xmm10
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   ghash_vaes_avx2(
;        const struct gcm_key_data *key_data,
;        const void   *in,
;        const u64    in_len,
;        void         *io_tag,
;        const u64    tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(ghash_vaes_avx2,function,)
ghash_vaes_avx2:
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        or      arg1, arg1
        jz      .error_ghash

        ;; Check in != NULL
        or      arg2, arg2
        jz      .error_ghash

        ;; Check in_len != 0
        or      arg3, arg3
        jz      .error_ghash

        ;; Check tag != NULL
        or      arg4, arg4
        jz      .error_ghash

        ;; Check tag_len != 0
        cmp     arg5, 0
        jz      .error_ghash
%endif

        ;; copy tag to xmm0
        vmovdqu xmm0, [arg4]
        vpshufb xmm0, [rel SHUF_MASK] ; perform a 16Byte swap

        mov     r12, arg2
        mov     r13, arg3
        call    ghash_internal_vaes_avx2
        vpshufb xmm0, [rel SHUF_MASK] ; perform a 16Byte swap

        simd_store_avx arg4, xmm0, arg5, r12, rax

align_label
.exit_ghash:
        FUNC_RESTORE
        ret

%ifdef SAFE_PARAM
align_label
.error_ghash:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check in != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_SRC

        ;; Check in_len != 0
        IMB_ERR_CHECK_ZERO arg3, rax, IMB_ERR_AUTH_LEN

        ;; Check tag != NULL
        IMB_ERR_CHECK_NULL arg4, rax, IMB_ERR_NULL_AUTH

        ;; Check tag_len != 0
        IMB_ERR_CHECK_ZERO arg5, rax, IMB_ERR_AUTH_TAG_LEN

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax

        jmp     .exit_ghash
%endif

mksection stack-noexec
