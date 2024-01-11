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
%include "include/gcm_vaes_avx512.inc"

%include "include/error.inc"
%include "include/clear_regs.inc"

mksection .text
default rel

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   ghash_pre_vaes_avx512
;       (const void *key, struct gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(ghash_pre_vaes_avx512,function,)
ghash_pre_vaes_avx512:
        endbranch64
;; Parameter is passed through register
%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key != NULL
        cmp     arg1, 0
        jz      error_ghash_pre

        ;; Check key_data != NULL
        cmp     arg2, 0
        jz      error_ghash_pre
%endif

        FUNC_SAVE small_frame

        vmovdqu xmm6, [arg1]
        vpshufb  xmm6, [rel SHUF_MASK]
        ;;;;;;;;;;;;;;;  PRECOMPUTATION of HashKey<<1 mod poly from the HashKey;;;;;;;;;;;;;;;
        vmovdqa  xmm2, xmm6
        vpsllq   xmm6, xmm6, 1
        vpsrlq   xmm2, xmm2, 63
        vmovdqa  xmm1, xmm2
        vpslldq  xmm2, xmm2, 8
        vpsrldq  xmm1, xmm1, 8
        vpor     xmm6, xmm6, xmm2
        ;reduction
        vpshufd  xmm2, xmm1, 00100100b
        vpcmpeqd xmm2, [rel TWOONE]
        vpand    xmm2, xmm2, [rel POLY]
        vpxor    xmm6, xmm6, xmm2                       ; xmm6 holds the HashKey<<1 mod poly
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqu  [arg2 + HashKey_1], xmm6                 ; store HashKey<<1 mod poly

        PRECOMPUTE arg2, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm7, xmm8
%ifdef SAFE_DATA
        clear_zmms_avx512 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8
%endif
        FUNC_RESTORE
exit_ghash_pre:

        ret

%ifdef SAFE_PARAM
error_ghash_pre:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_KEY

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_EXP_KEY

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_ghash_pre
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ghash_internal_vaes_avx512()
; r12 [in/clobbered] message pointer
; r13 [in/clobbered] message length
; xmm0 [in/out] ghash value
; arg1 [in] pointer to key structure
; clobbers: zmm1, zmm3-zmm13, zmm15-zmm20, rax, k1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(ghash_internal_vaes_avx512,function,internal)
ghash_internal_vaes_avx512:
        CALC_GHASH r12, r13, xmm0, arg1, zmm1, zmm3, zmm4, zmm5, \
                   zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, zmm12, zmm13, \
                   zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, rax, k1
        ;; **zmm3, zmm4, zmm5 and zmm6 may contain clear text
        ;; **zmm15, zmm16, zmm19 and zmm9 may contain hash key
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   ghash_vaes_avx512
;        const struct gcm_key_data *key_data,
;        const void   *in,
;        const u64    in_len,
;        void         *io_tag,
;        const u64    tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(ghash_vaes_avx512,function,)
ghash_vaes_avx512:
        endbranch64
        FUNC_SAVE small_frame

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      error_ghash

        ;; Check in != NULL
        cmp     arg2, 0
        jz      error_ghash

        ;; Check in_len != 0
        cmp     arg3, 0
        jz      error_ghash

        ;; Check tag != NULL
        cmp     arg4, 0
        jz      error_ghash

        ;; Check tag_len != 0
        cmp     arg5, 0
        jz      error_ghash
%endif

        ;; copy tag to xmm0
        vmovdqu	xmm0, [arg4]
        vpshufb xmm0, xmm0, [rel SHUF_MASK] ; perform a 16Byte swap

        ;; arg1 [in] pointer to key structure => arg1
        ;; r12 [in] message pointer => arg2
        ;; r13 [in] message length => arg3
        ;; xmm0 [in/out] ghash value
        mov     r12, arg2
        mov     r13, arg3
        call    ghash_internal_vaes_avx512

        vpshufb xmm0, xmm0, [rel SHUF_MASK] ; perform a 16Byte swap
        simd_store_avx arg4, xmm0, arg5, r12, rax
%ifdef SAFE_DATA
        clear_zmms_avx512 xmm0, xmm3, xmm4, xmm5, xmm6, xmm15, xmm16, xmm9, xmm19
%endif
exit_ghash:
        FUNC_RESTORE
        ret

%ifdef SAFE_PARAM
error_ghash:
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

        jmp     exit_ghash
%endif

mksection stack-noexec
