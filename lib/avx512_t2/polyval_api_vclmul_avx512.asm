;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2025 Intel Corporation All rights reserved.
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

%define GCM128_MODE 1 ; Need to define GCM128_MODE just for gcm_vaes_avx512.inc

%include "include/gcm_vaes_avx512.inc"

section .text
default rel

align_function
MKGLOBAL(polyval_pre_vclmul_avx512,function,)
polyval_pre_vclmul_avx512:
        endbranch64
        FUNC_SAVE small_frame

        ;;;   From Appendix A of RFC 8452
        ;;;   POLYVAL(H, X_1, ..., X_n) =
        ;;;   ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)), ByteReverse(X_1), ...,
        ;;;   ByteReverse(X_n)))

        vmovdqu xmm6, [arg1]
        ;; To compute polyval hash keys, first calculate internal key H' (mulX_GHASH(ByteReverse(H)))
        vmovdqa  xmm2, xmm6
        vpsrlq   xmm6, xmm6, 1
        vpsllq   xmm2, xmm2, 63
        vmovdqa  xmm1, xmm2
        vpsrldq  xmm2, xmm2, 8
        vpslldq  xmm1, xmm1, 8
        vpor     xmm6, xmm6, xmm2
        ;reduction
        vpshufd  xmm2, xmm1, 11100111b
        vpcmpeqd xmm2, [rel MSB_POLYVAL]
        vpand    xmm2, xmm2, [rel POLY_POLYVAL]
        vpxor    xmm6, xmm6, xmm2                       ; xmm6 holds the HashKey<<1 mod poly

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   polyval_16B_vclmul_avx512
;       (const void   *hash_key,
;        void   *in_out)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(polyval_16B_vclmul_avx512,function,)
polyval_16B_vclmul_avx512:
        endbranch64

        vmovdqu64  xmm0, [arg1]
        vmovdqu64  xmm1, [arg2]

        GHASH_MUL xmm1, xmm0, xmm2, xmm3, xmm4, xmm5, xmm16

        vmovdqu64 [arg2], xmm1

        vzeroupper

        ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   polyval_vclmul_avx512
;       (const struct gcm_key_data *key_data,
;        const void   *in,
;        const u64    in_len,
;        void         *io_tag)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(polyval_vclmul_avx512,function,)
polyval_vclmul_avx512:
        endbranch64

        ;; copy tag to xmm0
        vmovdqu  xmm0, [arg4]
        CALC_AAD_HASH arg2, arg3, xmm0, arg1, zmm1, zmm2, zmm3, zmm4, zmm5, zmm16, \
                        zmm17, zmm18, zmm19, zmm20, zmm21, zmm22, zmm23, zmm24, zmm25, \
                        zmm26, zmm27, zmm28, r10, r11, rax, k1, 1

        vmovdqu  [arg4], xmm0
%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%else
        vzeroupper
%endif
        ret
