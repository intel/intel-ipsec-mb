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

%define GCM128_MODE 1 ; Need to define GCM128_MODEi just for gcm_sse.inc

%include "include/gcm_sse.inc"
%include "include/align_sse.inc"

section .text
default rel

MKGLOBAL(polyval_pre_sse,function,)
align_function
polyval_pre_sse:
        endbranch64

%ifidn __OUTPUT_FORMAT__, win64
        sub     rsp, 1*16
        ; only xmm6 needs to be maintained
        movdqu  [rsp + 0*16], xmm6
%endif

        ;;;   From Appendix A of RFC 8452
        ;;;   POLYVAL(H, X_1, ..., X_n) =
        ;;;   ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)), ByteReverse(X_1), ...,
        ;;;   ByteReverse(X_n)))

        movdqu  xmm6, [arg1]
        ;; To compute polyval hash keys, first calculate internal key H' (mulX_GHASH(ByteReverse(H)))
        movdqa  xmm2, xmm6
        psrlq   xmm6, 1
        psllq   xmm2, 63
        movdqa  xmm1, xmm2
        psrldq  xmm2, 8
        pslldq  xmm1, 8
        por     xmm6, xmm2
        ;reduction
        pshufd  xmm2, xmm1, 11100111b
        pcmpeqd xmm2, [rel MSB_POLYVAL]
        pand    xmm2, [rel POLY_POLYVAL]
        pxor    xmm6, xmm2                       ; xmm6 holds the HashKey<<1 mod poly

        ;;;;;;;;;;;;;;;  PRECOMPUTATION of HashKey<<1 mod poly from the HashKey;;;;;;;;;;;;;;;
        movdqa  xmm2, xmm6
        psllq   xmm6, 1
        psrlq   xmm2, 63
        movdqa  xmm1, xmm2
        pslldq  xmm2, 8
        psrldq  xmm1, 8
        por     xmm6, xmm2
        ;reduction
        pshufd  xmm2, xmm1, 00100100b
        pcmpeqd xmm2, [rel TWOONE]
        pand    xmm2, [rel POLY]
        pxor    xmm6, xmm2                       ; xmm6 holds the HashKey<<1 mod poly
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        movdqu  [arg2 + HashKey], xmm6                 ; store HashKey<<1 mod poly

        PRECOMPUTE arg2, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5

%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_scratch_xmms_sse_asm
%endif
%ifidn __OUTPUT_FORMAT__, win64
        movdqu  xmm6, [rsp + 0*16]
        add     rsp, 1*16
%endif
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   polyval_16B_sse
;       (const void   *hash_key,
;        void   *in_out)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(polyval_16B_sse,function,)
align_function
polyval_16B_sse:
        endbranch64
%ifidn __OUTPUT_FORMAT__, win64
        sub     rsp, 1*16
        ; only xmm6 needs to be maintained
        movdqu  [rsp + 0*16], xmm6
%endif

        movdqu  xmm0, [arg1]
        movdqu  xmm1, [arg2]

        GHASH_MUL xmm1, xmm0, xmm2, xmm3, xmm4, xmm5, xmm6

        movdqu  [arg2], xmm1

%ifidn __OUTPUT_FORMAT__, win64
        movdqu  xmm6, [rsp + 0*16]
        add     rsp, 1*16
%endif
        ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   polyval_sse
;       (const struct gcm_key_data *key_data,
;        const void   *in,
;        const u64    in_len,
;        void         *io_tag)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(polyval_sse,function,)
align_function
polyval_sse:
        endbranch64
        FUNC_SAVE

        ;; copy tag to xmm0
        movdqu  xmm0, [arg4]

        CALC_AAD_HASH arg2, arg3, xmm0, arg1, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, \
                      r10, r11, r12, r13, rax, 1

        movdqu  [arg4], xmm0

        FUNC_RESTORE
        ret

