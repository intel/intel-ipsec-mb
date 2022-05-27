;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2021-2022 Intel Corporation All rights reserved.
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

%include "sse_t1/gcm_sse.inc"
%include "include/gcm_common.inc"

%ifndef GCM_GMAC_API_SSE_INC
%define GCM_GMAC_API_SSE_INC

section .text
default rel

%ifdef GCM128_MODE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   ghash_pre_sse / ghash_sse_no_aesni
;       (const void *key, struct gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifndef NO_AESNI
MKGLOBAL(ghash_pre_sse,function,)
ghash_pre_sse:
%else
MKGLOBAL(ghash_pre_sse_no_aesni,function,)
ghash_pre_sse_no_aesni:
%endif
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

%ifidn __OUTPUT_FORMAT__, win64
        push    r14
        mov     r14, rsp

        sub     rsp, VARIABLE_OFFSET
        and     rsp, ~63                                 ; align rsp to 64 bytes

        ; only xmm6 needs to be maintained
        movdqa [rsp + LOCAL_STORAGE + 0*16],xmm6
%endif
        movdqu xmm6, [arg1]
        pshufb  xmm6, [rel SHUF_MASK]
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
        movdqu xmm6, [rsp + LOCAL_STORAGE + 0*16]
        mov     rsp, r14
        pop     r14

%endif
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
;void   ghash_sse / ghash_sse_no_aesni
;       (const struct gcm_key_data *key_data,
;        const void   *in,
;        const u64    in_len,
;        void         *io_tag,
;        const u64    tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifndef NO_AESNI
MKGLOBAL(ghash_sse,function,)
ghash_sse:
%else
MKGLOBAL(ghash_sse_no_aesni,function,)
ghash_sse_no_aesni:
%endif
        endbranch64
        FUNC_SAVE

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
        movdqu  xmm0, [arg4]
        pshufb  xmm0, [rel SHUF_MASK] ; perform a 16Byte swap

        CALC_AAD_HASH arg2, arg3, xmm0, arg1, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, \
                      r10, r11, r12, r13, rax

        pshufb  xmm0, [rel SHUF_MASK] ; perform a 16Byte swap

        simd_store_sse arg4, xmm0, arg5, r12, rax

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

%endif ;; GCM128_MODE

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   imb_aes_gmac_update_128_sse / imb_aes_gmac_update_192_sse /
;       aes_gmac_update_256_sse
;        const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        const   u8 *in,
;        const   u64 msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(GMAC_FN_NAME(update),function,)
GMAC_FN_NAME(update):
        endbranch64
	FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET
%endif
        ;; Check if msg_len == 0
	cmp	arg4, 0
	je	exit_gmac_update

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      error_gmac_update

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      error_gmac_update

        ;; Check in != NULL (msg_len != 0)
        cmp     arg3, 0
        jz      error_gmac_update
%endif

        ; Increment size of "AAD length" for GMAC
        add     [arg2 + AadLen], arg4

        ;; Deal with previous partial block
	xor	r11, r11
	movdqu	xmm13, [arg1 + HashKey]
	movdqu	xmm8, [arg2 + AadHash]

	PARTIAL_BLOCK_GMAC arg1, arg2, arg3, arg4, r11, xmm8, xmm13

        ; CALC_AAD_HASH needs to deal with multiple of 16 bytes
        sub     arg4, r11
        add     arg3, r11

        movq    xmm7, arg4 ; Save remaining length
        and     arg4, -16 ; Get multiple of 16 bytes

        or      arg4, arg4
        jz      no_full_blocks

        ;; Calculate GHASH of this segment
        CALC_AAD_HASH arg3, arg4, xmm8, arg1, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, \
                      r10, r11, r12, r13, rax
	movdqu	[arg2 + AadHash], xmm8	; ctx_data.aad hash = aad_hash

no_full_blocks:
        add     arg3, arg4 ; Point at partial block

        movq    arg4, xmm7 ; Restore original remaining length
        and     arg4, 15
        jz      exit_gmac_update

        ; Save next partial block
        mov	[arg2 + PBlockLen], arg4
        READ_SMALL_DATA_INPUT_SSE xmm1, arg3, arg4, r11, r12, r13
        pshufb  xmm1, [rel SHUF_MASK]
        pxor    xmm8, xmm1
        movdqu  [arg2 + AadHash], xmm8

exit_gmac_update:
	FUNC_RESTORE

	ret

%ifdef SAFE_PARAM
error_gmac_update:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check in != NULL (msg_len != 0)
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_SRC

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_gmac_update
%endif

mksection stack-noexec

%endif ; GCM_GMAC_API_SSE_INC
