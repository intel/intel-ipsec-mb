;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2021-2023, Intel Corporation All rights reserved.
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

%include "include/gcm_vaes_avx512.inc"
%include "include/error.inc"
%include "include/clear_regs.inc"

%ifndef GCM_GMAC_API_VAES_AVX512_INC
%define GCM_GMAC_API_VAES_AVX512_INC

extern ghash_internal_vaes_avx512

mksection .text
default rel

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   imb_aes_gmac_update_128_vaes_avx512 /
;       imb_aes_gmac_update_192_vaes_avx512 /
;       imb_aes_gmac_update_256_vaes_avx512
;        const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        const   u8 *in,
;        const   u64 msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(GMAC_FN_NAME(update),function,)
GMAC_FN_NAME(update):
        endbranch64
	FUNC_SAVE small_frame

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
	vmovdqu64	xmm0, [arg2 + AadHash]

	PARTIAL_BLOCK_GMAC arg1, arg2, arg3, arg4, r11, xmm0, r10, r12, rax, \
                           zmm8, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, k1
%ifdef SAFE_DATA
        clear_zmms_avx512 xmm8
%endif
        ; CALC_AAD_HASH needs to deal with multiple of 16 bytes
        sub     arg4, r11
        add     arg3, r11

        vmovq   xmm21, arg4 ; Save remaining length
        and     arg4, -16 ; Get multiple of 16 bytes

        or      arg4, arg4
        jz      no_full_blocks

        ;; Calculate GHASH of this segment

        ;; arg1 [in] pointer to key structure - arg1 here
        ;; arg2 [in] message pointer - arg3 here
        ;; arg3 [in] message length  - arg4 here
        mov     r15, arg2
        mov     r13, arg3
        mov     arg2, arg3
        mov     arg3, arg4

        ;; xmm0 [in/out] ghash value
        call    ghash_internal_vaes_avx512

        ;; restore original arguments
        mov     arg2, r15
        mov     arg3, r13

	vmovdqu64	[arg2 + AadHash], xmm0	; ctx_data.aad hash = aad_hash

        ;; **zmm2, zmm3, zmm4 and zmm5 may contain clear text
        ;; **zmm19 may contain authentication key
%ifdef SAFE_DATA
        clear_zmms_avx512 xmm2, xmm3, xmm4, xmm5, xmm18, xmm19
%endif

no_full_blocks:
        add     arg3, arg4 ; Point at partial block

        vmovq   arg4, xmm21 ; Restore original remaining length
        and     arg4, 15
        jz      exit_gmac_update

        ; Save next partial block
        mov	[arg2 + PBlockLen], arg4
        READ_SMALL_DATA_INPUT_AVX512 xmm1, arg3, arg4, r11, k1
        vpshufb xmm1, xmm1, [rel SHUF_MASK]
        vpxorq  xmm0, xmm0, xmm1
        vmovdqu64 [arg2 + AadHash], xmm0
%ifdef SAFE_DATA
        ;; **xmm1 and xmm8 may contain some clear text
        clear_zmms_avx512 xmm1, xmm0
%endif
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

%endif ; GCM_GMAC_API_VAES_AVX512_INC
