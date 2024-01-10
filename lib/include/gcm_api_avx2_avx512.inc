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

%use smartalign

%include "include/gcm_common_avx2_avx512.inc"

mksection .text
default rel

extern GHASH_FN_NAME(ghash_internal)
extern GHASH_FN_NAME(partial_block_gmac)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_precomp_128_avx_gen4 /
;       aes_gcm_precomp_192_avx_gen4 /
;       aes_gcm_precomp_256_avx_gen4 /
;       aes_gcm_precomp_128_avx512 /
;       aes_gcm_precomp_192_avx512 /
;       aes_gcm_precomp_256_avx512
;       (struct gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(precomp,_),function,)
FN_NAME(precomp,_):
        endbranch64
%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        or      arg1, arg1
        jz      error_precomp
%endif

%ifidn __OUTPUT_FORMAT__, win64
        sub     rsp, 1*16
        ; only xmm6 needs to be maintained
        vmovdqu [rsp + 0*16],xmm6
%endif

        vpxor   xmm6, xmm6
        ENCRYPT_SINGLE_BLOCK    arg1, xmm6              ; xmm6 = HashKey

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
        vmovdqu  [arg1 + HashKey], xmm6                 ; store HashKey<<1 mod poly

        PRECOMPUTE arg1, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5

%ifdef SAFE_DATA
        clear_scratch_xmms_avx_asm
%endif

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu xmm6, [rsp + 0*16]
        add     rsp, 1*16
%endif

exit_precomp:

        ret

%ifdef SAFE_PARAM
error_precomp:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax

        jmp exit_precomp
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_128_avx_gen4 / aes_gcm_init_192_avx_gen4 / aes_gcm_init_256_avx_gen4 /
;       aes_gcm_init_128_avx512 / aes_gcm_init_192_avx512 / aes_gcm_init_256_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(init,_),function,)
FN_NAME(init,_):
        endbranch64
        push    r12
        push    r13
%ifidn __OUTPUT_FORMAT__, win64
        push    r14
        push    r15
        lea     r14, [rsp + 4*8]
	; xmm6 needs to be maintained for Windows
	sub	rsp, 1*16
	vmovdqu	[rsp + 0*16], xmm6
%endif

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        or      arg1, arg1
        jz      error_init

        ;; Check context_data != NULL
        or      arg2, arg2
        jz      error_init

        ;; Check IV != NULL
        or      arg3, arg3
        jz      error_init

        ;; Check if aad_len == 0
        cmp     arg5, 0
        jz      skip_aad_check_init

        ;; Check aad != NULL (aad_len != 0)
        or      arg4, arg4
        jz      error_init

skip_aad_check_init:
%endif
        GCM_INIT arg1, arg2, arg3, arg4, arg5

%ifdef SAFE_DATA
        clear_scratch_xmms_avx_asm
%endif
exit_init:

%ifidn __OUTPUT_FORMAT__, win64
	vmovdqu	xmm6 , [rsp + 0*16]
        add     rsp, 1*16
        pop     r15
        pop     r14
%endif
        pop     r13
        pop     r12
        ret

%ifdef SAFE_PARAM
error_init:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check IV != NULL
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_IV

        ;; Check if aad_len == 0
        cmp     arg5, 0
        jz      skip_aad_check_error_init

        ;; Check aad != NULL (aad_len != 0)
        IMB_ERR_CHECK_NULL arg4, rax, IMB_ERR_NULL_AAD

skip_aad_check_error_init:

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_init
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_var_iv_128_avx_gen4 / aes_gcm_init_var_iv_192_avx_gen4 /
;       aes_gcm_init_var_iv_256_avx_gen4
;       aes_gcm_init_var_iv_128_avx512 / aes_gcm_init_var_iv_192_avx512 /
;       aes_gcm_init_var_iv_256_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8        *iv,
;        const u64 iv_len,
;        const u8  *aad,
;        const u64 aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(init_var_iv,_),function,)
FN_NAME(init_var_iv,_):
        endbranch64
	push	r12
	push	r13
%ifidn __OUTPUT_FORMAT__, win64
        push    r14
        push    r15
        lea     r14, [rsp + 4*8]
	; xmm6 & xmm14 need to be maintained for Windows
	sub	rsp, 2*16
	vmovdqu	[rsp + 0*16], xmm6
	vmovdqu	[rsp + 1*16], xmm14
%endif

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        or      arg1, arg1
        jz      error_init_IV

        ;; Check context_data != NULL
        or      arg2, arg2
        jz      error_init_IV

        ;; Check IV != NULL
        or      arg3, arg3
        jz      error_init_IV

        ;; Check iv_len != 0
        or      arg4, arg4
        jz      error_init_IV

        ;; Check if aad_len == 0
        cmp     arg6, 0
        jz      skip_aad_check_init_IV

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg5, 0
        jz      error_init_IV

skip_aad_check_init_IV:
%endif

        GCM_INIT arg1, arg2, arg3, arg5, arg6, arg4

%ifdef SAFE_DATA
        clear_scratch_xmms_avx_asm
%endif
exit_init_IV:

%ifidn __OUTPUT_FORMAT__, win64
	vmovdqu	xmm6, [rsp + 0*16]
	vmovdqu	xmm14, [rsp + 1*16]
        add     rsp, 2*16
        pop     r15
        pop     r14
%endif
	pop	r13
	pop	r12
        ret

%ifdef SAFE_PARAM
error_init_IV:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check IV != NULL
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_IV

        ;; Check iv_len != 0
        IMB_ERR_CHECK_ZERO arg4, rax, IMB_ERR_IV_LEN

        ;; Check if aad_len == 0
        cmp     arg6, 0
        jz      skip_aad_check_error_init_IV

        ;; Check aad != NULL (aad_len != 0)
        IMB_ERR_CHECK_NULL arg5, rax, IMB_ERR_NULL_AAD

skip_aad_check_error_init_IV:

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_init_IV
%endif


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_update_avx_gen4 / aes_gcm_enc_192_update_avx_gen4 /
;       aes_gcm_enc_128_update_avx_gen4 /
;       aes_gcm_enc_128_update_avx512 / aes_gcm_enc_192_update_avx512 /
;       aes_gcm_enc_256_update_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(enc,_update_),function,)
FN_NAME(enc,_update_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
	;; Reset imb_errno
        IMB_ERR_CHECK_RESET

	;; Load max len to reg on windows
        INIT_GCM_MAX_LENGTH

        ;; Check key_data != NULL
        or      arg1, arg1
        jz      error_update_enc

        ;; Check context_data != NULL
        or      arg2, arg2
        jz      error_update_enc

        ;; Check if msg_len == 0
        cmp     arg5, 0
        jz      error_update_enc

        ;; Check if msg_len > max_len
        cmp     arg5, GCM_MAX_LENGTH
        ja      error_update_enc

        ;; Check out != NULL (msg_len != 0)
        or      arg3, arg3
        jz      error_update_enc

        ;; Check in != NULL (msg_len != 0)
        or      arg4, arg4
        jz      error_update_enc
%endif
        GCM_ENC_DEC arg1, arg2, arg3, arg4, arg5, ENC, multi_call

exit_update_enc:
        FUNC_RESTORE

        ret

%ifdef SAFE_PARAM
error_update_enc:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check if plaintext_len == 0
        cmp     arg5, 0
        jz      skip_in_out_check_error_update_enc

        ;; Check if msg_len > max_len
        IMB_ERR_CHECK_ABOVE arg5, GCM_MAX_LENGTH, rax, IMB_ERR_CIPH_LEN

        ;; Check out != NULL
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_DST

        ;; Check in != NULL (msg_len != 0)
        IMB_ERR_CHECK_NULL arg4, rax, IMB_ERR_NULL_SRC

skip_in_out_check_error_update_enc:
        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_update_enc
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_update_avx_gen4 / aes_gcm_dec_192_update_avx_gen4 /
;       aes_gcm_dec_256_update_avx_gen4 /
;       aes_gcm_dec_128_update_avx512 / aes_gcm_dec_192_update_avx512 /
;       aes_gcm_dec_256_update_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(dec,_update_),function,)
FN_NAME(dec,_update_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Load max len to reg on windows
        INIT_GCM_MAX_LENGTH

        ;; Check key_data != NULL
        or      arg1, arg1
        jz      error_update_dec

        ;; Check context_data != NULL
        or      arg2, arg2
        jz      error_update_dec

        ;; Check if msg_len == 0
        cmp     arg5, 0
        jz      error_update_dec

        ;; Check if msg_len > max_len
        cmp     arg5, GCM_MAX_LENGTH
        ja      error_update_dec

        ;; Check out != NULL (msg_len != 0)
        or      arg3, arg3
        jz      error_update_dec

        ;; Check in != NULL (msg_len != 0)
        or      arg4, arg4
        jz      error_update_dec
%endif

        GCM_ENC_DEC arg1, arg2, arg3, arg4, arg5, DEC, multi_call

exit_update_dec:
        FUNC_RESTORE

        ret

%ifdef SAFE_PARAM
error_update_dec:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check if plaintext_len == 0
        cmp     arg5, 0
        jz      skip_in_out_check_error_update_dec

        ;; Check if msg_len > max_len
        IMB_ERR_CHECK_ABOVE arg5, GCM_MAX_LENGTH, rax, IMB_ERR_CIPH_LEN

        ;; Check out != NULL
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_DST

        ;; Check in != NULL (plaintext_len != 0)
        IMB_ERR_CHECK_NULL arg4, rax, IMB_ERR_NULL_SRC

skip_in_out_check_error_update_dec:
        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_update_dec
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_finalize_avx_gen4 / aes_gcm_enc_192_finalize_avx_gen4 /
;	aes_gcm_enc_256_finalize_avx_gen4 /
;       aes_gcm_enc_128_finalize_avx512 / aes_gcm_enc_192_finalize_avx512 /
;	aes_gcm_enc_256_finalize_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(enc,_finalize_),function,)
FN_NAME(enc,_finalize_):
        endbranch64
%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        or      arg1, arg1
        jz      error_enc_fin

        ;; Check context_data != NULL
        or      arg2, arg2
        jz      error_enc_fin

        ;; Check auth_tag != NULL
        or      arg3, arg3
        jz      error_enc_fin

        ;; Check auth_tag_len == 0 or > 16
        or      arg4, arg4
        jz      error_enc_fin

        cmp     arg4, 16
        ja      error_enc_fin
%endif
        push r12

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
	sub	rsp, 7*16
        vmovdqu	[rsp + 0*16], xmm6
        vmovdqu	[rsp + 1*16], xmm9
        vmovdqu	[rsp + 2*16], xmm10
        vmovdqu	[rsp + 3*16], xmm11
        vmovdqu	[rsp + 4*16], xmm13
        vmovdqu	[rsp + 5*16], xmm14
        vmovdqu	[rsp + 6*16], xmm15
%endif
        GCM_COMPLETE    arg1, arg2, arg3, arg4, multi_call

%ifdef SAFE_DATA
        clear_scratch_xmms_avx_asm
%endif

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu	xmm15, [rsp + 6*16]
        vmovdqu	xmm14, [rsp + 5*16]
        vmovdqu	xmm13, [rsp + 4*16]
        vmovdqu	xmm11, [rsp + 3*16]
        vmovdqu	xmm10, [rsp + 2*16]
        vmovdqu	xmm9,  [rsp + 1*16]
        vmovdqu	xmm6,  [rsp + 0*16]
        add     rsp, 7*16
%endif
        pop r12
exit_enc_fin:
        ret

%ifdef SAFE_PARAM
error_enc_fin:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check auth_tag != NULL
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_AUTH

        ;; Check auth_tag_len == 0 or > 16
        IMB_ERR_CHECK_ZERO arg4, rax, IMB_ERR_AUTH_TAG_LEN

        IMB_ERR_CHECK_ABOVE arg4, 16, rax, IMB_ERR_AUTH_TAG_LEN

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_enc_fin
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_finalize_avx_gen4 / aes_gcm_dec_192_finalize_avx_gen4
;	aes_gcm_dec_256_finalize_avx_gen4 /
;       aes_gcm_dec_128_finalize_avx512 / aes_gcm_dec_192_finalize_avx512
;	aes_gcm_dec_256_finalize_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(dec,_finalize_),function,)
FN_NAME(dec,_finalize_):
        endbranch64
%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        or      arg1, arg1
        jz      error_dec_fin

        ;; Check context_data != NULL
        or      arg2, arg2
        jz      error_dec_fin

        ;; Check auth_tag != NULL
        or      arg3, arg3
        jz      error_dec_fin

        ;; Check auth_tag_len == 0 or > 16
        or      arg4, arg4
        jz      error_dec_fin

        cmp     arg4, 16
        ja      error_dec_fin
%endif

        push r12

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
	sub	rsp, 7*16
        vmovdqu	[rsp + 0*16], xmm6
        vmovdqu	[rsp + 1*16], xmm9
        vmovdqu	[rsp + 2*16], xmm10
        vmovdqu	[rsp + 3*16], xmm11
        vmovdqu	[rsp + 4*16], xmm13
        vmovdqu	[rsp + 5*16], xmm14
        vmovdqu	[rsp + 6*16], xmm15
%endif
        GCM_COMPLETE    arg1, arg2, arg3, arg4, multi_call

%ifdef SAFE_DATA
        clear_scratch_xmms_avx_asm
%endif
%ifidn __OUTPUT_FORMAT__, win64
        vmovdqu	xmm15, [rsp + 6*16]
        vmovdqu	xmm14, [rsp + 5*16]
        vmovdqu	xmm13, [rsp + 4*16]
        vmovdqu	xmm11, [rsp + 3*16]
        vmovdqu	xmm10, [rsp + 2*16]
        vmovdqu	xmm9,  [rsp + 1*16]
        vmovdqu	xmm6,  [rsp + 0*16]
        add     rsp, 7*16
%endif

        pop r12

exit_dec_fin:
        ret

%ifdef SAFE_PARAM
error_dec_fin:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check auth_tag != NULL
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_AUTH

        ;; Check auth_tag_len == 0 or > 16
        IMB_ERR_CHECK_ZERO arg4, rax, IMB_ERR_AUTH_TAG_LEN

        IMB_ERR_CHECK_ABOVE arg4, 16, rax, IMB_ERR_AUTH_TAG_LEN

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_dec_fin
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_avx_gen4 / aes_gcm_enc_192_avx_gen4 / aes_gcm_enc_256_avx_gen4 /
;       aes_gcm_enc_128_avx512 / aes_gcm_enc_192_avx512 / aes_gcm_enc_256_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(enc,_),function,)
FN_NAME(enc,_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Load max len to reg on windows
        INIT_GCM_MAX_LENGTH

        ;; Check key_data != NULL
        or      arg1, arg1
        jz      error_enc

        ;; Check context_data != NULL
        or      arg2, arg2
        jz      error_enc

        ;; Check IV != NULL
        cmp     arg6, 0
        jz      error_enc

        ;; Check auth_tag != NULL
        cmp     arg9, 0
        jz      error_enc

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg10, 0
        jz      error_enc

        cmp     arg10, 16
        ja      error_enc

        ;; Check if msg_len == 0
        cmp     arg5, 0
        jz      skip_in_out_check_enc

        ;; Check if msg_len > max_len
        cmp     arg5, GCM_MAX_LENGTH
        ja      error_enc

        ;; Check out != NULL (msg_len != 0)
        or      arg3, arg3
        jz      error_enc

        ;; Check in != NULL (msg_len != 0)
        or      arg4, arg4
        jz      error_enc

skip_in_out_check_enc:
        ;; Check if aad_len == 0
        cmp     arg8, 0
        jz      skip_aad_check_enc

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg7, 0
        jz      error_enc

skip_aad_check_enc:
%endif
        GCM_INIT arg1, arg2, arg6, arg7, arg8

        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, ENC, single_call

        GCM_COMPLETE arg1, arg2, arg9, arg10, single_call

exit_enc:
        FUNC_RESTORE

        ret

%ifdef SAFE_PARAM
error_enc:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check IV != NULL
        IMB_ERR_CHECK_NULL arg6, rax, IMB_ERR_NULL_IV

        ;; Check auth_tag != NULL
        IMB_ERR_CHECK_NULL arg9, rax, IMB_ERR_NULL_AUTH

        ;; Check auth_tag_len == 0 or > 16
        IMB_ERR_CHECK_ZERO arg10, rax, IMB_ERR_AUTH_TAG_LEN

        IMB_ERR_CHECK_ABOVE arg10, 16, rax, IMB_ERR_AUTH_TAG_LEN

        ;; Check if msg_len == 0
        cmp     arg5, 0
        jz      skip_in_out_check_error_enc

        ;; Check if msg_len > max_len
        IMB_ERR_CHECK_ABOVE arg5, GCM_MAX_LENGTH, rax, IMB_ERR_CIPH_LEN

        ;; Check out != NULL (msg_len != 0)
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_DST

        ;; Check in != NULL (msg_len != 0)
        IMB_ERR_CHECK_NULL arg4, rax, IMB_ERR_NULL_SRC

skip_in_out_check_error_enc:
        ;; Check if aad_len == 0
        cmp     arg8, 0
        jz      skip_aad_check_error_enc

        ;; Check aad != NULL (aad_len != 0)
        IMB_ERR_CHECK_NULL arg7, rax, IMB_ERR_NULL_AAD

skip_aad_check_error_enc:
        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_enc
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_avx_gen4 / aes_gcm_dec_192_avx_gen4 / aes_gcm_dec_256_avx_gen4 /
;       aes_gcm_dec_128_avx512 / aes_gcm_dec_192_avx512 / aes_gcm_dec_256_avx512
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(dec,_),function,)
FN_NAME(dec,_):
        endbranch64
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Load max len to reg on windows
        INIT_GCM_MAX_LENGTH

        ;; Check key_data != NULL
        or      arg1, arg1
        jz      error_dec

        ;; Check context_data != NULL
        or      arg2, arg2
        jz      error_dec

        ;; Check IV != NULL
        cmp     arg6, 0
        jz      error_dec

        ;; Check auth_tag != NULL
        cmp     arg9, 0
        jz      error_dec

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg10, 0
        jz      error_dec

        cmp     arg10, 16
        ja      error_dec

        ;; Check if msg_len == 0
        cmp     arg5, 0
        jz      skip_in_out_check_dec

        ;; Check if msg_len > max_len
        cmp     arg5, GCM_MAX_LENGTH
        ja      error_dec

        ;; Check out != NULL (msg_len != 0)
        or      arg3, arg3
        jz      error_dec

        ;; Check in != NULL (msg_len != 0)
        or      arg4, arg4
        jz      error_dec

skip_in_out_check_dec:
        ;; Check if aad_len == 0
        cmp     arg8, 0
        jz      skip_aad_check_dec

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg7, 0
        jz      error_dec

skip_aad_check_dec:
%endif
        GCM_INIT arg1, arg2, arg6, arg7, arg8

        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, DEC, single_call

        GCM_COMPLETE arg1, arg2, arg9, arg10, single_call

exit_dec:
        FUNC_RESTORE

        ret

%ifdef SAFE_PARAM
error_dec:
        ;; Clear reg and imb_errno
        IMB_ERR_CHECK_START rax

        ;; Check key_data != NULL
        IMB_ERR_CHECK_NULL arg1, rax, IMB_ERR_NULL_EXP_KEY

        ;; Check context_data != NULL
        IMB_ERR_CHECK_NULL arg2, rax, IMB_ERR_NULL_CTX

        ;; Check IV != NULL
        IMB_ERR_CHECK_NULL arg6, rax, IMB_ERR_NULL_IV

        ;; Check auth_tag != NULL
        IMB_ERR_CHECK_NULL arg9, rax, IMB_ERR_NULL_AUTH

        ;; Check auth_tag_len == 0 or > 16
        IMB_ERR_CHECK_ZERO arg10, rax, IMB_ERR_AUTH_TAG_LEN

        IMB_ERR_CHECK_ABOVE arg10, 16, rax, IMB_ERR_AUTH_TAG_LEN

        ;; Check if msg_len == 0
        cmp     arg5, 0
        jz      skip_in_out_check_error_dec

        ;; Check if msg_len > max_len
        IMB_ERR_CHECK_ABOVE arg5, GCM_MAX_LENGTH, rax, IMB_ERR_CIPH_LEN

        ;; Check out != NULL (msg_len != 0)
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_DST

        ;; Check in != NULL (msg_len != 0)
        IMB_ERR_CHECK_NULL arg4, rax, IMB_ERR_NULL_SRC

skip_in_out_check_error_dec:
        ;; Check if aad_len == 0
        cmp     arg8, 0
        jz      skip_aad_check_error_dec

        ;; Check aad != NULL (aad_len != 0)
        IMB_ERR_CHECK_NULL arg7, rax, IMB_ERR_NULL_AAD

skip_aad_check_error_dec:

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_dec
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; NOTE: THIS API IS USED BY JOB-API ONLY, NO NEED FOR 2ND SAFE PARAM CHECK
;
;IMB_JOB * aes_gcm_enc_var_iv_128_avx_gen4 / aes_gcm_enc_var_iv_192_avx_gen4 /
;       aes_gcm_enc_var_iv_256_avx_gen4 /
;       aes_gcm_enc_var_iv_128_avx512 / aes_gcm_enc_var_iv_192_avx512 /
;       aes_gcm_enc_var_iv_256_avx512
;       (IMB_MGR *state, IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(enc_var_iv,_),function,internal)
FN_NAME(enc_var_iv,_):
        endbranch64
	FUNC_SAVE alloc_context

        mov     arg1, [arg2 + _enc_keys]

        GCM_INIT arg1, {rsp + CONTEXT_OFFSET}, {[arg2 + _iv]}, \
                 {[arg2 + _gcm_aad]}, {qword [arg2 + _gcm_aad_len]}, \
                 {qword [arg2 + _iv_len_in_bytes]}

        mov     arg3, [arg2 + _src]
        add     arg3, [arg2 + _cipher_start_src_offset]
        mov     arg4, [arg2 + _dst]
        mov     [rsp + GP_OFFSET + 5*8], arg2   ; preserve job pointer
        mov     arg2, [arg2 + _msg_len_to_cipher]
	GCM_ENC_DEC  arg1, {rsp + CONTEXT_OFFSET}, arg4, arg3, arg2, ENC, single_call

        mov     arg2, [rsp + GP_OFFSET + 5*8]
        GCM_COMPLETE arg1, {rsp + CONTEXT_OFFSET}, \
                     {[arg2 + _auth_tag_output]}, {[arg2 + _auth_tag_output_len_in_bytes]}, \
                     single_call

        ;; mark job complete
        mov     dword [arg2 + _status], IMB_STATUS_COMPLETED

        mov     rax, arg2       ;; return the job

        FUNC_RESTORE
	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; NOTE: THIS API IS USED BY JOB-API ONLY, NO NEED FOR 2ND SAFE PARAM CHECK
;
;IMB_JOB *aes_gcm_dec_var_iv_128_avx_gen4 / aes_gcm_dec_var_iv_192_avx_gen4 /
;       aes_gcm_dec_var_iv_256_avx_gen4 /
;       aes_gcm_dec_var_iv_128_avx512 / aes_gcm_dec_var_iv_192_avx512 /
;       aes_gcm_dec_var_iv_256_avx512
;       (IMB_MGR *state, IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(FN_NAME(dec_var_iv,_),function,internal)
FN_NAME(dec_var_iv,_):
        endbranch64
	FUNC_SAVE alloc_context

        mov     arg1, [arg2 + _dec_keys]

        GCM_INIT arg1, {rsp + CONTEXT_OFFSET}, {[arg2 + _iv]}, \
                 {[arg2 + _gcm_aad]}, {qword [arg2 + _gcm_aad_len]}, \
                 {qword [arg2 + _iv_len_in_bytes]}

        mov     arg3, [arg2 + _src]
        add     arg3, [arg2 + _cipher_start_src_offset]
        mov     arg4, [arg2 + _dst]
        mov     [rsp + GP_OFFSET + 5*8], arg2   ; preserve job pointer
        mov     arg2, [arg2 + _msg_len_to_cipher]
	GCM_ENC_DEC  arg1, {rsp + CONTEXT_OFFSET}, arg4, arg3, arg2, DEC, single_call

        mov     arg2, [rsp + GP_OFFSET + 5*8]
        GCM_COMPLETE arg1, {rsp + CONTEXT_OFFSET}, \
                     {[arg2 + _auth_tag_output]}, {[arg2 + _auth_tag_output_len_in_bytes]}, \
                     single_call

        ;; mark job complete
        mov     dword [arg2 + _status], IMB_STATUS_COMPLETED

        mov     rax, arg2       ;; return the job

        FUNC_RESTORE
	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   imb_aes_gmac_update_128_avx_gen4 / imb_aes_gmac_update_192_avx_gen4 /
;       imb_aes_gmac_update_256_avx_gen4
;       imb_aes_gmac_update_128_avx512 / imb_aes_gmac_update_192_avx512 /
;       imb_aes_gmac_update_256_avx512 (
;        const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        const   u8 *in,
;        const   u64 msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align 32
MKGLOBAL(GMAC_FN_NAME(update),function,)
GMAC_FN_NAME(update):
        endbranch64
	FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET
%endif
        ;; Check if msg_len == 0
        or      arg4, arg4
        je	.exit_gmac_update

%ifdef SAFE_PARAM
        ;; Check key_data != NULL
        or      arg1, arg1
        jz      .error_gmac_update

        ;; Check context_data != NULL
        or      arg2, arg2
        jz      .error_gmac_update

        ;; Check in != NULL (msg_len != 0)
        or      arg3, arg3
        jz      .error_gmac_update
%endif

        ; Increment size of "AAD length" for GMAC
        add     [arg2 + AadLen], arg4

        vmovdqu	xmm0, [arg2 + AadHash]

        cmp	qword [arg2 + PBlockLen], 0
	je	.partial_block_is_zero_len

        ;; Deal with previous partial block
	vmovdqu	xmm13, [arg1 + HashKey_1]
	vmovdqu	xmm14, [arg1 + HashKeyK_1]
        ;; arg2 = [in] context
        ;; arg3 = [in] message pointer
        ;; arg4 = [in] message length
        ;; xmm0 = [in/out] hash
        ;; xmm13/xmm14 = [in] hash keys
        call    GHASH_FN_NAME(partial_block_gmac)
        ;; r11 = bytes processed

        ; CALC_AAD_HASH needs to deal with multiple of 16 bytes
        sub     arg4, r11
        add     arg3, r11

.partial_block_is_zero_len:
        vmovq   xmm7, arg4 ; Save remaining length
        and     arg4, -16 ; Get multiple of 16 bytes

        or      arg4, arg4
        jz      .no_full_blocks

        ;; Calculate GHASH of this segment
        mov     r12, arg3
        mov     r13, arg4
        ;; arg1 = key
        ;; xmm0 = hash in/out
        call    GHASH_FN_NAME(ghash_internal)

        vmovdqu	[arg2 + AadHash], xmm0	; ctx_data.aad hash = aad_hash

.no_full_blocks:
        add     arg3, arg4 ; Point at partial block

        vmovq   arg4, xmm7 ; Restore original remaining length
        and     arg4, 15
        jz      .exit_gmac_update

        ; Save next partial block
        mov	[arg2 + PBlockLen], arg4
%ifdef IS_AVX2_GCM
        READ_SMALL_DATA_INPUT_AVX xmm1, arg3, arg4, r11
%else
        READ_SMALL_DATA_INPUT_AVX512 xmm1, arg3, arg4, r11, k1
%endif
        vpshufb xmm1, xmm1, [rel SHUF_MASK]
        vpxor   xmm0, xmm0, xmm1
        vmovdqu [arg2 + AadHash], xmm0

.exit_gmac_update:
	FUNC_RESTORE

	ret

%ifdef SAFE_PARAM
.error_gmac_update:
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
        jmp     .exit_gmac_update
%endif

mksection stack-noexec
