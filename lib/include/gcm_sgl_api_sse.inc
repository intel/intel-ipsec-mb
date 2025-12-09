;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2021-2024 Intel Corporation All rights reserved.
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

%include "include/gcm_sse.inc"
%include "include/align_sse.inc"

%ifndef GCM_SGL_API_SSE_INC
%define GCM_SGL_API_SSE_INC

section .text
default rel

extern aes_gcm_enc_finalize_sse
extern aes_gcm_dec_finalize_sse
extern aes_gcm_enc_update_sse
extern aes_gcm_dec_update_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_128_sse / aes_gcm_init_192_sse / aes_gcm_init_256_sse (
;        const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *iv,
;        const   u8 *aad,
;        u64     aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
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
        sub     rsp, 1*16
        movdqu  [rsp + 0*16], xmm6
%endif

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      error_init

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      error_init

        ;; Check IV != NULL
        cmp     arg3, 0
        jz      error_init

        ;; Check if aad_len == 0
        cmp     arg5, 0
        jz      skip_aad_check_init

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg4, 0
        jz      error_init

align_label
skip_aad_check_init:
%endif
        GCM_INIT arg1, arg2, arg3, arg4, arg5

%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_scratch_xmms_sse_asm
%endif
align_label
exit_init:

%ifidn __OUTPUT_FORMAT__, win64
        movdqu  xmm6 , [rsp + 0*16]
        add     rsp, 16
        pop     r15
        pop     r14
%endif
        pop     r13
        pop     r12
        ret

%ifdef SAFE_PARAM
align_label
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

align_label
skip_aad_check_error_init:

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_init
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_init_var_iv_128_sse / aes_gcm_init_var_iv_192_sse /
;       aes_gcm_init_var_iv_256_sse (
;        const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8        *iv,
;        const u64 iv_len,
;        const u8  *aad,
;        const u64 aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(init_var_iv,_),function,)
FN_NAME(init_var_iv,_):
        endbranch64
        push    r12
        push    r13
%ifidn __OUTPUT_FORMAT__, win64
        push    r14
        push    r15
        lea     r14, [rsp + 4*8]
        ; xmm6 needs to be maintained for Windows
        sub     rsp, 1*16
        movdqu  [rsp + 0*16], xmm6
%endif

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      error_init_IV

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      error_init_IV

        ;; Check IV != NULL
        cmp     arg3, 0
        jz      error_init_IV

        ;; Check iv_len != 0
        cmp     arg4, 0
        jz      error_init_IV

        ;; Check if aad_len == 0
        cmp     arg6, 0
        jz      skip_aad_check_init_IV

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg5, 0
        jz      error_init_IV

align_label
skip_aad_check_init_IV:
%endif
        cmp     arg4, 12
        je      iv_len_12_init_IV

        GCM_INIT arg1, arg2, arg3, arg5, arg6, arg4
        jmp     skip_iv_len_12_init_IV

align_label
iv_len_12_init_IV:
        GCM_INIT arg1, arg2, arg3, arg5, arg6

align_label
skip_iv_len_12_init_IV:
%ifdef SAFE_DATA
        clear_scratch_gps_asm
        clear_scratch_xmms_sse_asm
%endif
align_label
exit_init_IV:

%ifidn __OUTPUT_FORMAT__, win64
        movdqu  xmm6 , [rsp + 0*16]
        add     rsp, 1*16
        pop     r15
        pop     r14
%endif
        pop     r13
        pop     r12
        ret

%ifdef SAFE_PARAM
align_label
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

align_label
skip_aad_check_error_init_IV:

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     exit_init_IV
%endif


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_update_sse / aes_gcm_enc_192_update_sse / aes_gcm_enc_256_update_sse
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *out,
;        const   u8 *in,
;        u64     msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc,_update_),function,)
FN_NAME(enc,_update_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_update_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_update_sse / aes_gcm_dec_192_update_sse / aes_gcm_dec_256_update_sse
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *out,
;        const   u8 *in,
;        u64     msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec,_update_),function,)
FN_NAME(dec,_update_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_update_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_128_finalize_sse / aes_gcm_enc_192_finalize_sse / aes_gcm_enc_256_finalize_sse
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *auth_tag,
;        u64     auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc,_finalize_),function,)
FN_NAME(enc,_finalize_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_finalize_sse

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_finalize_sse / aes_gcm_dec_192_finalize_sse / aes_gcm_dec_256_finalize_sse
;       (const struct gcm_key_data *key_data,
;        struct gcm_context_data *context_data,
;        u8      *auth_tag,
;        u64     auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec,_finalize_),function,)
FN_NAME(dec,_finalize_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_finalize_sse

mksection stack-noexec
%endif ; GCM_SGL_API_SSE_INC
