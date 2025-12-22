;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2025, Intel Corporation All rights reserved.
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
%include "include/align_avx512.inc"

mksection .text
default rel

extern ghash_internal_vaes_avx512
extern gcm_0_to_256_enc_wrapper_asm
extern gcm_0_to_256_dec_wrapper_asm

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_enc_vaes_avx512
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
;        Expects NROUNDS value (9, 11, 13) in r10
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(aes_gcm_enc_vaes_avx512,function,internal)
aes_gcm_enc_vaes_avx512:
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Load max len to reg on windows
        INIT_GCM_MAX_LENGTH

        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      .error_enc

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      .error_enc

        ;; Check IV != NULL
        cmp     arg6, 0
        jz      .error_enc

        ;; Check auth_tag != NULL
        cmp     arg9, 0
        jz      .error_enc

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg10, 0
        jz      .error_enc

        cmp     arg10, 16
        ja      .error_enc

        ;; Check if msg_len == 0
        cmp     arg5, 0
        jz      .skip_in_out_check_enc

        ;; Check if msg_len > max_len
        cmp     arg5, GCM_MAX_LENGTH
        ja      .error_enc

        ;; Check out != NULL (msg_len != 0)
        cmp     arg3, 0
        jz      .error_enc

        ;; Check in != NULL (msg_len != 0)
        cmp     arg4, 0
        jz      .error_enc

align_label
.skip_in_out_check_enc:
        ;; Check if aad_len == 0
        cmp     arg8, 0
        jz      .skip_aad_check_enc

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg7, 0
        jz      .error_enc

align_label
.skip_aad_check_enc:
%endif
        ;; Check if msg_len <= 256
        cmp     arg5, 16 * 16
        jbe     .small_packet_path

        mov r15, r10 ; save NROUNDS
        GCM_INIT arg1, arg2, arg6, arg7, arg8, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call
        mov r10, r15 ; restore NROUNDS

        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, ENC, single_call, '>256', r10
        GCM_COMPLETE arg1, arg2, arg9, arg10, single_call, k1, r13, r11, r12, r10
        jmp     .exit_enc

align_label
.small_packet_path:
%ifndef LINUX
        mov     rdi, arg5
        mov     rsi, arg6
%endif
        mov     r12, arg7
        mov     r13, arg8
        mov     rbp, arg9
        mov     r15, arg10

        mov     r11d, 12
        call    gcm_0_to_256_enc_wrapper_asm

align_label
.exit_enc:
        FUNC_RESTORE
        ret

%ifdef SAFE_PARAM
align_label
.error_enc:
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
        jz      .skip_in_out_check_error_enc

        ;; Check if msg_len > max_len
        IMB_ERR_CHECK_ABOVE arg5, GCM_MAX_LENGTH, rax, IMB_ERR_CIPH_LEN

        ;; Check out != NULL (msg_len != 0)
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_DST

        ;; Check in != NULL (msg_len != 0)
        IMB_ERR_CHECK_NULL arg4, rax, IMB_ERR_NULL_SRC

align_label
.skip_in_out_check_error_enc:
        ;; Check if aad_len == 0
        cmp     arg8, 0
        jz      .skip_aad_check_error_enc

        ;; Check aad != NULL (aad_len != 0)
        IMB_ERR_CHECK_NULL arg7, rax, IMB_ERR_NULL_AAD

align_label
.skip_aad_check_error_enc:
        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     .exit_enc
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_vaes_avx512
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
;        Expects NROUNDS value (9, 11, 13) in r10
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(aes_gcm_dec_vaes_avx512,function,internal)
aes_gcm_dec_vaes_avx512:
        FUNC_SAVE

%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Load max len to reg on windows
        INIT_GCM_MAX_LENGTH

        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      .error_dec

        ;; Check context_data != NULL
        cmp     arg2, 0
        jz      .error_dec

        ;; Check IV != NULL
        cmp     arg6, 0
        jz      .error_dec

        ;; Check auth_tag != NULL
        cmp     arg9, 0
        jz      .error_dec

        ;; Check auth_tag_len == 0 or > 16
        cmp     arg10, 0
        jz      .error_dec

        cmp     arg10, 16
        ja      .error_dec

        ;; Check if msg_len == 0
        cmp     arg5, 0
        jz      .skip_in_out_check_dec

        ;; Check if msg_len > max_len
        cmp     arg5, GCM_MAX_LENGTH
        ja      .error_dec

        ;; Check out != NULL (msg_len != 0)
        cmp     arg3, 0
        jz      .error_dec

        ;; Check in != NULL (msg_len != 0)
        cmp     arg4, 0
        jz      .error_dec

align_label
.skip_in_out_check_dec:
        ;; Check if aad_len == 0
        cmp     arg8, 0
        jz      .skip_aad_check_dec

        ;; Check aad != NULL (aad_len != 0)
        cmp     arg7, 0
        jz      .error_dec

align_label
.skip_aad_check_dec:
%endif
        ;; Check if msg_len <= 256
        cmp     arg5, 16 * 16
        jbe     .small_packet_path

        mov r15, r10 ; save NROUNDS
        GCM_INIT arg1, arg2, arg6, arg7, arg8, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call
        mov r10, r15 ; restore NROUNDS

        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, DEC, single_call, '>256', r10
        GCM_COMPLETE arg1, arg2, arg9, arg10, single_call, k1, r13, r11, r12, r10
%ifdef SAFE_DATA
        clear_zmms_avx512 xmm6
%endif
        jmp     .exit_dec

align_label
.small_packet_path:
%ifndef LINUX
        mov     rdi, arg5
        mov     rsi, arg6
%endif
        mov     r12, arg7
        mov     r13, arg8
        mov     rbp, arg9
        mov     r15, arg10

        mov     r11d, 12
        call    gcm_0_to_256_dec_wrapper_asm

align_label
.exit_dec:
        FUNC_RESTORE
        ret

%ifdef SAFE_PARAM
align_label
.error_dec:
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
        jz      .skip_in_out_check_error_dec

        ;; Check if msg_len > max_len
        IMB_ERR_CHECK_ABOVE arg5, GCM_MAX_LENGTH, rax, IMB_ERR_CIPH_LEN

        ;; Check out != NULL (msg_len != 0)
        IMB_ERR_CHECK_NULL arg3, rax, IMB_ERR_NULL_DST

        ;; Check in != NULL (msg_len != 0)
        IMB_ERR_CHECK_NULL arg4, rax, IMB_ERR_NULL_SRC

align_label
.skip_in_out_check_error_dec:
        ;; Check if aad_len == 0
        cmp     arg8, 0
        jz      .skip_aad_check_error_dec

        ;; Check aad != NULL (aad_len != 0)
        IMB_ERR_CHECK_NULL arg7, rax, IMB_ERR_NULL_AAD

align_label
.skip_aad_check_error_dec:

        ;; Set imb_errno
        IMB_ERR_CHECK_END rax
        jmp     .exit_dec
%endif
