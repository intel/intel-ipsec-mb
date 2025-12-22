;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2021-2024, Intel Corporation All rights reserved.
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
%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/imb_job.inc"
%include "include/align_avx512.inc"

%ifndef GCM_API_VAES_AVX512_INC
%define GCM_API_VAES_AVX512_INC

%ifdef GCM128_MODE
%define NROUNDS 9
%endif
%ifdef GCM192_MODE
%define NROUNDS 11
%endif
%ifdef GCM256_MODE
%define NROUNDS 13
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; External symbols
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
extern ghash_internal_vaes_avx512
extern gcm_0_to_256_enc_wrapper_asm
extern gcm_0_to_256_dec_wrapper_asm
extern aes_gcm_enc_vaes_avx512
extern aes_gcm_dec_vaes_avx512

mksection .text
default rel

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_precomp_128_vaes_avx512 /
;       aes_gcm_precomp_192_vaes_avx512 /
;       aes_gcm_precomp_256_vaes_avx512
;       (struct gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(precomp,_),function,)
FN_NAME(precomp,_):
        endbranch64
;; Parameter is passed through register
%ifdef SAFE_PARAM
        ;; Reset imb_errno
        IMB_ERR_CHECK_RESET

        ;; Check key_data != NULL
        cmp     arg1, 0
        jz      error_precomp
%endif

        FUNC_SAVE small_frame

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
        vmovdqu  [arg1 + HashKey_1], xmm6               ; store HashKey<<1 mod poly

        PRECOMPUTE arg1, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm7, xmm8

%ifdef SAFE_DATA
        clear_zmms_avx512 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8
%endif

        FUNC_RESTORE
align_label
exit_precomp:

        ret

%ifdef SAFE_PARAM
align_label
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
;void   aes_gcm_enc_128_vaes_avx512 / aes_gcm_enc_192_vaes_avx512 / aes_gcm_enc_256_vaes_avx512
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
align_function
MKGLOBAL(FN_NAME(enc,_),function,)
FN_NAME(enc,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_enc_vaes_avx512

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   aes_gcm_dec_128_vaes_avx512 / aes_gcm_dec_192_vaes_avx512 / aes_gcm_dec_256_vaes_avx512
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
align_function
MKGLOBAL(FN_NAME(dec,_),function,)
FN_NAME(dec,_):
        endbranch64
        mov r10d, NROUNDS
        jmp aes_gcm_dec_vaes_avx512

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; NOTE: THIS API IS USED BY JOB-API ONLY, NO NEED FOR 2ND SAFE PARAM CHECK
;
;IMB_JOB *aes_gcm_enc_var_iv_128_vaes_avx512 / aes_gcm_enc_var_iv_192_vaes_avx512 /
;       aes_gcm_enc_var_iv_256_vaes_avx512(IMB_MGR *state, IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(enc_var_iv,_),function,internal)
FN_NAME(enc_var_iv,_):
        endbranch64
        FUNC_SAVE alloc_context

        ;; Check if msg_len <= 256
        cmp     qword [arg2 + _msg_len_to_cipher], 16 * 16
        jbe     .small_packet_path

        mov     arg1, [arg2 + _enc_keys]

        GCM_INIT arg1, {rsp + CONTEXT_OFFSET}, {[arg2 + _iv]}, \
                {[arg2 + _gcm_aad]}, {qword [arg2 + _gcm_aad_len]}, \
                r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm11, zmm3, zmm4, zmm5,   zmm6, zmm7, zmm8, zmm9, zmm10, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call, \
                {qword [arg2 + _iv_len_in_bytes]}

        mov     arg3, [arg2 + _src]
        add     arg3, [arg2 + _cipher_start_src_offset]
        mov     arg4, [arg2 + _dst]
        mov     rbp, [arg2 + _msg_len_to_cipher]
        GCM_ENC_DEC  arg1, {rsp + CONTEXT_OFFSET}, arg4, arg3, rbp, ENC, single_call, '>256'

        GCM_COMPLETE arg1, {rsp + CONTEXT_OFFSET}, \
                        {[arg2 + _auth_tag_output]}, {[arg2 + _auth_tag_output_len_in_bytes]}, \
                        single_call, k1, r10, r11, r12

%ifdef SAFE_DATA
        clear_zmms_avx512 xmm1, xmm4, xmm6, xmm7, xmm8, xmm12, xmm13, xmm14, \
                        xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, xmm26, xmm30, xmm31
%endif
        jmp     .exit_enc

align_label
.small_packet_path:
        ;; Load arguments for wrapper function call
        mov     arg1, [arg2 + _enc_keys]
        mov     arg3, [arg2 + _dst]
        mov     arg4, [arg2 + _src]
        add     arg4, [arg2 + _cipher_start_src_offset]

%ifdef LINUX
        mov     arg5, [arg2 + _msg_len_to_cipher]
        mov     arg6, [arg2 + _iv]
%else
        ;; Windows save args 5-11 on stack
        mov     rdi, [arg2 + _msg_len_to_cipher]
        mov     rsi, [arg2 + _iv]
%endif
        mov     r12, [arg2 + _gcm_aad]
        mov     r13, [arg2 + _gcm_aad_len]
        mov     rbp, [arg2 + _auth_tag_output]
        mov     r15, [arg2 + _auth_tag_output_len_in_bytes]

        mov     r10d, NROUNDS
        mov     r11, [arg2 + _iv_len_in_bytes]
        call    gcm_0_to_256_enc_wrapper_asm

%ifdef SAFE_DATA
        clear_zmms_avx512 xmm0, xmm1, xmm2, xmm7, xmm8, xmm9, xmm11, xmm10, xmm14, \
                        xmm15, xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, xmm26
%endif

align_label
.exit_enc:
        ;; mark job complete
        mov     dword [arg2 + _status], IMB_STATUS_COMPLETED

        mov     rax, arg2       ;; return the job

        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; NOTE: THIS API IS USED BY JOB-API ONLY, NO NEED FOR 2ND SAFE PARAM CHECK
;
;IMB_JOB *aes_gcm_dec_var_iv_128_vaes_avx512 / aes_gcm_dec_var_iv_192_vaes_avx512 /
;       aes_gcm_dec_var_iv_256_vaes_avx512(IMB_MGR *state, IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(FN_NAME(dec_var_iv,_),function,internal)
FN_NAME(dec_var_iv,_):
        endbranch64
        FUNC_SAVE alloc_context

        ;; Check if msg_len <= 256
        cmp     qword [arg2 + _msg_len_to_cipher], 16 * 16
        jbe     .small_packet_path

        mov     arg1, [arg2 + _dec_keys]

        GCM_INIT arg1, {rsp + CONTEXT_OFFSET}, {[arg2 + _iv]}, \
                {[arg2 + _gcm_aad]}, {qword [arg2 + _gcm_aad_len]}, \
                r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm11, zmm3, zmm4, zmm5,   zmm6, zmm7, zmm8, zmm9, zmm10, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call, \
                {qword [arg2 + _iv_len_in_bytes]}

        mov     arg3, [arg2 + _src]
        add     arg3, [arg2 + _cipher_start_src_offset]
        mov     arg4, [arg2 + _dst]
        mov     rbp, [arg2 + _msg_len_to_cipher]
        GCM_ENC_DEC  arg1, {rsp + CONTEXT_OFFSET}, arg4, arg3, rbp, DEC, single_call, '>256'

        GCM_COMPLETE arg1, {rsp + CONTEXT_OFFSET}, \
                        {[arg2 + _auth_tag_output]}, {[arg2 + _auth_tag_output_len_in_bytes]}, \
                        single_call, k1, r10, r11, r12

%ifdef SAFE_DATA
        clear_zmms_avx512 xmm1, xmm4, xmm6, xmm7, xmm8, xmm12, xmm13, xmm14, \
                        xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, xmm26, xmm30, xmm31
%endif
        jmp     .exit_dec

align_label
.small_packet_path:
        ;; Load arguments for wrapper function call
        mov     arg1, [arg2 + _enc_keys]
        mov     arg3, [arg2 + _dst]
        mov     arg4, [arg2 + _src]
        add     arg4, [arg2 + _cipher_start_src_offset]

%ifdef LINUX
        mov     arg5, [arg2 + _msg_len_to_cipher]
        mov     arg6, [arg2 + _iv]
%else
        ;; Windows save args 5-11 on stack
        mov     rdi, [arg2 + _msg_len_to_cipher]
        mov     rsi, [arg2 + _iv]
%endif
        mov     r12, [arg2 + _gcm_aad]
        mov     r13, [arg2 + _gcm_aad_len]
        mov     rbp, [arg2 + _auth_tag_output]
        mov     r15, [arg2 + _auth_tag_output_len_in_bytes]

        mov     r10d, NROUNDS
        mov     r11, [arg2 + _iv_len_in_bytes]
        call    gcm_0_to_256_dec_wrapper_asm

%ifdef SAFE_DATA
        clear_zmms_avx512 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm8, xmm9, xmm11, xmm14, xmm15, \
                        xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, xmm26, xmm27
%endif
align_label
.exit_dec:
        ;; mark job complete
        mov     dword [arg2 + _status], IMB_STATUS_COMPLETED

        mov     rax, arg2       ;; return the job

        FUNC_RESTORE
        ret

mksection stack-noexec

%endif ; GCM_API_VAES_AVX512_INC
