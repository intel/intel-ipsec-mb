;;
;; Copyright (c) 2023-2024, Intel Corporation
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met:
;;
;;     * Redistributions of source code must retain the above copyright notice,
;;       this list of conditions and the following disclaimer.
;;     * Redistributions in binary form must reproduce the above copyright
;;       notice, this list of conditions and the following disclaimer in the
;;       documentation and/or other materials provided with the distribution.
;;     * Neither the name of Intel Corporation nor the names of its contributors
;;       may be used to endorse or promote products derived from this software
;;       without specific prior written permission.
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
;; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
;; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
;; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;

; routine to do AES ECB encrypt for QUIC on 16-byte buffers

; XMM registers are clobbered. Saving/restoring must be done at a higher level

; void aes_ecb_quic_enc_x_avx(void *in,
;                             UINT128  keys[],
;                             void    *out,
;                             UINT64   num_buffers);
;
; x = key size (128/256)
; arg 1: IN: array of pointers to input buffers
; arg 2: KEYS: pointer to keys (common for all buffers)
; arg 3: OUT: array of pointers to output buffers)
; arg 4: N_BUFS: number of 16-byte buffers
;

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/aes_common.inc"
%include "include/cet.inc"
%include "include/align_avx.inc"

%define AES_ECB_QUIC_ENC_128 aes_ecb_quic_enc_128_avx
%define AES_ECB_QUIC_ENC_256 aes_ecb_quic_enc_256_avx

;; =============================================================================
;; Loads 1 AES block from up to 8 buffers into XMM registers
%macro XMM_LOAD_BLOCKS_MULT_IN_0_8 11
%define %%NUM_BLOCKS    %1      ; [in] numerical value, number of AES blocks (0 to 16)
%define %%ARRAY_INP     %2      ; [in] array of input data pointers
%define %%INP           %3      ; [clobbered] input data pointer to read 16 bytes from
%define %%DST0          %4      ; [out] XMM register with loaded data
%define %%DST1          %5      ; [out] XMM register with loaded data
%define %%DST2          %6      ; [out] XMM register with loaded data
%define %%DST3          %7      ; [out] XMM register with loaded data
%define %%DST4          %8      ; [out] XMM register with loaded data
%define %%DST5          %9      ; [out] XMM register with loaded data
%define %%DST6          %10     ; [out] XMM register with loaded data
%define %%DST7          %11     ; [out] XMM register with loaded data

%assign dst_idx     0

%rep (%%NUM_BLOCKS)
%xdefine %%DSTREG %%DST %+ dst_idx
        mov             %%INP, [%%ARRAY_INP + dst_idx*8]
        vmovdqu         %%DSTREG, [%%INP]
%undef %%DSTREG
%assign dst_idx     (dst_idx + 1)
%endrep

%endmacro

;; =============================================================================
;; Stores 1 AES blocks to up to 8 buffers from XMM registers
%macro XMM_STORE_BLOCKS_MULT_OUT_0_8 12
%define %%NUM_BLOCKS    %1      ; [in] numerical value, number of AES blocks (0 to 8)
%define %%ARRAY_OUTP    %2      ; [in] array of output data pointers to write to
%define %%OUTP          %3      ; [clobbered] output data pointer to write to
%define %%SRC0          %4      ; [in] XMM register with data to store
%define %%SRC1          %5      ; [in] XMM register with data to store
%define %%SRC2          %6      ; [in] XMM register with data to store
%define %%SRC3          %7      ; [in] XMM register with data to store
%define %%SRC4          %8      ; [in] XMM register with data to store
%define %%SRC5          %9      ; [in] XMM register with data to store
%define %%SRC6          %10     ; [in] XMM register with data to store
%define %%SRC7          %11     ; [in] XMM register with data to store
%define %%TMP           %12     ; [clobbered] Temporary GP register

%assign src_idx     0
%rep (%%NUM_BLOCKS)
%xdefine %%SRCREG %%SRC %+ src_idx
        ; Store 5 bytes to each buffer
        mov     %%OUTP, [%%ARRAY_OUTP + src_idx*8]
        vmovd   [%%OUTP], %%SRCREG
        vpextrb [%%OUTP + 4], %%SRCREG, 4
%undef %%SRCREG
%assign src_idx     (src_idx + 1)
%endrep

%endmacro

%ifdef LINUX
%define IN              rdi
%define KEYS            rsi
%define OUT             rdx
%define N_BUFS          rcx
%else
%define IN              rcx
%define KEYS            rdx
%define OUT             r8
%define N_BUFS          r9
%endif

%define IDX             rax
%define TMP             IDX
%define XDATA0          xmm0
%define XDATA1          xmm1
%define XDATA2          xmm2
%define XDATA3          xmm3
%define XKEY0           xmm4
%define XKEY2           xmm5
%define XKEY4           xmm6
%define XKEY6           xmm7
%define XKEY10          xmm8
%define XKEY_A          xmm14
%define XKEY_B          xmm15

mksection .text

%macro AES_ECB_QUIC 1
%define %%NROUNDS     %1 ; [in] Number of rounds

%define IDX             rax
%define TMP             r11
%define TMP2            r10
%define XDATA0          xmm0
%define XDATA1          xmm1
%define XDATA2          xmm2
%define XDATA3          xmm3
%define XDATA4          xmm4
%define XDATA5          xmm5
%define XDATA6          xmm6
%define XDATA7          xmm7
%define XKEY1           xmm8

        or      N_BUFS, N_BUFS
        jz      %%done
        xor     IDX, IDX
        mov     TMP, N_BUFS
        and     TMP, 0x7        ; number of initial buffers (0 to 7 buffers)
        jz      %%main_loop
        ; branch to different code block based on remainder
        cmp     TMP, 4
        je      %%initial_num_buffers_is_4
        jb      %%initial_num_buffers_is_3_1
        cmp     TMP, 6
        je      %%initial_num_buffers_is_6
        jb      %%initial_num_buffers_is_5
        ja      %%initial_num_buffers_is_7
align_label
%%initial_num_buffers_is_3_1:
        ;; 3, 2 or 1
        cmp     TMP, 2
        ja      %%initial_num_buffers_is_3
        je      %%initial_num_buffers_is_2
        ;; fall through for `jmp %%initial_num_buffers_is_1`
%assign num_buffers 1
%rep 7
align_label
%%initial_num_buffers_is_ %+ num_buffers :
        ; load initial blocks
        XMM_LOAD_BLOCKS_MULT_IN_0_8 num_buffers, IN, TMP, XDATA0,\
                XDATA1, XDATA2, XDATA3, XDATA4, XDATA5,\
                XDATA6, XDATA7
%assign %%I 0
; Perform aesenc encryption on initial blocks
%rep (%%NROUNDS + 1)          ; 10/14
        movdqu      XKEY1, [KEYS + %%I*16]
        XMM_AESENC_ROUND_BLOCKS_AVX_0_8 XDATA0, XDATA1, XDATA2, XDATA3, XDATA4,\
                XDATA5, XDATA6, XDATA7, XKEY1, %%I, no_data,\
                no_data, no_data, no_data, no_data, no_data,\
                no_data, no_data, num_buffers, (%%NROUNDS - 1)
%assign %%I (%%I + 1)
%endrep
        ; store initial blocks
        XMM_STORE_BLOCKS_MULT_OUT_0_8 num_buffers, OUT, TMP, XDATA0, XDATA1,\
                XDATA2, XDATA3, XDATA4, XDATA5, XDATA6, XDATA7, TMP2
        add     IDX, num_buffers
        cmp     IDX, N_BUFS
        je      %%done
%assign num_buffers (num_buffers + 1)
        jmp     %%main_loop
%endrep
align_loop
%%main_loop:
        ; load next 8 blocks
        XMM_LOAD_BLOCKS_MULT_IN_0_8 8, {IN + IDX*8}, TMP, XDATA0,\
                XDATA1, XDATA2, XDATA3, XDATA4, XDATA5,\
                XDATA6, XDATA7
%assign %%I 0
; Perform AES encryption/decryption on 8 blocks
%rep (%%NROUNDS + 1)          ; 10/14
        movdqu      XKEY1, [KEYS + %%I*16]
        XMM_AESENC_ROUND_BLOCKS_AVX_0_8 XDATA0, XDATA1, XDATA2, XDATA3, XDATA4,\
                XDATA5, XDATA6, XDATA7, XKEY1, %%I, no_data,\
                no_data, no_data, no_data, no_data, no_data,\
                no_data, no_data, 8, (%%NROUNDS - 1)
%assign %%I (%%I + 1)
%endrep
        ; store 8 blocks
        XMM_STORE_BLOCKS_MULT_OUT_0_8 8, {OUT + IDX*8}, TMP, XDATA0, XDATA1,\
                XDATA2, XDATA3, XDATA4, XDATA5, XDATA6, XDATA7, TMP2
        add     IDX, 8
        cmp     IDX, N_BUFS
        jne     %%main_loop
align_label
%%done:
%ifdef SAFE_DATA
        clear_all_xmms_avx_asm
%endif
        ret
%endmacro

align_function
MKGLOBAL(AES_ECB_QUIC_ENC_128,function,internal)
AES_ECB_QUIC_ENC_128:
        endbranch64
        AES_ECB_QUIC 10

align_function
MKGLOBAL(AES_ECB_QUIC_ENC_256,function,internal)
AES_ECB_QUIC_ENC_256:
        endbranch64
        AES_ECB_QUIC 14

mksection stack-noexec
