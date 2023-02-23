;;
;; Copyright (c) 2023, Intel Corporation
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

; YMM registers are clobbered. Saving/restoring must be done at a higher level

; void aes_ecb_quic_enc_x_vaes_avx512(void *in,
;                                     UINT128  keys[],
;                                     void    *out,
;                                     UINT64   num_buffers);
;
; x = key size (128/192/256)
; arg 1: IN: array of pointers to input buffers
; arg 2: KEYS: pointer to keys (common for all buffers)
; arg 3: OUT: array of pointers to output buffers)
; arg 4: N_BUFS: number of 16-byte buffers
;

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/aes_common.inc"
%include "include/cet.inc"

%define AES_ECB_QUIC_ENC_128 aes_ecb_quic_enc_128_vaes_avx512
%define AES_ECB_QUIC_ENC_192 aes_ecb_quic_enc_192_vaes_avx512
%define AES_ECB_QUIC_ENC_256 aes_ecb_quic_enc_256_vaes_avx512

%ifdef LINUX
%define IN      rdi
%define KEYS    rsi
%define OUT     rdx
%define N_BUFS  rcx
%else
%define IN      rcx
%define KEYS    rdx
%define OUT     r8
%define N_BUFS  r9
%endif
%define IDX     rax
%define TMP     r11

%define YKEY1       ymm1
%define YDATA0      ymm2
%define YDATA1      ymm3
%define YDATA2      ymm4
%define YDATA3      ymm5
%define YDATA4      ymm6
%define YDATA5      ymm7
%define YDATA6      ymm8
%define YDATA7      ymm9

mksection .text

;; =============================================================================
;; Loads specified single 16-byte block from different buffers into YMM registers
%macro YMM_LOAD_BLOCKS_MULT_IN_0_16 11
%define %%NUM_BUFFERS   %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%ARRAY_INP     %2 ; [in] array of input data pointers
%define %%INP           %3 ; [clobbered] input data pointer to read 16 bytes from
%define %%DST0          %4 ; [out] YMM register with loaded data
%define %%DST1          %5 ; [out] YMM register with loaded data
%define %%DST2          %6 ; [out] YMM register with loaded data
%define %%DST3          %7 ; [out] YMM register with loaded data
%define %%DST4          %8 ; [out] YMM register with loaded data
%define %%DST5          %9 ; [out] YMM register with loaded data
%define %%DST6          %10 ; [out] YMM register with loaded data
%define %%DST7          %11 ; [out] YMM register with loaded data

%assign dst_idx     0
%assign buf_idx     0

%rep (%%NUM_BUFFERS / 2)
%xdefine %%DSTREG %%DST %+ dst_idx
        mov             %%INP, [%%ARRAY_INP + buf_idx]
        vmovdqu8        XWORD(%%DSTREG), [%%INP]
        mov             %%INP, [%%ARRAY_INP + buf_idx + 8]
        vinserti64x2    %%DSTREG, [%%INP], 1
%undef %%DSTREG
%assign dst_idx     (dst_idx + 1)
%assign buf_idx     (buf_idx + 16)
%endrep

%assign blocks_left (%%NUM_BUFFERS % 2)
%xdefine %%DSTREG %%DST %+ dst_idx

%if blocks_left == 1
        mov             %%INP, [%%ARRAY_INP + buf_idx]
        vmovdqu8        XWORD(%%DSTREG), [%%INP]
%endif

%endmacro

;; =============================================================================
;; Stores up to 16 bytes from YMM registers to different output buffers
%macro YMM_STORE_MASKED_BLOCKS_MULT_OUT_0_16 13
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%ARRAY_OUTP    %2 ; [in] array of output data pointers to write to
%define %%OUTP          %3 ; [clobbered] output data pointer to write to
%define %%SRC0          %4 ; [in] YMM register with data to store
%define %%SRC1          %5 ; [in] YMM register with data to store
%define %%SRC2          %6 ; [in] YMM register with data to store
%define %%SRC3          %7 ; [in] YMM register with data to store
%define %%SRC4          %8 ; [in] YMM register with data to store
%define %%SRC5          %9 ; [in] YMM register with data to store
%define %%SRC6          %10 ; [in] YMM register with data to store
%define %%SRC7          %11 ; [in] YMM register with data to store
%define %%XTMP          %12 ; [clobbered] XMM register
%define %%KMASK         %13 ; [in] K mask register

%assign src_idx     0
%assign buf_idx     0

%rep (%%NUM_BLOCKS / 2)
%xdefine %%SRCREG %%SRC %+ src_idx
        mov             %%OUTP, [%%ARRAY_OUTP + buf_idx]
        vmovdqu8        [%%OUTP]{%%KMASK}, XWORD(%%SRCREG)
        mov             %%OUTP, [%%ARRAY_OUTP + buf_idx + 8]
        vextracti64x2   %%XTMP, %%SRCREG, 1
        vmovdqu8        [%%OUTP]{%%KMASK}, %%XTMP
%undef %%SRCREG
%assign src_idx     (src_idx + 1)
%assign buf_idx     (buf_idx + 16)
%endrep

%assign blocks_left (%%NUM_BLOCKS % 2)
%xdefine %%SRCREG %%SRC %+ src_idx

%if blocks_left == 1
        mov             %%OUTP, [%%ARRAY_OUTP + buf_idx]
        vmovdqu8        [%%OUTP]{%%KMASK}, XWORD(%%SRCREG)
%endif

%endmacro

;
; Performs AES-ECB on 16-byte blocks from multiple buffers (IN, number = N_BUFS)
; and outputs 5 bytes of ciphertext to the same number of buffers (OUT),
; all sharing the same AES key
%macro AES_ECB_QUIC 1
%define %%NROUNDS %1 ; [in] Number of AES rounds, numerical value

        or      N_BUFS, N_BUFS
        mov     TMP, N_BUFS
        jz      %%done

        xor     IDX, IDX
        and     TMP, 0xf
        jz      %%main_loop

        ; branch to different code block based on remainder
        cmp     TMP, 8
        je      %%initial_num_buffers_is_8
        jb      %%initial_num_buffers_is_7_1
        cmp     TMP, 12
        je      %%initial_num_buffers_is_12
        jb      %%initial_num_buffers_is_11_9
        ;; 15, 14 or 13
        cmp     TMP, 14
        ja      %%initial_num_buffers_is_15
        je      %%initial_num_buffers_is_14
        jmp     %%initial_num_buffers_is_13
%%initial_num_buffers_is_11_9:
        ;; 11, 10 or 9
        cmp     TMP, 10
        ja      %%initial_num_buffers_is_11
        je      %%initial_num_buffers_is_10
        jmp     %%initial_num_buffers_is_9
%%initial_num_buffers_is_7_1:
        cmp     TMP, 4
        je      %%initial_num_buffers_is_4
        jb      %%initial_num_buffers_is_3_1
        ;; 7, 6 or 5
        cmp     TMP, 6
        ja      %%initial_num_buffers_is_7
        je      %%initial_num_buffers_is_6
        jmp     %%initial_num_buffers_is_5
%%initial_num_buffers_is_3_1:
        ;; 3, 2 or 1
        cmp     TMP, 2
        ja      %%initial_num_buffers_is_3
        je      %%initial_num_buffers_is_2
        ;; fall through for `jmp %%initial_num_buffers_is_1`

%assign num_buffers 1
%rep 15

        %%initial_num_buffers_is_ %+ num_buffers :
%assign %%I 0
        ; load blocks
        YMM_LOAD_BLOCKS_MULT_IN_0_16 num_buffers, IN, TMP, YDATA0,\
                YDATA1, YDATA2, YDATA3, YDATA4, YDATA5,\
                YDATA6, YDATA7

; Perform AES encryption on blocks
%rep (%%NROUNDS + 1)          ; 10/12/14
        vbroadcasti128      YKEY1, [KEYS + %%I*16]
        YMM_AESENC_ROUND_BLOCKS_0_16 YDATA0, YDATA1, YDATA2, YDATA3, YDATA4,\
                YDATA5, YDATA6, YDATA7, YKEY1, %%I, no_data,\
                no_data, no_data, no_data, no_data, no_data,\
                no_data, no_data, num_buffers, (%%NROUNDS - 1)
%assign %%I (%%I + 1)
%endrep

        ; store blocks
        mov     TMP, 0x1f
        kmovq   k1, TMP
        YMM_STORE_MASKED_BLOCKS_MULT_OUT_0_16 num_buffers, OUT, TMP, YDATA0, YDATA1,\
                YDATA2, YDATA3, YDATA4, YDATA5, YDATA6, YDATA7, XWORD(YKEY1), k1

        add     IDX, num_buffers
        cmp     IDX, N_BUFS
        je      %%done

%assign num_buffers (num_buffers + 1)
        jmp     %%main_loop
%endrep

align 16
%%main_loop:
        ; load next 16 blocks
        YMM_LOAD_BLOCKS_MULT_IN_0_16 16, {IN + IDX*8}, TMP, YDATA0,\
                YDATA1, YDATA2, YDATA3, YDATA4, YDATA5,\
                YDATA6, YDATA7

        ; Perform AES encryption/decryption on 16 blocks
%assign %%ROUNDNO 0        ; current key number
%rep (%%NROUNDS + 1)          ; 10/12/14
        vbroadcasti128      YKEY1, [KEYS + %%ROUNDNO*16]
        YMM_AESENC_ROUND_BLOCKS_0_16 YDATA0, YDATA1, YDATA2, YDATA3, YDATA4,\
                YDATA5, YDATA6, YDATA7, YKEY1, %%ROUNDNO, no_data,\
                no_data, no_data, no_data, no_data, no_data,\
                no_data, no_data, 16, (%%NROUNDS - 1)

%assign %%ROUNDNO (%%ROUNDNO + 1)
%endrep

        ; write 16 blocks to output
        mov     TMP, 0x1f
        kmovq   k1, TMP
        YMM_STORE_MASKED_BLOCKS_MULT_OUT_0_16 16, {OUT + IDX*8}, TMP, YDATA0, YDATA1,\
                YDATA2, YDATA3, YDATA4, YDATA5, YDATA6, YDATA7, XWORD(YKEY1), k1

        add     IDX, 16

        cmp     IDX, N_BUFS
        jne     %%main_loop

%%done:
%ifdef SAFE_DATA
        clear_all_zmms_asm
%else
        vzeroupper
%endif
%endmacro

align 16
MKGLOBAL(AES_ECB_QUIC_ENC_128,function,internal)
AES_ECB_QUIC_ENC_128:
        endbranch64
        AES_ECB_QUIC 10
        ret

align 16
MKGLOBAL(AES_ECB_QUIC_ENC_192,function,internal)
AES_ECB_QUIC_ENC_192:
        endbranch64
        AES_ECB_QUIC 12
        ret

align 16
MKGLOBAL(AES_ECB_QUIC_ENC_256,function,internal)
AES_ECB_QUIC_ENC_256:
        endbranch64
        AES_ECB_QUIC 14
        ret

mksection stack-noexec
