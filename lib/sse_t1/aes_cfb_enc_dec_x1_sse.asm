;;
;; Copyright (c) 2024, Intel Corporation
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

%include "include/os.inc"
%include "include/memcpy.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/error.inc"
%include "include/align_sse.inc"

;;; Routines to do 128/192/256 bit CFB AES encrypt/decrypt operations on one
;;; buffer at a time.

%define ENC 0
%define DEC 1

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%else   ;; WIN_ABI
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    [rsp + 5*8]
%endif

%define OUT     arg1
%define IN      arg2
%define IV      arg3
%define KEYS    arg4

%ifdef LINUX
%define LEN     arg5
%else
%define LEN2    arg5
%define LEN     r11
%endif

%define OUT_CPY r10

%define XDATA0  xmm0
%define XDATA1  xmm1
%define XDATA2  xmm2
%define XDATA3  xmm3
%define XDATA4  xmm4
%define XDATA5  xmm5
%define XDATA6  xmm6
%define XDATA7  xmm7
%define XIN     xmm8
%define KEY_N   xmm9

%define IDX     rax
%define NBLOCKS r14
%define NLOOPS  r15

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Stack frame definition
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifndef LINUX
        %define XMM_STORAGE     (4*16)      ; space for 4 XMM registers
        %define GP_STORAGE      ((3*8) + 24) ; space for 3 GP registers + 24 bytes for 64 byte alignment
%else
        %define XMM_STORAGE     0
        %define GP_STORAGE      (2*8)   ; space for 2 GP registers
%endif

;;; sequence is (bottom-up): GP, XMM, local
%define STACK_GP_OFFSET         0
%define STACK_XMM_OFFSET        (STACK_GP_OFFSET + GP_STORAGE)
%define STACK_FRAME_SIZE        (STACK_XMM_OFFSET + XMM_STORAGE)

mksection .text

%macro FUNC_SAVE 0

%assign my_frame_size (STACK_FRAME_SIZE)

        sub     rsp, my_frame_size

        mov     [rsp + STACK_GP_OFFSET + 0*8], r14
        mov     [rsp + STACK_GP_OFFSET + 1*8], r15
%ifndef LINUX
        mov     [rsp + STACK_GP_OFFSET + 2*8], rdi
        mov     [rsp + STACK_GP_OFFSET + 3*8], rsi
%endif

%ifndef LINUX
        ; xmm6:xmm15 need to be maintained for Windows. Used xmm[6:9]
        movdqu  [rsp + STACK_XMM_OFFSET + 0*16], xmm6
        movdqu  [rsp + STACK_XMM_OFFSET + 1*16], xmm7
        movdqu  [rsp + STACK_XMM_OFFSET + 2*16], xmm8
        movdqu  [rsp + STACK_XMM_OFFSET + 3*16], xmm9
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Restore register content for the caller
%macro FUNC_RESTORE 0

%ifndef LINUX
        movdqu  xmm9, [rsp + STACK_XMM_OFFSET + 3*16]
        movdqu  xmm8, [rsp + STACK_XMM_OFFSET + 2*16]
        movdqu  xmm7, [rsp + STACK_XMM_OFFSET + 1*16]
        movdqu  xmm6, [rsp + STACK_XMM_OFFSET + 0*16]
%endif

%ifndef LINUX
        mov     rdi, [rsp + STACK_GP_OFFSET + 2*8]
        mov     rsi, [rsp + STACK_GP_OFFSET + 3*8]
%endif
        mov     r14, [rsp + STACK_GP_OFFSET + 0*8]
        mov     r15, [rsp + STACK_GP_OFFSET + 1*8]
        add     rsp, my_frame_size
%endmacro


%macro SSE_AES_CFB_DEC_PARALLEL 2
%define %%NBLOCKS       %1
%define %%NROUNDS       %2

%xdefine %%NBYTES       (%%NBLOCKS * 16)

        movdqu  KEY_N,  [KEYS]
        pxor    XDATA0, KEY_N

%assign reg_idx 1
%rep (%%NBLOCKS - 1)
%xdefine %%DSTREG       XDATA %+ reg_idx
        movdqu  %%DSTREG, [IN + IDX + ((reg_idx - 1) * 16)]
        pxor    %%DSTREG, KEY_N
%assign reg_idx (reg_idx + 1)
%endrep

;; AES ENC ROUNDS
%assign i 16
%rep %%NROUNDS
        movdqu  KEY_N,  [KEYS + i]

%assign reg_idx 0
%rep %%NBLOCKS
%xdefine %%DSTREG       XDATA %+ reg_idx
        aesenc  %%DSTREG, KEY_N
%assign reg_idx (reg_idx + 1)
%endrep

%assign i (i+16)
;; Last Round of AES ENC
%endrep
        movdqu  KEY_N,  [KEYS + i]
%assign reg_idx 0
%rep %%NBLOCKS
%xdefine %%DSTREG       XDATA %+ reg_idx
        aesenclast              %%DSTREG, KEY_N
%assign reg_idx (reg_idx + 1)
%endrep

;; Save to Output Buffer
%assign reg_idx 0
%rep %%NBLOCKS
%xdefine %%DSTREG       XDATA %+ reg_idx
        movdqu  XIN, [IN + IDX + (16 * reg_idx)]
        pxor    %%DSTREG, XIN
        movdqu  [OUT + IDX + (16 * reg_idx)], %%DSTREG
%assign reg_idx (reg_idx + 1)
%endrep
        add     IDX, %%NBYTES

%endmacro
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Input: %%NROUNDS: number of aesenc rounds depending on key size:
;; 128b key: (10 - 1) rounds
;; 192b key: (12 - 1) rounds
;; 256b key: (14 - 1) rounds
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro do_cfb_dec 1
%define %%NROUNDS       %1

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES CFB dec entry point
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        xor     IDX, IDX
        mov     NBLOCKS, LEN
        shr     NBLOCKS, 4
        mov     NLOOPS, NBLOCKS
        shr     NLOOPS, 3
        and     NBLOCKS, 7
        je      %%pre_main_loop
align_label
%%block_jump_table:
        movdqu  XDATA0, [IV]
        cmp     NBLOCKS, 2
        jb      %%one_block_processing
        je      %%two_block_processing
        cmp     NBLOCKS, 4
        jb      %%three_block_processing
        je      %%four_block_processing
        cmp     NBLOCKS, 6
        jb      %%five_block_processing
        je      %%six_block_processing

%%seven_block_processing:
        SSE_AES_CFB_DEC_PARALLEL 7, %%NROUNDS
        jmp     %%check_remaining_blocks

align_label
%%six_block_processing:
        SSE_AES_CFB_DEC_PARALLEL 6, %%NROUNDS
        jmp     %%check_remaining_blocks

align_label
%%five_block_processing:
        SSE_AES_CFB_DEC_PARALLEL 5, %%NROUNDS
        jmp     %%check_remaining_blocks

align_label
%%four_block_processing:
        SSE_AES_CFB_DEC_PARALLEL 4, %%NROUNDS
        jmp     %%check_remaining_blocks

align_label
%%three_block_processing:
        SSE_AES_CFB_DEC_PARALLEL 3, %%NROUNDS
        jmp     %%check_remaining_blocks

align_label
%%two_block_processing:
        SSE_AES_CFB_DEC_PARALLEL 2, %%NROUNDS
        jmp     %%check_remaining_blocks

align_label
%%one_block_processing:
        SSE_AES_CFB_DEC_PARALLEL 1, %%NROUNDS

align_label
%%check_remaining_blocks:
        or      NLOOPS, NLOOPS
        je      %%post_processing
        movdqa  XDATA0, XIN
        jmp     %%main_loop

align_label
%%pre_main_loop:
        or      NLOOPS, NLOOPS
        je      %%post_processing
        movdqu  XDATA0, [IV]

align_loop
%%main_loop:
        SSE_AES_CFB_DEC_PARALLEL 8, %%NROUNDS
        sub     NLOOPS, 1
        je      %%post_processing
        movdqa  XDATA0, XIN
        jmp     %%main_loop

align_label
%%post_processing:
        cmp     LEN, IDX
        je      %%_done

align_label
%%_last_block: ;; 1 - 15 bytes left to process
        and     LEN, 15
        add     IN, IDX
        sub     IN, 16
        simd_load_sse_15_1 XIN, IN, LEN
        movdqa  XDATA0, XIN
        SSE_AES_CFB_DEC_PARALLEL 1, %%NROUNDS

align_label
%%_done:
%ifdef SAFE_DATA
        clear_xmms_sse  XDATA0, XDATA1, XDATA2, XDATA3, XDATA4, XDATA5, XDATA6, XDATA7, XIN, KEY_N
        clear_scratch_gps_asm
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Input: %%NROUNDS: number of aesenc rounds depending on key size:
;; 128b key: (10 - 1) rounds
;; 192b key: (12 - 1) rounds
;; 256b key: (14 - 1) rounds
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro do_cfb_enc 1
%define %%NROUNDS       %1

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES CFB enc entry point
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     IDX, 16
        movdqu  XDATA0, [IV]     ; IV, used for 1st block only
align_loop
%%single_block_processing:
        pxor    XDATA0, [KEYS]  ; key XOR plaintext

        cmp     LEN, IDX
        jb      %%_last_block

        movdqu  XIN, [IN + IDX - 16]

%assign i 16
%rep %%NROUNDS
        aesenc  XDATA0, [KEYS + i]
%assign i (i+16)
%endrep
        aesenclast      XDATA0, [KEYS + i]

        pxor    XDATA0, XIN
        movdqu  [OUT + IDX - 16], XDATA0
        cmp     LEN, IDX
        je      %%_done         ;; length was multiple of 16 bytes

        add     IDX, 16

        jmp     %%single_block_processing

align_label
%%_last_block: ;; 1 - 15 bytes left to process
        ;; use LEN and IN as temp
        and     LEN, 15
        add     IN, IDX
        sub     IN, 16
        simd_load_sse_15_1 XIN, IN, LEN

%assign i 16
%rep %%NROUNDS
        aesenc  XDATA0, [KEYS + i]      ; ENC with round key ()
%assign i (i+16)
%endrep
        aesenclast      XDATA0, [KEYS + i]
        pxor    XDATA0, XIN
        mov     OUT_CPY, OUT
        add     OUT_CPY, IDX
        sub     OUT_CPY, 16

        simd_store_sse  OUT_CPY, XDATA0, LEN, IN, IDX

align_label
%%_done:
%ifdef SAFE_DATA
        ;; XDATA and XIN are the only scratch SIMD registers used
        clear_xmms_sse  XDATA0, XIN
        clear_scratch_gps_asm
%endif

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cfb_/*128/192/256*/_/*enc/dec*/_sse
;;(void *out, void *in, void *iv, void *keys, uint64_t len)
;; arg 1: OUT : addr to put clear/cipher text out
;; arg 2: IN  : addr to take cipher/clear text from
;; arg 3: IV  : initialization vector
;; arg 4: KEYS: pointer to expanded keys structure (16 byte aligned)
;; arg 5: LEN:  length of the text to encrypt/decrypt
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifndef AES_CFB_128_ENC
%define AES_CFB_128_ENC aes_cfb_128_enc_sse
%define AES_CFB_192_ENC aes_cfb_192_enc_sse
%define AES_CFB_256_ENC aes_cfb_256_enc_sse
%define AES_CFB_128_DEC aes_cfb_128_dec_sse
%define AES_CFB_192_DEC aes_cfb_192_dec_sse
%define AES_CFB_256_DEC aes_cfb_256_dec_sse
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES CFB 128
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cfb_128_enc
MKGLOBAL(AES_CFB_128_ENC,function,)
align_function
AES_CFB_128_ENC:
endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        do_cfb_enc      9
        ret

;; void aes_cfb_128_dec
MKGLOBAL(AES_CFB_128_DEC,function,)
align_function
AES_CFB_128_DEC:
endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        FUNC_SAVE
        do_cfb_dec      9
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES CFB 192
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cfb_192_enc
MKGLOBAL(AES_CFB_192_ENC,function,)
align_function
AES_CFB_192_ENC:
endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        do_cfb_enc      11
        ret

;; void aes_cfb_192_dec
MKGLOBAL(AES_CFB_192_DEC,function,)
align_function
AES_CFB_192_DEC:
endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        FUNC_SAVE
        do_cfb_dec      11
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES CFB 256
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cfb_256_enc
MKGLOBAL(AES_CFB_256_ENC,function,)
align_function
AES_CFB_256_ENC:
endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        do_cfb_enc      13
        ret

;; void aes_cfb_256_dec
MKGLOBAL(AES_CFB_256_DEC,function,)
align_function
AES_CFB_256_DEC:
endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        FUNC_SAVE
        do_cfb_dec      13
        FUNC_RESTORE
        ret

mksection stack-noexec
