;;
;; Copyright (c) 2024-2026, Intel Corporation
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

;;; Routines to do 128/192/256 bit CFB AES decrypt operations on one
;;; buffer at a time.

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

%define NROUNDS r10
%define NBLOCKS rax
;; NBLOCKS and NLOOPS intentionally alias rax; their lifetimes do not overlap.
%define NLOOPS  rax

%define XDATA0  xmm0
%define XDATA1  xmm1
%define XDATA2  xmm2
%define XDATA3  xmm3
%define XDATA4  xmm4
%define XDATA5  xmm5
%define XDATA6  xmm6
%define XDATA7  xmm7

%define XTMP0   xmm8
%define XTMP1   xmm9
%define XTMP2   xmm10
%define XTMP3   xmm11
%define XTMP4   xmm12
%define XTMP5   xmm13
%define XTMP6   xmm14
%define XTMP7   xmm15

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Stack frame definition
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifndef LINUX
%define XMM_STORAGE     (10*16) ; space for 10 XMM registers
%define GP_STORAGE      (2*8)   ; space for 2 GP registers

;;; sequence is (bottom-up): GP, XMM, local
%define STACK_GP_OFFSET         0
%define STACK_XMM_OFFSET        (STACK_GP_OFFSET + GP_STORAGE)
%define STACK_FRAME_SIZE        (STACK_XMM_OFFSET + XMM_STORAGE)
%endif


mksection .text

;; XDATA0  [in/out] XMM; IV
;; IN      [in/out] GP; source pointer
;; OUT     [in/out] GP; destination pointer
;; NROUNDS [in] GP; run-time selected number of aesenc rounds
;; XTMP7   [clobbered]
%macro AES_CFB_DEC_1_TO_7 1-2
%define %%NBLOCKS       %1      ; [in] numerical value, number of blocks to process (1 to 7)
%define %%OUTBLOCK      %2      ; [in/out] (optional) XMM register with partial block message data

        ;; ARK
        ;; - load message NBLOCKS-1 into TMP0..TMP6
        movdqu  XTMP7,  [KEYS + 0*16]
        pxor    XDATA0, XTMP7

%assign tmp_idx 0
%assign reg_idx 1
%rep (%%NBLOCKS - 1)
        movdqu  XTMP %+ tmp_idx, [IN + (tmp_idx * 16)]
        movdqa  XDATA %+ reg_idx, XTMP %+ tmp_idx
        pxor    XDATA %+ reg_idx, XTMP7
%assign tmp_idx (tmp_idx + 1)
%assign reg_idx (reg_idx + 1)
%endrep

        ;; AES ENC ROUNDS
%assign i 1
%rep 9
        movdqu  XTMP7,  [KEYS + i*16]

%assign reg_idx 0
%rep %%NBLOCKS
        aesenc  XDATA %+ reg_idx, XTMP7
%assign reg_idx (reg_idx + 1)
%endrep ;; number of blocks x aesenc

%assign i (i + 1)
%endrep ;; 9 x {number of blocks x aesenc}

        cmp     DWORD(NROUNDS), 11
        ja      %%_key_256b
        je      %%_key_192b

        ;; fall through for 128b key
        movdqu  XTMP7,  [KEYS + 10*16]
%assign reg_idx 0
%rep %%NBLOCKS
        aesenclast  XDATA %+ reg_idx, XTMP7
%assign reg_idx (reg_idx + 1)
%endrep
        jmp     %%_aesenclast_done

align_label
%%_key_192b:
%assign i 10    ;; aesenc 10 and 11
%rep 2
        movdqu  XTMP7,  [KEYS + i*16]

%assign reg_idx 0
%rep %%NBLOCKS
        aesenc  XDATA %+ reg_idx, XTMP7
%assign reg_idx (reg_idx + 1)
%endrep ;; number of blocks x aesenc

%assign i (i + 1)
%endrep ;; 2 x {number of blocks x aesenc}

        movdqu  XTMP7,  [KEYS + 12*16]
%assign reg_idx 0
%rep %%NBLOCKS
        aesenclast  XDATA %+ reg_idx, XTMP7
%assign reg_idx (reg_idx + 1)
%endrep
        jmp     %%_aesenclast_done

align_label
%%_key_256b:
%assign i 10    ;; aesenc 10, 11, 12 and 13
%rep 4
        movdqu  XTMP7,  [KEYS + i*16]

%assign reg_idx 0
%rep %%NBLOCKS
        aesenc  XDATA %+ reg_idx, XTMP7
%assign reg_idx (reg_idx + 1)
%endrep ;; number of blocks x aesenc

%assign i (i + 1)
%endrep ;; 4 x {number of blocks x aesenc}

        movdqu  XTMP7,  [KEYS + 14*16]
%assign reg_idx 0
%rep %%NBLOCKS
        aesenclast  XDATA %+ reg_idx, XTMP7
%assign reg_idx (reg_idx + 1)
%endrep

align_label
%%_aesenclast_done:

        ;; Save to Output Buffer
%if %0 == 2
        ;; partial block case only
        pxor    %2, XDATA0
%else  
%assign reg_idx 0
%rep (%%NBLOCKS - 1)
        pxor    XDATA %+ reg_idx, XTMP %+ reg_idx
%assign reg_idx (reg_idx + 1)
%endrep

        movdqu  XTMP7, [IN + (16 * (%%NBLOCKS - 1))]
        pxor    XDATA %+ reg_idx, XTMP7

%assign reg_idx 0
%rep %%NBLOCKS
        movdqu  [OUT + (16 * reg_idx)], XDATA %+ reg_idx
%assign reg_idx (reg_idx + 1)
%endrep

        movdqa  XDATA0, XTMP7

        add     IN, (%%NBLOCKS * 16)
        add     OUT, (%%NBLOCKS * 16)
%endif

%endmacro ;; AES_CFB_DEC_1_TO_7

;; XDATA0  [in/out] XMM; IV
;; IN      [in/out] GP; source pointer
;; OUT     [in/out] GP; destination pointer
;; NROUNDS [in] GP; run-time selected number of aesenc rounds
;; XTMP7   [clobbered]
%macro AES_CFB_DEC_8 0-2
;; %1 [in] XMM with loaded message block 0
;; %2 [out] XMM to load message block 0 from the next group of 8 blocks

        ;; ARK
        ;; - load 7 message blocks into TMP0..TMP6
        movdqu  XTMP7,  [KEYS + 0*16]
        pxor    XDATA0, XTMP7

%if %0 >= 1
        movdqa  XTMP0, %1
%else
        movdqu  XTMP0, [IN + (0 * 16)]
%endif
        movdqa  XDATA1, XTMP0
        pxor    XDATA1, XTMP7

        movdqu  XTMP1, [IN + (1 * 16)]
        movdqa  XDATA2, XTMP1
        pxor    XDATA2, XTMP7

        movdqu  XTMP2, [IN + (2 * 16)]
        movdqa  XDATA3, XTMP2
        pxor    XDATA3, XTMP7

        movdqu  XTMP3, [IN + (3 * 16)]
        movdqa  XDATA4, XTMP3
        pxor    XDATA4, XTMP7

        movdqu  XTMP4, [IN + (4 * 16)]
        movdqa  XDATA5, XTMP4
        pxor    XDATA5, XTMP7

        movdqu  XTMP5, [IN + (5 * 16)]
        movdqa  XDATA6, XTMP5
        pxor    XDATA6, XTMP7

        movdqu  XTMP6, [IN + (6 * 16)]
        movdqa  XDATA7, XTMP6
        pxor    XDATA7, XTMP7

        ;; AES ENC ROUNDS
%assign i 1
%rep 9
        movdqu  XTMP7,  [KEYS + i*16]
        aesenc  XDATA0, XTMP7
        aesenc  XDATA1, XTMP7
        aesenc  XDATA2, XTMP7
        aesenc  XDATA3, XTMP7
        aesenc  XDATA4, XTMP7
        aesenc  XDATA5, XTMP7
        aesenc  XDATA6, XTMP7
        aesenc  XDATA7, XTMP7
%assign i (i + 1)
%endrep ;; 9 x {8 blocks x aesenc}

        cmp     DWORD(NROUNDS), 11
        ja      %%_key_256b
        je      %%_key_192b

        ;; fall through for 128b key
        movdqu          XTMP7,  [KEYS + 10*16]
        aesenclast      XDATA0, XTMP7
        aesenclast      XDATA1, XTMP7
        aesenclast      XDATA2, XTMP7
        aesenclast      XDATA3, XTMP7
        aesenclast      XDATA4, XTMP7
        aesenclast      XDATA5, XTMP7
        aesenclast      XDATA6, XTMP7
        aesenclast      XDATA7, XTMP7
        jmp     %%_aesenclast_done

align_label
%%_key_192b:
%assign i 10    ;; aesenc 10 and 11
%rep 2
        movdqu  XTMP7,  [KEYS + i*16]
        aesenc  XDATA0, XTMP7
        aesenc  XDATA1, XTMP7
        aesenc  XDATA2, XTMP7
        aesenc  XDATA3, XTMP7
        aesenc  XDATA4, XTMP7
        aesenc  XDATA5, XTMP7
        aesenc  XDATA6, XTMP7
        aesenc  XDATA7, XTMP7
%assign i (i + 1)
%endrep ;; 2 x {8 blocks x aesenc}

        movdqu          XTMP7,  [KEYS + 12*16]
        aesenclast      XDATA0, XTMP7
        aesenclast      XDATA1, XTMP7
        aesenclast      XDATA2, XTMP7
        aesenclast      XDATA3, XTMP7
        aesenclast      XDATA4, XTMP7
        aesenclast      XDATA5, XTMP7
        aesenclast      XDATA6, XTMP7
        aesenclast      XDATA7, XTMP7
        jmp     %%_aesenclast_done

align_label
%%_key_256b:
%assign i 10    ;; aesenc 10, 11, 12 and 13
%rep 4
        movdqu  XTMP7,  [KEYS + i*16]
        aesenc  XDATA0, XTMP7
        aesenc  XDATA1, XTMP7
        aesenc  XDATA2, XTMP7
        aesenc  XDATA3, XTMP7
        aesenc  XDATA4, XTMP7
        aesenc  XDATA5, XTMP7
        aesenc  XDATA6, XTMP7
        aesenc  XDATA7, XTMP7

%assign i (i + 1)
%endrep ;; 4 x {8 blocks x aesenc}

        movdqu          XTMP7,  [KEYS + 14*16]
        aesenclast      XDATA0, XTMP7
        aesenclast      XDATA1, XTMP7
        aesenclast      XDATA2, XTMP7
        aesenclast      XDATA3, XTMP7
        aesenclast      XDATA4, XTMP7
        aesenclast      XDATA5, XTMP7
        aesenclast      XDATA6, XTMP7
        aesenclast      XDATA7, XTMP7

align_label
%%_aesenclast_done:

        ;; Save to Output Buffer
        pxor    XDATA0, XTMP0
        pxor    XDATA1, XTMP1
        pxor    XDATA2, XTMP2
        pxor    XDATA3, XTMP3

        movdqu  [OUT + (16 * 0)], XDATA0
        movdqu  [OUT + (16 * 1)], XDATA1
        movdqu  [OUT + (16 * 2)], XDATA2
        movdqu  [OUT + (16 * 3)], XDATA3

        pxor    XDATA4, XTMP4
        pxor    XDATA5, XTMP5
        pxor    XDATA6, XTMP6
        movdqu  XTMP7, [IN + (16 * 7)]  ;; it wasn't loaded before
%if %0 == 2
        movdqu  %2,  [IN + (16 * 8)]    ;; load next block into designated register
%endif
        pxor    XDATA7, XTMP7

        movdqu  [OUT + (16 * 4)], XDATA4
        movdqu  [OUT + (16 * 5)], XDATA5
        movdqu  [OUT + (16 * 6)], XDATA6
        movdqu  [OUT + (16 * 7)], XDATA7

        movdqa  XDATA0, XTMP7           ;; IV for the next round

        add     IN, (8 * 16)
        add     OUT, (8 * 16)

%endmacro ;; AES_CFB_DEC_8

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES CFB dec entry point
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Input: %%NROUNDS: number of aesenc rounds depending on key size:
;; 128b key: (10 - 1) rounds
;; 192b key: (12 - 1) rounds
;; 256b key: (14 - 1) rounds
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

align_function
aes_cfb_dec_sse:
%ifndef LINUX
        sub     rsp, STACK_FRAME_SIZE

        mov     [rsp + STACK_GP_OFFSET + 0*8], rdi
        mov     [rsp + STACK_GP_OFFSET + 1*8], rsi

        ;; xmm6:xmm15 need to be maintained for Windows
        movdqu  [rsp + STACK_XMM_OFFSET + 0*16], xmm6
        movdqu  [rsp + STACK_XMM_OFFSET + 1*16], xmm7
        movdqu  [rsp + STACK_XMM_OFFSET + 2*16], xmm8
        movdqu  [rsp + STACK_XMM_OFFSET + 3*16], xmm9
        movdqu  [rsp + STACK_XMM_OFFSET + 4*16], xmm10
        movdqu  [rsp + STACK_XMM_OFFSET + 5*16], xmm11
        movdqu  [rsp + STACK_XMM_OFFSET + 6*16], xmm12
        movdqu  [rsp + STACK_XMM_OFFSET + 7*16], xmm13
        movdqu  [rsp + STACK_XMM_OFFSET + 8*16], xmm14
        movdqu  [rsp + STACK_XMM_OFFSET + 9*16], xmm15
%endif

        or      LEN, LEN
        je      .done

        movdqu  XDATA0, [IV]

        mov     NBLOCKS, LEN
        shr     NBLOCKS, 4
        and     DWORD(NBLOCKS), 7
        je      .check_remaining_blocks

        cmp     DWORD(NBLOCKS), 2
        jb      .one_block_processing
        je      .two_block_processing
        cmp     DWORD(NBLOCKS), 4
        jb      .three_block_processing
        je      .four_block_processing
        cmp     DWORD(NBLOCKS), 6
        jb      .five_block_processing
        je      .six_block_processing

        AES_CFB_DEC_1_TO_7 7
        jmp     .check_remaining_blocks

align_label
.six_block_processing:
        AES_CFB_DEC_1_TO_7 6
        jmp     .check_remaining_blocks

align_label
.five_block_processing:
        AES_CFB_DEC_1_TO_7 5
        jmp     .check_remaining_blocks

align_label
.four_block_processing:
        AES_CFB_DEC_1_TO_7 4
        jmp     .check_remaining_blocks

align_label
.three_block_processing:
        AES_CFB_DEC_1_TO_7 3
        jmp     .check_remaining_blocks

align_label
.two_block_processing:
        AES_CFB_DEC_1_TO_7 2
        jmp     .check_remaining_blocks

align_label
.one_block_processing:
        AES_CFB_DEC_1_TO_7 1

align_label
.check_remaining_blocks:
        mov     NLOOPS, LEN
        shr     NLOOPS, 7       ; 8 x 16 = 2^7 bytes process in the main loop
        je      .post_processing
        cmp     NLOOPS, 2
        jb      .last_loop

        movdqu  XTMP6, [IN]
        dec     NLOOPS          ; decrement 1 as last loop will always take place
align_loop
.main_loop:
        AES_CFB_DEC_8 XTMP6, XTMP6
        dec     NLOOPS
        jnz     .main_loop

align_label
.last_loop:
        AES_CFB_DEC_8

align_label
.post_processing:
        and     DWORD(LEN), 15
        je      .done

align_label
.last_block:
        ;; 1 - 15 bytes left to process
        simd_load_sse_15_1 XTMP6, IN, LEN
        AES_CFB_DEC_1_TO_7 1, XTMP6
        simd_store_sse  OUT, XTMP6, LEN, IN, NLOOPS

align_label
.done:
%ifdef SAFE_DATA
        clear_scratch_xmms_sse_asm
        clear_gps       IN, LEN, NLOOPS
%endif

%ifndef LINUX
        movdqu  xmm15, [rsp + STACK_XMM_OFFSET + 9*16]
        movdqu  xmm14, [rsp + STACK_XMM_OFFSET + 8*16]
        movdqu  xmm13, [rsp + STACK_XMM_OFFSET + 7*16]
        movdqu  xmm12, [rsp + STACK_XMM_OFFSET + 6*16]
        movdqu  xmm11, [rsp + STACK_XMM_OFFSET + 5*16]
        movdqu  xmm10, [rsp + STACK_XMM_OFFSET + 4*16]
        movdqu  xmm9, [rsp + STACK_XMM_OFFSET + 3*16]
        movdqu  xmm8, [rsp + STACK_XMM_OFFSET + 2*16]
        movdqu  xmm7, [rsp + STACK_XMM_OFFSET + 1*16]
        movdqu  xmm6, [rsp + STACK_XMM_OFFSET + 0*16]

        mov     rsi, [rsp + STACK_GP_OFFSET + 1*8]
        mov     rdi, [rsp + STACK_GP_OFFSET + 0*8]

        add     rsp, STACK_FRAME_SIZE
%endif
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_cfb_[128|192|256]_dec_sse
;;(void *out, void *in, void *iv, void *keys, uint64_t len)
;; arg 1: OUT : addr to put clear text out
;; arg 2: IN  : addr to take cipher text from
;; arg 3: IV  : initialization vector
;; arg 4: KEYS: pointer to expanded keys structure (16 byte aligned)
;; arg 5: LEN:  length of the text to decrypt
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; void aes_cfb_128_dec
MKGLOBAL(aes_cfb_128_dec_sse,function,)
align_function
aes_cfb_128_dec_sse:
        endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        mov     DWORD(NROUNDS), 9
        jmp     aes_cfb_dec_sse

;; void aes_cfb_192_dec
MKGLOBAL(aes_cfb_192_dec_sse,function,)
align_function
aes_cfb_192_dec_sse:
        endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        mov     DWORD(NROUNDS), 11
        jmp     aes_cfb_dec_sse

;; void aes_cfb_256_dec
MKGLOBAL(aes_cfb_256_dec_sse,function,)
align_function
aes_cfb_256_dec_sse:
        endbranch64
%ifdef WIN_ABI
        mov     LEN, LEN2
%endif
        mov     DWORD(NROUNDS), 13
        jmp     aes_cfb_dec_sse

mksection stack-noexec
