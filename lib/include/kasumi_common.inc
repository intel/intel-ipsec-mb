;;
;; Copyright (c) 2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; Shared register mappings.
%ifdef LINUX
        %define arg1    rdi
        %define arg2    rsi
        %define arg3    rdx
        %define arg4    rcx
        %define arg5    r8
%else
        %define arg1    rcx
        %define arg2    rdx
        %define arg3    r8
        %define arg4    r9
        %define arg5    [rsp + 5*8]
%endif

%define BLK_CNT rbp

%ifdef LINUX
%define UP_KEY_REG r8
%define UP_STATE_REG r9
%define UP_INPUT_REG r9
%define UP_CHAIN_REG rsi
%else
%define UP_KEY_REG rsi
%define UP_STATE_REG rdi
%define UP_INPUT_REG rdi
%define UP_CHAIN_REG rdx
%endif

;; ============================================================================
;; KASUMI_F8_UPDATE_BODY - Kasumi F8 updater
;;
;; Input:
;;   %1 (block_function) = local symbol for the ISA-specific one-block routine
;;   %2 (use_movbe)      = 1 for MOVBE; 0 for MOV plus BSWAP
;;   rax                 = byte length captured from arg5 before frame setup
;;   arg1                = key schedule
;;   arg2                = A/B/count state
;;   arg3                = input buffer
;;   arg4                = output buffer
;; Requires: KASUMI_UPDATE_START has run and the S-box constants are loaded.
;; Output: arg4 receives encrypted bytes; arg2 state is updated.
;; Clobbers: arg1, arg4, rax, rcx, r10, BLK_CNT, UP_KEY_REG, UP_INPUT_REG,
;;           UP_CHAIN_REG, TMP1, and registers clobbered by block_function.
;; Caller must invoke KASUMI_UPDATE_END and return.
;; ============================================================================
%macro KASUMI_F8_UPDATE_BODY 2
%define %%BLOCK_FN %1
%define %%USE_MOVBE %2
        ;; Save loop pointers; UP_CHAIN_REG points to B in the A/B/count state.
        mov     UP_KEY_REG, arg1
        mov     UP_INPUT_REG, arg3
        add     UP_CHAIN_REG, 8
        mov     qword [rsp + _output], arg4
        ;; Full blocks: length / 8; remaining bytes: length % 8.
        mov     BLK_CNT, rax
        shr     BLK_CNT, 3
        and     eax, 7
        mov     [rsp + _tail], rax
        ;; Check if there are any full 8-byte blocks to process.
        test    BLK_CNT, BLK_CNT
        jz      %%tail
align_loop
%%loop:
        ;; Encrypt B and XOR its byte-swapped value with the input block.
        mov     arg1, UP_KEY_REG
        call    %%BLOCK_FN
%if %%USE_MOVBE
        movbe   rax, [UP_CHAIN_REG]
%else
        mov     rax, [UP_CHAIN_REG]
        bswap   rax
%endif
        xor     rax, [UP_INPUT_REG]
        mov     rcx, [rsp + _output]
        mov     [rcx], rax
        dec     BLK_CNT
        jnz     %%prepare
        cmp     qword [rsp + _tail], 0
        jz      %%done
        ;; Only prepare B if another full block or a partial tail follows.
align_label
%%prepare:
        movzx   DWORD(TMP1), word [UP_CHAIN_REG + 8]
        inc     WORD(TMP1)
        mov     [UP_CHAIN_REG + 8], WORD(TMP1)
        mov     rax, [UP_CHAIN_REG - 8]
        xor     rax, TMP1
        xor     [UP_CHAIN_REG], rax
        ;; Advance the input and output pointers.
        add     UP_INPUT_REG, 8
        add     qword [rsp + _output], 8
        test    BLK_CNT, BLK_CNT
        jnz     %%loop
align_label
%%tail:
        mov     arg1, UP_KEY_REG
        call    %%BLOCK_FN
%if %%USE_MOVBE
        movbe   rax, [UP_CHAIN_REG]
%else
        mov     rax, [UP_CHAIN_REG]
        bswap   rax
%endif
        mov     rcx, [rsp + _output]
        mov     r10, [rsp + _tail]
align_label
%%tail_byte:
        ;; XOR one valid input byte with AL, then shift in the next keystream byte.
        xor     al, [UP_INPUT_REG]
        mov     [rcx], al
        shr     rax, 8
        inc     UP_INPUT_REG
        inc     rcx
        dec     r10
        jnz     %%tail_byte
align_label
%%done:
%endmacro

;; ============================================================================
;; KASUMI_F9_UPDATE_BODY - Kasumi F9 updater
;;
;; Input:
;;   %1 (block_function) = local symbol for the ISA-specific one-block routine
;;   %2 (use_movbe)      = 1 for MOVBE; 0 for MOV plus BSWAP
;;   arg1                = key schedule
;;   arg2                = A/B state
;;   arg3                = input buffer
;;   arg4                = input length in bytes
;; Requires: KASUMI_UPDATE_START has run and the S-box constants are loaded.
;; Output: arg2 A/B state is updated.
;; Clobbers: arg1, rax, rcx, r10, BLK_CNT, UP_KEY_REG, UP_INPUT_REG,
;;           UP_CHAIN_REG, and registers clobbered by block_function.
;; Caller must invoke KASUMI_UPDATE_END and return.
;; ============================================================================
%macro KASUMI_F9_UPDATE_BODY 2
%define %%BLOCK_FN %1
%define %%USE_MOVBE %2
        ;; Keep key, input, and A/B state pointers live across block calls.
        mov     UP_KEY_REG, arg1
        mov     UP_INPUT_REG, arg3
        mov     BLK_CNT, arg4
        ;; Split byte length into full 8-byte blocks and a 0-7 byte remainder.
        shr     BLK_CNT, 3
        mov     rax, arg4
        and     eax, 7
        mov     [rsp + _tail], rax
        ;; Check if there are any full 8-byte blocks to process.
        test    BLK_CNT, BLK_CNT
        jz      %%tail
align_loop
%%loop:
        ;; XOR the byte-swapped input block into accumulator A.
%if %%USE_MOVBE
        movbe   rax, [UP_INPUT_REG]
%else
        mov     rax, [UP_INPUT_REG]
        bswap   rax
%endif
        xor     [UP_CHAIN_REG], rax
        mov     arg1, UP_KEY_REG
        call    %%BLOCK_FN
        mov     rax, [UP_CHAIN_REG]
        xor     [UP_CHAIN_REG + 8], rax
        ;; Advance to the next input block.
        add     UP_INPUT_REG, 8
        dec     BLK_CNT
        jnz     %%loop
align_label
%%tail:
        mov     r10, [rsp + _tail]
        test    r10, r10
        jz      %%done
        ;; Append each valid input byte to RAX in message order without overreading.
        xor     eax, eax
align_label
%%tail_byte:
        shl     rax, 8
        movzx   ecx, byte [UP_INPUT_REG]
        or      rax, rcx
        inc     UP_INPUT_REG
        dec     r10
        jnz     %%tail_byte
        ;; Shift the bytes to the high end of the block, leaving zero padding below.
        mov     rcx, 8
        sub     rcx, [rsp + _tail]
        shl     rcx, 3
        shl     rax, cl
        ;; Mix the padded block into A, encrypt A, and accumulate it into B.
        xor     [UP_CHAIN_REG], rax
        mov     arg1, UP_KEY_REG
        call    %%BLOCK_FN
        mov     rax, [UP_CHAIN_REG]
        xor     [UP_CHAIN_REG + 8], rax
align_label
%%done:
%endmacro
