;;
;; Copyright (c) 2012-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;


;;; Routine to do a 128 bit CBC-MAC digest computation (AES-XCBC-MAC)
;;; processes 4 buffers at a time, single data structure as input
;;; Updates In pointers and ICVs at end

%include "include/os.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/clear_regs.inc"
%include "include/align_sse.inc"

%define MOVDQ movdqu ;; assume buffers not aligned

%macro pxor2 2
        MOVDQ   XTMP, %2
        pxor    %1, XTMP
%endm

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    rdi             ;r8
%define arg4    rsi             ;r9
%endif

%define ARG     arg1
%define LEN     arg2

%define IDX     rax

%define IN0     r8
%define IN1     r9
%define IN2     r10
%define IN3     r11

%define KEYS0   rbx
%define KEYS1   arg3
%define KEYS2   arg4
%define KEYS3   rbp

%define XDATA0          xmm0
%define XDATA1          xmm1
%define XDATA2          xmm2
%define XDATA3          xmm3

%define XKEY0_3         xmm4
%define XKEY0_6         [KEYS0 + 16*6]
%define XTMP            xmm5
%define XKEY0_9         xmm6

%define XKEY1_3         xmm7
%define XKEY1_6         xmm8
%define XKEY1_9         xmm9

%define XKEY2_3         xmm10
%define XKEY2_6         xmm11
%define XKEY2_9         xmm12

%define XKEY3_3         xmm13
%define XKEY3_6         xmm14
%define XKEY3_9         xmm15

mksection .text

%macro AES_CBC_X4 4
%define %%OFFSET        %1
%define %%ARG_IV        %2
%define %%ARG_KEYS      %3
%define %%ARG_IN        %4

%ifndef LINUX
        push    rsi
        push    rdi
%endif
        push    rbp
        push    rbx

        mov     IDX, %%OFFSET

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        mov             IN0,    [ARG + %%ARG_IN + 8*0]
        mov             IN1,    [ARG + %%ARG_IN + 8*1]
        mov             IN2,    [ARG + %%ARG_IN + 8*2]
        mov             IN3,    [ARG + %%ARG_IN + 8*3]

        MOVDQ           XDATA0, [IN0]           ; load first block of plain text
        MOVDQ           XDATA1, [IN1]           ; load first block of plain text
        MOVDQ           XDATA2, [IN2]           ; load first block of plain text
        MOVDQ           XDATA3, [IN3]           ; load first block of plain text

        mov             KEYS0,  [ARG + %%ARG_KEYS + 8*0]
        mov             KEYS1,  [ARG + %%ARG_KEYS + 8*1]
        mov             KEYS2,  [ARG + %%ARG_KEYS + 8*2]
        mov             KEYS3,  [ARG + %%ARG_KEYS + 8*3]

        pxor            XDATA0, [ARG + %%ARG_IV + 16*0] ; plain text XOR IV
        pxor            XDATA1, [ARG + %%ARG_IV + 16*1] ; plain text XOR IV
        pxor            XDATA2, [ARG + %%ARG_IV + 16*2] ; plain text XOR IV
        pxor            XDATA3, [ARG + %%ARG_IV + 16*3] ; plain text XOR IV

        pxor            XDATA0, [KEYS0 + 16*0]          ; 0. ARK
        pxor            XDATA1, [KEYS1 + 16*0]          ; 0. ARK
        pxor            XDATA2, [KEYS2 + 16*0]          ; 0. ARK
        pxor            XDATA3, [KEYS3 + 16*0]          ; 0. ARK

        aesenc          XDATA0, [KEYS0 + 16*1]  ; 1. ENC
        aesenc          XDATA1, [KEYS1 + 16*1]  ; 1. ENC
        aesenc          XDATA2, [KEYS2 + 16*1]  ; 1. ENC
        aesenc          XDATA3, [KEYS3 + 16*1]  ; 1. ENC

        aesenc          XDATA0, [KEYS0 + 16*2]  ; 2. ENC
        aesenc          XDATA1, [KEYS1 + 16*2]  ; 2. ENC
        aesenc          XDATA2, [KEYS2 + 16*2]  ; 2. ENC
        aesenc          XDATA3, [KEYS3 + 16*2]  ; 2. ENC

        movdqa          XKEY0_3, [KEYS0 + 16*3] ; load round 3 key
        movdqa          XKEY1_3, [KEYS1 + 16*3] ; load round 3 key
        movdqa          XKEY2_3, [KEYS2 + 16*3] ; load round 3 key
        movdqa          XKEY3_3, [KEYS3 + 16*3] ; load round 3 key

        aesenc          XDATA0, XKEY0_3         ; 3. ENC
        aesenc          XDATA1, XKEY1_3         ; 3. ENC
        aesenc          XDATA2, XKEY2_3         ; 3. ENC
        aesenc          XDATA3, XKEY3_3         ; 3. ENC

        aesenc          XDATA0, [KEYS0 + 16*4]  ; 4. ENC
        aesenc          XDATA1, [KEYS1 + 16*4]  ; 4. ENC
        aesenc          XDATA2, [KEYS2 + 16*4]  ; 4. ENC
        aesenc          XDATA3, [KEYS3 + 16*4]  ; 4. ENC

        aesenc          XDATA0, [KEYS0 + 16*5]  ; 5. ENC
        aesenc          XDATA1, [KEYS1 + 16*5]  ; 5. ENC
        aesenc          XDATA2, [KEYS2 + 16*5]  ; 5. ENC
        aesenc          XDATA3, [KEYS3 + 16*5]  ; 5. ENC

        movdqa          XKEY1_6, [KEYS1 + 16*6] ; load round 6 key
        movdqa          XKEY2_6, [KEYS2 + 16*6] ; load round 6 key
        movdqa          XKEY3_6, [KEYS3 + 16*6] ; load round 6 key

        aesenc          XDATA0, XKEY0_6         ; 6. ENC
        aesenc          XDATA1, XKEY1_6         ; 6. ENC
        aesenc          XDATA2, XKEY2_6         ; 6. ENC
        aesenc          XDATA3, XKEY3_6         ; 6. ENC

        aesenc          XDATA0, [KEYS0 + 16*7]  ; 7. ENC
        aesenc          XDATA1, [KEYS1 + 16*7]  ; 7. ENC
        aesenc          XDATA2, [KEYS2 + 16*7]  ; 7. ENC
        aesenc          XDATA3, [KEYS3 + 16*7]  ; 7. ENC

        aesenc          XDATA0, [KEYS0 + 16*8]  ; 8. ENC
        aesenc          XDATA1, [KEYS1 + 16*8]  ; 8. ENC
        aesenc          XDATA2, [KEYS2 + 16*8]  ; 8. ENC
        aesenc          XDATA3, [KEYS3 + 16*8]  ; 8. ENC

        movdqa          XKEY0_9, [KEYS0 + 16*9] ; load round 9 key
        movdqa          XKEY1_9, [KEYS1 + 16*9] ; load round 9 key
        movdqa          XKEY2_9, [KEYS2 + 16*9] ; load round 9 key
        movdqa          XKEY3_9, [KEYS3 + 16*9] ; load round 9 key

        aesenc          XDATA0, XKEY0_9         ; 9. ENC
        aesenc          XDATA1, XKEY1_9         ; 9. ENC
        aesenc          XDATA2, XKEY2_9         ; 9. ENC
        aesenc          XDATA3, XKEY3_9         ; 9. ENC

        aesenclast      XDATA0, [KEYS0 + 16*10] ; 10. ENC
        aesenclast      XDATA1, [KEYS1 + 16*10] ; 10. ENC
        aesenclast      XDATA2, [KEYS2 + 16*10] ; 10. ENC
        aesenclast      XDATA3, [KEYS3 + 16*10] ; 10. ENC

        cmp             LEN, IDX
        jbe             %%_done

align_loop
%%_main_loop:
        pxor2           XDATA0, [IN0 + IDX]     ; plain text XOR IV
        pxor2           XDATA1, [IN1 + IDX]     ; plain text XOR IV
        pxor2           XDATA2, [IN2 + IDX]     ; plain text XOR IV
        pxor2           XDATA3, [IN3 + IDX]     ; plain text XOR IV

        pxor            XDATA0, [KEYS0 + 16*0]  ; 0. ARK
        pxor            XDATA1, [KEYS1 + 16*0]  ; 0. ARK
        pxor            XDATA2, [KEYS2 + 16*0]  ; 0. ARK
        pxor            XDATA3, [KEYS3 + 16*0]  ; 0. ARK

        aesenc          XDATA0, [KEYS0 + 16*1]  ; 1. ENC
        aesenc          XDATA1, [KEYS1 + 16*1]  ; 1. ENC
        aesenc          XDATA2, [KEYS2 + 16*1]  ; 1. ENC
        aesenc          XDATA3, [KEYS3 + 16*1]  ; 1. ENC

        aesenc          XDATA0, [KEYS0 + 16*2]  ; 2. ENC
        aesenc          XDATA1, [KEYS1 + 16*2]  ; 2. ENC
        aesenc          XDATA2, [KEYS2 + 16*2]  ; 2. ENC
        aesenc          XDATA3, [KEYS3 + 16*2]  ; 2. ENC

        aesenc          XDATA0, XKEY0_3         ; 3. ENC
        aesenc          XDATA1, XKEY1_3         ; 3. ENC
        aesenc          XDATA2, XKEY2_3         ; 3. ENC
        aesenc          XDATA3, XKEY3_3         ; 3. ENC

        aesenc          XDATA0, [KEYS0 + 16*4]  ; 4. ENC
        aesenc          XDATA1, [KEYS1 + 16*4]  ; 4. ENC
        aesenc          XDATA2, [KEYS2 + 16*4]  ; 4. ENC
        aesenc          XDATA3, [KEYS3 + 16*4]  ; 4. ENC

        aesenc          XDATA0, [KEYS0 + 16*5]  ; 5. ENC
        aesenc          XDATA1, [KEYS1 + 16*5]  ; 5. ENC
        aesenc          XDATA2, [KEYS2 + 16*5]  ; 5. ENC
        aesenc          XDATA3, [KEYS3 + 16*5]  ; 5. ENC

        aesenc          XDATA0, XKEY0_6         ; 6. ENC
        aesenc          XDATA1, XKEY1_6         ; 6. ENC
        aesenc          XDATA2, XKEY2_6         ; 6. ENC
        aesenc          XDATA3, XKEY3_6         ; 6. ENC

        aesenc          XDATA0, [KEYS0 + 16*7]  ; 7. ENC
        aesenc          XDATA1, [KEYS1 + 16*7]  ; 7. ENC
        aesenc          XDATA2, [KEYS2 + 16*7]  ; 7. ENC
        aesenc          XDATA3, [KEYS3 + 16*7]  ; 7. ENC

        aesenc          XDATA0, [KEYS0 + 16*8]  ; 8. ENC
        aesenc          XDATA1, [KEYS1 + 16*8]  ; 8. ENC
        aesenc          XDATA2, [KEYS2 + 16*8]  ; 8. ENC
        aesenc          XDATA3, [KEYS3 + 16*8]  ; 8. ENC

        aesenc          XDATA0, XKEY0_9         ; 9. ENC
        aesenc          XDATA1, XKEY1_9         ; 9. ENC
        aesenc          XDATA2, XKEY2_9         ; 9. ENC
        aesenc          XDATA3, XKEY3_9         ; 9. ENC

        aesenclast      XDATA0, [KEYS0 + 16*10] ; 10. ENC
        aesenclast      XDATA1, [KEYS1 + 16*10] ; 10. ENC
        aesenclast      XDATA2, [KEYS2 + 16*10] ; 10. ENC
        aesenclast      XDATA3, [KEYS3 + 16*10] ; 10. ENC

        add     IDX, %%OFFSET
        cmp     LEN, IDX
        ja      %%_main_loop

align_label
%%_done:
        ;; update IV / store digest for CBC-MAC
        movdqa  [ARG + %%ARG_IV + 16*0], XDATA0
        movdqa  [ARG + %%ARG_IV + 16*1], XDATA1
        movdqa  [ARG + %%ARG_IV + 16*2], XDATA2
        movdqa  [ARG + %%ARG_IV + 16*3], XDATA3

        ;; update IN pointers
        add     IN0, LEN
        mov     [ARG + %%ARG_IN + 8*0], IN0
        add     IN1, LEN
        mov     [ARG + %%ARG_IN + 8*1], IN1
        add     IN2, LEN
        mov     [ARG + %%ARG_IN + 8*2], IN2
        add     IN3, LEN
        mov     [ARG + %%ARG_IN + 8*3], IN3

        pop     rbx
        pop     rbp
%ifndef LINUX
        pop     rdi
        pop     rsi
%endif

%ifdef SAFE_DATA
        clear_all_xmms_sse_asm
%endif ;; SAFE_DATA

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; struct AES_XCBC_ARGS_x16 {
;;     void*    in[16];
;;     UINT128* keys[16];
;;     UINT128  ICV[16];
;; }
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void aes_xcbc_mac_128_x4(AES_XCBC_ARGS_x16 *args, UINT64 len);

MKGLOBAL(aes_xcbc_mac_128_x4,function,internal)
align_function
aes_xcbc_mac_128_x4:
        AES_CBC_X4 16, _aesxcbcarg_ICV, _aesxcbcarg_keys, _aesxcbcarg_in
        ret

mksection stack-noexec
