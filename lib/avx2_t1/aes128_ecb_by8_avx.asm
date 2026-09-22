;;
;; Copyright (c) 2022-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

; routine to do AES ECB 128 encrypt/decrypt on 16n bytes doing AES by 8

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/aes_common.inc"
%include "include/align_avx.inc"

%ifdef LINUX
%define IN              rdi
%define KEYS            rsi
%define OUT             rdx
%define LEN             rcx
%else
%define IN              rcx
%define KEYS            rdx
%define OUT             r8
%define LEN             r9
%endif
%define IDX             rax
%define TMP             r11
%define XDATA0          xmm0
%define XDATA1          xmm1
%define XDATA2          xmm2
%define XDATA3          xmm3
%define XDATA4          xmm4
%define XDATA5          xmm5
%define XDATA6          xmm6
%define XDATA7          xmm7
%define XKEY1           xmm8

%ifndef AES_ECB_NROUNDS
%define AES_ECB_NROUNDS 10
%endif

%if AES_ECB_NROUNDS == 10
%define KEYSIZE 128
%elif AES_ECB_NROUNDS == 12
%define KEYSIZE 192
%else
%define KEYSIZE 256
%endif

%define AES_ECB_ENC aes_ecb_enc_ %+ KEYSIZE %+ _avx
%define AES_ECB_DEC aes_ecb_dec_ %+ KEYSIZE %+ _avx

%macro AES_ECB 1
%define %%DIR     %1 ; [in] Direction (ENC/DIR)
%ifidn %%DIR, ENC
%define AES      XMM_AESENC_ROUND_BLOCKS_AVX_0_8
%else ; DIR = DEC
%define AES      XMM_AESDEC_ROUND_BLOCKS_AVX_0_8
%endif
%ifndef LINUX
        ;; Windows x64 ABI: xmm6-xmm15 are callee-saved
        sub     rsp, 16*10
        vmovdqu [rsp + 16*0], xmm6
        vmovdqu [rsp + 16*1], xmm7
        vmovdqu [rsp + 16*2], xmm8
        vmovdqu [rsp + 16*3], xmm9
        vmovdqu [rsp + 16*4], xmm10
        vmovdqu [rsp + 16*5], xmm11
        vmovdqu [rsp + 16*6], xmm12
        vmovdqu [rsp + 16*7], xmm13
        vmovdqu [rsp + 16*8], xmm14
        vmovdqu [rsp + 16*9], xmm15
%endif
        or      LEN, LEN
        jz      %%done
        xor     IDX, IDX
        mov     TMP, LEN
        and     TMP, 127        ; number of initial bytes (0 to 7 AES blocks)
        jz      %%main_loop
        ; branch to different code block based on remainder
        cmp     TMP, 4*16
        je      %%initial_num_blocks_is_4
        jb      %%initial_num_blocks_is_3_1
        cmp     TMP, 6*16
        je      %%initial_num_blocks_is_6
        jb      %%initial_num_blocks_is_5
        ja      %%initial_num_blocks_is_7
align_label
%%initial_num_blocks_is_3_1:
        ;; 3, 2 or 1
        cmp     TMP, 2*16
        ja      %%initial_num_blocks_is_3
        je      %%initial_num_blocks_is_2
        ;; fall through for `jmp %%initial_num_blocks_is_1`
%assign num_blocks 1
%rep 7
align_label
%%initial_num_blocks_is_ %+ num_blocks :
        ; load initial blocks
        XMM_LOAD_BLOCKS_AVX_0_8 num_blocks, IN, 0, XDATA0,\
                XDATA1, XDATA2, XDATA3, XDATA4, XDATA5,\
                XDATA6, XDATA7
%assign %%I 0
; Perform AES encryption/decryption on initial blocks
%rep (AES_ECB_NROUNDS + 1)          ; 10/12/14
        vmovdqu      XKEY1, [KEYS + %%I*16]
        AES XDATA0, XDATA1, XDATA2, XDATA3, XDATA4,\
                XDATA5, XDATA6, XDATA7, XKEY1, %%I, no_data,\
                no_data, no_data, no_data, no_data, no_data,\
                no_data, no_data, num_blocks, (AES_ECB_NROUNDS - 1)
%assign %%I (%%I + 1)
%endrep
        ; store initial blocks
        XMM_STORE_BLOCKS_AVX_0_8 num_blocks, OUT, 0, XDATA0, XDATA1,\
                XDATA2, XDATA3, XDATA4, XDATA5, XDATA6, XDATA7
        add     IDX, num_blocks*16
        cmp     IDX, LEN
        je      %%done
%assign num_blocks (num_blocks + 1)
        jmp     %%main_loop
%endrep
align_loop
%%main_loop:
        ; load next 8 blocks
        XMM_LOAD_BLOCKS_AVX_0_8 8, {IN + IDX}, 0, XDATA0,\
                XDATA1, XDATA2, XDATA3, XDATA4, XDATA5,\
                XDATA6, XDATA7
%assign %%I 0
; Perform AES encryption/decryption on 8 blocks
%rep (AES_ECB_NROUNDS + 1)          ; 10/12/14
        vmovdqu      XKEY1, [KEYS + %%I*16]
        AES XDATA0, XDATA1, XDATA2, XDATA3, XDATA4,\
                XDATA5, XDATA6, XDATA7, XKEY1, %%I, no_data,\
                no_data, no_data, no_data, no_data, no_data,\
                no_data, no_data, 8, (AES_ECB_NROUNDS - 1)
%assign %%I (%%I + 1)
%endrep
        ; store 8 blocks
        XMM_STORE_BLOCKS_AVX_0_8 8, {OUT + IDX}, 0, XDATA0, XDATA1,\
                XDATA2, XDATA3, XDATA4, XDATA5, XDATA6, XDATA7
        add     IDX, 8*16
        cmp     IDX, LEN
        jne      %%main_loop
align_label
%%done:
%ifdef SAFE_DATA
        clear_scratch_xmms_avx_asm
%endif
%ifndef LINUX
        vmovdqu xmm6,  [rsp + 16*0]
        vmovdqu xmm7,  [rsp + 16*1]
        vmovdqu xmm8,  [rsp + 16*2]
        vmovdqu xmm9,  [rsp + 16*3]
        vmovdqu xmm10, [rsp + 16*4]
        vmovdqu xmm11, [rsp + 16*5]
        vmovdqu xmm12, [rsp + 16*6]
        vmovdqu xmm13, [rsp + 16*7]
        vmovdqu xmm14, [rsp + 16*8]
        vmovdqu xmm15, [rsp + 16*9]
        add     rsp, 16*10
%endif
%endmacro

mksection .text
align_function
MKGLOBAL(AES_ECB_ENC,function,internal)
AES_ECB_ENC:
        AES_ECB ENC
        ret
align_function
MKGLOBAL(AES_ECB_DEC,function,internal)
AES_ECB_DEC:
        AES_ECB DEC
        ret

mksection stack-noexec
