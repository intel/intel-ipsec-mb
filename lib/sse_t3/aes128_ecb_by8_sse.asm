;;
;; Copyright (c) 2022, Intel Corporation
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

; routine to do AES ECB 128 encrypt/decrypt on 16n bytes doing AES by 8

%include "include/os.asm"
%include "include/clear_regs.asm"
%include "include/aes_common.asm"

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

%define AES_ECB_ENC aes_ecb_enc_ %+ KEYSIZE %+ _by8_sse
%define AES_ECB_DEC aes_ecb_dec_ %+ KEYSIZE %+ _by8_sse

%macro AES_ECB 1
%define %%DIR     %1 ; [in] Direction (ENC/DEC)
%ifidn %%DIR, ENC
%define AES      XMM_AESENC_ROUND_BLOCKS_SSE_0_8
%else ; DIR = DEC
%define AES      XMM_AESDEC_ROUND_BLOCKS_SSE_0_8
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
%%initial_num_blocks_is_3_1:
        ;; 3, 2 or 1
        cmp     TMP, 2*16
        ja      %%initial_num_blocks_is_3
        je      %%initial_num_blocks_is_2
        ;; fall through for `jmp %%initial_num_blocks_is_1`
%assign num_blocks 1
%rep 7
%%initial_num_blocks_is_ %+ num_blocks :
        ; load initial blocks
        XMM_LOAD_BLOCKS_SSE_0_8 num_blocks, IN, 0, XDATA0,\
                XDATA1, XDATA2, XDATA3, XDATA4, XDATA5,\
                XDATA6, XDATA7
%assign %%I 0
; Perform AES encryption/decryption on initial blocks
%rep (AES_ECB_NROUNDS + 1)          ; 10/12/14
        movdqu      XKEY1, [KEYS + %%I*16]
        AES XDATA0, XDATA1, XDATA2, XDATA3, XDATA4,\
                XDATA5, XDATA6, XDATA7, XKEY1, %%I, no_data,\
                no_data, no_data, no_data, no_data, no_data,\
                no_data, no_data, num_blocks, (AES_ECB_NROUNDS - 1)
%assign %%I (%%I + 1)
%endrep
        ; store initial blocks
        XMM_STORE_BLOCKS_SSE_0_8 num_blocks, OUT, 0, XDATA0, XDATA1,\
                XDATA2, XDATA3, XDATA4, XDATA5, XDATA6, XDATA7
        add     IDX, num_blocks*16
        cmp     IDX, LEN
        je      %%done
%assign num_blocks (num_blocks + 1)
        jmp     %%main_loop
%endrep
align 16
%%main_loop:
        ; load next 8 blocks
        XMM_LOAD_BLOCKS_SSE_0_8 8, {IN + IDX}, 0, XDATA0,\
                XDATA1, XDATA2, XDATA3, XDATA4, XDATA5,\
                XDATA6, XDATA7
%assign %%I 0
; Perform AES encryption/decryption on 8 blocks
%rep (AES_ECB_NROUNDS + 1)          ; 10/12/14
        movdqu      XKEY1, [KEYS + %%I*16]
        AES XDATA0, XDATA1, XDATA2, XDATA3, XDATA4,\
                XDATA5, XDATA6, XDATA7, XKEY1, %%I, no_data,\
                no_data, no_data, no_data, no_data, no_data,\
                no_data, no_data, 8, (AES_ECB_NROUNDS - 1)
%assign %%I (%%I + 1)
%endrep
        ; store 8 blocks
        XMM_STORE_BLOCKS_SSE_0_8 8, {OUT + IDX}, 0, XDATA0, XDATA1,\
                XDATA2, XDATA3, XDATA4, XDATA5, XDATA6, XDATA7
        add     IDX, 8*16
        cmp     IDX, LEN
        jne      %%main_loop
%%done:
%ifdef SAFE_DATA
        clear_all_xmms_sse_asm
%endif
%endmacro

mksection .text
align 16
MKGLOBAL(AES_ECB_ENC,function,internal)
AES_ECB_ENC:
        AES_ECB ENC
        ret
align 16
MKGLOBAL(AES_ECB_DEC,function,internal)
AES_ECB_DEC:
        AES_ECB DEC
        ret

mksection stack-noexec
