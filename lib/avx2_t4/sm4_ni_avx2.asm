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

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/aes_common.inc"
%include "include/cet.inc"
%include "include/error.inc"
%include "include/memcpy.inc"

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%define arg6    r9
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    qword [rsp + 40]
%define arg6    qword [rsp + 48]
%endif

mksection .rodata
default rel

align 16
ddq_add_1:
dq 0x0000000000000001, 0x0000000000000000

align 16
byteswap_const:
dq  0x08090A0B0C0D0E0F, 0x0001020304050607
align 16
constants:
dd 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
dd 0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
dd 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
dd 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
dd 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
dd 0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
dd 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
dd 0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
dd 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279

align 32
in_shufb:
db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c
db 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04
db 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c

align 32
out_shufb:
db 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
db 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
db 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
db 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00

%define APPEND(x, y) x %+ y
mksection .text

;
; Shuffle up to 8 YMMs
;
%macro SHUFFLE_BLOCKS 10
%define %%NUM_BLOCKS %1
%define %%YDATA0     %2
%define %%YDATA1     %3
%define %%YDATA2     %4
%define %%YDATA3     %5
%define %%YDATA4     %6
%define %%YDATA5     %7
%define %%YDATA6     %8
%define %%YDATA7     %9
%define %%YSHUF      %10

%assign %%REMAIN_BLOCK (%%NUM_BLOCKS % 2)

%assign j 0
%rep %%NUM_BLOCKS / 2
        vpshufb APPEND(YDATA, j), %%YSHUF
%assign j (j+1)
%endrep
%if (%%REMAIN_BLOCK == 1)
        vpshufb APPEND(YDATA, j), %%YSHUF
%endif
%endmacro

;
; Perform 8 SM4 rounds on YMMs
;
%macro SM4_ROUNDS 10
%define %%NUM_BLOCKS %1
%define %%YDATA0     %2
%define %%YDATA1     %3
%define %%YDATA2     %4
%define %%YDATA3     %5
%define %%YDATA4     %6
%define %%YDATA5     %7
%define %%YDATA6     %8
%define %%YDATA7     %9
%define %%YKEY       %10

%assign %%REMAIN_BLOCK (%%NUM_BLOCKS % 2)

%assign %%I 0
%rep 8 ; Number of SM4 rounds
        vbroadcasti128 %%YKEY, [KEY_EXP + 16*%%I]
%assign %%J 0
%rep %%NUM_BLOCKS/2
        vsm4rnds4 APPEND(%%YDATA, %%J), APPEND(%%YDATA, %%J), %%YKEY
%assign %%J (%%J+1)
%endrep
%if (%%REMAIN_BLOCK == 1)
        vsm4rnds4 APPEND(%%YDATA, %%J), APPEND(%%YDATA, %%J), %%YKEY
%endif

%assign %%I (%%I + 1)
%endrep
%endmacro

align 32
MKGLOBAL(sm4_ecb_ni_avx2,function,internal)
sm4_ecb_ni_avx2:

%define	IN      arg1
%define	OUT     arg2
%define SIZE    arg3
%define	KEY_EXP arg4

%define IDX     r10
%define TMP     r11

%define YDATA0  ymm0
%define YDATA1  ymm1
%define YDATA2  ymm2
%define YDATA3  ymm3
%define YDATA4  ymm4
%define YDATA5  ymm5
%define YDATA6  ymm6
%define YDATA7  ymm7
%define YKEY    ymm15

%define YSHUFB_IN  ymm13
%define YSHUFB_OUT ymm14

%define NBLOCKS_MAIN 8*2

        or      SIZE, SIZE
        jz      done

        vmovdqa YSHUFB_IN,  [rel in_shufb]
        vmovdqa YSHUFB_OUT, [rel out_shufb]
        xor     IDX, IDX
        mov     TMP, SIZE
        and     TMP, 255    ; number of initial bytes (0 to 15 SM4 blocks)
        jz      main_loop

        ; branch to different code block based on remainder
        cmp     TMP, 8*16
        je      initial_num_blocks_is_8
        jb      initial_num_blocks_is_7_1
        cmp     TMP, 12*16
        je      initial_num_blocks_is_12
        jb      initial_num_blocks_is_11_9
        ;; 15, 14 or 13
        cmp     TMP, 14*16
        ja      initial_num_blocks_is_15
        je      initial_num_blocks_is_14
        jmp     initial_num_blocks_is_13
initial_num_blocks_is_11_9:
        ;; 11, 10 or 9
        cmp     TMP, 10*16
        ja      initial_num_blocks_is_11
        je      initial_num_blocks_is_10
        jmp     initial_num_blocks_is_9
initial_num_blocks_is_7_1:
        cmp     TMP, 4*16
        je      initial_num_blocks_is_4
        jb      initial_num_blocks_is_3_1
        ;; 7, 6 or 5
        cmp     TMP, 6*16
        ja      initial_num_blocks_is_7
        je      initial_num_blocks_is_6
        jmp     initial_num_blocks_is_5
initial_num_blocks_is_3_1:
        ;; 3, 2 or 1
        cmp     TMP, 2*16
        ja      initial_num_blocks_is_3
        je      initial_num_blocks_is_2
        ;; fall through for `jmp initial_num_blocks_is_1`

%assign initial_num_blocks 1
%rep 15

initial_num_blocks_is_ %+ initial_num_blocks :
%assign remaining_block (initial_num_blocks %% 2)

        ; load initial blocks
        YMM_LOAD_BLOCKS_AVX2_0_16 initial_num_blocks, IN, 0, YDATA0,\
                YDATA1, YDATA2, YDATA3, YDATA4, YDATA5,\
                YDATA6, YDATA7

        ; shuffle initial blocks initial blocks
        SHUFFLE_BLOCKS initial_num_blocks, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YSHUFB_IN

        SM4_ROUNDS initial_num_blocks, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YKEY

        SHUFFLE_BLOCKS initial_num_blocks, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YSHUFB_OUT

        ; store initial blocks
        YMM_STORE_BLOCKS_AVX2_0_16 initial_num_blocks, OUT, 0, YDATA0, YDATA1,\
                YDATA2, YDATA3, YDATA4, YDATA5, YDATA6, YDATA7

        add     IDX, initial_num_blocks*16
        cmp     IDX, SIZE
        je      done

%assign initial_num_blocks (initial_num_blocks + 1)
        jmp     main_loop
%endrep

align 32
main_loop:
        YMM_LOAD_BLOCKS_AVX2_0_16 NBLOCKS_MAIN, IN, IDX, YDATA0,\
                YDATA1, YDATA2, YDATA3, YDATA4, YDATA5,\
                YDATA6, YDATA7

        SHUFFLE_BLOCKS NBLOCKS_MAIN, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YSHUFB_IN

        SM4_ROUNDS NBLOCKS_MAIN, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YKEY

        SHUFFLE_BLOCKS NBLOCKS_MAIN, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YSHUFB_OUT

        ; store initial blocks
        YMM_STORE_BLOCKS_AVX2_0_16 NBLOCKS_MAIN, OUT, IDX, YDATA0, YDATA1,\
                YDATA2, YDATA3, YDATA4, YDATA5, YDATA6, YDATA7

        add     IDX, 16*NBLOCKS_MAIN
        cmp     IDX, SIZE
        jne     main_loop
done:

%ifdef SAFE_DATA
        clear_all_ymms_asm
%else
        vzeroupper
%endif
        ret

align 32
MKGLOBAL(sm4_cbc_enc_ni_avx2,function,internal)
sm4_cbc_enc_ni_avx2:

%define	IN      arg1
%define	OUT     arg2
%define SIZE    arg3
%define	KEY_EXP arg4

%define IV      r10
%define IDX     r11

%define XIN     xmm0
%define XOUT    xmm1
%define XKEY0   xmm2
%define XKEY1   xmm3
%define XKEY2   xmm4
%define XKEY3   xmm5
%define XKEY4   xmm6
%define XKEY5   xmm7
%define XKEY6   xmm8
%define XKEY7   xmm9

%define XSHUFB_IN  xmm10
%define XSHUFB_OUT xmm11

        or      SIZE, SIZE
        jz      cbc_enc_done

        mov     IV, arg5

        vmovdqa XSHUFB_IN,  [rel in_shufb]
        vmovdqa XSHUFB_OUT, [rel out_shufb]
        shr     SIZE,  4
        xor     IDX, IDX

        ; Load round keys
%assign i 0
%rep 8 ; Number of SM4 rounds
        vmovdqu APPEND(XKEY, i), [KEY_EXP + 16*i]
%assign i (i + 1)
%endrep

        ; Load IV
        vmovdqu XOUT, [IV]
align 32
cbc_enc_loop:
        or      SIZE, SIZE
        jz      cbc_enc_done

        vmovdqu XIN, [IN + IDX]
        vpxor   XIN, XOUT ; Plaintext[n] XOR CT[n-1] ; CT[-1] = IV

        vpshufb XIN, XSHUFB_IN

%assign i 0
%rep 8 ; Number of SM4 rounds
        vsm4rnds4 XIN, XIN, APPEND (XKEY, i)
%assign i (i + 1)
%endrep

        vpshufb XOUT, XIN, XSHUFB_OUT

        vmovdqu [OUT + IDX], XOUT

        add     IDX, 16
        dec     SIZE
        jmp     cbc_enc_loop
cbc_enc_done:

%ifdef SAFE_DATA
        clear_all_ymms_asm
%else
        vzeroupper
%endif
        ret

align 32
MKGLOBAL(sm4_cbc_dec_ni_avx2,function,internal)
sm4_cbc_dec_ni_avx2:

%define	IN      arg1
%define	OUT     arg2
%define SIZE    arg3
%define	KEY_EXP arg4

%define IV      r10

%define IDX     r10
%define TMP     r11

%define YDATA0  ymm0
%define YDATA1  ymm1
%define YDATA2  ymm2
%define YDATA3  ymm3
%define YDATA4  ymm4
%define YDATA5  ymm5
%define YDATA6  ymm6
%define YDATA7  ymm7
%define YDATA0x xmm0
%define YDATA1x xmm1
%define YDATA2x xmm2
%define YDATA3x xmm3
%define YDATA4x xmm4
%define YDATA5x xmm5
%define YDATA6x xmm6
%define YDATA7x xmm7
%define YKEY    ymm15

%define YSHUFB_IN  ymm13
%define YSHUFB_OUT ymm14

%define YPREV_CT   ymm12

%define NBLOCKS_MAIN 8*2

        mov     IV, arg5

        sub     rsp, 16

        or      SIZE, SIZE
        jz      cbc_dec_done

        vmovdqu xmm0, [IV]
        vmovdqu [rsp], xmm0

        vmovdqa YSHUFB_IN,  [rel in_shufb]
        vmovdqa YSHUFB_OUT, [rel out_shufb]
        xor     IDX, IDX
        mov     TMP, SIZE
        and     TMP, 255    ; number of initial bytes (0 to 15 SM4 blocks)
        jz      cbc_dec_main_loop

        ; branch to different code block based on remainder
        cmp     TMP, 8*16
        je      cbc_dec_initial_num_blocks_is_8
        jb      cbc_dec_initial_num_blocks_is_7_1
        cmp     TMP, 12*16
        je      cbc_dec_initial_num_blocks_is_12
        jb      cbc_dec_initial_num_blocks_is_11_9
        ;; 15, 14 or 13
        cmp     TMP, 14*16
        ja      cbc_dec_initial_num_blocks_is_15
        je      cbc_dec_initial_num_blocks_is_14
        jmp     cbc_dec_initial_num_blocks_is_13
cbc_dec_initial_num_blocks_is_11_9:
        ;; 11, 10 or 9
        cmp     TMP, 10*16
        ja      cbc_dec_initial_num_blocks_is_11
        je      cbc_dec_initial_num_blocks_is_10
        jmp     cbc_dec_initial_num_blocks_is_9
cbc_dec_initial_num_blocks_is_7_1:
        cmp     TMP, 4*16
        je      cbc_dec_initial_num_blocks_is_4
        jb      cbc_dec_initial_num_blocks_is_3_1
        ;; 7, 6 or 5
        cmp     TMP, 6*16
        ja      cbc_dec_initial_num_blocks_is_7
        je      cbc_dec_initial_num_blocks_is_6
        jmp     cbc_dec_initial_num_blocks_is_5
cbc_dec_initial_num_blocks_is_3_1:
        ;; 3, 2 or 1
        cmp     TMP, 2*16
        ja      cbc_dec_initial_num_blocks_is_3
        je      cbc_dec_initial_num_blocks_is_2
        ;; fall through for `jmp cbc_dec_initial_num_blocks_is_1`

%assign cbc_dec_initial_num_blocks 1
%rep 15

cbc_dec_initial_num_blocks_is_ %+ cbc_dec_initial_num_blocks :

        ; load initial blocks
        YMM_LOAD_BLOCKS_AVX2_0_16 cbc_dec_initial_num_blocks, IN, 0, YDATA0,\
                YDATA1, YDATA2, YDATA3, YDATA4, YDATA5,\
                YDATA6, YDATA7

        ; shuffle initial blocks initial blocks
        SHUFFLE_BLOCKS cbc_dec_initial_num_blocks, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YSHUFB_IN

        SM4_ROUNDS cbc_dec_initial_num_blocks, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YKEY

        SHUFFLE_BLOCKS cbc_dec_initial_num_blocks, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YSHUFB_OUT

        ; Load IV in first block
        vmovdqu XWORD(YPREV_CT), [rsp]

        ; Load previous ciphertexts and XOR with output from SM4 decryption stage
%if cbc_dec_initial_num_blocks > 1
        vinserti128     YPREV_CT, [IN], 1
        vpxor           YDATA0, YPREV_CT

        ; Up to 13 blocks left
%assign cbc_dec_blocks_left (cbc_dec_initial_num_blocks - 2)

%assign i 0
%assign j 1
%rep    (cbc_dec_blocks_left / 2)
        vmovdqu         YPREV_CT, [IN + 16 + 32*i]
        vpxor           APPEND(YDATA, j), YPREV_CT
%assign i (i + 1)
%assign j (j + 1)
%endrep

%if ((cbc_dec_blocks_left %% 2) == 1)
        vmovdqu         XWORD(YPREV_CT), [IN + 16 + 32*i]
        vpxor           XWORD(APPEND(YDATA, j)), XWORD(YPREV_CT)
%endif
%else ; cbc_dec_initial_num_blocks == 1
        vpxor   XWORD(YDATA0), XWORD(YPREV_CT)
%endif ; cbc_dec_initial_num_blocks > 1

        ; Save last ciphertext, before it potentially gets overwritten
        vmovdqu XWORD(YPREV_CT), [IN + 16 * (cbc_dec_initial_num_blocks - 1)]
        vmovdqu [rsp], XWORD(YPREV_CT)

        ; store initial blocks
        YMM_STORE_BLOCKS_AVX2_0_16 cbc_dec_initial_num_blocks, OUT, 0, YDATA0, YDATA1,\
                YDATA2, YDATA3, YDATA4, YDATA5, YDATA6, YDATA7

        add     IDX, cbc_dec_initial_num_blocks*16
        cmp     IDX, SIZE
        je      cbc_dec_done

%assign cbc_dec_initial_num_blocks (cbc_dec_initial_num_blocks + 1)
        jmp     cbc_dec_main_loop
%endrep

align 32
cbc_dec_main_loop:
        YMM_LOAD_BLOCKS_AVX2_0_16 NBLOCKS_MAIN, IN, IDX, YDATA0,\
                YDATA1, YDATA2, YDATA3, YDATA4, YDATA5,\
                YDATA6, YDATA7

        SHUFFLE_BLOCKS NBLOCKS_MAIN, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YSHUFB_IN

        SM4_ROUNDS NBLOCKS_MAIN, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YKEY

        SHUFFLE_BLOCKS NBLOCKS_MAIN, YDATA0, YDATA1, YDATA2, YDATA3, \
                       YDATA4, YDATA5, YDATA6, YDATA7, YSHUFB_OUT

        ; XOR with previous ciphertext
        vmovdqu         XWORD(YPREV_CT), [rsp]
        vinserti128     YPREV_CT, [IN + IDX], 1
        vpxor           YDATA0, YPREV_CT

%assign i 0
%assign j 1
%rep (14 / 2)
        vmovdqu         YPREV_CT, [IN + IDX + 16 + 32*i]
        vpxor           APPEND(YDATA, j), YPREV_CT
%assign i (i + 1)
%assign j (j + 1)
%endrep

        ; Save last ciphertext, before it potentially gets overwritten
        vmovdqu XWORD(YPREV_CT), [IN + IDX + 16 + 32*i]
        vmovdqu [rsp], XWORD(YPREV_CT)

        ; Store initial blocks
        YMM_STORE_BLOCKS_AVX2_0_16 NBLOCKS_MAIN, OUT, IDX, YDATA0, YDATA1,\
                YDATA2, YDATA3, YDATA4, YDATA5, YDATA6, YDATA7

        add     IDX, 16*NBLOCKS_MAIN
        cmp     IDX, SIZE
        jne     cbc_dec_main_loop
cbc_dec_done:

%ifdef SAFE_DATA
        clear_all_ymms_asm
%else
        vzeroupper
%endif

        add rsp, 16

        ret

align 32
MKGLOBAL(sm4_cntr_ni_avx2,function,internal)
sm4_cntr_ni_avx2:

%define	IN      arg1
%define	OUT     arg2
%define SIZE    arg3
%define	KEY_EXP arg4

%define IV      r10
%define IV_LEN  r11

%define IDX     r10
%define TMP     r11

%define XIN     xmm0
%define XIV     xmm1
%define XKEY0   xmm2
%define XKEY1   xmm3
%define XKEY2   xmm4
%define XKEY3   xmm5
%define XKEY4   xmm6
%define XKEY5   xmm7
%define XKEY6   xmm8
%define XKEY7   xmm9

%define XSHUFB_IN  xmm10
%define XSHUFB_OUT xmm11

        mov     IV, arg5
        mov     IV_LEN, arg6

        or      SIZE, SIZE
        jz      ctr_done

        test    IV_LEN, 16
        jnz     iv_len_is_16_bytes

        ; Read 12 bytes: Nonce + ESP IV. Then pad with block counter 0x00000001
        mov     DWORD(TMP), 0x01000000
        vpinsrq XIV, [IV], 0
        vpinsrd XIV, [IV + 8], 2
        vpinsrd XIV, DWORD(TMP), 3

        jmp     iv_read

iv_len_is_16_bytes:
        vmovdqu XIV, [IV]

iv_read:
        vmovdqa XSHUFB_IN,  [rel in_shufb]
        vmovdqa XSHUFB_OUT, [rel out_shufb]
        xor     IDX, IDX

        ; Load round keys
%assign i 0
%rep 8 ; Number of SM4 rounds
        vmovdqu APPEND(XKEY, i), [KEY_EXP + 16*i]
%assign i (i + 1)
%endrep

        mov     TMP, SIZE
        shr     TMP,  4 ; Number of full blocks
        jz      end_ctr_loop

align 32
ctr_loop:
        vpshufb XIN, XIV, XSHUFB_IN

%assign i 0
%rep 8 ; Number of SM4 rounds
        vsm4rnds4 XIN, XIN, APPEND (XKEY, i)
%assign i (i + 1)
%endrep

        vpshufb XIN, XIN, XSHUFB_OUT

        vpxor   XIN, [IN + IDX]
        vmovdqu [OUT + IDX], XIN

        vpshufb XIV, [rel byteswap_const]
        vpaddd  XIV, [rel ddq_add_1]
        vpshufb XIV, [rel byteswap_const]

        add     IDX, 16
        dec     TMP
        jnz     ctr_loop

end_ctr_loop:
        and     SIZE, 0xf
        jz      ctr_done

        vpshufb XIN, XIV, XSHUFB_IN

%assign i 0
%rep 8 ; Number of SM4 rounds
        vsm4rnds4 XIN, XIN, APPEND (XKEY, i)
%assign i (i + 1)
%endrep

        vpshufb XIN, XIN, XSHUFB_OUT

        add     IN, IDX
        simd_load_avx_15_1 XIV, IN, SIZE
        vpxor   XIN, XIV
        simd_store_avx OUT, XIN, SIZE, TMP, rax, IDX

ctr_done:

%ifdef SAFE_DATA
        clear_all_ymms_asm
%else
        vzeroupper
%endif
        ret

;;
;;void sm4_set_key_ni_avx2(const void *key, const uint32_t *exp_enc_keys,
;;                         const uint32_t *exp_dec_keys)
;;
; arg 1: KEY:  pointer to 128-bit key
; arg 2: EXP_ENC_KEYS: pointer to expanded encryption keys
; arg 3: EXP_DEC_KEYS: pointer to expanded decryption keys
;
align 32
MKGLOBAL(sm4_set_key_ni_avx2,function,internal)
sm4_set_key_ni_avx2:

%define	KEY             arg1
%define	ENC_KEY_EXP     arg2
%define	DEC_KEY_EXP     arg3

        endbranch64
%ifdef SAFE_PARAM
        IMB_ERR_CHECK_RESET

        cmp     KEY, 0
        jz      error_set_key_ni_avx2
        cmp     ENC_KEY_EXP, 0
        jz      error_set_key_ni_avx2
        cmp     DEC_KEY_EXP, 0
        jz      error_set_key_ni_avx2
%endif

        vmovdqu xmm0, [KEY]
        vpshufb xmm0, xmm0, [rel in_shufb]
        vpxor   xmm0, [rel constants]

%assign i 1
%rep 8
        vsm4key4 xmm0, xmm0, [rel constants + 16*i]
        vmovdqu [ENC_KEY_EXP + 16*(i-1)], xmm0
        vpshufd xmm1, xmm0, 0x1B
        vmovdqu [DEC_KEY_EXP + 16*(7-i+1)], xmm1

%assign i (i + 1)
%endrep

sm4_set_key_ni_avx2_return:

%ifdef SAFE_DATA
        clear_all_ymms_asm
%else
        vzeroupper
%endif
       ret

%ifdef SAFE_PARAM
error_set_key_ni_avx2:
        IMB_ERR_CHECK_START rax
        IMB_ERR_CHECK_NULL KEY, rax, IMB_ERR_NULL_KEY
        IMB_ERR_CHECK_NULL ENC_KEY_EXP, rax, IMB_ERR_NULL_EXP_KEY
        IMB_ERR_CHECK_NULL DEC_KEY_EXP, rax, IMB_ERR_NULL_EXP_KEY
        IMB_ERR_CHECK_END rax

        ret
%endif

mksection stack-noexec
