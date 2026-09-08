;;
;; Copyright (c) 2021-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/cet.inc"
%include "include/memcpy.inc"
%include "include/align_sse.inc"
%define APPEND(a,b) a %+ b
%define APPEND3(a,b,c) a %+ b %+ c

%ifdef LINUX
%define arg1 rdi
%define arg2 rsi
%define arg3 rdx
%define arg4 rcx
%else
%define arg1 rcx
%define arg2 rdx
%define arg3 r8
%define arg4 r9
%endif

%define E               rax
%define rem_bytes       r12
%define tmp4            r13
%define in_ptr          arg1
%define KS              arg2
%define byte_len        arg3

%define EV              xmm2
%define SNOW3G_CONST    xmm7
%define P1              xmm8

%ifndef SNOW3G_F9_1_BUFFER_INTERNAL
%define SNOW3G_F9_1_BUFFER_INTERNAL snow3g_f9_1_buffer_internal_sse
%endif

mksection .rodata
default rel

align 16
snow3g_constant:
dq      0x000000000000001b, 0x0000000000000000

align 16
bswap64:
dq      0x0001020304050607, 0x08090a0b0c0d0e0f

mksection .text

%ifidn __OUTPUT_FORMAT__, win64
        %define XMM_STORAGE     16*6
        %define GP_STORAGE      8*5
%else
        %define XMM_STORAGE     0
        %define GP_STORAGE      3*8
%endif

%define VARIABLE_OFFSET XMM_STORAGE + GP_STORAGE
%define GP_OFFSET XMM_STORAGE

%macro FUNC_SAVE 0
        mov     r11, rsp
        sub     rsp, VARIABLE_OFFSET
        and     rsp, ~15

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        movdqa [rsp + 0*16], xmm6
        movdqa [rsp + 1*16], xmm7
        movdqa [rsp + 2*16], xmm8
        movdqa [rsp + 3*16], xmm13
        movdqa [rsp + 4*16], xmm14
        movdqa [rsp + 5*16], xmm15
        mov     [rsp + GP_OFFSET + 24], rdi
        mov     [rsp + GP_OFFSET + 32], rsi
%endif
        mov     [rsp + GP_OFFSET],      r12
        mov     [rsp + GP_OFFSET + 8],  r13
        mov     [rsp + GP_OFFSET + 16], r11 ;; rsp pointer
%endmacro

%macro FUNC_RESTORE 0

%ifidn __OUTPUT_FORMAT__, win64
        movdqa xmm6,  [rsp + 0*16]
        movdqa xmm7,  [rsp + 1*16]
        movdqa xmm8,  [rsp + 2*16]
        movdqa xmm13, [rsp + 3*16]
        movdqa xmm14, [rsp + 4*16]
        movdqa xmm15, [rsp + 5*16]
        mov     rdi, [rsp + GP_OFFSET + 24]
        mov     rsi, [rsp + GP_OFFSET + 32]
%endif
        mov     r12, [rsp + GP_OFFSET]
        mov     r13, [rsp + GP_OFFSET + 8]
        mov     rsp, [rsp + GP_OFFSET + 16]
%endmacro

;; Reduce from 128 bits to 64 bits
%macro REDUCE_TO_64 2
%define %%IN_OUT        %1 ;; [in/out]
%define %%XTMP          %2 ;; [clobbered]

        movdqa          %%XTMP, %%IN_OUT

        pclmulqdq       %%XTMP, SNOW3G_CONST, 0x01
        pxor            %%IN_OUT, %%XTMP

        pclmulqdq       %%XTMP, SNOW3G_CONST, 0x01
        pxor            %%IN_OUT, %%XTMP

%endmacro

;; Multiply 64b x 64b and reduce result to 64 bits
;; Lower 64-bits of xmms are multiplied
%macro MUL_AND_REDUCE_TO_64 2-3
%define %%IN0_OUT       %1 ;; [in/out]
%define %%IN1           %2 ;; [in] Note: clobbered when only 3 args passed
%define %%XTMP          %3 ;; [clobbered]

        pclmulqdq       %%IN0_OUT, %%IN1, 0x00
%if %0 == 2
        ;; clobber XTMP if 3 args passed, otherwise preserve
        REDUCE_TO_64 %%IN0_OUT, %%IN1
%else
        REDUCE_TO_64 %%IN0_OUT, %%XTMP
%endif
%endmacro

%macro simd_load_bswap_sse_8_1 3
%define %%DST       %1    ; [out] destination XMM register
%define %%SRC       %2    ; [in] pointer to src data
%define %%SIZE      %3    ; [in] length in bytes (1-8 bytes)

        pxor    %%DST, %%DST ; clear XMM register
        cmp     %%SIZE, 2
        jb      %%_size_1
        je      %%_size_2
        cmp     %%SIZE, 4
        jb      %%_size_3
        je      %%_size_4
        cmp     %%SIZE, 6
        jb      %%_size_5
        je      %%_size_6
        cmp     %%SIZE, 8
        jb      %%_size_7
        ;; fall through %%_size_8
        pinsrb  %%DST, [%%SRC + 7], 0
%%_size_7:
        pinsrb  %%DST, [%%SRC + 6], 1
%%_size_6:
        pinsrb  %%DST, [%%SRC + 5], 2
%%_size_5:
        pinsrb  %%DST, [%%SRC + 4], 3
%%_size_4:
        pinsrb  %%DST, [%%SRC + 3], 4
%%_size_3:
        pinsrb  %%DST, [%%SRC + 2], 5
%%_size_2:
        pinsrb  %%DST, [%%SRC + 1], 6
%%_size_1:
        pinsrb  %%DST, [%%SRC + 0], 7

%endm

; rax   [in]    number of constants to compute 4 or 8
; P1    [in]    xmm with the first hash key
; xmm0  [out]   P1|P2
; xmm1  [out]   P3|P4
; xmm13 [out]   P5|P6
; xmm14 [out]   P7|P8
; xmm4, xmm3 [clobbered]

align_function
calc_hkey_powers:
        cmp             rem_bytes, byte_len            ;; lenInBytes == remainingBytes
        jne             .return

        ;; Setup powers for 8-block parallel processing and
        ;; pack powers for parallel processing
        movdqa          xmm1, P1
        MUL_AND_REDUCE_TO_64 xmm1, P1, xmm4     ;; xmm1 = P2
        movdqa          xmm0, P1
        punpcklqdq      xmm0, xmm1              ;; xmm0 = P1|P2
        MUL_AND_REDUCE_TO_64 xmm1, P1, xmm4     ;; xmm1 = P3
        movdqa          xmm3, xmm1
        MUL_AND_REDUCE_TO_64 xmm3, P1, xmm4     ;; xmm3 = P4
        punpcklqdq      xmm1, xmm3              ;; xmm1 = P3|P4

        cmp             eax, 8
        jb              .return

        ;; Compute additional powers P5, P6, P7, P8
        MUL_AND_REDUCE_TO_64 xmm3, P1, xmm4     ;; xmm3 = P5
        movdqa          xmm13, xmm3
        MUL_AND_REDUCE_TO_64 xmm3, P1, xmm4     ;; xmm3 = P6
        punpcklqdq      xmm13, xmm3             ;; xmm13 = P5|P6
        MUL_AND_REDUCE_TO_64 xmm3, P1, xmm4     ;; xmm3 = P7
        movdqa          xmm14, xmm3
        MUL_AND_REDUCE_TO_64 xmm3, P1, xmm4     ;; xmm3 = P8
        punpcklqdq      xmm14, xmm3             ;; xmm14 = P7|P8

align_label
.return:
        ret

;; uint32_t
;; snow3g_f9_1_buffer_internal_sse(const uint64_t *pBufferIn,
;;                                 const uint32_t KS[5],
;;                                 const uint64_t lengthInBytes);
MKGLOBAL(SNOW3G_F9_1_BUFFER_INTERNAL,function,internal)
align_function
SNOW3G_F9_1_BUFFER_INTERNAL:
        endbranch64

        FUNC_SAVE

        movdqa  SNOW3G_CONST, [rel snow3g_constant]
        pxor    EV, EV

        ;; Preload bswap value for use later
        movdqa  xmm6, [rel bswap64]

        ;; P = ((uint64_t)KS[0] << 32) | ((uint64_t)KS[1])
        movq    P1, [KS]
        pshufd  P1, P1, 1110_0001b

        mov     rem_bytes, byte_len            ;; Initialize bytes counter

        cmp     rem_bytes, 8                   ;; less than one block?
        jb      .partial_blk
        je      .single_blk_chk

        cmp     rem_bytes, 8*8                 ;; check at least 8 qwords
        jb      .check_4_blocks

        mov     eax, 8
        call    calc_hkey_powers

align_loop
.start_8_blk_loop:
        ;; Load all 8 blocks (64 bytes total)
        movdqu          xmm3, [in_ptr + 0*16]           ;; blocks 1,2
        movdqu          xmm4, [in_ptr + 1*16]           ;; blocks 3,4
        movdqu          xmm5, [in_ptr + 2*16]           ;; blocks 5,6
        movdqu          xmm15, [in_ptr + 3*16]          ;; blocks 7,8

        ;; Byte swap all 8 blocks
        pshufb          xmm3, xmm6                       ;; swap blocks 1,2
        pshufb          xmm4, xmm6                       ;; swap blocks 3,4
        pshufb          xmm5, xmm6                       ;; swap blocks 5,6
        pshufb          xmm15, xmm6                      ;; swap blocks 7,8

        ;; XOR first block with EV
        pxor            xmm3, EV                         ;; block1 XOR EV, block2 unchanged

        ;; Process blocks 1,2 with powers P8,P7
        movdqa          xmm2, xmm3
        pclmulqdq       xmm2, xmm14, 0x10               ;; block1 * P8
        pclmulqdq       xmm3, xmm14, 0x01               ;; block2 * P7
        pxor            xmm2, xmm3                       ;; combine results

        ;; Process blocks 3,4 with powers P6,P5
        movdqa          xmm3, xmm4
        pclmulqdq       xmm3, xmm13, 0x10               ;; block3 * P6
        pclmulqdq       xmm4, xmm13, 0x01               ;; block4 * P5
        pxor            xmm3, xmm4                       ;; combine results
        pxor            xmm2, xmm3                       ;; accumulate

        ;; Process blocks 5,6 with powers P4,P3
        movdqa          xmm3, xmm5
        pclmulqdq       xmm3, xmm1, 0x10                ;; block5 * P4
        pclmulqdq       xmm5, xmm1, 0x01                ;; block6 * P3
        pxor            xmm3, xmm5                       ;; combine results
        pxor            xmm2, xmm3                       ;; accumulate

        ;; Process blocks 7,8 with powers P2,P1
        movdqa          xmm3, xmm15
        pclmulqdq       xmm3, xmm0, 0x10                ;; block7 * P2
        pclmulqdq       xmm15, xmm0, 0x01               ;; block8 * P1
        pxor            xmm3, xmm15                      ;; combine results
        pxor            xmm2, xmm3                       ;; accumulate with previous results
        movdqa          EV, xmm2                         ;; final result

        REDUCE_TO_64    EV, xmm3                         ;; EV = reduce128_to_64(result);
        movq            EV, EV                           ;; clear high 64 bits

        add             in_ptr, 8*8                     ;; move to next 8 8-byte blocks
        sub             rem_bytes, 8*8
        cmp             rem_bytes, 8*8
        jae             .start_8_blk_loop                ;; process next 8 blocks

align_label
.check_4_blocks:
        cmp             rem_bytes, 4*8                  ;; check if any 4-block groups left
        jb              .single_blk_chk

        mov             eax, 4
        call            calc_hkey_powers

        ;; Load all 4 blocks (32 bytes total)
        movdqu          xmm3, [in_ptr + 0*16]           ;; blocks 1,2
        movdqu          xmm4, [in_ptr + 1*16]           ;; blocks 3,4

        ;; Byte swap all 4 blocks
        pshufb          xmm3, xmm6                       ;; swap blocks 1,2
        pshufb          xmm4, xmm6                       ;; swap blocks 3,4

        ;; XOR first block with EV
        pxor            xmm3, EV                         ;; block1 XOR EV, block2 unchanged

        ;; Process blocks 1,2 with powers P8,P7
        movdqa          xmm2, xmm3
        pclmulqdq       xmm2, xmm1, 0x10                 ;; block1 * P4
        pclmulqdq       xmm3, xmm1, 0x01                 ;; block2 * P3
        pxor            xmm2, xmm3                       ;; combine results

        ;; Process blocks 3,4 with powers P6,P5
        movdqa          xmm3, xmm4
        pclmulqdq       xmm3, xmm0, 0x10                 ;; block3 * P2
        pclmulqdq       xmm4, xmm0, 0x01                 ;; block4 * P1
        pxor            xmm3, xmm4                       ;; combine results
        pxor            xmm2, xmm3                       ;; accumulate

        movdqa          EV, xmm2                         ;; final result

        REDUCE_TO_64    EV, xmm3                         ;; EV = reduce128_to_64(result);
        movq            EV, EV                           ;; clear high 64 bits

        add             in_ptr, 4*8             ;; move to the next 4 blocks
        sub             rem_bytes, 4*8

align_loop
.single_blk_chk:
        cmp             rem_bytes, 8
        jb              .partial_blk

        ;; full block still available
        movq            xmm0, [in_ptr]
        pshufb          xmm0, xmm6

        pxor            EV, xmm0
        MUL_AND_REDUCE_TO_64 EV, P1, xmm1

        add             in_ptr, 8
        sub             rem_bytes, 8
        jmp             .single_blk_chk

        ;; partial block
align_label
.partial_blk:
        or              rem_bytes, rem_bytes
        jz              .skip_rem_bytes

        ;; load last 7 to 1 bytes
        ;; loaded bytes land in the top of the register and the rest is zeroed,
        ;; which is what the digest expects for a partial block
        simd_load_bswap_sse_8_1 xmm3, in_ptr, rem_bytes

        pxor            EV, xmm3
        MUL_AND_REDUCE_TO_64 EV, P1, xmm1

align_label
.skip_rem_bytes:
        ;; /* Multiply by Q */
        ;; E = multiply_and_reduce64(E ^ lengthInBits,
        ;;                           (((uint64_t)z[2] << 32) | ((uint64_t)z[3])));
        ;; /* Final MAC */
        ;; *(uint32_t *)pDigest =
        ;;        (uint32_t)BSWAP64(E ^ ((uint64_t)z[4] << 32));
        movq    xmm3, byte_len
        psllq   xmm3, 3                         ;; the digest is taken over the bit length
        pxor    EV, xmm3

        movq    xmm1, [KS + 8]                  ;; load z[2:3]
        pshufd  xmm1, xmm1, 1110_0001b

        mov     DWORD(tmp4), [KS + (4 * 4)]     ;; tmp4 == z[4] << 32
        shl     tmp4, 32

        MUL_AND_REDUCE_TO_64 EV, xmm1, xmm3
        movq    E, EV

        xor     E, tmp4

        bswap   E                               ;; return E (rax/eax)

        FUNC_RESTORE

        ret

mksection stack-noexec
