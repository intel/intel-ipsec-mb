;;
;; Copyright (c) 2011-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; Authors of original CRC implementation:
;;     Erdinc Ozturk
;;     Vinodh Gopal
;;     James Guilford

%include "include/os.inc"
%include "include/memcpy.inc"
%include "include/reg_sizes.inc"
%include "include/crc32_refl.inc"
%include "include/clear_regs.inc"
%include "include/align_avx.inc"

[bits 64]
default rel

%ifdef LINUX
%define arg1            rdi       ; init_crc
%define arg2            rsi       ; msg pointer
%define arg3            rdx       ; msg_len
%define arg4            rcx       ; const pointer
%else
%define arg1            rcx       ; init_crc
%define arg2            rdx       ; msg pointer
%define arg3            r8        ; msg_len
%define arg4            r9        ; const pointer
%endif

%define msg_ptr      arg2
%define msg_len      arg3
%define const_ptr    arg4
%define init_crc     DWORD(arg1)

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generic reflected CRC-32 using VPCLMULQDQ polynomial folding.
;; Processes 256 bytes per iteration on the fast path; scalar fallback
;; handles any residual length down to 1 byte.
;;
;; arg1 (init_crc)  - initial CRC value
;; arg2 (msg_ptr)   - pointer to input message
;; arg3 (msg_len)   - message length in bytes
;; arg4 (const_ptr) - pointer to precomputed polynomial fold constants
;;                    in CRC_FOLD_CONSTANTS struc layout (see crc32_refl.inc)
;;
;; Returns: raw CRC result in EAX (no XorOut applied)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(crc32_refl_vclmul_avx2, function, internal)
crc32_refl_vclmul_avx2:
%ifndef LINUX
        sub             rsp, 16*8
        vmovdqu         [rsp + 16*0], xmm6
        vmovdqu         [rsp + 16*1], xmm7
        vmovdqu         [rsp + 16*2], xmm8
        vmovdqu         [rsp + 16*3], xmm9
        vmovdqu         [rsp + 16*4], xmm10
        vmovdqu         [rsp + 16*5], xmm11
        vmovdqu         [rsp + 16*6], xmm12
        vmovdqu         [rsp + 16*7], xmm15
%endif

        cmp             msg_len, 256
        jb              ._less_than_256

        ;; --- fast path: >= 256 bytes ---
        ;; Load first 256B into ymm0-3 (4 x 2 lanes), XOR init_crc into lane 0.
        vmovd           xmm10, init_crc

        vmovdqu         ymm0, [msg_ptr + 16*0]
        vmovdqu         ymm1, [msg_ptr + 16*2]
        vmovdqu         ymm2, [msg_ptr + 16*4]
        vmovdqu         ymm3, [msg_ptr + 16*6]

        vpxor           ymm0, ymm10

        vbroadcasti128  ymm10, [const_ptr + crc32_const_fold_8x128b]

        sub             msg_len, 256
        cmp             msg_len, 256
        jb              ._fold_128_B_loop

        ;; >= 512B remaining: load another 256B into ymm8,9,11,12 and
        ;; use fold-by-16x128b constants to halve register pressure.
        vmovdqu         ymm8, [msg_ptr + 16*8]
        vmovdqu         ymm9, [msg_ptr + 16*10]
        vmovdqu         ymm11, [msg_ptr + 16*12]
        vmovdqu         ymm12, [msg_ptr + 16*14]

        vbroadcasti128  ymm15, [const_ptr + crc32_const_fold_16x128b]
        sub             msg_len, 256

align_loop
._fold_256_B_loop:
        ;; Fold 8 YMM pairs (512B) per iteration using fold-by-16x128b.
        add             msg_ptr, 256
        vpclmulqdq      ymm4, ymm0, ymm15, 0x10
        vpclmulqdq      ymm0, ymm0, ymm15, 0x01
        vpxor           ymm0, [msg_ptr + 16*0]
        vpxor           ymm0, ymm4

        vpclmulqdq      ymm5, ymm1, ymm15, 0x10
        vpclmulqdq      ymm1, ymm1, ymm15, 0x01
        vpxor           ymm1, [msg_ptr + 16*2]
        vpxor           ymm1, ymm5

        vpclmulqdq      ymm4, ymm2, ymm15, 0x10
        vpclmulqdq      ymm2, ymm2, ymm15, 0x01
        vpxor           ymm2, [msg_ptr + 16*4]
        vpxor           ymm2, ymm4

        vpclmulqdq      ymm5, ymm3, ymm15, 0x10
        vpclmulqdq      ymm3, ymm3, ymm15, 0x01
        vpxor           ymm3, [msg_ptr + 16*6]
        vpxor           ymm3, ymm5

        vpclmulqdq      ymm6, ymm8, ymm15, 0x10
        vpclmulqdq      ymm8, ymm8, ymm15, 0x01
        vpxor           ymm8, [msg_ptr + 16*8]
        vpxor           ymm8, ymm6

        vpclmulqdq      ymm7, ymm9, ymm15, 0x10
        vpclmulqdq      ymm9, ymm9, ymm15, 0x01
        vpxor           ymm9, [msg_ptr + 16*10]
        vpxor           ymm9, ymm7

        vpclmulqdq      ymm6, ymm11, ymm15, 0x10
        vpclmulqdq      ymm11, ymm11, ymm15, 0x01
        vpxor           ymm11, [msg_ptr + 16*12]
        vpxor           ymm11, ymm6

        vpclmulqdq      ymm7, ymm12, ymm15, 0x10
        vpclmulqdq      ymm12, ymm12, ymm15, 0x01
        vpxor           ymm12, [msg_ptr + 16*14]
        vpxor           ymm12, ymm7

        sub             msg_len, 256
        jge             ._fold_256_B_loop

        ;; Merge ymm8,9,11,12 into ymm0-3 using fold-by-8x128b, then
        ;; fall through to fold the remaining < 512B.
        add             msg_ptr, 128
        vpclmulqdq      ymm4, ymm0, ymm10, 0x10
        vpclmulqdq      ymm0, ymm0, ymm10, 0x01
        vpxor           ymm0, ymm4
        vpxor           ymm0, ymm8

        vpclmulqdq      ymm5, ymm1, ymm10, 0x10
        vpclmulqdq      ymm1, ymm1, ymm10, 0x01
        vpxor           ymm1, ymm5
        vpxor           ymm1, ymm9

        vpclmulqdq      ymm4, ymm2, ymm10, 0x10
        vpclmulqdq      ymm2, ymm2, ymm10, 0x01
        vpxor           ymm2, ymm4
        vpxor           ymm2, ymm11

        vpclmulqdq      ymm5, ymm3, ymm10, 0x10
        vpclmulqdq      ymm3, ymm3, ymm10, 0x01
        vpxor           ymm3, ymm5
        vpxor           ymm3, ymm12

        add             msg_len, 128
        cmp             msg_len, 128
        jl              ._fold_less_than_128_B  ; msg_len may be negative after sub loop

align_loop
._fold_128_B_loop:
        ;; Fold 4 YMM registers (256B) per iteration using fold-by-8x128b.
        add             msg_ptr, 128
        vpclmulqdq      ymm4, ymm0, ymm10, 0x10
        vpclmulqdq      ymm0, ymm0, ymm10, 0x1
        vpxor           ymm0, [msg_ptr + 16*0]
        vpxor           ymm0, ymm4

        vpclmulqdq      ymm5, ymm1, ymm10, 0x10
        vpclmulqdq      ymm1, ymm1, ymm10, 0x1
        vpxor           ymm1, [msg_ptr + 16*2]
        vpxor           ymm1, ymm5

        vpclmulqdq      ymm4, ymm2, ymm10, 0x10
        vpclmulqdq      ymm2, ymm2, ymm10, 0x1
        vpxor           ymm2, [msg_ptr + 16*4]
        vpxor           ymm2, ymm4

        vpclmulqdq      ymm5, ymm3, ymm10, 0x10
        vpclmulqdq      ymm3, ymm3, ymm10, 0x1
        vpxor           ymm3, [msg_ptr + 16*6]
        vpxor           ymm3, ymm5

        sub             msg_len, 128
        jge             ._fold_128_B_loop

align_label
._fold_less_than_128_B:
        ;; Reduce ymm0-3 down to a single XMM. Extract the upper lane of ymm3
        ;; into xmm7 (the running accumulator), then fold ymm0-2 and xmm3 into
        ;; ymm11 using per-distance constants, and merge with xmm7.
        add             msg_ptr, 128

        vextracti128    xmm7, ymm3, 1

        vmovdqu         ymm10, [const_ptr + crc32_const_fold_7x128b]
        vpclmulqdq      ymm4, ymm0, ymm10, 0x01
        vpclmulqdq      ymm11, ymm0, ymm10, 0x10
        vpxor           ymm11, ymm4

        vmovdqu         ymm10, [const_ptr + crc32_const_fold_5x128b]
        vpclmulqdq      ymm4, ymm1, ymm10, 0x01
        vpclmulqdq      ymm5, ymm1, ymm10, 0x10
        vpxor           ymm11, ymm4
        vpxor           ymm11, ymm5

        vmovdqu         ymm10, [const_ptr + crc32_const_fold_3x128b]
        vpclmulqdq      ymm4, ymm2, ymm10, 0x01
        vpclmulqdq      ymm5, ymm2, ymm10, 0x10
        vpxor           ymm11, ymm4
        vpxor           ymm11, ymm5

        vmovdqa         xmm10, [const_ptr + crc32_const_fold_1x128b]
        vpclmulqdq      xmm4, xmm3, xmm10, 0x01
        vpclmulqdq      xmm5, xmm3, xmm10, 0x10
        vpxor           ymm11, ymm4
        vpxor           ymm11, ymm5

        vextracti128    xmm4, ymm11, 1
        vpxor           xmm7, xmm4
        vpxor           xmm7, xmm11

        add             msg_len, 128 - 16
        jl              ._final_reduction_for_128  ; msg_len may be negative

align_loop
._16B_reduction_loop:
        ;; Fold one 16B block at a time into xmm7.
        vpclmulqdq      xmm8, xmm7, xmm10, 0x1
        vpclmulqdq      xmm7, xmm7, xmm10, 0x10
        vpxor           xmm7, xmm8
        vmovdqu         xmm0, [msg_ptr]
        vpxor           xmm7, xmm0
        add             msg_ptr, 16
        sub             msg_len, 16
        jge             ._16B_reduction_loop

align_label
._final_reduction_for_128:
        add             msg_len, 16
        je              ._128_done

align_label
._get_last_two_xmms:
        ;; Handle the final < 16B tail via an overlapping 16B load +
        ;; PSHUFB-based shift to blend residual bytes into xmm7.
        vmovdqa         xmm2, xmm7
        vmovdqu         xmm1, [msg_ptr - 16 + msg_len]

        lea             rax, [rel shf_table_refl]
        vmovdqu         xmm0, [rax + msg_len]

        vpshufb         xmm7, xmm0
        vpxor           xmm0, [rel shf_xor_mask]
        vpshufb         xmm2, xmm0

        vpblendvb       xmm2, xmm2, xmm1, xmm0

        vpclmulqdq      xmm8, xmm7, xmm10, 0x1
        vpclmulqdq      xmm7, xmm7, xmm10, 0x10
        vpxor           xmm7, xmm8
        vpxor           xmm7, xmm2

align_label
._128_done:
        ;; Fold 128 bits down to 64 bits.
        vmovdqa         xmm10, [const_ptr + crc32_const_fold_128b_to_64b]
        vmovdqa         xmm0, xmm7

        vpclmulqdq      xmm7, xmm10, 0
        vpsrldq         xmm0, 8
        vpxor           xmm7, xmm0

        vmovdqa         xmm0, xmm7
        vpslldq         xmm7, 4
        vpclmulqdq      xmm7, xmm10, 0x10
        vpxor           xmm7, xmm0

align_label
._barrett:
        ;; Barrett reduction: fold 64 bits down to 32 bits and extract result.
        vpand           xmm7, [rel lo32_clr_mask]
        vmovdqa         xmm1, xmm7
        vmovdqa         xmm2, xmm7
        vmovdqa         xmm10, [const_ptr + crc32_const_reduce_64b_to_32b]

        vpclmulqdq      xmm7, xmm10, 0
        vpxor           xmm7, xmm2
        vpand           xmm7, [rel hi64_mask]
        vmovdqa         xmm2, xmm7
        vpclmulqdq      xmm7, xmm10, 0x10
        vpxor           xmm7, xmm2
        vpxor           xmm7, xmm1
        vpextrd         eax, xmm7, 2

align_label
._cleanup:
%ifdef SAFE_DATA
        clear_scratch_ymms_asm
%else
        vzeroupper
%endif

%ifndef LINUX
        vmovdqu         xmm6,  [rsp + 16*0]
        vmovdqu         xmm7,  [rsp + 16*1]
        vmovdqu         xmm8,  [rsp + 16*2]
        vmovdqu         xmm9,  [rsp + 16*3]
        vmovdqu         xmm10, [rsp + 16*4]
        vmovdqu         xmm11, [rsp + 16*5]
        vmovdqu         xmm12, [rsp + 16*6]
        vmovdqu         xmm15, [rsp + 16*7]
        add             rsp, 16*8
%endif
        ret

align_label
._less_than_256:
        ;; Slow path: < 256 bytes. Use XMM-only folding.
        cmp             msg_len, 32
        jb              ._less_than_32

        vmovdqa         xmm10, [const_ptr + crc32_const_fold_1x128b]

        vmovd           xmm0, init_crc
        vmovdqu         xmm7, [msg_ptr]
        vpxor           xmm7, xmm0

        add             msg_ptr, 16
        sub             msg_len, 32
        jmp             ._16B_reduction_loop

align_label
._less_than_32:
        mov             eax, init_crc
        test            msg_len, msg_len
        je              ._cleanup

        vmovd           xmm0, init_crc

        cmp             msg_len, 16
        je              ._exact_16_left
        jb              ._less_than_16_left

        vmovdqu         xmm7, [msg_ptr]
        vpxor           xmm7, xmm0
        add             msg_ptr, 16
        sub             msg_len, 16
        vmovdqa         xmm10, [const_ptr + crc32_const_fold_1x128b]
        jmp             ._get_last_two_xmms

align_label
._exact_16_left:
        vmovdqu         xmm7, [msg_ptr]
        vpxor           xmm7, xmm0
        jmp             ._128_done

align_label
._less_than_16_left:
        simd_load_avx_15_1 xmm7, msg_ptr, msg_len
        vpxor           xmm7, xmm0

        cmp             msg_len, 4
        jb              ._only_less_than_4

        lea             rax, [rel shf_table_refl]
        vmovdqu         xmm0, [rax + msg_len]
        vpshufb         xmm7, xmm0
        jmp             ._128_done

align_label
._only_less_than_4:
        lea             rax, [rel tail_shuf_refl]
        vmovdqu         xmm0, [rax + msg_len]
        vpshufb         xmm7, xmm0
        jmp             ._barrett


mksection .rodata

lo32_clr_mask: dq 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF

align 16
hi64_mask:
        dq 0xFFFFFFFFFFFFFFFF, 0x0000000000000000

align 16
shf_table_refl:
        dq 0x8786858483828100, 0x8f8e8d8c8b8a8988
        dq 0x0706050403020100, 0x000e0d0c0b0a0908

align 16
shf_xor_mask:
        dq 0x8080808080808080, 0x8080808080808080

;; pshufb masks for shifting 1-3 bytes into Barrett position;
;; accessed as [tail_shuf_refl + msg_len] for msg_len in {1, 2, 3}
tail_shuf_refl:
        db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
        db 0x08, 0x09, 0x0A

mksection stack-noexec
