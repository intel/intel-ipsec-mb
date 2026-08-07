;;
;; Copyright (c) 2011-2026, Intel Corporation
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

;; Authors of original CRC implementation:
;;     Erdinc Ozturk
;;     Vinodh Gopal
;;     James Guilford

%include "include/os.inc"
%include "include/memcpy.inc"
%include "include/reg_sizes.inc"
%include "include/crc32.inc"
%include "include/clear_regs.inc"
%include "include/align_avx.inc"

[bits 64]
default rel

%ifdef LINUX
%define arg1            rdi       ; init_crc (eax/rax)
%define arg2            rsi       ; msg pointer
%define arg3            rdx       ; msg_len
%define arg4            rcx       ; const pointer
%else
%define arg1            rcx       ; init_crc
%define arg2            rdx       ; msg pointer
%define arg3            r8        ; msg_len
%define arg4            r9        ; const pointer
%endif

%define init_crc        arg1
%define msg_ptr         arg2
%define msg_len         arg3
%define const_ptr       arg4
%define msg_ptr_64      arg2
%define msg_len_64      arg3
%define const_ptr_64    arg4
%define init_crc_32     DWORD(arg1)

struc STACK_FRAME
_xmm_save:      resq    8 * 2
_rsp_save:      resq    1
endstruc

mksection .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generic CRC-32 (non-reflected) using VPCLMULQDQ polynomial folding.
;; Processes 256 bytes per iteration on the fast path; scalar fallback
;; handles any residual length down to 1 byte.
;;
;; arg1 (init_crc)  - initial CRC value, typically 0xFFFFFFFF
;; arg2 (msg_ptr)   - pointer to input message
;; arg3 (msg_len)   - message length in bytes
;; arg4 (const_ptr) - pointer to precomputed polynomial fold constants
;;                    in CRC32_CONSTANTS struc layout (see crc32.inc)
;;
;; Returns: CRC-32 result in EAX (with final NOT applied)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(crc32_vclmul_avx2, function, internal)
crc32_vclmul_avx2:
        ; r10 holds the const pointer
        mov             r10, const_ptr_64
        mov             eax, init_crc_32

        cmp             msg_len_64, 256
        jb              ._less_than_256

        ;; --- fast path: >= 256 bytes ---
        ;; Load first 256B into ymm0-3 (4 x 2 lanes), byte-swap to big-endian,
        ;; XOR init_crc into the MSB of the first lane.
        vmovd           xmm10, eax
        vpslldq         xmm10, 12
        vbroadcasti128  ymm11, [rel bswap_shuf_mask]

        vmovdqu         ymm0, [msg_ptr_64 + 16*0]
        vmovdqu         ymm1, [msg_ptr_64 + 16*2]
        vmovdqu         ymm2, [msg_ptr_64 + 16*4]
        vmovdqu         ymm3, [msg_ptr_64 + 16*6]

        vpshufb         ymm0, ymm11
        vpxor           ymm0, ymm10
        vpshufb         ymm1, ymm11
        vpshufb         ymm2, ymm11
        vpshufb         ymm3, ymm11

        vbroadcasti128  ymm10, [r10 + crc32_const_fold_8x128b]

        sub             msg_len_64, 256
        cmp             msg_len_64, 256
        jb              ._fold_128_B_loop

        ;; >= 512B remaining: load another 256B into ymm8,9,12,13 and
        ;; use fold-by-16x128b constants to halve register pressure.

        vmovdqu         ymm8, [msg_ptr_64 + 16*8]
        vmovdqu         ymm9, [msg_ptr_64 + 16*10]
        vmovdqu         ymm12, [msg_ptr_64 + 16*12]
        vmovdqu         ymm13, [msg_ptr_64 + 16*14]

        vpshufb         ymm8, ymm11
        vpshufb         ymm9, ymm11
        vpshufb         ymm12, ymm11
        vpshufb         ymm13, ymm11

        vbroadcasti128  ymm15, [r10 + crc32_const_fold_16x128b]
        sub             msg_len_64, 256

align_loop
._fold_256_B_loop:
        ;; Fold 8 YMM pairs (512B) per iteration using fold-by-16x128b.
        add             msg_ptr_64, 256

        vmovdqu         ymm14, [msg_ptr_64 + 16*0]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm4, ymm0, ymm15, 0x0
        vpclmulqdq      ymm0, ymm0, ymm15, 0x11
        vpxor           ymm0, ymm14
        vpxor           ymm0, ymm4

        vmovdqu         ymm14, [msg_ptr_64 + 16*2]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm5, ymm1, ymm15, 0x0
        vpclmulqdq      ymm1, ymm1, ymm15, 0x11
        vpxor           ymm1, ymm14
        vpxor           ymm1, ymm5

        vmovdqu         ymm14, [msg_ptr_64 + 16*4]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm4, ymm2, ymm15, 0x0
        vpclmulqdq      ymm2, ymm2, ymm15, 0x11
        vpxor           ymm2, ymm14
        vpxor           ymm2, ymm4

        vmovdqu         ymm14, [msg_ptr_64 + 16*6]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm5, ymm3, ymm15, 0x0
        vpclmulqdq      ymm3, ymm3, ymm15, 0x11
        vpxor           ymm3, ymm14
        vpxor           ymm3, ymm5

        vmovdqu         ymm14, [msg_ptr_64 + 16*8]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm6, ymm8, ymm15, 0x0
        vpclmulqdq      ymm8, ymm8, ymm15, 0x11
        vpxor           ymm8, ymm14
        vpxor           ymm8, ymm6

        vmovdqu         ymm14, [msg_ptr_64 + 16*10]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm7, ymm9, ymm15, 0x0
        vpclmulqdq      ymm9, ymm9, ymm15, 0x11
        vpxor           ymm9, ymm14
        vpxor           ymm9, ymm7

        vmovdqu         ymm14, [msg_ptr_64 + 16*12]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm6, ymm12, ymm15, 0x0
        vpclmulqdq      ymm12, ymm12, ymm15, 0x11
        vpxor           ymm12, ymm14
        vpxor           ymm12, ymm6

        vmovdqu         ymm14, [msg_ptr_64 + 16*14]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm7, ymm13, ymm15, 0x0
        vpclmulqdq      ymm13, ymm13, ymm15, 0x11
        vpxor           ymm13, ymm14
        vpxor           ymm13, ymm7

        sub             msg_len_64, 256
        jge             ._fold_256_B_loop

        ;; Merge ymm8,9,12,13 into ymm0-3 using fold-by-8x128b, then
        ;; fall through to fold the remaining < 512B.
        add             msg_ptr_64, 128
        vpclmulqdq      ymm4, ymm0, ymm10, 0x0
        vpclmulqdq      ymm0, ymm0, ymm10, 0x11
        vpxor           ymm0, ymm4
        vpxor           ymm0, ymm8

        vpclmulqdq      ymm5, ymm1, ymm10, 0x0
        vpclmulqdq      ymm1, ymm1, ymm10, 0x11
        vpxor           ymm1, ymm5
        vpxor           ymm1, ymm9

        vpclmulqdq      ymm4, ymm2, ymm10, 0x0
        vpclmulqdq      ymm2, ymm2, ymm10, 0x11
        vpxor           ymm2, ymm4
        vpxor           ymm2, ymm12

        vpclmulqdq      ymm5, ymm3, ymm10, 0x0
        vpclmulqdq      ymm3, ymm3, ymm10, 0x11
        vpxor           ymm3, ymm5
        vpxor           ymm3, ymm13

        add             msg_len_64, 128
        cmp             msg_len_64, 128
        jl              ._fold_less_than_128_B

align_loop
._fold_128_B_loop:
        ;; Fold 4 YMM registers (256B) per iteration using fold-by-8x128b.
        add             msg_ptr_64, 128

        vmovdqu         ymm14, [msg_ptr_64 + 16*0]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm4, ymm0, ymm10, 0x0
        vpclmulqdq      ymm0, ymm0, ymm10, 0x11
        vpxor           ymm0, ymm14
        vpxor           ymm0, ymm4

        vmovdqu         ymm14, [msg_ptr_64 + 16*2]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm5, ymm1, ymm10, 0x0
        vpclmulqdq      ymm1, ymm1, ymm10, 0x11
        vpxor           ymm1, ymm14
        vpxor           ymm1, ymm5

        vmovdqu         ymm14, [msg_ptr_64 + 16*4]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm4, ymm2, ymm10, 0x0
        vpclmulqdq      ymm2, ymm2, ymm10, 0x11
        vpxor           ymm2, ymm14
        vpxor           ymm2, ymm4

        vmovdqu         ymm14, [msg_ptr_64 + 16*6]
        vpshufb         ymm14, ymm11
        vpclmulqdq      ymm5, ymm3, ymm10, 0x0
        vpclmulqdq      ymm3, ymm3, ymm10, 0x11
        vpxor           ymm3, ymm14
        vpxor           ymm3, ymm5

        sub             msg_len_64, 128
        jge             ._fold_128_B_loop

align_label
._fold_less_than_128_B:
        ;; Reduce ymm0-3 down to a single XMM. Extract the upper lane of ymm3
        ;; into xmm7 (the running accumulator), then fold ymm0-2 and xmm3 into
        ;; ymm12 using per-distance constants, and merge with xmm7.
        add             msg_ptr_64, 128

        vextracti128    xmm7, ymm3, 1

        vmovdqu         ymm10, [r10 + crc32_const_fold_7x128b]  ; lo=fold_7, hi=fold_6 for ymm0 lanes
        vpclmulqdq      ymm4, ymm0, ymm10, 0x0
        vpclmulqdq      ymm12, ymm0, ymm10, 0x11
        vpxor           ymm12, ymm4

        vmovdqu         ymm10, [r10 + crc32_const_fold_5x128b]  ; lo=fold_5, hi=fold_4 for ymm1 lanes
        vpclmulqdq      ymm4, ymm1, ymm10, 0x0
        vpclmulqdq      ymm5, ymm1, ymm10, 0x11
        vpxor           ymm12, ymm4
        vpxor           ymm12, ymm5

        vmovdqu         ymm10, [r10 + crc32_const_fold_3x128b]  ; lo=fold_3, hi=fold_2 for ymm2 lanes
        vpclmulqdq      ymm4, ymm2, ymm10, 0x0
        vpclmulqdq      ymm5, ymm2, ymm10, 0x11
        vpxor           ymm12, ymm4
        vpxor           ymm12, ymm5

        vmovdqa         xmm10, [r10 + crc32_const_fold_1x128b]
        vpclmulqdq      xmm4, xmm3, xmm10, 0x0
        vpclmulqdq      xmm5, xmm3, xmm10, 0x11
        vpxor           ymm12, ymm4
        vpxor           ymm12, ymm5

        vextracti128    xmm4, ymm12, 1
        vpxor           xmm7, xmm4
        vpxor           xmm7, xmm12

        add             msg_len_64, 128 - 16
        jl              ._final_reduction_for_128

align_loop
._16B_reduction_loop:
        ;; Fold one 16B block at a time into xmm7.
        vmovdqa         xmm8, xmm7
        vpclmulqdq      xmm7, xmm10, 0x11
        vpclmulqdq      xmm8, xmm10, 0x0
        vpxor           xmm7, xmm8
        vmovdqu         xmm0, [msg_ptr_64]
        vpshufb         xmm0, xmm11
        vpxor           xmm7, xmm0
        add             msg_ptr_64, 16
        sub             msg_len_64, 16
        jge             ._16B_reduction_loop

align_label
._final_reduction_for_128:
        add             msg_len_64, 16
        je              ._128_done

align_label
._get_last_two_xmms:
        ;; Handle the final < 16B tail via an overlapping 16B load +
        ;; PSHUFB-based shift to blend residual bytes into xmm7.
        vmovdqa         xmm2, xmm7

        vmovdqu         xmm1, [msg_ptr_64 - 16 + msg_len_64]
        vpshufb         xmm1, xmm11

        lea             rax, [rel pshufb_shf_table + 16]
        sub             rax, msg_len_64
        vmovdqu         xmm0, [rax]

        vpshufb         xmm2, xmm0
        vpxor           xmm0, [rel mask1]
        vpshufb         xmm7, xmm0
        vpblendvb       xmm1, xmm1, xmm2, xmm0

        vmovdqa         xmm2, xmm1
        vmovdqa         xmm8, xmm7
        vpclmulqdq      xmm7, xmm10, 0x11
        vpclmulqdq      xmm8, xmm10, 0x0
        vpxor           xmm7, xmm8
        vpxor           xmm7, xmm2

align_label
._128_done:
        ;; Fold 128 bits down to 64 bits.
        vmovdqa         xmm10, [r10 + crc32_const_fold_128b_to_64b]
        vmovdqa         xmm0, xmm7

        vpclmulqdq      xmm7, xmm10, 0x1
        vpslldq         xmm0, 8
        vpxor           xmm7, xmm0

        vmovdqa         xmm0, xmm7
        vpand           xmm0, [rel mask2]
        vpsrldq         xmm7, 12
        vpclmulqdq      xmm7, xmm10, 0x10
        vpxor           xmm7, xmm0

align_label
._barrett:
        ;; Barrett reduction: fold 64 bits down to 32 bits and extract result.
        vmovdqa         xmm10, [r10 + crc32_const_reduce_64b_to_32b]
        vmovdqa         xmm0, xmm7
        vpclmulqdq      xmm7, xmm10, 0x01
        vpslldq         xmm7, 4
        vpclmulqdq      xmm7, xmm10, 0x11
        vpslldq         xmm7, 4
        vpxor           xmm7, xmm0
        vpextrd         eax, xmm7, 1

align_label
._cleanup:
        ret

align_label
._less_than_256:
        ;; Slow path: < 256 bytes. Use XMM-only folding.
        cmp             msg_len_64, 32
        jb              ._less_than_32
        vmovdqa         xmm11, [rel bswap_shuf_mask]

        vmovdqa         xmm10, [r10 + crc32_const_fold_1x128b]
        mov             ecx, init_crc_32        ; ecx = init value
        vmovd           xmm0, ecx                  ; move from ecx to xmm0
        vpslldq         xmm0, 12
        vmovdqu         xmm7, [msg_ptr_64]
        vpshufb         xmm7, xmm11
        vpxor           xmm7, xmm0

        add             msg_ptr_64, 16
        sub             msg_len_64, 32
        jmp             ._16B_reduction_loop

align_label
._less_than_32:
        mov             eax, init_crc_32
        test            msg_len_64, msg_len_64
        je              ._cleanup

        vmovdqa         xmm11, [rel bswap_shuf_mask]
        mov             ecx, init_crc_32        ; ecx = init value
        vmovd           xmm0, ecx                  ; move from ecx to xmm0
        vpslldq         xmm0, 12

        cmp             msg_len_64, 16
        je              ._exact_16_left
        jb              ._less_than_16_left

        vmovdqu         xmm7, [msg_ptr_64]
        vpshufb         xmm7, xmm11
        vpxor           xmm7, xmm0
        add             msg_ptr_64, 16
        sub             msg_len_64, 16
        vmovdqa         xmm10, [r10 + crc32_const_fold_1x128b]
        jmp             ._get_last_two_xmms

align_label
._exact_16_left:
        vmovdqu         xmm7, [msg_ptr_64]
        vpshufb         xmm7, xmm11
        vpxor           xmm7, xmm0
        jmp             ._128_done

align_label
._less_than_16_left:
        simd_load_avx_15_1 xmm7, msg_ptr_64, msg_len_64
        vpshufb         xmm7, xmm11
        vpxor           xmm7, xmm0

        cmp             msg_len_64, 4
        jb              ._only_less_than_4

        lea             rax, [rel pshufb_shf_table + 16]
        sub             rax, msg_len_64
        vmovdqu         xmm0, [rax]
        vpxor           xmm0, [rel mask1]
        vpshufb         xmm7, xmm0
        jmp             ._128_done

align_label
._only_less_than_4:
        cmp             msg_len_64, 3
        jb              ._only_less_than_3
        vpsrldq         xmm7, 5
        jmp             ._barrett

align_label
._only_less_than_3:
        cmp             msg_len_64, 2
        jb              ._only_less_than_2
        vpsrldq         xmm7, 6
        jmp             ._barrett

align_label
._only_less_than_2:
        vpsrldq         xmm7, 7
        jmp             ._barrett

mksection .rodata

align 16
mask1:
        dq 0x8080808080808080, 0x8080808080808080

align 16
mask2:
        dq 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF

align 16
bswap_shuf_mask:
        dq 0x08090A0B0C0D0E0F, 0x0001020304050607

align 16
pshufb_shf_table:
        dq 0x8786858483828100, 0x8f8e8d8c8b8a8988
        dq 0x0706050403020100, 0x000e0d0c0b0a0908

mksection stack-noexec
