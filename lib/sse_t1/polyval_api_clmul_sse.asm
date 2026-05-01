;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2026 Intel Corporation All rights reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions
;  are met:
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in
;      the documentation and/or other materials provided with the
;      distribution.
;    * Neither the name of Intel Corporation nor the names of its
;      contributors may be used to endorse or promote products derived
;      from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/memcpy.inc"
;; reuse AES-GCM argument definitions and access
%include "include/gcm_defines.inc"
%include "include/align_sse.inc"

;;
;; Key structure holds up to 4 hash keys
;;
%xdefine HashKey_4      (16 * 0) ; HashKey^4
%xdefine HashKey_3      (16 * 1) ; HashKey^3
%xdefine HashKey_2      (16 * 2) ; HashKey^2
%xdefine HashKey_1      (16 * 3) ; HashKey

%xdefine HKeyGap (4 * 16)
;; (HashKey^n mod POLY) x POLY constants

%xdefine HashKeyK_4     (HashKey_4 + HKeyGap)  ; HashKey^4 x POLY
%xdefine HashKeyK_3     (HashKey_3 + HKeyGap)  ; HashKey^3 x POLY
%xdefine HashKeyK_2     (HashKey_2 + HKeyGap)  ; HashKey^2 x POLY
%xdefine HashKeyK_1     (HashKey_1 + HKeyGap)  ; HashKey x POLY

%xdefine HKeySize (2*4*16)

mksection .rodata
default rel

align 16
POLY:
        dq     0x0000000000000001, 0xC200000000000000

mksection .text
default rel

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Stack frame definition
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifidn __OUTPUT_FORMAT__, win64
        %define XMM_STORAGE     (10*16)      ; space for 10 XMM registers
        %define GP_STORAGE      (9*8)        ; space for 8 GP registers + rsp
%else
        %define XMM_STORAGE     0
        %define GP_STORAGE      (7*8)        ; space for 6 GP registers + rsp
%endif

;; sequence is (bottom-up): GP, XMM
%define STACK_XMM_OFFSET        0
%define STACK_GP_OFFSET         (STACK_XMM_OFFSET + XMM_STORAGE)
%define STACK_FRAME_SIZE        (STACK_GP_OFFSET + GP_STORAGE)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Save register content for the caller
%macro FUNC_SAVE 0
        mov     rax, rsp

        sub     rsp, STACK_FRAME_SIZE
        and     rsp, ~15

        mov     [rsp + STACK_GP_OFFSET + 0*8], r12
        mov     [rsp + STACK_GP_OFFSET + 1*8], r13
        mov     [rsp + STACK_GP_OFFSET + 2*8], r14
        mov     [rsp + STACK_GP_OFFSET + 3*8], r15
        mov     [rsp + STACK_GP_OFFSET + 4*8], rax      ; stack
        mov     r14, rax                                ; r14 is used to retrieve stack args
        mov     [rsp + STACK_GP_OFFSET + 5*8], rbp
        mov     [rsp + STACK_GP_OFFSET + 6*8], rbx
%ifidn __OUTPUT_FORMAT__, win64
        mov     [rsp + STACK_GP_OFFSET + 7*8], rdi
        mov     [rsp + STACK_GP_OFFSET + 8*8], rsi
%endif

%ifidn __OUTPUT_FORMAT__, win64
        ; xmm6:xmm15 need to be maintained for Windows
        movdqa  [rsp + STACK_XMM_OFFSET + 0*16], xmm6
        movdqa  [rsp + STACK_XMM_OFFSET + 1*16], xmm7
        movdqa  [rsp + STACK_XMM_OFFSET + 2*16], xmm8
        movdqa  [rsp + STACK_XMM_OFFSET + 3*16], xmm9
        movdqa  [rsp + STACK_XMM_OFFSET + 4*16], xmm10
        movdqa  [rsp + STACK_XMM_OFFSET + 5*16], xmm11
        movdqa  [rsp + STACK_XMM_OFFSET + 6*16], xmm12
        movdqa  [rsp + STACK_XMM_OFFSET + 7*16], xmm13
        movdqa  [rsp + STACK_XMM_OFFSET + 8*16], xmm14
        movdqa  [rsp + STACK_XMM_OFFSET + 9*16], xmm15
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Restore register content for the caller
%macro FUNC_RESTORE 0

%ifidn __OUTPUT_FORMAT__, win64
        movdqa  xmm15, [rsp + STACK_XMM_OFFSET + 9*16]
        movdqa  xmm14, [rsp + STACK_XMM_OFFSET + 8*16]
        movdqa  xmm13, [rsp + STACK_XMM_OFFSET + 7*16]
        movdqa  xmm12, [rsp + STACK_XMM_OFFSET + 6*16]
        movdqa  xmm11, [rsp + STACK_XMM_OFFSET + 5*16]
        movdqa  xmm10, [rsp + STACK_XMM_OFFSET + 4*16]
        movdqa  xmm9, [rsp + STACK_XMM_OFFSET + 3*16]
        movdqa  xmm8, [rsp + STACK_XMM_OFFSET + 2*16]
        movdqa  xmm7, [rsp + STACK_XMM_OFFSET + 1*16]
        movdqa  xmm6, [rsp + STACK_XMM_OFFSET + 0*16]
%endif

        mov     rbp, [rsp + STACK_GP_OFFSET + 5*8]
        mov     rbx, [rsp + STACK_GP_OFFSET + 6*8]
%ifidn __OUTPUT_FORMAT__, win64
        mov     rdi, [rsp + STACK_GP_OFFSET + 7*8]
        mov     rsi, [rsp + STACK_GP_OFFSET + 8*8]
%endif
        mov     r12, [rsp + STACK_GP_OFFSET + 0*8]
        mov     r13, [rsp + STACK_GP_OFFSET + 1*8]
        mov     r14, [rsp + STACK_GP_OFFSET + 2*8]
        mov     r15, [rsp + STACK_GP_OFFSET + 3*8]
        mov     rsp, [rsp + STACK_GP_OFFSET + 4*8] ; stack
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; HASH_MUL2 MACRO to implement: Data*HashKey mod POLY (SSE version)
;; Input: A and B (128-bits each)
;; Output: C = A*B*x mod poly
;; To compute GH = GH*HashKey mod poly, give two constants:
;;   HK = HashKey<<1 mod poly as input
;;   KK = SWAP_H_L( HK_L * POLY) + HK
;;   POLY = 0xC2 << 56
;;
;; Realize four multiplications first, to achieve partially reduced product
;;   TLL = GH_L * KK_L
;;   TLH = GH_L * KK_H
;;   THL = GH_H * HK_L
;;   THH = GH_H * HK_H
;;
;; Accumulate results into 2 registers, with corresponding weights
;;   T1 = THH + TLH
;;   T2 = THL + TLL
;;
;; Begin reduction
;;    ----------
;;    |   T1   |
;;    ---------------
;;         |   T2   |
;;         ----------
;;
;;   T3 = SWAP_H_L(T2)
;;   T5 = T2_L * POLY
;;   GH = T1 + T5 + T3
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  HASH_MUL2  7
%define %%GH  %1        ;; [in/out] xmm with multiply operand(s) (128-bits)
%define %%HK  %2        ;; [in] xmm with hash key value(s) (128-bits)
%define %%KK  %3        ;; [in] xmm with hash key K value(s) (128-bits)
%define %%TLL %4        ;; [clobbered] xmm
%define %%TLH %5        ;; [clobbered] xmm
%define %%THL %6        ;; [clobbered] xmm
%define %%THH %7        ;; [clobbered] xmm

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        movdqa  %%TLL, %%GH
        pclmulqdq %%TLL, %%KK, 0x00     ; TLL = GH_L * KK_L
        movdqa  %%TLH, %%GH
        pclmulqdq %%TLH, %%KK, 0x10     ; TLH = GH_L * KK_H
        movdqa  %%THL, %%GH
        pclmulqdq %%THL, %%HK, 0x01     ; THL = GH_H * HK_L
        movdqa  %%THH, %%GH
        pclmulqdq %%THH, %%HK, 0x11     ; THH = GH_H * HK_H

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; add products
        pxor    %%TLL, %%THL
        pxor    %%THH, %%TLH

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; new reduction
        movdqa  %%GH, %%TLL
        pclmulqdq %%GH, [rel POLY], 0x10
        pshufd  %%TLH, %%TLL, 01001110b
        pxor    %%GH, %%THH
        pxor    %%GH, %%TLH
%endmacro

;; ===========================================================================
;; ===========================================================================
;; Compute KK constant from a hash key: KK = SWAP(HK_L * POLY) + HK
%macro COMPUTE_KK     3
%define %%HK  %1        ;; [in] xmm with hash key
%define %%KK  %2        ;; [out] xmm with K-constant
%define %%T1  %3        ;; [clobbered] xmm
        movdqa  %%KK, %%HK
        pclmulqdq %%KK, [rel POLY], 0x10
        pshufd  %%T1, %%HK, 01001110b
        pxor    %%KK, %%T1
%endmacro

;; ===========================================================================
;; ===========================================================================
;; Schoolbook multiply of 4 blocks
;; - XOR hash into first block
;; - Multiply each block with corresponding hash key
;; - Accumulate partial products
;; - Single reduction at the end
%macro HASH_4 10
%define %%INPTR      %1  ; [in] data input pointer
%define %%HKPTR      %2  ; [in] hash key pointer (r15)
%define %%HASH       %3  ; [in/out] xmm hash value in/out (xmm0)
%define %%BLK        %4  ; [clobbered] xmm for block data
%define %%TLL        %5  ; [clobbered] xmm
%define %%TLH        %6  ; [clobbered] xmm
%define %%THL        %7  ; [clobbered] xmm
%define %%GL         %8  ; [clobbered] xmm for accumulated GL
%define %%GH         %9  ; [clobbered] xmm for accumulated GH
%define %%HK_REG     %10 ; [clobbered] xmm for loading HK/KK

%define %%NUM_BLOCKS 4

%assign blk_idx 0
%rep %%NUM_BLOCKS
%assign hk_power (%%NUM_BLOCKS - blk_idx)

        ;; load block
        movdqu  %%BLK, [%%INPTR + (blk_idx * 16)]

%if blk_idx == 0
        ;; XOR hash into first block
        pxor    %%BLK, %%HASH
%endif

        ;; make copies for 4 clmul products
        movdqa  %%TLL, %%BLK
        movdqa  %%TLH, %%BLK
        movdqa  %%THL, %%BLK
        ;; %%BLK itself will be used for THH

        ;; load K-constant and multiply
        movdqu  %%HK_REG, [%%HKPTR + HashKeyK_ %+ hk_power]
        pclmulqdq %%TLL, %%HK_REG, 0x00 ; TLL = BLK_L * KK_L
        pclmulqdq %%TLH, %%HK_REG, 0x10 ; TLH = BLK_L * KK_H

        ;; load hash key and multiply
        movdqu  %%HK_REG, [%%HKPTR + HashKey_ %+ hk_power]
        pclmulqdq %%THL, %%HK_REG, 0x01 ; THL = BLK_H * HK_L
        pclmulqdq %%BLK, %%HK_REG, 0x11 ; THH = BLK_H * HK_H

        ;; combine partial products
        pxor    %%TLL, %%THL            ; TLL ^= THL
        pxor    %%TLH, %%BLK            ; TLH ^= THH

%if blk_idx == 0
        ;; initialize accumulators
        movdqa  %%GL, %%TLL
        movdqa  %%GH, %%TLH
%else
        ;; accumulate
        pxor    %%GL, %%TLL
        pxor    %%GH, %%TLH
%endif

%assign blk_idx (blk_idx + 1)
%endrep

        ;; reduction
        movdqa  %%HASH, %%GL
        pclmulqdq %%HASH, [rel POLY], 0x10
        pshufd  %%TLL, %%GL, 01001110b
        pxor    %%HASH, %%GH
        pxor    %%HASH, %%TLL

%endmacro

;; ===========================================================================
;; ===========================================================================
;; Schoolbook multiply of 1 to 4 blocks (one block at a time, SSE)
;; - handles partial last block via load_partial_block function
;; - XOR hash into first block
;; - Multiply each block with corresponding hash key
;; - Accumulate partial products
;; - Single reduction at the end
;;
;; Uses: r10 (data ptr), rax (number of partial bytes), r15 (hash key table)
%macro HASH_1_TO_N 9
%define %%NUM_BLOCKS %1  ; [in] numerical value: 1 to 4
%define %%HASH       %2  ; [in/out] xmm hash value
%define %%BLK        %3  ; [clobbered] xmm
%define %%TLL        %4  ; [clobbered] xmm
%define %%TLH        %5  ; [clobbered] xmm
%define %%THL        %6  ; [clobbered] xmm
%define %%GL         %7  ; [clobbered] xmm
%define %%GH         %8  ; [clobbered] xmm
%define %%HK_REG     %9  ; [clobbered] xmm

%assign blk_idx 0
%rep %%NUM_BLOCKS
%assign hk_power (%%NUM_BLOCKS - blk_idx)
%assign is_last (blk_idx == (%%NUM_BLOCKS - 1))

%if is_last
        ;; last block: may be partial
        ;; rax = partial bytes (0 means full block)
        test    rax, rax
        jz      %%_full_last_block_ %+ blk_idx

        ;; load partial block via function call
        lea     rbx, [r10 + (blk_idx * 16)]
        call    load_partial_block
        jmp     %%_block_loaded_ %+ blk_idx

%%_full_last_block_ %+ blk_idx:
%endif  ; is_last

        movdqu  %%BLK, [r10 + (blk_idx * 16)]

%if is_last
align_label
%%_block_loaded_ %+ blk_idx:
%endif

%if blk_idx == 0
        pxor    %%BLK, %%HASH
%endif

        ;; make copies for 4 clmul products
        movdqa  %%TLL, %%BLK
        movdqa  %%TLH, %%BLK
        movdqa  %%THL, %%BLK

        ;; load K-constant and multiply
        movdqu  %%HK_REG, [r15 + HashKeyK_ %+ hk_power]
        pclmulqdq %%TLL, %%HK_REG, 0x00
        pclmulqdq %%TLH, %%HK_REG, 0x10

        ;; load hash key and multiply
        movdqu  %%HK_REG, [r15 + HashKey_ %+ hk_power]
        pclmulqdq %%THL, %%HK_REG, 0x01
        pclmulqdq %%BLK, %%HK_REG, 0x11

        ;; combine partial products
        pxor    %%TLL, %%THL
        pxor    %%TLH, %%BLK

%if blk_idx == 0
        movdqa  %%GL, %%TLL
        movdqa  %%GH, %%TLH
%else
        pxor    %%GL, %%TLL
        pxor    %%GH, %%TLH
%endif

%assign blk_idx (blk_idx + 1)
%endrep

        ;; reduction
        movdqa  %%HASH, %%GL
        pclmulqdq %%HASH, [rel POLY], 0x10
        pshufd  %%TLL, %%GL, 01001110b
        pxor    %%HASH, %%GH
        pxor    %%HASH, %%TLL

%endmacro

;; =============================================================
;; Load 1-15 partial bytes into xmm1 with zero-padding
;; =============================================================
;; rbx [in] pointer to partial block data
;; rax [in] number of partial bytes (1-15)
;; xmm1 [out] loaded block
;; =============================================================
align_function
load_partial_block:
        simd_load_sse_15_1 xmm1, rbx, rax
        ret

;; =============================================================
;; Process remaining 1 to 4 blocks (including partials)
;; =============================================================
;; r10  [in] up to date msg pointer
;; r11  [in/clobbered] up to date msg length
;; xmm0 [in/out] - current hash value
;; r15  [in] hash key table pointer
;; rax, rbx, r12, xmm1-xmm7 [clobbered]
;; =============================================================
align_function
polyval_1_to_4:
        ;; prep partial byte count
        mov     DWORD(r12), DWORD(r11)

        ;; calculate number of blocks to hash (including partial bytes)
        add     DWORD(r11), 15
        shr     DWORD(r11), 4
        jz      .polyval_msg_done       ;; catch zero length

        ;; partial bytes in last block (0 = full block)
        mov     rax, r12
        and     rax, 15

        cmp     DWORD(r11), 2
        jb      .polyval_blocks_1
        je      .polyval_blocks_2
        cmp     DWORD(r11), 4
        jb      .polyval_blocks_3
        ;; fall through for 4 blocks

.polyval_blocks_4:
        HASH_1_TO_N 4, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
        ret

align_label
.polyval_blocks_3:
        HASH_1_TO_N 3, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
        ret

align_label
.polyval_blocks_2:
        HASH_1_TO_N 2, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
        ret

align_label
.polyval_blocks_1:
        HASH_1_TO_N 1, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
        ret

align_label
.polyval_msg_done:
        ret

;; ==============================================================
;; Computes polyval hash of the message using 4 hash keys.
;; It takes input hash value and returns updated value.
;; ==============================================================
;; r10   [in/out] ptr
;; r11   [in/out] length
;; xmm0  [in/out] hash
;; r15   [in] hash key table pointer
;; xmm1-xmm7 [clobbered]
;; ==============================================================
align_function
polyval_4:
        cmp             r11, (4*16)
        jb              .less_than_Nx16
align_loop
.loop_4x16:
        HASH_4          r10, r15, xmm0, \
                        xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7
        add             r10, (4*16)
        sub             r11, (4*16)
        jz              .polyval_msg_done
        cmp             r11, (4*16)
        jae             .loop_4x16

align_label
.less_than_Nx16:
        call            polyval_1_to_4

align_label
.polyval_msg_done:
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void nia_vclmul_sse(void *digest,
;;                     const void *hqp,
;;                     const void *msg,
;;                     const uint64_t msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(nia_clmul_sse,function,internal)
nia_clmul_sse:
        FUNC_SAVE

        sub             rsp, HKeySize   ;; reserve space for Hash Keys
        mov             r15, rsp        ;; r15 = pointer to HK table

        ;; Calculate powers of H and corresponding K-constant to
        ;; be used with HASH_MUL2 for improved reduction
        ;; H K-constant (KK) is in xmm8

        movdqu          xmm9, [arg2]            ;; load H (xmm9)
        COMPUTE_KK      xmm9, xmm8, xmm1

        ;; Compute K-constant for Q and save in xmm15 for later
        movdqu          xmm10, [arg2 + 16]      ;; load Q
        COMPUTE_KK      xmm10, xmm15, xmm1

        ;; HK^1 = H
        movdqa  [r15 + HashKey_1], xmm9
        movdqa  [r15 + HashKeyK_1], xmm8

        ;; xmm5 = H
        movdqa  xmm5, xmm9

        ;; compute HK^2..HK^4 and their K-constants
%assign key_idx 2
%rep 3
        HASH_MUL2       xmm5, xmm9, xmm8, xmm1, xmm2, xmm3, xmm4
        movdqu          [r15 + HashKey_ %+ key_idx], xmm5
        COMPUTE_KK      xmm5, xmm1, xmm2
        movdqu          [r15 + HashKeyK_ %+ key_idx], xmm1
%assign key_idx (key_idx + 1)
%endrep

        ;; xmm14 = block(message_len in bits)
        lea             rax, [arg4*8]
        movq            xmm14, rax
        pslldq          xmm14, 8

        ;; set hash to 0 (xmm0)
        pxor            xmm0, xmm0

        mov             r10, arg3       ; r10 = msg
        mov             r11, arg4       ; r11 = msg_len

        ;; =====================================================
        ;; process the message in 4 block chunks
        call            polyval_4

        ;; xmm0 = hash block
        ;; xmm14 = block(message_len in bits)
        pxor            xmm0, xmm14

        ;; xmm0 = xmm0 x Q mod POLY
        ;; KK for Q is already in xmm15
        movdqu          xmm1, [arg2 + 16]    ;; load Q
        HASH_MUL2   xmm0, xmm1, xmm15, xmm3, xmm4, xmm5, xmm6

        ;; xmm0 += P
        movdqu          xmm1, [arg2 + 32]    ;; load P
        pxor            xmm0, xmm1
        movdqu          [arg1], xmm0

%ifdef SAFE_DATA
        clear_scratch_xmms_sse_asm

        ;; clear stack frame with the hash keys
        pxor            xmm0, xmm0
%assign clr_idx 0
%rep 8
        movdqa          [r15 + (clr_idx * 16)], xmm0
%assign clr_idx (clr_idx + 1)
%endrep
%endif
        add     rsp, HKeySize
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void nca_vclmul_sse(void *digest,
;;                     const void *hqp,
;;                     const void *msg,
;;                     const uint64_t msg_len,
;;                     const void *aad,
;;                     const uint64_t aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(nca_clmul_sse,function,internal)
nca_clmul_sse:
        FUNC_SAVE

        sub             rsp, HKeySize   ;; reserve space for Hash Keys
        mov             r15, rsp        ;; r15 = pointer to HK table

        ;; Calculate powers of H and corresponding K-constant to
        ;; be used with HASH_MUL2 for improved reduction
        ;; H K-constant (KK) is in xmm8

        movdqu          xmm9, [arg2]            ;; load H (xmm9)
        COMPUTE_KK      xmm9, xmm8, xmm1

        ;; Compute KK for Q and save in xmm15 for later
        movdqu          xmm10, [arg2 + 16]      ;; load Q
        COMPUTE_KK      xmm10, xmm15, xmm1

        ;; HK^1 = H
        movdqa  [r15 + HashKey_1], xmm9
        movdqa  [r15 + HashKeyK_1], xmm8

        ;; xmm5 = H
        movdqa  xmm5, xmm9

        ;; compute HK^2..HK^4 and their K-constants
%assign key_idx 2
%rep 3
        HASH_MUL2       xmm5, xmm9, xmm8, xmm1, xmm2, xmm3, xmm4
        movdqa          [r15 + HashKey_ %+ key_idx], xmm5
        COMPUTE_KK      xmm5, xmm1, xmm2
        movdqa          [r15 + HashKeyK_ %+ key_idx], xmm1
%assign key_idx (key_idx + 1)
%endrep

        ;; xmm14 = block(message_len,aad_len)
        movq            xmm14, arg6             ;; aad_len in bits
        pslldq          xmm14, 8
        movq            xmm2, arg4              ;; msg_len in bits
        por             xmm14, xmm2
        psllq           xmm14, 3                ;; convert length in bytes to bits

        ;; set hash to 0 (xmm0)
        pxor            xmm0, xmm0

        ;; Save msg/msg_len in callee-safe registers before polyval calls
        ;; (polyval clobbers rcx/rbx via partial block handler)
        mov             rbp, arg3       ; rbp = msg
        mov             r13, arg4       ; r13 = msg_len

        ;; =====================================================
        ;; process the message in 4 block chunks
        mov             r10, arg5       ; r10 = aad
        mov             r11, arg6       ; r11 = aad_len
        call            polyval_4

        mov             r10, rbp        ; r10 = msg (saved)
        mov             r11, r13        ; r11 = msg_len (saved)
        call            polyval_4

        ;; xmm0 = hash block
        ;; xmm14 = block(aad_len,message_len)
        pxor            xmm0, xmm14

        ;; xmm0 = xmm0 x Q mod POLY
        ;; KK for Q is already in xmm15
        movdqu          xmm1, [arg2 + 16]    ;; load Q
        HASH_MUL2       xmm0, xmm1, xmm15, xmm3, xmm4, xmm5, xmm6

        ;; xmm0 += P
        movdqu          xmm1, [arg2 + 32]    ;; load P
        pxor            xmm0, xmm1
        movdqu          [arg1], xmm0

%ifdef SAFE_DATA
        clear_scratch_xmms_sse_asm

        ;; clear stack frame with the hash keys
        pxor            xmm0, xmm0
%assign clr_idx 0
%rep 8
        movdqa          [r15 + (clr_idx * 16)], xmm0
%assign clr_idx (clr_idx + 1)
%endrep
%endif
        add     rsp, HKeySize
        FUNC_RESTORE
        ret

mksection stack-noexec
