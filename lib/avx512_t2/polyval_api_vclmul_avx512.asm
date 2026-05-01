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
%include "include/aes_common.inc"
%include "include/align_avx512.inc"
;; reuse AES-GCM argument definitions and access
%include "include/gcm_defines.inc"

;; Above the cut-off length use 8 hash keys, otherwise 4 hash keys.
%define MSG_LEN_CUT_OFF 320

;;
;; Key structure holds up to 8 hash keys
;;
%xdefine HashKey_8      (16 * 0) ; HashKey^8
%xdefine HashKey_7      (16 * 1) ; HashKey^7
%xdefine HashKey_6      (16 * 2) ; HashKey^6
%xdefine HashKey_5      (16 * 3) ; HashKey^5
%xdefine HashKey_4      (16 * 4) ; HashKey^4
%xdefine HashKey_3      (16 * 5) ; HashKey^3
%xdefine HashKey_2      (16 * 6) ; HashKey^2
%xdefine HashKey_1      (16 * 7) ; HashKey

%xdefine HKeyGap (8 * 16)
;; (HashKey^n mod POLY) x POLY constants

%xdefine HashKeyK_8     (HashKey_8 + HKeyGap)  ; HashKey^8 x POLY
%xdefine HashKeyK_7     (HashKey_7 + HKeyGap)  ; HashKey^7 x POLY
%xdefine HashKeyK_6     (HashKey_6 + HKeyGap)  ; HashKey^6 x POLY
%xdefine HashKeyK_5     (HashKey_5 + HKeyGap)  ; HashKey^5 x POLY
%xdefine HashKeyK_4     (HashKey_4 + HKeyGap)  ; HashKey^4 x POLY
%xdefine HashKeyK_3     (HashKey_3 + HKeyGap)  ; HashKey^3 x POLY
%xdefine HashKeyK_2     (HashKey_2 + HKeyGap)  ; HashKey^2 x POLY
%xdefine HashKeyK_1     (HashKey_1 + HKeyGap)  ; HashKey x POLY

%xdefine HKeySize (2*8*16)

mksection .rodata
default rel

align 64
POLY:
        dq     0x0000000000000001, 0xC200000000000000
        dq     0x0000000000000001, 0xC200000000000000
        dq     0x0000000000000001, 0xC200000000000000
        dq     0x0000000000000001, 0xC200000000000000

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

;; sequence is (bottom-up): GP, XMM, local
%define STACK_XMM_OFFSET        0
%define STACK_GP_OFFSET         (STACK_XMM_OFFSET + XMM_STORAGE)
%define STACK_FRAME_SIZE        (STACK_GP_OFFSET + GP_STORAGE)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Save register content for the caller
%macro FUNC_SAVE 0
        ;; Required for Update/GMC_ENC
        mov     rax, rsp

        sub     rsp, STACK_FRAME_SIZE
        and     rsp, ~63

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
        vmovdqa [rsp + STACK_XMM_OFFSET + 0*16], xmm6
        vmovdqa [rsp + STACK_XMM_OFFSET + 1*16], xmm7
        vmovdqa [rsp + STACK_XMM_OFFSET + 2*16], xmm8
        vmovdqa [rsp + STACK_XMM_OFFSET + 3*16], xmm9
        vmovdqa [rsp + STACK_XMM_OFFSET + 4*16], xmm10
        vmovdqa [rsp + STACK_XMM_OFFSET + 5*16], xmm11
        vmovdqa [rsp + STACK_XMM_OFFSET + 6*16], xmm12
        vmovdqa [rsp + STACK_XMM_OFFSET + 7*16], xmm13
        vmovdqa [rsp + STACK_XMM_OFFSET + 8*16], xmm14
        vmovdqa [rsp + STACK_XMM_OFFSET + 9*16], xmm15
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Restore register content for the caller
%macro FUNC_RESTORE 0

        vzeroupper

%ifidn __OUTPUT_FORMAT__, win64
        vmovdqa xmm15, [rsp + STACK_XMM_OFFSET + 9*16]
        vmovdqa xmm14, [rsp + STACK_XMM_OFFSET + 8*16]
        vmovdqa xmm13, [rsp + STACK_XMM_OFFSET + 7*16]
        vmovdqa xmm12, [rsp + STACK_XMM_OFFSET + 6*16]
        vmovdqa xmm11, [rsp + STACK_XMM_OFFSET + 5*16]
        vmovdqa xmm10, [rsp + STACK_XMM_OFFSET + 4*16]
        vmovdqa xmm9, [rsp + STACK_XMM_OFFSET + 3*16]
        vmovdqa xmm8, [rsp + STACK_XMM_OFFSET + 2*16]
        vmovdqa xmm7, [rsp + STACK_XMM_OFFSET + 1*16]
        vmovdqa xmm6, [rsp + STACK_XMM_OFFSET + 0*16]
%endif

        ;; Required for Update/GCM_ENC
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

;; ===========================================================================
;; ===========================================================================
;; Horizontal XOR - 4 x 128bits xored together
%macro VHPXORI4x128 2
%define %%REG   %1      ; [in/out] ZMM with 4x128bits to xor; 128bit output
%define %%TMP   %2      ; [clobbered] ZMM temporary register
        vextracti64x4   YWORD(%%TMP), %%REG, 1
        vpxorq          YWORD(%%REG), YWORD(%%REG), YWORD(%%TMP)
        vextracti32x4   XWORD(%%TMP), YWORD(%%REG), 1
        vpxorq          XWORD(%%REG), XWORD(%%REG), XWORD(%%TMP)
%endmacro               ; VHPXORI4x128

;; ===========================================================================
;; ===========================================================================
;; Horizontal XOR - 2 x 128bits xored together
%macro VHPXORI2x128 2
%define %%REG   %1      ; [in/out] YMM with 2x128bits to xor; 128bit output
%define %%TMP   %2      ; [clobbered] YMM temporary register
        vextracti32x4   XWORD(%%TMP), YWORD(%%REG), 1
        vpxorq          XWORD(%%REG), XWORD(%%REG), XWORD(%%TMP)
%endmacro               ; VHPXORI2x128

;; ===========================================================================
;; ===========================================================================
;; Schoolbook multiply of 4 blocks (4 x 16 bytes) or 8 blocks (8 x 16 bytes)
;; - always starts POLYVAL process and performs reduction at the end
;; - LOAD TYPE options:
;;   - hk_load (default): load hash keys and do horizontal XOR after reduction
;;   - hk_broadcast: broadcast hash keys and NO horizontal XOR after reduction
%macro HASH_4_OR_8 14
%define %%LOADT %1      ; [in] hash key load type: hk_load (load) or hk_bcast (broadcast)
%define %%INPTR %2      ; [in] data input pointer
%define %%HKPTR %3      ; [in] hash key pointer
%define %%HASH  %4      ; [in/out] ZMM hash value in/out
%define %%NUM_BLOCKS %5 ; [in] numerical value: 4 or 8
%define %%ZTMP0 %6      ; [clobbered] temporary ZMM
%define %%ZTMP1 %7      ; [clobbered] temporary ZMM
%define %%ZTMP2 %8      ; [clobbered] temporary ZMM
%define %%ZTMP3 %9      ; [clobbered] temporary ZMM
%define %%ZTMP4 %10     ; [clobbered] temporary ZMM
%define %%ZTMP5 %11     ; [clobbered] temporary ZMM
%define %%ZTMP6 %12     ; [clobbered] temporary ZMM
%define %%GH    %13     ; [clobbered] temporary ZMM
%define %%GL    %14     ; [clobbered] temporary ZMM

        ;; in this use case, start-hash and reduction always take place
%assign hk_broadcast 0
%assign do_hxor 1

%ifidn %%LOADT, hk_bcast
%assign hk_broadcast 1
%assign do_hxor 0
%endif

        ;; hash blocks 0-3
        vmovdqu64       %%ZTMP5, [%%INPTR]
        vpxorq          %%ZTMP5, %%ZTMP5, %%HASH

%if hk_broadcast != 0
        vbroadcasti64x2 %%ZTMP4, [%%HKPTR]
        vbroadcasti64x2 %%ZTMP6, [%%HKPTR + HKeyGap]
%else
        vmovdqa64       %%ZTMP4, [%%HKPTR]
        vmovdqa64       %%ZTMP6, [%%HKPTR + HKeyGap]
%endif
        vpclmulqdq      %%ZTMP0, %%ZTMP5, %%ZTMP6, 0x00 ; TLL = ML*KL
        vpclmulqdq      %%ZTMP1, %%ZTMP5, %%ZTMP6, 0x10 ; TLH = ML*KH
        vpclmulqdq      %%ZTMP2, %%ZTMP5, %%ZTMP4, 0x01 ; THL = MH*HL
        vpclmulqdq      %%ZTMP3, %%ZTMP5, %%ZTMP4, 0x11 ; THH = MH*HH

        ;; update sums
        vpxorq          %%GL, %%ZTMP0, %%ZTMP2          ; GL = THL + TLL
        vpxorq          %%GH, %%ZTMP1, %%ZTMP3          ; GH = THH + TLH

%if %%NUM_BLOCKS == 8
        ;; hash blocks 4-7
        vmovdqu64       %%ZTMP5, [%%INPTR + 64]
%if hk_broadcast != 0
        vbroadcasti64x2 %%ZTMP4, [%%HKPTR + 64]
        vbroadcasti64x2 %%ZTMP6, [%%HKPTR + HKeyGap + 64]
%else
        vmovdqa64       %%ZTMP4, [%%HKPTR + 64]
        vmovdqa64       %%ZTMP6, [%%HKPTR + HKeyGap + 64]
%endif
        vpclmulqdq      %%ZTMP0, %%ZTMP5, %%ZTMP6, 0x00 ; TLL = ML*KL
        vpclmulqdq      %%ZTMP1, %%ZTMP5, %%ZTMP6, 0x10 ; TLH = ML*KH
        vpclmulqdq      %%ZTMP2, %%ZTMP5, %%ZTMP4, 0x01 ; THL = MH*HL
        vpclmulqdq      %%ZTMP3, %%ZTMP5, %%ZTMP4, 0x11 ; THH = MH*HH

        ;; update sums
        vpternlogq      %%GL, %%ZTMP2, %%ZTMP0, 0x96    ; GL += THL + TLL
        vpternlogq      %%GH, %%ZTMP3, %%ZTMP1, 0x96    ; GH += THH + TLH
%endif ;; 8 blocks

        ;; new reduction
        vpclmulqdq      %%HASH, %%GL, [rel POLY], 0x10
        vpshufd         %%ZTMP0, %%GL, 01001110b
        vpternlogq      %%HASH, %%GH, %%ZTMP0, 0x96
%if do_hxor != 0
        VHPXORI4x128    %%HASH, %%ZTMP0
%endif

%endmacro

;; ===========================================================================
;; ===========================================================================
;; HASH 1 to 8 blocks of cipher text
;; - performs reduction at the end
;; - it doesn't load the data and it assumed it is already loaded and
;;   shuffled
;; - single_call scenario only
%macro  HASH_1_TO_8 16
%define %%KP            %1      ; [in] pointer to hash keys
%define %%HASH          %2      ; [out] hash output
%define %%THH1          %3      ; [clobbered] temporary ZMM
%define %%THL1          %4      ; [clobbered] temporary ZMM
%define %%TLH1          %5      ; [clobbered] temporary ZMM
%define %%TLL1          %6      ; [clobbered] temporary ZMM
%define %%THH2          %7      ; [clobbered] temporary ZMM
%define %%THL2          %8      ; [clobbered] temporary ZMM
%define %%TLH2          %9      ; [clobbered] temporary ZMM
%define %%TLL2          %10     ; [clobbered] temporary ZMM
%define %%HK1           %11     ; [clobbered] temporary ZMM
%define %%HK2           %12     ; [clobbered] temporary ZMM
%define %%AAD_HASH_IN   %13     ; [in] input hash value
%define %%MSG_IN0       %14     ; [in] ZMM with message text blocks 0-3
%define %%MSG_IN1       %15     ; [in] ZMM with message text blocks 4-7
%define %%NUM_BLOCKS    %16     ; [in] numerical value, number of blocks

%assign hashk           HashKey_ %+ %%NUM_BLOCKS

        ;; Add current HASH value to block 0
        vpxorq          %%MSG_IN0, %%MSG_IN0, %%AAD_HASH_IN

%if %%NUM_BLOCKS == 8

        vmovdqu64       %%HK1, [%%KP + HashKey_8]
        vmovdqu64       %%HK2, [%%KP + HashKeyK_8]
        vpclmulqdq      %%TLL1, %%MSG_IN0, %%HK2, 0x00 ; TLL = ML*KL
        vpclmulqdq      %%TLH1, %%MSG_IN0, %%HK2, 0x10 ; TLH = ML*KH
        vpclmulqdq      %%THL1, %%MSG_IN0, %%HK1, 0x01 ; THL = MH*HL
        vpclmulqdq      %%THH1, %%MSG_IN0, %%HK1, 0x11 ; THH = MH*HH

        vmovdqu64       %%HK1, [%%KP + HashKey_4]
        vmovdqu64       %%HK2, [%%KP + HashKeyK_4]
        vpclmulqdq      %%TLL2, %%MSG_IN1, %%HK2, 0x00 ; TLL = ML*KL
        vpclmulqdq      %%TLH2, %%MSG_IN1, %%HK2, 0x10 ; TLH = ML*KH
        vpclmulqdq      %%THL2, %%MSG_IN1, %%HK1, 0x01 ; THL = MH*HL
        vpclmulqdq      %%THH2, %%MSG_IN1, %%HK1, 0x11 ; THH = MH*HH

        ;; add sums into THH1:TLL1
        vpxorq          %%TLL1, %%TLL1, %%THL1
        vpxorq          %%THH1, %%THH1, %%TLH1
        vpternlogq      %%TLL1, %%TLL2, %%THL2, 0x96
        vpternlogq      %%THH1, %%THH2, %%TLH2, 0x96

%assign hashk (hashk + (2 * 64))

%elif %%NUM_BLOCKS >= 4

        vmovdqu64       %%HK1, [%%KP + hashk]
        vmovdqu64       %%HK2, [%%KP + hashk + HKeyGap]
        vpclmulqdq      %%TLL1, %%MSG_IN0, %%HK2, 0x00 ; TLL = ML*KL
        vpclmulqdq      %%TLH1, %%MSG_IN0, %%HK2, 0x10 ; TLH = ML*KH
        vpclmulqdq      %%THL1, %%MSG_IN0, %%HK1, 0x01 ; THL = MH*HL
        vpclmulqdq      %%THH1, %%MSG_IN0, %%HK1, 0x11 ; THH = MH*HH

        ;; add sums into THH1:TLL1
        vpxorq          %%TLL1, %%TLL1, %%THL1
        vpxorq          %%THH1, %%THH1, %%TLH1

%assign hashk (hashk + (1 * 64))

%endif

        ;; T1H/L/M1/M2 - hold current product sums (provided %%NUM_BLOCKS >= 4)
%assign blocks_left (%%NUM_BLOCKS % 4)

%if blocks_left > 0
        ;; =====================================================
        ;; There are 1, 2 or 3 blocks left to process.
        ;; It may also be that they are the only blocks to process.

;; Set hash key and register index position for the remaining 1 to 3 blocks
%assign reg_idx (%%NUM_BLOCKS / 4)

%xdefine %%REG_IN %%MSG_IN %+ reg_idx

%if blocks_left == 1
        vmovdqu64       XWORD(%%HK1), [%%KP + hashk]
        vmovdqu64       XWORD(%%HK2), [%%KP + hashk + HKeyGap]
        vpclmulqdq      XWORD(%%TLL2), XWORD(%%REG_IN), XWORD(%%HK2), 0x00 ; TLL = ML*KL
        vpclmulqdq      XWORD(%%TLH2), XWORD(%%REG_IN), XWORD(%%HK2), 0x10 ; TLH = ML*KH
        vpclmulqdq      XWORD(%%THL2), XWORD(%%REG_IN), XWORD(%%HK1), 0x01 ; THL = MH*HL
        vpclmulqdq      XWORD(%%THH2), XWORD(%%REG_IN), XWORD(%%HK1), 0x11 ; THH = MH*HH
%elif blocks_left == 2
        vmovdqu64       YWORD(%%HK1), [%%KP + hashk]
        vmovdqu64       YWORD(%%HK2), [%%KP + hashk + HKeyGap]
        vpclmulqdq      YWORD(%%TLL2), YWORD(%%REG_IN), YWORD(%%HK2), 0x00 ; TLL = ML*KL
        vpclmulqdq      YWORD(%%TLH2), YWORD(%%REG_IN), YWORD(%%HK2), 0x10 ; TLH = ML*KH
        vpclmulqdq      YWORD(%%THL2), YWORD(%%REG_IN), YWORD(%%HK1), 0x01 ; THL = MH*HL
        vpclmulqdq      YWORD(%%THH2), YWORD(%%REG_IN), YWORD(%%HK1), 0x11 ; THH = MH*HH
%else ; blocks_left == 3
        vmovdqu64       YWORD(%%HK1), [%%KP + hashk]
        vmovdqu64       YWORD(%%HK2), [%%KP + hashk + HKeyGap]
        vinserti64x2    %%HK1, [%%KP + hashk + 32], 2
        vinserti64x2    %%HK2, [%%KP + hashk + HKeyGap + 32], 2
        vpclmulqdq      %%TLL2, %%REG_IN, %%HK2, 0x00 ; TLL = ML*KL
        vpclmulqdq      %%TLH2, %%REG_IN, %%HK2, 0x10 ; TLH = ML*KH
        vpclmulqdq      %%THL2, %%REG_IN, %%HK1, 0x01 ; THL = MH*HL
        vpclmulqdq      %%THH2, %%REG_IN, %%HK1, 0x11 ; THH = MH*HH
%endif ; blocks_left

        ;; add sums into THH1:TLL1
%if %%NUM_BLOCKS > 4
        vpternlogq      %%TLL1, %%TLL2, %%THL2, 0x96
        vpternlogq      %%THH1, %%THH2, %%TLH2, 0x96
%else
        vpxorq          %%TLL1, %%TLL2, %%THL2
        vpxorq          %%THH1, %%THH2, %%TLH2
%endif

%undef %%REG_IN
%endif ; blocks_left > 0

        ;; new reduction
%if %%NUM_BLOCKS == 1
        vpclmulqdq      XWORD(%%HASH), XWORD(%%TLL1), [rel POLY], 0x10
        vpshufd         XWORD(%%TLH1),  XWORD(%%TLL1), 01001110b
        vpternlogq      XWORD(%%HASH), XWORD(%%THH1), XWORD(%%TLH1), 0x96
%elif %%NUM_BLOCKS == 2
        vpclmulqdq      YWORD(%%HASH), YWORD(%%TLL1), [rel POLY], 0x10
        vpshufd         YWORD(%%TLH1),  YWORD(%%TLL1), 01001110b
        vpternlogq      YWORD(%%HASH), YWORD(%%THH1), YWORD(%%TLH1), 0x96
        VHPXORI2x128    YWORD(%%HASH), YWORD(%%TLH1)
%else
        vpclmulqdq      ZWORD(%%HASH), %%TLL1, [rel POLY], 0x10
        vpshufd         %%TLH1, %%TLL1, 01001110b
        vpternlogq      ZWORD(%%HASH), %%THH1, %%TLH1, 0x96
        VHPXORI4x128    ZWORD(%%HASH), %%TLH1
%endif


%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; HASH_MUL2 MACRO to implement: Data*HashKey mod POLY
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
        vpclmulqdq      %%TLL, %%GH, %%KK, 0x00     ; TLL = GH_L * KK_L
        vpclmulqdq      %%TLH, %%GH, %%KK, 0x10     ; TLH = GH_L * KK_H
        vpclmulqdq      %%THL, %%GH, %%HK, 0x01     ; THL = GH_H * HK_L
        vpclmulqdq      %%THH, %%GH, %%HK, 0x11     ; THH = GH_H * HK_H

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; add products
        vpxorq          %%TLL, %%TLL, %%THL
        vpxorq          %%THH, %%THH, %%TLH

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; new reduction
        vpclmulqdq      %%GH, %%TLL, [rel POLY], 0x10
        vpshufd         %%TLH, %%TLL, 01001110b
        vpternlogq      %%GH, %%THH, %%TLH, 0x96
%endmacro

mksection .text

;; =============================================================
;; process remaining 1 to 4/8 blocks (including partials)
;; =============================================================
;; r10  [in] up to date msg pointer
;; r11  [in/clobbered] up to date msg length
;; zmm0/xmm0 [in/out] - current hash value
;; r15  [in] hash key table pointer
;; rax, r12, zmm1-zmm12 [clobbered]
;; =============================================================
align_function
polyval_1_to_8:
        ;; prep for mask build up
        mov             DWORD(r12), DWORD(r11)
        mov             rax, -1                 ;; all ones for mask build-up

        ;; calculate number of blocks to hash (including partial bytes)
        add             DWORD(r11), 15
        shr             DWORD(r11), 4
        jz              .polyval_msg_done       ;; catch zero length
        cmp             DWORD(r11), 2
        jb              .polyval_blocks_1
        je              .polyval_blocks_2
        cmp             DWORD(r11), 4
        jb              .polyval_blocks_3
        je              .polyval_blocks_4
        sub             DWORD(r12), 4 * 16      ;; more than 4 blocks; adjust length for the mask
        cmp             DWORD(r11), 6
        jb              .polyval_blocks_5
        je              .polyval_blocks_6
        cmp             DWORD(r11), 8
        jb              .polyval_blocks_7
        ;; fall through for 8 blocks

%assign I 8
        ;; generate all 8 cases
%rep 8

%if I != 8
align_label
%endif

.polyval_blocks_ %+ I:
        bzhi            rax, rax, r12           ;; rax = (1<<len)-1, and len>=64 => all ones
        kmovq           k1, rax

        ZMM_LOAD_MASKED_BLOCKS_0_16 \
                        I, r10, 0, \
                        zmm11, zmm12, null_zmm, null_zmm, k1

        HASH_1_TO_8     r15, zmm0, \
                        zmm1, zmm2, zmm3, zmm4, zmm5, \
                        zmm6, zmm7, zmm8, zmm9, zmm10, \
                        zmm0, \
                        zmm11, zmm12, I
        ret
%assign I (I - 1)
%endrep

align_label
.polyval_msg_done:
        ret

; ==============================================================
; Computes polyval hash of the message using 4 hash keys.
; It takes input hash value and returns updated value.
; ==============================================================
; r10   [in/out] ptr
; r11   [in/out] length
; zmm0  [in/out] hash
; r15   [in] hash key table pointer
; zmm1-zmm9 [clobbered]
; ==============================================================
align_function
polyval_4:
        cmp             r11, (4*16)
        jb              .less_than_Nx16
align_loop
.loop_2x4x16:
        cmp             r11, (2*4*16)
        jb              .loop_4x16
        HASH_4_OR_8     hk_bcast, r10, {r15 + HashKey_4}, zmm0, 4, \
                        zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9
        add             r10, (4*16)
        sub             r11, (4*16)
        jz              .polyval_msg_done
        jmp             .loop_2x4x16

align_loop
.loop_4x16:
        HASH_4_OR_8     hk_load, r10, {r15 + HashKey_4}, zmm0, 4, \
                        zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9
        add             r10, (4*16)
        sub             r11, (4*16)
        jz              .polyval_msg_done
        cmp             r11, (4*16)
        jae             .loop_4x16

align_label
.less_than_Nx16:
        call            polyval_1_to_8

align_label
.polyval_msg_done:
        ret

; ==============================================================
; Computes polyval hash of the message using 8 hash keys.
; It takes input hash value and returns updated value.
; ==============================================================
; r10   [in/out] ptr
; r11   [in/out] length
; zmm0  [in/out] hash
; r15   [in] hash key table pointer
; zmm1-zmm9 [clobbered]
; ==============================================================
align_function
polyval_8:
        cmp             r11, (8*16)
        jb              .less_than_Nx16
align_loop
.loop_2x8x16:
        cmp             r11, (2*8*16)
        jb              .loop_8x16
        HASH_4_OR_8     hk_bcast, r10, {r15 + HashKey_8}, zmm0, 8, \
                        zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9
        add             r10, (8*16)
        sub             r11, (8*16)
        jz              .polyval_msg_done
        jmp             .loop_2x8x16

align_loop
.loop_8x16:
        HASH_4_OR_8     hk_load, r10, {r15 + HashKey_8}, zmm0, 8, \
                        zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9
        add             r10, (8*16)
        sub             r11, (8*16)
        jz              .polyval_msg_done
        cmp             r11, (8*16)
        jae             .loop_8x16

align_label
.less_than_Nx16:
        call            polyval_1_to_8

align_label
.polyval_msg_done:
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; void nia_vclmul_avx512(void *digest,
;                        const void *hqp,
;                        const void *msg,
;                        const uint64_t msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(nia_vclmul_avx512,function,internal)
nia_vclmul_avx512:
        FUNC_SAVE

        sub             rsp, HKeySize   ;; reserve space for Hash Keys
        mov             r15, rsp        ;; r15 = pointer to HK table

        vmovdqu64       xmm9, [arg2]            ;; load H (xmm9)
        vinserti64x2    ymm9, [arg2 + 16], 1    ;; load Q (ymm9)

        ;; Calculate K-constant for H and Q at the same time.
        vpclmulqdq      ymm8, ymm9, [rel POLY], 0x10
        vpshufd         ymm1, ymm9, 01001110b
        vpxorq          ymm8, ymm8, ymm1

        vextracti32x4   xmm15, ymm8, 1  ; save KK for Q in xmm15

        ;; Calculate powers of H and corresponding K-constant to
        ;; be used with HASH_MUL2 for improved reduction
        ;; H K-constant (KK) is in xmm8

        vmovdqa64       xmm5, xmm9
        vshufi64x2      zmm7, zmm9, zmm9, 0x00          ;; init zmm7 with HK^1

        ;; calculate HashKey^2 mod poly
        HASH_MUL2       xmm5, xmm9, xmm8, xmm1, xmm2, xmm3, xmm4
        vinserti64x2    zmm7, xmm5, 2

        ;; calculate HashKey^3 mod poly
        HASH_MUL2       xmm5, xmm9, xmm8, xmm1, xmm2, xmm3, xmm4
        vinserti64x2    zmm7, xmm5, 1

        ;; calculate HashKey^4 mod poly
        HASH_MUL2       xmm5, xmm9, xmm8, xmm1, xmm2, xmm3, xmm4
        vinserti64x2    zmm7, xmm5, 0
        vmovdqa64       [r15 + HashKey_4], zmm7

        vshufi64x2      zmm5, zmm5, zmm5, 0x00          ;; broadcast HK^4 across all zmm5

        ;; calculate HashKeyK = HashKey x POLY
        vpclmulqdq      zmm1, zmm7, [rel POLY], 0x10
        vpshufd         zmm2, zmm7, 01001110b
        vpxorq          zmm1, zmm1, zmm2
        vmovdqa64       [r15 + HashKeyK_4], zmm1

        ;; xmm14 = block(message_len in bits)
        lea             rax, [arg4*8]
        vmovq           xmm14, rax
        vpslldq         xmm14, xmm14, 8

        ;; zmm7 = HK^4 HK^3 HK^2 HK^1
        ;; zmm1 = KK^4 KK^3 KK^2 KK^1
        ;; zmm5 = HK^4 HK^4 HK^4 HK^4

        ;; set hash to 0 (xmm0)
        vpxorq          xmm0, xmm0, xmm0

        mov             r10, arg3       ; r10 = msg
        mov             r11, arg4       ; r11 = msg_len

        cmp             arg4, MSG_LEN_CUT_OFF
        ja              .polyval_msg_long

        ;; =====================================================
        ;; process the message in 4 block chunks
        call            polyval_4
        jmp             .polyval_msg_done

        ;; =====================================================
        ;; process the message in 8 block chunks
align_label
.polyval_msg_long:
        ;; Pick up H hash key computation for HK^5 to HK^8

        ;; zmm7 = HK^4 HK^3 HK^2 HK^1
        ;; zmm1 = KK^4 KK^3 KK^2 KK^1
        ;; zmm5 = HK^4 HK^4 HK^4 HK^4

        ;; calculate HK^5 mod poly, HK^6 mod poly, ... HK^8 mod poly
        HASH_MUL2       zmm5, zmm7, zmm1, zmm2, zmm3, zmm4, zmm6
        vmovdqa64       [r15 + HashKey_8], zmm5         ;; HK^8 to HK^5

        ;; calculate HashKeyX = HashKey x POLY
        vpclmulqdq      zmm1, zmm5, [rel POLY], 0x10
        vpshufd         zmm2, zmm5, 01001110b
        vpxorq          zmm1, zmm1, zmm2
        vmovdqa64       [r15 + HashKeyK_8], zmm1

        call            polyval_8

align_label
.polyval_msg_done:
        ;; xmm0 = hash block
        ;; xmm14 = block(message_len in bits)
        vpxorq          xmm0, xmm0, xmm14

        ;; xmm0 = xmm0 x Q mod POLY
        ;; KK for Q is already in xmm15
        vmovdqu64       xmm1, [arg2 + 16]    ;; load Q
        HASH_MUL2       xmm0, xmm1, xmm15, xmm3, xmm4, xmm5, xmm6

        ;; xmm0 += P
        vmovdqu64       xmm1, [arg2 + 32]    ;; load P
        vpxorq          xmm0, xmm0, xmm1
        vmovdqu64       [arg1], xmm0

%ifdef SAFE_DATA
        clear_scratch_zmms_asm

        ;; clear stack frame with the hash keys
        vmovdqa64       [r15 + HashKey_4], zmm0
        vmovdqa64       [r15 + HashKey_8], zmm0
        vmovdqa64       [r15 + HashKeyK_4], zmm0
        vmovdqa64       [r15 + HashKeyK_8], zmm0
%endif
        add             rsp, HKeySize
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; void nca_vclmul_avx512(void *digest,
;                        const void *hqp,
;                        const void *msg,
;                        const uint64_t msg_len,
;                        const void *aad,
;                        const uint64_t aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
MKGLOBAL(nca_vclmul_avx512,function,internal)
nca_vclmul_avx512:
        FUNC_SAVE

        sub             rsp, HKeySize   ;; reserve space for Hash Keys
        mov             r15, rsp        ;; r15 = pointer to HK table

        vmovdqu64       xmm9, [arg2]            ;; load H (xmm9)
        vinserti64x2    ymm9, [arg2 + 16], 1    ;; load Q (ymm9)

        ;; Calculate K-constant for H and Q at the same time.
        vpclmulqdq      ymm8, ymm9, [rel POLY], 0x10
        vpshufd         ymm1, ymm9, 01001110b
        vpxorq          ymm8, ymm8, ymm1

        vextracti32x4   xmm15, ymm8, 1  ; save KK for Q in xmm15

        ;; Calculate powers of H and corresponding K-constant to
        ;; be used with HASH_MUL2 for improved reduction
        ;; H K-constant (KK) is in xmm8
        vmovdqa64       xmm5, xmm9
        vshufi64x2      zmm7, zmm9, zmm9, 0x00          ;; init zmm7 with HK^1

        ;; calculate HashKey^2 mod poly
        HASH_MUL2       xmm5, xmm9, xmm8, xmm1, xmm2, xmm3, xmm4
        vinserti64x2    zmm7, xmm5, 2

        ;; calculate HashKey^3 mod poly
        HASH_MUL2       xmm5, xmm9, xmm8, xmm1, xmm2, xmm3, xmm4
        vinserti64x2    zmm7, xmm5, 1

        ;; calculate HashKey^4 mod poly
        HASH_MUL2       xmm5, xmm9, xmm8, xmm1, xmm2, xmm3, xmm4
        vinserti64x2    zmm7, xmm5, 0
        vmovdqa64       [r15 + HashKey_4], zmm7

        vshufi64x2      zmm5, zmm5, zmm5, 0x00          ;; broadcast HK^4 across all zmm5

        ;; calculate HashKeyK = HashKey x POLY
        vpclmulqdq      zmm1, zmm7, [rel POLY], 0x10
        vpshufd         zmm2, zmm7, 01001110b
        vpxorq          zmm1, zmm1, zmm2
        vmovdqa64       [r15 + HashKeyK_4], zmm1

        ;; xmm14 = block(message_len,aad_len)
        vmovq           xmm14, arg6             ;; aad_len in bytes
        vpslldq         xmm14, xmm14, 8
        vmovq           xmm2, arg4              ;; msg_len in bytes
        vporq           xmm14, xmm14, xmm2
        vpsllq          xmm14, xmm14, 3         ;; convert lengths in bytes to bits

        ;; zmm7 = HK^4 HK^3 HK^2 HK^1
        ;; zmm1 = KK^4 KK^3 KK^2 KK^1
        ;; zmm5 = HK^4 HK^4 HK^4 HK^4

        ;; set hash to 0 (xmm0)
        vpxorq          xmm0, xmm0, xmm0

        mov             r13, arg4       ; r13 = msg_len
        cmp             r13, arg6
        cmovb           r13, arg6       ; r13 = max(msg_len, aad_len)

        cmp             r13, MSG_LEN_CUT_OFF
        ja              .polyval_msg_long

        ;; =====================================================
        ;; process the message in 4 block chunks
        mov             r10, arg5       ; r10 = aad
        mov             r11, arg6       ; r11 = aad_len
        call            polyval_4

        mov             r10, arg3       ; r10 = msg
        mov             r11, arg4       ; r11 = msg_len
        call            polyval_4
        jmp             .polyval_msg_done

        ;; =====================================================
        ;; process the message in 8 block chunks
align_label
.polyval_msg_long:
        ;; Pick up H hash key computation for HK^5 to HK^8

        ;; zmm7 = HK^4 HK^3 HK^2 HK^1
        ;; zmm1 = KK^4 KK^3 KK^2 KK^1
        ;; zmm5 = HK^4 HK^4 HK^4 HK^4

        ;; calculate HK^5 mod poly, HK^6 mod poly, ... HK^8 mod poly
        HASH_MUL2       zmm5, zmm7, zmm1, zmm2, zmm3, zmm4, zmm6
        vmovdqa64       [r15 + HashKey_8], zmm5         ;; HK^8 to HK^5

        ;; calculate HashKeyX = HashKey x POLY
        vpclmulqdq      zmm1, zmm5, [rel POLY], 0x10
        vpshufd         zmm2, zmm5, 01001110b
        vpxorq          zmm1, zmm1, zmm2
        vmovdqa64       [r15 + HashKeyK_8], zmm1

        mov             r10, arg5       ; r10 = aad
        mov             r11, arg6       ; r11 = aad_len
        call            polyval_8

        mov             r10, arg3       ; r10 = msg
        mov             r11, arg4       ; r11 = msg_len
        call            polyval_8

align_label
.polyval_msg_done:
        ;; xmm0 = hash block
        ;; xmm14 = block(message_len in bits)
        vpxorq          xmm0, xmm0, xmm14

        ;; xmm0 = xmm0 x Q mod POLY
        ;; KK for Q is already in xmm15
        vmovdqu64       xmm1, [arg2 + 16]    ;; load Q
        HASH_MUL2       xmm0, xmm1, xmm15, xmm3, xmm4, xmm5, xmm6

        ;; xmm0 += P
        vmovdqu64       xmm1, [arg2 + 32]    ;; load P
        vpxorq          xmm0, xmm0, xmm1
        vmovdqu64       [arg1], xmm0

%ifdef SAFE_DATA
        clear_scratch_zmms_asm

        ;; clear stack frame with the hash keys
        vmovdqa64       [r15 + HashKey_4], zmm0
        vmovdqa64       [r15 + HashKey_8], zmm0
        vmovdqa64       [r15 + HashKeyK_4], zmm0
        vmovdqa64       [r15 + HashKeyK_8], zmm0
%endif
        add             rsp, HKeySize
        FUNC_RESTORE
        ret

mksection stack-noexec
