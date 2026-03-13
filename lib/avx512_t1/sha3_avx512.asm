; Copyright (c) 2026, Intel Corporation
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are met:
;
;   * Redistributions of source code must retain the above copyright notice,
;     this list of conditions and the following disclaimer.
;   * Redistributions in binary form must reproduce the above copyright notice,
;     this list of conditions and the following disclaimer in the documentation
;     and/or other materials provided with the distribution.
;   * Neither the name of Intel Corporation nor the names of its contributors
;     may be used to endorse or promote products derived from this software
;     without specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

; AVX-512 SHA3/SHAKE one-shot implementation for Intel IPSec MB library.
; Utility functions are NOT exported (no MKGLOBAL) so they remain local.
;
; Public API:
;   sha3_224_avx512(input, inplen, output)
;   sha3_256_avx512(input, inplen, output)
;   sha3_384_avx512(input, inplen, output)
;   sha3_512_avx512(input, inplen, output)
;   shake128_avx512(input, inplen, output, outlen)
;   shake256_avx512(input, inplen, output, outlen)

default rel

%include "include/align_avx512.inc"
%include "include/sha3_common.inc"
%include "include/cet.inc"

section .text

; ============================================================
; Local (non-exported) Keccak utility functions
; ============================================================

;; Initialise keccak state in registers to zero
;; output: xmm0-xmm24
align_function
keccak_1600_init_state:
        vpxorq          xmm0,  xmm0, xmm0
        vpxorq          xmm1,  xmm1, xmm1
        vpxorq          xmm2,  xmm2, xmm2
        vmovdqa64       ymm3,  ymm0
        vmovdqa64       ymm4,  ymm0
        vmovdqa64       ymm5,  ymm0
        vmovdqa64       ymm6,  ymm0
        vmovdqa64       ymm7,  ymm0
        vmovdqa64       ymm8,  ymm0
        vmovdqa64       ymm9,  ymm0
        vmovdqa64       ymm10, ymm0
        vmovdqa64       ymm11, ymm0
        vmovdqa64       ymm12, ymm0
        vmovdqa64       ymm13, ymm0
        vmovdqa64       ymm14, ymm0
        vmovdqa64       ymm15, ymm0
        vmovdqa64       ymm16, ymm0
        vmovdqa64       ymm17, ymm0
        vmovdqa64       ymm18, ymm0
        vmovdqa64       ymm19, ymm0
        vmovdqa64       ymm20, ymm0
        vmovdqa64       ymm21, ymm0
        vmovdqa64       ymm22, ymm0
        vmovdqa64       ymm23, ymm0
        vmovdqa64       ymm24, ymm0
        ret

;; Loads keccak state from memory
;; input:  arg1 - state pointer
;; output: xmm0-xmm24
align_function
keccak_1600_load_state:
        vmovq   xmm0,  [arg1 + 8*0]
        vmovq   xmm1,  [arg1 + 8*1]
        vmovq   xmm2,  [arg1 + 8*2]
        vmovq   xmm3,  [arg1 + 8*3]
        vmovq   xmm4,  [arg1 + 8*4]
        vmovq   xmm5,  [arg1 + 8*5]
        vmovq   xmm6,  [arg1 + 8*6]
        vmovq   xmm7,  [arg1 + 8*7]
        vmovq   xmm8,  [arg1 + 8*8]
        vmovq   xmm9,  [arg1 + 8*9]
        vmovq   xmm10, [arg1 + 8*10]
        vmovq   xmm11, [arg1 + 8*11]
        vmovq   xmm12, [arg1 + 8*12]
        vmovq   xmm13, [arg1 + 8*13]
        vmovq   xmm14, [arg1 + 8*14]
        vmovq   xmm15, [arg1 + 8*15]
        vmovq   xmm16, [arg1 + 8*16]
        vmovq   xmm17, [arg1 + 8*17]
        vmovq   xmm18, [arg1 + 8*18]
        vmovq   xmm19, [arg1 + 8*19]
        vmovq   xmm20, [arg1 + 8*20]
        vmovq   xmm21, [arg1 + 8*21]
        vmovq   xmm22, [arg1 + 8*22]
        vmovq   xmm23, [arg1 + 8*23]
        vmovq   xmm24, [arg1 + 8*24]
        ret

;; Saves keccak state to memory
;; input:  arg1 - state pointer
;;         xmm0-xmm24 - keccak state registers
align_function
keccak_1600_save_state:
        vmovq   [arg1 + 8*0],  xmm0
        vmovq   [arg1 + 8*1],  xmm1
        vmovq   [arg1 + 8*2],  xmm2
        vmovq   [arg1 + 8*3],  xmm3
        vmovq   [arg1 + 8*4],  xmm4
        vmovq   [arg1 + 8*5],  xmm5
        vmovq   [arg1 + 8*6],  xmm6
        vmovq   [arg1 + 8*7],  xmm7
        vmovq   [arg1 + 8*8],  xmm8
        vmovq   [arg1 + 8*9],  xmm9
        vmovq   [arg1 + 8*10], xmm10
        vmovq   [arg1 + 8*11], xmm11
        vmovq   [arg1 + 8*12], xmm12
        vmovq   [arg1 + 8*13], xmm13
        vmovq   [arg1 + 8*14], xmm14
        vmovq   [arg1 + 8*15], xmm15
        vmovq   [arg1 + 8*16], xmm16
        vmovq   [arg1 + 8*17], xmm17
        vmovq   [arg1 + 8*18], xmm18
        vmovq   [arg1 + 8*19], xmm19
        vmovq   [arg1 + 8*20], xmm20
        vmovq   [arg1 + 8*21], xmm21
        vmovq   [arg1 + 8*22], xmm22
        vmovq   [arg1 + 8*23], xmm23
        vmovq   [arg1 + 8*24], xmm24
        ret

;; Add input data to state (partial block, length < rate)
;; input:
;;    r13  - state
;;    arg2 - message pointer (updated on output)
;;    r12  - length (clobbered on output)
;; clobbered: rax, k1, ymm31
align_function
keccak_1600_partial_add:
.ymm_loop:
        cmp             r12, 32
        jb              .lt_32_bytes
        vmovdqu64       ymm31, [arg2]
        vpxorq          ymm31, ymm31, [r13]
        vmovdqu64       [r13], ymm31
        add             arg2, 32
        add             r13, 32
        sub             r12, 32
        jz              .zero_bytes
        jmp             .ymm_loop
.lt_32_bytes:
        xor             rax, rax
        bts             rax, r12
        dec             rax
        kmovq           k1, rax
        vmovdqu8        ymm31{k1}{z}, [arg2]
        vpxorq          ymm31, ymm31, [r13]
        vmovdqu8        [r13]{k1}, ymm31
        add             arg2, r12
.zero_bytes:
        ret

;; Extract bytes from state
;; input:
;;    r13  - state
;;    r10  - output pointer (updated on output)
;;    r12  - length (clobbered on output)
;; clobbered: rax, k1, ymm31
align_function
keccak_1600_extract_bytes:
.extract_32_byte_loop:
        cmp             r12, 32
        jb              .extract_lt_32_bytes
        vmovdqu64       ymm31, [r13]
        vmovdqu64       [r10], ymm31
        add             r13, 32
        add             r10, 32
        sub             r12, 32
        jz              .zero_bytes
        jmp             .extract_32_byte_loop
.extract_lt_32_bytes:
        xor             rax, rax
        bts             rax, r12
        dec             rax
        kmovq           k1, rax
        vmovdqu8        ymm31{k1}{z}, [r13]
        vmovdqu8        [r10]{k1}, ymm31
        add             r10, r12
.zero_bytes:
        ret

;; Copy partial block message into temporary buffer, add padding byte and EOM bit
;;    r13  [in/out] destination pointer
;;    r12  [in/out] source pointer
;;    r11  [in/out] length in bytes
;;    r9   [in] rate
;;    r8   [in] pointer to the padding byte
;; clobbered: rax, r15, k1, k2, ymm31
align_function
keccak_1600_copy_with_padding:
        vpxorq          ymm31, ymm31, ymm31
        vmovdqu64       [r13 + 32*0], ymm31
        vmovdqu64       [r13 + 32*1], ymm31
        vmovdqu64       [r13 + 32*2], ymm31
        vmovdqu64       [r13 + 32*3], ymm31
        vmovdqu64       [r13 + 32*4], ymm31
        vmovdqu64       [r13 + 32*5], ymm31
        vmovdqu64       [r13 + 32*6], ymm31
        vmovdqu64       [r13 + 32*7], ymm31
        xor             r15, r15
align_loop
.copy32_loop:
        cmp             r11, 32
        jb              .partial32_with_padding
        vmovdqu64       ymm31, [r12 + r15]
        vmovdqu64       [r13 + r15], ymm31
        sub             r11, 32
        add             r15, 32
        jmp             .copy32_loop
.partial32_with_padding:
        xor             rax, rax
        bts             rax, r11
        kmovq           k2, rax
        dec             rax
        kmovq           k1, rax
        vmovdqu8        ymm31{k1}{z}, [r12 + r15]
        vpbroadcastb    ymm31{k2}, [r8]
        vmovdqu64       [r13 + r15], ymm31
        xor             byte [r13 + r9 - 1], 0x80
        ret

;; Copy partial digest to output buffer
;;    r13  [in/out] destination pointer
;;    r12  [in/out] source pointer
;;    arg2 [in/out] length in bytes
;; clobbered: rax, k1, ymm31
align_function
keccak_1600_copy_digest:
.copy32_loop:
        cmp             arg2, 32
        jb              .partial32
        vmovdqu64       ymm31, [r12]
        vmovdqu64       [r13], ymm31
        add             r13, 32
        add             r12, 32
        sub             arg2, 32
        jz              .done
        jmp             .copy32_loop
.partial32:
        xor             rax, rax
        bts             rax, arg2
        dec             rax
        kmovq           k1, rax
        vmovdqu8        ymm31{k1}{z}, [r12]
        vmovdqu8        [r13]{k1}, ymm31
.done:
        ret

;; Keccak-f[1600] permutation
;; YMM0-YMM24    [in/out]    keccak state
;; YMM25-YMM31   [clobbered] temporaries
;; R13           [clobbered] round counter
;; R14           [clobbered] round constant table pointer
align_function
keccak1600_block_64bit:
        mov             r13d, 24
        lea             r14, [rel SHA3RC]
align_loop
keccak_rnd_loop:
        ; Theta step
        vmovdqa64       ymm25, ymm0
        vpternlogq      ymm25, ymm5, ymm10, 0x96
        vmovdqa64       ymm26, ymm1
        vpternlogq      ymm26, ymm6, ymm11, 0x96
        vmovdqa64       ymm27, ymm2
        vpternlogq      ymm27, ymm7, ymm12, 0x96
        vmovdqa64       ymm28, ymm3
        vpternlogq      ymm28, ymm8, ymm13, 0x96
        vmovdqa64       ymm29, ymm4
        vpternlogq      ymm29, ymm9, ymm14, 0x96
        vpternlogq      ymm25, ymm15, ymm20, 0x96
        vpternlogq      ymm26, ymm16, ymm21, 0x96
        vpternlogq      ymm27, ymm17, ymm22, 0x96
        vpternlogq      ymm28, ymm18, ymm23, 0x96
        vprolq          ymm30, ymm26, 1
        vprolq          ymm31, ymm27, 1
        vpternlogq      ymm29, ymm19, ymm24, 0x96
        vpternlogq      ymm0,  ymm29, ymm30, 0x96
        vpternlogq      ymm10, ymm29, ymm30, 0x96
        vpternlogq      ymm20, ymm29, ymm30, 0x96
        vpternlogq      ymm5,  ymm29, ymm30, 0x96
        vpternlogq      ymm15, ymm29, ymm30, 0x96
        vprolq          ymm30, ymm28, 1
        vpternlogq      ymm6,  ymm25, ymm31, 0x96
        vpternlogq      ymm16, ymm25, ymm31, 0x96
        vpternlogq      ymm1,  ymm25, ymm31, 0x96
        vpternlogq      ymm11, ymm25, ymm31, 0x96
        vpternlogq      ymm21, ymm25, ymm31, 0x96
        vprolq          ymm31, ymm29, 1
        vpbroadcastq    ymm29, [r14]
        add             r14, 8
        vpternlogq      ymm12, ymm26, ymm30, 0x96
        vpternlogq      ymm7,  ymm26, ymm30, 0x96
        vpternlogq      ymm22, ymm26, ymm30, 0x96
        vpternlogq      ymm17, ymm26, ymm30, 0x96
        vpternlogq      ymm2,  ymm26, ymm30, 0x96
        vprolq          ymm30, ymm25, 1
        vpternlogq      ymm3,  ymm27, ymm31, 0x96
        vpternlogq      ymm13, ymm27, ymm31, 0x96
        vpternlogq      ymm23, ymm27, ymm31, 0x96
        vprolq          ymm6,  ymm6,  44
        vpternlogq      ymm18, ymm27, ymm31, 0x96
        vpternlogq      ymm8,  ymm27, ymm31, 0x96
        vprolq          ymm12, ymm12, 43
        vprolq          ymm18, ymm18, 21
        vpternlogq      ymm24, ymm28, ymm30, 0x96
        vprolq          ymm24, ymm24, 14
        vprolq          ymm3,  ymm3,  28
        vpternlogq      ymm9,  ymm28, ymm30, 0x96
        vprolq          ymm9,  ymm9,  20
        vprolq          ymm10, ymm10, 3
        vpternlogq      ymm19, ymm28, ymm30, 0x96
        vprolq          ymm16, ymm16, 45
        vprolq          ymm22, ymm22, 61
        vpternlogq      ymm4,  ymm28, ymm30, 0x96
        vprolq          ymm1,  ymm1,  1
        vprolq          ymm7,  ymm7,  6
        vpternlogq      ymm14, ymm28, ymm30, 0x96
        vprolq          ymm13, ymm13, 25
        vprolq          ymm19, ymm19, 8
        vmovdqa64       ymm30, ymm0
        vpternlogq      ymm30, ymm6, ymm12, 0xD2
        vprolq          ymm20, ymm20, 18
        vprolq          ymm4,  ymm4,  27
        vpxorq          ymm30, ymm30, ymm29
        vprolq          ymm5,  ymm5,  36
        vprolq          ymm11, ymm11, 10
        vmovdqa64       ymm31, ymm6
        vpternlogq      ymm31, ymm12, ymm18, 0xD2
        vprolq          ymm17, ymm17, 15
        vprolq          ymm23, ymm23, 56
        vpternlogq      ymm12, ymm18, ymm24, 0xD2
        vprolq          ymm2,  ymm2,  62
        vprolq          ymm8,  ymm8,  55
        vpternlogq      ymm18, ymm24, ymm0, 0xD2
        vprolq          ymm14, ymm14, 39
        vprolq          ymm15, ymm15, 41
        vpternlogq      ymm24, ymm0, ymm6, 0xD2
        vmovdqa64       ymm0,  ymm30
        vmovdqa64       ymm6,  ymm31
        vprolq          ymm21, ymm21, 2
        vmovdqa64       ymm30, ymm3
        vpternlogq      ymm30, ymm9, ymm10, 0xD2
        vmovdqa64       ymm31, ymm9
        vpternlogq      ymm31, ymm10, ymm16, 0xD2
        vpternlogq      ymm10, ymm16, ymm22, 0xD2
        vpternlogq      ymm16, ymm22, ymm3, 0xD2
        vpternlogq      ymm22, ymm3, ymm9, 0xD2
        vmovdqa64       ymm3,  ymm30
        vmovdqa64       ymm9,  ymm31
        vmovdqa64       ymm30, ymm1
        vpternlogq      ymm30, ymm7, ymm13, 0xD2
        vmovdqa64       ymm31, ymm7
        vpternlogq      ymm31, ymm13, ymm19, 0xD2
        vpternlogq      ymm13, ymm19, ymm20, 0xD2
        vpternlogq      ymm19, ymm20, ymm1, 0xD2
        vpternlogq      ymm20, ymm1, ymm7, 0xD2
        vmovdqa64       ymm1,  ymm30
        vmovdqa64       ymm7,  ymm31
        vmovdqa64       ymm30, ymm4
        vpternlogq      ymm30, ymm5, ymm11, 0xD2
        vmovdqa64       ymm31, ymm5
        vpternlogq      ymm31, ymm11, ymm17, 0xD2
        vpternlogq      ymm11, ymm17, ymm23, 0xD2
        vpternlogq      ymm17, ymm23, ymm4, 0xD2
        vpternlogq      ymm23, ymm4, ymm5, 0xD2
        vmovdqa64       ymm4,  ymm30
        vmovdqa64       ymm5,  ymm31
        vmovdqa64       ymm30, ymm2
        vpternlogq      ymm30, ymm8, ymm14, 0xD2
        vmovdqa64       ymm31, ymm8
        vpternlogq      ymm31, ymm14, ymm15, 0xD2
        vpternlogq      ymm14, ymm15, ymm21, 0xD2
        vpternlogq      ymm15, ymm21, ymm2, 0xD2
        vpternlogq      ymm21, ymm2, ymm8, 0xD2
        vmovdqa64       ymm2,  ymm30
        vmovdqa64       ymm8,  ymm31
        ;; pi(rho(theta(A)))
        vmovdqa64       ymm30, ymm3
        vmovdqa64       ymm3,  ymm18
        vmovdqa64       ymm18, ymm17
        vmovdqa64       ymm17, ymm11
        vmovdqa64       ymm11, ymm7
        vmovdqa64       ymm7,  ymm10
        vmovdqa64       ymm10, ymm1
        vmovdqa64       ymm1,  ymm6
        vmovdqa64       ymm6,  ymm9
        vmovdqa64       ymm9,  ymm22
        vmovdqa64       ymm22, ymm14
        vmovdqa64       ymm14, ymm20
        vmovdqa64       ymm20, ymm2
        vmovdqa64       ymm2,  ymm12
        vmovdqa64       ymm12, ymm13
        vmovdqa64       ymm13, ymm19
        vmovdqa64       ymm19, ymm23
        vmovdqa64       ymm23, ymm15
        vmovdqa64       ymm15, ymm4
        vmovdqa64       ymm4,  ymm24
        vmovdqa64       ymm24, ymm21
        vmovdqa64       ymm21, ymm8
        vmovdqa64       ymm8,  ymm16
        vmovdqa64       ymm16, ymm5
        vmovdqa64       ymm5,  ymm30
        dec r13d
        jnz keccak_rnd_loop
        ret

; ============================================================
; Public one-shot SHA3 / SHAKE functions
; ============================================================

;; void sha3_224_avx512(const uint8_t *input, size_t inplen, uint8_t *output)
align_function
MKGLOBAL(sha3_224_avx512,function,)
sha3_224_avx512:
        endbranch64
        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15
        sub     rsp, 8*32
        mov     rbx, arg3               ; save output ptr (Win: arg3=r8, clobbered by lea r8 below)
        mov     r9d, SHA3_224_RATE      ; Initialize the rate for SHA3-224
        mov     r11, arg2               ; copy message length to r11
        xor     r12, r12                ; zero message offset
        call    keccak_1600_init_state
align_loop
.loop:
        cmp     r11, r9
        jb      .loop_done
        ABSORB_BYTES arg1, r12, SHA3_224_RATE
        sub     r11, r9
        add     r12, r9
        call    keccak1600_block_64bit
        jmp     .loop
align_label
.loop_done:
        mov     r13, rsp
        add     r12, arg1
        lea     r8, [rel SHA3_MULTI_RATE_PADDING]
        call    keccak_1600_copy_with_padding
        ABSORB_BYTES rsp, 0, SHA3_224_RATE
        call    keccak1600_block_64bit
        ;; Extract 28 bytes: 3 full qwords (24 bytes) + lower dword of xmm3 (4 bytes)
        STATE_EXTRACT rbx, 0, 3
        vmovd   [rbx + 8*3], xmm3

        ;; Clear stack buffer (256 bytes) containing padded message block
        vpxorq          ymm0, ymm0, ymm0
        vmovdqu64       [rsp + 32*0], ymm0
        vmovdqu64       [rsp + 32*1], ymm0
        vmovdqu64       [rsp + 32*2], ymm0
        vmovdqu64       [rsp + 32*3], ymm0
        vmovdqu64       [rsp + 32*4], ymm0
        vmovdqu64       [rsp + 32*5], ymm0
        vmovdqu64       [rsp + 32*6], ymm0
        vmovdqu64       [rsp + 32*7], ymm0

        add     rsp, 8*32
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
        ret

;; void sha3_256_avx512(const uint8_t *input, size_t inplen, uint8_t *output)
align_function
MKGLOBAL(sha3_256_avx512,function,)
sha3_256_avx512:
        endbranch64
        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15
        sub     rsp, 8*32
        mov     rbx, arg3               ; save output ptr (Win: arg3=r8, clobbered by lea r8 below)
        mov     r9d, SHA3_256_RATE
        mov     r11, arg2
        xor     r12, r12
        call    keccak_1600_init_state
align_loop
.loop:
        cmp     r11, r9
        jb      .loop_done
        ABSORB_BYTES arg1, r12, SHA3_256_RATE
        sub     r11, r9
        add     r12, r9
        call    keccak1600_block_64bit
        jmp     .loop
align_label
.loop_done:
        mov     r13, rsp
        add     r12, arg1
        lea     r8, [rel SHA3_MULTI_RATE_PADDING]
        call    keccak_1600_copy_with_padding
        ABSORB_BYTES rsp, 0, SHA3_256_RATE
        call    keccak1600_block_64bit
        STATE_EXTRACT rbx, 0, (SHA3_256_DIGEST_SZ / 8)

        ;; Clear stack buffer (256 bytes) containing padded message block
        vpxorq          ymm0, ymm0, ymm0
        vmovdqu64       [rsp + 32*0], ymm0
        vmovdqu64       [rsp + 32*1], ymm0
        vmovdqu64       [rsp + 32*2], ymm0
        vmovdqu64       [rsp + 32*3], ymm0
        vmovdqu64       [rsp + 32*4], ymm0
        vmovdqu64       [rsp + 32*5], ymm0
        vmovdqu64       [rsp + 32*6], ymm0
        vmovdqu64       [rsp + 32*7], ymm0

        add     rsp, 8*32
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
        ret

;; void sha3_384_avx512(const uint8_t *input, size_t inplen, uint8_t *output)
align_function
MKGLOBAL(sha3_384_avx512,function,)
sha3_384_avx512:
        endbranch64
        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15
        sub     rsp, 8*32
        mov     rbx, arg3               ; save output ptr (Win: arg3=r8, clobbered by lea r8 below)
        mov     r9d, SHA3_384_RATE
        mov     r11, arg2
        xor     r12, r12
        call    keccak_1600_init_state
align_loop
.loop:
        cmp     r11, r9
        jb      .loop_done
        ABSORB_BYTES arg1, r12, SHA3_384_RATE
        sub     r11, r9
        add     r12, r9
        call    keccak1600_block_64bit
        jmp     .loop
align_label
.loop_done:
        mov     r13, rsp
        add     r12, arg1
        lea     r8, [rel SHA3_MULTI_RATE_PADDING]
        call    keccak_1600_copy_with_padding
        ABSORB_BYTES rsp, 0, SHA3_384_RATE
        call    keccak1600_block_64bit
        STATE_EXTRACT rbx, 0, (SHA3_384_DIGEST_SZ / 8)

        ;; Clear stack buffer (256 bytes) containing padded message block
        vpxorq          ymm0, ymm0, ymm0
        vmovdqu64       [rsp + 32*0], ymm0
        vmovdqu64       [rsp + 32*1], ymm0
        vmovdqu64       [rsp + 32*2], ymm0
        vmovdqu64       [rsp + 32*3], ymm0
        vmovdqu64       [rsp + 32*4], ymm0
        vmovdqu64       [rsp + 32*5], ymm0
        vmovdqu64       [rsp + 32*6], ymm0
        vmovdqu64       [rsp + 32*7], ymm0

        add     rsp, 8*32
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
        ret

;; void sha3_512_avx512(const uint8_t *input, size_t inplen, uint8_t *output)
align_function
MKGLOBAL(sha3_512_avx512,function,)
sha3_512_avx512:
        endbranch64
        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15
        sub     rsp, 8*32
        mov     rbx, arg3               ; save output ptr (Win: arg3=r8, clobbered by lea r8 below)
        mov     r9d, SHA3_512_RATE
        mov     r11, arg2
        xor     r12, r12
        call    keccak_1600_init_state
align_loop
.loop:
        cmp     r11, r9
        jb      .loop_done
        ABSORB_BYTES arg1, r12, SHA3_512_RATE
        sub     r11, r9
        add     r12, r9
        call    keccak1600_block_64bit
        jmp     .loop
align_label
.loop_done:
        mov     r13, rsp
        add     r12, arg1
        lea     r8, [rel SHA3_MULTI_RATE_PADDING]
        call    keccak_1600_copy_with_padding
        ABSORB_BYTES rsp, 0, SHA3_512_RATE
        call    keccak1600_block_64bit
        STATE_EXTRACT rbx, 0, (SHA3_512_DIGEST_SZ / 8)

        ;; Clear stack buffer (256 bytes) containing padded message block
        vpxorq          ymm0, ymm0, ymm0
        vmovdqu64       [rsp + 32*0], ymm0
        vmovdqu64       [rsp + 32*1], ymm0
        vmovdqu64       [rsp + 32*2], ymm0
        vmovdqu64       [rsp + 32*3], ymm0
        vmovdqu64       [rsp + 32*4], ymm0
        vmovdqu64       [rsp + 32*5], ymm0
        vmovdqu64       [rsp + 32*6], ymm0
        vmovdqu64       [rsp + 32*7], ymm0

        add     rsp, 8*32
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
        ret

;; void shake128_avx512(const uint8_t *input, size_t inplen,
;;                        uint8_t *output, size_t outlen)
align_function
MKGLOBAL(shake128_avx512,function,)
shake128_avx512:
        endbranch64
        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15
        sub     rsp, 8*32
        mov     r11, arg2
        mov     rbx, arg3               ; save output ptr (Win: arg3=r8, clobbered by lea r8 below)
        mov     rbp, arg4               ; save outlen   (Win: arg4=r9, clobbered by mov r9d,RATE)
        mov     r9d, SHAKE128_RATE
        xor     r12, r12
        xor     r10, r10
        call    keccak_1600_init_state
align_loop
.loop:
        cmp     r11, r9
        jb      .loop_done
        ABSORB_BYTES arg1, r12, SHAKE128_RATE
        sub     r11, r9
        add     r12, r9
        call    keccak1600_block_64bit
        jmp     .loop
align_label
.loop_done:
        mov     r13, rsp
        add     r12, arg1
        lea     r8, [rel SHAKE_MULTI_RATE_PADDING]
        call    keccak_1600_copy_with_padding
        ABSORB_BYTES rsp, 0, SHAKE128_RATE
        call    keccak1600_block_64bit
align_loop
.continuexof:
        cmp     rbp, r9
        jb      .store_last_block
        STATE_EXTRACT rbx, r10, (SHAKE128_RATE / 8)
        call    keccak1600_block_64bit
        sub     rbp, r9
        jz      .done
        add     r10, r9
        jmp     .continuexof
align_label
.store_last_block:
        STATE_EXTRACT rsp, 0, (SHAKE128_RATE / 8)
        lea     r13, [rbx + r10]
        mov     r12, rsp
        mov     arg2, rbp
        call    keccak_1600_copy_digest
.done:

        ;; Clear stack buffer (256 bytes) containing padded message / extracted state
        vpxorq          ymm0, ymm0, ymm0
        vmovdqu64       [rsp + 32*0], ymm0
        vmovdqu64       [rsp + 32*1], ymm0
        vmovdqu64       [rsp + 32*2], ymm0
        vmovdqu64       [rsp + 32*3], ymm0
        vmovdqu64       [rsp + 32*4], ymm0
        vmovdqu64       [rsp + 32*5], ymm0
        vmovdqu64       [rsp + 32*6], ymm0
        vmovdqu64       [rsp + 32*7], ymm0

        add     rsp, 8*32
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
        ret

;; void shake256_avx512(const uint8_t *input, size_t inplen,
;;                        uint8_t *output, size_t outlen)
align_function
MKGLOBAL(shake256_avx512,function,)
shake256_avx512:
        endbranch64
        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15
        sub     rsp, 32 * 8
        mov     r11, arg2
        mov     rbx, arg3               ; save output ptr (Win: arg3=r8, clobbered by lea r8 below)
        mov     rbp, arg4               ; save outlen   (Win: arg4=r9, clobbered by mov r9d,RATE)
        mov     r9d, SHAKE256_RATE
        xor     r12, r12
        xor     r10, r10
        call    keccak_1600_init_state
align_loop
.loop:
        cmp     r11, r9
        jb      .loop_done
        ABSORB_BYTES arg1, r12, SHAKE256_RATE
        sub     r11, r9
        add     r12, r9
        call    keccak1600_block_64bit
        jmp     .loop
align_label
.loop_done:
        mov     r13, rsp
        add     r12, arg1
        lea     r8, [rel SHAKE_MULTI_RATE_PADDING]
        call    keccak_1600_copy_with_padding
        ABSORB_BYTES rsp, 0, SHAKE256_RATE
        call    keccak1600_block_64bit
align_loop
.continuexof:
        cmp     rbp, r9
        jb      .store_last_block
        STATE_EXTRACT rbx, r10, (SHAKE256_RATE / 8)
        call    keccak1600_block_64bit
        sub     rbp, r9
        jz      .done
        add     r10, SHAKE256_RATE
        jmp     .continuexof
align_label
.store_last_block:
        STATE_EXTRACT rsp, 0, (SHAKE256_RATE / 8)
        lea     r13, [rbx + r10]
        mov     r12, rsp
        mov     arg2, rbp
        call    keccak_1600_copy_digest
.done:

        ;; Clear stack buffer (256 bytes) containing padded message / extracted state
        vpxorq          ymm0, ymm0, ymm0
        vmovdqu64       [rsp + 32*0], ymm0
        vmovdqu64       [rsp + 32*1], ymm0
        vmovdqu64       [rsp + 32*2], ymm0
        vmovdqu64       [rsp + 32*3], ymm0
        vmovdqu64       [rsp + 32*4], ymm0
        vmovdqu64       [rsp + 32*5], ymm0
        vmovdqu64       [rsp + 32*6], ymm0
        vmovdqu64       [rsp + 32*7], ymm0

        add     rsp, 32 * 8
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
        ret

section .rodata

align 64
SHA3RC:
        DQ 0x0000000000000001, 0x0000000000008082
        DQ 0x800000000000808a, 0x8000000080008000
        DQ 0x000000000000808b, 0x0000000080000001
        DQ 0x8000000080008081, 0x8000000000008009
        DQ 0x000000000000008a, 0x0000000000000088
        DQ 0x0000000080008009, 0x000000008000000a
        DQ 0x000000008000808b, 0x800000000000008b
        DQ 0x8000000000008089, 0x8000000000008003
        DQ 0x8000000000008002, 0x8000000000000080
        DQ 0x000000000000800a, 0x800000008000000a
        DQ 0x8000000080008081, 0x8000000000008080
        DQ 0x0000000080000001, 0x8000000080008008

SHA3_MULTI_RATE_PADDING:
        DB 0x06

SHAKE_MULTI_RATE_PADDING:
        DB 0x1F

section .note.GNU-stack noalloc noexec nowrite progbits
