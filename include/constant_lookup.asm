;;
;; Copyright (c) 2019, Intel Corporation
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

%include "include/os.asm"
%include "include/reg_sizes.asm"

section .data
default rel

align 16
idx_tab8:
        db 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
        db 0x8,  0x9,  0xA,  0xB,  0xC,  0xD,  0xE,  0xF,

align 16
add_16:
        db 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        db 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10

align 16
idx_tab16:
        dw 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7

align 16
add_8:
        dw 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8

align 16
idx_tab32:
        dd 0x0,  0x1,  0x2,  0x3

align 16
add_4:
        dd 0x4, 0x4, 0x4, 0x4

align 16
bcast_mask:
        db 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        db 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01

section .text

%ifdef LINUX
        %define arg1    rdi
        %define arg2    rsi
        %define arg3    rdx
%else
        %define arg1    rcx
        %define arg2    rdx
        %define arg3    r8
%endif

%define bcast_idx xmm0
%define xadd      xmm1
%define accum_val xmm2
%define xindices  xmm3
%define xtmp      xmm4
%define xtmp2     xmm5
%define tmp       r9
%define offset    r10

%define table   arg1
%define idx     arg2
%define size    arg3

; uint8_t lookup_8bit_sse(const void *table, const uint32_t idx, const uint32_t size);
; arg 1 : pointer to table to look up
; arg 2 : index to look up
; arg 3 : size of table to look up (multiple of 16 bytes)
MKGLOBAL(lookup_8bit_sse,function,internal)
lookup_8bit_sse:

        ;; Number of loop iters = matrix size / 4 (number of values in XMM)
        shr     size, 4
        je      exit8_sse

        xor     offset, offset

        ;; Broadcast idx to look up
        movd    bcast_idx, DWORD(idx)
        pxor    xtmp, xtmp
        pxor    accum_val, accum_val
        pshufb  bcast_idx, xtmp

        movdqa  xadd,     [rel add_16]
        movdqa  xindices, [rel idx_tab8]

loop8_sse:
        movdqa  xtmp, xindices

        ;; Compare indices with idx
        ;; This generates a mask with all 0s except for the position where idx matches (all 1s here)
        pcmpeqb xtmp, bcast_idx

        ;; Load next 16 values
        movdqa  xtmp2, [table + offset]

        ;; This generates data with all 0s except the value we are looking for in the index to look up
        pand    xtmp2, xtmp

        por     accum_val, xtmp2

        ;; Get next 16 indices
        paddb   xindices, xadd

        add     offset, 16
        dec     size

        jne     loop8_sse

        ;; Extract value from XMM register
        movdqa  xtmp, accum_val
        pslldq  xtmp, 8      ; shift left by 64 bits
        por     accum_val, xtmp

        movdqa  xtmp, accum_val
        pslldq  xtmp, 4      ; shift left by 32 bits
        por     accum_val, xtmp

        movdqa  xtmp, accum_val
        pslldq  xtmp, 2      ; shift left by 16 bits
        por     accum_val, xtmp

        movdqa  xtmp, accum_val
        pslldq  xtmp, 1      ; shift left by 8 bits
        por     accum_val, xtmp

        pextrb  rax, accum_val, 15

exit8_sse:
        ret

; uint8_t lookup_8bit_avx(const void *table, const uint32_t idx, const uint32_t size);
; arg 1 : pointer to table to look up
; arg 2 : index to look up
; arg 3 : size of table to look up (multiple of 16 bytes)
MKGLOBAL(lookup_8bit_avx,function,internal)
lookup_8bit_avx:
        ;; Number of loop iters = matrix size / 4 (number of values in XMM)
        shr     size, 4
        je      exit8_avx

        xor     offset, offset

        ;; Broadcast idx to look up
        vmovd   bcast_idx, DWORD(idx)
        vpxor   xtmp, xtmp
        vpxor   accum_val, accum_val
        vpshufb bcast_idx, xtmp

        vmovdqa xadd,     [rel add_16]
        vmovdqa xindices, [rel idx_tab8]

loop8_avx:
        ;; Compare indices with idx
        ;; This generates a mask with all 0s except for the position where idx matches (all 1s here)
        vpcmpeqb xtmp, xindices, bcast_idx

        ;; Load next 16 values
        vmovdqa xtmp2, [table + offset]

        ;; This generates data with all 0s except the value we are looking for in the index to look up
        vpand   xtmp2, xtmp

        vpor    accum_val, xtmp2

        ;; Get next 16 indices
        vpaddb  xindices, xadd

        add     offset, 16
        dec     size

        jne     loop8_avx

        ;; Extract value from XMM register
        vpslldq xtmp, accum_val, 8      ; shift left by 64 bits
        vpor    accum_val, xtmp

        vpslldq xtmp, accum_val, 4      ; shift left by 32 bits
        vpor    accum_val, xtmp

        vpslldq xtmp, accum_val, 2      ; shift left by 16 bits
        vpor    accum_val, xtmp

        vpslldq xtmp, accum_val, 1      ; shift left by 8 bits
        vpor    accum_val, xtmp

        vpextrb rax, accum_val, 15

exit8_avx:

        ret

; uint8_t lookup_16bit_sse(const void *table, const uint32_t idx, const uint32_t size);
; arg 1 : pointer to table to look up
; arg 2 : index to look up
; arg 3 : size of table to look up
MKGLOBAL(lookup_16bit_sse,function,internal)
lookup_16bit_sse:

        ;; Number of loop iters = matrix size / 8 (number of values in XMM)
        shr     size, 3
        je      exit16_sse

        xor     offset, offset

        ;; Broadcast idx to look up
        movd    bcast_idx, DWORD(idx)
        movdqa  xtmp, [rel bcast_mask]
        pxor    accum_val, accum_val
        pshufb  bcast_idx, xtmp

        movdqa  xadd,     [rel add_8]
        movdqa  xindices, [rel idx_tab16]

loop16_sse:

        movdqa  xtmp, xindices

        ;; Compare indices with idx
        ;; This generates a mask with all 0s except for the position where idx matches (all 1s here)
        pcmpeqw xtmp, bcast_idx

        ;; Load next 8 values
        movdqa  xtmp2, [table + offset]

        ;; This generates data with all 0s except the value we are looking for in the index to look up
        pand    xtmp2, xtmp

        por     accum_val, xtmp2

        ;; Get next 8 indices
        paddw   xindices, xadd
        add     offset, 16
        dec     size

        jne     loop16_sse

        ;; Extract value from XMM register
        movdqa  xtmp, accum_val
        pslldq  xtmp, 8      ; shift left by 64 bits
        por     accum_val, xtmp

        movdqa  xtmp, accum_val
        pslldq  xtmp, 4      ; shift left by 32 bits
        por     accum_val, xtmp

        movdqa  xtmp, accum_val
        pslldq  xtmp, 2      ; shift left by 16 bits
        por     accum_val, xtmp

        pextrw  rax, accum_val, 7

exit16_sse:
        ret

; uint8_t lookup_16bit_avx(const void *table, const uint32_t idx, const uint32_t size);
; arg 1 : pointer to table to look up
; arg 2 : index to look up
; arg 3 : size of table to look up
MKGLOBAL(lookup_16bit_avx,function,internal)
lookup_16bit_avx:

        ;; Number of loop iters = matrix size / 8 (number of values in XMM)
        shr     size, 3
        je      exit16_avx

        xor     offset, offset

        ;; Broadcast idx to look up
        vmovd   bcast_idx, DWORD(idx)
        vmovdqa xtmp, [rel bcast_mask]
        vpxor   accum_val, accum_val
        vpshufb bcast_idx, xtmp

        vmovdqa xadd,     [rel add_8]
        vmovdqa xindices, [rel idx_tab16]

loop16_avx:

        ;; Compare indices with idx
        ;; This generates a mask with all 0s except for the position where idx matches (all 1s here)
        vpcmpeqw xtmp, xindices, bcast_idx

        ;; Load next 16 values
        vmovdqa xtmp2, [table + offset]

        ;; This generates data with all 0s except the value we are looking for in the index to look up
        vpand   xtmp2, xtmp

        vpor    accum_val, xtmp2

        ;; Get next 8 indices
        vpaddw  xindices, xadd
        add     offset, 16
        dec     size

        jne     loop16_avx

        ;; Extract value from XMM register
        vpslldq xtmp, accum_val, 8 ; shift left by 64 bits
        vpor    accum_val, xtmp

        vpslldq xtmp, accum_val, 4 ; shift left by 32 bits
        vpor    accum_val, xtmp

        vpslldq xtmp, accum_val, 2 ; shift left by 16 bits
        vpor    accum_val, xtmp

        vpextrw rax, accum_val, 7

exit16_avx:
        ret

; uint32_t lookup_32bit_sse(const void *table, const uint32_t idx, const uint32_t size);
; arg 1 : pointer to table to look up
; arg 2 : index to look up
; arg 3 : size of table to look up
MKGLOBAL(lookup_32bit_sse,function,internal)
lookup_32bit_sse:

        ;; Number of loop iters = matrix size / 4 (number of values in XMM)
        shr     size, 2
        je      exit32_sse

        xor     offset, offset

        ;; Broadcast idx to look up
        movd    bcast_idx, DWORD(idx)
        pxor    accum_val, accum_val
        pshufd  bcast_idx, bcast_idx, 0

        movdqa  xadd,     [rel add_4]
        movdqa  xindices, [rel idx_tab32]

loop32_sse:
        movdqa  xtmp, xindices

        ;; Compare indices with idx
        ;; This generates a mask with all 0s except for the position where idx matches (all 1s here)
        pcmpeqd xtmp, bcast_idx

        ;; Load next 4 values
        movdqa  xtmp2, [table + offset]

        ;; This generates data with all 0s except the value we are looking for in the index to look up
        pand    xtmp2, xtmp

        por     accum_val, xtmp2

        ;; Get next 4 indices
        paddd   xindices, xadd
        add     offset, 16
        dec     size

        jne     loop32_sse

        ;; Extract value from XMM register
        movdqa  xtmp, accum_val
        psrldq  xtmp, 8      ; shift right by 64 bits
        por     accum_val, xtmp

        movdqa  xtmp, accum_val
        psrldq  xtmp, 4      ; shift right by 32 bits
        por     accum_val, xtmp

        movd    eax, accum_val

exit32_sse:
        ret


; uint32_t lookup_32bit_avx(const void *table, const uint32_t idx, const uint32_t size);
; arg 1 : pointer to table to look up
; arg 2 : index to look up
; arg 3 : size of table to look up
MKGLOBAL(lookup_32bit_avx,function,internal)
lookup_32bit_avx:
        ;; Number of loop iters = matrix size / 4 (number of values in XMM)
        shr     size, 2
        je      exit32_avx

        xor     offset, offset

        ;; Broadcast idx to look up
        vmovd   bcast_idx, DWORD(idx)
        vpxor   accum_val, accum_val
        vpshufd bcast_idx, bcast_idx, 0

        vmovdqa xadd,     [rel add_4]
        vmovdqa xindices, [rel idx_tab32]

loop32_avx:
        ;; Compare indices with idx
        ;; This generates a mask with all 0s except for the position where idx matches (all 1s here)
        vpcmpeqd xtmp, xindices, bcast_idx

        ;; Load next 4 values
        vmovdqa xtmp2, [table + offset]

        ;; This generates data with all 0s except the value we are looking for in the index to look up
        vpand   xtmp2, xtmp

        vpor    accum_val, xtmp2

        ;; Get next 4 indices
        vpaddd  xindices, xadd
        add     offset, 16
        dec     size

        jne     loop32_avx

        ;; Extract value from XMM register
        vpsrldq xtmp, accum_val, 8 ; shift right by 64 bits
        vpor    accum_val, xtmp

        vpsrldq xtmp, accum_val, 4 ; shift right by 32 bits
        vpor    accum_val, xtmp

        vmovd   eax, accum_val

exit32_avx:
        ret


%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
