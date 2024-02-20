;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2019-2023, Intel Corporation All rights reserved.
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

%use smartalign

%ifdef LINUX
;;; macro to declare global symbols
;;;  - name : symbol name
;;;  - type : function or data
;;;  - scope : internal, private, default
%define MKGLOBAL(name,type,scope) global name %+ : %+ type scope

;;; ABI function arguments
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx

%define arg1d   edi
%define arg2d   esi
%define arg3d   edx
%define arg4d   ecx
%endif

%ifdef WIN_ABI
;;; macro to declare global symbols
;;;  - name : symbol name
;;;  - type : function or data
;;;  - scope : internal, private, default (ignored in win64 coff format)
%define MKGLOBAL(name,type,scope) global name

;;; ABI function arguments
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9

%define arg1d   ecx
%define arg2d   edx
%define arg3d   r8d
%define arg4d   r9d
%endif

;; External symbols
extern pattern8_cipher_key
extern pattern8_auth_key
extern pattern8_plain_text

;; Data section
section .data
default rel

align 16
        db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
shiftr:
        db 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        db 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff


section .bss
default rel

MKGLOBAL(gps,data,)
align 8
gps:	        resq	14

MKGLOBAL(simd_regs,data,)
alignb 64
simd_regs:	resb	32*64

section .text

;; ymm0 [in] pattern 1
;; ymm1 [in] pattern 2
;; ymm2 [in] pattern 3
;; xmm11 [in] data block (old)
;; xmm12 [in] data block (new)
;; ymm8 [in/out] - mask for pattern 1 matches
;; ymm9 [in/out] - mask for pattern 2 matches
;; ymm10 [in/out] - mask for pattern 3 matches
;; clobbers ymm3-ymm6
align 32
mem_search_helper_avx:
        vpalignr        xmm3, xmm12, xmm11, 9
        vpcmpeqq        xmm4, xmm0, xmm3
        vpcmpeqq        xmm5, xmm1, xmm3
        vpcmpeqq        xmm6, xmm2, xmm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        xmm3, xmm12, xmm11, 10
        vpcmpeqq        xmm4, xmm0, xmm3
        vpcmpeqq        xmm5, xmm1, xmm3
        vpcmpeqq        xmm6, xmm2, xmm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        xmm3, xmm12, xmm11, 11
        vpcmpeqq        xmm4, xmm0, xmm3
        vpcmpeqq        xmm5, xmm1, xmm3
        vpcmpeqq        xmm6, xmm2, xmm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        xmm3, xmm12, xmm11, 12
        vpcmpeqq        xmm4, xmm0, xmm3
        vpcmpeqq        xmm5, xmm1, xmm3
        vpcmpeqq        xmm6, xmm2, xmm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        xmm3, xmm12, xmm11, 13
        vpcmpeqq        xmm4, xmm0, xmm3
        vpcmpeqq        xmm5, xmm1, xmm3
        vpcmpeqq        xmm6, xmm2, xmm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        xmm3, xmm12, xmm11, 14
        vpcmpeqq        xmm4, xmm0, xmm3
        vpcmpeqq        xmm5, xmm1, xmm3
        vpcmpeqq        xmm6, xmm2, xmm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        xmm3, xmm12, xmm11, 15
        vpcmpeqq        xmm4, xmm0, xmm3
        vpcmpeqq        xmm5, xmm1, xmm3
        vpcmpeqq        xmm6, xmm2, xmm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpcmpeqq        xmm4, xmm0, xmm12
        vpcmpeqq        xmm5, xmm1, xmm12
        vpcmpeqq        xmm6, xmm2, xmm12
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6
        ret

;; Loads 0 to 8 bytes (arg2) from arg1 location
;; arg1 [in] current data pointer
;; arg2 [in] number of bytes to load
;; r15  [clobbered] temporary register
;; xmm5 [out] read data block (1 to 7 bytes)
;; xmm6 [clobbered] temporary read
align 32
mem_search_load_0_to_8_bytes:
        ;; read the rest of the bytes in the buffer
        ;; - read 8 from the end and remove overlapping bytes
        ;; - it is safe to do this read because message length is
        ;;   guaranteed to be >= 8 bytes
        lea             r15, [arg1 + arg2]
        vmovq           xmm5, [r15 - 8]

        lea             r15, [shiftr]
        sub             r15, arg2
        vmovdqu         xmm6, [r15]
        vpshufb         xmm5, xmm5, xmm6
        ret

;; uint64_t mem_search_avx2(const void *mem, const size_t size)
MKGLOBAL(mem_search_avx2,function,)
align 32
mem_search_avx2:
        push            r12
        push            r13
        push            r14
        push            r15

%ifdef WIN_ABI
        sub             rsp, 7 * 16
        vmovdqu         [rsp + 0*16], xmm6
        vmovdqu         [rsp + 1*16], xmm7
        vmovdqu         [rsp + 2*16], xmm8
        vmovdqu         [rsp + 3*16], xmm9
        vmovdqu         [rsp + 4*16], xmm10
        vmovdqu         [rsp + 5*16], xmm11
        vmovdqu         [rsp + 6*16], xmm12
%endif
        ;; clear result registers first; this is to return 0 if length is < 8
        vpxor           ymm8, ymm8, ymm8
        vpxor           ymm9, ymm9, ymm9
        vpxor           ymm10, ymm10, ymm10

        ;; quick length check
        cmp             arg2, 8
        jb              .exit

        ;; prepare data for the main loop
        vpxor           xmm11, xmm11, xmm11     ;; clear the data block (old)
        vpxor           xmm12, xmm12, xmm12     ;; clear the data block (new)

        vpbroadcastq    ymm0, [pattern8_cipher_key]
        vpbroadcastq    ymm1, [pattern8_auth_key]
        vpbroadcastq    ymm2, [pattern8_plain_text]

        cmp             arg2, 32 + 8
        jb              .loop16

align 32
.loop32:
        vmovdqu         ymm11, [arg1]

        vextracti128    xmm12, ymm11, 1
        vmovq           xmm3, [arg1 + 32]
        vinserti128     ymm12, xmm3, 1

        vpcmpeqq        ymm4, ymm0, ymm11
        vpcmpeqq        ymm5, ymm1, ymm11
        vpcmpeqq        ymm6, ymm2, ymm11
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        ymm3, ymm12, ymm11, 1
        vpcmpeqq        ymm4, ymm0, ymm3
        vpcmpeqq        ymm5, ymm1, ymm3
        vpcmpeqq        ymm6, ymm2, ymm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        ymm3, ymm12, ymm11, 2
        vpcmpeqq        ymm4, ymm0, ymm3
        vpcmpeqq        ymm5, ymm1, ymm3
        vpcmpeqq        ymm6, ymm2, ymm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        ymm3, ymm12, ymm11, 3
        vpcmpeqq        ymm4, ymm0, ymm3
        vpcmpeqq        ymm5, ymm1, ymm3
        vpcmpeqq        ymm6, ymm2, ymm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        ymm3, ymm12, ymm11, 4
        vpcmpeqq        ymm4, ymm0, ymm3
        vpcmpeqq        ymm5, ymm1, ymm3
        vpcmpeqq        ymm6, ymm2, ymm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        ymm3, ymm12, ymm11, 5
        vpcmpeqq        ymm4, ymm0, ymm3
        vpcmpeqq        ymm5, ymm1, ymm3
        vpcmpeqq        ymm6, ymm2, ymm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        ymm3, ymm12, ymm11, 6
        vpcmpeqq        ymm4, ymm0, ymm3
        vpcmpeqq        ymm5, ymm1, ymm3
        vpcmpeqq        ymm6, ymm2, ymm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        vpalignr        ymm3, ymm12, ymm11, 7
        vpcmpeqq        ymm4, ymm0, ymm3
        vpcmpeqq        ymm5, ymm1, ymm3
        vpcmpeqq        ymm6, ymm2, ymm3
        vpor            ymm8, ymm8, ymm4
        vpor            ymm9, ymm9, ymm5
        vpor            ymm10, ymm10, ymm6

        add             arg1, 32
        sub             arg2, 32
        cmp             arg2, 32 + 8
        jae             .loop32

        vmovdqu         xmm11, [arg1 - 16]

.loop16:
        cmp             arg2, 16
        jb              .process_below_16bytes
        vmovdqu         xmm12, [arg1]
        call            mem_search_helper_avx
        vmovdqa         xmm11, xmm12
        add             arg1, 16
        sub             arg2, 16
        jmp             .loop16

.process_below_16bytes:
        or              arg2, arg2
        jz              .exit

        cmp             arg2, 8
        jb              .process_below_8bytes

        ;; load 8 bytes
        vmovq           xmm4, [arg1]
        add             arg1, 8
        sub             arg2, 8
        ;; xmm4 = MSB [ ZERO 64-bit | full 64-bit data block ] LSB
        jz              .run_final_check
        ;; load bytes 9 to 15
        call            mem_search_load_0_to_8_bytes
        vpunpcklqdq     xmm4, xmm4, xmm5
        ;; xmm4 = MSB [ partial 64-bit data block | full 64-bit data block ] LSB
        jmp             .run_final_check

.process_below_8bytes:
        call            mem_search_load_0_to_8_bytes
        vmovdqa         xmm4, xmm5
        ;; xmm4 = MSB [ ZERO 64-bits | partial 64-bit data block ] LSB
        ;; fall through to run the final check

.run_final_check:
        vmovdqa         xmm12, xmm4
        call            mem_search_helper_avx

.exit:
        ;; fold the result masks to get the return status
        vpmovmskb       eax, ymm8
        vpmovmskb       r12d, ymm9
        vpmovmskb       r13d, ymm10
        or              eax, r12d
        or              eax, r13d

        vzeroupper

        ;; rax == 0 OK
        ;; rax != 0 match found (RAX = address to start precise scalar check)
%ifdef WIN_ABI
        vmovdqu         xmm6, [rsp + 0*16]
        vmovdqu         xmm7, [rsp + 1*16]
        vmovdqu         xmm8, [rsp + 2*16]
        vmovdqu         xmm9, [rsp + 3*16]
        vmovdqu         xmm10, [rsp + 4*16]
        vmovdqu         xmm11, [rsp + 5*16]
        vmovdqu         xmm12, [rsp + 6*16]
        add             rsp, 7 * 16
%endif
        pop             r15
        pop             r14
        pop             r13
        pop             r12
        ret

;; uint32_t avx_sse_transition_check(void)
MKGLOBAL(avx_sse_transition_check,function,)
align 16
avx_sse_transition_check:
        mov     ecx, 1
        xgetbv
        ;; result goes to edx:eax
        ;; we care about bits 2 and 6 only
        and     eax, (1 << 2) | (1 << 6)
        ret

;; void *nosimd_memcpy(void *dst, const void *src, size_t n)
MKGLOBAL(nosimd_memcpy,function,)
align 16
nosimd_memcpy:
        pushfq
        push    arg1
        cld                     ;; increment dst/src pointers

%ifdef WIN_ABI
        push    rdi
        push    rsi
        mov     rdi, arg1       ;; arg1 = rcx
        mov     rsi, arg2       ;; arg2 = rdx
        mov     rcx, arg3       ;; arg3 = r8
        rep movsb
        pop     rsi
        pop     rdi
%endif

%ifdef LINUX
        ;; rdi = arg1
        ;; rsi = arg2
        mov     rcx, arg3       ;; arg3 = rdx
        rep movsb
%endif

        pop     rax             ;; return `dst`
        popfq
        ret

;; void *nosimd_memset(void *p, int c, size_t n)
MKGLOBAL(nosimd_memset,function,)
align 16
nosimd_memset:
        pushfq
        push    arg1
        cld                     ;; increment dst pointer

%ifdef WIN_ABI
        push    rdi
        mov     rdi, arg1       ;; arg1 = rcx
        mov     rax, arg2       ;; arg2 = rdx
        mov     rcx, arg3       ;; arg3 = r8
        rep stosb
        pop     rdi
%endif

%ifdef LINUX
        ;; rdi = arg1
        mov     rax, arg2       ;; arg2 = rsi
        mov     rcx, arg3       ;; arg3 = rdx
        rep stosb
%endif

        pop     rax             ;; return `p`
        popfq
        ret

;; Returns RSP pointer with the value BEFORE the call, so 8 bytes need
;; to be added
MKGLOBAL(rdrsp,function,)
align 16
rdrsp:
        lea rax, [rsp + 8]
        ret

MKGLOBAL(dump_gps,function,)
align 16
dump_gps:

        mov     [rel gps],      rax
        mov     [rel gps + 8],  rbx
        mov     [rel gps + 16], rcx
        mov     [rel gps + 24], rdx
        mov     [rel gps + 32], rdi
        mov     [rel gps + 40], rsi

%assign i 8
%assign j 0
%rep 8
        mov     [rel gps + 48 + j], r %+i
%assign i (i+1)
%assign j (j+8)
%endrep

        ret

MKGLOBAL(dump_xmms_sse,function,)
align 16
dump_xmms_sse:

%assign i 0
%assign j 0
%rep 16
        movdqa  [rel simd_regs + j], xmm %+i
%assign i (i+1)
%assign j (j+16)
%endrep

        ret

MKGLOBAL(dump_xmms_avx,function,)
align 16
dump_xmms_avx:

%assign i 0
%assign j 0
%rep 16
        vmovdqa [rel simd_regs + j], xmm %+i
%assign i (i+1)
%assign j (j+16)
%endrep

        ret

MKGLOBAL(dump_ymms,function,)
align 16
dump_ymms:

%assign i 0
%assign j 0
%rep 16
        vmovdqa [rel simd_regs + j], ymm %+i
%assign i (i+1)
%assign j (j+32)
%endrep

        ret

MKGLOBAL(dump_zmms,function,)
align 16
dump_zmms:

%assign i 0
%assign j 0
%rep 32
        vmovdqa64 [rel simd_regs + j], zmm %+i
%assign i (i+1)
%assign j (j+64)
%endrep

        ret

;
; This function clears all scratch XMM registers
;
; void clr_scratch_xmms_sse(void)
MKGLOBAL(clr_scratch_xmms_sse,function,internal)
align 16
clr_scratch_xmms_sse:

%ifdef LINUX
%assign i 0
%rep 16
        pxor    xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
; On Windows, XMM0-XMM5 registers are scratch registers
%else
%assign i 0
%rep 6
        pxor    xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
%endif ; LINUX

        ret

;
; This function clears all scratch XMM registers
;
; It should be called before restoring the XMM registers
; for Windows (XMM6-XMM15)
;
; void clr_scratch_xmms_avx(void)
MKGLOBAL(clr_scratch_xmms_avx,function,internal)
align 16
clr_scratch_xmms_avx:

%ifdef LINUX
        vzeroall
; On Windows, XMM0-XMM5 registers are scratch registers
%else
%assign i 0
%rep 6
        vpxor   xmm %+ i, xmm %+ i
%assign i (i+1)
%endrep
%endif ; LINUX

        ret

;
; This function clears all scratch YMM registers
;
; It should be called before restoring the XMM registers
; for Windows (XMM6-XMM15)
;
; void clr_scratch_ymms(void)
MKGLOBAL(clr_scratch_ymms,function,internal)
align 16
clr_scratch_ymms:
; On Linux, all YMM registers are scratch registers
%ifdef LINUX
        vzeroall
; On Windows, YMM0-YMM5 registers are scratch registers.
; YMM6-YMM15 upper 128 bits are scratch registers too, but
; the lower 128 bits are to be restored after calling these function
; which clears the upper bits too.
%else
%assign i 0
%rep 6
        vpxor   ymm %+ i, ymm %+ i
%assign i (i+1)
%endrep
%endif ; LINUX

        ret

;
; This function clears all scratch ZMM registers
;
; It should be called before restoring the XMM registers
; for Windows (XMM6-XMM15). YMM registers are used
; on purpose, since XOR'ing YMM registers is faster
; than XOR'ing ZMM registers, and the operation clears
; also the upper 256 bits
;
; void clr_scratch_zmms(void)
MKGLOBAL(clr_scratch_zmms,function,internal)
align 16
clr_scratch_zmms:

; On Linux, all ZMM registers are scratch registers
%ifdef LINUX
        vzeroall
        ;; vzeroall only clears the first 16 ZMM registers
%assign i 16
%rep 16
        vpxorq  ymm %+ i, ymm %+ i
%assign i (i+1)
%endrep
; On Windows, ZMM0-ZMM5 and ZMM16-ZMM31 registers are scratch registers.
; ZMM6-ZMM15 upper 384 bits are scratch registers too, but
; the lower 128 bits are to be restored after calling these function
; which clears the upper bits too.
%else
%assign i 0
%rep 6
        vpxorq  ymm %+ i, ymm %+ i
%assign i (i+1)
%endrep

%assign i 16
%rep 16
        vpxorq  ymm %+ i, ymm %+ i
%assign i (i+1)
%endrep
%endif ; LINUX

        ret

;;
;; Wrapper for CPUID opcode
;;
;; Parameters:
;;    [in] leaf    - CPUID leaf number (EAX)
;;    [in] subleaf - CPUID sub-leaf number (ECX)
;;    [out] out    - registers structure to store results of CPUID into
;;
;; void misc_cpuid(const unsigned leaf, const unsigned subleaf, struct cpuid_regs *out)

MKGLOBAL(misc_cpuid,function,internal)
misc_cpuid:
        push    rbx

        mov     r11, arg3       ;; arg3 will get overwritten by cpuid on sysv
        mov     eax, arg1d
        mov     ecx, arg2d

        cpuid

        mov     [r11 + 0*4], eax
        mov     [r11 + 1*4], ebx
        mov     [r11 + 2*4], ecx
        mov     [r11 + 3*4], edx

        pop     rbx
        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
