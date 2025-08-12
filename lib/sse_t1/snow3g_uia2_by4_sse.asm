;;
;; Copyright (c) 2021-2024, Intel Corporation
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
%include "include/reg_sizes.inc"
%include "include/cet.inc"
%include "include/memcpy.inc"
%include "include/const.inc"
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
%define qword_len       r12
%define offset          r10
%define tmp             r10
%define tmp2            arg4
%define tmp3            r11
%define tmp4            r13
%define tmp5            r14
%define tmp6            r15
%define in_ptr          arg1
%define KS              arg2
%define bit_len         arg3
%define end_offset      tmp3

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

align 16
clear_hi64:
dq      0xffffffffffffffff, 0x0000000000000000

align 16
clear_low32:
dd      0x00000000, 0xffffffff, 0xffffffff, 0xffffffff

mksection .text

%ifidn __OUTPUT_FORMAT__, win64
        %define XMM_STORAGE     16*10
        %define GP_STORAGE      8*8
%else
        %define XMM_STORAGE     0
        %define GP_STORAGE      6*8
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
        movdqa [rsp + 3*16], xmm9
        movdqa [rsp + 4*16], xmm10
        movdqa [rsp + 5*16], xmm11
        movdqa [rsp + 6*16], xmm12
        movdqa [rsp + 7*16], xmm13
        movdqa [rsp + 8*16], xmm14
        movdqa [rsp + 9*16], xmm15
        mov     [rsp + GP_OFFSET + 48], rdi
        mov     [rsp + GP_OFFSET + 56], rsi
%endif
        mov     [rsp + GP_OFFSET],      r12
        mov     [rsp + GP_OFFSET + 8],  r13
        mov     [rsp + GP_OFFSET + 16], r14
        mov     [rsp + GP_OFFSET + 24], r15
        mov     [rsp + GP_OFFSET + 32], rbx
        mov     [rsp + GP_OFFSET + 40], r11 ;; rsp pointer
%endmacro

%macro FUNC_RESTORE 0

%ifidn __OUTPUT_FORMAT__, win64
        movdqa xmm6,  [rsp + 0*16]
        movdqa xmm7,  [rsp + 1*16]
        movdqa xmm8,  [rsp + 2*16]
        movdqa xmm9,  [rsp + 3*16]
        movdqa xmm10, [rsp + 4*16]
        movdqa xmm11, [rsp + 5*16]
        movdqa xmm12, [rsp + 6*16]
        movdqa xmm13, [rsp + 7*16]
        movdqa xmm14, [rsp + 8*16]
        movdqa xmm15, [rsp + 9*16]
        mov     rdi, [rsp + GP_OFFSET + 48]
        mov     rsi, [rsp + GP_OFFSET + 56]
%endif
        mov     r12, [rsp + GP_OFFSET]
        mov     r13, [rsp + GP_OFFSET + 8]
        mov     r14, [rsp + GP_OFFSET + 16]
        mov     r15, [rsp + GP_OFFSET + 24]
        mov     rbx, [rsp + GP_OFFSET + 32]
        mov     rsp, [rsp + GP_OFFSET + 40]
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

;; uint32_t
;; snow3g_f9_1_buffer_internal_sse(const uint64_t *pBufferIn,
;;                                 const uint32_t KS[5],
;;                                 const uint64_t lengthInBits);
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

        xor     offset, offset

        mov     qword_len, bit_len              ;; lenInBits -> lenInQwords
        shr     qword_len, 6
        je      partial_blk

        ;; Process 8 blocks at a time only for messages >= 320 bytes (40 qwords)
        cmp     qword_len, 8
        jb      check_4_blocks

        ;; Setup powers for 8-block parallel processing
        movdqa  xmm1, P1
        MUL_AND_REDUCE_TO_64 xmm1, P1, xmm4     ;; xmm1 = P2
        movdqa  xmm5, xmm1
        MUL_AND_REDUCE_TO_64 xmm5, P1, xmm4     ;; xmm5 = P3
        movq    xmm5, xmm5
        movdqa  xmm3, xmm5
        MUL_AND_REDUCE_TO_64 xmm3, P1, xmm4     ;; xmm3 = P4
        
        ;; Compute additional powers P5, P6, P7, P8
        movdqa  xmm9, xmm3
        MUL_AND_REDUCE_TO_64 xmm9, P1, xmm4     ;; xmm9 = P5
        movdqa  xmm10, xmm9
        MUL_AND_REDUCE_TO_64 xmm10, P1, xmm4    ;; xmm10 = P6
        movdqa  xmm11, xmm10
        MUL_AND_REDUCE_TO_64 xmm11, P1, xmm4    ;; xmm11 = P7
        movdqa  xmm12, xmm11
        MUL_AND_REDUCE_TO_64 xmm12, P1, xmm4    ;; xmm12 = P8

        ;; Pack powers for parallel processing
        movdqa     xmm0, P1
        punpcklqdq xmm0, xmm1                   ;; xmm0 = P1|P2
        movdqa     xmm1, xmm5
        punpcklqdq xmm1, xmm3                   ;; xmm1 = P3|P4
        movdqa     xmm13, xmm9
        punpcklqdq xmm13, xmm10                 ;; xmm13 = P5|P6
        movdqa     xmm14, xmm11
        punpcklqdq xmm14, xmm12                 ;; xmm14 = P7|P8

        mov     end_offset, qword_len
        and     end_offset, 0xfffffffffffffff8  ;; round down to nearest 8 blocks

align_loop
start_8_blk_loop:
        ;; Load all 8 blocks (64 bytes total)
        movdqu          xmm3, [in_ptr + offset * 8]      ;; blocks 1,2
        movdqu          xmm4, [in_ptr + offset * 8 + 16] ;; blocks 3,4
        movdqu          xmm5, [in_ptr + offset * 8 + 32] ;; blocks 5,6
        movdqu          xmm15, [in_ptr + offset * 8 + 48];; blocks 7,8

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

        add     	offset, 8                                ;; move to next 8 blocks
        cmp     	end_offset, offset
        jne     	start_8_blk_loop                         ;; process next 8 blocks

align_label
check_4_blocks:
        mov     	end_offset, qword_len
        and     	end_offset, 0xfffffffffffffffc  ;; round down to nearest 4 blocks
        cmp     	end_offset, offset              ;; check if any 4-block groups left
        jbe     	single_blk_chk

        ;; Setup powers if we didn't come from 8-block processing
        or     		offset, offset
        jne     	start_4_blk_loop                      ;; powers already setup from 8-block loop
        
        movdqa  	xmm1, P1
        MUL_AND_REDUCE_TO_64 xmm1, P1, xmm4     ;; xmm1 = P2
        movdqa  	xmm5, xmm1
        MUL_AND_REDUCE_TO_64 xmm5, P1, xmm4     ;; xmm5 = P3
        movq    	xmm5, xmm5
        movdqa  	xmm3, xmm5
        MUL_AND_REDUCE_TO_64 xmm3, P1, xmm4     ;; xmm3 = P4

        movdqa     	xmm0, P1
        punpcklqdq 	xmm0, xmm1                   ;; xmm0 = p1p2
        movdqa     	xmm1, xmm5
        punpcklqdq 	xmm1, xmm3                   ;; xmm1 = p3p4

align_label
start_4_blk_loop:
        movdqu          xmm3, [in_ptr + offset * 8]
        movdqu          xmm4, [in_ptr + offset * 8 + 16]

        pshufb          xmm3, xmm6
        pshufb          xmm4, xmm6

        pxor            xmm3, EV                ;; m1 XOR EV

        movdqa          xmm5, xmm4

        pclmulqdq       xmm5, xmm0, 0x10        ;; t1 = pclmulqdq_wrap(m2, p1p2, 0x10);
        pclmulqdq       xmm4, xmm0, 0x01        ;; t2 = pclmulqdq_wrap(m2, p1p2, 0x01);

        pxor            xmm5, xmm4

        movdqa          EV, xmm3
        pclmulqdq       EV, xmm1, 0x10          ;; t2 = pclmulqdq_wrap(m1, p3p4, 0x10);
        pclmulqdq       xmm3, xmm1, 0x01        ;; t3 = pclmulqdq_wrap(m1, p3p4, 0x01);

        pxor            EV, xmm3                ;; t2 = _mm_xor_si128(t2, t3);
        pxor            EV, xmm5                ;; t1 = _mm_xor_si128(t2, t1);

        REDUCE_TO_64    EV, xmm3                ;; EV = reduce128_to_64(t1);

        movq            EV, EV    ;; EV = _mm_and_si128(EV, clear_hi64);
 
        ;; less than 4 blocks left
        add     	offset, 4                       ;; move past the 4 blocks processed
        jmp     	single_blk_chk

align_loop
start_single_blk_loop:
        movq    xmm0, [in_ptr + offset * 8]
        pshufb  xmm0, xmm6
        pxor    EV, xmm0
        MUL_AND_REDUCE_TO_64 EV, P1, xmm1

        inc     offset

align_label
single_blk_chk:
        cmp     qword_len, offset
        ja      start_single_blk_loop

align_label
partial_blk:
        mov     tmp5, 0x3f      ;; len_in_bits % 64
        and     tmp5, bit_len
        jz      skip_rem_bits

        ;; load last N bytes
        mov     tmp2, tmp5      ;; (rem_bits + 7) / 8
        add     tmp2, 7
        shr     tmp2, 3

        shl     offset, 3       ;; qwords -> bytes
        add     in_ptr, offset  ;; in + offset to last block

        simd_load_sse_15_1 xmm3, in_ptr, tmp2
        movq    tmp3, xmm3
        bswap   tmp3

        mov     tmp, 0xffffffffffffffff
        mov     tmp6, 64
        sub     tmp6, tmp5

        SHIFT_GP tmp, tmp6, tmp, tmp5, left

        and     tmp3, tmp       ;;  V &= (((uint64_t)-1) << (64 - rem_bits)); /* mask extra bits */
        movq    xmm0, tmp3
        pxor    EV, xmm0

        MUL_AND_REDUCE_TO_64 EV, P1, xmm3

align_label
skip_rem_bits:
        ;; /* Multiply by Q */
        ;; E = multiply_and_reduce64(E ^ lengthInBits,
        ;;                           (((uint64_t)z[2] << 32) | ((uint64_t)z[3])));
        ;; /* Final MAC */
        ;; *(uint32_t *)pDigest =
        ;;        (uint32_t)BSWAP64(E ^ ((uint64_t)z[4] << 32));
        movq    xmm3, bit_len
        pxor    EV, xmm3

        movq    xmm1, [KS + 8]                  ;; load z[2:3]
        pshufd  xmm1, xmm1, 1110_0001b

        mov     DWORD(tmp4), [KS + (4 * 4)]         ;; tmp4 == z[4] << 32
        shl     tmp4, 32

        MUL_AND_REDUCE_TO_64 EV, xmm1, xmm3
        movq    E, EV
        xor     E, tmp4

        bswap   E                               ;; return E (rax/eax)

        FUNC_RESTORE

        ret

mksection stack-noexec
