;;
;; Copyright (c) 2019-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/align_sse.inc"

%ifdef LINUX
%xdefine arg1 rdi
%xdefine arg2 rsi
%xdefine arg3 rdx
%xdefine arg4 rcx
%else
%xdefine arg1 rcx
%xdefine arg2 rdx
%xdefine arg3 r8
%xdefine arg4 r9
%endif

default rel

mksection .text
;
; This function clears all scratch GP registers
;
; void clear_scratch_gps(void)
MKGLOBAL(clear_scratch_gps,function,internal)
align_function
clear_scratch_gps:
        clear_scratch_gps_asm
        ret

;
; This function clears all scratch XMM registers
;
; void clear_scratch_xmms_sse(void)
MKGLOBAL(clear_scratch_xmms_sse,function,internal)
align_function
clear_scratch_xmms_sse:
        clear_scratch_xmms_sse_asm
        ret

;
; This function clears all scratch XMM registers
;
; It should be called before restoring the XMM registers
; for Windows (XMM6-XMM15)
;
; void clear_scratch_xmms_avx(void)
MKGLOBAL(clear_scratch_xmms_avx,function,internal)
align_function
clear_scratch_xmms_avx:
        clear_scratch_xmms_avx_asm
        ret

;
; This function clears all scratch YMM registers
;
; It should be called before restoring the XMM registers
; for Windows (XMM6-XMM15)
;
; void clear_scratch_ymms(void)
MKGLOBAL(clear_scratch_ymms,function,internal)
align_function
clear_scratch_ymms:
        clear_scratch_ymms_asm
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
; void clear_scratch_zmms(void)
MKGLOBAL(clear_scratch_zmms,function,internal)
align_function
clear_scratch_zmms:
        clear_scratch_zmms_asm
        ret

;
; This function clears all memory passed
;
; void force_memset_zero(void *mem, const size_t size)
MKGLOBAL(force_memset_zero,function,internal)
;
; This function clears all memory passed (volatile version)
;
; void force_memset_zero(volatile void *mem, const size_t size)
MKGLOBAL(force_memset_zero_vol,function,internal)

align_function
force_memset_zero:
force_memset_zero_vol:
        pxor    xmm0, xmm0
        xor     eax, eax

        or      arg2, arg2
        jz      .end

align_loop
.loop16:
        cmp     arg2, 16
        jb      .check8
        movdqu  [arg1], xmm0
        add     arg1, 16
        sub     arg2, 16
        jz      .end
        jmp     .loop16

align_label
.check8:
        cmp     arg2, 8
        jb      .check4
        mov     [arg1], rax
        add     arg1, 8
        sub     arg2, 8
        jz      .end

align_label
.check4:
        cmp     arg2, 4
        jb      .loop1
        mov     [arg1], eax
        add     arg1, 4
        sub     arg2, 4
        jz      .end

align_loop
.loop1:
        mov     [arg1], al
        add     arg1, 1
        sub     arg2, 1
        jnz     .loop1

align_label
.end:
        ret

MKGLOBAL(imb_clear_mem,function,)
align_function
imb_clear_mem:
        endbranch64
        or      arg1, arg1
        jz      .return
        call    force_memset_zero
        sfence  ;; ensures stores complete
.return:
        ret

mksection stack-noexec
