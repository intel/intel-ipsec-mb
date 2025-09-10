;;
;; Copyright (c) 2012-2024, Intel Corporation
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
%include "include/imb_job.inc"
%include "include/memcpy.inc"
%include "include/const.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/align_sse.inc"

; routine to do AES256 CNTR enc/decrypt "by8"
; XMM registers are clobbered. Saving/restoring must be done at a higher level

%ifndef AES_CNTR_256
%define AES_CNTR_256 aes_cntr_256_sse
%endif

extern byteswap_const, set_byte15, ddq_add_1, ddq_add_2, ddq_add_3, ddq_add_4
extern ddq_add_5, ddq_add_6, ddq_add_7, ddq_add_8

%define CONCAT(a,b) a %+ b
%define MOVDQ movdqu

%define xdata0  xmm0
%define xdata1  xmm1
%define xpart   xmm1
%define xdata2  xmm2
%define xdata3  xmm3
%define xdata4  xmm4
%define xdata5  xmm5
%define xdata6  xmm6
%define xdata7  xmm7
%define xcounter xmm8
%define xtmp    xmm8
%define xbyteswap xmm9
%define xtmp2   xmm9
%define xkey0   xmm10
%define xtmp3   xmm10
%define xkey4   xmm11
%define xkey8   xmm12
%define xkey12  xmm13
%define xkeyA   xmm14
%define xkeyB   xmm15

%ifdef CNTR_CCM_SSE
%ifdef LINUX
%define job       rdi
%define p_in      rsi
%define p_keys    rdx
%define p_out     rcx
%define num_bytes r8
%define p_ivlen   r9
%else ;; LINUX
%define job       rcx
%define p_in      rdx
%define p_keys    r8
%define p_out     r9
%define num_bytes r10
%define p_ivlen   rax
%endif ;; LINUX
%define p_IV    r11
%else ;; CNTR_CCM_SSE
%ifdef LINUX
%define p_in      rdi
%define p_IV      rsi
%define p_keys    rdx
%define p_out     rcx
%define num_bytes r8
%define num_bits  r8
%define p_ivlen   r9
%else
%define p_in      rcx
%define p_IV      rdx
%define p_keys    r8
%define p_out     r9
%define num_bytes r10
%define num_bits  r10
%define p_ivlen   qword [rsp + 8*6]
%endif
%endif ;; CNTR_CCM_SSE

%define tmp     r11
%define flags   r11

%define r_bits   r12
%define tmp2    r13
%define mask    r14

%macro do_aes_load 2
        do_aes %1, %2, 1
%endmacro

%macro do_aes_noload 2
        do_aes %1, %2, 0
%endmacro

; do_aes num_in_par load_keys
; This increments p_in, but not p_out
%macro do_aes 3
%define %%by %1
%define %%cntr_type %2
%define %%load_keys %3

%define %%PADD paddd

%if (%%load_keys)
        movdqa  xkey0, [p_keys + 0*16]
%endif

        movdqa  xdata0, xcounter
        pshufb  xdata0, xbyteswap
%assign i 1
%rep (%%by - 1)
        movdqa  CONCAT(xdata,i), xcounter
        %%PADD  CONCAT(xdata,i), [rel CONCAT(ddq_add_,i)]
        pshufb  CONCAT(xdata,i), xbyteswap
%assign i (i + 1)
%endrep

        movdqa  xkeyA, [p_keys + 1*16]

        pxor    xdata0, xkey0
        %%PADD  xcounter, [rel CONCAT(ddq_add_,%%by)]

%assign i 1
%rep (%%by - 1)
        pxor    CONCAT(xdata,i), xkey0
%assign i (i + 1)
%endrep

        movdqa  xkeyB, [p_keys + 2*16]
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkeyA          ; key 1
%assign i (i+1)
%endrep

        movdqa  xkeyA, [p_keys + 3*16]
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkeyB          ; key 2
%assign i (i+1)
%endrep

        add     p_in, 16*%%by

%if (%%load_keys)
        movdqa  xkey4, [p_keys + 4*16]
%endif
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkeyA          ; key 3
%assign i (i+1)
%endrep

        movdqa  xkeyA, [p_keys + 5*16]
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkey4          ; key 4
%assign i (i+1)
%endrep

        movdqa  xkeyB, [p_keys + 6*16]
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkeyA          ; key 5
%assign i (i+1)
%endrep

        movdqa  xkeyA, [p_keys + 7*16]
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkeyB          ; key 6
%assign i (i+1)
%endrep

%if (%%load_keys)
        movdqa  xkey8, [p_keys + 8*16]
%endif
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkeyA          ; key 7
%assign i (i+1)
%endrep

        movdqa  xkeyA, [p_keys + 9*16]
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkey8          ; key 8
%assign i (i+1)
%endrep

        movdqa  xkeyB, [p_keys + 10*16]
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkeyA          ; key 9
%assign i (i+1)
%endrep

        movdqa  xkeyA, [p_keys + 11*16]
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkeyB          ; key 10
%assign i (i+1)
%endrep

%if (%%load_keys)
        movdqa  xkey12, [p_keys + 12*16]
%endif
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkeyA          ; key 11
%assign i (i+1)
%endrep

        movdqa  xkeyA, [p_keys + 13*16]
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkey12 ; key 12
%assign i (i+1)
%endrep

        movdqa  xkeyB, [p_keys + 14*16]
%assign i 0
%rep %%by
        aesenc  CONCAT(xdata,i), xkeyA          ; key 13
%assign i (i+1)
%endrep

%assign i 0
%rep %%by
        aesenclast      CONCAT(xdata,i), xkeyB  ; key 14
%assign i (i+1)
%endrep

%assign i 0
%rep (%%by / 2)
%assign j (i+1)
        MOVDQ   xkeyA, [p_in + i*16 - 16*%%by]
        MOVDQ   xkeyB, [p_in + j*16 - 16*%%by]
        pxor    CONCAT(xdata,i), xkeyA
        pxor    CONCAT(xdata,j), xkeyB
%assign i (i+2)
%endrep
%if (i < %%by)
        MOVDQ   xkeyA, [p_in + i*16 - 16*%%by]
        pxor    CONCAT(xdata,i), xkeyA
%endif

%assign i 0
%rep %%by
        MOVDQ   [p_out  + i*16], CONCAT(xdata,i)
%assign i (i+1)
%endrep
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
mksection .text

;; Macro performing AES-CTR.
;;
%macro DO_CNTR 1
%define %%CNTR_TYPE %1 ; [in] Type of CNTR operation to do (CNTR/CCM)

%ifidn %%CNTR_TYPE, CCM
        mov     p_in, [job + _src]
        add     p_in, [job + _cipher_start_src_offset_in_bytes]
        mov     p_ivlen, [job + _iv_len_in_bytes]
        mov     num_bytes, [job + _msg_len_to_cipher_in_bytes]
        mov     p_keys, [job + _enc_keys]
        mov     p_out, [job + _dst]

        movdqa  xbyteswap, [rel byteswap_const]
        ;; Prepare IV ;;

        ;; Byte 0: flags with L'
        ;; Calculate L' = 15 - Nonce length - 1 = 14 - IV length
        mov     flags, 14
        sub     flags, p_ivlen
        movd    xcounter, DWORD(flags)
        ;; Bytes 1 - 13: Nonce (7 - 13 bytes long)

        ;; Bytes 1 - 7 are always copied (first 7 bytes)
        mov     p_IV, [job + _iv]
        pinsrb  xcounter, [p_IV], 1
        pinsrw  xcounter, [p_IV + 1], 1
        pinsrd  xcounter, [p_IV + 3], 1

        cmp     p_ivlen, 10
        je      _iv_length_10
        ja      _iv_length_11_to_13

        cmp     p_ivlen, 8
        je      _iv_length_8
        jb      _finish_nonce_move   ; p_ivlen = 7
        jmp     _iv_length_9         ; p_ivlen = 9

_iv_length_11_to_13:
        ; p_ivlen > 10 (11, 12, or 13)
        cmp     p_ivlen, 12
        je      _iv_length_12
        jb      _iv_length_11

        ;; Bytes 8 - 13
_iv_length_13:
        pinsrb  xcounter, [p_IV + 12], 13
_iv_length_12:
        pinsrb  xcounter, [p_IV + 11], 12
_iv_length_11:
        pinsrd  xcounter, [p_IV + 7], 2
        jmp     _finish_nonce_move
_iv_length_10:
        pinsrb  xcounter, [p_IV + 9], 10
_iv_length_9:
        pinsrb  xcounter, [p_IV + 8], 9
_iv_length_8:
        pinsrb  xcounter, [p_IV + 7], 8

align_label
_finish_nonce_move:
        ; last byte = 1
        por     xcounter, [rel set_byte15]
%else ;; CNTR
%ifndef LINUX
        mov     num_bytes, [rsp + 8*5]
%endif

        movdqa  xbyteswap, [rel byteswap_const]
        test    p_ivlen, 16
        jnz     %%_iv_is_16_bytes
        ; Read 12 bytes: Nonce + ESP IV. Then pad with block counter 0x00000001
        mov     DWORD(tmp), 0x01000000
        pinsrq  xcounter, [p_IV], 0
        pinsrd  xcounter, [p_IV + 8], 2
        pinsrd  xcounter, DWORD(tmp), 3
%endif ;; CNTR/CCM

align_label
%%_bswap_iv:
        pshufb  xcounter, xbyteswap

        ;; calculate len
        mov     tmp, num_bytes
        and     tmp, 7*16
        jz      %%_chk       ; multiple of 8 blocks and/or below 16 bytes

        ; 1 <= tmp <= 7
        cmp     tmp, 4*16
        jg      %%_gt4
        je      %%_eq4

        ; 1 <= tmp <= 3
        cmp     tmp, 2*16
        jg      %%_eq3
        je      %%_eq2

align_label
%%_eq1:
        do_aes_load     1, %%CNTR_TYPE  ; 1 block
        add     p_out, 1*16
        jmp     %%_chk

align_label
%%_eq2:
        do_aes_load     2, %%CNTR_TYPE  ; 2 blocks
        add     p_out, 2*16
        jmp      %%_chk

align_label
%%_eq3:
        do_aes_load     3, %%CNTR_TYPE  ; 3 blocks
        add     p_out, 3*16
        jmp     %%_chk

align_label
%%_eq4:
        do_aes_load     4, %%CNTR_TYPE
        add     p_out, 4*16
        jmp     %%_chk

align_label
%%_gt4:
        ; 5 <= tmp <= 7
        cmp     tmp, 6*16
        jg      %%_eq7
        je      %%_eq6

align_label
%%_eq5:
        do_aes_load     5, %%CNTR_TYPE
        add     p_out, 5*16
        jmp     %%_chk

align_label
%%_eq6:
        do_aes_load     6, %%CNTR_TYPE
        add     p_out, 6*16
        jmp     %%_chk

align_label
%%_eq7:
        do_aes_load     7, %%CNTR_TYPE
        add     p_out, 7*16
        ; fall through to chk
align_label
%%_chk:
        and     num_bytes, ~(7*16)
        jz      %%_do_return2

        cmp     num_bytes, 16
        jb      %%_last

        ; process multiples of 4 blocks
        movdqa  xkey0, [p_keys + 0*16]
        movdqa  xkey4, [p_keys + 4*16]
        movdqa  xkey8, [p_keys + 8*16]
        movdqa  xkey12, [p_keys + 12*16]

align_loop
%%_main_loop2:
        ; num_bytes is a multiple of 8 blocks + partial bytes
        do_aes_noload   8, %%CNTR_TYPE
        add     p_out,  8*16
        sub     num_bytes, 8*16
        cmp     num_bytes, 8*16
        jae     %%_main_loop2

        ; Check if there is a partial block
        or      num_bytes, num_bytes
        jnz    %%_last

align_label
%%_do_return2:
%ifidn %%CNTR_TYPE, CCM
        mov     rax, job
        or      dword [rax + _status], IMB_STATUS_COMPLETED_CIPHER
%endif

%ifdef SAFE_DATA
        clear_all_xmms_sse_asm
%endif ;; SAFE_DATA

        ret

align_label
%%_last:

        ; load partial block into XMM register
        simd_load_sse_15_1 xpart, p_in, num_bytes

%%_final_ctr_enc:
        ; Encryption of a single partial block
        pshufb  xcounter, xbyteswap
        movdqa  xdata0, xcounter
        pxor    xdata0, [p_keys + 16*0]
%assign i 1
%rep 13
        aesenc  xdata0, [p_keys + 16*i]
%assign i (i+1)
%endrep
        ; created keystream
        aesenclast xdata0, [p_keys + 16*i]

        ; xor keystream with the message (scratch)
        pxor    xdata0, xpart

align_label
%%_store_output:
        ; copy result into the output buffer
        simd_store_sse_15 p_out, xdata0, num_bytes, tmp, rax

        jmp     %%_do_return2

align_label
%%_iv_is_16_bytes:
        ; Read 16 byte IV: Nonce + ESP IV + block counter (BE)
        movdqu  xcounter, [p_IV]
        jmp     %%_bswap_iv
%endmacro

%ifdef CNTR_CCM_SSE
; IMB_JOB * aes_cntr_ccm_256_<arch>(IMB_JOB *job)
; arg 1 : job
MKGLOBAL(AES_CNTR_CCM_256,function,internal)
align_function
AES_CNTR_CCM_256:
        endbranch64
        DO_CNTR CCM
%else
;; aes_cntr_256_sse(void *in, void *IV, void *keys, void *out, UINT64 num_bytes, UINT64 iv_len)
MKGLOBAL(AES_CNTR_256,function,internal)
align_function
AES_CNTR_256:
        DO_CNTR CNTR
%endif ;; CNTR_CCM_SSE

mksection stack-noexec
