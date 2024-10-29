;;
;; Copyright (c) 2023-2024, Intel Corporation
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

;; macro to do a AES-CBC decryption
;; - single-buffer implementation
;; - 8 blocks at a time

%use smartalign

%include "include/os.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/clear_regs.inc"
%include "include/reg_sizes.inc"

%define CONCAT(a,b) a %+ b

%define xdata0	xmm0
%define xdata1	xmm1
%define xdata2	xmm2
%define xdata3	xmm3
%define xdata4	xmm4
%define xdata5	xmm5
%define xdata6	xmm6
%define xdata7	xmm7

%define xiv0    xmm8
%define xiv1	xmm9
%define xiv2	xmm10
%define xiv3	xmm11
%define xiv4	xmm12
%define xiv5	xmm13
%define xiv6	xmm14

%define xkeytmp	xmm15

struc STACK
_IV:            resq	2
_IV_new:        resq	2
_rsp_save:	resq	1
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; DO_AES_DEC num_in_par load_keys
;; - it increments p_in and p_out
;; - ZF (zero-flag) gets updated
;;   - ZF means this is the end of the message

%macro DO_AES_DEC 7
%define %%p_in          %1      ;; [in/out] GP register with input pointer
%define %%p_out         %2      ;; [in/out] GP register with output pointer
%define %%p_keys        %3      ;; [in] GP register with pointer to AES round keys
%define %%by            %4      ;; [in] numeric value; number of blocks to process (1 to 8)
%define %%num_rounds    %5      ;; [in] numeric - number fo aesdec rounds (ark / declast not included)
%define %%length        %6      ;; [in/out] GP register with message length
%define %%type          %7      ;; [in] "main" or "last" selector of 8 block invocation
                                ;;      "short" or "start" selector for < 8 blocks

%assign is_1_to_7_short_or_8_last 0

%if %%by < 8
%ifidni %%type, short
%assign is_1_to_7_short_or_8_last 1
%endif
%endif

%if %%by == 8
%ifidni %%type, last
%assign is_1_to_7_short_or_8_last 1
%endif
%endif

        ;; load cipher text
%assign i 0
%rep %%by

%if !((%%by == 8) && (i == 0))
	vmovdqu	        CONCAT(xdata,i), [%%p_in  + (i * 16)]
%endif

%if i == (%%by - 1)
        vmovdqa         [rsp + _IV_new], CONCAT(xdata,i)
%else
        vmovdqa         CONCAT(xiv,i), CONCAT(xdata,i)
%endif
%assign i (i + 1)
%endrep

        ;; ARK
%assign i 0
        vmovdqa	        xkeytmp, [%%p_keys + (0 * 16)]
%rep %%by
	vpxor	        CONCAT(xdata,i), CONCAT(xdata,i), xkeytmp
%assign i (i + 1)
%endrep

        ;; AESDEC rounds
%assign round 1
%rep %%num_rounds
        vmovdqa	        xkeytmp, [%%p_keys + (round * 16)]
%assign i 0
%rep %%by
	vaesdec	        CONCAT(xdata,i), CONCAT(xdata,i), xkeytmp
%assign i (i + 1)
%endrep
%assign round (round + 1)
%endrep ;; round

        ;; AESDEC last
%assign i 0
        vmovdqa	        xkeytmp, [%%p_keys + (round * 16)]
%rep %%by
	vaesdeclast	CONCAT(xdata,i), CONCAT(xdata,i), xkeytmp
%assign i (i + 1)
%endrep

        ;; XOR IV
	vpxor	        xdata0, xdata0, [rsp + _IV]
%assign i 1
%assign j 0
%if (%%by > 1)
%rep (%%by - 1)
	vpxor	        CONCAT(xdata,i), CONCAT(xdata,i), CONCAT(xiv,j)
%assign i (i + 1)
%assign j (j + 1)
%endrep
%endif

%if is_1_to_7_short_or_8_last == 0
        ;; prepare IV for the next round
        vmovdqa	        xkeytmp, [rsp + _IV_new]
        vmovdqa         [rsp + _IV], xkeytmp
%endif

        ;; store plain text blocks

        ;; - do only (%%by - 1) stores first
%assign i 0
%rep %%by - 1
	vmovdqu	        [%%p_out  + (i * 16)], CONCAT(xdata,i)
%assign i (i + 1)
%endrep

%if %%by < 8
        ;; 1 to 7 block case:
%ifidni %%type, start
        ;; - check if message length is more than %%by blocks
        ;;     yes: load 1st block for the next round and then store the last block of this round
        ;;      no: store the last block of this round

        cmp             %%length, %%by * 16
        jbe             %%_just_finish_stores
        ;; load 1st block of data in the next round
	vmovdqu	        xkeytmp, [%%p_in  + (%%by * 16)]
	vmovdqu	        [%%p_out  + (i * 16)], CONCAT(xdata,i)
        vmovdqa         xdata0, xkeytmp
        jmp             %%_update_pointers

%%_just_finish_stores:
        vmovdqu	        [%%p_out  + (i * 16)], CONCAT(xdata,i)
%endif

%ifidni %%type, short
        ;; short message - just store
        vmovdqu	        [%%p_out  + (i * 16)], CONCAT(xdata,i)
%endif

%else
        ;; 8 block case
        ;; - two cases: main (main 8 block loop) and last (last 8 blocks)

%ifidni %%type, main
        ;; - MAIN: load 1st block for the next round and then store 8 blocks of this round
	vmovdqu	        xdata0, [%%p_in  + (%%by * 16)]
	vmovdqu	        [%%p_out  + (i * 16)], CONCAT(xdata,i)
%endif

%ifidni %%type, last
        ;; LAST: store all 8 blocks
	vmovdqu	        [%%p_out  + (i * 16)], CONCAT(xdata,i)
%endif
%endif ;; %%by

%%_update_pointers:

%if is_1_to_7_short_or_8_last == 0
        add	        %%p_in, (16 * %%by)
        add	        %%p_out, (16 * %%by)

        sub             %%length, %%by * 16
        ;; Z-Flag gets updated
        ;; - ZF means this is the end of the message
%endif

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%macro AES_CBC_DEC 7
%define %%p_in          %1      ;; [in/out] gp register; cipher text pointer
%define %%p_IV          %2      ;; [in] gp register; IV pointer
%define %%p_keys        %3      ;; [in] gp register; expanded keys pointer
%define %%p_out         %4      ;; [in/out] gp registerl plain text pointer
%define %%length        %5      ;; [in/clobbered] gp register; message length in bytes
%define %%tmp           %6      ;; [clobbered] gp register
%define %%num_rounds    %7      ;; [in] numeric value; number of AES rounds (excluding ARK and last round)

        mov             %%tmp, rsp
        sub	        rsp, STACK_size
        and             rsp, -16
        mov             [rsp + _rsp_save], %%tmp

        ;; load IV and put it on the stack frame
        vmovdqu	        xmm0, [%%p_IV]
        vmovdqa         [rsp + _IV], xmm0

        cmp             %%length, 8 * 16
        jae             %%_longer_than_8_blocks

        ;; process 1 to 7 blocks first
	mov	        DWORD(%%tmp), DWORD(%%length)
        shr             DWORD(%%tmp), 4
        and             DWORD(%%tmp), 7

	;; 1 <= %%tmp <= 7
	cmp	        DWORD(%%tmp), 4
	ja	        %%_sgt4
	je	        %%_seq4
%%_slt4:
	cmp	        DWORD(%%tmp), 2
	ja	        %%_seq3
	je	        %%_seq2
%%_seq1:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 1, %%num_rounds, %%length, short
	jmp	        %%_do_return

align 32
%%_seq2:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 2, %%num_rounds, %%length, short
	jmp	        %%_do_return

align 32
%%_seq3:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 3, %%num_rounds, %%length, short
	jmp	        %%_do_return

align 32
%%_seq4:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 4, %%num_rounds, %%length, short
	jmp	        %%_do_return

align 32
%%_sgt4:
	cmp	        DWORD(%%tmp), 6
	ja	        %%_seq7
	je	        %%_seq6
%%_seq5:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 5, %%num_rounds, %%length, short
	jmp	        %%_do_return

align 32
%%_seq6:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 6, %%num_rounds, %%length, short
	jmp	        %%_do_return

align 32
%%_seq7:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 7, %%num_rounds, %%length, short
	jmp	        %%_do_return

        ;; =====================================================================
        ;; message longer than 8 blocks

align 32
%%_longer_than_8_blocks:
        ;; process 1 to 7 blocks first
	mov	        DWORD(%%tmp), DWORD(%%length)
        shr             DWORD(%%tmp), 4
        and             DWORD(%%tmp), 7
	jz	        %%_eq0

	;; 1 <= %%tmp <= 7
	cmp	        DWORD(%%tmp), 4
	ja	        %%_gt4
	je	        %%_eq4
%%_lt4:
	cmp	        DWORD(%%tmp), 2
	ja	        %%_eq3
	je	        %%_eq2
%%_eq1:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 1, %%num_rounds, %%length, start
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq2:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 2, %%num_rounds, %%length, start
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq3:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 3, %%num_rounds, %%length, start
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq4:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 4, %%num_rounds, %%length, start
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_gt4:
	cmp	        DWORD(%%tmp), 6
	ja	        %%_eq7
	je	        %%_eq6
%%_eq5:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 5, %%num_rounds, %%length, start
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq6:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 6, %%num_rounds, %%length, start
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq7:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 7, %%num_rounds, %%length, start
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq0:
	vmovdqu	        xdata0, [%%p_in]

align 32
%%_main_loop:
        cmp             %%length, 2 * (8 * 16)
        jb              %%_the_last_8_blocks
        ;; %%length is a multiple of 8 blocks (length = N x 8 x 16-bytes, where N = 2, 3, ..)
        DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 8, %%num_rounds, %%length, main
        jmp	        %%_main_loop

align 32
%%_the_last_8_blocks:
        ;; %%length is 8 blocks (8 x 16-bytes)
        DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 8, %%num_rounds, %%length, last

align 32
%%_do_return:
%ifdef SAFE_DATA
        clear_xmms_avx xdata0, xdata1, xdata2, xdata3, xdata4, xdata5, xdata6, xdata7, xkeytmp
%endif ;; SAFE_DATA

       ;; restore the stack pointer
       ;; - IV is cipher text, no need to clear it from the stack
       mov              rsp, [rsp + _rsp_save]
%endmacro
