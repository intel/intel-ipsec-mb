;;
;; Copyright (c) 2023, Intel Corporation
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

;; macro to do a AES-CBCS decryption
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
_rdx:           resq    1
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
%define %%length        %6      ;; [in/out] GP register with message length (in blocks)
%define %%step          %7      ;; [in] numeric value; distance to next block for decrypt (16 default)


        ;; load cipher text
%assign i 0
%rep %%by
	vmovdqu	        CONCAT(xdata,i), [%%p_in  + (i * %%step)]
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

        ;; prepare IV for the next round
        vmovdqa	        xkeytmp, [rsp + _IV_new]
        vmovdqa         [rsp + _IV], xkeytmp

        ;; store plain text blocks
%assign i 0
%rep %%by
	vmovdqu	        [%%p_out  + (i * %%step)], CONCAT(xdata,i)
%assign i (i + 1)
%endrep

        ;; update pointers
        add	        %%p_in, (%%step * %%by)
        add	        %%p_out, (%%step * %%by)

        sub             %%length, %%by
        ;; Z-Flag gets updated
        ;; - ZF means this is the end of the message

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%macro AES_CBCS_DEC 9
%define %%p_in          %1      ;; [in/out] gp register; cipher text pointer
%define %%p_IV          %2      ;; [in] gp register; IV pointer
%define %%p_keys        %3      ;; [in] gp register; expanded keys pointer
%define %%p_out         %4      ;; [in/out] gp registerl plain text pointer
%define %%length        %5      ;; [in/clobbered] gp register; message length in bytes
%define %%tmp           %6      ;; [clobbered] gp register
%define %%num_rounds    %7      ;; [in] numeric value; number of AES rounds (excluding ARK and last round)
%define %%step          %8      ;; [in] numeric value; distance to next block for decrypt (16 default)
%define %%p_next_IV     %9      ;; [in/out] GP register; pointer to store next IV (used only if %%step > 16)

        mov             %%tmp, rsp
        sub	        rsp, STACK_size
        and             rsp, -16
        mov             [rsp + _rsp_save], %%tmp

        ;; load IV and put it on the stack frame
        vmovdqu	        xmm0, [%%p_IV]
        vmovdqa         [rsp + _IV], xmm0

        ;; convert length into number of blocks
        mov             [rsp + _rdx], rdx
        xor             rdx, rdx
%ifdef LINUX
        lea             rax, [%%length + (%%step - 16)] ;; round up the length
%else
        ;; %%length is RAX
        add             rax, (%%step - 16)      ;; round up the length
%endif
        mov             DWORD(%%tmp), %%step
        div             %%tmp
       ;; %%length = RAX = length in AES blocks
%ifdef LINUX
        mov             %%length, rax
%else
        ;; %%length is RAX
%endif
        mov             rdx, [rsp + _rdx]

        ;; process 1 to 7 blocks first
        mov             %%tmp, %%length
        and             DWORD(%%tmp), 7
	jz	        %%_main_loop

	;; 1 <= %%tmp <= 7
	cmp	        DWORD(%%tmp), 4
	ja	        %%_gt4
	je	        %%_eq4
%%_lt4:
	cmp	        DWORD(%%tmp), 2
	ja	        %%_eq3
	je	        %%_eq2
%%_eq1:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 1, %%num_rounds, %%length, %%step
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq2:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 2, %%num_rounds, %%length, %%step
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq3:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 3, %%num_rounds, %%length, %%step
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq4:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 4, %%num_rounds, %%length, %%step
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_gt4:
	cmp	        DWORD(%%tmp), 6
	ja	        %%_eq7
	je	        %%_eq6
%%_eq5:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 5, %%num_rounds, %%length, %%step
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq6:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 6, %%num_rounds, %%length, %%step
	jz	        %%_do_return
	jmp	        %%_main_loop

align 32
%%_eq7:
	DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 7, %%num_rounds, %%length, %%step
	jz	        %%_do_return

align 32
%%_main_loop:
        ;; %%length is a multiple of 8 blocks
        DO_AES_DEC      %%p_in, %%p_out, %%p_keys, 8, %%num_rounds, %%length, %%step
        jnz             %%_main_loop

align 32
%%_do_return:
        vmovdqa         xdata0, [rsp + _IV]
        vmovdqa         [%%p_next_IV], xdata0

%ifdef SAFE_DATA
        clear_xmms_avx xdata0, xdata1, xdata2, xdata3, xdata4, xdata5, xdata6, xdata7, xkeytmp
%endif ;; SAFE_DATA

       ;; restore the stack pointer
       ;; - IV is cipher text, no need to clear it from the stack
       mov              rsp, [rsp + _rsp_save]

%endmacro
