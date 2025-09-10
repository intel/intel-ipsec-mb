;
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

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "include/align_sse.inc"

; resdq = res0 => 16 bytes
struc frame
.ABEF_SAVE      reso    1
.CDGH_SAVE      reso    1
.XMM_SAVE       reso    4
.align          resq    1
endstruc

%ifdef LINUX
%define INP     rdi ; 1st arg
%define CTX     rsi ; 2nd arg
%define ARG3    rdx ; 3rd arg
%else
%define INP     rcx ; 1st arg
%define CTX     rdx ; 2nd arg
%define ARG3    r8  ; 3rd arg
%endif

;; MSG MUST be xmm0 (implicit argument)
%define MSG             xmm0
%define STATE0          xmm1
%define STATE1          xmm2
%define MSGTMP0         xmm3
%define MSGTMP1         xmm4
%define MSGTMP2         xmm5
%define MSGTMP3         xmm6
%define MSGTMP4         xmm7
%define MSGTMP          xmm14
%define SHUF_MASK       xmm15

;; Input: 64 byte input block (MSG)
;; Output: 32 byte digest (STATE0, STATE1)
%macro one_block_256_ni 0
        ;; Rounds 0-3
        movdqu          MSG, [INP + 0*16]
        pshufb          MSG, SHUF_MASK
        movdqa          MSGTMP0, MSG
        paddd           MSG, [rel K256 + 0*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument

        ;; Rounds 4-7
        movdqu          MSG, [INP + 1*16]
        pshufb          MSG, SHUF_MASK
        movdqa          MSGTMP1, MSG
        paddd           MSG, [rel K256 + 1*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP0, MSGTMP1

        ;; Rounds 8-11
        movdqu          MSG, [INP + 2*16]
        pshufb          MSG, SHUF_MASK
        movdqa          MSGTMP2, MSG
        paddd           MSG, [rel K256 + 2*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP1, MSGTMP2

        ;; Rounds 12-15
        movdqu          MSG, [INP + 3*16]
        pshufb          MSG, SHUF_MASK
        movdqa          MSGTMP3, MSG
        paddd           MSG, [rel K256 + 3*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP3
        palignr         MSGTMP, MSGTMP2, 4
        paddd           MSGTMP0, MSGTMP
        sha256msg2      MSGTMP0, MSGTMP3
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP2, MSGTMP3

        ;; Rounds 16-19
        movdqa          MSG, MSGTMP0
        paddd           MSG, [rel K256 + 4*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP0
        palignr         MSGTMP, MSGTMP3, 4
        paddd           MSGTMP1, MSGTMP
        sha256msg2      MSGTMP1, MSGTMP0
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP3, MSGTMP0

        ;; Rounds 20-23
        movdqa          MSG, MSGTMP1
        paddd           MSG, [rel K256 + 5*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP1
        palignr         MSGTMP, MSGTMP0, 4
        paddd           MSGTMP2, MSGTMP
        sha256msg2      MSGTMP2, MSGTMP1
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP0, MSGTMP1

        ;; Rounds 24-27
        movdqa          MSG, MSGTMP2
        paddd           MSG, [rel K256 + 6*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP2
        palignr         MSGTMP, MSGTMP1, 4
        paddd           MSGTMP3, MSGTMP
        sha256msg2      MSGTMP3, MSGTMP2
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP1, MSGTMP2

        ;; Rounds 28-31
        movdqa          MSG, MSGTMP3
        paddd           MSG, [rel K256 + 7*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP3
        palignr         MSGTMP, MSGTMP2, 4
        paddd           MSGTMP0, MSGTMP
        sha256msg2      MSGTMP0, MSGTMP3
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP2, MSGTMP3

        ;; Rounds 32-35
        movdqa          MSG, MSGTMP0
        paddd           MSG, [rel K256 + 8*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP0
        palignr         MSGTMP, MSGTMP3, 4
        paddd           MSGTMP1, MSGTMP
        sha256msg2      MSGTMP1, MSGTMP0
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP3, MSGTMP0

        ;; Rounds 36-39
        movdqa          MSG, MSGTMP1
        paddd           MSG, [rel K256 + 9*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP1
        palignr         MSGTMP, MSGTMP0, 4
        paddd           MSGTMP2, MSGTMP
        sha256msg2      MSGTMP2, MSGTMP1
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP0, MSGTMP1

        ;; Rounds 40-43
        movdqa          MSG, MSGTMP2
        paddd           MSG, [rel K256 + 10*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP2
        palignr         MSGTMP, MSGTMP1, 4
        paddd           MSGTMP3, MSGTMP
        sha256msg2      MSGTMP3, MSGTMP2
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP1, MSGTMP2

        ;; Rounds 44-47
        movdqa          MSG, MSGTMP3
        paddd           MSG, [rel K256 + 11*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP3
        palignr         MSGTMP, MSGTMP2, 4
        paddd           MSGTMP0, MSGTMP
        sha256msg2      MSGTMP0, MSGTMP3
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP2, MSGTMP3

        ;; Rounds 48-51
        movdqa          MSG, MSGTMP0
        paddd           MSG, [rel K256 + 12*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP0
        palignr         MSGTMP, MSGTMP3, 4
        paddd           MSGTMP1, MSGTMP
        sha256msg2      MSGTMP1, MSGTMP0
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument
        sha256msg1      MSGTMP3, MSGTMP0

        ;; Rounds 52-55
        movdqa          MSG, MSGTMP1
        paddd           MSG, [rel K256 + 13*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP1
        palignr         MSGTMP, MSGTMP0, 4
        paddd           MSGTMP2, MSGTMP
        sha256msg2      MSGTMP2, MSGTMP1
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument

        ;; Rounds 56-59
        movdqa          MSG, MSGTMP2
        paddd           MSG, [rel K256 + 14*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        movdqa          MSGTMP, MSGTMP2
        palignr         MSGTMP, MSGTMP1, 4
        paddd           MSGTMP3, MSGTMP
        sha256msg2      MSGTMP3, MSGTMP2
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument

        ;; Rounds 60-63
        movdqa          MSG, MSGTMP3
        paddd           MSG, [rel K256 + 15*16]
        sha256rnds2     STATE1, STATE0, MSG     ; MSG is implicit argument
        pshufd          MSG, MSG, 0x0E
        sha256rnds2     STATE0, STATE1, MSG     ; MSG is implicit argument

        paddd           STATE0, [rsp + frame.ABEF_SAVE]
        paddd           STATE1, [rsp + frame.CDGH_SAVE]
%endmacro

mksection .rodata
default rel

extern K256

align 64
PSHUFFLE_BYTE_FLIP_MASK:
        dq 0x0405060700010203, 0x0c0d0e0f08090a0b

mksection .text
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha256_ni_block_sse(void *input_data, UINT32 digest[8])
;; arg 1 : (in) pointer to one block of data
;; arg 2 : (in/out) pointer to read/write digest
MKGLOBAL(sha256_ni_block_sse,function,internal)
align_function
sha256_ni_block_sse:
        sub             rsp, frame_size

%ifndef LINUX
        movdqu          [rsp + frame.XMM_SAVE + 0*16], xmm6
        movdqu          [rsp + frame.XMM_SAVE + 1*16], xmm7
        movdqu          [rsp + frame.XMM_SAVE + 2*16], xmm14
        movdqu          [rsp + frame.XMM_SAVE + 3*16], xmm15
%endif

        ;; load initial digest
        ;; Probably need to reorder these appropriately
        ;; DCBA, HGFE -> ABEF, CDGH
        movdqu          STATE0, [CTX]
        movdqu          STATE1, [CTX + 16]

        pshufd          STATE0, STATE0, 0xB1    ; CDAB
        pshufd          STATE1, STATE1, 0x1B    ; EFGH
        movdqa          MSGTMP4, STATE0
        palignr         STATE0, STATE1, 8       ; ABEF
        pblendw         STATE1, MSGTMP4, 0xF0   ; CDGH

        movdqa          SHUF_MASK, [rel PSHUFFLE_BYTE_FLIP_MASK]

        ;; Save digests
        movdqu          [rsp + frame.ABEF_SAVE], STATE0
        movdqu          [rsp + frame.CDGH_SAVE], STATE1

        one_block_256_ni

        ; Reorder for writeback
        pshufd          STATE0, STATE0, 0x1B    ; FEBA
        pshufd          STATE1, STATE1, 0xB1    ; DCHG
        movdqa          MSGTMP4, STATE0
        pblendw         STATE0, STATE1,  0xF0   ; DCBA
        palignr         STATE1, MSGTMP4,  8     ; HGFE

        ;; update digests
        movdqu          [CTX], STATE0
        movdqu          [CTX + 16], STATE1

        ;; Clear stack frame (2*16 bytes)
%ifdef SAFE_DATA
        pxor            MSGTMP0, MSGTMP0
        pxor            MSGTMP1, MSGTMP1
        pxor            MSGTMP2, MSGTMP2
        pxor            MSGTMP3, MSGTMP3
        pxor            MSGTMP4, MSGTMP4
        pxor            MSGTMP, MSGTMP

        movdqu          [rsp + frame.ABEF_SAVE], MSGTMP0
        movdqu          [rsp + frame.CDGH_SAVE], MSGTMP0
%endif

%ifndef LINUX
        movdqu          xmm6, [rsp + frame.XMM_SAVE + 0*16]
        movdqu          xmm7, [rsp + frame.XMM_SAVE + 1*16]
        movdqu          xmm14, [rsp + frame.XMM_SAVE + 2*16]
        movdqu          xmm15, [rsp + frame.XMM_SAVE + 3*16]
%endif
        add             rsp, frame_size
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha256_ni_update_sse(void *input_data, UINT32 digest[8], UINT64 num_blks)
;; arg 1 : (in) pointer to one block of data
;; arg 2 : (in/out) pointer to read/write digest
;; arg 3 : (in) number of blocks to process
MKGLOBAL(sha256_ni_update_sse,function,internal)
align_function
sha256_ni_update_sse:
        sub             rsp, frame_size

%ifndef LINUX
        movdqu          [rsp + frame.XMM_SAVE + 0*16], xmm6
        movdqu          [rsp + frame.XMM_SAVE + 1*16], xmm7
        movdqu          [rsp + frame.XMM_SAVE + 2*16], xmm14
        movdqu          [rsp + frame.XMM_SAVE + 3*16], xmm15
%endif

        ;; load initial digest
        ;; Probably need to reorder these appropriately
        ;; DCBA, HGFE -> ABEF, CDGH
        movdqu          STATE0, [CTX]
        movdqu          STATE1, [CTX + 16]

        pshufd          STATE0, STATE0, 0xB1    ; CDAB
        pshufd          STATE1, STATE1, 0x1B    ; EFGH
        movdqa          MSGTMP4, STATE0
        palignr         STATE0, STATE1, 8       ; ABEF
        pblendw         STATE1, MSGTMP4, 0xF0   ; CDGH

        movdqa          SHUF_MASK, [rel PSHUFFLE_BYTE_FLIP_MASK]

align_loop
process_block:
        ;; Save digests
        movdqu          [rsp + frame.ABEF_SAVE], STATE0
        movdqu          [rsp + frame.CDGH_SAVE], STATE1

        one_block_256_ni

        add INP, 64
        dec ARG3
        jnz process_block

        ; Reorder for writeback
        pshufd          STATE0, STATE0, 0x1B    ; FEBA
        pshufd          STATE1, STATE1, 0xB1    ; DCHG
        movdqa          MSGTMP4, STATE0
        pblendw         STATE0, STATE1,  0xF0   ; DCBA
        palignr         STATE1, MSGTMP4,  8     ; HGFE

        ;; update digests
        movdqu          [CTX], STATE0
        movdqu          [CTX + 16], STATE1

        ;; Clear regs holding message
%ifdef SAFE_DATA
        pxor            MSGTMP0, MSGTMP0
        pxor            MSGTMP1, MSGTMP1
        pxor            MSGTMP2, MSGTMP2
        pxor            MSGTMP3, MSGTMP3
        pxor            MSGTMP4, MSGTMP4
        pxor            MSGTMP, MSGTMP
%endif

%ifndef LINUX
        movdqu          xmm6, [rsp + frame.XMM_SAVE + 0*16]
        movdqu          xmm7, [rsp + frame.XMM_SAVE + 1*16]
        movdqu          xmm14, [rsp + frame.XMM_SAVE + 2*16]
        movdqu          xmm15, [rsp + frame.XMM_SAVE + 3*16]
%endif
        add             rsp, frame_size
        ret

mksection stack-noexec
