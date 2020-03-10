;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2019-2020, Intel Corporation All rights reserved.
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

%include "include/os.asm"
%include "include/reg_sizes.asm"
%include "mb_mgr_datastruct.asm"
%include "imb_job.asm"
%include "include/memcpy.asm"

%include "include/aes_common.asm"
%include "include/const.inc"
%include "include/clear_regs.asm"

section .data
default rel

align 16
ONE:
        dq     0x0000000000000001, 0x0000000000000000

align 64
SHUF_MASK:
        dq     0x08090A0B0C0D0E0F, 0x0001020304050607
        dq     0x08090A0B0C0D0E0F, 0x0001020304050607
        dq     0x08090A0B0C0D0E0F, 0x0001020304050607
        dq     0x08090A0B0C0D0E0F, 0x0001020304050607

align 64
ddq_add_13_16:
        dq	0x000000000000000d, 0x0000000000000000
        dq	0x000000000000000e, 0x0000000000000000
        dq	0x000000000000000f, 0x0000000000000000
        dq	0x0000000000000010, 0x0000000000000000

align 64
ddq_add_9_12:
        dq	0x0000000000000009, 0x0000000000000000
        dq	0x000000000000000a, 0x0000000000000000
        dq	0x000000000000000b, 0x0000000000000000
        dq	0x000000000000000c, 0x0000000000000000

align 64
ddq_add_5_8:
        dq	0x0000000000000005, 0x0000000000000000
        dq	0x0000000000000006, 0x0000000000000000
        dq	0x0000000000000007, 0x0000000000000000
        dq	0x0000000000000008, 0x0000000000000000

align 64
ddq_add_1_4:
        dq	0x0000000000000001, 0x0000000000000000
        dq	0x0000000000000002, 0x0000000000000000
        dq	0x0000000000000003, 0x0000000000000000
        dq	0x0000000000000004, 0x0000000000000000

align 64
ddq_add_12_15:
        dq	0x000000000000000c, 0x0000000000000000
        dq	0x000000000000000d, 0x0000000000000000
        dq	0x000000000000000e, 0x0000000000000000
        dq	0x000000000000000f, 0x0000000000000000

align 64
ddq_add_8_11:
        dq	0x0000000000000008, 0x0000000000000000
        dq	0x0000000000000009, 0x0000000000000000
        dq	0x000000000000000a, 0x0000000000000000
        dq	0x000000000000000b, 0x0000000000000000

align 64
ddq_add_4_7:
        dq	0x0000000000000004, 0x0000000000000000
        dq	0x0000000000000005, 0x0000000000000000
        dq	0x0000000000000006, 0x0000000000000000
        dq	0x0000000000000007, 0x0000000000000000

align 64
ddq_add_0_3:
        dq	0x0000000000000000, 0x0000000000000000
        dq	0x0000000000000001, 0x0000000000000000
        dq	0x0000000000000002, 0x0000000000000000
        dq	0x0000000000000003, 0x0000000000000000

align 64
ddq_add_16:
        dq	0x0000000000000010, 0x0000000000000000
        dq	0x0000000000000010, 0x0000000000000000
        dq	0x0000000000000010, 0x0000000000000000
        dq	0x0000000000000010, 0x0000000000000000

align 64
byte_len_to_mask_table:
        dw      0x0000, 0x0001, 0x0003, 0x0007,
        dw      0x000f, 0x001f, 0x003f, 0x007f,
        dw      0x00ff, 0x01ff, 0x03ff, 0x07ff,
        dw      0x0fff, 0x1fff, 0x3fff, 0x7fff,
        dw      0xffff

align 64
byte64_len_to_mask_table:
        dq      0x0000000000000000, 0x0000000000000001
        dq      0x0000000000000003, 0x0000000000000007
        dq      0x000000000000000f, 0x000000000000001f
        dq      0x000000000000003f, 0x000000000000007f
        dq      0x00000000000000ff, 0x00000000000001ff
        dq      0x00000000000003ff, 0x00000000000007ff
        dq      0x0000000000000fff, 0x0000000000001fff
        dq      0x0000000000003fff, 0x0000000000007fff
        dq      0x000000000000ffff, 0x000000000001ffff
        dq      0x000000000003ffff, 0x000000000007ffff
        dq      0x00000000000fffff, 0x00000000001fffff
        dq      0x00000000003fffff, 0x00000000007fffff
        dq      0x0000000000ffffff, 0x0000000001ffffff
        dq      0x0000000003ffffff, 0x0000000007ffffff
        dq      0x000000000fffffff, 0x000000001fffffff
        dq      0x000000003fffffff, 0x000000007fffffff
        dq      0x00000000ffffffff, 0x00000001ffffffff
        dq      0x00000003ffffffff, 0x00000007ffffffff
        dq      0x0000000fffffffff, 0x0000001fffffffff
        dq      0x0000003fffffffff, 0x0000007fffffffff
        dq      0x000000ffffffffff, 0x000001ffffffffff
        dq      0x000003ffffffffff, 0x000007ffffffffff
        dq      0x00000fffffffffff, 0x00001fffffffffff
        dq      0x00003fffffffffff, 0x00007fffffffffff
        dq      0x0000ffffffffffff, 0x0001ffffffffffff
        dq      0x0003ffffffffffff, 0x0007ffffffffffff
        dq      0x000fffffffffffff, 0x001fffffffffffff
        dq      0x003fffffffffffff, 0x007fffffffffffff
        dq      0x00ffffffffffffff, 0x01ffffffffffffff
        dq      0x03ffffffffffffff, 0x07ffffffffffffff
        dq      0x0fffffffffffffff, 0x1fffffffffffffff
        dq      0x3fffffffffffffff, 0x7fffffffffffffff
        dq      0xffffffffffffffff

align 16
initial_12_IV_counter:
        dq      0x0000000000000000, 0x0100000000000000

mask_16_bytes:
        dq      0x000000000000ffff

section .text
default rel

%ifdef LINUX
%define arg1	  rdi
%else
%define arg1	  rcx
%endif

%define ZKEY0                 zmm17
%define ZKEY1                 zmm18
%define ZKEY2                 zmm19
%define ZKEY3                 zmm20
%define ZKEY4                 zmm21
%define ZKEY5                 zmm22
%define ZKEY6                 zmm23
%define ZKEY7                 zmm24
%define ZKEY8                 zmm25
%define ZKEY9                 zmm26
%define ZKEY10                zmm27
%define ZKEY11                zmm28
%define ZKEY12                zmm29
%define ZKEY13                zmm30
%define ZKEY14                zmm31

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Stack frame definition
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifidn __OUTPUT_FORMAT__, win64
        %define GP_STORAGE      (7*8)  ; space for 7 GP registers
%else
        %define GP_STORAGE      (5*8)  ; space for 5 GP registers
%endif

%define STACK_FRAME_SIZE        GP_STORAGE

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Utility Macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; This macro is used to maintain the bits from the output text
;;; when writing out the output blocks, in case there are some bits
;;; that do not require encryption
%macro PRESERVE_BITS            12-13
%define %%RBITS                 %1      ; [in] Remaining bits in last byte
%define %%LENGTH                %2      ; [in] Length of the last set of blocks
%define %%CYPH_PLAIN_OUT        %3      ; [in] Pointer to output buffer
%define %%ZIN_OUT               %4      ; [in/out] ZMM with last set of output blocks
%define %%ZTMP0                 %5      ; [clobbered] ZMM temporary
%define %%ZTMP1                 %6      ; [clobbered] ZMM temporary
%define %%ZTMP2                 %7      ; [clobbered] ZMM temporary
%define %%IA0                   %8      ; [clobbered] GP temporary
%define %%IA1                   %9      ; [clobbered] GP temporary
%define %%blocks_to_skip        %10     ; [in] Number of blocks to skip from output
%define %%FULL_PARTIAL          %11     ; [in] Last block type selection "full" or "partial"
%define %%MASKREG               %12     ; [clobbered] Mask register
%define %%DATA_OFFSET           %13     ; [in/out] Data offset
%define %%NUM_ARGS              %0

;; offset = number of sets of 4 blocks to skip
%assign offset (((%%blocks_to_skip) / 4) * 64)
;; num_left_blocks = number of blocks in the last set
%assign num_left_blocks (((%%blocks_to_skip) & 3) + 1) ;; Range 1-4 blocks

%if %%NUM_ARGS == 13
        ;; Load output to get last partial byte
%ifidn %%FULL_PARTIAL, partial
        vmovdqu8        %%ZTMP0{%%MASKREG}, [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + offset]
%else
        vmovdqu8        %%ZTMP0, [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + offset]
%endif ; %%FULL_PARTIAL == partial
%else
        ;; Load output to get last partial byte (loading up to the last 4 blocks)
        ZMM_LOAD_MASKED_BLOCKS_0_16 num_left_blocks, %%CYPH_PLAIN_OUT, offset, \
                        %%ZTMP0, no_zmm, no_zmm, no_zmm, %%MASKREG
%endif ;; %%NUM_ARGS == 13

        ;; Save RCX in temporary GP register
        mov             %%IA0, rcx
        mov             DWORD(%%IA1), 0xff
        mov             cl, BYTE(%%RBITS)
        shr             DWORD(%%IA1), cl ;; e.g. 3 remaining bits -> mask = 00011111
        mov             rcx, %%IA0

        vmovq           XWORD(%%ZTMP1), %%IA1

        ;; Get number of full bytes in last block.
        ;; Subtracting the bytes in the blocks to skip to the length of whole
        ;; set of blocks gives us the number of bytes in the last block,
        ;; but the last block has a partial byte at the end, so an extra byte
        ;; needs to be subtracted
        mov             %%IA1, %%LENGTH
        sub             %%IA1, (%%blocks_to_skip * 16 + 1)
        XVPSLLB         XWORD(%%ZTMP1), %%IA1, XWORD(%%ZTMP2), %%IA0
%if num_left_blocks == 4
        vshufi64x2      %%ZTMP1, %%ZTMP1, %%ZTMP1, 0x15
%elif num_left_blocks == 3
        vshufi64x2      %%ZTMP1, %%ZTMP1, %%ZTMP1, 0x45
%elif num_left_blocks == 2
        vshufi64x2      %%ZTMP1, %%ZTMP1, %%ZTMP1, 0x51
%endif ;; No need to shift if there is only one block

        ;; At this point, ZTMP1 contains a mask with all 0s, but with some ones
        ;; in the partial byte

        ;; First, clear the last bits (not to be ciphered) of the last output block
        ;; %%ZIN_OUT = %%ZIN_OUT AND NOT %%ZTMP1  (0x50 = andA!C)
        vpternlogq      %%ZIN_OUT, %%ZTMP1, %%ZTMP1, 0x50

        ;; Then, set these last bits to the last bits coming from the output
        ;; %%ZIN_OUT = %%ZIN_OUT OR (%%ZTMP0 AND %%ZTMP1)  (0xF8 = orAandBC)
        vpternlogq      %%ZIN_OUT, %%ZTMP0, %%ZTMP1, 0xF8

%endmacro
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; This macro is used to "warm-up" pipeline for ENCRYPT_16_PARALLEL
;;; macro code. It is called only for data lengths 256 and above.
;;; The flow is as follows:
;;; - encrypt the initial %%num_initial_blocks blocks (can be 0)
;;; - encrypt the next 16 blocks
;;;   - the last 16th block can be partial (lengths between 257 and 367)
;;;   - partial block ciphering is handled within this macro

%macro INITIAL_BLOCKS 26
%define %%KEY                   %1      ; [in] pointer to key
%define %%CYPH_PLAIN_OUT        %2      ; [in] output buffer
%define %%PLAIN_CYPH_IN         %3      ; [in] input buffer
%define %%LENGTH                %4      ; [in/out] number of bytes to process
%define %%DATA_OFFSET           %5      ; [in/out] data offset
%define %%num_initial_blocks    %6      ; [in] can be between 0 and 15
%define %%CTR                   %7      ; [in] XMM first counter block
%define %%CTR_1_4               %8      ; [out] ZMM next 1-4 counter blocks
%define %%CTR_5_8               %9      ; [out] ZMM next 5-8 counter blocks
%define %%CTR_9_12              %10     ; [out] ZMM next 9-12 counter blocks
%define %%CTR_13_16             %11     ; [out] ZMM next 13-16 counter blocks
%define %%ZT1                   %12     ; [clobbered] ZMM temporary
%define %%ZT2                   %13     ; [clobbered] ZMM temporary
%define %%ZT3                   %14     ; [clobbered] ZMM temporary
%define %%ZT4                   %15     ; [clobbered] ZMM temporary
%define %%ZT5                   %16     ; [clobbered] ZMM temporary
%define %%ZT6                   %17     ; [clobbered] ZMM temporary
%define %%ZT7                   %18     ; [clobbered] ZMM temporary
%define %%ZT8                   %19     ; [clobbered] ZMM temporary
%define %%IA0                   %20     ; [clobbered] GP temporary
%define %%IA1                   %21     ; [clobbered] GP temporary
%define %%MASKREG               %22     ; [clobbered] mask register
%define %%SHUFREG               %23     ; [in] ZMM register with shuffle mask
%define %%NROUNDS               %24     ; [in] number of rounds; numerical value
%define %%CNTR_TYPE             %25     ; [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
%define %%RBITS                 %26     ; [in] Number of remaining bits in last byte

%define %%T1 XWORD(%%ZT1)
%define %%T2 XWORD(%%ZT2)
%define %%T3 XWORD(%%ZT3)
%define %%T4 XWORD(%%ZT4)
%define %%T5 XWORD(%%ZT5)
%define %%T6 XWORD(%%ZT6)
%define %%T7 XWORD(%%ZT7)
%define %%T8 XWORD(%%ZT8)

%ifidn %%CNTR_TYPE, CNTR
%define %%VPADD vpaddd
%else
%define %%VPADD vpaddq
%endif

%if %%num_initial_blocks > 0
        ;; load plain/cipher text
        ZMM_LOAD_BLOCKS_0_16 %%num_initial_blocks, %%PLAIN_CYPH_IN, 0, \
                        %%ZT5, %%ZT6, %%ZT7, %%ZT8, load_4_instead_of_3

        ;; prepare AES counter blocks
%if %%num_initial_blocks > 1
%if %%num_initial_blocks == 2
        vshufi64x2      YWORD(%%ZT1), YWORD(%%CTR), YWORD(%%CTR), 0
        %%VPADD         YWORD(%%ZT1), YWORD(%%ZT1), [rel ddq_add_0_3]
%elif %%num_initial_blocks <= 4
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        %%VPADD         %%ZT1, ZWORD(%%CTR), [rel ddq_add_0_3]
%elif %%num_initial_blocks <= 8
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        %%VPADD         %%ZT1, ZWORD(%%CTR), [rel ddq_add_0_3]
        %%VPADD         %%ZT2, ZWORD(%%CTR), [rel ddq_add_4_7]
%elif %%num_initial_blocks <= 12
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        %%VPADD         %%ZT1, ZWORD(%%CTR), [rel ddq_add_0_3]
        %%VPADD         %%ZT2, ZWORD(%%CTR), [rel ddq_add_4_7]
        %%VPADD         %%ZT3, ZWORD(%%CTR), [rel ddq_add_8_11]
%else
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        %%VPADD         %%ZT1, ZWORD(%%CTR), [rel ddq_add_0_3]
        %%VPADD         %%ZT2, ZWORD(%%CTR), [rel ddq_add_4_7]
        %%VPADD         %%ZT3, ZWORD(%%CTR), [rel ddq_add_8_11]
        %%VPADD         %%ZT4, ZWORD(%%CTR), [rel ddq_add_12_15]
%endif
%endif

        ;; extract new counter value (%%T1)
        ;; shuffle the counters for AES rounds
%if %%num_initial_blocks == 1
        vpshufb         %%T1, %%CTR, XWORD(%%SHUFREG)
%elif %%num_initial_blocks == 2
        vextracti32x4   %%CTR, YWORD(%%ZT1), 1
        vpshufb         YWORD(%%ZT1), YWORD(%%SHUFREG)
%elif %%num_initial_blocks <= 4
        vextracti32x4   %%CTR, %%ZT1, (%%num_initial_blocks - 1)
        vpshufb         %%ZT1, %%SHUFREG
%elif %%num_initial_blocks == 5
        vmovdqa64       %%CTR, %%T2
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%T2, XWORD(%%SHUFREG)
%elif %%num_initial_blocks == 6
        vextracti32x4   %%CTR, YWORD(%%ZT2), 1
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         YWORD(%%ZT2), YWORD(%%SHUFREG)
%elif %%num_initial_blocks = 7
        vextracti32x4   %%CTR, %%ZT2, 2
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
%elif %%num_initial_blocks = 8
        vextracti32x4   %%CTR, %%ZT2, 3
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
%elif %%num_initial_blocks = 9
        vmovdqa64       %%CTR, %%T3
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
        vpshufb         %%T3, XWORD(%%SHUFREG)
%elif %%num_initial_blocks = 10
        vextracti32x4   %%CTR, YWORD(%%ZT3), 1
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
        vpshufb         YWORD(%%ZT3), YWORD(%%SHUFREG)
%elif %%num_initial_blocks = 11
        vextracti32x4   %%CTR, %%ZT3, 2
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
        vpshufb         %%ZT3, %%SHUFREG
%elif %%num_initial_blocks = 12
        vextracti32x4   %%CTR, %%ZT3, 3
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
        vpshufb         %%ZT3, %%SHUFREG
%elif %%num_initial_blocks = 13
        vmovdqa64       %%CTR, %%T4
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
        vpshufb         %%ZT3, %%SHUFREG
        vpshufb         %%T4, XWORD(%%SHUFREG)
%elif %%num_initial_blocks = 14
        vextracti32x4   %%CTR, YWORD(%%ZT4), 1
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
        vpshufb         %%ZT3, %%SHUFREG
        vpshufb         YWORD(%%ZT4), YWORD(%%SHUFREG)
%elif %%num_initial_blocks = 15
        vextracti32x4   %%CTR, %%ZT4, 2
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
        vpshufb         %%ZT3, %%SHUFREG
        vpshufb         %%ZT4, %%SHUFREG
%endif

        ;; AES rounds and XOR with plain/cipher text
%assign j 0
%rep (%%NROUNDS + 2)
        ZMM_AESENC_ROUND_BLOCKS_0_16 \
                        %%ZT1, %%ZT2, %%ZT3, %%ZT4, ZKEY %+ j, j, \
                        %%ZT5, %%ZT6, %%ZT7, %%ZT8, %%num_initial_blocks, \
                        %%NROUNDS
%assign j (j + 1)
%endrep

        ;; write cipher/plain text back to output
        ZMM_STORE_BLOCKS_0_16 %%num_initial_blocks, %%CYPH_PLAIN_OUT, 0, \
                        %%ZT1, %%ZT2, %%ZT3, %%ZT4

        ;; adjust data offset and length
        sub             %%LENGTH, (%%num_initial_blocks * 16)
        add             %%DATA_OFFSET, (%%num_initial_blocks * 16)
%endif                          ;  %%num_initial_blocks > 0

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; - cipher of %%num_initial_blocks is done
        ;; - prepare counter blocks for the next 16 blocks (ZT5-ZT8)
        ;;   - shuffle the blocks for AES
        ;; - encrypt the next 16 blocks

        ;; get text load/store mask (assume full mask by default)
        mov             %%IA0, 0xffff_ffff_ffff_ffff
%if %%num_initial_blocks > 0
        ;; NOTE: 'jge' is always taken for %%num_initial_blocks = 0
        ;;      This macro is executed for length 256 and up,
        ;;      zero length is checked in CNTR_ENC_DEC.
        ;; We know there is partial block if:
        ;;      LENGTH - 16*num_initial_blocks < 256
        cmp             %%LENGTH, 256
        jge             %%_initial_partial_block_continue
        mov             %%IA1, rcx
        mov             rcx, 256
        sub             rcx, %%LENGTH
        shr             %%IA0, cl
        mov             rcx, %%IA1
%%_initial_partial_block_continue:
%endif
        kmovq           %%MASKREG, %%IA0
        ;; load plain or cipher text
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT6, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
        vmovdqu8        %%ZT7, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 128]
        vmovdqu8        %%ZT8{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 192]

        ;; prepare next counter blocks
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
%if %%num_initial_blocks > 0
        %%VPADD         %%CTR_1_4, ZWORD(%%CTR), [rel ddq_add_1_4]
        %%VPADD         %%CTR_5_8, ZWORD(%%CTR), [rel ddq_add_5_8]
        %%VPADD         %%CTR_9_12, ZWORD(%%CTR), [rel ddq_add_9_12]
        %%VPADD         %%CTR_13_16, ZWORD(%%CTR), [rel ddq_add_13_16]
%else
        %%VPADD         %%CTR_1_4, ZWORD(%%CTR), [rel ddq_add_0_3]
        %%VPADD         %%CTR_5_8, ZWORD(%%CTR), [rel ddq_add_4_7]
        %%VPADD         %%CTR_9_12, ZWORD(%%CTR), [rel ddq_add_8_11]
        %%VPADD         %%CTR_13_16, ZWORD(%%CTR), [rel ddq_add_12_15]
%endif

        vpshufb         %%ZT1, %%CTR_1_4, %%SHUFREG
        vpshufb         %%ZT2, %%CTR_5_8, %%SHUFREG
        vpshufb         %%ZT3, %%CTR_9_12, %%SHUFREG
        vpshufb         %%ZT4, %%CTR_13_16, %%SHUFREG

        ;; AES rounds and XOR with plain/cipher text
%assign j 0
%rep (%%NROUNDS + 2)
        ZMM_AESENC_ROUND_BLOCKS_0_16 \
                        %%ZT1, %%ZT2, %%ZT3, %%ZT4, ZKEY %+ j, j, \
                        %%ZT5, %%ZT6, %%ZT7, %%ZT8, 16, %%NROUNDS
%assign j (j + 1)
%endrep

%ifidn %%CNTR_TYPE, CNTR_BIT
        ;; check if this is the end of the message
        cmp             %%LENGTH, 256
        jg              %%store_output
        ;; Check if there is a partial byte
        or              %%RBITS, %%RBITS
        jz              %%store_output

        ;; Copy the bits that are not ciphered from the output text,
        ;; into the last bits of the output block, before writing it out
        PRESERVE_BITS   %%RBITS, %%LENGTH, %%CYPH_PLAIN_OUT, %%ZT4, %%ZT5, %%ZT6, %%ZT7, \
                        %%IA0, %%IA1, 15, partial, %%MASKREG, %%DATA_OFFSET

%endif

%%store_output:
        ;; write cipher/plain text back to output
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64], %%ZT2
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 128], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 192]{%%MASKREG}, %%ZT4

        ;; check if there is partial block
        cmp             %%LENGTH, 256
        jl              %%_initial_partial_done
        ;; adjust offset and length
        add             %%DATA_OFFSET, 256
        sub             %%LENGTH, 256
        jmp             %%_initial_blocks_done
%%_initial_partial_done:
        ;; zero the length (all encryption is complete)
        xor             %%LENGTH, %%LENGTH
%%_initial_blocks_done:

%endmacro                       ; INITIAL_BLOCKS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; INITIAL_BLOCKS_PARTIAL macro with support for a partial final block.
;;; It may look similar to INITIAL_BLOCKS but its usage is different:
;;; - It is not meant to cipher counter blocks for the main by16 loop.
;;;   Just ciphers amount of blocks.
;;; - Small packets (<256 bytes)
;;;
;;; num_initial_blocks is expected to include the partial final block
;;; in the count.
%macro INITIAL_BLOCKS_PARTIAL 21
%define %%KEY                   %1  ; [in] key pointer
%define %%CYPH_PLAIN_OUT        %2  ; [in] text out pointer
%define %%PLAIN_CYPH_IN         %3  ; [in] text out pointer
%define %%LENGTH                %4  ; [in/clobbered] length in bytes
%define %%num_initial_blocks    %5  ; [in] can be from 1 to 16 (not 0)
%define %%CTR                   %6  ; [in/out] current counter value
%define %%ZT1                   %7  ; [clobbered] ZMM temporary
%define %%ZT2                   %8  ; [clobbered] ZMM temporary
%define %%ZT3                   %9  ; [clobbered] ZMM temporary
%define %%ZT4                   %10 ; [clobbered] ZMM temporary
%define %%ZT5                   %11 ; [clobbered] ZMM temporary
%define %%ZT6                   %12 ; [clobbered] ZMM temporary
%define %%ZT7                   %13 ; [clobbered] ZMM temporary
%define %%ZT8                   %14 ; [clobbered] ZMM temporary
%define %%IA0                   %15 ; [clobbered] GP temporary
%define %%IA1                   %16 ; [clobbered] GP temporary
%define %%MASKREG               %17 ; [clobbered] mask register
%define %%SHUFREG               %18 ; [in] ZMM register with shuffle mask
%define %%NROUNDS               %19 ; [in] number of rounds; numerical value
%define %%CNTR_TYPE             %20 ; [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
%define %%RBITS                 %21 ; [in] Number of remaining bits in last byte

%ifidn %%CNTR_TYPE, CNTR
%define %%VPADD vpaddd
%else
%define %%VPADD vpaddq
%endif

%define %%T1 XWORD(%%ZT1)
%define %%T2 XWORD(%%ZT2)
%define %%T3 XWORD(%%ZT3)
%define %%T4 XWORD(%%ZT4)
%define %%T5 XWORD(%%ZT5)
%define %%T6 XWORD(%%ZT6)
%define %%T7 XWORD(%%ZT7)
%define %%T8 XWORD(%%ZT8)

        ;; get load/store mask
        lea             %%IA0, [rel byte64_len_to_mask_table]
        mov             %%IA1, %%LENGTH
%if %%num_initial_blocks > 12
        sub             %%IA1, 192
%elif %%num_initial_blocks > 8
        sub             %%IA1, 128
%elif %%num_initial_blocks > 4
        sub             %%IA1, 64
%endif
        kmovq           %%MASKREG, [%%IA0 + %%IA1*8]

        ;; load plain/cipher text
        ZMM_LOAD_MASKED_BLOCKS_0_16 %%num_initial_blocks, %%PLAIN_CYPH_IN, 0, \
                        %%ZT5, %%ZT6, %%ZT7, %%ZT8, %%MASKREG

        ;; prepare AES counter blocks
%if %%num_initial_blocks == 1
        vmovdqa64       XWORD(%%ZT1), XWORD(%%CTR)
%elif %%num_initial_blocks == 2
        vshufi64x2      YWORD(%%ZT1), YWORD(%%CTR), YWORD(%%CTR), 0
        %%VPADD          YWORD(%%ZT1), YWORD(%%ZT1), [rel ddq_add_0_3]
%elif %%num_initial_blocks <= 4
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        %%VPADD          %%ZT1, ZWORD(%%CTR), [rel ddq_add_0_3]
%elif %%num_initial_blocks <= 8
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        %%VPADD          %%ZT1, ZWORD(%%CTR), [rel ddq_add_0_3]
        %%VPADD          %%ZT2, ZWORD(%%CTR), [rel ddq_add_4_7]
%elif %%num_initial_blocks <= 12
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        %%VPADD          %%ZT1, ZWORD(%%CTR), [rel ddq_add_0_3]
        %%VPADD          %%ZT2, ZWORD(%%CTR), [rel ddq_add_4_7]
        %%VPADD          %%ZT3, ZWORD(%%CTR), [rel ddq_add_8_11]
%else
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        %%VPADD          %%ZT1, ZWORD(%%CTR), [rel ddq_add_0_3]
        %%VPADD          %%ZT2, ZWORD(%%CTR), [rel ddq_add_4_7]
        %%VPADD          %%ZT3, ZWORD(%%CTR), [rel ddq_add_8_11]
        %%VPADD          %%ZT4, ZWORD(%%CTR), [rel ddq_add_12_15]
%endif

        ;; shuffle the counters for AES rounds
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%num_initial_blocks, vpshufb, \
                        %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        %%ZT1, %%ZT2, %%ZT3, %%ZT4, \
                        %%SHUFREG, %%SHUFREG, %%SHUFREG, %%SHUFREG

        ;; AES rounds and XOR with plain/cipher text
%assign j 0
%rep (%%NROUNDS + 2)
        ZMM_AESENC_ROUND_BLOCKS_0_16 \
                        %%ZT1, %%ZT2, %%ZT3, %%ZT4, ZKEY %+ j, j, \
                        %%ZT5, %%ZT6, %%ZT7, %%ZT8, %%num_initial_blocks, \
                        %%NROUNDS
%assign j (j + 1)
%endrep

%ifidn %%CNTR_TYPE, CNTR_BIT
        ;; Check if there is a partial byte
        or              %%RBITS, %%RBITS
        jz              %%store_output

        ;; Copy the bits that are not ciphered from the output text,
        ;; into the last bits of the output block, before writing it out
%if %%num_initial_blocks <= 4
        PRESERVE_BITS   %%RBITS, %%LENGTH, %%CYPH_PLAIN_OUT, %%ZT1, %%ZT5, %%ZT6, %%ZT7, \
                        %%IA0, %%IA1, (%%num_initial_blocks - 1), \
                        partial, %%MASKREG
%elif %%num_initial_blocks <= 8
        PRESERVE_BITS   %%RBITS, %%LENGTH, %%CYPH_PLAIN_OUT, %%ZT2, %%ZT5, %%ZT6, %%ZT7, \
                        %%IA0, %%IA1, (%%num_initial_blocks - 1), \
                        partial, %%MASKREG
%elif %%num_initial_blocks <= 12
        PRESERVE_BITS   %%RBITS, %%LENGTH, %%CYPH_PLAIN_OUT, %%ZT3, %%ZT5, %%ZT6, %%ZT7, \
                        %%IA0, %%IA1, (%%num_initial_blocks - 1), \
                        partial, %%MASKREG
%else
        PRESERVE_BITS   %%RBITS, %%LENGTH, %%CYPH_PLAIN_OUT, %%ZT4, %%ZT5, %%ZT6, %%ZT7, \
                        %%IA0, %%IA1, (%%num_initial_blocks - 1), \
                        partial, %%MASKREG
%endif

%endif

%%store_output:
        ;; write cipher/plain text back to output
        ZMM_STORE_MASKED_BLOCKS_0_16 %%num_initial_blocks, %%CYPH_PLAIN_OUT, 0, \
                        %%ZT1, %%ZT2, %%ZT3, %%ZT4, %%MASKREG

%endmacro                       ; INITIAL_BLOCKS_PARTIAL



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Main CNTR macro
;;; - operates on single stream
;;; - encrypts 16 blocks at a time
%macro  ENCRYPT_16_PARALLEL 26
%define %%KEY                   %1  ; [in] key pointer
%define %%CYPH_PLAIN_OUT        %2  ; [in] pointer to output buffer
%define %%PLAIN_CYPH_IN         %3  ; [in] pointer to input buffer
%define %%DATA_OFFSET           %4  ; [in] data offset
%define %%CTR_1_4               %5  ; [in/out] ZMM next 1-4 counter blocks
%define %%CTR_5_8               %6  ; [in/out] ZMM next 5-8 counter blocks
%define %%CTR_9_12              %7  ; [in/out] ZMM next 9-12 counter blocks
%define %%CTR_13_16             %8  ; [in/out] ZMM next 13-16 counter blocks
%define %%FULL_PARTIAL          %9  ; [in] last block type selection "full" or "partial"
%define %%IA0                   %10 ; [clobbered] temporary GP register
%define %%IA1                   %11 ; [clobbered] temporary GP register
%define %%LENGTH                %12 ; [in] length
%define %%ZT1                   %13 ; [clobbered] temporary ZMM (cipher)
%define %%ZT2                   %14 ; [clobbered] temporary ZMM (cipher)
%define %%ZT3                   %15 ; [clobbered] temporary ZMM (cipher)
%define %%ZT4                   %16 ; [clobbered] temporary ZMM (cipher)
%define %%ZT5                   %17 ; [clobbered] temporary ZMM (cipher)
%define %%ZT6                   %18 ; [clobbered] temporary ZMM (cipher)
%define %%ZT7                   %19 ; [clobbered] temporary ZMM (cipher)
%define %%ZT8                   %20 ; [clobbered] temporary ZMM (cipher)
%define %%MASKREG               %21 ; [clobbered] mask register for partial loads/stores
%define %%SHUFREG               %22 ; [in] ZMM register with shuffle mask
%define %%ADD8REG               %23 ; [in] ZMM register with increment by 8 mask
%define %%NROUNDS               %24 ; [in] number of rounds; numerical value
%define %%CNTR_TYPE             %25 ; [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
%define %%RBITS                 %26 ; [in] Number of remaining bits in last byte

%ifidn %%CNTR_TYPE, CNTR
%define %%VPADD vpaddd
%else
%define %%VPADD vpaddq
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; load/store mask (partial case) and load the text data
%ifidn %%FULL_PARTIAL, full
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT6, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
        vmovdqu8        %%ZT7, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 128]
        vmovdqu8        %%ZT8, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 192]
%else
        lea             %%IA0, [rel byte64_len_to_mask_table]
        mov             %%IA1, %%LENGTH
        sub             %%IA1, (3*64)
        kmovq           %%MASKREG, [%%IA0 + 8*%%IA1]
        vmovdqu8        %%ZT5, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT6, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
        vmovdqu8        %%ZT7, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 128]
        vmovdqu8        %%ZT8{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 192]
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; populate counter blocks
        ;; %%CTR is shuffled outside the scope of this macro
        ;; it has to be kept in unshuffled form
        %%VPADD          %%CTR_1_4, %%CTR_1_4, %%ADD8REG
        %%VPADD          %%CTR_5_8, %%CTR_5_8, %%ADD8REG
        %%VPADD          %%CTR_9_12, %%CTR_9_12, %%ADD8REG
        %%VPADD          %%CTR_13_16, %%CTR_13_16, %%ADD8REG

        vpshufb         %%ZT1, %%CTR_1_4, %%SHUFREG
        vpshufb         %%ZT2, %%CTR_5_8, %%SHUFREG
        vpshufb         %%ZT3, %%CTR_9_12, %%SHUFREG
        vpshufb         %%ZT4, %%CTR_13_16, %%SHUFREG

%assign j 0
%rep (%%NROUNDS + 2)
        ZMM_AESENC_ROUND_BLOCKS_0_16 \
                        %%ZT1, %%ZT2, %%ZT3, %%ZT4, ZKEY %+ j, j, \
                        %%ZT5, %%ZT6, %%ZT7, %%ZT8, 16, %%NROUNDS
%assign j (j + 1)
%endrep

%ifidn %%CNTR_TYPE, CNTR_BIT
        ;; Check if this is the last round
        cmp             %%LENGTH, 256
        jg              %%store_output
        ;; Check if there is a partial byte
        or              %%RBITS, %%RBITS
        jz              %%store_output

        ;; Copy the bits that are not ciphered from the output text,
        ;; into the last bits of the output block, before writing it out
        PRESERVE_BITS   %%RBITS, %%LENGTH, %%CYPH_PLAIN_OUT, %%ZT4, %%ZT5, %%ZT6, %%ZT7, \
                        %%IA0, %%IA1, 15, %%FULL_PARTIAL, %%MASKREG, %%DATA_OFFSET

%endif

%%store_output:

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; store the text data
%ifidn %%FULL_PARTIAL, full
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64], %%ZT2
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 128], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 192], %%ZT4
%else
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64], %%ZT2
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 128], %%ZT3
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 192]{%%MASKREG}, %%ZT4
%endif

%endmacro                       ; ENCRYPT_16_PARALLEL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Save register content for the caller
%macro FUNC_SAVE 1
%define %%CNTR_TYPE         %1  ; [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
        mov     rax, rsp

        sub     rsp, STACK_FRAME_SIZE
        and     rsp, ~63

        mov     [rsp + 0*8], r12
        mov     [rsp + 1*8], r13
%ifidn %%CNTR_TYPE, CNTR_BIT
        mov     [rsp + 2*8], r14
%endif
        mov     [rsp + 3*8], rax ; stack
%ifidn __OUTPUT_FORMAT__, win64
        mov     [rsp + 4*8], rdi
        mov     [rsp + 5*8], rsi
%endif

%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Restore register content for the caller
%macro FUNC_RESTORE 1
%define %%CNTR_TYPE         %1  ; [in] Type of CNTR operation to do (CNTR/CNTR_BIT)

%ifdef SAFE_DATA
	clear_all_zmms_asm
%else
        vzeroupper
%endif ;; SAFE_DATA

%ifidn __OUTPUT_FORMAT__, win64
        mov     rdi, [rsp + 4*8]
        mov     rsi, [rsp + 5*8]
%endif
        mov     r12, [rsp + 0*8]
        mov     r13, [rsp + 1*8]
%ifidn %%CNTR_TYPE, CNTR_BIT
        mov     r14, [rsp + 2*8]
%endif
        mov     rsp, [rsp + 3*8] ; stack
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Cipher payloads shorter than 256 bytes
;;; - number of blocks in the message comes as argument
;;; - depending on the number of blocks an optimized variant of
;;;   INITIAL_BLOCKS_PARTIAL is invoked
%macro  CNTR_ENC_DEC_SMALL   21
%define %%KEY               %1  ; [in] key pointer
%define %%CYPH_PLAIN_OUT    %2  ; [in] output buffer
%define %%PLAIN_CYPH_IN     %3  ; [in] input buffer
%define %%LENGTH            %4  ; [in] data length
%define %%NUM_BLOCKS        %5  ; [in] number of blocks to process 1 to 8
%define %%CTR               %6  ; [in/out] XMM counter block
%define %%ZTMP1             %7  ; [clobbered] ZMM register
%define %%ZTMP2             %8  ; [clobbered] ZMM register
%define %%ZTMP3             %9  ; [clobbered] ZMM register
%define %%ZTMP4             %10 ; [clobbered] ZMM register
%define %%ZTMP5             %11 ; [clobbered] ZMM register
%define %%ZTMP6             %12 ; [clobbered] ZMM register
%define %%ZTMP7             %13 ; [clobbered] ZMM register
%define %%ZTMP8             %14 ; [clobbered] ZMM register
%define %%IA0               %15 ; [clobbered] GP register
%define %%IA1               %16 ; [clobbered] GP register
%define %%MASKREG           %17 ; [clobbered] mask register
%define %%SHUFREG           %18 ; [in] ZMM register with shuffle mask
%define %%NROUNDS           %19 ; [in] number of rounds; numerical value
%define %%CNTR_TYPE         %20 ; [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
%define %%RBITS             %21 ; [in] Number of remaining bits in last byte

        cmp     %%NUM_BLOCKS, 8
        je      %%_small_initial_num_blocks_is_8
        jl      %%_small_initial_blocks_is_1_7

        ; Initial blocks 9-16
        cmp     %%NUM_BLOCKS, 12
        je      %%_small_initial_num_blocks_is_12
        jl      %%_small_initial_blocks_is_9_11

        ; Initial blocks 13-16
        cmp     %%NUM_BLOCKS, 16
        je      %%_small_initial_num_blocks_is_16
        cmp     %%NUM_BLOCKS, 15
        je      %%_small_initial_num_blocks_is_15
        cmp     %%NUM_BLOCKS, 14
        je      %%_small_initial_num_blocks_is_14
        cmp     %%NUM_BLOCKS, 13
        je      %%_small_initial_num_blocks_is_13

%%_small_initial_blocks_is_9_11:
        cmp     %%NUM_BLOCKS, 11
        je      %%_small_initial_num_blocks_is_11
        cmp     %%NUM_BLOCKS, 10
        je      %%_small_initial_num_blocks_is_10
        cmp     %%NUM_BLOCKS, 9
        je      %%_small_initial_num_blocks_is_9

%%_small_initial_blocks_is_1_7:
        cmp     %%NUM_BLOCKS, 4
        je      %%_small_initial_num_blocks_is_4
        jl      %%_small_initial_blocks_is_1_3

        ; Initial blocks 5-7
        cmp     %%NUM_BLOCKS, 7
        je      %%_small_initial_num_blocks_is_7
        cmp     %%NUM_BLOCKS, 6
        je      %%_small_initial_num_blocks_is_6
        cmp     %%NUM_BLOCKS, 5
        je      %%_small_initial_num_blocks_is_5

%%_small_initial_blocks_is_1_3:
        cmp     %%NUM_BLOCKS, 3
        je      %%_small_initial_num_blocks_is_3
        cmp     %%NUM_BLOCKS, 2
        je      %%_small_initial_num_blocks_is_2

        jmp     %%_small_initial_num_blocks_is_1


%%_small_initial_num_blocks_is_16:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 16, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_15:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 15, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_14:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 14, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_13:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 13, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_12:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 12, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_11:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 11, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_10:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 10, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_9:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 9, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted
%%_small_initial_num_blocks_is_8:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 8, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_7:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 7, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_6:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 6, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_5:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 5, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_4:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 4, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_3:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 3, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_2:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 2, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_1:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 1, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, %%ZTMP5, \
                %%ZTMP6, %%ZTMP7, %%ZTMP8, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS
%%_small_initial_blocks_encrypted:

%endmacro                       ; CNTR_ENC_DEC_SMALL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; CNTR_ENC_DEC Encodes/Decodes given data.
; Requires the input data be at least 1 byte long because of READ_SMALL_INPUT_DATA.
; Input: job structure and number of AES rounds
; Output: job structure
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  CNTR_ENC_DEC         3
%define %%JOB               %1  ; [in/out] job
%define %%NROUNDS           %2  ; [in] number of rounds; numerical value
%define %%CNTR_TYPE         %3  ; [in] Type of CNTR operation to do (CNTR/CNTR_BIT/CCM)

%define %%KEY               rax
%define %%CYPH_PLAIN_OUT    rdx
%define %%PLAIN_CYPH_IN     r8
%define %%LENGTH            r9
%define %%DATA_OFFSET       r13
%define %%RBITS             r14

%define %%IA0               r10
%define %%IA1               r11
%define %%IA2               r12

%define %%CTR_BLOCKx            xmm0
%define %%CTR_BLOCK_1_4          zmm1
%define %%CTR_BLOCK_5_8          zmm2
%define %%CTR_BLOCK_9_12         zmm3
%define %%CTR_BLOCK_13_16        zmm4

%define %%ZTMP0                 zmm5
%define %%ZTMP1                 zmm6
%define %%ZTMP2                 zmm7
%define %%ZTMP3                 zmm8
%define %%ZTMP4                 zmm9
%define %%ZTMP5                 zmm10
%define %%ZTMP6                 zmm11
%define %%ZTMP7                 zmm12
%define %%SHUFREG               zmm13
%define %%ADD8REG               zmm14

%define %%MASKREG               k1

;; vars only used for CCM initial block preparation
%define %%FLAGS                 %%IA0
%define %%P_IV                  %%IA1
%define %%IV_LEN                %%IA2
%define %%IV_MASK               r8

;;; Macro flow:
;;; - calculate the number of 16byte blocks in the message
;;; - process (number of 16byte blocks) mod 16 '%%_initial_num_blocks_is_# .. %%_initial_blocks_encrypted'
;;; - process 16x16 byte blocks at a time until all are done in %%_encrypt_by_16_new

%ifidn %%CNTR_TYPE, CCM
       ;; prepare initial block
        mov     %%IV_LEN, [%%JOB + _iv_len_in_bytes]

        ;; Prepare IV ;;
        mov     %%P_IV, [%%JOB + _iv]

        ;; Byte 0: flags with L'
        ;; Calculate L' = 15 - Nonce length - 1 = 14 - IV length
        mov     %%FLAGS, 14
        sub     %%FLAGS, %%IV_LEN

        ;; Bytes 1 - 13: Nonce (7 - 13 bytes long)
        lea     %%IV_MASK, [rel byte_len_to_mask_table]
        kmovw   %%MASKREG, [%%IV_MASK + %%IV_LEN*2]
        vmovdqu8 %%CTR_BLOCKx{%%MASKREG}{z}, [%%P_IV]

        vpslldq %%CTR_BLOCKx, %%CTR_BLOCKx, 1
        vpinsrb %%CTR_BLOCKx, BYTE(%%FLAGS), 0

        ; last byte = 1
        mov     %%IA2, 1
        vpinsrb %%CTR_BLOCKx, BYTE(%%IA2), 15

        mov	%%LENGTH, [%%JOB + _msg_len_to_cipher_in_bytes]

%else ;; CNTR/CNTR_BIT

        mov     %%LENGTH, [%%JOB + _msg_len_to_cipher]
        ;; calculate len
        ;; convert bits to bytes (message length in bits for CNTR_BIT)
%ifidn %%CNTR_TYPE, CNTR_BIT
        mov     %%RBITS, %%LENGTH
        add     %%LENGTH, 7
        shr     %%LENGTH, 3  ; LENGTH will hold number of bytes (including partial byte)
        and     %%RBITS, 7   ; Get remainder bits in last byte (0-7)
%endif

%ifidn __OUTPUT_FORMAT__, win64
        cmp             %%LENGTH, 0
%else
        or              %%LENGTH, %%LENGTH
%endif
        je              %%_enc_dec_done

%endif ;; CNTR_TYPE

        xor             %%DATA_OFFSET, %%DATA_OFFSET

        mov             %%PLAIN_CYPH_IN, [%%JOB + _src]
        add             %%PLAIN_CYPH_IN, [%%JOB + _cipher_start_src_offset_in_bytes]
        mov             %%CYPH_PLAIN_OUT, [%%JOB + _dst]
        mov             %%KEY, [%%JOB + _enc_keys]

        ;; Prepare round keys (only first 10, due to lack of registers)
%assign i 0
%rep (%%NROUNDS + 2)
        vbroadcastf64x2 ZKEY %+ i, [%%KEY + 16*i]
%assign i (i + 1)
%endrep

        mov             %%IA1, [%%JOB + _iv]
%ifidn %%CNTR_TYPE, CNTR
        ;; Prepare initial mask to read 12 IV bytes
        mov             %%IA0, 0x0000_0000_0000_0fff
        vmovdqa         %%CTR_BLOCKx, [rel initial_12_IV_counter]
        mov             %%IA2, [%%JOB + _iv_len_in_bytes]
        test            %%IA2, 16
        ;; Set mask to read 16 IV bytes if iv_len = 16
        cmovnz          %%IA0, [rel mask_16_bytes]

        kmovq           %%MASKREG, %%IA0
        vmovdqu8        %%CTR_BLOCKx{%%MASKREG}, [%%IA1]
%endif ;; CNTR

%ifidn %%CNTR_TYPE, CNTR_BIT
        ;; Read the full 16 bytes of IV
        vmovdqu8        %%CTR_BLOCKx, [%%IA1]
%endif ;; CNTR_BIT

        vmovdqa64       %%SHUFREG, [rel SHUF_MASK]
        ;; store IV as counter in LE format
        vpshufb         %%CTR_BLOCKx, XWORD(%%SHUFREG)

        ;; Determine how many blocks to process in INITIAL
        mov             %%IA1, %%LENGTH
        shr             %%IA1, 4
        and             %%IA1, 0xf

        ;; Process one additional block in INITIAL if there is a partial block
        mov             %%IA0, %%LENGTH
        and             %%IA0, 0xf
        add             %%IA0, 0xf
        shr             %%IA0, 4
        add             %%IA1, %%IA0
        ;; %%IA1 can be in the range from 0 to 16

        ;; Less than 256B will be handled by the small message code, which
        ;; can process up to 16 x blocks (16 bytes each)
        cmp             %%LENGTH, 256
        jge             %%_large_message_path

        CNTR_ENC_DEC_SMALL \
                %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, \
                %%IA1, %%CTR_BLOCKx, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, \
                %%IA0, %%IA2, %%MASKREG, %%SHUFREG, %%NROUNDS, \
                %%CNTR_TYPE, %%RBITS

        jmp     %%_enc_dec_done

%%_large_message_path:
        ;; Still, don't allow 16 INITIAL blocks since this will
        ;; can be handled by the x16 partial loop.
        and             %%IA1, 0xf
        je              %%_initial_num_blocks_is_0
        cmp             %%IA1, 15
        je              %%_initial_num_blocks_is_15
        cmp             %%IA1, 14
        je              %%_initial_num_blocks_is_14
        cmp             %%IA1, 13
        je              %%_initial_num_blocks_is_13
        cmp             %%IA1, 12
        je              %%_initial_num_blocks_is_12
        cmp             %%IA1, 11
        je              %%_initial_num_blocks_is_11
        cmp             %%IA1, 10
        je              %%_initial_num_blocks_is_10
        cmp             %%IA1, 9
        je              %%_initial_num_blocks_is_9
        cmp             %%IA1, 8
        je              %%_initial_num_blocks_is_8
        cmp             %%IA1, 7
        je              %%_initial_num_blocks_is_7
        cmp             %%IA1, 6
        je              %%_initial_num_blocks_is_6
        cmp             %%IA1, 5
        je              %%_initial_num_blocks_is_5
        cmp             %%IA1, 4
        je              %%_initial_num_blocks_is_4
        cmp             %%IA1, 3
        je              %%_initial_num_blocks_is_3
        cmp             %%IA1, 2
        je              %%_initial_num_blocks_is_2
        jmp             %%_initial_num_blocks_is_1

        and     %%IA1, 0xf
        je      %%_initial_num_blocks_is_0

        cmp     %%IA1, 8
        je      %%_initial_num_blocks_is_8
        jl      %%_initial_blocks_is_1_7

        ; Initial blocks 9-15
        cmp     %%IA1, 12
        je      %%_initial_num_blocks_is_12
        jl      %%_initial_blocks_is_9_11

        ; Initial blocks 13-15
        cmp     %%IA1, 15
        je      %%_initial_num_blocks_is_15
        cmp     %%IA1, 14
        je      %%_initial_num_blocks_is_14
        cmp     %%IA1, 13
        je      %%_initial_num_blocks_is_13

%%_initial_blocks_is_9_11:
        cmp     %%IA1, 11
        je      %%_initial_num_blocks_is_11
        cmp     %%IA1, 10
        je      %%_initial_num_blocks_is_10
        cmp     %%IA1, 9
        je      %%_initial_num_blocks_is_9

%%_initial_blocks_is_1_7:
        cmp     %%IA1, 4
        je      %%_initial_num_blocks_is_4
        jl      %%_initial_blocks_is_1_3

        ; Initial blocks 5-7
        cmp     %%IA1, 7
        je      %%_initial_num_blocks_is_7
        cmp     %%IA1, 6
        je      %%_initial_num_blocks_is_6
        cmp     %%IA1, 5
        je      %%_initial_num_blocks_is_5

%%_initial_blocks_is_1_3:
        cmp     %%IA1, 3
        je      %%_initial_num_blocks_is_3
        cmp     %%IA1, 2
        je      %%_initial_num_blocks_is_2

        jmp     %%_initial_num_blocks_is_1

%%_initial_num_blocks_is_15:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 15, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_14:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 14, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_13:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 13, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_12:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 12, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_11:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 11, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_10:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 10, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_9:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 9, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_8:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 8, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_7:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 7, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_6:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 6, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_5:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 5, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_4:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 4, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_3:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 3, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_2:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 2, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_1:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 1, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS
        jmp             %%_initial_blocks_encrypted
%%_initial_num_blocks_is_0:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 0, %%CTR_BLOCKx, \
                %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, %%CTR_BLOCK_9_12, \
                %%CTR_BLOCK_13_16, %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%ZTMP4, %%ZTMP5, %%ZTMP6, %%ZTMP7, %%IA0, %%IA1, %%MASKREG, \
                %%SHUFREG, %%NROUNDS, %%CNTR_TYPE, %%RBITS

%%_initial_blocks_encrypted:
        or              %%LENGTH, %%LENGTH
        je              %%_enc_dec_done

        vmovdqa64       %%ADD8REG, [rel ddq_add_16]
        ;; Process 15 full blocks plus a partial block
        cmp             %%LENGTH, 256
        jl              %%_encrypt_by_16_partial

%%_encrypt_by_16:
        ENCRYPT_16_PARALLEL  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%DATA_OFFSET, %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, \
                %%CTR_BLOCK_9_12, %%CTR_BLOCK_13_16, \
                full, %%IA0, %%IA1, %%LENGTH, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, \
                %%MASKREG, %%SHUFREG, %%ADD8REG, %%NROUNDS, %%CNTR_TYPE, \
                %%RBITS
        add             %%DATA_OFFSET, 256
        sub             %%LENGTH, 256
        cmp             %%LENGTH, 256
        jge             %%_encrypt_by_16

%%_encrypt_by_16_done:
        ;; Test to see if we need a by 16 with partial block. At this point
        ;; bytes remaining should be either zero or between 241-255.
        or              %%LENGTH, %%LENGTH
        je              %%_enc_dec_done

%%_encrypt_by_16_partial:

        ENCRYPT_16_PARALLEL  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%DATA_OFFSET, %%CTR_BLOCK_1_4, %%CTR_BLOCK_5_8, \
                %%CTR_BLOCK_9_12, %%CTR_BLOCK_13_16, \
                partial, %%IA0, %%IA1, %%LENGTH, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%ZTMP5, %%ZTMP6, %%ZTMP7, \
                %%MASKREG, %%SHUFREG, %%ADD8REG, %%NROUNDS, %%CNTR_TYPE, \
                %%RBITS

%%_enc_dec_done:
%ifidn %%CNTR_TYPE, CCM
	mov	rax, %%JOB
	or	dword [rax + _status], STS_COMPLETED_AES
%endif

%endmacro                       ; CNTR_ENC_DEC

%ifdef CNTR_CCM_AVX512
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;IMB_JOB * aes_cntr_ccm_128_vaes_avx512(IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_ccm_128_vaes_avx512,function,internal)
aes_cntr_ccm_128_vaes_avx512:
        FUNC_SAVE CNTR
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CNTR_BIT/CCM)
        CNTR_ENC_DEC arg1, 9, CCM
        FUNC_RESTORE CNTR

        ret

%else
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_128_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_128_submit_vaes_avx512,function,internal)
aes_cntr_128_submit_vaes_avx512:
        FUNC_SAVE CNTR
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
        CNTR_ENC_DEC arg1, 9, CNTR
        FUNC_RESTORE CNTR

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_192_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_192_submit_vaes_avx512,function,internal)
aes_cntr_192_submit_vaes_avx512:
        FUNC_SAVE CNTR
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
        CNTR_ENC_DEC arg1, 11, CNTR
        FUNC_RESTORE CNTR

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_256_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_256_submit_vaes_avx512,function,internal)
aes_cntr_256_submit_vaes_avx512:
        FUNC_SAVE CNTR
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
        CNTR_ENC_DEC arg1, 13, CNTR
        FUNC_RESTORE CNTR

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_bit_128_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_bit_128_submit_vaes_avx512,function,internal)
aes_cntr_bit_128_submit_vaes_avx512:
        FUNC_SAVE CNTR_BIT
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
        CNTR_ENC_DEC arg1, 9, CNTR_BIT
        FUNC_RESTORE CNTR_BIT

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_bit_192_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_bit_192_submit_vaes_avx512,function,internal)
aes_cntr_bit_192_submit_vaes_avx512:
        FUNC_SAVE CNTR_BIT
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
        CNTR_ENC_DEC arg1, 11, CNTR_BIT
        FUNC_RESTORE CNTR_BIT

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_bit_256_submit_vaes_avx512 (IMB_JOB *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_bit_256_submit_vaes_avx512,function,internal)
aes_cntr_bit_256_submit_vaes_avx512:
        FUNC_SAVE CNTR_BIT
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        ;; arg3 - [in] Type of CNTR operation to do (CNTR/CNTR_BIT)
        CNTR_ENC_DEC arg1, 13, CNTR_BIT
        FUNC_RESTORE CNTR_BIT

        ret

%endif ;; CNTR_CCM_AVX512

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
