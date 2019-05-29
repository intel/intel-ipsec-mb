;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2019, Intel Corporation All rights reserved.
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
%include "job_aes_hmac.asm"
%include "include/memcpy.asm"

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
ddq_add_5678:
        dq	0x0000000000000005, 0x0000000000000000
        dq	0x0000000000000006, 0x0000000000000000
        dq	0x0000000000000007, 0x0000000000000000
        dq	0x0000000000000008, 0x0000000000000000

align 64
ddq_add_4567:
        dq	0x0000000000000004, 0x0000000000000000
        dq	0x0000000000000005, 0x0000000000000000
        dq	0x0000000000000006, 0x0000000000000000
        dq	0x0000000000000007, 0x0000000000000000

align 64
ddq_add_0123:
        dq	0x0000000000000000, 0x0000000000000000
        dq	0x0000000000000001, 0x0000000000000000
        dq	0x0000000000000002, 0x0000000000000000
        dq	0x0000000000000003, 0x0000000000000000

align 64
ddq_add_1234:
        dq	0x0000000000000001, 0x0000000000000000
        dq	0x0000000000000002, 0x0000000000000000
        dq	0x0000000000000003, 0x0000000000000000
        dq	0x0000000000000004, 0x0000000000000000

align 64
ddq_add_8888:
        dq	0x0000000000000008, 0x0000000000000000
        dq	0x0000000000000008, 0x0000000000000000
        dq	0x0000000000000008, 0x0000000000000000
        dq	0x0000000000000008, 0x0000000000000000

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
        %define GP_STORAGE      (6*8)  ; space for 6 GP registers
%else
        %define GP_STORAGE      (4*8)  ; space for 4 GP registers
%endif

%define STACK_FRAME_SIZE        GP_STORAGE

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Utility Macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; This macro is used to "warm-up" pipeline for ENCRYPT_8_PARALLEL
;;; macro code. It is called only for data lengths 128 and above.
;;; The flow is as follows:
;;; - encrypt the initial %%num_initial_blocks blocks (can be 0)
;;; - encrypt the next 8 blocks
;;;   - the last 8th block can be partial (lengths between 129 and 239)
;;;   - partial block ciphering is handled within this macro

%macro INITIAL_BLOCKS 18
%define %%KEY                   %1      ; [in] pointer to key
%define %%CYPH_PLAIN_OUT        %2      ; [in] output buffer
%define %%PLAIN_CYPH_IN         %3      ; [in] input buffer
%define %%LENGTH                %4      ; [in/out] number of bytes to process
%define %%DATA_OFFSET           %5      ; [in/out] data offset
%define %%num_initial_blocks    %6      ; [in] can be 0, 1, 2, 3, 4, 5, 6 or 7
%define %%CTR                   %7      ; [in] XMM first counter block
%define %%CTR_14                %8      ; [out] ZMM next 1-4 counter blocks
%define %%CTR_58                %9      ; [out] ZMM next 5-8 counter blocks
%define %%ZT1                   %10     ; [clobbered] ZMM temporary
%define %%ZT2                   %11     ; [clobbered] ZMM temporary
%define %%ZT3                   %12     ; [clobbered] ZMM temporary
%define %%ZT4                   %13     ; [clobbered] ZMM temporary
%define %%IA0                   %14     ; [clobbered] GP temporary
%define %%IA1                   %15     ; [clobbered] GP temporary
%define %%MASKREG               %16     ; [clobbered] mask register
%define %%SHUFREG               %17     ; [in] ZMM register with shuffle mask
%define %%NROUNDS               %18     ; [in] number of rounds; numerical value

%define %%T1 XWORD(%%ZT1)
%define %%T2 XWORD(%%ZT2)
%define %%T3 XWORD(%%ZT3)
%define %%T4 XWORD(%%ZT4)

%if %%num_initial_blocks > 0
        ;; get load/store mask
%if (%%num_initial_blocks == 3) || (%%num_initial_blocks == 7)
        mov             %%IA0, 0x0000_ffff_ffff_ffff
        kmovq           %%MASKREG, %%IA0
%endif

        ;; load plain/cipher text
%if %%num_initial_blocks == 1
        vmovdqu8        %%T3, [%%PLAIN_CYPH_IN]
%elif %%num_initial_blocks == 2
        vmovdqu8        YWORD(%%ZT3), [%%PLAIN_CYPH_IN]
%elif %%num_initial_blocks == 3
        vmovdqu8        %%ZT3{%%MASKREG}{z}, [%%PLAIN_CYPH_IN]
%elif %%num_initial_blocks == 4
        vmovdqu8        %%ZT3, [%%PLAIN_CYPH_IN]
%elif %%num_initial_blocks == 5
        vmovdqu8        %%ZT3, [%%PLAIN_CYPH_IN]
        vmovdqu8        %%T4, [%%PLAIN_CYPH_IN + 64]
%elif %%num_initial_blocks == 6
        vmovdqu8        %%ZT3, [%%PLAIN_CYPH_IN]
        vmovdqu8        YWORD(%%ZT4), [%%PLAIN_CYPH_IN + 64]
%else
        vmovdqu8        %%ZT3, [%%PLAIN_CYPH_IN]
        vmovdqu8        %%ZT4{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + 64]
%endif

        ;; prepare AES counter blocks
%if %%num_initial_blocks > 1
%if %%num_initial_blocks == 2
        vshufi64x2      YWORD(%%ZT1), YWORD(%%CTR), YWORD(%%CTR), 0
        vpaddd          YWORD(%%ZT1), YWORD(%%ZT1), [rel ddq_add_0123]
%else
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        vpaddd          %%ZT1, ZWORD(%%CTR), [rel ddq_add_0123]
        vpaddd          %%ZT2, ZWORD(%%CTR), [rel ddq_add_4567]
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
%else ; num initial blocks = 7
        vextracti32x4   %%CTR, %%ZT2, 2
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
%endif

        ;; AES rounds and XOR with plain/cipher text
%assign j 0
%rep (%%NROUNDS + 2)
        AESROUND_1_TO_8_BLOCKS \
                        %%ZT1, %%ZT2, ZKEY %+ j, j, \
                        %%ZT3, %%ZT4, %%num_initial_blocks, \
                        %%NROUNDS
%assign j (j + 1)
%endrep

        ;; write cipher/plain text back to output
%if %%num_initial_blocks == 1
        vmovdqu8        [%%CYPH_PLAIN_OUT], %%T1
%elif %%num_initial_blocks == 2
        vmovdqu8        [%%CYPH_PLAIN_OUT], YWORD(%%ZT1)
%elif %%num_initial_blocks == 3
        ;; Blocks 3
        vmovdqu8        [%%CYPH_PLAIN_OUT]{%%MASKREG}, %%ZT1
%elif %%num_initial_blocks == 4
        ;; Blocks 4
        vmovdqu8        [%%CYPH_PLAIN_OUT], %%ZT1
%elif %%num_initial_blocks == 5
        vmovdqu8        [%%CYPH_PLAIN_OUT], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + 64], %%T2
%elif %%num_initial_blocks == 6
        vmovdqu8        [%%CYPH_PLAIN_OUT], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + 64], YWORD(%%ZT2)
%else
        ;; Blocks 7
        vmovdqu8        [%%CYPH_PLAIN_OUT], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + 64]{%%MASKREG}, %%ZT2
%endif

        ;; adjust data offset and length
        sub             %%LENGTH, (%%num_initial_blocks * 16)
        add             %%DATA_OFFSET, (%%num_initial_blocks * 16)
%endif                          ;  %%num_initial_blocks > 0

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; - cipher of %%num_initial_blocks is done
        ;; - prepare counter blocks for the next 8 blocks (ZT3 & ZT4)
        ;;   - shuffle the blocks for AES
        ;; - encrypt the next 8 blocks

        ;; get text load/store mask (assume full mask by default)
        mov             %%IA0, 0xffff_ffff_ffff_ffff
%if %%num_initial_blocks > 0
        ;; NOTE: 'jge' is always taken for %%num_initial_blocks = 0
        ;;      This macro is executed for lenght 128 and up,
        ;;      zero length is checked in CNTR_ENC_DEC.
        ;; We know there is partial block if:
        ;;      LENGTH - 16*num_initial_blocks < 128
        cmp             %%LENGTH, 128
        jge             %%_initial_partial_block_continue
        mov             %%IA1, rcx
        mov             rcx, 128
        sub             rcx, %%LENGTH
        shr             %%IA0, cl
        mov             rcx, %%IA1
%%_initial_partial_block_continue:
%endif
        kmovq           %%MASKREG, %%IA0
        ;; load plain or cipher text
        vmovdqu8        %%ZT3, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT4{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]

        ;; prepare next counter blocks
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
%if %%num_initial_blocks > 0
        vpaddd          %%CTR_14, ZWORD(%%CTR), [rel ddq_add_1234]
        vpaddd          %%CTR_58, ZWORD(%%CTR), [rel ddq_add_5678]
%else
        vpaddd          %%CTR_14, ZWORD(%%CTR), [rel ddq_add_0123]
        vpaddd          %%CTR_58, ZWORD(%%CTR), [rel ddq_add_4567]
%endif

        vpshufb         %%ZT1, %%CTR_14, %%SHUFREG
        vpshufb         %%ZT2, %%CTR_58, %%SHUFREG

        ;; AES rounds and XOR with plain/cipher text
%assign j 0
%rep (%%NROUNDS + 2)
        AESROUND_1_TO_8_BLOCKS \
                        %%ZT1, %%ZT2, ZKEY %+ j, j, \
                        %%ZT3, %%ZT4, 8, %%NROUNDS
%assign j (j + 1)
%endrep

        ;; write cipher/plain text back to output
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{%%MASKREG}, %%ZT2

        ;; check if there is partial block
        cmp             %%LENGTH, 128
        jl              %%_initial_partial_done
        ;; adjust offset and length
        add             %%DATA_OFFSET, 128
        sub             %%LENGTH, 128
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
;;; - It is not meant to cipher counter blocks for the main by8 loop.
;;;   Just ciphers amount of blocks.
;;; - Small packets (<128 bytes)
;;;
;;; num_initial_blocks is expected to include the partial final block
;;; in the count.
%macro INITIAL_BLOCKS_PARTIAL 15
%define %%KEY                   %1  ; [in] key pointer
%define %%CYPH_PLAIN_OUT        %2  ; [in] text out pointer
%define %%PLAIN_CYPH_IN         %3  ; [in] text out pointer
%define %%LENGTH                %4  ; [in] length in bytes
%define %%num_initial_blocks    %5  ; [in] can only be 1, 2, 3, 4, 5, 6, 7 or 8 (not 0)
%define %%CTR                   %6  ; [in/out] current counter value
%define %%ZT1                   %7  ; [clobbered] ZMM temporary
%define %%ZT2                   %8  ; [clobbered] ZMM temporary
%define %%ZT3                   %9  ; [clobbered] ZMM temporary
%define %%ZT4                   %10 ; [clobbered] ZMM temporary
%define %%IA0                   %11 ; [clobbered] GP temporary
%define %%IA1                   %12 ; [clobbered] GP temporary
%define %%MASKREG               %13 ; [clobbered] mask register
%define %%SHUFREG               %14 ; [in] ZMM register with shuffle mask
%define %%NROUNDS               %15 ; [in] number of rounds; numerical value

%define %%T1 XWORD(%%ZT1)
%define %%T2 XWORD(%%ZT2)
%define %%T3 XWORD(%%ZT3)
%define %%T4 XWORD(%%ZT4)

        ;; get load/store mask
        lea             %%IA0, [rel byte64_len_to_mask_table]
        mov             %%IA1, %%LENGTH
%if %%num_initial_blocks > 4
        sub             %%IA1, 64
%endif
        kmovq           %%MASKREG, [%%IA0 + %%IA1*8]

        ;; load plain/cipher text
%if %%num_initial_blocks == 1
        vmovdqu8        %%T3{%%MASKREG}{z}, [%%PLAIN_CYPH_IN]
%elif %%num_initial_blocks == 2
        vmovdqu8        YWORD(%%ZT3){%%MASKREG}{z}, [%%PLAIN_CYPH_IN]
%elif %%num_initial_blocks <= 4
        vmovdqu8        %%ZT3{%%MASKREG}{z}, [%%PLAIN_CYPH_IN]
%elif %%num_initial_blocks == 5
        vmovdqu8        %%ZT3, [%%PLAIN_CYPH_IN]
        vmovdqu8        %%T4{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + 64]
%elif %%num_initial_blocks == 6
        vmovdqu8        %%ZT3, [%%PLAIN_CYPH_IN]
        vmovdqu8        YWORD(%%ZT4){%%MASKREG}{z}, [%%PLAIN_CYPH_IN + 64]
%else
        vmovdqu8        %%ZT3, [%%PLAIN_CYPH_IN]
        vmovdqu8        %%ZT4{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + 64]
%endif

        ;; prepare AES counter blocks
%if %%num_initial_blocks > 1
%if %%num_initial_blocks == 2
        vshufi64x2      YWORD(%%ZT1), YWORD(%%CTR), YWORD(%%CTR), 0
        vpaddd          YWORD(%%ZT1), YWORD(%%ZT1), [rel ddq_add_0123]
%else
        vshufi64x2      ZWORD(%%CTR), ZWORD(%%CTR), ZWORD(%%CTR), 0
        vpaddd          %%ZT1, ZWORD(%%CTR), [rel ddq_add_0123]
        vpaddd          %%ZT2, ZWORD(%%CTR), [rel ddq_add_4567]
%endif
%endif

        ;; shuffle the counters for AES rounds
%if %%num_initial_blocks == 1
        vpshufb         %%T1, %%CTR, XWORD(%%SHUFREG)
%elif %%num_initial_blocks == 2
        vpshufb         YWORD(%%ZT1), YWORD(%%SHUFREG)
%elif %%num_initial_blocks <= 4
        vpshufb         %%ZT1, %%SHUFREG
%elif %%num_initial_blocks == 5
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%T2, XWORD(%%SHUFREG)
%elif %%num_initial_blocks == 6
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         YWORD(%%ZT2), YWORD(%%SHUFREG)
%else
        vpshufb         %%ZT1, %%SHUFREG
        vpshufb         %%ZT2, %%SHUFREG
%endif

        ;; AES rounds and XOR with plain/cipher text
%assign j 0
%rep (%%NROUNDS + 2)
        AESROUND_1_TO_8_BLOCKS \
                        %%ZT1, %%ZT2, ZKEY %+ j, j, \
                        %%ZT3, %%ZT4, %%num_initial_blocks, \
                        %%NROUNDS
%assign j (j + 1)
%endrep

        ;; write cipher/plain text back to output and
%if %%num_initial_blocks == 1
        vmovdqu8        [%%CYPH_PLAIN_OUT]{%%MASKREG}, %%T1
%elif %%num_initial_blocks == 2
        vmovdqu8        [%%CYPH_PLAIN_OUT]{%%MASKREG}, YWORD(%%ZT1)
%elif %%num_initial_blocks <= 4
        ;; Blocks 3 and 4
        vmovdqu8        [%%CYPH_PLAIN_OUT]{%%MASKREG}, %%ZT1
%elif %%num_initial_blocks == 5
        vmovdqu8        [%%CYPH_PLAIN_OUT], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + 64]{%%MASKREG}, %%T2
%elif %%num_initial_blocks == 6
        vmovdqu8        [%%CYPH_PLAIN_OUT], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + 64]{%%MASKREG}, YWORD(%%ZT2)
%else
        ;; Blocks 7 and 8
        vmovdqu8        [%%CYPH_PLAIN_OUT], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + 64]{%%MASKREG}, %%ZT2
%endif

%endmacro                       ; INITIAL_BLOCKS_PARTIAL



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Main CNTR macro
;;; - operates on single stream
;;; - encrypts 8 blocks at a time
%macro  ENCRYPT_8_PARALLEL 18
%define %%KEY                   %1  ; [in] key pointer
%define %%CYPH_PLAIN_OUT        %2  ; [in] pointer to output buffer
%define %%PLAIN_CYPH_IN         %3  ; [in] pointer to input buffer
%define %%DATA_OFFSET           %4  ; [in] data offset
%define %%CTR_14                %5  ; [in/out] ZMM next 1-4 counter blocks
%define %%CTR_58                %6  ; [in/out] ZMM next 5-8 counter blocks
%define %%FULL_PARTIAL          %7  ; [in] last block type selection "full" or "partial"
%define %%IA0                   %8  ; [clobbered] temporary GP register
%define %%IA1                   %9  ; [clobbered] temporary GP register
%define %%LENGTH                %10 ; [in] length
%define %%ZT1                   %11 ; [clobbered] temporary ZMM (cipher)
%define %%ZT2                   %12 ; [clobbered] temporary ZMM (cipher)
%define %%ZT3                   %13 ; [clobbered] temporary ZMM (cipher)
%define %%ZT4                   %14 ; [clobbered] temporary ZMM (cipher)
%define %%MASKREG               %15 ; [clobbered] mask register for partial loads/stores
%define %%SHUFREG               %16 ; [in] ZMM register with shuffle mask
%define %%ADD8REG               %17 ; [in] ZMM register with increment by 8 mask
%define %%NROUNDS               %18 ; [in] number of rounds; numerical value

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; load/store mask (partial case) and load the text data
%ifidn %%FULL_PARTIAL, full
        vmovdqu8        %%ZT3, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT4, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%else
        lea             %%IA0, [rel byte64_len_to_mask_table]
        mov             %%IA1, %%LENGTH
        sub             %%IA1, 64
        kmovq           %%MASKREG, [%%IA0 + 8*%%IA1]
        vmovdqu8        %%ZT3, [%%PLAIN_CYPH_IN + %%DATA_OFFSET]
        vmovdqu8        %%ZT4{%%MASKREG}{z}, [%%PLAIN_CYPH_IN + %%DATA_OFFSET + 64]
%endif

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; populate counter blocks
        ;; %%CTR is shuffled outside the scope of this macro
        ;; it has to be kept in unshuffled form
        vpaddd          %%CTR_14, %%CTR_14, %%ADD8REG
        vpaddd          %%CTR_58, %%CTR_58, %%ADD8REG
        vpshufb         %%ZT1, %%CTR_14, %%SHUFREG
        vpshufb         %%ZT2, %%CTR_58, %%SHUFREG

%assign j 0
%rep (%%NROUNDS + 2)
        AESROUND_1_TO_8_BLOCKS \
                        %%ZT1, %%ZT2, ZKEY %+ j, j, \
                        %%ZT3, %%ZT4, 8, %%NROUNDS
%assign j (j + 1)
%endrep

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;; store the text data
%ifidn %%FULL_PARTIAL, full
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64], %%ZT2
%else
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET], %%ZT1
        vmovdqu8        [%%CYPH_PLAIN_OUT + %%DATA_OFFSET + 64]{%%MASKREG}, %%ZT2
%endif

%endmacro                       ; ENCRYPT_8_PARALLEL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Save register content for the caller
%macro FUNC_SAVE 0
        mov     rax, rsp

        sub     rsp, STACK_FRAME_SIZE
        and     rsp, ~63

        mov     [rsp + 0*8], r12
        mov     [rsp + 1*8], r13
        mov     [rsp + 2*8], rax ; stack
%ifidn __OUTPUT_FORMAT__, win64
        mov     [rsp + 3*8], rdi
        mov     [rsp + 4*8], rsi
%endif

%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Restore register content for the caller
%macro FUNC_RESTORE 0

        vzeroupper
%ifidn __OUTPUT_FORMAT__, win64
        mov     rdi, [rsp + 3*8]
        mov     rsi, [rsp + 4*8]
%endif
        mov     r12, [rsp + 0*8]
        mov     r13, [rsp + 1*8]
        mov     rsp, [rsp + 2*8] ; stack
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Cipher payloads shorter than 128 bytes
;;; - number of blocks in the message comes as argument
;;; - depending on the number of blocks an optimized variant of
;;;   INITIAL_BLOCKS_PARTIAL is invoked
%macro  CNTR_ENC_DEC_SMALL   15
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
%define %%IA0               %11 ; [clobbered] GP register
%define %%IA1               %12 ; [clobbered] GP register
%define %%MASKREG           %13 ; [clobbered] mask register
%define %%SHUFREG           %14 ; [in] ZMM register with shuffle mask
%define %%NROUNDS           %15 ; [in] number of rounds; numerical value

        cmp     %%NUM_BLOCKS, 8
        je      %%_small_initial_num_blocks_is_8
        cmp     %%NUM_BLOCKS, 7
        je      %%_small_initial_num_blocks_is_7
        cmp     %%NUM_BLOCKS, 6
        je      %%_small_initial_num_blocks_is_6
        cmp     %%NUM_BLOCKS, 5
        je      %%_small_initial_num_blocks_is_5
        cmp     %%NUM_BLOCKS, 4
        je      %%_small_initial_num_blocks_is_4
        cmp     %%NUM_BLOCKS, 3
        je      %%_small_initial_num_blocks_is_3
        cmp     %%NUM_BLOCKS, 2
        je      %%_small_initial_num_blocks_is_2

        jmp     %%_small_initial_num_blocks_is_1


%%_small_initial_num_blocks_is_8:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 8, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_7:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 7, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_6:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 6, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_5:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 5, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_4:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 4, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_3:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 3, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_2:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 2, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp     %%_small_initial_blocks_encrypted

%%_small_initial_num_blocks_is_1:
        INITIAL_BLOCKS_PARTIAL  %%KEY, %%CYPH_PLAIN_OUT, \
                %%PLAIN_CYPH_IN, %%LENGTH, 1, \
                %%CTR, \
                %%ZTMP1, %%ZTMP2, %%ZTMP3, %%ZTMP4, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
%%_small_initial_blocks_encrypted:

%endmacro                       ; CNTR_ENC_DEC_SMALL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; CNTR_ENC_DEC Encodes/Decodes given data.
; Requires the input data be at least 1 byte long because of READ_SMALL_INPUT_DATA.
; Input: job structure and number of AES rounds
; Output: job structure
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro  CNTR_ENC_DEC         2
%define %%JOB               %1  ; [in/out] job
%define %%NROUNDS           %2  ; [in] number of rounds; numerical value

%define %%KEY               rax
%define %%CYPH_PLAIN_OUT    rdx
%define %%PLAIN_CYPH_IN     r8
%define %%LENGTH            r9
%define %%DATA_OFFSET       r13

%define %%IA0               r10
%define %%IA1               r11
%define %%IA2               r12

%define %%CTR_BLOCKx            xmm0
%define %%CTR_BLOCK_14          zmm1
%define %%CTR_BLOCK_58          zmm2

%define %%ZTMP0                 zmm3
%define %%ZTMP1                 zmm4
%define %%ZTMP2                 zmm5
%define %%ZTMP3                 zmm6
%define %%SHUFREG               zmm7
%define %%ADD8REG               zmm8

%define %%MASKREG               k1

;;; Macro flow:
;;; - calculate the number of 16byte blocks in the message
;;; - process (number of 16byte blocks) mod 8 '%%_initial_num_blocks_is_# .. %%_initial_blocks_encrypted'
;;; - process 8 16 byte blocks at a time until all are done in %%_encrypt_by_8_new

        mov             %%LENGTH, [%%JOB + _msg_len_to_cipher_in_bytes]
%ifidn __OUTPUT_FORMAT__, win64
        cmp             %%LENGTH, 0
%else
        or              %%LENGTH, %%LENGTH
%endif
        je              %%_enc_dec_done

        xor             %%DATA_OFFSET, %%DATA_OFFSET

        mov             %%PLAIN_CYPH_IN, [%%JOB + _src]
        add             %%PLAIN_CYPH_IN, [%%JOB + _cipher_start_src_offset_in_bytes]
        mov             %%CYPH_PLAIN_OUT, [%%JOB + _dst]
        mov             %%KEY, [%%JOB + _aes_enc_key_expanded]

        ;; Prepare round keys
%assign i 0
%rep (%%NROUNDS + 2)
        vbroadcastf64x2 ZKEY %+ i, [%%KEY + 16*i]
%assign i (i + 1)
%endrep

        ;; Prepare initial mask to read 12 IV bytes
        mov             %%IA0, 0x0000_0000_0000_0fff
        vmovdqa         %%CTR_BLOCKx, [rel initial_12_IV_counter]
        mov             %%IA2, [%%JOB + _iv_len_in_bytes]
        test            %%IA2, 16
        ;; Set mask to read 16 IV bytes if iv_len = 16
        cmovnz          %%IA0, [rel mask_16_bytes]
        mov             %%IA1, [%%JOB + _iv]

        kmovq           %%MASKREG, %%IA0
        vmovdqu8        %%CTR_BLOCKx{%%MASKREG}, [%%IA1]

        vmovdqa64       %%SHUFREG, [rel SHUF_MASK]
        ;; store IV as counter in LE format
        vpshufb         %%CTR_BLOCKx, XWORD(%%SHUFREG)

        ;; Determine how many blocks to process in INITIAL
        mov             %%IA1, %%LENGTH
        shr             %%IA1, 4
        and             %%IA1, 7

        ;; Process one additional block in INITIAL if there is a partial block
        mov             %%IA0, %%LENGTH
        and             %%IA0, 0xf
        add             %%IA0, 0xf
        shr             %%IA0, 4
        add             %%IA1, %%IA0
        ;; %%IA1 can be in the range from 0 to 8

        ;; Less than 128B will be handled by the small message code, which
        ;; can process up to 8 x blocks (16 bytes each)
        cmp             %%LENGTH, 128
        jge             %%_large_message_path

        CNTR_ENC_DEC_SMALL \
                %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, \
                %%IA1, %%CTR_BLOCKx, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%IA0, %%IA2, %%MASKREG, %%SHUFREG, %%NROUNDS

        jmp     %%_enc_dec_done

%%_large_message_path:
        ;; Still, don't allow 8 INITIAL blocks since this will
        ;; can be handled by the x8 partial loop.
        and             %%IA1, 0x7
        je              %%_initial_num_blocks_is_0
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

%%_initial_num_blocks_is_7:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 7, %%CTR_BLOCKx, %%CTR_BLOCK_14, %%CTR_BLOCK_58, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_6:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 6, %%CTR_BLOCKx, %%CTR_BLOCK_14, %%CTR_BLOCK_58, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_5:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 5, %%CTR_BLOCKx, %%CTR_BLOCK_14, %%CTR_BLOCK_58, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_4:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 4, %%CTR_BLOCKx, %%CTR_BLOCK_14, %%CTR_BLOCK_58, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_3:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 3, %%CTR_BLOCKx, %%CTR_BLOCK_14, %%CTR_BLOCK_58, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_2:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 2, %%CTR_BLOCKx, %%CTR_BLOCK_14, %%CTR_BLOCK_58, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_1:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 1, %%CTR_BLOCKx, %%CTR_BLOCK_14, %%CTR_BLOCK_58, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS
        jmp             %%_initial_blocks_encrypted

%%_initial_num_blocks_is_0:
        INITIAL_BLOCKS  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%LENGTH, %%DATA_OFFSET, 0, %%CTR_BLOCKx, %%CTR_BLOCK_14, %%CTR_BLOCK_58, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, \
                %%IA0, %%IA1, %%MASKREG, %%SHUFREG, %%NROUNDS

%%_initial_blocks_encrypted:
        or              %%LENGTH, %%LENGTH
        je              %%_enc_dec_done

        vmovdqa64       %%ADD8REG, [rel ddq_add_8888]
        ;; Process 7 full blocks plus a partial block
        cmp             %%LENGTH, 128
        jl              %%_encrypt_by_8_partial

%%_encrypt_by_8:
        ENCRYPT_8_PARALLEL  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%DATA_OFFSET, %%CTR_BLOCK_14, %%CTR_BLOCK_58, \
                full, %%IA0, %%IA1, %%LENGTH, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%MASKREG, \
                %%SHUFREG, %%ADD8REG, %%NROUNDS
        add             %%DATA_OFFSET, 128
        sub             %%LENGTH, 128
        cmp             %%LENGTH, 128
        jge             %%_encrypt_by_8

%%_encrypt_by_8_done:
        ;; Test to see if we need a by 8 with partial block. At this point
        ;; bytes remaining should be either zero or between 113-127.
        or              %%LENGTH, %%LENGTH
        je              %%_enc_dec_done

%%_encrypt_by_8_partial:

        ENCRYPT_8_PARALLEL  %%KEY, %%CYPH_PLAIN_OUT, %%PLAIN_CYPH_IN, \
                %%DATA_OFFSET, %%CTR_BLOCK_14, %%CTR_BLOCK_58, \
                partial, %%IA0, %%IA1, %%LENGTH, \
                %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3, %%MASKREG, \
                %%SHUFREG, %%ADD8REG, %%NROUNDS

%%_enc_dec_done:

%endmacro                       ; CNTR_ENC_DEC

;;; ===========================================================================
;;; AESROUND_1_TO_8_BLOCKS macro
;;; - 1 lane, 1 to 8 blocks per lane
;;; - it handles special cases: the last and zero rounds
;;; Uses NROUNDS macro defined at the top of the file to check the last round
%macro AESROUND_1_TO_8_BLOCKS 8
%define %%L0B03   %1      ; [in/out] zmm; blocks 0 to 3
%define %%L0B47   %2      ; [in/out] zmm; blocks 4 to 7
%define %%KEY     %3      ; [in] zmm containing round key
%define %%ROUND   %4      ; [in] round number
%define %%D0L     %5      ; [in] zmm or no_data; plain/cipher text blocks 0-3
%define %%D0H     %6      ; [in] zmm or no_data; plain/cipher text blocks 4-7
%define %%NUMBL   %7      ; [in] number of blocks; numerical value
%define %%NROUNDS %8      ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
%if (%%NUMBL > 6)
        ;; 7, 8 blocks
        vpxorq          %%L0B03, %%L0B03, %%KEY
        vpxorq          %%L0B47, %%L0B47, %%KEY
%elif (%%NUMBL == 6)
        ;; 6 blocks
        vpxorq          %%L0B03, %%L0B03, %%KEY
        vpxorq          YWORD(%%L0B47), YWORD(%%L0B47), YWORD(%%KEY)
%elif (%%NUMBL == 5)
        ;; 5 blocks
        vpxorq          %%L0B03, %%L0B03, %%KEY
        vpxorq          XWORD(%%L0B47), XWORD(%%L0B47), XWORD(%%KEY)
%elif (%%NUMBL > 2)
        ;; 3, 4 blocks
        vpxorq          %%L0B03, %%L0B03, %%KEY
%elif (%%NUMBL == 2)
        ;; 2 blocks
        vpxorq          YWORD(%%L0B03), YWORD(%%L0B03), YWORD(%%KEY)
%else
        ;; 1 block
        vpxorq          XWORD(%%L0B03), XWORD(%%L0B03), XWORD(%%KEY)
%endif                  ; NUM BLOCKS
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
%if (%%NUMBL > 6)
        ;; 7, 8 blocks
        vaesenc         %%L0B03, %%L0B03, %%KEY
        vaesenc         %%L0B47, %%L0B47, %%KEY
%elif (%%NUMBL == 6)
        ;; 6 blocks
        vaesenc         %%L0B03, %%L0B03, %%KEY
        vaesenc         YWORD(%%L0B47), YWORD(%%L0B47), YWORD(%%KEY)
%elif (%%NUMBL == 5)
        ;; 5 blocks
        vaesenc         %%L0B03, %%L0B03, %%KEY
        vaesenc         XWORD(%%L0B47), XWORD(%%L0B47), XWORD(%%KEY)
%elif (%%NUMBL > 2)
        ;; 3, 4 blocks
        vaesenc         %%L0B03, %%L0B03, %%KEY
%elif (%%NUMBL == 2)
        ;; 2 blocks
        vaesenc         YWORD(%%L0B03), YWORD(%%L0B03), YWORD(%%KEY)
%else
        ;; 1 block
        vaesenc         XWORD(%%L0B03), XWORD(%%L0B03), XWORD(%%KEY)
%endif                  ; NUM BLOCKS
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
%if (%%NUMBL > 6)
        ;; 7, 8 blocks
        vaesenclast     %%L0B03, %%L0B03, %%KEY
        vaesenclast     %%L0B47, %%L0B47, %%KEY
%elif (%%NUMBL == 6)
        ;; 6 blocks
        vaesenclast     %%L0B03, %%L0B03, %%KEY
        vaesenclast     YWORD(%%L0B47), YWORD(%%L0B47), YWORD(%%KEY)
%elif (%%NUMBL == 5)
        ;; 5 blocks
        vaesenclast     %%L0B03, %%L0B03, %%KEY
        vaesenclast     XWORD(%%L0B47), XWORD(%%L0B47), XWORD(%%KEY)
%elif (%%NUMBL > 2)
        ;; 3, 4 blocks
        vaesenclast     %%L0B03, %%L0B03, %%KEY
%elif (%%NUMBL == 2)
        ;; 2 blocks
        vaesenclast     YWORD(%%L0B03), YWORD(%%L0B03), YWORD(%%KEY)
%else
        ;; 1 block
        vaesenclast     XWORD(%%L0B03), XWORD(%%L0B03), XWORD(%%KEY)
%endif                  ; NUM BLOCKS

;;; === XOR with data
%ifnidn %%D0L, no_data
%if (%%NUMBL == 1)
        vpxorq          XWORD(%%L0B03), XWORD(%%L0B03), XWORD(%%D0L)
%elif (%%NUMBL == 2)
        vpxorq          YWORD(%%L0B03), YWORD(%%L0B03), YWORD(%%D0L)
%else
        vpxorq          %%L0B03, %%L0B03, %%D0L
%endif
%endif                          ; !no_data
%ifnidn %%D0H, no_data
%if (%%NUMBL == 5)
        vpxorq          XWORD(%%L0B47), XWORD(%%L0B47), XWORD(%%D0H)
%elif (%%NUMBL == 6)
        vpxorq          YWORD(%%L0B47), YWORD(%%L0B47), YWORD(%%D0H)
%elif (%%NUMBL > 6)
        vpxorq          %%L0B47, %%L0B47, %%D0H
%endif
%endif                  ; !no_data
%endif                  ; The last round

%endmacro               ; AESROUND_1_TO_8_BLOCKS

;;; ===========================================================================

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_128_submit_vaes_avx512 (JOB_AES_HMAC *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_128_submit_vaes_avx512,function,internal)
aes_cntr_128_submit_vaes_avx512:
        FUNC_SAVE
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        CNTR_ENC_DEC arg1, 9
        FUNC_RESTORE

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_192_submit_vaes_avx512 (JOB_AES_HMAC *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_192_submit_vaes_avx512,function,internal)
aes_cntr_192_submit_vaes_avx512:
        FUNC_SAVE
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        CNTR_ENC_DEC arg1, 11
        FUNC_RESTORE

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void aes_cntr_256_submit_vaes_avx512 (JOB_AES_HMAC *job)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cntr_256_submit_vaes_avx512,function,internal)
aes_cntr_256_submit_vaes_avx512:
        FUNC_SAVE
        ;; arg1 - [in] job
        ;; arg2 - [in] NROUNDS
        CNTR_ENC_DEC arg1, 13
        FUNC_RESTORE

        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
