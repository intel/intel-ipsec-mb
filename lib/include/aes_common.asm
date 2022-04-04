;;
;; Copyright (c) 2019-2022, Intel Corporation
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

%ifndef _AES_COMMON_ASM_
%define _AES_COMMON_ASM_

%include "include/reg_sizes.asm"

;; =============================================================================
;; Generic macro to produce code that executes %%OPCODE instruction
;; on selected number of AES blocks (16 bytes long ) between 0 and 16.
;; All three operands of the instruction come from registers.
;; Note: if 3 blocks are left at the end instruction is produced to operate all
;;       4 blocks (full width of ZMM)

%macro ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 14
%define %%NUM_BLOCKS    %1      ; [in] numerical value, number of AES blocks (0 to 16)
%define %%OPCODE        %2      ; [in] instruction name
%define %%DST0          %3      ; [out] destination ZMM register
%define %%DST1          %4      ; [out] destination ZMM register
%define %%DST2          %5      ; [out] destination ZMM register
%define %%DST3          %6      ; [out] destination ZMM register
%define %%SRC1_0        %7      ; [in] source 1 ZMM register
%define %%SRC1_1        %8      ; [in] source 1 ZMM register
%define %%SRC1_2        %9      ; [in] source 1 ZMM register
%define %%SRC1_3        %10     ; [in] source 1 ZMM register
%define %%SRC2_0        %11     ; [in] source 2 ZMM register
%define %%SRC2_1        %12     ; [in] source 2 ZMM register
%define %%SRC2_2        %13     ; [in] source 2 ZMM register
%define %%SRC2_3        %14     ; [in] source 2 ZMM register

%assign reg_idx     0
%assign blocks_left %%NUM_BLOCKS

%rep (%%NUM_BLOCKS / 4)
%xdefine %%DSTREG  %%DST %+ reg_idx
%xdefine %%SRC1REG %%SRC1_ %+ reg_idx
%xdefine %%SRC2REG %%SRC2_ %+ reg_idx
        %%OPCODE        %%DSTREG, %%SRC1REG, %%SRC2REG
%undef %%DSTREG
%undef %%SRC1REG
%undef %%SRC2REG
%assign reg_idx     (reg_idx + 1)
%assign blocks_left (blocks_left - 4)
%endrep

%xdefine %%DSTREG  %%DST %+ reg_idx
%xdefine %%SRC1REG %%SRC1_ %+ reg_idx
%xdefine %%SRC2REG %%SRC2_ %+ reg_idx

%if blocks_left == 1
        %%OPCODE        XWORD(%%DSTREG), XWORD(%%SRC1REG), XWORD(%%SRC2REG)
%elif blocks_left == 2
        %%OPCODE        YWORD(%%DSTREG), YWORD(%%SRC1REG), YWORD(%%SRC2REG)
%elif blocks_left == 3
        %%OPCODE        %%DSTREG, %%SRC1REG, %%SRC2REG
%endif

%endmacro

;; =============================================================================
;; Loads specified number of AES blocks into ZMM registers
;; %%FLAGS are optional and only affect behavior when 3 trailing blocks are left
;; - if %%FlAGS not provided then exactly 3 blocks are loaded (move and insert)
;; - if "load_4_instead_of_3" option is passed then 4 blocks are loaded
%macro ZMM_LOAD_BLOCKS_0_16 7-8
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%INP           %2 ; [in] input data pointer to read from
%define %%DATA_OFFSET   %3 ; [in] offset to the output pointer (GP or numerical)
%define %%DST0          %4 ; [out] ZMM register with loaded data
%define %%DST1          %5 ; [out] ZMM register with loaded data
%define %%DST2          %6 ; [out] ZMM register with loaded data
%define %%DST3          %7 ; [out] ZMM register with loaded data
%define %%FLAGS         %8 ; [in] optional "load_4_instead_of_3"

%assign src_offset  0
%assign dst_idx     0

%rep (%%NUM_BLOCKS / 4)
%xdefine %%DSTREG %%DST %+ dst_idx
        vmovdqu8        %%DSTREG, [%%INP + %%DATA_OFFSET + src_offset]
%undef %%DSTREG
%assign src_offset  (src_offset + 64)
%assign dst_idx     (dst_idx + 1)
%endrep

%assign blocks_left (%%NUM_BLOCKS % 4)
%xdefine %%DSTREG %%DST %+ dst_idx

%if blocks_left == 1
        vmovdqu8        XWORD(%%DSTREG), [%%INP + %%DATA_OFFSET + src_offset]
%elif blocks_left == 2
        vmovdqu8        YWORD(%%DSTREG), [%%INP + %%DATA_OFFSET + src_offset]
%elif blocks_left == 3
%ifidn %%FLAGS, load_4_instead_of_3
        vmovdqu8        %%DSTREG, [%%INP + %%DATA_OFFSET + src_offset]
%else
        vmovdqu8        YWORD(%%DSTREG), [%%INP + %%DATA_OFFSET + src_offset]
        vinserti64x2    %%DSTREG, [%%INP + %%DATA_OFFSET + src_offset + 32], 2
%endif
%endif

%endmacro

;; =============================================================================
;; Loads specified number of AES blocks into YMM registers
%macro YMM_LOAD_BLOCKS_0_16 11
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%INP           %2 ; [in] input data pointer to read from
%define %%DATA_OFFSET   %3 ; [in] offset to the output pointer (GP or numerical)
%define %%DST0          %4 ; [out] YMM register with loaded data
%define %%DST1          %5 ; [out] YMM register with loaded data
%define %%DST2          %6 ; [out] YMM register with loaded data
%define %%DST3          %7 ; [out] YMM register with loaded data
%define %%DST4          %8 ; [out] YMM register with loaded data
%define %%DST5          %9 ; [out] YMM register with loaded data
%define %%DST6          %10 ; [out] YMM register with loaded data
%define %%DST7          %11 ; [out] YMM register with loaded data

%assign src_offset  0
%assign dst_idx     0

%rep (%%NUM_BLOCKS / 2)
%xdefine %%DSTREG %%DST %+ dst_idx
        vmovdqu8        %%DSTREG, [%%INP + %%DATA_OFFSET + src_offset]
%undef %%DSTREG
%assign src_offset  (src_offset + 32)
%assign dst_idx     (dst_idx + 1)
%endrep

%assign blocks_left (%%NUM_BLOCKS % 2)
%xdefine %%DSTREG %%DST %+ dst_idx

%if blocks_left == 1
        vmovdqu8        XWORD(%%DSTREG), [%%INP + %%DATA_OFFSET + src_offset]
%endif

%endmacro

;; =============================================================================
;; Loads specified number of AES blocks at offsets into ZMM registers
;; DATA_OFFSET specifies the offset between blocks to load
%macro ZMM_LOAD_BLOCKS_0_16_OFFSET 4-7
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%INP           %2 ; [in] input data pointer to read from
%define %%DATA_OFFSET   %3 ; [in] offset to the output pointer (GP or numerical)
%define %%DST0          %4 ; [out] ZMM register with loaded data
%define %%DST1          %5 ; [out] ZMM register with loaded data
%define %%DST2          %6 ; [out] ZMM register with loaded data
%define %%DST3          %7 ; [out] ZMM register with loaded data

%assign src_offset  0
%assign idx         0
%assign dst_idx     0
%xdefine %%DSTREG %%DST %+ dst_idx

%rep %%NUM_BLOCKS

;; update DST register except for first block
%if (idx % 4) == 0
%if idx != 0
%assign dst_idx (dst_idx + 1)
%undef   %%DSTREG
%xdefine %%DSTREG %%DST %+ dst_idx
%endif
        vmovdqu64        XWORD(%%DSTREG), [%%INP + src_offset]
%else
        vinserti64x2    %%DSTREG, [%%INP + src_offset], (idx % 4)
%endif
%assign src_offset  (src_offset + %%DATA_OFFSET)
%assign idx         (idx + 1)
%endrep ;; %%NUM_BLOCKS

%endmacro

;; =============================================================================
;; Stores specified number of AES blocks at offsets from ZMM registers to memory
;; DATA_OFFSET specifies the offset between blocks to store
%macro ZMM_STORE_BLOCKS_0_16_OFFSET 4-7
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%OUTP          %2 ; [in] input data pointer to read from
%define %%DATA_OFFSET   %3 ; [in] offset to the output pointer (GP or numerical)
%define %%SRC0          %4 ; [out] ZMM register with loaded data
%define %%SRC1          %5 ; [out] ZMM register with loaded data
%define %%SRC2          %6 ; [out] ZMM register with loaded data
%define %%SRC3          %7 ; [out] ZMM register with loaded data

%assign dst_offset  0
%assign idx         0
%assign src_idx     0
%xdefine %%SRCREG %%SRC %+ src_idx

%rep %%NUM_BLOCKS

;; update SRC register except for first block
%if (idx % 4) == 0
%if idx != 0
%assign src_idx (src_idx + 1)
%undef   %%SRCREG
%xdefine %%SRCREG %%SRC %+ src_idx
%endif
        vmovdqu64        [%%OUTP + dst_offset], XWORD(%%SRCREG)

%else
        vextracti64x2    [%%OUTP + dst_offset], %%SRCREG, (idx % 4)
%endif
%assign dst_offset  (dst_offset + %%DATA_OFFSET)
%assign idx         (idx + 1)
%endrep ;; %%NUM_BLOCKS

%endmacro

;; =============================================================================
;; Loads specified number of AES blocks into ZMM registers using mask register
;; for the last loaded register (xmm, ymm or zmm).
;; Loads take place at 1 byte granularity.
%macro ZMM_LOAD_MASKED_BLOCKS_0_16 8
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%INP           %2 ; [in] input data pointer to read from
%define %%DATA_OFFSET   %3 ; [in] offset to the output pointer (GP or numerical)
%define %%DST0          %4 ; [out] ZMM register with loaded data
%define %%DST1          %5 ; [out] ZMM register with loaded data
%define %%DST2          %6 ; [out] ZMM register with loaded data
%define %%DST3          %7 ; [out] ZMM register with loaded data
%define %%MASK          %8 ; [in] mask register

%assign src_offset  0
%assign dst_idx     0
%assign blocks_left %%NUM_BLOCKS

%if %%NUM_BLOCKS > 0
%rep (((%%NUM_BLOCKS + 3) / 4) - 1)
%xdefine %%DSTREG %%DST %+ dst_idx
        vmovdqu8        %%DSTREG, [%%INP + %%DATA_OFFSET + src_offset]
%undef %%DSTREG
%assign src_offset  (src_offset + 64)
%assign dst_idx     (dst_idx + 1)
%assign blocks_left (blocks_left - 4)
%endrep
%endif  ; %if %%NUM_BLOCKS > 0

%xdefine %%DSTREG %%DST %+ dst_idx

%if blocks_left == 1
        vmovdqu8        XWORD(%%DSTREG){%%MASK}{z}, [%%INP + %%DATA_OFFSET + src_offset]
%elif blocks_left == 2
        vmovdqu8        YWORD(%%DSTREG){%%MASK}{z}, [%%INP + %%DATA_OFFSET + src_offset]
%elif (blocks_left == 3 || blocks_left == 4)
        vmovdqu8        %%DSTREG{%%MASK}{z}, [%%INP + %%DATA_OFFSET + src_offset]
%endif

%endmacro

;; =============================================================================
;; Stores specified number of AES blocks from ZMM registers
%macro ZMM_STORE_BLOCKS_0_16 7
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%OUTP          %2 ; [in] output data pointer to write to
%define %%DATA_OFFSET   %3 ; [in] offset to the output pointer (GP or numerical)
%define %%SRC0          %4 ; [in] ZMM register with data to store
%define %%SRC1          %5 ; [in] ZMM register with data to store
%define %%SRC2          %6 ; [in] ZMM register with data to store
%define %%SRC3          %7 ; [in] ZMM register with data to store

%assign dst_offset  0
%assign src_idx     0

%rep (%%NUM_BLOCKS / 4)
%xdefine %%SRCREG %%SRC %+ src_idx
        vmovdqu8         [%%OUTP + %%DATA_OFFSET + dst_offset], %%SRCREG
%undef %%SRCREG
%assign dst_offset  (dst_offset + 64)
%assign src_idx     (src_idx + 1)
%endrep

%assign blocks_left (%%NUM_BLOCKS % 4)
%xdefine %%SRCREG %%SRC %+ src_idx

%if blocks_left == 1
        vmovdqu8        [%%OUTP + %%DATA_OFFSET + dst_offset], XWORD(%%SRCREG)
%elif blocks_left == 2
        vmovdqu8        [%%OUTP + %%DATA_OFFSET + dst_offset], YWORD(%%SRCREG)
%elif blocks_left == 3
        vmovdqu8        [%%OUTP + %%DATA_OFFSET + dst_offset], YWORD(%%SRCREG)
        vextracti32x4   [%%OUTP + %%DATA_OFFSET + dst_offset + 32], %%SRCREG, 2
%endif

%endmacro

;; =============================================================================
;; Stores specified number of AES blocks from YMM registers
%macro YMM_STORE_BLOCKS_0_16 11
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%OUTP          %2 ; [in] output data pointer to write to
%define %%DATA_OFFSET   %3 ; [in] offset to the output pointer (GP or numerical)
%define %%SRC0          %4 ; [in] YMM register with data to store
%define %%SRC1          %5 ; [in] YMM register with data to store
%define %%SRC2          %6 ; [in] YMM register with data to store
%define %%SRC3          %7 ; [in] YMM register with data to store
%define %%SRC4          %8 ; [in] YMM register with data to store
%define %%SRC5          %9 ; [in] YMM register with data to store
%define %%SRC6          %10 ; [in] YMM register with data to store
%define %%SRC7          %11 ; [in] YMM register with data to store

%assign dst_offset  0
%assign src_idx     0

%rep (%%NUM_BLOCKS / 2)
%xdefine %%SRCREG %%SRC %+ src_idx
        vmovdqu8         [%%OUTP + %%DATA_OFFSET + dst_offset], %%SRCREG
%undef %%SRCREG
%assign dst_offset  (dst_offset + 32)
%assign src_idx     (src_idx + 1)
%endrep

%assign blocks_left (%%NUM_BLOCKS % 2)
%xdefine %%SRCREG %%SRC %+ src_idx

%if blocks_left == 1
        vmovdqu8        [%%OUTP + %%DATA_OFFSET + dst_offset], XWORD(%%SRCREG)
%endif

%endmacro

;; =============================================================================
;; Stores specified number of AES blocks from ZMM registers with mask register
;; for the last loaded register (xmm, ymm or zmm).
;; Stores take place at 1 byte granularity.
%macro ZMM_STORE_MASKED_BLOCKS_0_16 8
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%OUTP          %2 ; [in] output data pointer to write to
%define %%DATA_OFFSET   %3 ; [in] offset to the output pointer (GP or numerical)
%define %%SRC0          %4 ; [in] ZMM register with data to store
%define %%SRC1          %5 ; [in] ZMM register with data to store
%define %%SRC2          %6 ; [in] ZMM register with data to store
%define %%SRC3          %7 ; [in] ZMM register with data to store
%define %%MASK          %8 ; [in] mask register

%assign dst_offset  0
%assign src_idx     0
%assign blocks_left %%NUM_BLOCKS

%if %%NUM_BLOCKS > 0
%rep (((%%NUM_BLOCKS + 3) / 4) - 1)
%xdefine %%SRCREG %%SRC %+ src_idx
        vmovdqu8         [%%OUTP + %%DATA_OFFSET + dst_offset], %%SRCREG
%undef %%SRCREG
%assign dst_offset  (dst_offset + 64)
%assign src_idx     (src_idx + 1)
%assign blocks_left (blocks_left - 4)
%endrep
%endif  ; %if %%NUM_BLOCKS > 0

%xdefine %%SRCREG %%SRC %+ src_idx

%if blocks_left == 1
        vmovdqu8        [%%OUTP + %%DATA_OFFSET + dst_offset]{%%MASK}, XWORD(%%SRCREG)
%elif blocks_left == 2
        vmovdqu8        [%%OUTP + %%DATA_OFFSET + dst_offset]{%%MASK}, YWORD(%%SRCREG)
%elif (blocks_left == 3 || blocks_left == 4)
        vmovdqu8        [%%OUTP + %%DATA_OFFSET + dst_offset]{%%MASK}, %%SRCREG
%endif

%endmacro

;;; ===========================================================================
;;; Handles AES encryption rounds
;;; It handles special cases: the last and first rounds
;;; Optionally, it performs XOR with data after the last AES round.
;;; Uses NROUNDS parameterto check what needs to be done for the current round.
;;; If 3 blocks are trailing then operation on whole ZMM is performed (4 blocks).
%macro ZMM_AESENC_ROUND_BLOCKS_0_16 12
%define %%L0B0_3   %1      ; [in/out] zmm; blocks 0 to 3
%define %%L0B4_7   %2      ; [in/out] zmm; blocks 4 to 7
%define %%L0B8_11  %3      ; [in/out] zmm; blocks 8 to 11
%define %%L0B12_15 %4      ; [in/out] zmm; blocks 12 to 15
%define %%KEY      %5      ; [in] zmm containing round key
%define %%ROUND    %6      ; [in] round number
%define %%D0_3     %7      ; [in] zmm or no_data; plain/cipher text blocks 0-3
%define %%D4_7     %8      ; [in] zmm or no_data; plain/cipher text blocks 4-7
%define %%D8_11    %9      ; [in] zmm or no_data; plain/cipher text blocks 8-11
%define %%D12_15   %10     ; [in] zmm or no_data; plain/cipher text blocks 12-15
%define %%NUMBL    %11     ; [in] number of blocks; numerical value
%define %%NROUNDS  %12     ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxorq, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesenc, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesenclast, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY

;;; === XOR with data
%ifnidn %%D0_3, no_data
%ifnidn %%D4_7, no_data
%ifnidn %%D8_11, no_data
%ifnidn %%D12_15, no_data
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxorq, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%D0_3, %%D4_7, %%D8_11, %%D12_15
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data

%endif                  ; The last round

%endmacro

;;; ===========================================================================
;;; Handles AES decryption rounds
;;; It handles special cases: the last and first rounds
;;; Optionally, it performs XOR with data after the last AES round.
;;; Uses NROUNDS parameter to check what needs to be done for the current round.
;;; If 3 blocks are trailing then operation on whole ZMM is performed (4 blocks).
%macro ZMM_AESDEC_ROUND_BLOCKS_0_16 12
%define %%L0B0_3   %1      ; [in/out] zmm; blocks 0 to 3
%define %%L0B4_7   %2      ; [in/out] zmm; blocks 4 to 7
%define %%L0B8_11  %3      ; [in/out] zmm; blocks 8 to 11
%define %%L0B12_15 %4      ; [in/out] zmm; blocks 12 to 15
%define %%KEY      %5      ; [in] zmm containing round key
%define %%ROUND    %6      ; [in] round number
%define %%D0_3     %7      ; [in] zmm or no_data; cipher text blocks 0-3
%define %%D4_7     %8      ; [in] zmm or no_data; cipher text blocks 4-7
%define %%D8_11    %9      ; [in] zmm or no_data; cipher text blocks 8-11
%define %%D12_15   %10     ; [in] zmm or no_data; cipher text blocks 12-15
%define %%NUMBL    %11     ; [in] number of blocks; numerical value
%define %%NROUNDS  %12     ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxorq, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesdec, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesdeclast, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY

;;; === XOR with data
%ifnidn %%D0_3, no_data
%ifnidn %%D4_7, no_data
%ifnidn %%D8_11, no_data
%ifnidn %%D12_15, no_data
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxorq, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%L0B0_3, %%L0B4_7, %%L0B8_11, %%L0B12_15, \
                        %%D0_3, %%D4_7, %%D8_11, %%D12_15
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data

%endif                  ; The last round

%endmacro

;; =============================================================================
;; Generic macro to produce code that executes %%OPCODE instruction
;; on selected number of AES blocks (16 bytes long) between 0 and 16.
;; All three operands of the instruction come from registers.
%macro YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 26
%define %%NUM_BLOCKS    %1      ; [in] numerical value, number of AES blocks (0 to 16)
%define %%OPCODE        %2      ; [in] instruction name
%define %%DST0          %3      ; [out] destination YMM register
%define %%DST1          %4      ; [out] destination YMM register
%define %%DST2          %5      ; [out] destination YMM register
%define %%DST3          %6      ; [out] destination YMM register
%define %%DST4          %7      ; [out] destination YMM register
%define %%DST5          %8      ; [out] destination YMM register
%define %%DST6          %9      ; [out] destination YMM register
%define %%DST7          %10     ; [out] destination YMM register
%define %%SRC1_0        %11     ; [in] source 1 YMM register
%define %%SRC1_1        %12     ; [in] source 1 YMM register
%define %%SRC1_2        %13     ; [in] source 1 YMM register
%define %%SRC1_3        %14     ; [in] source 1 YMM register
%define %%SRC1_4        %15     ; [in] source 1 YMM register
%define %%SRC1_5        %16     ; [in] source 1 YMM register
%define %%SRC1_6        %17     ; [in] source 1 YMM register
%define %%SRC1_7        %18     ; [in] source 1 YMM register
%define %%SRC2_0        %19     ; [in] source 2 YMM register
%define %%SRC2_1        %20     ; [in] source 2 YMM register
%define %%SRC2_2        %21     ; [in] source 2 YMM register
%define %%SRC2_3        %22     ; [in] source 2 YMM register
%define %%SRC2_4        %23     ; [in] source 2 YMM register
%define %%SRC2_5        %24     ; [in] source 2 YMM register
%define %%SRC2_6        %25     ; [in] source 2 YMM register
%define %%SRC2_7        %26     ; [in] source 2 YMM register

%assign _reg_idx     0
%assign _blocks_left %%NUM_BLOCKS

%rep (%%NUM_BLOCKS / 2)
%xdefine %%DSTREG  %%DST %+ _reg_idx
%xdefine %%SRC1REG %%SRC1_ %+ _reg_idx
%xdefine %%SRC2REG %%SRC2_ %+ _reg_idx
        %%OPCODE        %%DSTREG, %%SRC1REG, %%SRC2REG
%undef %%DSTREG
%undef %%SRC1REG
%undef %%SRC2REG
%assign _reg_idx     (_reg_idx + 1)
%assign _blocks_left (_blocks_left - 2)
%endrep

%xdefine %%DSTREG  %%DST %+ _reg_idx
%xdefine %%SRC1REG %%SRC1_ %+ _reg_idx
%xdefine %%SRC2REG %%SRC2_ %+ _reg_idx

%if _blocks_left == 1
        %%OPCODE        XWORD(%%DSTREG), XWORD(%%SRC1REG), XWORD(%%SRC2REG)
%endif

%endmacro

;;; ===========================================================================
;;; Handles AES encryption rounds
;;; It handles special cases: the last and first rounds
;;; Optionally, it performs XOR with data after the last AES round.
;;; Uses NROUNDS parameter to check what needs to be done for the current round.
%macro YMM_AESENC_ROUND_BLOCKS_0_16 20
%define %%L0B0_1   %1      ; [in/out] ymm; ciphered blocks
%define %%L0B2_3   %2      ; [in/out] ymm; ciphered blocks
%define %%L0B4_5   %3      ; [in/out] ymm; ciphered blocks
%define %%L0B6_7   %4      ; [in/out] ymm; ciphered blocks
%define %%L0B8_9   %5      ; [in/out] ymm; ciphered blocks
%define %%L0B10_11 %6      ; [in/out] ymm; ciphered blocks
%define %%L0B12_13 %7      ; [in/out] ymm; ciphered blocks
%define %%L0B14_15 %8      ; [in/out] ymm; ciphered blocks
%define %%KEY      %9      ; [in] ymm containing round key
%define %%ROUND    %10     ; [in] round number
%define %%D0_1     %11     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D2_3     %12     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D4_5     %13     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D6_7     %14     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D8_9     %15     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D10_11   %16     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D12_13   %17     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D14_15   %18     ; [in] ymm or no_data; plain/cipher text blocks
%define %%NUMBL    %19     ; [in] number of blocks; numerical value
%define %%NROUNDS  %20     ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxorq, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesenc, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesenclast, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY

%ifnidn %%D0_1, no_data
%ifnidn %%D2_3, no_data
%ifnidn %%D4_5, no_data
%ifnidn %%D6_7, no_data
%ifnidn %%D8_9, no_data
%ifnidn %%D10_11, no_data
%ifnidn %%D12_13, no_data
%ifnidn %%D14_15, no_data
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxorq, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%D0_1, %%D2_3,   %%D4_5,   %%D6_7, \
                        %%D8_9, %%D10_11, %%D12_13, %%D14_15
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data

%endif                  ; The last round

%endmacro

;;; ===========================================================================
;;; Handles AES decryption rounds
;;; It handles special cases: the last and first rounds
;;; Optionally, it performs XOR with data after the last AES round.
;;; Uses NROUNDS parameterto check what needs to be done for the current round.
%macro YMM_AESDEC_ROUND_BLOCKS_0_16 20
%define %%L0B0_1   %1      ; [in/out] ymm; ciphered blocks
%define %%L0B2_3   %2      ; [in/out] ymm; ciphered blocks
%define %%L0B4_5   %3      ; [in/out] ymm; ciphered blocks
%define %%L0B6_7   %4      ; [in/out] ymm; ciphered blocks
%define %%L0B8_9   %5      ; [in/out] ymm; ciphered blocks
%define %%L0B10_11 %6      ; [in/out] ymm; ciphered blocks
%define %%L0B12_13 %7      ; [in/out] ymm; ciphered blocks
%define %%L0B14_15 %8      ; [in/out] ymm; ciphered blocks
%define %%KEY      %9      ; [in] ymm containing round key
%define %%ROUND    %10     ; [in] round number
%define %%D0_1     %11     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D2_3     %12     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D4_5     %13     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D6_7     %14     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D8_9     %15     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D10_11   %16     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D12_13   %17     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D14_15   %18     ; [in] ymm or no_data; plain/cipher text blocks
%define %%NUMBL    %19     ; [in] number of blocks; numerical value
%define %%NROUNDS  %20     ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxorq, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesdec, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesdeclast, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY

;;; === XOR with data
%ifnidn %%D0_1, no_data
%ifnidn %%D2_3, no_data
%ifnidn %%D4_5, no_data
%ifnidn %%D6_7, no_data
%ifnidn %%D8_9, no_data
%ifnidn %%D10_11, no_data
%ifnidn %%D12_13, no_data
%ifnidn %%D14_15, no_data
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxorq, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%D0_1, %%D2_3,   %%D4_5,   %%D6_7, \
                        %%D8_9, %%D10_11, %%D12_13, %%D14_15
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data

%endif                  ; The last round

%endmacro

;; =============================================================================
;; Generic macro to produce code that executes %%OPCODE instruction with 3
;; operands on selected number of AES blocks (16 bytes long) between 0 and 8.
;; All three operands of the instruction come from registers.
%macro XMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_8 26
%define %%NUM_BLOCKS    %1      ; [in] numerical value, number of AES blocks (0 to 8)
%define %%OPCODE        %2      ; [in] instruction name
%define %%DST0          %3      ; [out] destination XMM register
%define %%DST1          %4      ; [out] destination XMM register
%define %%DST2          %5      ; [out] destination XMM register
%define %%DST3          %6      ; [out] destination XMM register
%define %%DST4          %7      ; [out] destination XMM register
%define %%DST5          %8      ; [out] destination XMM register
%define %%DST6          %9      ; [out] destination XMM register
%define %%DST7          %10     ; [out] destination XMM register
%define %%SRC1_0        %11     ; [in] source 1 XMM register
%define %%SRC1_1        %12     ; [in] source 1 XMM register
%define %%SRC1_2        %13     ; [in] source 1 XMM register
%define %%SRC1_3        %14     ; [in] source 1 XMM register
%define %%SRC1_4        %15     ; [in] source 1 XMM register
%define %%SRC1_5        %16     ; [in] source 1 XMM register
%define %%SRC1_6        %17     ; [in] source 1 XMM register
%define %%SRC1_7        %18     ; [in] source 1 XMM register
%define %%SRC2_0        %19     ; [in] source 2 XMM register
%define %%SRC2_1        %20     ; [in] source 2 XMM register
%define %%SRC2_2        %21     ; [in] source 2 XMM register
%define %%SRC2_3        %22     ; [in] source 2 XMM register
%define %%SRC2_4        %23     ; [in] source 2 XMM register
%define %%SRC2_5        %24     ; [in] source 2 XMM register
%define %%SRC2_6        %25     ; [in] source 2 XMM register
%define %%SRC2_7        %26     ; [in] source 2 XMM register

%assign _reg_idx     0

%rep (%%NUM_BLOCKS)
%xdefine %%DSTREG  %%DST %+ _reg_idx
%xdefine %%SRC1REG %%SRC1_ %+ _reg_idx
%xdefine %%SRC2REG %%SRC2_ %+ _reg_idx
        %%OPCODE        %%DSTREG, %%SRC1REG, %%SRC2REG
%undef %%DSTREG
%undef %%SRC1REG
%undef %%SRC2REG
%assign _reg_idx     (_reg_idx + 1)
%endrep

%endmacro

;; =============================================================================
;; Generic macro to produce code that executes %%OPCODE instruction with 2
;; operands on selected number of AES blocks (16 bytes long) between 0 and 8.
;; Both operands of the instruction come from registers.
%macro XMM_OPCODE2_DSTR_SRCR_BLOCKS_0_8 18
%define %%NUM_BLOCKS    %1      ; [in] numerical value, number of AES blocks (0 to 8)
%define %%OPCODE        %2      ; [in] instruction name
%define %%DST0          %3      ; [out] destination YMM register
%define %%DST1          %4      ; [out] destination YMM register
%define %%DST2          %5      ; [out] destination YMM register
%define %%DST3          %6      ; [out] destination YMM register
%define %%DST4          %7      ; [out] destination YMM register
%define %%DST5          %8      ; [out] destination YMM register
%define %%DST6          %9      ; [out] destination YMM register
%define %%DST7          %10     ; [out] destination YMM register
%define %%SRC0          %11     ; [in] source YMM register
%define %%SRC1          %12     ; [in] source YMM register
%define %%SRC2          %13     ; [in] source YMM register
%define %%SRC3          %14     ; [in] source YMM register
%define %%SRC4          %15     ; [in] source YMM register
%define %%SRC5          %16     ; [in] source YMM register
%define %%SRC6          %17     ; [in] source YMM register
%define %%SRC7          %18     ; [in] source YMM register

%assign _reg_idx     0

%rep (%%NUM_BLOCKS)
%xdefine %%DSTREG  %%DST %+ _reg_idx
%xdefine %%SRCREG %%SRC %+ _reg_idx
        %%OPCODE        %%DSTREG, %%SRCREG
%undef %%DSTREG
%undef %%SRCREG
%assign _reg_idx     (_reg_idx + 1)
%endrep

%endmacro

;;; ===========================================================================
;;; Handles AES encryption rounds for 0 to 8 blocks on AVX
;;; It handles special cases: the last and first rounds
;;; Optionally, it performs XOR with data after the last AES round.
;;; Uses NROUNDS parameter to check what needs to be done for the current round.
%macro XMM_AESENC_ROUND_BLOCKS_AVX_0_8 20
%define %%L0B0          %1      ; [in/out] xmm; ciphered blocks
%define %%L0B1          %2      ; [in/out] xmm; ciphered blocks
%define %%L0B2          %3      ; [in/out] xmm; ciphered blocks
%define %%L0B3          %4      ; [in/out] xmm; ciphered blocks
%define %%L0B4          %5      ; [in/out] xmm; ciphered blocks
%define %%L0B5          %6      ; [in/out] xmm; ciphered blocks
%define %%L0B6          %7      ; [in/out] xmm; ciphered blocks
%define %%L0B7          %8      ; [in/out] xmm; ciphered blocks
%define %%KEY           %9      ; [in] xmm containing round key
%define %%ROUND         %10     ; [in] round number
%define %%D0            %11     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D1            %12     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D2            %13     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D3            %14     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D4            %15     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D5            %16     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D6            %17     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D7            %18     ; [in] xmm or no_data; plain/cipher text blocks
%define %%NUMBL         %19     ; [in] number of blocks; numerical value
%define %%NROUNDS       %20     ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
        XMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_8 %%NUMBL, vpxor, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
        XMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_8 %%NUMBL, vaesenc, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
        XMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_8 %%NUMBL, vaesenclast, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY

;;; === XOR with data
%ifnidn %%D0, no_data
%ifnidn %%D1, no_data
%ifnidn %%D2, no_data
%ifnidn %%D3, no_data
%ifnidn %%D4, no_data
%ifnidn %%D5, no_data
%ifnidn %%D6, no_data
%ifnidn %%D7, no_data
        XMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_8 %%NUMBL, vpxor, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%D0, %%D1,   %%D2,   %%D3, \
                        %%D4, %%D5, %%D6, %%D7
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data

%endif                  ; The last round

%endmacro

;;; ===========================================================================
;;; Handles AES encryption rounds for 0 to 8 blocks on SSE
;;; It handles special cases: the last and first rounds
;;; Optionally, it performs XOR with data after the last AES round.
;;; Uses NROUNDS parameter to check what needs to be done for the current round.
%macro XMM_AESENC_ROUND_BLOCKS_SSE_0_8 20
%define %%L0B0          %1      ; [in/out] xmm; ciphered blocks
%define %%L0B1          %2      ; [in/out] xmm; ciphered blocks
%define %%L0B2          %3      ; [in/out] xmm; ciphered blocks
%define %%L0B3          %4      ; [in/out] xmm; ciphered blocks
%define %%L0B4          %5      ; [in/out] xmm; ciphered blocks
%define %%L0B5          %6      ; [in/out] xmm; ciphered blocks
%define %%L0B6          %7      ; [in/out] xmm; ciphered blocks
%define %%L0B7          %8      ; [in/out] xmm; ciphered blocks
%define %%KEY           %9      ; [in] xmm containing round key
%define %%ROUND         %10     ; [in] round number
%define %%D0            %11     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D1            %12     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D2            %13     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D3            %14     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D4            %15     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D5            %16     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D6            %17     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D7            %18     ; [in] xmm or no_data; plain/cipher text blocks
%define %%NUMBL         %19     ; [in] number of blocks; numerical value
%define %%NROUNDS       %20     ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
        XMM_OPCODE2_DSTR_SRCR_BLOCKS_0_8 %%NUMBL, pxor, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
        XMM_OPCODE2_DSTR_SRCR_BLOCKS_0_8 %%NUMBL, aesenc, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
        XMM_OPCODE2_DSTR_SRCR_BLOCKS_0_8 %%NUMBL, aesenclast, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY

;;; === XOR with data
%ifnidn %%D0, no_data
%ifnidn %%D1, no_data
%ifnidn %%D2, no_data
%ifnidn %%D3, no_data
%ifnidn %%D4, no_data
%ifnidn %%D5, no_data
%ifnidn %%D6, no_data
%ifnidn %%D7, no_data
        XMM_OPCODE2_DSTR_SRCR_BLOCKS_0_8 %%NUMBL, pxor, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%D0, %%D1,   %%D2,   %%D3, \
                        %%D4, %%D5, %%D6, %%D7
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data

%endif                  ; The last round

%endmacro

;;; ===========================================================================
;;; Handles AES decryption rounds for 0 to 8 blocks on AVX
;;; It handles special cases: the last and first rounds
;;; Optionally, it performs XOR with data after the last AES round.
;;; Uses NROUNDS parameter to check what needs to be done for the current round.
%macro XMM_AESDEC_ROUND_BLOCKS_AVX_0_8 20
%define %%L0B0          %1      ; [in/out] xmm; ciphered blocks
%define %%L0B1          %2      ; [in/out] xmm; ciphered blocks
%define %%L0B2          %3      ; [in/out] xmm; ciphered blocks
%define %%L0B3          %4      ; [in/out] xmm; ciphered blocks
%define %%L0B4          %5      ; [in/out] xmm; ciphered blocks
%define %%L0B5          %6      ; [in/out] xmm; ciphered blocks
%define %%L0B6          %7      ; [in/out] xmm; ciphered blocks
%define %%L0B7          %8      ; [in/out] xmm; ciphered blocks
%define %%KEY           %9      ; [in] xmm containing round key
%define %%ROUND         %10     ; [in] round number
%define %%D0            %11     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D1            %12     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D2            %13     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D3            %14     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D4            %15     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D5            %16     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D6            %17     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D7            %18     ; [in] xmm or no_data; plain/cipher text blocks
%define %%NUMBL         %19     ; [in] number of blocks; numerical value
%define %%NROUNDS       %20     ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
        XMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_8 %%NUMBL, vpxor, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
        XMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_8 %%NUMBL, vaesdec, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
        XMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_8 %%NUMBL, vaesdeclast, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY

;;; === XOR with data
%ifnidn %%D0, no_data
%ifnidn %%D1, no_data
%ifnidn %%D2, no_data
%ifnidn %%D3, no_data
%ifnidn %%D4, no_data
%ifnidn %%D5, no_data
%ifnidn %%D6, no_data
%ifnidn %%D7, no_data
        XMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_8 %%NUMBL, vpxor, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%D0, %%D1,   %%D2,   %%D3, \
                        %%D4, %%D5, %%D6, %%D7
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data

%endif                  ; The last round

%endmacro

%endif ;; _AES_COMMON_ASM

;;; ===========================================================================
;;; Handles AES decryption rounds for 0 to 8 blocks on SSE
;;; It handles special cases: the last and first rounds
;;; Optionally, it performs XOR with data after the last AES round.
;;; Uses NROUNDS parameter to check what needs to be done for the current round.
%macro XMM_AESDEC_ROUND_BLOCKS_SSE_0_8 20
%define %%L0B0          %1      ; [in/out] xmm; ciphered blocks
%define %%L0B1          %2      ; [in/out] xmm; ciphered blocks
%define %%L0B2          %3      ; [in/out] xmm; ciphered blocks
%define %%L0B3          %4      ; [in/out] xmm; ciphered blocks
%define %%L0B4          %5      ; [in/out] xmm; ciphered blocks
%define %%L0B5          %6      ; [in/out] xmm; ciphered blocks
%define %%L0B6          %7      ; [in/out] xmm; ciphered blocks
%define %%L0B7          %8      ; [in/out] xmm; ciphered blocks
%define %%KEY           %9      ; [in] xmm containing round key
%define %%ROUND         %10     ; [in] round number
%define %%D0            %11     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D1            %12     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D2            %13     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D3            %14     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D4            %15     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D5            %16     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D6            %17     ; [in] xmm or no_data; plain/cipher text blocks
%define %%D7            %18     ; [in] xmm or no_data; plain/cipher text blocks
%define %%NUMBL         %19     ; [in] number of blocks; numerical value
%define %%NROUNDS       %20     ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
        XMM_OPCODE2_DSTR_SRCR_BLOCKS_0_8 %%NUMBL, pxor, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
        XMM_OPCODE2_DSTR_SRCR_BLOCKS_0_8 %%NUMBL, aesdec, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
        XMM_OPCODE2_DSTR_SRCR_BLOCKS_0_8 %%NUMBL, aesdeclast, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY

;;; === XOR with data
%ifnidn %%D0, no_data
%ifnidn %%D1, no_data
%ifnidn %%D2, no_data
%ifnidn %%D3, no_data
%ifnidn %%D4, no_data
%ifnidn %%D5, no_data
%ifnidn %%D6, no_data
%ifnidn %%D7, no_data
        XMM_OPCODE2_DSTR_SRCR_BLOCKS_0_8 %%NUMBL, pxor, \
                        %%L0B0, %%L0B1,   %%L0B2,   %%L0B3, \
                        %%L0B4, %%L0B5, %%L0B6, %%L0B7, \
                        %%D0, %%D1,   %%D2,   %%D3, \
                        %%D4, %%D5, %%D6, %%D7

%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data

%endif                  ; The last round

%endmacro

;; =============================================================================
;; Loads up to 8 blocks into XMM registers on AVX
%macro XMM_LOAD_BLOCKS_AVX_0_8 11
%define %%NUM_BLOCKS    %1      ; [in] numerical value, number of AES blocks (0 to 16)
%define %%INP           %2      ; [in] input data pointer to read from
%define %%DATA_OFFSET   %3      ; [in] offset to the output pointer (GP or numerical)
%define %%DST0          %4      ; [out] XMM register with loaded data
%define %%DST1          %5      ; [out] XMM register with loaded data
%define %%DST2          %6      ; [out] XMM register with loaded data
%define %%DST3          %7      ; [out] XMM register with loaded data
%define %%DST4          %8      ; [out] XMM register with loaded data
%define %%DST5          %9      ; [out] XMM register with loaded data
%define %%DST6          %10     ; [out] XMM register with loaded data
%define %%DST7          %11     ; [out] XMM register with loaded data

%assign src_offset  0
%assign dst_idx     0

%rep (%%NUM_BLOCKS)
%xdefine %%DSTREG %%DST %+ dst_idx
        vmovdqu         %%DSTREG, [%%INP + %%DATA_OFFSET + src_offset]
%undef %%DSTREG
%assign src_offset  (src_offset + 16)
%assign dst_idx     (dst_idx + 1)
%endrep

%endmacro

;; =============================================================================
;; Loads up to 8 AES blocks into XMM registers on SSE
%macro XMM_LOAD_BLOCKS_SSE_0_8 11
%define %%NUM_BLOCKS    %1      ; [in] numerical value, number of AES blocks (0 to 16)
%define %%INP           %2      ; [in] input data pointer to read from
%define %%DATA_OFFSET   %3      ; [in] offset to the output pointer (GP or numerical)
%define %%DST0          %4      ; [out] XMM register with loaded data
%define %%DST1          %5      ; [out] XMM register with loaded data
%define %%DST2          %6      ; [out] XMM register with loaded data
%define %%DST3          %7      ; [out] XMM register with loaded data
%define %%DST4          %8      ; [out] XMM register with loaded data
%define %%DST5          %9      ; [out] XMM register with loaded data
%define %%DST6          %10     ; [out] XMM register with loaded data
%define %%DST7          %11     ; [out] XMM register with loaded data

%assign src_offset  0
%assign dst_idx     0

%rep (%%NUM_BLOCKS)
%xdefine %%DSTREG %%DST %+ dst_idx
        movdqu         %%DSTREG, [%%INP + %%DATA_OFFSET + src_offset]
%undef %%DSTREG
%assign src_offset  (src_offset + 16)
%assign dst_idx     (dst_idx + 1)
%endrep

%endmacro

;; =============================================================================
;; Stores up to 8 AES blocks from XMM registers on AVX
%macro XMM_STORE_BLOCKS_AVX_0_8 11
%define %%NUM_BLOCKS    %1      ; [in] numerical value, number of AES blocks (0 to 8)
%define %%OUTP          %2      ; [in] output data pointer to write to
%define %%DATA_OFFSET   %3      ; [in] offset to the output pointer (GP or numerical)
%define %%SRC0          %4      ; [in] XMM register with data to store
%define %%SRC1          %5      ; [in] XMM register with data to store
%define %%SRC2          %6      ; [in] XMM register with data to store
%define %%SRC3          %7      ; [in] XMM register with data to store
%define %%SRC4          %8      ; [in] XMM register with data to store
%define %%SRC5          %9      ; [in] XMM register with data to store
%define %%SRC6          %10     ; [in] XMM register with data to store
%define %%SRC7          %11     ; [in] XMM register with data to store

%assign dst_offset  0
%assign src_idx     0

%rep (%%NUM_BLOCKS)
%xdefine %%SRCREG %%SRC %+ src_idx
        vmovdqu         [%%OUTP + %%DATA_OFFSET + dst_offset], %%SRCREG
%undef %%SRCREG
%assign dst_offset  (dst_offset + 16)
%assign src_idx     (src_idx + 1)
%endrep

%endmacro

;; =============================================================================
;; Stores up to 8 AES blocks from XMM registers on SSE
%macro XMM_STORE_BLOCKS_SSE_0_8 11
%define %%NUM_BLOCKS    %1      ; [in] numerical value, number of AES blocks (0 to 8)
%define %%OUTP          %2      ; [in] output data pointer to write to
%define %%DATA_OFFSET   %3      ; [in] offset to the output pointer (GP or numerical)
%define %%SRC0          %4      ; [in] XMM register with data to store
%define %%SRC1          %5      ; [in] XMM register with data to store
%define %%SRC2          %6      ; [in] XMM register with data to store
%define %%SRC3          %7      ; [in] XMM register with data to store
%define %%SRC4          %8      ; [in] XMM register with data to store
%define %%SRC5          %9      ; [in] XMM register with data to store
%define %%SRC6          %10     ; [in] XMM register with data to store
%define %%SRC7          %11     ; [in] XMM register with data to store

%assign dst_offset  0
%assign src_idx     0

%rep (%%NUM_BLOCKS)
%xdefine %%SRCREG %%SRC %+ src_idx
        movdqu         [%%OUTP + %%DATA_OFFSET + dst_offset], %%SRCREG
%undef %%SRCREG
%assign dst_offset  (dst_offset + 16)
%assign src_idx     (src_idx + 1)
%endrep

%endmacro

;; =============================================================================
;; Loads specified number of AES blocks into YMM registers
%macro YMM_LOAD_BLOCKS_AVX2_0_16 11
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%INP           %2 ; [in] input data pointer to read from
%define %%DATA_OFFSET   %3 ; [in] offset to the output pointer (GP or numerical)
%define %%DST0          %4 ; [out] YMM register with loaded data
%define %%DST1          %5 ; [out] YMM register with loaded data
%define %%DST2          %6 ; [out] YMM register with loaded data
%define %%DST3          %7 ; [out] YMM register with loaded data
%define %%DST4          %8 ; [out] YMM register with loaded data
%define %%DST5          %9 ; [out] YMM register with loaded data
%define %%DST6          %10 ; [out] YMM register with loaded data
%define %%DST7          %11 ; [out] YMM register with loaded data

%assign src_offset  0
%assign dst_idx     0

%rep (%%NUM_BLOCKS / 2)
%xdefine %%DSTREG %%DST %+ dst_idx
        vmovdqu        %%DSTREG, [%%INP + %%DATA_OFFSET + src_offset]
%undef %%DSTREG
%assign src_offset  (src_offset + 32)
%assign dst_idx     (dst_idx + 1)
%endrep

%assign blocks_left (%%NUM_BLOCKS % 2)
%xdefine %%DSTREG %%DST %+ dst_idx

%if blocks_left == 1
        vmovdqu        XWORD(%%DSTREG), [%%INP + %%DATA_OFFSET + src_offset]
%endif

%endmacro

;; =============================================================================
;; Stores specified number of AES blocks from YMM registers
%macro YMM_STORE_BLOCKS_AVX2_0_16 11
%define %%NUM_BLOCKS    %1 ; [in] numerical value, number of AES blocks (0 to 16)
%define %%OUTP          %2 ; [in] output data pointer to write to
%define %%DATA_OFFSET   %3 ; [in] offset to the output pointer (GP or numerical)
%define %%SRC0          %4 ; [in] YMM register with data to store
%define %%SRC1          %5 ; [in] YMM register with data to store
%define %%SRC2          %6 ; [in] YMM register with data to store
%define %%SRC3          %7 ; [in] YMM register with data to store
%define %%SRC4          %8 ; [in] YMM register with data to store
%define %%SRC5          %9 ; [in] YMM register with data to store
%define %%SRC6          %10 ; [in] YMM register with data to store
%define %%SRC7          %11 ; [in] YMM register with data to store

%assign dst_offset  0
%assign src_idx     0

%rep (%%NUM_BLOCKS / 2)
%xdefine %%SRCREG %%SRC %+ src_idx
        vmovdqu         [%%OUTP + %%DATA_OFFSET + dst_offset], %%SRCREG
%undef %%SRCREG
%assign dst_offset  (dst_offset + 32)
%assign src_idx     (src_idx + 1)
%endrep

%assign blocks_left (%%NUM_BLOCKS % 2)
%xdefine %%SRCREG %%SRC %+ src_idx

%if blocks_left == 1
        vmovdqu        [%%OUTP + %%DATA_OFFSET + dst_offset], XWORD(%%SRCREG)
%endif

%endmacro

;;; ===========================================================================
;;; Handles AES encryption rounds
;;; It handles special cases: the last and first rounds
;;; Optionally, it performs XOR with data after the last AES round.
;;; Uses NROUNDS parameter to check what needs to be done for the current round.
%macro YMM_AESENC_ROUND_BLOCKS_AVX2_0_16 20
%define %%L0B0_1   %1      ; [in/out] ymm; ciphered blocks
%define %%L0B2_3   %2      ; [in/out] ymm; ciphered blocks
%define %%L0B4_5   %3      ; [in/out] ymm; ciphered blocks
%define %%L0B6_7   %4      ; [in/out] ymm; ciphered blocks
%define %%L0B8_9   %5      ; [in/out] ymm; ciphered blocks
%define %%L0B10_11 %6      ; [in/out] ymm; ciphered blocks
%define %%L0B12_13 %7      ; [in/out] ymm; ciphered blocks
%define %%L0B14_15 %8      ; [in/out] ymm; ciphered blocks
%define %%KEY      %9      ; [in] ymm containing round key
%define %%ROUND    %10     ; [in] round number
%define %%D0_1     %11     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D2_3     %12     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D4_5     %13     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D6_7     %14     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D8_9     %15     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D10_11   %16     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D12_13   %17     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D14_15   %18     ; [in] ymm or no_data; plain/cipher text blocks
%define %%NUMBL    %19     ; [in] number of blocks; numerical value
%define %%NROUNDS  %20     ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxor, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesenc, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesenclast, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY

%ifnidn %%D0_1, no_data
%ifnidn %%D2_3, no_data
%ifnidn %%D4_5, no_data
%ifnidn %%D6_7, no_data
%ifnidn %%D8_9, no_data
%ifnidn %%D10_11, no_data
%ifnidn %%D12_13, no_data
%ifnidn %%D14_15, no_data
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxor, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%D0_1, %%D2_3,   %%D4_5,   %%D6_7, \
                        %%D8_9, %%D10_11, %%D12_13, %%D14_15
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data

%endif                  ; The last round

%endmacro

;;; ===========================================================================
;;; Handles AES decryption rounds
;;; It handles special cases: the last and first rounds
;;; Optionally, it performs XOR with data after the last AES round.
;;; Uses NROUNDS parameterto check what needs to be done for the current round.
%macro YMM_AESDEC_ROUND_BLOCKS_AVX2_0_16 20
%define %%L0B0_1   %1      ; [in/out] ymm; ciphered blocks
%define %%L0B2_3   %2      ; [in/out] ymm; ciphered blocks
%define %%L0B4_5   %3      ; [in/out] ymm; ciphered blocks
%define %%L0B6_7   %4      ; [in/out] ymm; ciphered blocks
%define %%L0B8_9   %5      ; [in/out] ymm; ciphered blocks
%define %%L0B10_11 %6      ; [in/out] ymm; ciphered blocks
%define %%L0B12_13 %7      ; [in/out] ymm; ciphered blocks
%define %%L0B14_15 %8      ; [in/out] ymm; ciphered blocks
%define %%KEY      %9      ; [in] ymm containing round key
%define %%ROUND    %10     ; [in] round number
%define %%D0_1     %11     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D2_3     %12     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D4_5     %13     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D6_7     %14     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D8_9     %15     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D10_11   %16     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D12_13   %17     ; [in] ymm or no_data; plain/cipher text blocks
%define %%D14_15   %18     ; [in] ymm or no_data; plain/cipher text blocks
%define %%NUMBL    %19     ; [in] number of blocks; numerical value
%define %%NROUNDS  %20     ; [in] number of rounds; numerical value

;;; === first AES round
%if (%%ROUND < 1)
        ;;  round 0
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxor, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; ROUND 0

;;; === middle AES rounds
%if (%%ROUND >= 1 && %%ROUND <= %%NROUNDS)
        ;; rounds 1 to 9/11/13
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesdec, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY
%endif                  ; rounds 1 to 9/11/13

;;; === last AES round
%if (%%ROUND > %%NROUNDS)
        ;; the last round - mix enclast with text xor's
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vaesdeclast, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY, %%KEY

;;; === XOR with data
%ifnidn %%D0_1, no_data
%ifnidn %%D2_3, no_data
%ifnidn %%D4_5, no_data
%ifnidn %%D6_7, no_data
%ifnidn %%D8_9, no_data
%ifnidn %%D10_11, no_data
%ifnidn %%D12_13, no_data
%ifnidn %%D14_15, no_data
        YMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 %%NUMBL, vpxor, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%L0B0_1, %%L0B2_3,   %%L0B4_5,   %%L0B6_7, \
                        %%L0B8_9, %%L0B10_11, %%L0B12_13, %%L0B14_15, \
                        %%D0_1, %%D2_3,   %%D4_5,   %%D6_7, \
                        %%D8_9, %%D10_11, %%D12_13, %%D14_15
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data
%endif                          ; !no_data

%endif                  ; The last round

%endmacro
