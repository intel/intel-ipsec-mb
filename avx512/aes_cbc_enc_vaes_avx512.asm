;;
;; Copyright (c) 2019-2020, Intel Corporation
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

;;; routines to do 128/192/256 bit CBC AES encrypt

%include "include/os.asm"
%include "mb_mgr_datastruct.asm"
%include "include/reg_sizes.asm"
%include "include/clear_regs.asm"

struc STACK
_gpr_save:      resq    3
endstruc

%define GPR_SAVE_AREA   rsp + _gpr_save

%ifdef LINUX
%define arg1            rdi
%define arg2            rsi
%define arg3            rcx
%define arg4            rdx
%else
%define arg1            rcx
%define arg2            rdx
%define arg3            rdi
%define arg4            rsi
%endif

%define ARG             arg1
%define LEN             arg2

%define IA0             rax
%define IA1             rbx
%define IA2             arg3
%define IA3             arg4
%define IA4             rbp
%define IA5             r8
%define IA6             r9
%define IA7             r10
%define IA8             r11
%define IA9             r13
%define IA10            r14
%define IA11            r15
%define IA12            r12

%define ZIV00_03        zmm8
%define ZIV04_07        zmm9
%define ZIV08_11        zmm10
%define ZIV12_15        zmm11

%define ZT0             zmm16
%define ZT1             zmm17
%define ZT2             zmm18
%define ZT3             zmm19
%define ZT4             zmm20
%define ZT5             zmm21
%define ZT6             zmm22
%define ZT7             zmm23
%define ZT8             zmm24
%define ZT9             zmm25
%define ZT10            zmm26
%define ZT11            zmm27
%define ZT12            zmm28
%define ZT13            zmm29
%define ZT14            zmm30
%define ZT15            zmm31

%define ZT16            zmm12
%define ZT17            zmm13
%define ZT18            zmm14
%define ZT19            zmm15

%define TAB_A0B0A1B1    zmm6
%define TAB_A2B2A3B3    zmm7

;; Save registers states
%macro FUNC_SAVE 0
        sub             rsp, STACK_size
        mov             [GPR_SAVE_AREA + 8*0], rbp
%ifndef LINUX
        mov             [GPR_SAVE_AREA + 8*1], rsi
        mov             [GPR_SAVE_AREA + 8*2], rdi
%endif
%endmacro

;; Restore register states
%macro FUNC_RESTORE 0
        ;; XMMs are saved at a higher level
        mov             rbp, [GPR_SAVE_AREA + 8*0]
%ifndef LINUX
        mov             rsi, [GPR_SAVE_AREA + 8*1]
        mov             rdi, [GPR_SAVE_AREA + 8*2]
%endif
        add             rsp, STACK_size
        vzeroupper
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Transpose macro - executes 4x4 transpose of 4 ZMM registers
; in: L0B0-3   out: B0L0-3
;     L1B0-3        B1L0-3
;     L2B0-3        B2L0-3
;     L3B0-3        B3L0-3
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro TRANSPOSE_4x4 8
%define %%IN_OUT_0      %1
%define %%IN_OUT_1      %2
%define %%IN_OUT_2      %3
%define %%IN_OUT_3      %4
%define %%ZTMP_0        %5
%define %%ZTMP_1        %6
%define %%ZTMP_2        %7
%define %%ZTMP_3        %8

        vmovdqa64       %%ZTMP_0, TAB_A0B0A1B1
        vmovdqa64       %%ZTMP_1, %%ZTMP_0
        vmovdqa64       %%ZTMP_2, TAB_A2B2A3B3
        vmovdqa64       %%ZTMP_3, %%ZTMP_2

        vpermi2q        %%ZTMP_0, %%IN_OUT_0, %%IN_OUT_1
        vpermi2q        %%ZTMP_1, %%IN_OUT_2, %%IN_OUT_3
        vpermi2q        %%ZTMP_2, %%IN_OUT_0, %%IN_OUT_1
        vpermi2q        %%ZTMP_3, %%IN_OUT_2, %%IN_OUT_3

        vshufi64x2      %%IN_OUT_0, %%ZTMP_0, %%ZTMP_1, 0x44
        vshufi64x2      %%IN_OUT_2, %%ZTMP_2, %%ZTMP_3, 0x44
        vshufi64x2      %%IN_OUT_1, %%ZTMP_0, %%ZTMP_1, 0xee
        vshufi64x2      %%IN_OUT_3, %%ZTMP_2, %%ZTMP_3, 0xee
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; LOAD_STORE - loads/stores 1-4 blocks (16 bytes) for 4 lanes into ZMM registers
; - Loads 4 blocks by default
; - Pass %%MASK_REG argument to load/store 1-3 blocks (optional)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro LOAD_STORE_x4 15-16
%define %%LANE_A        %1  ; [in] lane index to load/store (numerical)
%define %%LANE_B        %2  ; [in] lane index to load/store (numerical)
%define %%LANE_C        %3  ; [in] lane index to load/store (numerical)
%define %%LANE_D        %4  ; [in] lane index to load/store (numerical)
%define %%DATA_PTR      %5  ; [in] GP reg with ptr to lane input table
%define %%OFFSET        %6  ; [in] GP reg input/output buffer offset
%define %%ZDATA0        %7  ; [in/out] ZMM reg to load/store data
%define %%ZDATA1        %8  ; [in/out] ZMM reg to load/store data
%define %%ZDATA2        %9  ; [in/out] ZMM reg to load/store data
%define %%ZDATA3        %10 ; [in/out] ZMM reg to load/store data
%define %%GP0           %11 ; [clobbered] tmp GP reg
%define %%GP1           %12 ; [clobbered] tmp GP reg
%define %%GP2           %13 ; [clobbered] tmp GP reg
%define %%GP3           %14 ; [clobbered] tmp GP reg
%define %%LOAD_STORE    %15 ; [in] string value to select LOAD or STORE
%define %%MASK_REG      %16 ; [in] mask reg used for load/store mask
%define %%NUM_ARGS      %0

        mov             %%GP0, [%%DATA_PTR + 8*(%%LANE_A)]
        mov             %%GP1, [%%DATA_PTR + 8*(%%LANE_B)]
        mov             %%GP2, [%%DATA_PTR + 8*(%%LANE_C)]
        mov             %%GP3, [%%DATA_PTR + 8*(%%LANE_D)]

%if %%NUM_ARGS <= 15    ;; %%MASK_REG not set, assume 4 block load/store
%ifidn %%LOAD_STORE, LOAD
        vmovdqu8        %%ZDATA0, [%%GP0 + %%OFFSET]
        vmovdqu8        %%ZDATA1, [%%GP1 + %%OFFSET]
        vmovdqu8        %%ZDATA2, [%%GP2 + %%OFFSET]
        vmovdqu8        %%ZDATA3, [%%GP3 + %%OFFSET]
%else   ; STORE8
        vmovdqu8        [%%GP0 + %%OFFSET], %%ZDATA0
        vmovdqu8        [%%GP1 + %%OFFSET], %%ZDATA1
        vmovdqu8        [%%GP2 + %%OFFSET], %%ZDATA2
        vmovdqu8        [%%GP3 + %%OFFSET], %%ZDATA3
%endif
%else   ;; %%MASK_REG argument passed - 1, 2, or 3 block load/store
%ifidn %%LOAD_STORE, LOAD
        vmovdqu8        %%ZDATA0{%%MASK_REG}{z}, [%%GP0 + %%OFFSET]
        vmovdqu8        %%ZDATA1{%%MASK_REG}{z}, [%%GP1 + %%OFFSET]
        vmovdqu8        %%ZDATA2{%%MASK_REG}{z}, [%%GP2 + %%OFFSET]
        vmovdqu8        %%ZDATA3{%%MASK_REG}{z}, [%%GP3 + %%OFFSET]
%else   ; STORE
        vmovdqu8        [%%GP0 + %%OFFSET]{%%MASK_REG}, %%ZDATA0
        vmovdqu8        [%%GP1 + %%OFFSET]{%%MASK_REG}, %%ZDATA1
        vmovdqu8        [%%GP2 + %%OFFSET]{%%MASK_REG}, %%ZDATA2
        vmovdqu8        [%%GP3 + %%OFFSET]{%%MASK_REG}, %%ZDATA3
%endif
%endif  ;; %%NUM_ARGS
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; AESENC_ROUNDS_x16 macro
; - 16 lanes, 1 block per lane
; - performs AES encrypt rounds 1-NROUNDS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro AESENC_ROUNDS_x16 5
%define %%L00_03  %1              ; [in/out] ZMM with lane 0-3 blocks
%define %%L04_07  %2              ; [in/out] ZMM with lane 4-7 blocks
%define %%L08_11  %3              ; [in/out] ZMM with lane 8-11 blocks
%define %%L12_15  %4              ; [in/out] ZMM with lane 12-15 blocks
%define %%NROUNDS %5              ; [in] number of aes rounds

%define %%KP ARG + _aesarg_key_tab
%define K00_03_OFFSET 0
%define K04_07_OFFSET 64
%define K08_11_OFFSET 128
%define K12_15_OFFSET 192

%assign ROUND 1
%rep (%%NROUNDS + 1)

%if ROUND <= %%NROUNDS

        ;; rounds 1 to 9/11/13
        vaesenc         %%L00_03, %%L00_03, [%%KP + K00_03_OFFSET + ROUND * (16*16)]
        vaesenc         %%L04_07, %%L04_07, [%%KP + K04_07_OFFSET + ROUND * (16*16)]
        vaesenc         %%L08_11, %%L08_11, [%%KP + K08_11_OFFSET + ROUND * (16*16)]
        vaesenc         %%L12_15, %%L12_15, [%%KP + K12_15_OFFSET + ROUND * (16*16)]
%else
        ;; the last round
        vaesenclast     %%L00_03, %%L00_03, [%%KP + K00_03_OFFSET + ROUND * (16*16)]
        vaesenclast     %%L04_07, %%L04_07, [%%KP + K04_07_OFFSET + ROUND * (16*16)]
        vaesenclast     %%L08_11, %%L08_11, [%%KP + K08_11_OFFSET + ROUND * (16*16)]
        vaesenclast     %%L12_15, %%L12_15, [%%KP + K12_15_OFFSET + ROUND * (16*16)]
%endif

%assign ROUND (ROUND + 1)
%endrep

%endmacro                       ; AESENC_ROUNDS_x16


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ENCRYPT_16_PARALLEL - Encode all blocks up to multiple of 4
; - Operation
;   - loop encrypting %%LENGTH bytes of input data
;   - each loop encrypts 4 blocks across 16 lanes
;   - stop when %%LENGTH is less than 64 bytes (4 blocks)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro ENCRYPT_16_PARALLEL 32
%define %%ZIV00_03      %1  ;; [in] lane 0-3 IVs
%define %%ZIV04_07      %2  ;; [in] lane 4-7 IVs
%define %%ZIV08_11      %3  ;; [in] lane 8-11 IVs
%define %%ZIV12_15      %4  ;; [in] lane 12-15 IVs
%define %%LENGTH        %5  ;; [in/out] GP register with length in bytes
%define %%NROUNDS       %6  ;; [in] Number of AES rounds; numerical value
%define %%IDX           %7  ;; [clobbered] GP reg to maintain idx
%define %%B0L00_03      %8  ;; [clobbered] tmp ZMM register
%define %%B0L04_07      %9  ;; [clobbered] tmp ZMM register
%define %%B0L08_11      %10 ;; [clobbered] tmp ZMM register
%define %%B0L12_15      %11 ;; [clobbered] tmp ZMM register
%define %%B1L00_03      %12 ;; [clobbered] tmp ZMM register
%define %%B1L04_07      %13 ;; [clobbered] tmp ZMM register
%define %%B1L08_11      %14 ;; [clobbered] tmp ZMM register
%define %%B1L12_15      %15 ;; [clobbered] tmp ZMM register
%define %%B2L00_03      %16 ;; [clobbered] tmp ZMM register
%define %%B2L04_07      %17 ;; [clobbered] tmp ZMM register
%define %%B2L08_11      %18 ;; [clobbered] tmp ZMM register
%define %%B2L12_15      %19 ;; [clobbered] tmp ZMM register
%define %%B3L00_03      %20 ;; [clobbered] tmp ZMM register
%define %%B3L04_07      %21 ;; [clobbered] tmp ZMM register
%define %%B3L08_11      %22 ;; [clobbered] tmp ZMM register
%define %%B3L12_15      %23 ;; [clobbered] tmp ZMM register
%define %%ZTMP0         %24 ;; [clobbered] tmp ZMM register
%define %%ZTMP1         %25 ;; [clobbered] tmp ZMM register
%define %%ZTMP2         %26 ;; [clobbered] tmp ZMM register
%define %%ZTMP3         %27 ;; [clobbered] tmp ZMM register
%define %%TMP0          %28 ;; [clobbered] tmp GP register
%define %%TMP1          %29 ;; [clobbered] tmp GP register
%define %%TMP2          %30 ;; [clobbered] tmp GP register
%define %%TMP3          %31 ;; [clobbered] tmp GP register
%define %%CBC_MAC       %32 ;; CBC-MAC flag

%define %%IN    ARG + _aesarg_in
%define %%OUT   ARG + _aesarg_out
%define %%KP    ARG + _aesarg_key_tab
%define K00_03_OFFSET 0
%define K04_07_OFFSET 64
%define K08_11_OFFSET 128
%define K12_15_OFFSET 192

        ;; check for at least 4 blocks
        cmp             %%LENGTH, 64
        jl              %%encrypt_16_done

        xor             %%IDX, %%IDX
        ;; skip length check on first loop
        jmp             %%encrypt_16_first

%%encrypt_16_start:
        cmp             %%LENGTH, 64
        jl              %%encrypt_16_end

%%encrypt_16_first:
        ;; load 4 plaintext blocks for lanes 0-3
        LOAD_STORE_x4 0, 1, 2, 3, %%IN, %%IDX, %%B0L00_03, %%B1L00_03, \
                     %%B2L00_03, %%B3L00_03, %%TMP0, %%TMP1, %%TMP2, %%TMP3, LOAD

        TRANSPOSE_4x4 %%B0L00_03, %%B1L00_03, %%B2L00_03, %%B3L00_03, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        ;; load 4 plaintext blocks for lanes 4-7
        LOAD_STORE_x4 4, 5, 6, 7, %%IN, %%IDX, %%B0L04_07, %%B1L04_07, \
                     %%B2L04_07, %%B3L04_07, %%TMP0, %%TMP1, %%TMP2, %%TMP3, LOAD

        TRANSPOSE_4x4 %%B0L04_07, %%B1L04_07, %%B2L04_07, %%B3L04_07, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        ;; load 4 plaintext blocks for lanes 8-11
        LOAD_STORE_x4 8, 9, 10, 11, %%IN, %%IDX, %%B0L08_11, %%B1L08_11, \
                     %%B2L08_11, %%B3L08_11, %%TMP0, %%TMP1, %%TMP2, %%TMP3, LOAD

        TRANSPOSE_4x4 %%B0L08_11, %%B1L08_11, %%B2L08_11, %%B3L08_11, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        ;; load 4 plaintext blocks for lanes 12-15
        LOAD_STORE_x4 12, 13, 14, 15, %%IN, %%IDX, %%B0L12_15, %%B1L12_15, \
                     %%B2L12_15, %%B3L12_15, %%TMP0, %%TMP1, %%TMP2, %%TMP3, LOAD

        TRANSPOSE_4x4 %%B0L12_15, %%B1L12_15, %%B2L12_15, %%B3L12_15, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        ;; xor first plaintext block with IV and round zero key
        vpternlogq      %%B0L00_03, %%ZIV00_03, [%%KP + K00_03_OFFSET], 0x96
        vpternlogq      %%B0L04_07, %%ZIV04_07, [%%KP + K04_07_OFFSET], 0x96
        vpternlogq      %%B0L08_11, %%ZIV08_11, [%%KP + K08_11_OFFSET], 0x96
        vpternlogq      %%B0L12_15, %%ZIV12_15, [%%KP + K12_15_OFFSET], 0x96

        ;; encrypt block 0 lanes
        AESENC_ROUNDS_x16 %%B0L00_03, %%B0L04_07, %%B0L08_11, %%B0L12_15, %%NROUNDS

        ;; xor plaintext block with last cipher block and round zero key
        vpternlogq      %%B1L00_03, %%B0L00_03, [%%KP + K00_03_OFFSET], 0x96
        vpternlogq      %%B1L04_07, %%B0L04_07, [%%KP + K04_07_OFFSET], 0x96
        vpternlogq      %%B1L08_11, %%B0L08_11, [%%KP + K08_11_OFFSET], 0x96
        vpternlogq      %%B1L12_15, %%B0L12_15, [%%KP + K12_15_OFFSET], 0x96

        ;; encrypt block 1 lanes
        AESENC_ROUNDS_x16 %%B1L00_03, %%B1L04_07, %%B1L08_11, %%B1L12_15, %%NROUNDS

        ;; xor plaintext block with last cipher block and round zero key
        vpternlogq      %%B2L00_03, %%B1L00_03, [%%KP + K00_03_OFFSET], 0x96
        vpternlogq      %%B2L04_07, %%B1L04_07, [%%KP + K04_07_OFFSET], 0x96
        vpternlogq      %%B2L08_11, %%B1L08_11, [%%KP + K08_11_OFFSET], 0x96
        vpternlogq      %%B2L12_15, %%B1L12_15, [%%KP + K12_15_OFFSET], 0x96

        ;; encrypt block 2 lanes
        AESENC_ROUNDS_x16 %%B2L00_03, %%B2L04_07, %%B2L08_11, %%B2L12_15, %%NROUNDS

        ;; xor plaintext block with last cipher block and round zero key
        vpternlogq      %%B3L00_03, %%B2L00_03, [%%KP + K00_03_OFFSET], 0x96
        vpternlogq      %%B3L04_07, %%B2L04_07, [%%KP + K04_07_OFFSET], 0x96
        vpternlogq      %%B3L08_11, %%B2L08_11, [%%KP + K08_11_OFFSET], 0x96
        vpternlogq      %%B3L12_15, %%B2L12_15, [%%KP + K12_15_OFFSET], 0x96

        ;; encrypt block 3 lanes
        AESENC_ROUNDS_x16 %%B3L00_03, %%B3L04_07, %%B3L08_11, %%B3L12_15, %%NROUNDS

        ;; store last cipher block
        vmovdqa64       %%ZIV00_03, %%B3L00_03
        vmovdqa64       %%ZIV04_07, %%B3L04_07
        vmovdqa64       %%ZIV08_11, %%B3L08_11
        vmovdqa64       %%ZIV12_15, %%B3L12_15

        ;; Don't write back ciphertext for CBC-MAC
%if %%CBC_MAC == 0
        ;; write back cipher text for lanes 0-3
        TRANSPOSE_4x4 %%B0L00_03, %%B1L00_03, %%B2L00_03, %%B3L00_03, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        LOAD_STORE_x4 0, 1, 2, 3, %%OUT, %%IDX, %%B0L00_03, %%B1L00_03, \
                     %%B2L00_03, %%B3L00_03, %%TMP0, %%TMP1, %%TMP2, %%TMP3, STORE

        ;; write back cipher text for lanes 4-7
        TRANSPOSE_4x4 %%B0L04_07, %%B1L04_07, %%B2L04_07, %%B3L04_07, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        LOAD_STORE_x4 4, 5, 6, 7, %%OUT, %%IDX, %%B0L04_07, %%B1L04_07, \
                     %%B2L04_07, %%B3L04_07, %%TMP0, %%TMP1, %%TMP2, %%TMP3, STORE

        ;; write back cipher text for lanes 8-11
        TRANSPOSE_4x4 %%B0L08_11, %%B1L08_11, %%B2L08_11, %%B3L08_11, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        LOAD_STORE_x4 8, 9, 10, 11, %%OUT, %%IDX, %%B0L08_11, %%B1L08_11, \
                     %%B2L08_11, %%B3L08_11, %%TMP0, %%TMP1, %%TMP2, %%TMP3, STORE

        ;; write back cipher text for lanes 12-15
        TRANSPOSE_4x4 %%B0L12_15, %%B1L12_15, %%B2L12_15, %%B3L12_15, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        LOAD_STORE_x4 12, 13, 14, 15, %%OUT, %%IDX, %%B0L12_15, %%B1L12_15, \
                     %%B2L12_15, %%B3L12_15, %%TMP0, %%TMP1, %%TMP2, %%TMP3, STORE
%endif ;; !CBC_MAC
        sub             %%LENGTH, 64
        add             %%IDX, 64
        jmp             %%encrypt_16_start

%%encrypt_16_end:
        ;; update in/out pointers
        vpbroadcastq    %%ZTMP2, %%IDX
        vpaddq          %%ZTMP0, %%ZTMP2, [%%IN]
        vpaddq          %%ZTMP1, %%ZTMP2, [%%IN + 64]
        vmovdqa64       [%%IN], %%ZTMP0
        vmovdqa64       [%%IN + 64], %%ZTMP1
%if %%CBC_MAC == 0 ;; skip out pointer update for CBC_MAC
        vpaddq          %%ZTMP0, %%ZTMP2, [%%OUT]
        vpaddq          %%ZTMP1, %%ZTMP2, [%%OUT + 64]
        vmovdqa64       [%%OUT], %%ZTMP0
        vmovdqa64       [%%OUT + 64], %%ZTMP1
%endif ;; !CBC_MAC

%%encrypt_16_done:
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ENCRYPT_16_FINAL Encodes final blocks (less than 4) across 16 lanes
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro ENCRYPT_16_FINAL 32
%define %%ZIV00_03      %1  ;; [in] lane 0-3 IVs
%define %%ZIV04_07      %2  ;; [in] lane 4-7 IVs
%define %%ZIV08_11      %3  ;; [in] lane 8-11 IVs
%define %%ZIV12_15      %4  ;; [in] lane 12-15 IVs
%define %%NROUNDS       %5  ;; [in] Number of AES rounds; numerical value
%define %%IDX           %6  ;; [clobbered] GP reg to maintain idx
%define %%B0L00_03      %7  ;; [clobbered] tmp ZMM register
%define %%B0L04_07      %8  ;; [clobbered] tmp ZMM register
%define %%B0L08_11      %9  ;; [clobbered] tmp ZMM register
%define %%B0L12_15      %10 ;; [clobbered] tmp ZMM register
%define %%B1L00_03      %11 ;; [clobbered] tmp ZMM register
%define %%B1L04_07      %12 ;; [clobbered] tmp ZMM register
%define %%B1L08_11      %13 ;; [clobbered] tmp ZMM register
%define %%B1L12_15      %14 ;; [clobbered] tmp ZMM register
%define %%B2L00_03      %15 ;; [clobbered] tmp ZMM register
%define %%B2L04_07      %16 ;; [clobbered] tmp ZMM register
%define %%B2L08_11      %17 ;; [clobbered] tmp ZMM register
%define %%B2L12_15      %18 ;; [clobbered] tmp ZMM register
%define %%B3L00_03      %19 ;; [clobbered] tmp ZMM register
%define %%B3L04_07      %20 ;; [clobbered] tmp ZMM register
%define %%B3L08_11      %21 ;; [clobbered] tmp ZMM register
%define %%B3L12_15      %22 ;; [clobbered] tmp ZMM register
%define %%ZTMP0         %23 ;; [clobbered] tmp ZMM register
%define %%ZTMP1         %24 ;; [clobbered] tmp ZMM register
%define %%ZTMP2         %25 ;; [clobbered] tmp ZMM register
%define %%ZTMP3         %26 ;; [clobbered] tmp ZMM register
%define %%TMP0          %27 ;; [clobbered] tmp GP register
%define %%TMP1          %28 ;; [clobbered] tmp GP register
%define %%TMP2          %29 ;; [clobbered] tmp GP register
%define %%TMP3          %30 ;; [clobbered] tmp GP register
%define %%NUM_BLKS      %31 ;; [in] number of blocks (numerical value)
%define %%CBC_MAC       %32 ;; CBC_MAC flag

%define %%IN    ARG + _aesarg_in
%define %%OUT   ARG + _aesarg_out
%define %%KP    ARG + _aesarg_key_tab
%define K00_03_OFFSET 0
%define K04_07_OFFSET 64
%define K08_11_OFFSET 128
%define K12_15_OFFSET 192

%if %%NUM_BLKS == 1
        mov             %%TMP0, 0x0000_0000_0000_ffff
        kmovq           k1, %%TMP0
%elif %%NUM_BLKS == 2
        mov             %%TMP0, 0x0000_0000_ffff_ffff
        kmovq           k1, %%TMP0
%elif %%NUM_BLKS == 3
        mov             %%TMP0, 0x0000_ffff_ffff_ffff
        kmovq           k1, %%TMP0
%endif
        xor             %%IDX, %%IDX

        ;; load 4 plaintext blocks for lanes 0-3
        LOAD_STORE_x4 0, 1, 2, 3, %%IN, %%IDX, %%B0L00_03, %%B1L00_03, \
                      %%B2L00_03, %%B3L00_03, %%TMP0, %%TMP1, %%TMP2, \
                      %%TMP3, LOAD, k1

        TRANSPOSE_4x4 %%B0L00_03, %%B1L00_03, %%B2L00_03, %%B3L00_03, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        ;; load 4 plaintext blocks for lanes 4-7
        LOAD_STORE_x4 4, 5, 6, 7, %%IN, %%IDX, %%B0L04_07, %%B1L04_07, \
                      %%B2L04_07, %%B3L04_07, %%TMP0, %%TMP1, %%TMP2, \
                      %%TMP3, LOAD, k1

        TRANSPOSE_4x4 %%B0L04_07, %%B1L04_07, %%B2L04_07, %%B3L04_07, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        ;; load 4 plaintext blocks for lanes 8-11
        LOAD_STORE_x4 8, 9, 10, 11, %%IN, %%IDX, %%B0L08_11, %%B1L08_11, \
                      %%B2L08_11, %%B3L08_11, %%TMP0, %%TMP1, %%TMP2, \
                      %%TMP3, LOAD, k1

        TRANSPOSE_4x4 %%B0L08_11, %%B1L08_11, %%B2L08_11, %%B3L08_11, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        ;; load 4 plaintext blocks for lanes 12-15
        LOAD_STORE_x4 12, 13, 14, 15, %%IN, %%IDX, %%B0L12_15, %%B1L12_15, \
                      %%B2L12_15, %%B3L12_15, %%TMP0, %%TMP1, %%TMP2, \
                      %%TMP3, LOAD, k1

        TRANSPOSE_4x4 %%B0L12_15, %%B1L12_15, %%B2L12_15, %%B3L12_15, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        ;; xor plaintext block with IV and round zero key
        vpternlogq      %%B0L00_03, %%ZIV00_03, [%%KP + K00_03_OFFSET], 0x96
        vpternlogq      %%B0L04_07, %%ZIV04_07, [%%KP + K04_07_OFFSET], 0x96
        vpternlogq      %%B0L08_11, %%ZIV08_11, [%%KP + K08_11_OFFSET], 0x96
        vpternlogq      %%B0L12_15, %%ZIV12_15, [%%KP + K12_15_OFFSET], 0x96

        ;; encrypt block 0 lanes
        AESENC_ROUNDS_x16 %%B0L00_03, %%B0L04_07, %%B0L08_11, %%B0L12_15, %%NROUNDS

%if %%NUM_BLKS == 1
        ;; store last cipher block
        vmovdqa64       %%ZIV00_03, %%B0L00_03
        vmovdqa64       %%ZIV04_07, %%B0L04_07
        vmovdqa64       %%ZIV08_11, %%B0L08_11
        vmovdqa64       %%ZIV12_15, %%B0L12_15
%endif

%if %%NUM_BLKS >= 2
        ;; xor plaintext block with last cipher block and round zero key
        vpternlogq      %%B1L00_03, %%B0L00_03, [%%KP + K00_03_OFFSET], 0x96
        vpternlogq      %%B1L04_07, %%B0L04_07, [%%KP + K04_07_OFFSET], 0x96
        vpternlogq      %%B1L08_11, %%B0L08_11, [%%KP + K08_11_OFFSET], 0x96
        vpternlogq      %%B1L12_15, %%B0L12_15, [%%KP + K12_15_OFFSET], 0x96

        ;; encrypt block 1 lanes
        AESENC_ROUNDS_x16 %%B1L00_03, %%B1L04_07, %%B1L08_11, %%B1L12_15, %%NROUNDS
%endif
%if %%NUM_BLKS == 2
        ;; store last cipher block
        vmovdqa64       %%ZIV00_03, %%B1L00_03
        vmovdqa64       %%ZIV04_07, %%B1L04_07
        vmovdqa64       %%ZIV08_11, %%B1L08_11
        vmovdqa64       %%ZIV12_15, %%B1L12_15
%endif

%if %%NUM_BLKS >= 3
        ;; xor plaintext block with last cipher block and round zero key
        vpternlogq      %%B2L00_03, %%B1L00_03, [%%KP + K00_03_OFFSET], 0x96
        vpternlogq      %%B2L04_07, %%B1L04_07, [%%KP + K04_07_OFFSET], 0x96
        vpternlogq      %%B2L08_11, %%B1L08_11, [%%KP + K08_11_OFFSET], 0x96
        vpternlogq      %%B2L12_15, %%B1L12_15, [%%KP + K12_15_OFFSET], 0x96

        ;; encrypt block 2 lanes
        AESENC_ROUNDS_x16 %%B2L00_03, %%B2L04_07, %%B2L08_11, %%B2L12_15, %%NROUNDS
%endif
%if %%NUM_BLKS == 3
        ;; store last cipher block
        vmovdqa64       %%ZIV00_03, %%B2L00_03
        vmovdqa64       %%ZIV04_07, %%B2L04_07
        vmovdqa64       %%ZIV08_11, %%B2L08_11
        vmovdqa64       %%ZIV12_15, %%B2L12_15
%endif
        ;; Don't write back ciphertext for CBC-MAC
%if %%CBC_MAC == 0
        ;; write back cipher text for lanes 0-3
        TRANSPOSE_4x4 %%B0L00_03, %%B1L00_03, %%B2L00_03, %%B3L00_03, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        LOAD_STORE_x4 0, 1, 2, 3, %%OUT, %%IDX, %%B0L00_03, %%B1L00_03, \
                      %%B2L00_03, %%B3L00_03, %%TMP0, %%TMP1, %%TMP2, \
                      %%TMP3, STORE, k1

        ;; write back cipher text for lanes 4-7
        TRANSPOSE_4x4 %%B0L04_07, %%B1L04_07, %%B2L04_07, %%B3L04_07, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        LOAD_STORE_x4 4, 5, 6, 7, %%OUT, %%IDX, %%B0L04_07, %%B1L04_07, \
                      %%B2L04_07, %%B3L04_07, %%TMP0, %%TMP1, %%TMP2, \
                      %%TMP3, STORE, k1

        ;; write back cipher text for lanes 8-11
        TRANSPOSE_4x4 %%B0L08_11, %%B1L08_11, %%B2L08_11, %%B3L08_11, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        LOAD_STORE_x4 8, 9, 10, 11, %%OUT, %%IDX, %%B0L08_11, %%B1L08_11, \
                      %%B2L08_11, %%B3L08_11, %%TMP0, %%TMP1, %%TMP2, \
                      %%TMP3, STORE, k1

        ;; write back cipher text for lanes 12-15
        TRANSPOSE_4x4 %%B0L12_15, %%B1L12_15, %%B2L12_15, %%B3L12_15, \
                      %%ZTMP0, %%ZTMP1, %%ZTMP2, %%ZTMP3

        LOAD_STORE_x4 12, 13, 14, 15, %%OUT, %%IDX, %%B0L12_15, %%B1L12_15, \
                      %%B2L12_15, %%B3L12_15, %%TMP0, %%TMP1, %%TMP2, \
                      %%TMP3, STORE, k1
%endif ;; !CBC_MAC

        ;; update in/out pointers
        mov             %%IDX, %%NUM_BLKS
        shl             %%IDX, 4
        vpbroadcastq    %%ZTMP2, %%IDX
        vpaddq          %%ZTMP0, %%ZTMP2, [%%IN]
        vpaddq          %%ZTMP1, %%ZTMP2, [%%IN + 64]
        vmovdqa64       [%%IN], %%ZTMP0
        vmovdqa64       [%%IN + 64], %%ZTMP1
%if %%CBC_MAC == 0 ;; skip out pointer update for CBC-MAC
        vpaddq          %%ZTMP0, %%ZTMP2, [%%OUT]
        vpaddq          %%ZTMP1, %%ZTMP2, [%%OUT + 64]
        vmovdqa64       [%%OUT], %%ZTMP0
        vmovdqa64       [%%OUT + 64], %%ZTMP1
%endif ;; !CBC_MAC
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; CBC_ENC Encodes given data.
; Requires the input data be at least 1 block (16 bytes) long
; Input: Number of AES rounds
;
; First encrypts block up to multiple of 4
; Then encrypts final blocks (less than 4)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro CBC_ENC 2
%define %%ROUNDS        %1
%define %%CBC_MAC       %2

        ;; load transpose tables
        vmovdqa64       TAB_A0B0A1B1, [rel A0B0A1B1]
        vmovdqa64       TAB_A2B2A3B3, [rel A2B2A3B3]

        ;; load IV's per lane
        vmovdqa64       ZIV00_03, [ARG + _aesarg_IV + 16*0]
        vmovdqa64       ZIV04_07, [ARG + _aesarg_IV + 16*4]
        vmovdqa64       ZIV08_11, [ARG + _aesarg_IV + 16*8]
        vmovdqa64       ZIV12_15, [ARG + _aesarg_IV + 16*12]

        ENCRYPT_16_PARALLEL ZIV00_03, ZIV04_07, ZIV08_11, ZIV12_15, \
                            LEN, %%ROUNDS, IA12, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, \
                            ZT6, ZT7, ZT8, ZT9, ZT10, ZT11, ZT12, ZT13, ZT14, \
                            ZT15, ZT16, ZT17, ZT18, ZT19, IA2, IA3, IA4, IA5, \
                            %%CBC_MAC

        ;; get num remaining blocks
        shr             LEN, 4
        and             LEN, 3
        je              %%_cbc_enc_done
        cmp             LEN, 1
        je              %%_final_blocks_1
        cmp             LEN, 2
        je              %%_final_blocks_2

%%_final_blocks_3:
        ENCRYPT_16_FINAL ZIV00_03, ZIV04_07, ZIV08_11, ZIV12_15, \
                         %%ROUNDS, IA12, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7,  \
                         ZT8, ZT9, ZT10, ZT11, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, \
                         ZT18, ZT19, IA2, IA3, IA4, IA5, 3, %%CBC_MAC
        jmp             %%_cbc_enc_done
%%_final_blocks_1:
        ENCRYPT_16_FINAL ZIV00_03, ZIV04_07, ZIV08_11, ZIV12_15, \
                         %%ROUNDS, IA12, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7,  \
                         ZT8, ZT9, ZT10, ZT11, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, \
                         ZT18, ZT19, IA2, IA3, IA4, IA5, 1, %%CBC_MAC
        jmp             %%_cbc_enc_done
%%_final_blocks_2:
        ENCRYPT_16_FINAL ZIV00_03, ZIV04_07, ZIV08_11, ZIV12_15, \
                         %%ROUNDS, IA12, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7,  \
                         ZT8, ZT9, ZT10, ZT11, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, \
                         ZT18, ZT19, IA2, IA3, IA4, IA5, 2, %%CBC_MAC
%%_cbc_enc_done:
        ;; store IV's per lane
        vmovdqa64       [ARG + _aesarg_IV + 16*0],  ZIV00_03
        vmovdqa64       [ARG + _aesarg_IV + 16*4],  ZIV04_07
        vmovdqa64       [ARG + _aesarg_IV + 16*8],  ZIV08_11
        vmovdqa64       [ARG + _aesarg_IV + 16*12], ZIV12_15
%endmacro


section .data
;;;;;;;;;;;;;;;;;;
; Transpose tables
;;;;;;;;;;;;;;;;;;
default rel

align 64
A0B0A1B1:
        dq     0x0, 0x1, 0x8, 0x9, 0x2, 0x3, 0xa, 0xb

align 64
A2B2A3B3:
        dq     0x4, 0x5, 0xc, 0xd, 0x6, 0x7, 0xe, 0xf


section .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes_cbc_enc_128_vaes_avx512(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cbc_enc_128_vaes_avx512,function,internal)
aes_cbc_enc_128_vaes_avx512:
        FUNC_SAVE
        CBC_ENC 9, 0
        FUNC_RESTORE

%ifdef SAFE_DATA
	clear_all_zmms_asm
%endif ;; SAFE_DATA

        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes_cbc_enc_192_vaes_avx512(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cbc_enc_192_vaes_avx512,function,internal)
aes_cbc_enc_192_vaes_avx512:
        FUNC_SAVE
        CBC_ENC 11, 0
        FUNC_RESTORE

%ifdef SAFE_DATA
	clear_all_zmms_asm
%endif ;; SAFE_DATA

        ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes_cbc_enc_256_vaes_avx512(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes_cbc_enc_256_vaes_avx512,function,internal)
aes_cbc_enc_256_vaes_avx512:
        FUNC_SAVE
        CBC_ENC 13, 0
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;  void aes128_cbc_mac_vaes_avx512(AES_ARGS *args, uint64_t len_in_bytes);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(aes128_cbc_mac_vaes_avx512,function,internal)
aes128_cbc_mac_vaes_avx512:
        FUNC_SAVE
        CBC_ENC 9, 1
        FUNC_RESTORE

%ifdef SAFE_DATA
	clear_all_zmms_asm
%endif ;; SAFE_DATA

        ret

%ifdef LINUX
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
