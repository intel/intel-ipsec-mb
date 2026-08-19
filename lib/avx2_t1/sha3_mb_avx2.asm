; Copyright (c) 2026, Intel Corporation
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are met:
;
;   * Redistributions of source code must retain the above copyright notice,
;     this list of conditions and the following disclaimer.
;   * Redistributions in binary form must reproduce the above copyright notice,
;     this list of conditions and the following disclaimer in the documentation
;     and/or other materials provided with the distribution.
;   * Neither the name of Intel Corporation nor the names of its contributors
;     may be used to endorse or promote products derived from this software
;     without specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

; AVX2 SHA3 multi-buffer (4-lane) OOO submit/flush.
;
; State: kstate[W*32 + L*8] = word W, lane L  (W=0..24, L=0..3)
;   Interleaved layout: the 4 lane values for each Keccak word W are stored
;   contiguously in one 32-byte YMM-width slot, enabling single vpxor/vmovdqu
;   to operate on all 4 lanes simultaneously.
; Absorb: XOR 4 lanes into interleaved kstate, call keccak_f1600_x4_avx2.
; SHAKE squeeze: copy completing lane to 800B temp buffer, call x4.
;
; Register aliases (SHA3_OOO_SUBMIT_FLUSH_FN):
%define state           rbx     ; MB_MGR_SHA3_OOO* (callee-saved)
%define lane            r12     ; flush: first occupied lane index
%define min_idx         r13     ; index of lane with minimum length
%define num_blocks      r14     ; number of full rate-blocks to absorb
%define remaining       r15     ; bytes left after full blocks
%define min_len         rbp     ; minimum message length across active lanes
%define job             rsi     ; IMB_JOB*
%define data0           r8      ; data pointer lane 0
%define data1           r9      ; data pointer lane 1
%define data2           r10     ; data pointer lane 2
%define data3           r11     ; data pointer lane 3
; Squeeze-phase aliases (reuse callee-saved slots no longer needed after absorb)
%define outlen          rbp     ; output length (reuses min_len slot)
%define sq_out_ptr      r14     ; stable output pointer (reuses num_blocks)
%define lane_idx        r15     ; completing lane index (reuses remaining)
%define copy_off        r13     ; byte copy offset in tail (reuses min_idx)
%define buf_ptr         rsi     ; walking word pointer in squeeze tail (reuses job slot)

default rel

%include "include/sha3_common.inc"
%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/align_avx.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"

; arg1..arg10 come from sha3_common.inc.

; SHAKE (IS_XOF=1) Linux frame layout (after dynamic 32B alignment of rsp):
; SHA3  (IS_XOF=0) Linux frame: sub rsp,8 only - re-aligns to 16B for calls.
%ifdef LINUX
%define SHA3_LINUX_SCRATCH_SZ   800
%define SHA3_LINUX_SAVED_RSP    SHA3_LINUX_SCRATCH_SZ
%define SHA3_LINUX_FRAME_ALLOC  (SHA3_LINUX_SCRATCH_SZ + 8 + 31)  ; sub before and rsp,-32
%endif

%ifidn __OUTPUT_FORMAT__, win64
; SHAKE (IS_XOF=1) Win64 frame layout (after dynamic 32B alignment of rsp):
;   [rsp +   0 ..  799]  interleaved squeeze buffer (25×32B, 32B-aligned)
;   [rsp + 800 ..  959]  xmm6-xmm15 saves (10 × 16 B)   (WIN_XMM_OFF   = 800)
;   [rsp + 960]          rdi (8B)                         (WIN_RDI_OFF   = 960)
;   [rsp + 968]          rsi (8B)                         (WIN_RSI_OFF   = 968)
;   [rsp + 976 ..  983]  saved pre-alignment RSP (8B)     (WIN_SAVED_RSP = 976)
%define WIN_SCRATCH_SZ      800
%define WIN_XMM_SAVE_SZ     (10 * 16)           ; 160  xmm6..xmm15
%define WIN_XMM_OFF         WIN_SCRATCH_SZ
%define WIN_RDI_OFF        (WIN_XMM_OFF + WIN_XMM_SAVE_SZ)
%define WIN_RSI_OFF        (WIN_RDI_OFF + 8)
%define WIN_SAVED_RSP      (WIN_RSI_OFF + 8)    ; saved pre-alignment RSP (8B)
%define WIN_FRAME_ALLOC    (WIN_SAVED_RSP + 8 + 31) ; sub before and rsp,-32
; SHA3  (IS_XOF=0) Win64 frame layout (fixed sub, no scratch):
;   [rsp +   0 ..  159]  xmm6-xmm15 saves (10 × 16 B)   (WIN_SHA3_XMM_OFF =   0)
;   [rsp + 160 ..  167]  rdi (8B)                         (WIN_SHA3_RDI_OFF = 160)
;   [rsp + 168 ..  175]  rsi (8B)                         (WIN_SHA3_RSI_OFF = 168)
;   [rsp + 176 ..  183]  8B alignment pad (total 184B ≡ 8 mod 16 -> rsp 16B-aligned)
%define WIN_SHA3_XMM_OFF    0
%define WIN_SHA3_RDI_OFF   (WIN_SHA3_XMM_OFF + WIN_XMM_SAVE_SZ)
%define WIN_SHA3_RSI_OFF   (WIN_SHA3_RDI_OFF + 8)
%define WIN_SHA3_FRAME_SIZE (WIN_SHA3_RSI_OFF + 8 + 8)
%endif

; AVX2 64-bit lane rotate-left by immediate.
; vpshufb for rot=8/56 (1 insn); shift-or otherwise (3 insns, tmp in %%YTMP).
%macro VROL64 4
%define %%DST  %1       ; [out] destination YMM register
%define %%SRC  %2       ; [in]  source YMM register
%define %%IMM  %3       ; [in]  rotation amount (compile-time immediate)
%define %%YTMP %4       ; [clobbered] temporary YMM register (must not equal %%DST or %%SRC)
%if %%IMM == 8
        vpshufb %%DST, %%SRC, [rel SHA3MB_RHO8_SHUF]
%elif %%IMM == 56
        vpshufb %%DST, %%SRC, [rel SHA3MB_RHO56_SHUF]
%else
        vpsllq  %%DST,  %%SRC, %%IMM
        vpsrlq  %%YTMP, %%SRC, (64 - %%IMM)
        vpor    %%DST,  %%DST, %%YTMP
%endif
%endmacro

; ============================================================
; KF_ROUND - one Keccak round.
;
; Chi order [3,2,4,1,0]: row 3 ready at chain step 16, row 0 at step 25.
; pos-0 theta: B[0] kept in ymm15, no kstate store+reload (-2 mem ops/round).
; Chi row 0 uses ymm15 as B[0]_orig directly.
; The rho+pi chain folds each kstate load into the vpxor with D[x] (-24 insns
; per round) and produces B[15..19] straight into ymm5..ymm9 -- C[] is dead
; from the end of theta until chi row 3 reloads it, so those five words skip
; both the store here and the reload in chi (-5 loads, -5 stores per round).
;
; In/out: ymm5..ymm9 = C[0..4] (column parity, carried across rounds); dead
;         between theta and chi row 3, where they carry B[15..19] instead
; Clobbers: ymm0..ymm4, ymm10..ymm15; %%RCP advanced by 8
; ============================================================
%macro KF_ROUND 2
%xdefine %%KS  %1       ; [in]       interleaved kstate base address
%xdefine %%RCP %2       ; [in/out]   round-constant pointer (advanced by 8)

        ; theta: D[x] = C[x-1] ^ ROL(C[x+1],1)
        VROL64 ymm10, ymm6, 1, ymm1
        vpxor   ymm10, ymm10, ymm9              ; D[0] = ROL(C[1],1) ^ C[4]
        VROL64 ymm11, ymm7, 1, ymm1
        vpxor   ymm11, ymm11, ymm5              ; D[1] = ROL(C[2],1) ^ C[0]
        VROL64 ymm12, ymm8, 1, ymm1
        vpxor   ymm12, ymm12, ymm6              ; D[2] = ROL(C[3],1) ^ C[1]
        VROL64 ymm13, ymm9, 1, ymm1
        vpxor   ymm13, ymm13, ymm7              ; D[3] = ROL(C[4],1) ^ C[2]
        VROL64 ymm14, ymm5, 1, ymm1
        vpxor   ymm14, ymm14, ymm8              ; D[4] = ROL(C[0],1) ^ C[3]

        ; pos-0: B[0] = A[0]^D[0] in ymm15 (no store)
        vpxor   ymm15, ymm10, [%%KS + 0*32]

        ; rho+pi chain  (D[0..4]=ymm10..14, carry=ymm2)
        ; The kstate load is folded into the vpxor with D[x]; the store of
        ; the previous step's product goes to [%%KS + src*32] because
        ; dst(step-1) == src(step).  Steps producing B[15..19] target
        ; ymm5..ymm9 and the following step's store is dropped.

        ; src=1 (D[1]=ymm11, rho=1 -> dst=10)
        vpxor   ymm0,  ymm11, [%%KS + 1*32]
        VROL64 ymm2, ymm0, 1, ymm1

        ; src=10 (D[0]=ymm10, rho=3 -> dst=7)
        vpxor   ymm0,  ymm10, [%%KS +10*32]
        vmovdqu [%%KS +10*32], ymm2
        VROL64 ymm2, ymm0, 3, ymm1

        ; src=7 (D[2]=ymm12, rho=6 -> dst=11)
        vpxor   ymm0,  ymm12, [%%KS + 7*32]
        vmovdqu [%%KS + 7*32], ymm2
        VROL64 ymm2, ymm0, 6, ymm1

        ; src=11 (D[1]=ymm11, rho=10 -> dst=17)
        vpxor   ymm0,  ymm11, [%%KS +11*32]
        vmovdqu [%%KS +11*32], ymm2
        VROL64 ymm7, ymm0, 10, ymm1

        ; src=17 (D[2]=ymm12, rho=15 -> dst=18)
        vpxor   ymm0,  ymm12, [%%KS +17*32]
        VROL64 ymm8, ymm0, 15, ymm1

        ; src=18 (D[3]=ymm13, rho=21 -> dst=3)
        vpxor   ymm0,  ymm13, [%%KS +18*32]
        VROL64 ymm2, ymm0, 21, ymm1

        ; src=3 (D[3]=ymm13, rho=28 -> dst=5)
        vpxor   ymm0,  ymm13, [%%KS + 3*32]
        vmovdqu [%%KS + 3*32], ymm2
        VROL64 ymm2, ymm0, 28, ymm1

        ; src=5 (D[0]=ymm10, rho=36 -> dst=16)
        vpxor   ymm0,  ymm10, [%%KS + 5*32]
        vmovdqu [%%KS + 5*32], ymm2
        VROL64 ymm6, ymm0, 36, ymm1

        ; src=16 (D[1]=ymm11, rho=45 -> dst=8)
        vpxor   ymm0,  ymm11, [%%KS +16*32]
        VROL64 ymm2, ymm0, 45, ymm1

        ; src=8 (D[3]=ymm13, rho=55 -> dst=21)
        vpxor   ymm0,  ymm13, [%%KS + 8*32]
        vmovdqu [%%KS + 8*32], ymm2
        VROL64 ymm2, ymm0, 55, ymm1

        ; src=21 (D[1]=ymm11, rho=2 -> dst=24)
        vpxor   ymm0,  ymm11, [%%KS +21*32]
        vmovdqu [%%KS +21*32], ymm2
        VROL64 ymm2, ymm0, 2, ymm1

        ; src=24 (D[4]=ymm14, rho=14 -> dst=4)
        vpxor   ymm0,  ymm14, [%%KS +24*32]
        vmovdqu [%%KS +24*32], ymm2
        VROL64 ymm2, ymm0, 14, ymm1

        ; src=4 (D[4]=ymm14, rho=27 -> dst=15)
        vpxor   ymm0,  ymm14, [%%KS + 4*32]
        vmovdqu [%%KS + 4*32], ymm2
        VROL64 ymm5, ymm0, 27, ymm1

        ; src=15 (D[0]=ymm10, rho=41 -> dst=23)
        vpxor   ymm0,  ymm10, [%%KS +15*32]
        VROL64 ymm2, ymm0, 41, ymm1

        ; src=23 (D[3]=ymm13, rho=56 -> dst=19)
        vpxor   ymm0,  ymm13, [%%KS +23*32]
        vmovdqu [%%KS +23*32], ymm2
        VROL64 ymm9, ymm0, 56, ymm1

        ; src=19 (D[4]=ymm14, rho=8 -> dst=13)
        vpxor   ymm0,  ymm14, [%%KS +19*32]
        VROL64 ymm2, ymm0, 8, ymm1

        ; src=13 (D[3]=ymm13, rho=25 -> dst=12)
        vpxor   ymm0,  ymm13, [%%KS +13*32]
        vmovdqu [%%KS +13*32], ymm2
        VROL64 ymm2, ymm0, 25, ymm1

        ; src=12 (D[2]=ymm12, rho=43 -> dst=2)
        vpxor   ymm0,  ymm12, [%%KS +12*32]
        vmovdqu [%%KS +12*32], ymm2
        VROL64 ymm2, ymm0, 43, ymm1

        ; src=2 (D[2]=ymm12, rho=62 -> dst=20)
        vpxor   ymm0,  ymm12, [%%KS + 2*32]
        vmovdqu [%%KS + 2*32], ymm2
        VROL64 ymm2, ymm0, 62, ymm1

        ; src=20 (D[0]=ymm10, rho=18 -> dst=14)
        vpxor   ymm0,  ymm10, [%%KS +20*32]
        vmovdqu [%%KS +20*32], ymm2
        VROL64 ymm2, ymm0, 18, ymm1

        ; src=14 (D[4]=ymm14, rho=39 -> dst=22)
        vpxor   ymm0,  ymm14, [%%KS +14*32]
        vmovdqu [%%KS +14*32], ymm2
        VROL64 ymm2, ymm0, 39, ymm1

        ; src=22 (D[2]=ymm12, rho=61 -> dst=9)
        vpxor   ymm0,  ymm12, [%%KS +22*32]
        vmovdqu [%%KS +22*32], ymm2
        VROL64 ymm2, ymm0, 61, ymm1

        ; src=9 (D[4]=ymm14, rho=20 -> dst=6)
        vpxor   ymm0,  ymm14, [%%KS + 9*32]
        vmovdqu [%%KS + 9*32], ymm2
        VROL64 ymm2, ymm0, 20, ymm1

        ; src=6 (D[1]=ymm11, rho=44 -> dst=1)  closes cycle
        vpxor   ymm0,  ymm11, [%%KS + 6*32]
        vmovdqu [%%KS + 6*32], ymm2
        VROL64 ymm2, ymm0, 44, ymm1
        vmovdqu [%%KS + 1*32], ymm2            ; B[1] = close cycle

        ; chi [3,2,4,1,0] + C[] accumulation
        ; row 3 first (ready earliest in rho+pi chain)
        ; B[15..19] are already in ymm5..ymm9 from the chain - no reload, and
        ; kstate words 15..19 still hold the previous round's A[] until the
        ; stores below (nothing reads them in between).
        vmovdqa ymm10, ymm5                     ; save B[15] for chi wrap
        vmovdqa ymm11, ymm6                     ; save B[16] for chi wrap
        vpandn  ymm12, ymm6,  ymm7
        vpxor   ymm5,  ymm5,  ymm12
        vpandn  ymm12, ymm7,  ymm8
        vpxor   ymm6,  ymm6,  ymm12
        vpandn  ymm12, ymm8,  ymm9
        vpxor   ymm7,  ymm7,  ymm12
        vpandn  ymm12, ymm9,  ymm10
        vpxor   ymm8,  ymm8,  ymm12
        vpandn  ymm12, ymm10, ymm11
        vpxor   ymm9,  ymm9,  ymm12
        vmovdqu [%%KS +15*32], ymm5
        vmovdqu [%%KS +16*32], ymm6
        vmovdqu [%%KS +17*32], ymm7
        vmovdqu [%%KS +18*32], ymm8
        vmovdqu [%%KS +19*32], ymm9

        ; row 2
        vmovdqu ymm0,  [%%KS +10*32]
        vmovdqu ymm1,  [%%KS +11*32]
        vmovdqu ymm2,  [%%KS +12*32]
        vmovdqu ymm3,  [%%KS +13*32]
        vmovdqu ymm4,  [%%KS +14*32]
        vmovdqa ymm10, ymm0
        vmovdqa ymm11, ymm1
        vpandn  ymm12, ymm1,  ymm2
        vpxor   ymm0,  ymm0,  ymm12
        vpandn  ymm12, ymm2,  ymm3
        vpxor   ymm1,  ymm1,  ymm12
        vpandn  ymm12, ymm3,  ymm4
        vpxor   ymm2,  ymm2,  ymm12
        vpandn  ymm12, ymm4,  ymm10
        vpxor   ymm3,  ymm3,  ymm12
        vpandn  ymm12, ymm10, ymm11
        vpxor   ymm4,  ymm4,  ymm12
        vpxor   ymm5,  ymm5,  ymm0
        vpxor   ymm6,  ymm6,  ymm1
        vpxor   ymm7,  ymm7,  ymm2
        vpxor   ymm8,  ymm8,  ymm3
        vpxor   ymm9,  ymm9,  ymm4
        vmovdqu [%%KS +10*32], ymm0
        vmovdqu [%%KS +11*32], ymm1
        vmovdqu [%%KS +12*32], ymm2
        vmovdqu [%%KS +13*32], ymm3
        vmovdqu [%%KS +14*32], ymm4

        ; row 4
        vmovdqu ymm0,  [%%KS +20*32]
        vmovdqu ymm1,  [%%KS +21*32]
        vmovdqu ymm2,  [%%KS +22*32]
        vmovdqu ymm3,  [%%KS +23*32]
        vmovdqu ymm4,  [%%KS +24*32]
        vmovdqa ymm10, ymm0
        vmovdqa ymm11, ymm1
        vpandn  ymm12, ymm1,  ymm2
        vpxor   ymm0,  ymm0,  ymm12
        vpandn  ymm12, ymm2,  ymm3
        vpxor   ymm1,  ymm1,  ymm12
        vpandn  ymm12, ymm3,  ymm4
        vpxor   ymm2,  ymm2,  ymm12
        vpandn  ymm12, ymm4,  ymm10
        vpxor   ymm3,  ymm3,  ymm12
        vpandn  ymm12, ymm10, ymm11
        vpxor   ymm4,  ymm4,  ymm12
        vpxor   ymm5,  ymm5,  ymm0
        vpxor   ymm6,  ymm6,  ymm1
        vpxor   ymm7,  ymm7,  ymm2
        vpxor   ymm8,  ymm8,  ymm3
        vpxor   ymm9,  ymm9,  ymm4
        vmovdqu [%%KS +20*32], ymm0
        vmovdqu [%%KS +21*32], ymm1
        vmovdqu [%%KS +22*32], ymm2
        vmovdqu [%%KS +23*32], ymm3
        vmovdqu [%%KS +24*32], ymm4

        ; row 1
        vmovdqu ymm0,  [%%KS + 5*32]
        vmovdqu ymm1,  [%%KS + 6*32]
        vmovdqu ymm2,  [%%KS + 7*32]
        vmovdqu ymm3,  [%%KS + 8*32]
        vmovdqu ymm4,  [%%KS + 9*32]
        vmovdqa ymm10, ymm0
        vmovdqa ymm11, ymm1
        vpandn  ymm12, ymm1,  ymm2
        vpxor   ymm0,  ymm0,  ymm12
        vpandn  ymm12, ymm2,  ymm3
        vpxor   ymm1,  ymm1,  ymm12
        vpandn  ymm12, ymm3,  ymm4
        vpxor   ymm2,  ymm2,  ymm12
        vpandn  ymm12, ymm4,  ymm10
        vpxor   ymm3,  ymm3,  ymm12
        vpandn  ymm12, ymm10, ymm11
        vpxor   ymm4,  ymm4,  ymm12
        vpxor   ymm5,  ymm5,  ymm0
        vpxor   ymm6,  ymm6,  ymm1
        vpxor   ymm7,  ymm7,  ymm2
        vpxor   ymm8,  ymm8,  ymm3
        vpxor   ymm9,  ymm9,  ymm4
        vmovdqu [%%KS + 5*32], ymm0
        vmovdqu [%%KS + 6*32], ymm1
        vmovdqu [%%KS + 7*32], ymm2
        vmovdqu [%%KS + 8*32], ymm3
        vmovdqu [%%KS + 9*32], ymm4

        ; row 0 last: B[0]=ymm15 (no load), accumulate C[], iota
        vmovdqa ymm0,  ymm15                    ; B[0] (reg copy, no load)
        vmovdqu ymm1,  [%%KS + 1*32]
        vmovdqu ymm2,  [%%KS + 2*32]
        vmovdqu ymm3,  [%%KS + 3*32]
        vmovdqu ymm4,  [%%KS + 4*32]
        vmovdqa ymm11, ymm1                     ; save B[1]_orig for pos 4
        vpandn  ymm12, ymm1,  ymm2              ; ~B[1] & B[2]
        vpxor   ymm0,  ymm0,  ymm12             ; chi A[0]
        vpandn  ymm12, ymm2,  ymm3              ; ~B[2] & B[3]
        vpxor   ymm1,  ymm1,  ymm12             ; chi A[1]
        vpandn  ymm12, ymm3,  ymm4              ; ~B[3] & B[4]
        vpxor   ymm2,  ymm2,  ymm12             ; chi A[2]
        vpandn  ymm12, ymm4,  ymm15             ; ~B[4] & B[0]_orig (ymm15)
        vpxor   ymm3,  ymm3,  ymm12             ; chi A[3]
        vpandn  ymm12, ymm15, ymm11             ; ~B[0]_orig & B[1]_orig
        vpxor   ymm4,  ymm4,  ymm12             ; chi A[4]
        ; Iota: broadcast RC to all 4 lanes, XOR into word 0
        vpbroadcastq ymm12, [%%RCP]
        vpxor   ymm0,  ymm0,  ymm12
        add     %%RCP, 8
        vpxor   ymm5,  ymm5,  ymm0
        vpxor   ymm6,  ymm6,  ymm1
        vpxor   ymm7,  ymm7,  ymm2
        vpxor   ymm8,  ymm8,  ymm3
        vpxor   ymm9,  ymm9,  ymm4
        vmovdqu [%%KS + 0*32], ymm0
        vmovdqu [%%KS + 1*32], ymm1
        vmovdqu [%%KS + 2*32], ymm2
        vmovdqu [%%KS + 3*32], ymm3
        vmovdqu [%%KS + 4*32], ymm4

%endmacro

; ============================================================
; ZERO_EXTRA_BLOCK - clear %%RATE bytes of a lane's extra_block.
; Widest-first: 32B stores, then one 16B and one 8B store as the rate requires.
; Clobbers: ymm0
; ============================================================
%macro ZERO_EXTRA_BLOCK 2
%xdefine %%EB   %1      ; [in]   address of the lane's extra_block
%xdefine %%RATE %2      ; [in]   rate in bytes (compile-time constant)

        vpxor           ymm0, ymm0, ymm0
%assign %%OFF 0
%assign %%REM %%RATE
%rep (%%RATE / 32)
        vmovdqu         [%%EB + %%OFF], ymm0
%assign %%OFF (%%OFF+32)
%assign %%REM (%%REM-32)
%endrep
%if %%REM >= 16
        vmovdqu         [%%EB + %%OFF], xmm0
%assign %%OFF (%%OFF+16)
%assign %%REM (%%REM-16)
%endif
%if %%REM >= 8
        vmovq           [%%EB + %%OFF], xmm0
%endif
%endmacro

; ============================================================
; SHA3_OOO_SUBMIT_FLUSH_FN  fn_name, rate, digest_sz, pad_byte, is_xof, is_submit
;
; Unified SHA3 + SHAKE OOO submit/flush macro.
;   digest_sz  - output bytes for fixed-output (SHA3); ignored when is_xof=1
;   pad_byte   - domain-separation byte: SHA3_MRATE_PADDING or SHAKE_MRATE_PADDING
;   is_xof     - 0 = SHA3 (fixed output, copy from kstate), 1 = SHAKE (squeeze loop)
;   is_submit  - 1 = submit path, 0 = flush path
; ============================================================

%macro SHA3_OOO_SUBMIT_FLUSH_FN 6
%xdefine %%FN      %1       ; [in]       function name symbol
%xdefine %%RATE    %2       ; [in]       rate in bytes (compile-time constant)
%xdefine %%DSIZ    %3       ; [in]       digest size in bytes (ignored when %%IS_XOF=1)
%xdefine %%PAD     %4       ; [in]       domain-separation byte
%xdefine %%IS_XOF  %5       ; [in]       1 = XOF/SHAKE squeeze, 0 = SHA3 fixed output
%xdefine %%SUB     %6       ; [in]       1 = submit path, 0 = flush path

align_function
MKGLOBAL(%%FN,function,internal)
%%FN:
        push    r15             ; remaining
        push    r14             ; num_blocks
        push    r13             ; min_idx
        push    r12             ; lane
        push    rbx             ; state
        push    rbp             ; min_len
%ifidn __OUTPUT_FORMAT__, win64
%if %%IS_XOF
        mov     r11, rsp
        sub     rsp, WIN_FRAME_ALLOC
        and     rsp, -32
        mov     [rsp + WIN_SAVED_RSP], r11
        vmovdqa [rsp + WIN_XMM_OFF +  0*16], xmm6
        vmovdqa [rsp + WIN_XMM_OFF +  1*16], xmm7
        vmovdqa [rsp + WIN_XMM_OFF +  2*16], xmm8
        vmovdqa [rsp + WIN_XMM_OFF +  3*16], xmm9
        vmovdqa [rsp + WIN_XMM_OFF +  4*16], xmm10
        vmovdqa [rsp + WIN_XMM_OFF +  5*16], xmm11
        vmovdqa [rsp + WIN_XMM_OFF +  6*16], xmm12
        vmovdqa [rsp + WIN_XMM_OFF +  7*16], xmm13
        vmovdqa [rsp + WIN_XMM_OFF +  8*16], xmm14
        vmovdqa [rsp + WIN_XMM_OFF +  9*16], xmm15
        mov     [rsp + WIN_RDI_OFF], rdi
        mov     [rsp + WIN_RSI_OFF], job
%else
        sub     rsp, WIN_SHA3_FRAME_SIZE
        vmovdqa [rsp + WIN_SHA3_XMM_OFF +  0*16], xmm6
        vmovdqa [rsp + WIN_SHA3_XMM_OFF +  1*16], xmm7
        vmovdqa [rsp + WIN_SHA3_XMM_OFF +  2*16], xmm8
        vmovdqa [rsp + WIN_SHA3_XMM_OFF +  3*16], xmm9
        vmovdqa [rsp + WIN_SHA3_XMM_OFF +  4*16], xmm10
        vmovdqa [rsp + WIN_SHA3_XMM_OFF +  5*16], xmm11
        vmovdqa [rsp + WIN_SHA3_XMM_OFF +  6*16], xmm12
        vmovdqa [rsp + WIN_SHA3_XMM_OFF +  7*16], xmm13
        vmovdqa [rsp + WIN_SHA3_XMM_OFF +  8*16], xmm14
        vmovdqa [rsp + WIN_SHA3_XMM_OFF +  9*16], xmm15
        mov     [rsp + WIN_SHA3_RDI_OFF], rdi
        mov     [rsp + WIN_SHA3_RSI_OFF], job
%endif
%else
%if %%IS_XOF
        mov     r11, rsp
        sub     rsp, SHA3_LINUX_FRAME_ALLOC
        and     rsp, -32
        mov     [rsp + SHA3_LINUX_SAVED_RSP], r11
%else
        sub     rsp, 8          ; re-align rsp to 16B for calls (rsp%16=8 after 6 pushes)
%endif
%endif
        mov     state, arg1
%ifidn __OUTPUT_FORMAT__, win64
        mov     job, arg2      ; Win64: arg2=rdx, job=rsi
%endif

%if %%SUB
        ;; --- SUBMIT: allocate free lane ---
        mov     lane, [state + _sha3_unused_lanes]
        mov     min_idx, lane
        and     min_idx, 0xF
        shr     lane, 4
        mov     [state + _sha3_unused_lanes], lane
        inc     dword [state + _sha3_num_lanes_inuse]

        mov     rax, [job + _src]
        add     rax, [job + _hash_start_src_offset_in_bytes]
        mov     [state + _sha3_args_data_ptr + min_idx*8], rax

        ;; zero lane's 25 kstate words: load each 32B slot, clear min_idx lane, store
        vpxor           ymm0, ymm0, ymm0
        vmovq           xmm1, min_idx
        vpbroadcastq    ymm1, xmm1
        vmovdqa         ymm2, [rel SHA3MB_LANE_IDX]
        vpcmpeqq        ymm1, ymm1, ymm2            ; 0xFF..FF at min_idx lane, 0 elsewhere
%assign %%W 0
%rep 25
        vmovdqu         ymm2, [state + _sha3_args_kstate + %%W*32]
        vpblendvb       ymm2, ymm2, ymm0, ymm1      ; zero the min_idx lane
        vmovdqu         [state + _sha3_args_kstate + %%W*32], ymm2
%assign %%W (%%W+1)
%endrep

        imul    rax, min_idx, _SHA3_LANE_DATA_size
        mov     [state + _sha3_ldata + rax + _sha3_job_in_lane], job
        mov     dword [state + _sha3_ldata + rax + _sha3_finalized], 0

        mov     rcx, [job + _msg_len_to_hash_in_bytes]
        mov     [state + _sha3_lens + min_idx*8], rcx

        cmp     dword [state + _sha3_num_lanes_inuse], MAX_SHA3_LANES
        jne     %%ret_null
%else
        ;; --- FLUSH: find first occupied lane (unrolled, no branches) ---
        cmp     dword [state + _sha3_num_lanes_inuse], 0
        je      %%ret_null
        mov     lane, 3
        mov     rax, 2
        cmp     qword [state + _sha3_ldata + 2*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 0
        cmovne  lane, rax
        mov     rax, 1
        cmp     qword [state + _sha3_ldata + 1*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 0
        cmovne  lane, rax
        xor     rax, rax
        cmp     qword [state + _sha3_ldata + 0*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 0
        cmovne  lane, rax
%endif

align_loop
%%do_loop:

%if %%SUB == 0
        ;; --- FLUSH: fill null lanes with live ptr / UINT64_MAX before min-find ---
        ;; Build ymm0 = job_in_lane[0..3] using AVX2 instructions only
        vmovq      xmm0, [state + _sha3_ldata + 0*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        vpinsrq    xmm0, xmm0, [state + _sha3_ldata + 1*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 1
        vmovq      xmm1, [state + _sha3_ldata + 2*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        vpinsrq    xmm1, xmm1, [state + _sha3_ldata + 3*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 1
        vinserti128 ymm0, ymm0, xmm1, 1        ; ymm0 = job_in_lane[0..3]
        vpxor      ymm1, ymm1, ymm1             ; ymm1 = 0
        vpcmpeqq   ymm2, ymm0, ymm1            ; ymm2 = null-lane mask (FF..FF where null)

        ;; Fill null data_ptr slots with live lane's ptr
        vpbroadcastq ymm1, [state + _sha3_args_data_ptr + lane*8]
        vmovdqa    ymm0, [state + _sha3_args_data_ptr]
        vpblendvb  ymm0, ymm0, ymm1, ymm2
        vmovdqa    [state + _sha3_args_data_ptr], ymm0

        ;; Fill null lens with UINT64_MAX
        vpcmpeqd   ymm1, ymm1, ymm1             ; all-ones = UINT64_MAX
        vmovdqa    ymm0, [state + _sha3_lens]
        vpblendvb  ymm0, ymm0, ymm1, ymm2
        vmovdqa    [state + _sha3_lens], ymm0
%endif
        ;; unrolled branch-free min-find (flush: null lanes carry UINT64_MAX)
        mov     min_len, [state + _sha3_lens + 0*8]
        xor     min_idx, min_idx
        mov     rax, [state + _sha3_lens + 1*8]
        cmp     rax, min_len
        cmovb   min_len, rax
        mov     rcx, 1
        cmovb   min_idx, rcx
        mov     rax, [state + _sha3_lens + 2*8]
        cmp     rax, min_len
        cmovb   min_len, rax
        mov     rcx, 2
        cmovb   min_idx, rcx
        mov     rax, [state + _sha3_lens + 3*8]
        cmp     rax, min_len
        cmovb   min_len, rax
        mov     rcx, 3
        cmovb   min_idx, rcx

        ;; num_blocks = min_len / RATE,  remaining = min_len % RATE
        mov     rax, min_len
        xor     rdx, rdx
        mov     arg4, %%RATE
        div     arg4
        mov     num_blocks, rax
        mov     remaining, rdx

        ;; subtract num_blocks*RATE from all lens
        imul    rax, num_blocks, %%RATE
        sub     qword [state + _sha3_lens + 0*8], rax
        sub     qword [state + _sha3_lens + 1*8], rax
        sub     qword [state + _sha3_lens + 2*8], rax
        sub     qword [state + _sha3_lens + 3*8], rax

        ;; absorb num_blocks × RATE bytes across all 4 lanes

        test    num_blocks, num_blocks
        jz      %%no_absorb

        mov     data0, [state + _sha3_args_data_ptr + 0*8]
        mov     data1, [state + _sha3_args_data_ptr + 1*8]
        mov     data2, [state + _sha3_args_data_ptr + 2*8]
        mov     data3, [state + _sha3_args_data_ptr + 3*8]

align_loop
%%absorb_loop:
        ;; Gather word %%W from all 4 lane inputs into ymm1, XOR into kstate word.
        ;; 32-byte store matches the 32-byte loads in keccak_f1600_x4_avx2,
        ;; avoiding a store-forwarding penalty.
%assign %%W 0
%rep (%%RATE / 8)
        vmovdqu     ymm0, [state + _sha3_args_kstate + %%W*32]
        vmovq       xmm1, [data0 + %%W*8]
        vpinsrq     xmm1, xmm1, [data1 + %%W*8], 1
        vmovq       xmm2, [data2 + %%W*8]
        vpinsrq     xmm2, xmm2, [data3 + %%W*8], 1
        vinserti128 ymm1, ymm1, xmm2, 1
        vpxor       ymm0, ymm0, ymm1
        vmovdqu     [state + _sha3_args_kstate + %%W*32], ymm0
%assign %%W (%%W+1)
%endrep
        add     data0, %%RATE
        add     data1, %%RATE
        add     data2, %%RATE
        add     data3, %%RATE

        lea     rdi, [state + _sha3_args_kstate]
        call    keccak_f1600_x4_avx2

        dec     num_blocks
        jnz     %%absorb_loop

        ;; Save updated data pointers
        mov     [state + _sha3_args_data_ptr + 0*8], data0
        mov     [state + _sha3_args_data_ptr + 1*8], data1
        mov     [state + _sha3_args_data_ptr + 2*8], data2
        mov     [state + _sha3_args_data_ptr + 3*8], data3

align_label
%%no_absorb:
        ;; Finalize min lane: apply padding if not already done
        imul    rax, min_idx, _SHA3_LANE_DATA_size
        cmp     dword [state + _sha3_ldata + rax + _sha3_finalized], 1
        je      %%check_done

        ;; Zero extra_block[0..RATE-1]
        lea     arg1, [state + _sha3_ldata + rax + _sha3_extra_block]
        ZERO_EXTRA_BLOCK arg1, %%RATE

        ;; Copy remaining message bytes into extra_block via rep movsb
        mov     arg2, [state + _sha3_args_data_ptr + min_idx*8]
        mov     arg4, remaining
        test    arg4, arg4
        jz      %%no_copy
%ifndef LINUX
        mov     data2, rdi
        mov     data3, job
%endif
        mov     rdi, arg1
        mov     job, arg2
        mov     rcx, arg4
        rep     movsb
        mov     arg1, rdi
%ifndef LINUX
        mov     rdi, data2
        mov     job, data3
%endif
align_label
%%no_copy:
        ;; Write domain-separation byte and flip EOM bit
        xor     byte [arg1], %%PAD
        xor     byte [state + _sha3_ldata + rax + _sha3_extra_block + %%RATE - 1], 0x80

        ;; mark finalized before rax stops being the lane-data offset
        mov     dword [state + _sha3_ldata + rax + _sha3_finalized], 1
        lea     rax, [state + _sha3_ldata + rax + _sha3_extra_block]
        mov     [state + _sha3_args_data_ptr + min_idx*8], rax
        mov     qword [state + _sha3_lens + min_idx*8], %%RATE
        jmp     %%do_loop       ; lens = %%RATE > 0, no need to re-read and compare

align_label
%%check_done:
        cmp     qword [state + _sha3_lens + min_idx*8], 0
        jnz     %%do_loop

        ;; collect result
        imul    rax, min_idx, _SHA3_LANE_DATA_size
        mov     rax, [state + _sha3_ldata + rax + _sha3_job_in_lane]

        mov     arg4, [state + _sha3_unused_lanes]
        shl     arg4, 4
        or      arg4, min_idx
        mov     [state + _sha3_unused_lanes], arg4
        dec     dword [state + _sha3_num_lanes_inuse]

%if %%IS_XOF
        ;; XOF/SHAKE: isolate completing lane into a private 800B temp
        ;; buffer at [rsp], emit output rate-bytes at a time, call x4 between blocks.
        mov     lane_idx, min_idx

        mov     outlen,     [rax + _auth_tag_output_len_in_bytes]
        mov     sq_out_ptr, [rax + _auth_tag_output]

        ;; Copy completing lane to slot 0 of the 800B temp buffer at [rsp]
        ;; (rsp is 32B-aligned).
%assign %%W 0
%rep 25
        vmovq   xmm0, [state + _sha3_args_kstate + %%W*32 + lane_idx*8]
        vmovdqa [rsp + %%W*32], ymm0   ; rsp is 32B-aligned (see prologue)
%assign %%W (%%W+1)
%endrep

align_loop
%%squeeze_loop:
        cmp     outlen, %%RATE
        jb      %%squeeze_last

        ;; Full-rate block: write %%RATE bytes from temp -> sq_out_ptr
%assign %%W 0
%rep (%%RATE / 8)
        mov     rax, [rsp + %%W*32]
        mov     [sq_out_ptr + %%W*8], rax
%assign %%W (%%W+1)
%endrep
        add     sq_out_ptr, %%RATE
        sub     outlen, %%RATE
        jz      %%squeeze_done

        lea     rdi, [rsp]
        call    keccak_f1600_x4_avx2
        jmp     %%squeeze_loop

align_label
%%squeeze_last:
        ;; tail: outlen bytes (1..RATE-1), one qword at a time,
        ;; then remaining 1-7 bytes byte by byte.
        test    outlen, outlen
        jz      %%squeeze_done
        lea     buf_ptr, [rsp]          ; word 0 of interleaved buffer
        mov     rcx, outlen             ; countdown: bytes left
align_loop
%%squeeze_tail_qword:
        mov     rax, [buf_ptr]          ; load word
        add     buf_ptr, 32
        cmp     rcx, 8
        jb      %%squeeze_tail_bytes
        mov     [sq_out_ptr], rax
        add     sq_out_ptr, 8
        sub     rcx, 8
        jnz     %%squeeze_tail_qword
        jmp     %%squeeze_done
align_label
%%squeeze_tail_bytes:
        mov     [sq_out_ptr], BYTE(rax)
        shr     rax, 8
        inc     sq_out_ptr
        dec     rcx
        jnz     %%squeeze_tail_bytes

align_label
%%squeeze_done:
        ;; release lane
        imul    data0, lane_idx, _SHA3_LANE_DATA_size
        mov     rax, [state + _sha3_ldata + data0 + _sha3_job_in_lane]

        or      dword [rax + _status], IMB_STATUS_COMPLETED_AUTH
        mov     qword [state + _sha3_ldata + data0 + _sha3_job_in_lane], 0

%ifdef SAFE_DATA
        ;; Zero extra_block of completed lane
        ZERO_EXTRA_BLOCK state + _sha3_ldata + data0 + _sha3_extra_block, %%RATE

        ;; Zero interleaved temp buffer (may hold sensitive data from squeeze)
        ;; ymm0 is already zero from ZERO_EXTRA_BLOCK
%assign %%SOFF 0
%rep 25
        vmovdqa [rsp + %%SOFF], ymm0   ; rsp is 32B-aligned (see prologue)
%assign %%SOFF (%%SOFF+32)
%endrep

        ;; Zero completing lane's 25 kstate words in the shared state.
        vmovq           xmm1, lane_idx
        vpbroadcastq    ymm1, xmm1
        vmovdqa         ymm2, [rel SHA3MB_LANE_IDX]
        vpcmpeqq        ymm1, ymm1, ymm2
%assign %%W 0
%rep 25
        vmovdqu         ymm2, [state + _sha3_args_kstate + %%W*32]
        vpblendvb       ymm2, ymm2, ymm0, ymm1
        vmovdqu         [state + _sha3_args_kstate + %%W*32], ymm2
%assign %%W (%%W+1)
%endrep
%endif ; SAFE_DATA

%else ; SHA3 fixed-output
        mov     arg1, [rax + _auth_tag_output]
%assign %%W 0
%rep (%%DSIZ / 8)
        mov     data3, [state + _sha3_args_kstate + %%W*32 + min_idx*8]
        mov     [arg1 + %%W*8], data3
%assign %%W (%%W+1)
%endrep
%if (%%DSIZ % 8) != 0
        mov     DWORD(data3), [state + _sha3_args_kstate + %%W*32 + min_idx*8]
        mov     [arg1 + %%W*8], DWORD(data3)
%endif

        or      dword [rax + _status], IMB_STATUS_COMPLETED_AUTH

        imul    arg4, min_idx, _SHA3_LANE_DATA_size
        mov     qword [state + _sha3_ldata + arg4 + _sha3_job_in_lane], 0

%ifdef SAFE_DATA
        ;; Zero extra_block of completed lane
        ZERO_EXTRA_BLOCK state + _sha3_ldata + arg4 + _sha3_extra_block, %%RATE

        ;; Zero completing lane's 25 kstate words in the shared state.
        ;; ymm0 is already zero from ZERO_EXTRA_BLOCK.
        vmovq           xmm1, min_idx
        vpbroadcastq    ymm1, xmm1
        vmovdqa         ymm2, [rel SHA3MB_LANE_IDX]
        vpcmpeqq        ymm1, ymm1, ymm2
%assign %%W 0
%rep 25
        vmovdqu         ymm2, [state + _sha3_args_kstate + %%W*32]
        vpblendvb       ymm2, ymm2, ymm0, ymm1
        vmovdqu         [state + _sha3_args_kstate + %%W*32], ymm2
%assign %%W (%%W+1)
%endrep
%endif ; SAFE_DATA
%endif ; %%IS_XOF

%%return:
%ifidn __OUTPUT_FORMAT__, win64
%if %%IS_XOF
        vmovdqa xmm6,  [rsp + WIN_XMM_OFF +  0*16]
        vmovdqa xmm7,  [rsp + WIN_XMM_OFF +  1*16]
        vmovdqa xmm8,  [rsp + WIN_XMM_OFF +  2*16]
        vmovdqa xmm9,  [rsp + WIN_XMM_OFF +  3*16]
        vmovdqa xmm10, [rsp + WIN_XMM_OFF +  4*16]
        vmovdqa xmm11, [rsp + WIN_XMM_OFF +  5*16]
        vmovdqa xmm12, [rsp + WIN_XMM_OFF +  6*16]
        vmovdqa xmm13, [rsp + WIN_XMM_OFF +  7*16]
        vmovdqa xmm14, [rsp + WIN_XMM_OFF +  8*16]
        vmovdqa xmm15, [rsp + WIN_XMM_OFF +  9*16]
        mov     rdi, [rsp + WIN_RDI_OFF]
        mov     job, [rsp + WIN_RSI_OFF]
        mov     rsp, [rsp + WIN_SAVED_RSP]
%else
        vmovdqa xmm6,  [rsp + WIN_SHA3_XMM_OFF +  0*16]
        vmovdqa xmm7,  [rsp + WIN_SHA3_XMM_OFF +  1*16]
        vmovdqa xmm8,  [rsp + WIN_SHA3_XMM_OFF +  2*16]
        vmovdqa xmm9,  [rsp + WIN_SHA3_XMM_OFF +  3*16]
        vmovdqa xmm10, [rsp + WIN_SHA3_XMM_OFF +  4*16]
        vmovdqa xmm11, [rsp + WIN_SHA3_XMM_OFF +  5*16]
        vmovdqa xmm12, [rsp + WIN_SHA3_XMM_OFF +  6*16]
        vmovdqa xmm13, [rsp + WIN_SHA3_XMM_OFF +  7*16]
        vmovdqa xmm14, [rsp + WIN_SHA3_XMM_OFF +  8*16]
        vmovdqa xmm15, [rsp + WIN_SHA3_XMM_OFF +  9*16]
        mov     rdi, [rsp + WIN_SHA3_RDI_OFF]
        mov     job, [rsp + WIN_SHA3_RSI_OFF]
        add     rsp, WIN_SHA3_FRAME_SIZE
%endif
%else
%if %%IS_XOF
        mov     rsp, [rsp + SHA3_LINUX_SAVED_RSP]
%else
        add     rsp, 8
%endif
%endif
        pop     rbp             ; min_len
        pop     rbx             ; state
        pop     r12             ; lane
        pop     r13             ; min_idx
        pop     r14             ; num_blocks
        pop     r15             ; remaining
        vzeroupper
        ret

%%ret_null:
        xor     eax, eax
        jmp     %%return
%endmacro

; ============================================================
mksection .text
; ============================================================

; ============================================================
; keccak_f1600_x4_avx2  rdi = interleaved kstate pointer (private convention)
; Keccak-f[1600] across 4 interleaved lanes, 24 rounds.
; Clobbers: rax, rsi, ymm0-ymm15.
; Preserves: rbx, rbp, r12-r15, r8-r11, rcx, rdx.
; ============================================================
align_function
MKGLOBAL(keccak_f1600_x4_avx2,function,internal)
keccak_f1600_x4_avx2:
        lea     rsi, [rel SHA3MB_RC]

        ; initial C[0..4] in ymm5..ymm9
        vmovdqu ymm5,  [rdi + 0*32]
        vpxor   ymm5,  ymm5,  [rdi + 5*32]
        vpxor   ymm5,  ymm5,  [rdi +10*32]
        vpxor   ymm5,  ymm5,  [rdi +15*32]
        vpxor   ymm5,  ymm5,  [rdi +20*32]    ; C[0]

        vmovdqu ymm6,  [rdi + 1*32]
        vpxor   ymm6,  ymm6,  [rdi + 6*32]
        vpxor   ymm6,  ymm6,  [rdi +11*32]
        vpxor   ymm6,  ymm6,  [rdi +16*32]
        vpxor   ymm6,  ymm6,  [rdi +21*32]    ; C[1]

        vmovdqu ymm7,  [rdi + 2*32]
        vpxor   ymm7,  ymm7,  [rdi + 7*32]
        vpxor   ymm7,  ymm7,  [rdi +12*32]
        vpxor   ymm7,  ymm7,  [rdi +17*32]
        vpxor   ymm7,  ymm7,  [rdi +22*32]    ; C[2]

        vmovdqu ymm8,  [rdi + 3*32]
        vpxor   ymm8,  ymm8,  [rdi + 8*32]
        vpxor   ymm8,  ymm8,  [rdi +13*32]
        vpxor   ymm8,  ymm8,  [rdi +18*32]
        vpxor   ymm8,  ymm8,  [rdi +23*32]    ; C[3]

        vmovdqu ymm9,  [rdi + 4*32]
        vpxor   ymm9,  ymm9,  [rdi + 9*32]
        vpxor   ymm9,  ymm9,  [rdi +14*32]
        vpxor   ymm9,  ymm9,  [rdi +19*32]
        vpxor   ymm9,  ymm9,  [rdi +24*32]    ; C[4]

        mov     rax, 24                        ; 24 rounds

align_loop
kf1600_x4_avx2_loop:
        KF_ROUND rdi, rsi
        dec     rax
        jnz     kf1600_x4_avx2_loop

        ret

SHA3_OOO_SUBMIT_FLUSH_FN submit_job_sha3_224_avx2, SHA3_224_RATE, SHA3_224_DIGEST_SZ, SHA3_MRATE_PADDING, 0, 1
SHA3_OOO_SUBMIT_FLUSH_FN flush_job_sha3_224_avx2,  SHA3_224_RATE, SHA3_224_DIGEST_SZ, SHA3_MRATE_PADDING, 0, 0
SHA3_OOO_SUBMIT_FLUSH_FN submit_job_sha3_256_avx2, SHA3_256_RATE, SHA3_256_DIGEST_SZ, SHA3_MRATE_PADDING, 0, 1
SHA3_OOO_SUBMIT_FLUSH_FN flush_job_sha3_256_avx2,  SHA3_256_RATE, SHA3_256_DIGEST_SZ, SHA3_MRATE_PADDING, 0, 0
SHA3_OOO_SUBMIT_FLUSH_FN submit_job_sha3_384_avx2, SHA3_384_RATE, SHA3_384_DIGEST_SZ, SHA3_MRATE_PADDING, 0, 1
SHA3_OOO_SUBMIT_FLUSH_FN flush_job_sha3_384_avx2,  SHA3_384_RATE, SHA3_384_DIGEST_SZ, SHA3_MRATE_PADDING, 0, 0
SHA3_OOO_SUBMIT_FLUSH_FN submit_job_sha3_512_avx2, SHA3_512_RATE, SHA3_512_DIGEST_SZ, SHA3_MRATE_PADDING, 0, 1
SHA3_OOO_SUBMIT_FLUSH_FN flush_job_sha3_512_avx2,  SHA3_512_RATE, SHA3_512_DIGEST_SZ, SHA3_MRATE_PADDING, 0, 0

SHA3_OOO_SUBMIT_FLUSH_FN submit_job_shake128_avx2, SHAKE128_RATE, 0, SHAKE_MRATE_PADDING, 1, 1
SHA3_OOO_SUBMIT_FLUSH_FN flush_job_shake128_avx2,  SHAKE128_RATE, 0, SHAKE_MRATE_PADDING, 1, 0
SHA3_OOO_SUBMIT_FLUSH_FN submit_job_shake256_avx2, SHAKE256_RATE, 0, SHAKE_MRATE_PADDING, 1, 1
SHA3_OOO_SUBMIT_FLUSH_FN flush_job_shake256_avx2,  SHAKE256_RATE, 0, SHAKE_MRATE_PADDING, 1, 0

mksection .rodata

; vpshufb byte-shuffle masks for ROL64 by 8 and 56 within each 64-bit lane
align 32
SHA3MB_RHO8_SHUF:
        DQ 0x0605040302010007, 0x0E0D0C0B0A09080F
        DQ 0x0605040302010007, 0x0E0D0C0B0A09080F

align 32
SHA3MB_RHO56_SHUF:
        DQ 0x0007060504030201, 0x080F0E0D0C0B0A09
        DQ 0x0007060504030201, 0x080F0E0D0C0B0A09

; Lane index vector for runtime lane-clear (vpblendvb mask construction)
align 32
SHA3MB_LANE_IDX:
        DQ 0, 1, 2, 3

; Keccak-f[1600] round constants (24 × 64-bit).
align 32
SHA3MB_RC:
        DQ 0x0000000000000001, 0x0000000000008082
        DQ 0x800000000000808a, 0x8000000080008000
        DQ 0x000000000000808b, 0x0000000080000001
        DQ 0x8000000080008081, 0x8000000000008009
        DQ 0x000000000000008a, 0x0000000000000088
        DQ 0x0000000080008009, 0x000000008000000a
        DQ 0x000000008000808b, 0x800000000000008b
        DQ 0x8000000000008089, 0x8000000000008003
        DQ 0x8000000000008002, 0x8000000000000080
        DQ 0x000000000000800a, 0x800000008000000a
        DQ 0x8000000080008081, 0x8000000000008080
        DQ 0x0000000080000001, 0x8000000080008008

mksection stack-noexec
