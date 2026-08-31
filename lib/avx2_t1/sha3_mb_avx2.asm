; Copyright (c) 2026, Intel Corporation
; All rights reserved.
;
; SPDX-License-Identifier: BSD-3-Clause

; AVX2 SHA3 / SHAKE multi-buffer (4-lane) submit / flush.
;
; A single submit/flush pair serves SHA3-224/256/384/512 and SHAKE128/256.
; The sponge rate and the domain separation byte are per-lane runtime values
; kept in the OOO manager, so lanes running different algorithms are absorbed
; together and only one MB_MGR_SHA3_OOO instance is required.
;
; Lockstep control uses the per-lane whole-block count (blocks[i] = lens[i] /
; rate[i]) instead of the byte length, because with different rates the same
; number of bytes does not correspond to the same number of permutations.
; blocks[] is maintained incrementally so the loop never divides.
;
; State: kstate[W*32 + L*8] = word W, lane L  (W=0..24, L=0..3), i.e. the four
; lane values of a Keccak word share one 32-byte YMM slot.  The state lives in
; memory (unlike the AVX-512 version, AVX2 has too few registers to keep it in
; registers), and every update is a full 32-byte read-modify-write so that the
; store width always matches the load width.
;

default rel

%include "include/sha3_common.inc"
%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/align_avx.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"

;; arg1..arg4 come from sha3_common.inc

; ============================================================
; Named register aliases
;
; keccak_f1600_x4_avx2 preserves rbx, rbp, r12-r15 and r8-r11, so the lane
; pointers and all loop state survive the permutation without spilling.
; ============================================================
%define state           rbx     ; MB_MGR_SHA3_OOO*                 (callee-saved)
%define lane            r12     ; flush: first occupied lane index (callee-saved)
                                ; after completion: ldata[] byte offset of the
                                ; finishing lane
%define absorb_end      rbp     ; absorb: input bytes to cover
%define min_idx         r13     ; index of lane with fewest blocks left
%define num_blocks      r14     ; number of whole rate-blocks to absorb
%define remaining       r15     ; bytes left after the whole blocks
%define outlen          rbp     ; squeeze: bytes still to emit
%define out_ptr         r15     ; squeeze: output buffer pointer
%define job             rsi     ; IMB_JOB*

; ============================================================
; Physical register map
;
; The aliases above are not the whole story: much of this file addresses
; registers by their real names, so a new alias has to be checked against the
; list below or it will silently collide with an existing use.
;
;   rax     scratch throughout: absorb input offset, minimum search, the
;           copy/squeeze offset, and the ldata[] offset in submit
;   rbx     state                                             (callee-saved)
;   rcx     scratch throughout: absorb group end, byte counters, the
;           unused_lanes shuffle, the de-interleave and re-interleave loops
;   rdx     scratch: copy temporary, and &extra_block[0] in the finalize path
;   rsi     job in submit, but also the round-constant pointer inside
;           keccak_f1600_x4_avx2 - job is therefore dead before the core runs
;                                                             (win64: saved)
;   rdi     kstate pointer handed to keccak_f1600_x4_avx2     (win64: saved)
;   rbp     absorb_end during the absorb, outlen during the squeeze
;                                                             (callee-saved)
;   r8-r11  lane 0-3 input pointers for the whole absorb loop.  They are
;           reloaded from _sha3_args_data_ptr on entry to the loop and written
;           back on exit, so outside it they are free: the finalize path uses
;           r8 (destination), r9 (source) and r10 (ldata[] offset) as plain
;           scratch, and submit hands r8 to SHA3_MB_SET_LANE_PARAMS
;   r12     lane                                              (callee-saved)
;   r13     min_idx                                           (callee-saved)
;   r14     num_blocks                                        (callee-saved)
;   r15     remaining during the absorb, out_ptr during the squeeze
;                                                             (callee-saved)
;
;   ymm0-ymm9       sha3_mb_absorb_x4
;   ymm0-ymm15      keccak_f1600_x4_avx2
;   ymm0-ymm4       flush prologue, and the lane clear at completion
;   ymm0            SHA3_MB_ZERO_EXTRA_BLOCK, squeeze copies, SAFE_DATA
;                                       (win64: xmm6-xmm15 saved by submit and
;                                        flush, so all 16 are usable)
;
; SHA3_MB_SET_LANE_PARAMS clobbers rax, rcx, rdx and the temporary it is
; given, and it divides, so its lane argument must not be rax or rdx.
; ============================================================

; ============================================================
; Stack frame (identical for submit and flush).
;
; RSP is dynamically aligned to 32 bytes, so every offset below is also
; 32-byte aligned where it needs to be.
;
;   [rsp + _SQ_INTER]    800 B: interleaved 25x32 buffer used to run
;                        keccak_f1600_x4_avx2 on the completing lane alone
;   [rsp + _SQ_SCRATCH]  200 B used / 224 B reserved: the completing lane's 25
;                        state words laid out contiguously, so that an
;                        arbitrary output length can be copied from it
;   [rsp + _SQ_RATE]     completing lane's rate
;   [rsp + _SAVED_RSP]   RSP before the alignment
;
; The frame belongs to sha3_mb_core_avx2 and is allocated by it, so nothing in
; submit or flush depends on these offsets.
; ============================================================
%define _SQ_INTER       0
%define _SQ_SCRATCH     (_SQ_INTER + 800)
%define _SQ_RATE        (_SQ_SCRATCH + 224)
%define _SAVED_RSP      (_SQ_RATE + 8)
%define FRAME_SIZE      (_SAVED_RSP + 8)

; Windows only: xmm6-xmm15 are saved by submit/flush, below their GPR pushes.
%define _XMM_SAVE_SIZE  (10*16)

%macro VROL64 4
%define %%DST   %1      ; [out] destination YMM register
%define %%SRC   %2      ; [in]  source YMM register
%define %%IMM   %3      ; [in]  rotation amount (compile-time immediate)
%define %%YTMP  %4      ; [clobbered] temporary YMM register (must not equal %%DST or %%SRC)
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
; pos-0 theta: B[0] kept in %%B0
; Chi row 0 uses %%B0 as B[0]_orig directly.
; The rho+pi chain folds each kstate load into the vpxor with D[x] and
; produces B[15..19] straight into %%C0..%%C4.
;
; %%C0..%%C4 are the only values carried across rounds; everything else is
; scratch.  Theta and rho+pi are finished with %%D0..%%D2 by the time chi
; starts, so chi re-uses them as its two wrap saves and its scratch register
; (aliased below as %%W0, %%W1 and %%CT) rather than asking for three more.
; ============================================================
%macro KF_ROUND 18
%xdefine        %%KS    %1      ; [in]       interleaved kstate base address
%xdefine        %%RCP   %2      ; [in/out]   round-constant pointer (advanced by 8)
%xdefine        %%C0    %3      ; [in/out]   YMM C[0] (column parity); B[15] during chi
%xdefine        %%C1    %4      ; [in/out]   YMM C[1] (column parity); B[16] during chi
%xdefine        %%C2    %5      ; [in/out]   YMM C[2] (column parity); B[17] during chi
%xdefine        %%C3    %6      ; [in/out]   YMM C[3] (column parity); B[18] during chi
%xdefine        %%C4    %7      ; [in/out]   YMM C[4] (column parity); B[19] during chi
%xdefine        %%D0    %8      ; [clobbered] YMM theta D[0]
%xdefine        %%D1    %9      ; [clobbered] YMM theta D[1]
%xdefine        %%D2    %10     ; [clobbered] YMM theta D[2]
%xdefine        %%D3    %11     ; [clobbered] YMM theta D[3]
%xdefine        %%D4    %12     ; [clobbered] YMM theta D[4]
%xdefine        %%B0    %13     ; [clobbered] YMM B[0], held from theta to chi row 0
%xdefine        %%T0    %14     ; [clobbered] YMM rho+pi xor accumulator; chi row word 0
%xdefine        %%T1    %15     ; [clobbered] YMM VROL64 temporary; chi row word 1
%xdefine        %%T2    %16     ; [clobbered] YMM rho+pi carry; chi row word 2
%xdefine        %%T3    %17     ; [clobbered] YMM chi row word 3
%xdefine        %%T4    %18     ; [clobbered] YMM chi row word 4

%xdefine        %%W0    %%D0    ; [clobbered] chi wrap save 0 (D[0] is dead by then)
%xdefine        %%W1    %%D1    ; [clobbered] chi wrap save 1 (D[1] is dead by then)
%xdefine        %%CT    %%D2    ; [clobbered] chi scratch      (D[2] is dead by then)

        ; theta: D[x] = C[x-1] ^ ROL(C[x+1],1)
        VROL64  %%D0, %%C1, 1, %%T1
        vpxor   %%D0, %%D0, %%C4        ; D[0] = ROL(C[1],1) ^ C[4]
        VROL64  %%D1, %%C2, 1, %%T1
        vpxor   %%D1, %%D1, %%C0        ; D[1] = ROL(C[2],1) ^ C[0]
        VROL64  %%D2, %%C3, 1, %%T1
        vpxor   %%D2, %%D2, %%C1        ; D[2] = ROL(C[3],1) ^ C[1]
        VROL64  %%D3, %%C4, 1, %%T1
        vpxor   %%D3, %%D3, %%C2        ; D[3] = ROL(C[4],1) ^ C[2]
        VROL64  %%D4, %%C0, 1, %%T1
        vpxor   %%D4, %%D4, %%C3        ; D[4] = ROL(C[0],1) ^ C[3]

        ; pos-0: B[0] = A[0]^D[0] in %%B0 (no store)
        vpxor   %%B0, %%D0, [%%KS + 0*32]

        ; rho+pi chain  (D[0..4] = %%D0..%%D4, carry = %%T2)
        ; The kstate load is folded into the vpxor with D[x]; the store of
        ; the previous step's product goes to [%%KS + src*32] because
        ; dst(step-1) == src(step).  Steps producing B[15..19] target
        ; %%C0..%%C4 and the following step's store is dropped.

        ; src=1 (D[1]=%%D1, rho=1 -> dst=10)
        vpxor   %%T0,  %%D1, [%%KS + 1*32]
        VROL64  %%T2, %%T0, 1, %%T1

        ; src=10 (D[0]=%%D0, rho=3 -> dst=7)
        vpxor   %%T0,  %%D0, [%%KS +10*32]
        vmovdqu [%%KS +10*32], %%T2
        VROL64  %%T2, %%T0, 3, %%T1

        ; src=7 (D[2]=%%D2, rho=6 -> dst=11)
        vpxor   %%T0,  %%D2, [%%KS + 7*32]
        vmovdqu [%%KS + 7*32], %%T2
        VROL64  %%T2, %%T0, 6, %%T1

        ; src=11 (D[1]=%%D1, rho=10 -> dst=17)
        vpxor   %%T0,  %%D1, [%%KS +11*32]
        vmovdqu [%%KS +11*32], %%T2
        VROL64  %%C2, %%T0, 10, %%T1

        ; src=17 (D[2]=%%D2, rho=15 -> dst=18)
        vpxor   %%T0,  %%D2, [%%KS +17*32]
        VROL64  %%C3, %%T0, 15, %%T1

        ; src=18 (D[3]=%%D3, rho=21 -> dst=3)
        vpxor   %%T0,  %%D3, [%%KS +18*32]
        VROL64  %%T2, %%T0, 21, %%T1

        ; src=3 (D[3]=%%D3, rho=28 -> dst=5)
        vpxor   %%T0,  %%D3, [%%KS + 3*32]
        vmovdqu [%%KS + 3*32], %%T2
        VROL64  %%T2, %%T0, 28, %%T1

        ; src=5 (D[0]=%%D0, rho=36 -> dst=16)
        vpxor   %%T0,  %%D0, [%%KS + 5*32]
        vmovdqu [%%KS + 5*32], %%T2
        VROL64  %%C1, %%T0, 36, %%T1

        ; src=16 (D[1]=%%D1, rho=45 -> dst=8)
        vpxor   %%T0,  %%D1, [%%KS +16*32]
        VROL64  %%T2, %%T0, 45, %%T1

        ; src=8 (D[3]=%%D3, rho=55 -> dst=21)
        vpxor   %%T0,  %%D3, [%%KS + 8*32]
        vmovdqu [%%KS + 8*32], %%T2
        VROL64  %%T2, %%T0, 55, %%T1

        ; src=21 (D[1]=%%D1, rho=2 -> dst=24)
        vpxor   %%T0,  %%D1, [%%KS +21*32]
        vmovdqu [%%KS +21*32], %%T2
        VROL64  %%T2, %%T0, 2, %%T1

        ; src=24 (D[4]=%%D4, rho=14 -> dst=4)
        vpxor   %%T0,  %%D4, [%%KS +24*32]
        vmovdqu [%%KS +24*32], %%T2
        VROL64  %%T2, %%T0, 14, %%T1

        ; src=4 (D[4]=%%D4, rho=27 -> dst=15)
        vpxor   %%T0,  %%D4, [%%KS + 4*32]
        vmovdqu [%%KS + 4*32], %%T2
        VROL64  %%C0, %%T0, 27, %%T1

        ; src=15 (D[0]=%%D0, rho=41 -> dst=23)
        vpxor   %%T0,  %%D0, [%%KS +15*32]
        VROL64  %%T2, %%T0, 41, %%T1

        ; src=23 (D[3]=%%D3, rho=56 -> dst=19)
        vpxor   %%T0,  %%D3, [%%KS +23*32]
        vmovdqu [%%KS +23*32], %%T2
        VROL64  %%C4, %%T0, 56, %%T1

        ; src=19 (D[4]=%%D4, rho=8 -> dst=13)
        vpxor   %%T0,  %%D4, [%%KS +19*32]
        VROL64  %%T2, %%T0, 8, %%T1

        ; src=13 (D[3]=%%D3, rho=25 -> dst=12)
        vpxor   %%T0,  %%D3, [%%KS +13*32]
        vmovdqu [%%KS +13*32], %%T2
        VROL64  %%T2, %%T0, 25, %%T1

        ; src=12 (D[2]=%%D2, rho=43 -> dst=2)
        vpxor   %%T0,  %%D2, [%%KS +12*32]
        vmovdqu [%%KS +12*32], %%T2
        VROL64  %%T2, %%T0, 43, %%T1

        ; src=2 (D[2]=%%D2, rho=62 -> dst=20)
        vpxor   %%T0,  %%D2, [%%KS + 2*32]
        vmovdqu [%%KS + 2*32], %%T2
        VROL64  %%T2, %%T0, 62, %%T1

        ; src=20 (D[0]=%%D0, rho=18 -> dst=14)
        vpxor   %%T0,  %%D0, [%%KS +20*32]
        vmovdqu [%%KS +20*32], %%T2
        VROL64  %%T2, %%T0, 18, %%T1

        ; src=14 (D[4]=%%D4, rho=39 -> dst=22)
        vpxor   %%T0,  %%D4, [%%KS +14*32]
        vmovdqu [%%KS +14*32], %%T2
        VROL64  %%T2, %%T0, 39, %%T1

        ; src=22 (D[2]=%%D2, rho=61 -> dst=9)
        vpxor   %%T0,  %%D2, [%%KS +22*32]
        vmovdqu [%%KS +22*32], %%T2
        VROL64  %%T2, %%T0, 61, %%T1

        ; src=9 (D[4]=%%D4, rho=20 -> dst=6)
        vpxor   %%T0,  %%D4, [%%KS + 9*32]
        vmovdqu [%%KS + 9*32], %%T2
        VROL64  %%T2, %%T0, 20, %%T1

        ; src=6 (D[1]=%%D1, rho=44 -> dst=1)  closes cycle
        vpxor   %%T0,  %%D1, [%%KS + 6*32]
        vmovdqu [%%KS + 6*32], %%T2
        VROL64  %%T2, %%T0, 44, %%T1
        vmovdqu [%%KS + 1*32], %%T2     ; B[1] = close cycle

        ; chi [3,2,4,1,0] + C[] accumulation
        ; row 3 first (ready earliest in rho+pi chain)
        ; B[15..19] are already in %%C0..%%C4 from the chain - no reload, and
        ; kstate words 15..19 still hold the previous round's A[] until the
        ; stores below (nothing reads them in between).
        vmovdqa %%W0, %%C0      ; save B[15] for chi wrap
        vmovdqa %%W1, %%C1      ; save B[16] for chi wrap
        vpandn  %%CT, %%C1,  %%C2
        vpxor   %%C0,  %%C0,  %%CT
        vpandn  %%CT, %%C2,  %%C3
        vpxor   %%C1,  %%C1,  %%CT
        vpandn  %%CT, %%C3,  %%C4
        vpxor   %%C2,  %%C2,  %%CT
        vpandn  %%CT, %%C4,  %%W0
        vpxor   %%C3,  %%C3,  %%CT
        vpandn  %%CT, %%W0, %%W1
        vpxor   %%C4,  %%C4,  %%CT
        vmovdqu [%%KS +15*32], %%C0
        vmovdqu [%%KS +16*32], %%C1
        vmovdqu [%%KS +17*32], %%C2
        vmovdqu [%%KS +18*32], %%C3
        vmovdqu [%%KS +19*32], %%C4

        ; row 2
        vmovdqu %%T0,  [%%KS +10*32]
        vmovdqu %%T1,  [%%KS +11*32]
        vmovdqu %%T2,  [%%KS +12*32]
        vmovdqu %%T3,  [%%KS +13*32]
        vmovdqu %%T4,  [%%KS +14*32]
        vmovdqa %%W0, %%T0
        vmovdqa %%W1, %%T1
        vpandn  %%CT, %%T1,  %%T2
        vpxor   %%T0,  %%T0,  %%CT
        vpandn  %%CT, %%T2,  %%T3
        vpxor   %%T1,  %%T1,  %%CT
        vpandn  %%CT, %%T3,  %%T4
        vpxor   %%T2,  %%T2,  %%CT
        vpandn  %%CT, %%T4,  %%W0
        vpxor   %%T3,  %%T3,  %%CT
        vpandn  %%CT, %%W0, %%W1
        vpxor   %%T4,  %%T4,  %%CT
        vpxor   %%C0,  %%C0,  %%T0
        vpxor   %%C1,  %%C1,  %%T1
        vpxor   %%C2,  %%C2,  %%T2
        vpxor   %%C3,  %%C3,  %%T3
        vpxor   %%C4,  %%C4,  %%T4
        vmovdqu [%%KS +10*32], %%T0
        vmovdqu [%%KS +11*32], %%T1
        vmovdqu [%%KS +12*32], %%T2
        vmovdqu [%%KS +13*32], %%T3
        vmovdqu [%%KS +14*32], %%T4

        ; row 4
        vmovdqu %%T0,  [%%KS +20*32]
        vmovdqu %%T1,  [%%KS +21*32]
        vmovdqu %%T2,  [%%KS +22*32]
        vmovdqu %%T3,  [%%KS +23*32]
        vmovdqu %%T4,  [%%KS +24*32]
        vmovdqa %%W0, %%T0
        vmovdqa %%W1, %%T1
        vpandn  %%CT, %%T1,  %%T2
        vpxor   %%T0,  %%T0,  %%CT
        vpandn  %%CT, %%T2,  %%T3
        vpxor   %%T1,  %%T1,  %%CT
        vpandn  %%CT, %%T3,  %%T4
        vpxor   %%T2,  %%T2,  %%CT
        vpandn  %%CT, %%T4,  %%W0
        vpxor   %%T3,  %%T3,  %%CT
        vpandn  %%CT, %%W0, %%W1
        vpxor   %%T4,  %%T4,  %%CT
        vpxor   %%C0,  %%C0,  %%T0
        vpxor   %%C1,  %%C1,  %%T1
        vpxor   %%C2,  %%C2,  %%T2
        vpxor   %%C3,  %%C3,  %%T3
        vpxor   %%C4,  %%C4,  %%T4
        vmovdqu [%%KS +20*32], %%T0
        vmovdqu [%%KS +21*32], %%T1
        vmovdqu [%%KS +22*32], %%T2
        vmovdqu [%%KS +23*32], %%T3
        vmovdqu [%%KS +24*32], %%T4

        ; row 1
        vmovdqu %%T0,  [%%KS + 5*32]
        vmovdqu %%T1,  [%%KS + 6*32]
        vmovdqu %%T2,  [%%KS + 7*32]
        vmovdqu %%T3,  [%%KS + 8*32]
        vmovdqu %%T4,  [%%KS + 9*32]
        vmovdqa %%W0, %%T0
        vmovdqa %%W1, %%T1
        vpandn  %%CT, %%T1,  %%T2
        vpxor   %%T0,  %%T0,  %%CT
        vpandn  %%CT, %%T2,  %%T3
        vpxor   %%T1,  %%T1,  %%CT
        vpandn  %%CT, %%T3,  %%T4
        vpxor   %%T2,  %%T2,  %%CT
        vpandn  %%CT, %%T4,  %%W0
        vpxor   %%T3,  %%T3,  %%CT
        vpandn  %%CT, %%W0, %%W1
        vpxor   %%T4,  %%T4,  %%CT
        vpxor   %%C0,  %%C0,  %%T0
        vpxor   %%C1,  %%C1,  %%T1
        vpxor   %%C2,  %%C2,  %%T2
        vpxor   %%C3,  %%C3,  %%T3
        vpxor   %%C4,  %%C4,  %%T4
        vmovdqu [%%KS + 5*32], %%T0
        vmovdqu [%%KS + 6*32], %%T1
        vmovdqu [%%KS + 7*32], %%T2
        vmovdqu [%%KS + 8*32], %%T3
        vmovdqu [%%KS + 9*32], %%T4

        ; row 0 last: B[0]=%%B0 (no load), accumulate C[], iota
        vmovdqa %%T0,  %%B0     ; B[0] (reg copy, no load)
        vmovdqu %%T1,  [%%KS + 1*32]
        vmovdqu %%T2,  [%%KS + 2*32]
        vmovdqu %%T3,  [%%KS + 3*32]
        vmovdqu %%T4,  [%%KS + 4*32]
        vmovdqa %%W1, %%T1      ; save B[1]_orig for pos 4
        vpandn  %%CT, %%T1,  %%T2       ; ~B[1] & B[2]
        vpxor   %%T0,  %%T0,  %%CT      ; chi A[0]
        vpandn  %%CT, %%T2,  %%T3       ; ~B[2] & B[3]
        vpxor   %%T1,  %%T1,  %%CT      ; chi A[1]
        vpandn  %%CT, %%T3,  %%T4       ; ~B[3] & B[4]
        vpxor   %%T2,  %%T2,  %%CT      ; chi A[2]
        vpandn  %%CT, %%T4,  %%B0       ; ~B[4] & B[0]_orig (%%B0)
        vpxor   %%T3,  %%T3,  %%CT      ; chi A[3]
        vpandn  %%CT, %%B0, %%W1        ; ~B[0]_orig & B[1]_orig
        vpxor   %%T4,  %%T4,  %%CT      ; chi A[4]
        ; Iota: broadcast RC to all 4 lanes, XOR into word 0
        vpbroadcastq    %%CT, [%%RCP]
        vpxor   %%T0,  %%T0,  %%CT
        add     %%RCP, 8
        vpxor   %%C0,  %%C0,  %%T0
        vpxor   %%C1,  %%C1,  %%T1
        vpxor   %%C2,  %%C2,  %%T2
        vpxor   %%C3,  %%C3,  %%T3
        vpxor   %%C4,  %%C4,  %%T4
        vmovdqu [%%KS + 0*32], %%T0
        vmovdqu [%%KS + 1*32], %%T1
        vmovdqu [%%KS + 2*32], %%T2
        vmovdqu [%%KS + 3*32], %%T3
        vmovdqu [%%KS + 4*32], %%T4
%endmacro

mksection .text

; ============================================================
; 4-lane absorb, one block per lane at the lane's own rate.
;
; A single routine covers every rate. The four lanes are read in full
; 32-byte chunks or masked 4-word chunks. A load is skipped when the lane's
; block has already been absorbed.
;
;   in     : state (rbx) MB_MGR_SHA3_OOO*
;   in     : absorb_end  input bytes to cover, rounded up to a whole group
;   in/out : r8-r11      lane 0-3 input pointers
;   clobber: rax, rcx, ymm0-ymm9
; ============================================================
align_function
sha3_mb_absorb_x4:
        vmovdqa ymm9, [rel SHA3MB_QWORD_IDX]     ; absorb qword counter
        xor     eax, eax        ; input byte offset of the group

align_loop
.group_loop:
        lea     rcx, [rax + 32] ; rcx to be used if normal 32 byte load can be used

        vpxor   ymm0, ymm0, ymm0        ; zero the register in case load doesn't take place
        cmp     [state + _sha3_args_rate + 0*8], rax
        jbe     .lane0_done
        cmp     [state + _sha3_args_rate + 0*8], rcx
        jb      .partial_input_l0       ; less than 32 bytes to be loaded
        vmovdqu ymm0, [r8 + rax]        ; load full 32 bytes
        jmp     .lane0_done
align_label
.partial_input_l0:
        vpbroadcastq    ymm8, [state + _sha3_args_rate + 0*8]
        vpsrlq  ymm8, ymm8, 3   ; rate in 64-bit words
        vpcmpgtq        ymm4, ymm8, ymm9
        vpmaskmovq      ymm0, ymm4, [r8 + rax]
align_label
.lane0_done:

        vpxor   ymm1, ymm1, ymm1
        cmp     [state + _sha3_args_rate + 1*8], rax
        jbe     .lane1_done
        cmp     [state + _sha3_args_rate + 1*8], rcx
        jb      .partial_input_l1
        vmovdqu ymm1, [r9 + rax]
        jmp     .lane1_done
align_label
.partial_input_l1:
        vpbroadcastq    ymm8, [state + _sha3_args_rate + 1*8]
        vpsrlq  ymm8, ymm8, 3
        vpcmpgtq        ymm4, ymm8, ymm9
        vpmaskmovq      ymm1, ymm4, [r9 + rax]
align_label
.lane1_done:

        vpxor   ymm2, ymm2, ymm2
        cmp     [state + _sha3_args_rate + 2*8], rax
        jbe     .lane2_done
        cmp     [state + _sha3_args_rate + 2*8], rcx
        jb      .partial_input_l2
        vmovdqu ymm2, [r10 + rax]
        jmp     .lane2_done
align_label
.partial_input_l2:
        vpbroadcastq    ymm8, [state + _sha3_args_rate + 2*8]
        vpsrlq  ymm8, ymm8, 3
        vpcmpgtq        ymm4, ymm8, ymm9
        vpmaskmovq      ymm2, ymm4, [r10 + rax]
align_label
.lane2_done:

        vpxor   ymm3, ymm3, ymm3
        cmp     [state + _sha3_args_rate + 3*8], rax
        jbe     .lane3_done
        cmp     [state + _sha3_args_rate + 3*8], rcx
        jb      .partial_input_l3
        vmovdqu ymm3, [r11 + rax]
        jmp     .lane3_done
align_label
.partial_input_l3:
        vpbroadcastq    ymm8, [state + _sha3_args_rate + 3*8]
        vpsrlq  ymm8, ymm8, 3
        vpcmpgtq        ymm4, ymm8, ymm9
        vpmaskmovq      ymm3, ymm4, [r11 + rax]
align_label
.lane3_done:

        ;; 4x4 transpose of the 64-bit words; the lane registers are dead once
        ;; the unpacks have run, so the result goes back into them
        vpunpcklqdq     ymm4, ymm0, ymm1
        vpunpckhqdq     ymm5, ymm0, ymm1
        vpunpcklqdq     ymm6, ymm2, ymm3
        vpunpckhqdq     ymm7, ymm2, ymm3
        vperm2i128      ymm0, ymm4, ymm6, 0x20
        vperm2i128      ymm1, ymm5, ymm7, 0x20
        vperm2i128      ymm2, ymm4, ymm6, 0x31
        vperm2i128      ymm3, ymm5, ymm7, 0x31

        vpxor   ymm0, ymm0, [state + _sha3_args_kstate + rax*4 + 0*32]
        vmovdqu [state + _sha3_args_kstate + rax*4 + 0*32], ymm0
        vpxor   ymm1, ymm1, [state + _sha3_args_kstate + rax*4 + 1*32]
        vmovdqu [state + _sha3_args_kstate + rax*4 + 1*32], ymm1
        vpxor   ymm2, ymm2, [state + _sha3_args_kstate + rax*4 + 2*32]
        vmovdqu [state + _sha3_args_kstate + rax*4 + 2*32], ymm2
        vpxor   ymm3, ymm3, [state + _sha3_args_kstate + rax*4 + 3*32]
        vmovdqu [state + _sha3_args_kstate + rax*4 + 3*32], ymm3

        vpaddq  ymm9, ymm9, [rel SHA3MB_FOUR_Q]
        add     rax, 32
        cmp     rax, absorb_end
        jb      .group_loop

        ;; advance each lane by its own rate
        add     r8,  [state + _sha3_args_rate + 0*8]
        add     r9,  [state + _sha3_args_rate + 1*8]
        add     r10, [state + _sha3_args_rate + 2*8]
        add     r11, [state + _sha3_args_rate + 3*8]
        ret

; ============================================================
; SHA3_MB_ZERO_EXTRA_BLOCK
;
; Clears the whole 168-byte extra_block (the maximum rate) regardless of the
; lane's actual rate - six stores, cheaper than deriving the exact length.
;
;   %1      = register holding &extra_block[0]
;   clobber: ymm0
; ============================================================
%macro SHA3_MB_ZERO_EXTRA_BLOCK 1
        vpxor   ymm0, ymm0, ymm0
        vmovdqu [%1 + 0*32], ymm0
        vmovdqu [%1 + 1*32], ymm0
        vmovdqu [%1 + 2*32], ymm0
        vmovdqu [%1 + 3*32], ymm0
        vmovdqu [%1 + 4*32], ymm0
        vmovq   [%1 + 5*32], xmm0       ; bytes 160..167
%endmacro

; ============================================================
; sha3_mb_core_avx2
;
; The absorb / finalize / squeeze engine shared by submit and flush.  It owns
; the whole stack frame described above, so neither caller depends on any of
; the frame offsets.
;
; This is an internal routine, not an ABI function: arguments arrive in
; registers, every volatile and callee-saved register except the caller's own
; saved GPRs is fair game, and only the callers preserve what Windows requires.
;
; Every lane must be ready to be absorbed before entry: a lane holding a job
; carries its own rate, and a lane holding none carries a rate of zero and a
; block count that cannot win the minimum search.  Lanes are only released on
; the way out, so that stays true for the whole of the loop below.
;
; At least one lane must hold a job.  An idle lane carries blocks = UINT64_MAX,
; so with every lane idle the minimum search would return UINT64_MAX and the
; absorb loop would never terminate.  Submit only calls in once all four lanes
; are full, and flush returns early when num_lanes_inuse is zero, so the
; all-idle case cannot reach here.
;
;   in  : rbx  MB_MGR_SHA3_OOO*
;   out : rax  the IMB_JOB* that completed
; ============================================================
align_function
sha3_mb_core_avx2:
        mov     rax, rsp
        sub     rsp, FRAME_SIZE
        and     rsp, -32
        mov     [rsp + _SAVED_RSP], rax

        ;; ============================================================
        ;; absorb_end: how far the absorb group loop has to run, i.e. the
        ;; widest rate in use rounded up to a whole group.  The lane rates do
        ;; not change while the core runs, so this is computed once here rather
        ;; than on every pass of the loop below.
        ;;
        ;;   in     : state
        ;;   out    : absorb_end
        ;;   clobber: rax, rcx
        ;; ============================================================
        mov     rax, [state + _sha3_args_rate + 0*8]
        mov     rcx, [state + _sha3_args_rate + 1*8]
        cmp     rcx, rax
        cmova   rax, rcx
        mov     rcx, [state + _sha3_args_rate + 2*8]
        cmp     rcx, rax
        cmova   rax, rcx
        mov     rcx, [state + _sha3_args_rate + 3*8]
        cmp     rcx, rax
        cmova   rax, rcx
        add     rax, 31
        and     rax, -32
        mov     absorb_end, rax

        ;; =============================================
        ;; do { find-min; absorb; finalize } while lens[min] != 0
        ;; =============================================
align_loop
.do_loop:

        ;; num_blocks = min(blocks[]), min_idx = argmin (lowest index on a tie)
        mov     num_blocks, [state + _sha3_blocks + 0*8]
        xor     min_idx, min_idx
        mov     rax, [state + _sha3_blocks + 1*8]
        cmp     rax, num_blocks
        cmovb   num_blocks, rax
        mov     ecx, 1
        cmovb   min_idx, rcx
        mov     rax, [state + _sha3_blocks + 2*8]
        cmp     rax, num_blocks
        cmovb   num_blocks, rax
        mov     ecx, 2
        cmovb   min_idx, rcx
        mov     rax, [state + _sha3_blocks + 3*8]
        cmp     rax, num_blocks
        cmovb   num_blocks, rax
        mov     ecx, 3
        cmovb   min_idx, rcx

        test    num_blocks, num_blocks
        jz      .no_absorb

        ;; Each lane consumes num_blocks blocks of its own rate.  AVX2 has no
        ;; 64x64 multiply, but a rate fits in 16 bits, so the high half of the
        ;; product only needs one extra VPMULUDQ.
        vmovq   xmm1, num_blocks
        vpbroadcastq    ymm1, xmm1
        vmovdqa ymm2, [state + _sha3_args_rate]
        vpsrlq  ymm3, ymm1, 32
        vpmuludq        ymm3, ymm2, ymm3        ; rate * (num_blocks >> 32)
        vpsllq  ymm3, ymm3, 32
        vpmuludq        ymm2, ymm2, ymm1        ; rate * (num_blocks & ~0U)
        vpaddq  ymm2, ymm2, ymm3        ; bytes consumed per lane
        vmovdqa ymm3, [state + _sha3_lens]
        vpsubq  ymm3, ymm3, ymm2
        vmovdqa [state + _sha3_lens], ymm3
        vmovdqa ymm2, [state + _sha3_blocks]
        vpsubq  ymm2, ymm2, ymm1
        vmovdqa [state + _sha3_blocks], ymm2

        mov     r8,  [state + _sha3_args_data_ptr + 0*8]
        mov     r9,  [state + _sha3_args_data_ptr + 1*8]
        mov     r10, [state + _sha3_args_data_ptr + 2*8]
        mov     r11, [state + _sha3_args_data_ptr + 3*8]
align_loop
.absorb_loop:
        call    sha3_mb_absorb_x4
        lea     rdi, [state + _sha3_args_kstate]
        call    keccak_f1600_x4_avx2
        dec     num_blocks
        jnz     .absorb_loop

        mov     [state + _sha3_args_data_ptr + 0*8], r8
        mov     [state + _sha3_args_data_ptr + 1*8], r9
        mov     [state + _sha3_args_data_ptr + 2*8], r10
        mov     [state + _sha3_args_data_ptr + 3*8], r11

align_label
.no_absorb:
        ;; ------------------------------------------------------------
        ;; Finalize the minimum lane if padding has not been applied yet
        ;; ------------------------------------------------------------
        mov     remaining, [state + _sha3_lens + min_idx*8]

        imul    r10, min_idx, _SHA3_LANE_DATA_size

        ;; A finalized lane holds exactly blocks*rate bytes, and min_idx is the
        ;; lane the block count was taken from, so its remainder is now zero and
        ;; the job is complete.
        cmp     dword [state + _sha3_ldata + r10 + _sha3_finalized], 1
        je      .complete

        lea     r8, [state + _sha3_ldata + r10 + _sha3_extra_block]
        SHA3_MB_ZERO_EXTRA_BLOCK        r8

        ;; Copy the trailing partial block (0..rate-1 bytes) into extra_block.
        ;; The width steps down 32 -> 8 -> 1 byte, so no byte past the end of
        ;; the message is ever read.
        mov     r9, [state + _sha3_args_data_ptr + min_idx*8]
        mov     rcx, remaining
        xor     eax, eax

align_loop
.copy_loop:
        cmp     rcx, 32
        jb      .copy_qwords
        vmovdqu ymm0, [r9 + rax]
        vmovdqu [r8 + rax], ymm0
        add     rax, 32
        sub     rcx, 32
        jmp     .copy_loop

align_loop
.copy_qwords:
        cmp     rcx, 8
        jb      .copy_bytes
        mov     rdx, [r9 + rax]
        mov     [r8 + rax], rdx
        add     rax, 8
        sub     rcx, 8
        jmp     .copy_qwords

align_loop
.copy_bytes:
        test    rcx, rcx
        jz      .copy_done
        mov     dl, [r9 + rax]
        mov     [r8 + rax], dl
        inc     rax
        dec     rcx
        jmp     .copy_bytes

align_label
.copy_done:
        add     r8, remaining   ; r8 = &extra_block[remaining]

        ;; domain separation byte at extra_block[remaining]
        mov     al, byte [state + _sha3_args_pad + min_idx*8]
        xor     byte [r8], al

        ;; end-of-message bit at extra_block[rate - 1]
        mov     rcx, [state + _sha3_args_rate + min_idx*8]
        lea     rdx, [state + _sha3_ldata + r10 + _sha3_extra_block]
        xor     byte [rdx + rcx - 1], 0x80

        ;; absorb the padding block on the next pass
        mov     [state + _sha3_args_data_ptr + min_idx*8], rdx
        mov     [state + _sha3_lens + min_idx*8], rcx
        mov     qword [state + _sha3_blocks + min_idx*8], 1

        mov     dword [state + _sha3_ldata + r10 + _sha3_finalized], 1
        jmp     .do_loop        ; lens = rate > 0, no need to re-test

align_label
.complete:
        ;; ============================================================
        ;; Completion: release the lane and squeeze the output
        ;; ============================================================
        mov     rax, [state + _sha3_args_rate + min_idx*8]
        mov     [rsp + _SQ_RATE], rax

        mov     rcx, [state + _sha3_unused_lanes]
        shl     rcx, 4
        or      rcx, min_idx
        mov     [state + _sha3_unused_lanes], rcx
        dec     dword [state + _sha3_num_lanes_inuse]

        ;; De-interleave the finishing lane into the contiguous scratch buffer
        ;; so that an arbitrary output length can be copied from it.
%assign _W 0
%rep 25
        mov     rcx, [state + _sha3_args_kstate + _W*32 + min_idx*8]
        mov     [rsp + _SQ_SCRATCH + _W*8], rcx
%assign _W (_W+1)
%endrep

        imul    lane, min_idx, _SHA3_LANE_DATA_size     ; lane = ldata[] offset
        mov     rax, [state + _sha3_ldata + lane + _sha3_job_in_lane]
        mov     outlen,  [rax + _auth_tag_output_len_in_bytes]
        mov     out_ptr, [rax + _auth_tag_output]

align_loop
.squeeze_loop:
        ;; emit min(outlen, rate) bytes of the current block
        mov     rcx, [rsp + _SQ_RATE]
        cmp     outlen, rcx
        cmovb   rcx, outlen
        xor     rax, rax
        ;; The width steps down 32 -> 8 -> 1 byte, so no byte past the end of
        ;; the caller's output buffer is ever written.  AVX2 has no byte
        ;; granular masked store, so the last 0..7 bytes stay scalar.
align_loop
.squeeze_copy:
        cmp     rcx, 32
        jb      .squeeze_copy_qwords
        vmovdqa ymm0, [rsp + _SQ_SCRATCH + rax]
        vmovdqu [out_ptr + rax], ymm0
        add     rax, 32
        sub     rcx, 32
        jmp     .squeeze_copy

align_loop
.squeeze_copy_qwords:
        cmp     rcx, 8
        jb      .squeeze_copy_bytes
        mov     rdx, [rsp + _SQ_SCRATCH + rax]
        mov     [out_ptr + rax], rdx
        add     rax, 8
        sub     rcx, 8
        jmp     .squeeze_copy_qwords

align_loop
.squeeze_copy_bytes:
        test    rcx, rcx
        jz      .squeeze_emitted
        mov     dl, [rsp + _SQ_SCRATCH + rax]
        mov     [out_ptr + rax], dl
        inc     rax
        dec     rcx
        jmp     .squeeze_copy_bytes

align_label
.squeeze_emitted:
        add     out_ptr, rax
        sub     outlen, rax
        jz      .squeeze_done

        ;; more output requested than one block: permute and continue.
        ;; The permutation is only available in 4-lane form, so the state is
        ;; broadcast into all four slots of a private buffer and lane 0 of the
        ;; result is read back.
%assign _W 0
%rep 25
        vpbroadcastq    ymm0, [rsp + _SQ_SCRATCH + _W*8]
        vmovdqa [rsp + _SQ_INTER + _W*32], ymm0
%assign _W (_W+1)
%endrep
        lea     rdi, [rsp + _SQ_INTER]
        call    keccak_f1600_x4_avx2
%assign _W 0
%rep 25
        mov     rcx, [rsp + _SQ_INTER + _W*32]
        mov     [rsp + _SQ_SCRATCH + _W*8], rcx
%assign _W (_W+1)
%endrep
        jmp     .squeeze_loop

align_label
.squeeze_done:
        mov     rax, [state + _sha3_ldata + lane + _sha3_job_in_lane]
        or      dword [rax + _status], IMB_STATUS_COMPLETED_AUTH
        mov     qword [state + _sha3_ldata + lane + _sha3_job_in_lane], 0

%ifdef SAFE_DATA
        ;; clear message and digest material left behind
        lea     rcx, [state + _sha3_ldata + lane + _sha3_extra_block]
        SHA3_MB_ZERO_EXTRA_BLOCK        rcx

        vpxor   ymm0, ymm0, ymm0
        vmovdqa [rsp + _SQ_SCRATCH + 0*32], ymm0
        vmovdqa [rsp + _SQ_SCRATCH + 1*32], ymm0
        vmovdqa [rsp + _SQ_SCRATCH + 2*32], ymm0
        vmovdqa [rsp + _SQ_SCRATCH + 3*32], ymm0
        vmovdqa [rsp + _SQ_SCRATCH + 4*32], ymm0
        vmovdqa [rsp + _SQ_SCRATCH + 5*32], ymm0
        vmovdqa [rsp + _SQ_SCRATCH + 6*32], ymm0

%assign _W 0
%rep 25
        vmovdqa [rsp + _SQ_INTER + _W*32], ymm0
%assign _W (_W+1)
%endrep
%endif  ; SAFE_DATA

        ;; Zero the slice of the shared interleaved state belonging to every
        ;; lane that now holds no job, the one just finished included.
        ;;
        ;; Clearing only the finishing lane would not be enough: an unoccupied
        ;; lane is still carried through every permutation the occupied ones
        ;; ask for, so its words do not stay zero.
        vmovq   xmm2, [state + _sha3_ldata + 0*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        vpinsrq xmm2, xmm2, [state + _sha3_ldata + 1*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 1
        vmovq   xmm4, [state + _sha3_ldata + 2*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        vpinsrq xmm4, xmm4, [state + _sha3_ldata + 3*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 1
        vinserti128     ymm2, ymm2, xmm4, 1
        vpxor   ymm4, ymm4, ymm4
        vpcmpeqq        ymm2, ymm2, ymm4        ; all-ones where job_in_lane == 0
%assign _W 0
%rep 25
        vmovdqu ymm3, [state + _sha3_args_kstate + _W*32]
        vpandn  ymm3, ymm2, ymm3
        vmovdqu [state + _sha3_args_kstate + _W*32], ymm3
%assign _W (_W+1)
%endrep

        mov     rsp, [rsp + _SAVED_RSP]
        ret

; ============================================================
; SHA3_MB_SUBMIT_FLUSH_FN  fn_name, is_submit
;
;   submit: IMB_JOB *fn(MB_MGR_SHA3_OOO *state, IMB_JOB *job)
;   flush : IMB_JOB *fn(MB_MGR_SHA3_OOO *state, IMB_JOB *unused)
;
; The output length is taken from job->auth_tag_output_len_in_bytes, which the
; job validation layer pins to the digest size for SHA3 and leaves free for
; SHAKE.  A single squeeze loop therefore serves both.
; ============================================================
%macro SHA3_MB_SUBMIT_FLUSH_FN 2
%define %%FN    %1
%define %%SUB   %2

align_function
MKGLOBAL(%%FN,function,internal)
%%FN:
        push    r15
        push    r14
        push    r13
        push    r12
        push    rbx
        push    rbp
%ifidn __OUTPUT_FORMAT__, win64
        push    rdi
        push    rsi
        sub     rsp, _XMM_SAVE_SIZE
%assign %%I 0
%rep 10
%assign %%X (6 + %%I)
        vmovdqu [rsp + %%I*16], APPEND(xmm, %%X)
%assign %%I (%%I + 1)
%endrep
%endif
        mov     state, arg1
%ifndef LINUX
        mov     job, arg2
%endif

%if %%SUB
        ;; ------------------------------------------------------------
        ;; SUBMIT: allocate a free lane and record the job parameters
        ;; ------------------------------------------------------------
        mov     rax, [state + _sha3_unused_lanes]
        mov     min_idx, rax
        and     min_idx, 0xF    ; lane index in the low nibble
        shr     rax, 4
        mov     [state + _sha3_unused_lanes], rax
        inc     dword [state + _sha3_num_lanes_inuse]

        ;; Rate, domain separation byte, message length and block count of
        ;; this lane, all derived from the job's algorithm.
        SHA3_MB_SET_LANE_PARAMS state, job, min_idx, r8

        mov     rax, [job + _src]
        add     rax, [job + _hash_start_src_offset_in_bytes]
        mov     [state + _sha3_args_data_ptr + min_idx*8], rax

        ;; No need to zero this lane's slice of the interleaved kstate: the core
        ;; leaves every unoccupied lane zeroed on its way out.

        imul    rax, min_idx, _SHA3_LANE_DATA_size
        mov     [state + _sha3_ldata + rax + _sha3_job_in_lane], job
        mov     dword [state + _sha3_ldata + rax + _sha3_finalized], 0

        cmp     dword [state + _sha3_num_lanes_inuse], MAX_SHA3_LANES
        jne     %%ret_null
%else
        ;; ------------------------------------------------------------
        ;; FLUSH: pick the lowest occupied lane (branch-free)
        ;; ------------------------------------------------------------
        cmp     dword [state + _sha3_num_lanes_inuse], 0
        je      %%ret_null
        mov     DWORD(lane), 3
        mov     eax, 2
        cmp     qword [state + _sha3_ldata + 2*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 0
        cmovne  DWORD(lane), eax
        mov     eax, 1
        cmp     qword [state + _sha3_ldata + 1*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 0
        cmovne  DWORD(lane), eax
        xor     eax, eax
        cmp     qword [state + _sha3_ldata + 0*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 0
        cmovne  DWORD(lane), eax

        ;; Lanes holding no job are given a rate of zero, which makes every one
        ;; of the absorb's masked loads read nothing and leaves their input
        ;; pointer where it is, and a block count of UINT64_MAX so that they can
        ;; never win the minimum search.  A lane can only be released on the way
        ;; out of the core, so this holds for the whole of the core's loop and
        ;; belongs here rather than inside it.
        vmovq   xmm0, [state + _sha3_ldata + 0*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        vpinsrq xmm0, xmm0, [state + _sha3_ldata + 1*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 1
        vmovq   xmm1, [state + _sha3_ldata + 2*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        vpinsrq xmm1, xmm1, [state + _sha3_ldata + 3*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 1
        vinserti128     ymm0, ymm0, xmm1, 1
        vpxor   ymm1, ymm1, ymm1
        vpcmpeqq        ymm0, ymm0, ymm1        ; all-ones for lanes with no job

        vmovdqa ymm3, [state + _sha3_args_rate]
        vpandn  ymm3, ymm0, ymm3        ; rate = 0
        vmovdqa [state + _sha3_args_rate], ymm3

        ;; nothing is read through them, but keep the pointers of the idle lanes
        ;; pointing at real memory rather than at the NULL left by the reset
        vpbroadcastq    ymm2, [state + _sha3_args_data_ptr + lane*8]
        vmovdqa ymm3, [state + _sha3_args_data_ptr]
        vpblendvb       ymm3, ymm3, ymm2, ymm0
        vmovdqa [state + _sha3_args_data_ptr], ymm3

        vpcmpeqd        ymm2, ymm2, ymm2        ; all-ones = UINT64_MAX
        vmovdqa ymm3, [state + _sha3_blocks]
        vpblendvb       ymm3, ymm3, ymm2, ymm0
        vmovdqa [state + _sha3_blocks], ymm3
%endif

        call    sha3_mb_core_avx2

align_label
%%return:
%ifdef SAFE_DATA
        ;; The interleaved state left in the vector registers still holds
        ;; material belonging to the jobs in the other lanes.  Cleared here,
        ;; before the Windows non-volatile XMMs are restored below.
        clear_all_ymms_asm
%else
        vzeroupper
%endif
%ifidn __OUTPUT_FORMAT__, win64
%assign %%I 0
%rep 10
%assign %%X (6 + %%I)
        vmovdqu APPEND(xmm, %%X), [rsp + %%I*16]
%assign %%I (%%I + 1)
%endrep
        add     rsp, _XMM_SAVE_SIZE
        pop     rsi
        pop     rdi
%endif
        pop     rbp
        pop     rbx
        pop     r12
        pop     r13
        pop     r14
        pop     r15
        ret

align_label
%%ret_null:
        xor     eax, eax
        jmp     %%return
%endmacro

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
        vpxor   ymm5,  ymm5,  [rdi +20*32]      ; C[0]

        vmovdqu ymm6,  [rdi + 1*32]
        vpxor   ymm6,  ymm6,  [rdi + 6*32]
        vpxor   ymm6,  ymm6,  [rdi +11*32]
        vpxor   ymm6,  ymm6,  [rdi +16*32]
        vpxor   ymm6,  ymm6,  [rdi +21*32]      ; C[1]

        vmovdqu ymm7,  [rdi + 2*32]
        vpxor   ymm7,  ymm7,  [rdi + 7*32]
        vpxor   ymm7,  ymm7,  [rdi +12*32]
        vpxor   ymm7,  ymm7,  [rdi +17*32]
        vpxor   ymm7,  ymm7,  [rdi +22*32]      ; C[2]

        vmovdqu ymm8,  [rdi + 3*32]
        vpxor   ymm8,  ymm8,  [rdi + 8*32]
        vpxor   ymm8,  ymm8,  [rdi +13*32]
        vpxor   ymm8,  ymm8,  [rdi +18*32]
        vpxor   ymm8,  ymm8,  [rdi +23*32]      ; C[3]

        vmovdqu ymm9,  [rdi + 4*32]
        vpxor   ymm9,  ymm9,  [rdi + 9*32]
        vpxor   ymm9,  ymm9,  [rdi +14*32]
        vpxor   ymm9,  ymm9,  [rdi +19*32]
        vpxor   ymm9,  ymm9,  [rdi +24*32]      ; C[4]

        mov     rax, 24 ; 24 rounds

align_loop
kf1600_x4_avx2_loop:
        KF_ROUND        rdi, rsi, \
                        ymm5, ymm6, ymm7, ymm8, ymm9, \
                        ymm10, ymm11, ymm12, ymm13, ymm14, \
                        ymm15, \
                        ymm0, ymm1, ymm2, ymm3, ymm4
        dec     rax
        jnz     kf1600_x4_avx2_loop

        ret

; ============================================================
; keccak_f1600_x4_avx2_ossl - C/OpenSSL-callable wrapper
;
; keccak_f1600_x4_avx2 uses a private calling convention:
;   arg1 in rdi, freely clobbers rsi and ymm0-ymm15.
; This wrapper makes it safe to call from C:
;   Linux: just calls the inner function and issues vzeroupper
;   Win64: also translates arg1 rcx->rdi and saves/restores
;          rsi and ymm6-ymm15 (callee-saved on Windows)
; ============================================================
align_function
MKGLOBAL(keccak_f1600_x4_avx2_ossl,function,internal)
keccak_f1600_x4_avx2_ossl:
%ifndef LINUX
        push    rdi
        push    rsi
        sub     rsp, 10*32 + 8  ; 10 ymm regs + 8B alignment pad
        vmovdqu [rsp + 0*32], ymm6
        vmovdqu [rsp + 1*32], ymm7
        vmovdqu [rsp + 2*32], ymm8
        vmovdqu [rsp + 3*32], ymm9
        vmovdqu [rsp + 4*32], ymm10
        vmovdqu [rsp + 5*32], ymm11
        vmovdqu [rsp + 6*32], ymm12
        vmovdqu [rsp + 7*32], ymm13
        vmovdqu [rsp + 8*32], ymm14
        vmovdqu [rsp + 9*32], ymm15
        mov     rdi, rcx        ; translate Windows arg1 -> Linux arg1
%endif
        call    keccak_f1600_x4_avx2
%ifndef LINUX
        vmovdqu ymm6,  [rsp + 0*32]
        vmovdqu ymm7,  [rsp + 1*32]
        vmovdqu ymm8,  [rsp + 2*32]
        vmovdqu ymm9,  [rsp + 3*32]
        vmovdqu ymm10, [rsp + 4*32]
        vmovdqu ymm11, [rsp + 5*32]
        vmovdqu ymm12, [rsp + 6*32]
        vmovdqu ymm13, [rsp + 7*32]
        vmovdqu ymm14, [rsp + 8*32]
        vmovdqu ymm15, [rsp + 9*32]
        add     rsp, 10*32 + 8
        pop     rsi
        pop     rdi
%endif
        vzeroupper
        ret

SHA3_MB_SUBMIT_FLUSH_FN submit_job_sha3_avx2, 1
SHA3_MB_SUBMIT_FLUSH_FN flush_job_sha3_avx2,  0


mksection .rodata

; vpshufb byte-shuffle masks for ROL64 by 8 and 56 within each 64-bit lane
align 32
SHA3MB_RHO8_SHUF:
        DQ      0x0605040302010007, 0x0E0D0C0B0A09080F
        DQ      0x0605040302010007, 0x0E0D0C0B0A09080F

align 32
SHA3MB_RHO56_SHUF:
        DQ      0x0007060504030201, 0x080F0E0D0C0B0A09
        DQ      0x0007060504030201, 0x080F0E0D0C0B0A09

; Keccak-f[1600] round constants (24 × 64-bit).
align 32
SHA3MB_RC:
        DQ      0x0000000000000001, 0x0000000000008082
        DQ      0x800000000000808a, 0x8000000080008000
        DQ      0x000000000000808b, 0x0000000080000001
        DQ      0x8000000080008081, 0x8000000000008009
        DQ      0x000000000000008a, 0x0000000000000088
        DQ      0x0000000080008009, 0x000000008000000a
        DQ      0x000000008000808b, 0x800000000000008b
        DQ      0x8000000000008089, 0x8000000000008003
        DQ      0x8000000000008002, 0x8000000000000080
        DQ      0x000000000000800a, 0x800000008000000a
        DQ      0x8000000080008081, 0x8000000000008080
        DQ      0x0000000080000001, 0x8000000080008008

; Qword index vector [0,1,2,3].  Used by the absorb to turn a lane's remaining
; word count into a load mask; it indexes words within a group, not lanes.
align 32
SHA3MB_QWORD_IDX:
        DQ      0, 1, 2, 3

align 32
SHA3MB_FOUR_Q:
        DQ      4, 4, 4, 4

mksection stack-noexec
