; Copyright (c) 2026, Intel Corporation
; All rights reserved.
;
; SPDX-License-Identifier: BSD-3-Clause

; AVX-512 SHA3 / SHAKE multi-buffer (4-lane) submit / flush.
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

default rel

%include "include/sha3_common.inc"
%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/align_avx512.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"

;; arg1..arg4 come from sha3_common.inc
extern keccak1600_block_64bit

; ============================================================
; Named register aliases
; ============================================================
%define state           rbx     ; MB_MGR_SHA3_OOO*                 (callee-saved)
%define lane            r12     ; flush: first occupied lane index (callee-saved)
                                ; after completion: ldata[] byte offset of the
                                ; finishing lane
%define min_idx         r13     ; index of lane with fewest blocks left
%define num_blocks      r14     ; number of whole rate-blocks to absorb
%define remaining       r15     ; bytes left after the whole blocks
%define absorb_end      rbp     ; absorb: input bytes to cover
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
;   rax     scratch throughout: minimum search, the copy/squeeze offset, the
;           ldata[] offset, and the rate in the finalize path
;   rbx     state                                             (callee-saved)
;   rcx     scratch throughout: absorb mask build, byte counters, the
;           unused_lanes shuffle, the squeeze copies
;   rdx     scratch: absorb mask build, and the bzhi counts of the tail copies
;   rsi     job                                               (win64: saved)
;   rdi     unused; Linux arg1 is consumed into state at entry
;                                                             (win64: saved)
;   rbp     absorb_end during the absorb, outlen during the squeeze
;                                                             (callee-saved)
;   r8-r11  lane 0-3 input pointers for the whole absorb loop.  They are
;           reloaded from _sha3_args_data_ptr on entry to the loop and written
;           back on exit, so outside it they are free: the finalize path uses
;           r8 (destination) and r9 (source) as plain scratch, and submit hands
;           r8 to SHA3_MB_SET_LANE_PARAMS
;   r12     lane                                              (callee-saved)
;   r13     min_idx, but keccak1600_block_64bit uses r13d as its round
;           counter, so the absorb loop saves and restores it across the call
;                                                             (callee-saved)
;   r14     num_blocks, likewise clobbered by keccak1600_block_64bit as its
;           round-constant pointer                            (callee-saved)
;   r15     remaining during the absorb, out_ptr during the squeeze
;                                                             (callee-saved)
;
;   ymm0-ymm24      interleaved keccak state, held in registers for the whole
;                   absorb loop; during a SHAKE squeeze the same registers hold
;                   the finishing lane on its own, in xmm0-xmm24
;   ymm25-ymm31     absorb and keccak1600_block_64bit temporaries
;   ymm30, ymm31    completion, SAFE_DATA and tail-copy temporaries
;   ymm0-ymm3       flush prologue
;                                       (win64: xmm6-xmm15 saved by submit and
;                                        flush, so all 32 are usable)
;
;   k1      scratch mask (absorb group mask, every tail copy)
;   k2      flush: lanes holding no job
;   k4-k7   lane 0-3 rate coverage bitmaps, live for the whole of the core
;
; SHA3_MB_SET_LANE_PARAMS clobbers rax, rcx, rdx and the temporary it is
; given, and it divides, so its lane argument must not be rax or rdx.
; ============================================================

; Maximum sponge rate across all variants, in 64-bit state words
%define KECCAK_MAX_RATE_WORDS   (SHAKE128_RATE / 8)     ; 21
; The absorb reads the lanes in groups of four 64-bit words (ymm)
%define KECCAK_ABSORB_GROUPS    ((KECCAK_MAX_RATE_WORDS + 3) / 4)       ; 6

; ============================================================
; Stack frame (identical for submit and flush)
;
;   [rsp + _SQ_SCRATCH]  200 B used / 224 B reserved: the completing lane's 25
;                        state words, laid out contiguously so that a
;                        runtime-length copy to the output is possible
;   [rsp + _SQ_RATE]     completing lane's rate (survives keccak calls)
;   [rsp + _SAVED_RSP]   RSP before the alignment
;
; The frame belongs to sha3_mb_core_avx512 and is allocated by it, so nothing
; in submit or flush depends on these offsets.
; ============================================================
%define _SQ_SCRATCH     0
%define _SQ_RATE        (_SQ_SCRATCH + 224)
%define _SAVED_RSP      (_SQ_RATE + 8)
%define FRAME_SIZE      (_SAVED_RSP + 8)

; Windows only: xmm6-xmm15 are saved by submit/flush, below their GPR pushes.
%define _XMM_SAVE_SIZE  (10 * 16)

mksection .text

; ============================================================
; 4-lane absorb, one block per lane at the lane's own rate.
;
; A single routine covers every rate.  The four lanes are read with plain
; masked loads - four 4-word chunks, one per lane - and transposed into the
; interleaved state layout.  k4-k7 hold, one per lane, a bitmap of the state
; words that lane's rate covers, so the write mask of a group is just that
; bitmap shifted down by the group's first word.  A masked-off element of
; VMOVDQU64 performs no memory access, which is what makes it safe to run the
; same 4-word group for a lane whose rate ends inside it, or does not reach it
; at all: those words are XORed with zero and nothing is read for them.
;
;   in/out : ymm0-ymm24  interleaved keccak state
;   in/out : r8-r11      lane 0-3 input pointers
;   in     : k4-k7       lane 0-3 word coverage masks
;   in     : absorb_end  input bytes to cover, rounded up to a whole group
;   clobber: k1, ymm25-ymm31
; ============================================================
align_function
sha3_mb_absorb_x4:
%assign _G 0
%rep KECCAK_ABSORB_GROUPS
%if _G > 0
        cmp     absorb_end, _G*32
        jbe     .done
%endif
        ;; A lane whose rate does not reach this group has an all-zero mask, and
        ;; its load is skipped rather than issued with that mask, so no address
        ;; beyond the end of its input is ever formed.  The register still has
        ;; to be cleared, because the transpose below XORs all four lanes into
        ;; the state, so it is zeroed up front.
%assign _L 0
%rep 4
%assign _KR (4 + _L)    ; k4-k7 = lane 0-3 coverage masks
%assign _YD (25 + _L)   ; ymm25-ymm28 = lane 0-3 input words
%assign _PT (8 + _L)    ; r8-r11 = lane 0-3 input pointers
        vpxorq  APPEND(ymm, _YD), APPEND(ymm, _YD), APPEND(ymm, _YD)
        kshiftrd        k1, APPEND(k, _KR), _G*4
        ktestd  k1, k1
        jz      .no_input_l %+ _L %+ _g %+ _G
        vmovdqu64       APPEND(ymm, _YD){k1}{z}, [APPEND(r, _PT) + _G*32]
.no_input_l %+ _L %+ _g %+ _G :
%assign _L (_L+1)
%endrep

        ;; 4x4 transpose of the 64-bit words and add to the state
        vpunpcklqdq     ymm29, ymm25, ymm26
        vpunpckhqdq     ymm30, ymm25, ymm26
        vpunpcklqdq     ymm31, ymm27, ymm28
        vpunpckhqdq     ymm25, ymm27, ymm28

        vshufi64x2      ymm26, ymm29, ymm31, 0x0
%assign _W (_G*4)
        vpxorq  APPEND(ymm,_W), APPEND(ymm,_W), ymm26

        vshufi64x2      ymm27, ymm29, ymm31, 0x3
%assign _W (_G*4+2)
        vpxorq  APPEND(ymm,_W), APPEND(ymm,_W), ymm27

        vshufi64x2      ymm28, ymm30, ymm25, 0x0
%assign _W (_G*4+1)
        vpxorq  APPEND(ymm,_W), APPEND(ymm,_W), ymm28

        vshufi64x2      ymm29, ymm30, ymm25, 0x3
%assign _W (_G*4+3)
        vpxorq  APPEND(ymm,_W), APPEND(ymm,_W), ymm29

%assign _G (_G+1)
%endrep

align_label
.done:
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
;   clobber: ymm31
; ============================================================
%macro SHA3_MB_ZERO_EXTRA_BLOCK 1
        vpxorq  ymm31, ymm31, ymm31
        vmovdqu64       [%1 + 0*32], ymm31
        vmovdqu64       [%1 + 1*32], ymm31
        vmovdqu64       [%1 + 2*32], ymm31
        vmovdqu64       [%1 + 3*32], ymm31
        vmovdqu64       [%1 + 4*32], ymm31
        vmovq   [%1 + 5*32], xmm31      ; bytes 160..167
%endmacro

; ============================================================
; sha3_mb_core_avx512
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
;   in  : state (rbx)   MB_MGR_SHA3_OOO*
;   out : rax           the IMB_JOB* that completed
; ============================================================
align_function
sha3_mb_core_avx512:
        mov     rax, rsp
        sub     rsp, FRAME_SIZE
        and     rsp, -32
        mov     [rsp + _SAVED_RSP], rax

        ; ============================================================
        ; Absorb preparation
        ;
        ; k4-k7 = per-lane bitmap of the state words that lane's rate covers,
        ; and absorb_end = the widest rate in use, rounded up to a whole group.
        ;
        ;   in     : state
        ;
        ; The lane rates do not change while the core runs, so this is done once here
        ; rather than on every pass of the loop below.
        ;   out    : k4-k7, absorb_end
        ;   clobber: rax, rcx, rdx
        ; ============================================================
        mov     eax, -1
        xor     absorb_end, absorb_end
%assign _L 0
%rep 4
        mov     ecx, dword [state + _sha3_args_rate + _L*8]
        cmp     rcx, absorb_end
        cmova   absorb_end, rcx
        shr     ecx, 3  ; rate in 64-bit words
        bzhi    edx, eax, ecx
%assign _K (4 + _L)
        kmovd   APPEND(k,_K), edx
%assign _L (_L+1)
%endrep
        add     absorb_end, 31
        and     absorb_end, -32

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

        ;; Each lane consumes num_blocks blocks of its own rate
        vpbroadcastq    ymm25, num_blocks
        vmovdqa64       ymm26, [state + _sha3_args_rate]
        vpmullq ymm26, ymm26, ymm25     ; bytes consumed per lane
        vmovdqa64       ymm27, [state + _sha3_lens]
        vpsubq  ymm27, ymm27, ymm26
        vmovdqa64       [state + _sha3_lens], ymm27
        vmovdqa64       ymm26, [state + _sha3_blocks]
        vpsubq  ymm26, ymm26, ymm25
        vmovdqa64       [state + _sha3_blocks], ymm26

        ;; load the interleaved state into ymm0-ymm24, where it stays for the
        ;; whole absorb loop
%assign _I 0
%rep 25
        vmovdqu64       APPEND(ymm, _I), [state + _sha3_args_kstate + _I*32]
%assign _I (_I+1)
%endrep

        mov     r8,  [state + _sha3_args_data_ptr + 0*8]
        mov     r9,  [state + _sha3_args_data_ptr + 1*8]
        mov     r10, [state + _sha3_args_data_ptr + 2*8]
        mov     r11, [state + _sha3_args_data_ptr + 3*8]
align_loop
.absorb_loop:
        call    sha3_mb_absorb_x4
        push    min_idx         ; keccak1600_block_64bit clobbers
        push    num_blocks      ; r13 (round counter) and r14 (RC ptr)
        call    keccak1600_block_64bit
        pop     num_blocks
        pop     min_idx
        dec     num_blocks
        jnz     .absorb_loop

%assign _I 0
%rep 25
        vmovdqu64       [state + _sha3_args_kstate + _I*32], APPEND(ymm, _I)
%assign _I (_I+1)
%endrep
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

        imul    rax, min_idx, _SHA3_LANE_DATA_size
        ;; A finalized lane holds exactly blocks*rate bytes, and min_idx is the
        ;; lane the block count was taken from, so its remainder is now zero and
        ;; the job is complete.
        cmp     dword [state + _sha3_ldata + rax + _sha3_finalized], 1
        je      .complete

        lea     r8, [state + _sha3_ldata + rax + _sha3_extra_block]
        SHA3_MB_ZERO_EXTRA_BLOCK        r8

        ;; Copy the trailing partial block (0..rate-1 bytes) into extra_block.
        ;; The tail is masked rather than rounded up, so no byte past the end
        ;; of the message is ever read.
        mov     r9, [state + _sha3_args_data_ptr + min_idx*8]
        mov     rcx, remaining
        xor     eax, eax
        cmp     rcx, 32
        jb      .copy_tail
align_loop
.copy_loop:
        vmovdqu64       ymm31, [r9 + rax]
        vmovdqu64       [r8 + rax], ymm31
        add     rax, 32
        sub     rcx, 32
        cmp     rcx, 32
        jae     .copy_loop
align_label
.copy_tail:
        mov     edx, -1
        bzhi    edx, edx, ecx
        kmovd   k1, edx
        vmovdqu8        ymm31{k1}{z}, [r9 + rax]
        vmovdqu8        [r8 + rax]{k1}, ymm31

        ;; domain separation byte at extra_block[remaining]
        mov     al, byte [state + _sha3_args_pad + min_idx*8]
        xor     byte [r8 + remaining], al       ; &extra_block[remaining]

        ;; end-of-message bit at extra_block[rate - 1]
        mov     rax, [state + _sha3_args_rate + min_idx*8]
        xor     byte [r8 + rax - 1], 0x80

        ;; absorb the padding block on the next pass
        mov     [state + _sha3_args_data_ptr + min_idx*8], r8
        mov     [state + _sha3_lens + min_idx*8], rax
        mov     qword [state + _sha3_blocks + min_idx*8], 1

        imul    rax, min_idx, _SHA3_LANE_DATA_size
        mov     dword [state + _sha3_ldata + rax + _sha3_finalized], 1
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

        ;; Single-block output path.  Every rate is at least 72 bytes, so any
        ;; request of 64 bytes or less is covered by the block already in the
        ;; state.  That is every SHA3 digest, and also any SHAKE job asking for
        ;; 64 bytes or less.  Copy straight out of the interleaved state: going
        ;; through the scratch buffer would stall on store-to-load forwarding.
        imul    lane, min_idx, _SHA3_LANE_DATA_size     ; lane = ldata[] offset
        mov     rax, [state + _sha3_ldata + lane + _sha3_job_in_lane]
        mov     outlen,  [rax + _auth_tag_output_len_in_bytes]
        mov     out_ptr, [rax + _auth_tag_output]

        cmp     outlen, 64
        ja      .squeeze_long_shake

        ;; Single-block output path
        lea     rax, [min_idx*8]        ; byte offset into the interleaved state
        mov     rdx, outlen
        cmp     rdx, 8
        jb      .squeeze_one_block_tail

align_loop
.squeeze_one_block_loop:
        mov     rcx, [state + _sha3_args_kstate + rax]
        mov     [out_ptr], rcx
        add     rax, 32
        add     out_ptr, 8
        sub     rdx, 8
        cmp     rdx, 8
        jae     .squeeze_one_block_loop

align_label
.squeeze_one_block_tail:
        test    edx, edx        ; rdx = outlen & 7, and is what bzhi consumes
        jz      .squeeze_done
        vmovq   xmm31, [state + _sha3_args_kstate + rax]
        mov     ecx, -1
        bzhi    ecx, ecx, edx
        kmovb   k1, ecx
        vmovdqu8        [out_ptr]{k1}, xmm31
        jmp     .squeeze_done

        ;; Multi-block (long SHAKE) output path

        ;; De-interleave the finishing lane into the contiguous scratch buffer
        ;; so that an arbitrary output length can be copied from it.
align_label
.squeeze_long_shake:

        ;; load state into xmm registers and save in linear buffer for squeezing
%assign _W 0
%rep 25
        vmovq   APPEND(xmm, _W), [state + _sha3_args_kstate + _W*32 + min_idx*8]
        vmovq   [rsp + _SQ_SCRATCH + _W*8], APPEND(xmm, _W)
%assign _W (_W+1)
%endrep

align_loop
.squeeze_loop:
        ;; emit min(outlen, rate) bytes of the current block
        mov     rcx, [rsp + _SQ_RATE]
        cmp     outlen, rcx
        cmovb   rcx, outlen
        xor     rax, rax
align_loop
.squeeze_copy:
        cmp     rcx, 32
        jb      .squeeze_copy_tail
        vmovdqu64       ymm31, [rsp + _SQ_SCRATCH + rax]
        vmovdqu64       [out_ptr + rax], ymm31
        add     rax, 32
        sub     rcx, 32
        jmp     .squeeze_copy

align_label
.squeeze_copy_tail:
        test    rcx, rcx
        jz      .squeeze_emitted
        mov     edx, -1
        bzhi    edx, edx, ecx
        kmovd   k1, edx
        vmovdqu8        ymm31{k1}{z}, [rsp + _SQ_SCRATCH + rax]
        vmovdqu8        [out_ptr + rax]{k1}, ymm31
        add     rax, rcx

align_label
.squeeze_emitted:
        add     out_ptr, rax
        sub     outlen, rax
        jz      .squeeze_done

        ;; more output requested than one block: permute and continue
        call    keccak1600_block_64bit
%assign _W 0
%rep 25
        vmovq   [rsp + _SQ_SCRATCH + _W*8], APPEND(xmm, _W)
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

        vpxorq  ymm31, ymm31, ymm31
        vmovdqu64       [rsp + _SQ_SCRATCH + 0*32], ymm31
        vmovdqu64       [rsp + _SQ_SCRATCH + 1*32], ymm31
        vmovdqu64       [rsp + _SQ_SCRATCH + 2*32], ymm31
        vmovdqu64       [rsp + _SQ_SCRATCH + 3*32], ymm31
        vmovdqu64       [rsp + _SQ_SCRATCH + 4*32], ymm31
        vmovdqu64       [rsp + _SQ_SCRATCH + 5*32], ymm31
        vmovdqu64       [rsp + _SQ_SCRATCH + 6*32], ymm31

%endif  ; SAFE_DATA

        ;; Zero the slice of the shared interleaved state belonging to every
        ;; lane that now holds no job, the one just finished included.
        ;;
        ;; Clearing only the finishing lane would not be enough: an unoccupied
        ;; lane is still carried through every permutation the occupied ones
        ;; ask for, so its words do not stay zero.  The core is only ever
        ;; entered with work to do and only ever leaves from here, which makes
        ;; this the one place where "no job" implies "state is zero", and lets
        ;; submit hand a lane out without touching the state at all.
        vmovq   xmm0, [state + _sha3_ldata + 0*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        vpinsrq xmm0, xmm0, [state + _sha3_ldata + 1*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 1
        vmovq   xmm1, [state + _sha3_ldata + 2*_SHA3_LANE_DATA_size + _sha3_job_in_lane]
        vpinsrq xmm1, xmm1, [state + _sha3_ldata + 3*_SHA3_LANE_DATA_size + _sha3_job_in_lane], 1
        vinserti128     ymm0, ymm0, xmm1, 1
        vptestnmq       k1, ymm0, ymm0  ; set where job_in_lane == 0
        vpxorq  ymm31, ymm31, ymm31
%assign _W 0
%rep 25
        vmovdqu64       ymm30, [state + _sha3_args_kstate + _W*32]
        vmovdqu64       ymm30 {k1}, ymm31
        vmovdqu64       [state + _sha3_args_kstate + _W*32], ymm30
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
;
; Note: keccak1600_block_64bit clobbers r13 (min_idx) and r14 (num_blocks);
; the absorb loop saves and restores them around each call, and the squeeze
; phase keeps nothing live in them.
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
        vmovdqu64       [rsp + %%I*16], APPEND(xmm, %%X)
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
        vinserti32x4    ymm0, ymm0, xmm1, 1
        vpxorq  ymm1, ymm1, ymm1
        vpcmpeqq        k2, ymm0, ymm1  ; k2 = lanes with no job

        vmovdqa64       ymm3, [state + _sha3_args_rate]
        vmovdqa64       ymm3 {k2}, ymm1 ; rate = 0
        vmovdqa64       [state + _sha3_args_rate], ymm3

        ;; nothing is read through them, but keep the pointers of the idle lanes
        ;; pointing at real memory rather than at the NULL left by the reset
        vpbroadcastq    ymm2, [state + _sha3_args_data_ptr + lane*8]
        vmovdqa64       ymm3, [state + _sha3_args_data_ptr]
        vmovdqa64       ymm3 {k2}, ymm2
        vmovdqa64       [state + _sha3_args_data_ptr], ymm3

        vpternlogq      ymm2, ymm2, ymm2, 0xFF  ; all-ones = UINT64_MAX
        vmovdqa64       ymm3, [state + _sha3_blocks]
        vmovdqa64       ymm3 {k2}, ymm2
        vmovdqa64       [state + _sha3_blocks], ymm3
%endif

        call    sha3_mb_core_avx512

align_label
%%return:
%ifdef SAFE_DATA
        ;; The interleaved state left in the vector registers still holds
        ;; material belonging to the jobs in the other lanes, and on the
        ;; SHAKE path xmm0-xmm24 still hold the finishing lane's sponge.
        ;; Cleared here, before the Windows non-volatile XMMs are restored.
        clear_scratch_zmms_asm
%else
        vzeroupper
%endif
%ifidn __OUTPUT_FORMAT__, win64
%assign %%I 0
%rep 10
%assign %%X (6 + %%I)
        vmovdqu64       APPEND(xmm, %%X), [rsp + %%I*16]
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

SHA3_MB_SUBMIT_FLUSH_FN submit_job_sha3_avx512, 1
SHA3_MB_SUBMIT_FLUSH_FN flush_job_sha3_avx512,  0

mksection stack-noexec
