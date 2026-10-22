;;
;; Copyright (c) 2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;; SNOW5G-NCA4 2-buffer Submit/Flush functions for AVX512

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/clear_regs.inc"
%include "include/cet.inc"
%include "include/align_avx512.inc"
%include "include/snow5g_x2_vaes_avx512.inc"
%include "include/polyval_vclmul_avx512.inc"

;; Per-lane phases.  POLYVAL runs over ciphertext (enc: output; dec: input).
;; Transitions:
;;   IDLE    -> STASHED   job arrives, inputs stashed
;;   STASHED -> CIPHER    SNOW5G init + AAD hash into POLYVAL accumulator;
;;                        dec also hashes+finalizes
;;                        the whole input -> tag in digest[] (before in-place cipher)
;;   CIPHER  -> IDLE      enc: fold output into polyval_acc, tail+finalize -> tag
;;                        dec: cipher-only, reload tag from digest[]
;;                        job retired, lane freed
;;
%define NCA4_PHASE_IDLE         0       ;; no job assigned
%define NCA4_PHASE_STASHED      1       ;; job inputs in OOO structure, awaiting init
%define NCA4_PHASE_CIPHER       2       ;; SNOW5G state initialized, cipher in progress

%define NCA4_HQP_SIZE           48      ;; HQP: H(16) | Q(16) | P(16) = 48 bytes per lane

;; A survivor with less than one full block left is finished in the same call.
%define NCA4_CARRY_MIN_BYTES    16

%define NCA4_SCRATCH_HK4        1

;; Callee-saved GP register aliases
%define p_state         r12
%define p_job_in_lane   r13

struc STACK_NCA4_WORK
_digest_nca4:    resb    (16 * 2)                        ; 2 x 16-byte digest output
_keystream_nca4: resy    1                               ; 32-byte keystream scratch
;; POLYVAL HK tables: 2 lanes x 256 bytes (HK^8..HK^1 + KK^8..KK^1)
_hk_x2:          resb    (HKeySize * 2)
_gpr_save_nca4: resq     8
%ifndef LINUX
_xmm_save_nca4: reso     10
%endif
_rsp_save_nca4: resq     1
%ifdef SAFE_DATA
_scratch_used_nca4: resd 1
%endif
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; POLYVAL final reduction for one lane:
;;     tag = ((ACC XOR len_block) * Q) XOR P
;; with len_block = (aad_len_bits << 64) | msg_len_bits.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_POLYVAL_FINALIZE_LANE 11
%define %%ACC       %1  ;; [in/out]     xmm  -> tag
%define %%Q         %2  ;; [in]         xmm  Q key (HQP[16])
%define %%P         %3  ;; [in]         xmm  P key (HQP[32])
%define %%TMP0      %4  ;; [clobbered]  xmm
%define %%TMP1      %5  ;; [clobbered]  xmm
%define %%TMP2      %6  ;; [clobbered]  xmm
%define %%TMP3      %7  ;; [clobbered]  xmm
%define %%KKQ       %8  ;; [clobbered]  xmm  (built locally)
%define %%LBLK      %9  ;; [clobbered]  xmm  (len_block scratch)
%define %%AAD_BYTES %10 ;; [in]         gp   AAD length in bytes
%define %%MSG_BYTES %11 ;; [in]         gp   msg length in bytes

        ;; Build the HashKey_K helper for Q (needed by HASH_MUL2).
        HASHKEY_K_PRECOMPUTE %%KKQ, %%Q, %%TMP0

        ;; len_block = (aad_bits << 64) | msg_bits
        vmovq   %%LBLK, %%MSG_BYTES
        vpinsrq %%LBLK, %%LBLK, %%AAD_BYTES, 1
        vpsllq  %%LBLK, %%LBLK, 3

        ;; ACC ^= len_block; ACC = ACC * Q; ACC ^= P
        vpxorq          %%ACC, %%ACC, %%LBLK
        HASH_MUL2       %%ACC, %%Q, %%KKQ, %%TMP0, %%TMP1, %%TMP2, %%TMP3
        vpxorq          %%ACC, %%ACC, %%P
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Build HK^2..HK^4 + KK^1..KK^4 for one lane and store in _hk_x2[LANE].
;;
;; HK^3 = HK^2 * HK^1 and HK^4 = HK^2 * HK^2 each only depend on HK^1/HK^2 (not
;; on each other), so they are computed together with one ymm-width HASH_MUL2
;; (2 independent 128b lanes) instead of 2 serial xmm multiplies.
;;
;; On return: HK^4..HK^1 at HashKey_4..HashKey_1, KK^4..KK^1 at
;; HashKeyK_4..HashKeyK_1 in the lane's _hk_x2 slot.  %%HK1/%%KK1 preserved.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_POLYVAL_BUILD_HK_POWERS 13
%define %%LANE    %1     ;; [in] immediate: 0 or 1
%define %%HK1     %2     ;; [in] xmm: HK^1 (preserved)
%define %%KK1     %3     ;; [in] xmm: KK^1 (preserved)
%define %%HKN     %4     ;; [clobbered] xmm/ymm: HK^2, then [HK^4:HK^3] pack result
%define %%HK2     %5     ;; [clobbered] xmm: saved HK^2
%define %%KK2     %6     ;; [clobbered] xmm: HashKey_K helper for HK^2
%define %%PAIR_HK %7     ;; [clobbered] xmm/ymm: [HK^2:HK^1] multiplier pack
%define %%PAIR_KK %8     ;; [clobbered] xmm/ymm: [KK^2:KK^1] multiplier pack
%define %%T0      %9     ;; [clobbered] xmm/ymm: HASH_MUL2 scratch
%define %%T1      %10    ;; [clobbered] xmm/ymm/zmm: HASH_MUL2 scratch + KK build
%define %%T2      %11    ;; [clobbered] xmm/ymm/zmm: HASH_MUL2 scratch + KK build
%define %%T3      %12    ;; [clobbered] xmm/ymm: HASH_MUL2 scratch
%define %%ZBUILD  %13    ;; [clobbered] zmm: HK^4:HK^3:HK^2:HK^1 assembly + KK output
%ifdef SAFE_DATA
        or      dword [rsp + _scratch_used_nca4], (NCA4_SCRATCH_HK4 << %%LANE)
%endif
        ;; Store HK^1 at HashKey_1.
        vmovdqa64       [rsp + _hk_x2 + %%LANE*HKeySize + HashKey_1], %%HK1
        ;; HK^2 = HK^1 * HK^1.
        vmovdqa64       %%HKN, %%HK1
        HASH_MUL2       %%HKN, %%HK1, %%KK1, %%T0, %%T1, %%T2, %%T3
        vmovdqa64       [rsp + _hk_x2 + %%LANE*HKeySize + HashKey_2], %%HKN
        vmovdqa64       %%HK2, %%HKN

        ;; HK^3 = HK^2 * HK^1, HK^4 = HK^2 * HK^2: pack both independent
        ;; multiplies into a single ymm-width HASH_MUL2 call.
        HASHKEY_K_PRECOMPUTE %%KK2, %%HK2, %%T0
        vmovdqa64       XWORD(%%HKN), %%HK2
        vinserti32x4    YWORD(%%HKN), YWORD(%%HKN), %%HK2, 1          ;; GH = [HK^2 | HK^2]
        vmovdqa64       XWORD(%%PAIR_HK), %%HK2
        vinserti32x4    YWORD(%%PAIR_HK), YWORD(%%PAIR_HK), %%HK1, 1  ;; HK = [HK^2 | HK^1]
        vmovdqa64       XWORD(%%PAIR_KK), %%KK2
        vinserti32x4    YWORD(%%PAIR_KK), YWORD(%%PAIR_KK), %%KK1, 1  ;; KK = [KK^2 | KK^1]
        HASH_MUL2       YWORD(%%HKN), YWORD(%%PAIR_HK), YWORD(%%PAIR_KK), \
                YWORD(%%T0), YWORD(%%T1), YWORD(%%T2), YWORD(%%T3)
        ;; %%HKN low 256b now hold HK^4 (lane 0) : HK^3 (lane 1).
        vmovdqa64       [rsp + _hk_x2 + %%LANE*HKeySize + HashKey_4], XWORD(%%HKN)
        vextracti32x4   [rsp + _hk_x2 + %%LANE*HKeySize + HashKey_3], YWORD(%%HKN), 1

        ;; Assemble HK^4:HK^3:HK^2:HK^1 in-register (matches HashKey_4 layout);
        ;; a 64B reload here would incur a store-forward stall.
        vmovdqa64       YWORD(%%ZBUILD), YWORD(%%HKN)
        vinserti32x4    %%ZBUILD, %%ZBUILD, %%HK2, 2         ;; bits[383:256] = HK^2
        vinserti32x4    %%ZBUILD, %%ZBUILD, %%HK1, 3         ;; bits[511:384] = HK^1
        HASHKEY_K_PRECOMPUTE ZWORD(%%T1), %%ZBUILD, ZWORD(%%T2)
        vmovdqa64       [rsp + _hk_x2 + %%LANE*HKeySize + HashKeyK_4], ZWORD(%%T1)
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Build one lane's AAD seed accumulator:
;;   acc = POLYVAL_H(AAD) with zero-padded final partial block,
;; then store acc to OOO for later message absorb/finalize.
;; Empty AAD stores zero.
;; Pre: p_state loaded; %%LANE OOO slots valid.
;; The byte-absorb helper's fixed register contract also applies.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_HASH_AAD_LANE 10
%define %%LANE       %1  ;; [in] immediate: 0 or 1
%define %%JOB_GP     %2  ;; [clobbered] gp: job pointer
%define %%AAD_PTR_GP %3  ;; [clobbered] gp: AAD data pointer
%define %%AAD_LEN_GP %4  ;; [clobbered] gp: AAD length in bytes
%define %%HK1        %5  ;; [clobbered] xmm: HK^1
%define %%KK1        %6  ;; [clobbered] xmm: KK^1 (HashKey_K helper)
%define %%ACC        %7  ;; [clobbered] xmm: POLYVAL(AAD) accumulator
%define %%T0         %8  ;; [clobbered] xmm scratch
%define %%ABSORB_PTR_GP %9  ;; [clobbered] gp: rax, helper pointer argument
%define %%ABSORB_LEN_GP %10 ;; [clobbered] gp: rbx, helper length argument
        ;; Load AAD ptr/len from this lane's job.
        mov     %%JOB_GP, [p_state + _snow5g_job_in_lane + %%LANE*8]
        mov     %%AAD_PTR_GP, [%%JOB_GP + _nca_aad]
        mov     %%AAD_LEN_GP, [%%JOB_GP + _nca_aad_len]

        ;; HK^1 = HQP[0] for this lane; build KK^1 (HashKey_K helper).
        vmovdqu64       %%HK1, [p_state + _snow5g_nca4_hqp + %%LANE*NCA4_HQP_SIZE + 0]
        HASHKEY_K_PRECOMPUTE %%KK1, %%HK1, %%T0

        ;; Hash AAD into ACC starting from zero.
        vpxorq          %%ACC, %%ACC, %%ACC
        mov     %%ABSORB_PTR_GP, %%AAD_PTR_GP
        mov     %%ABSORB_LEN_GP, %%AAD_LEN_GP
        call    nca4_polyval_absorb_bytes_vaes_avx512

        ;; Store lane accumulator seed (POLYVAL(AAD)) for later message fold.
        vmovdqu64       [p_state + _snow5g_nca4_polyval_acc + %%LANE*16], %%ACC
%endmacro

;; Absorb one lane's message into its AAD-seeded POLYVAL accumulator and finalize the tag.
%macro NCA4_POLYVAL_LANE 27
%define %%LANE         %1  ;; [in] lane index (0 or 1)
%define %%DATA_FLD     %2  ;; [in] state field for msg pointer (_snow5g_args_in or _snow5g_args_out)
%define %%JOB_GP       %3  ;; [clobbered] gp: job pointer
%define %%MSG_PTR_GP   %4  ;; [clobbered] gp: message pointer (reused as AAD length at finalize)
%define %%MSG_LEN_GP   %5  ;; [clobbered] gp: bytes to absorb (whole msg, then tail)
%define %%GRP_CNT_GP   %6  ;; [clobbered] gp: 64B-group count
%define %%HK_PTR_GP    %7  ;; [clobbered] gp: HK^4 table pointer
%define %%HK1          %8  ;; [clobbered] xmm: HK^1
%define %%KK1          %9  ;; [clobbered] xmm: KK^1 (HashKey_K helper)
%define %%ACC          %10 ;; [clobbered] xmm/zmm: running POLYVAL accumulator
%define %%T0           %11 ;; [clobbered] xmm scratch
%define %%T1           %12 ;; [clobbered] xmm scratch (reused as Q key at finalize)
%define %%T2           %13 ;; [clobbered] xmm scratch (reused as P key at finalize)
%define %%T3           %14 ;; [clobbered] xmm scratch
%define %%T4           %15 ;; [clobbered] xmm scratch
%define %%T5           %16 ;; [clobbered] xmm scratch
%define %%HKN          %17 ;; [clobbered] xmm/zmm: rolling HK^n / HASH_4_OR_8 scratch
%define %%ZBUILD       %18 ;; [clobbered] zmm: HK powers assembly / HASH_4_OR_8 scratch
%define %%HASH4_T6     %19 ;; [clobbered] zmm: HASH_4_OR_8 extra scratch
%define %%ABSORB_T0    %20 ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%ABSORB_T1    %21 ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%ABSORB_T2    %22 ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%ABSORB_T3    %23 ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%ABSORB_T4    %24 ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%FINALIZE_SCR %25 ;; [clobbered] xmm: FINALIZE_LANE len_block scratch
%define %%ABSORB_PTR_GP %26 ;; [clobbered] gp: rax, helper pointer argument
%define %%ABSORB_LEN_GP %27 ;; [clobbered] gp: rbx, helper length argument

        mov     %%JOB_GP, [p_job_in_lane + %%LANE*8]

        ;; HK^1 = HQP[0], build KK^1 (L01 SNOW5G state regs preserved, unused).
        vmovdqu64       %%HK1,  [p_state + _snow5g_nca4_hqp + %%LANE * NCA4_HQP_SIZE + 0]
        HASHKEY_K_PRECOMPUTE %%KK1,  %%HK1, %%T0

        ;; Load running accumulator seeded with POLYVAL(AAD).
        vmovdqu64       %%ACC,  [p_state + _snow5g_nca4_polyval_acc + %%LANE*16]

        mov     %%MSG_PTR_GP,   [p_state + %%DATA_FLD + %%LANE*8]
        mov     %%MSG_LEN_GP, [%%JOB_GP + _msg_len_to_cipher_in_bytes]

        ;; Batched absorb (HASH_4_OR_8: 4 blocks/64B per reduction).  Only for
        ;; msg_len >= 128 B, to amortize the HK^2..^4 + KK build.
        cmp     %%MSG_LEN_GP, 128
        jb      %%absorb_1way_ %+ %%LANE

        NCA4_POLYVAL_BUILD_HK_POWERS %%LANE, %%HK1, %%KK1, %%HKN, %%T4, %%ABSORB_T0, %%ABSORB_T1, %%ABSORB_T2, \
                %%T0, %%T1, %%T2, %%T3, %%ZBUILD

        mov     %%GRP_CNT_GP, %%MSG_LEN_GP
        shr     %%GRP_CNT_GP, 6            ;; groups = msg_len / 64
        lea     %%HK_PTR_GP, [rsp + _hk_x2 + %%LANE*HKeySize + HashKey_4]
align_loop
%%hash4_loop_ %+ %%LANE:
        HASH_4_OR_8 hk_load, %%MSG_PTR_GP, %%HK_PTR_GP, ZWORD(%%ACC), 4, \
                ZWORD(%%T0), ZWORD(%%T1), ZWORD(%%T2), ZWORD(%%T3), ZWORD(%%T4), ZWORD(%%T5), %%HASH4_T6, ZWORD(%%HKN), %%ZBUILD
        add     %%MSG_PTR_GP, 64
        dec     %%GRP_CNT_GP
        jnz     %%hash4_loop_ %+ %%LANE

        and     %%MSG_LEN_GP, 63      ;; remaining tail bytes = msg_len & 63

align_label
%%absorb_1way_ %+ %%LANE:
        mov     %%ABSORB_PTR_GP, %%MSG_PTR_GP
        mov     %%ABSORB_LEN_GP, %%MSG_LEN_GP
        call    nca4_polyval_absorb_bytes_vaes_avx512

        ;; Finalize: tag = ((acc ^ len_block) * Q) ^ P.  Reload job (ABSORB
        ;; clobbered %%JOB_GP); Q = HQP[16], P = HQP[32].
        mov     %%JOB_GP, [p_job_in_lane + %%LANE*8]
        vmovdqu64       %%T1,  [p_state + _snow5g_nca4_hqp + %%LANE * NCA4_HQP_SIZE + 16]
        vmovdqu64       %%T2,  [p_state + _snow5g_nca4_hqp + %%LANE * NCA4_HQP_SIZE + 32]
        mov     %%MSG_PTR_GP,  [%%JOB_GP + _nca_aad_len]
        mov     %%MSG_LEN_GP,  [%%JOB_GP + _msg_len_to_cipher_in_bytes]
        NCA4_POLYVAL_FINALIZE_LANE %%ACC, %%T1, %%T2, \
                %%ABSORB_T0, %%ABSORB_T1, %%ABSORB_T2, %%ABSORB_T3, %%ABSORB_T4, %%FINALIZE_SCR, %%MSG_PTR_GP, %%MSG_LEN_GP

        ;; Stash tag for NCA4_COPY_TAG.
        vmovdqa64       [rsp + _digest_nca4 + %%LANE*16], %%ACC
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Per-lane tag output: masked store of digest to auth_tag_output
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_COPY_TAG 6
%define %%LANE       %1  ;; [in] lane index (0 or 1)
%define %%TMP0       %2  ;; [clobbered] xmm
%define %%JOB_GP     %3  ;; [clobbered] gp: job pointer
%define %%LEN_GP     %4  ;; [clobbered] gp: tag length in bytes
%define %%PTR_GP     %5  ;; [clobbered] gp: auth_tag_output pointer
%define %%MASK_K     %6  ;; [clobbered] k register: tag byte mask

        mov     %%JOB_GP, [p_job_in_lane + %%LANE*8]

        vmovdqa64 %%TMP0, [rsp + _digest_nca4 + %%LANE*16]
        mov     DWORD(%%LEN_GP), [%%JOB_GP + _auth_tag_output_len_in_bytes]
        mov     %%PTR_GP, [%%JOB_GP + _auth_tag_output]
        ;; Build byte mask from tag length: MASK_K = (1 << LEN_GP) - 1
        mov     DWORD(%%JOB_GP), -1
        bzhi    DWORD(%%JOB_GP), DWORD(%%JOB_GP), DWORD(%%LEN_GP)
        kmovw   %%MASK_K, DWORD(%%JOB_GP)
        vmovdqu8 [%%PTR_GP]{%%MASK_K}, %%TMP0
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;; Single-lane cipher round (XMM): 16B keystream, XOR %%SRC->%%DST, clock FSM/LFSR.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
%macro NCA4_CIPHER_ROUND_X1 14
%define %%FSM_R1        %1      ;; [in/out] xmm: FSM R1
%define %%FSM_R2        %2      ;; [in/out] xmm: FSM R2
%define %%FSM_R3        %3      ;; [in/out] xmm: FSM R3
%define %%LFSR_A_LDQ    %4      ;; [in/out] xmm: LFSR A low dqword
%define %%LFSR_A_HDQ    %5      ;; [in/out] xmm: LFSR A high dqword
%define %%LFSR_B_LDQ    %6      ;; [in/out] xmm: LFSR B low dqword
%define %%LFSR_B_HDQ    %7      ;; [in/out] xmm: LFSR B high dqword
%define %%SRC           %8      ;; [in] gp: source pointer
%define %%DST           %9      ;; [in] gp: destination pointer
%define %%OFF           %10     ;; [in/out] gp: byte offset into SRC/DST, advanced by 16
%define %%T0            %11     ;; [clobbered] xmm scratch
%define %%T1            %12     ;; [clobbered] xmm scratch
%define %%T2            %13     ;; [clobbered] xmm scratch
%define %%T3            %14     ;; [clobbered] xmm scratch

        ;; Keystream = (%%LFSR_B_HDQ + %%FSM_R1) XOR %%FSM_R2.
        vpaddw          %%T0, %%LFSR_B_HDQ, %%FSM_R1
        vpxord          %%T0, %%T0, %%FSM_R2

        ;; XOR with source, write to destination
        vmovdqu32       %%T1, [%%SRC + %%OFF]
        vpxord          %%T1, %%T0, %%T1
        vmovdqu32       [%%DST + %%OFF], %%T1

        ;; Clock FSM and update LFSR (cipher phase: no keystream feedback)
        SNOW5G_FSM_CLOCK_2 %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_HDQ, %%T0, %%T1
        SNOW5G_LFSR_UPDATE %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, \
                %%T2, %%T3, none, none, %%T0, %%T1
        add     %%OFF, 16
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;; Single-lane cipher tail round: like NCA4_CIPHER_ROUND_X1 but masked
;; load/store for the final partial block using %%MASK_TAIL_K; does not advance %%OFF.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_CIPHER_ROUND_TAIL_X1 15
%define %%FSM_R1        %1      ;; [in/out] xmm: FSM R1
%define %%FSM_R2        %2      ;; [in/out] xmm: FSM R2
%define %%FSM_R3        %3      ;; [in/out] xmm: FSM R3
%define %%LFSR_A_LDQ    %4      ;; [in/out] xmm: LFSR A low dqword
%define %%LFSR_A_HDQ    %5      ;; [in/out] xmm: LFSR A high dqword
%define %%LFSR_B_LDQ    %6      ;; [in/out] xmm: LFSR B low dqword
%define %%LFSR_B_HDQ    %7      ;; [in/out] xmm: LFSR B high dqword
%define %%SRC           %8      ;; [in] gp: source pointer
%define %%DST           %9      ;; [in] gp: destination pointer
%define %%OFF           %10     ;; [in] gp: byte offset into SRC/DST
%define %%T0            %11     ;; [clobbered] xmm scratch
%define %%T1            %12     ;; [clobbered] xmm scratch
%define %%T2            %13     ;; [clobbered] xmm scratch
%define %%T3            %14     ;; [clobbered] xmm scratch
%define %%MASK_TAIL_K   %15     ;; [in] k register: tail byte mask

        ;; Keystream = (%%LFSR_B_HDQ + %%FSM_R1) XOR %%FSM_R2.
        vpaddw          %%T0, %%LFSR_B_HDQ, %%FSM_R1
        vpxord          %%T0, %%T0, %%FSM_R2

        ;; Masked load, XOR, masked store (%%MASK_TAIL_K = tail byte mask, set by caller)
        vmovdqu8        %%T1{%%MASK_TAIL_K}{z}, [%%SRC + %%OFF]
        vpxord          %%T1, %%T0, %%T1
        vmovdqu8        [%%DST + %%OFF]{%%MASK_TAIL_K}, %%T1

        ;; Clock FSM and update LFSR (cipher phase: no keystream feedback)
        SNOW5G_FSM_CLOCK_2 %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_HDQ, %%T0, %%T1
        SNOW5G_LFSR_UPDATE %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, \
                %%T2, %%T3, none, none, %%T0, %%T1
%endmacro

;; Single-lane SNOW5G init round (XMM): advances FSM/LFSR only, no output.
;; %%MASK_K = all-ones enables the init-phase LFSR feedback XOR.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_INIT_ROUND_X1 12
%define %%FSM_R1        %1      ;; [in/out] xmm: FSM R1
%define %%FSM_R2        %2      ;; [in/out] xmm: FSM R2
%define %%FSM_R3        %3      ;; [in/out] xmm: FSM R3
%define %%LFSR_A_LDQ    %4      ;; [in/out] xmm: LFSR A low dqword
%define %%LFSR_A_HDQ    %5      ;; [in/out] xmm: LFSR A high dqword
%define %%LFSR_B_LDQ    %6      ;; [in/out] xmm: LFSR B low dqword
%define %%LFSR_B_HDQ    %7      ;; [in/out] xmm: LFSR B high dqword
%define %%T0            %8      ;; [clobbered] xmm scratch (holds the keystream)
%define %%T1            %9      ;; [clobbered] xmm scratch
%define %%T2            %10     ;; [clobbered] xmm scratch
%define %%T3            %11     ;; [clobbered] xmm scratch
%define %%MASK_K        %12     ;; [in] k register: LFSR feedback mask (all-ones = init phase)

        ;; Generate keystream (not output - just used for LFSR feedback)
        vpaddw          %%T0, %%LFSR_B_HDQ, %%FSM_R1
        vpxorq          %%T1, %%LFSR_A_HDQ, %%FSM_R3
        vpaddw          %%T1, %%T1, %%FSM_R2
        vpxord          %%T0, %%T0, %%FSM_R2

        ;; Clock FSM and update LFSR with the feedback XOR straight from T0
        vaesenc         %%FSM_R3, %%FSM_R2, [rel zero]
        vaesenc         %%FSM_R2, %%FSM_R1, [rel zero]
        vpshufb         %%FSM_R1, %%T1, [rel sigma]
        SNOW5G_LFSR_UPDATE %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, \
                %%T2, %%T3, %%T0, %%MASK_K, %%T1, %%T0
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;; Single-lane SNOW5G init + HQP generation (XMM).  Reads key/IV from OOO,
;; writes the 48B HQP to OOO, leaves post-init state in the given registers.
;; Init: state = {FSM=0, LFSR_B_LDQ=0, LFSR_A_LDQ=IV, LFSR_A_HDQ=key[0:16],
;;   LFSR_B_HDQ=key[16:32]}; 15 fb rounds; ^=key[0:16]; 1 fb round; ^=key[16:32];
;;   3 no-fb rounds -> HQP[H,Q,P].
;; %%LANE 0/1; p_state = OOO base.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_INIT_LANE_X1 16
%define %%LANE        %1      ;; [in] immediate: 0 or 1
%define %%FSM_R1      %2      ;; [in/out] xmm: this lane's FSM_R1 bank register
%define %%FSM_R2      %3      ;; [in/out] xmm: this lane's FSM_R2 bank register
%define %%FSM_R3      %4      ;; [in/out] xmm: this lane's FSM_R3 bank register
%define %%LFSR_A_LDQ  %5      ;; [in/out] xmm: this lane's LFSR_A_LDQ bank register
%define %%LFSR_A_HDQ  %6      ;; [in/out] xmm: this lane's LFSR_A_HDQ bank register
%define %%LFSR_B_LDQ  %7      ;; [in/out] xmm: this lane's LFSR_B_LDQ bank register
%define %%LFSR_B_HDQ  %8      ;; [in/out] xmm: this lane's LFSR_B_HDQ bank register
%define %%KEY_GP      %9      ;; [clobbered] gp: key pointer
%define %%LOOP_CNT_GP %10     ;; [clobbered] gp: feedback-round loop counter
%define %%MASK_FB_K   %11     ;; [clobbered] k register: LFSR feedback-enable mask (all-ones)
%define %%T0          %12     ;; [clobbered] xmm scratch
%define %%T1          %13     ;; [clobbered] xmm scratch
%define %%T2          %14     ;; [clobbered] xmm scratch
%define %%T3          %15     ;; [clobbered] xmm scratch
%define %%T4          %16     ;; [clobbered] xmm scratch: key-halves XOR scratch

        ;; --- Load key pointer + IV from this lane's OOO slots ----------------
        mov     %%KEY_GP, [p_state + _snow5g_args_keys + %%LANE*8]

        ;; --- INIT_STATE (single lane) ---------------------------------------
        vpxord          %%FSM_R1, %%FSM_R1, %%FSM_R1
        vmovdqa32       %%FSM_R2, %%FSM_R1
        vmovdqa32       %%FSM_R3, %%FSM_R1
        vmovdqa32       %%LFSR_B_LDQ, %%FSM_R1                     ;; LFSR_B_LDQ = 0
        vmovdqu32       %%LFSR_A_LDQ, [p_state + _snow5g_args_IV + %%LANE*16]  ;; LFSR_A_LDQ = IV
        vmovdqu32       %%LFSR_A_HDQ, [%%KEY_GP + 0]                ;; LFSR_A_HDQ = key[0:16]
        vmovdqu32       %%LFSR_B_HDQ, [%%KEY_GP + 16]               ;; LFSR_B_HDQ = key[16:32]

        ;; --- 15 feedback init rounds (MASK_FB_K = all-ones enables LFSR feedback) ---
        kxnord          %%MASK_FB_K, %%MASK_FB_K, %%MASK_FB_K
        mov             DWORD(%%LOOP_CNT_GP), 15
align_loop
%%init_lane_loop_ %+ %%LANE:
        NCA4_INIT_ROUND_X1 %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, \
                %%T0, %%T1, %%T2, %%T3, %%MASK_FB_K
        dec     DWORD(%%LOOP_CNT_GP)
        jnz     %%init_lane_loop_ %+ %%LANE

        ;; %%FSM_R1 ^= key[0:16]; 16th round; %%FSM_R1 ^= key[16:32]
        vmovdqu32       %%T4, [%%KEY_GP + 0]
        vpxord          %%FSM_R1, %%FSM_R1, %%T4
        NCA4_INIT_ROUND_X1 %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, \
                %%T0, %%T1, %%T2, %%T3, %%MASK_FB_K
        vmovdqu32       %%T4, [%%KEY_GP + 16]
        vpxord          %%FSM_R1, %%FSM_R1, %%T4

        ;; --- 3 no-feedback rounds: extract keystream -> HQP (H, Q, P) -------
%assign %%hi 0
%rep 3
        vpaddw          %%T0, %%LFSR_B_HDQ, %%FSM_R1               ;; keystream = LFSR_B_HDQ + FSM_R1
        vpxord          %%T0, %%T0, %%FSM_R2              ;;            XOR FSM_R2
        vmovdqu32       [p_state + _snow5g_nca4_hqp + %%LANE*NCA4_HQP_SIZE + %%hi], %%T0
        SNOW5G_FSM_CLOCK_2 %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_HDQ, %%T0, %%T1
        SNOW5G_LFSR_UPDATE %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, \
                %%T2, %%T3, none, none, %%T0, %%T1
%assign %%hi %%hi+16
%endrep
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;; Load one lane's SNOW5G state from OOO into the given lane-bank XMM registers.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
%macro NCA4_STATE_LOAD_X1 9
%define %%OOO         %1      ;; [in] GP reg: OOO base pointer
%define %%LANE        %2      ;; [in] immediate: 0 or 1
%define %%FSM_R1      %3      ;; [out] xmm: this lane's FSM_R1 bank register
%define %%FSM_R2      %4      ;; [out] xmm: this lane's FSM_R2 bank register
%define %%FSM_R3      %5      ;; [out] xmm: this lane's FSM_R3 bank register
%define %%LFSR_A_LDQ  %6      ;; [out] xmm: this lane's LFSR_A_LDQ bank register
%define %%LFSR_A_HDQ  %7      ;; [out] xmm: this lane's LFSR_A_HDQ bank register
%define %%LFSR_B_LDQ  %8      ;; [out] xmm: this lane's LFSR_B_LDQ bank register
%define %%LFSR_B_HDQ  %9      ;; [out] xmm: this lane's LFSR_B_HDQ bank register

        vmovdqu64       %%FSM_R1, [%%OOO + _snow5g_args_FSM_1 + %%LANE*16]
        vmovdqu64       %%FSM_R2, [%%OOO + _snow5g_args_FSM_2 + %%LANE*16]
        vmovdqu64       %%FSM_R3, [%%OOO + _snow5g_args_FSM_3 + %%LANE*16]
        vmovdqu64       %%LFSR_A_LDQ, [%%OOO + _snow5g_args_LFSRA_LO + %%LANE*16]
        vmovdqu64       %%LFSR_A_HDQ, [%%OOO + _snow5g_args_LFSRA_HI + %%LANE*16]
        vmovdqu64       %%LFSR_B_LDQ, [%%OOO + _snow5g_args_LFSRB_LO + %%LANE*16]
        vmovdqu64       %%LFSR_B_HDQ, [%%OOO + _snow5g_args_LFSRB_HI + %%LANE*16]
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;; Save one lane's SNOW5G state from XMM registers back to OOO.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
%macro NCA4_STATE_SAVE_X1 9
%define %%OOO         %1      ;; [in] GP reg: OOO base pointer
%define %%LANE        %2      ;; [in] immediate: 0 or 1
%define %%FSM_R1      %3      ;; [in] xmm: this lane's FSM_R1 bank register
%define %%FSM_R2      %4      ;; [in] xmm: this lane's FSM_R2 bank register
%define %%FSM_R3      %5      ;; [in] xmm: this lane's FSM_R3 bank register
%define %%LFSR_A_LDQ  %6      ;; [in] xmm: this lane's LFSR_A_LDQ bank register
%define %%LFSR_A_HDQ  %7      ;; [in] xmm: this lane's LFSR_A_HDQ bank register
%define %%LFSR_B_LDQ  %8      ;; [in] xmm: this lane's LFSR_B_LDQ bank register
%define %%LFSR_B_HDQ  %9      ;; [in] xmm: this lane's LFSR_B_HDQ bank register

        vmovdqu64       [%%OOO + _snow5g_args_FSM_1 + %%LANE*16],    %%FSM_R1
        vmovdqu64       [%%OOO + _snow5g_args_FSM_2 + %%LANE*16],    %%FSM_R2
        vmovdqu64       [%%OOO + _snow5g_args_FSM_3 + %%LANE*16],    %%FSM_R3
        vmovdqu64       [%%OOO + _snow5g_args_LFSRA_LO + %%LANE*16], %%LFSR_A_LDQ
        vmovdqu64       [%%OOO + _snow5g_args_LFSRA_HI + %%LANE*16], %%LFSR_A_HDQ
        vmovdqu64       [%%OOO + _snow5g_args_LFSRB_LO + %%LANE*16], %%LFSR_B_LDQ
        vmovdqu64       [%%OOO + _snow5g_args_LFSRB_HI + %%LANE*16], %%LFSR_B_HDQ
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;; SPLIT: Unpack a packed lane-pair YMM state (both lanes) into an independent
;; XMM register set for lane 1 (lane 0 already occupies the low half of each
;; packed register, so it needs no extraction).
;; Pre:  %%PAIR_* hold both lanes (low half = lane 0, high half = lane 1).
;; Post: %%FSM_R1/%%FSM_R2/%%FSM_R3/%%LFSR_A_LDQ/%%LFSR_A_HDQ/%%LFSR_B_LDQ/%%LFSR_B_HDQ
;;       hold lane 1's state (extracted high halves); %%PAIR_* are unchanged.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
%macro NCA4_STATE_SPLIT_X2 14
%define %%FSM_R1      %1      ;; [out] xmm: lane-1 FSM_R1 bank register
%define %%FSM_R2      %2      ;; [out] xmm: lane-1 FSM_R2 bank register
%define %%FSM_R3      %3      ;; [out] xmm: lane-1 FSM_R3 bank register
%define %%LFSR_A_LDQ  %4      ;; [out] xmm: lane-1 LFSR_A_LDQ bank register
%define %%LFSR_A_HDQ  %5      ;; [out] xmm: lane-1 LFSR_A_HDQ bank register
%define %%LFSR_B_LDQ  %6      ;; [out] xmm: lane-1 LFSR_B_LDQ bank register
%define %%LFSR_B_HDQ  %7      ;; [out] xmm: lane-1 LFSR_B_HDQ bank register
%define %%PAIR_R1  %8   ;; [in] ymm: packed lane-pair FSM_R1
%define %%PAIR_R2  %9   ;; [in] ymm: packed lane-pair FSM_R2
%define %%PAIR_R3  %10  ;; [in] ymm: packed lane-pair FSM_R3
%define %%PAIR_LA  %11  ;; [in] ymm: packed lane-pair LFSR_A_LDQ
%define %%PAIR_LB  %12  ;; [in] ymm: packed lane-pair LFSR_A_HDQ
%define %%PAIR_LC  %13  ;; [in] ymm: packed lane-pair LFSR_B_LDQ
%define %%PAIR_LD  %14  ;; [in] ymm: packed lane-pair LFSR_B_HDQ
        ;; Lane-1 destinations may require EVEX vextracti32x4 rather than vextracti128.
        vextracti32x4   %%FSM_R1, %%PAIR_R1, 1
        vextracti32x4   %%FSM_R2, %%PAIR_R2, 1
        vextracti32x4   %%FSM_R3, %%PAIR_R3, 1
        vextracti32x4   %%LFSR_A_LDQ, %%PAIR_LA, 1
        vextracti32x4   %%LFSR_A_HDQ, %%PAIR_LB, 1
        vextracti32x4   %%LFSR_B_LDQ, %%PAIR_LC, 1
        vextracti32x4   %%LFSR_B_HDQ, %%PAIR_LD, 1
%endmacro

%macro NCA4_CLEAR_LANE 1
%define %%LANE %1 ;; [in] immediate: lane index (0 or 1)
%ifdef SAFE_DATA
        vpxorq          xmm0, xmm0, xmm0
        vmovdqu64       [p_state + _snow5g_args_IV + %%LANE*16], xmm0
        vmovdqu64       [p_state + _snow5g_args_LFSRA_LO + %%LANE*16], xmm0
        vmovdqu64       [p_state + _snow5g_args_LFSRA_HI + %%LANE*16], xmm0
        vmovdqu64       [p_state + _snow5g_args_LFSRB_LO + %%LANE*16], xmm0
        vmovdqu64       [p_state + _snow5g_args_LFSRB_HI + %%LANE*16], xmm0
        vmovdqu64       [p_state + _snow5g_args_FSM_1 + %%LANE*16], xmm0
        vmovdqu64       [p_state + _snow5g_args_FSM_2 + %%LANE*16], xmm0
        vmovdqu64       [p_state + _snow5g_args_FSM_3 + %%LANE*16], xmm0
        vmovdqu64       [p_state + _snow5g_nca4_hqp + %%LANE*NCA4_HQP_SIZE], xmm0
        vmovdqu64       [p_state + _snow5g_nca4_hqp + %%LANE*NCA4_HQP_SIZE + 16], xmm0
        vmovdqu64       [p_state + _snow5g_nca4_hqp + %%LANE*NCA4_HQP_SIZE + 32], xmm0
        vmovdqu64       [p_state + _snow5g_nca4_polyval_acc + %%LANE*16], xmm0
        vmovdqu64       [p_state + _snow5g_nca4_digest + %%LANE*16], xmm0
        vmovq   [p_state + _snow5g_args_in + %%LANE*8], xmm0
        vmovq   [p_state + _snow5g_args_out + %%LANE*8], xmm0
        vmovq   [p_state + _snow5g_args_keys + %%LANE*8], xmm0
        vmovq   [p_state + _snow5g_nca4_aad_len + %%LANE*8], xmm0
        vmovq   [p_state + _snow5g_nca4_msg_len + %%LANE*8], xmm0
        vmovq   [p_state + _snow5g_nca4_bytes_processed + %%LANE*8], xmm0
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Complete one lane: cipher all remaining bytes, then produce and copy the tag.
;; Encrypt hashes the output after cipher; decrypt reloads the digest that the
;; lane init persisted in OOO.
;; p_state = OOO base.  Uses the cipher helper's fixed GP and SIMD registers.
;; Additional clobbers: p_job_in_lane, zmm4-5, zmm7, zmm10-11.
;; The byte-absorb helper's fixed register contract also applies.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_RUN_CIPHER_X1 20
%define %%LANE  %1            ;; [in] immediate: lane index (0 or 1)
%define %%DIR   %2            ;; [in] ENCRYPT or DECRYPT
%define %%OFF_GP      %3      ;; [clobbered] gp: byte offset within message
%define %%REM_GP      %4      ;; [clobbered] gp: remaining-bytes / full-rounds / mask-build scratch
%define %%START_OFF_GP %5     ;; [clobbered] gp: start offset, reused as msg_len at finalize
%define %%TAIL_GP     %6      ;; [clobbered] gp: tail bytes / tag-length-mask scratch
%define %%FOLD_PTR_GP %7      ;; [clobbered] gp: message pointer, reused as aad_len at finalize
%define %%FOLD_LEN_GP %8      ;; [clobbered] gp: rbx, helper length argument
%define %%MASK_CIPHER_K %9    ;; [clobbered] k register: tag byte mask (NCA4_COPY_TAG)
%define %%T0          %10     ;; [clobbered] xmm scratch
%define %%T1          %11     ;; [clobbered] xmm scratch (reused as Q key at finalize)
%define %%T2          %12     ;; [clobbered] xmm scratch (reused as P key at finalize)
%define %%T3          %13     ;; [clobbered] xmm scratch
%define %%ACC         %14     ;; [clobbered] xmm: POLYVAL accumulator
%define %%FIN0        %15     ;; [clobbered] xmm: POLYVAL finalize scratch
%define %%FIN1        %16     ;; [clobbered] xmm: POLYVAL finalize scratch
%define %%FIN2        %17     ;; [clobbered] xmm: POLYVAL finalize scratch
%define %%FIN3        %18     ;; [clobbered] xmm: POLYVAL finalize scratch
%define %%FIN4        %19     ;; [clobbered] xmm: POLYVAL finalize scratch
%define %%FIN5        %20     ;; [clobbered] xmm: POLYVAL finalize scratch

        lea     %%FOLD_PTR_GP, [p_state + %%LANE*8]
        lea     %%START_OFF_GP, [p_state + %%LANE*16]
        call    nca4_cipher_lane_x1_vaes_avx512

        ;; All bytes ciphered - finalize tag.
        lea     p_job_in_lane, [p_state + _snow5g_job_in_lane]
%ifidn %%DIR, ENCRYPT
        ;; ENCRYPT: hash the whole output into the AAD-seeded accumulator.
        NCA4_POLYVAL_LANE %%LANE, _snow5g_args_out, \
                %%REM_GP, %%FOLD_PTR_GP, %%START_OFF_GP, %%OFF_GP, %%TAIL_GP, xmm9, xmm8, %%ACC, %%T0, %%T1, %%T2, %%T3, xmm4, xmm5, \
                xmm10, zmm11, zmm7, %%FIN0, %%FIN1, %%FIN2, %%FIN3, %%FIN4, %%FIN5, %%REM_GP, %%FOLD_LEN_GP
%else
        ;; DECRYPT: reload persisted digest from OOO -> stack for NCA4_COPY_TAG.
        vmovdqu64 %%T0, [p_state + _snow5g_nca4_digest + %%LANE*16]
        vmovdqa64 [rsp + _digest_nca4 + %%LANE*16], %%T0
%endif
        NCA4_COPY_TAG %%LANE, %%T0, %%REM_GP, %%OFF_GP, %%TAIL_GP, %%MASK_CIPHER_K
%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Load SNOW5G LFSR/FSM state for BOTH lanes from OOO base into L01 YMM regs.
;; Each 32 B OOO field is loaded as two 16 B halves (lane 0 | lane 1); see the
;; store-forwarding note in the body before changing this to one ymm load.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro STATE_LOAD_NCA4_FROM_OOO 8
%define %%STATE_OOO     %1      ;; [in] GP reg: SNOW5G OOO base pointer
%define %%FSM_R1        %2      ;; [out] ymm: packed lane-pair FSM_R1
%define %%FSM_R2        %3      ;; [out] ymm: packed lane-pair FSM_R2
%define %%FSM_R3        %4      ;; [out] ymm: packed lane-pair FSM_R3
%define %%LFSR_A_LDQ    %5      ;; [out] ymm: packed lane-pair LFSR_A_LDQ
%define %%LFSR_A_HDQ    %6      ;; [out] ymm: packed lane-pair LFSR_A_HDQ
%define %%LFSR_B_LDQ    %7      ;; [out] ymm: packed lane-pair LFSR_B_LDQ
%define %%LFSR_B_HDQ    %8      ;; [out] ymm: packed lane-pair LFSR_B_HDQ
        ;; Each 32B field holds (lane0 | lane1).  On the one-fresh-lane path the
        ;; two halves are saved by separate 16B stores; loading the halves and
        ;; reassembling via vinserti32x4 avoids a store-forwarding stall.
        vmovdqu64       XWORD(%%FSM_R1),     [%%STATE_OOO + _snow5g_args_FSM_1]
        vinserti32x4    %%FSM_R1, %%FSM_R1, [%%STATE_OOO + _snow5g_args_FSM_1 + 16], 1
        vmovdqu64       XWORD(%%FSM_R2),     [%%STATE_OOO + _snow5g_args_FSM_2]
        vinserti32x4    %%FSM_R2, %%FSM_R2, [%%STATE_OOO + _snow5g_args_FSM_2 + 16], 1
        vmovdqu64       XWORD(%%FSM_R3),     [%%STATE_OOO + _snow5g_args_FSM_3]
        vinserti32x4    %%FSM_R3, %%FSM_R3, [%%STATE_OOO + _snow5g_args_FSM_3 + 16], 1
        vmovdqu64       XWORD(%%LFSR_A_LDQ), [%%STATE_OOO + _snow5g_args_LFSRA_LO]
        vinserti32x4    %%LFSR_A_LDQ, %%LFSR_A_LDQ, [%%STATE_OOO + _snow5g_args_LFSRA_LO + 16], 1
        vmovdqu64       XWORD(%%LFSR_A_HDQ), [%%STATE_OOO + _snow5g_args_LFSRA_HI]
        vinserti32x4    %%LFSR_A_HDQ, %%LFSR_A_HDQ, [%%STATE_OOO + _snow5g_args_LFSRA_HI + 16], 1
        vmovdqu64       XWORD(%%LFSR_B_LDQ), [%%STATE_OOO + _snow5g_args_LFSRB_LO]
        vinserti32x4    %%LFSR_B_LDQ, %%LFSR_B_LDQ, [%%STATE_OOO + _snow5g_args_LFSRB_LO + 16], 1
        vmovdqu64       XWORD(%%LFSR_B_HDQ), [%%STATE_OOO + _snow5g_args_LFSRB_HI]
        vinserti32x4    %%LFSR_B_HDQ, %%LFSR_B_HDQ, [%%STATE_OOO + _snow5g_args_LFSRB_HI + 16], 1
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Run SNOW5G init + HQP generation for BOTH lanes in one 2-lane pass.  Reads
;; keys/IVs from OOO, writes HQP + 7 state fields back to OOO, leaves post-init
;; state in L01.  Pre: both lanes' key/IV slots populated; p_state loaded.
;; Additional clobbers: rax, r10, r11.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_INIT_BOTH_LANES 14
%define %%FSM_R1        %1      ;; [out] ymm: packed lane-pair FSM_R1
%define %%FSM_R2        %2      ;; [out] ymm: packed lane-pair FSM_R2
%define %%FSM_R3        %3      ;; [out] ymm: packed lane-pair FSM_R3
%define %%LFSR_A_LDQ    %4      ;; [out] ymm: packed lane-pair LFSR_A_LDQ
%define %%LFSR_A_HDQ    %5      ;; [out] ymm: packed lane-pair LFSR_A_HDQ
%define %%LFSR_B_LDQ    %6      ;; [out] ymm: packed lane-pair LFSR_B_LDQ
%define %%LFSR_B_HDQ    %7      ;; [out] ymm: packed lane-pair LFSR_B_HDQ
%define %%TEMP0         %8      ;; [clobbered] ymm scratch
%define %%TEMP1         %9      ;; [clobbered] ymm scratch
%define %%TEMP2         %10     ;; [clobbered] ymm scratch
%define %%TEMP3         %11     ;; [clobbered] ymm scratch
%define %%COUNTER_GP    %12     ;; [clobbered] gp: byte offset counter
%define %%MASK_K1       %13     ;; [clobbered] k register
%define %%MASK_K2       %14     ;; [clobbered] k register
        ;; 2-lane init + 3 HQP rounds reading keys/IV from OOO, writing HQP to
        ;; OOO.  STATE_OUT=0 keeps state in L01 (persisted by the stores below).
        lea     rax, [p_state + _snow5g_args_keys]
        SNOW5G_GENERATE_HQP_X2 rax, {p_state + _snow5g_args_IV}, \
                {p_state + _snow5g_nca4_hqp}, 0, _keystream_nca4, \
                %%FSM_R1, %%FSM_R2, %%FSM_R3, \
                %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, \
                %%TEMP0, %%TEMP1, %%TEMP2, %%TEMP3, %%COUNTER_GP, %%MASK_K1, %%MASK_K2

        ;; Persist 2-lane state to OOO (one aligned ymm store per 32B field);
        ;; each 32B store forwards to the 16B half loads in STATE_LOAD_NCA4_FROM_OOO.
        vmovdqa64 [p_state + _snow5g_args_FSM_1   ], %%FSM_R1
        vmovdqa64 [p_state + _snow5g_args_FSM_2   ], %%FSM_R2
        vmovdqa64 [p_state + _snow5g_args_FSM_3   ], %%FSM_R3
        vmovdqa64 [p_state + _snow5g_args_LFSRA_LO], %%LFSR_A_LDQ
        vmovdqa64 [p_state + _snow5g_args_LFSRA_HI], %%LFSR_A_HDQ
        vmovdqa64 [p_state + _snow5g_args_LFSRB_LO], %%LFSR_B_LDQ
        vmovdqa64 [p_state + _snow5g_args_LFSRB_HI], %%LFSR_B_HDQ
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;; Finish a CIPHER lane with < 16 bytes left: emit the masked tail block (if
;; any), finalise the tag (enc: POLYVAL over output; dec: reload INIT digest),
;; copy the tag out.  Bulk already ciphered by the joint kernel.
;; Pre: p_state loaded; state saved in OOO; bytes_processed = msg_len - tail.
;; Additional clobber: p_job_in_lane; the byte-absorb helper's register contract also applies.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_FINISH_LANE_X1 33
%define %%LANE  %1      ;; [in] immediate: 0 or 1
%define %%DIR   %2      ;; [in] ENCRYPT or DECRYPT
%define %%FSM_R1      %3      ;; [in/out] xmm: this lane's FSM_R1 bank register
%define %%FSM_R2      %4      ;; [in/out] xmm: this lane's FSM_R2 bank register
%define %%FSM_R3      %5      ;; [in/out] xmm: this lane's FSM_R3 bank register
%define %%LFSR_A_LDQ  %6      ;; [in/out] xmm: this lane's LFSR_A_LDQ bank register
%define %%LFSR_A_HDQ  %7      ;; [in/out] xmm: this lane's LFSR_A_HDQ bank register
%define %%LFSR_B_LDQ  %8      ;; [in/out] xmm: this lane's LFSR_B_LDQ bank register
%define %%LFSR_B_HDQ  %9      ;; [in/out] xmm: this lane's LFSR_B_HDQ bank register
%define %%SRC_GP      %10     ;; [clobbered] gp: src pointer
%define %%DST_GP      %11     ;; [clobbered] gp: dst pointer
%define %%OFF_GP      %12     ;; [clobbered] gp: byte offset (bytes_processed)
%define %%REM_GP      %13     ;; [clobbered] gp: tail-bytes / mask-build / byte-offset scratch
%define %%MASK_TMP_GP %14     ;; [clobbered] gp: tail-mask build scratch
%define %%FOLD_PTR_GP %15     ;; [clobbered] gp: output pointer, reused as aad_len at finalize
%define %%MSG_LEN_GP  %16     ;; [clobbered] gp: msg length, reused as tail-byte count
%define %%MASK_CIPHER_K %17   ;; [clobbered] k register: cipher-phase LFSR feedback mask (always 0)
%define %%MASK_TAIL_K %18     ;; [clobbered] k register: tail byte mask
%define %%T0          %19     ;; [clobbered] xmm scratch
%define %%T1          %20     ;; [clobbered] xmm scratch (reused as Q key at finalize)
%define %%T2          %21     ;; [clobbered] xmm scratch (reused as P key at finalize)
%define %%T3          %22     ;; [clobbered] xmm scratch
%define %%ACC         %23     ;; [clobbered] xmm: POLYVAL accumulator
%define %%KK1         %24     ;; [clobbered] xmm: KK^1
%define %%HK1         %25     ;; [clobbered] xmm: HK^1
%define %%FIN0        %26     ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%FIN1        %27     ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%FIN2        %28     ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%FIN3        %29     ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%FIN4        %30     ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%FIN5        %31     ;; [clobbered] xmm: FINALIZE_LANE len_block scratch
%define %%ABSORB_PTR_GP %32   ;; [clobbered] gp: rax, helper pointer argument
%define %%ABSORB_LEN_GP %33   ;; [clobbered] gp: rbx, helper length argument

        ;; tail bytes = msg_len - bytes_processed  (0..15)
        mov     %%REM_GP, [p_state + _snow5g_nca4_msg_len + %%LANE*8]
        mov     %%OFF_GP, [p_state + _snow5g_nca4_bytes_processed + %%LANE*8]
        sub     %%REM_GP, %%OFF_GP
        jz      %%finish_no_tail_ %+ %%LANE

        NCA4_STATE_LOAD_X1 p_state, %%LANE, %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ
        mov     %%SRC_GP, [p_state + _snow5g_args_in + %%LANE*8]
        mov     %%DST_GP, [p_state + _snow5g_args_out + %%LANE*8]
        kxorq   %%MASK_CIPHER_K, %%MASK_CIPHER_K, %%MASK_CIPHER_K
        mov     DWORD(%%MASK_TMP_GP), -1
        bzhi    DWORD(%%MASK_TMP_GP), DWORD(%%MASK_TMP_GP), DWORD(%%REM_GP)
        kmovw   %%MASK_TAIL_K, DWORD(%%MASK_TMP_GP)
        NCA4_CIPHER_ROUND_TAIL_X1 %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, %%SRC_GP, %%DST_GP, %%OFF_GP, \
                %%T0, %%T1, %%T2, %%T3, %%MASK_TAIL_K
        mov     %%REM_GP, [p_state + _snow5g_nca4_msg_len + %%LANE*8]
        mov     [p_state + _snow5g_nca4_bytes_processed + %%LANE*8], %%REM_GP
align_label
%%finish_no_tail_ %+ %%LANE:

        lea     p_job_in_lane, [p_state + _snow5g_job_in_lane]
%ifidn %%DIR, ENCRYPT
        ;; ENCRYPT: hash the whole output into the AAD-seeded accumulator.
        NCA4_POLYVAL_LANE %%LANE, _snow5g_args_out, \
                %%REM_GP, %%FOLD_PTR_GP, %%MSG_LEN_GP, %%OFF_GP, %%MASK_TMP_GP, %%HK1, %%KK1, %%ACC, %%T0, %%T1, %%T2, %%T3, xmm4, xmm5, \
                xmm10, zmm11, zmm7, %%FIN0, %%FIN1, %%FIN2, %%FIN3, %%FIN4, %%FIN5, %%ABSORB_PTR_GP, %%ABSORB_LEN_GP
%else
        vmovdqu64 %%T0, [p_state + _snow5g_nca4_digest + %%LANE*16]
        vmovdqa64 [rsp + _digest_nca4 + %%LANE*16], %%T0
%endif
        NCA4_COPY_TAG %%LANE, %%T0, %%REM_GP, %%OFF_GP, %%MASK_TMP_GP, %%MASK_CIPHER_K
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;; Joint cipher + carry/retire.  Both lanes CIPHER (state in OOO, AAD-seeded accumulator,
;; dec digests persisted).  Runs min(remaining full blocks) for both lanes, then
;; finishes lane(s) with < 16 bytes left and carries the rest to the next call.
;; A survivor with < NCA4_CARRY_MIN_BYTES left is finished too (see define).
;; Retired lanes get IMB_STATUS_COMPLETED, slot cleared, phase=IDLE, lanes_in_use--;
;; job_rax = one completed job (or NULL).
;; Additional clobbers: p_job_in_lane, rdx, r11, zmm0-11, zmm16-21, k2, plus the
;; L01 state and lane-1 split bank arguments.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_SCHED_JOINT_CARRY 24
%define %%DIR         %1  ;; [in] ENCRYPT or DECRYPT
%define %%REM_GP      %2  ;; [clobbered] gp: remaining-blocks scratch (both lanes), reused as byte-count checks
%define %%HK_PTR_GP   %3  ;; [clobbered] gp: lane-1 remaining-blocks scratch, reused as JOINT's HK table pointer
%define %%NBLK_GP     %4  ;; [clobbered] gp: min(remaining full blocks) for both lanes, reused to hold job_rax across the survivor finish
%define %%SRC0_GP     %5  ;; [clobbered] gp: lane 0 src pointer
%define %%DST0_GP     %6  ;; [clobbered] gp: lane 0 dst pointer
%define %%SRC1_GP     %7  ;; [clobbered] gp: lane 1 src pointer
%define %%DST1_GP     %8  ;; [clobbered] gp: lane 1 dst pointer
%define %%COUNTER_GP  %9  ;; [clobbered] gp: shared byte-offset counter, reused as job-status scratch
%define %%MASK_CIPHER_K %10 ;; [clobbered] k register: cipher-phase LFSR feedback mask (always 0)
%define %%FSM_R1      %11 ;; [in/out] ymm: packed lane-pair FSM_R1 (L01 bank)
%define %%FSM_R2      %12 ;; [in/out] ymm: packed lane-pair FSM_R2 (L01 bank)
%define %%FSM_R3      %13 ;; [in/out] ymm: packed lane-pair FSM_R3 (L01 bank)
%define %%LFSR_A_LDQ  %14 ;; [in/out] ymm: packed lane-pair LFSR_A_LDQ (L01 bank)
%define %%LFSR_A_HDQ  %15 ;; [in/out] ymm: packed lane-pair LFSR_A_HDQ (L01 bank)
%define %%LFSR_B_LDQ  %16 ;; [in/out] ymm: packed lane-pair LFSR_B_LDQ (L01 bank)
%define %%LFSR_B_HDQ  %17 ;; [in/out] ymm: packed lane-pair LFSR_B_HDQ (L01 bank)
%define %%L1_FSM_R1   %18 ;; [out] xmm: lane-1 split FSM_R1 bank register
%define %%L1_FSM_R2   %19 ;; [out] xmm: lane-1 split FSM_R2 bank register
%define %%L1_FSM_R3   %20 ;; [out] xmm: lane-1 split FSM_R3 bank register
%define %%L1_LFSR_A_LDQ %21 ;; [out] xmm: lane-1 split LFSR_A_LDQ bank register
%define %%L1_LFSR_A_HDQ %22 ;; [out] xmm: lane-1 split LFSR_A_HDQ bank register
%define %%L1_LFSR_B_LDQ %23 ;; [out] xmm: lane-1 split LFSR_B_LDQ bank register
%define %%L1_LFSR_B_HDQ %24 ;; [out] xmm: lane-1 split LFSR_B_HDQ bank register

        ;; nblk = min( (msg_len0 - bp0) >> 4 , (msg_len1 - bp1) >> 4 )
        mov     %%REM_GP, [p_state + _snow5g_nca4_msg_len + 0]
        sub     %%REM_GP, [p_state + _snow5g_nca4_bytes_processed + 0]
        shr     %%REM_GP, 4
        mov     %%HK_PTR_GP, [p_state + _snow5g_nca4_msg_len + 8]
        sub     %%HK_PTR_GP, [p_state + _snow5g_nca4_bytes_processed + 8]
        shr     %%HK_PTR_GP, 4
        mov     %%NBLK_GP, %%REM_GP
        cmp     %%HK_PTR_GP, %%REM_GP
        cmovb   %%NBLK_GP, %%HK_PTR_GP                ;; NBLK_GP = nblk

        ;; Load both lanes' state and bias each lane's src/dst by its own
        ;; bytes_processed so a single shared offset advances both.
        STATE_LOAD_NCA4_FROM_OOO p_state, %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ
        mov     %%SRC0_GP,  [p_state + _snow5g_args_in + 0]
        add     %%SRC0_GP,  [p_state + _snow5g_nca4_bytes_processed + 0]
        mov     %%DST0_GP,  [p_state + _snow5g_args_out + 0]
        add     %%DST0_GP,  [p_state + _snow5g_nca4_bytes_processed + 0]
        mov     %%SRC1_GP, [p_state + _snow5g_args_in + 8]
        add     %%SRC1_GP, [p_state + _snow5g_nca4_bytes_processed + 8]
        mov     %%DST1_GP, [p_state + _snow5g_args_out + 8]
        add     %%DST1_GP, [p_state + _snow5g_nca4_bytes_processed + 8]
        xor     %%COUNTER_GP, %%COUNTER_GP
        kxorq   %%MASK_CIPHER_K, %%MASK_CIPHER_K, %%MASK_CIPHER_K

        test    DWORD(%%NBLK_GP), DWORD(%%NBLK_GP)
        jz      %%joint_done
align_loop
%%joint_loop:
        NCA4_CIPHER_LANE_PAIR %%FSM_R1, %%FSM_R2, %%FSM_R3, \
                %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, \
                ymm1, ymm2, %%SRC0_GP, %%DST0_GP, %%SRC1_GP, %%DST1_GP, %%COUNTER_GP, none, BOTH_LANES, \
                ymm4, ymm5
        add     %%COUNTER_GP, 16
        dec     DWORD(%%NBLK_GP)
        jnz     %%joint_loop
align_label
%%joint_done:

        ;; Split for per-lane state saves and uneven tail/carry handling below.
        ;; Persist advanced state and bytes_processed for both lanes.
        NCA4_STATE_SPLIT_X2 %%L1_FSM_R1, %%L1_FSM_R2, %%L1_FSM_R3, %%L1_LFSR_A_LDQ, %%L1_LFSR_A_HDQ, %%L1_LFSR_B_LDQ, %%L1_LFSR_B_HDQ, \
                %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ
        NCA4_STATE_SAVE_X1 p_state, 0, XWORD(%%FSM_R1), XWORD(%%FSM_R2), XWORD(%%FSM_R3), XWORD(%%LFSR_A_LDQ), XWORD(%%LFSR_A_HDQ), XWORD(%%LFSR_B_LDQ), XWORD(%%LFSR_B_HDQ)
        NCA4_STATE_SAVE_X1 p_state, 1, %%L1_FSM_R1, %%L1_FSM_R2, %%L1_FSM_R3, %%L1_LFSR_A_LDQ, %%L1_LFSR_A_HDQ, %%L1_LFSR_B_LDQ, %%L1_LFSR_B_HDQ
        add     qword [p_state + _snow5g_nca4_bytes_processed + 0], %%COUNTER_GP
        add     qword [p_state + _snow5g_nca4_bytes_processed + 8], %%COUNTER_GP

        ;; Lane 0: finish if < 16 bytes remain, else finish lane 1.
        mov     %%REM_GP, [p_state + _snow5g_nca4_msg_len + 0]
        sub     %%REM_GP, [p_state + _snow5g_nca4_bytes_processed + 0]
        cmp     %%REM_GP, 16
        jae     %%finish_l1
        NCA4_FINISH_LANE_X1 0, %%DIR, XWORD(%%FSM_R1), XWORD(%%FSM_R2), XWORD(%%FSM_R3), XWORD(%%LFSR_A_LDQ), XWORD(%%LFSR_A_HDQ), XWORD(%%LFSR_B_LDQ), XWORD(%%LFSR_B_HDQ), \
                %%SRC0_GP, %%DST0_GP, %%COUNTER_GP, %%REM_GP, rdx, %%SRC1_GP, r11, %%MASK_CIPHER_K, k2, xmm0, xmm1, xmm2, xmm3, xmm6, xmm8, xmm9, xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, %%REM_GP, %%HK_PTR_GP
        mov     %%COUNTER_GP, [p_state + _snow5g_job_in_lane + 0]
        or      dword [%%COUNTER_GP + _status], IMB_STATUS_COMPLETED
        mov     %%NBLK_GP, %%COUNTER_GP                 ;; returned job
        mov     qword [p_state + _snow5g_job_in_lane + 0], 0
        mov     qword [p_state + _snow5g_nca4_phase + 0], NCA4_PHASE_IDLE
        sub     qword [p_state + _snow5g_lanes_in_use], 1
        NCA4_CLEAR_LANE 0

        ;; Lane 1 survives: carry it unless it is too short to hide an init.
        mov     %%REM_GP, [p_state + _snow5g_nca4_msg_len + 8]
        sub     %%REM_GP, [p_state + _snow5g_nca4_bytes_processed + 8]
        cmp     %%REM_GP, NCA4_CARRY_MIN_BYTES
        jae     %%carry_done
        NCA4_RUN_CIPHER_X1 1, %%DIR, \
                %%COUNTER_GP, %%REM_GP, r11, rdx, %%SRC1_GP, %%HK_PTR_GP, %%MASK_CIPHER_K, \
                xmm0, xmm1, xmm2, xmm3, xmm6, xmm16, xmm17, xmm18, xmm19, xmm20, xmm21
        mov     %%COUNTER_GP, [p_state + _snow5g_job_in_lane + 8]
        or      dword [%%COUNTER_GP + _status], IMB_STATUS_COMPLETED
        mov     qword [p_state + _snow5g_job_in_lane + 8], 0
        mov     qword [p_state + _snow5g_nca4_phase + 8], NCA4_PHASE_IDLE
        sub     qword [p_state + _snow5g_lanes_in_use], 1
        NCA4_CLEAR_LANE 1
        jmp     %%carry_done
align_label
%%finish_l1:
        ;; we go here only when lane 1 is on its last 16B block, so lane 0 had >= 16B left
        mov     %%REM_GP, [p_state + _snow5g_nca4_msg_len + 8]
        sub     %%REM_GP, [p_state + _snow5g_nca4_bytes_processed + 8]
        NCA4_FINISH_LANE_X1 1, %%DIR, %%L1_FSM_R1, %%L1_FSM_R2, %%L1_FSM_R3, %%L1_LFSR_A_LDQ, %%L1_LFSR_A_HDQ, %%L1_LFSR_B_LDQ, %%L1_LFSR_B_HDQ, \
                %%SRC0_GP, %%DST0_GP, %%COUNTER_GP, %%REM_GP, rdx, %%SRC1_GP, r11, %%MASK_CIPHER_K, k2, xmm0, xmm1, xmm2, xmm3, xmm6, xmm8, xmm9, xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, %%REM_GP, %%HK_PTR_GP
        mov     %%COUNTER_GP, [p_state + _snow5g_job_in_lane + 8]
        or      dword [%%COUNTER_GP + _status], IMB_STATUS_COMPLETED
        mov     %%NBLK_GP, %%COUNTER_GP                 ;; returned job
        mov     qword [p_state + _snow5g_job_in_lane + 8], 0
        mov     qword [p_state + _snow5g_nca4_phase + 8], NCA4_PHASE_IDLE
        sub     qword [p_state + _snow5g_lanes_in_use], 1
        NCA4_CLEAR_LANE 1

%if NCA4_CARRY_MIN_BYTES > 16
        ;; Lane 0 survives with >= 16 bytes: carry it unless it is too short to hide an init.
        mov     %%REM_GP, [p_state + _snow5g_nca4_msg_len + 0]
        sub     %%REM_GP, [p_state + _snow5g_nca4_bytes_processed + 0]
        cmp     %%REM_GP, NCA4_CARRY_MIN_BYTES
        jae     %%carry_done
        NCA4_RUN_CIPHER_X1 0, %%DIR, \
                %%COUNTER_GP, %%REM_GP, r11, rdx, %%SRC1_GP, %%HK_PTR_GP, %%MASK_CIPHER_K, \
                xmm0, xmm1, xmm2, xmm3, xmm6, xmm16, xmm17, xmm18, xmm19, xmm20, xmm21
        mov     %%COUNTER_GP, [p_state + _snow5g_job_in_lane + 0]
        or      dword [%%COUNTER_GP + _status], IMB_STATUS_COMPLETED
        mov     qword [p_state + _snow5g_job_in_lane + 0], 0
        mov     qword [p_state + _snow5g_nca4_phase + 0], NCA4_PHASE_IDLE
        sub     qword [p_state + _snow5g_lanes_in_use], 1
        NCA4_CLEAR_LANE 0
%endif

align_label
%%carry_done:
        mov     job_rax, %%NBLK_GP
%endmacro

mksection .text
default rel
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; rax/rbx: pointer/length; xmm6: accumulator (upper zmm6 bits zero); xmm9/xmm8: HK^1/KK^1.
;; Lengths >= 128 B are absorbed 4 blocks per reduction using an HK^4..HK^1 /
;; KK^4..KK^1 table built on a 64B-aligned local stack area.
;; Clobbers rax, rbx, rdx, zmm0-4, k2; updates xmm6; preserves all other registers.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
align_function
nca4_polyval_absorb_bytes_vaes_avx512:
        cmp     rbx, 128
        jb      .bytes_check

        mov     rdx, rsp
        sub     rsp, 2*64
        and     rsp, -64
        ;; [rsp] = HK^4:HK^3:HK^2:HK^1, [rsp + 64] = KK^4:KK^3:KK^2:KK^1
        vmovdqa64       [rsp + 48], xmm9
        vmovdqa64       xmm4, xmm9
        HASH_MUL2       xmm4, xmm9, xmm8, xmm0, xmm1, xmm2, xmm3
        vmovdqa64       [rsp + 32], xmm4
        HASH_MUL2       xmm4, xmm9, xmm8, xmm0, xmm1, xmm2, xmm3
        vmovdqa64       [rsp + 16], xmm4
        HASH_MUL2       xmm4, xmm9, xmm8, xmm0, xmm1, xmm2, xmm3
        vinserti32x4    zmm4, zmm4, [rsp + 16], 1
        vinserti32x4    zmm4, zmm4, [rsp + 32], 2
        vinserti32x4    zmm4, zmm4, [rsp + 48], 3
        vmovdqa64       [rsp], zmm4
        HASHKEY_K_PRECOMPUTE zmm0, zmm4, zmm1
        vmovdqa64       [rsp + 64], zmm0
align_loop
.bytes_loop64:
        vpxorq          zmm4, zmm6, [rax]
        vpclmulqdq      zmm0, zmm4, [rsp + 64], 0x00    ; TLL = ML*KL
        vpclmulqdq      zmm1, zmm4, [rsp + 64], 0x10    ; TLH = ML*KH
        vpclmulqdq      zmm2, zmm4, [rsp], 0x01         ; THL = MH*HL
        vpclmulqdq      zmm3, zmm4, [rsp], 0x11         ; THH = MH*HH
        vpxorq          zmm0, zmm0, zmm2
        vpxorq          zmm1, zmm1, zmm3
        vpclmulqdq      zmm6, zmm0, [rel polyval_poly_avx512], 0x10
        vpshufd         zmm2, zmm0, 01001110b
        vpternlogq      zmm6, zmm1, zmm2, 0x96
        VHPXORI4x128    zmm6, zmm2
        add     rax, 64
        sub     rbx, 64
        cmp     rbx, 64
        jae     .bytes_loop64

%ifdef SAFE_DATA
        vpxorq          xmm0, xmm0, xmm0
        vmovdqa64       [rsp], zmm0
        vmovdqa64       [rsp + 64], zmm0
%endif
        mov     rsp, rdx

align_label
.bytes_check:
        test    rbx, rbx
        jz      .bytes_done
align_loop
.bytes_loop:
        cmp     rbx, 16
        jb      .bytes_partial
        vmovdqu64       xmm4, [rax]
        vpxorq          xmm6, xmm6, xmm4
        HASH_MUL2       xmm6, xmm9, xmm8, xmm0, xmm1, xmm2, xmm3
        add     rax, 16
        sub     rbx, 16
        jnz     .bytes_loop
        jmp     .bytes_done
align_label
.bytes_partial:
        mov     DWORD(rdx), -1
        bzhi    DWORD(rdx), DWORD(rdx), DWORD(rbx)
        kmovw   k2, DWORD(rdx)
        vmovdqu8        xmm4{k2}{z}, [rax]
        vpxorq          xmm6, xmm6, xmm4
        HASH_MUL2       xmm6, xmm9, xmm8, xmm0, xmm1, xmm2, xmm3
align_label
.bytes_done:
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Cipher one lane's remaining bytes and persist its state and byte offset, without hashing.
;; r10/r11 select the lane's GP/SIMD OOO fields; rcx/r11 return final/initial offsets.
;; Returns state in xmm12-14/xmm24-27; clobbers rax, rdx, r8-r9, xmm0-3, k2.
align_function
nca4_cipher_lane_x1_vaes_avx512:
        NCA4_STATE_LOAD_X1 r11, 0, xmm12, xmm13, xmm14, xmm24, xmm25, xmm26, xmm27
        mov     rax, [r10 + _snow5g_nca4_msg_len]
        mov     rcx, [r10 + _snow5g_nca4_bytes_processed]
        sub     rax, rcx
        jz      .empty
        mov     rdx, rax
        and     DWORD(rdx), 15
        shr     rax, 4
        mov     r8, [r10 + _snow5g_args_in]
        mov     r9, [r10 + _snow5g_args_out]
        test    DWORD(rax), DWORD(rax)
        jz      .full_done
align_loop
.cipher_loop:
        NCA4_CIPHER_ROUND_X1 xmm12, xmm13, xmm14, xmm24, xmm25, xmm26, xmm27, r8, r9, rcx, \
                xmm0, xmm1, xmm2, xmm3
        dec     DWORD(rax)
        jnz     .cipher_loop
align_label
.full_done:
        test    DWORD(rdx), DWORD(rdx)
        jz      .save
        mov     DWORD(rax), -1
        bzhi    DWORD(rax), DWORD(rax), DWORD(rdx)
        kmovw   k2, DWORD(rax)
        NCA4_CIPHER_ROUND_TAIL_X1 xmm12, xmm13, xmm14, xmm24, xmm25, xmm26, xmm27, r8, r9, rcx, \
                xmm0, xmm1, xmm2, xmm3, k2
        add     rcx, rdx
align_label
.save:
        NCA4_STATE_SAVE_X1 r11, 0, xmm12, xmm13, xmm14, xmm24, xmm25, xmm26, xmm27
        mov     r11, [r10 + _snow5g_nca4_bytes_processed]
        mov     [r10 + _snow5g_nca4_bytes_processed], rcx
        ret
align_label
.empty:
        mov     r11, rcx
        ret

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%define arg5    r8
%define arg6    r9
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%define arg5    qword [rsp + 32]
%define arg6    qword [rsp + 40]
%endif

%define state   arg1
%define job     arg2
%define job_rax rax

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Saves register contents and creates stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NCA4_FUNC_START 0
        mov     rax, rsp
        sub     rsp, STACK_NCA4_WORK_size
        and     rsp, -64

        mov     [rsp + _gpr_save_nca4 + 8*0], rbx
        mov     [rsp + _gpr_save_nca4 + 8*1], rbp
        mov     [rsp + _gpr_save_nca4 + 8*2], r12
        mov     [rsp + _gpr_save_nca4 + 8*3], r13
        mov     [rsp + _gpr_save_nca4 + 8*4], r14
        mov     [rsp + _gpr_save_nca4 + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save_nca4 + 8*6], rsi
        mov     [rsp + _gpr_save_nca4 + 8*7], rdi
        ;; Save XMM6-15 (Windows callee-saved)
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 0], xmm6
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 1], xmm7
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 2], xmm8
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 3], xmm9
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 4], xmm10
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 5], xmm11
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 6], xmm12
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 7], xmm13
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 8], xmm14
        vmovdqa [rsp + _xmm_save_nca4 + 16 * 9], xmm15
%endif
        mov     [rsp + _rsp_save_nca4], rax
%ifdef SAFE_DATA
        mov     dword [rsp + _scratch_used_nca4], 0
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Restores register contents and removes the stack frame
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NCA4_FUNC_END 1
%define %%ZERO %1 ;; [clobbered] zmm: zero for stack clearing
%ifdef SAFE_DATA
        vpxorq          %%ZERO, %%ZERO, %%ZERO
%assign %%lane 0
%rep 2
        test    dword [rsp + _scratch_used_nca4], (NCA4_SCRATCH_HK4 << %%lane)
        jz      %%hk4_cleared_ %+ %%lane
        vmovdqa32       [rsp + _hk_x2 + %%lane*HKeySize + HashKey_4], %%ZERO
        vmovdqa32       [rsp + _hk_x2 + %%lane*HKeySize + HashKeyK_4], %%ZERO
align_label
%%hk4_cleared_ %+ %%lane:
%assign %%lane (%%lane + 1)
%endrep
        vmovdqa32       [rsp + _keystream_nca4], YWORD(%%ZERO)
        clear_scratch_zmms_asm
%else
        vzeroupper
%endif
        mov     rbx, [rsp + _gpr_save_nca4 + 8*0]
        mov     rbp, [rsp + _gpr_save_nca4 + 8*1]
        mov     r12, [rsp + _gpr_save_nca4 + 8*2]
        mov     r13, [rsp + _gpr_save_nca4 + 8*3]
        mov     r14, [rsp + _gpr_save_nca4 + 8*4]
        mov     r15, [rsp + _gpr_save_nca4 + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save_nca4 + 8*6]
        mov     rdi, [rsp + _gpr_save_nca4 + 8*7]
        vmovdqa xmm6,  [rsp + _xmm_save_nca4 + 16 * 0]
        vmovdqa xmm7,  [rsp + _xmm_save_nca4 + 16 * 1]
        vmovdqa xmm8,  [rsp + _xmm_save_nca4 + 16 * 2]
        vmovdqa xmm9,  [rsp + _xmm_save_nca4 + 16 * 3]
        vmovdqa xmm10, [rsp + _xmm_save_nca4 + 16 * 4]
        vmovdqa xmm11, [rsp + _xmm_save_nca4 + 16 * 5]
        vmovdqa xmm12, [rsp + _xmm_save_nca4 + 16 * 6]
        vmovdqa xmm13, [rsp + _xmm_save_nca4 + 16 * 7]
        vmovdqa xmm14, [rsp + _xmm_save_nca4 + 16 * 8]
        vmovdqa xmm15, [rsp + _xmm_save_nca4 + 16 * 9]
%endif
        mov     rsp, [rsp + _rsp_save_nca4]     ;; original SP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Stash per-lane job inputs into OOO (slot LANE): args_in = src+offset,
;; args_out = dst, args_keys = enc_keys, args_IV = *iv, job_in_lane = job,
;; aad_len, msg_len.  Increments lanes_in_use.
;; Returns %%LANE_OUT = allocated (IDLE) lane.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_STASH_LANE_FROM_JOB 5
%define %%LANE_OUT      %1      ;; [out] GP reg: allocated lane index (0 or 1)
%define %%TMP_GP        %2      ;; [clobbered] GP reg
%define %%JOB_REG       %3      ;; [in] GP reg holding the job pointer
%define %%OFF_GP        %4      ;; [clobbered] GP reg: IV byte-offset scratch
%define %%IV_SCR        %5      ;; [clobbered] xmm: IV load scratch

        ;; Pick the IDLE lane (carry scheduler frees 0 or 1, so lanes_in_use is
        ;; not a valid index).  A free lane always exists: every submit that fills
        ;; both lanes retires at least one before returning.
        xor     %%LANE_OUT, %%LANE_OUT
        cmp     qword [state + _snow5g_nca4_phase + 0], NCA4_PHASE_IDLE
        setne   BYTE(%%LANE_OUT)
        add     qword [state + _snow5g_lanes_in_use], 1

        mov     [state + _snow5g_job_in_lane + %%LANE_OUT*8], %%JOB_REG

        mov     %%TMP_GP, [%%JOB_REG + _src]
        add     %%TMP_GP, [%%JOB_REG + _cipher_start_src_offset_in_bytes]
        mov     [state + _snow5g_args_in   + %%LANE_OUT*8], %%TMP_GP

        mov     %%TMP_GP, [%%JOB_REG + _dst]
        mov     [state + _snow5g_args_out  + %%LANE_OUT*8], %%TMP_GP

        mov     %%TMP_GP, [%%JOB_REG + _enc_keys]
        mov     [state + _snow5g_args_keys + %%LANE_OUT*8], %%TMP_GP

        mov     %%TMP_GP, [%%JOB_REG + _iv]
        vmovdqu64 %%IV_SCR, [%%TMP_GP]
        ;; IV stride is 16 bytes per lane.  Use a separate scaled index so
        ;; LANE_OUT is preserved for subsequent uses.
        mov     %%OFF_GP, %%LANE_OUT
        shl     %%OFF_GP, 4
        vmovdqu64 [state + _snow5g_args_IV + %%OFF_GP], %%IV_SCR

        ;; NCA4 extension fields.
        mov     %%TMP_GP, [%%JOB_REG + _nca_aad_len]
        mov     [state + _snow5g_nca4_aad_len + %%LANE_OUT*8], %%TMP_GP

        mov     %%TMP_GP, [%%JOB_REG + _msg_len_to_cipher_in_bytes]
        mov     [state + _snow5g_nca4_msg_len + %%LANE_OUT*8], %%TMP_GP
%endmacro

%macro SUBMIT_JOB_SNOW5G_NCA4_X2 43
%define %%DIR            %1      ;; [in] ENCRYPT or DECRYPT
%define %%LANE_GP        %2      ;; [clobbered] gp: allocated lane index scratch
%define %%TMP_GP         %3      ;; [clobbered] gp: opposite-lane scratch
%define %%REM_GP         %4      ;; [clobbered] gp: general scratch (job ptr / mask build / msg len)
%define %%T0             %5      ;; [clobbered] ymm/xmm scratch
%define %%FSM_R1         %6      ;; [in/out] ymm: packed lane-pair FSM_R1 (L01 bank)
%define %%FSM_R2         %7      ;; [in/out] ymm: packed lane-pair FSM_R2 (L01 bank)
%define %%FSM_R3         %8      ;; [in/out] ymm: packed lane-pair FSM_R3 (L01 bank)
%define %%LFSR_A_LDQ     %9      ;; [in/out] ymm: packed lane-pair LFSR_A_LDQ (L01 bank)
%define %%LFSR_A_HDQ     %10     ;; [in/out] ymm: packed lane-pair LFSR_A_HDQ (L01 bank)
%define %%LFSR_B_LDQ     %11     ;; [in/out] ymm: packed lane-pair LFSR_B_LDQ (L01 bank)
%define %%LFSR_B_HDQ     %12     ;; [in/out] ymm: packed lane-pair LFSR_B_HDQ (L01 bank)
%define %%T1             %13     ;; [clobbered] ymm/xmm scratch
%define %%T4             %14     ;; [clobbered] ymm/xmm scratch
%define %%T5             %15     ;; [clobbered] ymm/xmm scratch
%define %%COUNTER_GP     %16     ;; [clobbered] gp: byte offset counter
%define %%MASK_K1        %17     ;; [clobbered] k register
%define %%MASK_K2        %18     ;; [clobbered] k register
%define %%FOLD_PTR_GP    %19     ;; [clobbered] gp: message pointer / AAD pointer scratch
%define %%MSG_LEN_GP     %20     ;; [clobbered] gp: AAD/message length scratch
%define %%HK1            %21     ;; [clobbered] xmm: HK^1
%define %%KK1            %22     ;; [clobbered] xmm: KK^1
%define %%ACC            %23     ;; [clobbered] xmm/zmm: POLYVAL accumulator
%define %%T2             %24     ;; [clobbered] xmm scratch
%define %%T3             %25     ;; [clobbered] xmm scratch
%define %%FOLD_LEN_GP    %26     ;; [clobbered] gp: 64B-group count
%define %%TAIL_GP        %27     ;; [clobbered] gp: HK table pointer / tail bytes
%define %%HKN            %28     ;; [clobbered] xmm/zmm: rolling HK^n
%define %%ZBUILD         %29     ;; [clobbered] zmm: HK powers assembly
%define %%HASH4_T6       %30     ;; [clobbered] zmm: HASH_4_OR_8 extra scratch
%define %%FIN0           %31     ;; [clobbered] xmm: finalize scratch / lane-1 split FSM_R2 bank
%define %%FIN1           %32     ;; [clobbered] xmm: finalize scratch / lane-1 split FSM_R3 bank
%define %%FIN2           %33     ;; [clobbered] xmm: finalize scratch
%define %%FIN3           %34     ;; [clobbered] xmm: finalize scratch
%define %%FIN4           %35     ;; [clobbered] xmm: finalize scratch
%define %%FIN5           %36     ;; [clobbered] xmm: finalize scratch
%define %%L1_FSM_R1      %37     ;; [out] xmm: lane-1 split FSM_R1 bank register
%define %%L1_LFSR_A_LDQ  %38     ;; [out] xmm: lane-1 split LFSR_A_LDQ bank register
%define %%L1_LFSR_A_HDQ  %39     ;; [out] xmm: lane-1 split LFSR_A_HDQ bank register
%define %%L1_LFSR_B_LDQ  %40     ;; [out] xmm: lane-1 split LFSR_B_LDQ bank register
%define %%L1_LFSR_B_HDQ  %41     ;; [out] xmm: lane-1 split LFSR_B_HDQ bank register
%define %%DST_GP         %42     ;; [clobbered] gp: lane 0 dst pointer / fresh-lane key pointer scratch
%define %%DST1_GP        %43     ;; [clobbered] gp: lane 1 dst pointer

        SNOW5G_NCA4_FUNC_START

        NCA4_STASH_LANE_FROM_JOB %%LANE_GP, %%TMP_GP, job, %%REM_GP, XWORD(%%T0)
        mov     qword [state + _snow5g_nca4_phase + %%LANE_GP*8], NCA4_PHASE_STASHED

        ;; If only one lane busy, park: return NULL with NO init work done.
        cmp     qword [state + _snow5g_lanes_in_use], 2
        jne     %%return_null_submit

        ;; arg1 (rcx on Windows) is reused as scratch below.
        mov     p_state, state

        ;; Current lane is STASHED; check the opposite lane.
        mov     %%TMP_GP, %%LANE_GP
        xor     %%TMP_GP, 1
        cmp     qword [p_state + _snow5g_nca4_phase + %%TMP_GP*8], NCA4_PHASE_STASHED
        jne     %%one_fresh_lane

        ;; Both lanes fresh: 2-lane SNOW5G init + per-lane AAD seed build.
        NCA4_INIT_BOTH_LANES %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, %%T0, %%T1, \
                %%T4, %%T5, %%COUNTER_GP, %%MASK_K1, %%MASK_K2
        NCA4_HASH_AAD_LANE 0, %%REM_GP, %%FOLD_PTR_GP, %%MSG_LEN_GP, %%HK1, %%KK1, %%ACC, XWORD(%%T0), %%REM_GP, %%FOLD_LEN_GP
        NCA4_HASH_AAD_LANE 1, %%REM_GP, %%FOLD_PTR_GP, %%MSG_LEN_GP, %%HK1, %%KK1, %%ACC, XWORD(%%T0), %%REM_GP, %%FOLD_LEN_GP

        mov     qword [p_state + _snow5g_nca4_bytes_processed + 0], 0
        mov     qword [p_state + _snow5g_nca4_bytes_processed + 8], 0
        mov     qword [p_state + _snow5g_nca4_phase + 0], NCA4_PHASE_CIPHER
        mov     qword [p_state + _snow5g_nca4_phase + 8], NCA4_PHASE_CIPHER
%ifidn %%DIR, DECRYPT
        lea             p_job_in_lane, [p_state + _snow5g_job_in_lane]
        NCA4_POLYVAL_LANE 0, _snow5g_args_in, \
                %%REM_GP, %%FOLD_PTR_GP, %%MSG_LEN_GP, %%COUNTER_GP, %%TAIL_GP, %%HK1, %%KK1, %%ACC, XWORD(%%T0), XWORD(%%T1), %%T2, %%T3, XWORD(%%T4), XWORD(%%T5), \
                %%HKN, %%ZBUILD, %%HASH4_T6, %%FIN0, %%FIN1, %%FIN2, %%FIN3, %%FIN4, %%FIN5, %%REM_GP, %%FOLD_LEN_GP
        vmovdqa64       XWORD(%%T0), [rsp + _digest_nca4 + 0*16]
        vmovdqu64       [p_state + _snow5g_nca4_digest + 0*16], XWORD(%%T0)
        NCA4_POLYVAL_LANE 1, _snow5g_args_in, \
                %%REM_GP, %%FOLD_PTR_GP, %%MSG_LEN_GP, %%COUNTER_GP, %%TAIL_GP, %%HK1, %%KK1, %%ACC, XWORD(%%T0), XWORD(%%T1), %%T2, %%T3, XWORD(%%T4), XWORD(%%T5), \
                %%HKN, %%ZBUILD, %%HASH4_T6, %%FIN0, %%FIN1, %%FIN2, %%FIN3, %%FIN4, %%FIN5, %%REM_GP, %%FOLD_LEN_GP
        vmovdqa64       XWORD(%%T0), [rsp + _digest_nca4 + 1*16]
        vmovdqu64       [p_state + _snow5g_nca4_digest + 1*16], XWORD(%%T0)
%endif
        jmp     %%do_joint_carry

align_label
%%one_fresh_lane:
        ;; One lane is a carried CIPHER stream (state in OOO); init only the
        ;; freshly STASHED lane on the single-lane path.
        test    %%LANE_GP, %%LANE_GP
        jnz     %%fresh_1
%assign %%fl 0
%rep 2
align_label
%%fresh_ %+ %%fl:
        NCA4_INIT_LANE_X1 %%fl, XWORD(%%FSM_R1), XWORD(%%FSM_R2), XWORD(%%FSM_R3), XWORD(%%LFSR_A_LDQ), XWORD(%%LFSR_A_HDQ), XWORD(%%LFSR_B_LDQ), XWORD(%%LFSR_B_HDQ), \
                %%DST_GP, %%COUNTER_GP, %%MASK_K2, XWORD(%%T0), XWORD(%%T1), %%T2, %%T3, XWORD(%%T4)
        NCA4_STATE_SAVE_X1 p_state, %%fl, XWORD(%%FSM_R1), XWORD(%%FSM_R2), XWORD(%%FSM_R3), XWORD(%%LFSR_A_LDQ), XWORD(%%LFSR_A_HDQ), XWORD(%%LFSR_B_LDQ), XWORD(%%LFSR_B_HDQ)
        NCA4_HASH_AAD_LANE %%fl, %%REM_GP, %%FOLD_PTR_GP, %%MSG_LEN_GP, %%HK1, %%KK1, %%ACC, XWORD(%%T0), %%REM_GP, %%FOLD_LEN_GP
        mov     qword [p_state + _snow5g_nca4_bytes_processed + %%fl*8], 0
        mov     qword [p_state + _snow5g_nca4_phase + %%fl*8], NCA4_PHASE_CIPHER
%ifidn %%DIR, DECRYPT
        lea             p_job_in_lane, [p_state + _snow5g_job_in_lane]
        NCA4_POLYVAL_LANE %%fl, _snow5g_args_in, \
                %%REM_GP, %%FOLD_PTR_GP, %%MSG_LEN_GP, %%COUNTER_GP, %%TAIL_GP, %%HK1, %%KK1, %%ACC, XWORD(%%T0), XWORD(%%T1), %%T2, %%T3, XWORD(%%T4), XWORD(%%T5), \
                %%HKN, %%ZBUILD, %%HASH4_T6, %%FIN0, %%FIN1, %%FIN2, %%FIN3, %%FIN4, %%FIN5, %%REM_GP, %%FOLD_LEN_GP
        vmovdqa64       XWORD(%%T0), [rsp + _digest_nca4 + %%fl*16]
        vmovdqu64       [p_state + _snow5g_nca4_digest + %%fl*16], XWORD(%%T0)
%endif
        jmp     %%do_joint_carry
%assign %%fl (%%fl + 1)
%endrep

align_label
%%do_joint_carry:
        NCA4_SCHED_JOINT_CARRY %%DIR, %%REM_GP, %%FOLD_LEN_GP, %%TMP_GP, %%LANE_GP, %%DST_GP, %%FOLD_PTR_GP, %%DST1_GP, %%COUNTER_GP, %%MASK_K1, \
                %%FSM_R1, %%FSM_R2, %%FSM_R3, %%LFSR_A_LDQ, %%LFSR_A_HDQ, %%LFSR_B_LDQ, %%LFSR_B_HDQ, \
                %%L1_FSM_R1, %%FIN0, %%FIN1, %%L1_LFSR_A_LDQ, %%L1_LFSR_A_HDQ, %%L1_LFSR_B_LDQ, %%L1_LFSR_B_HDQ
        jmp     %%exit_submit

align_label
%%return_null_submit:
        xor     job_rax, job_rax

align_label
%%exit_submit:
        SNOW5G_NCA4_FUNC_END zmm0
%endmacro

%macro FLUSH_JOB_SNOW5G_NCA4_X2 35
%define %%DIR           %1      ;; [in] ENCRYPT or DECRYPT
%define %%KEY_GP        %2      ;; [clobbered] gp: key pointer scratch
%define %%LOOP_CNT_GP   %3      ;; [clobbered] gp: init-round loop counter
%define %%MASK_FB_K     %4      ;; [clobbered] k register: LFSR feedback-enable mask
%define %%MASK_NOFB_K   %5      ;; [clobbered] k register: LFSR feedback-disable mask / cipher-phase mask
%define %%T0            %6      ;; [clobbered] xmm scratch
%define %%T1            %7      ;; [clobbered] xmm scratch
%define %%T2            %8      ;; [clobbered] xmm scratch
%define %%T3            %9      ;; [clobbered] xmm scratch
%define %%T4            %10     ;; [clobbered] xmm scratch
%define %%FSM_R1_L0     %11     ;; [in/out] xmm: lane 0 FSM_R1 bank register
%define %%FSM_R2_L0     %12     ;; [in/out] xmm: lane 0 FSM_R2 bank register
%define %%FSM_R3_L0     %13     ;; [in/out] xmm: lane 0 FSM_R3 bank register
%define %%LFSR_A_LDQ_L0 %14     ;; [in/out] xmm: lane 0 LFSR_A_LDQ bank register
%define %%LFSR_A_HDQ_L0 %15     ;; [in/out] xmm: lane 0 LFSR_A_HDQ bank register
%define %%LFSR_B_LDQ_L0 %16     ;; [in/out] xmm: lane 0 LFSR_B_LDQ bank register
%define %%LFSR_B_HDQ_L0 %17     ;; [in/out] xmm: lane 0 LFSR_B_HDQ bank register
%define %%JOB_GP        %18     ;; [clobbered] gp: job pointer / remaining-bytes scratch
%define %%AAD_LEN_GP    %19     ;; [clobbered] gp: AAD length / start-offset scratch
%define %%HK1           %20     ;; [clobbered] xmm: HK^1
%define %%KK1           %21     ;; [clobbered] xmm: KK^1
%define %%ACC           %22     ;; [clobbered] xmm: POLYVAL accumulator
%define %%TAIL_GP       %23     ;; [clobbered] gp: tail-byte-mask build scratch
%define %%FOLD_LEN_GP   %24     ;; [clobbered] gp: rbx, absorb helper length argument
%define %%FIN0          %25     ;; [clobbered] xmm: finalize scratch / lane 1 FSM_R2 bank
%define %%FIN1          %26     ;; [clobbered] xmm: finalize scratch / lane 1 FSM_R3 bank
%define %%FIN2          %27     ;; [clobbered] xmm: finalize scratch
%define %%FIN3          %28     ;; [clobbered] xmm: finalize scratch
%define %%FIN4          %29     ;; [clobbered] xmm: finalize scratch
%define %%FIN5          %30     ;; [clobbered] xmm: finalize scratch
%define %%FSM_R1_L1     %31     ;; [in/out] xmm: lane 1 FSM_R1 bank register
%define %%LFSR_A_LDQ_L1 %32     ;; [in/out] xmm: lane 1 LFSR_A_LDQ bank register
%define %%LFSR_A_HDQ_L1 %33     ;; [in/out] xmm: lane 1 LFSR_A_HDQ bank register
%define %%LFSR_B_LDQ_L1 %34     ;; [in/out] xmm: lane 1 LFSR_B_LDQ bank register
%define %%LFSR_B_HDQ_L1 %35     ;; [in/out] xmm: lane 1 LFSR_B_HDQ bank register

        SNOW5G_NCA4_FUNC_START

        xor     job_rax, job_rax
        ;; There is 1 or 0 active lanes; if 0, return NULL (no work done)
        cmp     qword [state + _snow5g_lanes_in_use], 0
        jz      %%exit_flush

        ;; arg1 (rcx on Windows) is reused as scratch below.
        mov     p_state, state
        lea     p_job_in_lane, [p_state + _snow5g_job_in_lane]

        ;; --- Init any STASHED lanes (single-lane XMM init per lane) ---
        ;; Each stashed lane is brought up independently in its own X1 register
        ;; bank, leaving any already-CIPHER partner lane's OOO state untouched.
        ;; Check lane 0 phase.
        cmp     qword [p_state + _snow5g_nca4_phase + 0], NCA4_PHASE_STASHED
        jne     %%lane0_check_cipher
        ;; process lane 0 only - no job in lane 1.
        NCA4_INIT_LANE_X1 0, %%FSM_R1_L0, %%FSM_R2_L0, %%FSM_R3_L0, %%LFSR_A_LDQ_L0, %%LFSR_A_HDQ_L0, %%LFSR_B_LDQ_L0, %%LFSR_B_HDQ_L0, \
                %%KEY_GP, %%LOOP_CNT_GP, %%MASK_FB_K, %%T0, %%T1, %%T2, %%T3, %%T4
        NCA4_STATE_SAVE_X1 p_state, 0, %%FSM_R1_L0, %%FSM_R2_L0, %%FSM_R3_L0, %%LFSR_A_LDQ_L0, %%LFSR_A_HDQ_L0, %%LFSR_B_LDQ_L0, %%LFSR_B_HDQ_L0
        NCA4_HASH_AAD_LANE 0, %%JOB_GP, %%KEY_GP, %%AAD_LEN_GP, %%HK1, %%KK1, %%ACC, %%T0, %%JOB_GP, %%FOLD_LEN_GP
        mov     qword [p_state + _snow5g_nca4_phase + 0], NCA4_PHASE_CIPHER
        mov     qword [p_state + _snow5g_nca4_bytes_processed + 0], 0
%ifidn %%DIR, DECRYPT
        ;; Hash + finalize the whole input before any in-place cipher; keep tag in OOO.
        NCA4_POLYVAL_LANE 0, _snow5g_args_in, \
                %%JOB_GP, %%KEY_GP, %%AAD_LEN_GP, %%LOOP_CNT_GP, %%TAIL_GP, %%HK1, %%KK1, %%ACC, %%T0, %%T1, %%T2, %%T3, xmm4, xmm5, \
                xmm10, zmm11, zmm7, %%FIN0, %%FIN1, %%FIN2, %%FIN3, %%FIN4, %%FIN5, %%JOB_GP, %%FOLD_LEN_GP
        vmovdqa64 %%T0, [rsp + _digest_nca4 + 0*16]
        vmovdqu64 [p_state + _snow5g_nca4_digest + 0*16], %%T0
%endif
        jmp     %%lane0_cipher
align_label
%%lane0_check_cipher:
        cmp     qword [p_state + _snow5g_nca4_phase + 0], NCA4_PHASE_CIPHER
        jne     %%lane1_check_stashed

align_label
%%lane0_cipher:
        NCA4_RUN_CIPHER_X1 0, %%DIR, \
                %%LOOP_CNT_GP, %%JOB_GP, %%AAD_LEN_GP, %%TAIL_GP, %%KEY_GP, %%FOLD_LEN_GP, %%MASK_NOFB_K, \
                %%T0, %%T1, %%T2, %%T3, %%ACC, %%FIN0, %%FIN1, %%FIN2, %%FIN3, %%FIN4, %%FIN5
        ;; lane 0 is done, retire it and return its job.
        mov     job_rax, [p_state + _snow5g_job_in_lane]
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED
        mov     qword [p_state + _snow5g_job_in_lane], 0
        mov     qword [p_state + _snow5g_nca4_phase + 0], NCA4_PHASE_IDLE
        sub     qword [p_state + _snow5g_lanes_in_use], 1
        NCA4_CLEAR_LANE 0
        jmp     %%exit_flush

align_label
%%lane1_check_stashed:
        ;; no job at lane 0 - job must be at lane 1, check lane 1 phase.
        cmp     qword [p_state + _snow5g_nca4_phase + 8], NCA4_PHASE_STASHED
        jne     %%lane1_cipher
        NCA4_INIT_LANE_X1 1, %%FSM_R1_L1, %%FIN0, %%FIN1, %%LFSR_A_LDQ_L1, %%LFSR_A_HDQ_L1, %%LFSR_B_LDQ_L1, %%LFSR_B_HDQ_L1, \
                %%KEY_GP, %%LOOP_CNT_GP, %%MASK_FB_K, %%T0, %%T1, %%T2, %%T3, %%T4
        NCA4_STATE_SAVE_X1 p_state, 1, %%FSM_R1_L1, %%FIN0, %%FIN1, %%LFSR_A_LDQ_L1, %%LFSR_A_HDQ_L1, %%LFSR_B_LDQ_L1, %%LFSR_B_HDQ_L1
        NCA4_HASH_AAD_LANE 1, %%JOB_GP, %%KEY_GP, %%AAD_LEN_GP, %%HK1, %%KK1, %%ACC, %%T0, %%JOB_GP, %%FOLD_LEN_GP
        mov     qword [p_state + _snow5g_nca4_phase + 8], NCA4_PHASE_CIPHER
        mov     qword [p_state + _snow5g_nca4_bytes_processed + 8], 0
%ifidn %%DIR, DECRYPT
        ;; Hash + finalize the whole input before any in-place cipher; keep tag in OOO.
        NCA4_POLYVAL_LANE 1, _snow5g_args_in, \
                %%JOB_GP, %%KEY_GP, %%AAD_LEN_GP, %%LOOP_CNT_GP, %%TAIL_GP, %%HK1, %%KK1, %%ACC, %%T0, %%T1, %%T2, %%T3, xmm4, xmm5, \
                xmm10, zmm11, zmm7, %%FIN0, %%FIN1, %%FIN2, %%FIN3, %%FIN4, %%FIN5, %%JOB_GP, %%FOLD_LEN_GP
        vmovdqa64 %%T0, [rsp + _digest_nca4 + 1*16]
        vmovdqu64 [p_state + _snow5g_nca4_digest + 1*16], %%T0
%endif
align_label
%%lane1_cipher:
        NCA4_RUN_CIPHER_X1 1, %%DIR, \
                %%LOOP_CNT_GP, %%JOB_GP, %%AAD_LEN_GP, %%TAIL_GP, %%KEY_GP, %%FOLD_LEN_GP, %%MASK_NOFB_K, \
                %%T0, %%T1, %%T2, %%T3, %%ACC, %%FIN0, %%FIN1, %%FIN2, %%FIN3, %%FIN4, %%FIN5

        ;; lane 1 is done
        mov     job_rax, [p_state + _snow5g_job_in_lane + 8]
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED
        mov     qword [p_state + _snow5g_job_in_lane + 8], 0
        mov     qword [p_state + _snow5g_nca4_phase + 8], NCA4_PHASE_IDLE
        sub     qword [p_state + _snow5g_lanes_in_use], 1
        NCA4_CLEAR_LANE 1
        jmp     %%exit_flush

align_label
%%exit_flush:
        SNOW5G_NCA4_FUNC_END zmm0
%endmacro

;; submit_job_snow5g_nca4_enc_vaes_avx512(state, job) - encrypt queue
MKGLOBAL(submit_job_snow5g_nca4_enc_vaes_avx512,function,internal)
align_function
submit_job_snow5g_nca4_enc_vaes_avx512:
        SUBMIT_JOB_SNOW5G_NCA4_X2 ENCRYPT, r8, r15, rax, ymm0, ymm12, ymm13, ymm14, ymm24, ymm25, ymm26, ymm27, ymm1, ymm4, ymm5, rcx, k1, k2, \
                r10, r11, xmm9, xmm8, xmm6, xmm2, xmm3, rbx, rdx, xmm10, zmm11, zmm7, \
                xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, xmm15, xmm28, xmm29, xmm30, xmm31, r9, rbp
        ret

;; flush_job_snow5g_nca4_enc_vaes_avx512(state) - encrypt queue
MKGLOBAL(flush_job_snow5g_nca4_enc_vaes_avx512,function,internal)
align_function
flush_job_snow5g_nca4_enc_vaes_avx512:
        FLUSH_JOB_SNOW5G_NCA4_X2 ENCRYPT, r10, rcx, k2, k1, xmm0, xmm1, xmm2, xmm3, xmm4, \
                xmm12, xmm13, xmm14, xmm24, xmm25, xmm26, xmm27, rax, r11, xmm9, xmm8, xmm6, rdx, rbx, \
                xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, xmm15, xmm28, xmm29, xmm30, xmm31
        ret

;; submit_job_snow5g_nca4_dec_vaes_avx512(state, job) - decrypt queue
MKGLOBAL(submit_job_snow5g_nca4_dec_vaes_avx512,function,internal)
align_function
submit_job_snow5g_nca4_dec_vaes_avx512:
        SUBMIT_JOB_SNOW5G_NCA4_X2 DECRYPT, r8, r15, rax, ymm0, ymm12, ymm13, ymm14, ymm24, ymm25, ymm26, ymm27, ymm1, ymm4, ymm5, rcx, k1, k2, \
                r10, r11, xmm9, xmm8, xmm6, xmm2, xmm3, rbx, rdx, xmm10, zmm11, zmm7, \
                xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, xmm15, xmm28, xmm29, xmm30, xmm31, r9, rbp
        ret

;; flush_job_snow5g_nca4_dec_vaes_avx512(state) - decrypt queue
MKGLOBAL(flush_job_snow5g_nca4_dec_vaes_avx512,function,internal)
align_function
flush_job_snow5g_nca4_dec_vaes_avx512:
        FLUSH_JOB_SNOW5G_NCA4_X2 DECRYPT, r10, rcx, k2, k1, xmm0, xmm1, xmm2, xmm3, xmm4, \
                xmm12, xmm13, xmm14, xmm24, xmm25, xmm26, xmm27, rax, r11, xmm9, xmm8, xmm6, rdx, rbx, \
                xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, xmm15, xmm28, xmm29, xmm30, xmm31
        ret

mksection stack-noexec
