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

%xdefine TEMP0                  ymm0
%xdefine TEMP1                  ymm1
%xdefine TEMP2                  ymm2
%xdefine FSM_R1_L01             ymm12
%xdefine FSM_R2_L01             ymm13
%xdefine FSM_R3_L01             ymm14
%xdefine LFSR_A_LDQ_L01         ymm24
%xdefine LFSR_A_HDQ_L01         ymm25
%xdefine LFSR_B_LDQ_L01         ymm26
%xdefine LFSR_B_HDQ_L01         ymm27

%define NCA4_HQP_SIZE           48  ;; HQP: H(16) | Q(16) | P(16) = 48 bytes per lane

%define NCA4_SCRATCH_HK4        1

;; Callee-saved GP register aliases
%define p_state         r12
%define p_job_in_lane   r13

struc STACK_NCA4_WORK
_digest_nca4:    resb    (16 * 2)                        ; 2 x 16-byte digest output
_keystream_nca4: resy    1                               ; 32-byte keystream scratch
;; POLYVAL HK tables: 2 lanes x 256 bytes (HK^8..HK^1 + KK^8..KK^1)
_hk_x2:          resb    (HKeySize * 2)
_gpr_save_nca4: resq     10
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
%macro NCA4_POLYVAL_LANE 28
%define %%LANE         %1  ;; [in] lane index (0 or 1)
%define %%DATA_FLD     %2  ;; [in] state field for msg pointer (_snow5g_args_in or _snow5g_args_out)
%define %%CHECK_NULL   %3  ;; [in] 1 = guard against NULL job, 0 = job guaranteed non-NULL
%define %%JOB_GP       %4  ;; [clobbered] gp: job pointer
%define %%MSG_PTR_GP   %5  ;; [clobbered] gp: message pointer (reused as AAD length at finalize)
%define %%MSG_LEN_GP   %6  ;; [clobbered] gp: bytes to absorb (whole msg, then tail)
%define %%GRP_CNT_GP   %7  ;; [clobbered] gp: 64B-group count
%define %%HK_PTR_GP    %8  ;; [clobbered] gp: HK^4 table pointer
%define %%HK1          %9  ;; [clobbered] xmm: HK^1
%define %%KK1          %10 ;; [clobbered] xmm: KK^1 (HashKey_K helper)
%define %%ACC          %11 ;; [clobbered] xmm/zmm: running POLYVAL accumulator
%define %%T0           %12 ;; [clobbered] xmm scratch
%define %%T1           %13 ;; [clobbered] xmm scratch (reused as Q key at finalize)
%define %%T2           %14 ;; [clobbered] xmm scratch (reused as P key at finalize)
%define %%T3           %15 ;; [clobbered] xmm scratch
%define %%T4           %16 ;; [clobbered] xmm scratch
%define %%T5           %17 ;; [clobbered] xmm scratch
%define %%HKN          %18 ;; [clobbered] xmm/zmm: rolling HK^n / HASH_4_OR_8 scratch
%define %%ZBUILD       %19 ;; [clobbered] zmm: HK powers assembly / HASH_4_OR_8 scratch
%define %%HASH4_T6     %20 ;; [clobbered] zmm: HASH_4_OR_8 extra scratch
%define %%ABSORB_T0    %21 ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%ABSORB_T1    %22 ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%ABSORB_T2    %23 ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%ABSORB_T3    %24 ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%ABSORB_T4    %25 ;; [clobbered] xmm: ABSORB_BYTES/FINALIZE_LANE scratch
%define %%FINALIZE_SCR %26 ;; [clobbered] xmm: FINALIZE_LANE len_block scratch
%define %%ABSORB_PTR_GP %27 ;; [clobbered] gp: rax, helper pointer argument
%define %%ABSORB_LEN_GP %28 ;; [clobbered] gp: rbx, helper length argument

        mov     %%JOB_GP, [p_job_in_lane + %%LANE*8]
%if %%CHECK_NULL
        test    %%JOB_GP, %%JOB_GP
        jz      %%skip_polyval_ %+ %%LANE
%endif

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

%if %%CHECK_NULL
%%skip_polyval_ %+ %%LANE:
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Per-lane tag output: masked store of digest to auth_tag_output
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro NCA4_COPY_TAG 7
%define %%LANE       %1  ;; [in] lane index (0 or 1)
%define %%CHECK_NULL %2 ;; [in] 1 = guard against NULL job, 0 = job guaranteed non-NULL
%define %%TMP0       %3  ;; [clobbered] xmm
%define %%JOB_GP     %4  ;; [clobbered] gp: job pointer
%define %%LEN_GP     %5  ;; [clobbered] gp: tag length in bytes
%define %%PTR_GP     %6  ;; [clobbered] gp: auth_tag_output pointer
%define %%MASK_K     %7  ;; [clobbered] k register: tag byte mask

        mov     %%JOB_GP, [p_job_in_lane + %%LANE*8]
%if %%CHECK_NULL
        ;; During flush the inactive lane's job slot may be NULL
        test    %%JOB_GP, %%JOB_GP
        jz      %%skip_tag_ %+ %%LANE
%endif

        vmovdqa64 %%TMP0, [rsp + _digest_nca4 + %%LANE*16]
        mov     DWORD(%%LEN_GP), [%%JOB_GP + _auth_tag_output_len_in_bytes]
        mov     %%PTR_GP, [%%JOB_GP + _auth_tag_output]
        ;; Build byte mask from tag length: MASK_K = (1 << LEN_GP) - 1
        mov     DWORD(%%JOB_GP), -1
        bzhi    DWORD(%%JOB_GP), DWORD(%%JOB_GP), DWORD(%%LEN_GP)
        kmovw   %%MASK_K, DWORD(%%JOB_GP)
        vmovdqu8 [%%PTR_GP]{%%MASK_K}, %%TMP0

%if %%CHECK_NULL
%%skip_tag_ %+ %%LANE:
%endif
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; 2-lane cipher: full 16-byte blocks + masked tail per lane.
;; Clobbers: rax, rbx, rbp, r8-r15, ymm0-ymm5, k1
;; Expects the FSM/LFSR state live in the L01 YMM registers.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NCA4_CIPHER_X2 0
%define %%rem0          r12
%define %%rem1          rbx
%define %%num_blocks    r13
%define %%len0          r14     ;; [in] lane 0 length in bytes, [clobbered] extra full blocks
%define %%longer_lane   r11
%define %%len1          r15     ;; [in] lane 1 length in bytes, [clobbered] byte offset

        mov     rax, %%len0
        or      rax, %%len1
        jz      %%cipher_done

        ;; Load src/dst pointers ONCE for all phases (constant across loop).
        ;; Read directly via p_state (r12) before %%rem0 alias overwrites it.
        mov     r8,  [p_state + _snow5g_args_in + 0]    ;; src lane 0
        mov     r9,  [p_state + _snow5g_args_out + 0]   ;; dst lane 0
        mov     r10, [p_state + _snow5g_args_in + 8]    ;; src lane 1
        mov     rbp, [p_state + _snow5g_args_out + 8]   ;; dst lane 1

        mov     DWORD(%%rem0), DWORD(%%len0)
        mov     DWORD(%%rem1), DWORD(%%len1)
        and     DWORD(%%rem0), 15
        and     DWORD(%%rem1), 15
        shr     DWORD(%%len0), 4
        shr     DWORD(%%len1), 4

        mov     DWORD(%%num_blocks), DWORD(%%len0)
        xor     DWORD(%%longer_lane), DWORD(%%longer_lane)
        cmp     DWORD(%%len0), DWORD(%%len1)
        cmova   DWORD(%%num_blocks), DWORD(%%len1)
        cmovb   DWORD(%%len0), DWORD(%%len1)
        setb    BYTE(%%longer_lane)
        sub     DWORD(%%len0), DWORD(%%num_blocks)
        xor     %%len1, %%len1          ;; repurpose %%len1 as byte offset into src/dst buffers
%define %%offset        %%len1

        kxord   k1, k1, k1

        ;; Phase 1: both lanes, full blocks
        test    DWORD(%%num_blocks), DWORD(%%num_blocks)
        jz      %%phase1_done
align_loop
%%phase1:
        NCA4_CIPHER_LANE_PAIR FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                TEMP1, TEMP2, r8, r9, r10, rbp, %%offset, k1, BOTH_LANES, ymm4, ymm5
        add     %%offset, 16
        dec     DWORD(%%num_blocks)
        jnz     %%phase1
align_label
%%phase1_done:

        ;; Phase 2: extra full blocks for the longer lane
        test    DWORD(%%len0), DWORD(%%len0)
        jz      %%phase2_done

        ;; The two lanes have different block counts, so phase 2 will advance
        ;; both %%offset and the shared keystream past the end of the shorter
        ;; lane.  Emit the shorter lane's partial tail here, while %%offset and
        ;; the pending keystream still belong to it, and clear its remainder so
        ;; that the common tail below only handles the longer lane.
        vpaddw  TEMP1, LFSR_B_HDQ_L01, FSM_R1_L01
        vpxord  TEMP1, TEMP1, FSM_R2_L01
        lea     rax, [rel byte_len_to_mask_table_nca4]

        test    DWORD(%%longer_lane), DWORD(%%longer_lane)
        jnz     %%short_tail_lane0

        ;; lane 0 is the longer lane, so lane 1 holds the short tail
        kmovw           k1, [rax + %%rem1*2]
        vextracti32x4   XWORD(TEMP0), TEMP1, 1
        vmovdqu8        XWORD(TEMP2){k1}{z}, [r10 + %%offset]
        vpxord          XWORD(TEMP2), XWORD(TEMP0), XWORD(TEMP2)
        vmovdqu8        [rbp + %%offset]{k1}, XWORD(TEMP2)
        xor             DWORD(%%rem1), DWORD(%%rem1)
        kxord           k1, k1, k1
        jmp             %%phase2_lane0

align_label
%%short_tail_lane0:
        ;; lane 1 is the longer lane, so lane 0 holds the short tail
        kmovw           k1, [rax + %%rem0*2]
        vmovdqu8        XWORD(TEMP2){k1}{z}, [r8 + %%offset]
        vpxord          XWORD(TEMP2), XWORD(TEMP1), XWORD(TEMP2)
        vmovdqu8        [r9 + %%offset]{k1}, XWORD(TEMP2)
        xor             DWORD(%%rem0), DWORD(%%rem0)
        kxord           k1, k1, k1
        jmp             %%phase2_lane1
align_loop
%%phase2_lane0:
        NCA4_CIPHER_LANE_PAIR FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                TEMP1, TEMP2, r8, r9, r10, rbp, %%offset, k1, LANE0_ONLY, ymm4, ymm5
        add     %%offset, 16
        dec     DWORD(%%len0)
        jnz     %%phase2_lane0
        jmp     %%phase2_done
align_loop
%%phase2_lane1:
        NCA4_CIPHER_LANE_PAIR FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                TEMP1, TEMP2, r8, r9, r10, rbp, %%offset, k1, LANE1_ONLY, ymm4, ymm5
        add     %%offset, 16
        dec     DWORD(%%len0)
        jnz     %%phase2_lane1
align_label
%%phase2_done:

        ;; Tail: partial bytes via masked stores
        mov     DWORD(rax), DWORD(%%rem0)
        or      DWORD(rax), DWORD(%%rem1)
        jz      %%skip_tail

        vpaddw  TEMP1, LFSR_B_HDQ_L01, FSM_R1_L01
        vpxord  TEMP1, TEMP1, FSM_R2_L01

        lea     rax, [rel byte_len_to_mask_table_nca4]
        kmovw   k1, [rax + %%rem0*2]
        vmovdqu8        XWORD(TEMP2){k1}{z}, [r8 + %%offset]
        vpxord          XWORD(TEMP2), XWORD(TEMP1), XWORD(TEMP2)
        vmovdqu8        [r9 + %%offset]{k1}, XWORD(TEMP2)

        vextracti32x4   XWORD(TEMP1), TEMP1, 1
        kmovw   k1, [rax + %%rem1*2]
        vmovdqu8        XWORD(TEMP2){k1}{z}, [r10 + %%offset]
        vpxord          XWORD(TEMP2), XWORD(TEMP1), XWORD(TEMP2)
        vmovdqu8        [rbp + %%offset]{k1}, XWORD(TEMP2)
%undef %%offset

%%skip_tail:
        ;; Restore p_state/p_job_in_lane clobbered by cipher
        mov     p_state, [rsp + _gpr_save_nca4 + 8*8]
        lea     p_job_in_lane, [p_state + _snow5g_job_in_lane]
%%cipher_done:
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; NCA4 2-lane AEAD core: HQP generation, POLYVAL, cipher, tag output
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NCA4_CORE 3
%define %%STATE         %1  ;; [in] GP reg: SNOW5G OOO state pointer
%define %%DIR           %2  ;; [in] ENCRYPT or DECRYPT
%define %%LANE1_VALID   %3  ;; [in] 1=lane 1 has a job (submit), 0=lane 1 NULL (flush)

        mov     p_state, %%STATE
        lea     p_job_in_lane, [%%STATE + _snow5g_job_in_lane]

        ;; Generate HQP and SNOW5G cipher state for both lanes; the state stays
        ;; live in the L01 YMMs across AAD/message POLYVAL and the cipher.
        lea     rax, [p_state + _snow5g_args_keys]
        SNOW5G_GENERATE_HQP_X2 rax, {p_state + _snow5g_args_IV}, \
                {p_state + _snow5g_nca4_hqp}, 0, _keystream_nca4, \
                FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                TEMP0, TEMP1, ymm4, ymm5, rcx, k1, k2

        ;; Seed per-lane POLYVAL accumulators with POLYVAL(AAD)
        NCA4_HASH_AAD_LANE 0, rax, r10, r11, xmm9, xmm8, xmm6, xmm0, rax, rbx
%if %%LANE1_VALID
        NCA4_HASH_AAD_LANE 1, rax, r10, r11, xmm9, xmm8, xmm6, xmm0, rax, rbx
%endif

        ;; Collect cipher lengths into r14 (lane 0) and r15 (lane 1)
        ;; Lane 0 is always valid; lane 1 only when called from submit.
        mov     rax, [p_job_in_lane]
        mov     r14, [rax + _msg_len_to_cipher_in_bytes]
%if %%LANE1_VALID
        mov     rax, [p_job_in_lane + 8]
        mov     r15, [rax + _msg_len_to_cipher_in_bytes]
%else
        xor     r15d, r15d
%endif

        ;; POLYVAL runs over ciphertext: decrypt input before cipher, encrypt output after
%ifidn %%DIR, DECRYPT
%define %%MSG_FLD _snow5g_args_in
%else
%define %%MSG_FLD _snow5g_args_out
%endif

%ifidn %%DIR, DECRYPT
        NCA4_POLYVAL_LANE 0, %%MSG_FLD, 0, \
                rax, r10, r11, rcx, rdx, xmm9, xmm8, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, \
                xmm10, zmm11, zmm7, xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, rax, rbx
        NCA4_POLYVAL_LANE 1, %%MSG_FLD, (1 - %%LANE1_VALID), \
                rax, r10, r11, rcx, rdx, xmm9, xmm8, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, \
                xmm10, zmm11, zmm7, xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, rax, rbx
        SNOW5G_NCA4_CIPHER_X2
%else
        SNOW5G_NCA4_CIPHER_X2
        NCA4_POLYVAL_LANE 0, %%MSG_FLD, 0, \
                rax, r10, r11, rcx, rdx, xmm9, xmm8, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, \
                xmm10, zmm11, zmm7, xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, rax, rbx
        NCA4_POLYVAL_LANE 1, %%MSG_FLD, (1 - %%LANE1_VALID), \
                rax, r10, r11, rcx, rdx, xmm9, xmm8, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, \
                xmm10, zmm11, zmm7, xmm16, xmm17, xmm18, xmm19, xmm20, xmm21, rax, rbx
%endif

        NCA4_COPY_TAG 0, 0, xmm0, rax, rcx, rdx, k1
        NCA4_COPY_TAG 1, (1 - %%LANE1_VALID), xmm0, rax, rcx, rdx, k1

%ifdef SAFE_DATA
        vpxorq  xmm0, xmm0, xmm0
        vmovdqu64 [p_state + _snow5g_nca4_hqp], zmm0
        vmovdqu64 [p_state + _snow5g_nca4_hqp + 64], ymm0
        vmovdqu64 [p_state + _snow5g_nca4_polyval_acc], ymm0
        vmovdqa32 [rsp + _keystream_nca4], ymm0
%endif

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
        mov     [rsp + _gpr_save_nca4 + 8*8], state
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
%%hk4_cleared_ %+ %%lane:
%assign %%lane (%%lane + 1)
%endrep
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
;; Submits a job to the 2-buffer SNOW5G-NCA4 scheduler
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SUBMIT_JOB_SNOW5G_NCA4_X2 1

%define %%lane           r8
%define %%tmp            r15
%define %%tmp2           xmm0

        SNOW5G_NCA4_FUNC_START

        ;; Lane index = current lanes in use (0 or 1)
        mov     %%lane, [state + _snow5g_lanes_in_use]
        add     qword [state + _snow5g_lanes_in_use], 1

        ;; Store job pointer in lane
        mov     [state + _snow5g_job_in_lane + %%lane*8], job

        ;; Copy job data into lane arrays
        mov     %%tmp, [job + _src]
        add     %%tmp, [job + _cipher_start_src_offset_in_bytes]
        mov     [state + _snow5g_args_in + %%lane*8], %%tmp

        mov     %%tmp, [job + _dst]
        mov     [state + _snow5g_args_out + %%lane*8], %%tmp

        mov     %%tmp, [job + _enc_keys]
        mov     [state + _snow5g_args_keys + %%lane*8], %%tmp

        ;; Copy IV to state array (16 bytes per lane)
        mov     %%tmp, [job + _iv]
        vmovdqu %%tmp2, [%%tmp]
        shl     %%lane, 4
        vmovdqu [state + _snow5g_args_IV + %%lane], %%tmp2

        ;; Check if all 2 lanes are full (%%lane != 0 after shl means old count was 1)
        test    %%lane, %%lane
        jz      %%return_null_submit

        ;; Both lanes full - process them
        SNOW5G_NCA4_CORE state, %1, 1

        ;; Complete both jobs and reset state
        mov     job_rax, [p_state + _snow5g_job_in_lane]
        mov     rbx, [p_state + _snow5g_job_in_lane + 8]
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED
        or      dword [rbx + _status], IMB_STATUS_COMPLETED
        mov     qword [p_state + _snow5g_job_in_lane], 0
        mov     qword [p_state + _snow5g_job_in_lane + 8], 0
        mov     qword [p_state + _snow5g_lanes_in_use], 0
        jmp     %%exit_submit

align_label
%%return_null_submit:
        xor     job_rax, job_rax

align_label
%%exit_submit:
        SNOW5G_NCA4_FUNC_END zmm0
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Flushes completed jobs from the 2-buffer SNOW5G-NCA4 scheduler
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro FLUSH_JOB_SNOW5G_NCA4_X2 1

%define %%tmp            r11
%define %%tmp2           xmm0

        SNOW5G_NCA4_FUNC_START

        ;; Check for empty
        cmp     qword [state + _snow5g_lanes_in_use], 0
        jz      %%return_null_flush_nca4

        ;; With 2 lanes, flush always has lane 0 valid, lane 1 null.
        ;; Fill lane 1 from lane 0.
        mov             %%tmp, [state + _snow5g_args_in]
        mov             [state + _snow5g_args_in + 8], %%tmp

        mov             %%tmp, [state + _snow5g_args_out]
        mov             [state + _snow5g_args_out + 8], %%tmp

        mov             %%tmp, [state + _snow5g_args_keys]
        mov             [state + _snow5g_args_keys + 8], %%tmp

        vmovdqa64       %%tmp2, [state + _snow5g_args_IV]
        vmovdqa64       [state + _snow5g_args_IV + 16], %%tmp2

        SNOW5G_NCA4_CORE state, %1, 0

        ;; Complete lane 0 job and reset state
        mov     job_rax, [p_state + _snow5g_job_in_lane]
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED
        mov     qword [p_state + _snow5g_job_in_lane], 0
        mov     qword [p_state + _snow5g_lanes_in_use], 0

        jmp     %%exit_flush

align_label
%%return_null_flush_nca4:
        xor     job_rax, job_rax

align_label
%%exit_flush:
        SNOW5G_NCA4_FUNC_END zmm0
%endmacro

;; submit_job_snow5g_nca4_enc_vaes_avx512(state, job) - encrypt queue
MKGLOBAL(submit_job_snow5g_nca4_enc_vaes_avx512,function,internal)
align_function
submit_job_snow5g_nca4_enc_vaes_avx512:
        SUBMIT_JOB_SNOW5G_NCA4_X2 ENCRYPT
        ret

;; flush_job_snow5g_nca4_enc_vaes_avx512(state) - encrypt queue
MKGLOBAL(flush_job_snow5g_nca4_enc_vaes_avx512,function,internal)
align_function
flush_job_snow5g_nca4_enc_vaes_avx512:
        FLUSH_JOB_SNOW5G_NCA4_X2 ENCRYPT
        ret

;; submit_job_snow5g_nca4_dec_vaes_avx512(state, job) - decrypt queue
MKGLOBAL(submit_job_snow5g_nca4_dec_vaes_avx512,function,internal)
align_function
submit_job_snow5g_nca4_dec_vaes_avx512:
        SUBMIT_JOB_SNOW5G_NCA4_X2 DECRYPT
        ret

;; flush_job_snow5g_nca4_dec_vaes_avx512(state) - decrypt queue
MKGLOBAL(flush_job_snow5g_nca4_dec_vaes_avx512,function,internal)
align_function
flush_job_snow5g_nca4_dec_vaes_avx512:
        FLUSH_JOB_SNOW5G_NCA4_X2 DECRYPT
        ret

mksection stack-noexec
