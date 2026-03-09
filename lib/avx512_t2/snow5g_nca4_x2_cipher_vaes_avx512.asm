;;
;; Copyright (c) 2026, Intel Corporation
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

;; SNOW5G-NCA4 2-lane cipher and HQP generation for AVX512-VAES

%include "include/snow5g_x8_vaes_avx512.inc"

%ifdef LINUX
%define arg4    rcx
%define arg5    r8
%else
%define arg4    r9
%endif

mksection .text
default rel

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; generate_hqp_snow5g_nca4_x2_vaes_avx512(keys[2], ivs, hqp_out, state_out)
;; Generate H, Q, P and initialized SNOW5G states for 2 lanes
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(generate_hqp_snow5g_nca4_x2_vaes_avx512,function,internal)
align_function
generate_hqp_snow5g_nca4_x2_vaes_avx512:
        SNOW5G_FUNC_START

        mov     r12, arg4

        SNOW5G_INIT_STATE_X2 arg1, arg2
        SNOW5G_INIT_ROUNDS_X2 arg1

        kxord   k2, k2, k2
        SNOW5G_ENC_DEC_LANE_PAIR 0, FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                _LFSR_A_HDQ_01, _LFSR_B_HDQ_01, _keystream_01, \
                TEMP0, TEMP1, 0, 0, 0, 0, r10, r11, k2, k3, 1
        vmovdqa32       TEMP0, [rsp + _keystream_01]
        vmovdqu32       [arg3 + 0*48 + 0], XWORD(TEMP0)
        vextracti32x4   [arg3 + 1*48 + 0], TEMP0, 1
        SNOW5G_ENC_DEC_LANE_PAIR 0, FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                _LFSR_A_HDQ_01, _LFSR_B_HDQ_01, _keystream_01, \
                TEMP0, TEMP1, 0, 0, 0, 0, r10, r11, k2, k3, 1
        vmovdqa32       TEMP0, [rsp + _keystream_01]
        vmovdqu32       [arg3 + 0*48 + 16], XWORD(TEMP0)
        vextracti32x4   [arg3 + 1*48 + 16], TEMP0, 1
        SNOW5G_ENC_DEC_LANE_PAIR 0, FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                _LFSR_A_HDQ_01, _LFSR_B_HDQ_01, _keystream_01, \
                TEMP0, TEMP1, 0, 0, 0, 0, r10, r11, k2, k3, 1
        vmovdqa32       TEMP0, [rsp + _keystream_01]
        vmovdqu32       [arg3 + 0*48 + 32], XWORD(TEMP0)
        vextracti32x4   [arg3 + 1*48 + 32], TEMP0, 1

        test    r12, r12
        jz      .skip_state_store_x2
        STATE_STORE_NCA4_X2 r12
align_label
.skip_state_store_x2:

        SNOW5G_FUNC_END
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; snow5g_nca4_cipher_x2(states, src[2], dst[2], len_lane0, len_lane1)
;; 2-lane cipher: 16-byte blocks (both/single lane) + masked tail.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(snow5g_nca4_cipher_x2,function,internal)
align_function
snow5g_nca4_cipher_x2:
        SNOW5G_FUNC_START

%define rem0            r12
%define rem1            rbx
%define num_blocks      r13
%define num_extra       r14
%define longer_lane     r11
%define offset          r15

%ifdef LINUX
        mov     num_extra, arg4
        mov     offset, arg5
%else
        mov     num_extra, arg4
        ;; arg5: 5th Windows stack param at [original_rsp + 40]
        mov     offset, [rsp + _rsp_save]
        mov     offset, [offset + 40]
%endif
        mov     DWORD(rem0), DWORD(num_extra)
        mov     DWORD(rem1), DWORD(offset)
        and     DWORD(rem0), 15
        and     DWORD(rem1), 15
        shr     DWORD(num_extra), 4
        shr     DWORD(offset), 4

        mov     DWORD(num_blocks), DWORD(num_extra)
        xor     DWORD(longer_lane), DWORD(longer_lane)
        cmp     DWORD(num_extra), DWORD(offset)
        cmova   DWORD(num_blocks), DWORD(offset)
        cmovb   DWORD(num_extra), DWORD(offset)
        setb    BYTE(longer_lane)
        sub     DWORD(num_extra), DWORD(num_blocks)
        xor     offset, offset

        STATE_LOAD_NCA4_X2 arg1
        kxord   k1, k1, k1

        ;; Phase 1: both lanes, full blocks
        test    DWORD(num_blocks), DWORD(num_blocks)
        jz      .phase1_done
align_loop
.phase1:
        NCA4_CIPHER_L01 offset, 2
        add     offset, 16
        dec     DWORD(num_blocks)
        jnz     .phase1
align_label
.phase1_done:

        ;; Phase 2: extra full blocks for the longer lane
        test    DWORD(num_extra), DWORD(num_extra)
        jz      .phase2_done
        test    DWORD(longer_lane), DWORD(longer_lane)
        jnz     .phase2_lane1
align_loop
.phase2_lane0:
        NCA4_CIPHER_L01 offset, 0
        add     offset, 16
        dec     DWORD(num_extra)
        jnz     .phase2_lane0
        jmp     .phase2_done
align_loop
.phase2_lane1:
        NCA4_CIPHER_L01 offset, 1
        add     offset, 16
        dec     DWORD(num_extra)
        jnz     .phase2_lane1
align_label
.phase2_done:

        ;; Tail: partial bytes via table-driven masked stores
        mov     DWORD(rbp), DWORD(rem0)
        or      DWORD(rbp), DWORD(rem1)
        jz      .skip_cipher_x2

        vpaddw  TEMP1, LFSR_B_HDQ_L01, FSM_R1_L01
        vpxord  TEMP1, TEMP1, FSM_R2_L01

        lea     rax, [rel byte_len_to_mask_table_nca4]
        kmovw   k1, [rax + rem0*2]
        mov     rbp, [arg2]
        vmovdqu8        XWORD(TEMP2){k1}{z}, [rbp + offset]
        vpxord          XWORD(TEMP2), XWORD(TEMP1), XWORD(TEMP2)
        mov     r10, [arg3]
        vmovdqu8        [r10 + offset]{k1}, XWORD(TEMP2)

        vextracti32x4   XWORD(TEMP1), TEMP1, 1
        kmovw   k1, [rax + rem1*2]
        mov     rbp, [arg2 + 8]
        vmovdqu8        XWORD(TEMP2){k1}{z}, [rbp + offset]
        vpxord          XWORD(TEMP2), XWORD(TEMP1), XWORD(TEMP2)
        mov     r10, [arg3 + 8]
        vmovdqu8        [r10 + offset]{k1}, XWORD(TEMP2)

.skip_cipher_x2:
        SNOW5G_FUNC_END
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; snow5g_nca4_cipher_x1(states, src[2], dst[2], len_lane0)
;; 1-lane cipher (lane 0 only): 16-byte blocks + masked tail.
;; Lane 1 state is clocked but no data is processed for it.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
MKGLOBAL(snow5g_nca4_cipher_x1,function,internal)
align_function
snow5g_nca4_cipher_x1:
        SNOW5G_FUNC_START

%define rem0            r12
%define num_blocks      r14
%define offset          r15

        mov     num_blocks, arg4
        mov     DWORD(rem0), DWORD(num_blocks)
        and     DWORD(rem0), 15
        shr     DWORD(num_blocks), 4
        xor     offset, offset

        STATE_LOAD_NCA4_X2 arg1
        kxord   k1, k1, k1

        test    DWORD(num_blocks), DWORD(num_blocks)
        jz      .x1_blocks_done
align_loop
.x1_blocks:
        NCA4_CIPHER_L01 offset, 0
        add     offset, 16
        dec     DWORD(num_blocks)
        jnz     .x1_blocks
align_label
.x1_blocks_done:

        ;; Tail: partial bytes for lane 0 only
        test    DWORD(rem0), DWORD(rem0)
        jz      .skip_cipher_x1

        vpaddw  TEMP1, LFSR_B_HDQ_L01, FSM_R1_L01
        vpxord  TEMP1, TEMP1, FSM_R2_L01

        lea     rax, [rel byte_len_to_mask_table_nca4]
        kmovw   k1, [rax + rem0*2]
        mov     rbp, [arg2]
        vmovdqu8        XWORD(TEMP2){k1}{z}, [rbp + offset]
        vpxord          XWORD(TEMP2), XWORD(TEMP1), XWORD(TEMP2)
        mov     r10, [arg3]
        vmovdqu8        [r10 + offset]{k1}, XWORD(TEMP2)

.skip_cipher_x1:
        SNOW5G_FUNC_END
        ret

mksection stack-noexec
