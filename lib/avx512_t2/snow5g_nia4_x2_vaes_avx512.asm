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

;; SNOW5G-NIA4 2-lane POLYVAL-based authentication macros for AVX512-VAES

%define GCM128_MODE 1
%include "include/gcm_vaes_avx512.inc"

extern polyval_vclmul_avx512
extern polyval_pre_vclmul_avx512

;; polyval_pre_vclmul_avx512(key, gdata) — ABI-agnostic call wrapper
%macro CALL_POLYVAL_PRE 2   ;; %%key_expr, %%gdata_expr
%ifdef LINUX
        lea     rdi, [%1]
        lea     rsi, [%2]
%else
        lea     rcx, [%1]
        lea     rdx, [%2]
%endif
        call    polyval_pre_vclmul_avx512
%endmacro

%define p_buffer_in     r12
%define p_mac_i         r13
%define len_bytes       r14
%define job_in_lane     r15
%define p_hqp           rbp

struc STACK_NIA4
_hqp_nia4:           resb    (48 * 2)        ; HQP: 2 lanes x 48 bytes (H+Q+P)
_digest_nia4:        resb    16
                        resb    16              ; padding to 32B boundary
_keystream_nia4:     resb    32
_gdata_nia4:         resb    1280            ; struct gcm_key_data (lane 0)
_gdata_nia4_1:       resb    1280            ; struct gcm_key_data (lane 1)
_gpr_save_nia4:      resq    10
%ifndef LINUX
_xmm_save_nia4:      resb    (16 * 10)       ; XMM6-15 save area (Windows only)
%endif
_rsp_save_nia4:      resq    1
_idx_save_nia4:      resq    1
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Per-lane POLYVAL authentication
;; Calls polyval_vclmul_avx512 function for bulk hash (i-cache friendly),
;; then inlines digest XOR, single-block GHASH_MUL finalization, and tag output.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PROCESS_NIA4_LANE 5
%define %%LANE          %1   ;; [in] lane index (0 or 1)
%define %%GDATA_REG     %2   ;; [in] GP reg: pointer to gcm_key_data (pre-loaded)
%define %%SRC_REG       %3   ;; [in] GP reg: source data pointer (pre-loaded)
%define %%LEN_REG       %4   ;; [in] GP reg: byte length (pre-loaded)
%define %%MASKREG       %5   ;; [clobbered] k-register

        ;; polyval_vclmul_avx512(gdata_key, in, in_len, io_tag)
        ;; arg1=rdi, arg2=rsi, arg3=rdx, arg4=rcx (Linux ABI)
%ifdef LINUX
        mov     rdi, %%GDATA_REG
        mov     rsi, %%SRC_REG
        mov     edx, DWORD(%%LEN_REG)
        lea     rcx, [rsp + _digest_nia4]
%else
        mov     rcx, %%GDATA_REG
        mov     rdx, %%SRC_REG
        mov     r8d, DWORD(%%LEN_REG)
        lea     r9, [rsp + _digest_nia4]
%endif
        call    polyval_vclmul_avx512

        ;; digest ^= { 0, lengthInBytes[lane] * 8 }
        ;; vpinsrq xmm1, xmm1(zero), rax, 1: 1 P5 uop, 3cy (vs vmovq+vpslldq: 2 P5 uops, 5cy)
        vmovdqa         xmm0, [rsp + _digest_nia4]
        mov             eax, [len_bytes + %%LANE*4]
        shl             rax, 3
        vpxorq          xmm1, xmm1, xmm1
        vpinsrq         xmm1, xmm1, rax, 1
        vpxorq          xmm0, xmm0, xmm1

        ;; single-block POLYVAL of digest with Q key
        ;; Note: GHASH_MUL T4/T5 (params 6-7) are unused — xmm5 aliased safely
        vmovdqu64       xmm1, [p_hqp + 16]
        GHASH_MUL       xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm5

        ;; tag = digest ^ P
        vpxorq          xmm0, xmm0, [p_hqp + 32]

        ;; Copy tag to output — use bzhi (BMI2) for mask generation
        mov             rax, [job_in_lane + %%LANE*8]
        mov             ecx, [rax + _auth_tag_output_len_in_bytes]
        mov             eax, -1
        bzhi            eax, eax, ecx           ;; mask = low tag_len_bytes bits
        kmovw           %%MASKREG, eax
        mov             rdx, [p_mac_i + %%LANE*8]
        vmovdqu8        [rdx]{%%MASKREG}, xmm0
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; NIA4 authentication for 2 lanes — expects state pointer in r11
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NIA4_AUTH_X2 0
        ;; Register assignments
%define NIA4_T_GP       rax     ;; GP scratch / job pointer check
%define NIA4_GDATA0     rdi     ;; gcm_key_data ptr (lane 0; also Linux arg1)
%define NIA4_SRC0       rsi     ;; source data ptr  (lane 0; also Linux arg2)
%define NIA4_LEN0       rcx     ;; byte length      (lane 0; also Linux arg3)
%define NIA4_GDATA1     r8      ;; gcm_key_data ptr (lane 1)
%define NIA4_SRC1       r9      ;; source data ptr  (lane 1)
%define NIA4_LEN1       r11     ;; byte length      (lane 1; r11 free after state saved)
%define NIA4_MASKREG    k1      ;; k-register for masked store
%define NIA4_STATE      r11     ;; SNOW5G OOO state pointer (input; reused as NIA4_LEN1)
%define NIA4_KMASK2     k2      ;; SNOW5G k-register scratch
        ;; Save state field addresses into callee-saved regs before r11 is repurposed
        lea     p_buffer_in, [NIA4_STATE + _snow5g_args_in]
        lea     p_mac_i,     [NIA4_STATE + _snow5g_args_out]
        lea     len_bytes,   [NIA4_STATE + _snow5g_lens_dqw]
        lea     job_in_lane, [NIA4_STATE + _snow5g_job_in_lane]

        RESERVE_STACK_SPACE 4

        lea     NIA4_T_GP, [NIA4_STATE + _snow5g_args_keys]
        SNOW5G_GENERATE_HQP_X2 NIA4_T_GP, NIA4_STATE + _snow5g_args_IV, \
                rsp + _hqp_nia4, 0, _keystream_nia4, \
                FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                TEMP0, TEMP1, ymm4, ymm5, NIA4_LEN0, NIA4_MASKREG, NIA4_KMASK2

        mov     NIA4_T_GP, [job_in_lane + 0*8]
        test    NIA4_T_GP, NIA4_T_GP
        jz      .lane0_empty

        ;; Lane 0 PRE: compute POLYVAL HashKey table
        CALL_POLYVAL_PRE rsp + _hqp_nia4 + 0, rsp + _gdata_nia4

        ;; Lane 1 PRE: compute POLYVAL HashKey table (skip if no lane 1 job)
        mov     NIA4_T_GP, [job_in_lane + 1*8]
        test    NIA4_T_GP, NIA4_T_GP
        jz      .process_lane0
        CALL_POLYVAL_PRE rsp + _hqp_nia4 + 48, rsp + _gdata_nia4_1

.process_lane0:
        ;; Reload caller-saved regs clobbered by CALL_POLYVAL_PRE
        lea     NIA4_GDATA0,      [rsp + _gdata_nia4]
        mov     NIA4_SRC0,        [p_buffer_in + 0*8]
        mov     DWORD(NIA4_LEN0), [len_bytes + 0*4]
        vpxorq  xmm0, xmm0, xmm0
        vmovdqa [rsp + _digest_nia4], xmm0
        lea     p_hqp, [rsp + _hqp_nia4 + 0]
        PROCESS_NIA4_LANE 0, NIA4_GDATA0, NIA4_SRC0, NIA4_LEN0, NIA4_MASKREG

        ;; Lane 1: process if present (regs clobbered by PROCESS_NIA4_LANE above)
        mov     NIA4_T_GP, [job_in_lane + 1*8]
        test    NIA4_T_GP, NIA4_T_GP
        jz      .auth_done
        lea     NIA4_GDATA1,      [rsp + _gdata_nia4_1]
        mov     NIA4_SRC1,        [p_buffer_in + 1*8]
        mov     DWORD(NIA4_LEN1), [len_bytes + 1*4]
        vpxorq  xmm0, xmm0, xmm0
        vmovdqa [rsp + _digest_nia4], xmm0
        lea     p_hqp, [rsp + _hqp_nia4 + 48]
        PROCESS_NIA4_LANE 1, NIA4_GDATA1, NIA4_SRC1, NIA4_LEN1, NIA4_MASKREG
        jmp     .auth_done

.lane0_empty:
        ;; Lane 0 absent: process lane 1 only (reusing _gdata_nia4 area)
        mov     NIA4_T_GP, [job_in_lane + 1*8]
        test    NIA4_T_GP, NIA4_T_GP
        jz      .auth_done
        CALL_POLYVAL_PRE rsp + _hqp_nia4 + 48, rsp + _gdata_nia4
        lea     NIA4_GDATA0,      [rsp + _gdata_nia4]
        mov     NIA4_SRC0,        [p_buffer_in + 1*8]
        mov     DWORD(NIA4_LEN0), [len_bytes + 1*4]
        vpxorq  xmm0, xmm0, xmm0
        vmovdqa [rsp + _digest_nia4], xmm0
        lea     p_hqp, [rsp + _hqp_nia4 + 48]
        PROCESS_NIA4_LANE 1, NIA4_GDATA0, NIA4_SRC0, NIA4_LEN0, NIA4_MASKREG

.auth_done:

%ifdef SAFE_DATA
        vpxorq  zmm0, zmm0, zmm0
        vmovdqa64 [rsp + _hqp_nia4], zmm0
        vmovdqa32 [rsp + _hqp_nia4 + 64], ymm0
        vmovdqa [rsp + _digest_nia4], xmm0
        vmovdqa32 [rsp + _keystream_nia4], ymm0
%assign i 0
%rep 20
        vmovdqu64 [rsp + _gdata_nia4 + 64 * i], zmm0
%assign i (i + 1)
%endrep
%assign i 0
%rep 20
        vmovdqu64 [rsp + _gdata_nia4_1 + 64 * i], zmm0
%assign i (i + 1)
%endrep
%endif

        RESTORE_STACK_SPACE 4
%endmacro

%ifndef _SNOW5G_NIA4_X2_INCLUDED_
%include "include/os.inc"
mksection stack-noexec
%endif
