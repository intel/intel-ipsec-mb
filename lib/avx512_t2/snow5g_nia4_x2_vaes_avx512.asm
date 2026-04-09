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

%define GCM128_MODE 1    ; Need to define GCM128_MODE just for gcm_vaes_avx512.inc
%include "include/gcm_vaes_avx512.inc"

extern polyval_vclmul_avx512
extern polyval_pre_vclmul_avx512

;; HQP field layout: H(16) | Q(16) | P(16) = 48 bytes per lane
%define NIA4_HQP_STRIDE         48
;; gcm_key_data: expanded_keys(16*15) + vaes_avx512.shifted_hkey(16*32*2), padded to 64B
%define NIA4_GCM_KEY_DATA_LEN   (((16*15 + 16*32*2) + 63) & ~63)
;; Number of 64-byte blocks covering NIA4_GCM_KEY_DATA_LEN (= 20)
%define NIA4_GCM_KEY_BLOCKS     (NIA4_GCM_KEY_DATA_LEN / 64)

;; Callee-saved GP register aliases — live across all calls in SNOW5G_NIA4_AUTH_X2
%define p_buffer_in     r12
%define p_mac_i         r13
%define len_bytes       r14
%define job_in_lane     r15
%define p_hqp           rbp

;; ABI function call argument registers
%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%endif

struc STACK_NIA4
;; NIA4 auth working data (used by SNOW5G_NIA4_AUTH_X2 / PROCESS_NIA4_LANE)
_hqp_nia4:      resb    (NIA4_HQP_STRIDE * 2)   ; HQP: 2 lanes x 48 bytes (H+Q+P)
_keystream_nia4: resy   1                        ; 32-byte keystream scratch
_gdata_nia4:    resb    NIA4_GCM_KEY_DATA_LEN    ; struct gcm_key_data (shared, reused per lane)
_digest_nia4:   reso    1                        ; 16-byte POLYVAL digest
;; Function frame (used by mb_mgr SNOW5G_NIA4_FUNC_START/END)
_gpr_save_nia4: resq    8                        ; callee-saved GP regs
_state_save_nia4: resq   1                        ; state (arg1) save
_job_save_nia4: resq     1                        ; job (arg2) save
%ifndef LINUX
_xmm_save_nia4: reso    10                       ; XMM6-15 save area (Windows only)
%endif
_rsp_save_nia4: resq    1                        ; original RSP before alignment
_idx_save_nia4: resq    1                        ; lane index saved across AUTH_X2 call
endstruc

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Per-lane POLYVAL authentication: build HashKey table, call polyval bulk hash,
;; digest XOR with length, single-block GHASH_MUL finalization, and tag output.
;; Uses file-scope callee-saved aliases: p_buffer_in, p_mac_i, len_bytes,
;; job_in_lane, p_hqp.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PROCESS_NIA4_LANE 11
%define %%LANE      %1   ;; [in] lane index (0 or 1)
%define %%SRC_IDX   %2   ;; [in] source slot index for p_buffer_in / len_bytes arrays
%define %%GDATA     %3   ;; [in] address expression for gcm_key_data area
%define %%HQP_OFF   %4   ;; [in] HQP byte offset (0 or NIA4_HQP_STRIDE)
%define %%DIGEST    %5   ;; [clobbered] XMM digest accumulator / final tag
%define %%XTMP0     %6   ;; [clobbered] XMM temp
%define %%XTMP1     %7   ;; [clobbered] XMM temp (GHASH_MUL)
%define %%XTMP2     %8   ;; [clobbered] XMM temp (GHASH_MUL)
%define %%XTMP3     %9   ;; [clobbered] XMM temp (GHASH_MUL)
%define %%XTMP4     %10  ;; [clobbered] XMM temp (GHASH_MUL)
%define %%KMASK     %11  ;; [clobbered] opmask for tag store
;; Implicit GP registers — ABI arg aliases (arg1..arg4) used for polyval calls;
;; rax, ecx used as volatile scratch after calls.

        ;; polyval_pre_vclmul_avx512(arg1=key, arg2=gdata)
        lea     arg1, [rsp + _hqp_nia4 + %%HQP_OFF]
        lea     arg2, [%%GDATA]
        call    polyval_pre_vclmul_avx512

        ;; Setup: load polyval args, clear digest
        lea     arg1, [%%GDATA]                            ;; gdata_key
        mov     arg2, [p_buffer_in + %%SRC_IDX*8]          ;; src
        mov     DWORD(arg3), [len_bytes + %%SRC_IDX*4]     ;; len
        vpxorq  %%DIGEST, %%DIGEST, %%DIGEST
        vmovdqu64 [rsp + _digest_nia4], %%DIGEST           ;; digest = 0

        ;; polyval_vclmul_avx512(arg1=gdata, arg2=src, arg3=len, arg4=io_tag)
        ;; arg1=gdata, arg2=src, arg3=len already set from above
        lea     arg4, [rsp + _digest_nia4]                 ;; arg4 = io_tag
        call    polyval_vclmul_avx512

        lea     p_hqp, [rsp + _hqp_nia4 + %%HQP_OFF]

        ;; digest ^= { 0, lengthInBytes[lane] * 8 }
        vmovdqu64 %%DIGEST, [rsp + _digest_nia4]
        mov       eax, [len_bytes + %%LANE*4]             ;; len in bytes
        shl       rax, 3                                  ;; len in bits
        vmovq     %%XTMP0, rax
        vpslldq   %%XTMP0, %%XTMP0, 8                     ;; { 0, len_bits }
        vpxorq    %%DIGEST, %%DIGEST, %%XTMP0

        ;; single-block POLYVAL of digest with Q key
        vmovdqu64 %%XTMP0, [p_hqp + 16]                  ;; Q key
        GHASH_MUL %%DIGEST, %%XTMP0, %%XTMP1, %%XTMP2, %%XTMP3, %%XTMP4, %%XTMP4

        ;; tag = digest ^ P
        vpxorq    %%DIGEST, %%DIGEST, [p_hqp + 32]       ;; P key

        ;; Copy tag to output — masked store for partial tag lengths
        mov       rax, [job_in_lane + %%LANE*8]           ;; job pointer
        mov       ecx, [rax + _auth_tag_output_len_in_bytes]
        mov       eax, -1
        bzhi      eax, eax, ecx                           ;; mask = low tag_len bits
        kmovw     %%KMASK, eax
        mov       rdx, [p_mac_i + %%LANE*8]               ;; output pointer
        vmovdqu8  [rdx]{%%KMASK}, %%DIGEST
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; NIA4 authentication for 2 lanes
;; Clobbered callee-saved GPRs: rbp, r12, r13, r14, r15
;; Clobbered SIMD/opmask: all volatile (contains function calls)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro SNOW5G_NIA4_AUTH_X2 1
%define %%STATE     %1   ;; [in] GP reg: SNOW5G OOO state pointer

        ;; Save state field addresses into callee-saved regs
        lea     p_buffer_in, [%%STATE + _snow5g_args_in]
        lea     p_mac_i,     [%%STATE + _snow5g_args_out]
        lea     len_bytes,   [%%STATE + _snow5g_lens_dqw]
        lea     job_in_lane, [%%STATE + _snow5g_job_in_lane]

        lea     rax, [%%STATE + _snow5g_args_keys]
        SNOW5G_GENERATE_HQP_X2 rax, {%%STATE + _snow5g_args_IV}, \
                {rsp + _hqp_nia4}, 0, _keystream_nia4, \
                FSM_R1_L01, FSM_R2_L01, FSM_R3_L01, \
                LFSR_A_LDQ_L01, LFSR_A_HDQ_L01, LFSR_B_LDQ_L01, LFSR_B_HDQ_L01, \
                TEMP0, TEMP1, ymm4, ymm5, rcx, k1, k2

        mov     rax, [job_in_lane]
        test    rax, rax
        jz      .check_lane1

        PROCESS_NIA4_LANE 0, 0, {rsp + _gdata_nia4}, 0, \
                xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, k1

.check_lane1:
        mov     rax, [job_in_lane + 1*8]
        test    rax, rax
        jz      .auth_done
        PROCESS_NIA4_LANE 1, 1, {rsp + _gdata_nia4}, NIA4_HQP_STRIDE, \
                xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, k1

.auth_done:

%ifdef SAFE_DATA
        vpxorq  zmm0, zmm0, zmm0
        vmovdqa64 [rsp + _hqp_nia4], zmm0
        vmovdqa32 [rsp + _hqp_nia4 + 64], ymm0
        vmovdqa32 [rsp + _digest_nia4], xmm0
        vmovdqa32 [rsp + _keystream_nia4], ymm0
%assign i 0
%rep NIA4_GCM_KEY_BLOCKS
        vmovdqu64 [rsp + _gdata_nia4 + 64 * i], zmm0
%assign i (i + 1)
%endrep
%endif

%endmacro

mksection stack-noexec
