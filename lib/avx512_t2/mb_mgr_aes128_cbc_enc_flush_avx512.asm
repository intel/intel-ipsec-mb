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

%include "include/os.asm"
%include "include/imb_job.asm"
%include "include/mb_mgr_datastruct.asm"
%include "include/constants.asm"
%include "include/reg_sizes.asm"
%include "include/clear_regs.asm"

%ifndef AES_CBC_ENC_X16
%define AES_CBC_ENC_X16 aes_cbc_enc_128_flush_vaes_avx512
%define FLUSH_JOB_AES_ENC flush_job_aes128_enc_vaes_avx512
%define NUM_KEYS 11
%endif

; void AES_CBC_ENC_X16(AES_ARGS *args, UINT64 len_in_bytes);
extern AES_CBC_ENC_X16

mksection .text

%define APPEND(a,b) a %+ b

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%endif

%define state   arg1
%define job     arg2
%define len2    arg2

%define job_rax          rax

%if 1
%define unused_lanes     rbx
%define tmp1             rbx

%define iv               rdx

%define tmp2             rax

; idx needs to be in rbp
%define tmp              rbp
%define idx              rbp

%define tmp3             r9
%define tmp4             r10
%endif

; copy IV's and round keys into NULL lanes
%macro COPY_IV_KEYS_TO_NULL_LANES 6
%define %%IDX           %1 ; [in] GP with good lane idx (scaled x16)
%define %%NULL_MASK     %2 ; [clobbered] GP to store NULL lane mask
%define %%KEY_TAB       %3 ; [clobbered] GP to store key table pointer
%define %%XTMP1         %4 ; [clobbered] temp XMM reg
%define %%XTMP2         %5 ; [clobbered] temp XMM reg
%define %%MASK_REG      %6 ; [in] mask register

        vmovdqa64       %%XTMP1, [state + _aes_args_IV + %%IDX]
        lea             %%KEY_TAB, [state + _aesarg_key_tab]
        kmovw           DWORD(%%NULL_MASK), %%MASK_REG

%assign j 0 ; outer loop to iterate through round keys
%rep 15
        vmovdqa64       %%XTMP2, [%%KEY_TAB + j + %%IDX]

%assign k 0 ; inner loop to iterate through lanes
%rep 16
        bt              %%NULL_MASK, k
        jnc             %%_skip_copy %+ j %+ _ %+ k

%if j == 0 ;; copy IVs for each lane just once
        vmovdqa64       [state + _aes_args_IV + (k*16)], %%XTMP1
%endif
        ;; copy key for each lane
        vmovdqa64       [%%KEY_TAB + j + (k*16)], %%XTMP2
%%_skip_copy %+ j %+ _ %+ k:
%assign k (k + 1)
%endrep

%assign j (j + 256)
%endrep

%endmacro

; clear IVs, scratch buffers and round key's in NULL lanes
%macro CLEAR_IV_KEYS_IN_NULL_LANES 3
%define %%NULL_MASK     %1 ; [clobbered] GP to store NULL lane mask
%define %%XTMP          %2 ; [clobbered] temp XMM reg
%define %%MASK_REG      %3 ; [in] mask register

        vpxorq          %%XTMP, %%XTMP
        kmovw           DWORD(%%NULL_MASK), %%MASK_REG
%assign k 0 ; outer loop to iterate through lanes
%rep 16
        bt              %%NULL_MASK, k
        jnc             %%_skip_clear %+ k

        ;; clear lane IV buffers
        vmovdqa64       [state + _aes_args_IV + (k*16)], %%XTMP

%assign j 0 ; inner loop to iterate through round keys
%rep NUM_KEYS
        vmovdqa64       [state + _aesarg_key_tab + j + (k*16)], %%XTMP
%assign j (j + 256)

%endrep
%%_skip_clear %+ k:
%assign k (k + 1)
%endrep

%endmacro

; STACK_SPACE needs to be an odd multiple of 8
; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    8
_rsp_save:      resq    1
endstruc

%ifndef CBCS

; JOB* FLUSH_JOB_AES_ENC(MB_MGR_AES_OOO *state, IMB_JOB *job)
; arg 1 : state
; arg 2 : job
MKGLOBAL(FLUSH_JOB_AES_ENC,function,internal)
FLUSH_JOB_AES_ENC:
        mov     rax, rsp
        sub     rsp, STACK_size
        and     rsp, -16

        mov     [rsp + _gpr_save + 8*0], rbx
        mov     [rsp + _gpr_save + 8*1], rbp
        mov     [rsp + _gpr_save + 8*2], r12
        mov     [rsp + _gpr_save + 8*3], r13
        mov     [rsp + _gpr_save + 8*4], r14
        mov     [rsp + _gpr_save + 8*5], r15
%ifndef LINUX
        mov     [rsp + _gpr_save + 8*6], rsi
        mov     [rsp + _gpr_save + 8*7], rdi
%endif
        mov     [rsp + _rsp_save], rax  ; original SP

        ; check for empty
        cmp     qword [state + _aes_lanes_in_use], 0
        je      return_null

        ; find a lane with a non-null job
        vpxord          zmm0, zmm0, zmm0
        vmovdqu64       zmm1, [state + _aes_job_in_lane + (0*PTR_SZ)]
        vmovdqu64       zmm2, [state + _aes_job_in_lane + (8*PTR_SZ)]
        vpcmpq          k1, zmm1, zmm0, 4 ; NEQ
        vpcmpq          k2, zmm2, zmm0, 4 ; NEQ
        kshiftlw        k2, k2, 8
        korw            k6, k2, k1
        kmovw           DWORD(arg3), k6 ; mask of non-null lanes in arg3
        knotw           k6, k6
        kshiftrw        k5, k6, 8 ; mask of NULL jobs in k4, k5 and k6

        xor             tmp2, tmp2
        bsf             WORD(tmp2), WORD(arg3)   ; index of the 1st set bit in tmp2

        ;; copy good lane output pointer into NULL lanes in & out
        ;; NOTE: NULL lanes not updated so any valid address can be used
        mov             tmp, [state + _aes_args_out + tmp2*8]
        vpbroadcastq    zmm1, tmp
        vmovdqa64       [state + _aes_args_in + (0*PTR_SZ)]{k6}, zmm1
        vmovdqa64       [state + _aes_args_in + (8*PTR_SZ)]{k5}, zmm1
        vmovdqa64       [state + _aes_args_out + (0*PTR_SZ)]{k6}, zmm1
        vmovdqa64       [state + _aes_args_out + (8*PTR_SZ)]{k5}, zmm1

        ;; - set len to UINT16_MAX
        mov             WORD(tmp), 0xffff
        vpbroadcastw    ymm3, WORD(tmp)
        vmovdqa64       ymm0, [state + _aes_lens]
        vmovdqu16       ymm0{k6}, ymm3
        vmovdqa64       [state + _aes_lens], ymm0

        ;; Find min length for lanes 0-7
        vphminposuw     xmm2, xmm0

        ; extract min length of lanes 0-7
        vpextrw         DWORD(len2), xmm2, 0   ; min value
        vpextrw         DWORD(idx), xmm2, 1   ; min index

        ;; Update lens and find min for lanes 8-15
        vextracti128    xmm1, ymm0, 1
        vphminposuw     xmm2, xmm1
        vpextrw         DWORD(tmp3), xmm2, 0       ; min value
        cmp             DWORD(len2), DWORD(tmp3)
        jle             use_min
        vpextrw         DWORD(idx), xmm2, 1   ; min index
        add             DWORD(idx), 8               ; but index +8
        mov             len2, tmp3                    ; min len
use_min:
        or              len2, len2
        je              len_is_0

        vpbroadcastw    ymm3, WORD(len2)
        vpsubw          ymm0, ymm0, ymm3
        vmovdqa         [state + _aes_lens], ymm0

        ; "state" and "args" are the same address, arg1
        ; len is arg2
        ; valid lane mask is arg3
        call    AES_CBC_ENC_X16
        ; state and idx are intact

len_is_0:
        ; process completed job "idx"
        mov     job_rax, [state + _aes_job_in_lane + idx*8]
        mov     unused_lanes, [state + _aes_unused_lanes]
        mov     qword [state + _aes_job_in_lane + idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_CIPHER
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _aes_unused_lanes], unused_lanes
        sub     qword [state + _aes_lanes_in_use], 1

%ifdef SAFE_DATA
        ;; Clear IV
        vpxorq  xmm0, xmm0
        shl     idx, 4 ; multiply by 16

        ;; Clear expanded keys
%assign round 0
%rep NUM_KEYS
        vmovdqa [state + _aesarg_key_tab + round * (16*16) + idx], xmm0
%assign round (round + 1)
%endrep

%endif

return:
%ifdef SAFE_DATA
	clear_all_zmms_asm
%else
        vzeroupper
%endif ;; SAFE_DATA

        mov     rbx, [rsp + _gpr_save + 8*0]
        mov     rbp, [rsp + _gpr_save + 8*1]
        mov     r12, [rsp + _gpr_save + 8*2]
        mov     r13, [rsp + _gpr_save + 8*3]
        mov     r14, [rsp + _gpr_save + 8*4]
        mov     r15, [rsp + _gpr_save + 8*5]
%ifndef LINUX
        mov     rsi, [rsp + _gpr_save + 8*6]
        mov     rdi, [rsp + _gpr_save + 8*7]
%endif
        mov     rsp, [rsp + _rsp_save]  ; original SP

        ret

return_null:
        xor     job_rax, job_rax
        jmp     return

mksection stack-noexec

%endif ;; CBCS
