;;
;; Copyright (c) 2019-2024, Intel Corporation
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

%ifndef MB_MGR_AES_CCM_SUBMIT_FLUSH_SSE_INC
%define MB_MGR_AES_CCM_SUBMIT_FLUSH_SSE_INC

%include "include/os.inc"
%include "include/imb_job.inc"
%include "include/mb_mgr_datastruct.inc"
%include "include/reg_sizes.inc"
%include "include/const.inc"
%include "include/memcpy.inc"
%include "include/cet.inc"
%include "include/align_sse.inc"

%define NUM_LANES 8

%define APPEND(a,b) a %+ b

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%else
%define arg1    rcx
%define arg2    rdx
%endif

%define state   arg1
%define job     arg2
%define len2    arg2

%define job_rax          rax
%define tmp4             rax
%define auth_len_aad     rax

%define min_idx          rbp
%define flags            rbp

%define lane             r8

%define iv_len           r9
%define auth_len         r9

%define aad_len          r10
%define init_block_addr  r11

%define unused_lanes     rbx
%define r                rbx

%define tmp              r12
%define tmp2             r13
%define tmp3             r14

%define good_lane        r15
%define min_job          r15

%define init_block0      xmm0
%define ccm_lens         xmm1
%define min_len_idx      xmm2
%define xtmp0            xmm3
%define xtmp1            xmm4
%define xtmp2            xmm5
%define xtmp3            xmm6
%define xtmp4            xmm7

; STACK_SPACE needs to be an odd multiple of 8
; This routine and its callee clobbers all GPRs
struc STACK
_gpr_save:      resq    8
_rsp_save:      resq    1
endstruc

;;; ===========================================================================
;;; ===========================================================================
;;; MACROS
;;; ===========================================================================
;;; ===========================================================================

%macro  ENCRYPT_SINGLE_BLOCK 3
%define %%KEYP          %1 ;; [in] pointer to AES round keys
%define %%XMM0          %2 ;; [in/out] XMM SIMD register with data block for encryption
%define %%NROUNDS       %3 ;; [in] number of AESENC rounds (9 - aes128; 11 - aes192; 13 - aes256)
                pxor           %%XMM0, [%%KEYP+16*0]
%assign i 1
%rep %%NROUNDS
                aesenc         %%XMM0, [%%KEYP+16*i]
%assign i (i+1)
%endrep
                aesenclast     %%XMM0, [%%KEYP+16*i]
%endmacro

;; Set all NULL job lanes to UINT16_MAX
%macro SET_NULL_JOB_LENS_TO_MAX 5
%define %%CCM_LENS      %1 ;; [in/out] xmm containing lane lengths
%define %%XTMP0         %2 ;; [clobbered] tmp xmm reg
%define %%XTMP1         %3 ;; [clobbered] tmp xmm reg
%define %%XTMP2         %4 ;; [clobbered] tmp xmm reg
%define %%XTMP3         %5 ;; [clobbered] tmp xmm reg

        pxor            %%XTMP0, %%XTMP0
        pxor            %%XTMP1, %%XTMP1
        pcmpeqq         %%XTMP0, [state + _aes_ccm_job_in_lane + 0]
        pcmpeqq         %%XTMP1, [state + _aes_ccm_job_in_lane + 16]
        pshufb          %%XTMP0, [rel len_shuf_masks + 0]
        pshufb          %%XTMP1, [rel len_shuf_masks + 16]
        por             %%CCM_LENS, %%XTMP0
        por             %%CCM_LENS, %%XTMP1

        pxor            %%XTMP2, %%XTMP2
        pxor            %%XTMP3, %%XTMP3
        pcmpeqq         %%XTMP2, [state + _aes_ccm_job_in_lane + 32]
        pcmpeqq         %%XTMP3, [state + _aes_ccm_job_in_lane + 48]
        pshufb          %%XTMP2, [rel len_shuf_masks + 32]
        pshufb          %%XTMP3, [rel len_shuf_masks + 48]
        por             %%CCM_LENS, %%XTMP2
        por             %%CCM_LENS, %%XTMP3
%endmacro

;;; ===========================================================================
;;; AES CCM auth job submit & flush
;;; ===========================================================================
;;; SUBMIT_FLUSH [in] - SUBMIT, FLUSH job selection
%macro GENERIC_SUBMIT_FLUSH_JOB_AES_CCM_AUTH_SSE 3
%define %%SUBMIT_FLUSH %1 ;; [in] "SUBMIT" or "FLUSH" selection
%define %%AES_CBC_MAC  %2 ;; [in] function to process CBC MAC algorithm on all lanes
%define %%NROUNDS      %3 ;; [in] number of AESENC rounds (9 - aes128; 11 - aes192; 13 - aes256)

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

        ;; Find free lane
        mov     unused_lanes, [state + _aes_ccm_unused_lanes]

%ifidn %%SUBMIT_FLUSH, SUBMIT

        mov     lane, unused_lanes
        and     lane, 15
        shr     unused_lanes, 4
        mov     [state + _aes_ccm_unused_lanes], unused_lanes

        ;; Copy job info into lane
        mov     [state + _aes_ccm_job_in_lane + lane*8], job
        ;; Copy keys into lane args
        mov     tmp, [job + _enc_keys]
        mov     [state + _aes_ccm_args_keys + lane*8], tmp
        ;; init_done = 0
        mov     word [state + _aes_ccm_init_done + lane*2], 0
        lea     tmp, [lane * 8]

        pxor    init_block0, init_block0
        movdqa  [state + _aes_ccm_args_IV + tmp*2], init_block0

        ;; Prepare initial Block 0 for CBC-MAC-128

        ;; Byte 0: flags with L' and M' (AAD later)
        ;; Calculate L' = 15 - IV length - 1 = 14 - IV length
        mov     flags, 14
        mov     iv_len, [job + _iv_len_in_bytes]
        sub     flags, iv_len
        ;; Calculate M' = (Digest length - 2) / 2
        mov     tmp, [job + _auth_tag_output_len_in_bytes]
        sub     tmp, 2

        shl     tmp, 2 ; M' << 3 (combine 1xshr, to div by 2, and 3xshl)
        or      flags, tmp

        ;; Bytes 1 - 13: Nonce (7 - 13 bytes long)

        ;; Bytes 1 - 7 are always copied (first 7 bytes)
        mov     tmp, [job + _iv]
        pinsrb  init_block0, [tmp], 1
        pinsrw  init_block0, [tmp + 1], 1
        pinsrd  init_block0, [tmp + 3], 1

        cmp     iv_len, 10
        je      %%_iv_length_10
        ja      %%_iv_length_11_to_13

        cmp     iv_len, 8
        je      %%_iv_length_8
        jb      %%_finish_nonce_move   ; iv_len = 7
        jmp     %%_iv_length_9         ; iv_len = 9

%%_iv_length_11_to_13:
        ; iv_len > 10 (11, 12, or 13)
        cmp     iv_len, 12
        je      %%_iv_length_12
        jb      %%_iv_length_11

        ;; Bytes 8 - 13
%%_iv_length_13:
        pinsrb init_block0, [tmp + 12], 13
%%_iv_length_12:
        pinsrb init_block0, [tmp + 11], 12
%%_iv_length_11:
        pinsrd init_block0, [tmp + 7], 2
        jmp     %%_finish_nonce_move
%%_iv_length_10:
        pinsrb init_block0, [tmp + 9], 10
%%_iv_length_9:
        pinsrb init_block0, [tmp + 8], 9
%%_iv_length_8:
        pinsrb init_block0, [tmp + 7], 8

align_label
%%_finish_nonce_move:

        ;; Bytes 14 & 15 (message length), in Big Endian
        mov     ax, [job + _msg_len_to_hash_in_bytes]
        xchg    al, ah
        pinsrw  init_block0, ax, 7

        mov     aad_len, [job + _cbcmac_aad_len]
        ;; Initial length to authenticate (Block 0)
        mov     auth_len, 16
        ;; Length to authenticate (Block 0 + len(AAD) (2B) + AAD padded,
        ;; so length is multiple of 64B)
        lea     auth_len_aad, [aad_len + (2 + 15) + 16]
        and     auth_len_aad, -16

        or      aad_len, aad_len
        cmovne  auth_len, auth_len_aad
        ;; Update lengths to authenticate and find min length
        movdqa  ccm_lens, [state + _aes_ccm_lens]
        XPINSRW ccm_lens, xtmp0, tmp2, lane, auth_len, scale_x16
        movdqa  [state + _aes_ccm_lens], ccm_lens
        phminposuw min_len_idx, ccm_lens

        mov     tmp, lane
        shl     tmp, 6
        lea     init_block_addr, [state + _aes_ccm_init_blocks + tmp]
        or      aad_len, aad_len
        je      %%_aad_complete

        or      flags, (1 << 6) ; Set Adata bit in flags

        ;; Copy AAD
        ;; Set all 0s in last block (padding)
        lea     tmp, [init_block_addr + auth_len]
        sub     tmp, 16
        pxor    xtmp0, xtmp0
        movdqa  [tmp], xtmp0

        ;; Start copying from second block
        lea     tmp, [init_block_addr+16]
        mov     rax, aad_len
        xchg    al, ah
        mov     [tmp], ax
        add     tmp, 2
        mov     tmp2, [job + _cbcmac_aad]
        memcpy_sse_64_1 tmp, tmp2, aad_len, tmp3, tmp4, xtmp0, xtmp1, xtmp2, xtmp3

align_label
%%_aad_complete:

        ;; Finish Block 0 with Byte 0
        pinsrb  init_block0, BYTE(flags), 0
        movdqa  [init_block_addr], init_block0

        ;; args.in[lane] = &initial_block
        mov     [state + _aes_ccm_args_in + lane * 8], init_block_addr

        cmp     byte [state + _aes_ccm_unused_lanes], 0xf
        jne     %%_return_null

%else ; end SUBMIT

        ;; Check at least one job
	bt	unused_lanes, ((NUM_LANES * 4) + 3)
        jc      %%_return_null

        ;; Find a lane with a non-null job
        xor     good_lane, good_lane
        cmp     qword [state + _aes_ccm_job_in_lane + 1*8], 0
        cmovne  good_lane, [rel one]
        cmp     qword [state + _aes_ccm_job_in_lane + 2*8], 0
        cmovne  good_lane, [rel two]
        cmp     qword [state + _aes_ccm_job_in_lane + 3*8], 0
        cmovne  good_lane, [rel three]
        cmp     qword [state + _aes_ccm_job_in_lane + 4*8], 0
        cmovne  good_lane, [rel four]
        cmp     qword [state + _aes_ccm_job_in_lane + 5*8], 0
        cmovne  good_lane, [rel five]
        cmp     qword [state + _aes_ccm_job_in_lane + 6*8], 0
        cmovne  good_lane, [rel six]
        cmp     qword [state + _aes_ccm_job_in_lane + 7*8], 0
        cmovne  good_lane, [rel seven]

        ; Copy good_lane to empty lanes
        movzx   tmp,  word [state + _aes_ccm_init_done + good_lane*2]
        mov     tmp2, [state + _aes_ccm_args_in + good_lane*8]
        mov     tmp3, [state + _aes_ccm_args_keys + good_lane*8]
        shl     good_lane, 4 ; multiply by 16
        movdqa  xtmp0, [state + _aes_ccm_args_IV + good_lane]
        movdqa  ccm_lens, [state + _aes_ccm_lens]

%assign I 0
%rep NUM_LANES
        cmp     qword [state + _aes_ccm_job_in_lane + I*8], 0
        jne     APPEND(%%_skip_,I)
        por     ccm_lens, [rel len_masks + 16*I]
        mov     [state + _aes_ccm_init_done + I*2], WORD(tmp)
        mov     [state + _aes_ccm_args_in + I*8], tmp2
        mov     [state + _aes_ccm_args_keys + I*8], tmp3
        movdqa  [state + _aes_ccm_args_IV + I*16], xtmp0
APPEND(%%_skip_,I):
%assign I (I+1)
%endrep
        movdqa  [state + _aes_ccm_lens], ccm_lens
        ;; Find min length
        phminposuw min_len_idx, ccm_lens
        jmp     %%_ccm_round

align_loop
%%_ccm_round_flush:
        ;; This is identical to the above block but optimized for
        ;; a repeat flush operation when keys etc. are already set
        ;; - vphminposuw was already executed
        ;; - good_lane is already known
        ;; - copy input pointer from good lane to empty lanes
        mov     tmp2, [state + _aes_ccm_args_in + good_lane*8]
%assign I 0
%rep NUM_LANES
        cmp     qword [state + _aes_ccm_job_in_lane + I*8], 0
        jne     APPEND(%%_skip2_,I)
        mov     [state + _aes_ccm_args_in + I*8], tmp2
APPEND(%%_skip2_,I):
%assign I (I+1)
%endrep

%endif ; end FLUSH

align_loop
%%_ccm_round:
        pextrw  len2, min_len_idx, 0    ; min value
        pextrw  min_idx, min_len_idx, 1         ; min index (0...3)

        mov     min_job, [state + _aes_ccm_job_in_lane + min_idx*8]

        or      len2, len2
        je      %%_len_is_0
        ;; subtract min length from all lengths
	pshufb	min_len_idx, [rel dupw]     ; duplicate words across all lanes
        psubw   ccm_lens, min_len_idx
        movdqa  [state + _aes_ccm_lens], ccm_lens

        ; "state" and "args" are the same address, arg1
        ; len2 is arg2
        call    %%AES_CBC_MAC
        ; state and min_idx are intact

align_label
%%_len_is_0:

        movzx   tmp, WORD [state + _aes_ccm_init_done + min_idx*2]
        cmp     WORD(tmp), 0
        je      %%_prepare_full_blocks_to_auth
        cmp     WORD(tmp), 1
        je      %%_prepare_partial_block_to_auth

align_label
%%_encrypt_digest:

        ;; Set counter block 0 (reusing previous initial block 0)
        mov     tmp, min_idx
        shl     tmp, 3
        movdqa  init_block0, [state + _aes_ccm_init_blocks + tmp * 8]

        pand   init_block0, [rel counter_mask]

        mov     tmp2, [state + _aes_ccm_args_keys + tmp]
        ENCRYPT_SINGLE_BLOCK tmp2, init_block0, %%NROUNDS
        pxor    init_block0, [state + _aes_ccm_args_IV + tmp * 2]

        ;; Copy Mlen bytes into auth_tag_output (Mlen = 4,6,8,10,12,14,16)
        mov     min_job, [state + _aes_ccm_job_in_lane + tmp]
        mov     tmp3, [min_job + _auth_tag_output_len_in_bytes]
        mov     tmp2, [min_job + _auth_tag_output]

        simd_store_sse tmp2, init_block0, tmp3, tmp, rax

align_label
%%_update_lanes:
        ; Update unused lanes
        mov     unused_lanes, [state + _aes_ccm_unused_lanes]
        shl     unused_lanes, 4
        or      unused_lanes, min_idx
        mov     [state + _aes_ccm_unused_lanes], unused_lanes

        ; Set return job
        mov     job_rax, min_job

        mov     qword [state + _aes_ccm_job_in_lane + min_idx*8], 0
        or      dword [job_rax + _status], IMB_STATUS_COMPLETED_AUTH

%ifdef SAFE_DATA
        pxor    xmm0, xmm0
        shl     min_idx, 6
        movdqa  [state + _aes_ccm_init_blocks + min_idx + 0*16], xmm0
        movdqa  [state + _aes_ccm_init_blocks + min_idx + 1*16], xmm0
        movdqa  [state + _aes_ccm_init_blocks + min_idx + 2*16], xmm0
        movdqa  [state + _aes_ccm_init_blocks + min_idx + 3*16], xmm0
%endif

align_label
%%_return:
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

align_label
%%_return_null:
        xor     job_rax, job_rax
        jmp     %%_return

align_label
%%_prepare_full_blocks_to_auth:

        cmp     dword [min_job + _cipher_direction], 2 ; DECRYPT
        je      %%_decrypt

align_label
%%_encrypt:
        mov     tmp, [min_job + _src]
        add     tmp, [min_job + _hash_start_src_offset_in_bytes]
        jmp     %%_set_init_done_1

align_label
%%_decrypt:
        mov     tmp, [min_job + _dst]

align_label
%%_set_init_done_1:
        mov     [state + _aes_ccm_args_in + min_idx*8], tmp
        mov     word [state + _aes_ccm_init_done + min_idx*2], 1

        ; Check if there are full blocks to hash
        mov     tmp, [min_job + _msg_len_to_hash_in_bytes]
        and     tmp, -16
        je      %%_prepare_partial_block_to_auth

        ;; Update lengths to authenticate and find min length
        movdqa  ccm_lens, [state + _aes_ccm_lens]

        ; Reset NULL lane lens to UINT16_MAX
%ifidn %%SUBMIT_FLUSH, FLUSH
        SET_NULL_JOB_LENS_TO_MAX ccm_lens, xtmp0, xtmp1, xtmp2, xtmp3
        mov     good_lane, min_idx
%endif
        XPINSRW ccm_lens, xtmp0, tmp2, min_idx, tmp, scale_x16
        phminposuw min_len_idx, ccm_lens
        movdqa  [state + _aes_ccm_lens], ccm_lens

%ifidn %%SUBMIT_FLUSH, FLUSH
        jmp     %%_ccm_round_flush
%else
        jmp     %%_ccm_round
%endif

align_label
%%_prepare_partial_block_to_auth:
        ; Check if partial block needs to be hashed
        mov     auth_len, [min_job + _msg_len_to_hash_in_bytes]
        and     auth_len, 15
        je      %%_encrypt_digest

        mov     word [state + _aes_ccm_init_done + min_idx * 2], 2
        ;; Update lengths to authenticate and find min length
        movdqa  ccm_lens, [state + _aes_ccm_lens]
        ; Reset NULL lane lens to UINT16_MAX
%ifidn %%SUBMIT_FLUSH, FLUSH
        SET_NULL_JOB_LENS_TO_MAX ccm_lens, xtmp0, xtmp1, xtmp2, xtmp3
%endif
        XPINSRW ccm_lens, xtmp0, tmp2, min_idx, 16, scale_x16
        phminposuw min_len_idx, ccm_lens
        movdqa  [state + _aes_ccm_lens], ccm_lens

        mov     tmp2, min_idx
        shl     tmp2, 6
        add     tmp2, 16 ; pb[AES_BLOCK_SIZE]
        lea     init_block_addr, [state + _aes_ccm_init_blocks + tmp2]
        mov     tmp2, [state + _aes_ccm_args_in + min_idx * 8]

        simd_load_sse_15_1 xtmp0, tmp2, auth_len

align_label
%%_finish_partial_block_copy:
        movdqa  [init_block_addr], xtmp0
        mov     [state + _aes_ccm_args_in + min_idx * 8], init_block_addr

%ifidn %%SUBMIT_FLUSH, FLUSH
        mov     good_lane, min_idx
        jmp     %%_ccm_round_flush
%else
        jmp     %%_ccm_round
%endif
%endmacro

%endif ;; MB_MGR_AES_CCM_SUBMIT_FLUSH_SSE_INC
