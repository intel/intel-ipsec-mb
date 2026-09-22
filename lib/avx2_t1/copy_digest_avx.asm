;;
;; Copyright (c) 2025-2026, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

%include "include/os.inc"
%include "include/reg_sizes.inc"
%include "include/memcpy.inc"
%include "include/align_avx.inc"

mksection .text

;; Function: copy_digest_avx
;; Universal implementation for AVX2
;; r9: pointer to dst (not modified)
;; xmm0: src data (clobbered)
;; rbx: length in bytes (not modified)
;; r10: 64-bit temp GPR (preserved)
;; r11: 64-bit temp GPR to store dst idx (preserved)
MKGLOBAL(copy_digest_avx,function,internal)
align_function
copy_digest_avx:
        ;; Preserve registers
        push r10
        push r11

        simd_store_avx r9, xmm0, rbx, r10, r11

        ;; Restore registers
        pop r11
        pop r10

        ret

mksection stack-noexec
