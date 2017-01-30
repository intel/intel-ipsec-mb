;;;
;;; Copyright (c) 2017
;;; 
;;;
;;; Routines to do simple AES ECB Enc on one block
;;;
;;;void
;;; aes_ecbenc_KEY_ENV(const void *in, const void *roundkey, void *out);
;;;     arg 1: plain text pointer
;;;     arg 2: expaneded roundkey pointer
;;;     arg 3: cipher text pointer

%ifdef LINUX    
%define IN	rdi	; arg 1
%define KEY	rsi	; arg 2
%define OUT	rdx	; arg 3
%else
%define IN	rcx	; arg 1
%define KEY	rdx	; arg 2
%define OUT	r8	; arg 3
%endif

%define XDATA	xmm1

;;Encryption of a single block for SSE
%macro ENCRYPT_SSE 1
%define %%by %1

%ifndef LINUX
	mov OUT, [rsp + 8*3]
%endif
       
        movdqu XDATA, [IN]	; load plain text
        pxor XDATA, [KEY + 16*0]
%assign i 1
%rep %%by
        aesenc XDATA, [KEY + 16*i]
%assign i (i+1)
%endrep
        aesenclast XDATA, [KEY + 16*i]
        movdqu [OUT], XDATA
%endmacro

        
;;Encryption of a single block for AVX
%macro ENCRYPT_AVX 1
%define %%by %1

%ifndef LINUX
	mov OUT, [rsp + 8*3]
%endif
       
        vmovdqu XDATA, [IN]	; load plain text
        vpxor XDATA, [KEY + 16*0]
%assign i 1
%rep %%by
        vaesenc XDATA, [KEY + 16*i]
%assign i (i+1)
%endrep
        vaesenclast XDATA, [KEY + 16*i]
        vmovdqu [OUT], XDATA
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
section .text

;;;
;;;SSE
;;; 
;; aes_ecbenc_128_sse(const void *in, const void *keys, void *out, );
global aes_ecbenc_128_sse
aes_ecbenc_128_sse:
        ENCRYPT_SSE     9
        ret
;;; 
;; aes_ecbenc_192_sse(const void *in, const void *keys, void *out);
global aes_ecbenc_192_sse
aes_ecbenc_192_sse:
        ENCRYPT_SSE	11
        ret
;;; 
;; aes_ecbenc_256_sse(const void *in, const void *keys, void *out);
global aes_ecbenc_256_sse
aes_ecbenc_256_sse:
        ENCRYPT_SSE	13
        ret
;;;
;;; AVX
;;; 
;; aes_ecbenc_128_avx(const void *in, const void *keys, void *out);
global aes_ecbenc_128_avx
aes_ecbenc_128_avx:      
        ENCRYPT_AVX	9
        ret
;;; 
;; aes_ecbenc_192_avx(const void *in, const void *keys, void *out);
global aes_ecbenc_192_avx
aes_ecbenc_192_avx:      
        ENCRYPT_AVX	11
        ret
;;; 
;; aes_ecbenc_256_avx(const void *in, const void *keys, void *out);
global aes_ecbenc_256_avx
aes_ecbenc_256_avx:      
        ENCRYPT_AVX	13
        ret
;;; 
