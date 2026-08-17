;;
;; Copyright (c) 2012-2024, Intel Corporation
;;
;; SPDX-License-Identifier: BSD-3-Clause
;;

;;;  Generic constants
%define PTR_SZ                  8

;;; hash constants

%define MD5_DIGEST_WORD_SIZE    4
%define SHA1_DIGEST_WORD_SIZE   4
%define SHA256_DIGEST_WORD_SIZE 4
%define SHA512_DIGEST_WORD_SIZE 8
;; AVX512 constants
%define MAX_MD5_LANES           32
%define MAX_SHA1_LANES          16
%define MAX_SHA256_LANES        16
%define MAX_SHA512_LANES        8
%define MAX_SHA3_LANES          4

%define NUM_MD5_DIGEST_WORDS    4
%define NUM_SHA1_DIGEST_WORDS   5
%define NUM_SHA256_DIGEST_WORDS 8
%define NUM_SHA512_DIGEST_WORDS 8

%define MD5_DIGEST_ROW_SIZE     (MAX_MD5_LANES    * MD5_DIGEST_WORD_SIZE)
%define SHA1_DIGEST_ROW_SIZE    (MAX_SHA1_LANES   * SHA1_DIGEST_WORD_SIZE)
%define SHA256_DIGEST_ROW_SIZE  (MAX_SHA256_LANES * SHA256_DIGEST_WORD_SIZE)
%define SHA512_DIGEST_ROW_SIZE  (MAX_SHA512_LANES * SHA512_DIGEST_WORD_SIZE)

%define MD5_DIGEST_SIZE         (MD5_DIGEST_ROW_SIZE    * NUM_MD5_DIGEST_WORDS)
%define SHA1_DIGEST_SIZE        (SHA1_DIGEST_ROW_SIZE   * NUM_SHA1_DIGEST_WORDS)
%define SHA256_DIGEST_SIZE      (SHA256_DIGEST_ROW_SIZE * NUM_SHA256_DIGEST_WORDS)
%define SHA512_DIGEST_SIZE      (SHA512_DIGEST_ROW_SIZE * NUM_SHA512_DIGEST_WORDS)

;; Used only by SHA-NI implementations
;; Sanity checks to fail build if not satisfied
%define SHA1NI_DIGEST_ROW_SIZE   (NUM_SHA1_DIGEST_WORDS * SHA1_DIGEST_WORD_SIZE)
%define SHA256NI_DIGEST_ROW_SIZE (NUM_SHA256_DIGEST_WORDS * SHA256_DIGEST_WORD_SIZE)
%define SHA512NI_DIGEST_ROW_SIZE (NUM_SHA512_DIGEST_WORDS * SHA512_DIGEST_WORD_SIZE)

%define MD5_BLK_SZ              128  ; in bytes
%define SHA1_BLK_SZ             64   ; in bytes
%define SHA256_BLK_SZ           64   ; in bytes
%define SHA512_BLK_SZ           128  ; in bytes
