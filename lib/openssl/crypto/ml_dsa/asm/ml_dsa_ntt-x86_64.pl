#! /usr/bin/env perl
#
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2026 Intel Corporation. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

###############################################################################
# ML-DSA AVX2 Vectorized NTT/INTT Assembly Routines
#
# Description:
#   This file provides optimized x86_64 assembly implementations of the Number
#   Theoretic Transform (NTT) and inverse NTT (INTT) and their modular Montgomery
#   reduction building blocks for the ML-DSA signature scheme.
#
#   The routines are vectorized using AVX2 instructions, performing
#   modular arithmetic and butterfly operations on multiple
#   coefficients in parallel. The mathematical structure and transformations strictly
#   follow those implemented in the corresponding C code (ml_dsa_ntt.c),
#   ensuring that this file provides a drop-in, performant backend using the
#   same algorithms and data layout.
#   Dedicated forward and inverse zeta tables are emitted here for the AVX2 path.
#   Additional preformatted level-5/level-6 forward tables, preformatted level-1/level-2
#   inverse tables, and the full inverse table reduce shuffle/broadcast overhead in the
#   AVX2 NTT/INTT implementations.
#
#   This module supports both the forward (NTT) and inverse (INTT)
#   polynomial transforms, as well as element-wise NTT-domain polynomial
#   multiplication, compatible with the ML-DSA cryptographic protocol.
#
#   Step, offset and zeta index details provided for NTT and INTT level operations
#   correspond directly to the original C implementations from ml_dsa_ntt.c file.
#
# Notes:
#   - Uses AVX2 instructions and YMM registers that accommodate 8 32-bit coefficients
#   - Must be kept functionally synchronized with the math and
#     interface of ml_dsa_ntt.c
#   - Data structures, twiddle factors ("zetas"), and constants must match
#     those in the C implementation
###############################################################################

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64 = 0;
$win64 = 1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$avx2 = 0;

$0 =~ m/(.*[\/\\])[^\/\\]+$/;
$dir = $1;
($xlate = "${dir}x86_64-xlate.pl" and -f $xlate)
  or ($xlate = "${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate)
  or ($xlate = "${dir}../../../perlasm/x86_64-xlate.pl" and -f $xlate)
  or die "can't locate x86_64-xlate.pl";

# Assembler used for the nasm flavour. The build forwards its choice via
# $ENV{ASM} so the probe inspects the same nasm that assembles the output.
my $nasm = $ENV{ASM} || "nasm";

# Check for AVX2 support in assembler
if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1` =~ /GNU assembler version ([2-9]\.[0-9]+)/) {
  $avx2 = ($1 >= 2.22);
}

if (!$avx2
  && $win64
  && ($flavour =~ /nasm/ || ($ENV{ASM} // "") =~ /nasm/)
  && `"$nasm" -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)(?:\.([0-9]+))?/)
{
  $avx2 = ($1 >= 2.10);
}

if (!$avx2 && `$ENV{CC} -v 2>&1` =~ /((?:clang|LLVM) version|.*based on LLVM) ([0-9]+\.[0-9]+)/) {
    $avx2 = ($2>=3.3); # minimal tested version for AVX2
}

# The optimised kernels are mandatory: fail the build (rather than emit
# trapping stubs) when the assembler cannot encode them.
$avx2 > 0
    or die "AVX2 support is required in the assembler to build the ML-DSA NTT kernels.\nMinimum assembler versions: GNU as 2.22, clang 3.3, nasm 2.10.\n";

open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
  or die "can't call $xlate: $!";
*STDOUT = *OUT;

# ML-DSA constants
my $ML_DSA_Q = 8380417;             # Q = 2^23 - 2^13 + 1 (FIPS 204, Table 1)
my $ML_DSA_Q_NEG_INV = 4236238847;  # -Q^{-1} mod 2^32 (unsigned Montgomery parameter)
my $QINV = 58728449;                 # Q^{-1} mod 2^32  (for signed Montgomery butterfly)

# Forward NTT twiddle factors in bit-reversal order.
# zetas_fwd[i] = zeta^{brv_8(i)} mod Q, where zeta = 1753 is the primitive
# 512th root of unity in Z_Q (FIPS 204, Table 1: zeta = 1753, N = 256).
# brv_8 is the bit-reversal permutation of 8-bit integers.
# Entry 0 is unused (Montgomery form of 1); entries 1..255 are the twiddle factors.
my @zetas_fwd = (
    4193792,   25847, 5771523, 7861508,  237124, 7602457, 7504169,  466468,
    1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
    2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497,  280005,
    2706023,   95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
     811944,  531354,  954230, 3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489,  126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034,  264944,  508951, 3097992,   44288, 7280319,  904516, 3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440,  759969, 7063561,
     189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
    2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
     266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
     900702, 1859098,  909542,  819034,  495491, 6767243, 8337157, 7857917,
    7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
     342297,  286988, 5942594, 4108315, 3437287, 5038140, 1735879,  203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
    7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165,  777191, 2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147,  594136, 4603424,
    6366809, 2432395, 2454455, 8215696, 1957272, 3369112,  185531, 7173032,
    5196991,  162844, 1616392, 3014001,  810149, 1652634, 4686184, 6581310,
    5341501, 3523897, 3866901,  269760, 2213111, 7404533, 1717735,  472078,
    7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090,  183443, 7403526, 1612842, 4834730,
    7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782
);

# Precomputed zeta_qinv = (zeta * QINV) mod 2^32 for each entry in @zetas_fwd
my @zetas_fwd_qinv = map { int(($_ * $QINV) % (2**32)) } @zetas_fwd;

#  The multiplicative inverse of 256 mod Q, in Montgomery form is
#  ((256^{-1} mod Q) * ((2^32 * 2^32) mod Q)) mod Q = (8347681 * 2365951) mod 8380417
#  N = 256 is the polynomial degree (FIPS 204, Table 1)
my $inverse_degree_montgomery = 41978;

# Byte offset from a 256-entry zeta table to its immediately-following companion
# qinv table (256 entries × 4 bytes/entry = 1024 bytes).
# Used in assembly addressing as: base_reg + $ZETA256_QINV_OFS
my $ZETA256_QINV_OFS = 256 * 4;

# Byte offset from a preformatted 16-row × 32-byte/row zeta table to its
# immediately-following companion qinv table (16 rows × 32 bytes/row = 512 bytes).
# Used in assembly addressing as: base_reg + $ZETA16R_QINV_OFS
my $ZETA16R_QINV_OFS = 16 * 32;

$code .= <<___;
.text
___

###############################################################################
# multiply_mod_Q
#
# Description:
#   Unsigned Montgomery modular multiplication using vpmuludq.
#   For inputs A ∈ [0, ~384Q) and B ∈ [0, Q): computes A×B×R^{-1} mod Q ∈ [0, Q).
#   Uses -Q^{-1} mod 2^32 (q_neg_inv) so the correction term is computed as
#   an unsigned add, keeping hi32 always positive (no conditional reduce on the
#   correction itself). A single conditional subtract reduces the final result
#   to [0, Q).
#
#   Still used in two places:
#     1. intt_levels5to7 — 1/N normalization (8 calls after the last INTT butterfly level)
#     2. poly_ntt_mult_avx2 — pointwise NTT-domain polynomial multiplication
#
#   NOTE: The NTT/INTT butterfly operations use a separate inlined signed multiply
#   (vpmuldq + QINV) rather than calling this subroutine, because the signed butterfly
#   chain does not need strict [0, Q) output. This subroutine is kept for the two
#   callers above which require strict [0, Q) output.
#
# Parameters:
#   inA       - Input YMM containing 8 unsigned 32-bit values (A), range [0, ~384Q)
#   inB       - Input YMM containing 8 unsigned 32-bit values (B), range [0, Q)
#   out       - Output YMM for (A * B * R^{-1} mod Q), range [0, Q)
#   tmp0-tmp2 - Temporary registers for intermediate values
#   q_neg_inv - YMM containing -Q^{-1} mod 2^32 (= 4236238847) broadcast 64-bit
#   q         - YMM containing modulus Q (broadcast 32-bit)
#   bcast32   – if 1, `inB` is assumed to have each qword formed by
#               repeating its low dword (DW|DW). Multiplication uses only
#               the low dword, avoiding the need for `vmovshdup` when
#               zetas are uniform across all lanes of `inA`.
#
# Output:
#   out      - Resulting 8 packed 32-bit integers, each (A * B * R^{-1}) mod Q,
#              in range [0, Q) after conditional reduction.
#
# Side effects:
#   Clobbers tmp0, tmp1, tmp2
#
# Notes:
#   inA or inB can also be used as out.
###############################################################################
sub multiply_mod_Q {
    my ($inA, $inB, $out,
        $tmp0, $tmp1, $tmp2,
        $q_neg_inv, $q, $bcast32) = @_;

    if (!defined($bcast32)) {
        $bcast32 = 0;
    }

    $code .= <<___;
    # multiply even-lane 32-bit elements (low dword of each 64-bit lane)
    vpmuludq $inA, $inB, $tmp0
    # shift each odd dword into the low position of its 64-bit lane for vpmuludq
    vmovshdup $inA, $tmp1
___
    if ($bcast32 == 0) {
        $code .= <<___;
    vmovshdup $inB, $tmp2
    vpmuludq $tmp1, $tmp2, $tmp1  # multiply odd indexes
___
    } else {
        $code .= <<___;
    vpmuludq $tmp1, $inB, $tmp1
___
    }
    $code .= <<___;
    # compute Montgomery correction factor
    vpmuludq $q_neg_inv, $tmp0, $out
    vpmuludq $q_neg_inv, $tmp1, $tmp2

    # multiply correction factor with modulus
    vpmuludq $out, $q, $out
    vpmuludq $tmp2, $q, $tmp2

    # add correction to get integer multiple of R
    vpaddq  $out, $tmp0, $out
    vpaddq  $tmp2, $tmp1, $tmp1

    # move upper 32 bits of each 64-bit lane result into the low dword position
    vmovshdup $out, $out
    # 0xAA = 0b10101010: merge odd lanes (tmp1) into even lanes (out)
    vpblendd \$0xAA, $tmp1, $out, $out

    # branchless conditional subtract to [0, Q)
    vpcmpgtd $out, $q, $tmp0           # mask: 0xFFFFFFFF where out < q (no subtract needed)
    vpandn $q, $tmp0, $tmp0            # tmp0 = (out >= q) ? q : 0
    vpsubd $tmp0, $out, $out           # out -= tmp0
___
}

###############################################################################
###############################################################################
###
### NTT (Number Theoretic Transform)
###
###############################################################################
###############################################################################

###############################################################################
# ntt_butterfly
#
# Description:
#   Performs one butterfly step of a single NTT level on two 8-element YMM vectors.
#   Uses signed Montgomery multiplication (vpmuldq) for the twiddle product:
#
#     t = hi32(zeta × w_odd) − hi32(Q × lo32(zeta_qinv × w_odd))   ∈ (−Q, Q)
#
#   Outputs are NOT biased — they remain signed and can be negative:
#
#     n_even = w_even + t   ∈ (−2Q, 2Q)
#     n_odd  = w_even − t   ∈ (−2Q, 2Q)
#
#   After 7 levels the worst-case coefficient range is (−7Q, 9Q) ≈ ±75 M,
#   which fits comfortably in signed int32 (max ~2.1 B).
#   The caller (ml_dsa_poly_ntt_avx2) adds a one-time +8Q correction pass
#   after all levels so outputs are non-negative for downstream vpmuludq.
#
# Parameters:
#   w_even     - YMM containing the even-indexed input coefficients
#   w_odd      - YMM containing the odd-indexed input coefficients
#   zetas      - YMM containing the twiddle factors (zeta values)
#   zetas_qinv - YMM containing the precomputed (zeta × QINV) mod 2^32 companions
#   n_even     - Output YMM for updated even coefficients
#   n_odd      - Output YMM for updated odd coefficients
#   tmp0..tmp3 - Scratch YMM registers
#   q          - YMM broadcast with modulus Q
#   level      - current NTT level (controls bcast32 mode:
#                  level < 7  → bcast32=1, all 8 lanes share one zeta (vpbroadcastd)
#                  level >= 7 → bcast32=0, each lane has a distinct zeta (vmovdqu))
#
# Side effects:
#   Clobbers tmp0, tmp1, tmp2, tmp3
###############################################################################
sub ntt_butterfly {
    my ($w_even, $w_odd,
        $zetas, $zetas_qinv,
        $n_even, $n_odd,
        $tmp0, $tmp1, $tmp2, $tmp3,
        $q, $level) = @_;

    if ($level >= 7) {
        # bcast32=0: each dword in the YMM register is a different zeta
        $code .= <<___;
    vpmuldq $zetas_qinv, $w_odd, $tmp0
    vmovshdup $w_odd, $tmp1
    vmovshdup $zetas_qinv, $tmp2
    vpmuldq $tmp2, $tmp1, $tmp2
    vpmuldq $zetas, $w_odd, $w_odd
    vmovshdup $zetas, $tmp3
    vpmuldq $tmp3, $tmp1, $tmp1
___
    } else {
        # bcast32=1: all dwords in the YMM register are the same zeta (broadcast)
        $code .= <<___;
    vpmuldq $zetas_qinv, $w_odd, $tmp0
    vmovshdup $w_odd, $tmp1
    vpmuldq $zetas_qinv, $tmp1, $tmp2
    vpmuldq $zetas, $w_odd, $w_odd
    vpmuldq $zetas, $tmp1, $tmp1
___
    }
    $code .= <<___;
    vpmuldq $q, $tmp0, $tmp0
    vpmuldq $q, $tmp2, $tmp2
    # move upper 32 bits of each 64-bit lane product into the low dword position
    vmovshdup $w_odd, $w_odd
    # 0xAA = 0b10101010: merge odd-lane results (tmp1) into even lanes (w_odd)
    vpblendd \$0xAA, $tmp1, $w_odd, $w_odd
    vmovshdup $tmp0, $tmp0
    vpblendd \$0xAA, $tmp2, $tmp0, $tmp0
    vpsubd $w_odd, $w_even, $tmp1
    vpaddd $w_odd, $w_even, $n_even
    vpaddd $tmp0, $tmp1, $n_odd
    vpsubd $tmp0, $n_even, $n_even
___
}

###############################################################################
# ntt_levels0to2
#
# Description: Performs the first three layers (levels 0, 1, and 2) of the NTT.
#   It works on 8 YMM registers, 8 32-bit coefficients each. Coefficients loaded into
#   YMM's are separated by 32 coefficients (32 x 4 bytes = 128 bytes). All 8 YMM registers
#   undergo consecutive butterfly operations with the appropriate "zetas" (twiddle factors) for
#   each level. This function must be called 4 times with different offsets to process all 256
#   coefficients.
#
# Layer/level details:
#   - Level 0:  offset = 128, step = 1, uses zeta index 1
#   - Level 1:  offset =  64, step = 2, uses zeta indexes 2, 3
#   - Level 2:  offset =  32, step = 4, uses zeta indexes 4, 5, 6, 7
#
# Prerequisites:
#   %rdi    - pointer to the coefficients
#   %r11    - pointer to the zetas (twiddle factors) table
#   %ymm15  - register with modulus Q
#
# Arguments:
#   $off    - offset to the start of a group of 8 coefficients (in bytes, relative to %rdi)
#             valid values: 0*4, 8*4, 16*4 or 24*4
#
# Output:
#   In-place NTT updated coefficients in memory.
#
# Notes:
#   - Must be invoked 4 times for complete polynomial: offsets 0, 8*4, 16*4, 24*4
###############################################################################

sub ntt_levels0to2 {
    my ($off) = @_;
    $code .= <<___;
    vmovdqu $off+0*4(%rdi), %ymm0
    vmovdqu $off+32*4(%rdi), %ymm1
    vmovdqu $off+64*4(%rdi), %ymm2
    vmovdqu $off+96*4(%rdi), %ymm3
    vmovdqu $off+128*4(%rdi), %ymm4
    vmovdqu $off+160*4(%rdi), %ymm5
    vmovdqu $off+192*4(%rdi), %ymm6
    vmovdqu $off+224*4(%rdi), %ymm7

    # ==============================================================
    # level 0: offset = 128, step = 1
    # zeta index = 1

    vpbroadcastd 1*4(%r11), %ymm13
    vpbroadcastd 1*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm0", "%ymm4", "%ymm13", "%ymm14", "%ymm0", "%ymm4",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 0);
    &ntt_butterfly("%ymm1", "%ymm5", "%ymm13", "%ymm14", "%ymm1", "%ymm5",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 0);
    &ntt_butterfly("%ymm2", "%ymm6", "%ymm13", "%ymm14", "%ymm2", "%ymm6",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 0);
    &ntt_butterfly("%ymm3", "%ymm7", "%ymm13", "%ymm14", "%ymm3", "%ymm7",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 0);
    $code .= <<___;

    # ==============================================================
    # level 1: offset = 64, step = 2
    # zeta indexes = 2..3

    vpbroadcastd 2*4(%r11), %ymm13
    vpbroadcastd 2*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm0", "%ymm2", "%ymm13", "%ymm14", "%ymm0", "%ymm2",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 1);
    &ntt_butterfly("%ymm1", "%ymm3", "%ymm13", "%ymm14", "%ymm1", "%ymm3",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 1);
    $code .= <<___;
    vpbroadcastd 3*4(%r11), %ymm13
    vpbroadcastd 3*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm4", "%ymm6", "%ymm13", "%ymm14", "%ymm4", "%ymm6",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 1);
    &ntt_butterfly("%ymm5", "%ymm7", "%ymm13", "%ymm14", "%ymm5", "%ymm7",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 1);
$code .= <<___;

    # ==============================================================
    # level 2: offset = 32, step = 4
    # zeta indexes = 4..7

    vpbroadcastd 4*4(%r11), %ymm13
    vpbroadcastd 4*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm0", "%ymm1", "%ymm13", "%ymm14", "%ymm0", "%ymm1",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 2);
    $code .= <<___;
    vpbroadcastd 5*4(%r11), %ymm13
    vpbroadcastd 5*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm2", "%ymm3", "%ymm13", "%ymm14", "%ymm2", "%ymm3",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 2);
    $code .= <<___;
    vpbroadcastd 6*4(%r11), %ymm13
    vpbroadcastd 6*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm4", "%ymm5", "%ymm13", "%ymm14", "%ymm4", "%ymm5",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 2);
    $code .= <<___;
    vpbroadcastd 7*4(%r11), %ymm13
    vpbroadcastd 7*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm6", "%ymm7", "%ymm13", "%ymm14", "%ymm6", "%ymm7",
                   "%ymm8", "%ymm9", "%ymm10", "%ymm11",
                   "%ymm15", 2);
$code .= <<___;

    vmovdqu %ymm0, $off+0*4(%rdi)
    vmovdqu %ymm1, $off+32*4(%rdi)
    vmovdqu %ymm2, $off+64*4(%rdi)
    vmovdqu %ymm3, $off+96*4(%rdi)
    vmovdqu %ymm4, $off+128*4(%rdi)
    vmovdqu %ymm5, $off+160*4(%rdi)
    vmovdqu %ymm6, $off+192*4(%rdi)
    vmovdqu %ymm7, $off+224*4(%rdi)
___
}

###############################################################################
# ntt_levels3to7
#
# Description:
#   Performs layers 3 through 7 of the NTT on 64 coefficients.
#
#   It operates on 8 YMM's registers, each YMM packs 8 32-bit coefficients (64
#   in total).
#   Contiguous coefficients are loaded into the YMM registers (no gap between them).
#
#   The function must be called 4 times to process 256 coefficients.  At each level, the
#   function executes butterfly operations in the correct coefficient pattern and applies the
#   corresponding twiddle factors ("zetas").
#
# Layer/level details:
#   - Level 3: offset = 16, step = 8;   zeta indexes 8...15
#   - Level 4: offset =  8, step = 16;  zeta indexes 16...31
#   - Level 5: offset =  4, step = 32;  zeta indexes 32...63
#   - Level 6: offset =  2, step = 64;  zeta indexes 64...127
#   - Level 7: offset =  1, step = 128; zeta indexes 128...255
#
# Prerequisites:
#   %rdi    - pointer to the coefficients
#   %r11    - pointer to the forward zetas table used by levels 3, 4 and 7
#   %ymm15  - Q (modulus)
#
# Arguments:
#   $off, $l3, $l4, $l5, $l6, $l7, $ntt5_reg, $ntt6_reg
#     $off - offset to the start of a set of 8 coefficients (in bytes, relative to %rdi)
#     $l3, $l4, $l7 - offsets to required zetas in the forward zetas table
#     $l5 - byte offset into the preformatted level-5 zeta table
#     $l6 - byte offset into the preformatted level-6 zeta table
#     $ntt5_reg - register holding the base pointer to the level-5 zeta table
#     $ntt6_reg - register holding the base pointer to the level-6 zeta table
#
# Output:
#   In-place NTT-transformed coefficients for the selected group.
#
# Notes:
#   - Should be called 4 times per complete 256-coefficient transform (offsets 0, 64*4, 128*4, 192*4).
#   - All butterfly operations and twiddle applications handled by subroutine ntt_butterfly.
###############################################################################
sub ntt_levels3to7 {
    my ($off,$l3,$l4,$l5,$l6,$l7,$ntt5_reg,$ntt6_reg) = @_;

    $code .= <<___;
    # ==============================================================
    # level 3: offset = 16, step = 8
    # zeta indexes = 8..15

    # broadcast zeta for first butterfly group
    vpbroadcastd $l3(%r11), %ymm13
    vpbroadcastd $l3+$ZETA256_QINV_OFS(%r11), %ymm14

    # load w_even and w_odd
    vmovdqu $off(%rdi), %ymm0       # coefficients 0..7
    vmovdqu $off+32(%rdi), %ymm1    # coefficients 8..15
    vmovdqu $off+64(%rdi), %ymm2    # coefficients 16..23
    vmovdqu $off+96(%rdi), %ymm3    # coefficients 24..31
___
    &ntt_butterfly("%ymm0", "%ymm2", "%ymm13", "%ymm14", "%ymm0", "%ymm2",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 3);
    &ntt_butterfly("%ymm1", "%ymm3", "%ymm13", "%ymm14", "%ymm1", "%ymm3",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 3);
$code .= <<___;
    # broadcast zeta for next butterfly group
    vpbroadcastd $l3+1*4(%r11), %ymm13
    vpbroadcastd $l3+1*4+$ZETA256_QINV_OFS(%r11), %ymm14

    # load w_even and w_odd
    vmovdqu $off+128(%rdi), %ymm4   # coefficients 32..39
    vmovdqu $off+160(%rdi), %ymm5   # coefficients 40..47
    vmovdqu $off+192(%rdi), %ymm6   # coefficients 48..55
    vmovdqu $off+224(%rdi), %ymm7   # coefficients 56..63
___
    &ntt_butterfly("%ymm4", "%ymm6", "%ymm13", "%ymm14", "%ymm4", "%ymm6",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 3);
    &ntt_butterfly("%ymm5", "%ymm7", "%ymm13", "%ymm14", "%ymm5", "%ymm7",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 3);
$code .= <<___;

    # ==============================================================
    # level 4: offset = 8, step = 16
    # zeta indexes = 16..31

    # broadcast zetas for first butterfly group
    vpbroadcastd $l4(%r11), %ymm13      # zeta for coefficients 0..7
    vpbroadcastd $l4+$ZETA256_QINV_OFS(%r11), %ymm14

    # Input dword layout from level 3:
    #   ymm0 = [ 0  1  2  3 |  4  5  6  7]   butterfly even half
    #   ymm1 = [ 8  9 10 11 | 12 13 14 15]   butterfly odd  half
    #   ymm2 = [16 17 18 19 | 20 21 22 23]   butterfly even half
    #   ymm3 = [24 25 26 27 | 28 29 30 31]   butterfly odd  half
    # ymm4..ymm7 follow the same pattern for coefficients 32..63.
    # No rearrangement needed; ymm0 pairs with ymm1, ymm2 pairs with ymm3, etc.

___
    &ntt_butterfly("%ymm0", "%ymm1", "%ymm13", "%ymm14", "%ymm0", "%ymm1",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 4);
$code .= <<___;
    # broadcast zeta for next butterfly group
    vpbroadcastd $l4+1*4(%r11), %ymm13  # zeta for coefficients 8..15
    vpbroadcastd $l4+1*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm2", "%ymm3", "%ymm13", "%ymm14", "%ymm2", "%ymm3",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 4);
    $code .= <<___;
    # broadcast zeta for next butterfly group
    vpbroadcastd $l4+2*4(%r11), %ymm13  # zeta for coefficients 16..23
    vpbroadcastd $l4+2*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm4", "%ymm5", "%ymm13", "%ymm14", "%ymm4", "%ymm5",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 4);
$code .= <<___;
    # broadcast zeta for next butterfly group
    vpbroadcastd $l4+3*4(%r11), %ymm13  # zeta for coefficients 24..31
    vpbroadcastd $l4+3*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm6", "%ymm7", "%ymm13", "%ymm14", "%ymm6", "%ymm7",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 4);
    $code .= <<___;

    # ==============================================================
    # level 5: offset = 4, step = 32
    # zeta indexes = 32..63

    # rearrange into butterfly halves:
    #   input:  ymm0 = [0..3|4..7], ymm1 = [8..11|12..15]
    #   output: ymm8 = [0..3|8..11] (even half), ymm1 = [4..7|12..15] (odd half)
    # 0x20 = {src1_low128, src2_low128}, 0x31 = {src1_high128, src2_high128}
    vperm2i128 \$0x20, %ymm1, %ymm0, %ymm8  # ymm8 = [0..3 | 8..11]
    vperm2i128 \$0x31, %ymm1, %ymm0, %ymm1  # ymm1 = [4..7 | 12..15]

    # load preformatted zetas for first butterfly group
    vmovdqu $l5($ntt5_reg), %ymm13
    vmovdqu $l5+$ZETA16R_QINV_OFS($ntt5_reg), %ymm14

___
    &ntt_butterfly("%ymm8", "%ymm1", "%ymm13", "%ymm14", "%ymm0", "%ymm1",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 5);
$code .= <<___;
    # rearrange ymm2/ymm3 into butterfly halves (same pattern as above)
    vperm2i128 \$0x20, %ymm3, %ymm2, %ymm8  # ymm8 = [16..19 | 24..27]
    vperm2i128 \$0x31, %ymm3, %ymm2, %ymm3  # ymm3 = [20..23 | 28..31]

    # load preformatted zetas for next butterfly group
    vmovdqu $l5+32($ntt5_reg), %ymm13
    vmovdqu $l5+32+$ZETA16R_QINV_OFS($ntt5_reg), %ymm14

___
    &ntt_butterfly("%ymm8", "%ymm3", "%ymm13", "%ymm14", "%ymm2", "%ymm3",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 5);
    $code .= <<___;
    # rearrange ymm4/ymm5 into butterfly halves (same pattern)
    vperm2i128 \$0x20, %ymm5, %ymm4, %ymm8
    vperm2i128 \$0x31, %ymm5, %ymm4, %ymm5

    # load preformatted zetas for next butterfly group
    vmovdqu $l5+64($ntt5_reg), %ymm13
    vmovdqu $l5+64+$ZETA16R_QINV_OFS($ntt5_reg), %ymm14

___
    &ntt_butterfly("%ymm8", "%ymm5", "%ymm13", "%ymm14", "%ymm4", "%ymm5",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 5);
$code .= <<___;
    # rearrange ymm6/ymm7 (same pattern)
    vperm2i128 \$0x20, %ymm7, %ymm6, %ymm8
    vperm2i128 \$0x31, %ymm7, %ymm6, %ymm7

    # load preformatted zetas for last butterfly group
    vmovdqu $l5+3*32($ntt5_reg), %ymm13
    vmovdqu $l5+3*32+$ZETA16R_QINV_OFS($ntt5_reg), %ymm14

___
    &ntt_butterfly("%ymm8", "%ymm7", "%ymm13", "%ymm14", "%ymm6", "%ymm7",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 5);
    $code .= <<___;

    # ==============================================================
    # level 6: offset = 2, step = 64
    # zeta indexes = 64..127

    # rearrange into butterfly halves using 64-bit interleave:
    #   input:  ymm0 = [0..3|8..11], ymm1 = [4..7|12..15]
    #   output: ymm8 = [0,1,4,5|8,9,12,13] (even half), ymm1 = [2,3,6,7|10,11,14,15] (odd half)
    vmovdqu $l6($ntt6_reg), %ymm13
    vmovdqu $l6+$ZETA16R_QINV_OFS($ntt6_reg), %ymm14

    vpunpcklqdq %ymm1, %ymm0, %ymm8    # low qwords of each 128-bit lane
    vpunpckhqdq %ymm1, %ymm0, %ymm1    # high qwords of each 128-bit lane
___
    &ntt_butterfly("%ymm8", "%ymm1", "%ymm13", "%ymm14", "%ymm0", "%ymm1",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 6);
    $code .= <<___;
    # rearrange ymm2/ymm3 into butterfly halves (same 64-bit interleave pattern)
    vmovdqu $l6+32($ntt6_reg), %ymm13
    vmovdqu $l6+32+$ZETA16R_QINV_OFS($ntt6_reg), %ymm14

    vpunpcklqdq %ymm3, %ymm2, %ymm8
    vpunpckhqdq %ymm3, %ymm2, %ymm3
___
    &ntt_butterfly("%ymm8", "%ymm3", "%ymm13", "%ymm14", "%ymm2", "%ymm3",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 6);
    $code .= <<___;
    # rearrange ymm4/ymm5 (same pattern)
    vmovdqu $l6+64($ntt6_reg), %ymm13
    vmovdqu $l6+64+$ZETA16R_QINV_OFS($ntt6_reg), %ymm14

    vpunpcklqdq %ymm5, %ymm4, %ymm8
    vpunpckhqdq %ymm5, %ymm4, %ymm5
___
    &ntt_butterfly("%ymm8", "%ymm5", "%ymm13", "%ymm14", "%ymm4", "%ymm5",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 6);
$code .= <<___;
    # rearrange ymm6/ymm7 (same pattern)
    vmovdqu $l6+96($ntt6_reg), %ymm13
    vmovdqu $l6+96+$ZETA16R_QINV_OFS($ntt6_reg), %ymm14

    vpunpcklqdq %ymm7, %ymm6, %ymm8
    vpunpckhqdq %ymm7, %ymm6, %ymm7
___
    &ntt_butterfly("%ymm8", "%ymm7", "%ymm13", "%ymm14", "%ymm6", "%ymm7",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 6);
    $code .= <<___;

    # ==============================================================
    # level 7: offset = 1, step = 128
    # zeta indexes = 128, 129, 130, ..., 254, 255

    # ==============================================================
    # level 7: offset = 1, step = 128
    # zeta indexes = 128..255

    # rearrange into butterfly halves using 32-bit interleave + vshufps:
    #   input:  ymm0 = [0,1,4,5|8,9,12,13], ymm1 = [2,3,6,7|10,11,14,15]
    #   output: ymm0 = [0,2,4,6|8,10,12,14] (even), ymm1 = [1,3,5,7|9,11,13,15] (odd)

    vpunpckldq   %ymm1, %ymm0, %ymm8      # ymm8 = [0,2,1,3|8,10,9,11]
    vpunpckhdq   %ymm1, %ymm0, %ymm9      # ymm9 = [4,6,5,7|12,14,13,15]

    # 0xEE = [2,3,2,3]: select upper 32-bit pairs from each 128-bit lane
    vshufps      \$0xEE, %ymm9, %ymm8, %ymm1   # ymm1 = [1,3,5,7|9,11,13,15]
    # 0x44 = [0,1,0,1]: select lower 32-bit pairs from each 128-bit lane
    vshufps      \$0x44, %ymm9, %ymm8, %ymm0   # ymm0 = [0,2,4,6|8,10,12,14]

    vmovdqu $l7(%r11), %ymm13
    vmovdqu $l7+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &ntt_butterfly("%ymm0", "%ymm1", "%ymm13", "%ymm14", "%ymm0", "%ymm1",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 7);
$code .= <<___;
    # rearrange ymm2/ymm3 (same 32-bit interleave + vshufps pattern)
    vmovdqu $l7+1*32(%r11), %ymm13
    vmovdqu $l7+1*32+$ZETA256_QINV_OFS(%r11), %ymm14

    vpunpckldq   %ymm3, %ymm2, %ymm8
    vpunpckhdq   %ymm3, %ymm2, %ymm9

    vshufps      \$0xEE, %ymm9, %ymm8, %ymm3   # odd half
    vshufps      \$0x44, %ymm9, %ymm8, %ymm2   # even half
___
    &ntt_butterfly("%ymm2", "%ymm3", "%ymm13", "%ymm14", "%ymm2", "%ymm3",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 7);
    $code .= <<___;

    # rearrange ymm4/ymm5 (same pattern)
    vmovdqu $l7+2*32(%r11), %ymm13
    vmovdqu $l7+2*32+$ZETA256_QINV_OFS(%r11), %ymm14

    vpunpckldq   %ymm5, %ymm4, %ymm8
    vpunpckhdq   %ymm5, %ymm4, %ymm9

    vshufps      \$0xEE, %ymm9, %ymm8, %ymm5   # odd half
    vshufps      \$0x44, %ymm9, %ymm8, %ymm4   # even half
___
    &ntt_butterfly("%ymm4", "%ymm5", "%ymm13", "%ymm14", "%ymm4", "%ymm5",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 7);
$code .= <<___;
    # rearrange ymm6/ymm7 (same pattern)
    vmovdqu $l7+3*32(%r11), %ymm13
    vmovdqu $l7+3*32+$ZETA256_QINV_OFS(%r11), %ymm14

    vpunpckldq   %ymm7, %ymm6, %ymm8
    vpunpckhdq   %ymm7, %ymm6, %ymm9

    vshufps      \$0xEE, %ymm9, %ymm8, %ymm7   # odd half
    vshufps      \$0x44, %ymm9, %ymm8, %ymm6   # even half
___
    &ntt_butterfly("%ymm6", "%ymm7", "%ymm13", "%ymm14", "%ymm6", "%ymm7",
                   "%ymm9", "%ymm10", "%ymm11", "%ymm12",
                   "%ymm15", 7);
    $code .= <<___;

    # interleave and store: reverse the butterfly half split back to natural order
    # 0x20 = {src1_low128, src2_low128}, 0x31 = {src1_high128, src2_high128}
    vpunpckldq %ymm1, %ymm0, %ymm8
    vpunpckhdq %ymm1, %ymm0, %ymm9

    vperm2i128 \$0x20, %ymm9, %ymm8, %ymm10   # coefficients 0..7
    vperm2i128 \$0x31, %ymm9, %ymm8, %ymm11   # coefficients 8..15
    vmovdqu %ymm10, $off(%rdi)
    vmovdqu %ymm11, $off+32(%rdi)

    vpunpckldq  %ymm3, %ymm2, %ymm8
    vpunpckhdq  %ymm3, %ymm2, %ymm9

    vperm2i128 \$0x20, %ymm9, %ymm8, %ymm10   # coefficients 16..23
    vperm2i128 \$0x31, %ymm9, %ymm8, %ymm11   # coefficients 24..31
    vmovdqu %ymm10, $off+64(%rdi)
    vmovdqu %ymm11, $off+96(%rdi)

    # store second half (same pattern)
    vpunpckldq %ymm5, %ymm4, %ymm8
    vpunpckhdq %ymm5, %ymm4, %ymm9

    vperm2i128 \$0x20, %ymm9, %ymm8, %ymm10   # coefficients 32..39
    vperm2i128 \$0x31, %ymm9, %ymm8, %ymm11   # coefficients 40..47
    vmovdqu %ymm10, $off+128(%rdi)
    vmovdqu %ymm11, $off+160(%rdi)

    vpunpckldq  %ymm7, %ymm6, %ymm8
    vpunpckhdq  %ymm7, %ymm6, %ymm9

    vperm2i128 \$0x20, %ymm9, %ymm8, %ymm10   # coefficients 48..55
    vperm2i128 \$0x31, %ymm9, %ymm8, %ymm11   # coefficients 56..63
    vmovdqu %ymm10, $off+192(%rdi)
    vmovdqu %ymm11, $off+224(%rdi)
___
}

###############################################################################
###############################################################################
###
### INTT (Inverse Number Theoretic Transform)
###
###############################################################################
###############################################################################

###############################################################################
# intt_butterfly
#
# Description:
#   Performs one butterfly step of a single INTT level on two 8-element YMM vectors.
#   Uses signed Montgomery multiplication (vpmuldq) for the twiddle product.
#
#   The INTT butterfly is the algebraic inverse of the NTT butterfly:
#
#     n_even = w_even + w_odd                                    (plain addition)
#     diff   = w_even − w_odd
#     n_odd  = hi32(zeta × diff) − hi32(Q × lo32(zeta_qinv × diff))   ∈ (−Q, Q)
#
#   After 8 levels the worst-case signed range is (-128Q, 256Q) ≈ ±1 B, far
#   below int32 overflow. The caller (intt_levels5to7) adds a one-time +128Q
#   correction to all 8 coefficient registers before the unsigned 1/N scaling.
#
# Parameters:
#   w_even     - YMM containing even-indexed input coefficients
#   w_odd      - YMM containing odd-indexed input coefficients
#   zetas      - YMM containing the twiddle factors
#   zetas_qinv - YMM containing the precomputed (zeta × QINV) mod 2^32 companions
#   tmp0..tmp3 - Scratch YMM registers (n_odd is reused as a 5th temporary
#                after n_even is written)
#   n_even     - Output YMM for updated even coefficients
#   n_odd      - Output YMM for updated odd coefficients
#   q          - YMM broadcast with modulus Q
#   level      - current INTT level (controls bcast32 mode:
#                  level >= 1 → bcast32=1, shared zeta (vpbroadcastd)
#                  level < 1  → bcast32=0, per-lane distinct zetas (vmovdqu))
#
# Side effects:
#   Clobbers tmp0, tmp1, tmp2, tmp3
###############################################################################

sub intt_butterfly {
    my ($w_even, $w_odd,
        $zetas, $zetas_qinv,
        $tmp0, $tmp1, $tmp2, $tmp3,
        $n_even, $n_odd,
        $q, $level) = @_;

    if ($level < 1) {
        # bcast32=0: each dword in zeta YMM is different (level 0)
        # n_odd register is used as 5th temp after n_even is computed
        $code .= <<___;
    vpsubd $w_odd, $w_even, $tmp0
    vpaddd $w_even, $w_odd, $n_even
    # n_odd now used as scratch (5th temp) until n_even is finalized above
    vmovshdup $tmp0, $n_odd
    vpmuldq $zetas_qinv, $tmp0, $tmp1
    vmovshdup $zetas_qinv, $tmp3
    vpmuldq $tmp3, $n_odd, $tmp2
    vpmuldq $zetas, $tmp0, $tmp0
    vmovshdup $zetas, $tmp3
    vpmuldq $tmp3, $n_odd, $n_odd
___
    } else {
        # bcast32=1: same zeta for all elements (levels 1-7)
        # n_odd register is used as 5th temp after n_even is computed
        $code .= <<___;
    vpsubd $w_odd, $w_even, $tmp0
    vpaddd $w_even, $w_odd, $n_even
    # n_odd now used as scratch (5th temp) until n_even is finalized above
    vmovshdup $tmp0, $n_odd
    vpmuldq $zetas_qinv, $tmp0, $tmp1
    vpmuldq $zetas_qinv, $n_odd, $tmp2
    vpmuldq $zetas, $tmp0, $tmp0
    vpmuldq $zetas, $n_odd, $n_odd
___
    }
    $code .= <<___;
    vpmuldq $q, $tmp1, $tmp1
    vpmuldq $q, $tmp2, $tmp2
    # move upper 32 bits of each 64-bit lane product into the low dword position
    vmovshdup $tmp0, $tmp0
    # 0xAA = 0b10101010: merge odd-lane results (n_odd scratch) into even lanes (tmp0)
    vpblendd \$0xAA, $n_odd, $tmp0, $tmp0
    vmovshdup $tmp1, $tmp1
    vpblendd \$0xAA, $tmp2, $tmp1, $tmp1
    vpsubd $tmp1, $tmp0, $n_odd
___
}

###############################################################################
# intt_levels0to4
#
# Description:
#   Executes the first five stages (levels 0–4) of the INTT
#   on a block of 64 coefficients (8 YMM registers).
#
#   This function hierarchically mixes and transforms groups of coefficients using
#   butterfly operations and level specific zeta (twiddle) factors, performing all required
#   re-packing and permutations for each layer.
#
#   Each call operates on a block of 64 coefficients, and must be repeated 4 times (with
#   offsets 0, 64*4, 128*4, 192*4) to process all 256 coefficients.
#
# Layer/Level details:
#   - Level 0: offset = 1,   step = 128;  zeta indexes (new) = 0..127
#   - Level 1: offset = 2,   step = 64;   zeta indexes (new) = 128..191
#   - Level 2: offset = 4,   step = 32;   zeta indexes (new) = 192..223
#   - Level 3: offset = 8,   step = 16;   zeta indexes (new) = 224..239
#   - Level 4: offset = 16,  step = 8;    zeta indexes (new) = 240..247
#
# Prerequisites:
#   %rdi          - pointer to the coefficients array
#   %r11          - pointer to the zetas_inverse table (used by levels 0, 3, 4)
#   $intt1_reg    - register holding pointer to ml_dsa_zetas_intt1 (used by level 1)
#   $intt2_reg    - register holding pointer to ml_dsa_zetas_intt2 (used by level 2)
#   %ymm15        - Q (modulus)
#
# Arguments:
#   $off           - offset (in bytes) to the start of the 64-coefficient block
#   $l0            - byte offset into zetas_inverse for level 0
#   $l1            - byte offset into ml_dsa_zetas_intt1 for level 1
#   $l2            - byte offset into ml_dsa_zetas_intt2 for level 2
#   $l3, $l4       - byte offsets into zetas_inverse for levels 3 and 4
#   $intt1_reg     - register holding base pointer to ml_dsa_zetas_intt1
#   $intt2_reg     - register holding base pointer to ml_dsa_zetas_intt2
#
# Output:
#   Updated coefficients are written in-place in memory.
#
# Notes:
#   - Function must be called 4 times for a full 256-coefficient INTT layer sweep.
###############################################################################

sub intt_levels0to4 {
    my ($off,$l0,$l1,$l2,$l3,$l4,$intt1_reg,$intt2_reg) = @_;
    my ($l1a,$l1b,$l1c,$l1d) = ($l1, $l1+32, $l1+64, $l1+96);
    my ($l2a,$l2b,$l2c,$l2d) = ($l2, $l2+32, $l2+64, $l2+96);
    $code .= <<___;
    # ==============================================================
    # level 0: offset = 1, step = 128
    # zeta indexes = 0..127  (zetas_inverse table)

    # separate interleaved coefficient pairs into even and odd YMM registers.
    # memory layout: ymm8 = [0,1,2,3|4,5,6,7], ymm9 = [8,9,10,11|12,13,14,15]
    # target layout: ymm0 = [0,2,4,6|8,10,12,14] (even), ymm1 = [1,3,5,7|9,11,13,15] (odd)
    # idx_even/idx_odd are vpermd index vectors that gather even/odd dwords to lanes 0..3.
    # 0xf0 = 0b11110000: select upper 4 dwords (lanes 4..7) from ymm11 (src2).

    # load w_even and w_odd
    vmovdqu $off(%rdi), %ymm8
    vmovdqu $off+32(%rdi), %ymm9

    # compact even words into ymm0 (w_even[0:7])
    vmovdqa idx_even(%rip), %ymm13
    vpermd %ymm8, %ymm13, %ymm10            # [ 0, 2, 4, 6 | 0, 2, 4, 6]
    vpermd %ymm9, %ymm13, %ymm11            # [ 8,10,12,14 | 8,10,12,14]
    vpblendd \$0xf0, %ymm11, %ymm10, %ymm0  # [ 0, 2, 4, 6 | 8,10,12,14]

    # compact odd words into ymm1 (w_odd[0..7])
    vmovdqa idx_odd(%rip), %ymm13
    vpermd %ymm8, %ymm13, %ymm10            # [ 1, 3, 5, 7 | 1, 3, 5, 7]
    vpermd %ymm9, %ymm13, %ymm11            # [ 9,11,13,15 | 9,11,13,15]
    vpblendd \$0xf0, %ymm11, %ymm10, %ymm1  # [ 1, 3, 5, 7 | 9,11,13,15]

    # load 8 zetas and 8 qinv companions
    vmovdqu $l0(%r11), %ymm13
    vmovdqu $l0+$ZETA256_QINV_OFS(%r11), %ymm14

___
    &intt_butterfly("%ymm0", "%ymm1", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm0", "%ymm1",
                    "%ymm15", 0);

$code .= <<___;

    # same even/odd separation for the next coefficient group (same pattern as above)
    vmovdqu $off+64(%rdi), %ymm8
    vmovdqu $off+96(%rdi), %ymm9

    # compact even words into ymm2 (w_even[8..15])
    vmovdqa idx_even(%rip), %ymm13
    vpermd %ymm8, %ymm13, %ymm10
    vpermd %ymm9, %ymm13, %ymm11
    vpblendd \$0xf0, %ymm11, %ymm10, %ymm2

    # compact odd words into ymm3 (w_odd[8..15])
    vmovdqa idx_odd(%rip), %ymm13
    vpermd %ymm8, %ymm13, %ymm10
    vpermd %ymm9, %ymm13, %ymm11
    vpblendd \$0xf0, %ymm11, %ymm10, %ymm3

    # load 8 zetas and 8 qinv companions
    vmovdqu $l0+1*32(%r11), %ymm13
    vmovdqu $l0+1*32+$ZETA256_QINV_OFS(%r11), %ymm14

___
    &intt_butterfly("%ymm2", "%ymm3", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm2", "%ymm3",
                    "%ymm15", 0);

$code .= <<___;
    # load w_even and w_odd
    vmovdqu $off+128(%rdi), %ymm8
    vmovdqu $off+160(%rdi), %ymm9

    # compact even words into ymm4 (w_even[16..23])
    vmovdqa idx_even(%rip), %ymm13
    vpermd %ymm8, %ymm13, %ymm10            # [ 0, 2, 4, 6 | 0, 2, 4, 6]
    vpermd %ymm9, %ymm13, %ymm11            # [ 8,10,12,14 | 8,10,12,14]
    vpblendd \$0xf0, %ymm11, %ymm10, %ymm4  # [ 0, 2, 4, 6 | 8,10,12,14]

    # compact odd words into ymm5 (w_odd[16..23])
    vmovdqa idx_odd(%rip), %ymm13
    vpermd %ymm8, %ymm13, %ymm10            # [ 1, 3, 5, 7 | 1, 3, 5, 7]
    vpermd %ymm9, %ymm13, %ymm11            # [ 9,11,13,15 | 9,11,13,15]
    vpblendd \$0xf0, %ymm11, %ymm10, %ymm5  # [ 1, 3, 5, 7 | 9,11,13,15]

    # load 8 zetas and 8 qinv companions
    vmovdqu $l0+2*32(%r11), %ymm13
    vmovdqu $l0+2*32+$ZETA256_QINV_OFS(%r11), %ymm14

___
    &intt_butterfly("%ymm4", "%ymm5", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm4", "%ymm5",
                    "%ymm15", 0);

$code .= <<___;

    # load w_even and w_odd
    vmovdqu $off+192(%rdi), %ymm8
    vmovdqu $off+224(%rdi), %ymm9

    # compact even words into ymm6 (w_even[24..31])
    vmovdqa idx_even(%rip), %ymm13
    vpermd %ymm8, %ymm13, %ymm10
    vpermd %ymm9, %ymm13, %ymm11
    vpblendd \$0xf0, %ymm11, %ymm10, %ymm6

    # compact odd words into ymm7 (w_odd[24..31])
    vmovdqa idx_odd(%rip), %ymm13
    vpermd %ymm8, %ymm13, %ymm10
    vpermd %ymm9, %ymm13, %ymm11
    vpblendd \$0xf0, %ymm11, %ymm10, %ymm7

    # load 8 zetas and 8 qinv companions
    vmovdqu $l0+3*32(%r11), %ymm13
    vmovdqu $l0+3*32+$ZETA256_QINV_OFS(%r11), %ymm14

___
    &intt_butterfly("%ymm6", "%ymm7", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm6", "%ymm7",
                    "%ymm15", 0);

$code .= <<___;

    # ==============================================================
    # level 1: offset = 2, step = 64
    # zeta indexes = 128..191  (ml_dsa_zetas_intt1 table)

    # rearrange even/odd registers into butterfly halves using 32-bit interleave + vshufps:
    #   input:  ymm0 = [0,2,4,6|8,10,12,14], ymm1 = [1,3,5,7|9,11,13,15]
    #   output: ymm0 = [0,1,4,5|8,9,12,13],  ymm1 = [2,3,6,7|10,11,14,15]
    # 0x44 = [0,1,0,1]: select lower 32-bit pairs from each 128-bit lane
    # 0xEE = [2,3,2,3]: select upper 32-bit pairs from each 128-bit lane
    #   %ymm0 = [0,1,4,5,8,9,12,13]
    #   %ymm1 = [2,3,6,7,10,11,14,15]

    # interleave even/odd registers into butterfly halves (see level 1 comment above)
    vpunpckldq %ymm1, %ymm0, %ymm8     # low dwords of each 64-bit lane pair
    vpunpckhdq %ymm1, %ymm0, %ymm9     # high dwords of each 64-bit lane pair
    vshufps \$0x44, %ymm9, %ymm8, %ymm0   # even half: [0,1,4,5|8,9,12,13]
    vshufps \$0xEE, %ymm9, %ymm8, %ymm1   # odd half:  [2,3,6,7|10,11,14,15]

    vmovdqu $l1a($intt1_reg), %ymm13
    vmovdqu $l1a+$ZETA16R_QINV_OFS($intt1_reg), %ymm14
___
    &intt_butterfly("%ymm0", "%ymm1", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm0", "%ymm1",
                    "%ymm15", 1);

$code .= <<___;
    # same rearrangement for ymm2/ymm3
    vpunpckldq %ymm3, %ymm2, %ymm8
    vpunpckhdq %ymm3, %ymm2, %ymm9
    vshufps \$0x44, %ymm9, %ymm8, %ymm2
    vshufps \$0xEE, %ymm9, %ymm8, %ymm3

    vmovdqu $l1b($intt1_reg), %ymm13
    vmovdqu $l1b+$ZETA16R_QINV_OFS($intt1_reg), %ymm14
___
    &intt_butterfly("%ymm2", "%ymm3", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm2", "%ymm3",
                    "%ymm15", 1);

$code .= <<___;
    # same rearrangement for ymm4/ymm5
    vpunpckldq %ymm5, %ymm4, %ymm8
    vpunpckhdq %ymm5, %ymm4, %ymm9
    vshufps \$0x44, %ymm9, %ymm8, %ymm4
    vshufps \$0xEE, %ymm9, %ymm8, %ymm5

    vmovdqu $l1c($intt1_reg), %ymm13
    vmovdqu $l1c+$ZETA16R_QINV_OFS($intt1_reg), %ymm14
___
    &intt_butterfly("%ymm4", "%ymm5", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm4", "%ymm5",
                    "%ymm15", 1);

$code .= <<___;
    # same rearrangement for ymm6/ymm7
    vpunpckldq %ymm7, %ymm6, %ymm8
    vpunpckhdq %ymm7, %ymm6, %ymm9
    vshufps \$0x44, %ymm9, %ymm8, %ymm6
    vshufps \$0xEE, %ymm9, %ymm8, %ymm7

    vmovdqu $l1d($intt1_reg), %ymm13
    vmovdqu $l1d+$ZETA16R_QINV_OFS($intt1_reg), %ymm14
___
    &intt_butterfly("%ymm6", "%ymm7", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm6", "%ymm7",
                    "%ymm15", 1);

$code .= <<___;

    # ==============================================================
    # level 2: offset = 4, step = 32
    # zeta indexes = 192..223  (ml_dsa_zetas_intt2 table)

    # rearrange into butterfly halves using vshufps (same 0x44/0xEE pattern):
    #   input:  ymm0 = [0,1,4,5|8,9,12,13], ymm1 = [2,3,6,7|10,11,14,15]
    #   output: ymm8 = [0,1,2,3|8,9,10,11], ymm1 = [4,5,6,7|12,13,14,15]
    vshufps \$0x44, %ymm1, %ymm0, %ymm8    # even half: gather low pairs
    vshufps \$0xEE, %ymm1, %ymm0, %ymm1    # odd half:  gather high pairs

    vmovdqu $l2a($intt2_reg), %ymm13
    vmovdqu $l2a+$ZETA16R_QINV_OFS($intt2_reg), %ymm14
___
    &intt_butterfly("%ymm8", "%ymm1", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm0", "%ymm1",
                    "%ymm15", 2);

$code .= <<___;
    # same rearrangement for ymm2/ymm3
    vshufps \$0x44, %ymm3, %ymm2, %ymm8
    vshufps \$0xEE, %ymm3, %ymm2, %ymm3

    vmovdqu $l2b($intt2_reg), %ymm13
    vmovdqu $l2b+$ZETA16R_QINV_OFS($intt2_reg), %ymm14
___
    &intt_butterfly("%ymm8", "%ymm3", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm2", "%ymm3",
                    "%ymm15", 2);

$code .= <<___;
    # same rearrangement for ymm4/ymm5
    vshufps \$0x44, %ymm5, %ymm4, %ymm8
    vshufps \$0xEE, %ymm5, %ymm4, %ymm5

    vmovdqu $l2c($intt2_reg), %ymm13
    vmovdqu $l2c+$ZETA16R_QINV_OFS($intt2_reg), %ymm14
___
    &intt_butterfly("%ymm8", "%ymm5", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm4", "%ymm5",
                    "%ymm15", 2);

$code .= <<___;
    # same rearrangement for ymm6/ymm7
    vshufps \$0x44, %ymm7, %ymm6, %ymm8
    vshufps \$0xEE, %ymm7, %ymm6, %ymm7

    # load pre-formatted zeta pair
    vmovdqu $l2d($intt2_reg), %ymm13
    vmovdqu $l2d+$ZETA16R_QINV_OFS($intt2_reg), %ymm14
___
    &intt_butterfly("%ymm8", "%ymm7", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm6", "%ymm7",
                    "%ymm15", 2);

$code .= <<___;

    # ==============================================================
    # level 3: offset = 8, step = 16
    # zeta indexes = 224..239  (zetas_inverse table)

    # rearrange into butterfly halves using vperm2i128:
    #   input:  ymm0 = [0,1,2,3|8,9,10,11], ymm1 = [16,17,18,19|24,25,26,27]
    #   output: ymm8 = [0,1,2,3|4,5,6,7]  (low 128-bit halves)
    #           ymm1 = [8,9,10,11|12,13,14,15] (high 128-bit halves)
    # 0x20 = {src1_low128, src2_low128}, 0x31 = {src1_high128, src2_high128}
    vperm2i128 \$0x20, %ymm1, %ymm0, %ymm8
    vperm2i128 \$0x31, %ymm1, %ymm0, %ymm1

    # broadcast zetas
    vpbroadcastd $l3(%r11), %ymm13
    vpbroadcastd $l3+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm8", "%ymm1", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm0", "%ymm1",
                    "%ymm15", 3);

$code .= <<___;
    # same rearrangement for ymm2/ymm3
    vperm2i128 \$0x20, %ymm3, %ymm2, %ymm8
    vperm2i128 \$0x31, %ymm3, %ymm2, %ymm3

    vpbroadcastd $l3+1*4(%r11), %ymm13
    vpbroadcastd $l3+1*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm8", "%ymm3", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm2", "%ymm3",
                    "%ymm15", 3);

$code .= <<___;
    # same rearrangement for ymm4/ymm5
    vperm2i128 \$0x20, %ymm5, %ymm4, %ymm8
    vperm2i128 \$0x31, %ymm5, %ymm4, %ymm5

    vpbroadcastd $l3+2*4(%r11), %ymm13
    vpbroadcastd $l3+2*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm8", "%ymm5", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm4", "%ymm5",
                    "%ymm15", 3);

$code .= <<___;
    # same rearrangement for ymm6/ymm7
    vperm2i128 \$0x20, %ymm7, %ymm6, %ymm8
    vperm2i128 \$0x31, %ymm7, %ymm6, %ymm7

    vpbroadcastd $l3+3*4(%r11), %ymm13
    vpbroadcastd $l3+3*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm8", "%ymm7", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm6", "%ymm7",
                    "%ymm15", 3);

$code .= <<___;

    # ==============================================================
    # level 4: offset = 16, step = 8
    # zeta indexes = 240..247  (zetas_inverse table)

    # broadcast zetas
    vpbroadcastd $l4(%r11), %ymm13
    vpbroadcastd $l4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm0", "%ymm2", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm0", "%ymm2",
                    "%ymm15", 4);

    &intt_butterfly("%ymm1", "%ymm3", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm1", "%ymm3",
                    "%ymm15", 4);

$code .= <<___;
    vpbroadcastd $l4+1*4(%r11), %ymm13
    vpbroadcastd $l4+1*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm4", "%ymm6", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm4", "%ymm6",
                    "%ymm15", 4);

    &intt_butterfly("%ymm5", "%ymm7", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm5", "%ymm7",
                    "%ymm15", 4);

$code .= <<___;

    # store results
    vmovdqu %ymm0, $off(%rdi)
    vmovdqu %ymm1, $off+32(%rdi)
    vmovdqu %ymm2, $off+64(%rdi)
    vmovdqu %ymm3, $off+96(%rdi)
    vmovdqu %ymm4, $off+128(%rdi)
    vmovdqu %ymm5, $off+160(%rdi)
    vmovdqu %ymm6, $off+192(%rdi)
    vmovdqu %ymm7, $off+224(%rdi)
___
}

###############################################################################
# intt_levels5to7
#
# Description:
#   Processes the last three levels (5 to 7) of the INTT on 64 coefficients.
#
#   It completes the hierarchical merging of INTT, applying stage-specific zeta
#   (twiddle) factors and modular butterfly operations for each level, and performs the final
#   post-processing Montgomery multiplication at the end of the transform.
#
#   It must be invoked 4 times with offsets equal to 0*4, 8*4, 16*4 and 24*4 to cover
#   all 256 coefficients.
#
# Layer/Level details:
#   - Level 5: offset =  32, step = 4;   zeta indexes (new) = 248..251
#   - Level 6: offset =  64, step = 2;   zeta indexes (new) = 252, 253
#   - Level 7: offset = 128, step = 1;   zeta index   (new) = 254
#
#   After all INTT levels, multiplies the output by the Montgomery factor
#   corresponding to the inverse transform scaling (usually the modular inverse of the
#   NTT degree in Montgomery form), to obtain the final reduced coefficients.
#
# Prerequisites:
#   %rdi    - pointer to the coefficients array
#   %r11    - pointer to the zetas (twiddle factors) table
#   %ymm15  - Q (modulus)
#
# Arguments:
#   $off    - offset (in bytes) to the start of the 8-coefficient group
#
# Output:
#   Overwrites memory at the given offset with the INTT-processed coefficients.
#
# Notes:
#   - This subroutine must be called 4 times with appropriate offsets to process
#     all 256 coefficients.
###############################################################################

sub intt_levels5to7 {
    my ($off) = @_;
    $code .= <<___;
    vmovdqu $off+0*4(%rdi), %ymm0
    vmovdqu $off+32*4(%rdi), %ymm1
    vmovdqu $off+64*4(%rdi), %ymm2
    vmovdqu $off+96*4(%rdi), %ymm3
    vmovdqu $off+128*4(%rdi), %ymm4
    vmovdqu $off+160*4(%rdi), %ymm5
    vmovdqu $off+192*4(%rdi), %ymm6
    vmovdqu $off+224*4(%rdi), %ymm7

    # ==============================================================
    # level 5: offset = 32, step = 4

    vpbroadcastd 248*4(%r11), %ymm13
    vpbroadcastd 248*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm0", "%ymm1", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm0", "%ymm1",
                    "%ymm15", 5);
    $code .= <<___;
    vpbroadcastd 249*4(%r11), %ymm13
    vpbroadcastd 249*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm2", "%ymm3", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm2", "%ymm3",
                    "%ymm15", 5);

    $code .= <<___;
    vpbroadcastd 250*4(%r11), %ymm13
    vpbroadcastd 250*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm4", "%ymm5", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm4", "%ymm5",
                    "%ymm15", 5);

    $code .= <<___;
    vpbroadcastd 251*4(%r11), %ymm13
    vpbroadcastd 251*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm6", "%ymm7", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm6", "%ymm7",
                    "%ymm15", 5);
    $code .= <<___;

    # ==============================================================
    # level 6: offset = 64, step = 2

    vpbroadcastd 252*4(%r11), %ymm13
    vpbroadcastd 252*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm0", "%ymm2", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm0", "%ymm2",
                    "%ymm15", 6);
    &intt_butterfly("%ymm1", "%ymm3", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm1", "%ymm3",
                    "%ymm15", 6);
    $code .= <<___;
    vpbroadcastd 253*4(%r11), %ymm13
    vpbroadcastd 253*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm4", "%ymm6", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm4", "%ymm6",
                    "%ymm15", 6);
    &intt_butterfly("%ymm5", "%ymm7", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm5", "%ymm7",
                    "%ymm15", 6);
$code .= <<___;

    # ==============================================================
    # level 7: offset = 128, step = 1

    vpbroadcastd 254*4(%r11), %ymm13
    vpbroadcastd 254*4+$ZETA256_QINV_OFS(%r11), %ymm14
___
    &intt_butterfly("%ymm0", "%ymm4", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm0", "%ymm4",
                    "%ymm15", 7);
    &intt_butterfly("%ymm1", "%ymm5", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm1", "%ymm5",
                    "%ymm15", 7);
    &intt_butterfly("%ymm2", "%ymm6", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm2", "%ymm6",
                    "%ymm15", 7);
    &intt_butterfly("%ymm3", "%ymm7", "%ymm13", "%ymm14",
                    "%ymm10", "%ymm11", "%ymm12", "%ymm9",
                    "%ymm3", "%ymm7",
                    "%ymm15", 7);
$code .= <<___;

    # Bias INTT outputs by +128Q before unsigned Montgomery 1/N scaling.
    # Without per-butterfly +Q, n_even sums can accumulate over 8 levels.
    # In the worst case n_even pairs with another biased n_even at each level,
    # doubling the deficit: after 8 levels the minimum value is ~-128Q.
    # Adding 128Q guarantees all values >= 0, giving a max of ~384Q < 2^32
    # which multiply_mod_Q handles correctly (result still in [0, Q)).
    # Adding a multiple of Q does not affect the result modulo Q.
    vpslld  \$7, %ymm15, %ymm12       # ymm12 = 128 * Q
    vpaddd  %ymm12, %ymm0, %ymm0
    vpaddd  %ymm12, %ymm1, %ymm1
    vpaddd  %ymm12, %ymm2, %ymm2
    vpaddd  %ymm12, %ymm3, %ymm3
    vpaddd  %ymm12, %ymm4, %ymm4
    vpaddd  %ymm12, %ymm5, %ymm5
    vpaddd  %ymm12, %ymm6, %ymm6
    vpaddd  %ymm12, %ymm7, %ymm7

    # ==============================================================
    # 1/N scaling: multiply each coefficient by N^{-1} in Montgomery form
    vpbroadcastq ml_dsa_q_neg_inv(%rip), %ymm14
    vpbroadcastd ml_dsa_inverse_degree_montgomery(%rip), %ymm13
___

    &multiply_mod_Q("%ymm0", "%ymm13", "%ymm0",
                    "%ymm10", "%ymm11", "%ymm12",
                    "%ymm14", "%ymm15", 1);
    &multiply_mod_Q("%ymm4", "%ymm13", "%ymm4",
                    "%ymm10", "%ymm11", "%ymm12",
                    "%ymm14", "%ymm15", 1);
    &multiply_mod_Q("%ymm1", "%ymm13", "%ymm1",
                    "%ymm10", "%ymm11", "%ymm12",
                    "%ymm14", "%ymm15", 1);
    &multiply_mod_Q("%ymm5", "%ymm13", "%ymm5",
                    "%ymm10", "%ymm11", "%ymm12",
                    "%ymm14", "%ymm15", 1);
    &multiply_mod_Q("%ymm2", "%ymm13", "%ymm2",
                    "%ymm10", "%ymm11", "%ymm12",
                    "%ymm14", "%ymm15", 1);
    &multiply_mod_Q("%ymm6", "%ymm13", "%ymm6",
                    "%ymm10", "%ymm11", "%ymm12",
                    "%ymm14", "%ymm15", 1);
    &multiply_mod_Q("%ymm3", "%ymm13", "%ymm3",
                    "%ymm10", "%ymm11", "%ymm12",
                    "%ymm14", "%ymm15", 1);
    &multiply_mod_Q("%ymm7", "%ymm13", "%ymm7",
                    "%ymm10", "%ymm11", "%ymm12",
                    "%ymm14", "%ymm15", 1);

$code .= <<___;

    vmovdqu %ymm0, $off+0*4(%rdi)
    vmovdqu %ymm1, $off+32*4(%rdi)
    vmovdqu %ymm2, $off+64*4(%rdi)
    vmovdqu %ymm3, $off+96*4(%rdi)
    vmovdqu %ymm4, $off+128*4(%rdi)
    vmovdqu %ymm5, $off+160*4(%rdi)
    vmovdqu %ymm6, $off+192*4(%rdi)
    vmovdqu %ymm7, $off+224*4(%rdi)
___
}

$code .= <<___;
###############################################################################
###############################################################################
### Data section

.section .rodata

###############################################################################
# ml_dsa_zetas_forward, ml_dsa_zetas_ntt5, ml_dsa_zetas_ntt6,
# ml_dsa_zetas_intt1, ml_dsa_zetas_intt2:
#
# Description:
#   NTT zeta tables for the AVX2 path.
#   ml_dsa_zetas_forward preserves the canonical 256-entry Montgomery-form table
#   used by scalar code and levels 3, 4 and 7 of the AVX2 forward NTT.
#   ml_dsa_zetas_ntt5 and ml_dsa_zetas_ntt6 are preformatted subsets for forward
#   NTT levels 5 and 6 that reduce broadcast/shuffle overhead in the AVX2 path.
#   ml_dsa_zetas_intt1 and ml_dsa_zetas_intt2 are preformatted subsets for
#   inverse NTT levels 1 and 2 that eliminate vpmovzxdq and vpbroadcastd/vpblendd
#   sequences in the AVX2 inverse NTT path.
###############################################################################
.align 32
.globl  ml_dsa_zetas_forward
.hidden ml_dsa_zetas_forward
ml_dsa_zetas_forward:
___
# Each of the 256 entries is the Montgomery-form twiddle factor:
#   zetas_forward[i] = zeta^{brv_8(i)} mod Q  (FIPS 204, Table 1: zeta = 1753)
# Used by the forward NTT (FIPS 204, Algorithm 35) scalar path and AVX2 levels 3, 4, 7.
for (my $i = 0; $i < 256; $i += 8) {
    $code .= "    .long " . join(", ", @zetas_fwd[$i..$i+7]) . "\n";
}

$code .= <<___;
# ml_dsa_zetas_forward_qinv: companion table to ml_dsa_zetas_forward.
# Each entry is (zetas_forward[i] * QINV) mod 2^32, used for signed Montgomery butterfly.
# Stored as signed int32. 256 entries x 4 bytes = 1024 bytes.
# Must be placed immediately after ml_dsa_zetas_forward (offset 1024) so that
# the qinv table is accessible via the same base pointer (%r11) with offset +$ZETA256_QINV_OFS.
.align 32
ml_dsa_zetas_forward_qinv:
___
for (my $i = 0; $i < scalar(@zetas_fwd_qinv); $i += 8) {
    my @row;
    for (my $j = 0; $j < 8 && $i+$j < scalar(@zetas_fwd_qinv); $j++) {
        my $qinv = $zetas_fwd_qinv[$i+$j];
        $qinv -= (2**32) if $qinv >= (2**31);
        push @row, $qinv;
    }
    $code .= "    .long " . join(", ", @row) . "\n";
}

$code .= <<___;
# ml_dsa_zetas_ntt5: preformatted zetas for forward NTT level 5.
# Each YMM-width row holds a pair of consecutive entries from @zetas_fwd[32..63]
# broadcast-duplicated 4× each: [z0, z0, z0, z0, z1, z1, z1, z1].
# A single vmovdqu loads both twiddle factors for 8 coefficients, replacing
# two vpbroadcastd instructions per butterfly group.
# Generated from @zetas_fwd[32..63] (indices 32..63), 2 per row, 16 rows.
# 16 rows × 32 bytes = $ZETA16R_QINV_OFS bytes; companion qinv table follows at that offset.
.align 32
ml_dsa_zetas_ntt5:
___
for (my $i = 32; $i < 64; $i += 2) {
    my ($z0, $z1) = @zetas_fwd[$i, $i+1];
    $code .= "    .long $z0, $z0, $z0, $z0, $z1, $z1, $z1, $z1\n";
}

$code .= <<___;
# ml_dsa_zetas_ntt5_qinv: companion to ml_dsa_zetas_ntt5 for signed Montgomery.
# Same layout as ml_dsa_zetas_ntt5 but with qinv values.
# Generated from @zetas_fwd_qinv[32..63], 2 per row, 16 rows.
# Placed immediately after ml_dsa_zetas_ntt5 at byte offset $ZETA16R_QINV_OFS.
.align 32
ml_dsa_zetas_ntt5_qinv:
___
for (my $i = 32; $i < 64; $i += 2) {
    my $q0 = $zetas_fwd_qinv[$i];
    my $q1 = $zetas_fwd_qinv[$i+1];
    $q0 -= (2**32) if $q0 >= (2**31);
    $q1 -= (2**32) if $q1 >= (2**31);
    $code .= "    .long $q0, $q0, $q0, $q0, $q1, $q1, $q1, $q1\n";
}

$code .= <<___;
# ml_dsa_zetas_ntt6: preformatted zetas for forward NTT level 6.
# Each YMM-width row holds four consecutive entries from @zetas_fwd[64..127]
# in zero-extended dqword layout [z0, 0, z1, 0, z2, 0, z3, 0], matching the
# vpmuldq input format (operates on low 32 bits of each 64-bit lane).
# A single vmovdqu replaces vmovdqu-xmm + vpmovzxdq.
# Generated from @zetas_fwd[64..127] (indices 64..127), 4 per row, 16 rows.
# 16 rows × 32 bytes = $ZETA16R_QINV_OFS bytes; companion qinv table follows at that offset.
.align 64
ml_dsa_zetas_ntt6:
___
for (my $i = 64; $i < 128; $i += 4) {
    my @z = @zetas_fwd[$i..$i+3];
    $code .= "    .long $z[0], 0, $z[1], 0, $z[2], 0, $z[3], 0\n";
}

$code .= <<___;
# ml_dsa_zetas_ntt6_qinv: companion to ml_dsa_zetas_ntt6 for signed Montgomery.
# Same layout [qinv, 0, qinv, 0, qinv, 0, qinv, 0] as ml_dsa_zetas_ntt6.
# Generated from @zetas_fwd_qinv[64..127], 4 per row, 16 rows.
# Placed immediately after ml_dsa_zetas_ntt6 at byte offset $ZETA16R_QINV_OFS.
.align 32
ml_dsa_zetas_ntt6_qinv:
___
for (my $i = 64; $i < 128; $i += 4) {
    my @qv;
    for (my $j = 0; $j < 4; $j++) {
        my $q = $zetas_fwd_qinv[$i+$j];
        $q -= (2**32) if $q >= (2**31);
        push @qv, $q;
    }
    $code .= "    .long $qv[0], 0, $qv[1], 0, $qv[2], 0, $qv[3], 0\n";
}

$code .= <<___;
# ml_dsa_zetas_intt1: preformatted zetas for INTT level 1 (inverse of NTT level 6).
# Each YMM-width row holds four entries from the inverse zeta sequence
# (Q - @zetas_fwd[64..127], processed in reverse index order) in zero-extended
# dqword layout [zi, 0, zi+1, 0, zi+2, 0, zi+3, 0], matching vpmuldq input format.
# Generated from Q - @zetas_fwd[127..64] (indices 127 down to 64), 4 per row, 16 rows.
# 16 rows × 32 bytes = $ZETA16R_QINV_OFS bytes; companion qinv table follows at that offset.
.align 32
ml_dsa_zetas_intt1:
___
for (my $i = 127; $i >= 64; $i -= 4) {
    my @z = map { $ML_DSA_Q - $zetas_fwd[$i - $_] } (0..3);
    $code .= "    .long $z[0], 0, $z[1], 0, $z[2], 0, $z[3], 0\n";
}

$code .= <<___;
# ml_dsa_zetas_intt1_qinv: companion to ml_dsa_zetas_intt1.
# Same layout [qinv, 0, qinv, 0, qinv, 0, qinv, 0] as ml_dsa_zetas_intt1.
# Generated from (Q - @zetas_fwd[127..64]) × QINV mod 2^32, 4 per row, 16 rows.
# Placed immediately after ml_dsa_zetas_intt1 at byte offset $ZETA16R_QINV_OFS.
.align 32
ml_dsa_zetas_intt1_qinv:
___
for (my $i = 127; $i >= 64; $i -= 4) {
    my @qv;
    for (my $j = 0; $j < 4; $j++) {
        my $z_inv = $ML_DSA_Q - $zetas_fwd[$i - $j];
        my $q = int(($z_inv * $QINV) % (2**32));
        $q -= (2**32) if $q >= (2**31);
        push @qv, $q;
    }
    $code .= "    .long $qv[0], 0, $qv[1], 0, $qv[2], 0, $qv[3], 0\n";
}

$code .= <<___;
# ml_dsa_zetas_intt2: preformatted zetas for INTT level 2 (inverse of NTT level 5).
# Each YMM-width row holds a pair of entries from the inverse zeta sequence
# (Q - @zetas_fwd[32..63], processed in reverse index order) broadcast-duplicated
# 4× each: [zi, zi, zi, zi, zi+1, zi+1, zi+1, zi+1].
# Generated from Q - @zetas_fwd[63..32] (indices 63 down to 32), 2 per row, 16 rows.
# 16 rows × 32 bytes = $ZETA16R_QINV_OFS bytes; companion qinv table follows at that offset.
.align 32
ml_dsa_zetas_intt2:
___
for (my $i = 63; $i >= 32; $i -= 2) {
    my ($z0, $z1) = ($ML_DSA_Q - $zetas_fwd[$i], $ML_DSA_Q - $zetas_fwd[$i-1]);
    $code .= "    .long $z0, $z0, $z0, $z0, $z1, $z1, $z1, $z1\n";
}

$code .= <<___;
# ml_dsa_zetas_intt2_qinv: companion to ml_dsa_zetas_intt2.
# Same layout as ml_dsa_zetas_intt2 but with qinv values.
# Generated from (Q - @zetas_fwd[63..32]) × QINV mod 2^32, 2 per row, 16 rows.
# Placed immediately after ml_dsa_zetas_intt2 at byte offset $ZETA16R_QINV_OFS.
.align 32
ml_dsa_zetas_intt2_qinv:
___
for (my $i = 63; $i >= 32; $i -= 2) {
    my $z0 = $ML_DSA_Q - $zetas_fwd[$i];
    my $z1 = $ML_DSA_Q - $zetas_fwd[$i-1];
    my $q0 = int(($z0 * $QINV) % (2**32));
    my $q1 = int(($z1 * $QINV) % (2**32));
    $q0 -= (2**32) if $q0 >= (2**31);
    $q1 -= (2**32) if $q1 >= (2**31);
    $code .= "    .long $q0, $q0, $q0, $q0, $q1, $q1, $q1, $q1\n";
}

$code .= <<___;
# zetas_inverse: 256-entry inverse NTT twiddle-factor table (FIPS 204, Algorithm 36).
# Entry i = Q - @zetas_fwd[255-i] — the negated forward zeta in reversed traversal
# order, so the INTT can apply forward-table entries in reverse without a
# per-butterfly negation step.
# Used by INTT levels 0, 3, 4, 5, 6, 7 via the same base pointer with byte offsets.
# 256 entries × 4 bytes = $ZETA256_QINV_OFS bytes; companion qinv table follows at that offset.
.align 32
zetas_inverse:
___
for (my $i = 255; $i >= 0; $i -= 8) {
    my @row = map { $ML_DSA_Q - $zetas_fwd[$i - $_] } (0..7);
    $code .= "    .long " . join(", ", @row) . "\n";
}

$code .= <<___;
# zetas_inverse_qinv: companion to zetas_inverse.
# Each entry is (zetas_inverse[i] × QINV) mod 2^32.
# Generated from (Q - @zetas_fwd[255..0]) × QINV mod 2^32, 8 per row, 32 rows.
# Placed immediately after zetas_inverse at byte offset $ZETA256_QINV_OFS.
.align 32
zetas_inverse_qinv:
___
for (my $i = 0; $i < 256; $i += 8) {
    my @row;
    for (my $j = 0; $j < 8 && $i+$j < 256; $j++) {
        my $z_inv = $ML_DSA_Q - $zetas_fwd[255 - ($i+$j)];
        my $q = int(($z_inv * $QINV) % (2**32));
        $q -= (2**32) if $q >= (2**31);
        push @row, $q;
    }
    $code .= "    .long " . join(", ", @row) . "\n";
}

$code .= <<___;
.align 32
idx_even:
    # vpermd index vector: gathers even-indexed dwords [0,2,4,6] from each 128-bit lane
    .long 0,2,4,6, 0,2,4,6

.align 32
idx_odd:
    # vpermd index vector: gathers odd-indexed dwords [1,3,5,7] from each 128-bit lane
    .long 1,3,5,7, 1,3,5,7

# Modulus Q = 2^23 - 2^13 + 1 (FIPS 204, Table 1)
.align 8
ml_dsa_q:
    .quad $ML_DSA_Q

# -Q^{-1} mod 2^32 — unsigned Montgomery parameter for multiply_mod_Q
.align 8
ml_dsa_q_neg_inv:
    .quad $ML_DSA_Q_NEG_INV

# N^{-1} mod Q in Montgomery form — for INTT 1/N scaling (FIPS 204, Table 1: N = 256)
.align 8
ml_dsa_inverse_degree_montgomery:
    .quad $inverse_degree_montgomery

###############################################################################
###############################################################################
### Code section

.text

###############################################################################
# ml_dsa_poly_ntt_mult_avx2
#
# AVX2 implementation of FIPS 204, §8.3 Algorithm 37 (MultiplyNTTs).
#
# C Prototype:
#   void ml_dsa_poly_ntt_mult_avx2(
#       const uint32_t *a,       // (rdi) Input polynomial A (in NTT domain)
#       const uint32_t *b,       // (rsi) Input polynomial B (in NTT domain)
#       uint32_t *out,           // (rdx) Output polynomial (result)
#   );
#
# Description:
#   Top-level routine for polynomial multiplication in ML-DSA,
#   using number-theoretic transform (NTT) methods. This function performs
#   multiplication of two polynomials in the NTT domain, making full use of
#   AVX2 vector instructions.
#   It assumes there are 256 coefficients.
#
#   out[i] = a[i] x b[i] mod Q
#
#   The function:
#     - Takes pointers to source polynomials (NTT domain) and destination buffer
#     - Performs element-wise modular (pointwise) multiplication in the NTT domain
#     - Applies Montgomery reduction for efficient modular arithmetic
#
# Inputs:
#   a   - First input polynomial, NTT domain
#   b   - Second input polynomial, NTT domain
#   out - Destination buffer for output coefficients
#
# Output:
#   - Output buffer 'out' contains the coefficient-wise modular product of
#     the input polynomials (still in NTT domain)
#
###############################################################################

.globl  ml_dsa_poly_ntt_mult_avx2
.type   ml_dsa_poly_ntt_mult_avx2,\@function,3
.align 32
ml_dsa_poly_ntt_mult_avx2:
.cfi_startproc
    endbranch
___
$code .= <<___ if ($win64);
    # Win64 ABI: save XMM6-XMM15 (caller-saved); 10 regs x 16 bytes = 160, +8 align = 168
    lea     -168(%rax), %rsp
    vmovdqu %xmm6,   0(%rsp)
    vmovdqu %xmm7,   16(%rsp)
    vmovdqu %xmm8,   32(%rsp)
    vmovdqu %xmm9,   48(%rsp)
    vmovdqu %xmm10,  64(%rsp)
    vmovdqu %xmm11,  80(%rsp)
    vmovdqu %xmm12,  96(%rsp)
    vmovdqu %xmm13,  112(%rsp)
    vmovdqu %xmm14,  128(%rsp)
    vmovdqu %xmm15,  144(%rsp)
___
$code .= <<___;
.Lntt_mult_body:
    vpbroadcastq ml_dsa_q_neg_inv(%rip), %ymm14
    vpbroadcastd ml_dsa_q(%rip), %ymm15
    xor %r10d, %r10d

.align 32
.Lmult_loop:
    # Load a and b into ymm registers
    vmovdqu (%rdi,%r10), %ymm0   # a[0:7]
    vmovdqu (%rsi,%r10), %ymm1   # b[0:7]

    # multiply this part of input data
___

    &multiply_mod_Q("%ymm0", "%ymm1", "%ymm0",  # A, B, out (AxB)
                    "%ymm8", "%ymm9", "%ymm10", # tmp
                    "%ymm14", "%ymm15", 0);     # qinv, q, bcast32

$code .= <<___;
    # store result to output
    vmovdqu %ymm0, (%rdx,%r10)

    # advance by 8 coefficients × 4 bytes = 32 bytes per iteration
    add \$8*4, %r10d
    cmp \$256*4, %r10d             # 256 coefficients total
    jb .Lmult_loop

    # clear YMM registers to prevent leakage of intermediate values
    vzeroall
___
$code .= <<___ if ($win64);
    vmovdqu 0(%rsp),   %xmm6
    vmovdqu 16(%rsp),  %xmm7
    vmovdqu 32(%rsp),  %xmm8
    vmovdqu 48(%rsp),  %xmm9
    vmovdqu 64(%rsp),  %xmm10
    vmovdqu 80(%rsp),  %xmm11
    vmovdqu 96(%rsp),  %xmm12
    vmovdqu 112(%rsp), %xmm13
    vmovdqu 128(%rsp), %xmm14
    vmovdqu 144(%rsp), %xmm15
    lea     (%rax), %rsp
___
$code .= <<___;
.Lntt_mult_epilogue:
    ret
.cfi_endproc
.size   ml_dsa_poly_ntt_mult_avx2, .-ml_dsa_poly_ntt_mult_avx2

###############################################################################
# ml_dsa_poly_ntt_avx2
#
# AVX2 implementation of FIPS 204, §8.3 Algorithm 35 (NTT).
#
# C Prototype:
#   void ml_dsa_poly_ntt_avx2(
#       uint32_t *p_coeffs // Pointer to coefficients (input: normal domain, output: NTT domain)
#   );
#
# Description:
#   Top-level implementation of the forward Number Theoretic
#   Transform (NTT) for ML-DSA polynomials. This function converts a polynomial
#   from its standard coefficient (normal) form to its NTT representation,
#   storing the result in-place in the provided coefficients array. The function
#   uses stage-specific "zeta" (twiddle factor) tables emitted in this file.
#
#   The function:
#     - Takes a buffer of polynomial coefficients in normal (standard) order
#     - Uses the embedded forward zeta tables for all twiddle-factor multiplications
#     - Processes the NTT in a breadth-first, layered fashion with AVX2 SIMD
#     - Overwrites the input buffer with its NTT-domain representation
#
# Inputs:
#   p_coeffs - Pointer to the coefficient array (will be overwritten in-place by the NTT result)
#
# Output:
#   - The 'p_coeffs' array is updated in-place with the corresponding NTT-domain representation.
###############################################################################
.globl  ml_dsa_poly_ntt_avx2
.type   ml_dsa_poly_ntt_avx2,\@function,1
.align 32
ml_dsa_poly_ntt_avx2:
.cfi_startproc
    endbranch
___
$code .= <<___ if ($win64);
    # Win64 ABI: save XMM6-XMM15 (caller-saved); 10 regs x 16 bytes = 160, +8 align = 168
    lea     -168(%rax), %rsp
    vmovdqu %xmm6,   0(%rsp)
    vmovdqu %xmm7,   16(%rsp)
    vmovdqu %xmm8,   32(%rsp)
    vmovdqu %xmm9,   48(%rsp)
    vmovdqu %xmm10,  64(%rsp)
    vmovdqu %xmm11,  80(%rsp)
    vmovdqu %xmm12,  96(%rsp)
    vmovdqu %xmm13,  112(%rsp)
    vmovdqu %xmm14,  128(%rsp)
    vmovdqu %xmm15,  144(%rsp)
___
$code .= <<___;
.Lntt_body:

    # load pointers to embedded forward zeta tables
    lea ml_dsa_zetas_forward(%rip), %r11

    # load constants
    vpbroadcastd ml_dsa_q(%rip), %ymm15     # 32-bit Q

    # ==============================================================
    # - level 0: offset = 128, step = 1, zeta indexes = 1
    # - level 1: offset = 64, step = 2, zeta indexes = 2, 3
    # - level 2: offset = 32, step = 4, zeta indexes = 4, 5, 6, 7
    # p_coeffs already in rdi
___

    &ntt_levels0to2(0*4);
    &ntt_levels0to2(8*4);
    &ntt_levels0to2(16*4);
    &ntt_levels0to2(24*4);

$code .= <<___;

    # ==============================================================
    # - level 3: offset = 16, step = 8
    #     zeta indexes = 8, 9, 10, 11, 12, 13, 14, 15
    # - level 4: offset = 8, step = 16
    #     zeta indexes = 16, 17, 18, ..., 30, 31
    # - level 5: offset = 4, step = 32
    #     zeta indexes = 32, 33, 34, ..., 62, 63
    # - level 6: offset = 2, step = 64
    #     zeta indexes = 64, 65, 66, ..., 126, 127
    # - level 7: offset = 1, step = 128
    #     zeta indexes = 128, 129, 130, ..., 254, 255
    # p_coeffs already in rdi
    lea ml_dsa_zetas_ntt5(%rip), %rsi
    lea ml_dsa_zetas_ntt6(%rip), %r10
___

    # arguments:    coeff,   l3,    l4,   l5,  l6,    l7,   ntt5,   ntt6
    &ntt_levels3to7(  0*4,  8*4, 16*4,   0,   0, 128*4, "%rsi", "%r10");
    &ntt_levels3to7( 64*4, 10*4, 20*4, 128, 128, 160*4, "%rsi", "%r10");
    &ntt_levels3to7(128*4, 12*4, 24*4, 256, 256, 192*4, "%rsi", "%r10");
    &ntt_levels3to7(192*4, 14*4, 28*4, 384, 384, 224*4, "%rsi", "%r10");

$code .= <<___;

    # Bias all 256 NTT coefficients by +8Q to guarantee non-negative values
    # for downstream unsigned vpmuludq in poly_ntt_mult_avx2.
    # Without per-butterfly +Q, outputs are in (-(N-1)Q, (N+1)Q) where N=7 levels,
    # i.e. (-7Q, 8Q). Adding 8Q maps the worst case (-7Q) to +Q > 0.
    vpslld  \$3, %ymm15, %ymm0       # ymm0 = 8Q  (ymm15 still holds Q from above)
    lea     (%rdi), %rsi             # %rsi is free here; ntt5 pointer no longer needed
    mov     \$32, %ecx               # 256 coefficients / 8 per YMM = 32 iterations
.Lntt_bias_loop:
    vmovdqu (%rsi), %ymm1
    vpaddd  %ymm0, %ymm1, %ymm1
    vmovdqu %ymm1, (%rsi)
    add     \$32, %rsi
    dec     %ecx
    jnz     .Lntt_bias_loop

    # clear YMM registers to prevent leakage of intermediate values
    vzeroall
___
$code .= <<___ if ($win64);
    vmovdqu 0(%rsp),   %xmm6
    vmovdqu 16(%rsp),  %xmm7
    vmovdqu 32(%rsp),  %xmm8
    vmovdqu 48(%rsp),  %xmm9
    vmovdqu 64(%rsp),  %xmm10
    vmovdqu 80(%rsp),  %xmm11
    vmovdqu 96(%rsp),  %xmm12
    vmovdqu 112(%rsp), %xmm13
    vmovdqu 128(%rsp), %xmm14
    vmovdqu 144(%rsp), %xmm15
    lea     (%rax), %rsp
___
$code .= <<___;
.Lntt_epilogue:
    ret
.cfi_endproc
.size   ml_dsa_poly_ntt_avx2, .-ml_dsa_poly_ntt_avx2

###############################################################################
# ml_dsa_poly_ntt_inverse_avx2
#
# AVX2 implementation of FIPS 204, §8.3 Algorithm 36 (NTT^{-1}).
#
# C Prototype:
#     void ml_dsa_poly_ntt_inverse_avx2(
#        uint32_t *p_coeffs // (rdi) Pointer to coefficients
#                           // input: NTT domain, output: normal domain, in-place
#     );
#
# Description:
#   Top-level implementation of the inverse Number Theoretic
#   Transform (INTT) for ML-DSA polynomial. This function converts a polynomial
#   from its NTT domain back to the standard coefficient (normal) domain,
#   storing the result in-place in the provided buffer. The required inverse zeta
#   (twiddle) factors are managed internally.
#
#   The function:
#     - Accepts a buffer of NTT-domain coefficients
#     - Overwrites the input buffer with the result in the normal (coefficient) domain
#
# Inputs:
#   p_coeffs - Pointer to the polynomial coefficient array (in-place transform)
#
# Output:
#   - The 'p_coeffs' array is updated in-place to contain the standard domain polynomial.
#   - Uses 'zetas_inverse', 'ml_dsa_zetas_intt1', and 'ml_dsa_zetas_intt2' tables
###############################################################################
.globl  ml_dsa_poly_ntt_inverse_avx2
.type   ml_dsa_poly_ntt_inverse_avx2,\@function,1
.align 32
ml_dsa_poly_ntt_inverse_avx2:
.cfi_startproc
    endbranch
___
$code .= <<___ if ($win64);
    # Win64 ABI: save XMM6-XMM15 (caller-saved); 10 regs x 16 bytes = 160, +8 align = 168
    lea     -168(%rax), %rsp
    vmovdqu %xmm6,   0(%rsp)
    vmovdqu %xmm7,   16(%rsp)
    vmovdqu %xmm8,   32(%rsp)
    vmovdqu %xmm9,   48(%rsp)
    vmovdqu %xmm10,  64(%rsp)
    vmovdqu %xmm11,  80(%rsp)
    vmovdqu %xmm12,  96(%rsp)
    vmovdqu %xmm13,  112(%rsp)
    vmovdqu %xmm14,  128(%rsp)
    vmovdqu %xmm15,  144(%rsp)
___
$code .= <<___;
.Lintt_body:
    lea zetas_inverse(%rip), %r11
    # load pointers to preformatted INTT level-1 and level-2 zeta tables
    lea ml_dsa_zetas_intt1(%rip), %rsi
    lea ml_dsa_zetas_intt2(%rip), %r10

    vpbroadcastd ml_dsa_q(%rip), %ymm15

    # ==============================================================
    # - level 0: offset = 1, step = 128
    #     zeta indexes (original table) = 255, 254, 253, ... 129, 128
    #     zeta indexes (new table) = 0, 1, 2, .. 127
    # - level 1: offset = 2, step = 64
    #     zeta indexes (original table) = 127, 126, 125, ... 65, 64
    #     zeta indexes (new table) = 128, 129, .. 191
    # - level 2: offset = 4, step = 32
    #     zeta indexes (original table) = 63, 62, 61, ... 33, 32
    #     zeta indexes (new table) = 192, 193, 194, ... 223
    # - level 3: offset = 8, step = 16
    #     zeta indexes (original table) = 31, 30, 29, ... 17, 16
    #     zeta indexes (new table) = 224, 225, 226, ... 239
    # - level 4: offset = 16, step = 8
    #     zeta indexes (original table) = 15, 14, 13, ..., 9, 8
    #     zeta indexes (new table) = 240, 241, 242, ... 247

___

    #  arguments:    coeff,   l0,    l1,  l2,    l3,    l4,      intt1,   intt2
    &intt_levels0to4(0*4,    0*4,   0,   0,   224*4, 240*4, "%rsi", "%r10");
    &intt_levels0to4(64*4,  32*4, 128, 128,  228*4, 242*4, "%rsi", "%r10");
    &intt_levels0to4(128*4, 64*4, 256, 256,  232*4, 244*4, "%rsi", "%r10");
    &intt_levels0to4(192*4, 96*4, 384, 384,  236*4, 246*4, "%rsi", "%r10");

$code .= <<___;

    # ==============================================================
    # - level 5: offset = 32, step = 4
    #   zeta indexes (original table) = 7, 6, 5, 4
    #   zeta indexes (new table) = 248, 249, 250, 251
    # - level 6: offset = 64, step = 2
    #   zeta indexes (original table) = 3, 2
    #   zeta indexes (new table) = 252, 253
    # - level 7: offset = 128, step = 1
    #   zeta indexes (original table) = 1
    #   zeta indexes (new table) = 254
___
    &intt_levels5to7(0*4);
    &intt_levels5to7(8*4);
    &intt_levels5to7(16*4);
    &intt_levels5to7(24*4);
    $code .= <<___;

    # clear YMM registers to prevent leakage of intermediate values
    vzeroall
___
$code .= <<___ if ($win64);
    vmovdqu 0(%rsp),   %xmm6
    vmovdqu 16(%rsp),  %xmm7
    vmovdqu 32(%rsp),  %xmm8
    vmovdqu 48(%rsp),  %xmm9
    vmovdqu 64(%rsp),  %xmm10
    vmovdqu 80(%rsp),  %xmm11
    vmovdqu 96(%rsp),  %xmm12
    vmovdqu 112(%rsp), %xmm13
    vmovdqu 128(%rsp), %xmm14
    vmovdqu 144(%rsp), %xmm15
    lea     (%rax), %rsp
___
$code .= <<___;
.Lintt_epilogue:
    ret
.cfi_endproc
.size   ml_dsa_poly_ntt_inverse_avx2, .-ml_dsa_poly_ntt_inverse_avx2
___

# Windows SEH exception handler and unwind data
if ($win64) {
my $context = "%r8";
my $disp    = "%r9";

$code .= <<___;
.extern __imp_RtlVirtualUnwind
.type   ntt_se_handler,\@abi-omnipotent
.align  16
ntt_se_handler:
    push    %rsi
    push    %rdi
    push    %rbx
    push    %rbp
    push    %r12
    push    %r13
    push    %r14
    push    %r15
    pushfq
    sub     \$64, %rsp

    mov     120($context), %rax     # context->Rax = original %rsp (saved by xlate preamble)
    mov     248($context), %rbx     # context->Rip

    mov     8($disp), %rsi          # disp->ImageBase
    mov     56($disp), %r11         # disp->HandlerData

    mov     0(%r11), %r10d          # HandlerData[0]: body label (rva)
    lea     (%rsi,%r10), %r10
    cmp     %r10, %rbx              # Rip < body?
    jb      .Lntt_in_prologue

    mov     4(%r11), %r10d          # HandlerData[1]: epilogue label (rva)
    lea     (%rsi,%r10), %r10
    cmp     %r10, %rbx              # Rip >= epilogue?
    jae     .Lntt_in_prologue

    # In function body: XMM6-XMM15 are saved at 0..144(new_rsp).
    # context->Rsp = new_rsp = rax - 168
    mov     152($context), %rsi     # context->Rsp = new_rsp (address of XMM saves)
    lea     512($context), %rdi     # &context->Xmm6
    mov     \$20, %ecx              # 10 XMMs * 2 qwords = 20 qwords
    .long   0xa548f3fc              # cld; rep movsq

.Lntt_in_prologue:
    # Restore rdi and rsi saved by xlate preamble in shadow space
    mov     8(%rax), %rcx
    mov     16(%rax), %rdx
    mov     %rcx, 176($context)     # context->Rdi
    mov     %rdx, 168($context)     # context->Rsi
    mov     %rax, 152($context)     # context->Rsp = original %rsp

    mov     40($disp), %rdi         # disp->ContextRecord
    mov     $context, %rsi
    mov     \$154, %ecx             # sizeof(CONTEXT)/8
    .long   0xa548f3fc              # cld; rep movsq

    mov     $disp, %rsi
    xor     %rcx, %rcx              # UNW_FLAG_NHANDLER
    mov     8(%rsi), %rdx           # disp->ImageBase
    mov     0(%rsi), %r8            # disp->ControlPc
    mov     16(%rsi), %r9           # disp->FunctionEntry
    mov     40(%rsi), %r10          # disp->ContextRecord
    lea     56(%rsi), %r11          # &disp->HandlerData
    lea     24(%rsi), %r12          # &disp->EstablisherFrame
    mov     %r10, 32(%rsp)
    mov     %r11, 40(%rsp)
    mov     %r12, 48(%rsp)
    mov     %rcx, 56(%rsp)
    call    *__imp_RtlVirtualUnwind(%rip)

    mov     \$1, %eax               # ExceptionContinueSearch
    add     \$64, %rsp
    popfq
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbp
    pop     %rbx
    pop     %rdi
    pop     %rsi
    ret
.size   ntt_se_handler,.-ntt_se_handler

.section    .pdata
.align  4
    .rva    .LSEH_begin_ml_dsa_poly_ntt_mult_avx2
    .rva    .LSEH_end_ml_dsa_poly_ntt_mult_avx2
    .rva    .LSEH_info_ml_dsa_poly_ntt_mult_avx2
    .rva    .LSEH_begin_ml_dsa_poly_ntt_avx2
    .rva    .LSEH_end_ml_dsa_poly_ntt_avx2
    .rva    .LSEH_info_ml_dsa_poly_ntt_avx2
    .rva    .LSEH_begin_ml_dsa_poly_ntt_inverse_avx2
    .rva    .LSEH_end_ml_dsa_poly_ntt_inverse_avx2
    .rva    .LSEH_info_ml_dsa_poly_ntt_inverse_avx2

.section    .xdata
.align  8
.LSEH_info_ml_dsa_poly_ntt_mult_avx2:
    .byte   9,0,0,0
    .rva    ntt_se_handler
    .rva    .Lntt_mult_body,.Lntt_mult_epilogue
.LSEH_info_ml_dsa_poly_ntt_avx2:
    .byte   9,0,0,0
    .rva    ntt_se_handler
    .rva    .Lntt_body,.Lntt_epilogue
.LSEH_info_ml_dsa_poly_ntt_inverse_avx2:
    .byte   9,0,0,0
    .rva    ntt_se_handler
    .rva    .Lintt_body,.Lintt_epilogue
___
}


print $code;
close STDOUT or die "error closing STDOUT: $!";
