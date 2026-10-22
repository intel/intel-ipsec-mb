#! /usr/bin/env perl
#
# Copyright (c) 2026, Intel Corporation. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

###############################################################################
# ML-DSA AVX2 Polynomial Arithmetic Routines
#
# Description:
#   AVX2 implementations of the ML-DSA polynomial operations used by signing
#   and verification (FIPS 204): HighBits, LowBits, Decompose and MakeHint
#   for both gamma2 values, modular addition and subtraction, infinity norm
#   checks (including a fused low - c*s2 check), hint counting and w1/z bit
#   packing.
#
# Notes:
#   - Each routine processes 256 32-bit coefficients, 8 per loop iteration,
#     with a fixed trip count and unaligned loads/stores
#   - %r10 holds the byte offset into the polynomial
#   - Only YMM0-YMM5 are used (volatile on SysV and Win64); they are cleared
#     before returning
#   - Must be kept functionally synchronized with the base implementations
#     in ml_dsa_poly.c
###############################################################################

$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64 = 0;
$win64 = 1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$avx2 = 0;

$0 =~ m/(.*[\/\\])[^\/\\]+$/;
$dir = $1;
($xlate = "${dir}x86_64-xlate.pl" and -f $xlate)
    or ($xlate = "${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate)
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
    or die "AVX2 support is required in the assembler to build the ML-DSA polynomial kernels.\nMinimum assembler versions: GNU as 2.22, clang 3.3, nasm 2.10.\n";

open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT = *OUT;

my $code = '';

###############################################################################
# reduce_once
#
# Description:
#   Maps 8 coefficients from [0, 2Q) to [0, Q). The unsigned minimum selects
#   x when x - Q wraps around.
#
# Parameters:
#   x   - YMM with input/output coefficients
#   q   - YMM loaded with Q
#   tmp - scratch YMM
#
# Side effects:
#   Clobbers q, tmp
###############################################################################
sub reduce_once {
    my ($x, $q, $tmp) = @_;

    $code .= <<___;
    vpbroadcastd ml_dsa_q(%rip), $q
    vpsubd  $q, $x, $tmp
    vpminud $tmp, $x, $x
___
}

###############################################################################
# high_bits
#
# Description:
#   Computes HighBits(r) of 8 coefficients for gamma2 = (Q-1)/divisor
#   (FIPS 204, Algorithm 36) without division:
#     h = ((((r + 127) >> 7) * mul + round) >> shift)
#   The top interval, including the r = Q-1 special case, wraps to 0: by
#   masking with 15 for /32, or by zeroing values above 43 for /88.
#
# Parameters:
#   divisor - 32 or 88
#   r       - YMM with input coefficients in [0, Q); preserved
#   h       - YMM for the output high parts
#   tmp0    - scratch YMM
#   tmp1    - scratch YMM (used for /88 only)
#
# Side effects:
#   Clobbers tmp0, tmp1
###############################################################################
sub high_bits {
    my ($divisor, $r, $h, $tmp0, $tmp1) = @_;
    my $shift = ($divisor == 32) ? 22 : 24;

    $code .= <<___;
    vpbroadcastd ml_dsa_hb_add(%rip), $tmp0
    vpaddd  $tmp0, $r, $h
    vpsrld  \$7, $h, $h
    vpbroadcastd ml_dsa_hb_mul_${divisor}(%rip), $tmp0
    vpmulld $tmp0, $h, $h
    vpbroadcastd ml_dsa_hb_round_${divisor}(%rip), $tmp0
    vpaddd  $tmp0, $h, $h
    vpsrld  \$$shift, $h, $h
___
    if ($divisor == 32) {
        $code .= <<___;
    vpbroadcastd ml_dsa_hb_mask_32(%rip), $tmp0
    vpand   $tmp0, $h, $h
___
    } else {
        $code .= <<___;
    vpbroadcastd ml_dsa_hb_max_88(%rip), $tmp0
    vpcmpgtd $tmp0, $h, $tmp1
    vpandn  $h, $tmp1, $h
___
    }
}

###############################################################################
# low_bits
#
# Description:
#   Computes the signed LowBits(r) of 8 coefficients from r and HighBits(r)
#   (FIPS 204, Algorithm 36): l = r - h * 2*gamma2, minus Q if l > (Q-1)/2.
#
# Parameters:
#   divisor - 32 or 88
#   r       - YMM with input coefficients in [0, Q); replaced by low parts
#   h       - YMM with high parts from high_bits; preserved
#   tmp0    - scratch YMM
#   tmp1    - scratch YMM
#
# Side effects:
#   Clobbers tmp0, tmp1
###############################################################################
sub low_bits {
    my ($divisor, $r, $h, $tmp0, $tmp1) = @_;

    $code .= <<___;
    vpbroadcastd ml_dsa_2gamma2_${divisor}(%rip), $tmp0
    vpmulld $tmp0, $h, $tmp0
    vpsubd  $tmp0, $r, $r
    vpbroadcastd ml_dsa_q_half(%rip), $tmp0
    vpcmpgtd $tmp0, $r, $tmp1
    vpbroadcastd ml_dsa_q(%rip), $tmp0
    vpand   $tmp0, $tmp1, $tmp1
    vpsubd  $tmp1, $r, $r
___
}

$code .= <<___;
.text

###############################################################################
# ml_dsa_poly_add_avx2
#
# Coefficient-wise addition modulo Q (FIPS 204, Algorithm 7).
#
# C Prototype:
#   void ml_dsa_poly_add_avx2(
#       const POLY *lhs,  // (rdi) First input polynomial
#       const POLY *rhs,  // (rsi) Second input polynomial
#       POLY *out         // (rdx) Output polynomial
#   );
#
# Description:
#   lhs + rhs is in [0, 2Q), so a single reduction gives the result.
#
# Inputs:
#   lhs, rhs - coefficients in [0, Q)
#
# Output:
#   out - lhs + rhs mod Q, in [0, Q); may alias either input
###############################################################################
.align 32
.globl  ml_dsa_poly_add_avx2
.type   ml_dsa_poly_add_avx2,\@function,3
ml_dsa_poly_add_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d

.align 32
.Ladd_loop:
    vmovdqu (%rdi,%r10), %ymm0
    vpaddd  (%rsi,%r10), %ymm0, %ymm0
___
    reduce_once("%ymm0", "%ymm4", "%ymm5");
$code .= <<___;
    vmovdqu %ymm0, (%rdx,%r10)

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Ladd_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_add_avx2, .-ml_dsa_poly_add_avx2

###############################################################################
# ml_dsa_poly_sub_avx2
#
# Coefficient-wise subtraction modulo Q (FIPS 204, Algorithm 7).
#
# C Prototype:
#   void ml_dsa_poly_sub_avx2(
#       const POLY *lhs,  // (rdi) Polynomial to subtract from
#       const POLY *rhs,  // (rsi) Polynomial to subtract
#       POLY *out         // (rdx) Output polynomial
#   );
#
# Description:
#   lhs - rhs + Q is in (0, 2Q), so a single reduction gives the result.
#
# Inputs:
#   lhs, rhs - coefficients in [0, Q)
#
# Output:
#   out - lhs - rhs mod Q, in [0, Q); may alias either input
###############################################################################
.align 32
.globl  ml_dsa_poly_sub_avx2
.type   ml_dsa_poly_sub_avx2,\@function,3
ml_dsa_poly_sub_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d

.align 32
.Lsub_loop:
    vmovdqu (%rdi,%r10), %ymm0
    vpsubd  (%rsi,%r10), %ymm0, %ymm0
    vpbroadcastd ml_dsa_q(%rip), %ymm4
    vpaddd  %ymm4, %ymm0, %ymm0
___
    reduce_once("%ymm0", "%ymm4", "%ymm5");
$code .= <<___;
    vmovdqu %ymm0, (%rdx,%r10)

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Lsub_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_sub_avx2, .-ml_dsa_poly_sub_avx2

###############################################################################
# ml_dsa_poly_chknorm_avx2
#
# Infinity norm check of a canonical polynomial (FIPS 204, Algorithm 7).
#
# C Prototype:
#   uint32_t ml_dsa_poly_chknorm_avx2(
#       const POLY *p,   // (rdi) Input polynomial
#       uint32_t bound   // (esi) Infinity norm bound
#   );
#
# Description:
#   |x| is computed as min(x, Q - x). The whole polynomial is always scanned.
#
# Inputs:
#   p     - coefficients in [0, Q)
#   bound - norm bound
#
# Output:
#   eax - 1 if any |x| >= bound, 0 otherwise
###############################################################################
.align 32
.globl  ml_dsa_poly_chknorm_avx2
.type   ml_dsa_poly_chknorm_avx2,\@function,2
ml_dsa_poly_chknorm_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d
    vmovd   %esi, %xmm2
    vpbroadcastd %xmm2, %ymm2           # ymm2 = bound
    vpxor   %ymm3, %ymm3, %ymm3         # ymm3 = accumulated failures

.align 32
.Lchknorm_loop:
    vmovdqu (%rdi,%r10), %ymm0
    vpbroadcastd ml_dsa_q(%rip), %ymm4
    vpsubd  %ymm0, %ymm4, %ymm1
    vpminud %ymm1, %ymm0, %ymm0
    # |x| >= bound <=> max(|x|, bound) == |x|
    vpmaxud %ymm2, %ymm0, %ymm1
    vpcmpeqd %ymm0, %ymm1, %ymm1
    vpor    %ymm1, %ymm3, %ymm3

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Lchknorm_loop

    xor     %eax, %eax
    vptest  %ymm3, %ymm3
    setnz   %al

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_chknorm_avx2, .-ml_dsa_poly_chknorm_avx2

###############################################################################
# ml_dsa_poly_chknorm_signed_avx2
#
# Infinity norm check of a signed polynomial (FIPS 204, Algorithm 7).
#
# C Prototype:
#   uint32_t ml_dsa_poly_chknorm_signed_avx2(
#       const POLY *p,   // (rdi) Input polynomial
#       uint32_t bound   // (esi) Infinity norm bound
#   );
#
# Description:
#   |x| is computed with vpabsd and compared unsigned, so abs(INT32_MIN)
#   = 2^31 is handled. The whole polynomial is always scanned.
#
# Inputs:
#   p     - signed 32-bit coefficients
#   bound - norm bound
#
# Output:
#   eax - 1 if any |x| >= bound, 0 otherwise
###############################################################################
.align 32
.globl  ml_dsa_poly_chknorm_signed_avx2
.type   ml_dsa_poly_chknorm_signed_avx2,\@function,2
ml_dsa_poly_chknorm_signed_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d
    vmovd   %esi, %xmm2
    vpbroadcastd %xmm2, %ymm2           # ymm2 = bound
    vpxor   %ymm3, %ymm3, %ymm3         # ymm3 = accumulated failures

.align 32
.Lchknorm_signed_loop:
    vmovdqu (%rdi,%r10), %ymm0
    vpabsd  %ymm0, %ymm0
    # |x| >= bound <=> max(|x|, bound) == |x|
    vpmaxud %ymm2, %ymm0, %ymm1
    vpcmpeqd %ymm0, %ymm1, %ymm1
    vpor    %ymm1, %ymm3, %ymm3

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Lchknorm_signed_loop

    xor     %eax, %eax
    vptest  %ymm3, %ymm3
    setnz   %al

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_chknorm_signed_avx2, .-ml_dsa_poly_chknorm_signed_avx2

###############################################################################
# ml_dsa_poly_sub_chknorm_avx2
#
# Infinity norm check of low - c*s2 (FIPS 204, Algorithm 7).
#
# C Prototype:
#   uint32_t ml_dsa_poly_sub_chknorm_avx2(
#       const POLY *low,  // (rdi) Signed low parts of w
#       const POLY *cs2,  // (rsi) c*s2 polynomial
#       uint32_t bound    // (edx) Infinity norm bound
#   );
#
# Description:
#   cs2 is centered to (-(Q-1)/2, (Q-1)/2] before the subtraction, as modular
#   subtraction is incorrect for the signed low parts. |centered(cs2)| <= beta
#   during signing, so the difference fits in 32 bits. The whole polynomial
#   is always scanned and neither input is modified.
#
# Inputs:
#   low   - signed 32-bit coefficients
#   cs2   - coefficients in [0, Q)
#   bound - norm bound
#
# Output:
#   eax - 1 if any |low - centered(cs2)| >= bound, 0 otherwise
###############################################################################
.align 32
.globl  ml_dsa_poly_sub_chknorm_avx2
.type   ml_dsa_poly_sub_chknorm_avx2,\@function,3
ml_dsa_poly_sub_chknorm_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d
    vmovd   %edx, %xmm2
    vpbroadcastd %xmm2, %ymm2           # ymm2 = bound
    vpxor   %ymm3, %ymm3, %ymm3         # ymm3 = accumulated failures
    vpbroadcastd ml_dsa_q(%rip), %ymm4
    vpbroadcastd ml_dsa_q_half(%rip), %ymm5

.align 32
.Lsub_chknorm_loop:
    vmovdqu (%rsi,%r10), %ymm0
    vpcmpgtd %ymm5, %ymm0, %ymm1
    vpand   %ymm4, %ymm1, %ymm1
    vpsubd  %ymm1, %ymm0, %ymm0         # ymm0 = centered(cs2)
    vmovdqu (%rdi,%r10), %ymm1
    vpsubd  %ymm0, %ymm1, %ymm0
    vpabsd  %ymm0, %ymm0
    # |x| >= bound <=> max(|x|, bound) == |x|
    vpmaxud %ymm2, %ymm0, %ymm1
    vpcmpeqd %ymm0, %ymm1, %ymm1
    vpor    %ymm1, %ymm3, %ymm3

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Lsub_chknorm_loop

    xor     %eax, %eax
    vptest  %ymm3, %ymm3
    setnz   %al

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_sub_chknorm_avx2, .-ml_dsa_poly_sub_chknorm_avx2

###############################################################################
# ml_dsa_poly_count_ones_avx2
#
# Hint count for the omega rejection check (FIPS 204, Algorithm 7).
#
# C Prototype:
#   uint32_t ml_dsa_poly_count_ones_avx2(
#       const POLY *p    // (rdi) Hint polynomial
#   );
#
# Description:
#   Sums the coefficients into 8 lanes, then reduces horizontally.
#
# Inputs:
#   p - coefficients, each 0 or 1
#
# Output:
#   eax - number of 1 coefficients, in [0, 256]
###############################################################################
.align 32
.globl  ml_dsa_poly_count_ones_avx2
.type   ml_dsa_poly_count_ones_avx2,\@function,1
ml_dsa_poly_count_ones_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d
    vpxor   %ymm0, %ymm0, %ymm0

.align 32
.Lcount_ones_loop:
    vpaddd  (%rdi,%r10), %ymm0, %ymm0

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Lcount_ones_loop

    vextracti128 \$1, %ymm0, %xmm1
    vpaddd  %xmm1, %xmm0, %xmm0
    vphaddd %xmm0, %xmm0, %xmm0
    vphaddd %xmm0, %xmm0, %xmm0
    vmovd   %xmm0, %eax

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_count_ones_avx2, .-ml_dsa_poly_count_ones_avx2
___

###############################################################################
# Rounding routines, generated for gamma2 = (Q-1)/32 (ML-DSA-65/87) and
# gamma2 = (Q-1)/88 (ML-DSA-44). The C initializer selects one set per
# context, so there is no runtime gamma2 branch.
###############################################################################
for my $d (32, 88) {
    my $hmax = ($d == 32) ? 15 : 43;

$code .= <<___;

###############################################################################
# ml_dsa_poly_high_bits_${d}_avx2
#
# HighBits with gamma2 = (Q-1)/$d (FIPS 204, Algorithm 37).
#
# C Prototype:
#   void ml_dsa_poly_high_bits_${d}_avx2(
#       const POLY *in,   // (rdi) Input polynomial
#       POLY *out         // (rsi) Output polynomial
#   );
#
# Inputs:
#   in - coefficients in [0, Q)
#
# Output:
#   out - high parts, in [0, $hmax]; may alias in
###############################################################################
.align 32
.globl  ml_dsa_poly_high_bits_${d}_avx2
.type   ml_dsa_poly_high_bits_${d}_avx2,\@function,2
ml_dsa_poly_high_bits_${d}_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d

.align 32
.Lhigh_bits_${d}_loop:
    vmovdqu (%rdi,%r10), %ymm0
___
    high_bits($d, "%ymm0", "%ymm1", "%ymm4", "%ymm5");
$code .= <<___;
    vmovdqu %ymm1, (%rsi,%r10)

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Lhigh_bits_${d}_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_high_bits_${d}_avx2, .-ml_dsa_poly_high_bits_${d}_avx2

###############################################################################
# ml_dsa_poly_low_bits_${d}_avx2
#
# LowBits with gamma2 = (Q-1)/$d (FIPS 204, Algorithm 38).
#
# C Prototype:
#   void ml_dsa_poly_low_bits_${d}_avx2(
#       const POLY *in,   // (rdi) Input polynomial
#       POLY *out         // (rsi) Output polynomial
#   );
#
# Inputs:
#   in - coefficients in [0, Q)
#
# Output:
#   out - signed low parts; may alias in
###############################################################################
.align 32
.globl  ml_dsa_poly_low_bits_${d}_avx2
.type   ml_dsa_poly_low_bits_${d}_avx2,\@function,2
ml_dsa_poly_low_bits_${d}_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d

.align 32
.Llow_bits_${d}_loop:
    vmovdqu (%rdi,%r10), %ymm0
___
    high_bits($d, "%ymm0", "%ymm1", "%ymm4", "%ymm5");
    low_bits($d, "%ymm0", "%ymm1", "%ymm4", "%ymm5");
$code .= <<___;
    vmovdqu %ymm0, (%rsi,%r10)

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Llow_bits_${d}_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_low_bits_${d}_avx2, .-ml_dsa_poly_low_bits_${d}_avx2

###############################################################################
# ml_dsa_poly_decompose_${d}_avx2
#
# Decompose with gamma2 = (Q-1)/$d (FIPS 204, Algorithm 36).
#
# C Prototype:
#   void ml_dsa_poly_decompose_${d}_avx2(
#       const POLY *in,   // (rdi) Input polynomial
#       POLY *high,       // (rsi) Output high parts
#       POLY *low         // (rdx) Output low parts
#   );
#
# Inputs:
#   in - coefficients in [0, Q)
#
# Output:
#   high - high parts, in [0, $hmax]
#   low  - signed low parts
#   high and low must be distinct; either may alias in
###############################################################################
.align 32
.globl  ml_dsa_poly_decompose_${d}_avx2
.type   ml_dsa_poly_decompose_${d}_avx2,\@function,3
ml_dsa_poly_decompose_${d}_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d

.align 32
.Ldecompose_${d}_loop:
    vmovdqu (%rdi,%r10), %ymm0
___
    high_bits($d, "%ymm0", "%ymm1", "%ymm4", "%ymm5");
    low_bits($d, "%ymm0", "%ymm1", "%ymm4", "%ymm5");
$code .= <<___;
    vmovdqu %ymm1, (%rsi,%r10)
    vmovdqu %ymm0, (%rdx,%r10)

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Ldecompose_${d}_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_decompose_${d}_avx2, .-ml_dsa_poly_decompose_${d}_avx2

###############################################################################
# ml_dsa_poly_make_hint_${d}_avx2
#
# MakeHint with gamma2 = (Q-1)/$d (FIPS 204, Algorithms 7 and 39).
#
# C Prototype:
#   void ml_dsa_poly_make_hint_${d}_avx2(
#       const POLY *ct0,  // (rdi) c*t0
#       const POLY *cs2,  // (rsi) c*s2
#       const POLY *w,    // (rdx) w
#       POLY *out         // (rcx) Output hint polynomial
#   );
#
# Description:
#   out = [HighBits(w - cs2) != HighBits(w - cs2 + ct0)]
#
# Inputs:
#   ct0, cs2, w - coefficients in [0, Q)
#
# Output:
#   out - hints, each 0 or 1
###############################################################################
.align 32
.globl  ml_dsa_poly_make_hint_${d}_avx2
.type   ml_dsa_poly_make_hint_${d}_avx2,\@function,4
ml_dsa_poly_make_hint_${d}_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d

.align 32
.Lmake_hint_${d}_loop:
    vmovdqu (%rdx,%r10), %ymm0
    vpsubd  (%rsi,%r10), %ymm0, %ymm0
    vpbroadcastd ml_dsa_q(%rip), %ymm4
    vpaddd  %ymm4, %ymm0, %ymm0
___
    reduce_once("%ymm0", "%ymm4", "%ymm5");
    high_bits($d, "%ymm0", "%ymm1", "%ymm4", "%ymm5");
$code .= <<___;
    vmovdqa %ymm1, %ymm2                # ymm2 = HighBits(w - cs2)
    vpaddd  (%rdi,%r10), %ymm0, %ymm0
___
    reduce_once("%ymm0", "%ymm4", "%ymm5");
    high_bits($d, "%ymm0", "%ymm1", "%ymm4", "%ymm5");
$code .= <<___;
    vpcmpeqd %ymm1, %ymm2, %ymm1
    vpbroadcastd ml_dsa_one(%rip), %ymm4
    vpandn  %ymm4, %ymm1, %ymm1
    vmovdqu %ymm1, (%rcx,%r10)

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Lmake_hint_${d}_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_make_hint_${d}_avx2, .-ml_dsa_poly_make_hint_${d}_avx2
___
}

$code .= <<___;

###############################################################################
# ml_dsa_poly_pack_w1_4_avx2
#
# SimpleBitPack(w1, 15) for ML-DSA-65/87 (FIPS 204, Algorithm 16).
#
# C Prototype:
#   void ml_dsa_poly_pack_w1_4_avx2(
#       const POLY *p,    // (rdi) Input polynomial
#       uint8_t *out      // (rsi) Output buffer
#   );
#
# Description:
#   Each pair of coefficients is merged into one byte within its qword. The
#   shuffle gathers 2 bytes per 128-bit lane, and the lanes are combined to
#   store 4 bytes per iteration.
#
# Inputs:
#   p - coefficients in [0, 15]
#
# Output:
#   out - exactly 128 bytes written
###############################################################################
.align 32
.globl  ml_dsa_poly_pack_w1_4_avx2
.type   ml_dsa_poly_pack_w1_4_avx2,\@function,2
ml_dsa_poly_pack_w1_4_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d
    vmovdqa ml_dsa_pack_w1_4_shuf(%rip), %ymm2

.align 32
.Lpack_w1_4_loop:
    vmovdqu (%rdi,%r10), %ymm0
    vpsrlq  \$28, %ymm0, %ymm1
    vpor    %ymm1, %ymm0, %ymm0
    vpshufb %ymm2, %ymm0, %ymm0
    vextracti128 \$1, %ymm0, %xmm1
    vpunpcklwd %xmm1, %xmm0, %xmm0
    vmovd   %xmm0, (%rsi)
    add     \$4, %rsi

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Lpack_w1_4_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_pack_w1_4_avx2, .-ml_dsa_poly_pack_w1_4_avx2

###############################################################################
# ml_dsa_poly_pack_z_20_avx2
#
# BitPack(z, gamma1 - 1, gamma1) for ML-DSA-65/87 (FIPS 204, Algorithm 17).
#
# C Prototype:
#   void ml_dsa_poly_pack_z_20_avx2(
#       const POLY *p,    // (rdi) Input polynomial
#       uint8_t *out      // (rsi) Output buffer
#   );
#
# Description:
#   t = (gamma1 - z) mod Q is in [0, 2^20). Each pair is combined as
#   t_even | (t_odd << 20), giving 5 bytes per qword; the shuffle gathers
#   10 bytes per 128-bit lane. 8 + 2 byte stores avoid writing past the
#   end of the output buffer.
#
# Inputs:
#   p - z mod Q, with z in [-(gamma1 - 1), gamma1]
#
# Output:
#   out - exactly 640 bytes written
###############################################################################
.align 32
.globl  ml_dsa_poly_pack_z_20_avx2
.type   ml_dsa_poly_pack_z_20_avx2,\@function,2
ml_dsa_poly_pack_z_20_avx2:
.cfi_startproc
    endbranch
    xor     %r10d, %r10d
    vmovdqa ml_dsa_pack_z_20_shuf(%rip), %ymm2
    vpbroadcastd ml_dsa_gamma1(%rip), %ymm3

.align 32
.Lpack_z_20_loop:
    vpsubd  (%rdi,%r10), %ymm3, %ymm0
    vpbroadcastd ml_dsa_q(%rip), %ymm4
    vpaddd  %ymm4, %ymm0, %ymm0
___
    reduce_once("%ymm0", "%ymm4", "%ymm5");
$code .= <<___;
    vpsllq  \$32, %ymm0, %ymm1
    vpsrlq  \$32, %ymm1, %ymm1          # ymm1 = t_even
    vpsrlq  \$32, %ymm0, %ymm0
    vpsllq  \$20, %ymm0, %ymm0          # ymm0 = t_odd << 20
    vpor    %ymm1, %ymm0, %ymm0
    vpshufb %ymm2, %ymm0, %ymm0
    vextracti128 \$1, %ymm0, %xmm1
    vmovq   %xmm0, (%rsi)
    vpextrw \$4, %xmm0, %eax
    mov     %ax, 8(%rsi)
    vmovq   %xmm1, 10(%rsi)
    vpextrw \$4, %xmm1, %eax
    mov     %ax, 18(%rsi)
    add     \$20, %rsi

    add     \$8*4, %r10
    cmp     \$256*4, %r10
    jb      .Lpack_z_20_loop

    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vzeroupper
    ret
.cfi_endproc
.size   ml_dsa_poly_pack_z_20_avx2, .-ml_dsa_poly_pack_z_20_avx2

.section    .rodata

# Modulus Q = 2^23 - 2^13 + 1 (FIPS 204, Table 1)
.align 4
ml_dsa_q:
    .long 8380417

# (Q-1)/2; low parts above this are reduced by Q
.align 4
ml_dsa_q_half:
    .long 4190208

# gamma1 = 2^19 for ML-DSA-65/87 (FIPS 204, Table 1)
.align 4
ml_dsa_gamma1:
    .long 524288

.align 4
ml_dsa_one:
    .long 1

# HighBits constants (see high_bits)
.align 4
ml_dsa_hb_add:
    .long 127
.align 4
ml_dsa_hb_mul_32:
    .long 1025
.align 4
ml_dsa_hb_round_32:
    .long 2097152
.align 4
ml_dsa_hb_mask_32:
    .long 15
.align 4
ml_dsa_hb_mul_88:
    .long 11275
.align 4
ml_dsa_hb_round_88:
    .long 8388608
.align 4
ml_dsa_hb_max_88:
    .long 43

# 2*gamma2 for gamma2 = (Q-1)/32 and (Q-1)/88
.align 4
ml_dsa_2gamma2_32:
    .long 523776
.align 4
ml_dsa_2gamma2_88:
    .long 190464

# vpshufb masks, same for both 128-bit lanes; 0x80 zeroes the byte
.align 32
ml_dsa_pack_w1_4_shuf:
    .byte 0,8,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80
    .byte 0,8,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80
.align 32
ml_dsa_pack_z_20_shuf:
    .byte 0,1,2,3,4,8,9,10,11,12,0x80,0x80,0x80,0x80,0x80,0x80
    .byte 0,1,2,3,4,8,9,10,11,12,0x80,0x80,0x80,0x80,0x80,0x80

.section    .note.GNU-stack,"",\@progbits
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
