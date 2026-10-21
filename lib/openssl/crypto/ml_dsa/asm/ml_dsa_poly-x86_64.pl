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
#   and verification (FIPS 204): modular addition and subtraction, infinity
#   norm checks and hint counting.
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

.section    .rodata

# Modulus Q = 2^23 - 2^13 + 1 (FIPS 204, Table 1)
.align 4
ml_dsa_q:
    .long 8380417

.section    .note.GNU-stack,"",\@progbits
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
