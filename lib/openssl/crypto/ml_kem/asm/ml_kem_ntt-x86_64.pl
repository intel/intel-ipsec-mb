#! /usr/bin/env perl
#
# Copyright (c) 2026, Intel Corporation. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

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
    or die "AVX2 support is required in the assembler to build the ML-KEM NTT kernels.\nMinimum assembler versions: GNU as 2.22, clang 3.3, nasm 2.10.\n";

open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT = *OUT;

my $code = '';

# ---------------------------------------------------------------------------
# Signed 16-bit range analysis (q = 3329, R = 2^16)
#
# Every kernel in this file operates on signed 16-bit lanes without widening
# (except ntt_reduce). The bounds below are the invariants that keep every
# intermediate inside [-32768, 32767]; any change to the butterfly structure,
# the reduction points or the twiddle encoding must be re-checked against them.
#
# Montgomery product helper bound
#   All multiplies have the form   t = high(a*c_hi) - high(low16(a*c_lo) * q)
#   with c_lo = c_hi * q^-1 mod 2^16. The two floors cancel exactly, so
#       t = (a*c_hi - m*q) / 2^16,   m = low16(a*c_lo), |m| <= 2^15
#   and therefore
#       |t| <= |a|*|c_hi| / 2^16 + q/2.                                 (M)
#   Twiddle high parts (kNTTZetaHi, kInvNTTZetaHi, kDotMulHi) and the
#   R^2 / 512 constants are stored in signed canonical form, |c_hi| <= (q-1)/2,
#   so for any signed 16-bit |a| the product satisfies |t| <= 3q/4 < q.
#
# Forward NTT (ml_kem_ntt_avx2)
#   Precondition: input coefficients canonical, in [0, q-1].
#   Levels 1..7 run lazily (no reduction); each level widens the interval by
#   the level's |t| bound from (M) applied to the incoming magnitude:
#       after L1: (-0.53q, 1.53q)      after L5: (-2.76q, 3.76q)
#       after L2: (-1.06q, 2.06q)      after L6: (-3.36q, 4.36q)
#       after L3: (-1.62q, 2.62q)      after L7: (-3.97q, 4.97q)
#       after L4: (-2.18q, 3.18q)
#   Worst case after level 7 is (-13216, +16544), well inside int16.
#   ntt_reduce then requires x > -5q so that (x + 5q) is non-negative before
#   the logical shift in the Barrett step; the level-7 bound gives
#   x + 5q in (q, 10q), and (10q)*5039 < 2^31 keeps the dword product exact.
#   Output: canonical [0, q-1].
#
# Inverse NTT (ml_kem_inverse_ntt_avx2)
#   Precondition: input canonical, in [0, q-1].
#   intt_butterfly fully reduces both outputs at every level, so every level
#   sees canonical inputs: w_even + w_odd in [0, 2q) feeds reduce_once, and
#   w_even - w_odd in (-q, q) feeds the Montgomery multiply, giving
#   |t| <= q*(q-1)/2 / 2^16 + q/2 < 0.53q. The final inverse-degree scale
#   (intt_scale_reduce) is a Montgomery multiply by 512 (= 2^9, so the result
#   is x * 2^9 * 2^-16 = x/128 mod q), again bounded by (M).
#   Output: canonical [0, q-1].
#
# Row dot product (ml_kem_ntt_dot_avx2 / ml_kem_ntt_dot_add_avx2)
#   Precondition: all operands canonical, in [0, q-1]; count <= 4 (rank).
#       lz = M(l, c):                    |.| <= 3328*1636/2^16 + q/2 ~ 1748
#       vpmaddwd(lz, r) per term:        |.| <= 2*1748*3328          ~ 11.6M
#       vpmaddwd(l, swap(r)) per term:   |.| <= 2*3328*3328          ~ 22.2M
#       4-term int32 sums:               |.| <= 88.6M < 2^31
#   The 32-bit Montgomery step t = (x - m*q) / 2^16 with |m| <= 2^15 gives
#   |t| <= (88.6M + 2^15*q) / 2^16 ~ 3017 < q, so the even outputs are in
#   (-q, q); the odd outputs M(t, R^2) satisfy |.| <= 3017*1353/2^16 + q/2
#   ~ 1727. The conditional +q therefore maps both to canonical [0, q-1].
#   ml_kem_ntt_dot_add_avx2 adds this canonical sum to a canonical accumulator
#   ([0, 2q)) and applies reduce_once.
#
# Add / sub (ml_kem_add_avx2 / ml_kem_sub_avx2)
#   Precondition: both operands canonical. Sum in [0, 2q) feeds reduce_once;
#   difference in (-q, q) is fixed up with a conditional +q.
# ---------------------------------------------------------------------------

# intt_scale_reduce: Multiply 16 coefficients by the inverse-degree factor
# and reduce the results to the range [0, q-1]. Used on the final inverse NTT
# output vectors to avoid an extra store/reload pass, similar to how
# ntt_reduce is integrated into the forward NTT.
#
# The inverse-degree scale is a signed 16-bit Montgomery multiply by the
# constant whose high half is 512 (= 2^9):
#     scaled = high(x * 512) - high((x << 9) * q)
# followed by a negative fixup (+q where negative) and a reduce_once (-q where
# still >= q) to land the result in [0, q-1].
#
# Constants (passed pre-broadcast so callers can hoist them):
#   $c512     = 512 broadcast as words, high half of the inverse-degree factor.
#   $qw       = q (3329) broadcast as words, for the Montgomery correction term.
#   $signmask = q broadcast as words (the same q vector), added where the scaled
#             value is negative to bring it into [0, 2q).
#   $minusq   = -q (3329) broadcast as words, for the final reduce_once.
sub intt_scale_reduce {
    my ($in, $out,
        $c512, $qw, $signmask, $minusq,
        $t0, $t1) = @_;

    $code .= <<___;
    vpsllw          \$9, $in, $t0                        # x * 512 (low-path term)
    vpmulhw         $in, $c512, $out                     # high(x * 512)
    vpmulhw         $t0, $qw, $t0                        # correction term
    vpsubw          $t0, $out, $out                      # inverse-degree scaled x
    vpsraw          \$15, $out, $t1                      # sign mask
    vpand           $signmask, $t1, $t1                  # add q if negative
    vpaddw          $t1, $out, $out                      # now in [0, 2q)
    vpaddw          $minusq, $out, $t1                   # candidate x - q
    vpsraw          \$15, $t1, $t0                       # select mask
    vpblendvb       $t0, $out, $t1, $out                 # reduce_once to [0, q-1]
___
}

# ntt_butterfly: forward (Cooley-Tukey) butterfly, FIPS 203 Alg 9 inner step.
# Computes t = zeta * w_odd with a 16-bit Montgomery multiply, then
#     n_even = w_even + t,   n_odd = w_even - t.
# Outputs stay in a bounded signed range; the final level normalizes to [0, q-1].
# Args: (w_even, w_odd, zeta_lo, zeta_hi, tmp0, tmp1, n_even, n_odd, q).
sub ntt_butterfly {
    my ($w_even, $w_odd,
        $zetas_lo, $zetas_hi,
        $tmp0, $tmp1,
        $n_even, $n_odd,
        $q) = @_;

    $code .= <<___;
    # t = zeta * w_odd
    vpmullw     $w_odd, $zetas_lo, $tmp0
    vpmulhw     $tmp0, $q, $tmp0
    vpmulhw     $zetas_hi, $w_odd, $tmp1
    vpsubw      $tmp0, $tmp1, $tmp0

    # n_odd  = w_even - t
    # n_even = w_even + t
    # Keep subtraction first so calls may alias n_even with w_even safely.
    vpsubw      $tmp0, $w_even, $n_odd
    vpaddw      $w_even, $tmp0, $n_even
___
}

# ntt_reduce: reduce 16 signed 16-bit coefficients to canonical [0, q-1].
#
# Used directly on the final ymm results of NTT levels 4..7 to avoid a
# separate normalization pass with extra stores and loads.
#
# Barrett-style reduction, computed in 32-bit lanes:
#     qhat = ((x + 5*q) * floor(2^24 / q)) >> 24
#     r    = (x + 5*q) - qhat*q            # == x mod q, in [0, 2q)
# followed by a conditional subtract of q (reduce_once) to land in [0, q-1].
#
# Constants (passed pre-broadcast so callers can hoist them):
#   $c16645 = 5*q                = 16645, broadcast as dwords. Bias that lifts a
#             signed input to a non-negative value before the reciprocal
#             multiply; the 5 extra multiples of q are removed by qhat*q, so the
#             residue mod q is unchanged.
#   $c5039  = floor(2^24 / q)    = 5039,  broadcast as dwords. Fixed-point
#             reciprocal of q used to estimate the quotient via (x*c)>>24.
#   $q      = q (3329)           broadcast as dwords, for the qhat*q product.
#   $signmask = q broadcast as words (the same q vector; 0x0d01 per word), added
#             where the packed residue is negative to bring it into [0, 2q).
#   $minus_q  = -q (3329) broadcast as words, for the final reduce_once.
#
# All compute steps operate on ymm registers (16-wide) for throughput: the
# 16->32-bit widening uses vpsraw + vpunpck{l,h}wd rather than a 128-bit
# vpmovsxwd split, which also keeps the lanes ordered so vpackssdw restores the
# original layout without a fix-up vpermq.
sub ntt_reduce {
    my ($in, $out,
        $q, $minus_q, $signmask,
        $c5039, $c16645,
        $s0, $s1, $s2) = @_;

    $code .= <<___;
    # widen 16 x int16 -> 2 x (8 x int32) via sign extension (all-ymm)
    vpsraw      \$15, $in, $s2                  # sign words
    vpunpcklwd  $s2, $in, $s0                   # int32 lanes {0..3 | 8..11}
    vpunpckhwd  $s2, $in, $s1                   # int32 lanes {4..7 | 12..15}

    # qhat = ((x + 5q) * floor(2^24/q)) >> 24 ; residue = (x + 5q) - qhat*q
    vpaddd      $c16645, $s0, $s0               # + 5q bias
    vpaddd      $c16645, $s1, $s1
    vpmulld     $c5039, $s0, $s2                # * reciprocal
    vpsrld      \$24, $s2, $s2                  # qhat (low half)
    vpmulld     $q, $s2, $s2                    # qhat * q
    vpsubd      $s2, $s0, $s0                   # residue (low half)
    vpmulld     $c5039, $s1, $s2
    vpsrld      \$24, $s2, $s2                  # qhat (high half)
    vpmulld     $q, $s2, $s2
    vpsubd      $s2, $s1, $s1                   # residue (high half)

    vpackssdw   $s1, $s0, $out                 # back to int16, natural lane order

    # negative fixup -> [0, 2q), then reduce_once -> [0, q-1]
    vpsraw      \$15, $out, $s2                 # sign bits
    vpand       $signmask, $s2, $s2            # q where negative
    vpaddw      $out, $s2, $out                # now in [0, 2q)
    vpaddw      $minus_q, $out, $s0            # candidate x - q
    vpsraw      \$15, $s0, $s1                  # mask where candidate < 0
    vpblendvb   $s1, $out, $s0, $out           # final reduce_once
___
}

# reduce_once($v, $qw, $t1, $t2): Reduce 16 signed words in [0, 2q) to
# [0, q-1]. Subtracts q and keeps the result if it is non-negative;
# otherwise keeps the original value. $qw contains q broadcast across the
# vector; $t1 and $t2 are scratch registers.
#
# Used by ml_kem_add and ml_kem_ntt_dot_add. ntt_reduce and intt_scale_reduce
# perform the same step inline as part of their normalization logic.
sub reduce_once {
    my ($v, $qw, $t1, $t2) = @_;
    $code .= <<___;
    vpsubw      $qw, $v, $t1                    # $v - q
    vpsraw      \$15, $t1, $t2                  # mask: set where $v < q (underflow)
    vpblendvb   $t2, $v, $t1, $v                # keep $v-q unless it underflowed
___
}

# emit_ml_kem_ntt_level1_3: forward butterfly levels 1-3 (len 128/64/32) over 128
# interleaved coefficients at byte offset $off (stride-32 positions).  Called twice
# with off=0 and off=32 to cover all 256 coefficients.  These coarse levels keep
# each butterfly arm in a whole ymm register, so no in-lane shuffles are needed.
sub emit_ml_kem_ntt_level1_3 {
    my ($off) = @_;

    $code .= <<___;
    # Forward NTT butterflies level 1 (len=128),
    # level 2 (len=64) and level 3 (len=32).

    vmovdqu        $off+0*2(%rdi), %ymm0         # L1 even, L2 even, L3 even
    vmovdqu        $off+32*2(%rdi), %ymm1        # L1 even, L2 even, L3 odd
    vmovdqu        $off+64*2(%rdi), %ymm2        # L1 even, L2 odd, L3 even
    vmovdqu        $off+96*2(%rdi), %ymm3        # L1 even, L2 odd, L3 odd
    vmovdqu        $off+128*2(%rdi), %ymm4       # L1 odd, L2 even, L3 even
    vmovdqu        $off+160*2(%rdi), %ymm5       # L1 odd, L2 even, L3 odd
    vmovdqu        $off+192*2(%rdi), %ymm6       # L1 odd, L2 odd, L3 even
    vmovdqu        $off+224*2(%rdi), %ymm7       # L1 odd, L2 odd, L3 odd

    vpbroadcastw   ${ZETA_L1}(%r14), %ymm13    # L1 lo
    vpbroadcastw   ${ZETA_L1}(%r15), %ymm14    # L1 hi
___
    # L1 (len=128): pairs (0,4)(1,5)(2,6)(3,7) -> ${ZETA_L1}
    foreach my $p (["%ymm0","%ymm4"],  ["%ymm1","%ymm5"],
                   ["%ymm2","%ymm6"], ["%ymm3","%ymm7"]) {
        my ($a,$b) = @$p;
        &ntt_butterfly($a, $b, "%ymm13", "%ymm14",
                       "%ymm8", "%ymm9", $a, $b, "%ymm15");
    }

    # L2 (len=64): (0,2)(1,3) -> ${ZETA_L2}+0
    $code .= <<___;
    vpbroadcastw   ${ZETA_L2}(%r14), %ymm13    # L2 lo
    vpbroadcastw   ${ZETA_L2}(%r15), %ymm14    # L2 hi
___

    foreach my $p (["%ymm0","%ymm2"], ["%ymm1","%ymm3"]) {
        my ($a,$b) = @$p;
        &ntt_butterfly($a, $b, "%ymm13", "%ymm14",
                       "%ymm8", "%ymm9", $a, $b, "%ymm15");
    }

    # L2 (len=64): (4,6)(5,7) -> ${ZETA_L2}+2
    $code .= <<___;
    vpbroadcastw   ${ZETA_L2}+2(%r14), %ymm13  # L2 lo
    vpbroadcastw   ${ZETA_L2}+2(%r15), %ymm14  # L2 hi
___

    foreach my $p (["%ymm4","%ymm6"], ["%ymm5","%ymm7"]) {
        my ($a,$b) = @$p;
        &ntt_butterfly($a, $b, "%ymm13", "%ymm14",
                       "%ymm8", "%ymm9", $a, $b, "%ymm15");
    }

    # L3 (len=32): (0,1)(2,3)(4,5)(6,7) -> ${ZETA_L3} + {0,2,4,6}
    foreach my $p (["%ymm0","%ymm1",0], ["%ymm2","%ymm3",2],
                   ["%ymm4","%ymm5",4], ["%ymm6","%ymm7",6]) {
        my ($a,$b,$z) = @$p;
        $code .= <<___;
    vpbroadcastw   ${ZETA_L3}+$z(%r14), %ymm13    # L3 lo
    vpbroadcastw   ${ZETA_L3}+$z(%r15), %ymm14    # L3 hi
___
        &ntt_butterfly($a, $b, "%ymm13", "%ymm14",
                       "%ymm8", "%ymm9", $a, $b, "%ymm15");
    }

    $code .= <<___;
    vmovdqu        %ymm0, $off+0*2(%rdi)
    vmovdqu        %ymm1, $off+32*2(%rdi)
    vmovdqu        %ymm2, $off+64*2(%rdi)
    vmovdqu        %ymm3, $off+96*2(%rdi)
    vmovdqu        %ymm4, $off+128*2(%rdi)
    vmovdqu        %ymm5, $off+160*2(%rdi)
    vmovdqu        %ymm6, $off+192*2(%rdi)
    vmovdqu        %ymm7, $off+224*2(%rdi)
___
}

# emit_ml_kem_ntt_level4_7: forward butterfly levels 4-7 (len 16/8/4/2) over the
# 128 coefficients at byte offset $off, followed by the final normalization to
# [0, q-1].  These fine levels pair coefficients that share a ymm register, so
# each level first gathers its butterfly arms with lane shuffles (vperm2i128 /
# vpunpck*) and un-gathers afterwards.  $first selects the twiddle slice: the two
# 128-coefficient halves use different zeta offsets within the shared tables.
sub emit_ml_kem_ntt_level4_7 {
    my ($off, $first) = @_;
    my $l4off = $first ? 0 : 4*2;
    my $l567off = $first ? 0 : 64*2;

    $code .= <<___;
    # Forward NTT butterflies level 4 (len=16),
    # level 5 (len=8), level 6 (len=4) and level 7 (len=2)

    vmovdqu        $off+0*2(%rdi), %ymm0    # L4 even
    vmovdqu        $off+16*2(%rdi), %ymm1   # L4 odd
    vmovdqu        $off+32*2(%rdi), %ymm2   # L4 even
    vmovdqu        $off+48*2(%rdi), %ymm3   # L4 odd
    vmovdqu        $off+64*2(%rdi), %ymm4   # L4 even
    vmovdqu        $off+80*2(%rdi), %ymm5   # L4 odd
    vmovdqu        $off+96*2(%rdi), %ymm6   # L4 even
    vmovdqu        $off+112*2(%rdi), %ymm7  # L4 odd
___

    # L4 (len=16): pairs (0,1)(2,3)(4,5)(6,7)
    foreach my $p (["%ymm0","%ymm1",0], ["%ymm2","%ymm3",1],
                   ["%ymm4","%ymm5",2], ["%ymm6","%ymm7",3]) {
        my ($A, $B, $k) = @$p;
        my $z4 = $l4off + $k*2;
        $code .= <<___;
    vpbroadcastw   $z4+${ZETA_L4}(%r14), %ymm13    # L4 lo
    vpbroadcastw   $z4+${ZETA_L4}(%r15), %ymm14    # L4 hi
___
        &ntt_butterfly($A, $B, "%ymm13", "%ymm14",
                       "%ymm8", "%ymm9", $A, $B, "%ymm15");
    }

    # L5 (len=8): pairs (0,1)(2,3)(4,5)(6,7)
    foreach my $p (["%ymm0","%ymm1",0], ["%ymm2","%ymm3",1],
                   ["%ymm4","%ymm5",2], ["%ymm6","%ymm7",3]) {
        my ($A, $B, $k) = @$p;
        my $z = $l567off + $k*32;
        $code .= <<___;
    vmovdqu        $z+${ZETA_L5}(%r14), %ymm13    # L5 lo
    vmovdqu        $z+${ZETA_L5}(%r15), %ymm14    # L5 hi
    vperm2i128     \$0x20, $B, $A, %ymm10  # lo | lo
    vperm2i128     \$0x31, $B, $A, %ymm11  # hi | hi
___
        &ntt_butterfly("%ymm10", "%ymm11", "%ymm13", "%ymm14",
                       "%ymm8", "%ymm9", $A, $B, "%ymm15");
    }

    # L6 (len=4): pairs (0,1)(2,3)(4,5)(6,7)
    foreach my $p (["%ymm0","%ymm1",0], ["%ymm2","%ymm3",1],
                   ["%ymm4","%ymm5",2], ["%ymm6","%ymm7",3]) {
        my ($A, $B, $k) = @$p;
        my $z = $l567off + $k*32;
        $code .= <<___;
    vmovdqu        $z+${ZETA_L6}(%r14), %ymm13    # L6 lo
    vmovdqu        $z+${ZETA_L6}(%r15), %ymm14    # L6 hi
    vpunpcklqdq    $B, $A, %ymm10 # even
    vpunpckhqdq    $B, $A, %ymm11 # odd
___
        &ntt_butterfly("%ymm10", "%ymm11", "%ymm13", "%ymm14",
                       "%ymm8", "%ymm9", $A, $B, "%ymm15");
    }

    # L7 (len=2): pairs (0,1)(2,3)(4,5)(6,7)
    foreach my $p (["%ymm0","%ymm1",0], ["%ymm2","%ymm3",1],
                   ["%ymm4","%ymm5",2], ["%ymm6","%ymm7",3]) {
        my ($A, $B, $k) = @$p;
        my $z = $l567off + $k*32;
        $code .= <<___;
    vmovdqu        $z+${ZETA_L7}(%r14), %ymm13    # L7 lo
    vmovdqu        $z+${ZETA_L7}(%r15), %ymm14    # L7 hi
    vpunpckldq     $B, $A, %ymm10 # [d0|d0'|d1|d1']
    vpunpckhdq     $B, $A, %ymm11 # [d2|d2'|d3|d3']
    vpunpcklqdq    %ymm11, %ymm10, %ymm12 # even
    vpunpckhqdq    %ymm11, %ymm10, %ymm11 # odd
___
        &ntt_butterfly("%ymm12", "%ymm11", "%ymm13", "%ymm14",
                       "%ymm8", "%ymm9", $A, $B, "%ymm15");
    }

    # ---- Normalize level-4..7 results (ymm0..ymm7) to canonical [0, q-1] ----
    # ymm15 stays live: it holds q broadcast as words, which doubles as the
    # negative-fixup mask (signmask) below, so it is only read, never clobbered.
    $code .= <<'___';
    vpbroadcastd   bias_5q(%rip), %ymm8                 # c16645 (dwords)
    vpbroadcastd   floor2p24_div_q(%rip), %ymm9         # c5039 (dwords)
    vpbroadcastd   q(%rip), %ymm10                      # q (dwords) for qhat*q
    vpbroadcastw   minus_q(%rip), %ymm11                # -q as words (reduce_once)
___

    for my $r (0 .. 7) {
        &ntt_reduce("%ymm$r", "%ymm$r",
                    "%ymm10", "%ymm11", "%ymm15",       # q(dword), -q(word), q(word)=signmask
                    "%ymm9", "%ymm8",                    # c5039, c16645
                    "%ymm12", "%ymm13", "%ymm14");       # scratch (ymm15 must stay = q)
    }

    # Scatter L4..L7 results back to natural order and store.
    foreach my $p (["%ymm0","%ymm1",0,16], ["%ymm2","%ymm3",32,48],
                   ["%ymm4","%ymm5",64,80], ["%ymm6","%ymm7",96,112]) {
        my ($A, $B, $e, $o) = @$p;
        $code .= <<___;
    vpunpckldq     $B, $A, %ymm12
    vpunpckhdq     $B, $A, %ymm13
    vperm2i128     \$0x20, %ymm13, %ymm12, %ymm10
    vperm2i128     \$0x31, %ymm13, %ymm12, %ymm11
    vmovdqu        %ymm10, $off+$e*2(%rdi)
    vmovdqu        %ymm11, $off+$o*2(%rdi)
___
    }
}

# intt_butterfly: inverse (Gentleman-Sande) butterfly, FIPS 203 Alg 10 inner step.
#     n_even = reduce_once(w_even + w_odd)
#     n_odd  = reduce_once(zeta * (w_even - w_odd))   (16-bit Montgomery multiply)
# Both outputs are canonical [0, q-1].
# Args: (w_even, w_odd, zeta_lo, zeta_hi, tmp0, tmp1, n_even, n_odd, q).
sub intt_butterfly {
    my ($w_even, $w_odd,
        $zetas_lo, $zetas_hi,
        $tmp0, $tmp1,
        $n_even, $n_odd,
        $q) = @_;

    $code .= <<___;

    vpsubw      $w_odd, $w_even, $tmp1          # n_odd: tmp1 = w_even - w_odd
    vpaddw      $w_even, $w_odd, $n_even        # n_even: w_even + w_odd

    # n_odd: zeta * (even - odd)
    vpmullw     $tmp1, $zetas_lo, $tmp0         # tmp0 = zeta_lo * (even - odd)
    vpmulhw     $zetas_hi, $tmp1, $tmp1         # tmp1 = zeta_hi * (even - odd)
    vpmulhw     $tmp0, $q, $tmp0                # tmp0 = tmp0 * Q
    vpsubw      $tmp0, $tmp1, $n_odd            # zeta_hi * (even - odd) - (Q * (zeta_lo * (even - odd)))

    # n_even = reduce_once(w_even + w_odd)
    vpcmpgtw     $n_even, $q, $tmp0             # $tmp0 = $q > $n_even ? 0xffff : 0
    vpandn      $q, $tmp0, $tmp0                # $tmp0 = ~$tmp0 & $q
    vpsubw      $tmp0, $n_even, $n_even         # $n_even -= $tmp0

    # n_odd = reduce_once(n_odd), but first canonicalize negatives:
    # Montgomery product lands in (-q, q), so add q where negative to move
    # into [0, 2q) before the final conditional subtract.
    vpsraw       \$15, $n_odd, $tmp0            # sign mask
    vpand        $q, $tmp0, $tmp0               # +q where negative
    vpaddw       $tmp0, $n_odd, $n_odd          # now in [0, 2q)
    vpcmpgtw     $n_odd, $q, $tmp0              # $tmp0 = $q > $n_odd ? 0xffff : 0
    vpandn       $q, $tmp0, $tmp0               # $tmp0 = ~$tmp0 & $q
    vpsubw       $tmp0, $n_odd, $n_odd          # $n_odd -= $tmp0
___
}

# emit_ml_kem_intt_level7_4: inverse butterfly levels 7-4 (len 2/4/8/16) over the
# 128 coefficients at byte offset $off.  Mirror of emit_ml_kem_ntt_level4_7: the
# fine levels gather butterfly arms with lane shuffles and progressively un-gather
# back to natural order.  $first selects the twiddle slice for this half.
sub emit_ml_kem_intt_level7_4 {
    my ($off, $first) = @_;
    my $l4off   = $first ? 0 : 4*2;
    my $l567off = $first ? 0 : 64*2;

    $code .= <<___;
    # Inverse NTT butterflies level 7 (len=2), level 6 (len=4),
    # level 5 (len=8) and level 4 (len=16) over 128 contiguous coefficients.
    # The 128 coefficients are held in ymm0..ymm7 (four independent 32-coeff
    # register pairs).  Each pair is gathered into the level-7 arm layout,
    # then butterflied and progressively un-gathered back to natural order.
    vmovdqu        $off+0*2(%rdi), %ymm0
    vmovdqu        $off+16*2(%rdi), %ymm1
    vmovdqu        $off+32*2(%rdi), %ymm2
    vmovdqu        $off+48*2(%rdi), %ymm3
    vmovdqu        $off+64*2(%rdi), %ymm4
    vmovdqu        $off+80*2(%rdi), %ymm5
    vmovdqu        $off+96*2(%rdi), %ymm6
    vmovdqu        $off+112*2(%rdi), %ymm7
___

    foreach my $p (["%ymm0","%ymm1",0], ["%ymm2","%ymm3",1],
                   ["%ymm4","%ymm5",2], ["%ymm6","%ymm7",3]) {
        my ($A, $B, $k) = @$p;
        my $zoff = $l567off + $k*32;

        # ---- Level 7 (len=2) : gather natural -> L7 arms ----
        $code .= <<___;
    # pair $k : level 7 (len=2)
    vmovdqu        $zoff+${ZETA_L7}(%r14), %ymm13
    vmovdqu        $zoff+${ZETA_L7}(%r15), %ymm14
    vperm2i128     \$0x20, $B, $A, %ymm10
    vperm2i128     \$0x31, $B, $A, %ymm11
    vpshufd        \$0xd8, %ymm10, %ymm10
    vpshufd        \$0xd8, %ymm11, %ymm11
    vpunpcklqdq    %ymm11, %ymm10, %ymm12       # L7 w_even
    vpunpckhqdq    %ymm11, %ymm10, %ymm11       # L7 w_odd
___
        &intt_butterfly("%ymm12", "%ymm11", "%ymm13", "%ymm14",
                        "%ymm8", "%ymm9", $A, $B, "%ymm15");
    }

    foreach my $p (["%ymm0","%ymm1",0], ["%ymm2","%ymm3",1],
                   ["%ymm4","%ymm5",2], ["%ymm6","%ymm7",3]) {
        my ($A, $B, $k) = @$p;
        my $zoff = $l567off + $k*32;

        # ---- Level 6 (len=4) : L7 arms -> L6 arms ----
        $code .= <<___;
    # pair $k : level 6 (len=4)
    vmovdqu        $zoff+${ZETA_L6}(%r14), %ymm13
    vmovdqu        $zoff+${ZETA_L6}(%r15), %ymm14
    vpunpckldq     $B, $A, %ymm10
    vpunpckhdq     $B, $A, %ymm11
    vpunpcklqdq    %ymm11, %ymm10, %ymm12       # L6 w_even
    vpunpckhqdq    %ymm11, %ymm10, %ymm11       # L6 w_odd
___
        &intt_butterfly("%ymm12", "%ymm11", "%ymm13", "%ymm14",
                        "%ymm8", "%ymm9", $A, $B, "%ymm15");
    }

    foreach my $p (["%ymm0","%ymm1",0], ["%ymm2","%ymm3",1],
                   ["%ymm4","%ymm5",2], ["%ymm6","%ymm7",3]) {
        my ($A, $B, $k) = @$p;
        my $zoff = $l567off + $k*32;

        # ---- Level 5 (len=8) : L6 arms -> L5 arms ----
        $code .= <<___;
    # pair $k : level 5 (len=8)
    vmovdqu        $zoff+${ZETA_L5}(%r14), %ymm13
    vmovdqu        $zoff+${ZETA_L5}(%r15), %ymm14
    vpunpcklqdq    $B, $A, %ymm12               # L5 w_even
    vpunpckhqdq    $B, $A, %ymm11               # L5 w_odd
___
        &intt_butterfly("%ymm12", "%ymm11", "%ymm13", "%ymm14",
                        "%ymm8", "%ymm9", $A, $B, "%ymm15");
    }

    foreach my $p (["%ymm0","%ymm1",0], ["%ymm2","%ymm3",1],
                   ["%ymm4","%ymm5",2], ["%ymm6","%ymm7",3]) {
        my ($A, $B, $k) = @$p;
        my $z4 = $l4off + $k*2;

        # ---- Level 4 (len=16) : L5 arms -> natural, register-wise ----
        $code .= <<___;
    # pair $k : level 4 (len=16)
    vpbroadcastw   $z4+${ZETA_L4}(%r14), %ymm13
    vpbroadcastw   $z4+${ZETA_L4}(%r15), %ymm14
    vperm2i128     \$0x20, $B, $A, %ymm12       # L4 w_even
    vperm2i128     \$0x31, $B, $A, %ymm11       # L4 w_odd
___
        &intt_butterfly("%ymm12", "%ymm11", "%ymm13", "%ymm14",
                        "%ymm8", "%ymm9", $A, $B, "%ymm15");
    }

    $code .= <<___;
    vmovdqu        %ymm0, $off+0*2(%rdi)
    vmovdqu        %ymm1, $off+16*2(%rdi)
    vmovdqu        %ymm2, $off+32*2(%rdi)
    vmovdqu        %ymm3, $off+48*2(%rdi)
    vmovdqu        %ymm4, $off+64*2(%rdi)
    vmovdqu        %ymm5, $off+80*2(%rdi)
    vmovdqu        %ymm6, $off+96*2(%rdi)
    vmovdqu        %ymm7, $off+112*2(%rdi)
___
}

# emit_ml_kem_intt_level3_1: inverse butterfly levels 3-1 (len 32/64/128) over 128
# interleaved coefficients at byte offset $off (stride-32 positions).  Called twice
# with off=0 and off=32 to cover all 256 coefficients.  Coarse levels are
# register-wise (no shuffles).  The FIPS 203 Alg 10 final 1/n scaling and
# canonicalization to [0, q-1] are fused into the last level so results are stored
# just once.
sub emit_ml_kem_intt_level3_1 {
    my ($off) = @_;

    $code .= <<___;
    # Inverse NTT butterflies level 3 (len=32), level 2 (len=64)
    # and level 1 (len=128).  Register-wise, no lane permutations.
    vmovdqu        $off+0*2(%rdi), %ymm0
    vmovdqu        $off+32*2(%rdi), %ymm1
    vmovdqu        $off+64*2(%rdi), %ymm2
    vmovdqu        $off+96*2(%rdi), %ymm3
    vmovdqu        $off+128*2(%rdi), %ymm4
    vmovdqu        $off+160*2(%rdi), %ymm5
    vmovdqu        $off+192*2(%rdi), %ymm6
    vmovdqu        $off+224*2(%rdi), %ymm7
___

    # L3 (len=32): pairs (0,1)(2,3)(4,5)(6,7) -> ${ZETA_L3} + {0,2,4,6}
    foreach my $p (["%ymm0","%ymm1",0], ["%ymm2","%ymm3",2],
                   ["%ymm4","%ymm5",4], ["%ymm6","%ymm7",6]) {
        my ($a,$b,$z) = @$p;
        $code .= <<___;
    vpbroadcastw   ${ZETA_L3}+$z(%r14), %ymm13
    vpbroadcastw   ${ZETA_L3}+$z(%r15), %ymm14
___
        &intt_butterfly($a, $b, "%ymm13", "%ymm14",
                        "%ymm8", "%ymm9", $a, $b, "%ymm15");
    }

    # L2 (len=64): pairs (0,2)(1,3)->${ZETA_L2}+0 ; (4,6)(5,7)->${ZETA_L2}+2
    foreach my $p (["%ymm0","%ymm2",0], ["%ymm1","%ymm3",0],
                   ["%ymm4","%ymm6",2], ["%ymm5","%ymm7",2]) {
        my ($a,$b,$z) = @$p;
        $code .= <<___;
    vpbroadcastw   ${ZETA_L2}+$z(%r14), %ymm13
    vpbroadcastw   ${ZETA_L2}+$z(%r15), %ymm14
___
        &intt_butterfly($a, $b, "%ymm13", "%ymm14",
                        "%ymm8", "%ymm9", $a, $b, "%ymm15");
    }

    # L1 (len=128): pairs (0,4)(1,5)(2,6)(3,7) -> ${ZETA_L1}
    $code .= <<___;
    vpbroadcastw   ${ZETA_L1}(%r14), %ymm13
    vpbroadcastw   ${ZETA_L1}(%r15), %ymm14
___
    foreach my $p (["%ymm0","%ymm4"], ["%ymm1","%ymm5"],
                   ["%ymm2","%ymm6"], ["%ymm3","%ymm7"]) {
        my ($a,$b) = @$p;
        &intt_butterfly($a, $b, "%ymm13", "%ymm14",
                        "%ymm8", "%ymm9", $a, $b, "%ymm15");
    }

    # ---- Scale by the inverse degree and canonicalize to [0, q-1] ----
    # Fused into the final level so the results are normalized in-register and
    # stored once, instead of a separate store + reload sweep.  ymm15 stays live
    # (q as words), reused here as the Montgomery correction term.
    $code .= <<___;
    vpbroadcastw   inv_deg_factor(%rip), %ymm8           # 512 (words) inverse degree factor
    vpbroadcastw   q(%rip), %ymm9                        # q (words) negative fixup
    vpbroadcastw   minus_q(%rip), %ymm10                 # -q (words) reduce_once
___

    for my $r (0 .. 7) {
        &intt_scale_reduce("%ymm$r", "%ymm$r",
                           "%ymm8", "%ymm15", "%ymm9", "%ymm10",
                           "%ymm11", "%ymm12");
    }

    $code .= <<___;
    vmovdqu        %ymm0, $off+0*2(%rdi)
    vmovdqu        %ymm1, $off+32*2(%rdi)
    vmovdqu        %ymm2, $off+64*2(%rdi)
    vmovdqu        %ymm3, $off+96*2(%rdi)
    vmovdqu        %ymm4, $off+128*2(%rdi)
    vmovdqu        %ymm5, $off+160*2(%rdi)
    vmovdqu        %ymm6, $off+192*2(%rdi)
    vmovdqu        %ymm7, $off+224*2(%rdi)
___
}

# NTT-domain row dot product helpers.
#
# After the forward NTT, the 256 coefficients are arranged as 128 independent
# elements of GF(q)[X]/(X^2 - zeta_i). Each element is stored as a consecutive
# coefficient pair (l0, l1) = (lhs[2i], lhs[2i+1]). The product of two such
# elements is:
#
#     out[2i]   = l0*r0 + l1*r1*zeta_i   (mod q)
#     out[2i+1] = l0*r1 + l1*r0          (mod q)
#
# This matches poly_mult_base() in ml_kem.c (roots = kModRoots). The kernels
# below compute a whole matrix row (or inner product) at once:
#
#     out = sum_j lhs[j * stride] (*) rhs[j],   j = 0..count-1
#
# The pairs are kept interleaved, so no even/odd split is needed:
#
#     lz  = M(l, c),   c = [R^2, zeta_i*R^2] per pair  -> [l0*R, l1*zeta_i*R]
#     x0 += vpmaddwd(lz, r)                            -> (l0*r0 + l1*r1*zeta_i)*R
#     x1 += vpmaddwd(l, swap(r))                       -> l0*r1 + l1*r0
#
# with M(a,b) = a*b*R^-1 mod q the signed 16-bit Montgomery multiply and
# R = 2^16. The int32 sums are reduced once per output coefficient with an
# exact 32-bit to 16-bit Montgomery reduction:
#
#     m = low16(x) * q^-1 mod 2^16,   t = (x - m*q) / 2^16 = x*R^-1 mod q
#
# giving out[2i] = t(x0) and out[2i+1] = M(t(x1), R^2). kDotMul{Hi,Lo} hold c
# in the same split representation as the twiddle-factor tables.
#
# Fixed register assignments:
#     ymm15 = q (words)
#     ymm14 = vpshufb mask swapping the two words of each dword
#     ymm13 = [q^-1 mod 2^16, 0] per dword
#     ymm12 = [q, 0] per dword

# dot_term: accumulate one term of the row dot product for 16 coefficients.
#   $l  = lhs vector (scratch, loaded by the caller)
#   $r  = rhs memory operand
#   $chi, $clo = per-pair constant c (hi/lo)
#   $x0, $x1 = int32 accumulators for the even and odd outputs
sub dot_term {
    my ($l, $r, $chi, $clo, $x0, $x1, $t0, $t1, $t2) = @_;
    $code .= <<___;
    vpmullw     $clo, $l, $t0                   # t  = clo*l (mod 2^16)
    vpmulhw     $chi, $l, $t1                   # lz = high(chi*l)
    vpmulhw     %ymm15, $t0, $t0                # t  = high(q * t)
    vpsubw      $t0, $t1, $t1                   # lz = [l0*R, l1*zeta*R]
    vmovdqu     $r, $t2                         # [r0, r1]
    vpmaddwd    $t2, $t1, $t1                   # l0*r0*R + l1*r1*zeta*R
    vpaddd      $t1, $x0, $x0
    vpshufb     %ymm14, $t2, $t2                # [r1, r0]
    vpmaddwd    $t2, $l, $t2                    # l0*r1 + l1*r0
    vpaddd      $t2, $x1, $x1
___
}

# dot_reduce: reduce the int32 accumulators of 16 coefficients to canonical
# [0, q-1] and interleave them back into (even, odd) pairs in $x0.
# $r2hi/$r2lo hold R^2 mod q in split form.
sub dot_reduce {
    my ($x0, $x1, $r2hi, $r2lo, $t0) = @_;
    $code .= <<___;
    vpmullw     %ymm13, $x0, $t0                # m = low16(x0) * q^-1, high word 0
    vpmaddwd    %ymm12, $t0, $t0                # m*q (exact int32)
    vpsubd      $t0, $x0, $x0                   # x0 - m*q, low word is 0
    vpsrld      \$16, $x0, $x0                  # even outputs in the low words
    vpmullw     %ymm13, $x1, $t0                # same reduction for the odd sums
    vpmaddwd    %ymm12, $t0, $t0
    vpsubd      $t0, $x1, $x1                   # odd outputs * R^-1 in the high words
    vpmullw     $r2lo, $x1, $t0                 # M(x1, R^2): remove the R^-1
    vpmulhw     $r2hi, $x1, $x1
    vpmulhw     %ymm15, $t0, $t0
    vpsubw      $t0, $x1, $x1                   # low words stay 0
    vpor        $x1, $x0, $x0                   # re-interleave (even, odd) pairs
    vpsraw      \$15, $x0, $t0                  # canonicalize: +q if < 0
    vpand       %ymm15, $t0, $t0
    vpaddw      $t0, $x0, $x0
___
}

# Emit the body of ml_kem_ntt_dot_avx2 ($acc=0) or ml_kem_ntt_dot_add_avx2 ($acc=1).
# rdi = out, rsi = lhs, rdx = lhs stride (scalars), rcx = rhs, r8 = count.
# Each outer iteration produces 32 output coefficients (two ymm halves).
sub emit_ml_kem_dot {
    my ($acc) = @_;
    my $sfx = $acc ? "_add" : "";

    $code .= <<___;
    vpbroadcastw   q(%rip), %ymm15                      # q (words)
    vmovdqa        dot_swap_mask(%rip), %ymm14          # word swap within dwords
    vpbroadcastd   dot_qinv(%rip), %ymm13               # [q^-1 mod 2^16, 0]
    vpbroadcastd   q(%rip), %ymm12                      # [q, 0]
    shl            \$9, %rdx                            # lhs stride in bytes
    shl            \$9, %r8                             # count * sizeof(scalar)
    lea            kDotMulHi(%rip), %r10                # c table (lo at +512)
    lea            kDotMulHi+512(%rip), %r11            # end of the hi table

.align 32
.Lntt_dot${sfx}_coeff_loop:
    vmovdqu        (%r10), %ymm8                        # c hi, coefficients 0..15
    vmovdqu        32(%r10), %ymm9                      # c hi, coefficients 16..31
    vmovdqu        512(%r10), %ymm10                    # c lo, coefficients 0..15
    vmovdqu        512+32(%r10), %ymm11                 # c lo, coefficients 16..31
    vpxor          %ymm0, %ymm0, %ymm0                  # even sums, 0..15
    vpxor          %ymm1, %ymm1, %ymm1                  # even sums, 16..31
    vpxor          %ymm2, %ymm2, %ymm2                  # odd sums, 0..15
    vpxor          %ymm3, %ymm3, %ymm3                  # odd sums, 16..31
    mov            %rsi, %r9                            # lhs term pointer
    xor            %eax, %eax                           # rhs term offset

.align 32
.Lntt_dot${sfx}_poly_loop:
    vmovdqu        (%r9), %ymm4
___
    &dot_term("%ymm4", "(%rcx,%rax)", "%ymm8", "%ymm10",
              "%ymm0", "%ymm2", "%ymm5", "%ymm6", "%ymm7");
    $code .= <<___;
    vmovdqu        32(%r9), %ymm4
___
    &dot_term("%ymm4", "32(%rcx,%rax)", "%ymm9", "%ymm11",
              "%ymm1", "%ymm3", "%ymm5", "%ymm6", "%ymm7");
    $code .= <<___;
    add            %rdx, %r9
    add            \$512, %rax
    cmp            %r8, %rax
    jb             .Lntt_dot${sfx}_poly_loop

    vpbroadcastw   dot_r2_hi(%rip), %ymm8               # (R^2 mod q) hi
    vpbroadcastw   dot_r2_lo(%rip), %ymm10              # (R^2 mod q) lo
___
    &dot_reduce("%ymm0", "%ymm2", "%ymm8", "%ymm10", "%ymm4");
    &dot_reduce("%ymm1", "%ymm3", "%ymm8", "%ymm10", "%ymm4");

    if ($acc) {
        # out = reduce_once(out + product), both canonical
        $code .= <<___;
    vpaddw         (%rdi), %ymm0, %ymm0
    vpaddw         32(%rdi), %ymm1, %ymm1
___
        reduce_once("%ymm0", "%ymm15", "%ymm4", "%ymm5");
        reduce_once("%ymm1", "%ymm15", "%ymm4", "%ymm5");
    }

    $code .= <<___;
    vmovdqu        %ymm0, (%rdi)
    vmovdqu        %ymm1, 32(%rdi)
    add            \$64, %rdi
    add            \$64, %rsi
    add            \$64, %rcx
    add            \$64, %r10
    cmp            %r11, %r10
    jne            .Lntt_dot${sfx}_coeff_loop
___
}

# Per-level byte offsets into a zeta table.
#
# All four zeta tables (kNTTZetaLo, kNTTZetaHi, kInvNTTZetaLo, kInvNTTZetaHi)
# share one identical level-7..level-1 layout: three 256-byte pre-expanded
# blocks (levels 7/6/5) followed by the packed level-4..level-1 slices
# (16/8/4/2 bytes). Because the layout is common, a single set of offsets
# addresses any level of any table as "<table_base> + $ZETA_L<n>".
#
# For best portability these are plain perl (package) variables.
$ZETA_BLK = 256;                    # bytes per pre-expanded block, 128 words (levels 7/6/5)
$ZETA_L7  = 0;                      # level-7 slice (len=2, idx 64..127 fwd)
$ZETA_L6  = "$ZETA_L7+$ZETA_BLK";   # level-6 slice (len=4)
$ZETA_L5  = "$ZETA_L6+$ZETA_BLK";   # level-5 slice (len=8)
$ZETA_L4  = "$ZETA_L5+$ZETA_BLK";   # level-4 slice (8 words)
$ZETA_L3  = "$ZETA_L4+16";          # level-3 slice (4 words)
$ZETA_L2  = "$ZETA_L3+8";           # level-2 slice (2 words)
$ZETA_L1  = "$ZETA_L2+4";           # level-1 slice (1 word)

$code .= <<'___';
.text


###############################################################################
# ml_kem_ntt_avx2
#
# Prototype:
#   void ml_kem_ntt_avx2(scalar *s)
#
# Arguments (System V AMD64 ABI; Windows x64 rcx is remapped to
# rdi by the x86_64-xlate.pl, so the names below apply to both):
#   rdi: pointer to scalar coefficients (256 x uint16_t)
#
# Returns:
#   none (in-place transform)
#
# Description:
#   Performs the forward ML-KEM NTT using AVX2 and 16-bit Montgomery
#   arithmetic. The routine applies all butterfly layers and then
#   normalizes coefficients back to [0, q-1].
# 
# Forward level schedule and twiddle usage:
#   emit_ml_kem_ntt_level1_3 (called twice, off=0 and off=32):
#     levels 1-3 (len 128/64/32), zeta indices 1..7.
#   emit_ml_kem_ntt_level4_7 (called twice, off=0 and off=128*2):
#     levels 4-7 (len 16/8/4/2), zeta indices 8..127; followed by final
#     normalization to [0, q-1].
#
# Why two zeta tables (Hi/Lo):
#   For each twiddle zeta[i], we store a pair used by the 16-bit Montgomery
#   multiply sequence:
#       t = mulhi(x, zeta_hi) - mulhi(mullo(x, zeta_lo), q)
#   where:
#       zeta_hi = centered signed twiddle in [-q/2, q/2]
#       zeta_lo = int16((-zeta_hi * 3327) mod 2^16)
#   and 3327 = (-q^{-1}) mod 2^16 for q = 3329.
###############################################################################
.align 32
.globl ml_kem_ntt_avx2
.type  ml_kem_ntt_avx2,@function,1
# Forward NTT over 256 ML-KEM coefficients using 16-bit Montgomery arithmetic.
# Applies 7 butterfly layers and a final normalization to [0, q-1].
ml_kem_ntt_avx2:
.cfi_startproc
    endbranch
    push           %r14
    push           %r15
___

# Windows x64: preserve the caller's callee-saved xmm6..15 (low 128 bits).
$code .= <<'___' if $win64;
    sub            $160, %rsp
    vmovdqu        %xmm6, 0(%rsp)
    vmovdqu        %xmm7, 16(%rsp)
    vmovdqu        %xmm8, 32(%rsp)
    vmovdqu        %xmm9, 48(%rsp)
    vmovdqu        %xmm10, 64(%rsp)
    vmovdqu        %xmm11, 80(%rsp)
    vmovdqu        %xmm12, 96(%rsp)
    vmovdqu        %xmm13, 112(%rsp)
    vmovdqu        %xmm14, 128(%rsp)
    vmovdqu        %xmm15, 144(%rsp)
___

$code .= <<'___';
    # arg0/%rdi -> base pointer, set by xlate on both ABIs
    vpbroadcastw   q(%rip), %ymm15                      # [q q q ...] for Montgomery fixup

    lea            kNTTZetaLo(%rip), %r14               # zeta lo slice
    lea            kNTTZetaHi(%rip), %r15               # zeta hi slice
___

&emit_ml_kem_ntt_level1_3(0);
&emit_ml_kem_ntt_level1_3(16*2);

&emit_ml_kem_ntt_level4_7(0*2, 1);
&emit_ml_kem_ntt_level4_7(128*2, 0);

$code .= <<'___';
    vzeroall                                            # clear all vector regs (secret scrub)
___

# Windows x64: restore xmm6..15 after the scrub, so the caller's values return.
$code .= <<'___' if $win64;
    vmovdqu        0(%rsp), %xmm6
    vmovdqu        16(%rsp), %xmm7
    vmovdqu        32(%rsp), %xmm8
    vmovdqu        48(%rsp), %xmm9
    vmovdqu        64(%rsp), %xmm10
    vmovdqu        80(%rsp), %xmm11
    vmovdqu        96(%rsp), %xmm12
    vmovdqu        112(%rsp), %xmm13
    vmovdqu        128(%rsp), %xmm14
    vmovdqu        144(%rsp), %xmm15
    add            $160, %rsp
___

$code .= <<'___';
    pop            %r15
    pop            %r14
    ret
.cfi_endproc
.size    ml_kem_ntt_avx2, .-ml_kem_ntt_avx2

###############################################################################
# ml_kem_inverse_ntt_avx2
#
# Prototype:
#   void ml_kem_inverse_ntt_avx2(scalar *s)
#
# Arguments (System V AMD64 ABI; Windows x64 rcx is remapped to
# rdi by the x86_64-xlate.pl, so the names below apply to both):
#   rdi: pointer to scalar coefficients (256 x uint16_t)
#
# Returns:
#   none (in-place transform)
#
# Description:
#   Performs the inverse ML-KEM NTT using AVX2 and 16-bit Montgomery
#   arithmetic. It applies inverse butterflies, multiplies by the inverse
#   degree factor, and normalizes to canonical [0, q-1] coefficients.
#
# Inverse level schedule and twiddle usage:
#   emit_ml_kem_intt_level7_4 (called twice, off=0 and off=128*2):
#     levels 7-4 (len 2/4/8/16), zeta indices 0..126 (pre-expanded blocks).
#   emit_ml_kem_intt_level3_1 (called twice, off=0 and off=32):
#     levels 3-1 (len 32/64/128), zeta indices 112..126 (packed slices);
#     fused 1/n scaling and canonicalization to [0, q-1].
#
# Hi/Lo table semantics are identical to forward NTT:
#   zeta_hi[i] = centered signed twiddle
#   zeta_lo[i] = int16((-zeta_hi[i] * 3327) mod 2^16)
# The butterflies consume both with Montgomery multiply in 16-bit lanes.
###############################################################################
.align 32
.globl ml_kem_inverse_ntt_avx2
.type  ml_kem_inverse_ntt_avx2,@function,1
# Inverse NTT over 256 ML-KEM coefficients using 16-bit Montgomery arithmetic.
# Applies inverse butterflies, scales by inverse degree, and normalizes to [0, q-1].
ml_kem_inverse_ntt_avx2:
.cfi_startproc
    endbranch
    push           %r14
    push           %r15
___

# Windows x64: preserve the caller's callee-saved xmm6..15 (low 128 bits).
$code .= <<'___' if $win64;
    sub            $160, %rsp
    vmovdqu        %xmm6, 0(%rsp)
    vmovdqu        %xmm7, 16(%rsp)
    vmovdqu        %xmm8, 32(%rsp)
    vmovdqu        %xmm9, 48(%rsp)
    vmovdqu        %xmm10, 64(%rsp)
    vmovdqu        %xmm11, 80(%rsp)
    vmovdqu        %xmm12, 96(%rsp)
    vmovdqu        %xmm13, 112(%rsp)
    vmovdqu        %xmm14, 128(%rsp)
    vmovdqu        %xmm15, 144(%rsp)
___

$code .= <<'___';
    # arg0/rdi -> base pointer, set by xlate on both ABIs
    vpbroadcastw   q(%rip), %ymm15                      # [q q q ...] for Montgomery fixup

    lea            kInvNTTZetaLo(%rip), %r14            # inverse zeta lo table base
    lea            kInvNTTZetaHi(%rip), %r15            # inverse zeta hi table base
___

&emit_ml_kem_intt_level7_4(0*2, 1);
&emit_ml_kem_intt_level7_4(128*2, 0);

&emit_ml_kem_intt_level3_1(0);
&emit_ml_kem_intt_level3_1(16*2);

$code .= <<'___';
    vzeroall                                            # clear all vector regs (secret scrub)
___

# Windows x64: restore xmm6..15 after the scrub, so the caller's values return.
$code .= <<'___' if $win64;
    vmovdqu        0(%rsp), %xmm6
    vmovdqu        16(%rsp), %xmm7
    vmovdqu        32(%rsp), %xmm8
    vmovdqu        48(%rsp), %xmm9
    vmovdqu        64(%rsp), %xmm10
    vmovdqu        80(%rsp), %xmm11
    vmovdqu        96(%rsp), %xmm12
    vmovdqu        112(%rsp), %xmm13
    vmovdqu        128(%rsp), %xmm14
    vmovdqu        144(%rsp), %xmm15
    add            $160, %rsp
___

$code .= <<'___';
    pop            %r15
    pop            %r14
    ret
.cfi_endproc
.size    ml_kem_inverse_ntt_avx2, .-ml_kem_inverse_ntt_avx2

###############################################################################
# ml_kem_add_avx2
#
# Prototype:
#   void ml_kem_add_avx2(scalar *lhs, const scalar *rhs)
#
# Arguments (System V AMD64 ABI; Windows x64 rcx/rdx/r8 are remapped to
# rdi/rsi/rdx by the x86_64-xlate.pl prologue, so the names below apply to both):
#   rdi: lhs (updated in place)
#   rsi: rhs
#
# Returns:
#   none
#
# Description:
#   Vectorized modular addition: lhs[i] = reduce_once(lhs[i] + rhs[i])
#   for all 256 coefficients.
###############################################################################
.align 32
.globl ml_kem_add_avx2
.type  ml_kem_add_avx2,@function,2
# Vectorized modular add: lhs[i] = reduce_once(lhs[i] + rhs[i]) for 256 coefficients.
ml_kem_add_avx2:
.cfi_startproc
    endbranch
    vpbroadcastw   q(%rip), %ymm0
___

for (my $off = 0; $off <= (256*2 - 32); $off += 32) {
    my $lhs = $off == 0 ? "(%rdi)" : "${off}(%rdi)";
    my $rhs = $off == 0 ? "(%rsi)" : "${off}(%rsi)";
    $code .= <<"___";
    vmovdqu         $lhs, %ymm4                           # lhs chunk @ +$off
    vpaddw          $rhs, %ymm4, %ymm1                    # lhs + rhs, in [0, 2q)
___
    reduce_once("%ymm1", "%ymm0", "%ymm2", "%ymm3");
    $code .= <<"___";
    vmovdqu         %ymm1, $lhs                           # store chunk
___
}

$code .= <<'___';
    vpxor          %xmm0, %xmm0, %xmm0                  # scrub working regs (no xmm6..15 used here)
    vpxor          %xmm1, %xmm1, %xmm1
    vpxor          %xmm2, %xmm2, %xmm2
    vpxor          %xmm3, %xmm3, %xmm3
    vpxor          %xmm4, %xmm4, %xmm4
    vzeroupper
    ret
.cfi_endproc
.size    ml_kem_add_avx2, .-ml_kem_add_avx2

###############################################################################
# ml_kem_sub_avx2
#
# Prototype:
#   void ml_kem_sub_avx2(scalar *lhs, const scalar *rhs)
#
# Arguments (System V AMD64 ABI; Windows x64 rcx/rdx/r8 are remapped to
# rdi/rsi/rdx by the x86_64-xlate.pl prologue, so the names below apply to both):
#   rdi: lhs (updated in place)
#   rsi: rhs
#
# Returns:
#   none
#
# Description:
#   Vectorized modular subtraction: lhs[i] = reduce_once(lhs[i] + q - rhs[i])
#   for all 256 coefficients.
#
#   Note: this does not call the shared reduce_once helper.  The raw difference
#   lhs-rhs already IS the reduce_once candidate (value-q), so the helper's
#   vpsubw would be redundant work; the loop reuses that difference directly and
#   only computes difference+q for the negative case, saving one instruction per
#   chunk.
###############################################################################
.align 32
.globl ml_kem_sub_avx2
.type  ml_kem_sub_avx2,@function,2
# Vectorized modular subtract: lhs[i] = reduce_once(lhs[i] + q - rhs[i]) for 256 coefficients.
ml_kem_sub_avx2:
.cfi_startproc
    endbranch
    vpbroadcastw   q(%rip), %ymm0
___

for (my $off = 0; $off <= (256*2 - 32); $off += 32) {
    my $lhs = $off == 0 ? "(%rdi)" : "${off}(%rdi)";
    my $rhs = $off == 0 ? "(%rsi)" : "${off}(%rsi)";
    $code .= <<"___";
    vmovdqu         $lhs, %ymm4                           # lhs chunk @ +$off
    vpsubw          $rhs, %ymm4, %ymm1                    # lhs - rhs, in (-q, q)
    vpaddw          %ymm0, %ymm1, %ymm2                   # + q -> (0, 2q)
    vpsraw          \$15, %ymm1, %ymm3                    # mask from sign of the difference
    vpblendvb       %ymm3, %ymm2, %ymm1, %ymm1            # fused reduce_once (see note)
    vmovdqu         %ymm1, $lhs                           # store chunk
___
}

$code .= <<'___';
    vpxor          %xmm0, %xmm0, %xmm0                  # scrub working regs (no xmm6..15 used here)
    vpxor          %xmm1, %xmm1, %xmm1
    vpxor          %xmm2, %xmm2, %xmm2
    vpxor          %xmm3, %xmm3, %xmm3
    vpxor          %xmm4, %xmm4, %xmm4
    vzeroupper
    ret
.cfi_endproc
.size    ml_kem_sub_avx2, .-ml_kem_sub_avx2

###############################################################################
# ml_kem_ntt_dot_avx2
#
# Prototype:
#   void ml_kem_ntt_dot_avx2(scalar *out, const scalar *lhs, size_t lhs_stride,
#                            const scalar *rhs, size_t count)
#
# Arguments (System V AMD64 ABI; Windows x64 rcx/rdx/r8/r9/stack are remapped to
# rdi/rsi/rdx/rcx/r8 by the x86_64-xlate.pl prologue, so the names below apply
# to both):
#   rdi: out (canonical result; must not overlap the inputs)
#   rsi: lhs, first of count polynomials spaced lhs_stride scalars apart
#   rdx: lhs_stride, in scalars
#   rcx: rhs, count consecutive polynomials
#   r8:  count, number of terms (1 or more)
#
# Returns:
#   none
#
# Description:
#   Vectorized NTT-domain row dot product: with (*) the pointwise multiply of
#   the 128 (even, odd) coefficient pairs as elements of GF(q)[X]/(X^2 - zeta_i),
#       out = sum_j lhs[j * lhs_stride] (*) rhs[j],   j = 0..count-1
#   accumulating in 32-bit lanes and reducing once per output coefficient.
#   Equivalent to repeated poly_mult_base() / poly_mult_add_base() calls.
###############################################################################
.align 32
.globl ml_kem_ntt_dot_avx2
.type  ml_kem_ntt_dot_avx2,@function,5
ml_kem_ntt_dot_avx2:
.cfi_startproc
    endbranch
___

# Windows x64: preserve the caller's callee-saved xmm6..15 (low 128 bits).
$code .= <<'___' if $win64;
    sub            $160, %rsp
    vmovdqu        %xmm6, 0(%rsp)
    vmovdqu        %xmm7, 16(%rsp)
    vmovdqu        %xmm8, 32(%rsp)
    vmovdqu        %xmm9, 48(%rsp)
    vmovdqu        %xmm10, 64(%rsp)
    vmovdqu        %xmm11, 80(%rsp)
    vmovdqu        %xmm12, 96(%rsp)
    vmovdqu        %xmm13, 112(%rsp)
    vmovdqu        %xmm14, 128(%rsp)
    vmovdqu        %xmm15, 144(%rsp)
___

&emit_ml_kem_dot(0);

$code .= <<'___';
    vzeroall                                            # clear all vector regs (secret scrub)
___

# Windows x64: restore xmm6..15 after the scrub, so the caller's values return.
$code .= <<'___' if $win64;
    vmovdqu        0(%rsp), %xmm6
    vmovdqu        16(%rsp), %xmm7
    vmovdqu        32(%rsp), %xmm8
    vmovdqu        48(%rsp), %xmm9
    vmovdqu        64(%rsp), %xmm10
    vmovdqu        80(%rsp), %xmm11
    vmovdqu        96(%rsp), %xmm12
    vmovdqu        112(%rsp), %xmm13
    vmovdqu        128(%rsp), %xmm14
    vmovdqu        144(%rsp), %xmm15
    add            $160, %rsp
___

$code .= <<'___';
    ret
.cfi_endproc
.size    ml_kem_ntt_dot_avx2, .-ml_kem_ntt_dot_avx2

###############################################################################
# ml_kem_ntt_dot_add_avx2
#
# Prototype:
#   void ml_kem_ntt_dot_add_avx2(scalar *out, const scalar *lhs, size_t lhs_stride,
#                                const scalar *rhs, size_t count)
#
# Arguments (System V AMD64 ABI; Windows x64 rcx/rdx/r8/r9/stack are remapped to
# rdi/rsi/rdx/rcx/r8 by the x86_64-xlate.pl prologue, so the names below apply
# to both):
#   rdi: out (accumulated in place; must not overlap the inputs)
#   rsi: lhs, first of count polynomials spaced lhs_stride scalars apart
#   rdx: lhs_stride, in scalars
#   rcx: rhs, count consecutive polynomials
#   r8:  count, number of terms (1 or more)
#
# Returns:
#   none
#
# Description:
#   As ml_kem_ntt_dot_avx2, but accumulates the row dot product into out:
#       out[k] = reduce_once(out[k] + (sum_j lhs[j * lhs_stride] (*) rhs[j])[k]).
###############################################################################
.align 32
.globl ml_kem_ntt_dot_add_avx2
.type  ml_kem_ntt_dot_add_avx2,@function,5
ml_kem_ntt_dot_add_avx2:
.cfi_startproc
    endbranch
___

# Windows x64: preserve the caller's callee-saved xmm6..15 (low 128 bits).
$code .= <<'___' if $win64;
    sub            $160, %rsp
    vmovdqu        %xmm6, 0(%rsp)
    vmovdqu        %xmm7, 16(%rsp)
    vmovdqu        %xmm8, 32(%rsp)
    vmovdqu        %xmm9, 48(%rsp)
    vmovdqu        %xmm10, 64(%rsp)
    vmovdqu        %xmm11, 80(%rsp)
    vmovdqu        %xmm12, 96(%rsp)
    vmovdqu        %xmm13, 112(%rsp)
    vmovdqu        %xmm14, 128(%rsp)
    vmovdqu        %xmm15, 144(%rsp)
___

&emit_ml_kem_dot(1);

$code .= <<'___';
    vzeroall                                            # clear all vector regs (secret scrub)
___

# Windows x64: restore xmm6..15 after the scrub, so the caller's values return.
$code .= <<'___' if $win64;
    vmovdqu        0(%rsp), %xmm6
    vmovdqu        16(%rsp), %xmm7
    vmovdqu        32(%rsp), %xmm8
    vmovdqu        48(%rsp), %xmm9
    vmovdqu        64(%rsp), %xmm10
    vmovdqu        80(%rsp), %xmm11
    vmovdqu        96(%rsp), %xmm12
    vmovdqu        112(%rsp), %xmm13
    vmovdqu        128(%rsp), %xmm14
    vmovdqu        144(%rsp), %xmm15
    add            $160, %rsp
___

$code .= <<'___';
    ret
.cfi_endproc
.size    ml_kem_ntt_dot_add_avx2, .-ml_kem_ntt_dot_add_avx2

# Twiddle tables for forward and inverse ML-KEM NTT in Montgomery form.
#
# How these tables were built:
#   1) Start from the ML-KEM reference twiddle streams in *butterfly-consumption
#      order* (not natural exponent order).
#   2) Convert each twiddle zeta to centered signed form:
#         zeta_hi = zeta <= q/2 ? zeta : zeta - q
#   3) Build paired Montgomery helper:
#         zeta_lo = int16((-zeta_hi * 3327) mod 2^16),
#      where 3327 = (-q^{-1}) mod 2^16 and q = 3329.
#   4) Store zeta_hi/zeta_lo at the same index i so each butterfly can load
#      the pair directly and compute Montgomery products branch-free.
#
# Forward table index usage:
#   idx 1..15   -> len 128/64/32/16 (Block A..D / levels 1..4, kNTTZeta{Lo,Hi})
#   idx 16..31  -> len 8            (Block E / level 5, kNTTZeta{Lo,Hi}5)
#   idx 32..63  -> len 4            (Block F / level 6, kNTTZeta{Lo,Hi}6)
#   idx 64..127 -> len 2            (Block G / level 7, kNTTZeta{Lo,Hi}7)
#
# Inverse table index usage:
#   idx 0..63   -> len 2            (Block A / level 7, kInvNTTZeta{Lo,Hi}7)
#   idx 64..95  -> len 4            (Block B / level 6, kInvNTTZeta{Lo,Hi}6)
#   idx 96..111 -> len 8            (Block C / level 5, kInvNTTZeta{Lo,Hi}5)
#   idx 112..126-> len 16/32/64/128 (Block D..G / levels 4..1, kInvNTTZeta{Lo,Hi})
.section    .rodata

.align 32
.type    kInvNTTZetaLo, @object
kInvNTTZetaLo:

# Inverse level 7 (len=2, zeta indices 0..63).  Each 32-byte block holds eight
# consecutive zetas, each broadcast across 2 lanes, matching the len=2 butterfly.
# --- kInvNTTZetaLo7  (base + ZETA_L7) ---
.value  -23132, -23132,  17422, 17422,  -7756, -7756, -23998, -23998
.value   20257,  20257, -28644,-28644,  23860, 23860, -31636, -31636
.value   17442,  17442, -10906,-10906, -23210,-23210,  22502, 22502
.value   20198,  20198,   7934,  7934,  21498, 21498, -10335,-10335
.value  -14469, -14469, -16989,-16989,  11044, 11044, -24214,-24214
.value   14903,  14903, -10946,-10946,   6280,  6280,  20927, 20927
.value   32384,  32384, -24391,-24391, -15355,-15355,   7382,  7382
.value   -2146,  -2146, -25435,-25435, -20297,-20297,  31183, 31183
.value   12619,  12619,   5276,  5276, -19529,-19529,  14430, 14430
.value  -18525, -18525, -17560,-17560, -20100,-20100,  18486, 18486
.value  -12639, -12639,  28762, 28762,  18741, 18741, -29175,-29175
.value  -30317, -30317, -10631,-10631,  32502, 32502, -32010,-32010
.value   -5493,  -5493,  -6182, -6182, -23092,-23092,  14883, 14883
.value    4587,   4587,   -945,  -945, -13131,-13131,  27738, 27738
.value   21655,  21655, -20494,-20494,  14233, 14233,  32227, 32227
.value  -13387, -13387,  11477, 11477, -11182,-11182,    335,   335

# Inverse level 6 (len=4, zeta indices 64..95).  Each 32-byte block holds four
# consecutive zetas, each broadcast across 4 lanes, matching the len=4 butterfly.
# --- kInvNTTZetaLo6  (base + ZETA_L6) ---
.value   17915, 17915, 17915, 17915,  24155, 24155, 24155, 24155
.value   -4311, -4311, -4311, -4311, -16832,-16832,-16832,-16832
.value   12757, 12757, 12757, 12757,  29156, 29156, 29156, 29156
.value  -14017,-14017,-14017,-14017, -13426,-13426,-13426,-13426
.value  -18249,-18249,-18249,-18249,  30199, 30199, 30199, 30199
.value   -9075, -9075, -9075, -9075,  28309, 28309, 28309, 28309
.value    8898,  8898,  8898,  8898,  15887, 15887, 15887, 15887
.value   28250, 28250, 28250, 28250, -19883,-19883,-19883,-19883
.value  -27837,-27837,-27837,-27837,  25986, 25986, 25986, 25986
.value     650,   650,   650,   650,  -9134, -9134, -9134, -9134
.value   12442, 12442, 12442, 12442, -16064,-16064,-16064,-16064
.value  -26616,-26616,-26616,-26616,  12796, 12796, 12796, 12796
.value  -25080,-25080,-25080,-25080, -20710,-20710,-20710,-20710
.value  -20179,-20179,-20179,-20179,  23565, 23565, 23565, 23565
.value  -30967,-30967,-30967,-30967,  -1496, -1496, -1496, -1496
.value    6516,  6516,  6516,  6516,   5689,  5689,  5689,  5689

# Level-5 pre-expanded twiddles (zeta indices 96..111).
# Each 32-byte block holds zeta[idx] broadcast across the low 8 lanes and
# zeta[idx+1] broadcast across the high 8 lanes, matching the [group0|group1]
# layout consumed by the len=8 inverse butterfly.
# --- kInvNTTZetaLo5  (base + ZETA_L5) ---
.value   16163, 16163, 16163, 16163, 16163, 16163, 16163, 16163
.value  -26675,-26675,-26675,-26675,-26675,-26675,-26675,-26675
.value   -8859, -8859, -8859, -8859, -8859, -8859, -8859, -8859
.value  -18426,-18426,-18426,-18426,-18426,-18426,-18426,-18426
.value   -8800, -8800, -8800, -8800, -8800, -8800, -8800, -8800
.value   10532, 10532, 10532, 10532, 10532, 10532, 10532, 10532
.value  -24313,-24313,-24313,-24313,-24313,-24313,-24313,-24313
.value   28073, 28073, 28073, 28073, 28073, 28073, 28073, 28073
.value   26242, 26242, 26242, 26242, 26242, 26242, 26242, 26242
.value  -21438,-21438,-21438,-21438,-21438,-21438,-21438,-21438
.value    1102,  1102,  1102,  1102,  1102,  1102,  1102,  1102
.value   -5571, -5571, -5571, -5571, -5571, -5571, -5571, -5571
.value   29057, 29057, 29057, 29057, 29057, 29057, 29057, 29057
.value   26360, 26360, 26360, 26360, 26360, 26360, 26360, 26360
.value  -17363,-17363,-17363,-17363,-17363,-17363,-17363,-17363
.value    5827,  5827,  5827,  5827,  5827,  5827,  5827,  5827

# Inverse zetas for levels 4..1 (former zeta indices 112..126). Each level
# reads its own contiguous slice starting at byte offset 0 through the
# per-level labels below, so no index-bias arithmetic is needed.
# --- kInvNTTZetaLo4  (base + ZETA_L4) ---
.value  -31164,   11202,   -1358,  -10690,   15690,    3799,  -27758,   20907
# --- kInvNTTZetaLo3  (base + ZETA_L3) ---
.value   16694,  -28191,   12402,  -13525
# --- kInvNTTZetaLo2  (base + ZETA_L2) ---
.value    -787,  -14745
# --- kInvNTTZetaLo1  (base + ZETA_L1) ---
.value  -31498

.size    kInvNTTZetaLo, . - kInvNTTZetaLo

.align 32
.type    kInvNTTZetaHi, @object
kInvNTTZetaHi:
# Inverse level 7 (len=2, zeta indices 0..63); layout matches kInvNTTZetaLo7.
# --- kInvNTTZetaHi7  (base + ZETA_L7) ---
.value   -1628, -1628,  -1522, -1522,   1460,  1460,   -958,  -958
.value    -991,  -991,   -996,  -996,    308,   308,    108,   108
.value    -478,  -478,    870,   870,    854,   854,   1510,  1510
.value    -794,  -794,   1278,  1278,   1530,  1530,   1185,  1185
.value    1659,  1659,   1187,  1187,   -220,  -220,    874,   874
.value    1335,  1335,  -1218, -1218,    136,   136,   1215,  1215
.value    -384,  -384,   1465,  1465,   1285,  1285,  -1322, -1322
.value    -610,  -610,   -603,  -603,  -1097, -1097,   -817,  -817
.value      75,    75,    156,   156,   -329,  -329,   -418,  -418
.value    -349,  -349,    872,   872,   -644,  -644,   1590,  1590
.value   -1119, -1119,    602,   602,  -1483, -1483,    777,   777
.value     147,   147,  -1159, -1159,   -778,  -778,    246,   246
.value   -1653, -1653,  -1574, -1574,    460,   460,    291,   291
.value     235,   235,   -177,  -177,   -587,  -587,   -422,  -422
.value    -105,  -105,  -1550, -1550,   -871,  -871,   1251,  1251
.value    -843,  -843,   -555,  -555,   -430,  -430,   1103,  1103

# Inverse level 6 (len=4, zeta indices 64..95); layout matches kInvNTTZetaLo6.
# --- kInvNTTZetaHi6  (base + ZETA_L6) ---
.value    1275,  1275,  1275,  1275,   -677,  -677,  -677,  -677
.value    1065,  1065,  1065,  1065,   -448,  -448,  -448,  -448
.value     725,   725,   725,   725,   1508,  1508,  1508,  1508
.value    -961,  -961,  -961,  -961,    398,   398,   398,   398
.value     951,   951,   951,   951,    247,   247,   247,   247
.value    1421,  1421,  1421,  1421,   -107,  -107,  -107,  -107
.value    -830,  -830,  -830,  -830,    271,   271,   271,   271
.value      90,    90,    90,    90,    853,   853,   853,   853
.value   -1469, -1469, -1469, -1469,   -126,  -126,  -126,  -126
.value    1162,  1162,  1162,  1162,   1618,  1618,  1618,  1618
.value     666,   666,   666,   666,    320,   320,   320,   320
.value       8,     8,     8,     8,   -516,  -516,  -516,  -516
.value    1544,  1544,  1544,  1544,    282,   282,   282,   282
.value   -1491, -1491, -1491, -1491,   1293,  1293,  1293,  1293
.value   -1015, -1015, -1015, -1015,    552,   552,   552,   552
.value    -652,  -652,  -652,  -652,  -1223, -1223, -1223, -1223

# Level-5 pre-expanded twiddles (zeta indices 96..111).
# Each 32-byte block holds zeta[idx] broadcast across the low 8 lanes and
# zeta[idx+1] broadcast across the high 8 lanes, matching the [group0|group1]
# layout consumed by the len=8 inverse butterfly.
# --- kInvNTTZetaHi5  (base + ZETA_L5) ---
.value    1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571
.value     205,   205,   205,   205,   205,   205,   205,   205
.value    -411,  -411,  -411,  -411,  -411,  -411,  -411,  -411
.value    1542,  1542,  1542,  1542,  1542,  1542,  1542,  1542
.value    -608,  -608,  -608,  -608,  -608,  -608,  -608,  -608
.value    -732,  -732,  -732,  -732,  -732,  -732,  -732,  -732
.value   -1017, -1017, -1017, -1017, -1017, -1017, -1017, -1017
.value     681,   681,   681,   681,   681,   681,   681,   681
.value     130,   130,   130,   130,   130,   130,   130,   130
.value    1602,  1602,  1602,  1602,  1602,  1602,  1602,  1602
.value   -1458, -1458, -1458, -1458, -1458, -1458, -1458, -1458
.value     829,   829,   829,   829,   829,   829,   829,   829
.value    -383,  -383,  -383,  -383,  -383,  -383,  -383,  -383
.value    -264,  -264,  -264,  -264,  -264,  -264,  -264,  -264
.value    1325,  1325,  1325,  1325,  1325,  1325,  1325,  1325
.value    -573,  -573,  -573,  -573,  -573,  -573,  -573,  -573

# Inverse zetas for levels 4..1 (former zeta indices 112..126). Each level
# reads its own contiguous slice starting at byte offset 0 through the
# per-level labels below, so no index-bias arithmetic is needed.
# --- kInvNTTZetaHi4  (base + ZETA_L4) ---
.value   -1468,    1474,    1202,    -962,    -182,   -1577,    -622,     171
# --- kInvNTTZetaHi3  (base + ZETA_L3) ---
.value    -202,    -287,   -1422,   -1493
# --- kInvNTTZetaHi2  (base + ZETA_L2) ---
.value    1517,     359
# --- kInvNTTZetaHi1  (base + ZETA_L1) ---
.value     758
.size    kInvNTTZetaHi, . - kInvNTTZetaHi

.align 32
.type    kNTTZetaLo, @object
kNTTZetaLo:
# Level-7 pre-expanded twiddles (zeta indices 64..127, len=2 groups). Each
# 32-byte block holds eight consecutive zetas, each broadcast across 2 lanes.
# --- kNTTZetaLo7  (base + ZETA_L7) ---
.value    -335,   -335,  11182,  11182, -11477, -11477,  13387,  13387
.value  -32227, -32227, -14233, -14233,  20494,  20494, -21655, -21655
.value  -27738, -27738,  13131,  13131,    945,    945,  -4587,  -4587
.value  -14883, -14883,  23092,  23092,   6182,   6182,   5493,   5493
.value   32010,  32010, -32502, -32502,  10631,  10631,  30317,  30317
.value   29175,  29175, -18741, -18741, -28762, -28762,  12639,  12639
.value  -18486, -18486,  20100,  20100,  17560,  17560,  18525,  18525
.value  -14430, -14430,  19529,  19529,  -5276,  -5276, -12619, -12619
.value  -31183, -31183,  20297,  20297,  25435,  25435,   2146,   2146
.value   -7382,  -7382,  15355,  15355,  24391,  24391, -32384, -32384
.value  -20927, -20927,  -6280,  -6280,  10946,  10946, -14903, -14903
.value   24214,  24214, -11044, -11044,  16989,  16989,  14469,  14469
.value   10335,  10335, -21498, -21498,  -7934,  -7934, -20198, -20198
.value  -22502, -22502,  23210,  23210,  10906,  10906, -17442, -17442
.value   31636,  31636, -23860, -23860,  28644,  28644, -20257, -20257
.value   23998,  23998,   7756,   7756, -17422, -17422,  23132,  23132

# Level-6 pre-expanded twiddles (zeta indices 32..63, len=4 groups). Each
# 32-byte block holds four consecutive zetas, each broadcast across 4 lanes.
# --- kNTTZetaLo6  (base + ZETA_L6) ---
.value   -5689,  -5689,  -5689,  -5689,  -6516,  -6516,  -6516,  -6516
.value    1496,   1496,   1496,   1496,  30967,  30967,  30967,  30967
.value  -23565, -23565, -23565, -23565,  20179,  20179,  20179,  20179
.value   20710,  20710,  20710,  20710,  25080,  25080,  25080,  25080
.value  -12796, -12796, -12796, -12796,  26616,  26616,  26616,  26616
.value   16064,  16064,  16064,  16064, -12442, -12442, -12442, -12442
.value    9134,   9134,   9134,   9134,   -650,   -650,   -650,   -650
.value  -25986, -25986, -25986, -25986,  27837,  27837,  27837,  27837
.value   19883,  19883,  19883,  19883, -28250, -28250, -28250, -28250
.value  -15887, -15887, -15887, -15887,  -8898,  -8898,  -8898,  -8898
.value  -28309, -28309, -28309, -28309,   9075,   9075,   9075,   9075
.value  -30199, -30199, -30199, -30199,  18249,  18249,  18249,  18249
.value   13426,  13426,  13426,  13426,  14017,  14017,  14017,  14017
.value  -29156, -29156, -29156, -29156, -12757, -12757, -12757, -12757
.value   16832,  16832,  16832,  16832,   4311,   4311,   4311,   4311
.value  -24155, -24155, -24155, -24155, -17915, -17915, -17915, -17915


# Level-5 pre-expanded twiddles (zeta indices 16..31, len=8 groups). Each
# 32-byte block holds zeta[idx] across the low 8 lanes and zeta[idx+1] across
# the high 8 lanes.
# --- kNTTZetaLo5  (base + ZETA_L5) ---
.value   -5827,  -5827,  -5827,  -5827,  -5827,  -5827,  -5827,  -5827
.value   17363,  17363,  17363,  17363,  17363,  17363,  17363,  17363
.value  -26360, -26360, -26360, -26360, -26360, -26360, -26360, -26360
.value  -29057, -29057, -29057, -29057, -29057, -29057, -29057, -29057
.value    5571,   5571,   5571,   5571,   5571,   5571,   5571,   5571
.value   -1102,  -1102,  -1102,  -1102,  -1102,  -1102,  -1102,  -1102
.value   21438,  21438,  21438,  21438,  21438,  21438,  21438,  21438
.value  -26242, -26242, -26242, -26242, -26242, -26242, -26242, -26242
.value  -28073, -28073, -28073, -28073, -28073, -28073, -28073, -28073
.value   24313,  24313,  24313,  24313,  24313,  24313,  24313,  24313
.value  -10532, -10532, -10532, -10532, -10532, -10532, -10532, -10532
.value    8800,   8800,   8800,   8800,   8800,   8800,   8800,   8800
.value   18426,  18426,  18426,  18426,  18426,  18426,  18426,  18426
.value    8859,   8859,   8859,   8859,   8859,   8859,   8859,   8859
.value   26675,  26675,  26675,  26675,  26675,  26675,  26675,  26675
.value  -16163, -16163, -16163, -16163, -16163, -16163, -16163, -16163

# Forward zetas for levels 1..4 (zeta indices 1..15). Levels 5..7 use the
# per-level pre-expanded tables kNTTZeta{Lo,Hi}5/6/7 above. Each level reads
# its own contiguous slice starting at byte offset 0 through the per-level
# labels, so no index-bias arithmetic is needed.
# --- kNTTZetaLo4  (base + ZETA_L4) ---
.value  -20907,  27758,  -3799, -15690,  10690,   1358, -11202,  31164
# --- kNTTZetaLo3  (base + ZETA_L3) ---
.value   13525, -12402,  28191, -16694
# --- kNTTZetaLo2  (base + ZETA_L2) ---
.value   14745,    787
# --- kNTTZetaLo1  (base + ZETA_L1) ---
.value   31498
.size    kNTTZetaLo, . - kNTTZetaLo

.align 32
.type    kNTTZetaHi, @object
kNTTZetaHi:
# Level-7 pre-expanded twiddles (zeta indices 64..127, len=2 groups). Each
# 32-byte block holds eight consecutive zetas, each broadcast across 2 lanes.
# --- kNTTZetaHi7  (base + ZETA_L7) ---
.value   -1103,  -1103,    430,    430,    555,    555,    843,    843
.value   -1251,  -1251,    871,    871,   1550,   1550,    105,    105
.value     422,    422,    587,    587,    177,    177,   -235,   -235
.value    -291,   -291,   -460,   -460,   1574,   1574,   1653,   1653
.value    -246,   -246,    778,    778,   1159,   1159,   -147,   -147
.value    -777,   -777,   1483,   1483,   -602,   -602,   1119,   1119
.value   -1590,  -1590,    644,    644,   -872,   -872,    349,    349
.value     418,    418,    329,    329,   -156,   -156,    -75,    -75
.value     817,    817,   1097,   1097,    603,    603,    610,    610
.value    1322,   1322,  -1285,  -1285,  -1465,  -1465,    384,    384
.value   -1215,  -1215,   -136,   -136,   1218,   1218,  -1335,  -1335
.value    -874,   -874,    220,    220,  -1187,  -1187,  -1659,  -1659
.value   -1185,  -1185,  -1530,  -1530,  -1278,  -1278,    794,    794
.value   -1510,  -1510,   -854,   -854,   -870,   -870,    478,    478
.value    -108,   -108,   -308,   -308,    996,    996,    991,    991
.value     958,    958,  -1460,  -1460,   1522,   1522,   1628,   1628

# Level-6 pre-expanded twiddles (zeta indices 32..63, len=4 groups). Each
# 32-byte block holds four consecutive zetas, each broadcast across 4 lanes.
# --- kNTTZetaHi6  (base + ZETA_L6) ---
.value    1223,   1223,   1223,   1223,    652,    652,    652,    652
.value    -552,   -552,   -552,   -552,   1015,   1015,   1015,   1015
.value   -1293,  -1293,  -1293,  -1293,   1491,   1491,   1491,   1491
.value    -282,   -282,   -282,   -282,  -1544,  -1544,  -1544,  -1544
.value     516,    516,    516,    516,     -8,     -8,     -8,     -8
.value    -320,   -320,   -320,   -320,   -666,   -666,   -666,   -666
.value   -1618,  -1618,  -1618,  -1618,  -1162,  -1162,  -1162,  -1162
.value     126,    126,    126,    126,   1469,   1469,   1469,   1469
.value    -853,   -853,   -853,   -853,    -90,    -90,    -90,    -90
.value    -271,   -271,   -271,   -271,    830,    830,    830,    830
.value     107,    107,    107,    107,  -1421,  -1421,  -1421,  -1421
.value    -247,   -247,   -247,   -247,   -951,   -951,   -951,   -951
.value    -398,   -398,   -398,   -398,    961,    961,    961,    961
.value   -1508,  -1508,  -1508,  -1508,   -725,   -725,   -725,   -725
.value     448,    448,    448,    448,  -1065,  -1065,  -1065,  -1065
.value     677,    677,    677,    677,  -1275,  -1275,  -1275,  -1275

# Level-5 pre-expanded twiddles (zeta indices 16..31, len=8 groups). Each
# 32-byte block holds zeta[idx] across the low 8 lanes and zeta[idx+1] across
# the high 8 lanes.
# --- kNTTZetaHi5  (base + ZETA_L5) ---
.value     573,    573,    573,    573,    573,    573,    573,    573
.value   -1325,  -1325,  -1325,  -1325,  -1325,  -1325,  -1325,  -1325
.value     264,    264,    264,    264,    264,    264,    264,    264
.value     383,    383,    383,    383,    383,    383,    383,    383
.value    -829,   -829,   -829,   -829,   -829,   -829,   -829,   -829
.value    1458,   1458,   1458,   1458,   1458,   1458,   1458,   1458
.value   -1602,  -1602,  -1602,  -1602,  -1602,  -1602,  -1602,  -1602
.value    -130,   -130,   -130,   -130,   -130,   -130,   -130,   -130
.value    -681,   -681,   -681,   -681,   -681,   -681,   -681,   -681
.value    1017,   1017,   1017,   1017,   1017,   1017,   1017,   1017
.value     732,    732,    732,    732,    732,    732,    732,    732
.value     608,    608,    608,    608,    608,    608,    608,    608
.value   -1542,  -1542,  -1542,  -1542,  -1542,  -1542,  -1542,  -1542
.value     411,    411,    411,    411,    411,    411,    411,    411
.value    -205,   -205,   -205,   -205,   -205,   -205,   -205,   -205
.value   -1571,  -1571,  -1571,  -1571,  -1571,  -1571,  -1571,  -1571

# Forward zetas for levels 1..4 (zeta indices 1..15). Levels 5..7 use the
# per-level pre-expanded tables kNTTZeta{Lo,Hi}5/6/7 above. Each level reads
# its own contiguous slice starting at byte offset 0 through the per-level
# labels, so no index-bias arithmetic is needed.
# --- kNTTZetaHi4  (base + ZETA_L4) ---
.value    -171,    622,   1577,    182,    962,  -1202,  -1474,   1468
# --- kNTTZetaHi3  (base + ZETA_L3) ---
.value    1493,   1422,    287,    202
# --- kNTTZetaHi2  (base + ZETA_L2) ---
.value    -359,  -1517
# --- kNTTZetaHi1  (base + ZETA_L1) ---
.value    -758
.size    kNTTZetaHi, . - kNTTZetaHi


# Row dot product constants: per coefficient pair i, c = [R^2 mod q,
# kModRoots[i] * R^2 mod q] in centered/Montgomery split form, natural order.
# M(lhs, c) yields [l0*R, l1*zeta_i*R] for ml_kem_ntt_dot_avx2 /
# ml_kem_ntt_dot_add_avx2. kDotMulLo must directly follow kDotMulHi (512 bytes).
.align 32
.type    kDotMulHi, @object
kDotMulHi:
    .value   1353,   -302,   1353,    302,   1353,    495,   1353,   -495
    .value   1353,   -174,   1353,    174,   1353,  -1236,   1353,   1236
    .value   1353,   1076,   1353,  -1076,   1353,   -507,   1353,    507
    .value   1353,   -306,   1353,    306,   1353,    237,   1353,   -237
    .value   1353,  -1140,   1353,   1140,   1353,   -292,   1353,    292
    .value   1353,   1636,   1353,  -1636,   1353,  -1006,   1353,   1006
    .value   1353,    865,   1353,   -865,   1353,    864,   1353,   -864
    .value   1353,   1270,   1353,  -1270,   1353,  -1310,   1353,   1310
    .value   1353,    491,   1353,   -491,   1353,     44,   1353,    -44
    .value   1353,  -1569,   1353,   1569,   1353,    334,   1353,   -334
    .value   1353,  -1088,   1353,   1088,   1353,   -267,   1353,    267
    .value   1353,   -693,   1353,    693,   1353,    243,   1353,   -243
    .value   1353,  -1211,   1353,   1211,   1353,    122,   1353,   -122
    .value   1353,   1551,   1353,  -1551,   1353,  -1495,   1353,   1495
    .value   1353,   -293,   1353,    293,   1353,   -589,   1353,    589
    .value   1353,   -257,   1353,    257,   1353,  -1596,   1353,   1596
    .value   1353,   -724,   1353,    724,   1353,    -92,   1353,     92
    .value   1353,   -351,   1353,    351,   1353,  -1001,   1353,   1001
    .value   1353,   1367,   1353,  -1367,   1353,    -47,   1353,     47
    .value   1353,   1449,   1353,  -1449,   1353,  -1416,   1353,   1416
    .value   1353,    111,   1353,   -111,   1353,  -1163,   1353,   1163
    .value   1353,     86,   1353,    -86,   1353,  -1111,   1353,   1111
    .value   1353,    310,   1353,   -310,   1353,     21,   1353,    -21
    .value   1353,    840,   1353,   -840,   1353,    916,   1353,   -916
    .value   1353,  -1248,   1353,   1248,   1353,   -600,   1353,    600
    .value   1353,   -697,   1353,    697,   1353,    -15,   1353,     15
    .value   1353,  -1506,   1353,   1506,   1353,   -596,   1353,    596
    .value   1353,   -537,   1353,    537,   1353,    318,   1353,   -318
    .value   1353,   -434,   1353,    434,   1353,  -1361,   1353,   1361
    .value   1353,  -1176,   1353,   1176,   1353,    715,   1353,   -715
    .value   1353,  -1452,   1353,   1452,   1353,   -442,   1353,    442
    .value   1353,  -1035,   1353,   1035,   1353,   1487,   1353,  -1487
.size    kDotMulHi, . - kDotMulHi

.type    kDotMulLo, @object
kDotMulLo:
    .value  20553,  21714,  20553, -21714,  20553,  -8465,  20553,   8465
    .value  20553, -10926,  20553,  10926,  20553, -16596,  20553,  16596
    .value  20553,  24628,  20553, -24628,  20553, -17147,  20553,  17147
    .value  20553, -30514,  20553,  30514,  20553,  -2067,  20553,   2067
    .value  20553,  -8308,  20553,   8308,  20553, -11556,  20553,  11556
    .value  20553,  -3484,  20553,   3484,  20553,   4626,  20553,  -4626
    .value  20553,   5729,  20553,  -5729,  20553,   9056,  20553,  -9056
    .value  20553, -30986,  20553,  30986,  20553, -32542,  20553,  32542
    .value  20553,   4843,  20553,  -4843,  20553, -15316,  20553,  15316
    .value  20553, -22817,  20553,  22817,  20553,   2894,  20553,  -2894
    .value  20553,  15296,  20553, -15296,  20553, -29195,  20553,  29195
    .value  20553,  11851,  20553, -11851,  20553, -22029,  20553,  22029
    .value  20553,  31301,  20553, -31301,  20553, -12678,  20553,  12678
    .value  20553,  17167,  20553, -17167,  20553,  -6871,  20553,   6871
    .value  20553,  -8229,  20553,   8229,  20553,  -6477,  20553,   6477
    .value  20553,   3071,  20553,  -3071,  20553,   1476,  20553,  -1476
    .value  20553, -16084,  20553,  16084,  20553, -21596,  20553,  21596
    .value  20553, -11871,  20553,  11871,  20553, -12009,  20553,  12009
    .value  20553, -26025,  20553,  26025,  20553,  25297,  20553, -25297
    .value  20553,  28841,  20553, -28841,  20553,  -7560,  20553,   7560
    .value  20553,  23919,  20553, -23919,  20553,   2677,  20553,  -2677
    .value  20553, -23978,  20553,  23978,  20553,  26281,  20553, -26281
    .value  20553,  17206,  20553, -17206,  20553,  -4331,  20553,   4331
    .value  20553,  23368,  20553, -23368,  20553,  32660,  20553, -32660
    .value  20553,  23328,  20553, -23328,  20553,  30120,  20553, -30120
    .value  20553,  25159,  20553, -25159,  20553, -15631,  20553,  15631
    .value  20553,  29726,  20553, -29726,  20553,  16812,  20553, -16812
    .value  20553,  17127,  20553, -17127,  20553,  -9410,  20553,   9410
    .value  20553,   2126,  20553,  -2126,  20553,   6063,  20553,  -6063
    .value  20553, -19608,  20553,  19608,  20553, -19509,  20553,  19509
    .value  20553, -18860,  20553,  18860,  20553,  28742,  20553, -28742
    .value  20553, -29963,  20553,  29963,  20553, -32049,  20553,  32049
.size    kDotMulLo, . - kDotMulLo

# vpshufb mask swapping the two words of every dword: [r0, r1] -> [r1, r0].
.align 32
dot_swap_mask:
    .byte 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13
    .byte 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13


# Scalar broadcast constants.  Barrett-reduction values (ntt_reduce) are read as
# dwords via vpbroadcastd; the modulus q is stored as a .long so the same label
# feeds both the dword (qhat*q) and word (Montgomery/add/sub/dot) broadcasts.

# 5*q = 16645; dword bias in ntt_reduce that lifts a signed lane non-negative
# before the reciprocal multiply (the extra 5q are removed by qhat*q).
.align 4
bias_5q:
    .long 16645

# floor(2^24 / q) = 5039; dword fixed-point reciprocal of q for the Barrett
# quotient estimate qhat = (x * 5039) >> 24 in ntt_reduce.
.align 4
floor2p24_div_q:
    .long 5039

# -q = -3329; broadcast as words for the final conditional subtract (reduce_once)
# at the tail of ntt_reduce and the inverse-NTT levels.
.align 4
minus_q:
    .long -3329

# Modulus q = 3329.  Broadcast as dwords for qhat*q (Barrett) and as words for
# Montgomery fixups and the add/sub/dot reduce_once steps.
.align 4
q:
    .long 3329

# Inverse-degree Montgomery factor for the inverse NTT's 1/n scaling: its value
# is n^-1 * R mod q = 512 (= 2^9).  Read as a word and used as the vpmulhw hi
# operand in intt_scale_reduce (FIPS 203 Alg 10 final 1/n multiply).
.align 4
inv_deg_factor:
    .long 512

# q^-1 mod 2^16 = 62209 in the low word of a dword (high word 0), read via
# vpbroadcastd for the 32-bit Montgomery reduction in ml_kem_ntt_dot_avx2.
.align 4
dot_qinv:
    .long 62209

# R2 = (2^16)^2 mod q in the Montgomery split form: hi = R^2 mod q (centered),
# lo = int16(hi * q^-1 mod 2^16).
.align 2
dot_r2_hi:
    .value 1353
.align 2
dot_r2_lo:
    .value 20553

.section    .note.GNU-stack,"",@progbits

___


print $code;
close STDOUT or die "error closing STDOUT: $!";
