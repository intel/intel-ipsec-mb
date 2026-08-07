#! /usr/bin/env perl
#
# Copyright (c) 2026, Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Intel Corporation nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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

# Check for AVX2 support in assembler
if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1` =~ /GNU assembler version ([2-9]\.[0-9]+)/) {
  $avx2 = ($1 >= 2.22);
}

if (!$avx2
  && $win64
  && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/)
  && `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)(?:\.([0-9]+))?/)
{
  $avx2 = ($1 >= 2.10);
}

if (!$avx2 && `$ENV{CC} -v 2>&1` =~ /((?:clang|LLVM) version|.*based on LLVM) ([0-9]+\.[0-9]+)/) {
    $avx2 = ($2>=3.3); # minimal tested version for AVX2
}

open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT = *OUT;

my $code = '';

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
# Used by ml_kem_add and ml_kem_mul_add. ntt_reduce and intt_scale_reduce
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

# NTT-domain pointwise multiplication ("basemul") helpers.
#
# After the forward NTT, the 256 coefficients are arranged as 128 independent
# elements of GF(q)[X]/(X^2 - zeta_i). Each element is stored as a consecutive
# coefficient pair:
#
#     (l0, l1) = (lhs[2i], lhs[2i+1])
#     (r0, r1) = (rhs[2i], rhs[2i+1])
#
# The product of two such elements is:
#
#     out[2i]   = l0*r0 + l1*r1*zeta_i   (mod q)
#     out[2i+1] = l0*r1 + l1*r0          (mod q)
#
# This matches scalar_mult() and scalar_mult_add() in ml_kem.c
# (roots = kModRoots).
#
# The implementation uses signed 16-bit Montgomery multiplication
#
#     M(a,b) = a*b*R^-1 mod q,  R = 2^16
#
# so all intermediate values remain in 16-bit lanes and no 32-bit widening
# is required:
#
#     A = M(l0,r0)
#     B = M(l1,r1)
#     C = M(B, zeta*R mod q)
#     D = M(l0,r1)
#     E = M(l1,r0)
#
#     out[2i]   = M(A+C, R^2 mod q)
#     out[2i+1] = M(D+E, R^2 mod q)
#
# The outputs are in (-q, q). A final conditional add of q converts negative
# values to the canonical range [0, q-1].
#
# kBaseMulZeta{Hi,Lo} contains zeta*R mod q, and basemul_R2{Hi,Lo} contains
# R^2 mod q. Both use the same split representation as the twiddle-factor
# tables.
#
# Fixed register assignments:
#     ymm15 = q
#     ymm14 = -q^-1 mod 2^16
#     ymm13 = R2 high part
#     ymm12 = R2 low part
#     ymm11 = 0x0000ffff dword mask (even/odd split)

# Signed Montgomery multiply of two live vectors: $out = $a * $b * R^-1 mod q.
sub bm_fqmul {
    my ($a, $b, $out, $t) = @_;
    $code .= <<___;
    vpmullw     $b, $a, $t                      # lo = a*b (mod 2^16)
    vpmulhw     $b, $a, $out                    # hi = high(a*b)
    vpmullw     %ymm14, $t, $t                  # t  = lo * (-q^-1)
    vpmulhw     %ymm15, $t, $t                  # t  = high(t * q)
    vpsubw      $t, $out, $out                  # out = hi - t
___
}

# Signed Montgomery multiply of a live vector by a table constant (hi/lo pair):
# $out = $data * chi * R^-1 mod q.  $out may alias $data.
sub bm_mconst {
    my ($data, $chi, $clo, $out, $t) = @_;
    $code .= <<___;
    vpmullw     $clo, $data, $t                 # t  = clo*data (mod 2^16)
    vpmulhw     $chi, $data, $out               # out = high(chi*data)
    vpmulhw     %ymm15, $t, $t                  # t  = high(q * t)
    vpsubw      $t, $out, $out                  # out = out - t
___
}

# Split 16 consecutive (even, odd) 16-bit pairs held in ($a, $b) into an
# even-lane vector $even and an odd-lane vector $odd, both in natural pair order.
sub bm_deint {
    my ($a, $b, $even, $odd, $t0, $t1) = @_;
    $code .= <<___;
    vpand       %ymm11, $a, $t0                 # even words of $a
    vpand       %ymm11, $b, $t1                 # even words of $b
    vpackusdw   $t1, $t0, $even
    vpermq      \$0xd8, $even, $even            # -> natural pair order
    vpsrld      \$16, $a, $t0                   # odd words of $a
    vpsrld      \$16, $b, $t1                   # odd words of $b
    vpackusdw   $t1, $t0, $odd
    vpermq      \$0xd8, $odd, $odd
___
}

# Emit the body of ml_kem_mul_avx2 ($acc=0) or ml_kem_mul_add_avx2 ($acc=1).
# rdi = out, rsi = lhs, rdx = rhs.
sub emit_ml_kem_basemul {
    my ($acc) = @_;

    $code .= <<___;
    vpbroadcastw   q(%rip), %ymm15                      # q
    vpbroadcastw   basemul_qinv(%rip), %ymm14           # -q^-1 mod 2^16
    vpbroadcastw   basemul_R2hi(%rip), %ymm13           # (R^2 mod q) hi
    vpbroadcastw   basemul_R2lo(%rip), %ymm12           # (R^2 mod q) lo
    vpcmpeqd       %ymm11, %ymm11, %ymm11               # 0xffffffff
    vpsrld         \$16, %ymm11, %ymm11                 # 0x0000ffff dword mask
    lea            kBaseMulZetaHi(%rip), %r15
    lea            kBaseMulZetaLo(%rip), %r14
___

    for my $it (0 .. 7) {
        my $bo = $it * 64;                               # byte offset: 32 words
        my $zo = $it * 32;                               # zeta byte offset: 16 words
        my ($p0, $p1) = ($it * 16, $it * 16 + 15);

        $code .= "    # ---- pairs $p0..$p1 ----\n";
        $code .= <<___;
    vmovdqu        $bo(%rsi), %ymm6
    vmovdqu        $bo+32(%rsi), %ymm7
___
        &bm_deint("%ymm6", "%ymm7", "%ymm0", "%ymm1", "%ymm8", "%ymm9");
        $code .= <<___;
    vmovdqu        $bo(%rdx), %ymm6
    vmovdqu        $bo+32(%rdx), %ymm7
___
        &bm_deint("%ymm6", "%ymm7", "%ymm2", "%ymm3", "%ymm8", "%ymm9");
        $code .= <<___;
    vmovdqu        $zo(%r15), %ymm4                     # zeta*R hi
    vmovdqu        $zo(%r14), %ymm5                     # zeta*R lo
___
        &bm_fqmul("%ymm0", "%ymm2", "%ymm6", "%ymm10");   # A = M(l0,r0)
        &bm_fqmul("%ymm1", "%ymm3", "%ymm7", "%ymm10");   # B = M(l1,r1)
        &bm_mconst("%ymm7", "%ymm4", "%ymm5", "%ymm8", "%ymm10"); # C = M(B,zeta)
        $code .= "    vpaddw      %ymm8, %ymm6, %ymm6            # o0raw = A + C\n";
        &bm_fqmul("%ymm0", "%ymm3", "%ymm7", "%ymm10");   # D = M(l0,r1)
        &bm_fqmul("%ymm1", "%ymm2", "%ymm8", "%ymm10");   # E = M(l1,r0)
        $code .= "    vpaddw      %ymm8, %ymm7, %ymm7            # o1raw = D + E\n";
        &bm_mconst("%ymm6", "%ymm13", "%ymm12", "%ymm6", "%ymm10"); # o0 = M(o0raw,R2)
        &bm_mconst("%ymm7", "%ymm13", "%ymm12", "%ymm7", "%ymm10"); # o1 = M(o1raw,R2)
        $code .= <<___;
    vpsraw         \$15, %ymm6, %ymm8                   # canonicalize o0: +q if < 0
    vpand          %ymm15, %ymm8, %ymm8
    vpaddw         %ymm8, %ymm6, %ymm6
    vpsraw         \$15, %ymm7, %ymm8                   # canonicalize o1: +q if < 0
    vpand          %ymm15, %ymm8, %ymm8
    vpaddw         %ymm8, %ymm7, %ymm7
    vpunpcklwd     %ymm7, %ymm6, %ymm8                  # re-interleave even/odd
    vpunpckhwd     %ymm7, %ymm6, %ymm9
    vperm2i128     \$0x20, %ymm9, %ymm8, %ymm6          # pairs $p0..${\($p0+7)}
    vperm2i128     \$0x31, %ymm9, %ymm8, %ymm7          # pairs ${\($p0+8)}..$p1
___
        if (!$acc) {
            $code .= <<___;
    vmovdqu        %ymm6, $bo(%rdi)
    vmovdqu        %ymm7, $bo+32(%rdi)
___
        } else {
            # out = reduce_once(out + product), product in [0, q-1]
            $code .= <<___;
    vmovdqu        $bo(%rdi), %ymm8
    vpaddw         %ymm6, %ymm8, %ymm8                  # out + prod, in [0, 2q)
___
            reduce_once("%ymm8", "%ymm15", "%ymm9", "%ymm10");
            $code .= <<___;
    vmovdqu        %ymm8, $bo(%rdi)
    vmovdqu        $bo+32(%rdi), %ymm8
    vpaddw         %ymm7, %ymm8, %ymm8
___
            reduce_once("%ymm8", "%ymm15", "%ymm9", "%ymm10");
            $code .= <<___;
    vmovdqu        %ymm8, $bo+32(%rdi)
___
        }
    }
}

if ($avx2>0) {{{

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
.extern OPENSSL_ia32cap_P

###############################################################################
# ml_kem_ntt_avx2_capable
#
# Prototype:
#   int ml_kem_ntt_avx2_capable(void)
#
# Arguments:
#   none
#
# Returns:
#   1 if AVX2 is available, 0 otherwise.
#
# Description:
#   Reads OPENSSL_ia32cap_P[2] and checks bit 5 (AVX2 capability).
#   This is used by ML-KEM runtime dispatch to select AVX2 assembly paths.
###############################################################################
.align 4
.globl ml_kem_ntt_avx2_capable
.type  ml_kem_ntt_avx2_capable,@abi-omnipotent
# Detect AVX2 support from OPENSSL_ia32cap_P (bit 5 in capability word 2).
# Returns 1 when AVX2 is available, otherwise 0.
ml_kem_ntt_avx2_capable:
.cfi_startproc
    endbranch
    mov            OPENSSL_ia32cap_P+8(%rip), %eax
    shr            $5, %eax
    and            $1, %eax
    ret
.cfi_endproc
.size    ml_kem_ntt_avx2_capable, .-ml_kem_ntt_avx2_capable


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
# ml_kem_mul_avx2
#
# Prototype:
#   void ml_kem_mul_avx2(scalar *out, const scalar *lhs, const scalar *rhs)
#
# Arguments (System V AMD64 ABI; Windows x64 rcx/rdx/r8 are remapped to
# rdi/rsi/rdx by the x86_64-xlate.pl prologue, so the names below apply to both):
#   rdi: out (must not overlap the inputs)
#   rsi: lhs
#   rdx: rhs
#
# Returns:
#   none
#
# Description:
#   Vectorized NTT-domain pointwise multiply ("basemul"): for each of the 128
#   (even, odd) coefficient pairs interpreted as an element of
#   GF(q)[X]/(X^2 - zeta_i),
#       out[2i]   = lhs0*rhs0 + lhs1*rhs1*zeta_i   (mod q)
#       out[2i+1] = lhs0*rhs1 + lhs1*rhs0          (mod q)
#   using 16-bit Montgomery arithmetic.  Equivalent to scalar_mult().
###############################################################################
.align 32
.globl ml_kem_mul_avx2
.type  ml_kem_mul_avx2,@function,3
ml_kem_mul_avx2:
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

&emit_ml_kem_basemul(0);

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
.size    ml_kem_mul_avx2, .-ml_kem_mul_avx2

###############################################################################
# ml_kem_mul_add_avx2
#
# Prototype:
#   void ml_kem_mul_add_avx2(scalar *out, const scalar *lhs, const scalar *rhs)
#
# Arguments (System V AMD64 ABI; Windows x64 rcx/rdx/r8 are remapped to
# rdi/rsi/rdx by the x86_64-xlate.pl prologue, so the names below apply to both):
#   rdi: out (accumulated in place; must not overlap the inputs)
#   rsi: lhs
#   rdx: rhs
#
# Returns:
#   none
#
# Description:
#   As ml_kem_mul_avx2, but accumulates the product into out:
#       out[k] = reduce_once(out[k] + (lhs (*) rhs)[k]).
#   Equivalent to scalar_mult_add().
###############################################################################
.align 32
.globl ml_kem_mul_add_avx2
.type  ml_kem_mul_add_avx2,@function,3
ml_kem_mul_add_avx2:
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

&emit_ml_kem_basemul(1);

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
.size    ml_kem_mul_add_avx2, .-ml_kem_mul_add_avx2

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
.short  -23132, -23132,  17422, 17422,  -7756, -7756, -23998, -23998
.short   20257,  20257, -28644,-28644,  23860, 23860, -31636, -31636
.short   17442,  17442, -10906,-10906, -23210,-23210,  22502, 22502
.short   20198,  20198,   7934,  7934,  21498, 21498, -10335,-10335
.short  -14469, -14469, -16989,-16989,  11044, 11044, -24214,-24214
.short   14903,  14903, -10946,-10946,   6280,  6280,  20927, 20927
.short   32384,  32384, -24391,-24391, -15355,-15355,   7382,  7382
.short   -2146,  -2146, -25435,-25435, -20297,-20297,  31183, 31183
.short   12619,  12619,   5276,  5276, -19529,-19529,  14430, 14430
.short  -18525, -18525, -17560,-17560, -20100,-20100,  18486, 18486
.short  -12639, -12639,  28762, 28762,  18741, 18741, -29175,-29175
.short  -30317, -30317, -10631,-10631,  32502, 32502, -32010,-32010
.short   -5493,  -5493,  -6182, -6182, -23092,-23092,  14883, 14883
.short    4587,   4587,   -945,  -945, -13131,-13131,  27738, 27738
.short   21655,  21655, -20494,-20494,  14233, 14233,  32227, 32227
.short  -13387, -13387,  11477, 11477, -11182,-11182,    335,   335

# Inverse level 6 (len=4, zeta indices 64..95).  Each 32-byte block holds four
# consecutive zetas, each broadcast across 4 lanes, matching the len=4 butterfly.
# --- kInvNTTZetaLo6  (base + ZETA_L6) ---
.short   17915, 17915, 17915, 17915,  24155, 24155, 24155, 24155
.short   -4311, -4311, -4311, -4311, -16832,-16832,-16832,-16832
.short   12757, 12757, 12757, 12757,  29156, 29156, 29156, 29156
.short  -14017,-14017,-14017,-14017, -13426,-13426,-13426,-13426
.short  -18249,-18249,-18249,-18249,  30199, 30199, 30199, 30199
.short   -9075, -9075, -9075, -9075,  28309, 28309, 28309, 28309
.short    8898,  8898,  8898,  8898,  15887, 15887, 15887, 15887
.short   28250, 28250, 28250, 28250, -19883,-19883,-19883,-19883
.short  -27837,-27837,-27837,-27837,  25986, 25986, 25986, 25986
.short     650,   650,   650,   650,  -9134, -9134, -9134, -9134
.short   12442, 12442, 12442, 12442, -16064,-16064,-16064,-16064
.short  -26616,-26616,-26616,-26616,  12796, 12796, 12796, 12796
.short  -25080,-25080,-25080,-25080, -20710,-20710,-20710,-20710
.short  -20179,-20179,-20179,-20179,  23565, 23565, 23565, 23565
.short  -30967,-30967,-30967,-30967,  -1496, -1496, -1496, -1496
.short    6516,  6516,  6516,  6516,   5689,  5689,  5689,  5689

# Level-5 pre-expanded twiddles (zeta indices 96..111).
# Each 32-byte block holds zeta[idx] broadcast across the low 8 lanes and
# zeta[idx+1] broadcast across the high 8 lanes, matching the [group0|group1]
# layout consumed by the len=8 inverse butterfly.
# --- kInvNTTZetaLo5  (base + ZETA_L5) ---
.short   16163, 16163, 16163, 16163, 16163, 16163, 16163, 16163
.short  -26675,-26675,-26675,-26675,-26675,-26675,-26675,-26675
.short   -8859, -8859, -8859, -8859, -8859, -8859, -8859, -8859
.short  -18426,-18426,-18426,-18426,-18426,-18426,-18426,-18426
.short   -8800, -8800, -8800, -8800, -8800, -8800, -8800, -8800
.short   10532, 10532, 10532, 10532, 10532, 10532, 10532, 10532
.short  -24313,-24313,-24313,-24313,-24313,-24313,-24313,-24313
.short   28073, 28073, 28073, 28073, 28073, 28073, 28073, 28073
.short   26242, 26242, 26242, 26242, 26242, 26242, 26242, 26242
.short  -21438,-21438,-21438,-21438,-21438,-21438,-21438,-21438
.short    1102,  1102,  1102,  1102,  1102,  1102,  1102,  1102
.short   -5571, -5571, -5571, -5571, -5571, -5571, -5571, -5571
.short   29057, 29057, 29057, 29057, 29057, 29057, 29057, 29057
.short   26360, 26360, 26360, 26360, 26360, 26360, 26360, 26360
.short  -17363,-17363,-17363,-17363,-17363,-17363,-17363,-17363
.short    5827,  5827,  5827,  5827,  5827,  5827,  5827,  5827

# Inverse zetas for levels 4..1 (former zeta indices 112..126). Each level
# reads its own contiguous slice starting at byte offset 0 through the
# per-level labels below, so no index-bias arithmetic is needed.
# --- kInvNTTZetaLo4  (base + ZETA_L4) ---
.short  -31164,   11202,   -1358,  -10690,   15690,    3799,  -27758,   20907
# --- kInvNTTZetaLo3  (base + ZETA_L3) ---
.short   16694,  -28191,   12402,  -13525
# --- kInvNTTZetaLo2  (base + ZETA_L2) ---
.short    -787,  -14745
# --- kInvNTTZetaLo1  (base + ZETA_L1) ---
.short  -31498

.size    kInvNTTZetaLo, . - kInvNTTZetaLo

.align 32
.type    kInvNTTZetaHi, @object
kInvNTTZetaHi:
# Inverse level 7 (len=2, zeta indices 0..63); layout matches kInvNTTZetaLo7.
# --- kInvNTTZetaHi7  (base + ZETA_L7) ---
.short   -1628, -1628,  -1522, -1522,   1460,  1460,   -958,  -958
.short    -991,  -991,   -996,  -996,    308,   308,    108,   108
.short    -478,  -478,    870,   870,    854,   854,   1510,  1510
.short    -794,  -794,   1278,  1278,   1530,  1530,   1185,  1185
.short    1659,  1659,   1187,  1187,   -220,  -220,    874,   874
.short    1335,  1335,  -1218, -1218,    136,   136,   1215,  1215
.short    -384,  -384,   1465,  1465,   1285,  1285,  -1322, -1322
.short    -610,  -610,   -603,  -603,  -1097, -1097,   -817,  -817
.short      75,    75,    156,   156,   -329,  -329,   -418,  -418
.short    -349,  -349,    872,   872,   -644,  -644,   1590,  1590
.short   -1119, -1119,    602,   602,  -1483, -1483,    777,   777
.short     147,   147,  -1159, -1159,   -778,  -778,    246,   246
.short   -1653, -1653,  -1574, -1574,    460,   460,    291,   291
.short     235,   235,   -177,  -177,   -587,  -587,   -422,  -422
.short    -105,  -105,  -1550, -1550,   -871,  -871,   1251,  1251
.short    -843,  -843,   -555,  -555,   -430,  -430,   1103,  1103

# Inverse level 6 (len=4, zeta indices 64..95); layout matches kInvNTTZetaLo6.
# --- kInvNTTZetaHi6  (base + ZETA_L6) ---
.short    1275,  1275,  1275,  1275,   -677,  -677,  -677,  -677
.short    1065,  1065,  1065,  1065,   -448,  -448,  -448,  -448
.short     725,   725,   725,   725,   1508,  1508,  1508,  1508
.short    -961,  -961,  -961,  -961,    398,   398,   398,   398
.short     951,   951,   951,   951,    247,   247,   247,   247
.short    1421,  1421,  1421,  1421,   -107,  -107,  -107,  -107
.short    -830,  -830,  -830,  -830,    271,   271,   271,   271
.short      90,    90,    90,    90,    853,   853,   853,   853
.short   -1469, -1469, -1469, -1469,   -126,  -126,  -126,  -126
.short    1162,  1162,  1162,  1162,   1618,  1618,  1618,  1618
.short     666,   666,   666,   666,    320,   320,   320,   320
.short       8,     8,     8,     8,   -516,  -516,  -516,  -516
.short    1544,  1544,  1544,  1544,    282,   282,   282,   282
.short   -1491, -1491, -1491, -1491,   1293,  1293,  1293,  1293
.short   -1015, -1015, -1015, -1015,    552,   552,   552,   552
.short    -652,  -652,  -652,  -652,  -1223, -1223, -1223, -1223

# Level-5 pre-expanded twiddles (zeta indices 96..111).
# Each 32-byte block holds zeta[idx] broadcast across the low 8 lanes and
# zeta[idx+1] broadcast across the high 8 lanes, matching the [group0|group1]
# layout consumed by the len=8 inverse butterfly.
# --- kInvNTTZetaHi5  (base + ZETA_L5) ---
.short    1571,  1571,  1571,  1571,  1571,  1571,  1571,  1571
.short     205,   205,   205,   205,   205,   205,   205,   205
.short    -411,  -411,  -411,  -411,  -411,  -411,  -411,  -411
.short    1542,  1542,  1542,  1542,  1542,  1542,  1542,  1542
.short    -608,  -608,  -608,  -608,  -608,  -608,  -608,  -608
.short    -732,  -732,  -732,  -732,  -732,  -732,  -732,  -732
.short   -1017, -1017, -1017, -1017, -1017, -1017, -1017, -1017
.short     681,   681,   681,   681,   681,   681,   681,   681
.short     130,   130,   130,   130,   130,   130,   130,   130
.short    1602,  1602,  1602,  1602,  1602,  1602,  1602,  1602
.short   -1458, -1458, -1458, -1458, -1458, -1458, -1458, -1458
.short     829,   829,   829,   829,   829,   829,   829,   829
.short    -383,  -383,  -383,  -383,  -383,  -383,  -383,  -383
.short    -264,  -264,  -264,  -264,  -264,  -264,  -264,  -264
.short    1325,  1325,  1325,  1325,  1325,  1325,  1325,  1325
.short    -573,  -573,  -573,  -573,  -573,  -573,  -573,  -573

# Inverse zetas for levels 4..1 (former zeta indices 112..126). Each level
# reads its own contiguous slice starting at byte offset 0 through the
# per-level labels below, so no index-bias arithmetic is needed.
# --- kInvNTTZetaHi4  (base + ZETA_L4) ---
.short   -1468,    1474,    1202,    -962,    -182,   -1577,    -622,     171
# --- kInvNTTZetaHi3  (base + ZETA_L3) ---
.short    -202,    -287,   -1422,   -1493
# --- kInvNTTZetaHi2  (base + ZETA_L2) ---
.short    1517,     359
# --- kInvNTTZetaHi1  (base + ZETA_L1) ---
.short     758
.size    kInvNTTZetaHi, . - kInvNTTZetaHi

.align 32
.type    kNTTZetaLo, @object
kNTTZetaLo:
# Level-7 pre-expanded twiddles (zeta indices 64..127, len=2 groups). Each
# 32-byte block holds eight consecutive zetas, each broadcast across 2 lanes.
# --- kNTTZetaLo7  (base + ZETA_L7) ---
.short    -335,   -335,  11182,  11182, -11477, -11477,  13387,  13387
.short  -32227, -32227, -14233, -14233,  20494,  20494, -21655, -21655
.short  -27738, -27738,  13131,  13131,    945,    945,  -4587,  -4587
.short  -14883, -14883,  23092,  23092,   6182,   6182,   5493,   5493
.short   32010,  32010, -32502, -32502,  10631,  10631,  30317,  30317
.short   29175,  29175, -18741, -18741, -28762, -28762,  12639,  12639
.short  -18486, -18486,  20100,  20100,  17560,  17560,  18525,  18525
.short  -14430, -14430,  19529,  19529,  -5276,  -5276, -12619, -12619
.short  -31183, -31183,  20297,  20297,  25435,  25435,   2146,   2146
.short   -7382,  -7382,  15355,  15355,  24391,  24391, -32384, -32384
.short  -20927, -20927,  -6280,  -6280,  10946,  10946, -14903, -14903
.short   24214,  24214, -11044, -11044,  16989,  16989,  14469,  14469
.short   10335,  10335, -21498, -21498,  -7934,  -7934, -20198, -20198
.short  -22502, -22502,  23210,  23210,  10906,  10906, -17442, -17442
.short   31636,  31636, -23860, -23860,  28644,  28644, -20257, -20257
.short   23998,  23998,   7756,   7756, -17422, -17422,  23132,  23132

# Level-6 pre-expanded twiddles (zeta indices 32..63, len=4 groups). Each
# 32-byte block holds four consecutive zetas, each broadcast across 4 lanes.
# --- kNTTZetaLo6  (base + ZETA_L6) ---
.short   -5689,  -5689,  -5689,  -5689,  -6516,  -6516,  -6516,  -6516
.short    1496,   1496,   1496,   1496,  30967,  30967,  30967,  30967
.short  -23565, -23565, -23565, -23565,  20179,  20179,  20179,  20179
.short   20710,  20710,  20710,  20710,  25080,  25080,  25080,  25080
.short  -12796, -12796, -12796, -12796,  26616,  26616,  26616,  26616
.short   16064,  16064,  16064,  16064, -12442, -12442, -12442, -12442
.short    9134,   9134,   9134,   9134,   -650,   -650,   -650,   -650
.short  -25986, -25986, -25986, -25986,  27837,  27837,  27837,  27837
.short   19883,  19883,  19883,  19883, -28250, -28250, -28250, -28250
.short  -15887, -15887, -15887, -15887,  -8898,  -8898,  -8898,  -8898
.short  -28309, -28309, -28309, -28309,   9075,   9075,   9075,   9075
.short  -30199, -30199, -30199, -30199,  18249,  18249,  18249,  18249
.short   13426,  13426,  13426,  13426,  14017,  14017,  14017,  14017
.short  -29156, -29156, -29156, -29156, -12757, -12757, -12757, -12757
.short   16832,  16832,  16832,  16832,   4311,   4311,   4311,   4311
.short  -24155, -24155, -24155, -24155, -17915, -17915, -17915, -17915


# Level-5 pre-expanded twiddles (zeta indices 16..31, len=8 groups). Each
# 32-byte block holds zeta[idx] across the low 8 lanes and zeta[idx+1] across
# the high 8 lanes.
# --- kNTTZetaLo5  (base + ZETA_L5) ---
.short   -5827,  -5827,  -5827,  -5827,  -5827,  -5827,  -5827,  -5827
.short   17363,  17363,  17363,  17363,  17363,  17363,  17363,  17363
.short  -26360, -26360, -26360, -26360, -26360, -26360, -26360, -26360
.short  -29057, -29057, -29057, -29057, -29057, -29057, -29057, -29057
.short    5571,   5571,   5571,   5571,   5571,   5571,   5571,   5571
.short   -1102,  -1102,  -1102,  -1102,  -1102,  -1102,  -1102,  -1102
.short   21438,  21438,  21438,  21438,  21438,  21438,  21438,  21438
.short  -26242, -26242, -26242, -26242, -26242, -26242, -26242, -26242
.short  -28073, -28073, -28073, -28073, -28073, -28073, -28073, -28073
.short   24313,  24313,  24313,  24313,  24313,  24313,  24313,  24313
.short  -10532, -10532, -10532, -10532, -10532, -10532, -10532, -10532
.short    8800,   8800,   8800,   8800,   8800,   8800,   8800,   8800
.short   18426,  18426,  18426,  18426,  18426,  18426,  18426,  18426
.short    8859,   8859,   8859,   8859,   8859,   8859,   8859,   8859
.short   26675,  26675,  26675,  26675,  26675,  26675,  26675,  26675
.short  -16163, -16163, -16163, -16163, -16163, -16163, -16163, -16163

# Forward zetas for levels 1..4 (zeta indices 1..15). Levels 5..7 use the
# per-level pre-expanded tables kNTTZeta{Lo,Hi}5/6/7 above. Each level reads
# its own contiguous slice starting at byte offset 0 through the per-level
# labels, so no index-bias arithmetic is needed.
# --- kNTTZetaLo4  (base + ZETA_L4) ---
.short  -20907,  27758,  -3799, -15690,  10690,   1358, -11202,  31164
# --- kNTTZetaLo3  (base + ZETA_L3) ---
.short   13525, -12402,  28191, -16694
# --- kNTTZetaLo2  (base + ZETA_L2) ---
.short   14745,    787
# --- kNTTZetaLo1  (base + ZETA_L1) ---
.short   31498
.size    kNTTZetaLo, . - kNTTZetaLo

.align 32
.type    kNTTZetaHi, @object
kNTTZetaHi:
# Level-7 pre-expanded twiddles (zeta indices 64..127, len=2 groups). Each
# 32-byte block holds eight consecutive zetas, each broadcast across 2 lanes.
# --- kNTTZetaHi7  (base + ZETA_L7) ---
.short   -1103,  -1103,    430,    430,    555,    555,    843,    843
.short   -1251,  -1251,    871,    871,   1550,   1550,    105,    105
.short     422,    422,    587,    587,    177,    177,   -235,   -235
.short    -291,   -291,   -460,   -460,   1574,   1574,   1653,   1653
.short    -246,   -246,    778,    778,   1159,   1159,   -147,   -147
.short    -777,   -777,   1483,   1483,   -602,   -602,   1119,   1119
.short   -1590,  -1590,    644,    644,   -872,   -872,    349,    349
.short     418,    418,    329,    329,   -156,   -156,    -75,    -75
.short     817,    817,   1097,   1097,    603,    603,    610,    610
.short    1322,   1322,  -1285,  -1285,  -1465,  -1465,    384,    384
.short   -1215,  -1215,   -136,   -136,   1218,   1218,  -1335,  -1335
.short    -874,   -874,    220,    220,  -1187,  -1187,  -1659,  -1659
.short   -1185,  -1185,  -1530,  -1530,  -1278,  -1278,    794,    794
.short   -1510,  -1510,   -854,   -854,   -870,   -870,    478,    478
.short    -108,   -108,   -308,   -308,    996,    996,    991,    991
.short     958,    958,  -1460,  -1460,   1522,   1522,   1628,   1628

# Level-6 pre-expanded twiddles (zeta indices 32..63, len=4 groups). Each
# 32-byte block holds four consecutive zetas, each broadcast across 4 lanes.
# --- kNTTZetaHi6  (base + ZETA_L6) ---
.short    1223,   1223,   1223,   1223,    652,    652,    652,    652
.short    -552,   -552,   -552,   -552,   1015,   1015,   1015,   1015
.short   -1293,  -1293,  -1293,  -1293,   1491,   1491,   1491,   1491
.short    -282,   -282,   -282,   -282,  -1544,  -1544,  -1544,  -1544
.short     516,    516,    516,    516,     -8,     -8,     -8,     -8
.short    -320,   -320,   -320,   -320,   -666,   -666,   -666,   -666
.short   -1618,  -1618,  -1618,  -1618,  -1162,  -1162,  -1162,  -1162
.short     126,    126,    126,    126,   1469,   1469,   1469,   1469
.short    -853,   -853,   -853,   -853,    -90,    -90,    -90,    -90
.short    -271,   -271,   -271,   -271,    830,    830,    830,    830
.short     107,    107,    107,    107,  -1421,  -1421,  -1421,  -1421
.short    -247,   -247,   -247,   -247,   -951,   -951,   -951,   -951
.short    -398,   -398,   -398,   -398,    961,    961,    961,    961
.short   -1508,  -1508,  -1508,  -1508,   -725,   -725,   -725,   -725
.short     448,    448,    448,    448,  -1065,  -1065,  -1065,  -1065
.short     677,    677,    677,    677,  -1275,  -1275,  -1275,  -1275

# Level-5 pre-expanded twiddles (zeta indices 16..31, len=8 groups). Each
# 32-byte block holds zeta[idx] across the low 8 lanes and zeta[idx+1] across
# the high 8 lanes.
# --- kNTTZetaHi5  (base + ZETA_L5) ---
.short     573,    573,    573,    573,    573,    573,    573,    573
.short   -1325,  -1325,  -1325,  -1325,  -1325,  -1325,  -1325,  -1325
.short     264,    264,    264,    264,    264,    264,    264,    264
.short     383,    383,    383,    383,    383,    383,    383,    383
.short    -829,   -829,   -829,   -829,   -829,   -829,   -829,   -829
.short    1458,   1458,   1458,   1458,   1458,   1458,   1458,   1458
.short   -1602,  -1602,  -1602,  -1602,  -1602,  -1602,  -1602,  -1602
.short    -130,   -130,   -130,   -130,   -130,   -130,   -130,   -130
.short    -681,   -681,   -681,   -681,   -681,   -681,   -681,   -681
.short    1017,   1017,   1017,   1017,   1017,   1017,   1017,   1017
.short     732,    732,    732,    732,    732,    732,    732,    732
.short     608,    608,    608,    608,    608,    608,    608,    608
.short   -1542,  -1542,  -1542,  -1542,  -1542,  -1542,  -1542,  -1542
.short     411,    411,    411,    411,    411,    411,    411,    411
.short    -205,   -205,   -205,   -205,   -205,   -205,   -205,   -205
.short   -1571,  -1571,  -1571,  -1571,  -1571,  -1571,  -1571,  -1571

# Forward zetas for levels 1..4 (zeta indices 1..15). Levels 5..7 use the
# per-level pre-expanded tables kNTTZeta{Lo,Hi}5/6/7 above. Each level reads
# its own contiguous slice starting at byte offset 0 through the per-level
# labels, so no index-bias arithmetic is needed.
# --- kNTTZetaHi4  (base + ZETA_L4) ---
.short    -171,    622,   1577,    182,    962,  -1202,  -1474,   1468
# --- kNTTZetaHi3  (base + ZETA_L3) ---
.short    1493,   1422,    287,    202
# --- kNTTZetaHi2  (base + ZETA_L2) ---
.short    -359,  -1517
# --- kNTTZetaHi1  (base + ZETA_L1) ---
.short    -758
.size    kNTTZetaHi, . - kNTTZetaHi


# Basemul twiddles: (kModRoots[i] * R mod q) in centered/Montgomery split form,
# in natural pair order (i = 0..127).  Consumed by ml_kem_mul_avx2 /
# ml_kem_mul_add_avx2 with the 16-bit Montgomery multiply.
.align 32
.type    kBaseMulZetaHi, @object
kBaseMulZetaHi:
    .short  -1103,   1103,    430,   -430,    555,   -555,    843,   -843
    .short  -1251,   1251,    871,   -871,   1550,  -1550,    105,   -105
    .short    422,   -422,    587,   -587,    177,   -177,   -235,    235
    .short   -291,    291,   -460,    460,   1574,  -1574,   1653,  -1653
    .short   -246,    246,    778,   -778,   1159,  -1159,   -147,    147
    .short   -777,    777,   1483,  -1483,   -602,    602,   1119,  -1119
    .short  -1590,   1590,    644,   -644,   -872,    872,    349,   -349
    .short    418,   -418,    329,   -329,   -156,    156,    -75,     75
    .short    817,   -817,   1097,  -1097,    603,   -603,    610,   -610
    .short   1322,  -1322,  -1285,   1285,  -1465,   1465,    384,   -384
    .short  -1215,   1215,   -136,    136,   1218,  -1218,  -1335,   1335
    .short   -874,    874,    220,   -220,  -1187,   1187,  -1659,   1659
    .short  -1185,   1185,  -1530,   1530,  -1278,   1278,    794,   -794
    .short  -1510,   1510,   -854,    854,   -870,    870,    478,   -478
    .short   -108,    108,   -308,    308,    996,   -996,    991,   -991
    .short    958,   -958,  -1460,   1460,   1522,  -1522,   1628,  -1628
.size    kBaseMulZetaHi, . - kBaseMulZetaHi

.align 32
.type    kBaseMulZetaLo, @object
kBaseMulZetaLo:
    .short   -335,    335,  11182, -11182, -11477,  11477,  13387, -13387
    .short -32227,  32227, -14233,  14233,  20494, -20494, -21655,  21655
    .short -27738,  27738,  13131, -13131,    945,   -945,  -4587,   4587
    .short -14883,  14883,  23092, -23092,   6182,  -6182,   5493,  -5493
    .short  32010, -32010, -32502,  32502,  10631, -10631,  30317, -30317
    .short  29175, -29175, -18741,  18741, -28762,  28762,  12639, -12639
    .short -18486,  18486,  20100, -20100,  17560, -17560,  18525, -18525
    .short -14430,  14430,  19529, -19529,  -5276,   5276, -12619,  12619
    .short -31183,  31183,  20297, -20297,  25435, -25435,   2146,  -2146
    .short  -7382,   7382,  15355, -15355,  24391, -24391, -32384,  32384
    .short -20927,  20927,  -6280,   6280,  10946, -10946, -14903,  14903
    .short  24214, -24214, -11044,  11044,  16989, -16989,  14469, -14469
    .short  10335, -10335, -21498,  21498,  -7934,   7934, -20198,  20198
    .short -22502,  22502,  23210, -23210,  10906, -10906, -17442,  17442
    .short  31636, -31636, -23860,  23860,  28644, -28644, -20257,  20257
    .short  23998, -23998,   7756,  -7756, -17422,  17422,  23132, -23132
.size    kBaseMulZetaLo, . - kBaseMulZetaLo


# Scalar broadcast constants.  Barrett-reduction values (ntt_reduce) are read as
# dwords via vpbroadcastd; the modulus q is stored as a .long so the same label
# feeds both the dword (qhat*q) and word (Montgomery/add/sub/basemul) broadcasts.

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
# Montgomery fixups and the add/sub/basemul reduce_once steps.
.align 4
q:
    .long 3329

# Inverse-degree Montgomery factor for the inverse NTT's 1/n scaling: its value
# is n^-1 * R mod q = 512 (= 2^9).  Read as a word and used as the vpmulhw hi
# operand in intt_scale_reduce (FIPS 203 Alg 10 final 1/n multiply).
.align 4
inv_deg_factor:
    .long 512

# Basemul constants (16-bit).  qinv = -q^-1 mod 2^16; R2 = (2^16)^2 mod q in
# the Montgomery split form: hi = R^2 mod q (centered), lo = int16(-hi*3327).
.align 2
basemul_qinv:
    .short -3327
.align 2
basemul_R2hi:
    .short 1353
.align 2
basemul_R2lo:
    .short 20553

.section    .note.GNU-stack,"",@progbits

___

}}} else {{{
# When AVX2 is not available in the assembler, output safe stubs.
$code .= <<___;
.text

.globl  ml_kem_ntt_avx2_capable
.type   ml_kem_ntt_avx2_capable,\@abi-omnipotent
ml_kem_ntt_avx2_capable:
    endbranch
    xor     %eax, %eax
    ret
.size   ml_kem_ntt_avx2_capable, .-ml_kem_ntt_avx2_capable

.globl  ml_kem_ntt_avx2
.type   ml_kem_ntt_avx2,\@abi-omnipotent
ml_kem_ntt_avx2:
    endbranch
    .byte   0x0f,0x0b       # ud2
    ret
.size   ml_kem_ntt_avx2, .-ml_kem_ntt_avx2

.globl  ml_kem_inverse_ntt_avx2
.type   ml_kem_inverse_ntt_avx2,\@abi-omnipotent
ml_kem_inverse_ntt_avx2:
    endbranch
    .byte   0x0f,0x0b       # ud2
    ret
.size   ml_kem_inverse_ntt_avx2, .-ml_kem_inverse_ntt_avx2

.globl  ml_kem_add_avx2
.type   ml_kem_add_avx2,\@abi-omnipotent
ml_kem_add_avx2:
    endbranch
    .byte   0x0f,0x0b       # ud2
    ret
.size   ml_kem_add_avx2, .-ml_kem_add_avx2

.globl  ml_kem_sub_avx2
.type   ml_kem_sub_avx2,\@abi-omnipotent
ml_kem_sub_avx2:
    endbranch
    .byte   0x0f,0x0b       # ud2
    ret
.size   ml_kem_sub_avx2, .-ml_kem_sub_avx2

.globl  ml_kem_mul_avx2
.type   ml_kem_mul_avx2,\@abi-omnipotent
ml_kem_mul_avx2:
    endbranch
    .byte   0x0f,0x0b       # ud2
    ret
.size   ml_kem_mul_avx2, .-ml_kem_mul_avx2

.globl  ml_kem_mul_add_avx2
.type   ml_kem_mul_add_avx2,\@abi-omnipotent
ml_kem_mul_add_avx2:
    endbranch
    .byte   0x0f,0x0b       # ud2
    ret
.size   ml_kem_mul_add_avx2, .-ml_kem_mul_add_avx2
___
}}}

print $code;
close STDOUT or die "error closing STDOUT: $!";
