# Intel(R) Multi-Buffer Crypto for IPsec Library - ABI Check Application

## Contents

- Overview
- Usage


## Overview

The ABI check application verifies that XMM6-XMM15 and the general
purpose registers RBX, RBP, RSI, RDI, R12-R15 - all registers the
Windows x64 calling convention declares callee-saved (besides RSP) - keep
their value across `IMB_SUBMIT_JOB()` and `IMB_FLUSH_JOB()` calls.

Before submitting or flushing a job, these registers are filled with
unique per-register sentinel patterns. After the call returns, the
registers are compared against the sentinels; any mismatch means the
library clobbered a register it was required to preserve.

The application scans every algorithm accessible through the job API:
cipher-only algorithms (paired with NULL-HASH), hash-only algorithms
(paired with NULL-CIPHER) and combined AEAD algorithms (e.g. AES-GCM,
AES-CCM), across every architecture supported by the CPU. Failing
algorithm/architecture/stage combinations, along with the specific
registers that were not preserved, are printed at the end of the run.

With the optional `--check-vzeroupper` flag, for architectures that
execute AVX+ code (AVX2/AVX512/AVX10) the application also makes a
best-effort check for a missing `VZEROUPPER`: the upper 128 bits of
YMM6-YMM15 are seeded with a non-zero pattern and checked for being left
dirty afterwards. This is reported as a `vzeroupper` entry in the
REGISTERS column; unlike the XMM/GP register entries it is not a
callee-saved register ABI violation (the upper YMM/ZMM halves are not
defined as callee-saved) but a performance-cliff issue for callers that
subsequently run legacy SSE code. This check is disabled by default
because it cannot tell "never touched AVX/YMM state" apart from "used
it and forgot to clean up", so it is expected to report false positives
for algorithms/stages that don't happen to execute any AVX-encoded
instruction on the probed call (e.g. NULL-CIPHER, or a submit call that
only buffers the job) - any hits reported with this flag should be
manually reviewed rather than treated as confirmed bugs.

The application does not verify any cryptographic results and does not
attempt to fix any register preservation problem it finds - use the
[cross validation application](../xvalid-app/README.md) for result
validation.

This application is Windows-only: on Linux (System V x64 ABI), XMM6-XMM15
are not callee-saved and the callee-saved GP register set differs, so the
check does not apply.


## Usage

Before running the application, ensure the library is installed by following the instructions
in the [README](https://github.com/intel/intel-ipsec-mb/tree/main/test#library-installation).

To scan all algorithms on all architectures:  
`imb-abi-check.exe`

To scan all algorithms on AVX512 only:  
`imb-abi-check.exe --arch AVX512`

To display an extensive help page:  
`imb-abi-check.exe --help`
