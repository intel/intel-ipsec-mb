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
