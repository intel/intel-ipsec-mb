# Intel(R) Multi-Buffer Crypto for IPsec Library - Safe Check Application

## Contents

- Overview
- Usage


## Overview

The safe check application looks for sensitive data (cipher keys, authentication keys
and message data) left behind in general purpose registers, SIMD registers, stack,
`IMB_MGR` structure and out-of-order managers after key expansion and job processing.

Keys and messages are filled with unique byte patterns which are searched for after
each operation. The application does not verify any cryptographic results - use the
[cross validation application](../xvalid-app/README.md) for result validation.

By default all algorithms are scanned across:
- all supported architectures
- all key sizes
- range of message sizes
- both cipher directions (encrypt and decrypt)
- 1, 3, 4, 5, 7, 8, 9, 15, 16 and 17 jobs submitted in one go

Jobs of mixed (randomized) sizes submitted in one go are scanned on top of the above
when `--imix` is used.

When a match is found, the patterns are regenerated and the test case is repeated
(see `--safe-retries`). A failure is only reported when the same match is detected
with different patterns, which eliminates false positives.

The library needs to be compiled with the SAFE_DATA option (default setting).


## Usage

Before running the application, ensure the library is installed by following the instructions
in the [README](https://github.com/intel/intel-ipsec-mb/tree/main/test#library-installation).

### Linux
To scan all algorithms on all architectures:  
`./imb-safe-check`

To scan all algorithms on AVX512 only:  
`./imb-safe-check --arch AVX512`

To scan all algorithms in the encrypt direction only:  
`./imb-safe-check --cipher-dir ENCRYPT`

To scan AES-CBC-128 using only 512 byte buffers:  
`./imb-safe-check --cipher-algo aes-cbc-128 --job-size 512`

To additionally scan jobs of mixed (randomized) sizes submitted in one go:  
`./imb-safe-check --imix`

To scan AES-GCM-128 submitting 16 jobs in one go through the burst API:  
`./imb-safe-check --aead-algo aes-gcm-128 --num-jobs 16 --burst-api`

To display an extensive help page:  
`./imb-safe-check --help`

### Windows
To scan all algorithms on all architectures:  
`imb-safe-check.exe`

To scan all algorithms on AVX512 only:  
`imb-safe-check.exe --arch AVX512`

To scan all algorithms in the encrypt direction only:  
`imb-safe-check.exe --cipher-dir ENCRYPT`

To scan AES-CBC-128 using only 512 byte buffers:  
`imb-safe-check.exe --cipher-algo aes-cbc-128 --job-size 512`

To additionally scan jobs of mixed (randomized) sizes submitted in one go:  
`imb-safe-check.exe --imix`

To scan AES-GCM-128 submitting 16 jobs in one go through the burst API:  
`imb-safe-check.exe --aead-algo aes-gcm-128 --num-jobs 16 --burst-api`

To display an extensive help page:  
`imb-safe-check.exe --help`
