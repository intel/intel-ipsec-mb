# Intel(R) Multi-Buffer Crypto for IPsec Library - Fuzz Test Applications

## Contents

- Overview
- Dependencies
- Usage
- Application arguments


## Overview

The fuzz test applications aim to discover defects in the library by passing randomly
generated data to the library APIs. Currently there are three fuzzing applications, the
`imb-fuzz-api` application targets job and burst API, `imb-fuzz-direct-api` targets
the direct API and `imb-fuzz-pqc-api` targets the post-quantum cryptography (PQC)
direct API, i.e. ML-DSA (FIPS 204) and ML-KEM (FIPS 203).

The PQC API is fuzzed by a separate application because it is stateful (an opaque
context caches a decoded key) and because its entry points parse structured byte
strings (encoded keys, ciphertexts and signatures) which are far more expensive to
process than the rest of the direct API. `imb-fuzz-pqc-api` generates one known good
key pair, signature and ciphertext per parameter set from a fixed seed and caches
them, so that mutated - but nearly well formed - inputs reach the decoders and the
sign/verify/encapsulate/decapsulate operations. Parameter set selectors, buffer
lengths and the optional parameter structures are fuzzed alongside the payloads.


## Dependencies
- clang
- libfuzzer

## Usage

Before running the application, ensure the library is installed by following the instructions
in the [README](https://github.com/intel/intel-ipsec-mb/tree/main/test#library-installation).  
**Note:** The library must be compiled with SAFE_PARAM option enabled (default setting).
[CLANG/LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html) package is required for building and running the fuzz applications.
### Linux
To fuzz the library job and burst API:  
`./imb-fuzz-api`  

To fuzz the library direct API:  
`./imb-fuzz-direct-api`  

To fuzz the library PQC (ML-DSA and ML-KEM) direct API:  
`./imb-fuzz-pqc-api`  

To display an extensive help page for libfuzzer options:  
`./imb-fuzz-api -help=1`   

### Application arguments

To pass application arguments, place them after a `--` separator.
Everything following `--` is consumed by the application and hidden from
libfuzzer, so `--` and its arguments must come last:  
`./imb-fuzz-api -runs=100000 -- AVX2 API=BURST NJOBS=32`   

The following arguments are recognized by all three applications:

| Argument | Description |
| --- | --- |
| `SSE`, `AVX2`, `AVX512`, `AVX10` | Architecture to initialize the multi-buffer manager for. May also be given as `ARCH=<name>`. By default the best architecture available on the running CPU is used. |
| `SHANI-OFF`, `GFNI-OFF` | Disable the respective CPU feature. May also be given as `FLAGS=<name>`. |

The following arguments are recognized only by the `imb-fuzz-api` application:

| Argument | Description |
| --- | --- |
| `API=JOB`, `API=BURST`, `API=CIPHER-BURST`, `API=HASH-BURST` | API to exercise, job API by default. `SINGLE`, `BURST`, `CIPHER_BURST` and `HASH_BURST` are accepted as well. |
| `NJOBS=<n>` | Number of jobs per burst, 10 by default. Must not exceed `IMB_MAX_BURST_SIZE`. |
| `KEYLEN=<n>` | Cipher key length in bytes, 16 by default. |
| `DIR=ENCRYPT`, `DIR=DECRYPT` | Cipher direction, encrypt by default. `ENCRYPT` and `DECRYPT` are accepted as well. |
| `IMB_CIPHER_<mode>` | Fuzz one specific cipher mode, for example `IMB_CIPHER_CBC`. By default the cipher mode is taken from the fuzz input. |
| `IMB_AUTH_<alg>` | Fuzz one specific hash algorithm, for example `IMB_AUTH_HMAC_SHA_256`. By default the hash algorithm is taken from the fuzz input. |

Examples:  
`./imb-fuzz-pqc-api -runs=100000 -- AVX10`  
`./imb-fuzz-direct-api -runs=100000 -- AVX2 SHANI-OFF`  
`./imb-fuzz-api -- ARCH=SSE API=CIPHER-BURST IMB_CIPHER_CBC DIR=DECRYPT KEYLEN=32`  

**Note:** the selected architecture must be supported by the CPU the application
is running on.

### Windows
Not currently supported.

