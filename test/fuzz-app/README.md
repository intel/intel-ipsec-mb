# Intel(R) Multi-Buffer Crypto for IPsec Library - Fuzz Test Applications

## Contents

- Overview
- Dependencies
- Usage


## Overview

The fuzz test applications aim to discover defects in the library by passing randomly
generated data to the library API's. Currently there are three fuzzing applications, the
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

### Architecture selection

By default the applications initialize the multi-buffer manager for the best
architecture available on the running CPU.

`imb-fuzz-direct-api` and `imb-fuzz-pqc-api` accept an optional `--` argument,
after which `SSE`, `AVX2`, `AVX512` or `AVX10` selects the architecture and
`SHANI-OFF` / `GFNI-OFF` disable the respective CPU features. All arguments
following `--` are consumed by the application and hidden from libfuzzer, so
`--` must come last:  
`./imb-fuzz-pqc-api -runs=100000 -- AVX10`  

`imb-fuzz-api` selects the architecture through the `ARCH` environment variable
(`SSE`, `AVX2`, `AVX512` or `AVX10`):  
`ARCH=AVX10 ./imb-fuzz-api`  

**Note:** the selected architecture must be supported by the CPU the application
is running on.

### Windows
Not currently supported.

