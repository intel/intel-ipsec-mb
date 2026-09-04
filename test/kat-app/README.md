# Intel(R) Multi-Buffer Crypto for IPsec Library - Known Answer Test (KAT) Application

## Contents

- Overview
- Common KAT modules
- Usage


## Overview

The KAT application validates correct algorithm implementations by passing
predefined inputs to the library API and verifying the generated output against a
known correct result. By default, the application will test all algorithms across all
architectures e.g. SSE, AVX, AVX2, AVX512 and prints overall test result "PASS" or "FAIL".

Test vectors are loaded at runtime from the JSON files in the `vectors` directory.
Use `--vector-dir <DIR>` to point the application at a different directory.

### Common KAT modules

The common KAT modules `kat_common_cipher` and `kat_common_hash` provide reusable
job setup, submission, completion, cleanup, and result-validation paths for cipher
and hash algorithms. Algorithm-specific tests supply preparation and cleanup callbacks
for fields and resources owned by that algorithm. The helpers allocate independent
output buffers, retain each job's vector index for out-of-order completion, and validate
results against the corresponding vector. They support the standard job API and the
applicable generic, cipher-only, or hash-only burst APIs.

The cipher and hash helpers are intentionally separate. Cipher jobs validate plaintext
or ciphertext and may need in-place handling, while hash jobs validate authentication tags
and may configure hash-specific fields. The callbacks keep those algorithm-specific details
out of the common submission and completion logic.

There are a few limitations. A helper does not infer algorithm-specific job fields, key
schedule formats, IV construction, or special vector framing; those remain in the caller's
callbacks. Not every test can use the helpers, particularly direct APIs, AEAD tests with
additional tag/AAD behavior, and tests that mix algorithms in one operation. The helpers
also cover job and burst APIs, not direct API validation.

The [Project Wycheproof](https://github.com/google/wycheproof) vectors are held in
the `wycheproof_*.json` files and are run as part of the test type of the algorithm
they belong to (`GCM`, `CCM`, `CHACHA20_POLY1305`, `CMAC`, `GMAC`, `HMAC_SHA1` and
`HMAC_SHA256`). Unlike the other vector files these include negative test cases,
which pass when the library rejects the operation or produces a result differing
from the recorded one. Vectors using parameters the library does not support are
skipped and reported as such.

## Usage

Before running the application, ensure the library is installed by following the instructions
in the [README](https://github.com/intel/intel-ipsec-mb/tree/main/test#library-installation).

### Linux
To test all algorithms across all architectures:  
`./imb-kat`  

To test all algorithms on SSE architecture only:  
`./imb-kat --no-avx --no-avx2 --no-avx512`  

To test AES-GCM on AVX512 architecture only:  
`./imb-kat --no-sse --no-avx --no-avx2 --test-type GCM`  

To run the AES-CMAC tests, including the Project Wycheproof AES-CMAC vectors:  
`./imb-kat --test-type CMAC`  

To display an extensive help page:  
`./imb-kat --help`   

### Windows
To test all algorithms across all architectures:  
`imb-kat.exe`  

To test all algorithms on SSE architecture only:  
`imb-kat.exe --no-avx --no-avx2 --no-avx512`  

To test AES-GCM on AVX512 architecture only:  
`imb-kat.exe --no-sse --no-avx --no-avx2 --test-type GCM`  

To run the AES-CMAC tests, including the Project Wycheproof AES-CMAC vectors:  
`imb-kat.exe --test-type CMAC`  

To display an extensive help page:  
`imb-kat.exe --help`   
