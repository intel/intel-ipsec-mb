# Intel(R) Multi-Buffer Crypto for IPsec Library - Known Answer Test (KAT) Application

## Contents

- Overview
- Usage


## Overview

The KAT application validates correct algorithm implementations by passing
predefined inputs to the library API and verifying the generated output against a
known correct result. By default, the application will test all algorithms across all
architectures e.g. SSE, AVX, AVX2, AVX512 and prints overall test result "PASS" or "FAIL".

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

To display an extensive help page:  
`./imb-kat --help`   

### Windows
To test all algorithms across all architectures:  
`imb-kat.exe`  

To test all algorithms on SSE architecture only:  
`imb-kat.exe --no-avx --no-avx2 --no-avx512`  

To test AES-GCM on AVX512 architecture only:  
`imb-kat.exe --no-sse --no-avx --no-avx2 --test-type GCM`  

To display an extensive help page:  
`imb-kat.exe --help`   
