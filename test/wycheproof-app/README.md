# Intel(R) Multi-Buffer Crypto for IPsec Library - Wycheproof Test Application

## Contents

- Overview
- Usage


## Overview

The wycheproof test application verifies supported algorithm implementations against
[Project Wycheproof](https://github.com/google/wycheproof) test vectors. Project Wycheproof
provides a set of vectors to check for expected behaviors and detect known weaknesses for
specific algorithms.

## Usage

Before running the application, ensure the library is installed by following the instructions
in the [README](https://github.com/intel/intel-ipsec-mb/tree/main/test#library-installation).

### Linux
To test all supported algorithms on all architectures:  
`./imb-wycheproof`  

To test all supported algorithms on AVX512 architecture only:  
`./imb-wycheproof --avx512`  

To display an extensive help page:  
`./imb-wycheproof --help`   

### Windows
To test all supported algorithms on all architectures:  
`imb-wycheproof.exe`  

To test all supported algorithms on AVX512 architecture only:  
`imb-wycheproof.exe --avx512`  

To display an extensive help page:  
`imb-wycheproof.exe --help`
