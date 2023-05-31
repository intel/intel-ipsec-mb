# Intel(R) Multi-Buffer Crypto for IPsec Library - Fuzz Test Applications

## Contents

- Overview
- Dependencies
- Usage


## Overview

The fuzz test applications aim to discover defects in the library by passing randomly
generated data to the library API's. Currently there are two fuzzing applications, the
`imb-fuzz-api` application targets job and burst API and `imb-fuzz-direct-api` targets
the direct API.


## Dependencies
- clang
- libfuzzer

## Usage

Before running the application, ensure the library is installed by following the instructions
in the [README](https://github.com/intel/intel-ipsec-mb/tree/main/test#library-installation).  
**Note:** The library must be compiled with SAFE_PARAM option enabled (default setting).

### Linux
To fuzz the library job and burst API:  
`./imb-fuzz-api`  

To fuzz the library direct API:  
`./imb-fuzz-direct-api`  

To display an extensive help page for libfuzzer options:  
`./imb-fuzz-api -help=1`   

### Windows
Not currently supported.
