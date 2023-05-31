# Intel(R) Multi-Buffer Crypto for IPsec Library - Cross Validation Application

## Contents

- Overview
- Usage


## Overview

The cross validation application validates correct algorithm implementation by encrypting
randomly generated data with one architectural implementation and decrypting with another.
The decrypted data is verified by comparing against the original. By default, the
tool will cross validate all algorithms across all combinations of architectures.

For release builds of the library with the SAFE_DATA option enabled (default setting),
the cross validation application can be used to check all sensitive data has been cleared
from processor registers and memory.


## Usage

Before running the application, ensure the library is installed by following the instructions
in the [README](https://github.com/intel/intel-ipsec-mb/tree/main/test#library-installation).

### Linux
To cross validate all algorithms across all architectures:  
`./imb-xvalid`  

To validate all SSE algorithm implementations against AVX512:  
`./imb-xvalid --enc-arch SSE --dec-arch AVX512`  

To validate AES-CBC-128 AVX algorithm implementation against SSE:  
`./imb-xvalid --enc-arch AVX --dec-arch SSE --cipher-algo aes-cbc-128`  

To validate AES-GCM-128 using only 512 byte buffers:  
`./imb-xvalid --aead-algo aes-gcm-128 --job-size 512`  

To check for sensitive data left in registers or memory:  
`./imb-xvalid --safe-check` 

To display an extensive help page:  
`./imb-xvalid --help`   

### Windows
To cross validate all algorithms across all architectures:  
`imb-xvalid.exe`  

To validate all SSE algorithm implementations against AVX512:  
`imb-xvalid.exe --enc-arch SSE --dec-arch AVX512`  

To validate AES-CBC-128 AVX algorithm implementation against SSE:  
`imb-xvalid.exe --enc-arch AVX --dec-arch SSE --cipher-algo aes-cbc-128`  

To validate AES-GCM-128 using only 512 byte buffers:  
`imb-xvalid.exe --aead-algo aes-gcm-128 --job-size 512`  

To check for sensitive data left in registers or memory:  
`imb-xvalid.exe --safe-check` 

To display an extensive help page:  
`imb-xvalid.exe --help`  
