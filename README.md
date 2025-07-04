![Linux](https://github.com/intel/intel-ipsec-mb/actions/workflows/linux.yml/badge.svg)
![Windows](https://github.com/intel/intel-ipsec-mb/actions/workflows/windows.yml/badge.svg)
![FreeBSD](https://github.com/intel/intel-ipsec-mb/actions/workflows/freebsd.yml/badge.svg)
[![Coverity Status](https://scan.coverity.com/projects/16449/badge.svg)](https://scan.coverity.com/projects/intel-ipsec-mb)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intel/intel-ipsec-mb/badge)](https://securityscorecards.dev/viewer/?uri=github.com/intel/intel-ipsec-mb)

# Intel(R) Multi-Buffer Crypto for IPsec Library

The library provides software crypto acceleration primarily targeting packet processing
applications. It can be used for application such as: IPsec, TLS, Wireless (RAN), Cable or MPEG DRM.

The library is hosted on [GitHub](https://github.com/intel/intel-ipsec-mb) and is used as software crypto
provider in [DPDK](https://www.dpdk.org/), [Intel(R) QAT Engine](https://github.com/intel/QAT_Engine)
and [FD.io](https://fd.io/).

Using crypto interfaces from the above frameworks gives freedom to change providers
without subsequent application modifications. The library can also be used directly
through its native API.

Key differentiating features:

- operation chaining (encryption and authentication)
- advanced cryptographic pipelining
  - job manager with scheduling and dispatching functions
  - API hides underlying implementation details from an application
- multi-buffer and function stitching innovations
- low level implementations using latest instruction extensions

## Contents

1. Overview
2. Processor Extensions
3. Recommendations
4. Package Content
5. Documentation
6. Compilation
7. Installation
8. Security Considerations & Options for Increased Security
9. Backwards compatibility
10. Disclaimer (ZUC, KASUMI, SNOW3G)
11. Legal Disclaimer
12. FIPS Compliance
13. DLL Injection

## 1. Overview

Intel Multi-Buffer Crypto for IPsec Library is highly-optimized software
implementations of the core cryptographic processing for IPsec,
which provides industry-leading performance on a range of Intel(R) Processors.

For information on how the library works, see the Intel White Paper:
["Fast Multi-buffer IPsec Implementations on Intel Architecture Processors". Jim Guilford, Sean Gulley, et. al.](https://github.com/intel/intel-ipsec-mb/wiki/doc/fast-multi-buffer-ipsec-implementations-ia-processors-paper.pdf)

Table 1. List of supported cipher algorithms and their implementations.
```
+------------------------------------------------------------------------------------------------------------+
|                |                              Implementation                                               |
| Encryption     +-------------------------------------------------------------------------------------------|
|                | SSE    | SSE    | SSE    | AVX2   | AVX2   | AVX2   | AVX2   | AVX512 | AVX512   | AVX10  |
|                | Type 1 | Type 2 | Type 3 | Type 1 | Type 2 | Type 3 | Type 4 | Type 1 | Type 2   | Type 1 |
|                | [S1]   | [S2]   | [S3]   | [A2-1] | [A2-2] | [A2-3] | [A2-4] | [A3-1] | [A3-2]   | [A4-1] |
|----------------+--------+--------+--------+--------+--------+--------+--------+--------+----------|--------|
| AES128-GCM     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 | [A2-1] | [A2-2] | [A2-1] | Y   by32 |  <---  |
| AES192-GCM     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 | [A2-1] | [A2-2] | [A2-1] | Y   by32 |  <---  |
| AES256-GCM     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 | [A2-1] | [A2-2] | [A2-1] | Y   by32 |  <---  |
| AES128-CCM     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 |  <---  |  <---  |  <---  | Y   by16 |  <---  |
| AES256-CCM     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 |  <---  |  <---  |  <---  | Y   by16 |  <---  |
| AES128-CBC     | Y(1)   |  <---  |  <---  | Y(1)   |  Y (3) |  <---  |  <---  |  <---  | Y(3)     |  <---  |
| AES192-CBC     | Y(1)   |  <---  |  <---  | Y(1)   |  Y (3) |  <---  |  <---  |  <---  | Y(3)     |  <---  |
| AES256-CBC     | Y(1)   |  <---  |  <---  | Y(1)   |  Y (3) |  <---  |  <---  |  <---  | Y(3)     |  <---  |
| AES128-CTR     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 |  <---  |  <---  |  <---  | Y   by16 |  <---  |
| AES192-CTR     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 |  <---  |  <---  |  <---  | Y   by16 |  <---  |
| AES256-CTR     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 |  <---  |  <---  |  <---  | Y   by16 |  <---  |
| AES128-ECB     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 |  <---  |  <---  |  <---  | Y   by16 |  <---  |
| AES192-ECB     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 |  <---  |  <---  |  <---  | Y   by16 |  <---  |
| AES256-ECB     | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 |  <---  |  <---  |  <---  | Y   by16 |  <---  |
| AES128-CFB     | Y(2)   |  <---  |  <---  |  <---  |  Y (3) |  <---  |  <---  |  <---  | Y(3)     |  <---  |
| AES192-CFB     | Y(2)   |  <---  |  <---  |  <---  |  Y (3) |  <---  |  <---  |  <---  | Y(3)     |  <---  |
| AES256-CFB     | Y(2)   |  <---  |  <---  |  <---  |  Y (3) |  <---  |  <---  |  <---  | Y(3)     |  <---  |
| AES128-DOCSIS  | Y(1)   |  <---  |  <---  | Y(1)   |  <---  |  <---  |  <---  | Y(1)   | Y(3)     |  <---  |
| AES256-DOCSIS  | Y(1)   |  <---  |  <---  | Y(1)   |  <---  |  <---  |  <---  | Y(1)   | Y(3)     |  <---  |
| DES-DOCSIS     | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  | Y  x16 |  <---    |  <---  |
| 3DES/TDES      | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  | Y  x16 |  <---    |  <---  |
| DES            | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  | Y  x16 |  <---    |  <---  |
| KASUMI-F8      | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---    |  <---  |
| ZUC-EEA3       | Y   x4 |  <---  | Y(4)x4 | Y  x8  | Y(4)x8 |  <---  |  <---  | Y  x16 | Y(4) x16 |  <---  |
| SNOW3G-UEA2    | Y   x4 |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  | Y  x16 | Y    x16 |  <---  |
| Chacha20       | Y      |  <---  |  <---  | Y      |  <---  |  <---  |  <---  | Y      |  <---    |  <---  |
| Chacha20 AEAD  | Y      |  <---  |  <---  | Y      |  <---  |  <---  |  <---  | Y      |  <---    |  <---  |
| PON-CRC-BIP    | Y  by8 |  <---  |  <---  | Y by8  |  <---  |  <---  |  <---  |  <---  | Y   by16 |  <---  |
| SM4-ECB        | Y      |  <---  |  <---  |  <---  |  <---  |  <---  | Y(5)   | [S1]   | [S1]     | [A2-4] |
| SM4-CBC        | Y      |  <---  |  <---  |  <---  |  <---  |  <---  | Y(6)   | [S1]   | [S1]     | [A2-4] |
| SM4-CTR        | Y      |  <---  |  <---  |  <---  |  <---  |  <---  | Y(7)   | [S1]   | [S1]     | [A2-4] |
| SM4-GCM        | Y      |  <---  |  <---  |  <---  |  <---  |  <---  | Y(7)   | [S1]   | [S1]     | [A2-4] |
+------------------------------------------------------------------------------------------------------------+

```
Notes:  
(1)   - Decryption is by8 and encryption is x8.  
(2)   - Single block decryption and encryption.  
(3)   - Decryption is by16 and encryption is x16.  
(4)   - Implementation using GFNI extensions.  
(5)   - Implementation using SM4NI extensions, by16.  
(6)   - Implementation using SM4NI extensions, single block encryption and by16 decryption.  
(7)   - Implementation using SM4NI extensions, by8.  

Legend:  
` byY`- single buffer Y blocks at a time  
`  xY`- Y buffers at a time  
`[xyz]`- same as `xyz` implementation  
`<---`- same as the column to the left  

Table 2. List of supported integrity algorithms and their implementations.
```
+--------------------------------------------------------------------------------------------------------------+
|                   |                             Implementation                                               |
| Integrity         +------------------------------------------------------------------------------------------|
|                   | SSE    | SSE    | SSE    | AVX2   | AVX2   | AVX2   | AVX2   | AVX512 | AVX512  | AVX10  |
|                   | Type 1 | Type 2 | Type 3 | Type 1 | Type 2 | Type 3 | Type 4 | Type 1 | Type 2  | Type 1 |
|                   | [S1]   | [S2]   | [S3]   | [A2-1] | [A2-2] | [A2-3] | [A2-4] | [A3-1] | [A3-2]  | [A4-1] |
|-------------------+--------+--------+--------+--------+--------+--------+--------+--------+---------|--------|
| AES-XCBC-96       | Y   x4 |  <---  |  <---  | Y   x8 |  <---  |  <---  |  <---  |  <---  | Y   x16 |  <---  |
| HMAC-MD5-96       | Y(1)x4 |  <---  |  <---  | Y   x8 |  <---  |  <---  |  <---  |  <---  |  <---   |  <---  |
| HMAC-SHA1-96      | Y   x4 | Y(2)x2 |  <---  | Y   x8 | Y(2)x2 |  <---  | [A2-1] | Y  x16 |  <---   |  <---  |
| HMAC-SHA2-224_112 | Y   x4 | Y(2)x2 |  <---  | Y   x8 | Y(2)x2 |  <---  |  <---  | Y  x16 |  <---   |  <---  |
| HMAC-SHA2-256_128 | Y   x4 | Y(2)x2 |  <---  | Y   x8 | Y(2)x2 |  <---  |  <---  | Y  x16 |  <---   |  <---  |
| HMAC-SHA2-384_192 | Y   x2 |  <---  |  <---  | Y   x4 |  <---  |  <---  | Y(6)x2 | Y   x8 |  <---   | [A2-4] |
| HMAC-SHA2-512_256 | Y   x2 |  <---  |  <---  | Y   x4 |  <---  |  <---  | Y(6)x2 | Y   x8 |  <---   | [A2-4] |
| SHA1              | Y(2)x4 | Y(2)x2 |  <---  | Y   x8 | Y(2)x2 |  <---  | [A2-1] | Y  x16 |  <---   |  <---  |
| SHA2-224          | Y(2)x4 | Y(2)x2 |  <---  | Y   x8 | Y(2)x2 |  <---  |  <---  | Y  x16 |  <---   |  <---  |
| SHA2-256          | Y(2)x4 | Y(2)x2 |  <---  | Y   x8 | Y(2)x2 |  <---  |  <---  | Y  x16 |  <---   |  <---  |
| SHA2-384          | Y   x2 |  <---  |  <---  | Y   x4 |  <---  |  <---  | Y(6)x2 | Y   x8 |  <---   | [A2-4] |
| SHA2-512          | Y   x2 |  <---  |  <---  | Y   x4 |  <---  |  <---  | Y(6)x2 | Y   x8 |  <---   | [A2-4] |
| AES128-GMAC       | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 | [A2-1] | [A2-2] | [A2-1] | Y  by32 |  <---  |
| AES192-GMAC       | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 | [A2-1] | [A2-2] | [A2-1] | Y  by32 |  <---  |
| AES256-GMAC       | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 | [A2-1] | [A2-2] | [A2-1] | Y  by32 |  <---  |
| AES128-CCM        | Y   x8 |  <---  |  <---  | Y   x8 | Y  x16 |  <---  |  <---  |  <---  | Y   x16 |  <---  |
| AES256-CCM        | Y   x8 |  <---  |  <---  | Y   x8 | Y  x16 |  <---  |  <---  |  <---  | Y   x16 |  <---  |
| AES128-CMAC-96    | Y   x8 |  <---  |  <---  | Y   x8 | Y  x16 |  <---  |  <---  |  <---  | Y   x16 |  <---  |
| AES256-CMAC-96    | Y   x8 |  <---  |  <---  | Y   x8 | Y  x16 |  <---  |  <---  |  <---  | Y   x16 |  <---  |
| KASUMI-F9         | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---   |  <---  |
| ZUC-EIA3          | Y   x4 |  <---  | Y(3)x4 | Y   x8 | Y(3)x8 |  <---  |  <---  | Y  x16 | Y(3)x16 |  <---  |
| SNOW3G-UIA2       | Y(10)  |  <---  |  <---  | Y(10)  |  <---  |  <---  |  <---  |  <---  | Y(11)   |  <---  |
| DOCSIS-CRC32(8)   | Y      |  <---  |  <---  | Y      |  <---  |  <---  |  <---  |  <---  | Y       |  <---  |
| HEC               | Y      |  <---  |  <---  | Y      |  <---  |  <---  |  <---  |  <---  |  <---   |  <---  |
| POLY1305          | Y      |  <---  |  <---  |  <---  |  <---  | Y(4)   |  <---  | Y      | Y(4)    |  <---  |
| POLY1305 AEAD     | Y      |  <---  |  <---  |  <---  |  <---  | Y(4)   |  <---  | Y      | Y(4)    |  <---  |
| GHASH             | Y  by8 |  <---  |  <---  | Y  by8 | Y by16 | [A2-1] | [A2-2] | [A2-1] | Y  by32 |  <---  |
| CRC(7)            | Y  by8 |  <---  |  <---  | Y  by8 |  <---  |  <---  |  <---  |  <---  | Y  by16 |  <---  |
| PON-CRC-BIP(9)    | Y      |  <---  |  <---  | Y      |  <---  |  <---  |  <---  |  <---  | Y  by16 |  <---  |
| SM3               | Y      |  <---  |  <---  |  <---  |  <---  |  <---  | Y(5)x2 | [S1]   |  <---   | [A4-2] |
| HMAC-SM3          | Y      |  <---  |  <---  |  <---  |  <---  |  <---  | Y(5)x2 | [S1]   |  <---   | [A4-2] |
| SM4-GCM           | Y      |  <---  |  <---  | Y  by8 | Y by16 | [A2-1] | [A2-2] | [A2-1] | Y  by32 |  <---  |
| SHA3-224          | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---   |  <---  |
| SHA3-256          | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---   |  <---  |
| SHA3-384          | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---   |  <---  |
| SHA3-512          | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---   |  <---  |
| SHAKE128          | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---   |  <---  |
| SHAKE256          | Y      |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---  |  <---   |  <---  |
+--------------------------------------------------------------------------------------------------------------+
```
Notes:  
(1)  - MD5 over one block implemented in C.  
(2)  - Implementation using SHANI extensions.  
(3)  - Implementation using GFNI extensions.  
(4)  - Implementation using IFMA extensions.  
(5)  - Implementation using SM3NI extensions.  
(6)  - Implementation using SHA512NI extensions.  
(7)  - Supported CRC types:  
 - CRC32: Ethernet FCS, SCTP, WIMAX OFDMA  
 - CRC24: LTE A, LTE B  
 - CRC16: X25, FP data  
 - CRC11: FP header  
 - CRC10: IUUP data  
 - CRC8: WIMAX OFDMA HCS  
 - CRC7: FP header  
 - CRC6: IUUP header  
  
(8)  - used only with AES256-DOCSIS and AES128-DOCSIS ciphers.  
(9)  - used only with PON-AES128-CTR cipher.  
(10) - x4 for init keystream generation, then by4.  
(11) - x16 for init keystream generation, then by32.  

Legend:  
` byY`- single buffer Y blocks at a time  
`  xY`- Y buffers at a time  
`[xyz]`- same as `xyz` implementation  
`<---`- same as the column to the left  

Table 3. Encryption and integrity algorithm combinations
```
+-----------------------------------------------------------------------------+
| Encryption Algorithm                | Allowed Integrity Algorithms          |
|-------------------------------------+---------------------------------------|
| AES128-GCM                          | AES128-GMAC                           |
|-------------------------------------+---------------------------------------|
| AES192-GCM                          | AES192-GMAC                           |
|-------------------------------------+---------------------------------------|
| AES256-GCM                          | AES256-GMAC                           |
|-------------------------------------+---------------------------------------|
| AES128-CCM                          | AES128-CCM                            |
|-------------------------------------+---------------------------------------|
| AES256-CCM                          | AES256-CCM                            |
|-------------------------------------+---------------------------------------|
| SM4-GCM                             | SM4-GCM                               |
|-------------------------------------+---------------------------------------|
| AES128-CBC, AES192-CBC, AES256-CBC, | AES-XCBC-96, AES128-CMAC-96,          |
| AES128-CTR, AES192-CTR, AES256-CTR, | HMAC-SHA1-96, HMAC-SHA2-224_112,      |
| AES128-ECB, AES192-ECB, AES256-ECB, | HMAC-SHA2-256_128, HMAC-SHA2-384_192, |
| AES128-CFB, AES192-CFB, AES256-CFB, | HMAC-SHA2-512_256, NULL, POLY1305,    |
| NULL, Chacha20,                     | AES128-GMAC, AES192-GMAC, AES256-GMAC,|
| AES128-DOCSIS, AES256-DOCSIS,       | GHASH, SM3, HMAC-SM3                  |
| DES-DOCSIS, 3DES, DES,              | ZUC-EIA3, SNOW3G-UIA3, KASUMI-F9      |
| KASUMI-F8, SNOW-V, SNOW3G-UEA3,     |                                       |
| ZUC-EEA3,                           |                                       |
| SM4-ECB, SM4-CBC, SM4-CTR           |                                       |
|-------------------------------------+---------------------------------------|
| AES128-DOCSIS, AES256-DOCSIS        | DOCSIS-CRC32                          |
|-------------------------------------+---------------------------------------|
| PON-AES128-CTR                      | PON-CRC-BIP                           |
|-------------------------------------+---------------------------------------|
| CHACHA20 AEAD                       | POLY1305 AEAD                         |
|-------------------------------------+---------------------------------------|
| SNOW-V AEAD                         | SNOW-V AEAD (GHASH)                   |
+-------------------------------------+---------------------------------------+
```

## 2. Processor Extensions and Architecture Types

Table 4. Processor extensions used in the library
```
+---------------------------------------------------------------------------------------+
| Architecture  | Instruction Extensions                 | Example Products             |
| Type          |                                        |                              |
|---------------+----------------------------------------+------------------------------|
| SSE Type 1    | SSE4.2, AESNI, PCLMULQDQ, CMOV, BSWAP  | Westmere, Sandy Bridge,      |
|               |                                        | Ivy Bridge, Rangeley, Avoton |
|---------------+----------------------------------------+------------------------------|
| SSE Type 2    | [SSE Type 1] + SHANI                   | Denverton                    |
|---------------+----------------------------------------+------------------------------|
| SSE Type 3    | [SSE Type 2] + GFNI                    | Snow Ridge                   |
|---------------+----------------------------------------+------------------------------|
| AVX2 Type 1   | [SSE Type 1] + XSAVE, OSXSAVE, AVX,    | Haswell, Broadwell           |
|               | AVX2, BMI2                             |                              |
|---------------+----------------------------------------+------------------------------|
| AVX2 Type 2   | [AVX2 Type 1] + SHANI, GFNI, VAES,     | Arizona Beach, Alder Lake    |
|               | VPCLMULQDQ                             | Raptor Lake                  |
|---------------+----------------------------------------+------------------------------|
| AVX2 Type 3   | [AVX2 Type 2] + AVX-IFMA               | Sierra Forest                |
|---------------+----------------------------------------+------------------------------|
| AVX2 Type 4   | [AVX2 Type 3] + SM3NI, SM4NI, SHA512NI | Lunar Lake                   |
|---------------+----------------------------------------+------------------------------|
| AVX512 Type 1 | [AVX2 Type 1] + AVX512F, AVX512DQ,     | Sky Lake, Cascade Lake       |
|               | AVX512CD, AVX512BW, AVX512VL           |                              |
|---------------+----------------------------------------+------------------------------|
| AVX512 Type 2 | [AVX512 Type 1] + SHANI, GFNI,         | Ice Lake, Sapphire Rapids,   |
|               | AVX512-IFMA, VAES, VPCLMULQDQ          | Emerald Rapids               |
|---------------+----------------------------------------+------------------------------|
| AVX10 Type 1  | [AVX512 Type 2] + SM3NI, SM4NI,        |                              |
|               | SHA512NI, APX, AVX10.2                 |                              |
+---------------------------------------------------------------------------------------+
```

## 3. Recommendations

Legacy or to be avoided algorithms listed in the table below are implemented
in the library in order to support legacy applications. Please use corresponding
alternative algorithms instead.
```
+--------------------------------------------------------------+
| # | Algorithm           | Recommendation | Alternative       |
|---+---------------------+----------------+-------------------|
| 1 | DES encryption      | Avoid          | AES encryption    |
|---+---------------------+----------------+-------------------|
| 2 | 3DES encryption     | Avoid          | AES encryption    |
|---+---------------------+----------------+-------------------|
| 3 | HMAC-MD5 integrity  | Legacy         | HMAC-SHA256       |
|---+---------------------+----------------+-------------------|
| 4 | AES-ECB encryption  | Avoid          | AES-CBC, AES-CNTR |
|---+---------------------+----------------+-------------------|
| 3 | HMAC-SHA1 integrity | Avoid          | HMAC-SHA256       |
+--------------------------------------------------------------+
```
Intel(R) Multi-Buffer Crypto for IPsec Library depends on C library and
it is recommended to use its latest version.

Applications using the Intel(R) Multi-Buffer Crypto for IPsec Library rely on
Operating System to provide process isolation.
As the result, it is recommended to use latest Operating System patches and
security updates.

## 4. Package Content

- test - Library test applications
- perf - Library performance application
- lib - Library source files
- lib/x86_64 - Non-SIMD routines
- lib/sse_* - Intel(R) SSE optimized routines
- lib/avx2_* - Intel(R) AVX2 optimized routines
- lib/avx512_* - Intel(R) AVX512 optimized routines

**Note:**   
There is just one branch used in the project. All development is done on the main branch.  
Code taken from the tip of the main branch should not be considered fit for production.  

Refer to the releases tab for stable code versions:  
https://github.com/intel/intel-ipsec-mb/releases

## 5. Documentation

Full documentation can be found at: https://intel.github.io/intel-ipsec-mb

To generate documentation locally, run:  
`> make doxy`

## 6. Compilation

Refer to the compilation section of the [INSTALL](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#compilation) file for instructions.

## 7. Installation

Refer to the installation section of the [INSTALL](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#installation) file for instructions.

## 8. Security Considerations & Options for Increased Security

Refer to the [SECURITY](https://github.com/intel/intel-ipsec-mb/blob/main/SECURITY.md#security-considerations--options-for-increased-security) file for security related information.

## 9. Backwards compatibility

In version 1.4, backward compile time symbol compatibility with
library version 0.53 has been removed.

Applications are encouraged to use new symbol names introduced in version 0.54.

If required, compatibility symbol mapping can be implemented in the application.
See compatibility symbol mapping in v1.3 header file:
https://github.com/intel/intel-ipsec-mb/blob/v1.3/lib/intel-ipsec-mb.h#L246

## 10. Disclaimer (ZUC, KASUMI, SNOW3G)

Please note that cryptographic material, such as ciphering algorithms, may be
subject to national regulations. What is more, use of some algorithms in
real networks and production equipment can be subject to agreement or
licensing by the GSMA and/or the ETSI.

For more details please see:  
- GSMA https://www.gsma.com/security/security-algorithms/  
- ETSI https://www.etsi.org/security-algorithms-and-codes/cellular-algorithm-licences

## 11. Legal Disclaimer

THIS SOFTWARE IS PROVIDED BY INTEL"AS IS". NO LICENSE, EXPRESS OR   
IMPLIED, BY ESTOPPEL OR OTHERWISE, TO ANY INTELLECTUAL PROPERTY RIGHTS   
ARE GRANTED THROUGH USE. EXCEPT AS PROVIDED IN INTEL'S TERMS AND   
CONDITIONS OF SALE, INTEL ASSUMES NO LIABILITY WHATSOEVER AND INTEL  
DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY, RELATING TO SALE AND/OR   
USE OF INTEL PRODUCTS INCLUDING LIABILITY OR WARRANTIES RELATING TO   
FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABILITY, OR INFRINGEMENT   
OF ANY PATENT, COPYRIGHT OR OTHER INTELLECTUAL PROPERTY RIGHT.  

## 12. FIPS Compliance

The library does not fulfill technical requirements to achieve Cryptographic Module (CMVP) certification as a standalone component. It is fit for Cryptographic Algorithm validation and certification (CAVP) and it can be part of CMVP as one of the components.

### CAVP

ACVP test application located in `test` directory is to support CAVP process. It implements validation of the following algorithms:  
- AES-GCM  
- AES-GMAC  
- AES-CCM  
- AES-CBC  
- AES-EBC
- AES-CFB
- TDES-EDE-CBC  
- AES-CTR  
- AES-CMAC  
- SHA1 (SHA-1)  
- SHA224 (SHA2-224)  
- SHA256 (SHA2-256)  
- SHA384 (SHA2-384)  
- SHA512 (SHA2-512)  
- HMAC-SHA1 (HMAC-SHA-1)  
- HMAC-SHA224 (HMAC-SHA2-224)  
- HMAC-SHA256 (HMAC-SHA2-256)  
- HMAC-SHA384 (HMAC-SHA2-384)  
- HMAC-SHA512 (HMAC-SHA2-512)  
- SHA3-224  
- SHA3-256  
- SHA3-384  
- SHA3-512  
- SHAKE-128  
- SHAKE-256  

Note: the acvp-app requires libacvp 2.0+ to be built.

### CAVP Algorithm Parameters

**Note:** all sizes in bits
```
+--------------------------------------------------------------------------------------------+
| Algorithm           | Standard  | Parameters                                               |
|---------------------+-----------+----------------------------------------------------------|
| AES-GCM             | SP800-38D | Key size: 128, 192, 256                                  |
|                     |           | Direction: encrypt and decrypt                           |
|                     |           | ivLen: [min = 8, max = 1024, increment 8]                |
|                     |           | tagLen: 32, 64, 96, 104, 112, 120, 128                   |
|                     |           | payloadLen: [min = 0, max = 65536, increment = 8]        |
|                     |           | aadLen: [min = 0, max = 65536, increment = 8]            |
|---------------------+-----------+----------------------------------------------------------|
| AES-CBC             | SP800-38A | Key size: 128, 192, 256                                  |
|                     |           | Direction: encrypt and decrypt                           |
|---------------------+-----------+----------------------------------------------------------|
| AES-CTR             | SP800-38A | Key size: 128, 192, 256                                  |
|                     |           | Direction: encrypt and decrypt                           |
|                     |           | payloadLen: [min = 8, max = 128, increment = 8]          |
|---------------------+-----------+----------------------------------------------------------|
| AES-ECB             | SP800-38A | Key size: 128, 192, 256                                  |
|                     |           | Direction: encrypt and decrypt                           |
|---------------------+-----------+----------------------------------------------------------|
| AES-CFB128          | SP800-38A | Key size: 128, 192, 256                                  |
|                     |           | Direction: encrypt and decrypt                           |
|---------------------+-----------+----------------------------------------------------------|
| TDES-EDE-CBC        | SP800-38A | Key size: 192                                            |
|                     |           | Direction: encrypt and decrypt                           |
|---------------------+-----------+----------------------------------------------------------|
| SHA1 (SHA-1)        | FIPS180-4 | messageLength: [min = 0, max = 65528, increment = 8]     |
|---------------------+-----------+----------------------------------------------------------|
| SHA224 (SHA2-224)   | FIPS180-4 | messageLength: [min = 0, max = 65528, increment = 8]     |
|---------------------+-----------+----------------------------------------------------------|
| SHA256 (SHA2-256)   | FIPS180-4 | messageLength: [min = 0, max = 65528, increment = 8]     |
|---------------------+-----------+----------------------------------------------------------|
| SHA384 (SHA2-384)   | FIPS180-4 | messageLength: [min = 0, max = 65528, increment = 8]     |
|---------------------+-----------+----------------------------------------------------------|
| SHA512 (SHA2-512)   | FIPS180-4 | messageLength: [min = 0, max = 65528, increment = 8]     |
|---------------------+-----------+----------------------------------------------------------|
| AES-CCM             | SP800-38C | Key size: 128, 256                                       |
|                     |           | Direction: encrypt and decrypt                           |
|                     |           | ivLen: [min = 56, max = 104, increment 8]                |
|                     |           | tagLen: 32, 48, 64, 80, 96, 112, 128                     |
|                     |           | payloadLen: [min = 0, max = 256, increment = 8]          |
|                     |           | aadLen: [min = 0, max = 368, increment = 8]              |
|---------------------+-----------+----------------------------------------------------------|
| AES-GMAC            | SP800-38B | Key size: 128, 192, 256                                  |
|                     |           | ivLen: [min = 8, max = 1024, increment 8]                |
|                     |           | tagLen: 32, 64, 96, 104, 112, 120, 128                   |
|                     |           | aadLen: [min = 0, max = 65536, increment = 8]            |
|---------------------+-----------+----------------------------------------------------------|
| AES-CMAC            | SP800-38B | Key size: 128, 256                                       |
|                     |           | msgLen: [min = 8, max = 65528, increment 8]              |
|                     |           | macLen: [min = 8, max = 128, increment = 8]              |
|---------------------+-----------+----------------------------------------------------------|
| HMAC-SHA1           | FIPS198-1 | keyLen: [min = 8, max = 524288, increment = 8]           |
| (HMAC-SHA-1)        |           | macLen: [min = 32, max = 160, increment = 8]             |
|---------------------+-----------+----------------------------------------------------------|
| HMAC-SHA224         | FIPS198-1 | keyLen: [min = 8, max = 524288, increment = 8]           |
| (HMAC-SHA2-224)     |           | macLen: [min = 32, max = 224, increment = 8]             |
|---------------------+-----------+----------------------------------------------------------|
| HMAC-SHA256         | FIPS198-1 | keyLen: [min = 8, max = 524288, increment = 8]           |
| (HMAC-SHA2-256)     |           | macLen: [min = 32, max = 256, increment = 8]             |
|---------------------+-----------+----------------------------------------------------------|
| HMAC-SHA384         | FIPS198-1 | keyLen: [min = 8, max = 524288, increment = 8]           |
| (HMAC-SHA2-384)     |           | macLen: [min = 32, max = 384, increment = 8]             |
|---------------------+-----------+----------------------------------------------------------|
| HMAC-SHA512         | FIPS198-1 | keyLen: [min = 8, max = 524288, increment = 8]           |
| (HMAC-SHA2-512)     |           | macLen: [min = 32, max = 512, increment = 8]             |
|---------------------+-----------+----------------------------------------------------------|
| SHA3-224            | FIPS202   | messageLength: [min = 0, max = 65536, increment = 8]     |
|---------------------+-----------+----------------------------------------------------------|
| SHA3-256            | FIPS202   | messageLength: [min = 0, max = 65536, increment = 8]     |
|---------------------+-----------+----------------------------------------------------------|
| SHA3-384            | FIPS202   | messageLength: [min = 0, max = 65536, increment = 8]     |
|---------------------+-----------+----------------------------------------------------------|
| SHA3-512            | FIPS202   | messageLength: [min = 0, max = 65536, increment = 8]     |
|---------------------+-----------+----------------------------------------------------------|
| SHAKE-128           | FIPS202   | outputLen: [min = 16, max = 65536, increment = 8]        |
|---------------------+-----------+----------------------------------------------------------|
| SHAKE-256           | FIPS202   | outputLen: [min = 16, max = 65536, increment = 8]        |
+--------------------------------------------------------------------------------------------+
```
### Self-Test

In order to support CMVP, the library implements Self-Test functionality that is available with all compilation options.
The test is always performed as part of library initialization (power-up). There is no conditional self-test functionality as none of such conditions occur (i.e. pair-wise consistency test,
software/firmware load test, manual key entry test, continuous random number generator test, and
bypass test).

Application can register self-test callback function to track test progress. Optionally application can corrupt input message for selected tests and observe change in the test result.

Example sequence of callbacks received by an application is:
- callback(data.phase = IMB_SELF_TEST_PHASE_START, data.type = IMB_SELF_TEST_TYPE_KAT_CIPHER, data.descr = "AES128-CBC") => return 1
- callback(data.phase = IMB_SELF_TEST_PHASE_CORRUPT)
  - return 1: no message corruption
  - return 0: corrupt single bit in the 1st byte
- callback(data.phase = IMB_SELF_TEST_PHASE_PASS or IMB_SELF_TEST_PHASE_PASS) => return 1
- callback(data.phase = IMB_SELF_TEST_PHASE_START, data.type = IMB_SELF_TEST_TYPE_KAT_CIPHER, data.descr = "AES192-CBC") => return 1
- ...
Note that value returned by application self-test callback function only matters in the corrupt phase.

The self-test consists of Cryptographic algorithm test (known answer test) on following types and algorithms:  
- KAT_AEAD:
  - AES-GCM  
  - AES-CCM  
- KAT_Cipher:
  - AES-CBC  
  - AES-CTR  
  - AES-ECB  
  - AES-CFB
  - TDES-EDE-CBC  
- KAT_Auth:
  - AES-GMAC  
  - AES-CMAC  
  - SHA1  
  - SHA224  
  - SHA256  
  - SHA384  
  - SHA512  
  - HMAC-SHA1  
  - HMAC-SHA224  
  - HMAC-SHA256  
  - HMAC-SHA384  
  - HMAC-SHA512  
  - SHA3-224  
  - SHA3-256  
  - SHA3-384  
  - SHA3-512  
  - SHAKE-128  
  - SHAKE-256  

KAT_Cipher and KAT_AEAD types conduct tests in encrypt and decrypt cipher directions. However, the corrupt callback is made only for the encrypt direction. No callback is made for the decrypt direction at the moment.

Example detection of library self-test completion & error in the application:
```
IMB_ARCH arch;
IMB_MGR *p_mgr = alloc_mb_mgr(0);

init_mb_mgr_auto(p_mgr, &arch); /* or init_mb_mgr_sse/avx/avx2/avx512 */

/*
 * check for self-test presence and successful
 * - requires library version v1.3 or newer
 */
if (p_mgr->features & IMB_FEATURE_SELF_TEST) {
        /* self-test feature present */
        if (p_mgr->features & IMB_FEATURE_SELF_TEST_PASS) {
                printf("SELF-TEST: PASS\n");
        } else {
                printf("SELF-TEST: FAIL\n");
	}
} else {
        printf("SELF-TEST: N/A (requires library >= v1.3)\n");
}

/* check for initialization self-test error */
if (imb_get_errno(p_mgr) == IMB_ERR_SELFTEST) {
        /* self-test error */
        exit(EXIT_FAILURE);
}
```

Example registration of self-test callback function:
```
int self_test_corrupt = 0;

int callback(void *arg, const IMB_SELF_TEST_CALLBACK_DATA *data)
{
        const char *phase = "";
        const char *type = "";
        const char *descr = "";

        (void) arg;

        if (data != NULL) {
                if (data->phase != NULL)
                        phase = data->phase;
                if (data->type != NULL)
                        type = data->type;
                if (data->descr != NULL)
                        descr = data->descr;
        }

        if (strcmp(phase, IMB_SELF_TEST_PHASE_START) == 0)
                printf("%s : %s : ", type, descr);

        if ((strcmp(phase, IMB_SELF_TEST_PHASE_CORRUPT) == 0) && (self_test_corrupt == 1))
                return 0; /* corrupt input message */

        if (strcmp(phase, IMB_SELF_TEST_PHASE_PASS) == 0 ||
            strcmp(phase, IMB_SELF_TEST_PHASE_FAIL) == 0)
                printf("%s\n", phase);

        return 1;
}

...

IMB_ARCH arch;
IMB_MGR *p_mgr = alloc_mb_mgr(0);

/*
 * Register self-test callback that will be invoked during
 * subsequent init operation
 */
imb_self_test_set_cb(p_mgr, callback, NULL);

init_mb_mgr_auto(p_mgr, &arch); /* or init_mb_mgr_sse/avx/avx2/avx512 */

...

```

## 13.DLL Injection Attack

### Problem

The Windows OS has an insecure predefined search order and set of defaults when trying to locate a resource. If the resource location is not specified by the software, an attacker need only place a malicious version in one of the locations Windows will search, and it will be loaded instead. Although this weakness can occur with any resource, it is especially common with DLL files.

### Solutions

Applications using intel-ipsec-mb DLL library may need to apply one of the solutions to prevent from DLL injection attack.

Two solutions are available:
- Using a Fully Qualified Path is the most secure way to load a DLL    
- Signature verification of the DLL    

### Resources and Solution Details

- Security remarks section of LoadLibraryEx documentation by Microsoft: <https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa#security-remarks>   
- Microsoft Dynamic Link Library Security article: <https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security>   
- Hijack Execution Flow: DLL Search Order Hijacking: <https://attack.mitre.org/techniques/T1574/001>    
- Hijack Execution Flow: DLL Side-Loading: <https://attack.mitre.org/techniques/T1574/002>    
