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
+---------------------------------------------------------------------------------+
|                |                        Implementation                          |
| Encryption     +----------------------------------------------------------------|
|                | x86_64 | SSE      | AVX    | AVX2         | AVX512 | AVX512(3) |
|                |        | Type 1/2 | Type 1 | Type 1/2/3/4 | Type 1 | Type 2    |
|----------------+--------+----------+--------+--------------+--------+-----------|
| AES128-GCM     | N      | Y  by8   | N      | Y(7)         | Y  by8 | Y by32    |
| AES192-GCM     | N      | Y  by8   | N      | Y(7)         | Y  by8 | Y by32    |
| AES256-GCM     | N      | Y  by8   | N      | Y(7)         | Y  by8 | Y by32    |
| AES128-CCM     | N      | Y  by8   | N      | Y  by8       | N      | Y by16    |
| AES256-CCM     | N      | Y  by8   | N      | Y  by8       | N      | Y by16    |
| AES128-CBC     | N      | Y(2)     | N      | Y(2)         | N      | Y(4)      |
| AES192-CBC     | N      | Y(2)     | N      | Y(2)         | N      | Y(4)      |
| AES256-CBC     | N      | Y(2)     | N      | Y(2)         | N      | Y(4)      |
| AES128-CTR     | N      | Y  by8   | N      | Y(7)         | N      | Y by16    |
| AES192-CTR     | N      | Y  by8   | N      | Y(7)         | N      | Y by16    |
| AES256-CTR     | N      | Y  by8   | N      | Y(7)         | N      | Y by16    |
| AES128-ECB     | N      | Y(2)     | N      | Y(7)         | N      | Y by16    |
| AES192-ECB     | N      | Y(2)     | N      | Y(7)         | N      | Y by16    |
| AES256-ECB     | N      | Y(2)     | N      | Y(7)         | N      | Y by16    |
| AES128-CFB     | N      | Y        | N      | N            | N      | Y(4)      |
| AES192-CFB     | N      | Y        | N      | N            | N      | Y(4)      |
| AES256-CFB     | N      | Y        | N      | N            | N      | Y(4)      |
| NULL           | Y      | N        | N      | N            | N      | N         |
| AES128-DOCSIS  | N      | Y(2)     | N      | Y(2)         | Y(5)   | Y(4)      |
| AES256-DOCSIS  | N      | Y(2)     | N      | Y(2)         | Y(5)   | Y(4)      |
| DES-DOCSIS     | Y      | N        | N      | N            | Y  x16 | N         |
| 3DES           | Y      | N        | N      | N            | Y  x16 | N         |
| DES            | Y      | N        | N      | N            | Y  x16 | N         |
| KASUMI-F8      | Y      | N        | N      | N            | N      | N         |
| ZUC-EEA3       | N      | Y  x4    | N      | Y  x8        | Y  x16 | Y  x16    |
| ZUC-EEA3-256   | N      | Y  x4    | N      | Y  x8        | Y  x16 | Y  x16    |
| SNOW3G-UEA2    | N      | Y  x4    | N      | Y            | Y  x16 | Y  x16    |
| AES128-CBCS(6) | N      | Y(1)     | N      | Y(2)         | N      | Y(4)      |
| Chacha20       | N      | Y        | N      | Y            | Y      | N         |
| Chacha20 AEAD  | N      | Y        | N      | Y            | Y      | N         |
| SNOW-V         | N      | Y        | Y      | N            | N      | N         |
| SNOW-V AEAD    | N      | Y        | Y      | N            | N      | N         |
| PON-CRC-BIP    | N      | Y  by8   | Y  by8 | N            | N      | Y         |
| SM4-ECB        | N      | Y        | N      | Y(8)         | N      | N         |
| SM4-CBC        | N      | Y        | N      | Y(9)         | N      | N         |
| SM4-CTR        | N      | Y        | N      | Y(10)        | N      | N         |
| SM4-GCM        | N      | Y        | N      | Y(10)        | N      | N         |
+---------------------------------------------------------------------------------+
```
Notes:  
(1)   - decryption is by4 and encryption is x4  
(2)   - decryption is by8 and encryption is x8  
(3)   - AVX512 plus VAES, VPCLMULQDQ and GFNI extensions  
(4)   - decryption is by16 and encryption is x16  
(5)   - same as AES-CBC for AVX, combines cipher and CRC32  
(6)   - currently 1:9 crypt:skip pattern supported  
(7)   - by default, decryption and encryption are AVX by8.  
        On CPUs supporting VAES, decryption and encryption might use AVX2-VAES by16,
        if beneficial.
(8)   - AVX2 using SM4-NI ISA, by16, if the ISA is available, if not,
        fallback to SSE implementation.
(9)   - AVX2 using SM4-NI ISA if the ISA is available, if not,
        fallback to SSE implementation. Single block in encryption,
        by16 in decryption.
(10)  - AVX2 using SM4-NI ISA, by8, if the ISA is available, if not,
        fallback to SSE implementation.

Legend:  
` byY` - single buffer Y blocks at a time  
`  xY` - Y buffers at a time

As an example of how to read table 1 and 2, if one uses AVX512 interface
to perform AES128-CBC encryption then there is no native AVX512
implementation for this cipher. In such case, the library uses best
available implementation which is AVX for AES128-CBC.


Table 2. List of supported integrity algorithms and their implementations.
```
+------------------------------------------------------------------------------------+
|                   |                        Implementation                          |
| Integrity         +----------------------------------------------------------------|
|                   | x86_64 | SSE      | AVX    | AVX2         | AVX512 | AVX512(3) |
|                   |        | Type 1/2 | Type 1 | Type 1/2/3/4 | Type 1 | Type 2    |
|-------------------+--------+----------+--------+--------------+--------+-----------|
| AES-XCBC-96       | N      | Y   x4   | N      | Y x8         | N      | Y x16     |
| HMAC-MD5-96       | Y(1)   | Y x4x2   | N      | Y x8x2       | N      | N         |
| HMAC-SHA1-96      | N      | Y(2)x4   | N      | Y(2)x8       | Y  x16 | N         |
| HMAC-SHA2-224_112 | N      | Y(2)x4   | N      | Y(2)x8       | Y  x16 | N         |
| HMAC-SHA2-256_128 | N      | Y(2)x4   | N      | Y(2)x8       | Y  x16 | N         |
| HMAC-SHA2-384_192 | N      | Y   x2   | N      | Y(9)x4       | Y   x8 | N         |
| HMAC-SHA2-512_256 | N      | Y   x2   | N      | Y(9)x4       | Y   x8 | N         |
| SHA1              | N      | Y(2)x4   | N      | Y(2)x8       | Y  x16 | N         |
| SHA2-224          | N      | Y(2)x4   | N      | Y(2)x8       | Y  x16 | N         |
| SHA2-256          | N      | Y(2)x4   | N      | Y(2)x8       | Y  x16 | N         |
| SHA2-384          | N      | Y   x2   | N      | Y(9)x4       | Y   x8 | N         |
| SHA2-512          | N      | Y   x2   | N      | Y(9)x4       | Y   x8 | N         |
| AES128-GMAC       | N      | Y  by8   | N      | Y  by8       | Y  by8 | Y by32    |
| AES192-GMAC       | N      | Y  by8   | N      | Y  by8       | Y  by8 | Y by32    |
| AES256-GMAC       | N      | Y  by8   | N      | Y  by8       | Y  by8 | Y by32    |
| NULL              | Y      | N        | N      | N            | N      | N         |
| AES128-CCM        | N      | Y   x8   | N      | Y  x8        | N      | Y x16     |
| AES256-CCM        | N      | Y   x8   | N      | Y  x8        | N      | Y x16     |
| AES128-CMAC-96    | Y      | Y   x8   | N      | Y  x8        | N      | Y x16     |
| AES256-CMAC-96    | Y      | Y   x8   | N      | Y  x8        | N      | Y x16     |
| KASUMI-F9         | Y      | N        | N      | Y  x8        | N      | N         |
| ZUC-EIA3          | N      | Y  x4    | N      | Y  x8        | Y  x16 | Y  x16    |
| ZUC-EIA3-256      | N      | Y  x4    | N      | Y  x8        | Y  x16 | Y  x16    |
| SNOW3G-UIA2(7)    | N      | Y by4    | N      | Y  by4       | Y by32 | Y by32    |
| DOCSIS-CRC32(4)   | N      | Y        | N      | Y            | Y      | Y         |
| HEC               | N      | Y        | Y      | N            | N      | N         |
| POLY1305          | Y      | N        | N      | Y(8)         | Y      | Y         |
| POLY1305 AEAD     | Y      | N        | N      | Y(8)         | Y      | Y         |
| SNOW-V AEAD       | N      | Y  by8   | Y  by8 | Y  by8       | Y  by8 | Y by32    |
| GHASH             | N      | Y  by8   | N      | Y  by8       | Y  by8 | Y by32    |
| CRC(5)            | N      | Y  by8   | N      | Y  by8       | N      | Y by16    |
| PON-CRC-BIP(6)    | N      | Y        | Y      | N            | N      | Y         |
| SM3               | Y      | N        | N      | Y(10)        | N      | N         |
| HMAC-SM3          | Y      | N        | N      | Y(10)        | N      | N         |
| SM4-GCM           | N      | Y        | N      | Y            | N      | N         |
+------------------------------------------------------------------------------------+
```
Notes:  
(1)  - MD5 over one block implemented in C  
(2)  - Implementation using SHANI extensions is x2  
(3)  - AVX512 plus VAES, VPCLMULQDQ, GFNI and IFMA extensions  
(4)  - used only with AES256-DOCSIS and AES128-DOCSIS ciphers  
(5)  - Supported CRC types:
 - CRC32: Ethernet FCS, SCTP, WIMAX OFDMA  
 - CRC24: LTE A, LTE B  
 - CRC16: X25, FP data  
 - CRC11: FP header  
 - CRC10: IUUP data  
 - CRC8: WIMAX OFDMA HCS  
 - CRC7: FP header  
 - CRC6: IUUP header  
(6)  - used only with PON-AES128-CTR cipher  
(7)  - x4/x16 for init keystream generation, then by4/by32  
(8)  - Only if AVX-IFMA instructions are supported  
(9)  - using SHA512-NI ISA and x2 implementation, if the ISA is available  
(10) - using SM3-NI ISA, if available  

Legend:  
` byY`- single buffer Y blocks at a time  
`  xY`- Y buffers at a time  

Table 3. Encryption and integrity algorithm combinations
```
+---------------------------------------------------------------------+
| Encryption    | Allowed Integrity Algorithms                        |
|---------------+-----------------------------------------------------|
| AES128-GCM    | AES128-GMAC                                         |
|---------------+-----------------------------------------------------|
| AES192-GCM    | AES192-GMAC                                         |
|---------------+-----------------------------------------------------|
| AES256-GCM    | AES256-GMAC                                         |
|---------------+-----------------------------------------------------|
| AES128-CCM    | AES128-CCM                                          |
|---------------+-----------------------------------------------------|
| AES256-CCM    | AES256-CCM                                          |
|---------------+-----------------------------------------------------|
| SM4-GCM       | SM4-GCM                                             |
|---------------+-----------------------------------------------------|
| AES128-CBC,   | AES-XCBC-96,                                        |
| AES192-CBC,   | HMAC-SHA1-96, HMAC-SHA2-224_112, HMAC-SHA2-256_128, |
| AES256-CBC,   | HMAC-SHA2-384_192, HMAC-SHA2-512_256,               |
| AES128-CTR,   | AES128-CMAC-96,                                     |
| AES192-CTR,   | NULL,                                               |
| AES256-CTR,   | KASUMI-F9,                                          |
| AES128-ECB,   | ZUC-EIA3, ZUC-EIA3-256,                             |
| AES192-ECB,   | SNOW3G-UIA3,                                        |
| AES256-ECB,   | POLY1305,                                           |
| AES128-CFB,   |                                                     |
| AES192-CFB,   |                                                     |
| AES256-CFB,   |                                                     |
| NULL,         | AES128-GMAC, AES192-GMAC, AES256-GMAC, GHASH,       |
| AES128-DOCSIS,| SM3, HMAC-SM3                                       |
| AES256-DOCSIS,|                                                     |
| DES-DOCSIS,   |                                                     |
| 3DES,         |                                                     |
| DES,          |                                                     |
| Chacha20,     |                                                     |
| KASUMI-F8,    |                                                     |
| ZUC-EEA3,     |                                                     |
| ZUC-EEA3-256, |                                                     |
| SNOW3G-UEA3   |                                                     |
| SNOW-V        |                                                     |
| SM4-ECB       |                                                     |
| SM4-CBC       |                                                     |
| SM4-CTR       |                                                     |
|---------------+-----------------------------------------------------|
| AES128-DOCSIS,| DOCSIS-CRC32                                        |
| AES256-DOCSIS |                                                     |
|---------------+-----------------------------------------------------|
| PON-AES128-CTR| PON-CRC-BIP                                         |
|---------------+-----------------------------------------------------|
| CHACHA20 AEAD | POLY1305 AEAD                                       |
+---------------+-----------------------------------------------------+
| SNOW-V AEAD   | SNOW-V AEAD (GHASH)                                 |
+---------------+-----------------------------------------------------+
```

## 2. Processor Extensions

Table 4. Processor extensions used in the library
```
+-------------------------------------------------------------------------+
| Algorithm         | Interface | Extensions                              |
|-------------------+-----------+-----------------------------------------|
| HMAC-SHA1-96,     | AVX512    | AVX512F, AVX512BW, AVX512VL             |
| HMAC-SHA2-224_112,|           |                                         |
| HMAC-SHA2-256_128,|           |                                         |
| HMAC-SHA2-384_192,|           |                                         |
| HMAC-SHA2-512_256 |           |                                         |
|-------------------+-----------+-----------------------------------------|
| DES, 3DES,        | AVX512    | AVX512F, AVX512BW                       |
| DOCSIS-DES        |           |                                         |
|-------------------+-----------+-----------------------------------------|
| HMAC-SHA1-96,     | SSE       | SHANI                                   |
| HMAC-SHA2-224_112,|           | - presence is autodetected and library  |
| HMAC-SHA2-256_128,|           |   falls back to SSE implementation      |
| HMAC-SHA2-384_192,|           |   if not present                        |
| HMAC-SHA2-512_256 |           |                                         |
+-------------------+-----------+-----------------------------------------+
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
- lib/avx_* - Intel(R) AVX optimized routines
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
