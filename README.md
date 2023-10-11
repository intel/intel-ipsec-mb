![Linux](https://github.com/intel/intel-ipsec-mb/actions/workflows/linux.yml/badge.svg)
![Windows](https://github.com/intel/intel-ipsec-mb/actions/workflows/windows.yml/badge.svg)
![FreeBSD](https://github.com/intel/intel-ipsec-mb/actions/workflows/freebsd.yml/badge.svg)
[![Coverity Status](https://scan.coverity.com/projects/16449/badge.svg)](https://scan.coverity.com/projects/intel-ipsec-mb)

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
7. Security Considerations & Options for Increased Security
8. Installation
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
+----------------------------------------------------------------------+
|                |                   Implementation                    |
| Encryption     +-----------------------------------------------------|
|                | x86_64 | SSE    | AVX    | AVX2   | AVX512 | VAES(5)|
|----------------+--------+--------+--------+--------+--------+--------|
| AES128-GCM     | N      | Y  by8 | N      | Y(10)  | Y  by8 | Y by32 |
| AES192-GCM     | N      | Y  by8 | N      | Y(10)  | Y  by8 | Y by32 |
| AES256-GCM     | N      | Y  by8 | N      | Y(10)  | Y  by8 | Y by32 |
| AES128-CCM     | N      | Y  by8 | Y  by8 | N      | N      | Y by16 |
| AES256-CCM     | N      | Y  by8 | Y  by8 | N      | N      | Y by16 |
| AES128-CBC     | N      | Y(1)   | Y(3)   | N      | N      | Y(6)   |
| AES192-CBC     | N      | Y(1)   | Y(3)   | N      | N      | Y(6)   |
| AES256-CBC     | N      | Y(1)   | Y(3)   | N      | N      | Y(6)   |
| AES128-CTR     | N      | Y  by8 | Y  by8 | Y(10)  | N      | Y by16 |
| AES192-CTR     | N      | Y  by8 | Y  by8 | Y(10)  | N      | Y by16 |
| AES256-CTR     | N      | Y  by8 | Y  by8 | Y(10)  | N      | Y by16 |
| AES128-ECB     | N      | Y(1)   | Y  by8 | Y(10)  | N      | Y by16 |
| AES192-ECB     | N      | Y(1)   | Y  by8 | Y(10)  | N      | Y by16 |
| AES256-ECB     | N      | Y(1)   | Y  by8 | Y(10)  | N      | Y by16 |
| NULL           | Y      | N      | N      | N      | N      | N      |
| AES128-DOCSIS  | N      | Y(2)   | Y(4)   | N      | Y(7)   | Y(8)   |
| AES256-DOCSIS  | N      | Y(2)   | Y(4)   | N      | Y(7)   | Y(8)   |
| DES-DOCSIS     | Y      | N      | N      | N      | Y  x16 | N      |
| 3DES           | Y      | N      | N      | N      | Y  x16 | N      |
| DES            | Y      | N      | N      | N      | Y  x16 | N      |
| KASUMI-F8      | Y      | N      | N      | N      | N      | N      |
| ZUC-EEA3       | N      | Y  x4  | Y  x4  | Y  x8  | Y  x16 | Y  x16 |
| ZUC-EEA3-256   | N      | Y  x4  | Y  x4  | Y  x8  | Y  x16 | Y  x16 |
| SNOW3G-UEA2    | N      | Y  x4  | Y      | Y      | Y  x16 | Y  x16 |
| AES128-CBCS(9) | N      | Y(1)   | Y(3)   | N      | N      | Y(6)   |
| Chacha20       | N      | Y      | Y      | Y      | Y      | N      |
| Chacha20 AEAD  | N      | Y      | Y      | Y      | Y      | N      |
| SNOW-V         | N      | Y      | Y      | N      | N      | N      |
| SNOW-V AEAD    | N      | Y      | Y      | N      | N      | N      |
| PON-CRC-BIP    | N      | Y  by8 | Y  by8 | N      | N      | Y      |
| SM4-ECB        | N      | Y      | N      | N      | N      | N      |
| SM4-CBC        | N      | Y      | N      | N      | N      | N      |
+----------------------------------------------------------------------+
```
Notes:  
(1,2) - By default, decryption is by4 and encryption is x4.  
        On CPU's supporting GFNI, decryption is by8 and encryption is x8.  
(3,4) - decryption is by8 and encryption is x8  
(5)   - AVX512 plus VAES, VPCLMULQDQ and GFNI extensions  
(6)   - decryption is by16 and encryption is x16  
(7)   - same as AES128-CBC for AVX, combines cipher and CRC32  
(8)   - decryption is by16 and encryption is x16  
(9)   - currently 1:9 crypt:skip pattern supported  
(10)  - by default, decryption and encryption are AVX by8.  
        On CPUs supporting VAES, decryption and encryption are AVX2-VAES by16.  

Legend:  
` byY` - single buffer Y blocks at a time  
`  xY` - Y buffers at a time

As an example of how to read table 1 and 2, if one uses AVX512 interface
to perform AES128-CBC encryption then there is no native AVX512
implementation for this cipher. In such case, the library uses best
available implementation which is AVX for AES128-CBC.


Table 2. List of supported integrity algorithms and their implementations.
```
+-------------------------------------------------------------------------+
|                   |                   Implementation                    |
| Integrity         +-----------------------------------------------------|
|                   | x86_64 | SSE    | AVX    | AVX2   | AVX512 | VAES(3)|
|-------------------+--------+--------+--------+--------+--------+--------|
| AES-XCBC-96       | N      | Y   x4 | Y   x8 | N      | N      | Y x16  |
| HMAC-MD5-96       | Y(1)   | Y x4x2 | Y x4x2 | Y x8x2 | N      | N      |
| HMAC-SHA1-96      | N      | Y(2)x4 | Y   x4 | Y   x8 | Y  x16 | N      |
| HMAC-SHA2-224_112 | N      | Y(2)x4 | Y   x4 | Y   x8 | Y  x16 | N      |
| HMAC-SHA2-256_128 | N      | Y(2)x4 | Y   x4 | Y   x8 | Y  x16 | N      |
| HMAC-SHA2-384_192 | N      | Y   x2 | Y   x2 | Y   x4 | Y   x8 | N      |
| HMAC-SHA2-512_256 | N      | Y   x2 | Y   x2 | Y   x4 | Y   x8 | N      |
| SHA1              | N      | Y(2)x4 | Y   x4 | Y   x8 | Y  x16 | N      |
| SHA2-224          | N      | Y(2)x4 | Y   x4 | Y   x8 | Y  x16 | N      |
| SHA2-256          | N      | Y(2)x4 | Y   x4 | Y   x8 | Y  x16 | N      |
| SHA2-384          | N      | Y   x2 | Y   x2 | Y   x4 | Y   x8 | N      |
| SHA2-512          | N      | Y   x2 | Y   x2 | Y   x4 | Y   x8 | N      |
| AES128-GMAC       | N      | Y  by8 | N      | Y  by8 | Y  by8 | Y by32 |
| AES192-GMAC       | N      | Y  by8 | N      | Y  by8 | Y  by8 | Y by32 |
| AES256-GMAC       | N      | Y  by8 | N      | Y  by8 | Y  by8 | Y by32 |
| NULL              | Y      | N      | N      | N      | N      | N      |
| AES128-CCM        | N      | Y(5)x4 | Y   x8 | N      | N      | Y x16  |
| AES256-CCM        | N      | Y(5)x4 | Y   x8 | N      | N      | Y x16  |
| AES128-CMAC-96    | Y      | Y(5)x4 | Y   x8 | N      | N      | Y x16  |
| AES256-CMAC-96    | Y      | Y(5)x4 | Y   x8 | N      | N      | Y x16  |
| KASUMI-F9         | Y      | N      | N      | N      | N      | N      |
| ZUC-EIA3          | N      | Y  x4  | Y  x4  | Y  x8  | Y  x16 | Y  x16 |
| ZUC-EIA3-256      | N      | Y  x4  | Y  x4  | Y  x8  | Y  x16 | Y  x16 |
| SNOW3G-UIA2(8)    | N      | Y by4  | Y by4  | N      | Y by32 | Y by32 |
| DOCSIS-CRC32(4)   | N      | Y      | Y      | N      | Y      | Y      |
| HEC               | N      | Y      | Y      | N      | N      | N      |
| POLY1305          | Y      | N      | N      | Y(9)   | Y      | Y      |
| POLY1305 AEAD     | Y      | N      | N      | Y(9)   | Y      | Y      |
| SNOW-V AEAD       | N      | Y  by8 | Y  by8 | Y  by8 | Y  by8 | Y by32 |
| GHASH             | N      | Y  by8 | N      | Y  by8 | Y  by8 | Y by32 |
| CRC(6)            | N      | Y  by8 | Y  by8 | N      | N      | Y by16 |
| PON-CRC-BIP(7)    | N      | Y      | Y      | N      | N      | Y      |
| SM3               | Y      | N      | N      | N      | N      | N      |
+-------------------------------------------------------------------------+
```
Notes:  
(1) - MD5 over one block implemented in C  
(2) - Implementation using SHANI extensions is x2  
(3) - AVX512 plus VAES, VPCLMULQDQ, GFNI and IFMA extensions  
(4) - used only with AES256-DOCSIS and AES128-DOCSIS ciphers  
(5) - x8 on selected CPU's supporting GFNI  
(6) - Supported CRC types:
 - CRC32: Ethernet FCS, SCTP, WIMAX OFDMA  
 - CRC24: LTE A, LTE B  
 - CRC16: X25, FP data  
 - CRC11: FP header  
 - CRC10: IUUP data  
 - CRC8: WIMAX OFDMA HCS  
 - CRC7: FP header  
 - CRC6: IUUP header  
(7) - used only with PON-AES128-CTR cipher  
(8) - x4/x16 for init keystream generation, then by4/by32  
(9) - Only if AVX-IFMA instructions are supported

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
| AES128-CBC,   | AES-XCBC-96,                                        |
| AES192-CBC,   | HMAC-SHA1-96, HMAC-SHA2-224_112, HMAC-SHA2-256_128, |
| AES256-CBC,   | HMAC-SHA2-384_192, HMAC-SHA2-512_256,               |
| AES128-CTR,   | AES128-CMAC-96,                                     |
| AES192-CTR,   | NULL,                                               |
| AES256-CTR,   | KASUMI-F9,                                          |
| AES128-ECB,   | ZUC-EIA3, ZUC-EIA3-256,                             |
| AES192-ECB,   | SNOW3G-UIA3,                                        |
| AES256-ECB,   | POLY1305,                                           |
| NULL,         | AES128-GMAC, AES192-GMAC, AES256-GMAC, GHASH        |
| AES128-DOCSIS,|                                                     |
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
- lib/sse - Intel(R) SSE optimized routines
- lib/avx - Intel(R) AVX optimized routines
- lib/avx2 - Intel(R) AVX2 optimized routines
- lib/avx512 - Intel(R) AVX512 optimized routines
- lib/no-aesni - Non-AESNI accelerated routines

**Note:**   
There is just one branch used in the project. All development is done on the master branch.  
Code taken from the tip of the master branch should not be considered fit for production.  

Refer to the releases tab for stable code versions:  
https://github.com/intel/intel-ipsec-mb/releases

## 5. Documentation

Full documentation can be found at: https://intel.github.io/intel-ipsec-mb

To generate documentation locally, run:  
`> make doxy`

## 6. Compilation

### Linux (64-bit only)

Required tools:  
- GNU make  
- NASM version 2.14 (or newer)  
- gcc (GCC) 4.8.3 (or newer)  

Shared library:  
`> make`

Static library:  
`> make SHARED=n`

Clean the build:  
`> make clean`  
or  
`> make clean SHARED=n`

Build with debugging information:  
`> make DEBUG=y`

Build with AESNI emulation support (disabled by default):  
`> make AESNI_EMU=y`

**Note:** Building with debugging information is not advised for production use.

For more build options and their explanation run:   
`> make help`

### Windows MSVS (x64 only)

Required tools:  
- Microsoft (R) Visual Studio 2019:  
  - NMAKE: Microsoft (R) Program Maintenance Utility Version 14.29.30148.0  
  - CL: Microsoft (R) C/C++ Optimizing Compiler Version 19.29.30148 for x64  
  - LIB: Microsoft (R) Library Manager Version 14.29.30148.0  
  - LINK: Microsoft (R) Incremental Linker Version 14.29.30148.0  
  - Note: Building on later versions should work but is not verified  
- NASM version 2.14 (or newer)  

Shared library (DLL):  
`> nmake /f win_x64.mak`

Static library:  
`> nmake /f win_x64.mak SHARED=n`

Clean the build:   
`> nmake /f win_x64.mak clean`   
or   
`> nmake /f win_x64.mak clean SHARED=n`

Build without safety features:  
- SAFE_DATA clears sensitive information stored temporarily on stack, registers or internal data structures  
- SAFE_PARAM adds extra checks on input parameters  
- SAFE_LOOKUP uses constant-time lookups (enabled by default)  
- SAFE_OPTIONS additional option to disable all safe options. Enabled by default.  
  Disable to turn off: SAFE_DATA, SAFE_PARAM and SAFE_LOOKUP.  

`> nmake /f win_x64.mak SAFE_DATA=n SAFE_PARAM=n`
`> nmake /f win_x64.mak SAFE_OPTIONS=n`

Build with debugging information:   
`> nmake /f win_x64.mak DEBUG=y`

Build with AESNI emulation support (disabled by default):   
`> nmake /f win_x64.mak AESNI_EMU=y`

**Note:** Building with debugging information is not advised for production use.

For more build options and their explanation run:   
`> nmake /f win_x64.mak help`

### Windows Mingw-w64 (64-bit only)

Required tools:  
- GNU mingw32-make.exe  
- NASM version 2.14 (or newer)  
- gcc (GCC) 10.3.0 (or newer)

Shared library:  
`> mingw32-make.exe`

Static library:  
`> mingw32-make.exe SHARED=n`

Clean the build:  
`> mingw32-make.exe clean`  
or  
`> mingw32-make.exe clean SHARED=n`

Build with debugging information:  
`> mingw32-make.exe DEBUG=y`

**Note:** Building with debugging information is not advised for production use.

For more build options and their explanation run:   
`> mingw32-make.exe help`

### FreeBSD (64-bit only)

Required tools:  
- GNU make  
- NASM version 2.14 (or newer)  
- gcc (GCC) 4.8.3 (or newer) / clang 5.0 (or newer)  

Shared library:   
`> gmake`

Static library:   
`> gmake SHARED=n`

Clean the build:   
`> gmake clean`   
or   
`> gmake clean SHARED=n`

Build with debugging information:   
`> gmake DEBUG=y`

**Note:** Building with debugging information is not advised for production use.

For more build options and their explanation run:   
`> gmake help`

### Building with CMake (experimental)

Minimum CMake version: 3.16

Create build directory:
```
mkdir build
cd build
```

#### Unix Makefiles (Linux and FreeBSD)

Shared library (default):
```
cmake ..
cmake --build . --parallel
```

Static library:
```
cmake -DBUILD_SHARED_LIBS=OFF ..
cmake --build . --parallel
```

Debug build:
```
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build . --parallel
```

For more build options and their explanation run:
`cmake --build . --target print_help`

#### Windows MSVS (x64 only)

Shared library with debugging information (default for MSVS)
```
cmake -Ax64 ..
cmake --build .
```

Release build:
```
cmake -Ax64 ..
cmake --build . --config Release
```

Static library:
```
cmake -Ax64 -DBUILD_SHARED_LIBS=OFF ..
cmake --build . --config Release
```

For more build options and their explanation run:
`cmake --build . --target print_help`

####  Ninja (Linux, FreeBSD and Windows):
```
cmake -G Ninja ..
cmake --build .
```

For more build options and their explanation run:
```
cmake --build . --target print_help
```

Library and applications can be found in:
```
build/lib
build/test
build/perf
```

## 7. Security Considerations & Options for Increased Security

### Security Considerations
The security of a system that uses cryptography depends on the strength of
the cryptographic algorithms as well as the strength of the keys.
Cryptographic key strength is dependent on several factors, with some of the
most important factors including the length of the key, the entropy of the key
bits, and maintaining the secrecy of the key.

The selection of an appropriate algorithm and mode of operation critically
affects the security of a system. Appropriate selection criteria is beyond the
scope of this document and should be determined based upon usage, appropriate
standards and consultation with a cryptographic expert. This library includes some
algorithms, which are considered cryptographically weak and are included only
for legacy and interoperability reasons. See the "Recommendations" section for
more details.

Secure creation of key material is not a part of this library. This library
assumes that cryptographic keys have been created using approved methods with
an appropriate and secure entropy source. Users of this library are
referred to NIST SP800-133 Revision 1, Recommendation for Cryptographic Key
Generation, found at https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r1.pdf

Even with the use of strong cryptographic algorithms and robustly generated
keys, software implementations of cryptographic algorithms may be attacked
at the implementation through cache-timing attacks, buffer-over-reads, and
other software vulnerabilities. Counter-measures against these types of
attacks are possible but require additional processing cycles. Whether a
particular system should provide such counter-measures depends on the threats
to that system, and cannot be determined by a general library such as this
one. In order to provide the most flexible implementation, this library allows
certain counter-measures to be enabled or disabled at compile time. These
options are listed below as the "Options for Increased Security" and are
enabled through various build flags.

### Options for Increased Security

There are three build options that are used to increase safety in
the code and help protect external functions from incorrect input data.
The SAFE_DATA, SAFE_PARAM and SAFE_LOOKUP options are enabled by default.
Due to the potential performance impact associated to the extra code, these
can be disabled by setting the parameter equal to "n" (e.g. make SAFE_LOOKUP=n).

No specific code has been added, and no specific validation or security
tests have been performed to help protect against or check for side-channel
attacks.

### SAFE_DATA

Stack and registers containing sensitive information, such as keys or IVs, are
cleared upon completion of a function call.

### SAFE_PARAM

Input parameters are checked, looking generally for NULL pointers or an 
incorrect input length.

### SAFE_LOOKUP

Lookups which depend on sensitive information are implemented with constant
time functions.

Algorithms where these constant time functions are used are the following:  
- AESNI emulation  
- DES: SSE, AVX and AVX2 implementations  
- KASUMI: all architectures  
- SNOW3G: all architectures  

If SAFE_LOOKUP is not enabled in the build (e.g. make SAFE_LOOKUP=n) then the
algorithms listed above may be susceptible to timing attacks which could expose
the cryptographic key.

### SAFE_OPTIONS

SAFE_OPTIONS is a parameter that can be used to disable/enable
all supported safe options (i.e. SAFE_DATA, SAFE_PARAM, SAFE_LOOKUP).
It is set to `y` by default and all safe options are enabled.
`SAFE_OPTIONS=n` disables all safe options.

### Security API

**Force clearing/zeroing of memory**
```c
IMB_DLL_EXPORT void imb_clear_mem(void *mem, const size_t size);
```
To assist in clearing sensitive application data such as keys, plaintext etc.
the library provides the `imb_clear_mem()` API. This API zeros _'size'_ bytes
of memory pointed to by _'mem'_ followed by the _sfence_ instruction to
ensure memory is cleared before the function returns.

### Galois Counter Mode (GCM) TAG Size

The library GCM and GMAC implementation provides flexibility as to tag size selection.
As explained in [NIST Special Publication 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) section 5.2.1.2 and Appendix C, using tag sizes shorter than 96 bits can be insecure.
Please refer to the aforementioned sections to understand the details, trade offs and mitigations of using shorter tag sizes.

## 8. Installation

### Linux (64-bit only)

First compile the library and then install:   
`> make`  
`> sudo make install`

To uninstall the library run:   
`> sudo make uninstall`

If you want to change install location then define PREFIX:   
`> sudo make install PREFIX=<path>`

If there is no need to run ldconfig at install stage please use NOLDCONFIG=y option:   
`> sudo make install NOLDCONFIG=y`

If library was compiled as an archive (not a default option) then install it using SHARED=n option:   
`> sudo make install SHARED=n`

### Windows (x64 only)

First compile the library and then install from a command prompt in administrator mode:   
`> nmake /f win_x64.mak`  
`> nmake /f win_x64.mak install`

To uninstall the library run:   
`> nmake /f win_x64.mak uninstall`

If you want to change install location then define PREFIX (default C:\Program Files):   
`> nmake /f win_x64.mak install PREFIX=<path>`

If library was compiled as a static library (not a default option) then install it using SHARED=n option:   
`> nmake /f win_x64.mak install SHARED=n`

### FreeBSD (64-bit only)

First compile the library and then install:   
`> gmake`  
`> sudo gmake install`

To uninstall the library run:   
`> sudo gmake uninstall`

If you want to change install location then define PREFIX:   
`> sudo gmake install PREFIX=<path>`

If there is no need to run ldconfig at install stage please use NOLDCONFIG=y option:   
`> sudo gmake install NOLDCONFIG=y`

If library was compiled as an archive (not a default option) then install it using SHARED=n option:   
`> sudo gmake install SHARED=n`

## Installing with CMake (experimental)

### Unix (Linux and FreeBSD)

First compile the library and then install:   
```
cmake --build .
sudo cmake --install .
```

To uninstall the library run:   
`sudo cmake --build . --target uninstall`

If you want to change install location then define PREFIX:   
`sudo cmake --install . --prefix=<path>`

Or set install directory variables during configuration:
```
cmake -DLIB_INSTALL_DIR=/usr/lib64 -DINCLUDE_INSTALL_DIR=/usr/include ..
cmake --build . --parallel
sudo cmake --install .
```

### Windows (x64 only)

First compile the library and then install from a command prompt in administrator mode:   
```
cmake --build . --config Release
cmake --install . --config Release
```

To uninstall the library run:   
`cmake --build . --target uninstall`

If you want to change install location then define PREFIX (default C:\Program Files):   
`cmake --install . --config Release --prefix=<path>`

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
