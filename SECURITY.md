# Security Policy

## Overview

1. [Supported Versions](https://github.com/intel/intel-ipsec-mb/blob/main/SECURITY.md#supported-versions)
2. [Reporting a Vulnerability](https://github.com/intel/intel-ipsec-mb/blob/main/SECURITY.md#reporting-a-vulnerability)
3. [Security Considerations & Options for Increased Security](https://github.com/intel/intel-ipsec-mb/blob/main/SECURITY.md#security-considerations--options-for-increased-security)

## Supported Versions

Versions of the library that are currently being supported with security updates.

| Version | Supported          | Frameworks using this version       |
| ------- | ------------------ | ----------------------------------- |
| 2.0     | :white_check_mark: | DPDK 24.11, OpenSSL QAT Engine, VPP |
| 1.5     | :white_check_mark: | DPDK 23.11, OpenSSL QAT Engine, VPP |
| 1.4     | :x:                | DPDK 23.07                          |
| 1.3     | :white_check_mark: | DPDK 22.11, OpenSSL QAT Engine, VPP |
| 1.2     | :x:                | -                                   |
| 1.1     | :x:                | -                                   |
| 1.0     | :x:                | DPDK 21.11                          |
| < 1.0   | :x:                | -                                   |

## Reporting a Vulnerability

For reporting a vulnerability please follow steps from [Vulnerability Handling Guidelines](https://www.intel.com/content/www/us/en/security-center/vulnerability-handling-guidelines.html).

If the vulnerability is accepted then an update will be developed and provided against reported library version.
Timeline for providing an update depends on development complexity.

## Security Considerations & Options for Increased Security

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

### Galois Counter Mode Key/IV Pair Uniqueness

This library does not check for uniqueness on AES-GCM key/IV pair.
It is up to the application using the library AES-GCM API to conduct this check.
Please refer to [NIST Special Publication 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) section 8 and Appendix A, to find requirements details and instructions on constructing an IV.
