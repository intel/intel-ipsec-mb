# Security Policy

## Overview

1. [Supported Versions](https://github.com/intel/intel-ipsec-mb/blob/main/SECURITY.md#supported-versions)
2. [Reporting a Vulnerability](https://github.com/intel/intel-ipsec-mb/blob/main/SECURITY.md#reporting-a-vulnerability)
3. [Security Considerations & Options for Increased Security](https://github.com/intel/intel-ipsec-mb/blob/main/SECURITY.md#security-considerations--options-for-increased-security)

## Supported Versions

Versions of the library that are currently being supported with security updates.

| Version | Supported          | Frameworks using this version             |
| ------- | ------------------ | ----------------------------------------- |
| 3.0     | :white_check_mark: | -                                         |
| 2.0     | :white_check_mark: | DPDK 24.11, OpenSSL QAT Engine, VPP, SPDK |
| 1.5     | :x:                | DPDK 23.11, OpenSSL QAT Engine, VPP, SPDK |
| 1.4     | :x:                | DPDK 23.07                                |
| 1.3     | :x:                | DPDK 22.11, OpenSSL QAT Engine, VPP, SPDK |
| 1.2     | :x:                | -                                         |
| 1.1     | :x:                | -                                         |
| 1.0     | :x:                | DPDK 21.11                                |
| < 1.0   | :x:                | -                                         |

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
can be disabled with CMake options (e.g. `cmake -DSAFE_LOOKUP=OFF ..`).

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

Algorithms where the SAFE_LOOKUP build option selects constant time lookups are
the following:
- SNOW3G (UEA2 and UIA2): single buffer and 2 buffer S2 box paths and the
  MULa/DIVa alpha table paths, in the SSE, AVX2 and AVX512 Type 1 (non-VAES)
  implementations

If SAFE_LOOKUP is not enabled in the build (e.g. `cmake -DSAFE_LOOKUP=OFF ..`) then the
code paths listed above fall back to direct table indexing and may be
susceptible to timing attacks which could expose the cryptographic key.

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

### Self-Test Failure (Fail-Closed)

The library runs a power-up self-test (known answer tests) in every `init_mb_mgr_*()` call.
If any test fails the manager is put into a fail-closed error state:
all job, burst and direct cryptographic APIs on that manager are replaced with stubs that
perform no operation, produce no output and report `IMB_ERR_SELFTEST`; ML-KEM/ML-DSA context
operations (new or pre-existing contexts) return `IMB_ERR_SELFTEST`;
`imb_get_errno()` returns `IMB_ERR_SELFTEST` and `IMB_FEATURE_SELF_TEST_PASS` is cleared.
This prevents an application from unknowingly using a library instance whose code or
underlying hardware may be faulty. See the *Self-Test* section in README.md for details.

### Authentication Tag Verification

The library does not verify authentication tags on decryption.
For all AEAD and MAC algorithms (AES-GCM, AES-CCM, ChaCha20-Poly1305, SM4-GCM,
AES-GMAC, AES-CMAC, HMAC-*, etc.) and for the JOB, burst and direct APIs alike,
the decrypt/verify direction only **computes** the tag and writes it to the
`auth_tag_output` / `auth_tag` buffer supplied by the application.
It is up to the application to compare the computed tag against the tag
received with the message and to discard the plaintext if they differ, as
required by [NIST Special Publication 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) section 7.2.
The comparison must be done in constant time (i.e. without a data dependent
early exit such as in `memcmp()`), otherwise timing differences may allow an
attacker to forge a valid tag byte by byte.

### Galois Counter Mode (GCM) TAG Size

The library GCM and GMAC implementation provides flexibility as to tag size selection.
As explained in [NIST Special Publication 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) section 5.2.1.2 and Appendix C, using tag sizes shorter than 96 bits can be insecure.
Please refer to the aforementioned sections to understand the details, trade offs and mitigations of using shorter tag sizes.

### Key/IV (Nonce) Pair Uniqueness

This library does not check for uniqueness of the key/IV (nonce) pair.
It is up to the application using the library to guarantee it.
This applies to every counter based and AEAD mode offered by the library, in particular:
- AES-GCM, AES-GMAC and SM4-GCM: see [NIST Special Publication 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) section 8 and Appendix A for requirements and instructions on constructing an IV.
  Reusing a key/IV pair with GCM leaks the XOR of the plaintexts and allows recovery of the authentication key.
- AES-CTR, PON-AES-CTR, SM4-CTR, ChaCha20 and ChaCha20-Poly1305: see [NIST Special Publication 800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final) Appendix B and [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) section 4.
  Reusing a key/counter block or key/nonce pair leaks the XOR of the plaintexts.
- AES-CCM: see [NIST Special Publication 800-38C](https://csrc.nist.gov/publications/detail/sp/800-38c/final) Appendix A.
- 3GPP algorithms (SNOW3G, ZUC, KASUMI, SNOW5G, AES-NEA5/NIA5/NCA5): COUNT/BEARER/DIRECTION derived IVs must be unique per key as required by the respective 3GPP specifications.

Unlike in AES-CBC, where IV reuse is a lesser confidentiality leak, reuse of a key/IV pair in the modes above is a critical failure and the library cannot detect it because it keeps no per key state across jobs.

### KASUMI
The AVX2 KASUMI bitsliced S-box implementation uses the BMI2 `PEXT` instruction
with a fixed, public mask to extract the result. On supported Intel platforms,
its execution is considered data-independent.
