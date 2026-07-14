# lib/openssl/

This tree holds vendored OpenSSL `.c` / `.pl` sources, mirroring the layout of
the upstream OpenSSL `crypto/` directory. No headers live here — see
`lib/include/openssl/` for the corresponding vendored and compatibility
headers.

Files under this tree are licensed under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) and carry
the OpenSSL Project Authors copyright notice, since they are copied verbatim
(or with only cosmetic/Intel modifications) from the

Some files carry an additional Intel Corporation copyright notice where the
original code was authored by Intel as a contribution to OpenSSL and later
adapted for ipsec-mb. The `LICENSE.OpenSSL` file at the repository root
covers all files in this tree.

Files were ported from OpenSSL at commit:
626ff8fd9344eb46e50464960ce84dcbacf5a4dd

## Directory Layout

| Directory | Contents |
|---|---|
| `crypto/ml_dsa/` | Core ML-DSA (FIPS 204) algorithm: key generation, sign/verify, NTT, matrix/vector arithmetic, sampling, and encoders |
| `crypto/ml_dsa/asm/` | Perlasm for ML-DSA NTT/Montgomery arithmetic (AVX2/AVX512), authored by Intel as an OpenSSL contribution |
| `crypto/ml_kem/` | Reserved for a future ML-KEM (FIPS 203) port, sharing the SHA-3/perlasm infrastructure below |
| `crypto/sha/` | SHA-3/SHAKE single-buffer implementation and its x4 AVX512VL parallel variant |
| `crypto/sha/asm/` | Perlasm for the Keccak-1600 permutation (single-buffer and x4 AVX512VL) |
| `crypto/perlasm/` | OpenSSL's perlasm assembler back-end (`x86_64-xlate.pl`) and support scripts, shared by all vendored asm above |
