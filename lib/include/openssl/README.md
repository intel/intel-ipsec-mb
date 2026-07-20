# lib/include/openssl/

This tree holds headers that support the vendored OpenSSL sources in
`lib/openssl/`. It has two distinct parts with different licensing:

## Genuine vendored OpenSSL headers

| Directory | Contents |
|---|---|
| `crypto/` | Ported OpenSSL headers (e.g. `ml_dsa.h`, `ml_dsa/*.h`, `ml_kem.h`), mirroring the upstream `include/crypto/` tree |
| `internal/` | Ported OpenSSL internal headers (e.g. `constant_time.h`), mirroring the upstream `include/internal/` tree |

These carry the OpenSSL Project Authors copyright and are licensed under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). The `LICENSE.OpenSSL` file at the repository root covers these files.

Files were ported from OpenSSL at commit:
626ff8fd9344eb46e50464960ce84dcbacf5a4dd

## `compat/` — ipsec-mb compatibility shims

`compat/` provides header-only stand-ins for OpenSSL headers that the ML-DSA
and ML-KEM ports need at compile time but that were *not* vendored from
OpenSSL.
Sub-folders mirror the OpenSSL include namespace each stub replaces
(`compat/openssl/` for `<openssl/*.h>`, `compat/internal/` for
`"internal/*.h"`, `compat/crypto/` for `"crypto/*.h"`), so the vendored
sources' `#include` lines resolve unchanged via the compiler include path.

Most files here are original ipsec-mb glue code (Intel copyright only) that
just maps an OpenSSL API name onto an ipsec-mb/libc equivalent. A few,
however, reuse actual logic or struct layout copied from genuine OpenSSL
sources rather than merely replicating the API surface, and therefore carry a
dual Intel + OpenSSL copyright/license header:

- `openssl_compat.h` — `CRYPTO_memcmp()`, `OPENSSL_memdup()`, and the
  `OPENSSL_{store,load}_u{16,32,64}_le()` helpers are adapted from OpenSSL's
  `crypto/cpuid.c`, `crypto/o_str.c`, and `include/openssl/byteorder.h`.
- `compat/internal/sha3.h` — the macros, `struct keccak_st` layout, and
  function declarations are copied near-verbatim from OpenSSL's
  `include/internal/sha3.h`.
- `compat/internal/packet.h` — the `PACKET` struct and its
  `packet_forward()` / `PACKET_remaining()` / `PACKET_buf_init()` functions
  are copied near-verbatim from OpenSSL's `include/internal/packet.h` (the
  `WPACKET` side is an original, reduced-scope reimplementation).

When adding a new compat shim, check whether you are reusing OpenSSL logic
(struct layouts, algorithms, non-trivial control flow) versus just
reimplementing an API name against ipsec-mb primitives — the former requires
the dual copyright header, the latter does not.
