# JSON Vector Parser

This document describes the self-contained JSON vector parser used by Intel
IPsec Multi-Buffer test applications to load Known-Answer Test (KAT) vectors
from JSON files on disk. The parser lives in `test/common/` and is designed to
be shared across multiple test applications.

---

## Glossary

| Term | Meaning |
|---|---|
| **KAT (Known-Answer Test)** | A test where fixed, pre-computed inputs and their expected outputs are compared against a live crypto implementation to verify correctness. |
| **Test vector** | One set of KAT inputs and expected outputs (key, plaintext, ciphertext, tag, …). |
| **Tokenisation** | The first stage of parsing: scanning the raw JSON text and recording the type and byte-range of each structural element (object, array, string, number) without copying any data. |
| **Token** | A lightweight descriptor pointing into the raw JSON buffer. Tokens are never decoded or copied — they are just `(type, start, end)` tuples. |
| **Decoding** | The second stage of parsing: reading a token's byte range from the raw buffer and converting it into its final form (e.g. decoding a hex string into binary bytes). |
| **Hex string** | A string where every two characters represent one byte in hexadecimal (e.g. `"2b7e"` → `0x2b 0x7e`). All binary fields in the JSON files use this encoding. |
| **Sentinel-terminated array** | An array whose last element is a zero-initialised dummy entry that signals the end of the data. Callers loop until they hit it rather than needing a separate length variable. For both `mac_test` and `cipher_test`, the sentinel is detected by `msg == NULL`. |
| **Allocation context** | An opaque object (`struct test_json_alloc_ctx`) that tracks every heap allocation made during a parse. Passing it to `json_free_test_ctx()` releases all memory in one call — callers never need to free individual fields. |
| **Field inheritance** | A mechanism by which fields defined at the `testGroups` level automatically apply to every test case in that group, unless the test case defines the same field itself. |
| **`result` field** | A mandatory string in every test case that is either `"valid"` (the operation should succeed and produce the expected output) or `"invalid"` (the operation is expected to fail or produce a different output). Maps to `resultValid = 1` or `0`. |

---

## Overview

The parser lives in `test/common/vector_utils.c` and is exposed through the
header `test/include/vector_utils.h`. It has **no external library
dependencies** — tokenisation and decoding are implemented from scratch using
only the C standard library.

Two high-level entry points are provided:

| Function | Fills struct |
|---|---|
| `json_load_mac_test()` | `struct mac_test` array |
| `json_load_cipher_test()` | `struct cipher_test` array |

Both functions share identical calling conventions and return a
sentinel-terminated array plus an opaque allocation context. All memory is
released in a single call to `json_free_test_ctx()`.

---

## JSON File Format

Vector files follow a subset of the
[Wycheproof](https://github.com/google/wycheproof) schema. The root of every
file must be a JSON **object** containing a `testGroups` **array**. Each
element of `testGroups` is an object that contains a nested `tests` **array**
of individual test cases.

```json
{
  "testGroups": [
    {
      "key":     "2b7e151628aed2a6abf7158809cf4f3c",
      "keySize": 128,
      "tests": [
        {
          "tcId":    1,
          "msg":     "6bc1bee22e409f96e93d7e117393172a",
          "msgSize": 128,
          "tag":     "070a16b46b4d4144f79bdd9dd04a287c",
          "tagSize": 128,
          "result":  "valid"
        }
      ]
    }
  ]
}
```

### Fields

All binary fields (`key`, `iv`, `msg`, `tag`, `ct`) are **lowercase or
uppercase hexadecimal strings**. Size fields (`keySize`, `ivSize`, `msgSize`,
`tagSize`) express lengths in **bits**.

#### MAC test fields (`struct mac_test`)

| Field | Type | Required | Description |
|---|---|---|---|
| `tcId` | number | optional | Numeric test-case identifier |
| `key` | hex string | **required** | Key material |
| `keySize` | number (bits) | optional* | Key size in bits |
| `msg` | hex string | **required** | Input message |
| `msgSize` | number (bits) | optional* | Message size in bits |
| `tag` | hex string | **required** | Expected authentication tag |
| `tagSize` | number (bits) | optional* | Tag size in bits |
| `iv` | hex string | optional | Initialisation vector (absent for nonce-free MACs such as CMAC) |
| `ivSize` | number (bits) | optional* | IV size in bits |
| `result` | `"valid"` or `"invalid"` | **required** | Expected outcome |

#### Cipher test fields (`struct cipher_test`)

| Field | Type | Required | Description |
|---|---|---|---|
| `tcId` | number | optional | Numeric test-case identifier |
| `key` | hex string | **required** | Encryption key |
| `keySize` | number (bits) | optional* | Key size in bits |
| `iv` | hex string | **required** | Initialisation vector |
| `ivSize` | number (bits) | optional* | IV size in bits |
| `msg` | hex string | **required** | Plaintext |
| `msgSize` | number (bits) | optional* | Plaintext size in bits |
| `ct` | hex string | **required** | Ciphertext |
| `result` | `"valid"` or `"invalid"` | **required** | Expected outcome |

> **\* Size derivation.** When a `*Size` field is absent, the parser derives
> the bit length from the hex-string length: `len(hex_string) * 4`. If both
> the explicit size field and the hex string are present, the explicit size
> takes precedence and is not overwritten. For `keySize` and `ivSize` the
> explicit value must exactly match the hex-string length (a mismatch is a
> parse error). For `tagSize` and `msgSize` the explicit value may be smaller
> than the hex-string length — this covers truncated tags and non-byte-aligned
> messages where the hex field carries the full output but only the declared
> number of bits are significant.

### Field inheritance

Fields may be specified at the **`testGroups` level** and inherited by every
test case inside that group. A field on a test-case object **overrides** the
group-level value. This allows compact files where, for example, a single
`key` applies to every vector in a group:

```json
{
  "testGroups": [
    {
      "key":     "2b7e151628aed2a6abf7158809cf4f3c",
      "keySize": 128,
      "tests": [
        { "tcId": 1, "msg": "...", "tag": "...", "result": "valid" },
        { "tcId": 2, "msg": "...", "tag": "...", "result": "invalid" }
      ]
    }
  ]
}
```

---

## Internal Architecture

### Tokeniser

The parser uses a single-pass, recursive-descent tokeniser built around a
flat array of `json_tok` structs. Each token records:

```c
typedef struct {
    json_tok_type type;  /* OBJECT, ARRAY, STRING, or PRIMITIVE */
    int start;           /* inclusive byte offset in the raw JSON text */
    int end;             /* exclusive byte offset in the raw JSON text */
    int size;            /* number of direct children */
} json_tok;
```

The tokeniser never copies string data — every token is just a window into the
original in-memory document. Strings are read directly from the raw buffer at
decode time.

**Token types**

| Type | Description |
|---|---|
| `JSON_TOK_OBJECT` | `{…}` — children are alternating key/value tokens |
| `JSON_TOK_ARRAY` | `[…]` — children are value tokens |
| `JSON_TOK_STRING` | `"…"` — `start`/`end` exclude the surrounding quotes |
| `JSON_TOK_PRIMITIVE` | Numbers, `true`, `false`, `null` |

Error codes returned by the tokeniser:

| Code | Meaning |
|---|---|
| `JSON_PARSE_NOMEM` | Token array capacity exhausted |
| `JSON_PARSE_INVAL` | Invalid JSON syntax |
| `JSON_PARSE_PART` | Document is truncated / incomplete |

### Allocation context

All heap memory — the JSON text buffer, the token array, the decoded binary
buffers, and the output vector array — is tracked by a single
`struct test_json_alloc_ctx`. The context holds a growable pointer table; on
success it is returned to the caller and on failure `json_free_test_ctx()`
releases everything in one call.

```
test_json_alloc_ctx
  └── ptrs[]
        ├── [0] raw JSON text  (char*)
        ├── [1] token array    (json_tok*)
        ├── [2] vector array   (mac_test* / cipher_test*)
        ├── [3] key buffer     (unsigned char*)
        ├── [4] msg buffer
        └── …
```

---

## Parsing Flow

```
json_load_mac_test() / json_load_cipher_test()
    │
    ├─ 1. Allocate test_json_alloc_ctx
    │
    ├─ 2. json_load_doc()
    │       ├─ fopen() + read entire file into heap buffer
    │       ├─ json_tokenize_document()
    │       │     ├─ json_parse_value_token()          ← dispatch on first char
    │       │     │     ├─ json_parse_object_token()   ← '{' … '}'
    │       │     │     ├─ json_parse_array_token()    ← '[' … ']'
    │       │     │     ├─ json_parse_string_token()   ← '"' … '"'
    │       │     │     └─ json_parse_primitive_token()← numbers / keywords
    │       │     └─ retry with 2× capacity on JSON_PARSE_NOMEM
    │       └─ register token array in alloc context
    │
    ├─ 3. Validate top-level structure
    │       ├─ tokens[0].type == JSON_TOK_OBJECT
    │       └─ "testGroups" is a JSON_TOK_ARRAY
    │
    ├─ 4. First pass — count tests
    │       └─ iterate testGroups → sum tokens[tests_idx].size
    │
    ├─ 5. Allocate output vector array (test_cnt + 1 elements; last is zero sentinel)
    │
    └─ 6. Second pass — decode each test case
            ├─ json_member_with_fallback()  ← tc scope, then tg scope
            ├─ json_parse_size_t()          ← numeric fields
            ├─ json_hex_token_len_bytes()   ← validate hex length
            ├─ json_decode_hex_token()      ← hex → binary buffer in ctx
            ├─ json_validate_declared_size()← declared bits fit in buffer
            └─ json_result_to_valid()       ← "valid"→1, "invalid"→0
```

### Key helpers

| Helper | Purpose |
|---|---|
| `json_object_get()` | Find a key inside an object token, return value token index |
| `json_member_with_fallback()` | Look up a key in tc object first, then tg object |
| `json_token_skip()` | Walk past a token subtree (used to advance the cursor) |
| `json_token_eq()` | Compare a string token against a C string literal |
| `json_decode_hex_token()` | Decode a hex string token into a binary buffer |
| `json_parse_size_t()` | Parse an unsigned decimal primitive into `size_t` |

---

## Public API

### Load MAC vectors

```c
#include "vector_utils.h"
#include "mac_test.h"

struct mac_test *vectors;
struct test_json_alloc_ctx *ctx;

if (json_load_mac_test("path/to/vectors.json", &vectors, &ctx) != 0) {
    /* handle error */
}

/* Iterate until sentinel (msg == NULL for last + 1 entry) */
for (size_t i = 0; vectors[i].msg != NULL; i++) {
    /* use vectors[i].key, vectors[i].msg, vectors[i].tag, … */
}

json_free_test_ctx(ctx);
```

### Load cipher vectors

```c
#include "vector_utils.h"
#include "cipher_test.h"

struct cipher_test *vectors;
struct test_json_alloc_ctx *ctx;

if (json_load_cipher_test("path/to/vectors.json", &vectors, &ctx) != 0) {
    /* handle error */
}

for (size_t i = 0; vectors[i].msg != NULL; i++) {
    /* use vectors[i].key, vectors[i].iv, vectors[i].msg, vectors[i].ct, … */
}

json_free_test_ctx(ctx);
```

### Return values

| Return | Meaning |
|---|---|
| `0` | Success — `*out_vectors` and `*out_ctx` are valid |
| `-1` | Failure — `*out_vectors` and `*out_ctx` are `NULL`; error printed to `stderr` in `DEBUG` builds |

### Sentinel detection

The output array has one extra zero-initialised element appended. For MAC
vectors the sentinel is detected by `msg == NULL`; for cipher vectors likewise.
Do **not** use `tcId` or size fields for sentinel detection — they are `0` in
the sentinel but could also be `0` in a real vector.

---

## Data Structures

### `struct mac_test`

```c
struct mac_test {
    size_t       keySize;     /* key size in bits */
    size_t       tagSize;     /* tag size in bits */
    size_t       tcId;        /* test-case identifier */
    const char  *key;         /* decoded key bytes */
    const char  *msg;         /* decoded message bytes (NULL in sentinel) */
    const char  *tag;         /* decoded tag bytes */
    int          resultValid; /* 1 = "valid", 0 = "invalid" */
    size_t       msgSize;     /* message size in bits */
    const char  *iv;          /* decoded IV bytes (optional) */
    size_t       ivSize;      /* IV size in bits */
};
```

### `struct cipher_test`

```c
struct cipher_test {
    size_t       ivSize;      /* IV size in bits */
    size_t       keySize;     /* key size in bits */
    size_t       tcId;        /* test-case identifier */
    const char  *key;         /* decoded key bytes */
    const char  *iv;          /* decoded IV bytes */
    const char  *msg;         /* decoded plaintext (NULL in sentinel) */
    const char  *ct;          /* decoded ciphertext */
    int          resultValid; /* 1 = "valid", 0 = "invalid" */
    size_t       msgSize;     /* plaintext size in bits */
};
```

> All `const char *` payload pointers point into buffers owned by the
> `test_json_alloc_ctx`. They become dangling after `json_free_test_ctx()`.

---

## Error Handling and Diagnostics

Every error path calls the internal `json_report_parse_error()` helper which
always prints a structured message to `stderr`:

```
JSON parse error: file="path.json", stage="json_load_mac_test",
  reason="missing or invalid result field",
  testGroup=2, test=3, tcId=42
```

The `-1` return value also signals failure to callers that redirect stderr
(e.g. negative unit tests that intentionally trigger errors).

### Conditions that cause `-1`

| Condition | Stage |
|---|---|
| File not found or unreadable | `json_load_doc` |
| Truncated / invalid JSON | `json_load_doc/tokenize` |
| Root element is not a JSON object | load function |
| `testGroups` missing or not an array | load function |
| A `tests` member missing or not an array | load function |
| `result` field absent | load function |
| `result` value is not `"valid"` or `"invalid"` | load function |
| Invalid hex characters in any binary field | load function |
| Odd-length hex string | load function |
| Negative size value | load function |
| Size value overflows `size_t` | load function |
| Declared bit size exceeds decoded buffer | load function |
| Declared size does not match hex field length | load function |
| Required field (`key`, `msg`, `tag`) missing from MAC test case | load function |
| Required field (`key`, `iv`, `msg`, `ct`) missing from cipher test case | load function |
| Memory allocation failure | any stage |

---

## Usage in Test Applications

Any test application that links against the common library can use the parser
with the following pattern:

1. **Resolve the vector file path** using whatever mechanism the application
   provides (a compiled-in default, a command-line argument, an environment
   variable, etc.).
2. **Call the loader** (`json_load_mac_test` or `json_load_cipher_test`) with
   the resolved path.
3. **Iterate the sentinel-terminated array** to run the crypto operation against
   each vector.
4. **Free all resources** with a single `json_free_test_ctx()` call.

```c
/* Generic usage pattern */
int
run_my_test(void)
{
    struct test_json_alloc_ctx *ctx = NULL;
    struct cipher_test *vectors = NULL;
    int errors = 0;

    if (json_load_cipher_test("/path/to/vectors.json", &vectors, &ctx) != 0)
        return 1;

    for (size_t i = 0; vectors[i].msg != NULL; i++) {
        const struct cipher_test *v = &vectors[i];
        /* ... run crypto operation using v->key, v->iv, v->msg ... */
        /* ... compare output to v->ct ... */
    }

    json_free_test_ctx(ctx);
    return errors;
}
```

### Supplying the vector path

The parser itself has no concept of a "default" vector directory — that is the
responsibility of the calling application. Common approaches used in this
repository include:

- **Compiled-in default** — the CMake build system defines a preprocessor
  macro (e.g. `MY_APP_VECTOR_DIR`) pointing to the `vectors/` subdirectory
  at configure time, so the binary works out of the box.
- **Runtime override** — a command-line option (e.g. `--vector-dir <DIR>`)
  lets the caller replace the compiled-in path without rebuilding.

Each application is free to combine, extend, or replace these mechanisms as
needed.

---

## Testing the Parser Itself

`test/kat-app/json_parser_test.c` contains a self-contained unit test suite
that exercises both positive and negative paths without touching the file
system beyond temporary files:

| Test | What it checks |
|---|---|
| P1 | Single MAC vector, all fields present |
| P2 | MAC vector with `"result": "invalid"` → `resultValid == 0` |
| P3 | Fields at `testGroups` level inherited by test case |
| P4 | Multiple `testGroups`, all vectors collected |
| P5 | Single cipher vector with `iv` and `ct` fields |
| P6 | Size fields absent — derived from hex length |
| N1 | Empty file → `-1` |
| N2 | Empty JSON object `{}` → `-1` |
| N3 | Root is array `[]` → `-1` |
| N4 | `testGroups` is not an array → `-1` |
| N5 | `tests` is not an array → `-1` |
| N6 | Missing `result` field → `-1` |
| N7 | Invalid `result` value (`"maybe"`) → `-1` |
| N8 | Invalid hex characters in `key` → `-1` |
| N9 | Truncated JSON document → `-1` |
| N10 | Negative `keySize` → `-1` |
| N11 | `keySize` integer overflow → `-1` |
