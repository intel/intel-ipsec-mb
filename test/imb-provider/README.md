# imb-provider

imb-provider is a test crypto provider for IPSecMB library.

imb-provider is intended for **evaluation, development, and benchmarking only**.
It is **not intended for production deployment**.

For production environments, use qat-provider from QAT Engine https://github.com/intel/qat_engine.


## Requirements

- CMake [3.16]

## Building

To build the project, follow these steps:

1. Create a build directory and navigate into it:
    ```sh
    mkdir build
    cd build
    ```

2. Run CMake to configure the project:
    ```sh
    cmake -DWITH_IPSEC_INSTALL_DIR=/local/ipsec-install/ -DWITH_IPSEC_BUILD_DIR=/ipsec-mb/build/ -DOPENSSL_INSTALL_DIR=/custom/openssl/ ..
    ```

    ### CMake Options

    - `-DWITH_IPSEC_INSTALL_DIR`: Specifies the directory where IPSecMB is installed.
    - `-DWITH_IPSEC_BUILD_DIR`: Specifies the directory where IPSecMB is built.
    - `-DOPENSSL_INSTALL_DIR`: Specifies the installation directory of a custom OpenSSL. Without this option, the provider will be built where CMake is executed.

    These options configure the paths for the necessary dependencies and installation directories.

3. Build & Install the provider:
    ```sh
    cmake --build . --parallel
    cmake --install .
    ```

    > **Note:** If you are installing the provider to the system OpenSSL directory, you may need to use `sudo cmake --install .` to ensure you have the necessary permissions.

## Usage

Test `imb-provider.so` with system OpenSSL:
```sh
openssl speed -provider-path ipsec-mb/test/imb-provider/build -provider imb-provider -elapsed --bytes 16384 -evp aes-256-gcm
openssl speed -provider-path ipsec-mb/test/imb-provider/build -provider imb-provider -elapsed --bytes 16384 --async_jobs 16 -hmac sha256
```

Test `imb-provider.so` with a custom OpenSSL. With the `-DOPENSSL_INSTALL_DIR` option, the `imb-provider.so` is installed into the custom OpenSSL directory specified.

```sh
/custom/openssl/bin/openssl speed -provider imb-provider -elapsed --bytes 16384 -evp aes-256-gcm
```
> **Note:** Add ```-async_jobs 72``` for algorithms enabled in multi buffer API.

## Enabled Algorithms

The `imb-provider` supports the following cryptographic algorithms:

- **Symmetric Encryption**:
    - AES-128-GCM
    - AES-192-GCM
    - AES-256-GCM
    - AES-128-CFB
    - AES-192-CFB
    - AES-256-CFB
    - AES-128-CCM
    - AES-256-CCM
    - SM4-CBC
    - SM4-ECB
    - SM4-CTR
    - SM4-GCM
    - ChaCha20-Poly1305
    - ChaCha20

    To test the OpenSSL speed, use ```-evp aes-256-gcm```, ```-evp aes-128-cfb```, or ```-evp sm4-gcm``` option.

- **Hashing**:
    - SHA1
    - SHA224
    - SHA256
    - SHA384
    - SHA512

    To test the OpenSSL speed, use ```sha512``` option.

- **HMAC**:
    - HMAC-SHA1
    - HMAC-SHA224
    - HMAC-SHA256
    - HMAC-SHA384
    - HMAC-SHA512
    - HMAC-SHA3-224
    - HMAC-SHA3-256
    - HMAC-SHA3-384
    - HMAC-SHA3-512

    To test the OpenSSL speed, use ```-hmac sha512``` or ```-hmac SHA3-256``` option.

- **Authentication & MAC**:
    - Poly1305

    To test the OpenSSL speed, use ```-evp poly1305``` option.

- **Post-Quantum Signatures (ML-DSA)**:
    - ML-DSA-44
    - ML-DSA-65
    - ML-DSA-87

    Exposed as `OSSL_OP_KEYMGMT` and `OSSL_OP_SIGNATURE`, i.e. `EVP_PKEY_keygen()`,
    `EVP_PKEY_sign_init()`/`EVP_PKEY_sign()` and
    `EVP_PKEY_verify_init()`/`EVP_PKEY_verify()`.

- **Post-Quantum Key Encapsulation (ML-KEM)**:
    - ML-KEM-512
    - ML-KEM-768
    - ML-KEM-1024

    Exposed as `OSSL_OP_KEYMGMT` and `OSSL_OP_KEM`, i.e. `EVP_PKEY_keygen()`,
    `EVP_PKEY_encapsulate_init()`/`EVP_PKEY_encapsulate()` and
    `EVP_PKEY_decapsulate_init()`/`EVP_PKEY_decapsulate()`.

    Note: ML-DSA and ML-KEM require OpenSSL 3.0 or later, but do not need the
    native OpenSSL 3.5 ML-DSA/ML-KEM implementations. Keys are handled as raw
    encodings through `EVP_PKEY_fromdata()`/`EVP_PKEY_get_octet_string_param()`
    with the `pub`, `priv` and `seed` key parameters.

### Post-quantum key caching

```c
EVP_PKEY_CTX *genctx = EVP_PKEY_CTX_new_from_name(libctx, "ML-KEM-768",
                                                  "provider=imb-provider");
EVP_PKEY_keygen_init(genctx);
EVP_PKEY_keygen(genctx, &pkey);                     /* key decoded and cached here */

EVP_PKEY_CTX *encctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey,
                                                  "provider=imb-provider");
EVP_PKEY_encapsulate_init(encctx, NULL);            /* reuses the cached key */
for (i = 0; i < iterations; i++)
        EVP_PKEY_encapsulate(encctx, ct, &ct_len, ss, &ss_len);
```

An IMB PQC context is not safe for concurrent use, so neither is a key object
built on top of one - use one `EVP_PKEY` per thread. `EVP_PKEY_dup()` gives the
copy its own IMB context with its own cached key.

These algorithms are optimized for performance using the IPSecMB library.
##
