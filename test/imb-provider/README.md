# imb-provider

imb-provider is a test crypto provider for IPSecMB library. 

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
    - `-DOPENSSL_INSTALL_DIR`: Specifies the installation directory of a custom OpenSSL. Without this option, the provider will be built where CMake and make are executed.

    These options configure the paths for the necessary dependencies and installation directories.
    ```

3. Build & Install the provider:
    ```sh
    make && make install
    ```

    > **Note:** If you are installing the provider to the system OpenSSL directory, you may need to use `sudo make install` to ensure you have the necessary permissions.

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
    - HMAC-SHA128
    - HMAC-SHA256
    - HMAC-SHA384
    - HMAC-SHA512

    To test the OpenSSL speed, use ```-hmac sha512``` option.

These algorithms are optimized for performance using the IPSecMB library.
## 
