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
```

Test `imb-provider.so` with a custom OpenSSL. With the `-DOPENSSL_INSTALL_DIR` option, the `imb-provider.so` is installed into the custom OpenSSL directory specified.

```sh
/custom/openssl/bin/openssl speed -provider imb-provider -elapsed --bytes 16384 -evp aes-256-gcm
```

## Supported Algorithms

The `imb-provider` supports the following cryptographic algorithms:

- **Symmetric Encryption:**
    - AES-128-GCM
    - AES-192-GCM
    - AES-256-GCM

- **Hashing:**
    - SHA-1
    - SHA-224
    - SHA-256
    - SHA-384
    - SHA-512
