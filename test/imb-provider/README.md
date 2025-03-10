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
    cmake -DWITH_PROV_SW_IPSEC_MB_INSTALL_DIR=/local/ipsec-install/ -DWITH_IPSEC_BUILD_DIR=/ipsec-mb/build/ -DOPENSSL_INSTALL_DIR=/custom/openssl/ ..
    ```

    ### CMake Options

    - `-DWITH_PROV_SW_IPSEC_MB_INSTALL_DIR`: Specifies the directory where IPSecMB is installed.
    - `-DWITH_IPSEC_BUILD_DIR`: Specifies the directory where IPSecMB is built.
    - `-DOPENSSL_INSTALL_DIR`: Specifies the installation directory of a custom OpenSSL. imb-provider will be installed into system OpenSSL without this option.

    These options configure the paths for the necessary dependencies and installation directories.
    ```

3. Build & Install the provider:
    ```sh
    make && make install
    ```

    > **Note:** If you are installing the provider to the system OpenSSL directory, you may need to use `sudo make install` to ensure you have the necessary permissions.

## Usage

Install imb-provider.so for OpenSSL and test with OpenSSL speed:
```sh
/custom/openssl/bin/openssl speed -provider imb-provider -elapsed --bytes 16384 -evp aes-256-gcm
```