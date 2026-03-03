# Building and installing the library

## Contents

1. [Compilation](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#compilation)
2. [Creating Installation Packages](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#creating-installation-packages)
3. [Installation](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#installation)
4. [Testing](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#testing)

## Compilation (x64 only)

### Building with CMake

Minimum CMake version: 3.16
CMake is the only supported build system.

Create build directory:
```
mkdir build
cd build
```

#### Unix (Linux and FreeBSD)

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
Library only build (without applications):
```
cmake -DBUILD_LIBRARY_ONLY=ON ..
cmake --build . --parallel
```

Debug build:
```
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build . --parallel
```

For more build options and their explanation run:   
`cmake --build . --target print_help`

#### Windows MSVS

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

Library only build (without applications):
```
cmake -Ax64 -DBUILD_LIBRARY_ONLY=ON ..
cmake --build . --parallel
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
#### Other CMake compilation notes

- To set path to C compiler:
```
cmake -DCMAKE_C_COMPILER=/usr/local/bin/gcc ..
```

- To set path to NASM assembler:
```
cmake -DCMAKE_ASM_NASM_COMPILER=/usr/local/bin/nasm ..
```

- To disable all safe options:
```
cmake -DSAFE_OPTIONS=OFF ..
```

- To disable safe options individually:
```
cmake -DSAFE_DATA=OFF -DSAFE_PARAM=OFF -DSAFE_LOOKUP=OFF ..
```

## Creating Installation Packages

### Linux Packages (DEB and RPM)

After building the library with CMake, you can create installation packages using CPack.

#### Prerequisites
Ensure you have the required packaging tools installed:
- For DEB packages: `dpkg-dev`
- For RPM packages: `rpm` on Debian/Ubuntu or `rpm-build` on RHEL/Fedora/SUSE

#### Creating DEB Packages (Debian/Ubuntu)
```bash
# Configure and build
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_LIBRARY_ONLY=ON
cmake --build build --parallel

# Create DEB package
cd build
cpack -G DEB
```

This will generate a `.deb` package file: `intel-ipsec-mb_<version>_amd64.deb`

#### Creating RPM Packages (RHEL/Fedora/SUSE)
```bash
# Configure and build
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_LIBRARY_ONLY=ON
cmake --build build --parallel

# Create RPM package
cd build
cpack -G RPM
```

This will generate an `.rpm` package file: `intel-ipsec-mb-<version>-1.x86_64.rpm`

## Installation

### Installing from Packages (Linux)

#### Debian/Ubuntu (.deb packages)

To install from a .deb package:
```bash
sudo dpkg -i intel-ipsec-mb_<version>_amd64.deb
```

After installation, the library files are installed to `/usr/local/lib`.  
To ensure the dynamic linker can find the library, you may need to update the linker cache:

```bash
sudo ldconfig
```

If the library path is not in the default linker search path, create a configuration file:
```bash
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/intel-ipsec-mb.conf
sudo ldconfig
```

To verify the library is found by the linker:
```bash
ldconfig -p | grep libIPSec_MB
```

To uninstall:
```bash
sudo dpkg -r intel-ipsec-mb
```

#### RHEL/Fedora/SUSE (.rpm packages)

To install from an .rpm package:
```bash
sudo rpm -ivh intel-ipsec-mb-<version>-1.x86_64.rpm
```

Or using yum/dnf:
```bash
sudo yum install intel-ipsec-mb-<version>-1.x86_64.rpm
# or
sudo dnf install intel-ipsec-mb-<version>-1.x86_64.rpm
```

After installation, update the linker cache:
```bash
sudo ldconfig
```

If the library path is not in the default linker search path, create a configuration file:
```bash
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/intel-ipsec-mb.conf
sudo ldconfig
```

To verify the library is found by the linker:
```bash
ldconfig -p | grep libIPSec_MB
```

To uninstall:
```bash
sudo rpm -e intel-ipsec-mb
```

Or using yum/dnf:
```bash
sudo yum remove intel-ipsec-mb
# or
sudo dnf remove intel-ipsec-mb
```

### Building and Installing from Source

#### Unix (Linux and FreeBSD)

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

### Windows

First compile the library and then install from a command prompt in administrator mode:   
```
cmake --build . --config Release
cmake --install . --config Release
```

To uninstall the library run:   
`cmake --build . --target uninstall`

If you want to change install location then define PREFIX (default C:\Program Files):   
`cmake --install . --config Release --prefix=<path>`

## Testing

First compile the library and applications:   
`cmake --build . --parallel`

To run all tests:   
`cmake --build . --target test`

Use CTest to run tests in parallel:   
`ctest --output-on-failure -j 10`

Exclude extended tests:   
`ctest -E EXT --output-on-failure -j 10`

Include only KAT tests:   
`ctest -R KAT --output-on-failure -j 10`
