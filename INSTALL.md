# Building and installing the library

## Contents

1. [Compilation](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#compilation)
2. [Creating Installation Packages](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#creating-installation-packages)
3. [Installation](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#installation)
4. [Testing](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#testing)

## Compilation (x64 only)

### Building with CMake

Minimum CMake version: 3.18

Create build directory:
```
mkdir build
cd build
```

#### Unix Makefiles (Linux and FreeBSD)

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

### Linux (Deprecated - replaced by CMake)

Required tools:  
- GNU make  
- NASM version 2.14 (or newer)  
- gcc (GCC) 4.8.3 (or newer)  

Shared library:  
`> make`

Static library:  
`> make SHARED=n`

Clean the build:  
`> make clean`  
or  
`> make clean SHARED=n`

Build with debugging information:  
`> make DEBUG=y`

**Note:** Building with debugging information is not advised for production use.

For more build options and their explanation run:   
`> make help`

### Windows MSVS (Deprecated - replaced by CMake)

Required tools:  
- Microsoft (R) Visual Studio 2019:  
  - NMAKE: Microsoft (R) Program Maintenance Utility Version 14.29.30148.0  
  - CL: Microsoft (R) C/C++ Optimizing Compiler Version 19.29.30148 for x64  
  - LIB: Microsoft (R) Library Manager Version 14.29.30148.0  
  - LINK: Microsoft (R) Incremental Linker Version 14.29.30148.0  
  - Note: Building on later versions should work but is not verified  
- NASM version 2.14 (or newer)  

Shared library (DLL):  
`> nmake /f win_x64.mak`

Static library:  
`> nmake /f win_x64.mak SHARED=n`

Clean the build:   
`> nmake /f win_x64.mak clean`   
or   
`> nmake /f win_x64.mak clean SHARED=n`

Build without safety features:  
- SAFE_DATA clears sensitive information stored temporarily on stack, registers or internal data structures  
- SAFE_PARAM adds extra checks on input parameters  
- SAFE_LOOKUP uses constant-time lookups (enabled by default)  
- SAFE_OPTIONS additional option to disable all safe options. Enabled by default.  
  Disable to turn off: SAFE_DATA, SAFE_PARAM and SAFE_LOOKUP.  

`> nmake /f win_x64.mak SAFE_DATA=n SAFE_PARAM=n`
`> nmake /f win_x64.mak SAFE_OPTIONS=n`

Build with debugging information:   
`> nmake /f win_x64.mak DEBUG=y`

**Note:** Building with debugging information is not advised for production use.

For more build options and their explanation run:   
`> nmake /f win_x64.mak help`

### Windows Mingw-w64 (Deprecated - replaced by CMake)

Required tools:  
- GNU mingw32-make.exe  
- NASM version 2.14 (or newer)  
- gcc (GCC) 10.3.0 (or newer)

Shared library:  
`> mingw32-make.exe`

Static library:  
`> mingw32-make.exe SHARED=n`

Clean the build:  
`> mingw32-make.exe clean`  
or  
`> mingw32-make.exe clean SHARED=n`

Build with debugging information:  
`> mingw32-make.exe DEBUG=y`

**Note:** Building with debugging information is not advised for production use.

For more build options and their explanation run:   
`> mingw32-make.exe help`

### FreeBSD (Deprecated - replaced by CMake)

Required tools:  
- GNU make  
- NASM version 2.14 (or newer)  
- gcc (GCC) 4.8.3 (or newer) / clang 5.0 (or newer)  

Shared library:   
`> gmake`

Static library:   
`> gmake SHARED=n`

Clean the build:   
`> gmake clean`   
or   
`> gmake clean SHARED=n`

Build with debugging information:   
`> gmake DEBUG=y`

**Note:** Building with debugging information is not advised for production use.

For more build options and their explanation run:   
`> gmake help`

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

### Linux (Deprecated - replaced by CMake)

First compile the library and then install:   
`> make`  
`> sudo make install`

To uninstall the library run:   
`> sudo make uninstall`

If you want to change install location then define PREFIX:   
`> sudo make install PREFIX=<path>`

If there is no need to run ldconfig at install stage please use NOLDCONFIG=y option:   
`> sudo make install NOLDCONFIG=y`

If library was compiled as an archive (not a default option) then install it using SHARED=n option:   
`> sudo make install SHARED=n`

### Windows (Deprecated - replaced by CMake)

First compile the library and then install from a command prompt in administrator mode:   
`> nmake /f win_x64.mak`  
`> nmake /f win_x64.mak install`

To uninstall the library run:   
`> nmake /f win_x64.mak uninstall`

If you want to change install location then define PREFIX (default C:\Program Files):   
`> nmake /f win_x64.mak install PREFIX=<path>`

If library was compiled as a static library (not a default option) then install it using SHARED=n option:   
`> nmake /f win_x64.mak install SHARED=n`

### FreeBSD (Deprecated - replaced by CMake)

First compile the library and then install:   
`> gmake`  
`> sudo gmake install`

To uninstall the library run:   
`> sudo gmake uninstall`

If you want to change install location then define PREFIX:   
`> sudo gmake install PREFIX=<path>`

If there is no need to run ldconfig at install stage please use NOLDCONFIG=y option:   
`> sudo gmake install NOLDCONFIG=y`

If library was compiled as an archive (not a default option) then install it using SHARED=n option:   
`> sudo gmake install SHARED=n`

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
