# Building and installing the library

## Contents

1. [Compilation](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#compilation)
2. [Installation](https://github.com/intel/intel-ipsec-mb/blob/main/INSTALL.md#installation)

## Compilation

### Linux (64-bit only)

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

Build with AESNI emulation support (disabled by default):  
`> make AESNI_EMU=y`

**Note:** Building with debugging information is not advised for production use.

For more build options and their explanation run:   
`> make help`

### Windows MSVS (x64 only)

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

Build with AESNI emulation support (disabled by default):   
`> nmake /f win_x64.mak AESNI_EMU=y`

**Note:** Building with debugging information is not advised for production use.

For more build options and their explanation run:   
`> nmake /f win_x64.mak help`

### Windows Mingw-w64 (64-bit only)

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

### FreeBSD (64-bit only)

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

### Building with CMake (experimental)

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

#### Windows MSVS (x64 only)

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
## Installation

### Linux (64-bit only)

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

### Windows (x64 only)

First compile the library and then install from a command prompt in administrator mode:   
`> nmake /f win_x64.mak`  
`> nmake /f win_x64.mak install`

To uninstall the library run:   
`> nmake /f win_x64.mak uninstall`

If you want to change install location then define PREFIX (default C:\Program Files):   
`> nmake /f win_x64.mak install PREFIX=<path>`

If library was compiled as a static library (not a default option) then install it using SHARED=n option:   
`> nmake /f win_x64.mak install SHARED=n`

### FreeBSD (64-bit only)

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

## Installing with CMake (experimental)

### Unix (Linux and FreeBSD)

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

### Windows (x64 only)

First compile the library and then install from a command prompt in administrator mode:   
```
cmake --build . --config Release
cmake --install . --config Release
```

To uninstall the library run:   
`cmake --build . --target uninstall`

If you want to change install location then define PREFIX (default C:\Program Files):   
`cmake --install . --config Release --prefix=<path>`
