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

- Post-quantum cryptography (ML-DSA / FIPS 204) is always built. Perl is
  required at configure time to generate assembly from the vendored
  OpenSSL-style scripts.

- To enable constant-time validation using Valgrind memcheck (Linux only):
```
cmake -DCONSTANT_TIME_VALIDATION=ON ..
```
  The option is independent of `CMAKE_BUILD_TYPE` and works with any of them.
  This single option turns on two complementary sets of annotations, which mark
  secret data as "undefined" so that Valgrind reports any branch or memory
  index taken on it.

  Requires `valgrind/memcheck.h` at build time (e.g. `valgrind-devel` /
  `valgrind` package).  When the option is off, no annotation code is generated
  at all, so default builds are unaffected.  Run the test applications under
  Valgrind to exercise the checks:
```
valgrind --tool=memcheck --error-exitcode=1 ./test/kat-app/imb-kat --test-type ML_KEM
valgrind --tool=memcheck --error-exitcode=1 ./test/kat-app/imb-kat --test-type ML_DSA
valgrind --tool=memcheck --error-exitcode=1 ./test/kat-app/imb-kat --test-type GCM
```
  Or via CTest:
```
ctest -T memcheck
```
  Any "Conditional jump or move depends on uninitialised value" error reported
  by Valgrind in this mode should be treated as a potential constant-time violation
  (or a real uninitialised-memory bug) and investigated.

- To build the KAT test application with sanitizer instrumentation:
```
cmake -DSANITIZERS="address;undefined" ..
```
  Note that only `imb-kat` is instrumented at the moment. The other test and
  example applications are built as usual, so the option has no effect on
  them. With `SANITIZE_LIB` enabled they do link the sanitizer runtime,
  because they consume the instrumented library.

  Supported sanitizers are `address`, `undefined`, `thread`, `memory` and
  `leak`. `address`, `thread` and `memory` are mutually exclusive and have to
  be used in separate builds. `leak` is implied by `address` and is dropped
  when both are given. Each requested sanitizer is probed at configure time,
  so a missing runtime library (e.g. `libasan` / `compiler-rt`) is reported
  immediately.

  Recommended combination, and the one the KAT suite is verified against:
```
cmake -DSANITIZERS="address;undefined" -DSANITIZE_LIB=ON ..
```

  Per-sanitizer notes:

  | Sanitizer   | Status                                                     |
  |-------------|------------------------------------------------------------|
  | `address`   | works, recommended                                          |
  | `undefined` | works, recommended                                          |
  | `leak`      | works; the KAT suite is leak free                           |
  | `thread`    | works, but the run-time aborts with `unexpected memory mapping` when the kernel uses more than 28 bits of mmap randomisation. Run the tests under `setarch -R`, or `sysctl -w vm.mmap_rnd_bits=28`. |
  | `memory`    | **not usable with this library** (clang only feature). MemorySanitizer needs every memory write to be instrumented, but the hand-written NASM/GAS code cannot be and their results are always reported as uninitialised. |

  Platform support:

  | Platform         | Support                                                |
  |------------------|--------------------------------------------------------|
  | Linux (gcc)      | `address`, `undefined`, `leak`, `thread`. GCC has no MemorySanitizer, so `memory` fails the configure-time probe |
  | Linux (clang)    | `address`, `undefined`, `leak`, `thread`. `memory` builds but is not usable, see above |
  | FreeBSD (clang)  | `address`, `undefined`, `thread`. No LeakSanitizer, so `leak` is dropped and leak detection is disabled in `ASAN_OPTIONS`. `memory` builds but is not usable, see above |
  | Windows (MSVC)   | `address` only (`/fsanitize=address`, Visual Studio 2019 16.9 or newer); the others are ignored with a warning |
  | Windows (MinGW)  | none - the option is ignored with a warning             |

  On Windows the AddressSanitizer runtime DLL is located next to `cl.exe` and
  is added to `PATH` automatically when the tests are run through CTest.

  Only the KAT application is instrumented by default.
  The AddressSanitizer allocator interceptors are process wide, so heap errors
  triggered through the library are still caught, but red zones and undefined
  behavior sanitizer checks inside the library itself require the library to
  be instrumented too:
```
cmake -DSANITIZERS="address;undefined" -DSANITIZE_LIB=ON ..
```
  Only the C sources of the library are instrumented and the hand-written assembly is
  never touched. Which can result in false positives (typically `stack-buffer-overflow`
  reports on the register spill areas of the assembly code). For this reason
  the option is off by default.

  Run the instrumented tests as usual; the sanitizer runtime options are set on
  the CTest tests, so that a report fails the test instead of only being
  printed:
```
cmake --build . --target imb-kat
ctest -R KAT
```

  A LeakSanitizer suppressions file can be supplied with:
```
cmake -DSANITIZERS=address -DSANITIZER_SUPPRESSIONS=/path/to/lsan.supp ..
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
