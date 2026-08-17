# cmake-format: off
# Copyright (c) 2023-2024, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# ##############################################################################
# Test application CMake MinGW config
# ##############################################################################

set(IPSEC_MB_LIB IPSec_MB)

# set NASM flags
set(CMAKE_ASM_NASM_FLAGS "-Werror -fwin64 -Xvc -gcv8 -DWIN_ABI")

# set compiler definitions
set(APP_DEFINES _GNU_SOURCE)

# set C compiler flags
set(CMAKE_C_FLAGS
    "-W -Wall -Wextra -Wmissing-declarations \
-Wpointer-arith -Wcast-qual -Wundef -Wwrite-strings -Wformat \
-Wformat-security -Wunreachable-code -Wmissing-noreturn -Wsign-compare \
-Wno-endif-labels -Wstrict-prototypes -Wmissing-prototypes \
-Wold-style-definition -fno-delete-null-pointer-checks -fwrapv -std=c99")
set(CMAKE_C_FLAGS_DEBUG "-O0 -DDEBUG -g")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_EXE_LINKER_FLAGS "-fPIE")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-g")

# -fno-strict-overflow is not supported by clang
if(CMAKE_COMPILER_IS_GNUCC)
  string(APPEND CMAKE_C_FLAGS " -fno-strict-overflow")
endif()
