# cmake-format: off
# Copyright (c) 2023-2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# ##############################################################################
# Test application CMake Windows config
# ##############################################################################

set(IPSEC_MB_LIB libIPSec_MB)

# set NASM flags
set(CMAKE_ASM_NASM_FLAGS "-Werror -fwin64 -Xvc -DWIN_ABI")

# set C compiler flags
set(CMAKE_C_FLAGS
    "/nologo /D_CRT_SECURE_NO_WARNINGS /Y- /W3 /WX- /Gm- /fp:precise /EHsc /std:c11 ${EXTRA_CFLAGS}"
)
set(CMAKE_C_FLAGS_DEBUG "/Od /DDEBUG /Z7")
set(CMAKE_C_FLAGS_RELEASE "/O2 /Oi")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/debug")
