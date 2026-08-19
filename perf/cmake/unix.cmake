# cmake-format: off
# Copyright (c) 2023-2024, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# ##############################################################################
# Performance application CMake Unix config
# ##############################################################################

set(IPSEC_MB_LIB IPSec_MB)

# set NASM flags
set(CMAKE_ASM_NASM_FLAGS "-Werror -felf64 -Xgnu -gdwarf -DLINUX -D__linux__")

# set compiler definitions
set(APP_DEFINES LINUX _GNU_SOURCE)

# set C compiler flags
set(CMAKE_C_FLAGS
    "-W -Wall -Wextra -Wmissing-declarations \
-Wpointer-arith -Wcast-qual -Wundef -Wwrite-strings -Wformat \
-Wformat-security -Wunreachable-code -Wmissing-noreturn -Wsign-compare \
-Wno-endif-labels -Wstrict-prototypes -Wmissing-prototypes \
-Wold-style-definition -fno-delete-null-pointer-checks -fwrapv -std=c11")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -fPIE -fstack-protector -D_FORTIFY_SOURCE=2")
set(CMAKE_EXE_LINKER_FLAGS "-fPIE -z noexecstack -z relro -z now -pthread")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-g")
# -fno-strict-overflow is not supported by clang
if(CMAKE_COMPILER_IS_GNUCC)
  string(APPEND CMAKE_C_FLAGS " -fno-strict-overflow")
endif()

if(CET_SUPPORT)
  string(APPEND CMAKE_C_FLAGS " -fcf-protection=full")
  string(APPEND CMAKE_EXE_LINKER_FLAGS
         " -Wl,-z,ibt -Wl,-z,shstk -Wl,-z,cet-report=error")
endif()

# set destination dir to copy scripts
if(IMB_BIN_DIR)
  set(COPY_DST_DIR ${IMB_BIN_DIR})
else()
  set(COPY_DST_DIR ${CMAKE_CURRENT_BINARY_DIR})
endif()

# copy perf scripts to binary directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ipsec_diff_tool.py
               ${COPY_DST_DIR}/ipsec_diff_tool.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/imb-perf-tool.py
               ${COPY_DST_DIR}/imb-perf-tool.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/imb-speed.py
               ${COPY_DST_DIR}/imb-speed.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/imb-perf-cmp.py
               ${COPY_DST_DIR}/imb-perf-cmp.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/imb-slope-to-stat.pl
               ${COPY_DST_DIR}/imb-slope-to-stat.pl COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/imb-stat-algo-report.pl
               ${COPY_DST_DIR}/imb-stat-algo-report.pl COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/imb-stat-avg.pl
               ${COPY_DST_DIR}/imb-stat-avg.pl COPYONLY)
