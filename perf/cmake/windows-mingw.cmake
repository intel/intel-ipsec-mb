# cmake-format: off
# Copyright (c) 2023-2024, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# * Neither the name of Intel Corporation nor the names of its contributors may
#   be used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# cmake-format: on

# ##############################################################################
# Performance application CMake MinGW config
# ##############################################################################

set(IPSEC_MB_LIB IPSec_MB)

# set NASM flags
set(CMAKE_ASM_NASM_FLAGS " -Werror -fwin64 -Xvc -gcv8 -DWIN_ABI")

# set C compiler flags
set(CMAKE_C_FLAGS
    "-W -Wall -Wextra -Wmissing-declarations \
-Wpointer-arith -Wcast-qual -Wundef -Wwrite-strings -Wformat \
-Wformat-security -Wunreachable-code -Wmissing-noreturn -Wsign-compare \
-Wno-endif-labels -Wstrict-prototypes -Wmissing-prototypes \
-Wold-style-definition -fno-delete-null-pointer-checks -fwrapv -std=c99")
set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG -O0")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_EXE_LINKER_FLAGS "-fPIE")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-g")
# -fno-strict-overflow is not supported by clang
if(CMAKE_COMPILER_IS_GNUCC)
  string(APPEND CMAKE_C_FLAGS " -fno-strict-overflow")
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
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ipsec_perf_tool.py
               ${COPY_DST_DIR}/ipsec_perf_tool.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/imb-speed.py
               ${COPY_DST_DIR}/imb-speed.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/imb-perf-cmp.py
               ${COPY_DST_DIR}/imb-perf-cmp.py COPYONLY)

