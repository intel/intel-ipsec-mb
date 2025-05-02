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
# Performance application CMake Windows config
# ##############################################################################

set(IPSEC_MB_LIB libIPSec_MB)

# set NASM flags
set(CMAKE_ASM_NASM_FLAGS "-Werror -fwin64 -Xvc -DWIN_ABI")

if(WINRING0_DIR)
  string(APPEND EXTRA_CFLAGS " /DWIN_MSR -I ${WINRING0_DIR}")
endif()

# set C compiler flags
set(CMAKE_C_FLAGS
    "/nologo /D_CRT_SECURE_NO_WARNINGS /Y- /W3 /WX- /Gm- /fp:precise /EHsc /std:c11 ${EXTRA_CFLAGS}"
)
set(CMAKE_C_FLAGS_DEBUG "/Od /DDEBUG /Z7")
set(CMAKE_C_FLAGS_RELEASE "/O2 /Oi")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/debug")

# copy perf scripts to binary directory
add_custom_command(
  TARGET ${PERF_APP}
  POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/ipsec_diff_tool.py"
    $<TARGET_FILE_DIR:${PERF_APP}>)
add_custom_command(
  TARGET ${PERF_APP}
  POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/imb-perf-tool.py"
    $<TARGET_FILE_DIR:${PERF_APP}>)
add_custom_command(
  TARGET ${PERF_APP}
  POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/imb-speed.py"
    $<TARGET_FILE_DIR:${PERF_APP}>)
add_custom_command(
  TARGET ${PERF_APP}
  POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/imb-perf-cmp.py"
    $<TARGET_FILE_DIR:${PERF_APP}>)
