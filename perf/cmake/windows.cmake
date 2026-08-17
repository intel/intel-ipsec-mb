# cmake-format: off
# Copyright (c) 2023-2024, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
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
    ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/imb-slope-to-stat.pl"
    $<TARGET_FILE_DIR:${PERF_APP}>)
add_custom_command(
  TARGET ${PERF_APP}
  POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/imb-stat-algo-report.pl"
    $<TARGET_FILE_DIR:${PERF_APP}>)
add_custom_command(
  TARGET ${PERF_APP}
  POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/imb-stat-avg.pl"
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
