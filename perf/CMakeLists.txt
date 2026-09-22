# cmake-format: off
# Copyright (c) 2023-2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# Ensure building entire project
if(NOT FULL_PROJECT_BUILD)
  message(FATAL_ERROR "Please run CMake from project root directory")
endif()

# ##############################################################################
# set app and library names
# ##############################################################################
set(PERF_APP imb-perf)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../lib)

# ##############################################################################
# set source files
# ##############################################################################
set(PERF_APP_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/ipsec_perf.c
                       ${CMAKE_CURRENT_SOURCE_DIR}/msr.c)

set(PERF_APP_SRC_FILES_ASM ${CMAKE_CURRENT_SOURCE_DIR}/misc.asm)

# ##############################################################################
# add target
# ##############################################################################
add_executable(${PERF_APP} ${PERF_APP_SRC_FILES} ${PERF_APP_SRC_FILES_ASM})

# ##############################################################################
# setup NASM
# ##############################################################################
enable_language(ASM_NASM)
if(NOT CMAKE_ASM_NASM_COMPILER_LOADED)
  message(FATAL_ERROR "Can't find assembler")
endif()
set(CAN_USE_ASSEMBLER TRUE)

# ##############################################################################
# set C compiler and NASM options
# ##############################################################################
# add OS specific options
if(WINDOWS)
  if(CMAKE_GENERATOR MATCHES "MinGW Makefiles")
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/windows-mingw.cmake)
  else()
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/windows.cmake)
  endif()
else()
  include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/unix.cmake)
endif()

# ##############################################################################
# extra target properties
# ##############################################################################
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${LIB_DIR})
link_directories(${LIB_DIR})

target_link_libraries(${PERF_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${PERF_APP} PRIVATE ${APP_DEFINES})

# ##############################################################################
# build post-quantum performance application
# ##############################################################################

set(PQC_PERF_APP imb-speed-pqc)
set(PQC_PERF_APP_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/pqc_perf.c)

add_executable(${PQC_PERF_APP} ${PQC_PERF_APP_SRC_FILES})
target_link_libraries(${PQC_PERF_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${PQC_PERF_APP} PRIVATE ${APP_DEFINES})

# ##############################################################################
# include tests
# ##############################################################################

include(perf_tests.cmake)
