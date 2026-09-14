# cmake-format: off
# Copyright (c) 2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# Ensure building entire project
if(NOT FULL_PROJECT_BUILD)
  message(FATAL_ERROR "Please run CMake from project root directory")
endif()

# imb-abi-check checks the callee-saved register set of the host x86-64 ABI:
# XMM6-XMM15 plus RBX, RBP, RSI, RDI, R12-R15 on Windows x64, and RBX, RBP,
# R12-R15 on System V AMD64 (which has no callee-saved XMM registers).

# ##############################################################################
# set app and library names
# ##############################################################################
set(ABI_CHECK_APP imb-abi-check)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)
set(TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set(LIB_INCLUDE_DIR ${LIB_DIR}/include)

# ##############################################################################
# set imb-abi-check source files
# ##############################################################################
set(ABI_CHECK_APP_SRC_FILES_C
    ${CMAKE_CURRENT_SOURCE_DIR}/abi_check_test.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/algo_maps.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/job_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/utils.c)
set(ABI_CHECK_APP_SRC_FILES_ASM ${CMAKE_CURRENT_SOURCE_DIR}/abi_probe.asm
                                ${CMAKE_CURRENT_SOURCE_DIR}/../common/misc.asm)

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
if(WINDOWS)
  if(CMAKE_GENERATOR MATCHES "MinGW Makefiles")
    include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/windows-mingw.cmake)
  else()
    include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/windows.cmake)
  endif()
else()
  include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/unix.cmake)
endif()

# abi_probe.asm pulls in cet.inc from the library include directory
string(APPEND CMAKE_ASM_NASM_FLAGS " -I${LIB_INCLUDE_DIR}/")

# ##############################################################################
# add targets
# ##############################################################################
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${LIB_DIR} ${TEST_INCLUDE_DIR})
link_directories(${LIB_DIR})

add_executable(${ABI_CHECK_APP} ${ABI_CHECK_APP_SRC_FILES_C}
                                ${ABI_CHECK_APP_SRC_FILES_ASM})
target_link_libraries(${ABI_CHECK_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${ABI_CHECK_APP} PRIVATE ${APP_DEFINES})

# ##############################################################################
# register test with CTest
# ##############################################################################
if(IMB_BIN_DIR)
  set(ABI_CHECK_APP_BIN_DIR "${IMB_BIN_DIR}")
else()
  set(ABI_CHECK_APP_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}")
endif()

get_property(multi_config_gen GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(multi_config_gen)
  string(APPEND ABI_CHECK_APP_BIN_DIR "/$<IF:$<CONFIG:Debug>,Debug,Release>")
endif()

add_test(
  NAME ABI_CHECK::DEFAULT
  COMMAND ${ABI_CHECK_APP}
  WORKING_DIRECTORY ${ABI_CHECK_APP_BIN_DIR})
