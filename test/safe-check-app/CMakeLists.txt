# cmake-format: off
# Copyright (c) 2026, Intel Corporation
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
set(SAFE_CHECK_APP imb-safe-check)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)
set(TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# ##############################################################################
# set imb-safe-check source files
# ##############################################################################
set(SAFE_CHECK_APP_SRC_FILES_C
    ${CMAKE_CURRENT_SOURCE_DIR}/safe_check_test.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/algo_maps.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/job_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/utils.c)
set(SAFE_CHECK_APP_SRC_FILES_ASM ${CMAKE_CURRENT_SOURCE_DIR}/../common/misc.asm)

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
    include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/windows-mingw.cmake)
  else()
    include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/windows.cmake)
  endif()
else()
  include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/unix.cmake)
endif()

# ##############################################################################
# add targets
# ##############################################################################
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${LIB_DIR} ${TEST_INCLUDE_DIR})
link_directories(${LIB_DIR})

add_executable(${SAFE_CHECK_APP} ${SAFE_CHECK_APP_SRC_FILES_C}
                                 ${SAFE_CHECK_APP_SRC_FILES_ASM})
target_link_libraries(${SAFE_CHECK_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${SAFE_CHECK_APP} PRIVATE ${APP_DEFINES})

# ##############################################################################
# add tests
# ##############################################################################

include(safe_check_tests.cmake)
