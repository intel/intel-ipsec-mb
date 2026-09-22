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
set(ACVP_APP imb-acvp)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)
set(TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# ##############################################################################
# set imb-acvp source files
# ##############################################################################
set(ACVP_APP_SRC_FILES_C ${CMAKE_CURRENT_SOURCE_DIR}/acvp_app_main.c
                         ${CMAKE_CURRENT_SOURCE_DIR}/../common/utils.c)

# ##############################################################################
# set toolchain options
# ##############################################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/unix.cmake)

include_directories(${LIB_DIR} ${TEST_INCLUDE_DIR} ${ACVP_INCLUDE_DIR})
link_directories(${LIB_DIR})
include_directories(${LIB_DIR}/include)

# ##############################################################################
# add target
# ##############################################################################
add_executable(${ACVP_APP} ${ACVP_APP_SRC_FILES_C})
target_link_libraries(${ACVP_APP} PRIVATE ${IPSEC_MB_LIB} ${ACVP_LIB})
target_compile_definitions(${ACVP_APP} PRIVATE ${APP_DEFINES})
