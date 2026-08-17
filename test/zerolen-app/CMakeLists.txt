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
set(TEST_APP imb-zerolen)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)
set(TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# ##############################################################################
# set source files
# ##############################################################################
set(TEST_APP_SRC_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/zerolen_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/utils.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/guard_mem.c)

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

add_executable(${TEST_APP} ${TEST_APP_SRC_FILES})
target_link_libraries(${TEST_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${TEST_APP} PRIVATE ${APP_DEFINES})


# ##############################################################################
# register test with CTest
# ##############################################################################
if(IMB_BIN_DIR)
  set(TEST_APP_BIN_DIR "${IMB_BIN_DIR}")
else()
  set(TEST_APP_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}")
endif()

add_test(
  NAME ZEROLEN::DEFAULT
  COMMAND ${TEST_APP}
  WORKING_DIRECTORY ${TEST_APP_BIN_DIR})

add_test(
  NAME ZEROLEN::GFNIOFF
  COMMAND ${TEST_APP} --gfni-off
  WORKING_DIRECTORY ${TEST_APP_BIN_DIR})

add_test(
  NAME ZEROLEN::SHANIOFF
  COMMAND ${TEST_APP} --shani-off
  WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
