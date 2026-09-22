# cmake-format: off
# Copyright (c) 2025-2026, Intel Corporation
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
set(SAMPLE_APP imb-single-buff)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)
set(TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# ##############################################################################
# set imb-burst source files
# ##############################################################################
set(SAMPLE_APP_SRC_FILES_C ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

# ##############################################################################
# set C compiler options
# ##############################################################################
# add OS specific options
if(CMAKE_HOST_UNIX)
  include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/unix.cmake)
else()
  if(CMAKE_GENERATOR MATCHES "MinGW Makefiles")
    include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/windows-mingw.cmake)
  else()
    include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/windows.cmake)
  endif()
endif()

# ##############################################################################
# add targets
# ##############################################################################
include_directories(${LIB_DIR})
link_directories(${LIB_DIR})

add_executable(${SAMPLE_APP} ${SAMPLE_APP_SRC_FILES_C})
target_link_libraries(${SAMPLE_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${SAMPLE_APP} PRIVATE ${APP_DEFINES})

# ##############################################################################
# add tests
# ##############################################################################

# set working directory for tests
if(IMB_BIN_DIR)
  set(APP_BIN_DIR "${IMB_BIN_DIR}")
else()
  set(APP_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}")
endif()

# append config type for multi-config generators
get_property(multi_config_gen GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(multi_config_gen)
  string(APPEND APP_BIN_DIR "/$<IF:$<CONFIG:Debug>,Debug,Release>")
endif()

add_test(
  NAME EXAMPLE::SINGLE_BUFF::SHA1
  COMMAND ${SAMPLE_APP} SHA1
  WORKING_DIRECTORY ${APP_BIN_DIR})

  add_test(
  NAME EXAMPLE::SINGLE_BUFF::SHA224
  COMMAND ${SAMPLE_APP} SHA224
  WORKING_DIRECTORY ${APP_BIN_DIR})

  add_test(
  NAME EXAMPLE::SINGLE_BUFF::SHA256
  COMMAND ${SAMPLE_APP} SHA256
  WORKING_DIRECTORY ${APP_BIN_DIR})

  add_test(
  NAME EXAMPLE::SINGLE_BUFF::SHA384
  COMMAND ${SAMPLE_APP} SHA384
  WORKING_DIRECTORY ${APP_BIN_DIR})

  add_test(
  NAME EXAMPLE::SINGLE_BUFF::SHA512
  COMMAND ${SAMPLE_APP} SHA512
  WORKING_DIRECTORY ${APP_BIN_DIR})
