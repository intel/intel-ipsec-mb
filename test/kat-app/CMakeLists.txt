# cmake-format: off
# Copyright (c) 2023-2024, Intel Corporation
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
set(TEST_APP imb-kat)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)
set(TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# ##############################################################################
# set imb-kat source files
# ##############################################################################
file(GLOB TEST_APP_SRC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
list(APPEND TEST_APP_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/../common/utils.c)
list(APPEND TEST_APP_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/../common/vector_utils.c)

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

# imb-kat's ML-DSA (FIPS 204) internal-interface (Sign_internal/
# Verify_internal) KAT coverage relies on the internal test API declared in
# lib/include/ml_dsa/ml_dsa_internal_api.h. That header is not part of the
# installed public API, so expose it to the app by adding lib/include to the
# search path; the library always exports these symbols (see
# lib/include/ml_dsa/ml_dsa_internal_api.h for details).
include_directories(${LIB_DIR}/include)

add_executable(${TEST_APP} ${TEST_APP_SRC_FILES})
target_link_libraries(${TEST_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(
  ${TEST_APP} PRIVATE ${APP_DEFINES}
                      KAT_APP_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors")

# ##############################################################################
# include tests
# ##############################################################################

include(kat_tests.cmake)

# On Windows shared-library builds, the DLL lives in <build>/lib but CTest
# runs tests from their own working directory where the DLL is not present.
# Prepend the DLL directory to PATH so test executables can find
# libIPSec_MB.dll at runtime without requiring an install step.
if(WINDOWS AND BUILD_SHARED_LIBS)
        get_property(_kat_tests DIRECTORY PROPERTY TESTS)
        set_property(
    TEST ${_kat_tests}
    APPEND
    PROPERTY ENVIRONMENT_MODIFICATION
             "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/lib")
endif()
