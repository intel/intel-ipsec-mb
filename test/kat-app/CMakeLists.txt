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

# drop toolchain flags that are incompatible with the sanitizer runtime
imb_san_strip_incompatible_flags()

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

# apply sanitizer instrumentation when requested (see cmake/sanitizers.cmake).
# This application is always instrumented. The library is instrumented only
# when SANITIZE_LIB is enabled: the ASan allocator interceptors are process
# wide, so heap errors triggered through the library are still caught, but
# redzones and UBSan checks inside the library itself require the library to
# be built with SANITIZE_LIB=ON.
imb_target_add_sanitizers(${TEST_APP})

# ##############################################################################
# include tests
# ##############################################################################

include(kat_tests.cmake)

# On Windows shared-library builds, CTest runs tests from their own working
# directory where the DLL is not present. Prepend the DLL directory to PATH so
# test executables can find libIPSec_MB.dll at runtime without requiring an
# install step. The directory is resolved from the library target because
# multi-config generators (e.g. Visual Studio) place it in lib/<CONFIG>.
if(WINDOWS AND BUILD_SHARED_LIBS AND TARGET ${IPSEC_MB_LIB})
        get_property(_kat_tests DIRECTORY PROPERTY TESTS)
        set_property(
    TEST ${_kat_tests}
    APPEND
    PROPERTY ENVIRONMENT_MODIFICATION
             "PATH=path_list_prepend:$<TARGET_FILE_DIR:${IPSEC_MB_LIB}>")
endif()

# ##############################################################################
# sanitizer runtime configuration for the tests
# ##############################################################################
if(IMB_SAN_ENABLED)
  get_property(_kat_tests DIRECTORY PROPERTY TESTS)

  # without these the sanitizers only print a report and the test still passes
  if(IMB_SAN_TEST_ENV)
    set_property(
      TEST ${_kat_tests}
      APPEND
      PROPERTY ENVIRONMENT ${IMB_SAN_TEST_ENV})
  endif()

  # the MSVC AddressSanitizer runtime DLL is not in the default search path
  if(IMB_SAN_RUNTIME_DIR)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.22)
      set_property(
        TEST ${_kat_tests}
        APPEND
        PROPERTY ENVIRONMENT_MODIFICATION
                 "PATH=path_list_prepend:${IMB_SAN_RUNTIME_DIR}")
    else()
      message(
        WARNING
          "CMake 3.22 or newer is required to extend PATH for the tests. "
          "Add ${IMB_SAN_RUNTIME_DIR} to PATH manually before running ctest.")
    endif()
  endif()
endif()
