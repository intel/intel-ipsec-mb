# cmake-format: off
# Copyright (c) 2022-2026, Intel Corporation
# Copyright 2000-2023 Kitware, Inc. and Contributors
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

cmake_minimum_required(VERSION 3.16)
cmake_policy(VERSION 3.16)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")

# get version from public header file
set(IMB_HDR "${CMAKE_CURRENT_SOURCE_DIR}/lib/intel-ipsec-mb.h")
imb_get_version(${IMB_HDR})
message(STATUS "Project Version: ${IPSEC_MB_VERSION_FULL}")

# set default project values
imb_set_proj_defaults()

project(
  intel-ipsec-mb
  VERSION ${IPSEC_MB_VERSION}
  DESCRIPTION "Intel(R) IPsec Multi-Buffer library"
  LANGUAGES C ASM
  HOMEPAGE_URL https://github.com/intel/intel-ipsec-mb/)

# Configure CTest/Valgrind memcheck. Must precede include(CTest), which bakes
# MEMORYCHECK_* into the configuration as they stand at that point.
if(CONSTANT_TIME_VALIDATION)
  find_program(VALGRIND_EXECUTABLE valgrind)
  if(VALGRIND_EXECUTABLE)
    set(MEMORYCHECK_COMMAND "${VALGRIND_EXECUTABLE}")
    set(MEMORYCHECK_COMMAND_OPTIONS
        "--tool=memcheck --error-exitcode=1 --errors-for-leak-kinds=all")
  else()
    message(WARNING
      "CONSTANT_TIME_VALIDATION=ON but valgrind executable not found in PATH. "
      "'ctest -T memcheck' will not be available.")
  endif()
endif()

# add testing support
include(CTest)

# set binary output directory if specified
imb_set_binary_dir()

# detect OS
imb_detect_os()

# do compiler checks
imb_compiler_check()

# configure sanitizer instrumentation (SANITIZERS / SANITIZE_LIB)
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/sanitizers.cmake")
imb_setup_sanitizers()

# post-quantum cryptography (ML-DSA) requires perl for OpenSSL-style asm gen
find_package(Perl REQUIRED)
message(STATUS "PERL_EXECUTABLE...         ${PERL_EXECUTABLE}")

# ##############################################################################
# configure pre gen custom targets
# ##############################################################################

# add custom target to uninstall library
imb_add_target_uninstall(
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/cmake/uninstall.cmake.in")

# style check target
imb_add_target_style_checks()

# TAGS target
imb_add_target_tags()

# spellcheck target
imb_add_target_spellcheck()

# cppcheck and bughunt targets
imb_add_target_cppcheck_bughunt()

# doxy target to generate documentation
imb_add_target_doxy()

# ##############################################################################
# configure main project targets
# ##############################################################################

# build library
add_subdirectory(lib)

if(NOT BUILD_LIBRARY_ONLY)
  # build perf application
  add_subdirectory(perf)

  # build test applications
  add_subdirectory(test)

  # build example applications
  add_subdirectory(examples)
endif()

# ##############################################################################
# configure post gen custom targets
# ##############################################################################

# add custom target to print help information
imb_add_target_print_help("${IPSEC_MB_OPTIONS}")

# ##############################################################################
# configure CPack for package generation
# ##############################################################################

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/cpack.cmake")
