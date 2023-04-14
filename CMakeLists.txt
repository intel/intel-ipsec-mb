# Copyright (c) 2022, Intel Corporation
# Copyright 2000-2023 Kitware, Inc. and Contributors
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Intel Corporation nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# set default CMakeCache.txt values
set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Selected build type")
# clear default release build C Compiler Flags
set(CMAKE_C_FLAGS_RELEASE "" CACHE STRING "" FORCE)
# clear default debug build C Compiler Flags
set(CMAKE_C_FLAGS_DEBUG "" CACHE STRING "" FORCE)

# get version from public header file
set(IMB_HDR "${CMAKE_CURRENT_SOURCE_DIR}/lib/intel-ipsec-mb.h")
file(STRINGS ${IMB_HDR} VER_STR REGEX "^.*IMB_VERSION_STR.*$")
string(REGEX MATCH "[0-9]+.[0-9]+.[0-9]+(-[a-z]+)?" IPSEC_MB_VERSION_FULL ${VER_STR})
string(REGEX MATCH "[0-9]+.[0-9]+.[0-9]+" IPSEC_MB_VERSION ${IPSEC_MB_VERSION_FULL})
message(STATUS "Project Version: ${IPSEC_MB_VERSION_FULL}")

cmake_minimum_required(VERSION 3.16)
project(intel-ipsec-mb VERSION ${IPSEC_MB_VERSION}
    DESCRIPTION "Intel(R) IPsec Multi-Buffer library")

# project options list (used by print_help target)
set(IPSEC_MB_OPTIONS CMAKE_BUILD_TYPE)

# flag to force full project build
set(FULL_PROJECT_BUILD TRUE)

# check compiler version
if(("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU") AND
    (CMAKE_C_COMPILER_VERSION VERSION_LESS 5.0))
    message(FATAL_ERROR "GNU C Compiler version must be 5.0 or higher")
endif()

# build library
add_subdirectory(lib)

# build perf application
add_subdirectory(perf)

# build test applications
add_subdirectory(test)

#######################################
# configure custom targets
#######################################

# add custom target to uninstall library
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/lib/cmake/uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

# add custom target to print help information
add_custom_target(
  print_help
  COMMAND ${CMAKE_COMMAND} -E echo "Available build options:"
  VERBATIM
)

foreach (OPTION ${IPSEC_MB_OPTIONS})
  get_property(HELP_TEXT CACHE ${OPTION} PROPERTY HELPSTRING)
  if(HELP_TEXT)
    add_custom_command(TARGET print_help
      COMMAND
      ${CMAKE_COMMAND} -E echo "    ${OPTION}=${${OPTION}} - ${HELP_TEXT}"
    )
  endif()
endforeach()

