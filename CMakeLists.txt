# Copyright (c) 2022, Intel Corporation
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
set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Set default build to release")
set(CMAKE_C_FLAGS_RELEASE "" CACHE STRING "Clear default release build C Compiler Flags" FORCE)
set(CMAKE_C_FLAGS_DEBUG "" CACHE STRING "Clear default debug build C Compiler Flags" FORCE)

# get version from public header file
set(IMB_HDR "${CMAKE_CURRENT_SOURCE_DIR}/lib/intel-ipsec-mb.h")
file(STRINGS ${IMB_HDR} VER_STR REGEX "^.*IMB_VERSION_STR.*$")
string(REGEX MATCH "[0-9]+.[0-9]+.[0-9]+(-[a-z]+)?" IPSEC_MB_VERSION_FULL ${VER_STR})
string(REGEX MATCH "[0-9]+.[0-9]+.[0-9]+" IPSEC_MB_VERSION ${IPSEC_MB_VERSION_FULL})
message(STATUS "Project Version: ${IPSEC_MB_VERSION_FULL}")

cmake_minimum_required(VERSION 3.16)
project(intel-ipsec-mb VERSION ${IPSEC_MB_VERSION}
    DESCRIPTION "Intel(R) IPsec Multi-Buffer library")

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
