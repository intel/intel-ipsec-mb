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

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")

# get version from public header file
imb_get_version("${CMAKE_CURRENT_SOURCE_DIR}/lib/intel-ipsec-mb.h")
message(STATUS "Project Version: ${IPSEC_MB_VERSION_FULL}")

cmake_minimum_required(VERSION 3.16)
project(intel-ipsec-mb VERSION ${IPSEC_MB_VERSION}
    DESCRIPTION "Intel(R) IPsec Multi-Buffer library")

# set default project values
imb_set_proj_defaults()

# do compiler checks
imb_compiler_check()

# add testing support
include(CTest)

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
imb_add_target_uninstall("${CMAKE_CURRENT_SOURCE_DIR}/lib/cmake/uninstall.cmake.in")

# add custom target to print help information
imb_add_target_print_help("${IPSEC_MB_OPTIONS}")

