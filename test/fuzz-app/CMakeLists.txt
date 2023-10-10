# Copyright (c) 2023, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# * Neither the name of Intel Corporation nor the names of its contributors may
#   be used to endorse or promote products derived from this software without
#   specific prior written permission.
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

# Ensure building entire project
if(NOT FULL_PROJECT_BUILD)
  message(FATAL_ERROR "Please run CMake from project root directory")
endif()

# ##############################################################################
# set app and library names
# ##############################################################################
set(FUZZ_APP imb-fuzz-api)
set(DIRECT_FUZZ_APP imb-fuzz-direct-api)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)
set(TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# ##############################################################################
# set source files
# ##############################################################################
set(FUZZ_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/job_api_fuzz_test.c)
set(DIRECT_FUZZ_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/direct_api_fuzz_test.c)

# ##############################################################################
# set toolchain options
# ##############################################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/unix.cmake)
string(APPEND CMAKE_C_FLAGS " -g -fsanitize=fuzzer,address,leak")

include_directories(${LIB_DIR} ${TEST_INCLUDE_DIR})

# ##############################################################################
# add targets
# ##############################################################################
add_executable(${FUZZ_APP} ${FUZZ_SOURCES})
target_link_libraries(${FUZZ_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${FUZZ_APP} PRIVATE ${APP_DEFINES})

add_executable(${DIRECT_FUZZ_APP} ${DIRECT_FUZZ_SOURCES})
target_link_libraries(${DIRECT_FUZZ_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${DIRECT_FUZZ_APP} PRIVATE ${APP_DEFINES})
