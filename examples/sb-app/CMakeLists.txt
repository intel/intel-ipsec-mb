# cmake-format: off
# Copyright (c) 2025, Intel Corporation
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
