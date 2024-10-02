# cmake-format: off
# Copyright (c) 2024, Intel Corporation
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

# set cmake-format binary name
if(NOT CMAKE_FORMAT_BIN)
  set(CMAKE_FORMAT_BIN cmake-format)
endif()

find_program(CMAKE_FORMAT NAMES ${CMAKE_FORMAT_BIN})

# set up target if cmake-format available
if(CMAKE_FORMAT)
  set(CMAKE_FORMAT_REQUIRED "0.6.13")

  execute_process(
    COMMAND ${CMAKE_FORMAT} --version
    RESULT_VARIABLE CMAKE_FORMAT_VERSION_STATUS
    OUTPUT_VARIABLE CMAKE_FORMAT_VERSION_OUTPUT
    ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

  string(REGEX MATCH "([0-9]*.[0-9]*.[0-9]*)" CMAKE_FORMAT_VERSION
               "${CMAKE_FORMAT_VERSION_OUTPUT}")

  if(CMAKE_FORMAT_VERSION_STATUS EQUAL 0 AND CMAKE_FORMAT_VERSION)
    message(STATUS "cmake-format version: ${CMAKE_MATCH_1}")
    if(CMAKE_FORMAT_REQUIRED VERSION_LESS_EQUAL ${CMAKE_MATCH_1})
      file(
        GLOB_RECURSE
        CMAKE_FORMAT_SRC_FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/*.cmake"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/*CMakeLists.txt"
        "${CMAKE_CURRENT_SOURCE_DIR}/lib/*.cmake"
        "${CMAKE_CURRENT_SOURCE_DIR}/lib/*CMakeLists.txt"
        "${CMAKE_CURRENT_SOURCE_DIR}/perf/**/*.cmake"
        "${CMAKE_CURRENT_SOURCE_DIR}/perf/**/CMakeLists.txt"
        "${CMAKE_CURRENT_SOURCE_DIR}/test/**/*.cmake"
        "${CMAKE_CURRENT_SOURCE_DIR}/test/**/CMakeLists.txt"
        "${CMAKE_CURRENT_SOURCE_DIR}/examples/**/*.cmake"
        "${CMAKE_CURRENT_SOURCE_DIR}/examples/**/CMakeLists.txt")

      add_custom_target(
        cmake-style
        COMMENT "Checking CMake style using cmake-format"
        COMMAND ${CMAKE_FORMAT} --check ${CMAKE_FORMAT_SRC_FILES})

      add_custom_target(
        cmake-style-fix
        COMMENT "Fixing style issues using cmake-format"
        COMMAND ${CMAKE_FORMAT} -i ${CMAKE_FORMAT_SRC_FILES})
    else()
      set(MIN_VERSION_MSG
          "target requires at least cmake-format version ${CMAKE_FORMAT_REQUIRED}! Found version ${CMAKE_MATCH_1}"
      )
      message(DEBUG "WARNING: ${MIN_VERSION_MSG}")
      add_custom_target(
        cmake-style
        COMMENT "Checking style using cmake-format"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red "${MIN_VERSION_MSG}")
      add_custom_target(
        cmake-style-fix
        COMMENT "Fixing style issues using cmake-format"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red "${MIN_VERSION_MSG}")
    endif()
  endif()
endif()
