# Copyright (c) 2023, Intel Corporation
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

# set clang-format binary name
if(NOT CLANG_FORMAT_BIN)
  set(CLANG_FORMAT_BIN clang-format)
endif()

find_program(CLANG_FORMAT NAMES ${CLANG_FORMAT_BIN})

# set up target if clang-format available
if(CLANG_FORMAT)
  set(CLANG_FORMAT_REQUIRED "13.0.1")

  execute_process(
    COMMAND ${CLANG_FORMAT} --version
    RESULT_VARIABLE CLANG_FORMAT_VERSION_STATUS
    OUTPUT_VARIABLE CLANG_FORMAT_VERSION_OUTPUT
    ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

  string(REGEX MATCH "clang-format version ([0-9]*.[0-9]*.[0-9]*)"
               CLANG_FORMAT_VERSION "${CLANG_FORMAT_VERSION_OUTPUT}")

  if(CLANG_FORMAT_VERSION_STATUS EQUAL 0 AND CLANG_FORMAT_VERSION)
    message(STATUS "clang-format version: ${CMAKE_MATCH_1}")
    if(CLANG_FORMAT_REQUIRED VERSION_LESS_EQUAL ${CMAKE_MATCH_1})
      file(
        GLOB_RECURSE
        CLANG_FORMAT_SRC_FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/lib/*.[ch]"
        "${CMAKE_CURRENT_SOURCE_DIR}/perf/*.[ch]"
        "${CMAKE_CURRENT_SOURCE_DIR}/test/*.[ch]"
        "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.[ch]")

      add_custom_target(
        style
        COMMENT "Checking style using clang-format"
        COMMAND ${CLANG_FORMAT} -style=file --dry-run --Werror
                ${CLANG_FORMAT_SRC_FILES})

      add_custom_target(
        style-fix
        COMMENT "Fixing style issues using clang-format"
        COMMAND ${CLANG_FORMAT} -style=file -i ${CLANG_FORMAT_SRC_FILES})
    else()
      set(MIN_VERSION_MSG
          "target requires at least clang-format version ${CLANG_FORMAT_REQUIRED}! Found version ${CMAKE_MATCH_1}"
      )
      message(DEBUG "WARNING: ${MIN_VERSION_MSG}")
      add_custom_target(
        style
        COMMENT "Checking style using clang-format"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red "${MIN_VERSION_MSG}")
      add_custom_target(
        style-fix
        COMMENT "Fixing style issues using clang-format"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red "${MIN_VERSION_MSG}")
    endif()
  endif()
endif()
