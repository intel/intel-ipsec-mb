# cmake-format: off
# Copyright (c) 2023-2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# set clang-format binary name
if(NOT CLANG_FORMAT_BIN)
  set(CLANG_FORMAT_BIN clang-format)
endif()

find_program(CLANG_FORMAT NAMES ${CLANG_FORMAT_BIN})

# set up target if clang-format available
if(CLANG_FORMAT)
  set(CLANG_FORMAT_REQUIRED "18.1.0")

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
