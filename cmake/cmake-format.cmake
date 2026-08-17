# cmake-format: off
# Copyright (c) 2024, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
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
