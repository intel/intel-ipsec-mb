# cmake-format: off
# Copyright (c) 2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# Check/replace special characters in source files.
# Targets:
#   special-chars      -- scan and report; fails the build if any are found
#   special-chars-fix  -- replace characters in-place with ASCII equivalents

set(SPECIAL_CHARS_SCRIPT
    "${CMAKE_CURRENT_SOURCE_DIR}/tools/special-chars.py")

find_program(PYTHON3 NAMES python3)

if(PYTHON3)
    # Directories to scan
    set(SPECIAL_CHARS_DIRS
        "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        "${CMAKE_CURRENT_SOURCE_DIR}/perf"
        "${CMAKE_CURRENT_SOURCE_DIR}/test"
        "${CMAKE_CURRENT_SOURCE_DIR}/examples"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
        "${CMAKE_CURRENT_SOURCE_DIR}/tools"
    )

    add_custom_target(
        special-chars
        COMMENT "Checking for special characters"
        COMMAND ${PYTHON3} ${SPECIAL_CHARS_SCRIPT} --check ${SPECIAL_CHARS_DIRS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        VERBATIM)

    add_custom_target(
        special-chars-fix
        COMMENT "Replacing special characters"
        COMMAND ${PYTHON3} ${SPECIAL_CHARS_SCRIPT} --fix ${SPECIAL_CHARS_DIRS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        VERBATIM)

    # Hook special-chars-fix into style-fix so it runs automatically.
    if(TARGET style-fix)
        add_dependencies(style-fix special-chars-fix)
    endif()
endif()
