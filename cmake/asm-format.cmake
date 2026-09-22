# cmake-format: off
# Copyright (c) 2025-2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# set asm-format binary name
if(NOT ASM_FORMAT_BIN)
    set(ASM_FORMAT_BIN "${CMAKE_CURRENT_SOURCE_DIR}/tools/asm-format.py")
endif()

find_program(ASM_FORMAT NAMES ${ASM_FORMAT_BIN})

# set up target if asm-format available
if(ASM_FORMAT)
    file(
        GLOB_RECURSE
        ASM_FORMAT_SRC_FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/lib/*.asm"
        "${CMAKE_CURRENT_SOURCE_DIR}/lib/*.inc"
        "${CMAKE_CURRENT_SOURCE_DIR}/perf/*.asm"
        "${CMAKE_CURRENT_SOURCE_DIR}/perf/*.inc"
        "${CMAKE_CURRENT_SOURCE_DIR}/test/*.asm"
        "${CMAKE_CURRENT_SOURCE_DIR}/test/*.inc"
        "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.asm"
        "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.inc"
    )

    add_custom_target(
        asm-style
        COMMENT "Checking style using asm-format.py"
        COMMAND ${ASM_FORMAT} --silent ${ASM_FORMAT_SRC_FILES})

     add_custom_target(
        asm-style-fix
        COMMENT "Fixing style issues using asm-format.py"
        COMMAND ${ASM_FORMAT} --format-in-place ${ASM_FORMAT_SRC_FILES})
else()
    set(ASM_FORMAT_MISSING_MSG "Could not find ${ASM_FORMAT_BIN}")

    message(DEBUG "WARNING: ${ASM_FORMAT_MISSING_MSG}")
    add_custom_target(
        asm-style
        COMMENT "Checking style using asm-format.py"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red "${ASM_FORMAT_MISSING_MSG}")
    add_custom_target(
        asm-style-fix
        COMMENT "Fixing style issues using asm-format.py"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --red "${ASM_FORMAT_MISSING_MSG}")
endif()
