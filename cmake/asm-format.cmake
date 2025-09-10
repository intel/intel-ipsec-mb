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
