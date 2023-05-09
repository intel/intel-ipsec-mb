# Copyright (c) 2022, Intel Corporation
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

# ##############################################################################
# Build IPSec_MB library
# ##############################################################################

# ensure building entire project
if(NOT FULL_PROJECT_BUILD)
  message(FATAL_ERROR "Please run CMake from project root directory")
endif()

#######################################
# set default library options
#######################################
option(AESNI_EMU "AESNI emulation support" OFF)
option(SAFE_PARAM "API input parameter checking" ON)
option(SAFE_DATA "Sensitive data cleared from registers and memory at operation end" ON)
option(SAFE_LOOKUP "Lookups depending on sensitive data are constant time" ON)
option(SAFE_OPTIONS "Enable all safe options" ON)
option(NO_COMPAT_IMB_API_053 "Disable compatibility with v0.53" ON)
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(CMAKE_VERBOSE_MAKEFILE "Verbose build output" OFF)
set(EXTRA_CFLAGS "" CACHE STRING "Extra compiler flags")

# add library options to options list (used by print_help target)
list(APPEND IPSEC_MB_OPTIONS
  AESNI_EMU SAFE_PARAM SAFE_DATA SAFE_LOOKUP
  SAFE_OPTIONS NO_COMPAT_IMB_API_053 BUILD_SHARED_LIBS
  CMAKE_VERBOSE_MAKEFILE EXTRA_CFLAGS
)
set(IPSEC_MB_OPTIONS ${IPSEC_MB_OPTIONS} PARENT_SCOPE)

# disable all SAFE options when SAFE_OPTIONS false
if(NOT SAFE_OPTIONS)
  message(STATUS "SAFE_OPTIONS disabled")
  set(SAFE_PARAM OFF)
  set(SAFE_DATA OFF)
  set(SAFE_LOOKUP OFF)
endif()

#######################################
# set library directories
#######################################
set(DIR_CURRENT ${CMAKE_CURRENT_SOURCE_DIR}/)
set(DIR_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(DIR_AVX_T1 ${CMAKE_CURRENT_SOURCE_DIR}/avx_t1)
set(DIR_AVX_T2 ${CMAKE_CURRENT_SOURCE_DIR}/avx_t2)
set(DIR_AVX2_T1 ${CMAKE_CURRENT_SOURCE_DIR}/avx2_t1)
set(DIR_AVX2_T2 ${CMAKE_CURRENT_SOURCE_DIR}/avx2_t2)
set(DIR_AVX512_T1 ${CMAKE_CURRENT_SOURCE_DIR}/avx512_t1)
set(DIR_AVX512_T2 ${CMAKE_CURRENT_SOURCE_DIR}/avx512_t2)
set(DIR_SSE_T1 ${CMAKE_CURRENT_SOURCE_DIR}/sse_t1)
set(DIR_SSE_T2 ${CMAKE_CURRENT_SOURCE_DIR}/sse_t2)
set(DIR_SSE_T3 ${CMAKE_CURRENT_SOURCE_DIR}/sse_t3)
set(DIR_X86_64 ${CMAKE_CURRENT_SOURCE_DIR}/x86_64)
set(DIR_NO_AESNI ${CMAKE_CURRENT_SOURCE_DIR}/no-aesni)
if(AVX_IFMA)
  set(DIR_AVX2_T3 ${CMAKE_CURRENT_SOURCE_DIR}/avx2_t3)
endif()

########################################
# create list of all source directories
########################################
set(DIR_SOURCES
  ${DIR_AVX_T1}
  ${DIR_AVX_T2}
  ${DIR_AVX2_T1}
  ${DIR_AVX2_T2}
  ${DIR_AVX512_T1}
  ${DIR_AVX512_T2}
  ${DIR_SSE_T1}
  ${DIR_SSE_T2}
  ${DIR_SSE_T3}
  ${DIR_X86_64}
)
if(AESNI_EMU)
  list(APPEND DIR_SOURCES ${DIR_NO_AESNI})
endif()

if(AVX_IFMA)
  list(APPEND DIR_SOURCES ${DIR_AVX2_T3})
endif()

########################################
# find C source files in all directories
########################################
file(GLOB SRC_FILES_AVX_T1 "${DIR_AVX_T1}/*.c")
file(GLOB SRC_FILES_AVX_T2 "${DIR_AVX_T2}/*.c")
file(GLOB SRC_FILES_AVX2_T1 "${DIR_AVX2_T1}/*.c")
file(GLOB SRC_FILES_AVX2_T2 "${DIR_AVX2_T2}/*.c")
file(GLOB SRC_FILES_AVX2_T3 "${DIR_AVX2_T3}/*.c")
file(GLOB SRC_FILES_AVX512_T1 "${DIR_AVX512_T1}/*.c")
file(GLOB SRC_FILES_AVX512_T2 "${DIR_AVX512_T2}/*.c")
file(GLOB SRC_FILES_SSE_T1 "${DIR_SSE_T1}/*.c")
file(GLOB SRC_FILES_SSE_T2 "${DIR_SSE_T2}/*.c")
file(GLOB SRC_FILES_SSE_T3 "${DIR_SSE_T3}/*.c")
file(GLOB SRC_FILES_X86_64 "${DIR_X86_64}/*.c")
file(GLOB SRC_FILES_NO_AESNI "${DIR_NO_AESNI}/*.c")

# create list of all C source files
set(SRC_FILES_C
  ${SRC_FILES_AVX_T1}
  ${SRC_FILES_AVX_T2}
  ${SRC_FILES_AVX2_T1}
  ${SRC_FILES_AVX2_T2}
  ${SRC_FILES_AVX512_T1}
  ${SRC_FILES_AVX512_T2}
  ${SRC_FILES_SSE_T1}
  ${SRC_FILES_SSE_T2}
  ${SRC_FILES_SSE_T3}
  ${SRC_FILES_X86_64}
)
if(AESNI_EMU)
  list(APPEND SRC_FILES_C ${SRC_FILES_NO_AESNI})
endif()
if(AVX_IFMA)
  list(APPEND SRC_FILES_C ${SRC_FILES_AVX2_T3})
endif()

list(SORT SRC_FILES_C)

########################################
# generate list of assembly source files
########################################
foreach(DIR ${DIR_SOURCES})
  file(GLOB_RECURSE TMP "${DIR}/*.asm")
  list(APPEND SRC_FILES_ASM ${TMP})
endforeach()

list(SORT SRC_FILES_ASM)

########################################
# print build information
########################################
message(STATUS "AESNI emulation support... ${AESNI_EMU}")
message(STATUS "SAFE_OPTIONS...            ${SAFE_OPTIONS}")
message(STATUS "SAFE_PARAM...              ${SAFE_PARAM}")
message(STATUS "SAFE_DATA...               ${SAFE_DATA}")
message(STATUS "SAFE_LOOKUP...             ${SAFE_LOOKUP}")
message(STATUS "BUILD_SHARED_LIBS...       ${BUILD_SHARED_LIBS}")
message(STATUS "EXTRA_CFLAGS...            ${EXTRA_CFLAGS}")
message(STATUS "NO_COMPAT_IMB_API_053...   ${NO_COMPAT_IMB_API_053}")
message(STATUS "CMAKE_GENERATOR...         ${CMAKE_GENERATOR}")
message(STATUS "PLATFORM...                ${CMAKE_GENERATOR_PLATFORM}")

########################################
# set C compiler options
########################################
set(LIB_DEFINES)

# enable SAFE OPTIONS
if(SAFE_DATA)
  list(APPEND LIB_DEFINES SAFE_DATA)
  string(APPEND CMAKE_ASM_NASM_FLAGS " -DSAFE_DATA")
endif()
if(SAFE_PARAM)
  list(APPEND LIB_DEFINES SAFE_PARAM)
  string(APPEND CMAKE_ASM_NASM_FLAGS " -DSAFE_PARAM")
endif()
if(SAFE_LOOKUP)
  list(APPEND LIB_DEFINES SAFE_LOOKUP)
  string(APPEND CMAKE_ASM_NASM_FLAGS " -DSAFE_LOOKUP")
endif()
if(AESNI_EMU)
  list(APPEND LIB_DEFINES AESNI_EMU)
  string(APPEND CMAKE_ASM_NASM_FLAGS " -DAESNI_EMU")
endif()

# enable backward compatibility
if(NO_COMPAT_IMB_API_053)
  list(APPEND LIB_DEFINES NO_COMPAT_IMB_API_053)
endif()

# enable AVX IFMA support
if(AVX_IFMA)
  list(APPEND LIB_DEFINES AVX_IFMA)
endif()

########################################
# setup NASM
########################################
enable_language(ASM_NASM)
if(NOT CMAKE_ASM_NASM_COMPILER_LOADED)
  message(FATAL_ERROR "Can't find assembler")
endif()
set(CAN_USE_ASSEMBLER 1)

########################################
# add OS specific options
########################################
if(WINDOWS)
  include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/windows.cmake)
else()
  include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/unix.cmake)
endif()

# add user defined cflags
string(APPEND CMAKE_C_FLAGS " ${EXTRA_CFLAGS}")

# add library definitions to all C source files
foreach(FILE ${SRC_FILES_C})
  set_source_files_properties(${FILE} PROPERTIES
    COMPILE_DEFINITIONS "${LIB_DEFINES}")
endforeach()

# add include directories
target_include_directories(${LIB} PRIVATE
  ${DIR_CURRENT} ${DIR_INCLUDE} ${DIR_NO_AESNI})

