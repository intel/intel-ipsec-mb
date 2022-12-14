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

cmake_minimum_required(VERSION 3.16)
project(intel-ipsec-mb)

# set default options
option(AESNI_EMU "AESNI emulation support" OFF)
option(SAFE_PARAM "Parameter checking" ON)
option(SAFE_DATA "Clear sensitive data from registers and memory" ON)
option(SAFE_LOOKUP "Secure table lookups" ON)
option(SAFE_OPTIONS "Library security features" ON)
option(NO_COMPAT_IMB_API_053 "Disable compatibility with v0.53" ON)
option(BUILD_SHARED_LIBS "Build shared library" ON)
set(EXTRA_CFLAGS "" CACHE STRING "Extra compiler flags")

# disable all SAFE options when SAFE_OPTIONS false
if(NOT SAFE_OPTIONS)
  message(STATUS "SAFE_OPTIONS disabled")
  set(SAFE_PARAM OFF)
  set(SAFE_DATA OFF)
  set(SAFE_LOOKUP OFF)
endif()

message(STATUS "AESNI emulation support... ${AESNI_EMU}")
message(STATUS "SAFE_OPTIONS...            ${SAFE_OPTIONS}")
message(STATUS "SAFE_PARAM...              ${SAFE_PARAM}")
message(STATUS "SAFE_DATA...               ${SAFE_DATA}")
message(STATUS "SAFE_LOOKUP...             ${SAFE_LOOKUP}")
message(STATUS "BUILD_SHARED_LIBS...       ${BUILD_SHARED_LIBS}")
message(STATUS "EXTRA_CFLAGS...            ${EXTRA_CFLAGS}")
message(STATUS "NO_COMPAT_IMB_API_053...   ${NO_COMPAT_IMB_API_053}")

# set directories
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

# list all source directories
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

# set compiler definitions
set(LIB_DEFINES -DLINUX)
if(SAFE_DATA)
  list(APPEND LIB_DEFINES -DSAFE_DATA)
endif()
if(SAFE_PARAM)
  list(APPEND LIB_DEFINES -DSAFE_PARAM)
endif()
if(SAFE_LOOKUP)
  list(APPEND LIB_DEFINES -DSAFE_LOOKUP)
endif()
if(NO_COMPAT_IMB_API_053)
  list(APPEND LIB_DEFINES -DNO_COMPAT_IMB_API_053)
endif()

# set up NASM compilation
enable_language(ASM_NASM)
if(NOT CMAKE_ASM_NASM_COMPILER_LOADED)
  message(FATAL_ERROR "Can't find assembler")
endif()
set(CAN_USE_ASSEMBLER 1)

# generate list of assembly source files
foreach(DIR ${DIR_SOURCES})
  file(GLOB_RECURSE TMP "${DIR}/*.asm")
  list(APPEND SRC_FILES_ASM ${TMP})
endforeach()

# set NASM flags
set(CMAKE_ASM_NASM_FLAGS "-Werror -felf64 -Xgnu -gdwarf -I${DIR_INCLUDE}")

# generate list of C source files
file(GLOB SRC_FILES_AVX_T1 "${DIR_AVX_T1}/*.c")
file(GLOB SRC_FILES_AVX_T2 "${DIR_AVX_T2}/*.c")
file(GLOB SRC_FILES_AVX2_T1 "${DIR_AVX2_T1}/*.c")
file(GLOB SRC_FILES_AVX2_T2 "${DIR_AVX2_T2}/*.c")
file(GLOB SRC_FILES_AVX512_T1 "${DIR_AVX512_T1}/*.c")
file(GLOB SRC_FILES_AVX512_T2 "${DIR_AVX512_T2}/*.c")
file(GLOB SRC_FILES_SSE_T1 "${DIR_SSE_T1}/*.c")
file(GLOB SRC_FILES_SSE_T2 "${DIR_SSE_T2}/*.c")
file(GLOB SRC_FILES_SSE_T3 "${DIR_SSE_T3}/*.c")
file(GLOB SRC_FILES_X86_64 "${DIR_X86_64}/*.c")
file(GLOB SRC_FILES_NO_AESNI "${DIR_NO_AESNI}/*.c")

# set compiler flags
set_source_files_properties(
  ${SRC_FILES_AVX_T1} ${SRC_FILES_AVX_T2}
  PPROPERTIES COMPILE_FLAGS
  "-march=sandybridge -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_AVX2_T1} ${SRC_FILES_AVX2_T2}
  PPROPERTIES COMPILE_FLAGS
  "-march=haswell -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_AVX512_T1} ${SRC_FILES_AVX512_T2}
  PPROPERTIES COMPILE_FLAGS 
  "-march=broadwell -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_SSE_T1} ${SRC_FILES_SSE_T2} ${SRC_FILES_SSE_T3} 
  PROPERTIES COMPILE_FLAGS
  "-march=nehalem -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_X86_64}
  PROPERTIES COMPILE_FLAGS 
  "-msse4.2")
if(AESNI_EMU)
  set_source_files_properties(
    ${SRC_FILES_NO_AESNI}
    PROPERTIES COMPILE_FLAGS
    "-march=nehalem -mno-pclmul")
  list(APPEND SOURCES ${SRC_FILES_NO_AESNI})
endif()

set(CFLAGS "
  -fPIC
  -W
  -Wall
  -Wextra
  -Wmissing-declarations
  -Wpointer-arith
  -Wcast-qual
  -Wundef
  -Wwrite-strings
  -Wformat
  -Wformat-security
  -Wunreachable-code
  -Wmissing-noreturn
  -Wsign-compare
  -Wno-endif-labels
  -Wstrict-prototypes
  -Wmissing-prototypes
  -Wold-style-definition
  -fno-delete-null-pointer-checks
  -fwrapv"
  )
# -fno-strict-overflow is not supported by clang
if(CMAKE_COMPILER_IS_GNUCC)
  list(APPEND CFLAGS "-fno-strict-overflow")
endif()
if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
  list(APPEND CFLAGS "-g -DDEBUG")
  list(APPEND CFLAGS "-O0")
else()
  list(APPEND CFLAGS "-O2 -fstack-protector -d_fortify_source=2")
endif()
list(APPEND CFLAGS ${EXTRA_CFLAGS})

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

# add the library
add_library(IPSec_MB ${SRC_FILES_ASM} ${SRC_FILES_C})
target_include_directories(IPSec_MB PRIVATE ${DIR_CURRENT} ${DIR_INCLUDE} ${DIR_NO_AESNI})
target_compile_definitions(IPSec_MB PRIVATE ${LIB_DEFINES})

