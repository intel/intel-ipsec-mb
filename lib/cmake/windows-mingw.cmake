# cmake-format: off
# Copyright (c) 2023, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# * Neither the name of Intel Corporation nor the names of its contributors may
#   be used to endorse or promote products derived from this software without
#   specific prior written permission.
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

# ##############################################################################
# IPSec_MB library CMake MinGW config
# ##############################################################################

set(LIB IPSec_MB) # 'lib' prefix assumed with MinGW
set(SRC_DEF_FILE ${CMAKE_CURRENT_BINARY_DIR}/lib${LIB}_lnk.def)

# set NASM flags
string(APPEND CMAKE_ASM_NASM_FLAGS " -Werror -fwin64 -Xvc -gcv8 -DWIN_ABI")

# set C compiler flags
set(CMAKE_C_FLAGS
    "-fPIC -W -Wall -Wextra -Wmissing-declarations \
-Wpointer-arith -Wcast-qual -Wundef -Wwrite-strings -Wformat \
-Wformat-security -Wunreachable-code -Wmissing-noreturn \
-Wsign-compare -Wno-endif-labels -Wstrict-prototypes \
-Wmissing-prototypes -Wold-style-definition \
-fno-delete-null-pointer-checks -fwrapv -std=c99")

if(NOT DEBUG_OPT)
  set(DEBUG_OPT "-O0")
endif()

set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG ${DEBUG_OPT}")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_SHARED_LINKER_FLAGS "-s")

# -fno-strict-overflow is not supported by clang
if(CMAKE_COMPILER_IS_GNUCC)
  string(APPEND CMAKE_C_FLAGS " -fno-strict-overflow")
endif()

# set directory specific C compiler flags
set_source_files_properties(${SRC_FILES_AVX_T1} ${SRC_FILES_AVX_T2} PPROPERTIES
                            COMPILE_FLAGS "-march=sandybridge -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_AVX2_T1} ${SRC_FILES_AVX2_T2} ${SRC_FILES_AVX2_T3} PPROPERTIES
  COMPILE_FLAGS "-march=haswell -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_AVX512_T1} ${SRC_FILES_AVX512_T2}
  PROPERTIES COMPILE_FLAGS "-march=broadwell -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_SSE_T1} ${SRC_FILES_SSE_T2} ${SRC_FILES_SSE_T3}
  PROPERTIES COMPILE_FLAGS "-march=nehalem -maes -mpclmul")
set_source_files_properties(${SRC_FILES_X86_64} PROPERTIES COMPILE_FLAGS
                                                           "-msse4.2")

# generate windows DEF file
if(NOT AVX_IFMA)
  set(STR_FILTER "${STR_FILTER} /c:_avx2_t3")
endif()
if(NOT SMX_NI)
  set(STR_FILTER "${STR_FILTER} /c:_avx2_t4")
endif()

# filter unused symbol exports
if(NOT STR_FILTER)
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E copy "lib${LIB}.def" ${SRC_DEF_FILE}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
else()
  execute_process(
    COMMAND cmd /C "findstr /v ${STR_FILTER} lib${LIB}.def > ${SRC_DEF_FILE}"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# ##############################################################################
# add library target
# ##############################################################################

add_library(${LIB} ${SRC_FILES_ASM} ${SRC_FILES_C} ${SRC_DEF_FILE})

# ##############################################################################
# library install rules
# ##############################################################################
message(STATUS "CMAKE_INSTALL_PREFIX...    ${CMAKE_INSTALL_PREFIX}")

install(
  TARGETS ${LIB}
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)

# install required shared library files
if(BUILD_SHARED_LIBS)
  # install library in system folder if prefix not modified
  if(CMAKE_INSTALL_PREFIX STREQUAL ${DEFAULT_INSTALL_PREFIX})
    install(FILES $<TARGET_FILE_DIR:${LIB}>/lib${LIB}.dll
            DESTINATION $ENV{WINDIR}/system32)
  endif()
endif()

# install header files
install(FILES ${IMB_HDR} DESTINATION include)
