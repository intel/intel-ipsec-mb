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

# ##############################################################################
# IPSec_MB library CMake Unix config
# ##############################################################################

set(LINUX 1)
set(LIB IPSec_MB) # 'lib' prefix assumed on Linux

message(STATUS "BUILD_TYPE...              ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_VERBOSE_MAKEFILE...  ${CMAKE_VERBOSE_MAKEFILE}")

# set compiler definitions
list(APPEND LIB_DEFINES LINUX)

# set NASM flags
string(APPEND CMAKE_ASM_NASM_FLAGS
       " -Werror -felf64 -Xgnu -gdwarf -DLINUX -D__linux__")

# set C compiler flags
set(CMAKE_C_FLAGS
    "-fPIC -W -Wall -Wextra -Wmissing-declarations \
-Wpointer-arith -Wcast-qual -Wundef -Wwrite-strings -Wformat \
-Wformat-security -Wunreachable-code -Wmissing-noreturn \
-Wsign-compare -Wno-endif-labels -Wstrict-prototypes \
-Wmissing-prototypes -Wold-style-definition \
-fno-delete-null-pointer-checks -fwrapv -std=c99")
set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG -O0")
set(CMAKE_C_FLAGS_RELEASE "-fstack-protector -D_FORTIFY_SOURCE=2 -O3")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -lc")

# -fno-strict-overflow is not supported by clang
if(CMAKE_COMPILER_IS_GNUCC)
  string(APPEND CMAKE_C_FLAGS " -fno-strict-overflow")
endif()

# set directory specific C compiler flags
set_source_files_properties(
  ${SRC_FILES_AVX_T1} ${SRC_FILES_AVX_T2}
  PPROPERTIES COMPILE_FLAGS
  "-march=sandybridge -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_AVX2_T1} ${SRC_FILES_AVX2_T2} ${SRC_FILES_AVX2_T3}
  PPROPERTIES COMPILE_FLAGS
  "-march=haswell -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_AVX512_T1} ${SRC_FILES_AVX512_T2}
  PROPERTIES COMPILE_FLAGS
  "-march=broadwell -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_SSE_T1} ${SRC_FILES_SSE_T2} ${SRC_FILES_SSE_T3}
  PROPERTIES COMPILE_FLAGS
  "-march=nehalem -maes -mpclmul")
set_source_files_properties(${SRC_FILES_X86_64}
  PROPERTIES COMPILE_FLAGS
  "-msse4.2")
if(AESNI_EMU)
  set_source_files_properties(
    ${SRC_FILES_NO_AESNI}
    PROPERTIES COMPILE_FLAGS
    "-march=nehalem -mno-pclmul")
endif()

########################################
# add library target
########################################

add_library(${LIB} ${SRC_FILES_ASM} ${SRC_FILES_C})

# set library SO version
string(REPLACE "." ";" VERSION_LIST ${IPSEC_MB_VERSION})
list(GET VERSION_LIST 0 SO_MAJOR_VER)
set_target_properties(${LIB} PROPERTIES
  VERSION ${IPSEC_MB_VERSION_FULL}
  SOVERSION ${SO_MAJOR_VER})

# set install rules
set(CMAKE_INSTALL_PREFIX "/usr"
  CACHE STRING "Set default installation directory" FORCE)
install(TARGETS ${LIB} DESTINATION lib)
install(FILES ${IMB_HDR} DESTINATION include)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libipsec-mb.7
              ${CMAKE_CURRENT_SOURCE_DIR}/libipsec-mb-dev.7
              DESTINATION man/man7)

