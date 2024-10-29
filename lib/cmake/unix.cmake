# cmake-format: off
# Copyright (c) 2023-2024, Intel Corporation
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
# IPSec_MB library CMake Unix config
# ##############################################################################
include(GNUInstallDirs)

set(LIB IPSec_MB) # 'lib' prefix assumed on Linux

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

if(CET_SUPPORT)
  string(APPEND CMAKE_C_FLAGS " -fcf-protection=full")
  string(APPEND CMAKE_SHARED_LINKER_FLAGS
         " -Wl,-z,ibt -Wl,-z,shstk -Wl,-z,cet-report=error")
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

# ##############################################################################
# add library target
# ##############################################################################

add_library(${LIB} ${SRC_FILES_ASM} ${SRC_FILES_C})

# set library SO version
string(REPLACE "." ";" VERSION_LIST ${IPSEC_MB_VERSION})
list(GET VERSION_LIST 0 SO_MAJOR_VER)
set_target_properties(${LIB} PROPERTIES VERSION ${IPSEC_MB_VERSION_FULL}
                                        SOVERSION ${SO_MAJOR_VER})

# set install rules
if(NOT CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX
      "/usr"
      CACHE STRING "Set default installation directory" FORCE)
endif()
if(NOT LIB_INSTALL_DIR)
  set(LIB_INSTALL_DIR "${CMAKE_INSTALL_FULL_LIBDIR}")
endif()
if(NOT INCLUDE_INSTALL_DIR)
  set(INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
endif()
if(NOT MAN_INSTALL_DIR)
  set(MAN_INSTALL_DIR "${CMAKE_INSTALL_FULL_MANDIR}/man7")
endif()

message(STATUS "LIB_INSTALL_DIR...         ${LIB_INSTALL_DIR}")
message(STATUS "INCLUDE_INSTALL_DIR...     ${INCLUDE_INSTALL_DIR}")
message(STATUS "MAN_INSTALL_DIR...         ${MAN_INSTALL_DIR}")

install(TARGETS ${LIB} DESTINATION ${LIB_INSTALL_DIR})
install(FILES ${IMB_HDR} DESTINATION ${INCLUDE_INSTALL_DIR})
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libipsec-mb.7
              ${CMAKE_CURRENT_SOURCE_DIR}/libipsec-mb-dev.7
        DESTINATION ${MAN_INSTALL_DIR})
