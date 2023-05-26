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
# IPSec_MB library CMake Windows config
# ##############################################################################

set(LIB libIPSec_MB)
set(SRC_DEF_FILE ${CMAKE_CURRENT_BINARY_DIR}/${LIB}_lnk.def)

if(CMAKE_GENERATOR MATCHES "Visual Studio")
  if(NOT (${CMAKE_GENERATOR_PLATFORM} MATCHES "x64"))
    message(FATAL_ERROR "Only 64-bit platform supported. Re-run with '-A x64' option.")
  endif()
endif()

# set NASM flags
string(APPEND CMAKE_ASM_NASM_FLAGS " -Werror -Xvc -DWIN_ABI")
set_source_files_properties(${SRC_FILES_ASM} PROPERTIES
  COMPILE_FLAGS "$<$<CONFIG:DEBUG>:-gcv8>")

# set C compiler flags
set(CMAKE_C_FLAGS "/nologo /Y- /W3 /WX- /Gm- /fp:precise /EHsc /std:c11")
set(CMAKE_C_FLAGS_DEBUG "/Od /DDEBUG /Z7")
set(CMAKE_SHARED_LINKER_FLAGS "/nologo")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "/RELEASE /DEBUG /OPT:REF /OPT:ICF /INCREMENTAL:NO")
set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "/DEBUG /INCREMENTAL:NO")
set(CMAKE_STATIC_LINKER_FLAGS "/nologo /nodefaultlib")

# set compiler optimization flags
set_source_files_properties(
  ${SRC_FILES_AVX_T1} ${SRC_FILES_AVX_T2}
  ${SRC_FILES_AVX2_T1} ${SRC_FILES_AVX2_T2}
  ${SRC_FILES_AVX2_T3} ${SRC_FILES_AVX512_T1}
  ${SRC_FILES_AVX512_T2}
  PROPERTIES COMPILE_FLAGS
  "/arch:AVX $<$<CONFIG:RELEASE>:/Oi /O2>")

set_source_files_properties(
  ${SRC_FILES_SSE_T1} ${SRC_FILES_SSE_T2}
  ${SRC_FILES_SSE_T3} ${SRC_FILES_X86_64}
  PROPERTIES COMPILE_FLAGS
  "$<$<CONFIG:RELEASE>:/Oi /O2>")

# set AESNI_EMU specific compiler flags
foreach(FILE ${SRC_FILES_NO_AESNI})
  set_source_files_properties(${FILE} PROPERTIES
    COMPILE_DEFINITIONS "${LIB_DEFINES}"
    COMPILE_FLAGS "$<$<CONFIG:RELEASE>:/Od /Oi>")
endforeach()

# generate windows DEF file
if(NOT AESNI_EMU)
  set(STR_FILTER "/c:_no_aesni")
endif()
if(NOT AVX_IFMA)
  set(STR_FILTER "${STR_FILTER} /c:_avx2_t3")
endif()

# filter unused symbol exports
if(NOT STR_FILTER)
  set(GEN_DEF_FILE_CMD "copy /Y ${LIB}.def ${SRC_DEF_FILE}")
else()
  set(GEN_DEF_FILE_CMD "findstr /v ${STR_FILTER} ${LIB}.def > ${SRC_DEF_FILE}")
endif()

########################################
# add library target
########################################

add_library(${LIB} ${SRC_FILES_ASM} ${SRC_FILES_C} ${SRC_DEF_FILE})

# set install rules
set(CMAKE_INSTALL_PREFIX "c:/Program Files"
  CACHE STRING "Set default installation directory" FORCE)
install(TARGETS ${LIB}
  DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_PROJECT_NAME})
install(FILES
  ${IMB_HDR}
  ${SRC_DEF_FILE}
  DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_PROJECT_NAME})
if(BUILD_SHARED_LIBS)
  install(FILES
    $<TARGET_FILE_DIR:${LIB}>/${LIB}.exp
    $<TARGET_FILE_DIR:${LIB}>/${LIB}.pdb
    DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_PROJECT_NAME})
  install(FILES
    $<TARGET_FILE_DIR:${LIB}>/${LIB}.dll
    DESTINATION $ENV{WINDIR}/system32)
endif()

execute_process(
  COMMAND cmd /C ${GEN_DEF_FILE_CMD}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_QUIET
)

