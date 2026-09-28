# cmake-format: off
# Copyright (c) 2023-2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# ##############################################################################
# IPSec_MB library CMake Unix config
# ##############################################################################
include(GNUInstallDirs)
include(CheckCCompilerFlag)

set(LIB IPSec_MB) # 'lib' prefix assumed on Linux

# set compiler definitions
list(APPEND LIB_DEFINES LINUX)

# set NASM flags
string(APPEND CMAKE_ASM_NASM_FLAGS
       " -Werror -felf64 -Xgnu -gdwarf -DLINUX -D__linux__")

# set C compiler flags
set(CMAKE_C_FLAGS
    "-fPIC -fvisibility=hidden -W -Wall -Wextra -Wmissing-declarations \
-Wpointer-arith -Wcast-qual -Wundef -Wwrite-strings -Wformat \
-Wformat-security -Wunreachable-code -Wmissing-noreturn \
-Wsign-compare -Wno-endif-labels -Wstrict-prototypes \
-Wmissing-prototypes -Wold-style-definition \
-fno-delete-null-pointer-checks -fwrapv -std=c11")
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
set_source_files_properties(
  ${SRC_FILES_AVX2_T1} ${SRC_FILES_AVX2_T2} ${SRC_FILES_AVX2_T3} ${SRC_FILES_AVX2_T4} PROPERTIES
  COMPILE_FLAGS "-march=haswell -maes -mpclmul")
set_source_files_properties(
  ${SRC_FILES_AVX512_T1} ${SRC_FILES_AVX512_T2} ${SRC_FILES_AVX10_T1}
  PROPERTIES COMPILE_FLAGS "-march=skylake-avx512 -maes -mpclmul")

# -march=x86-64-v2 requires GCC 11++ and older versions do not support it.
# Suppress output from the "Failed" keyword in C compiler flag availability check.
set(SAVED_CMAKE_REQUIRED_QUIET ${CMAKE_REQUIRED_QUIET})
set(CMAKE_REQUIRED_QUIET TRUE)
check_c_compiler_flag("-march=x86-64-v2" COMPILER_SUPPORTS_X86_64_V2)
set(CMAKE_REQUIRED_QUIET ${SAVED_CMAKE_REQUIRED_QUIET})
if(COMPILER_SUPPORTS_X86_64_V2)
  set(SSE_MARCH_FLAG "-march=x86-64-v2")
else()
  set(SSE_MARCH_FLAG "-march=x86-64 -msse4.2")
endif()
set_source_files_properties(
  ${SRC_FILES_SSE_T1} ${SRC_FILES_SSE_T2} ${SRC_FILES_SSE_T3}
  PROPERTIES COMPILE_FLAGS "${SSE_MARCH_FLAG} -maes -mpclmul")
set_source_files_properties(${SRC_FILES_X86_64} ${SRC_FILES_OPENSSL}
  PROPERTIES COMPILE_FLAGS "-msse4.2")

# ##############################################################################
# add library target
# ##############################################################################

add_library(${LIB} ${SRC_FILES_ASM} ${SRC_FILES_C})

# Exports are controlled via libIPSec_MB.def / opaque handle API, so the
# ${LIB}_EXPORTS macro CMake adds by default for shared libraries is unused.
# Disable it: it otherwise gets passed as -D to the raw (non-preprocessed)
# ML-DSA .s assembly sources, which clang flags as an unused command-line
# argument warning.
set_target_properties(${LIB} PROPERTIES DEFINE_SYMBOL "")

# set library SO version
string(REPLACE "." ";" VERSION_LIST ${IPSEC_MB_VERSION})
list(GET VERSION_LIST 0 SO_MAJOR_VER)
set_target_properties(${LIB} PROPERTIES VERSION ${IPSEC_MB_VERSION_FULL}
                                        SOVERSION ${SO_MAJOR_VER})

# set install rules
# Relative install dirs so CPack can apply its own packaging prefix (/usr).
if(NOT LIB_INSTALL_DIR)
  set(LIB_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}")
endif()
if(NOT INCLUDE_INSTALL_DIR)
  set(INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_INCLUDEDIR}")
endif()
if(NOT MAN_INSTALL_DIR)
  set(MAN_INSTALL_DIR "${CMAKE_INSTALL_MANDIR}/man7")
endif()

foreach(_dir LIB INCLUDE MAN)
  if(IS_ABSOLUTE "${${_dir}_INSTALL_DIR}")
    set(${_dir}_INSTALL_FULL_DIR "${${_dir}_INSTALL_DIR}")
  else()
    set(${_dir}_INSTALL_FULL_DIR
        "${CMAKE_INSTALL_PREFIX}/${${_dir}_INSTALL_DIR}")
  endif()
endforeach()
unset(_dir)

message(STATUS "CMAKE_INSTALL_PREFIX...    ${CMAKE_INSTALL_PREFIX}")
message(STATUS "LIB_INSTALL_DIR...         ${LIB_INSTALL_FULL_DIR}")
message(STATUS "INCLUDE_INSTALL_DIR...     ${INCLUDE_INSTALL_FULL_DIR}")
message(STATUS "MAN_INSTALL_DIR...         ${MAN_INSTALL_FULL_DIR}")

install(TARGETS ${LIB} DESTINATION ${LIB_INSTALL_DIR})
install(FILES ${IMB_HDR} DESTINATION ${INCLUDE_INSTALL_DIR})
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libipsec-mb.7
              ${CMAKE_CURRENT_SOURCE_DIR}/libipsec-mb-dev.7
        DESTINATION ${MAN_INSTALL_DIR})

# Never modify system loader configuration; remind the user to run ldconfig
# instead. Skipped for staged (DESTDIR) installs.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND BUILD_SHARED_LIBS)
  # Resolve at install time to reflect `cmake --install --prefix` overrides
  if(IS_ABSOLUTE "${LIB_INSTALL_DIR}")
    set(_lib_dir_expr "${LIB_INSTALL_DIR}")
  else()
    set(_lib_dir_expr "\${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}")
  endif()
  install(
    CODE "if(NOT DEFINED ENV{DESTDIR})
  message(STATUS \"intel-ipsec-mb: run 'ldconfig' to refresh the linker cache. \"
                 \"If ${_lib_dir_expr} is not searched by the dynamic linker, \"
                 \"register it in /etc/ld.so.conf.d or set LD_LIBRARY_PATH.\")
endif()")
  unset(_lib_dir_expr)
endif()
