# cmake-format: off
# Copyright (c) 2022-2024, Intel Corporation
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

# ##############################################################################
# Build IPSec_MB library
# ##############################################################################

# ensure building entire project
if(NOT FULL_PROJECT_BUILD)
  message(FATAL_ERROR "Please run CMake from project root directory")
endif()

# ##############################################################################
# setup NASM
# ##############################################################################
if(NOT CMAKE_ASM_NASM_COMPILER)
  set(CMAKE_ASM_NASM_COMPILER nasm)
endif()
enable_language(ASM_NASM)
if(NOT CMAKE_ASM_NASM_COMPILER_LOADED)
  message(FATAL_ERROR "Can't find assembler")
endif()

set(NASM_VERSION_REQUIRED "2.14")
set(NASM_VERSION_AVX_IFMA "2.16")
set(NASM_VERSION_SMX_NI "2.16.02")

execute_process(
  COMMAND ${CMAKE_ASM_NASM_COMPILER} -v
  OUTPUT_VARIABLE NASM_VERSION_OUTPUT
  OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX MATCH "NASM version ([0-9]*.[0-9]*.[0-9]*)" NASM_VERSION
             "${NASM_VERSION_OUTPUT}")
if(NASM_VERSION)
  if(NASM_VERSION_REQUIRED VERSION_GREATER ${CMAKE_MATCH_1})
    message(
      FATAL_ERROR "NASM version must be at least ${NASM_VERSION_REQUIRED}!")
  endif()
  message(STATUS "NASM version: ${CMAKE_MATCH_1}")
  if(NASM_VERSION_AVX_IFMA VERSION_GREATER ${CMAKE_MATCH_1})
    message(
      NOTICE
      "Minimum required NASM version for AVX-IFMA: ${NASM_VERSION_AVX_IFMA}. AVX-IFMA code not compiled - update NASM."
    )
  else()
    # AVX IFMA supported by NASM
    set(AVX_IFMA 1)
  endif()
  if(NASM_VERSION_SMX_NI VERSION_GREATER ${CMAKE_MATCH_1})
    message(
      NOTICE
      "Minimum required NASM version for SM3/SM4/SHA512-NI: ${NASM_VERSION_SMX_NI}. SM3/SM4/SHA512-NI code not compiled - update NASM."
    )
  else()
    # SM3/SM4/SHA512-NI supported by NASM
    set(SMX_NI 1)
  endif()
else()
  message(
    WARNING
      "Could not parse NASM version string: ${NASM_VERSION_OUTPUT}.\nPlease, be sure that ${CMAKE_ASM_NASM_COMPILER} version is >= ${NASM_VERSION_REQUIRED}"
  )
endif()

set(CAN_USE_ASSEMBLER 1)

# ##############################################################################
# set library directories
# ##############################################################################
set(DIR_CURRENT ${CMAKE_CURRENT_SOURCE_DIR}/)
set(DIR_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(DIR_AVX_T1 ${CMAKE_CURRENT_SOURCE_DIR}/avx_t1)
set(DIR_AVX2_T1 ${CMAKE_CURRENT_SOURCE_DIR}/avx2_t1)
set(DIR_AVX2_T2 ${CMAKE_CURRENT_SOURCE_DIR}/avx2_t2)
set(DIR_AVX512_T1 ${CMAKE_CURRENT_SOURCE_DIR}/avx512_t1)
set(DIR_AVX512_T2 ${CMAKE_CURRENT_SOURCE_DIR}/avx512_t2)
set(DIR_AVX10_T1 ${CMAKE_CURRENT_SOURCE_DIR}/avx10_t1)
set(DIR_SSE_T1 ${CMAKE_CURRENT_SOURCE_DIR}/sse_t1)
set(DIR_SSE_T2 ${CMAKE_CURRENT_SOURCE_DIR}/sse_t2)
set(DIR_SSE_T3 ${CMAKE_CURRENT_SOURCE_DIR}/sse_t3)
set(DIR_X86_64 ${CMAKE_CURRENT_SOURCE_DIR}/x86_64)
if(AVX_IFMA)
  set(DIR_AVX2_T3 ${CMAKE_CURRENT_SOURCE_DIR}/avx2_t3)
endif()
if(SMX_NI)
  set(DIR_AVX2_T4 ${CMAKE_CURRENT_SOURCE_DIR}/avx2_t4)
endif()
# ##############################################################################
# create list of all source directories
# ##############################################################################
set(DIR_SOURCES
    ${DIR_AVX_T1}
    ${DIR_AVX_T2}
    ${DIR_AVX2_T1}
    ${DIR_AVX2_T2}
    ${DIR_AVX2_T4}
    ${DIR_AVX512_T1}
    ${DIR_AVX512_T2}
    ${DIR_AVX10_T1}
    ${DIR_SSE_T1}
    ${DIR_SSE_T2}
    ${DIR_SSE_T3}
    ${DIR_X86_64})

if(AVX_IFMA)
  list(APPEND DIR_SOURCES ${DIR_AVX2_T3})
endif()

# ##############################################################################
# find C source files in all directories
# ##############################################################################
file(GLOB SRC_FILES_AVX_T1 "${DIR_AVX_T1}/*.c")
file(GLOB SRC_FILES_AVX_T2 "${DIR_AVX_T2}/*.c")
file(GLOB SRC_FILES_AVX2_T1 "${DIR_AVX2_T1}/*.c")
file(GLOB SRC_FILES_AVX2_T2 "${DIR_AVX2_T2}/*.c")
file(GLOB SRC_FILES_AVX2_T3 "${DIR_AVX2_T3}/*.c")
file(GLOB SRC_FILES_AVX2_T4 "${DIR_AVX2_T4}/*.c")
file(GLOB SRC_FILES_AVX512_T1 "${DIR_AVX512_T1}/*.c")
file(GLOB SRC_FILES_AVX512_T2 "${DIR_AVX512_T2}/*.c")
file(GLOB SRC_FILES_AVX10_T1 "${DIR_AVX10_T1}/*.c")
file(GLOB SRC_FILES_SSE_T1 "${DIR_SSE_T1}/*.c")
file(GLOB SRC_FILES_SSE_T2 "${DIR_SSE_T2}/*.c")
file(GLOB SRC_FILES_SSE_T3 "${DIR_SSE_T3}/*.c")
file(GLOB SRC_FILES_X86_64 "${DIR_X86_64}/*.c")

# create list of all C source files
set(SRC_FILES_C
    ${SRC_FILES_AVX_T1}
    ${SRC_FILES_AVX_T2}
    ${SRC_FILES_AVX2_T1}
    ${SRC_FILES_AVX2_T2}
    ${SRC_FILES_AVX512_T1}
    ${SRC_FILES_AVX512_T2}
    ${SRC_FILES_AVX10_T1}
    ${SRC_FILES_SSE_T1}
    ${SRC_FILES_SSE_T2}
    ${SRC_FILES_SSE_T3}
    ${SRC_FILES_X86_64}
    ${SRC_FILES_AVX2_T4})
if(AVX_IFMA)
  list(APPEND SRC_FILES_C ${SRC_FILES_AVX2_T3})
endif()
if(SMX_NI)
  list(APPEND SRC_FILES_C ${SRC_FILES_AVX2_T4})
endif()

# post-quantum: ML-DSA (FIPS 204) and ML-KEM (FIPS 203) C sources. Vendored
# OpenSSL sources (the core ML-DSA/ML-KEM algorithms and the shared SHA-3/SHAKE
# implementation, including the x4 AVX512VL wrapper sha3_x4_avx512vl.c) live
# under lib/openssl/crypto; the ipsec-mb glue (public API and internal ops)
# stays in lib/x86_64/ml_dsa and lib/x86_64/ml_kem.
file(GLOB SRC_FILES_OPENSSL "${DIR_X86_64}/ml_dsa/*.c" "${DIR_X86_64}/ml_kem/*.c"
    "${DIR_CURRENT}/openssl/crypto/ml_dsa/*.c"
    "${DIR_CURRENT}/openssl/crypto/ml_kem/*.c"
    "${DIR_CURRENT}/openssl/crypto/sha/*.c")
list(APPEND SRC_FILES_C ${SRC_FILES_OPENSSL})

list(SORT SRC_FILES_C)

# ##############################################################################
# generate list of assembly source files
# ##############################################################################
foreach(DIR ${DIR_SOURCES})
  file(GLOB_RECURSE TMP "${DIR}/*.asm")
  list(APPEND SRC_FILES_ASM ${TMP})
endforeach()

list(SORT SRC_FILES_ASM)

# post-quantum: ML-DSA (FIPS 204) optimized asm kernels, generated from the
# vendored OpenSSL perl-asm. The AVX2 NTT and the x4 AVX512VL Keccak/SHAKE
# replace the portable-C baseline at run time (selected via OPENSSL_ia32cap_P).
# On Linux the perl-asm emits GAS (.S, LANGUAGE ASM); on Windows it emits NASM
# (.asm, LANGUAGE ASM_NASM) to match the imb_perlasm_flavour selection, and
# avoid the MSVC_RUNTIME_LIBRARY configure error caused by GAS (as.exe from
# Strawberry Perl MinGW) not being an MSVC-family assembler. The Linux output
# uses an upper-case .S extension (rather than .s) so the assembler driver
# treats it as assembler-with-cpp: this consumes compiler-driven flags like
# -D/-MD/-MT/-MF instead of ignoring them (clang otherwise flags them as
# unused command-line arguments on a raw, non-preprocessed .s file).
if(WINDOWS)
  set(MLDSA_NTT_S ${CMAKE_CURRENT_BINARY_DIR}/ml_dsa_ntt-x86_64.asm)
  set(KECCAK1600_S ${CMAKE_CURRENT_BINARY_DIR}/keccak1600-x86_64.asm)
  set(KECCAK_X4_S ${CMAKE_CURRENT_BINARY_DIR}/keccak1600x4-avx512vl.asm)
  set(ML_DSA_ASM_LANGUAGE ASM_NASM)
else()
  set(MLDSA_NTT_S ${CMAKE_CURRENT_BINARY_DIR}/ml_dsa_ntt-x86_64.S)
  set(KECCAK1600_S ${CMAKE_CURRENT_BINARY_DIR}/keccak1600-x86_64.S)
  set(KECCAK_X4_S ${CMAKE_CURRENT_BINARY_DIR}/keccak1600x4-avx512vl.S)
  set(ML_DSA_ASM_LANGUAGE ASM)
endif()

set(MLDSA_NTT_PL ${CMAKE_CURRENT_SOURCE_DIR}/openssl/crypto/ml_dsa/asm/ml_dsa_ntt-x86_64.pl)
imb_add_perlasm(${MLDSA_NTT_PL} ${MLDSA_NTT_S})

set(KECCAK1600_PL ${CMAKE_CURRENT_SOURCE_DIR}/openssl/crypto/sha/asm/keccak1600-x86_64.pl)
imb_add_perlasm(${KECCAK1600_PL} ${KECCAK1600_S})

set(KECCAK_X4_PL ${CMAKE_CURRENT_SOURCE_DIR}/openssl/crypto/sha/asm/keccak1600x4-avx512vl.pl)
imb_add_perlasm(${KECCAK_X4_PL} ${KECCAK_X4_S})

set(SRC_FILES_ML_DSA_ASM ${MLDSA_NTT_S} ${KECCAK1600_S} ${KECCAK_X4_S})
set_source_files_properties(${SRC_FILES_ML_DSA_ASM} PROPERTIES GENERATED TRUE
                                                               LANGUAGE ${ML_DSA_ASM_LANGUAGE})
list(APPEND SRC_FILES_ASM ${SRC_FILES_ML_DSA_ASM})

# post-quantum: ML-KEM (FIPS 203) optimized asm kernels, generated from the
# vendored OpenSSL perl-asm. The AVX2 NTT replaces the portable-C baseline at
# run time (selected via OPENSSL_ia32cap_P).
if(WINDOWS)
  set(MLKEM_NTT_S ${CMAKE_CURRENT_BINARY_DIR}/ml_kem_ntt-x86_64.asm)
  set(ML_KEM_ASM_LANGUAGE ASM_NASM)
else()
  set(MLKEM_NTT_S ${CMAKE_CURRENT_BINARY_DIR}/ml_kem_ntt-x86_64.S)
  set(ML_KEM_ASM_LANGUAGE ASM)
endif()

set(MLKEM_NTT_PL ${CMAKE_CURRENT_SOURCE_DIR}/openssl/crypto/ml_kem/asm/ml_kem_ntt-x86_64.pl)
imb_add_perlasm(${MLKEM_NTT_PL} ${MLKEM_NTT_S})

set(SRC_FILES_ML_KEM_ASM ${MLKEM_NTT_S})
set_source_files_properties(${SRC_FILES_ML_KEM_ASM} PROPERTIES GENERATED TRUE
  LANGUAGE ${ML_KEM_ASM_LANGUAGE})
list(APPEND SRC_FILES_ASM ${SRC_FILES_ML_KEM_ASM})

# ##############################################################################
# set C compiler options
# ##############################################################################
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

# enable AVX IFMA support
if(AVX_IFMA)
  list(APPEND LIB_DEFINES AVX_IFMA)
endif()
# enable SMX-NI support
if(SMX_NI)
  list(APPEND LIB_DEFINES SMX_NI)
endif()

# ##############################################################################
# add OS specific options
# ##############################################################################
if(WINDOWS)
  if(CMAKE_GENERATOR MATCHES "MinGW Makefiles")
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/windows-mingw.cmake)
  else()
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/windows.cmake)
  endif()
else()
  include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/unix.cmake)
endif()

# add user defined cflags
string(APPEND CMAKE_C_FLAGS " ${EXTRA_CFLAGS}")

# add library definitions to all C source files
foreach(FILE ${SRC_FILES_C})
  set_source_files_properties(${FILE} PROPERTIES COMPILE_DEFINITIONS
                                                 "${LIB_DEFINES}")
endforeach()

# add include directories
target_include_directories(${LIB} PRIVATE ${DIR_CURRENT} ${DIR_INCLUDE})

# ##############################################################################
# ML-DSA (FIPS 204) and ML-KEM (FIPS 203) build wiring
# ##############################################################################
# The vendored OpenSSL sources compile against a self-contained compat include
# tree rooted at include/openssl:
#   include/openssl/crypto        - genuine ported OpenSSL headers
#                                    (e.g. crypto/ml_dsa.h, crypto/ml_kem.h)
#   include/openssl/crypto/ml_dsa - genuine ported OpenSSL ML-DSA headers
#   include/openssl/internal      - genuine ported OpenSSL internal headers
#   include/openssl/compat        - ipsec-mb compatibility helpers
#                                    (vendored sources include openssl_compat.h
#                                    directly; compat/openssl/* and
#                                    compat/internal/* provide remaining
#                                    non-vendored OpenSSL type/constant shims)
# Defining KECCAK1600_ASM (and leaving OPENSSL_NO_ASM undefined) enables the
# asm-accelerated paths: ml_dsa_ntt.c selects the AVX2 NTT and ml_dsa_sample.c
# pulls in the x4 AVX512VL SHAKE sampling, both chosen at run time via
# OPENSSL_ia32cap_P (populated by the generic lib/x86_64/imb_ossl_ia32cap.c,
# built unconditionally via SRC_FILES_X86_64, see above). ML-KEM reuses the
# same vendored SHA-3/SHAKE implementation (lib/openssl/crypto/sha) so it needs
# KECCAK1600_ASM too, for its compat EVP shim to resolve.
target_include_directories(
  ${LIB} PRIVATE ${DIR_INCLUDE}/ml_dsa ${DIR_INCLUDE}/ml_kem ${DIR_INCLUDE}/openssl
                 ${DIR_INCLUDE}/openssl/crypto/ml_dsa ${DIR_INCLUDE}/openssl/compat)
foreach(FILE ${SRC_FILES_OPENSSL})
  set_source_files_properties(
    ${FILE} PROPERTIES COMPILE_DEFINITIONS
                       "${LIB_DEFINES};KECCAK1600_ASM")
endforeach()
