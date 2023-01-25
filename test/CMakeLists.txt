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

cmake_minimum_required(VERSION 3.16)
project(intel-ipsec-mb)

# Ensure building entire project
if(NOT FULL_PROJECT_BUILD)
  message(FATAL_ERROR "Please run CMake from project root directory")
endif()

# #################
# Test Applications
# #################

set(TEST_APP ipsec_MB_testapp)
set(XVALID_APP ipsec_xvalid_test)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../lib)

# detect Linux or Windows system
if(CMAKE_HOST_UNIX)
  set(LINUX 1)
  set(IPSEC_MB_LIB IPSec_MB)
else()
  set(WINDOWS 1)
  set(IPSEC_MB_LIB libIPSec_MB)
endif()

# set up NASM compilation
enable_language(ASM_NASM)
if(NOT CMAKE_ASM_NASM_COMPILER_LOADED)
  message(FATAL_ERROR "Can't find assembler")
endif()
set(CAN_USE_ASSEMBLER TRUE)
if(LINUX)
  set(CMAKE_ASM_NASM_FLAGS "-felf64 -Xgnu -gdwarf -DLINUX -D__linux__")
else()
  set(CMAKE_ASM_NASM_FLAGS "-Werror -fwin64 -Xvc -DWIN_ABI")
endif()

# set ipsec_MB_test source files
set(TEST_APP_SRC_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/gcm_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ctr_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/customop_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/des_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ccm_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cmac_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/utils.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha1_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha256_sha512_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_md5_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/aes_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/sha_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/chained_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/api_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/pon_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ecb_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/zuc_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/kasumi_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/snow3g_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/direct_api_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/clear_mem_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hec_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/xcbc_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/aes_cbcs_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/crc_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/chacha_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/poly1305_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/chacha20_poly1305_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/null_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/snow_v_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/direct_api_param_test.c
)

# set ipsec_xvalid_test source files
set(XVALID_APP_SRC_FILES_C
  ${CMAKE_CURRENT_SOURCE_DIR}/ipsec_xvalid.c
  ${CMAKE_CURRENT_SOURCE_DIR}/utils.c
)
set(XVALID_APP_SRC_FILES_ASM
  ${CMAKE_CURRENT_SOURCE_DIR}/misc.asm
)

# set flags for different OS's
if(LINUX)
  set(CMAKE_C_FLAGS "-MMD -W -Wall -Wextra -Wmissing-declarations \
    -Wpointer-arith -Wcast-qual -Wundef -Wwrite-strings -Wformat \
    -Wformat-security -Wunreachable-code -Wmissing-noreturn -Wsign-compare \
    -Wno-endif-labels -Wstrict-prototypes -Wmissing-prototypes \
    -Wold-style-definition -fno-delete-null-pointer-checks -fwrapv"
  )
  set(CMAKE_C_FLAGS_DEBUG "-O0 -DDEBUG -g")
  set(CMAKE_C_FLAGS_RELEASE "-O3")
  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-g")

  # -fno-strict-overflow is not supported by clang
  if(CMAKE_COMPILER_IS_GNUCC)
    string(APPEND CMAKE_C_FLAGS " -fno-strict-overflow")
  endif()
else()
  # windows
  set(CMAKE_C_FLAGS "/nologo /DNO_COMPAT_IMB_API_053 /D_CRT_SECURE_NO_WARNINGS /Y- /W3 /WX- /Gm- /fp:precise /EHsc ${EXTRA_CFLAGS}")
  set(CMAKE_C_FLAGS_DEBUG "/Od /DDEBUG /Z7")
  set(CMAKE_C_FLAGS_RELEASE "/O2 /Oi")
  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/debug")
endif()

if(LINUX)
  set(APP_DEFINES LINUX _GNU_SOURCE NO_COMPAT_IMB_API_053)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${LIB_DIR})
link_directories(${LIB_DIR})

add_executable(${TEST_APP} ${TEST_APP_SRC_FILES})
target_link_libraries(${TEST_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${TEST_APP} PRIVATE ${APP_DEFINES})

add_executable(${XVALID_APP} ${XVALID_APP_SRC_FILES_C} ${XVALID_APP_SRC_FILES_ASM})
target_link_libraries(${XVALID_APP} PRIVATE ${IPSEC_MB_LIB})
