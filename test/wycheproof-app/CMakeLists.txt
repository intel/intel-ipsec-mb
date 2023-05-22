# Copyright (c) 2023, Intel Corporation
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

########################################
# set app and library names
########################################
set(WYCHEPROOF_APP imb-wycheproof)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)
set(TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

########################################
# set imb-wycheproof source files
########################################
set(WYCHEPROOF_APP_SRC_FILES_C
  ${CMAKE_CURRENT_SOURCE_DIR}/aes_gcm_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/aes_ccm_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/chacha20_poly1305_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/aes_cmac_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/gmac_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/gmac_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha1_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha224_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha256_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha384_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha512_test.json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wycheproof.c
)

########################################
# set C compiler and NASM options
########################################
# add OS specific options
if(WINDOWS)
  include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/windows.cmake)
else()
  include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/unix.cmake)
endif()


########################################
# add targets
########################################
include_directories(${LIB_DIR} ${TEST_INCLUDE_DIR})
link_directories(${LIB_DIR})

add_executable(${WYCHEPROOF_APP} ${WYCHEPROOF_APP_SRC_FILES_C})
target_link_libraries(${WYCHEPROOF_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${WYCHEPROOF_APP} PRIVATE ${APP_DEFINES})

########################################
# add tests
########################################

add_test(WYCHEPROOF ${WYCHEPROOF_APP})
add_test(WYCHEPROOF-SHANI-OFF ${WYCHEPROOF_APP} --shani-off)
add_test(WYCHEPROOF-GFNI-OFF ${WYCHEPROOF_APP} --gfni-off)

