# cmake-format: off
# Copyright (c) 2025, Intel Corporation
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

cmake_minimum_required(VERSION 3.16)
cmake_policy(VERSION 3.16)
project(imb-provider)

# Source files
set(PROV_COMMON_SRC e_prov.c prov_evp.c)
set(PROV_SRC prov_init.c prov_ciphers.c prov_bio.c)
set(PROV_SW_IPSEC_SRC prov_sw_gcm.c prov_sha.c prov_sw_sha.c prov_sw_ipsec_inf.c)
set(PROV_SW_ASYNC prov_sw_submit.c prov_sw_freelist.c prov_sw_polling.c prov_sw_queue.c prov_sw_init.c prov_events.c prov_sw_hmac_sha.c prov_hmac_sha.c prov_sw_aes_cfb.c prov_aes_cfb.c prov_aes_ccm.c prov_sw_ccm.c prov_sm4.c prov_chacha20_poly1305.c prov_sw_chacha20_poly1305.c prov_sw_chacha20.c prov_chacha20.c)
set(IPSEC_SRC ${CMAKE_SOURCE_DIR}/../../lib/intel-ipsec-mb.h)
include_directories(${CMAKE_SOURCE_DIR}/../../lib)

# Add the library target
add_library(imb-provider SHARED ${PROV_COMMON_SRC} ${PROV_SRC} ${PROV_SW_IPSEC_SRC} ${PROV_SW_ASYNC} ${IPSEC_SRC})

# Compiler flags
set(CFLAGS_COMMON "-Wall -Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong")

if(OPENSSL_INSTALL_DIR)
  if(OPENSSL_INSTALL_DIR MATCHES "^~")
    string(SUBSTRING ${OPENSSL_INSTALL_DIR} 2 -1 OPENSSL_INSTALL_DIR)
    file(TO_CMAKE_PATH "$ENV{HOME}/${OPENSSL_INSTALL_DIR}" OPENSSL_INSTALL_DIR)
  endif()
  set(ENV{LD_LIBRARY_PATH} "${OPENSSL_INSTALL_DIR}/usr/local/:$ENV{LD_LIBRARY_PATH}")
  set(ENV{PATH} "${OPENSSL_INSTALL_DIR}/usr/local/bin:$ENV{PATH}")
  set(LIBDIR "${OPENSSL_INSTALL_DIR}/lib64/ossl-modules")
  set(CFLAGS_OPENSSL_3 "-DOPENSSL_SUPPRESS_DEPRECATED")
  set(OPENSSL_LIB "-Wl,-rpath,${OPENSSL_INSTALL_DIR}/lib64 -L${OPENSSL_INSTALL_DIR}/lib64 -lcrypto")
  set(INCLUDES_OPENSSL "-I${OPENSSL_INSTALL_DIR}/usr/local")
  install(TARGETS imb-provider DESTINATION ${LIBDIR})
else() 
  set(OPENSSL_LIB "-lcrypto")
  set(CFLAGS_OPENSSL_3 "-DOPENSSL_SUPPRESS_DEPRECATED")
endif()

if(WITH_IPSEC_BUILD_DIR)
  if(WITH_IPSEC_BUILD_DIR MATCHES "^~")
    string(SUBSTRING ${WITH_IPSEC_BUILD_DIR} 2 -1 WITH_IPSEC_BUILD_DIR)
    file(TO_CMAKE_PATH "$ENV{HOME}/${WITH_IPSEC_BUILD_DIR}" PROV_SW_IPSEC_MB_LIB)
    set(PROV_SW_IPSEC_MB_LIB "${PROV_SW_IPSEC_MB_LIB}/lib/libIPSec_MB.so")
  else()
    set(PROV_SW_IPSEC_MB_LIB "${WITH_IPSEC_BUILD_DIR}/lib/libIPSec_MB.so")
  endif()
  link_directories(${PROV_SW_IPSEC_MB_LIB})
  set_target_properties(imb-provider PROPERTIES LINK_FLAGS "-shared ${PROV_SW_IPSEC_MB_LIB}")
  target_link_libraries(imb-provider ${PROV_SW_IPSEC_MB_LIB})
endif()

if(WITH_IPSEC_INSTALL_DIR)
  if(WITH_IPSEC_INSTALL_DIR MATCHES "^~")
    string(SUBSTRING ${WITH_IPSEC_INSTALL_DIR} 2 -1 WITH_IPSEC_INSTALL_DIR)
    file(TO_CMAKE_PATH "$ENV{HOME}/${WITH_IPSEC_INSTALL_DIR}" WITH_IPSEC_INSTALL_DIR)
  endif()
  include_directories(${WITH_IPSEC_INSTALL_DIR}/usr/include)
  set(INCLUDES_PROV_SW_IPSEC_MB "-I${WITH_IPSEC_INSTALL_DIR}/include")
  find_library(PROV_SW_IPSEC_MB_LIB NAMES IPSec_MB PATHS ${WITH_IPSEC_INSTALL_DIR})
endif()

# Output settings
include_directories(${INCLUDES_OPENSSL} ${INCLUDES_PROV_SW_IPSEC_MB})
add_definitions(${CFLAGS_COMMON} ${CFLAGS_OPENSSL_3})
set_target_properties(imb-provider PROPERTIES INSTALL_RPATH "${OPENSSL_INSTALL_DIR}/usr/local/lib64/")
link_libraries(${OPENSSL_LIB} ${PROV_SW_IPSEC_MB_LIB})

# Set empty prefix
set(CMAKE_STATIC_LIBRARY_PREFIX "")
set(CMAKE_SHARED_LIBRARY_PREFIX "")

# Enable testing
enable_testing()

# Add test subdirectory
add_subdirectory(test)

# Copy imb-provider.so to test directory after build
add_custom_command(
  TARGET imb-provider
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:imb-provider>
    ${CMAKE_CURRENT_BINARY_DIR}/test/
  COMMENT "Copying imb-provider.so to test directory"
)
