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
set(PROV_SW_IPSEC_SRC prov_sw_gcm.c prov_sha2.c prov_sw_sha2.c prov_sw_ipsec_inf.c)

# Add the library target
add_library(imb-provider SHARED ${PROV_COMMON_SRC} ${PROV_SRC} ${PROV_SW_IPSEC_SRC})

# Set compiler and linker flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${includes_openssl} ${includes_prov_sw_ipsec_mb} ${cflags_mem_driver} ${cflags_openssl_3} ${cflags_prov_sw} ${cflags_prov_sw_ipsec} ${cflags_common}")
set(PROV_SW_IPSEC_MB_LIB "${WITH_IPSEC_BUILD_DIR}/lib/libIPSec_MB.so")
link_directories(${PROV_SW_IPSEC_MB_LIB})
set_target_properties(imb-provider PROPERTIES LINK_FLAGS "-shared ${PROV_LD_LIB} ${PROV_SW_IPSEC_MB_LIB}")
target_link_libraries(imb-provider ${PROV_SW_IPSEC_MB_LIB})

# Compiler flags
set(CFLAGS_COMMON "-Wall -Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong")

# Output enabled algorithms and additional flags
message(STATUS "==============================================================================")
message(STATUS "Enabled Algorithms and Additional Flags")
message(STATUS "==============================================================================")
message(STATUS "PROV_SW ALGORITHMS : ${cflags_prov_sw}")
message(STATUS "ADDITIONAL FLAGS  : ${CFLAGS_COMMON} ${cflags_openssl_3}")
message(STATUS "==============================================================================")

# OpenSSL settings
if(OPENSSL_INSTALL_DIR)
  set(LIBDIR "${OPENSSL_INSTALL_DIR}/lib64/ossl-modules")
  set(CFLAGS_OPENSSL_3 "-DOPENSSL_SUPPRESS_DEPRECATED")
  set(OPENSSL_LIB "-Wl,-rpath,${OPENSSL_INSTALL_DIR}/lib -L${OPENSSL_INSTALL_DIR}/lib -lcrypto")
  set(INCLUDES_OPENSSL "-I${OPENSSL_INSTALL_DIR}/include")
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(OPENSSL libcrypto)
  set(LIBDIR "${OPENSSL_LIBDIR}/ossl-modules")
  set(INCLUDES_OPENSSL "${OPENSSL_INCLUDE_DIRS}")
  set(CFLAGS_OPENSSL_3 "-DOPENSSL_SUPPRESS_DEPRECATED")
  set(OPENSSL_LIB "-lcrypto")
endif()

# IPSec settings
if(WITH_PROV_SW_IPSEC_MB_INSTALL_DIR)
  include_directories(${WITH_PROV_SW_IPSEC_MB_INSTALL_DIR}/usr/include)
  set(CFLAGS_PROV_SW_IPSEC "-DPROV_SW_IPSEC")
  set(INCLUDES_PROV_SW_IPSEC_MB "-I${WITH_PROV_SW_IPSEC_MB_INSTALL_DIR}/include")
  find_library(PROV_SW_IPSEC_MB_LIB NAMES IPSec_MB PATHS ${WITH_PROV_SW_IPSEC_MB_INSTALL_DIR}/lib)
  if(NOT PROV_SW_IPSEC_MB_LIB)
    message(FATAL_ERROR "${WITH_PROV_SW_IPSEC_MB_INSTALL_DIR}/lib/libIPSec_MB.so not found. Install it and try again.")
  endif()
endif()

# Output settings
include_directories(${INCLUDES_OPENSSL} ${INCLUDES_PROV_SW_IPSEC_MB})
add_definitions(${CFLAGS_COMMON} ${CFLAGS_OPENSSL_3} ${CFLAGS_PROV_SW_IPSEC})
link_libraries(${OPENSSL_LIB} ${PROV_SW_IPSEC_MB_LIB} ${PROV_LD_LIB})

# Add the install targets
message(STATUS "${OPENSSL_INSTALL_DIR}")
set(CMAKE_STATIC_LIBRARY_PREFIX "")
set(CMAKE_SHARED_LIBRARY_PREFIX "")
install(TARGETS imb-provider DESTINATION ${LIBDIR})