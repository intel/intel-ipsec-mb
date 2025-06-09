# cmake-format: off
# Copyright (c) 2024, Intel Corporation
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

# set working directory for tests
if(IMB_BIN_DIR)
  set(TEST_APP_BIN_DIR "${IMB_BIN_DIR}")
else()
  set(TEST_APP_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}")
endif()

# append config type for multi-config generators
get_property(multi_config_gen GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(multi_config_gen)
  string(APPEND TEST_APP_BIN_DIR "/$<IF:$<CONFIG:Debug>,Debug,Release>")
endif()

set(TEST_TYPES
    KAT
    DO_TEST
    CBC
    CFB_ONE
    CFB
    CTR
    PON
    XCBC
    GCM
    GMAC
    GHASH
    CUSTOMOP
    DES
    CCM
    CMAC
    ZUC_EEA3
    ZUC_EIA3
    KASUMI
    SNOW3G
    HMAC_SHA1
    HMAC_SHA256
    HMAC_MD5
    AES
    ECB
    SHA
    CHAINED
    HEC
    CHACHA
    POLY1305
    API
    DIRECT_API
    CLEAR_MEM
    CRC
    CHACHA20_POLY1305
    NULL
    DIRECT_API_PARAM
    QUIC-ECB
    QUIC_CHACHA20
    SM4_ECB
    SM4_CBC
    SM3
    HMAC_SM3
    SM4_CTR
    SM4_GCM)

# add tests
foreach(TYPE ${TEST_TYPES})
  add_test(
    NAME KAT::${TYPE}
    COMMAND ${TEST_APP} --test-type ${TYPE}
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
endforeach()
