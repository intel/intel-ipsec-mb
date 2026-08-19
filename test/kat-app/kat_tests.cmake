# cmake-format: off
# Copyright (c) 2024, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
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
    JSON_PARSER
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
    ZUC_EEA3_NEA6
    ZUC_EIA3_NIA6
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
    SM4_ECB
    SM4_CBC
    SM3
    HMAC_SM3
    SM4_CTR
    SM4_GCM
    SHA3
    ML_DSA
    ML_KEM)

# add tests
foreach(TYPE ${TEST_TYPES})
  add_test(
    NAME KAT::${TYPE}
    COMMAND ${TEST_APP} --test-type ${TYPE}
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
endforeach()

# additionally run the algorithms carrying the Wycheproof vectors with CPU
# extensions disabled
set(SHANI_OFF_TEST_TYPES HMAC_SHA1 HMAC_SHA256)

foreach(TYPE ${SHANI_OFF_TEST_TYPES})
  add_test(
    NAME KAT::${TYPE}_SHANI_OFF
    COMMAND ${TEST_APP} --test-type ${TYPE} --shani-off
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
endforeach()

set(GFNI_OFF_TEST_TYPES GCM GMAC CCM CMAC CHACHA20_POLY1305)

foreach(TYPE ${GFNI_OFF_TEST_TYPES})
  add_test(
    NAME KAT::${TYPE}_GFNI_OFF
    COMMAND ${TEST_APP} --test-type ${TYPE} --gfni-off
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
endforeach()
