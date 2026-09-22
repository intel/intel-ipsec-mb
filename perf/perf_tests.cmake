# cmake-format: off
# Copyright (c) 2024-2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# set working directory for tests
if(IMB_BIN_DIR)
  set(APP_BIN_DIR "${IMB_BIN_DIR}")
else()
  set(APP_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}")
endif()

# append config type for multi-config generators
get_property(multi_config_gen GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if (multi_config_gen)
  STRING(APPEND APP_BIN_DIR "/$<IF:$<CONFIG:Debug>,Debug,Release>")
endif()

########################################
# cipher tests
########################################

set(CIPHER_ALGOS
  aes-cbc-128
  aes-cbc-192
  aes-cbc-256
  aes-ctr-128
  aes-ctr-192
  aes-ctr-256
  aes-ecb-128
  aes-ecb-192
  aes-ecb-256
  aes-docsis-128
  aes-docsis-256
  des-docsis
  des-cbc
  3des-cbc
  zuc-eea3
  snow3g-uea2
  kasumi-uea1
  chacha20
  sm4-ecb
  sm4-cbc
  sm4-ctr
  aes-cfb-128
  aes-cfb-192
  aes-cfb-256
  zuc-nea6
  snow5g-nea4
  aes-nea5
  null)

# cipher smoke tests (burst API)
foreach(ALGO ${CIPHER_ALGOS})
  add_test(NAME PERF::SMOKE::CIPHER::BURST_API::${ALGO}
    COMMAND ${PERF_APP} --smoke --burst-api --cipher-algo ${ALGO}
    WORKING_DIRECTORY ${APP_BIN_DIR})
endforeach()

# cipher smoke tests (job API)
foreach(ALGO ${CIPHER_ALGOS})
  add_test(NAME PERF::SMOKE::CIPHER::JOB_API::${ALGO}
    COMMAND ${PERF_APP} --smoke --job-api --cipher-algo ${ALGO}
    WORKING_DIRECTORY ${APP_BIN_DIR})
endforeach()

########################################
# hash tests
########################################

set(HASH_ALGOS
  sha1-hmac
  sha224-hmac
  sha256-hmac
  sha384-hmac
  sha512-hmac
  aes-xcbc
  md5-hmac
  aes-cmac
  sha1
  sha224
  sha256
  sha384
  sha512
  null
  zuc-eia3
  snow3g-uia2
  kasumi-uia1
  aes-gmac-128
  aes-gmac-192
  aes-gmac-256
  aes-cmac-256
  poly-1305
  crc32-ethernet-fcs
  crc32-sctp
  crc32-wimax-ofdma-data
  crc24-lte-a
  crc24-lte-b
  crc16-x25
  crc16-fp-data
  crc11-fp-header
  crc10-iuup-data
  crc8-wimax-ofdma-hcs
  crc7-fp-header
  crc6-iuup-header
  ghash
  sm3
  sm3-hmac
  sha3-224
  sha3-256
  sha3-384
  sha3-512
  shake-128
  shake-256
  aes-nia5
  zuc-nia6
  snow5g-nia4
  sha3-224-hmac
  sha3-256-hmac
  sha3-384-hmac
  sha3-512-hmac)

# hash smoke tests (burst API)
foreach(ALGO ${HASH_ALGOS})
  add_test(NAME PERF::SMOKE::HASH::BURST_API::${ALGO}
    COMMAND ${PERF_APP} --smoke --burst-api --hash-algo ${ALGO}
    WORKING_DIRECTORY ${APP_BIN_DIR})
endforeach()

# hash smoke tests (job API)
foreach(ALGO ${HASH_ALGOS})
  add_test(NAME PERF::SMOKE::HASH::JOB_API::${ALGO}
    COMMAND ${PERF_APP} --smoke --job-api --hash-algo ${ALGO}
    WORKING_DIRECTORY ${APP_BIN_DIR})
endforeach()

########################################
# aead tests
########################################

set(AEAD_ALGOS
  aes-gcm-128
  aes-gcm-192
  aes-gcm-256
  aes-ccm-128
  aes-ccm-256
  pon-128
  pon-128-no-ctr
  chacha20-poly1305
  aes-docsis-128-crc32
  aes-docsis-256-crc32
  sm4-gcm
  aes-nca5
  zuc-nca6)

# aead smoke tests (burst API)
foreach(ALGO ${AEAD_ALGOS})
  add_test(NAME PERF::SMOKE::AEAD::BURST_API::${ALGO}
    COMMAND ${PERF_APP} --smoke --burst-api --aead-algo ${ALGO}
    WORKING_DIRECTORY ${APP_BIN_DIR})
endforeach()

# aead smoke tests (job API)
foreach(ALGO ${AEAD_ALGOS})
  add_test(NAME PERF::SMOKE::AEAD::JOB_API::${ALGO}
    COMMAND ${PERF_APP} --smoke --job-api --aead-algo ${ALGO}
    WORKING_DIRECTORY ${APP_BIN_DIR})
endforeach()

########################################
# direct API tests
########################################

set(DIRECT_API_ALGOS
  aes-gcm-128
  aes-gcm-192
  aes-gcm-256
  chacha20-poly1305)

# aead smoke tests (direct API)
foreach(ALGO ${DIRECT_API_ALGOS})
  add_test(NAME PERF::SMOKE::AEAD::DIRECT_API::${ALGO}
    COMMAND ${PERF_APP} --smoke --direct-api --aead-algo ${ALGO}
    WORKING_DIRECTORY ${APP_BIN_DIR})
endforeach()

########################################
# cipher burst API tests
########################################

set(CIPHER_BURST_API_ALGOS
  aes-cbc-128
  aes-cbc-192
  aes-cbc-256
  aes-cfb-128
  aes-cfb-192
  aes-cfb-256
  aes-ctr-128
  aes-ctr-192
  aes-ctr-256
  aes-ecb-128
  aes-ecb-192
  aes-ecb-256)

# cipher smoke tests (cipher burst API)
foreach(ALGO ${CIPHER_BURST_API_ALGOS})
  add_test(NAME PERF::SMOKE::CIPHER::CIPHER_BURST_API::${ALGO}
    COMMAND ${PERF_APP} --smoke --cipher-burst-api --cipher-algo ${ALGO}
    WORKING_DIRECTORY ${APP_BIN_DIR})
endforeach()


########################################
# hash burst API tests
########################################

set(HASH_BURST_API_ALGOS
  sha1-hmac
  sha224-hmac
  sha256-hmac
  sha384-hmac
  sha512-hmac
  aes-cmac
  sha1
  sha224
  sha256
  sha384
  sha512)

# hash smoke tests (hash burst API)
foreach(ALGO ${HASH_BURST_API_ALGOS})
  add_test(NAME PERF::SMOKE::HASH::HASH_BURST_API::${ALGO}
    COMMAND ${PERF_APP} --smoke --hash-burst-api --hash-algo ${ALGO}
    WORKING_DIRECTORY ${APP_BIN_DIR})
endforeach()

########################################
# aead burst API tests
########################################

set(AEAD_BURST_API_ALGOS
  aes-ccm-128
  aes-ccm-256)

# aead smoke tests (aead burst API)
foreach(ALGO ${AEAD_BURST_API_ALGOS})
  add_test(NAME PERF::SMOKE::AEAD::AEAD_BURST_API::${ALGO}
    COMMAND ${PERF_APP} --smoke --aead-burst-api --aead-algo ${ALGO}
    WORKING_DIRECTORY ${APP_BIN_DIR})
endforeach()

########################################
# PQC smoke test
########################################

add_test(
  NAME PERF::PQC::SMOKE
  COMMAND ${PQC_PERF_APP} --seconds 0.05
  WORKING_DIRECTORY ${APP_BIN_DIR})
