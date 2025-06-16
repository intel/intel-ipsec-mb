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
  aes-cmac-bitlen
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
  sm3-hmac)

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
  sm4-gcm)

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

set(CIHPER_BURST_API_ALGOS
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
foreach(ALGO ${CIHPER_BURST_API_ALGOS})
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
  aes-cmac-bitlen
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
