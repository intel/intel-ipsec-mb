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

set(DEFAULT_JOB_SIZES 16:16:128 128:128:2048)
set(EXTENDED_JOB_SIZES 1:4:1024 2:4:1024 3:4:1024 4:4:1024)

# ##############################################################################
# quick sweep of all combinations
# ##############################################################################

add_test(
    NAME XVALID::64B-SWEEP
    COMMAND ${XVALID_APP} --job-size 64
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})

# ##############################################################################
# cipher tests
# ##############################################################################

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
    docsis-sec-128
    docsis-sec-256
    docsis-des-64
    des-cbc-64
    3des-cbc-192
    zuc-eea3
    snow3g-uea2
    kasumi-f8
    chacha20-256
    sm4-ecb-128
    sm4-cbc-128
    sm4-ctr-128
    null-cipher
    aes-cfb-128
    aes-cfb-192
    aes-cfb-256)

# cipher short tests
foreach(ALGO ${CIPHER_ALGOS})
  foreach(JOB_SIZE ${DEFAULT_JOB_SIZES})
    add_test(
      NAME XVALID::CIPHER::${ALGO}::${JOB_SIZE}
      COMMAND ${XVALID_APP} --job-size ${JOB_SIZE} --cipher-algo ${ALGO}
      WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
  endforeach()
endforeach()

# cipher extended tests
foreach(ALGO ${CIPHER_ALGOS})
  foreach(JOB_SIZE ${EXTENDED_JOB_SIZES})
    add_test(
      NAME XVALID::EXT::CIPHER::${ALGO}::${JOB_SIZE}
      COMMAND ${XVALID_APP} --job-size ${JOB_SIZE} --cipher-algo ${ALGO}
      WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
  endforeach()
endforeach()

# ##############################################################################
# hash tests
# ##############################################################################

set(HASH_ALGOS
    hmac-sha1
    hmac-sha224
    hmac-sha256
    hmac-sha384
    hmac-sha512
    aes-xcbc-128
    hmac-md5
    aes-cmac-128
    null-hash
    aes-cmac-128-bit-length
    sha1
    sha224
    sha256
    sha384
    sha512
    zuc-eia3
    snow3g-uia2
    kasumi-f9
    aes-gmac-128
    aes-gmac-192
    aes-gmac-256
    aes-cmac-256
    poly1305
    ghash
    eth-crc32
    sctp-crc32
    wimax-ofdma-crc32
    lte-a-crc24
    lte-b-crc24
    x25-crc16
    fp-crc16
    fp-crc11
    iuup-crc10
    wimax-ofdma-crc8
    fp-crc7
    iuup-crc6
    sm3
    hmac-sm3
    sha3-224
    sha3-256
    sha3-384
    sha3-512
    shake-128
    shake-256)

# hash short tests
foreach(ALGO ${HASH_ALGOS})
  foreach(JOB_SIZE ${DEFAULT_JOB_SIZES})
    add_test(
      NAME XVALID::HASH::${ALGO}::${JOB_SIZE}
      COMMAND ${XVALID_APP} --job-size ${JOB_SIZE} --hash-algo ${ALGO}
      WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
  endforeach()
endforeach()

# hash extended tests
foreach(ALGO ${HASH_ALGOS})
  foreach(JOB_SIZE ${EXTENDED_JOB_SIZES})
    add_test(
      NAME XVALID::EXT::HASH::${ALGO}::${JOB_SIZE}
      COMMAND ${XVALID_APP} --job-size ${JOB_SIZE} --hash-algo ${ALGO}
      WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
  endforeach()
endforeach()

# ##############################################################################
# aead tests
# ##############################################################################

set(AEAD_ALGOS
    aes-gcm-128
    aes-gcm-192
    aes-gcm-256
    aes-ccm-128
    aes-ccm-256
    docsis-sec-128-crc32
    pon-128-bip-crc32
    pon-128-no-ctr
    aead-chacha20-256-poly1305
    sm4-gcm)

# aead short tests
foreach(ALGO ${AEAD_ALGOS})
  foreach(JOB_SIZE ${DEFAULT_JOB_SIZES})
    add_test(
      NAME XVALID::AEAD::${ALGO}::${JOB_SIZE}
      COMMAND ${XVALID_APP} --job-size ${JOB_SIZE} --aead-algo ${ALGO}
      WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
  endforeach()
endforeach()

# aead extended tests
foreach(ALGO ${AEAD_ALGOS})
  foreach(JOB_SIZE ${EXTENDED_JOB_SIZES})
    add_test(
      NAME XVALID::EXT::AEAD::${ALGO}::${JOB_SIZE}
      COMMAND ${XVALID_APP} --job-size ${JOB_SIZE} --aead-algo ${ALGO}
      WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
  endforeach()
endforeach()

# ##############################################################################
# other tests
# ##############################################################################

# run safe check only when SAFE_DATA is enabled and only run on release build
if(SAFE_DATA)
  add_test(
    NAME XVALID::SAFE_CHECK
    COMMAND ${XVALID_APP} --safe-check --job-size 64
    CONFIGURATIONS Release
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})

  add_test(
    NAME XVALID::EXT::SAFE_CHECK
    COMMAND ${XVALID_APP} --safe-check --job-size 16:16:512
    CONFIGURATIONS Release
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
endif()
