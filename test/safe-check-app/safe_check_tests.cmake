# cmake-format: off
# Copyright (c) 2026, Intel Corporation
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

# safe check requires SAFE_DATA enabled library and is only run on release build
if(SAFE_DATA)
  add_test(
    NAME SAFE_CHECK::64B
    COMMAND ${SAFE_CHECK_APP} --job-size 64 --num-jobs 1
    CONFIGURATIONS Release
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})

  add_test(
    NAME SAFE_CHECK::64B::BURST
    COMMAND ${SAFE_CHECK_APP} --job-size 64 --num-jobs 16 --burst-api
    CONFIGURATIONS Release
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})

  add_test(
    NAME SAFE_CHECK::EXT::SWEEP
    COMMAND ${SAFE_CHECK_APP} --job-size 16:16:512
    CONFIGURATIONS Release
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})

  add_test(
    NAME SAFE_CHECK::EXT::SWEEP::BURST
    COMMAND ${SAFE_CHECK_APP} --job-size 16:16:512 --burst-api
    CONFIGURATIONS Release
    WORKING_DIRECTORY ${TEST_APP_BIN_DIR})
endif()
