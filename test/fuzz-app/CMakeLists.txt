# cmake-format: off
# Copyright (c) 2023-2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# Ensure building entire project
if(NOT FULL_PROJECT_BUILD)
  message(FATAL_ERROR "Please run CMake from project root directory")
endif()

# ##############################################################################
# set app and library names
# ##############################################################################
set(FUZZ_APP imb-fuzz-api)
set(DIRECT_FUZZ_APP imb-fuzz-direct-api)
set(PQC_FUZZ_APP imb-fuzz-pqc-api)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)
set(TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# ##############################################################################
# set source files
# ##############################################################################
set(FUZZ_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/job_api_fuzz_test.c)
set(DIRECT_FUZZ_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/direct_api_fuzz_test.c)
set(PQC_FUZZ_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/pqc_api_fuzz_test.c)

# ##############################################################################
# set toolchain options
# ##############################################################################
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/unix.cmake)

# Fuzzer and sanitizer instrumentation. Applied to the fuzz applications only,
# never to the library under test: it is linked in as built by the project, so
# that the applications fuzz the library as it is actually shipped. Build the
# library separately with sanitizers if deeper instrumentation is required.
set(FUZZ_INSTRUMENTATION -g -fsanitize=fuzzer,address,leak)

include_directories(${LIB_DIR} ${TEST_INCLUDE_DIR})

# ##############################################################################
# add targets
# ##############################################################################
add_executable(${FUZZ_APP} ${FUZZ_SOURCES})
target_link_libraries(${FUZZ_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${FUZZ_APP} PRIVATE ${APP_DEFINES})
target_compile_options(${FUZZ_APP} PRIVATE ${FUZZ_INSTRUMENTATION})
target_link_options(${FUZZ_APP} PRIVATE ${FUZZ_INSTRUMENTATION})

add_executable(${DIRECT_FUZZ_APP} ${DIRECT_FUZZ_SOURCES})
target_link_libraries(${DIRECT_FUZZ_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${DIRECT_FUZZ_APP} PRIVATE ${APP_DEFINES})
target_compile_options(${DIRECT_FUZZ_APP} PRIVATE ${FUZZ_INSTRUMENTATION})
target_link_options(${DIRECT_FUZZ_APP} PRIVATE ${FUZZ_INSTRUMENTATION})

add_executable(${PQC_FUZZ_APP} ${PQC_FUZZ_SOURCES})
target_link_libraries(${PQC_FUZZ_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${PQC_FUZZ_APP} PRIVATE ${APP_DEFINES})
target_compile_options(${PQC_FUZZ_APP} PRIVATE ${FUZZ_INSTRUMENTATION})
target_link_options(${PQC_FUZZ_APP} PRIVATE ${FUZZ_INSTRUMENTATION})
