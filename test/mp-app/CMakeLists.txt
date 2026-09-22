# cmake-format: off
# Copyright (c) 2024-2026, Intel Corporation
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
set(MP_APP_PRI imb-mp-primary)
set(MP_APP_SEC imb-mp-secondary)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lib)
set(TEST_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

# ##############################################################################
# set imb-mp-primary source files
# ##############################################################################
set(MP_APP_PRI_SRC_FILES_C
    ${CMAKE_CURRENT_SOURCE_DIR}/imb-mp-primary.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mp_shared_mem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mp_imb.c ${CMAKE_CURRENT_SOURCE_DIR}/mp_alloc.c)

# ##############################################################################
# set imb-mp-secondary source files
# ##############################################################################
set(MP_APP_SEC_SRC_FILES_C
    ${CMAKE_CURRENT_SOURCE_DIR}/imb-mp-secondary.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mp_shared_mem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mp_imb.c ${CMAKE_CURRENT_SOURCE_DIR}/mp_alloc.c)

# ##############################################################################
# set C compiler and NASM options
# ##############################################################################
# add OS specific options
if(WINDOWS)
  if(CMAKE_GENERATOR MATCHES "MinGW Makefiles")
    include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/windows-mingw.cmake)
  else()
    include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/windows.cmake)
  endif()
else()
  include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/unix.cmake)
endif()

# ##############################################################################
# add targets
# ##############################################################################
include_directories(${LIB_DIR} ${TEST_INCLUDE_DIR})
link_directories(${LIB_DIR})

add_executable(${MP_APP_PRI} ${MP_APP_PRI_SRC_FILES_C})
if(LINUX)
  target_link_libraries(${MP_APP_PRI} PRIVATE ${IPSEC_MB_LIB} rt)
else()
  target_link_libraries(${MP_APP_PRI} PRIVATE ${IPSEC_MB_LIB})
endif()
target_compile_definitions(${MP_APP_PRI} PRIVATE ${APP_DEFINES})

add_executable(${MP_APP_SEC} ${MP_APP_SEC_SRC_FILES_C})
if(LINUX)
  target_link_libraries(${MP_APP_SEC} PRIVATE ${IPSEC_MB_LIB} rt)
else()
  target_link_libraries(${MP_APP_SEC} PRIVATE ${IPSEC_MB_LIB})
endif()
target_compile_definitions(${MP_APP_SEC} PRIVATE ${APP_DEFINES})

# ##############################################################################
# add tests
# ##############################################################################

# set working directory for tests
if(IMB_BIN_DIR)
  set(APP_BIN_DIR "${IMB_BIN_DIR}")
else()
  set(APP_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}")
endif()

# append config type for multi-config generators
get_property(multi_config_gen GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(multi_config_gen)
  string(APPEND APP_BIN_DIR "/$<IF:$<CONFIG:Debug>,Debug,Release>")
endif()

add_test(
  NAME MULTIPROCESS::DEFAULT
  COMMAND ${MP_APP_PRI} ${APP_BIN_DIR}/${MP_APP_SEC}
  WORKING_DIRECTORY ${APP_BIN_DIR})
