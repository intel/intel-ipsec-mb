# cmake-format: off
# Copyright (c) 2022-2024, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# Ensure building entire project
if(NOT FULL_PROJECT_BUILD)
  message(FATAL_ERROR "Please run CMake from project root directory")
endif()

# build imb-kat application
add_subdirectory(kat-app)

# build imb-xvalid application
add_subdirectory(xvalid-app)

# build imb-mp application
add_subdirectory(mp-app)

# build imb-zerolen application
add_subdirectory(zerolen-app)

# build imb-oob application
add_subdirectory(oob-app)

if(NOT WINDOWS)
  # build imb-acvp if libacvp available
  if(NOT ACVP_LOC)
    set(ACVP_LOC "/usr/local/acvp")
  endif()
  set(ACVP_INCLUDE_DIR "${ACVP_LOC}/include")

  # find libacvp
  find_library(
    ACVP_LIB libacvp.a libacvp
    PATHS ${ACVP_LOC}
    PATH_SUFFIXES lib)

  # add imb-acvp app if found
  if(ACVP_LIB)
    message(STATUS "ACVP_LIB...                ${ACVP_LIB}")
    add_subdirectory(acvp-app)
  endif()

  # add fuzz apps if using clang
  if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_subdirectory(fuzz-app)
  endif()
endif()
