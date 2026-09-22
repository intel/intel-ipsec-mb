# cmake-format: off
# Copyright (c) 2023-2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# Ensure building entire project
if(NOT FULL_PROJECT_BUILD)
  message(FATAL_ERROR "Please run CMake from project root directory")
endif()

# build imb-burst application
add_subdirectory(burst-app)

# build imb-single-buff application
add_subdirectory(sb-app)