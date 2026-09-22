# cmake-format: off
# Copyright (c) 2025-2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

cmake_minimum_required(VERSION 3.10)

project(imb_provider_test C)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the test executable
add_executable(load_imb-provider load_imb-provider.c)

target_include_directories(load_imb-provider PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(load_imb-provider PRIVATE OpenSSL::Crypto)
