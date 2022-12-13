cmake_minimum_required(VERSION 3.16)
project(intel-ipsec-mb VERSION 1.3.0 DESCRIPTION "Intel(R) IPSec Multi-Buffer library")

# Check compiler version
if(("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU") AND
    (CMAKE_C_COMPILER_VERSION VERSION_LESS 5.0))
    message(FATAL_ERROR "GNU C Compiler version must be 5.0 or higher")
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "")
  message(STATUS "CMAKE_BUILD_TYPE not set, defaulting to Release")
  set(CMAKE_BUILD_TYPE "Release")
endif()

add_subdirectory(lib)

