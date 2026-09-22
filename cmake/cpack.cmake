# cmake-format: off
# Copyright (c) 2025-2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# ##############################################################################
# CPack configuration for intel-ipsec-mb
# ##############################################################################

# Common package settings
set(CPACK_PACKAGE_NAME "intel-ipsec-mb")
set(CPACK_PACKAGE_VENDOR "Intel Corporation")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Intel(R) Multi-Buffer Crypto for IPsec Library")
set(CPACK_PACKAGE_DESCRIPTION
    "Intel(R) Multi-Buffer Crypto for IPsec Library is highly-optimized \
software implementations of the core cryptographic processing for IPsec, \
which provides industry-leading performance on a range of Intel(R) Processors.")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/intel/intel-ipsec-mb")
set(CPACK_PACKAGE_VERSION ${IPSEC_MB_VERSION_FULL})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_PACKAGE_CONTACT "Marcel Cornu <marcel.d.cornu@intel.com>")
set(CPACK_STRIP_FILES ON)
set(CPACK_PACKAGE_RELOCATABLE ON)

# Set package file name
set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}"
)

# ##############################################################################
# Linux-specific CPack configuration (DEB and RPM)
# ##############################################################################
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # DEB package configuration
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER ${CPACK_PACKAGE_CONTACT})
  set(CPACK_DEBIAN_PACKAGE_SECTION "libs")
  set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.14)")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
  set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "${CPACK_PACKAGE_HOMEPAGE_URL}")
  set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

  # RPM package configuration
  set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause AND Apache-2.0")
  set(CPACK_RPM_PACKAGE_GROUP "Development/Libraries")
  set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.14")
  set(CPACK_RPM_PACKAGE_ARCHITECTURE "x86_64")
  set(CPACK_RPM_PACKAGE_URL "${CPACK_PACKAGE_HOMEPAGE_URL}")
  set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
  # Disable debuginfo package
  set(CPACK_RPM_DEBUGINFO_PACKAGE OFF)
  set(CPACK_RPM_PACKAGE_DEBUG OFF)

  # Set generators for Linux
  set(CPACK_GENERATOR "DEB;RPM")
endif()

# Include CPack module (must be after all CPACK_* variables are set)
include(CPack)
