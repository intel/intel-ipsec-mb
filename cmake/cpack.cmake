# cmake-format: off
# Copyright (c) 2025, Intel Corporation
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
  set(CPACK_RPM_PACKAGE_LICENSE "BSD")
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
