# cmake-format: off
# Copyright (c) 2023-2024, Intel Corporation
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

include(CheckCCompilerFlag)
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.18")
  include(CheckLinkerFlag)
endif()

# extract library version from header file
macro(imb_get_version IMB_HDR_FILE)
  file(STRINGS ${IMB_HDR_FILE} VER_STR REGEX "^.*IMB_VERSION_STR.*$")
  string(REGEX MATCH "[0-9]+.[0-9]+.[0-9]+(-[a-z]+)?" IPSEC_MB_VERSION_FULL
               ${VER_STR})
  string(REGEX MATCH "[0-9]+.[0-9]+.[0-9]+" IPSEC_MB_VERSION
               ${IPSEC_MB_VERSION_FULL})
endmacro()

macro(imb_detect_os)
  message(STATUS "OPERATING SYSTEM...        ${CMAKE_HOST_SYSTEM_NAME}")
  if(CMAKE_HOST_UNIX)
    if(CMAKE_HOST_SYSTEM_NAME STREQUAL "FreeBSD")
      set(FREEBSD 1)
    else()
      set(LINUX 1)
    endif()
  else()
    set(WINDOWS 1)
  endif()
endmacro()

# set default project settings
macro(imb_set_proj_defaults)
  # flag to force full project build
  set(FULL_PROJECT_BUILD TRUE)

  # set default build type if not specified and not a multi-config generator
  get_property(multi_config_gen GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
  if(NOT CMAKE_BUILD_TYPE
     AND NOT CMAKE_CONFIGURATION_TYPES
     AND NOT multi_config_gen)
    set(CMAKE_BUILD_TYPE
        "Release"
        CACHE STRING "Selected build type")
  endif()

  # ############################################################################
  # set default library options
  # ############################################################################
  option(SAFE_PARAM "API input parameter checking" ON)
  option(SAFE_DATA
         "Sensitive data cleared from registers and memory at operation end" ON)
  option(SAFE_LOOKUP "Lookups depending on sensitive data are constant time" ON)
  option(SAFE_OPTIONS "Enable all safe options" ON)
  option(BUILD_SHARED_LIBS "Build shared library" ON)
  option(CMAKE_VERBOSE_MAKEFILE "Verbose build output" OFF)
  option(BUILD_LIBRARY_ONLY "Build library only without applications" OFF)
  set(EXTRA_CFLAGS
      ""
      CACHE STRING "Extra compiler flags")

  # disable all SAFE options when SAFE_OPTIONS false
  if(NOT SAFE_OPTIONS)
    message(STATUS "SAFE_OPTIONS disabled")
    set(SAFE_PARAM OFF)
    set(SAFE_DATA OFF)
    set(SAFE_LOOKUP OFF)
  endif()

  # project options list (used by print_help target)
  set(IPSEC_MB_OPTIONS
      CMAKE_BUILD_TYPE
      IPSEC_MB_OPTIONS
      SAFE_PARAM
      SAFE_DATA
      SAFE_LOOKUP
      SAFE_OPTIONS
      BUILD_LIBRARY_ONLY
      BUILD_SHARED_LIBS
      CMAKE_VERBOSE_MAKEFILE
      EXTRA_CFLAGS)

  # clear default release build C Compiler Flags
  set(CMAKE_C_FLAGS_RELEASE
      ""
      CACHE STRING "" FORCE)
  # clear default debug build C Compiler Flags
  set(CMAKE_C_FLAGS_DEBUG
      ""
      CACHE STRING "" FORCE)

  if(WIN32)
    set(DEFAULT_INSTALL_PREFIX "C:/Program Files/intel-ipsec-mb")
    set(CMAKE_INSTALL_PREFIX
        ${DEFAULT_INSTALL_PREFIX}
        CACHE STRING "Set default installation directory")
  endif()

  # ############################################################################
  # print build information
  # ############################################################################
  message(STATUS "SAFE_OPTIONS...            ${SAFE_OPTIONS}")
  message(STATUS "SAFE_PARAM...              ${SAFE_PARAM}")
  message(STATUS "SAFE_DATA...               ${SAFE_DATA}")
  message(STATUS "SAFE_LOOKUP...             ${SAFE_LOOKUP}")
  message(STATUS "BUILD_LIBRARY_ONLY...      ${BUILD_LIBRARY_ONLY}")
  message(STATUS "BUILD_SHARED_LIBS...       ${BUILD_SHARED_LIBS}")
  message(STATUS "CMAKE_GENERATOR...         ${CMAKE_GENERATOR}")
  if(${CMAKE_GENERATOR_PLATFORM})
    message(STATUS "GENERATOR PLATFORM...      ${CMAKE_GENERATOR_PLATFORM}")
  endif()
  if(NOT multi_config_gen)
    message(STATUS "BUILD_TYPE...              ${CMAKE_BUILD_TYPE}")
    message(STATUS "CMAKE_VERBOSE_MAKEFILE...  ${CMAKE_VERBOSE_MAKEFILE}")
  endif()
  if(EXTRA_CFLAGS)
    message(STATUS "EXTRA_CFLAGS...            ${EXTRA_CFLAGS}")
  endif()

endmacro()

# set binary output directory if specified
macro(imb_set_binary_dir)
  # place all binaries in ${IMB_BIN_DIR}
  if(IMB_BIN_DIR)
    message(STATUS "BINARY DIRECTORY...        ${IMB_BIN_DIR}")
    get_property(multi_config_gen GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${IMB_BIN_DIR})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${IMB_BIN_DIR})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${IMB_BIN_DIR})
  endif()
endmacro()

# compiler checks
macro(imb_compiler_check)
  if((${CMAKE_C_COMPILER_ID} STREQUAL "GNU") AND (CMAKE_C_COMPILER_VERSION
                                                  VERSION_LESS 5.0))
    message(FATAL_ERROR "GNU C Compiler version must be 5.0 or higher")
  endif()

  # enable CET if supported by both compiler and linker
  check_c_compiler_flag("-fcf-protection=full" CC_CET_CHECK)

  if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.18")
    check_linker_flag("C" "-z ibt" LD_IBT_CHECK)
    if(CC_CET_CHECK AND LD_IBT_CHECK)
      set(CET_SUPPORT YES)
    else()
      set(CET_SUPPORT NO)
    endif()
    message(STATUS "CET SUPPORT...             ${CET_SUPPORT}")
  endif()
endmacro()

# add uninstall target
macro(imb_add_target_uninstall UNINSTALL_ROUTINE)
  configure_file(
    ${UNINSTALL_ROUTINE} "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(
    uninstall COMMAND ${CMAKE_COMMAND} -P
                      ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endmacro()

# add print_help target
macro(imb_add_target_print_help OPTIONS)
  add_custom_target(
    print_help
    COMMAND ${CMAKE_COMMAND} -E echo "Available build options:"
    VERBATIM)

  foreach(OPTION ${OPTIONS})
    get_property(
      HELP_TEXT
      CACHE ${OPTION}
      PROPERTY HELPSTRING)
    if(HELP_TEXT)
      add_custom_command(
        TARGET print_help
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "    ${OPTION}=${${OPTION}} - ${HELP_TEXT}")
    endif()
  endforeach()
endmacro()

# style check using clang & cmake format
macro(imb_add_target_style_checks)
  include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/clang-format.cmake")
  include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake-format.cmake")
endmacro()

# add TAGS target
macro(imb_add_target_tags)
  if(NOT WINDOWS)
    add_custom_target(
      TAGS
      COMMAND ${CMAKE_COMMAND} -E echo "Building Tags table"
      COMMAND bash -c "find . -name *.[ch] -print | etags -"
      COMMAND bash -c "find ./ -name '*.asm'  | etags -a -"
      COMMAND bash -c "find ./ -name '*.inc'  | etags -a -"
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      VERBATIM)
  endif()
endmacro()

# add cppcheck targets
macro(imb_add_target_cppcheck_bughunt)
  if(NOT WINDOWS)
    # set cppcheck binary name
    if(NOT CPPCHECK_BIN)
      set(CPPCHECK_BIN cppcheck)
    endif()

    find_program(CPPCHECK NAMES ${CPPCHECK_BIN})

    # add targets if cppcheck available
    if(CPPCHECK)
      # output compilation database
      set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
      execute_process(
        COMMAND bash -c "getconf _NPROCESSORS_ONLN"
        OUTPUT_VARIABLE nprocs
        OUTPUT_STRIP_TRAILING_WHITESPACE)

      # set flags
      set(CPPCHECK_FLAGS "-j ${nprocs}")
      set(CPPCHECK_FLAGS1 "--cppcheck-build-dir=.cppcheck ${CPPCHECK_FLAGS}")
      set(CPPCHECK_FLAGS2 "--cppcheck-build-dir=.bughunt ${CPPCHECK_FLAGS}")

      # add cppcheck target
      add_custom_target(
        cppcheck
        COMMAND ${CMAKE_COMMAND} -E echo "Running cppcheck:"
        COMMAND bash -c "mkdir -p .cppcheck"
        COMMAND
          bash -c
          "${CPPCHECK} --force --enable=all ${CPPCHECK_FLAGS1} --project=./compile_commands.json"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        VERBATIM)

      # add bughunt target
      add_custom_target(
        bughunt
        COMMAND ${CMAKE_COMMAND} -E echo "Running cppcheck bughunt:"
        COMMAND bash -c "mkdir -p .bughunt"
        COMMAND
          bash -c
          "${CPPCHECK} --bug-hunting --inconclusive ${CPPCHECK_FLAGS2} --project=./compile_commands.json"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        VERBATIM)
    endif(CPPCHECK)
  endif(NOT WINDOWS)
endmacro()

# add spellcheck target
#
# Check spelling in the code with codespell. See
# https://github.com/codespell-project/codespell for more details. Codespell
# options explained: -d        -- disable colours (emacs colours it anyway) -L
# -- List of words to be ignored -S <skip> -- skip file types -I FILE   -- File
# containing words to be ignored
macro(imb_add_target_spellcheck)
  # set cppcheck binary name
  if(NOT CODESPELL_BIN)
    set(CODESPELL_BIN codespell)
  endif()

  find_program(CODESPELL NAMES ${CODESPELL_BIN})

  # ignore some needed words
  set(CS_IGNORE_WORDS "iinclude,struc,fo,ue,od,ba,padd")

  if(CODESPELL)
    add_custom_target(
      spellcheck
      COMMAND ${CMAKE_COMMAND} -E echo "Running spellcheck:"
      COMMAND
        bash -c "${CODESPELL} -d -L ${CS_IGNORE_WORDS} \
	      -S '*.obj,*.o,*.a,*.so,*.lib,*~,*.so,*.so.*,*.d,imb-perf' \
	      -S 'imb-kat,imb-xvalid' \
	      ./lib ./perf ./test README.md SECURITY.md CONTRIBUTING \
	      Makefile win_x64.mak ReleaseNotes.txt LICENSE ${CS_EXTRA_OPTS}"
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      VERBATIM)
  endif()
endmacro()

# add doxy target
macro(imb_add_target_doxy)
  if(NOT WINDOWS)
    add_custom_target(
      doxy
      COMMAND ${CMAKE_COMMAND} -E echo "Generating documentation..."
      COMMAND bash -c "doxygen api_doxygen.conf"
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib
      VERBATIM)
  endif()
endmacro()
