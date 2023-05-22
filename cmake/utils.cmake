# Copyright (c) 2023, Intel Corporation
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

# extract library version from header file
macro(imb_get_version IMB_HDR_FILE)
  file(STRINGS ${IMB_HDR_FILE} VER_STR REGEX "^.*IMB_VERSION_STR.*$")
  string(REGEX MATCH "[0-9]+.[0-9]+.[0-9]+(-[a-z]+)?" IPSEC_MB_VERSION_FULL ${VER_STR})
  string(REGEX MATCH "[0-9]+.[0-9]+.[0-9]+" IPSEC_MB_VERSION ${IPSEC_MB_VERSION_FULL})
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
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Selected build type")
  # clear default release build C Compiler Flags
  set(CMAKE_C_FLAGS_RELEASE "" CACHE STRING "" FORCE)
  # clear default debug build C Compiler Flags
  set(CMAKE_C_FLAGS_DEBUG "" CACHE STRING "" FORCE)

  # project options list (used by print_help target)
  set(IPSEC_MB_OPTIONS CMAKE_BUILD_TYPE)

  # flag to force full project build
  set(FULL_PROJECT_BUILD TRUE)

  # place all binaries in a single bin directory
  if(USE_BIN_DIR)
    set(BIN_DIR "${PROJECT_BINARY_DIR}/bin")
    message(STATUS "BINARY DIRECTORY...        ${BIN_DIR}")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${BIN_DIR})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BIN_DIR})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})
  endif()
endmacro()

# compiler checks
macro(imb_compiler_check)
  if((${CMAKE_C_COMPILER_ID} STREQUAL "GNU") AND
    (CMAKE_C_COMPILER_VERSION VERSION_LESS 5.0))
    message(FATAL_ERROR "GNU C Compiler version must be 5.0 or higher")
  endif()
endmacro()

# add uninstall target
macro(imb_add_target_uninstall UNINSTALL_ROUTINE)
  configure_file(${UNINSTALL_ROUTINE}
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endmacro()

# add print_help target
macro(imb_add_target_print_help OPTIONS)
  add_custom_target(
    print_help
    COMMAND ${CMAKE_COMMAND} -E echo "Available build options:"
    VERBATIM
    )

  foreach (OPTION ${OPTIONS})
    get_property(HELP_TEXT CACHE ${OPTION} PROPERTY HELPSTRING)
    if(HELP_TEXT)
      add_custom_command(TARGET print_help
        COMMAND
        ${CMAKE_COMMAND} -E echo "    ${OPTION}=${${OPTION}} - ${HELP_TEXT}"
        )
    endif()
  endforeach()
endmacro()

# style check using clang format
macro(imb_add_target_style_check)
  include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/clang-format.cmake")
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
      VERBATIM
      )
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
