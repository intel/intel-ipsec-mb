# cmake-format: off
# Copyright (c) 2026, Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
# cmake-format: on

# ##############################################################################
# Sanitizer support (AddressSanitizer, UndefinedBehaviorSanitizer, ...)
#
# Driven by the SANITIZERS cache variable, e.g.
#   cmake -DSANITIZERS="address;undefined" ..
#   cmake -DSANITIZERS=address -DSANITIZE_LIB=ON ..
#
# imb_setup_sanitizers() validates the request against the toolchain and sets:
#   IMB_SAN_ENABLED       - TRUE when instrumentation is to be applied
#   IMB_SAN_COMPILE_OPTS  - options for target_compile_options()
#   IMB_SAN_LINK_OPTS     - options for target_link_options()
#   IMB_SAN_TEST_ENV      - runtime environment for add_test() properties
#   IMB_SAN_RUNTIME_DIR   - directory holding the sanitizer runtime DLL
#                           (MSVC only, empty elsewhere)
#
# The options are applied per target (see test/kat-app), never globally, so
# that assembly sources and un-instrumented targets stay untouched.
# ##############################################################################

include(CheckCCompilerFlag)

# Check that a flag is accepted both when compiling and when linking. A
# compile-only probe is not sufficient: sanitizer flags also select a runtime
# library, which is frequently missing even though the compiler knows the flag
# (e.g. UBSan on FreeBSD without compiler-rt installed).
function(imb_san_check_flag FLAG OUT_VAR)
  string(MAKE_C_IDENTIFIER "IMB_SAN_HAVE_${FLAG}" CACHE_VAR)
  set(CMAKE_REQUIRED_LINK_OPTIONS ${FLAG})
  check_c_compiler_flag("${FLAG}" ${CACHE_VAR})
  set(${OUT_VAR}
      ${${CACHE_VAR}}
      PARENT_SCOPE)
endfunction()

# Append FLAG to the compile and link option lists if the toolchain supports it
macro(imb_san_try_flag FLAG)
  imb_san_check_flag("${FLAG}" _san_supported)
  if(_san_supported)
    list(APPEND IMB_SAN_COMPILE_OPTS "${FLAG}")
    list(APPEND IMB_SAN_LINK_OPTS "${FLAG}")
  else()
    message(STATUS "Sanitizers: '${FLAG}' not supported - skipped")
  endif()
endmacro()

macro(imb_setup_sanitizers)
  set(IMB_SAN_ENABLED FALSE)
  set(IMB_SAN_COMPILE_OPTS "")
  set(IMB_SAN_LINK_OPTS "")
  set(IMB_SAN_TEST_ENV "")
  set(IMB_SAN_RUNTIME_DIR "")

  if(SANITIZERS)
    # accept both "address;undefined" and "address,undefined"
    string(REPLACE "," ";" _san_list "${SANITIZERS}")
    string(TOLOWER "${_san_list}" _san_list)
    list(REMOVE_DUPLICATES _san_list)

    # ##########################################################################
    # validate the request
    # ##########################################################################
    set(_san_known address undefined thread memory leak)
    foreach(_san IN LISTS _san_list)
      if(NOT _san IN_LIST _san_known)
        message(
          FATAL_ERROR
            "SANITIZERS: unknown sanitizer '${_san}'. Supported: ${_san_known}")
      endif()
    endforeach()

    # address, thread and memory each replace the compiler runtime's memory
    # model, so at most one of them can be active in a single binary
    set(_san_exclusive "")
    foreach(_san address thread memory)
      if(_san IN_LIST _san_list)
        list(APPEND _san_exclusive ${_san})
      endif()
    endforeach()
    list(LENGTH _san_exclusive _san_exclusive_cnt)
    if(_san_exclusive_cnt GREATER 1)
      message(
        FATAL_ERROR
          "SANITIZERS: '${_san_exclusive}' are mutually exclusive - "
          "build separately with one of them at a time")
    endif()

    # LeakSanitizer is part of AddressSanitizer
    if(address IN_LIST _san_list AND leak IN_LIST _san_list)
      message(STATUS "Sanitizers: 'leak' is implied by 'address' - dropped")
      list(REMOVE_ITEM _san_list leak)
    endif()

    # ##########################################################################
    # translate to toolchain options
    # ##########################################################################
    if(MSVC)
      imb_san_setup_msvc()
    elseif(WINDOWS)
      # MinGW/Cygwin GCC ships no sanitizer runtime for Windows targets
      message(
        WARNING "Sanitizers are not supported by the MinGW toolchain - ignored")
    else()
      imb_san_setup_gnu()
    endif()
  endif()

  if(IMB_SAN_ENABLED)
    message(STATUS "Sanitizers enabled...      ${_san_list}")
    message(STATUS "SANITIZE_LIB...            ${SANITIZE_LIB}")
    message(STATUS "Sanitizer compile options... ${IMB_SAN_COMPILE_OPTS}")
    message(STATUS "Sanitizer link options...  ${IMB_SAN_LINK_OPTS}")
  elseif(SANITIZE_LIB)
    message(WARNING "SANITIZE_LIB has no effect without SANITIZERS")
  endif()
endmacro()

# ##############################################################################
# GCC / Clang (Linux, FreeBSD, other Unix)
# ##############################################################################
macro(imb_san_setup_gnu)
  # LeakSanitizer has no FreeBSD implementation
  if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" AND leak IN_LIST _san_list)
    message(
      WARNING "LeakSanitizer is not available on FreeBSD - 'leak' dropped")
    list(REMOVE_ITEM _san_list leak)
  endif()

  # MemorySanitizer only reports correctly when every instruction that writes
  # to memory is instrumented. This library is built around hand-written
  # NASM/GAS kernels (starting with mbcpuid at IMB_MGR allocation time) which
  # clang cannot instrument, so their outputs are always considered
  # uninitialised. The result is a guaranteed false positive before the first
  # test vector is processed, with or without SANITIZE_LIB.
  if(memory IN_LIST _san_list)
    # GCC has never implemented MemorySanitizer; without this the generic
    # probe failure below would suggest installing a runtime that
    # does not exist for this compiler.
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
      message(
        FATAL_ERROR
          "SANITIZERS: GCC does not implement MemorySanitizer. It is "
          "available with clang only, and even there it is not usable with "
          "this library because the hand-written assembly cannot be "
          "instrumented. Use 'address' and 'undefined', or "
          "CONSTANT_TIME_VALIDATION=ON for Valgrind based uninitialised "
          "memory checking.")
    endif()
    message(
      WARNING
        "MemorySanitizer is not usable with this library: the hand-written "
        "assembly cannot be instrumented, so its results are always reported "
        "as uninitialised. Expect false positives at start-up. Use "
        "'address' and 'undefined', or CONSTANT_TIME_VALIDATION=ON for "
        "Valgrind based uninitialised memory checking.")
  endif()

  # ThreadSanitizer cannot map its shadow memory when the kernel uses more
  # than 28 bits of mmap randomisation (the default on recent distributions),
  # and aborts with "unexpected memory mapping" at start-up. The sysctl is
  # often readable by root only, so warn unless it is known to be safe.
  if(thread IN_LIST _san_list AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(_mmap_rnd_bits "")
    if(EXISTS "/proc/sys/vm/mmap_rnd_bits")
      file(READ "/proc/sys/vm/mmap_rnd_bits" _mmap_rnd_bits)
      string(STRIP "${_mmap_rnd_bits}" _mmap_rnd_bits)
    endif()
    if(NOT _mmap_rnd_bits MATCHES "^[0-9]+$" OR _mmap_rnd_bits GREATER 28)
      message(
        WARNING
          "ThreadSanitizer aborts with 'unexpected memory mapping' when "
          "vm.mmap_rnd_bits is greater than 28 (current value: "
          "'${_mmap_rnd_bits}', unreadable when empty). Run the tests via "
          "'setarch -R ctest ...' or set 'sysctl -w vm.mmap_rnd_bits=28'.")
    endif()
  endif()

  if(_san_list)
    string(REPLACE ";" "," _san_arg "${_san_list}")
    imb_san_check_flag("-fsanitize=${_san_arg}" _san_supported)
    if(NOT _san_supported)
      message(
        FATAL_ERROR
          "SANITIZERS: the toolchain cannot compile and link "
          "'-fsanitize=${_san_arg}'. Install the matching runtime "
          "(e.g. libasan/libubsan or compiler-rt) or select a different set.")
    endif()

    set(IMB_SAN_ENABLED TRUE)
    set(IMB_SAN_COMPILE_OPTS -fsanitize=${_san_arg} -fno-omit-frame-pointer -g)
    set(IMB_SAN_LINK_OPTS -fsanitize=${_san_arg})

    # report the first error instead of continuing with poisoned state
    imb_san_try_flag(-fno-sanitize-recover=all)

    if(address IN_LIST _san_list)
      imb_san_try_flag(-fsanitize-address-use-after-scope)
    endif()

    if(undefined IN_LIST _san_list)
      # not part of the 'undefined' group
      imb_san_try_flag(-fsanitize=float-divide-by-zero)
      # local-bounds has no runtime handler, so it must trap
      imb_san_check_flag("-fsanitize=local-bounds" _san_supported)
      if(_san_supported)
        list(APPEND IMB_SAN_COMPILE_OPTS -fsanitize=local-bounds
             -fsanitize-trap=local-bounds)
        list(APPEND IMB_SAN_LINK_OPTS -fsanitize=local-bounds)
      endif()
    endif()

    imb_san_runtime_env()
  endif()
endmacro()

# ##############################################################################
# MSVC (Visual Studio / Ninja with cl.exe)
# ##############################################################################
macro(imb_san_setup_msvc)
  # MSVC only implements AddressSanitizer
  set(_san_unsupported ${_san_list})
  list(REMOVE_ITEM _san_unsupported address)
  if(_san_unsupported)
    message(
      WARNING
        "MSVC only supports the 'address' sanitizer - "
        "ignoring: ${_san_unsupported}")
    list(REMOVE_ITEM _san_list ${_san_unsupported})
  endif()

  if(address IN_LIST _san_list)
    imb_san_check_flag("/fsanitize=address" _san_supported)
    if(NOT _san_supported)
      message(
        FATAL_ERROR
          "SANITIZERS: /fsanitize=address is not supported by this compiler "
          "(requires Visual Studio 2019 16.9 or newer)")
    endif()

    set(IMB_SAN_ENABLED TRUE)
    # /Z7 keeps the debug info in the object files so that the ASan reports
    # are symbolized in every configuration, not only in Debug
    set(IMB_SAN_COMPILE_OPTS /fsanitize=address /Z7)
    # ASan is incompatible with incremental linking
    set(IMB_SAN_LINK_OPTS /INCREMENTAL:NO)

    # the ASan runtime DLL lives next to cl.exe and has to be on PATH when the
    # instrumented binaries run
    get_filename_component(_san_cl_dir "${CMAKE_C_COMPILER}" DIRECTORY)
    find_file(
      IMB_SAN_ASAN_DLL
      NAMES clang_rt.asan_dynamic-x86_64.dll
      HINTS "${_san_cl_dir}"
      NO_DEFAULT_PATH)
    if(IMB_SAN_ASAN_DLL)
      get_filename_component(IMB_SAN_RUNTIME_DIR "${IMB_SAN_ASAN_DLL}"
                             DIRECTORY)
    else()
      message(
        WARNING
          "AddressSanitizer runtime DLL not found next to the compiler - "
          "add its location to PATH manually before running the tests")
    endif()

    imb_san_runtime_env()
  endif()
endmacro()

# ##############################################################################
# runtime options passed to the instrumented tests
# ##############################################################################
macro(imb_san_runtime_env)
  # 'leak' has already been folded into 'address' at this point, so it can only
  # still be present when the standalone LeakSanitizer was requested. The
  # standalone runtime reads LSAN_OPTIONS, not ASAN_OPTIONS.
  if(address IN_LIST _san_list)
    set(_asan_opts "abort_on_error=1:detect_stack_use_after_return=1")
    if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR MSVC)
      # no LeakSanitizer on FreeBSD or Windows
      string(APPEND _asan_opts ":detect_leaks=0")
    elseif(SANITIZER_SUPPRESSIONS)
      list(APPEND IMB_SAN_TEST_ENV
           "LSAN_OPTIONS=suppressions=${SANITIZER_SUPPRESSIONS}")
    endif()
    list(APPEND IMB_SAN_TEST_ENV "ASAN_OPTIONS=${_asan_opts}")
  elseif(leak IN_LIST _san_list)
    set(_lsan_opts "exitcode=23")
    if(SANITIZER_SUPPRESSIONS)
      string(APPEND _lsan_opts ":suppressions=${SANITIZER_SUPPRESSIONS}")
    endif()
    list(APPEND IMB_SAN_TEST_ENV "LSAN_OPTIONS=${_lsan_opts}")
  endif()
  if(memory IN_LIST _san_list)
    list(APPEND IMB_SAN_TEST_ENV
         "MSAN_OPTIONS=abort_on_error=1:halt_on_error=1")
  endif()
  if(thread IN_LIST _san_list)
    list(APPEND IMB_SAN_TEST_ENV "TSAN_OPTIONS=halt_on_error=1")
  endif()
  if(undefined IN_LIST _san_list)
    list(APPEND IMB_SAN_TEST_ENV
         "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")
  endif()
endmacro()

# Apply the sanitizer instrumentation to TARGET. Restricted to C sources so
# that the NASM and GAS assembly of the library is left alone.
function(imb_target_add_sanitizers TARGET)
  if(NOT IMB_SAN_ENABLED)
    return()
  endif()
  # wrap each option individually: a list inside a single generator expression
  # would be split on the semicolons and corrupt the expression
  foreach(_opt IN LISTS IMB_SAN_COMPILE_OPTS)
    target_compile_options(${TARGET}
                           PRIVATE "$<$<COMPILE_LANGUAGE:C>:${_opt}>")
  endforeach()

  get_target_property(_target_type ${TARGET} TYPE)
  if(_target_type STREQUAL "STATIC_LIBRARY")
    # An archive has no link step of its own, so the options must reach every
    # executable that consumes it. Without this the instrumented objects pulled
    # out of the archive leave undefined __asan_*/__ubsan_* references in
    # applications that are not instrumented themselves (imb-perf, the
    # examples and the other test applications).
    target_link_options(${TARGET} INTERFACE ${IMB_SAN_LINK_OPTS})
  elseif(_target_type STREQUAL "SHARED_LIBRARY")
    # the shared library pulls in the runtime itself, but propagating the
    # options keeps the link order right for its consumers too
    target_link_options(${TARGET} PUBLIC ${IMB_SAN_LINK_OPTS})
  else()
    target_link_options(${TARGET} PRIVATE ${IMB_SAN_LINK_OPTS})
  endif()
endfunction()

# AddressSanitizer is incompatible with the MSVC run-time error checks and with
# whole-program optimization. Call this after the OS specific flag setup of a
# directory, so that the flags it sets are cleaned up as well.
macro(imb_san_strip_incompatible_flags)
  if(IMB_SAN_ENABLED AND MSVC)
    foreach(_flags_var CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
                       CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_MINSIZEREL)
      string(REGEX REPLACE "/RTC[1csu]+" "" ${_flags_var} "${${_flags_var}}")
      string(REGEX REPLACE "/GL([ \t]|$)" "\\1" ${_flags_var}
                           "${${_flags_var}}")
    endforeach()
  endif()
endmacro()
