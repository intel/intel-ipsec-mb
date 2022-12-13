cmake_minimum_required(VERSION 3.16)
project(intel-ipsec-mb)

# #################
# Test Applications
# #################

set(TEST_APP ipsec_MB_testapp)
set(XVALID_APP ipsec_xvalid_test)
set(IPSEC_MB_LIB IPSec_MB)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../lib)

# set up NASM compilation
enable_language(ASM_NASM)
if(NOT CMAKE_ASM_NASM_COMPILER_LOADED)
  message(FATAL_ERROR "Can't find assembler")
endif()
set(CAN_USE_ASSEMBLER TRUE)
set(CMAKE_ASM_NASM_FLAGS "-felf64 -Xgnu -gdwarf -DLINUX -D__linux__")

# set ipsec_MB_test source files
set(TEST_APP_SRC_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/gcm_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ctr_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/customop_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/des_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ccm_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/cmac_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/utils.c
	${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha1_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/hmac_sha256_sha512_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/hmac_md5_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/aes_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/sha_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/chained_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/api_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/pon_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/ecb_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/zuc_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/kasumi_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/snow3g_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/direct_api_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/clear_mem_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/hec_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/xcbc_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/aes_cbcs_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/crc_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/chacha_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/poly1305_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/chacha20_poly1305_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/null_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/snow_v_test.c
	${CMAKE_CURRENT_SOURCE_DIR}/direct_api_param_test.c
)

# set ipsec_xvalid_test source files
set(XVALID_APP_SRC_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/ipsec_xvalid.c
  ${CMAKE_CURRENT_SOURCE_DIR}/utils.c
  ${CMAKE_CURRENT_SOURCE_DIR}/misc.asm
)

# set flags for different OS's
set(CFLAGS "
  -MMD
  -W
  -Wall
  -Wextra 
  -Wmissing-declarations
  -Wpointer-arith
  -Wcast-qual -Wundef
  -Wwrite-strings
  -Wformat -Wformat-security
  -Wunreachable-code
  -Wmissing-noreturn
  -Wsign-compare
  -Wno-endif-labels
  -Wstrict-prototypes
  -Wmissing-prototypes
  -Wold-style-definition
  -fno-delete-null-pointer-checks
  -fwrapv"
)

# -fno-strict-overflow is not supported by clang
if(CMAKE_COMPILER_IS_GNUCC)
  list(APPEND CFLAGS "-fno-strict-overflow")
endif()

set(APP_DEFINES 
  -DLINUX
  -D_GNU_SOURCE
  -DNO_COMPAT_IMB_API_053
)

add_executable(${XVALID_APP} ${XVALID_APP_SRC_FILES})
target_link_libraries(${XVALID_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${XVALID_APP} PRIVATE ${APP_DEFINES})
target_include_directories(${XVALID_APP} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${LIB_DIR})

add_executable(${TEST_APP} ${TEST_APP_SRC_FILES})
target_link_libraries(${TEST_APP} PRIVATE ${IPSEC_MB_LIB})
target_compile_definitions(${TEST_APP} PRIVATE ${APP_DEFINES})
target_include_directories(${TEST_APP} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${LIB_DIR})

