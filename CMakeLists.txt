cmake_minimum_required(VERSION 3.22)
project(cryptographyI LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_testing()

# ============================================
# Crypto Library
# ============================================
add_library(crypto
    crypto/des.c
    crypto/aes.c
    crypto/aes_cbc.c
    crypto/aes_ctr.c
    crypto/sha.c
    crypto/hmac.c
)

target_include_directories(crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
)

# ============================================
# Utils Library
# ============================================
add_library(utils
    utils/utils.c
)
target_include_directories(utils PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

# ============================================
# Bignum Library
# ============================================
add_library(bignum
    bignum/bignum.c
)
target_include_directories(bignum PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/bignum
)
target_link_libraries(bignum PUBLIC m)

# ============================================
# FIPS Test Infrastructure
# ============================================
# Find Python
find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)

# Macro to add FIPS tests for a category
# Usage: add_fips_tests(test_executable cavp prefix)
# Example: add_fips_tests(test_aes_ecb "aes/fips_kat" "ECB")
macro(add_fips_tests TEST_EXECUTABLE CAVP_DIR PREFIX)
    # Find all .rsp files matching the prefix
    file(GLOB RSP_FILES "${CMAKE_SOURCE_DIR}/tests/${CAVP_DIR}/${PREFIX}*.rsp")
    
    if(RSP_FILES)
        message(STATUS "Found ${CAVP_DIR}/${PREFIX} test vectors:")
        foreach(RSP_FILE ${RSP_FILES})
            get_filename_component(TEST_NAME ${RSP_FILE} NAME_WE)
            message(STATUS "  - ${TEST_NAME}")
            
            # Register test with CTest
            add_test(
                NAME FIPS_${TEST_NAME}
                COMMAND ${Python3_EXECUTABLE} 
                        ${CMAKE_SOURCE_DIR}/tests/run_fips_tests.py
                        $<TARGET_FILE:${TEST_EXECUTABLE}>
                        ${RSP_FILE}
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            )
        endforeach()
    else()
        message(WARNING "No ${PREFIX} test vectors found in {CAVP_DIR}")
    endif()
endmacro()

# ============================================
# FIPS Test Declaration
# ============================================
add_executable(test_des_ecb     tests/des/test_des_ecb.c)
add_executable(test_aes_ecb     tests/aes/test_aes_ecb.c)
add_executable(test_aes_ecb_mct tests/aes/test_aes_ecb_mct.c)
add_executable(test_aes_cbc     tests/aes/test_aes_cbc.c)
add_executable(test_aes_cbc_mct tests/aes/test_aes_cbc_mct.c)
add_executable(test_aes_ctr     tests/aes/test_aes_ctr.c)
add_executable(test_sha         tests/sha/test_sha.c)
add_executable(test_sha_mct     tests/sha/test_sha_mct.c)
add_executable(test_hmac        tests/hmac/test_hmac.c)

target_link_libraries(test_des_ecb      PRIVATE crypto utils)
target_link_libraries(test_aes_ecb      PRIVATE crypto utils)
target_link_libraries(test_aes_ecb_mct  PRIVATE crypto utils)
target_link_libraries(test_aes_cbc      PRIVATE crypto utils)
target_link_libraries(test_aes_cbc_mct  PRIVATE crypto utils)
target_link_libraries(test_aes_ctr      PRIVATE crypto utils)
target_link_libraries(test_sha          PRIVATE crypto utils)
target_link_libraries(test_sha_mct      PRIVATE crypto utils)
target_link_libraries(test_hmac         PRIVATE crypto utils)

add_fips_tests(test_des_ecb     "des/fips_kat" "TECB")
add_fips_tests(test_aes_ecb     "aes/fips_kat" "ECB")
add_fips_tests(test_aes_ecb_mct "aes/fips_mct" "ECB")
add_fips_tests(test_aes_cbc     "aes/fips_kat" "CBC")
add_fips_tests(test_aes_cbc_mct "aes/fips_mct" "CBC")
add_fips_tests(test_aes_ctr     "aes/fips_kat" "CTR")
add_fips_tests(test_sha         "sha/fips_kat" "SHA")
add_fips_tests(test_sha_mct     "sha/fips_mct" "SHA")
add_fips_tests(test_hmac        "hmac"         "HMAC")

# ============================================
# GMP dependency (for bignum differential testing)
# ============================================
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(GMP QUIET gmp)
endif()
if(NOT GMP_FOUND)
    find_path(GMP_INCLUDE_DIR gmp.h)
    find_library(GMP_LIBRARIES gmp)
    if(GMP_INCLUDE_DIR AND GMP_LIBRARIES)
        set(GMP_FOUND TRUE)
        set(GMP_INCLUDE_DIRS ${GMP_INCLUDE_DIR})
    endif()
endif()
if(NOT GMP_FOUND)
    message(FATAL_ERROR "libgmp-dev (or equivalent) not found; required for bignum differential tests")
endif()

# ============================================
# Bignum Differential + Property Test Declaration
# ============================================
add_executable(test_bignum
    tests/bignum/test_bignum.c
    tests/bignum/bn_test_gmp_bridge.c
    tests/bignum/bn_test_report.c
)
target_include_directories(test_bignum PRIVATE ${GMP_INCLUDE_DIRS})
target_link_libraries(test_bignum PRIVATE bignum ${GMP_LIBRARIES})

set(BIGNUM_SEED 0 CACHE STRING "Fixed seed for bignum test reproducibility (0 = time-based)")
set(BIGNUM_ITERATIONS 1000 CACHE STRING "Random iterations per bignum operation test")

add_test(NAME BIGNUM_bridge
    COMMAND test_bignum bridge --seed ${BIGNUM_SEED})

# Fully/partially implemented today: real signal expected.
foreach(OP init reset tostring)
    add_test(NAME BIGNUM_${OP}
        COMMAND test_bignum ${OP} --seed ${BIGNUM_SEED} --iterations ${BIGNUM_ITERATIONS})
endforeach()

add_test(NAME BIGNUM_add
    COMMAND test_bignum add --scenario basic --seed ${BIGNUM_SEED} --iterations ${BIGNUM_ITERATIONS})

# bn_add's negative-operand and in-place paths are TODOs in bignum.c even
# though the positive/non-in-place path is live; kept as separate CTest
# entries so they don't get lumped in with the passing basic scenario.
add_test(NAME BIGNUM_add_negative
    COMMAND test_bignum add --scenario negative --seed ${BIGNUM_SEED} --iterations ${BIGNUM_ITERATIONS})
set_tests_properties(BIGNUM_add_negative PROPERTIES WILL_FAIL TRUE)

add_test(NAME BIGNUM_add_inplace
    COMMAND test_bignum add --scenario inplace --seed ${BIGNUM_SEED})
set_tests_properties(BIGNUM_add_inplace PROPERTIES WILL_FAIL TRUE)

# Still-stubbed operations (bignum.c: `return BN_OK;` with no logic).
# WILL_FAIL is a forcing function: this test currently "passes" because it's
# *expected* to fail; the day the stub is implemented, remove WILL_FAIL in
# the same change, or CTest will start reporting a spurious failure here.
foreach(OP sub mul div mod modexp)
    add_test(NAME BIGNUM_${OP}
        COMMAND test_bignum ${OP} --seed ${BIGNUM_SEED} --iterations ${BIGNUM_ITERATIONS})
    set_tests_properties(BIGNUM_${OP} PROPERTIES WILL_FAIL TRUE)
endforeach()

# ============================================
# Cryptography I Solutions
# ============================================
add_executable(week1 pa/week1.c)
add_executable(week2 pa/week2.c)
add_executable(week3 pa/week3.c)

target_link_libraries(week1 PRIVATE utils)
target_link_libraries(week2 PRIVATE crypto utils)
target_link_libraries(week3 PRIVATE crypto utils curl)
