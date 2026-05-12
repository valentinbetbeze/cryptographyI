cmake_minimum_required(VERSION 3.31)
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
# FIPS Test Infrastructure
# ============================================
# Find Python
find_package(Python3 COMPONENTS Interpreter REQUIRED)

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

target_link_libraries(test_des_ecb      PRIVATE crypto utils)
target_link_libraries(test_aes_ecb      PRIVATE crypto utils)
target_link_libraries(test_aes_ecb_mct  PRIVATE crypto utils)
target_link_libraries(test_aes_cbc      PRIVATE crypto utils)
target_link_libraries(test_aes_cbc_mct  PRIVATE crypto utils)
target_link_libraries(test_aes_ctr      PRIVATE crypto utils)
target_link_libraries(test_sha          PRIVATE crypto utils)
target_link_libraries(test_sha_mct      PRIVATE crypto utils)

add_fips_tests(test_des_ecb     "des/fips_kat" "TECB")
add_fips_tests(test_aes_ecb     "aes/fips_kat" "ECB")
add_fips_tests(test_aes_ecb_mct "aes/fips_mct" "ECB")
add_fips_tests(test_aes_cbc     "aes/fips_kat" "CBC")
add_fips_tests(test_aes_cbc_mct "aes/fips_mct" "CBC")
add_fips_tests(test_aes_ctr     "aes/fips_kat" "CTR")
add_fips_tests(test_sha         "sha/fips_kat" "SHA")
add_fips_tests(test_sha         "sha/fips_mct" "SHA")

# ============================================
# Cryptography I Solutions
# ============================================
add_executable(week1 pa/week1.c)
add_executable(week2 pa/week2.c)

target_link_libraries(week1 PRIVATE utils)
target_link_libraries(week2 PRIVATE crypto utils)
