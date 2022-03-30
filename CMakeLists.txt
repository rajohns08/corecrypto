# Copyright (c) (2018-2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#

# CMake corecrypto build for Linux
#
# This CMake generates corecrypto_static library. It is meant to be
# used for Linux only.
#

cmake_minimum_required(VERSION 3.4.3)
execute_process(COMMAND "xcrun --sdk macosx --show-sdk-path" OUTPUT_VARIABLE SDK_DIR)
set(CMAKE_OSX_SYSROOT ${SDK_DIR}) # NOTE: This must be set before the call to project
project (corecrypto C)

option(CC_LINUX_ASM "Enable assembler support on Linux platform" OFF)

include (CoreCryptoSources.cmake)

#
# Build Macros and Targets
#

# get_include_dirs: extract include directories from list of headers
macro (get_include_dirs out in)
    foreach (file ${in})

	# Add directory including the header
        get_filename_component(dir ${file} DIRECTORY)
        list(APPEND ${out} ${dir})

        # If the directory is corecrypto, we should also add its
        # parent to the include dir.
        get_filename_component(dirname ${dir} NAME)
	if (${dirname} STREQUAL "corecrypto")
            get_filename_component(parent ${dir} DIRECTORY)
	    list(APPEND ${out} ${parent})
        endif()

    endforeach()
endmacro()


# Project-level settings

## Build all objects with -fPIC
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

## CMake spelling of -std=gnu99
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS ON)

## Project-globals
set_property(DIRECTORY
    APPEND PROPERTY COMPILE_DEFINITIONS
        COMPILING_CORECRYPTO=1
        $<$<CONFIG:Debug>:DEBUG=1>
        $<$<CONFIG:Release>:NDEBUG>
)
set(CC_C_OPTIONS
    -DBUILDKERNEL=0
    -Wundef
    -Wcast-qual
    -Wno-error=deprecated-declarations
    $<$<CONFIG:Debug>:-Werror>
)
add_compile_options(
    "$<$<COMPILE_LANGUAGE:C>:${CC_C_OPTIONS}>"
)

# System dependencies
find_package(UnixCommands REQUIRED) # For ${BASH}
find_package(Threads REQUIRED)
find_library(MATH_LIBRARY m DOC "libm")
if(NOT MATH_LIBRARY)
    message(SEND_ERROR "Could not find libm")
endif()

# Platform-specific dependencies
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")

    find_library(SYSTEM_FRAMEWORK NAMES System)
    mark_as_advanced(SYSTEM_FRAMEWORK)
    find_path(SYSTEM_CPU_CAPABILITIES_PATH i386/cpu_capabilities.h
        HINTS "${SYSTEM_FRAMEWORK}/PrivateHeaders")
    mark_as_advanced(SYSTEM_CPU_CAPABILITIES_PATH)
    if(NOT SYSTEM_FRAMEWORK OR NOT SYSTEM_CPU_CAPABILITIES_PATH)
        unset(SYSTEM_FRAMEWORK CACHE)
        message(SEND_ERROR
            "Could not find internal System.framework\n"
            "HINT: Run cmake with xcrun to point it at the right SDK, or try:\n"
            "  ${CMAKE_COMMAND} -DCMAKE_OSX_SYSROOT=macosx.internal .")
    else()
        message("-- Found internal System.framework")
    endif()

    # Compile assembler sources in OSX
    enable_language(ASM)

    # Enable FIPS POST trace in OSX
    set_source_files_properties(cc_fips/src/fipspost_trace.c cc_fips/crypto_test/crypto_test_cc_fips.c
        PROPERTIES COMPILE_FLAGS -DCORECRYPTO_POST_TRACE=1)

elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")

    # Exclude sources that don't apply to Linux (or haven't yet been ported)
    set (CORECRYPTO_EXCLUDE_SRCS
        # exclude files that are OSX dependent
        cc_fips/src/fipspost_get_cpu_key.c
        cc_fips/src/fipspost_get_hmac.c
        cckprng/src/cckprng_diag.c
        cckprng/src/cckprng_diaggens.c
        cckprng/src/cckprng_generate.c
        cckprng/src/cckprng_init.c
        cckprng/src/cckprng_initgen.c
        cckprng/src/cckprng_loadseed.c
        cckprng/src/cckprng_printdiag.c
        cckprng/src/cckprng_ratchetseed.c
        cckprng/src/cckprng_refresh.c
        cckprng/src/cckprng_rekeygen.c
        cckprng/src/cckprng_rekeygens.c
        cckprng/src/cckprng_reseed.c
        cckprng/src/cckprng_storeseed.c
        cckprng/src/prng.c
    )

    set (CORECRYPTO_TEST_EXCLUDE_SRCS
        # exclude files that are OSX dependent
        cc_fips/src/fipspost_get_cpu_key.c
        cc_fips/src/fipspost_get_hmac.c
        corecrypto_test/lib/ccshadow.c
        corecrypto_test/lib/cccycles.c
        cckprng/crypto_test/crypto_test_kprng.c

        # this test requires trace to be enabled
        cc_fips/crypto_test/crypto_test_cc_fips.c
    )

    set (CORECRYPTO_PERF_EXCLUDE_SRCS
        # exclude files that are OSX dependent
        corecrypto_perf/src/ccperf_kprng.c
    )

    if (CC_LINUX_ASM)
        enable_language(ASM)

        # Add assembler specific clang flags
        set (CC_ASM_OPTIONS
            -integrated-as        # Always use clang internal assembler
            -x assembler-with-cpp # Run preprocessor despite .s name
        )
        add_compile_options(
            "$<$<COMPILE_LANGUAGE:ASM>:${CC_ASM_OPTIONS}>"
        )

       # Enable Linux assembler in corecrypto
        add_compile_options(
            "-DCC_LINUX_ASM=1"
        )
    endif()
endif()

include(GNUInstallDirs)
if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
	message(FATAL_ERROR "Only clang is supported for compilation, found ${CMAKE_C_COMPILER_ID} (${CMAKE_C_COMPILER})")
endif()

#
# corecrypto_static library target
#

# A few include dirs cannot be automatically generated by the above headers
# list. Manually fix it up.
set (CORECRYPTO_FIXED_INCLUDE_DIRS
    ccaes/src/vng
    cckprng
    cckprng/corecrypto
    corecrypto_test/include
    acceleratecrypto/Include
    acceleratecrypto/Header
    ccec25519/src
)

# Find include dirs for corecrypto_static headers.
set (cc_include_dir ${CORECRYPTO_FIXED_INCLUDE_DIRS})
get_include_dirs (cc_include_dir "${CORECRYPTO_PROJECT_HDRS}")
get_include_dirs (cc_include_dir "${CORECRYPTO_PUBLIC_HDRS}")
get_include_dirs (cc_include_dir "${CORECRYPTO_PRIVATE_HDRS}")
list (REMOVE_DUPLICATES cc_include_dir)


# Filter out excluded sources
if(CORECRYPTO_EXCLUDE_SRCS)
    list(REMOVE_ITEM CORECRYPTO_SRCS ${CORECRYPTO_EXCLUDE_SRCS})
endif()


# Create target for corecrypto_static
add_library(corecrypto_static STATIC ${CORECRYPTO_SRCS})
target_link_libraries(corecrypto_static
                      PRIVATE $<$<PLATFORM_ID:Darwin>:${SYSTEM_FRAMEWORK}> ${MATH_LIBRARY})
target_include_directories(corecrypto_static PRIVATE ${cc_include_dir})
set_property(TARGET corecrypto_static PROPERTY POSITION_INDEPENDENT_CODE ON)

# Generate pkgconfig for corecrypto_static
configure_file("corecrypto.pc.in" "corecrypto.pc" @ONLY)

# Install corecrypto_static
install (TARGETS corecrypto_static ARCHIVE
         DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install (FILES ${CORECRYPTO_PUBLIC_HDRS} ${CORECRYPTO_PRIVATE_HDRS}
         DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/corecrypto")
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/corecrypto.pc
         DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")


#
# corecrypto_test target
#

# Remove the .inc and other non C files from the sources
foreach (file ${CORECRYPTO_TEST_SRCS})
    string (REGEX MATCH ".+\\.c$" match ${file})
    if (NOT match)
        list (REMOVE_ITEM CORECRYPTO_TEST_SRCS ${file})
    endif()
endforeach()

# A few include dirs cannot be automatically generated by the above headers
# list. Manually fix it up.
set (CORECRYPTO_TEST_FIXED_INCLUDE_DIRS
    ccsha2/src
    ccrng/src
    ccec25519/src
    ccaes/src/ios_hardware
    corecrypto_test
    cczp/src
)

# Find include dirs for corecrypto_test headers.
set (cctest_include_dir ${CORECRYPTO_TEST_FIXED_INCLUDE_DIRS})
get_include_dirs (cctest_include_dir "${CORECRYPTO_TEST_HDRS}")
get_include_dirs (cctest_include_dir "${CORECRYPTO_TEST_SRCS}")
list (REMOVE_DUPLICATES cctest_include_dir)


# Create target for corecrypto_test
if(CORECRYPTO_TEST_EXCLUDE_SRCS)
    list (REMOVE_ITEM CORECRYPTO_TEST_SRCS ${CORECRYPTO_TEST_EXCLUDE_SRCS})
endif()
add_executable(corecrypto_test ${CORECRYPTO_TEST_SRCS})
target_compile_definitions(corecrypto_test PRIVATE CC_UNITTEST=1)
target_include_directories(corecrypto_test
			   PRIVATE ${cctest_include_dir} ${cc_include_dir})
target_link_libraries(corecrypto_test PRIVATE corecrypto_static
                      Threads::Threads ${MATH_LIBRARY} ${CMAKE_DL_LIBS})

# Generate test vectors
set(CC_CONVERT_TEST_VECTORS scripts/convert_testvectors.sh)
set(CC_TEST_VECTORS corecrypto_test/test_vectors/wycheproof/chacha20_poly1305_test.json)
set(GENERATED_TEST_VECTORS_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen/corecrypto_test/include)
set(GENERATED_TEST_VECTORS ${GENERATED_TEST_VECTORS_DIR}/cc_generated_test_vectors.h
)
add_custom_command(
    OUTPUT ${GENERATED_TEST_VECTORS}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${GENERATED_TEST_VECTORS_DIR}
    COMMAND ${BASH} ${CMAKE_SOURCE_DIR}/${CC_CONVERT_TEST_VECTORS} ${GENERATED_TEST_VECTORS} ${CMAKE_CURRENT_SOURCE_DIR}/corecrypto_test/test_vectors/wycheproof
    COMMENT "Generating test vectors"
    DEPENDS ${CC_CONVERT_TEST_VECTORS} ${CC_TEST_VECTORS}
)
target_sources(corecrypto_test PRIVATE ${GENERATED_TEST_VECTORS})
target_include_directories(corecrypto_test PRIVATE ${GENERATED_TEST_VECTORS_DIR})

set(CC_CONVERT_TEST_VECTORS_PC scripts/convert_h2c_testvectors.py)
message(STATUS "Running python convert_h2c_testvectors.py")
execute_process(
    COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/${CC_CONVERT_TEST_VECTORS_PC} ${CMAKE_CURRENT_SOURCE_DIR}
    RESULT_VARIABLE RESULT_PC
    OUTPUT_VARIABLE OUTPUT_PC
    ERROR_VARIABLE ERROR_PC
)
message(STATUS "result convert_vectors: ${RESULT_PC}")
message(STATUS "output convert_vectors: ${OUTPUT_PC}")
message(STATUS "error convert_vectors: ${ERROR_PC}")

#
# corecrypto_perf target
#

# ccperf.h lives in corecrypto_perf/corecrypto. Add it up
set (CORECRYPTO_PERF_FIXED_INCLUDE_DIRS
    corecrypto_perf/corecrypto
)
set (ccperf_include_dir ${CORECRYPTO_PERF_FIXED_INCLUDE_DIRS})

# Create target for corecrypto_perf
if(CORECRYPTO_PERF_EXCLUDE_SRCS)
    list (REMOVE_ITEM CORECRYPTO_PERF_SRCS ${CORECRYPTO_PERF_EXCLUDE_SRCS})
endif()
add_executable(corecrypto_perf ${CORECRYPTO_PERF_SRCS})
target_include_directories(corecrypto_perf
			   PRIVATE ${ccperf_include_dir} ${cctest_include_dir} ${cc_include_dir})
target_link_libraries(corecrypto_perf PRIVATE corecrypto_static Threads::Threads ${MATH_LIBRARY})
