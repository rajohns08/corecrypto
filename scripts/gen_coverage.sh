# Copyright (c) (2018,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#!/bin/bash

# Grab the root directory before anything else happens.
export ROOTDIR=${PWD}
export BRANCHDEFAULT=${BRANCH:=master}

# Echo to stderr.
echoerr() { echo "$@" 1>&2; }

# Polling xcodebuild for project settings is slow; do it only once
# for a given execution.
set_globals() {
    export XCODEPROJ=`ls -d *.xcodeproj | head -1`     # Auto-find the .xcodeproj file.

    echoerr "Finding project directories..."
    export OBJROOT=`xcodebuild -project ${XCODEPROJ} -showBuildSettings -configuration Debug 2>/dev/null | \
        grep " OBJROOT =" | awk '{print $3}'`
    export PRODROOT=`xcodebuild -project ${XCODEPROJ} -showBuildSettings -configuration Debug 2>/dev/null | \
        grep " BUILT_PRODUCTS_DIR = " | awk '{print $3}'`
    export COVROOT=${OBJROOT}/CodeCoverage
    # Required clang flags for enabling coverage
    export COVFLAGS="-fprofile-instr-generate -fcoverage-mapping"

    # For whatever reason, xcodebuild never outputs the top level directory.
    export PROJROOT="$(dirname $(dirname $(dirname ${PRODROOT})))"
    export REPORTDIR="${PWD}/cov_report"
    mkdir -p ${REPORTDIR}
}

compile_for_coverage() {
    XCODESCHEME=$1

    LOG=${REPORTDIR}/build-${XCODESCHEME}.log
    echoerr "Building ${XCODESCHEME}..."
    xcodebuild build -project ${XCODEPROJ} -scheme ${XCODESCHEME}       \
            -configuration Debug                                        \
            -destination 'platform=macOS,arch=x86_64' --                \
            OTHER_CFLAGS="${COVFLAGS} \${inherited}"                    \
            OTHER_LDFLAGS="${COVFLAGS} \${inherited}"                   \
        >> ${LOG} 2>&1
    ERR=$?
    if [ ${ERR} != 0 ]; then
        echoerr "Failed; examine ${LOG}"
        exit -1
    fi
}

# Execute an arbitrary binary built through the specified xcode project
# and acquire the coverage results.
#
# Expects the binary to already have been built.
#
# generate_bin_coverage <scheme>
#
# For example:
#    generate_bin_coverage corecrypto_test
generate_bin_coverage() {
    XCODESCHEME=$1

    if [ "${XCODESCHEME}" == "" ]; then
        echoerr "missing: xcodescheme"
        exit -1
    fi

    # If the binary is deployed/installed somewhere else, it ends up in a
    # BuildProducts subdirectory.  Use find to simplify searching.
    TESTBIN=`find ${PRODROOT} -name ${XCODESCHEME} | grep -v dSYM | head -1`
    echoerr "Executing ${TESTBIN}..."

    echo DYLD_PRINT_LIBRARIES=1                                         \
            DYLD_PRINT_LIBRARIES_POST_LAUNCH=1                          \
            DYLD_FRAMEWORK_PATH=${PRODROOT}                             \
            DYLD_LIBRARY_PATH=${PRODROOT}                               \
            LLVM_PROFILE_FILE=${REPORTDIR}/${XCODESCHEME}.profraw       \
            ${TESTBIN}                                                  \
        >> ${REPORTDIR}/${XCODESCHEME}.log 2>&1
    DYLD_PRINT_LIBRARIES=1                                              \
            DYLD_PRINT_LIBRARIES_POST_LAUNCH=1                          \
            DYLD_FRAMEWORK_PATH=${PRODROOT}                             \
            DYLD_LIBRARY_PATH=${PRODROOT}                               \
            LLVM_PROFILE_FILE=${REPORTDIR}/${XCODESCHEME}.profraw       \
            ${TESTBIN}                                                  \
        >> ${REPORTDIR}/${XCODESCHEME}.log 2>&1
    RET=$?
    if [ ${RET} != 0 ]; then
        echoerr "Note: test ${TESTBIN} failed: ${RET}"
        exit -1
    fi

    # Add to the list of binaries that've been tested.
    BINARIES="${BINARIES} ${TESTBIN}"
}

# Create a report from a 'run.profdata' file in the report directory
#
# generate_report [exclude paths...]
#
# For example:
#    generate_report Applications OSX
generate_report() {
    EXCLUDE_PATHS="$@"

    if [ "${BINARIES}" == "" ]; then
        echoerr "missing: tested binaries"
        exit -1
    fi

    COVBINS=
    BINARIES="`ls ${BINARIES} | sort -u`"
    echo "Generating list of binaries:"
    for bin in ${BINARIES}; do
        echo "    -- ${bin}"
        if [ "${COVBINS}" == "" ]; then
            COVBINS=${bin}
        else
            COVBINS="${COVBINS} -object ${bin}"
        fi
    done

    echoerr "Merging coverage data..."
    xcrun llvm-profdata merge ${REPORTDIR}/*.profraw -o ${REPORTDIR}/run.profdata
    RET=$?
    if [ ${RET} != 0 ]; then
        echoerr "failed merging coverage data: ${RET}"
        exit -1
    fi

    echoerr "Generating coverage report..."
    echo xcrun --toolchain osx llvm-cov show                                                                     \
            -instr-profile=${REPORTDIR}/run.profdata -format=html -output-dir=${REPORTDIR}  \
            ${COVBINS}
    xcrun --toolchain osx llvm-cov show                                                                     \
            -instr-profile=${REPORTDIR}/run.profdata -format=html -output-dir=${REPORTDIR}  \
            ${COVBINS}
    RET=$?
    if [ ${RET} != 0 ]; then
        echoerr "failed coverage report generation: ${RET}"
        echoerr ""
        echoerr "This failure often occurs because binaries that weren't"
        echoerr "exercised as part of the unit tests are included in the llvm-cov report"
        echoerr "generation.  If the test uses the 'add_all_binaries_to_report' command,"
        echoerr "consider switching to one of the more specific variants.  Because there"
        echoerr "is quite a bit of variability on where frameworks live, the 'find_'"
        echoerr "variant of the function may be necessary instead."
        exit -1
    fi

    open ${REPORTDIR}/index.html
}