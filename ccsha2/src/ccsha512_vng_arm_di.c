/* Copyright (c) (2016-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>
#include <corecrypto/cc_runtime_config.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccdigest_priv.h>
#include "ccsha2_internal.h"

#if CC_USE_ASM && CCSHA2_VNG_ARM /* for arm64 or armv7 with neon */

#if CC_ACCELERATECRYPTO
#include "AccelerateCrypto.h"

static void AccelerateCrypto_SHA512(ccdigest_state_t c, size_t num, const void *p)
{
#if !CC_KERNEL && !CC_IBOOT && defined(__arm64__)
#if CC_DARWIN && CC_INTERNAL_SDK
    if (CC_HAS_SHA512()) 
        AccelerateCrypto_SHA512_compress_hwassist((uint64_t*) c, num, p);
    else
#endif
#endif
        AccelerateCrypto_SHA512_compress((uint64_t*) c, num, p);
}

const struct ccdigest_info ccsha512_vng_arm_di = {
    .output_size = CCSHA512_OUTPUT_SIZE,
    .state_size = CCSHA512_STATE_SIZE,
    .block_size = CCSHA512_BLOCK_SIZE,
    .oid_size = ccoid_sha512_len,
    .oid = CC_DIGEST_OID_SHA512,
    .initial_state = ccsha512_initial_state,
    .compress = AccelerateCrypto_SHA512,
    .final = ccsha512_final,
};

const struct ccdigest_info ccsha512_256_vng_arm_di = {
    .output_size = CCSHA512_256_OUTPUT_SIZE,
    .state_size = CCSHA512_256_STATE_SIZE,
    .block_size = CCSHA512_256_BLOCK_SIZE,
    .oid_size = ccoid_sha512_256_len,
    .oid = CC_DIGEST_OID_SHA512_256,
    .initial_state = ccsha512_256_initial_state,
    .compress = AccelerateCrypto_SHA512,
    .final = ccsha512_final,
};

#else   // CC_ACCELERATECRYPTO

void ccsha512_vng_arm64_compress(ccdigest_state_t c, size_t num, const void *p);

const struct ccdigest_info ccsha512_vng_arm_di = {
    .output_size = CCSHA512_OUTPUT_SIZE,
    .state_size = CCSHA512_STATE_SIZE,
    .block_size = CCSHA512_BLOCK_SIZE,
    .oid_size = ccoid_sha512_len,
    .oid = CC_DIGEST_OID_SHA512,
    .initial_state = ccsha512_initial_state,
    .compress = ccsha512_vng_arm64_compress,
    .final = ccsha512_final,
};

const struct ccdigest_info ccsha512_256_vng_arm_di = {
    .output_size = CCSHA512_256_OUTPUT_SIZE,
    .state_size = CCSHA512_256_STATE_SIZE,
    .block_size = CCSHA512_256_BLOCK_SIZE,
    .oid_size = ccoid_sha512_256_len,
    .oid = CC_DIGEST_OID_SHA512_256,
    .initial_state = ccsha512_256_initial_state,
    .compress = ccsha512_vng_arm64_compress,
    .final = ccsha512_final,
};

#endif  // CC_ACCELERATECRYPTO

#endif /* CC_USE_ASM && CCSHA2_VNG_ARM */
